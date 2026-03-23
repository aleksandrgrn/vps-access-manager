from unittest.mock import Mock, patch

import pytest

from app.models import KeyDeployment, SSHKey, User


@pytest.fixture
def mock_ssh_keygen():
    with patch("app.services.ssh.keys.generate_ssh_key") as mock:
        yield mock


@pytest.fixture
def mock_ssh_fingerprint():
    with patch("app.services.ssh.keys.get_fingerprint") as mock:
        yield mock


@pytest.fixture
def mock_ssh_validate():
    with patch("app.services.ssh.keys.validate_ssh_public_key") as mock:
        yield mock


def test_generate_key_success(auth_client, mock_ssh_keygen, mock_ssh_fingerprint):
    """Test successful key generation."""
    mock_ssh_keygen.return_value = ("private_pem", "ssh-ed25519 public_key")
    mock_ssh_fingerprint.return_value = "SHA256:new_fingerprint"

    response = auth_client.post(
        "/api/keys/generate", data=dict(name="New Key", key_type="ed25519"), follow_redirects=True
    )

    assert response.status_code == 200
    assert b"New Key" in response.data
    assert SSHKey.query.filter_by(name="New Key").first() is not None


def test_generate_key_duplicate_name(auth_client, new_ssh_key):
    """Test generating key with duplicate name."""
    response = auth_client.post(
        "/api/keys/generate",
        data=dict(name="Test Key", key_type="ed25519"),  # Already exists
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert (
        b"\xd1\x83\xd0\xb6\xd0\xb5 \xd1\x81\xd1\x83\xd1\x89\xd0\xb5\xd1\x81\xd1\x82"
        b"\xd0\xb2\xd1\x83\xd0\xb5\xd1\x82" in response.data
    )  # "уже существует"


def test_upload_key_success(auth_client, mock_ssh_validate, mock_ssh_fingerprint):
    """Test successful key upload."""
    mock_ssh_validate.return_value = True
    mock_ssh_fingerprint.return_value = "SHA256:uploaded_fingerprint"

    response = auth_client.post(
        "/api/keys/upload",
        data=dict(name="Uploaded Key", public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Uploaded Key" in response.data
    assert SSHKey.query.filter_by(name="Uploaded Key").first() is not None


def test_delete_key(auth_client, new_ssh_key):
    """Test deleting a key."""
    response = auth_client.post(f"/api/keys/delete/{new_ssh_key.id}", follow_redirects=True)
    assert response.status_code == 200
    assert SSHKey.query.get(new_ssh_key.id) is None


def test_download_key_pem_success(auth_client, new_ssh_key):
    """Test successful PEM private key download."""
    private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "A" * 128
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    with patch("app.routes.keys.decrypt_access_key") as mock_decrypt:
        mock_decrypt.return_value = {"success": True, "private_key": private_key}

        response = auth_client.get(f"/api/keys/download/{new_ssh_key.id}")

    assert response.status_code == 200
    assert response.data == private_key.encode("utf-8")
    assert "TestKey.pem" in response.headers["Content-Disposition"]
    assert response.mimetype == "application/x-pem-file"
    assert response.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"


def test_download_key_ppk_success(auth_client, new_ssh_key):
    """Test successful PPK private key download."""
    private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "B" * 128
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    ppk_content = b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"

    def mock_puttygen(command, capture_output, text, timeout, check):
        output_path = command[-1]
        with open(output_path, "wb") as output_file:
            output_file.write(ppk_content)

        return Mock(returncode=0, stdout="", stderr="")

    with patch("app.routes.keys.decrypt_access_key") as mock_decrypt, patch(
        "app.services.ssh.keys.get_secure_temp_dir", return_value="/tmp"
    ), patch("app.services.ssh.keys.get_puttygen_path", return_value="/usr/bin/puttygen"), patch(
        "app.services.ssh.keys.subprocess.run", side_effect=mock_puttygen
    ):
        mock_decrypt.return_value = {"success": True, "private_key": private_key}

        response = auth_client.get(f"/api/keys/download/{new_ssh_key.id}/ppk")

    assert response.status_code == 200
    assert response.data == ppk_content
    assert "TestKey.ppk" in response.headers["Content-Disposition"]
    assert response.mimetype == "application/octet-stream"
    assert response.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"


def test_download_key_ppk_missing_private_material(auth_client, new_ssh_key):
    """Test PPK download returns controlled error for public-only keys."""
    with patch("app.routes.keys.decrypt_access_key") as mock_decrypt, patch(
        "app.services.ssh.keys.subprocess.run"
    ) as mock_puttygen:
        mock_decrypt.return_value = {
            "success": False,
            "message": "Расшифрованный ключ невалиден",
            "error_type": "invalid_decrypted_key",
        }

        response = auth_client.get(
            f"/api/keys/download/{new_ssh_key.id}/ppk", follow_redirects=True
        )

    assert response.status_code == 200
    assert "Для этого ключа недоступна выгрузка .ppk".encode("utf-8") in response.data
    mock_puttygen.assert_not_called()


def test_download_key_ppk_conversion_error(auth_client, new_ssh_key):
    """Test PPK download returns controlled error when conversion fails."""
    private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "C" * 128
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    with patch("app.routes.keys.decrypt_access_key") as mock_decrypt, patch(
        "app.services.ssh.keys.get_secure_temp_dir", return_value="/tmp"
    ), patch("app.services.ssh.keys.get_puttygen_path", return_value="/usr/bin/puttygen"), patch(
        "app.services.ssh.keys.subprocess.run"
    ) as mock_puttygen:
        mock_decrypt.return_value = {"success": True, "private_key": private_key}
        mock_puttygen.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="conversion failed",
        )

        response = auth_client.get(
            f"/api/keys/download/{new_ssh_key.id}/ppk", follow_redirects=True
        )

    assert response.status_code == 200
    assert "Ошибка при скачивании .ppk".encode("utf-8") in response.data


def test_deploy_key_success(auth_client, new_server, new_ssh_key):
    """Test successful key deployment."""
    # Setup server access key
    new_server.access_key = new_ssh_key
    from app import db

    db.session.commit()

    # Get the user ID (auth_client uses 'testuser')
    user = User.query.filter_by(username="testuser").first()
    assert user is not None

    # We mock the specific low-level SSH operations, not the whole service
    with patch("app.services.deployment_service.decrypt_access_key") as mock_decrypt, patch(
        "app.services.deployment_service.ssh_connection"
    ) as mock_conn, patch("app.services.deployment_service.deploy_key_to_server") as mock_deploy_op:

        # 1. Mock decryption success
        mock_decrypt.return_value = {"success": True, "private_key": "fake_private_key"}

        # 2. Mock SSH connection (context manager)
        # mock_conn is a context manager, so we mock what it yields
        mock_conn.return_value.__enter__.return_value = "mock_connection"

        # 3. Mock deployment operation success
        mock_deploy_op.return_value = {"success": True, "message": "Key successfully deployed"}

        response = auth_client.post(
            "/api/keys/deploy", json={"key_id": new_ssh_key.id, "server_id": new_server.id}
        )

        assert response.status_code == 200
        assert response.json["success"] is True

        # Verify mocks were called
        mock_decrypt.assert_called_once()
        mock_conn.assert_called_once()
        mock_deploy_op.assert_called_once()

        # Verify DB side effects: KeyDeployment should be created
        deployment = KeyDeployment.query.filter_by(
            ssh_key_id=new_ssh_key.id, server_id=new_server.id, revoked_at=None
        ).first()

        assert deployment is not None
        assert deployment.deployed_by == user.id


def test_bulk_deploy_keys(auth_client, new_server, new_ssh_key):
    """Test bulk key deployment."""
    new_server.access_key = new_ssh_key
    from app import db

    db.session.commit()

    with patch("app.routes.keys.bulk_deploy_keys") as mock_bulk, patch(
        "app.routes.keys.decrypt_access_key"
    ) as mock_decrypt:

        mock_decrypt.return_value = {"success": True, "private_key": "priv"}
        mock_bulk.return_value = {
            "deployed": [{"server_id": new_server.id, "server_name": new_server.name}],
            "failed": [],
            "total": 1,
        }

        response = auth_client.post(
            "/api/keys/bulk-deploy", json={"key_id": new_ssh_key.id, "server_ids": [new_server.id]}
        )

        assert response.status_code == 200
        assert response.json["success"] is True
        assert len(response.json["deployed"]) == 1


def test_bulk_deploy_keys_with_skipped(auth_client, new_server, new_ssh_key):
    """Test bulk key deployment with skipped items."""
    new_server.access_key = new_ssh_key
    from app import db

    db.session.commit()

    with patch("app.routes.keys.bulk_deploy_keys") as mock_bulk, patch(
        "app.routes.keys.decrypt_access_key"
    ) as mock_decrypt:

        mock_decrypt.return_value = {"success": True, "private_key": "priv"}
        mock_bulk.return_value = {
            "deployed": [],
            "skipped": [
                {
                    "server_id": new_server.id,
                    "server_name": new_server.name,
                    "reason": "Already exists",
                }
            ],
            "failed": [],
            "total": 1,
        }

        response = auth_client.post(
            "/api/keys/bulk-deploy", json={"key_id": new_ssh_key.id, "server_ids": [new_server.id]}
        )

        assert response.status_code == 200
        assert response.json["success"] is True
        assert len(response.json["deployed"]) == 0
        assert len(response.json["skipped"]) == 1
        assert response.json["skipped"][0]["reason"] == "Already exists"
