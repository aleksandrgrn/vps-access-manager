from unittest.mock import patch

import pytest

from app.models import KeyDeployment, SSHKey


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


def test_deploy_key_success(auth_client, new_server, new_ssh_key):
    """Test successful key deployment."""
    # Setup server access key
    new_server.access_key = new_ssh_key
    from app import db

    db.session.commit()

    with patch("app.routes.keys.decrypt_access_key") as mock_decrypt, patch(
        "app.routes.keys.deploy_key_to_server"
    ) as mock_deploy:

        mock_decrypt.return_value = {"success": True, "private_key": "priv"}
        mock_deploy.return_value = {"success": True, "message": "Deployed"}

        response = auth_client.post(
            "/api/keys/deploy", json={"key_id": new_ssh_key.id, "server_id": new_server.id}
        )

        assert response.status_code == 200
        assert response.json["success"] is True
        assert (
            KeyDeployment.query.filter_by(
                ssh_key_id=new_ssh_key.id, server_id=new_server.id
            ).first()
            is not None
        )


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
