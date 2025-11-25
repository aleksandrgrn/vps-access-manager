from unittest.mock import patch

import pytest

from app.models import Server


@pytest.fixture
def mock_ssh_init():
    with patch("app.services.ssh.initialize_server") as mock:
        yield mock


@pytest.fixture
def mock_ssh_keygen():
    with patch("app.services.ssh.generate_ssh_key") as mock:
        yield mock


@pytest.fixture
def mock_ssh_fingerprint():
    with patch("app.services.ssh.get_fingerprint") as mock:
        yield mock


@pytest.fixture
def mock_ssh_deploy_password():
    with patch("app.services.ssh.deploy_key_with_password") as mock:
        yield mock


@pytest.mark.skip(reason="Требует рефакторинга SSH")
def test_add_server_success(
    auth_client, mock_ssh_init, mock_ssh_keygen, mock_ssh_fingerprint, mock_ssh_deploy_password
):
    """Test successful server addition."""
    # Setup mocks
    mock_ssh_init.return_value = {
        "success": True,
        "openssh_version": "OpenSSH_8.9p1",
        "requires_legacy_ssh": False,
    }
    mock_ssh_keygen.return_value = ("private_pem", "ssh-ed25519 public_key")
    mock_ssh_fingerprint.return_value = "SHA256:fingerprint"
    mock_ssh_deploy_password.return_value = {"success": True}

    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="New Server",
            ip_address="192.168.1.200",
            ssh_port=22,
            username="root",
            password="password",
        ),
        follow_redirects=True,
    )

    if b"New Server" not in response.data:
        with open("debug_server_add.html", "wb") as f:
            f.write(response.data)

    assert response.status_code == 200
    assert b"New Server" in response.data
    assert Server.query.filter_by(name="New Server").first() is not None


@pytest.mark.skip(reason="Требует рефакторинга SSH")
def test_add_server_duplicate(auth_client, new_server):
    """Test adding a duplicate server."""
    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="Duplicate Server",
            ip_address="192.168.1.100",  # Same IP as new_server
            ssh_port=22,
            username="root",
            password="password",
        ),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert (
        b"\xd1\x83\xd0\xb6\xd0\xb5 \xd0\xb4\xd0\xbe\xd0\xb1\xd0\xb0\xd0\xb2\xd0\xbb\xd0\xb5\xd0\xbd"
        in response.data
    )  # "уже добавлен"


@pytest.mark.skip(reason="Требует рефакторинга SSH")
def test_add_server_init_fail(auth_client, mock_ssh_init):
    """Test server addition with initialization failure."""
    mock_ssh_init.return_value = {"success": False, "message": "Connection failed"}

    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="Fail Init Server",
            ip_address="192.168.1.201",
            ssh_port=22,
            username="root",
            password="password",
        ),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Connection failed" in response.data
    assert Server.query.filter_by(name="Fail Init Server").first() is None


@pytest.mark.skip(reason="Требует рефакторинга SSH")
def test_add_server_deploy_fail(
    auth_client, mock_ssh_init, mock_ssh_keygen, mock_ssh_fingerprint, mock_ssh_deploy_password
):
    """Test server addition with deployment failure."""
    mock_ssh_init.return_value = {
        "success": True,
        "openssh_version": "OpenSSH_8.9p1",
        "requires_legacy_ssh": False,
    }
    mock_ssh_keygen.return_value = ("private_pem", "ssh-ed25519 public_key")
    mock_ssh_fingerprint.return_value = "SHA256:fingerprint_fail"
    mock_ssh_deploy_password.return_value = {"success": False, "message": "Auth failed"}

    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="Fail Deploy Server",
            ip_address="192.168.1.202",
            ssh_port=22,
            username="root",
            password="password",
        ),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Auth failed" in response.data
    assert Server.query.filter_by(name="Fail Deploy Server").first() is None


def test_edit_server(auth_client, new_server):
    """Test editing a server."""
    response = auth_client.post(
        f"/api/servers/edit/{new_server.id}",
        data=dict(
            name="Updated Server",
            ip_address="192.168.1.101",
            ssh_port=2222,
            username="admin",
            requires_legacy_ssh="y",
        ),
        follow_redirects=True,
    )

    assert response.status_code == 200
    updated_server = Server.query.get(new_server.id)
    assert updated_server.name == "Updated Server"
    assert updated_server.ip_address == "192.168.1.101"
    assert updated_server.ssh_port == 2222
    assert updated_server.username == "admin"


def test_delete_server(auth_client, new_server):
    """Test deleting a server."""
    response = auth_client.post(f"/api/servers/delete/{new_server.id}", follow_redirects=True)
    assert response.status_code == 200
    assert Server.query.get(new_server.id) is None


def test_test_server_connection_success(auth_client, new_server, new_ssh_key):
    """Test server connection check success."""
    # Assign key to server
    new_server.access_key = new_ssh_key
    from app import db

    db.session.commit()

    with patch("app.routes.servers.test_server_connection") as mock_test:
        mock_test.return_value = {"success": True, "message": "Connected"}
        with patch("app.routes.servers.decrypt_access_key") as mock_decrypt:
            mock_decrypt.return_value = {"success": True, "private_key": "privkey"}

            response = auth_client.post(f"/api/servers/test/{new_server.id}")

            assert response.status_code == 200
            assert response.json["success"] is True
            assert response.json["status"] == "online"


@pytest.mark.skip(reason="Требует рефакторинга SSH")
def test_bulk_import_servers(auth_client):
    """Test bulk import of servers."""
    data = {"servers_data": "server1 root pass 10.0.0.10 22\nserver2 root pass 10.0.0.11 22"}

    with patch("app.services.ssh.initialize_server") as mock_init, patch(
        "app.services.ssh.generate_ssh_key"
    ) as mock_gen, patch("app.services.ssh.get_fingerprint") as mock_fp, patch(
        "app.services.ssh.deploy_key_with_password"
    ) as mock_deploy:

        mock_init.return_value = {
            "success": True,
            "message": "Initialized",
            "openssh_version": "OpenSSH_8.9p1",
            "requires_legacy_ssh": False,
        }
        mock_gen.return_value = ("priv", "pub")
        mock_fp.side_effect = ["fp1", "fp2"]
        mock_deploy.return_value = {"success": True, "message": "Deployed"}

        response = auth_client.post("/api/bulk-import-servers", json=data)

        if response.json["added"] != 2:
            print(f"Bulk import response: {response.json}")

        assert response.status_code == 200
        assert response.json["added"] == 2
        assert Server.query.filter_by(name="server1").first() is not None
        assert Server.query.filter_by(name="server2").first() is not None
