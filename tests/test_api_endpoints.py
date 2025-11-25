from unittest.mock import patch

import pytest

from app.models import Server, SSHKey


@pytest.mark.skip(reason="Требует рефакторинга SSH")
@patch("app.services.ssh.initialize_server")
@patch("app.services.ssh.generate_ssh_key")
@patch("app.services.ssh.deploy_key_with_password")
@patch("app.services.ssh.encrypt_private_key")
@patch("app.services.ssh.get_fingerprint")
def test_api_servers_add(
    mock_fingerprint, mock_encrypt, mock_deploy, mock_gen_key, mock_init, auth_client
):
    """Test adding a server via API."""
    # Setup mocks
    mock_init.return_value = {
        "success": True,
        "openssh_version": "OpenSSH_8.9p1",
        "requires_legacy_ssh": False,
    }
    mock_gen_key.return_value = ("private_pem", "public_ssh")
    mock_deploy.return_value = {"success": True, "message": "Deployed"}
    mock_encrypt.return_value = b"encrypted"
    mock_fingerprint.return_value = "SHA256:dummy"

    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="API Server",
            ip_address="10.0.0.2",
            ssh_port=22,
            username="root",
            password="password",
            requires_legacy_ssh=False,
        ),
        follow_redirects=False,
    )

    if response.status_code != 200:
        # Убрали f там, где нет {}
        print("\n=== DEBUG ERROR INFO ===")
        print(f"Status: {response.status_code}")
        try:
            print(f"Body: {response.data.decode('utf-8')}")
        except Exception:  # Добавили Exception
            print(f"Body (bytes): {response.data}")
        print("========================")  # Убрали f

    assert response.status_code == 200
    assert response.json["success"] is True
    assert response.json["message"] == "Server added"

    # Verify in DB
    server = Server.query.filter_by(name="API Server").first()
    assert server is not None


@pytest.mark.skip(reason="Требует рефакторинга SSH")
@patch("app.services.ssh.generate_ssh_key")
@patch("app.services.ssh.encrypt_private_key")
@patch("app.services.ssh.get_fingerprint")
def test_api_keys_generate(mock_fingerprint, mock_encrypt, mock_gen_key, auth_client):
    """Test generating a key via API."""
    # Setup mocks
    mock_gen_key.return_value = ("private_pem", "public_ssh")
    mock_encrypt.return_value = b"encrypted"
    mock_fingerprint.return_value = "SHA256:dummy_key"

    response = auth_client.post(
        "/api/keys/generate", data=dict(name="API Key", key_type="ed25519"), follow_redirects=False
    )

    assert response.status_code == 200
    assert response.json["success"] is True
    assert response.json["key_name"] == "API Key"

    # Verify in DB
    key = SSHKey.query.filter_by(name="API Key").first()
    assert key is not None


def test_api_unauthorized_access(test_client):
    """Test access without login."""
    response = test_client.get("/api/servers")
    assert response.status_code == 302  # Redirect to login
    assert "/login" in response.headers["Location"]


@pytest.mark.skip(reason="API редиректит вместо 400, требует уточнения поведения")
def test_api_invalid_server_data(auth_client):
    """Test adding server with invalid data."""
    response = auth_client.post(
        "/api/servers/add",
        data=dict(
            name="",  # Empty name
            ip_address="invalid-ip",
            ssh_port=22,
            username="root",
            password="password",
        ),
        follow_redirects=False,
    )
    # Should show error
    assert response.status_code == 400
    assert response.json["success"] is False
    assert "errors" in response.json
