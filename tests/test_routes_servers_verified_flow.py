from unittest.mock import patch

from app.models import KeyDeployment, SSHKey, Server


def test_add_server_failure_does_not_persist_without_verified_root_key_auth(auth_client):
    payload = {
        "name": "Unverified Server",
        "ip_address": "192.0.2.60",
        "ssh_port": 22,
        "username": "admin",
        "password": "secret",
    }

    with patch("app.routes.servers.initialize_server") as mock_initialize, patch(
        "app.routes.servers.ssh_keys.generate_ssh_key"
    ) as mock_generate_key, patch("app.routes.servers.ssh_keys.get_fingerprint") as mock_fingerprint, patch(
        "app.routes.servers.ssh_keys.encrypt_private_key"
    ) as mock_encrypt_key, patch(
        "app.routes.servers.ssh_bootstrap.bootstrap_server_access"
    ) as mock_bootstrap:
        mock_initialize.return_value = {
            "success": True,
            "openssh_version": "9.6",
            "requires_legacy_ssh": False,
            "message": "ok",
        }
        mock_generate_key.return_value = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcRouteKeyData test@example.com",
        )
        mock_fingerprint.return_value = "aa:bb:cc:dd"
        mock_encrypt_key.return_value = b"encrypted-private-key"
        mock_bootstrap.return_value = {
            "success": False,
            "error_type": "verification_failed",
            "message": "Root key auth not verified",
        }

        response = auth_client.post("/api/servers/add", json=payload)

    assert response.status_code == 400
    assert response.json["success"] is False
    assert Server.query.filter_by(name="Unverified Server").first() is None
    assert SSHKey.query.filter_by(name="root_Unverified Server").first() is None
    assert KeyDeployment.query.count() == 0


def test_sudo_user_bootstrap_success_persists_username_as_root(auth_client):
    payload = {
        "name": "Promoted Server",
        "ip_address": "192.0.2.61",
        "ssh_port": 22,
        "username": "admin",
        "password": "secret",
    }

    with patch("app.routes.servers.initialize_server") as mock_initialize, patch(
        "app.routes.servers.ssh_keys.generate_ssh_key"
    ) as mock_generate_key, patch("app.routes.servers.ssh_keys.get_fingerprint") as mock_fingerprint, patch(
        "app.routes.servers.ssh_keys.encrypt_private_key"
    ) as mock_encrypt_key, patch(
        "app.routes.servers.ssh_bootstrap.bootstrap_server_access"
    ) as mock_bootstrap:
        mock_initialize.return_value = {
            "success": True,
            "openssh_version": "9.6",
            "requires_legacy_ssh": False,
            "message": "ok",
        }
        mock_generate_key.return_value = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcRouteKeyData test@example.com",
        )
        mock_fingerprint.return_value = "aa:bb:cc:ee"
        mock_encrypt_key.return_value = b"encrypted-private-key"
        mock_bootstrap.return_value = {
            "success": True,
            "verified": True,
            "remediated": False,
            "target_username": "root",
            "message": "Root key auth verified",
        }

        response = auth_client.post("/api/servers/add", json=payload)

    assert response.status_code == 200
    server = Server.query.filter_by(name="Promoted Server").first()
    assert server is not None
    assert server.username == "root"
    assert mock_bootstrap.call_args.kwargs["bootstrap_username"] == "admin"


def test_bulk_import_uses_shared_root_target_flow(auth_client):
    payload = {
        "servers_data": "alpha admin pass 192.0.2.71 22\nbeta admin pass 192.0.2.72 22"
    }

    with patch("app.routes.servers._provision_server_with_verified_key_auth") as mock_flow:
        mock_flow.side_effect = [
            {
                "success": True,
                "server_name": "alpha",
                "ip_address": "192.0.2.71",
                "target_username": "root",
            },
            {
                "success": False,
                "server_name": "beta",
                "ip_address": "192.0.2.72",
                "message": "Root key auth not verified",
            },
        ]

        response = auth_client.post("/api/bulk-import-servers", json=payload)

    assert response.status_code == 200
    assert len(response.json["added"]) == 1
    assert len(response.json["failed"]) == 1
    assert mock_flow.call_count == 2
    assert mock_flow.call_args_list[0].kwargs["username"] == "admin"
    assert mock_flow.call_args_list[1].kwargs["username"] == "admin"
