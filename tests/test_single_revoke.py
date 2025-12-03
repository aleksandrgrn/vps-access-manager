from unittest.mock import patch

import pytest

from app import create_app, db
from app.models import User


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for testing

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_user(app):
    user = User(username="testuser")
    user.set_password("password")
    db.session.add(user)
    db.session.commit()
    return user


def login(client, user):
    client.post(
        "/login", data={"username": user.username, "password": "password"}, follow_redirects=True
    )


@patch("app.routes.deployments.deployment_service")
def test_revoke_single_success(mock_service, client, auth_user):
    login(client, auth_user)

    # Mock service response
    mock_service.revoke_deployment_by_id.return_value = {
        "success": True,
        "message": "Key successfully revoked from VPS",
        "server": "test-server",
        "ip": "192.168.1.1",
        "key_name": "test-key",
    }

    response = client.post("/api/key-deployments/revoke", json={"deployment_id": 123})

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["server_name"] == "test-server"
    assert data["server_ip"] == "192.168.1.1"
    assert data["key_name"] == "test-key"
    assert data["status"] == "revoked"


@patch("app.routes.deployments.deployment_service")
def test_revoke_single_failed(mock_service, client, auth_user):
    login(client, auth_user)

    # Mock service response
    mock_service.revoke_deployment_by_id.return_value = {
        "success": False,
        "message": "SSH connection failed",
        "server": "test-server",
        "error_type": "ssh_error",
        "key_name": "test-key",
    }

    response = client.post("/api/key-deployments/revoke", json={"deployment_id": 123})

    assert response.status_code == 500  # Route returns 500 for generic errors
    data = response.get_json()
    assert data["success"] is False
    assert data["server_name"] == "test-server"
    assert data["status"] == "failed"
    assert data["error_type"] == "ssh_error"


@patch("app.routes.deployments.deployment_service")
def test_revoke_single_skipped(mock_service, client, auth_user):
    login(client, auth_user)

    # Mock service response
    mock_service.revoke_deployment_by_id.return_value = {
        "success": False,
        "message": "Key already revoked",
        "error_type": "already_revoked",
        "key_name": "test-key",
    }

    response = client.post("/api/key-deployments/revoke", json={"deployment_id": 123})

    assert response.status_code == 400  # Route returns 400 for already_revoked
    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "skipped"
    assert data["error_type"] == "already_revoked"
