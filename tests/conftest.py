import os

import pytest

from app import create_app, db
from app.models import KeyDeployment, Server, SSHKey, User


@pytest.fixture(scope="module")
def test_client():
    # Set the Testing configuration prior to creating the Flask application
    os.environ["FLASK_ENV"] = "testing"
    flask_app = create_app("testing")

    # Create a test client using the Flask application configured for testing
    with flask_app.test_client() as testing_client:
        # Establish an application context
        with flask_app.app_context():
            yield testing_client


@pytest.fixture(scope="function")
def init_database(test_client):
    # Create the database and the database table
    db.create_all()

    # Insert user data
    user = User(username="testuser", is_admin=True)
    user.set_password("testpassword")
    db.session.add(user)
    db.session.commit()

    yield db

    db.session.remove()
    db.drop_all()


@pytest.fixture(scope="function")
def auth_client(test_client, init_database):
    # Login
    test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=True
    )

    yield test_client

    # Logout
    test_client.get("/logout", follow_redirects=True)


@pytest.fixture(scope="function")
def new_user():
    user = User(username="newuser", is_admin=False)
    user.set_password("newpassword")
    return user


@pytest.fixture(scope="function")
def new_server(init_database):
    user = User.query.filter_by(username="testuser").first()
    server = Server(
        name="Test Server",
        ip_address="192.168.1.100",
        username="root",
        user_id=user.id,
        ssh_port=22,
    )
    db.session.add(server)
    db.session.commit()
    return server


@pytest.fixture(scope="function")
def new_ssh_key(init_database):
    user = User.query.filter_by(username="testuser").first()
    # Generate a dummy key for testing
    key_content = b"dummy_encrypted_private_key"
    ssh_key = SSHKey(
        name="Test Key",
        public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL... comment",
        private_key_encrypted=key_content,
        fingerprint="SHA256:dummyfingerprint",
        key_type="Ed25519",
        user_id=user.id,
    )
    db.session.add(ssh_key)
    db.session.commit()
    return ssh_key
