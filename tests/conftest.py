import os

import pytest
from flask.testing import FlaskClient

from app import create_app, db
from app.models import Server, SSHKey, User


class CSRFTestClient(FlaskClient):
    def __init__(self, *args, **kwargs):
        super(CSRFTestClient, self).__init__(*args, **kwargs)

    def open(self, *args, **kwargs):
        # Only add CSRF token for state-changing methods
        if kwargs.get("method", "GET") in ["POST", "PUT", "DELETE", "PATCH"]:
            csrf_token = None

            # Try to get raw token from session
            with self.session_transaction() as sess:
                raw_token = sess.get("csrf_token")

            if not raw_token:
                # Make a GET request to trigger token generation in session
                super(CSRFTestClient, self).open("/", method="GET")

                # Try getting token again
                with self.session_transaction() as sess:
                    raw_token = sess.get("csrf_token")

            if raw_token:
                # Sign the token using the app's secret key
                from itsdangerous import URLSafeTimedSerializer

                secret_key = (
                    self.application.config.get("WTF_CSRF_SECRET_KEY")
                    or self.application.config["SECRET_KEY"]
                )
                s = URLSafeTimedSerializer(secret_key, salt="wtf-csrf-token")
                csrf_token = s.dumps(raw_token)

                # print(f"DEBUG: Signed CSRF Token: {csrf_token}")

            if csrf_token:
                # Inject into headers
                headers = kwargs.get("headers", {})
                if "X-CSRFToken" not in headers:
                    headers["X-CSRFToken"] = csrf_token

                # Add Referer to satisfy strict CSRF checks if enabled
                if "Referer" not in headers:
                    headers["Referer"] = "http://localhost/"

                kwargs["headers"] = headers

                # Also inject into data if it's a dict (for form data)
                data = kwargs.get("data")
                if data and isinstance(data, dict) and "csrf_token" not in data:
                    data["csrf_token"] = csrf_token

        return super(CSRFTestClient, self).open(*args, **kwargs)


@pytest.fixture(scope="module")
def test_client():
    # Set the Testing configuration prior to creating the Flask application
    os.environ["FLASK_ENV"] = "testing"
    flask_app = create_app("testing")

    # Set custom client class
    flask_app.test_client_class = CSRFTestClient

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
    response = test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=True
    )
    assert response.status_code == 200, f"Login failed: {response.data}"

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
