from app import db
from app.models import KeyDeployment, Server, User


def test_user_password_hashing(new_user):
    """Test password hashing."""
    assert new_user.password_hash != "newpassword"
    assert new_user.check_password("newpassword")
    assert not new_user.check_password("wrongpassword")


def test_server_model_creation(new_server):
    """Test server model creation."""
    db.session.add(new_server)
    db.session.commit()
    assert new_server.name == "Test Server"
    assert new_server.ip_address == "192.168.1.100"
    assert new_server.username == "root"
    assert new_server.ssh_port == 22


def test_model_relationships(init_database):
    """Test relationships between models."""
    user = User.query.filter_by(username="testuser").first()
    server = Server(name="Rel Server", ip_address="10.0.0.1", username="root", user_id=user.id)
    db.session.add(server)
    db.session.commit()

    assert server in user.servers
    assert server.user == user


def test_key_deployment_tracking(init_database, new_server, new_ssh_key):
    """Test key deployment tracking."""
    db.session.add(new_server)
    db.session.add(new_ssh_key)
    db.session.commit()

    user = User.query.filter_by(username="testuser").first()

    deployment = KeyDeployment(
        ssh_key_id=new_ssh_key.id, server_id=new_server.id, deployed_by=user.id
    )
    db.session.add(deployment)
    db.session.commit()

    assert deployment.ssh_key == new_ssh_key
    assert deployment.server == new_server
    assert deployment.deployer == user
