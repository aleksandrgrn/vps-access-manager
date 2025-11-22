
from app import create_app, db
from app.models import Server, SSHKey, KeyDeployment, Log

app = create_app()

with app.app_context():
    print("--- Servers ---")
    servers = Server.query.all()
    for s in servers:
        print(f"ID: {s.id}, Name: {s.name}, IP: {s.ip_address}, Port: {s.ssh_port}")

    print("\n--- SSH Keys ---")
    keys = SSHKey.query.all()
    for k in keys:
        print(f"ID: {k.id}, Name: {k.name}, Type: {k.key_type}, Fingerprint: {k.fingerprint}")

    print("\n--- Deployments ---")
    deployments = KeyDeployment.query.all()
    for d in deployments:
        print(f"ID: {d.id}, Key: {d.ssh_key.name}, Server: {d.server.name}, Deployed At: {d.deployed_at}")

    print("\n--- Logs (Last 5) ---")
    logs = Log.query.order_by(Log.timestamp.desc()).limit(5).all()
    for l in logs:
        print(f"[{l.timestamp}] Action: {l.action}, Target: {l.target}, Details: {l.details}")
