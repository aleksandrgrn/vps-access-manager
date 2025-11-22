
from app import create_app, db
from app.models import Server, SSHKey, KeyDeployment, Log

app = create_app()

with app.app_context():
    print("Cleaning up test data...")
    KeyDeployment.query.delete()
    Server.query.delete()
    SSHKey.query.delete()
    Log.query.delete()
    db.session.commit()
    print("Cleanup complete.")
