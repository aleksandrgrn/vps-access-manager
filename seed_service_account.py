import secrets

from app import create_app, db
from app.models import User


def seed_service_account():
    """Create the pass-manager-svc user if it doesn't exist (idempotent)."""
    app = create_app()

    with app.app_context():
        svc_user = User.query.filter_by(username="pass-manager-svc").first()

        if svc_user:
            print("⚠️  pass-manager-svc user already exists!")
            return

        # Пароль не используется для логина — доступ только по SERVICE_ACCOUNT_TOKEN
        # через request_loader (Bearer). Генерируем случайный, чтобы не было known secret.
        svc_user = User(username="pass-manager-svc", is_admin=False)
        svc_user.set_password(secrets.token_urlsafe(32))

        db.session.add(svc_user)
        db.session.commit()

        print("✅ pass-manager-svc user created!")


if __name__ == "__main__":
    seed_service_account()
