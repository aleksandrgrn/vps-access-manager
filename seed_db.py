from app import create_app, db
from app.models import User


def seed_default_user():
    """Create default admin user if it doesn't exist"""
    app = create_app()

    with app.app_context():
        admin_user = User.query.filter_by(username="admin").first()

        if admin_user:
            print("⚠️  Admin user already exists!")
            return

        # Create admin user
        admin = User(username="admin")
        admin.set_password("admin")

        db.session.add(admin)
        db.session.commit()

        print("✅ Default admin user created!")
        print("   Username: admin")
        print("   Password: admin")
        print("⚠️  ВАЖНО: Смените пароль после первого входа!")


if __name__ == "__main__":
    seed_default_user()
