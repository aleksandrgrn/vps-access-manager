from app import app, db

def seed_default_user():
    """Create default admin user if it doesn't exist"""
    with app.app_context():
        from app import User
        
        admin_user = User.query.filter_by(username='admin').first()
        
        if admin_user:
            print("⚠️  Admin user already exists!")
            return
        
        # Create admin user - only username required
        admin = User(username='admin')
        admin.set_password('admin')  # Set password after creation
        
        db.session.add(admin)
        db.session.commit()
        
        print("✅ Default admin user created!")
        print("   Username: admin")
        print("   Password: admin")
        print("⚠️  ВАЖНО: Смените пароль после первого входа!")

if __name__ == '__main__':
    seed_default_user()
