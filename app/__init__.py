"""
VPS Manager Application Factory

Создаёт и конфигурирует Flask приложение с blueprints.
"""
import os
from typing import Optional
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv


# Загрузка переменных окружения
load_dotenv()


# Инициализация расширений (без привязки к app)
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Фабрика приложения Flask.
    
    Args:
        config_name: Имя конфигурации ('development', 'testing', 'production')
    
    Returns:
        Flask: Сконфигурированное приложение
    """
    
    # ✅ ГЛАВНОЕ: Получи корневую директорию проекта
    # app/__init__.py находится в app/, поэтому:
    # dirname(__file__) = C:\Projects\vps-manager\app
    # dirname(dirname(...)) = C:\Projects\vps-manager\
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_folder = os.path.join(project_root, 'templates')
    static_folder = os.path.join(project_root, 'static')
    
    # ✅ Передай пути в Flask
    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder
    )
    
    # Базовая конфигурация
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32).hex()),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///vps_manager.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=3600,  # 1 час
        SESSION_REFRESH_EACH_REQUEST=True,
        WTF_CSRF_TIME_LIMIT=3600,
        WTF_CSRF_CHECK_DEFAULT=True,
        WTF_CSRF_SSL_STRICT=False,
        JSON_AS_ASCII=False
    )
    
    # Конфигурация для тестирования
    if config_name == 'testing':
        app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
            WTF_CSRF_ENABLED=False
        )
    
    # Инициализация расширений
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Настройка Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'
    login_manager.login_message_category = 'info'
    
    # CSRF cookie middleware
    @app.after_request
    def set_csrf_cookie(response):
        if 'CSRF-TOKEN' not in request.cookies:
            response.set_cookie('CSRF-TOKEN', generate_csrf())
        return response
    
    # Регистрация blueprints
    from app.routes import auth, servers, keys, deployments
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(servers.bp, url_prefix='/api')
    app.register_blueprint(keys.bp, url_prefix='/api')
    app.register_blueprint(deployments.bp, url_prefix='/api')
    
    # Загрузчик пользователя для Flask-Login
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(int(user_id))
    
    # CLI команды
    @app.cli.command('init-db')
    def init_db_command():
        """Создает таблицы базы данных."""
        with app.app_context():
            db.create_all()
            print('✅ Таблицы базы данных успешно созданы.')
    
    @app.cli.command('generate-fernet-key')
    def generate_fernet_key_command():
        """Генерирует ключ шифрования Fernet."""
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        print('Ваш ключ шифрования (добавьте его в .env как ENCRYPTION_KEY):')
        print(key.decode())
    
    return app
