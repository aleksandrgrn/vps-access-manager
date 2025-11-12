"""
VPS Manager - Точка входа приложения

Использует фабрику приложения из app/__init__.py
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from app import create_app

# Создание приложения
app = create_app()

# Настройка ProxyFix для корректной работы за обратным прокси
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_prefix=0
)

# Настройка логирования
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'vps_manager.log')

if not app.debug:
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('VPS Manager startup')

if __name__ == '__main__':
    # Для локальной разработки: python run.py
    # В production используется Gunicorn, этот блок не выполняется
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
