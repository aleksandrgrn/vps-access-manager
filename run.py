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

# Настройка логирования
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/vps_manager.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('VPS Manager startup')

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_ENV') == 'development')
