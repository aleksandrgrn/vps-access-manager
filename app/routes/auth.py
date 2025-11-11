"""
Authentication Routes

Маршруты для входа/выхода с полной обработкой ошибок.
"""
from typing import Any
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Server, SSHKey, Log
from app.forms import LoginForm
from app.utils import add_log

bp = Blueprint('auth', __name__)


@bp.route('/')
def index() -> Any:
    """Главная страница - редирект на dashboard или login."""
    if current_user.is_authenticated:
        return redirect(url_for('servers.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/login', methods=['GET', 'POST'])
def login() -> Any:
    """
    Страница входа в систему.
    
    GET: Показывает форму входа
    POST: Обрабатывает вход пользователя
    """
    if current_user.is_authenticated:
        return redirect(url_for('servers.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            
            if user and user.check_password(form.password.data):
                login_user(user)
                add_log('login_success', target=user.username)
                
                # Перенаправление на следующую страницу, если она была указана
                next_page = request.args.get('next')
                return redirect(next_page or url_for('servers.dashboard'))
            else:
                add_log('login_failed', target=form.username.data)
                flash('Неправильный логин или пароль.', 'error')
        
        except Exception as e:
            flash(f'Ошибка при входе: {str(e)}', 'error')
            add_log('login_error', details={'error': str(e)})
    
    return render_template('login.html', form=form)


@bp.route('/logout')
@login_required
def logout() -> Any:
    """
    Выход из системы.
    
    Логирует выход и очищает сессию.
    """
    try:
        username = current_user.username
        add_log('logout', target=username)
        logout_user()
        flash('Вы успешно вышли из системы.', 'success')
    except Exception as e:
        flash(f'Ошибка при выходе: {str(e)}', 'error')
    
    return redirect(url_for('auth.login'))


@bp.route('/change-password', methods=['POST'])
@login_required
def change_password() -> Any:
    """
    Смена пароля пользователя через модальное окно
    
    Валидация:
    - Все поля заполнены
    - Минимальная длина нового пароля: 8 символов
    - Текущий пароль верный
    - Новый пароль и подтверждение совпадают
    - Новый пароль отличается от текущего
    """
    try:
        # Получение данных из формы
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # ───────────────────────────────────────────────────────────
        # Валидация 1: Все поля заполнены
        # ───────────────────────────────────────────────────────────
        if not all([current_password, new_password, confirm_password]):
            flash('Все поля обязательны для заполнения', 'error')
            return redirect(url_for('servers.dashboard'))
        
        # ───────────────────────────────────────────────────────────
        # Валидация 2: Минимальная длина пароля (8 символов)
        # ───────────────────────────────────────────────────────────
        if len(new_password) < 8:
            flash('Новый пароль должен содержать минимум 8 символов', 'error')
            return redirect(url_for('servers.dashboard'))
        
        # ───────────────────────────────────────────────────────────
        # Валидация 3: Проверка текущего пароля
        # ───────────────────────────────────────────────────────────
        if not current_user.check_password(current_password):
            flash('Неверный текущий пароль', 'error')
            return redirect(url_for('servers.dashboard'))
        
        # ───────────────────────────────────────────────────────────
        # Валидация 4: Совпадение нового пароля и подтверждения
        # ───────────────────────────────────────────────────────────
        if new_password != confirm_password:
            flash('Новый пароль и подтверждение не совпадают', 'error')
            return redirect(url_for('servers.dashboard'))
        
        # ───────────────────────────────────────────────────────────
        # Валидация 5: Новый пароль отличается от текущего
        # ───────────────────────────────────────────────────────────
        if current_password == new_password:
            flash('Новый пароль должен отличаться от текущего', 'error')
            return redirect(url_for('servers.dashboard'))
        
        # ───────────────────────────────────────────────────────────
        # Смена пароля
        # ───────────────────────────────────────────────────────────
        current_user.set_password(new_password)
        db.session.commit()
        
        # Логирование события
        try:
            add_log('change_password', target=current_user.username)
        except:
            pass  # Если add_log не существует - пропускаем
        
        flash('Пароль успешно изменён!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при смене пароля: {str(e)}', 'error')
    
    return redirect(url_for('servers.dashboard'))
