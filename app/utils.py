"""
Вспомогательные функции для VPS Manager

Общие утилиты, используемые в разных частях приложения.
"""
import json
from typing import Optional, Dict, Any
from flask import request
from flask_login import current_user
from app import db
from app.models import Log


def add_log(action: str, target: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Добавляет запись в журнал событий.
    
    Args:
        action: Тип действия (например, 'login', 'deploy_key')
        target: Цель действия (например, имя сервера или ключа)
        details: Дополнительные детали в виде словаря
    
    Note:
        Не логирует если пользователь не аутентифицирован.
    """
    if not current_user.is_authenticated:
        return
    
    try:
        log_entry = Log(
            user_id=current_user.id,
            action=action,
            target=target,
            details=json.dumps(details, ensure_ascii=False) if details else None,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # Логирование не должно ломать основной функционал
        db.session.rollback()
        print(f"[LOG_ERROR] Не удалось записать лог: {str(e)}")
