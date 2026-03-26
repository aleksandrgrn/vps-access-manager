"""
Server Routes - ЧАСТЬ 1

Маршруты для управления серверами с полной валидацией и обработкой ошибок.
"""

import logging
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from app import db
from app.forms import ServerForm
from app.models import KeyDeployment, Log, Server, ServerCategory, SSHKey
from app.services.ssh import bootstrap as ssh_bootstrap
from app.services.ssh import keys as ssh_keys
from app.services.ssh.server_manager import initialize_server, test_connection
from app.utils import add_log

bp = Blueprint("servers", __name__)
logger = logging.getLogger(__name__)


def _provision_server_with_verified_key_auth(
    *,
    name: str,
    ip_address: str,
    port: int,
    username: str,
    password: str,
    category_ids: List[int] | None = None,
    requires_legacy_ssh_override: bool = False,
) -> Dict[str, Any]:
    """Shared add/import flow: deploy key, verify fresh login, then persist DB state."""

    category_ids = category_ids or []

    try:
        existing_server = Server.query.filter_by(
            user_id=current_user.id,
            ip_address=ip_address,
            ssh_port=port,
        ).first()
        if existing_server:
            add_log("add_server_duplicate", details={"ip": ip_address, "port": port})
            return {
                "success": False,
                "status_code": 400,
                "error_type": "duplicate",
                "message": f"Сервер {ip_address}:{port} уже добавлен.",
                "server_name": name,
                "ip_address": ip_address,
            }

        init_result = initialize_server(ip_address, port, username, password)
        if not init_result["success"]:
            add_log(
                "add_server_failed", details={"ip": ip_address, "error": init_result["message"]}
            )
            return {
                "success": False,
                "status_code": 400,
                "error_type": "initialization_failed",
                "message": f"Ошибка инициализации: {init_result['message']}",
                "server_name": name,
                "ip_address": ip_address,
            }

        openssh_version = init_result["openssh_version"]
        requires_legacy_ssh = init_result["requires_legacy_ssh"]
        if requires_legacy_ssh_override:
            requires_legacy_ssh = True

        private_key_pem, public_key_ssh = ssh_keys.generate_ssh_key("rsa")
        fingerprint = ssh_keys.get_fingerprint(public_key_ssh)
        if not fingerprint or SSHKey.query.filter_by(fingerprint=fingerprint).first():
            db.session.rollback()
            return {
                "success": False,
                "status_code": 500,
                "error_type": "key_generation_failed",
                "message": "Не удалось сгенерировать ключ. Попробуйте снова.",
                "server_name": name,
                "ip_address": ip_address,
            }

        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            db.session.rollback()
            return {
                "success": False,
                "status_code": 500,
                "error_type": "missing_encryption_key",
                "message": "ENCRYPTION_KEY не установлен на сервере",
                "server_name": name,
                "ip_address": ip_address,
            }

        encrypted_private_key = ssh_keys.encrypt_private_key(private_key_pem, encryption_key)
        new_root_key = SSHKey(
            name=f"root_{name}",
            public_key=public_key_ssh,
            private_key_encrypted=encrypted_private_key,
            fingerprint=fingerprint,
            key_type="rsa",
            user_id=current_user.id,
        )
        db.session.add(new_root_key)
        db.session.flush()

        bootstrap_result = ssh_bootstrap.bootstrap_server_access(
            host=ip_address,
            port=port,
            bootstrap_username=username,
            password=password,
            public_key=public_key_ssh,
            private_key=private_key_pem,
            requires_legacy_ssh=requires_legacy_ssh,
            openssh_version=openssh_version,
            server_name=name,
        )
        if not bootstrap_result["success"]:
            db.session.rollback()
            return {
                "success": False,
                "status_code": 400,
                "error_type": bootstrap_result.get("error_type", "ssh_bootstrap_failed"),
                "message": bootstrap_result["message"],
                "server_name": name,
                "ip_address": ip_address,
            }

        new_server = Server(
            name=name,
            ip_address=ip_address,
            ssh_port=port,
            username="root",
            user_id=current_user.id,
            status="online",
            openssh_version=openssh_version,
            requires_legacy_ssh=requires_legacy_ssh,
            access_key_id=new_root_key.id,
        )
        db.session.add(new_server)
        db.session.flush()

        for cat_id in category_ids:
            category = ServerCategory.query.get(cat_id)
            if category:
                new_server.categories.append(category)

        deployment = KeyDeployment(
            ssh_key_id=new_root_key.id,
            server_id=new_server.id,
            deployed_by=current_user.id,
            deployed_at=datetime.now(timezone.utc),
        )
        db.session.add(deployment)
        db.session.commit()

        add_log(
            "add_server",
            target=new_server.name,
            details={
                "ip": new_server.ip_address,
                "key_id": new_root_key.id,
                "openssh_version": openssh_version,
            },
        )

        return {
            "success": True,
            "status_code": 200,
            "message": (
                "Сервер успешно добавлен. " f"OpenSSH версия: {openssh_version}. Key auth verified."
            ),
            "server_name": new_server.name,
            "ip_address": new_server.ip_address,
            "server_id": new_server.id,
            "key_id": new_root_key.id,
            "openssh_version": openssh_version,
            "requires_legacy_ssh": requires_legacy_ssh,
        }
    except Exception as e:
        logger.error("[SERVER_PROVISION_ERROR] %s", str(e))
        db.session.rollback()
        return {
            "success": False,
            "status_code": 500,
            "error_type": "exception",
            "message": f"Ошибка при добавлении сервера: {str(e)}",
            "server_name": name,
            "ip_address": ip_address,
        }


@bp.route("/dashboard")
@login_required
def dashboard() -> str:
    """
    Главная панель управления.

    Показывает статистику: количество серверов, ключей, онлайн серверов и последние логи.
    """
    try:
        servers_count = Server.query.filter_by(user_id=current_user.id).count()
        keys_count = SSHKey.query.filter_by(user_id=current_user.id).count()
        online_count = Server.query.filter_by(user_id=current_user.id, status="online").count()
        recent_logs = (
            Log.query.filter_by(user_id=current_user.id)
            .order_by(Log.timestamp.desc())
            .limit(5)
            .all()
        )

        return render_template(
            "dashboard.html",
            servers_count=servers_count,
            keys_count=keys_count,
            online_count=online_count,
            recent_logs=recent_logs,
        )

    except Exception as e:
        logger.error(f"Ошибка при загрузке dashboard: {str(e)}")
        flash(f"Ошибка при загрузке панели: {str(e)}", "error")
        return render_template(
            "dashboard.html", servers_count=0, keys_count=0, online_count=0, recent_logs=[]
        )


@bp.route("/servers", methods=["GET"])
@login_required
def servers() -> str:
    """
    Страница списка серверов.

    Показывает все серверы пользователя с формой добавления.
    """
    try:
        form = ServerForm()
        user_servers = Server.query.filter_by(user_id=current_user.id).all()
        status_colors = {"online": "success", "offline": "danger", "unknown": "secondary"}
        return render_template(
            "servers.html", form=form, servers=user_servers, status_colors=status_colors
        )

    except Exception as e:
        logger.error(f"Ошибка при загрузке списка серверов: {str(e)}")
        flash(f"Ошибка при загрузке серверов: {str(e)}", "error")
        return render_template("servers.html", form=ServerForm(), servers=[], status_colors={})


@bp.route("/api/servers", methods=["GET"])
@login_required
def get_servers() -> Tuple[Dict[str, Any], int]:
    """
    API эндпоинт для получения списка серверов с категориями.

    Returns:
        JSON со списком серверов и их категориями
    """
    try:
        user_servers = Server.query.filter_by(user_id=current_user.id).all()

        servers_data = []
        for server in user_servers:
            # Получаем категории сервера
            categories = [
                {"id": cat.id, "name": cat.name, "color": cat.color}
                for cat in server.categories.all()
            ]

            servers_data.append(
                {
                    "id": server.id,
                    "name": server.name,
                    "ip_address": server.ip_address,
                    "ssh_port": server.ssh_port,
                    "username": server.username,
                    "status": server.status,
                    "openssh_version": server.openssh_version,
                    "requires_legacy_ssh": server.requires_legacy_ssh,
                    "categories": categories,
                    "created_at": server.created_at.isoformat() if server.created_at else None,
                }
            )

        return jsonify({"success": True, "servers": servers_data}), 200

    except Exception as e:
        logger.error(f"Ошибка при получении списка серверов: {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/servers/add", methods=["POST"])
@login_required
def add_server() -> Any:
    """
    Добавление нового сервера с паролем.

    Процесс:
    1. Инициализация сервера (определение версии OpenSSH)
    2. Генерация уникального root ключа
    3. Развёртывание ключа на сервере через пароль
    4. Сохранение сервера и ключа в БД
    5. Создание KeyDeployment записи

    ЯКОРЬ: БД обновляется ТОЛЬКО после успешного развёртывания ключа!
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Данные не предоставлены"}), 400

        # Валидация обязательных полей
        required_fields = ["name", "ip_address", "ssh_port", "username", "password"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "message": f"Поле '{field}' обязательно"}), 400

        result = _provision_server_with_verified_key_auth(
            name=data["name"],
            ip_address=data["ip_address"],
            port=data["ssh_port"],
            username=data["username"],
            password=data["password"],
            category_ids=data.get("category_ids", []),
            requires_legacy_ssh_override=data.get("requires_legacy_ssh", False),
        )
        return (
            jsonify({"success": result["success"], "message": result["message"]}),
            result["status_code"],
        )

    except Exception as e:
        logger.error(f"[ADD_SERVER_FATAL] Непредвиденная ошибка: {str(e)}")
        return jsonify({"success": False, "message": f"Непредвиденная ошибка: {str(e)}"}), 500


@bp.route("/servers/edit/<int:server_id>", methods=["POST"])
@login_required
def edit_server(server_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Редактирование данных сервера и его категорий.

    Args:
        server_id: ID сервера

    Returns:
        JSON с результатом операции
    """
    try:
        server = Server.query.get_or_404(server_id)

        # Проверка доступа
        if server.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Получение данных из JSON или form-data
        data = request.get_json(silent=True)
        if data is None:
            data = request.form.to_dict()
            if "category_ids" in request.form:
                data["category_ids"] = request.form.getlist("category_ids")
        if not data:
            return jsonify({"success": False, "message": "Отсутствуют данные запроса"}), 400

        # Валидация обязательных полей
        required_fields = ["name", "ip_address", "ssh_port", "username"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "message": f"Поле '{field}' обязательно"}), 400

        # Обновление основных полей
        server.name = data.get("name")
        server.ip_address = data.get("ip_address")
        server.ssh_port = data.get("ssh_port")
        server.username = data.get("username")
        # requires_legacy_ssh НЕ обновляется при редактировании

        # Обновление категорий
        category_ids = data.get("category_ids", [])
        # Очищаем существующие категории (для lazy="dynamic" используем remove)
        for category in server.categories.all():
            server.categories.remove(category)
        # Добавляем новые категории
        if category_ids:
            for cat_id in category_ids:
                category = ServerCategory.query.get(cat_id)
                if category:
                    server.categories.append(category)
                    logger.info(
                        f"[EDIT_SERVER] Привязана категория {category.name} "
                        f"к серверу {server.id}"
                    )

        db.session.commit()

        logger.info(
            f"[EDIT_SERVER] Сервер {server.name} обновлён. "
            f"Legacy SSH: {server.requires_legacy_ssh}, Категорий: {len(category_ids)}"
        )
        add_log(
            "edit_server",
            target=server.name,
            details={
                "requires_legacy_ssh": server.requires_legacy_ssh,
                "categories": len(category_ids),
            },
        )
        return jsonify({"success": True, "message": "Сервер обновлён"}), 200

    except Exception as e:
        logger.error(f"[EDIT_SERVER_ERROR] {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/servers/delete/<int:server_id>", methods=["POST"])
@login_required
def delete_server(server_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Удаление сервера.

    Args:
        server_id: ID сервера

    Returns:
        JSON с результатом операции

    Note:
        Cascade удаление KeyDeployment происходит автоматически.
    """
    try:
        server = Server.query.get_or_404(server_id)

        # Проверка доступа
        if server.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        server_name = server.name
        db.session.delete(server)
        db.session.commit()

        add_log("delete_server", target=server_name)
        return jsonify({"success": True, "message": "Сервер успешно удален."}), 200

    except Exception as e:
        logger.error(f"[DELETE_SERVER_ERROR] {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/servers/test/<int:server_id>", methods=["POST"])
@login_required
def test_server(server_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Тестирование SSH соединения с сервером.

    Args:
        server_id: ID сервера

    Returns:
        JSON с результатом теста
    """
    try:
        server = Server.query.get_or_404(server_id)

        # Проверка доступа
        if server.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Проверка access_key
        if not server.access_key:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": (
                            "Для этого сервера не настроен ключ доступа. "
                            "Пожалуйста, пересоздайте сервер."
                        ),
                    }
                ),
                400,
            )

        # Тест соединения
        test_result = test_connection(server)

        # Обновление статуса сервера
        server.status = "online" if test_result["success"] else "offline"
        server.last_check = datetime.now(timezone.utc)
        db.session.commit()

        add_log(
            "test_connection",
            target=server.name,
            details={"result": "success" if test_result["success"] else "failed"},
        )

        return (
            jsonify(
                {
                    "success": test_result["success"],
                    "message": test_result["message"],
                    "status": server.status,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"[TEST_SERVER_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/bulk-import-servers", methods=["POST"])
@login_required
def bulk_import_servers() -> Tuple[Dict[str, Any], int]:
    """
    Массовый импорт серверов из текстовых данных.

    Формат: domain username password ip-address ssh-port (5 полей через пробел)
    Для каждого сервера создается уникальный SSH ключ и развертывается на сервер.

    Returns:
        JSON с результатами импорта
    """
    try:
        data = request.get_json()
        if not data or "servers_data" not in data:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Отсутствуют данные для импорта",
                        "added": [],
                        "skipped": [],
                        "failed": [],
                    }
                ),
                400,
            )

        servers_data = data["servers_data"].strip()
        if not servers_data:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Данные пусты",
                        "added": [],
                        "skipped": [],
                        "failed": [],
                    }
                ),
                400,
            )

        lines = servers_data.split("\n")

        # Списки для детальных результатов
        added_details = []
        skipped_details = []
        failed_details = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Парсинг строки: domain username password ip-address ssh-port
            parts = line.split()

            if len(parts) != 5:
                logger.warning(f"[BULK_IMPORT] Неверный формат строки: {line}")
                failed_details.append(
                    {
                        "name": line[:30] + "..." if len(line) > 30 else line,
                        "ip": "N/A",
                        "reason": "Неверный формат строки (ожидается 5 полей)",
                    }
                )
                continue

            domain, username, password, ip_address, ssh_port_str = parts

            # Валидация IP
            try:
                import ipaddress

                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.warning(f"[BULK_IMPORT] Неверный IP адрес: {ip_address}")
                failed_details.append(
                    {"name": domain, "ip": ip_address, "reason": "Неверный IP адрес"}
                )
                continue

            # Валидация порта
            try:
                ssh_port = int(ssh_port_str)
                if ssh_port < 1 or ssh_port > 65535:
                    logger.warning(f"[BULK_IMPORT] SSH порт вне диапазона: {ssh_port}")
                    failed_details.append(
                        {
                            "name": domain,
                            "ip": ip_address,
                            "reason": f"SSH порт вне диапазона: {ssh_port}",
                        }
                    )
                    continue
            except ValueError:
                logger.warning(f"[BULK_IMPORT] Неверный SSH порт: {ssh_port_str}")
                failed_details.append(
                    {
                        "name": domain,
                        "ip": ip_address,
                        "reason": f"Неверный SSH порт: {ssh_port_str}",
                    }
                )
                continue

            result = _provision_server_with_verified_key_auth(
                name=domain,
                ip_address=ip_address,
                port=ssh_port,
                username=username,
                password=password,
                category_ids=data.get("category_ids", []),
            )

            if result["success"]:
                added_details.append({"name": domain, "ip": ip_address, "status": "success"})
            elif result.get("error_type") == "duplicate":
                skipped_details.append(
                    {"name": domain, "ip": ip_address, "reason": result["message"]}
                )
            else:
                failed_details.append(
                    {"name": domain, "ip": ip_address, "reason": result["message"]}
                )

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Импорт завершен",
                    "added": added_details,
                    "skipped": skipped_details,
                    "failed": failed_details,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"[BULK_IMPORT_ERROR] {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Критическая ошибка сервера: {str(e)}",
                    "added": [],
                    "skipped": [],
                    "failed": [],
                }
            ),
            500,
        )


@bp.route("/logs")
@login_required
def logs() -> str:
    """
    Страница журнала событий с пагинацией.

    Query params:
        page (int): Номер страницы (по умолчанию 1)
    """
    try:
        page = request.args.get("page", 1, type=int)
        logs_query = Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc())
        logs_pagination = logs_query.paginate(page=page, per_page=50, error_out=False)

        # Если на запрошенной странице нет элементов (например, ввели page=999),
        # и это не первая страница, то перенаправляем на последнюю существующую страницу.
        if not logs_pagination.items and page > 1:
            return redirect(url_for("servers.logs", page=logs_pagination.pages or 1))

    except Exception as e:
        current_app.logger.error(f"Could not retrieve logs: {e}")
        # Создаем безопасный объект-пустышку для пагинации, если произошла ошибка
        logs_pagination = SimpleNamespace(
            items=[],
            total=0,
            page=1,
            pages=0,
            has_next=False,
            has_prev=False,
            iter_pages=lambda: [],
        )

    # Словарь с цветами остается как есть
    action_colors = {
        "login_success": "success",
        "login_failed": "warning",
        "logout": "secondary",
        "add_server": "info",
        "edit_server": "info",
        "delete_server": "danger",
        "generate_key": "primary",
        "delete_key": "danger",
        "deploy_key": "success",
        "test_connection": "secondary",
        "revoke_key": "warning",
    }

    return render_template(
        "logs.html", logs_pagination=logs_pagination, action_colors=action_colors
    )
