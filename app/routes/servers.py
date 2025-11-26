"""
Server Routes - ЧАСТЬ 1

Маршруты для управления серверами с полной валидацией и обработкой ошибок.
"""

import logging
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Tuple

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
from app.models import KeyDeployment, Log, Server, SSHKey
from app.services.key_service import decrypt_access_key, test_server_connection
from app.services.ssh import keys as ssh_keys
from app.services.ssh.connection import SSHConnection
from app.utils import add_log

bp = Blueprint("servers", __name__)
logger = logging.getLogger(__name__)


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
    form = ServerForm()

    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")
        return redirect(url_for("servers.servers"))

    ip_address = form.ip_address.data
    port = form.ssh_port.data
    username = form.username.data
    password = request.form.get("password")

    # ЭТАП 0: Проверка на дубликаты
    existing_server = Server.query.filter_by(
        user_id=current_user.id, ip_address=ip_address, ssh_port=port
    ).first()

    if existing_server:
        flash(f"Сервер {ip_address}:{port} уже добавлен.", "danger")
        add_log("add_server_duplicate", details={"ip": ip_address, "port": port})
        return redirect(url_for("servers.servers"))

    # ЭТАП 0.1: Валидация пароля
    if not password:
        flash("Пароль не может быть пустым.", "danger")
        return redirect(url_for("servers.servers"))

    # ЭТАП 1: Инициализация сервера (определение версии OpenSSH)
    try:
        logger.info(f"[ADD_SERVER] Инициализация сервера {ip_address}:{port}")

        # Подключаемся и определяем версию OpenSSH
        conn = SSHConnection(ip_address, port, username)
        conn_success, conn_error = conn.connect_with_password(password)

        if not conn_success:
            flash(f"Ошибка подключения: {conn_error}", "danger")
            add_log("add_server_failed", details={"ip": ip_address, "error": conn_error})
            return redirect(url_for("servers.servers"))

        try:
            # Определяем версию OpenSSH
            cmd_success, stdout, stderr = conn.execute("ssh -V 2>&1", timeout=10)
            if cmd_success and stdout:
                import re

                match = re.search(r"OpenSSH_(\S+)", stdout)
                openssh_version = match.group(1) if match else "unknown"
                logger.info(f"Определена версия OpenSSH: {openssh_version}")
            else:
                openssh_version = "unknown"
                logger.warning(f"Не удалось определить версию OpenSSH: {stderr}")
        finally:
            conn.close()

        # Определяем, нужен ли legacy SSH (OpenSSH < 7.2)
        try:
            version_parts = openssh_version.replace("p", ".").split(".")
            major = int(version_parts[0]) if version_parts else 0
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            requires_legacy_ssh = (major < 7) or (major == 7 and minor < 2)
        except (ValueError, IndexError):
            requires_legacy_ssh = False  # По умолчанию используем modern SSH

        # Переопределяем, если пользователь явно указал в форме
        if form.requires_legacy_ssh.data is not None:
            requires_legacy_ssh = form.requires_legacy_ssh.data

        logger.info(
            f"[ADD_SERVER] Сервер инициализирован. OpenSSH: {openssh_version}, "
            f"Legacy: {requires_legacy_ssh}"
        )
        flash(f"Сервер инициализирован. OpenSSH версия: {openssh_version}", "info")

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка инициализации: {str(e)}")
        flash(f"Ошибка при инициализации сервера: {str(e)}", "danger")
        add_log("add_server_exception", details={"ip": ip_address, "error": str(e)})
        return redirect(url_for("servers.servers"))

    # ЭТАП 2: Генерация уникального root ключа
    try:
        logger.info(f"[ADD_SERVER] Генерация root ключа для {ip_address}")
        private_key_pem, public_key_ssh = ssh_keys.generate_ssh_key("rsa")
        fingerprint = ssh_keys.get_fingerprint(public_key_ssh)

        if not fingerprint or SSHKey.query.filter_by(fingerprint=fingerprint).first():
            flash("Не удалось сгенерировать уникальный ключ. Попробуйте еще раз.", "danger")
            return redirect(url_for("servers.servers"))

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка генерации ключа: {str(e)}")
        flash(f"Ошибка при генерации ключа: {str(e)}", "danger")
        return redirect(url_for("servers.servers"))

    # ЭТАП 3: Сохранение ключа в БД
    try:
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            flash("ENCRYPTION_KEY не установлен на сервере", "danger")
            return redirect(url_for("servers.servers"))

        encrypted_private_key = ssh_keys.encrypt_private_key(private_key_pem, encryption_key)

        root_key_name = f"root_{form.name.data}"
        new_root_key = SSHKey(
            name=root_key_name,
            public_key=public_key_ssh,
            private_key_encrypted=encrypted_private_key,
            fingerprint=fingerprint,
            key_type="rsa",
            user_id=current_user.id,
        )
        db.session.add(new_root_key)
        db.session.flush()  # Получаем ID ключа
        logger.info(f"[ADD_SERVER] Создан root ключ {root_key_name} (ID: {new_root_key.id})")

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка сохранения ключа: {str(e)}")
        flash(f"Ошибка при сохранении ключа в БД: {str(e)}", "danger")
        db.session.rollback()
        return redirect(url_for("servers.servers"))

    # ЭТАП 4: Развёртывание ключа на сервере (КРИТИЧНО!)
    try:
        logger.info(f"[ADD_SERVER] Развёртывание ключа на {ip_address}")

        # Разворачиваем ключ через SSH
        conn = SSHConnection(ip_address, port, username)
        conn_success, conn_error = conn.connect_with_password(password)

        # Удаляем пароль из памяти сразу после использования
        del password

        if not conn_success:
            logger.warning(f"[ADD_SERVER_DEPLOY_FAILED] {conn_error}")
            flash(f"Не удалось подключиться для развёртывания ключа: {conn_error}", "danger")
            db.session.rollback()
            return redirect(url_for("servers.servers"))

        try:
            # Валидация ключа
            if not ssh_keys.validate_ssh_public_key(public_key_ssh):
                flash("Невалидный формат публичного ключа", "danger")
                db.session.rollback()
                return redirect(url_for("servers.servers"))

            # Шаг 1: Создаём .ssh директорию
            cmd1_success, _, stderr1 = conn.execute(
                "mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=15
            )
            if not cmd1_success:
                logger.error(f"[ADD_SERVER_MKDIR_FAILED] {stderr1}")
                flash(f"Не удалось создать .ssh: {stderr1}", "danger")
                db.session.rollback()
                return redirect(url_for("servers.servers"))

            # Шаг 2: Проверяем, не установлен ли уже ключ
            cmd2_success, existing_keys, _ = conn.execute(
                "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''", timeout=10
            )
            if public_key_ssh.strip() in existing_keys:
                logger.info(f"[ADD_SERVER_KEY_EXISTS] Ключ уже установлен на {ip_address}")
            else:
                # Шаг 3: Добавляем ключ
                escaped_key = public_key_ssh.strip().replace("'", "'\\''")
                cmd3_success, _, stderr3 = conn.execute(
                    f"echo '{escaped_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",  # noqa: E501
                    timeout=15,
                )

                if not cmd3_success:
                    logger.error(f"[ADD_SERVER_APPEND_FAILED] {stderr3}")
                    flash(f"Не удалось добавить ключ: {stderr3}", "danger")
                    db.session.rollback()
                    return redirect(url_for("servers.servers"))

            logger.info(f"[ADD_SERVER_DEPLOY_SUCCESS] Ключ успешно развёрнут на {ip_address}")
        finally:
            conn.close()

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка развёртывания: {str(e)}")
        flash(f"Ошибка при развёртывании ключа: {str(e)}", "danger")
        db.session.rollback()
        return redirect(url_for("servers.servers"))

    # ЭТАП 5: Сохранение сервера в БД (ТОЛЬКО после успешного развёртывания!)
    try:
        new_server = Server(
            name=form.name.data,
            ip_address=ip_address,
            ssh_port=port,
            username=username,
            user_id=current_user.id,
            status="online",
            openssh_version=openssh_version,
            requires_legacy_ssh=requires_legacy_ssh,
            access_key_id=new_root_key.id,
        )
        db.session.add(new_server)
        db.session.flush()
        logger.info(f"[ADD_SERVER] Создан сервер {form.name.data} (ID: {new_server.id})")

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка сохранения сервера: {str(e)}")
        flash(f"Ошибка при сохранении сервера в БД: {str(e)}", "danger")
        db.session.rollback()
        return redirect(url_for("servers.servers"))

    # ЭТАП 6: Создание KeyDeployment
    try:
        deployment = KeyDeployment(
            ssh_key_id=new_root_key.id,
            server_id=new_server.id,
            deployed_by=current_user.id,
            deployed_at=datetime.now(timezone.utc),
        )
        db.session.add(deployment)
        db.session.commit()
        logger.info(
            f"[ADD_SERVER] KeyDeployment создан: ключ {new_root_key.id} -> сервер {new_server.id}"
        )

        add_log(
            "add_server",
            target=new_server.name,
            details={
                "ip": new_server.ip_address,
                "key_id": new_root_key.id,
                "openssh_version": openssh_version,
            },
        )
        flash(f"✅ Сервер успешно добавлен. OpenSSH версия: {openssh_version}", "success")

    except Exception as e:
        logger.error(f"[ADD_SERVER_ERROR] Ошибка создания deployment: {str(e)}")
        flash(f"Ошибка при создании записи развертывания: {str(e)}", "danger")
        db.session.rollback()
        return redirect(url_for("servers.servers"))

    return redirect(url_for("servers.servers"))


@bp.route("/servers/edit/<int:server_id>", methods=["POST"])
@login_required
def edit_server(server_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Редактирование данных сервера.

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

        form = ServerForm()
        if form.validate_on_submit():
            server.name = form.name.data
            server.ip_address = form.ip_address.data
            server.ssh_port = form.ssh_port.data
            server.username = form.username.data
            server.requires_legacy_ssh = form.requires_legacy_ssh.data
            db.session.commit()

            logger.info(
                f"[EDIT_SERVER] Сервер {server.name} обновлён. "
                f"Legacy SSH: {server.requires_legacy_ssh}"
            )
            add_log(
                "edit_server",
                target=server.name,
                details={"requires_legacy_ssh": server.requires_legacy_ssh},
            )
            flash("Данные сервера успешно обновлены.", "success")
            return jsonify({"success": True, "message": "Сервер обновлён"}), 200
        else:
            errors = []
            for field, field_errors in form.errors.items():
                for error in field_errors:
                    errors.append(f"{getattr(form, field).label.text}: {error}")

            return jsonify({"success": False, "message": "Ошибки валидации", "errors": errors}), 400

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

        # Расшифровка ключа
        decrypt_result = decrypt_access_key(server.access_key)
        if not decrypt_result["success"]:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f'Ошибка расшифровки: {decrypt_result["message"]}',
                    }
                ),
                500,
            )

        # Тест соединения
        test_result = test_server_connection(server, decrypt_result["private_key"])

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

    ЯКОРЬ: БД обновляется ТОЛЬКО после успешного развёртывания ключа!
    """
    try:
        data = request.get_json()
        if not data or "servers_data" not in data:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Отсутствуют данные для импорта",
                        "added": 0,
                        "skipped": 0,
                        "failed": 0,
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
                        "added": 0,
                        "skipped": 0,
                        "failed": 0,
                    }
                ),
                400,
            )

        lines = servers_data.split("\n")
        added = 0
        skipped = 0
        failed = 0

        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "ENCRYPTION_KEY не установлен",
                        "added": 0,
                        "skipped": 0,
                        "failed": 0,
                    }
                ),
                500,
            )

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Парсинг строки: domain username password ip-address ssh-port
            parts = line.split()

            if len(parts) != 5:
                logger.warning(f"[BULK_IMPORT] Неверный формат строки (ожидается 5 полей): {line}")
                failed += 1
                continue

            domain, username, password, ip_address, ssh_port_str = parts

            # Валидация IP
            try:
                import ipaddress

                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.warning(f"[BULK_IMPORT] Неверный IP адрес: {ip_address}")
                failed += 1
                continue

            # Валидация порта
            try:
                ssh_port = int(ssh_port_str)
                if ssh_port < 1 or ssh_port > 65535:
                    logger.warning(f"[BULK_IMPORT] SSH порт вне диапазона: {ssh_port}")
                    failed += 1
                    continue
            except ValueError:
                logger.warning(f"[BULK_IMPORT] Неверный SSH порт: {ssh_port_str}")
                failed += 1
                continue

            # Проверка дубликатов
            existing_server = Server.query.filter_by(
                ip_address=ip_address, user_id=current_user.id
            ).first()

            if existing_server:
                logger.info(f"[BULK_IMPORT] Сервер {ip_address} уже существует, пропускаем")
                skipped += 1
                continue

            # Инициализация сервера
            try:
                logger.info(f"[BULK_IMPORT] Инициализация {domain} ({ip_address}:{ssh_port})")

                # Подключаемся и определяем версию OpenSSH
                conn = SSHConnection(ip_address, ssh_port, username)
                conn_success, conn_error = conn.connect_with_password(password)

                if not conn_success:
                    logger.warning(f"[BULK_IMPORT] {domain}: Ошибка подключения - {conn_error}")
                    failed += 1
                    continue

                try:
                    # Определяем версию OpenSSH
                    cmd_success, stdout, stderr = conn.execute("ssh -V 2>&1", timeout=10)
                    if cmd_success and stdout:
                        import re

                        match = re.search(r"OpenSSH_(\S+)", stdout)
                        openssh_version = match.group(1) if match else "unknown"
                    else:
                        openssh_version = "unknown"

                    # Определяем, нужен ли legacy SSH
                    try:
                        version_parts = openssh_version.replace("p", ".").split(".")
                        major = int(version_parts[0]) if version_parts else 0
                        minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                        requires_legacy_ssh = (major < 7) or (major == 7 and minor < 2)
                    except (ValueError, IndexError):
                        requires_legacy_ssh = False

                finally:
                    conn.close()

                logger.info(
                    f"[BULK_IMPORT] {domain}: OpenSSH {openssh_version}, "
                    f"legacy={requires_legacy_ssh}"
                )

            except Exception as e:
                logger.error(f"[BULK_IMPORT] Ошибка инициализации {domain}: {str(e)}")
                failed += 1
                continue

            # STEP 2: Поиск или создание SSH-ключа
            try:
                root_key_name = f"root_{domain}"

                existing_key = SSHKey.query.filter_by(
                    user_id=current_user.id, name=root_key_name
                ).first()

                if existing_key:
                    logger.info(
                        f"[BULK_IMPORT] {domain}: используется существующий ключ '"
                        f"{existing_key.name}' (ID: {existing_key.id})"
                    )
                    new_root_key = existing_key
                    public_key_ssh = existing_key.public_key  # ✅ КЛЮЧЕВАЯ СТРОКА
                else:
                    logger.info(f"[BULK_IMPORT] Генерация ключа для {domain}")
                    private_key_pem, public_key_ssh = ssh_keys.generate_ssh_key("rsa")
                    fingerprint = ssh_keys.get_fingerprint(public_key_ssh)

                    if not fingerprint:
                        logger.error(f"[BULK_IMPORT] {domain}: не удалось получить fingerprint")
                        failed += 1
                        continue

                    encrypted_private_key = ssh_keys.encrypt_private_key(
                        private_key_pem, encryption_key
                    )

                    new_root_key = SSHKey(
                        name=root_key_name,
                        public_key=public_key_ssh,
                        private_key_encrypted=encrypted_private_key,
                        fingerprint=fingerprint,
                        key_type="rsa",
                        user_id=current_user.id,
                    )
                    db.session.add(new_root_key)
                    db.session.flush()
                    logger.info(
                        f"[BULK_IMPORT] Создан ключ {root_key_name} (ID: {new_root_key.id})"
                    )

            except Exception as e:
                db.session.rollback()
                logger.error(f"[BULK_IMPORT] Ошибка при работе с ключом для {domain}: {str(e)}")
                failed += 1
                continue

            # Развёртывание ключа (КРИТИЧНО!)
            try:
                logger.info(f"[BULK_IMPORT] Развёртывание ключа на {domain}")

                # Разворачиваем ключ через SSH
                conn = SSHConnection(ip_address, ssh_port, username)
                conn_success, conn_error = conn.connect_with_password(password)

                if not conn_success:
                    logger.error(f"[BULK_IMPORT] {domain}: Ошибка подключения - {conn_error}")
                    db.session.rollback()
                    failed += 1
                    continue

                try:
                    # Валидация ключа
                    if not ssh_keys.validate_ssh_public_key(public_key_ssh):
                        logger.error(f"[BULK_IMPORT] {domain}: Невалидный ключ")
                        db.session.rollback()
                        failed += 1
                        continue

                    # Создаём .ssh и добавляем ключ
                    cmd1_success, _, stderr1 = conn.execute(
                        "mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=15
                    )
                    if not cmd1_success:
                        logger.error(f"[BULK_IMPORT] {domain}: Ошибка создания .ssh - {stderr1}")
                        db.session.rollback()
                        failed += 1
                        continue

                    # Проверяем существование ключа
                    cmd2_success, existing_keys, _ = conn.execute(
                        "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''", timeout=10
                    )

                    if public_key_ssh.strip() not in existing_keys:
                        # Добавляем ключ
                        escaped_key = public_key_ssh.strip().replace("'", "'\\''")
                        cmd3_success, _, stderr3 = conn.execute(
                            f"echo '{escaped_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",  # noqa: E501
                            timeout=15,
                        )

                        if not cmd3_success:
                            logger.error(
                                f"[BULK_IMPORT] {domain}: Ошибка добавления ключа - {stderr3}"
                            )
                            db.session.rollback()
                            failed += 1
                            continue

                    logger.info(f"[BULK_IMPORT] {domain}: Ключ успешно развёрнут")
                finally:
                    conn.close()

            except Exception as e:
                db.session.rollback()
                logger.error(f"[BULK_IMPORT] Ошибка развёртывания на {domain}: {str(e)}")
                failed += 1
                continue

            # Создание сервера (ТОЛЬКО после успешного развёртывания!)
            try:
                new_server = Server(
                    name=domain,
                    ip_address=ip_address,
                    username=username,
                    ssh_port=ssh_port,
                    user_id=current_user.id,
                    status="online",
                    openssh_version=openssh_version,
                    requires_legacy_ssh=requires_legacy_ssh,
                    access_key_id=new_root_key.id,
                )
                db.session.add(new_server)
                db.session.flush()
                logger.info(f"[BULK_IMPORT] Создан сервер {domain} (ID: {new_server.id})")

            except Exception as e:
                db.session.rollback()
                logger.error(f"[BULK_IMPORT] Ошибка создания сервера {domain}: {str(e)}")
                failed += 1
                continue

            # Создание KeyDeployment
            try:
                deployment = KeyDeployment(
                    ssh_key_id=new_root_key.id,
                    server_id=new_server.id,
                    deployed_by=current_user.id,
                    deployed_at=datetime.now(timezone.utc),
                )
                db.session.add(deployment)
                db.session.commit()
                logger.info(
                    f"[BULK_IMPORT] KeyDeployment создан: ключ {new_root_key.id} -> "
                    f"сервер {new_server.id}"
                )

            except Exception as e:
                db.session.rollback()
                logger.error(f"[BULK_IMPORT] Ошибка создания deployment для {domain}: {str(e)}")
                failed += 1
                continue

            add_log(
                "add_server",
                target=domain,
                details={"ip": ip_address, "port": ssh_port, "key_id": new_root_key.id},
            )
            added += 1

        return (
            jsonify(
                {
                    "success": True,
                    "message": "OK",
                    "added": added,
                    "skipped": skipped,
                    "failed": failed,
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
                    "message": f"Ошибка сервера: {str(e)}",
                    "added": 0,
                    "skipped": 0,
                    "failed": 0,
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
