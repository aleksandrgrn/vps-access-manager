"""
Keys Routes

Маршруты для управления SSH ключами с type hints и обработкой ошибок.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import ssh_manager
from app import db
from app.forms import GenerateKeyForm, UploadKeyForm
from app.models import KeyDeployment, Server, SSHKey
from app.services.key_service import decrypt_access_key, deploy_key_to_server
from app.utils import add_log

bp = Blueprint("keys", __name__)
logger = logging.getLogger(__name__)


@bp.route("/keys")
@login_required
def keys() -> str:
    """Страница списка SSH ключей."""
    try:
        generate_form = GenerateKeyForm()
        upload_form = UploadKeyForm()
        user_keys = SSHKey.query.filter_by(user_id=current_user.id).all()
        user_servers = Server.query.filter_by(user_id=current_user.id).all()

        return render_template(
            "keys.html",
            generate_form=generate_form,
            upload_form=upload_form,
            keys=user_keys,
            servers=user_servers,
        )

    except Exception as e:
        logger.error(f"[KEYS_ERROR] {str(e)}")
        flash(f"Ошибка при загрузке ключей: {str(e)}", "error")
        return render_template(
            "keys.html",
            generate_form=GenerateKeyForm(),
            upload_form=UploadKeyForm(),
            keys=[],
            servers=[],
        )


@bp.route("/keys/generate", methods=["POST"])
@login_required
def generate_key() -> Any:
    """Генерация нового SSH ключа."""
    form = GenerateKeyForm()

    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")
        return redirect(url_for("keys.keys"))

    try:
        # Генерация ключа
        private_key_pem, public_key_ssh = ssh_manager.generate_ssh_key(form.key_type.data)
        fingerprint = ssh_manager.get_fingerprint(public_key_ssh)

        if not fingerprint:
            flash("Не удалось вычислить fingerprint ключа.", "danger")
            return redirect(url_for("keys.keys"))

        # Проверка: существует ли ключ с таким fingerprint?
        existing_key = SSHKey.query.filter_by(
            user_id=current_user.id, fingerprint=fingerprint
        ).first()

        if existing_key:
            # Ключ уже существует - используем его
            logger.info(
                f"[KEY_EXISTS] Ключ с fingerprint {fingerprint} уже существует (ID: {existing_key.id}, имя: '{existing_key.name}')"
            )
            flash(
                f'ℹ️ Ключ с таким fingerprint уже существует: "{existing_key.name}". Будет использован существующий ключ.',
                "info",
            )
            key_to_use = existing_key
        else:
            # Проверка имени (только если создаём новый ключ)
            existing_name = SSHKey.query.filter_by(
                user_id=current_user.id, name=form.name.data
            ).first()
            if existing_name:
                flash(
                    f'❌ Ключ с именем "{form.name.data}" уже существует. Выберите другое имя.',
                    "danger",
                )
                return redirect(url_for("keys.keys"))

            # Шифрование приватного ключа
            encryption_key = os.environ.get("ENCRYPTION_KEY")
            if not encryption_key:
                flash("ENCRYPTION_KEY не установлен на сервере", "danger")
                return redirect(url_for("keys.keys"))

            encrypted_private_key = ssh_manager.encrypt_private_key(private_key_pem, encryption_key)

            # Создание нового ключа
            new_key = SSHKey(
                name=form.name.data,
                public_key=public_key_ssh,
                private_key_encrypted=encrypted_private_key,
                fingerprint=fingerprint,
                key_type=form.key_type.data,
                user_id=current_user.id,
            )
            db.session.add(new_key)
            db.session.commit()

            add_log("generate_key", target=new_key.name, details={"key_type": form.key_type.data})
            logger.info(f"[KEY_CREATED] Новый ключ создан (ID: {new_key.id})")
            key_to_use = new_key

        # Используем key_to_use для дальнейших операций
        flash(f'✅ Ключ "{key_to_use.name}" готов к использованию.', "success")

    except Exception as e:
        logger.error(f"[GENERATE_KEY_ERROR] {str(e)}")
        db.session.rollback()
        flash(f"Ошибка при генерации ключа: {str(e)}", "danger")

    return redirect(url_for("keys.keys"))


@bp.route("/keys/upload", methods=["POST"])
@login_required
def upload_key() -> Any:
    """Загрузка публичного SSH ключа."""
    form = UploadKeyForm()

    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")
        return redirect(url_for("keys.keys"))

    try:
        public_key = form.public_key.data.strip()

        # Валидация формата ключа
        if not ssh_manager.validate_ssh_public_key(public_key):
            flash("Неверный формат публичного ключа.", "danger")
            return redirect(url_for("keys.keys"))

        # Вычисление fingerprint
        fingerprint = ssh_manager.get_fingerprint(public_key)
        if not fingerprint:
            flash("Не удалось вычислить fingerprint ключа.", "danger")
            return redirect(url_for("keys.keys"))

        # Проверка: существует ли ключ с таким fingerprint?
        existing_key = SSHKey.query.filter_by(
            user_id=current_user.id, fingerprint=fingerprint
        ).first()

        if existing_key:
            # Ключ уже существует - используем его
            logger.info(
                f"[KEY_EXISTS] Ключ с fingerprint {fingerprint} уже существует (ID: {existing_key.id}, имя: '{existing_key.name}')"
            )
            flash(
                f'ℹ️ Ключ с таким fingerprint уже существует: "{existing_key.name}". Будет использован существующий ключ.',
                "info",
            )
            key_to_use = existing_key
        else:
            # Проверка имени (только если создаём новый ключ)
            existing_name = SSHKey.query.filter_by(
                user_id=current_user.id, name=form.name.data
            ).first()
            if existing_name:
                flash(
                    f'❌ Ключ с именем "{form.name.data}" уже существует. Выберите другое имя.',
                    "danger",
                )
                return redirect(url_for("keys.keys"))

            # Определение типа ключа
            key_type = public_key.split()[0].replace("ssh-", "")

            # Создание пустого зашифрованного приватного ключа (его нет при загрузке)
            encryption_key = os.environ.get("ENCRYPTION_KEY")
            empty_encrypted = ssh_manager.encrypt_private_key("", encryption_key)

            # Создание нового ключа
            new_key = SSHKey(
                name=form.name.data,
                public_key=public_key,
                private_key_encrypted=empty_encrypted,
                fingerprint=fingerprint,
                key_type=key_type,
                user_id=current_user.id,
            )
            db.session.add(new_key)
            db.session.commit()

            add_log("upload_key", target=new_key.name)
            logger.info(f"[KEY_CREATED] Новый ключ создан (ID: {new_key.id})")
            key_to_use = new_key

        # Используем key_to_use для дальнейших операций
        flash(f'✅ Ключ "{key_to_use.name}" готов к использованию.', "success")

    except Exception as e:
        logger.error(f"[UPLOAD_KEY_ERROR] {str(e)}")
        db.session.rollback()
        flash(f"Ошибка при загрузке ключа: {str(e)}", "danger")

    return redirect(url_for("keys.keys"))


@bp.route("/keys/delete/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id: int) -> Tuple[Dict[str, Any], int]:
    """Удаление SSH ключа."""
    try:
        key = SSHKey.query.get_or_404(key_id)

        # Проверка доступа
        if key.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        key_name = key.name
        db.session.delete(key)
        db.session.commit()

        add_log("delete_key", target=key_name)
        return jsonify({"success": True, "message": "Ключ успешно удален."}), 200

    except Exception as e:
        logger.error(f"[DELETE_KEY_ERROR] {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/keys/deploy", methods=["POST"])
@login_required
def deploy_key() -> Tuple[Dict[str, Any], int]:
    """
    Развёртывание SSH ключа на сервере.

    JSON Input:
        key_id (int): ID ключа для развёртывания
        server_id (int): ID сервера

    Returns:
        JSON с результатом операции

    ЯКОРЬ: БД обновляется ТОЛЬКО после успешного развёртывания!
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Пустой JSON"}), 400

        key_id = data.get("key_id")
        server_id = data.get("server_id")

        if not key_id or not server_id:
            return jsonify({"success": False, "message": "key_id и server_id обязательны"}), 400

        # Получение объектов из БД
        key_to_deploy = SSHKey.query.get(key_id)
        server = Server.query.get(server_id)

        if not key_to_deploy or not server:
            return jsonify({"success": False, "message": "Ключ или сервер не найден"}), 404

        # Проверка доступа
        if key_to_deploy.user_id != current_user.id or server.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Проверка дубликата развёртывания
        existing_deployment = KeyDeployment.query.filter_by(
            ssh_key_id=key_id, server_id=server_id, revoked_at=None
        ).first()

        if existing_deployment:
            return (
                jsonify(
                    {"success": False, "message": f"Ключ уже развёрнут на сервере {server.name}"}
                ),
                400,
            )

        # Проверка access_key сервера
        if not server.access_key:
            return (
                jsonify(
                    {"success": False, "message": "Для этого сервера не настроен ключ доступа"}
                ),
                400,
            )

        # Расшифровка access_key
        decrypt_result = decrypt_access_key(server.access_key)
        if not decrypt_result["success"]:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f'Ошибка расшифровки: {decrypt_result["message"]}',
                        "error_type": decrypt_result.get("error_type"),
                    }
                ),
                500,
            )

        # SSH развёртывание (КРИТИЧНО!)
        deploy_result = deploy_key_to_server(server, decrypt_result["private_key"], key_to_deploy)

        if not deploy_result["success"]:
            logger.warning(f"[DEPLOY_KEY_FAILED] {deploy_result['message']}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": deploy_result["message"],
                        "error_type": deploy_result.get("error_type"),
                    }
                ),
                500,
            )

        # ✅ ТОЛЬКО ПОСЛЕ УСПЕХА SSH → создать KeyDeployment
        try:
            deployment = KeyDeployment(
                ssh_key_id=key_id,
                server_id=server_id,
                deployed_by=current_user.id,
                deployed_at=datetime.now(timezone.utc),
            )
            db.session.add(deployment)
            db.session.commit()

            add_log("deploy_key", target=f"{key_to_deploy.name} -> {server.name}")

            return (
                jsonify(
                    {"success": True, "message": f"✅ Ключ успешно развёрнут на {server.name}"}
                ),
                200,
            )

        except Exception as db_error:
            db.session.rollback()
            logger.error(f"[DEPLOY_KEY_DB_ERROR] {str(db_error)}")
            return (
                jsonify(
                    {"success": False, "message": f"SSH успешно, но ошибка БД: {str(db_error)}"}
                ),
                500,
            )

    except Exception as e:
        logger.error(f"[DEPLOY_KEY_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/key-servers/<int:key_id>", methods=["GET"])
@login_required
def get_key_servers(key_id: int) -> Tuple[Dict[str, Any], int]:
    """Получить список серверов где развёрнут ключ."""
    try:
        ssh_key = SSHKey.query.get(key_id)

        if not ssh_key:
            return jsonify({"success": False, "message": "Ключ не найден"}), 404

        if ssh_key.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Получение активных развертываний
        deployments = KeyDeployment.query.filter_by(ssh_key_id=key_id, revoked_at=None).all()

        servers = []
        for deployment in deployments:
            server = Server.query.get(deployment.server_id)
            if server:
                servers.append(
                    {"id": server.id, "name": server.name, "ip_address": server.ip_address}
                )

        return jsonify({"success": True, "servers": servers}), 200

    except Exception as e:
        logger.error(f"[GET_KEY_SERVERS_ERROR] {str(e)}")
        return jsonify({"success": False, "message": "Ошибка сервера"}), 500


@bp.route("/keys/view/<int:key_id>", methods=["GET"])
@login_required
def view_key(key_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Возвращает расшифрованный приватный ключ для просмотра.

    Args:
        key_id: ID SSH ключа

    Returns:
        JSON: {
            'success': bool,
            'private_key': str,  # Расшифрованный ключ (если success)
            'key_name': str,
            'message': str       # Ошибка (если !success)
        }

    Security:
        - Только владелец ключа может его просмотреть
        - Приватный ключ расшифровывается через decrypt_access_key()
    """
    try:
        # Получи ключ
        ssh_key = SSHKey.query.get(key_id)

        if not ssh_key:
            logger.error(f"[VIEW_KEY] Key not found: id={key_id}")
            return jsonify({"success": False, "message": "Ключ не найден"}), 404

        # Проверка доступа
        if ssh_key.user_id != current_user.id:
            logger.error(
                f"[VIEW_KEY] Access denied: user_id={current_user.id}, key_user_id={ssh_key.user_id}"
            )
            return jsonify({"success": False, "message": "Доступ запрещён"}), 403

        # Расшифруй приватный ключ
        decrypt_result = decrypt_access_key(ssh_key)

        if not decrypt_result["success"]:
            logger.error(f"[VIEW_KEY] Decrypt failed: {decrypt_result['message']}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Ошибка расшифровки: {decrypt_result['message']}",
                    }
                ),
                500,
            )

        logger.info(f"[VIEW_KEY] Key viewed: {ssh_key.name} by user {current_user.id}")

        add_log("view_key", target=ssh_key.name)

        return (
            jsonify(
                {
                    "success": True,
                    "private_key": decrypt_result["private_key"],
                    "key_name": ssh_key.name,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"[VIEW_KEY_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/keys/bulk-deploy", methods=["POST"])
@login_required
def bulk_deploy_key() -> Tuple[Dict[str, Any], int]:
    """
    Массовое развертывание SSH-ключа на выбранные серверы.

    JSON Input:
        {
            "key_id": int,
            "server_ids": [int, ...]
        }

    JSON Output:
        {
            "success": bool,
            "deployed": [{"server_id": int, "server_name": str}, ...],
            "failed": [{"server_id": int, "server_name": str, "error": str}, ...],
            "total": int,
            "message": str
        }

    КРИТИЧНО:
        - Использует параллельную обработку через ThreadPoolExecutor
        - KeyDeployment создается ТОЛЬКО для успешных развертываний
        - Логирует каждое успешное развертывание
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Пустой JSON"}), 400

        key_id = data.get("key_id")
        server_ids = data.get("server_ids", [])

        # Валидация входных данных
        if not key_id:
            return jsonify({"success": False, "message": "key_id обязателен"}), 400

        if not server_ids or not isinstance(server_ids, list):
            return (
                jsonify({"success": False, "message": "server_ids должен быть непустым списком"}),
                400,
            )

        # Получение ключа
        key = SSHKey.query.get(key_id)
        if not key:
            return jsonify({"success": False, "message": "Ключ не найден"}), 404

        # Проверка доступа к ключу
        if key.user_id != current_user.id:
            logger.warning(
                f"[BULK_DEPLOY] Попытка доступа к чужому ключу: user={current_user.id}, key_owner={key.user_id}"
            )
            return jsonify({"success": False, "message": "Доступ запрещён"}), 403

        # Получение серверов
        servers = Server.query.filter(
            Server.id.in_(server_ids), Server.user_id == current_user.id
        ).all()

        if not servers:
            return (
                jsonify({"success": False, "message": "Не найдено ни одного доступного сервера"}),
                404,
            )

        # Проверка access_key у каждого сервера
        servers_without_access_key = []
        for server in servers:
            if not server.access_key:
                servers_without_access_key.append(server.name)

        if servers_without_access_key:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f'Серверы без ключа доступа: {", ".join(servers_without_access_key)}',
                    }
                ),
                400,
            )

        # Проверка на дубликаты развертывания
        existing_deployments = KeyDeployment.query.filter(
            KeyDeployment.ssh_key_id == key_id,
            KeyDeployment.server_id.in_(server_ids),
            KeyDeployment.revoked_at == None,
        ).all()

        if existing_deployments:
            existing_server_ids = [d.server_id for d in existing_deployments]
            existing_servers = Server.query.filter(Server.id.in_(existing_server_ids)).all()
            existing_names = [s.name for s in existing_servers]
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f'Ключ уже развёрнут на серверах: {", ".join(existing_names)}',
                    }
                ),
                400,
            )

        logger.info(
            f"[BULK_DEPLOY] Начало массового развертывания ключа {key.name} на {len(servers)} серверов"
        )

        # Массовое развертывание через ssh_manager
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            return (
                jsonify({"success": False, "message": "ENCRYPTION_KEY не установлен на сервере"}),
                500,
            )

        results = ssh_manager.deploy_key_to_multiple_servers(key, servers, encryption_key)

        # Создать KeyDeployment ТОЛЬКО для успешных развертываний
        deployment_count = 0
        for deployed in results["deployed"]:
            try:
                deployment = KeyDeployment(
                    ssh_key_id=key_id,
                    server_id=deployed["server_id"],
                    deployed_by=current_user.id,
                    deployed_at=datetime.now(timezone.utc),
                )
                db.session.add(deployment)

                # Логирование каждого успешного развертывания
                add_log("deploy_key", target=f"{key.name} -> {deployed['server_name']}")
                deployment_count += 1

            except Exception as db_error:
                logger.error(
                    f"[BULK_DEPLOY] Ошибка БД для сервера {deployed['server_name']}: {str(db_error)}"
                )
                # Не прерываем процесс, продолжаем для других серверов

        # Коммитим все успешные развертывания
        try:
            db.session.commit()
            logger.info(f"[BULK_DEPLOY] Успешно сохранено {deployment_count} развертываний в БД")
        except Exception as commit_error:
            db.session.rollback()
            logger.error(f"[BULK_DEPLOY] Ошибка при коммите: {str(commit_error)}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"SSH развертывание успешно, но ошибка БД: {str(commit_error)}",
                        "deployed": results["deployed"],
                        "failed": results["failed"],
                        "total": results["total"],
                    }
                ),
                500,
            )

        # Формирование ответа
        success_count = len(results["deployed"])
        failed_count = len(results["failed"])

        if success_count > 0 and failed_count == 0:
            message = f"✅ Ключ успешно развёрнут на всех {success_count} серверах"
        elif success_count > 0 and failed_count > 0:
            message = f"⚠️ Развёрнуто на {success_count} серверах, ошибок: {failed_count}"
        else:
            message = f"❌ Не удалось развернуть ни на одном сервере"

        logger.info(f"[BULK_DEPLOY] Завершено. {message}")

        return (
            jsonify(
                {
                    "success": success_count > 0,
                    "deployed": results["deployed"],
                    "failed": results["failed"],
                    "total": results["total"],
                    "message": message,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"[BULK_DEPLOY_ERROR] {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500
