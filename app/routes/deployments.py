"""
Deployments Routes - КРИТИЧНЫЙ ФАЙЛ

Маршруты для отзыва SSH ключей с ПОЛНОЙ обработкой ошибок.
ЯКОРЬ #1: БД обновляется ТОЛЬКО после успешной SSH операции!
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from flask import Blueprint, flash, jsonify, render_template, request
from flask_login import current_user, login_required

from app import db
from app.models import KeyDeployment, Server, SSHKey
from app.services.key_service import (
    decrypt_access_key,
    deploy_key_to_server,
    revoke_key_from_all_servers,
    revoke_key_from_single_server,
)
from app.utils import add_log

bp = Blueprint("deployments", __name__)
logger = logging.getLogger(__name__)


@bp.route("/key-deployments")
@login_required
def key_deployments() -> str:
    """Страница списка развёртываний ключей с поддержкой фильтрации."""
    try:
        # Получение параметров фильтрации из URL
        key_id = request.args.get("key_id", type=int)
        server_id = request.args.get("server_id", type=int)
        status = request.args.get("status", "")

        # Базовый запрос
        query = KeyDeployment.query.filter_by(deployed_by=current_user.id)

        # Применение фильтров
        if key_id:
            query = query.filter_by(ssh_key_id=key_id)

        if server_id:
            query = query.filter_by(server_id=server_id)

        if status == "active":
            query = query.filter_by(revoked_at=None)
        elif status == "revoked":
            query = query.filter(KeyDeployment.revoked_at.isnot(None))

        deployments = query.all()

        # Получение всех ключей и серверов для выпадающих списков фильтров
        all_keys = SSHKey.query.filter_by(user_id=current_user.id).all()
        all_servers = Server.query.filter_by(user_id=current_user.id).all()

        return render_template(
            "key-deployments.html",
            deployments=deployments,
            all_keys=all_keys,
            all_servers=all_servers,
        )
    except Exception as e:
        logger.error(f"[KEY_DEPLOYMENTS_ERROR] {str(e)}")
        flash(f"Ошибка при загрузке развёртываний: {str(e)}", "error")
        return render_template("key-deployments.html", deployments=[], all_keys=[], all_servers=[])


@bp.route("/key-deployments/revoke", methods=["POST"])
@login_required
def revoke_key_deployment() -> Tuple[Dict[str, Any], int]:
    """
    Отзыв SSH ключа с сервера.

    Поддерживает 3 сценария:
    - Scenario 0: Отзыв по deployment_id (конкретное развёртывание)
    - Scenario 1: Отзыв со всех серверов (key_id без server_id)
    - Scenario 2: Отзыв с одного сервера (key_id + server_id)

    JSON Input:
        deployment_id (int): ID развёртывания (Scenario 0)
        key_id (int): ID ключа (Scenario 1, 2)
        server_id (int): ID сервера (Scenario 2)

    Returns:
        JSON с результатом операции

    ЯКОРЬ #1: БД обновляется ТОЛЬКО после успешной SSH операции!
    ЯКОРЬ #2: Возвращает детальный JSON с error_type, details, server_info
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Пустой JSON"}), 400

        deployment_id = data.get("deployment_id")
        key_id = data.get("key_id")
        server_id = data.get("server_id")

        # ========== SCENARIO 0: Отзыв по deployment_id ==========
        if deployment_id:
            logger.info(f"[REVOKE_START] Scenario 0: deployment_id={deployment_id}")

            # ЭТАП 1: Получение deployment
            deployment = KeyDeployment.query.get(deployment_id)
            if not deployment:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Развёртывание не найдено",
                            "error_type": "not_found",
                        }
                    ),
                    404,
                )

            # Проверка что уже не отозван
            if deployment.revoked_at:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Ключ уже отозван",
                            "error_type": "already_revoked",
                        }
                    ),
                    400,
                )

            key_to_revoke = deployment.ssh_key
            server = deployment.server

            logger.info(f"[REVOKE_DEBUG] Ключ: {key_to_revoke.name}, Сервер: {server.name}")

            # ЭТАП 2: Проверка доступа
            if key_to_revoke.user_id != current_user.id:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "У вас нет доступа к этому ключу",
                            "error_type": "access_denied",
                        }
                    ),
                    403,
                )

            # ЭТАП 3: Проверка access_key сервера
            if not server.access_key:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Для этого сервера не настроен ключ доступа",
                            "server": server.name,
                            "ip": server.ip_address,
                            "error_type": "missing_access_key",
                        }
                    ),
                    400,
                )

            # ЭТАП 4: Расшифровка access_key (МОЖЕТ ОШИБИТЬСЯ!)
            logger.info(f"[REVOKE_DECRYPT] Расшифровка access_key для {server.name}")
            decrypt_result = decrypt_access_key(server.access_key)

            if not decrypt_result["success"]:
                logger.error(f"[REVOKE_DECRYPT_FAILED] {decrypt_result['message']}")
                add_log(
                    "revoke_key_decrypt_failed",
                    target=key_to_revoke.name,
                    details={"server": server.name, "error": decrypt_result["message"]},
                )
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f'Ошибка расшифровки: {decrypt_result["message"]}',
                            "details": "Проверьте ENCRYPTION_KEY на сервере",
                            "server": server.name,
                            "ip": server.ip_address,
                            "error_type": "decryption_error",
                            "server_info": {
                                "name": server.name,
                                "ip": server.ip_address,
                                "port": server.ssh_port,
                                "username": server.username,
                            },
                        }
                    ),
                    500,
                )

            private_key = decrypt_result["private_key"]

            # ЭТАП 5: РЕАЛЬНАЯ SSH ОПЕРАЦИЯ (КРИТИЧНАЯ!)
            # ❌ БЕЗ ЭТОГО ШАГА НЕ ОБНОВЛЯЕМ БД!
            logger.info(f"[REVOKE_SSH_START] Попытка отзыва ключа с {server.name}")

            try:
                revoke_result = revoke_key_from_single_server(server, private_key, key_to_revoke)
            except Exception as ssh_error:
                logger.error(f"[REVOKE_SSH_EXCEPTION] {str(ssh_error)}")
                add_log(
                    "revoke_key_exception",
                    target=key_to_revoke.name,
                    details={"server": server.name, "error": str(ssh_error)},
                )
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"SSH ошибка: {str(ssh_error)}",
                            "details": "Проверьте доступность сервера и SSH параметры",
                            "server": server.name,
                            "ip": server.ip_address,
                            "error_type": "ssh_exception",
                            "server_info": {
                                "name": server.name,
                                "ip": server.ip_address,
                                "port": server.ssh_port,
                                "username": server.username,
                            },
                        }
                    ),
                    500,
                )

            # ЭТАП 6: ПРОВЕРКА РЕЗУЛЬТАТА SSH
            if not revoke_result["success"]:
                logger.warning(f"[REVOKE_SSH_FAILED] {revoke_result['message']}")
                add_log(
                    "revoke_key_failed",
                    target=key_to_revoke.name,
                    details={
                        "server": server.name,
                        "error": revoke_result.get("message", "Unknown error"),
                    },
                )
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f'Не удалось отозвать ключ: {revoke_result["message"]}',
                            "details": revoke_result.get("details", ""),
                            "server": server.name,
                            "ip": server.ip_address,
                            "error_type": revoke_result.get("error_type", "ssh_error"),
                            "server_info": {
                                "name": server.name,
                                "ip": server.ip_address,
                                "port": server.ssh_port,
                                "username": server.username,
                            },
                        }
                    ),
                    500,
                )

            # ✅ ЭТАП 7: ТОЛЬКО ЕСЛИ SSH УСПЕХ → ОБНОВИТЬ БД!
            try:
                deployment.revoked_at = datetime.now(timezone.utc)
                deployment.revoked_by = current_user.id
                db.session.commit()

                logger.info(f"[REVOKE_SUCCESS] Ключ {key_to_revoke.name} отозван с {server.name}")
                add_log(
                    "revoke_key",
                    target=key_to_revoke.name,
                    details={"server": server.name, "result": "success"},
                )

                return (
                    jsonify(
                        {
                            "success": True,
                            "message": "✅ Ключ успешно отозван с VPS",
                            "server": server.name,
                            "ip": server.ip_address,
                        }
                    ),
                    200,
                )

            except Exception as db_error:
                db.session.rollback()
                logger.error(f"[REVOKE_DB_ERROR] {str(db_error)}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Ошибка БД: {str(db_error)}",
                            "details": "SSH операция выполнена, но не удалось обновить БД",
                            "server": server.name,
                            "ip": server.ip_address,
                            "error_type": "database_error",
                        }
                    ),
                    500,
                )

        # ========== SCENARIO 1: Отзыв со всех серверов ==========
        elif key_id and not server_id:
            logger.info(f"[REVOKE_START] Scenario 1: key_id={key_id} (bulk revoke)")

            key_to_revoke = SSHKey.query.get(key_id)
            if not key_to_revoke:
                return jsonify({"success": False, "message": "Ключ не найден"}), 404

            if key_to_revoke.user_id != current_user.id:
                return jsonify({"success": False, "message": "Доступ запрещен"}), 403

            # Получение всех активных развёртываний
            active_deployments = KeyDeployment.query.filter_by(
                ssh_key_id=key_id, revoked_at=None
            ).all()

            if not active_deployments:
                return (
                    jsonify(
                        {"success": False, "message": "Нет активных развёртываний для этого ключа"}
                    ),
                    400,
                )

            # Получение серверов и access_keys
            servers = []
            access_keys = {}
            for deployment in active_deployments:
                server = Server.query.get(deployment.server_id)
                if server and server.access_key:
                    servers.append(server)
                    access_keys[server.id] = server.access_key

            # Массовый отзыв
            bulk_result = revoke_key_from_all_servers(key_to_revoke, servers, access_keys)

            # Обновление БД для успешных отзывов
            for result in bulk_result["results"]:
                if result["success"]:
                    deployment = KeyDeployment.query.filter_by(
                        ssh_key_id=key_id,
                        server_id=next(
                            (s.id for s in servers if s.name == result["server_name"]), None
                        ),
                        revoked_at=None,
                    ).first()

                    if deployment:
                        deployment.revoked_at = datetime.now(timezone.utc)
                        deployment.revoked_by = current_user.id

            db.session.commit()

            add_log(
                "revoke_key_bulk",
                target=key_to_revoke.name,
                details={
                    "success_count": bulk_result["success_count"],
                    "failed_count": bulk_result["failed_count"],
                },
            )

            return (
                jsonify(
                    {
                        "success": True,
                        "message": f'Отозвано с {bulk_result["success_count"]} серверов',
                        "success_count": bulk_result["success_count"],
                        "failed_count": bulk_result["failed_count"],
                        "results": bulk_result["results"],
                    }
                ),
                200,
            )

        # ========== SCENARIO 2: Отзыв с одного сервера ==========
        elif key_id and server_id:
            logger.info(f"[REVOKE_START] Scenario 2: key_id={key_id}, server_id={server_id}")

            key_to_revoke = SSHKey.query.get(key_id)
            server = Server.query.get(server_id)

            if not key_to_revoke or not server:
                return jsonify({"success": False, "message": "Ключ или сервер не найден"}), 404

            if key_to_revoke.user_id != current_user.id:
                return jsonify({"success": False, "message": "Доступ запрещен"}), 403

            # Получение deployment
            deployment = KeyDeployment.query.filter_by(
                ssh_key_id=key_id, server_id=server_id, revoked_at=None
            ).first()

            if not deployment:
                return (
                    jsonify({"success": False, "message": "Активное развёртывание не найдено"}),
                    404,
                )

            # Расшифровка и отзыв (аналогично Scenario 0)
            if not server.access_key:
                return (
                    jsonify(
                        {"success": False, "message": "Для этого сервера не настроен ключ доступа"}
                    ),
                    400,
                )

            decrypt_result = decrypt_access_key(server.access_key)
            if not decrypt_result["success"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f'Ошибка расшифровки: {decrypt_result["message"]}',
                            "error_type": "decryption_error",
                        }
                    ),
                    500,
                )

            revoke_result = revoke_key_from_single_server(
                server, decrypt_result["private_key"], key_to_revoke
            )

            if not revoke_result["success"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": revoke_result["message"],
                            "error_type": revoke_result.get("error_type"),
                        }
                    ),
                    500,
                )

            # Обновление БД
            deployment.revoked_at = datetime.now(timezone.utc)
            deployment.revoked_by = current_user.id
            db.session.commit()

            add_log("revoke_key", target=key_to_revoke.name, details={"server": server.name})

            return jsonify({"success": True, "message": f"✅ Ключ отозван с {server.name}"}), 200

        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Неверные параметры: требуется deployment_id или key_id",
                    }
                ),
                400,
            )

    except Exception as critical_error:
        logger.error(f"[REVOKE_CRITICAL] {str(critical_error)}")
        add_log("revoke_key_critical", details={"error": str(critical_error)})
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"КРИТИЧЕСКАЯ ОШИБКА: {str(critical_error)}",
                    "error_type": "critical",
                }
            ),
            500,
        )


@bp.route("/revoke-key-all", methods=["POST"])
@login_required
def revoke_key_all() -> Tuple[Dict[str, Any], int]:
    """
    Массовый отзыв ключа со всех серверов где он развёрнут.

    JSON Input:
        ssh_key_id (int): ID ключа для отзыва

    Returns:
        JSON: {
            'success': bool,
            'message': str,
            'total': int,
            'completed': int,
            'failed': int
        }
    """
    try:
        data = request.get_json()

        if not data:
            logger.error("[REVOKE_ALL] Empty JSON received")
            return jsonify({"success": False, "message": "Empty JSON"}), 400

        ssh_key_id = data.get("ssh_key_id")

        if not ssh_key_id:
            logger.error("[REVOKE_ALL] Missing ssh_key_id")
            return jsonify({"success": False, "message": "ssh_key_id required"}), 400

        logger.info(f"[REVOKE_ALL_START] ssh_key_id={ssh_key_id}")

        # Получи ключ
        key_to_revoke = SSHKey.query.get(ssh_key_id)

        if not key_to_revoke:
            logger.error(f"[REVOKE_ALL] Key not found: id={ssh_key_id}")
            return jsonify({"success": False, "message": "Key not found"}), 404

        # Проверка доступа
        if key_to_revoke.user_id != current_user.id:
            logger.error(
                f"[REVOKE_ALL] Access denied: user_id={current_user.id}, "
                f"key_user_id={key_to_revoke.user_id}"
            )
            return jsonify({"success": False, "message": "Access denied"}), 403

        # Найди все активные deployments
        active_deployments = KeyDeployment.query.filter_by(
            ssh_key_id=ssh_key_id, revoked_at=None
        ).all()

        if not active_deployments:
            logger.info(f"[REVOKE_ALL] No active deployments for key_id={ssh_key_id}")
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Нет активных развёртываний",
                        "total": 0,
                        "completed": 0,
                        "failed": 0,
                    }
                ),
                200,
            )

        # Собери серверы и access keys
        servers = []
        access_keys = {}

        for deployment in active_deployments:
            server = Server.query.get(deployment.server_id)
            if server and server.access_key:
                servers.append(server)
                access_keys[server.id] = server.access_key
                logger.debug(
                    f"[REVOKE_ALL] Added server {server.name} "
                    f"(access_key_id={server.access_key.id})"
                )
            else:
                logger.warning(
                    f"[REVOKE_ALL] Skipping server "
                    f"{server.name if server else 'Unknown'} - no access_key"
                )

        if not servers:
            logger.error(f"[REVOKE_ALL] No valid servers found for key_id={ssh_key_id}")
            return jsonify({"success": False, "message": "Нет доступных серверов"}), 400

        logger.info(f"[REVOKE_ALL] Starting revoke on {len(servers)} servers")

        # Массовый отзыв
        bulk_result = revoke_key_from_all_servers(key_to_revoke, servers, access_keys)

        # Обнови БД для успешных отзывов
        for result in bulk_result["results"]:
            if result["success"]:
                # Найди deployment по имени сервера
                server_match = next((s for s in servers if s.name == result["server_name"]), None)
                if server_match:
                    deployment = KeyDeployment.query.filter_by(
                        ssh_key_id=ssh_key_id, server_id=server_match.id, revoked_at=None
                    ).first()

                    if deployment:
                        deployment.revoked_at = datetime.now(timezone.utc)
                        deployment.revoked_by = current_user.id
                        logger.info(f"[REVOKE_ALL] Updated deployment id={deployment.id}")

        db.session.commit()

        add_log(
            "revoke_key_bulk",
            target=key_to_revoke.name,
            details={
                "total": len(servers),
                "success_count": bulk_result["success_count"],
                "failed_count": bulk_result["failed_count"],
            },
        )

        logger.info(
            f"[REVOKE_ALL_SUCCESS] Revoked from "
            f"{bulk_result['success_count']}/{len(servers)} servers"
        )

        return (
            jsonify(
                {
                    "success": True,
                    "message": (
                        f"✅ Отозвано с {bulk_result['success_count']} из "
                        f"{len(servers)} серверов"
                    ),
                    "total": len(servers),
                    "completed": bulk_result["success_count"],
                    "failed": bulk_result["failed_count"],
                }
            ),
            200,
        )

    except Exception as critical_error:
        logger.error(f"[REVOKE_ALL_CRITICAL] {str(critical_error)}")
        return (
            jsonify({"success": False, "message": f"Критическая ошибка: {str(critical_error)}"}),
            500,
        )


@bp.route("/key-deployments/filter", methods=["POST"])
@login_required
def filter_key_deployments() -> Tuple[Dict[str, Any], int]:
    """
    Фильтрация развёртываний ключей.

    JSON Input:
        key_id (int, optional): Фильтр по ключу
        server_id (int, optional): Фильтр по серверу
        status (str, optional): 'active' или 'revoked'
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Пустой JSON"}), 400

        query = KeyDeployment.query.filter_by(deployed_by=current_user.id)

        # Фильтр по ключу
        if data.get("key_id"):
            query = query.filter_by(ssh_key_id=data["key_id"])

        # Фильтр по серверу
        if data.get("server_id"):
            query = query.filter_by(server_id=data["server_id"])

        # Фильтр по статусу
        status = data.get("status")
        if status == "active":
            query = query.filter_by(revoked_at=None)
        elif status == "revoked":
            query = query.filter(KeyDeployment.revoked_at.isnot(None))

        deployments = query.all()

        results = []
        for deployment in deployments:
            results.append(
                {
                    "id": deployment.id,
                    "key_name": deployment.ssh_key.name,
                    "server_name": deployment.server.name,
                    "deployed_at": (
                        deployment.deployed_at.isoformat() if deployment.deployed_at else None
                    ),
                    "revoked_at": (
                        deployment.revoked_at.isoformat() if deployment.revoked_at else None
                    ),
                    "status": "revoked" if deployment.revoked_at else "active",
                }
            )

        return jsonify({"success": True, "deployments": results}), 200

    except Exception as e:
        logger.error(f"[FILTER_DEPLOYMENTS_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/key-deployments/deploy", methods=["POST"])
@login_required
def deploy_key() -> Tuple[Dict[str, Any], int]:
    """
    Развёртывание SSH ключа на серверы.

    JSON Input:
        key_id (int): ID ключа для развёртывания
        server_ids (List[int]): Список ID серверов

    Returns:
        JSON с результатами развёртывания на каждом сервере

    ЯКОРЬ: БД обновляется ТОЛЬКО после успешной SSH операции!
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify({"success": False, "message": "Пустой JSON", "error_type": "empty_json"}),
                400,
            )

        key_id = data.get("key_id")
        server_ids = data.get("server_ids", [])

        # Валидация входных данных
        if not key_id or not server_ids:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "key_id и server_ids обязательны",
                        "error_type": "missing_parameters",
                    }
                ),
                400,
            )

        # Проверка ключа
        key = SSHKey.query.get(key_id)
        if not key:
            return (
                jsonify(
                    {"success": False, "message": "Ключ не найден", "error_type": "key_not_found"}
                ),
                404,
            )

        # Проверка доступа к ключу
        if key.user_id != current_user.id:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "У вас нет доступа к этому ключу",
                        "error_type": "access_denied",
                    }
                ),
                403,
            )

        logger.info(
            f"[DEPLOY_KEY_START] Развёртывание ключа {key.name} на {len(server_ids)} серверов"
        )

        results = []
        success_count = 0
        failed_count = 0

        for server_id in server_ids:
            try:
                server_id = int(server_id)
                server = Server.query.get(server_id)

                if not server:
                    results.append(
                        {
                            "server_id": server_id,
                            "success": False,
                            "error": "Сервер не найден",
                            "error_type": "server_not_found",
                        }
                    )
                    failed_count += 1
                    continue

                # Проверка доступа к серверу
                if server.user_id != current_user.id:
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": "У вас нет доступа к этому серверу",
                            "error_type": "access_denied",
                        }
                    )
                    failed_count += 1
                    continue

                # Проверка на существующее развёртывание
                existing_deployment = KeyDeployment.query.filter_by(
                    ssh_key_id=key_id, server_id=server_id, revoked_at=None
                ).first()

                if existing_deployment:
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": "Ключ уже развёрнут на этом сервере",
                            "error_type": "already_deployed",
                        }
                    )
                    failed_count += 1
                    continue

                # Проверка access_key сервера
                if not server.access_key:
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": "Для этого сервера не настроен ключ доступа",
                            "error_type": "missing_access_key",
                        }
                    )
                    failed_count += 1
                    continue

                # Расшифровка access_key
                decrypt_result = decrypt_access_key(server.access_key)
                if not decrypt_result["success"]:
                    logger.error(
                        f"[DEPLOY_KEY_DECRYPT_FAILED] {server.name}: {decrypt_result['message']}"
                    )
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": f'Ошибка расшифровки: {decrypt_result["message"]}',
                            "error_type": "decryption_error",
                        }
                    )
                    failed_count += 1
                    continue

                # КРИТИЧНАЯ SSH ОПЕРАЦИЯ
                logger.info(f"[DEPLOY_KEY_SSH] Развёртывание на {server.name}")
                deploy_result = deploy_key_to_server(server, decrypt_result["private_key"], key)

                if deploy_result["success"]:
                    # ✅ ТОЛЬКО ПОСЛЕ УСПЕХА → ОБНОВИТЬ БД
                    try:
                        deployment = KeyDeployment(
                            ssh_key_id=key_id,
                            server_id=server_id,
                            deployed_by=current_user.id,
                            deployed_at=datetime.now(timezone.utc),
                        )
                        db.session.add(deployment)
                        db.session.commit()

                        logger.info(f"[DEPLOY_KEY_SUCCESS] Ключ развёрнут на {server.name}")
                        results.append(
                            {
                                "server_id": server_id,
                                "server_name": server.name,
                                "success": True,
                                "message": f"Ключ успешно развёрнут на {server.name}",
                            }
                        )
                        success_count += 1

                    except Exception as db_error:
                        db.session.rollback()
                        logger.error(f"[DEPLOY_KEY_DB_ERROR] {str(db_error)}")
                        results.append(
                            {
                                "server_id": server_id,
                                "server_name": server.name,
                                "success": False,
                                "error": f"SSH успешно, но ошибка БД: {str(db_error)}",
                                "error_type": "database_error",
                            }
                        )
                        failed_count += 1
                else:
                    logger.warning(f"[DEPLOY_KEY_FAILED] {server.name}: {deploy_result['message']}")
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": deploy_result["message"],
                            "error_type": deploy_result.get("error_type", "deploy_failed"),
                        }
                    )
                    failed_count += 1

            except ValueError:
                results.append(
                    {
                        "server_id": server_id,
                        "success": False,
                        "error": "Неверный ID сервера",
                        "error_type": "invalid_server_id",
                    }
                )
                failed_count += 1

            except Exception as e:
                logger.error(f"[DEPLOY_KEY_EXCEPTION] Сервер {server_id}: {str(e)}")
                results.append(
                    {
                        "server_id": server_id,
                        "success": False,
                        "error": str(e),
                        "error_type": "exception",
                    }
                )
                failed_count += 1

        # Логирование операции
        add_log(
            "deploy_key",
            target=key.name,
            details={"servers": len(server_ids), "success": success_count, "failed": failed_count},
        )

        logger.info(f"[DEPLOY_KEY_COMPLETE] Успешно: {success_count}, Ошибок: {failed_count}")

        return (
            jsonify(
                {
                    "success": True,
                    "message": (
                        f"Развёртывание завершено: {success_count} успешно, "
                        f"{failed_count} ошибок"
                    ),
                    "success_count": success_count,
                    "failed_count": failed_count,
                    "results": results,
                }
            ),
            200,
        )

    except Exception as critical_error:
        logger.error(f"[DEPLOY_KEY_CRITICAL] {str(critical_error)}")
        add_log("deploy_key_critical", details={"error": str(critical_error)})
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"КРИТИЧЕСКАЯ ОШИБКА: {str(critical_error)}",
                    "error_type": "critical",
                }
            ),
            500,
        )
