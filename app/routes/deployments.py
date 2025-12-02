"""
Deployments Routes - КРИТИЧНЫЙ ФАЙЛ

Маршруты для отзыва SSH ключей с ПОЛНОЙ обработкой ошибок.
ЯКОРЬ #1: БД обновляется ТОЛЬКО после успешной SSH операции!
"""

import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, flash, jsonify, render_template, request
from flask_login import current_user, login_required

from app.models import KeyDeployment, Server, SSHKey
from app.services import deployment_service

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
            result = deployment_service.revoke_deployment_by_id(current_user.id, deployment_id)

            # Определяем HTTP статус код
            if not result["success"]:
                error_type = result.get("error_type", "error")
                if error_type == "not_found":
                    status_code = 404
                elif error_type == "access_denied":
                    status_code = 403
                elif error_type == "already_revoked":
                    status_code = 400
                else:
                    status_code = 500
            else:
                status_code = 200

            # Добавляем server_info если есть server в результате
            if "server" in result and result["success"]:
                response = {
                    "success": True,
                    "message": "✅ Ключ успешно отозван с VPS",
                    "server": result["server"],
                    "ip": result.get("ip", ""),
                }
            else:
                response = result

            return jsonify(response), status_code

        # ========== SCENARIO 1: Отзыв со всех серверов ==========
        elif key_id and not server_id:
            logger.info(f"[REVOKE_START] Scenario 1: key_id={key_id} (bulk revoke)")
            result = deployment_service.revoke_key_globally(current_user.id, key_id)

            if not result["success"]:
                error_type = result.get("error_type", "error")
                status_code = (
                    404
                    if error_type == "not_found"
                    else 403 if error_type == "access_denied" else 400
                )
            else:
                status_code = 200

            # Формируем ответ в формате, ожидаемом фронтэндом
            response = {
                "success": result["success"],
                "message": result["message"],
                "success_count": result.get("completed", 0),
                "failed_count": result.get("failed", 0),
                "results": result.get("results", []),
            }

            return jsonify(response), status_code

        # ========== SCENARIO 2: Отзыв с одного сервера ==========
        elif key_id and server_id:
            logger.info(f"[REVOKE_START] Scenario 2: key_id={key_id}, server_id={server_id}")
            result = deployment_service.revoke_key_from_server_by_ids(
                current_user.id, key_id, server_id
            )

            if not result["success"]:
                error_type = result.get("error_type", "error")
                if error_type in ["not_found", "deployment_not_found"]:
                    status_code = 404
                elif error_type == "access_denied":
                    status_code = 403
                else:
                    status_code = 500
            else:
                status_code = 200

            # Формируем ответ для успешного случая
            if result["success"] and "server" in result:
                response = {
                    "success": True,
                    "message": f"✅ Ключ отозван с {result['server']}",
                }
            else:
                response = result

            return jsonify(response), status_code

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
            'revoked': List[Dict],  # Успешно отозванные
            'skipped': List[Dict],  # Пропущенные (ключ не найден)
            'failed': List[Dict],   # Ошибки отзыва
            'total': int,
            'message': str
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

        # Получаем список deployments для маппинга server_name -> server
        deployments = KeyDeployment.query.filter_by(ssh_key_id=ssh_key_id, revoked_at=None).all()

        # Вызов сервиса
        result = deployment_service.revoke_key_globally(current_user.id, ssh_key_id)

        # Определяем HTTP статус
        if not result["success"]:
            error_type = result.get("error_type", "error")
            if error_type == "not_found":
                status_code = 404
            elif error_type == "access_denied":
                status_code = 403
            else:
                status_code = 400
        else:
            status_code = 200

        # Разделяем результаты на категории для детального отображения в UI
        revoked = []
        skipped = []
        failed = []

        # Получаем mapping server_name -> server для доступа к server_id и ip_address
        server_map = {}
        for deployment in deployments:
            server = Server.query.get(deployment.server_id)
            if server:
                server_map[server.name] = server

        # Классифицируем результаты
        for r in result.get("results", []):
            server_name = r["server_name"]
            server_obj = server_map.get(server_name)

            # Базовая информация о сервере
            server_info = {
                "server_id": server_obj.id if server_obj else None,
                "server_name": server_name,
                "server_ip": server_obj.ip_address if server_obj else r.get("server_ip", "unknown"),
            }

            if r["success"]:
                # Успешно отозван
                revoked.append(server_info)
            else:
                # Проверяем причину неудачи
                message = r["message"].lower()
                # Если ключ не найден/отсутствует - это "пропущено"
                if "не найден" in message or "отсутствует" in message or "not found" in message:
                    skipped.append({**server_info, "reason": r["message"]})
                else:
                    # Все остальные ошибки - это "failed"
                    failed.append({**server_info, "error": r["message"]})

        # Формируем сообщение
        parts = []
        if revoked:
            parts.append(f"Отозвано: {len(revoked)}")
        if skipped:
            parts.append(f"Пропущено: {len(skipped)}")
        if failed:
            parts.append(f"Ошибок: {len(failed)}")

        message = ", ".join(parts) if parts else "Нет результатов"

        response = {
            "success": result["success"],
            "revoked": revoked,
            "skipped": skipped,
            "failed": failed,
            "total": result.get("total", 0),
            "message": message,
        }

        # Отладка: логируем финальный ответ
        logger.info(
            f"[REVOKE_RESPONSE] revoked={len(revoked)}, skipped={len(skipped)}, "
            f"failed={len(failed)}, total={result.get('total', 0)}"
        )
        logger.debug(f"[REVOKE_RESPONSE] Full response: {response}")

        return jsonify(response), status_code

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

        logger.info(f"[DEPLOY_KEY_START] key_id={key_id}, servers={len(server_ids)}")

        # Вызов сервиса
        result = deployment_service.deploy_key_to_servers(current_user.id, key_id, server_ids)

        logger.info(
            f"[DEPLOY_KEY_COMPLETE] Success: {result.get('success_count', 0)}, "
            f"Failed: {result.get('failed_count', 0)}"
        )

        return jsonify(result), 200

    except Exception as critical_error:
        logger.error(f"[DEPLOY_KEY_CRITICAL] {str(critical_error)}")
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
