"""
/api/svc — тонкий service-контракт для pass-manager (Track C, срез A2).

Аутентификация: только Bearer SERVICE_ACCOUNT_TOKEN через
login_manager.request_loader (см. app/__init__.py). current_user на этих
маршрутах — единственный User "pass-manager-svc"; все нижеиспользуемые
функции (_provision_server_with_verified_key_auth, deployment_service,
decrypt_access_key, ...) переиспользуются как есть, без owner-рефактора.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from app import db
from app.models import KeyDeployment, Server, SSHKey
from app.routes import servers as servers_routes
from app.services import deployment_service
from app.services.key_service import decrypt_access_key
from app.services.ssh import keys as ssh_keys
from app.services.ssh.server_manager import test_connection

bp = Blueprint("api_svc", __name__)
logger = logging.getLogger(__name__)


@bp.before_request
def require_service_account() -> None:
    # request_loader (app/__init__.py) отдаёт pass-manager-svc только по валидному
    # Bearer-токену. Без токена Flask-Login откатывается на session-пользователя —
    # эта проверка не пускает залогиненного в браузере человека на /api/svc.
    if not (current_user.is_authenticated and current_user.username == "pass-manager-svc"):
        abort(401)


def _server_to_dict(server: Server) -> Dict[str, Any]:
    return {
        "id": server.id,
        "name": server.name,
        "ip_address": server.ip_address,
        "ssh_port": server.ssh_port,
        "status": server.status,
        "categories": [c.name for c in server.categories],
    }


def _key_to_dict(key: SSHKey) -> Dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "fingerprint": key.fingerprint,
        "description": key.description,
    }


# ---------------------------------------------------------------------------
# E1 — bootstrap сервера (идемпотентно по bootstrap_request_id)
# ---------------------------------------------------------------------------
@bp.route("/servers/add", methods=["POST"])
@login_required
def add_server() -> Tuple[Dict[str, Any], int]:
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Данные не предоставлены"}), 400

    required_fields = ["name", "ip_address", "ssh_port", "username", "password", "bootstrap_request_id"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "message": f"Поле '{field}' обязательно"}), 400

    bootstrap_request_id = data["bootstrap_request_id"]

    # Идемпотентность: тот же bootstrap_request_id — вернуть уже созданный сервер.
    existing = Server.query.filter_by(bootstrap_request_id=bootstrap_request_id).first()
    if existing:
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Сервер уже был создан по этому bootstrap_request_id",
                    "server_id": existing.id,
                    "server_name": existing.name,
                }
            ),
            200,
        )

    result = servers_routes._provision_server_with_verified_key_auth(
        name=data["name"],
        ip_address=data["ip_address"],
        port=data["ssh_port"],
        username=data["username"],
        password=data["password"],
        category_ids=data.get("category_ids", []),
    )

    if result["success"]:
        server = Server.query.get(result["server_id"])
        server.bootstrap_request_id = bootstrap_request_id
        db.session.commit()

    return (
        jsonify(
            {
                "success": result["success"],
                "message": result["message"],
                "server_id": result.get("server_id"),
                "server_name": result.get("server_name"),
            }
        ),
        result["status_code"],
    )


# ---------------------------------------------------------------------------
# E2 — список ключей svc-аккаунта
# ---------------------------------------------------------------------------
@bp.route("/keys", methods=["GET"])
@login_required
def list_keys() -> Tuple[Dict[str, Any], int]:
    query = SSHKey.query
    name_fragment = request.args.get("name")
    if name_fragment:
        query = query.filter(SSHKey.name.ilike(f"%{name_fragment}%"))

    keys = query.all()
    return jsonify({"success": True, "keys": [_key_to_dict(k) for k in keys]}), 200


# ---------------------------------------------------------------------------
# E3 — генерация нового ключа под svc-аккаунтом
# ---------------------------------------------------------------------------
@bp.route("/keys/generate", methods=["POST"])
@login_required
def generate_key() -> Tuple[Dict[str, Any], int]:
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Данные не предоставлены"}), 400

    name = data.get("name")
    key_type = data.get("key_type")
    if not name or not key_type:
        return jsonify({"success": False, "message": "Поля 'name' и 'key_type' обязательны"}), 400

    try:
        private_key_pem, public_key_ssh = ssh_keys.generate_ssh_key(key_type)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    fingerprint = ssh_keys.get_fingerprint(public_key_ssh)
    if not fingerprint:
        return jsonify({"success": False, "message": "Не удалось вычислить fingerprint ключа."}), 500

    # Dedup по fingerprint (как в keys.py:106) — не плодим дубликаты.
    # Фильтр по владельцу не ставим: fingerprint уникален на всю таблицу (app/models.py:121),
    # иначе дедуп не увидит чужой ключ с тем же отпечатком и INSERT упадёт на уникальном индексе.
    existing_key = SSHKey.query.filter_by(fingerprint=fingerprint).first()
    if existing_key:
        return jsonify({"success": True, "message": "Ключ с таким fingerprint уже существует", **_key_to_dict(existing_key)}), 200

    encryption_key = os.environ.get("ENCRYPTION_KEY")
    if not encryption_key:
        return jsonify({"success": False, "message": "ENCRYPTION_KEY не установлен на сервере"}), 500

    encrypted_private_key = ssh_keys.encrypt_private_key(private_key_pem, encryption_key)
    new_key = SSHKey(
        name=name,
        public_key=public_key_ssh,
        private_key_encrypted=encrypted_private_key,
        fingerprint=fingerprint,
        key_type=key_type,
        description=data.get("description"),
        user_id=current_user.id,
    )
    db.session.add(new_key)
    db.session.commit()

    return jsonify({"success": True, "message": "Ключ создан", **_key_to_dict(new_key)}), 200


# ---------------------------------------------------------------------------
# E4 — deploy ключа на сервер (идемпотентно по активному KeyDeployment)
# ---------------------------------------------------------------------------
@bp.route("/keys/deploy", methods=["POST"])
@login_required
def deploy_key() -> Tuple[Dict[str, Any], int]:
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Данные не предоставлены"}), 400

    key_id = data.get("key_id")
    server_id = data.get("server_id")
    if not key_id or not server_id:
        return jsonify({"success": False, "message": "key_id и server_id обязательны"}), 400

    existing_deployment = KeyDeployment.query.filter_by(
        ssh_key_id=key_id, server_id=server_id, revoked_at=None
    ).first()
    if existing_deployment:
        return jsonify({"success": True, "message": "Ключ уже развёрнут на этом сервере"}), 200

    result = deployment_service.deploy_key_to_servers(
        user_id=current_user.id, key_id=key_id, server_ids=[server_id], bypass_owner=True
    )

    if not result["success"] or result.get("success_count", 0) == 0:
        error_details = result.get("results", [{}])[0] if result.get("results") else {}
        return (
            jsonify(
                {
                    "success": False,
                    "message": error_details.get("error", result.get("message")),
                    "error_type": error_details.get("error_type", result.get("error_type")),
                }
            ),
            400,
        )

    return jsonify({"success": True, "message": result["message"]}), 200


# ---------------------------------------------------------------------------
# E5a — revoke ключа с конкретного сервера
# ---------------------------------------------------------------------------
@bp.route("/key-deployments/revoke", methods=["POST"])
@login_required
def revoke_deployment() -> Tuple[Dict[str, Any], int]:
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Данные не предоставлены"}), 400

    key_id = data.get("key_id")
    server_id = data.get("server_id")
    if not key_id or not server_id:
        return jsonify({"success": False, "message": "key_id и server_id обязательны"}), 400

    result = deployment_service.revoke_key_from_server_by_ids(
        user_id=current_user.id, key_id=key_id, server_id=server_id, bypass_owner=True
    )

    return jsonify(result), (200 if result["success"] else 400)


# ---------------------------------------------------------------------------
# E5b — revoke ключа со всех серверов
# ---------------------------------------------------------------------------
@bp.route("/keys/revoke-all/<int:key_id>", methods=["POST"])
@login_required
def revoke_key_all(key_id: int) -> Tuple[Dict[str, Any], int]:
    result = deployment_service.revoke_key_globally(
        user_id=current_user.id, key_id=key_id, bypass_owner=True
    )
    return jsonify(result), (200 if result["success"] else 400)


# ---------------------------------------------------------------------------
# E6 — список серверов svc-аккаунта
# ---------------------------------------------------------------------------
@bp.route("/servers", methods=["GET"])
@login_required
def list_servers() -> Tuple[Dict[str, Any], int]:
    query = Server.query
    name_fragment = request.args.get("name")
    if name_fragment:
        query = query.filter(Server.name.ilike(f"%{name_fragment}%"))

    servers = query.all()
    return jsonify({"success": True, "servers": [_server_to_dict(s) for s in servers]}), 200


# ---------------------------------------------------------------------------
# E7 — тест SSH-соединения
# ---------------------------------------------------------------------------
@bp.route("/servers/test/<int:server_id>", methods=["POST"])
@login_required
def test_server(server_id: int) -> Tuple[Dict[str, Any], int]:
    server = Server.query.get(server_id)
    if not server:
        return jsonify({"success": False, "message": "Сервер не найден"}), 404

    if not server.access_key:
        return jsonify({"success": False, "message": "Для этого сервера не настроен ключ доступа"}), 400

    test_result = test_connection(server)
    server.status = "online" if test_result["success"] else "offline"
    server.last_check = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({"success": test_result["success"], "message": test_result["message"], "status": server.status}), 200


# ---------------------------------------------------------------------------
# E8 — приватный per-server root-ключ (только под токеном!)
# ---------------------------------------------------------------------------
@bp.route("/servers/<int:server_id>/access-key", methods=["GET"])
@login_required
def get_access_key(server_id: int) -> Tuple[Dict[str, Any], int]:
    server = Server.query.get(server_id)
    if not server:
        return jsonify({"success": False, "message": "Сервер не найден"}), 404

    if not server.access_key:
        return jsonify({"success": False, "message": "Для этого сервера не настроен ключ доступа"}), 400

    decrypt_result = decrypt_access_key(server.access_key)
    if not decrypt_result["success"]:
        return jsonify({"success": False, "message": decrypt_result["message"]}), 500

    return jsonify({"success": True, "private_key": decrypt_result["private_key"]}), 200


# ---------------------------------------------------------------------------
# E9 — активные раскатки ключей (для импорта парка в pass-manager)
# ---------------------------------------------------------------------------
@bp.route("/key-deployments", methods=["GET"])
@login_required
def list_key_deployments() -> Tuple[Dict[str, Any], int]:
    deployments = KeyDeployment.query.filter_by(revoked_at=None).all()
    return (
        jsonify(
            {
                "success": True,
                "deployments": [
                    {
                        "key_id": d.ssh_key_id,
                        "server_id": d.server_id,
                        "deployed_at": d.deployed_at.isoformat() if d.deployed_at else None,
                    }
                    for d in deployments
                ],
            }
        ),
        200,
    )
