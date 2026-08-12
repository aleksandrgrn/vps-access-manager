"""
Тесты для /api/svc — блюпринт-контракт Track C A2 (token-auth, request_loader,
идемпотентность E1/E4, CSRF-exempt).

Паттерн фикстур — как в tests/test_single_revoke.py (function-scoped app/client,
db.create_all() на in-memory sqlite). Каждая auth-чувствительная сценарий-функция
делает ровно один HTTP-вызов на current_user-состояние — Flask переиспользует уже
открытый app_context внутри одного `with app.app_context():"-блока для всех запросов
одного теста (Flask-Login кеширует current_user в `g` при первом обращении за
контекст), поэтому НЕЛЬЗЯ смешивать в одном тесте два запроса с разным ожидаемым
auth-результатом — только с одинаковым (напр. два запроса с одним и тем же валидным
токеном для проверки идемпотентности, что безопасно).
"""

from unittest.mock import patch

import pytest

from app import create_app, db
from app.models import KeyDeployment, Log, Server, ServerCategory, SSHKey, User

SERVICE_TOKEN = "test-service-token-abc123"


@pytest.fixture
def app():
    # ВАЖНО: create_app("testing") — не create_app() + переопределение конфига
    # постфактум. Flask-SQLAlchemy 3.x биндит engine на SQLALCHEMY_DATABASE_URI
    # ВНУТРИ db.init_app() (вызывается внутри create_app()); правки app.config
    # после возврата create_app() на реальный engine уже не влияют. "testing"
    # выставляет :memory: ДО init_app — единственный безопасный способ не задеть
    # реальный dev-файл instance/vps_manager.db.
    flask_app = create_app("testing")
    flask_app.config["SERVICE_ACCOUNT_TOKEN"] = SERVICE_TOKEN

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def svc_user(app):
    user = User(username="pass-manager-svc")
    user.set_password("unused-random-password")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def other_user(app):
    user = User(username="someone-else")
    user.set_password("password")
    db.session.add(user)
    db.session.commit()
    return user


def auth_headers(token=SERVICE_TOKEN):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Auth / request_loader
# ---------------------------------------------------------------------------


def test_no_token_returns_401(client, svc_user):
    response = client.get("/api/svc/servers")
    assert response.status_code == 401


def test_wrong_token_returns_401(client, svc_user):
    response = client.get("/api/svc/servers", headers=auth_headers("wrong-token"))
    assert response.status_code == 401


def test_valid_token_authenticates_as_svc_user(client, svc_user):
    response = client.get("/api/svc/servers", headers=auth_headers())
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_valid_token_does_not_authenticate_on_session_route(client, svc_user):
    # Тот же Bearer-токен на существующем session-маршруте не должен пускать как svc:
    # path-check в request_loader ограничивает его строго /api/svc.
    # Без активной сессии login_required редиректит на /login (302), а не 200.
    response = client.get("/api/dashboard", headers=auth_headers())
    assert response.status_code == 302


def test_session_human_without_token_denied(client, other_user):
    # Дыра, которую закрывает before_request-гард: без Bearer-токена Flask-Login
    # берёт пользователя из сессии (user_loader), request_loader не вызывается.
    # Залогиненный человек НЕ должен попадать на /api/svc как он сам.
    with client.session_transaction() as sess:
        sess["_user_id"] = str(other_user.id)
    response = client.get("/api/svc/servers")  # сессия есть, токена нет
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# E1 — bootstrap идемпотентность по bootstrap_request_id
# ---------------------------------------------------------------------------


def test_e1_bootstrap_idempotent_by_request_id(client, svc_user):
    payload = {
        "name": "svc-server",
        "ip_address": "192.0.2.10",
        "ssh_port": 22,
        "username": "root",
        "password": "secret",
        "bootstrap_request_id": "req-uuid-1",
    }

    with patch("app.routes.servers.initialize_server") as mock_init, patch(
        "app.routes.servers.ssh_keys.generate_ssh_key"
    ) as mock_gen, patch("app.routes.servers.ssh_keys.get_fingerprint") as mock_fp, patch(
        "app.routes.servers.ssh_keys.encrypt_private_key"
    ) as mock_enc, patch(
        "app.routes.servers.ssh_bootstrap.bootstrap_server_access"
    ) as mock_bootstrap:
        mock_init.return_value = {
            "success": True,
            "openssh_version": "9.6",
            "requires_legacy_ssh": False,
            "message": "ok",
        }
        mock_gen.return_value = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcRouteKeyData svc@example.com",
        )
        mock_fp.return_value = "aa:bb:cc:dd"
        mock_enc.return_value = b"encrypted"
        mock_bootstrap.return_value = {
            "success": True,
            "verified": True,
            "remediated": False,
            "target_username": "root",
            "message": "ok",
        }

        r1 = client.post("/api/svc/servers/add", json=payload, headers=auth_headers())
        r2 = client.post("/api/svc/servers/add", json=payload, headers=auth_headers())

    assert r1.status_code == 200
    assert r1.get_json()["success"] is True
    assert r2.status_code == 200
    assert r2.get_json()["success"] is True
    assert r2.get_json()["server_id"] == r1.get_json()["server_id"]

    assert Server.query.count() == 1
    assert mock_bootstrap.call_count == 1  # второй запрос НЕ дошёл до bootstrap
    assert Server.query.first().bootstrap_request_id == "req-uuid-1"


# ---------------------------------------------------------------------------
# E2 — список ключей
# ---------------------------------------------------------------------------


def test_e2_list_keys_filtered_by_name(client, svc_user):
    key_a = SSHKey(
        name="alpha-key",
        public_key="ssh-ed25519 AAAA... a",
        private_key_encrypted=b"x",
        fingerprint="fp-a",
        key_type="ed25519",
        user_id=svc_user.id,
    )
    key_b = SSHKey(
        name="beta-key",
        public_key="ssh-ed25519 AAAA... b",
        private_key_encrypted=b"y",
        fingerprint="fp-b",
        key_type="ed25519",
        user_id=svc_user.id,
    )
    db.session.add_all([key_a, key_b])
    db.session.commit()

    response = client.get("/api/svc/keys?name=alpha", headers=auth_headers())
    assert response.status_code == 200
    keys = response.get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["name"] == "alpha-key"


# ---------------------------------------------------------------------------
# E3 — генерация ключа + dedup по fingerprint
# ---------------------------------------------------------------------------


def test_e3_generate_key_creates_key_for_svc_user(client, svc_user):
    with patch("app.routes.api_svc.ssh_keys.generate_ssh_key") as mock_gen, patch(
        "app.routes.api_svc.ssh_keys.get_fingerprint"
    ) as mock_fp, patch("app.routes.api_svc.ssh_keys.encrypt_private_key") as mock_enc:
        mock_gen.return_value = ("pem-private", "ssh-rsa AAAA...")
        mock_fp.return_value = "fp-new"
        mock_enc.return_value = b"encrypted-blob"

        response = client.post(
            "/api/svc/keys/generate",
            json={"name": "Ivanov", "key_type": "rsa", "description": "for Ivanov"},
            headers=auth_headers(),
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True

    key = SSHKey.query.filter_by(fingerprint="fp-new").first()
    assert key is not None
    assert key.user_id == svc_user.id
    assert key.name == "Ivanov"


def test_e3_generate_key_dedup_by_fingerprint(client, svc_user):
    existing = SSHKey(
        name="existing-key",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"blob",
        fingerprint="fp-dup",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add(existing)
    db.session.commit()

    with patch("app.routes.api_svc.ssh_keys.generate_ssh_key") as mock_gen, patch(
        "app.routes.api_svc.ssh_keys.get_fingerprint"
    ) as mock_fp:
        mock_gen.return_value = ("pem-private", "ssh-rsa AAAA...")
        mock_fp.return_value = "fp-dup"

        response = client.post(
            "/api/svc/keys/generate",
            json={"name": "Petrov", "key_type": "rsa"},
            headers=auth_headers(),
        )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert SSHKey.query.count() == 1  # дубликат не создан


# ---------------------------------------------------------------------------
# E4 — deploy ключа + идемпотентность
# ---------------------------------------------------------------------------


def test_e4_deploy_key_calls_deployment_service(client, svc_user):
    server = Server(
        name="srv", ip_address="192.0.2.20", username="root", user_id=svc_user.id, ssh_port=22
    )
    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"x",
        fingerprint="fp1",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add_all([server, key])
    db.session.commit()

    with patch("app.routes.api_svc.deployment_service.deploy_key_to_servers") as mock_deploy:
        mock_deploy.return_value = {
            "success": True,
            "message": "Deployment complete: 1 success, 0 failed",
            "success_count": 1,
            "failed_count": 0,
            "results": [],
        }

        response = client.post(
            "/api/svc/keys/deploy",
            json={"key_id": key.id, "server_id": server.id},
            headers=auth_headers(),
        )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    mock_deploy.assert_called_once_with(
        user_id=svc_user.id, key_id=key.id, server_ids=[server.id], bypass_owner=True
    )


def test_e4_deploy_key_idempotent_when_already_deployed(client, svc_user):
    server = Server(
        name="srv", ip_address="192.0.2.21", username="root", user_id=svc_user.id, ssh_port=22
    )
    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"x",
        fingerprint="fp2",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add_all([server, key])
    db.session.flush()
    deployment = KeyDeployment(ssh_key_id=key.id, server_id=server.id, deployed_by=svc_user.id)
    db.session.add(deployment)
    db.session.commit()

    with patch("app.routes.api_svc.deployment_service.deploy_key_to_servers") as mock_deploy:
        response = client.post(
            "/api/svc/keys/deploy",
            json={"key_id": key.id, "server_id": server.id},
            headers=auth_headers(),
        )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    mock_deploy.assert_not_called()  # идемпотентно — уже развёрнут, SSH не дёргаем повторно


# ---------------------------------------------------------------------------
# E5a / E5b — revoke
# ---------------------------------------------------------------------------


def test_e5a_revoke_deployment_by_ids(client, svc_user):
    with patch(
        "app.routes.api_svc.deployment_service.revoke_key_from_server_by_ids"
    ) as mock_revoke:
        mock_revoke.return_value = {"success": True, "message": "revoked", "server": "srv"}

        response = client.post(
            "/api/svc/key-deployments/revoke",
            json={"key_id": 1, "server_id": 2},
            headers=auth_headers(),
        )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    mock_revoke.assert_called_once_with(
        user_id=svc_user.id, key_id=1, server_id=2, bypass_owner=True
    )


def test_e5b_revoke_key_globally(client, svc_user):
    with patch("app.routes.api_svc.deployment_service.revoke_key_globally") as mock_revoke:
        mock_revoke.return_value = {"success": True, "message": "revoked all", "completed": 2}

        response = client.post("/api/svc/keys/revoke-all/5", headers=auth_headers())

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    mock_revoke.assert_called_once_with(user_id=svc_user.id, key_id=5, bypass_owner=True)


# ---------------------------------------------------------------------------
# E6 — список серверов
# ---------------------------------------------------------------------------


def test_e6_list_servers_filtered_by_name(client, svc_user):
    server_a = Server(
        name="alpha-srv", ip_address="192.0.2.30", username="root", user_id=svc_user.id, ssh_port=22
    )
    server_b = Server(
        name="beta-srv", ip_address="192.0.2.31", username="root", user_id=svc_user.id, ssh_port=22
    )
    db.session.add_all([server_a, server_b])
    db.session.commit()

    response = client.get("/api/svc/servers?name=alpha", headers=auth_headers())
    assert response.status_code == 200
    servers = response.get_json()["servers"]
    assert len(servers) == 1
    assert servers[0]["name"] == "alpha-srv"


# ---------------------------------------------------------------------------
# E7 — test connection
# ---------------------------------------------------------------------------


def test_e7_test_server_updates_status(client, svc_user):
    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"x",
        fingerprint="fp3",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add(key)
    db.session.flush()
    server = Server(
        name="srv",
        ip_address="192.0.2.40",
        username="root",
        user_id=svc_user.id,
        ssh_port=22,
        access_key_id=key.id,
    )
    db.session.add(server)
    db.session.commit()

    with patch("app.routes.api_svc.test_connection") as mock_test:
        mock_test.return_value = {"success": True, "message": "ok"}
        response = client.post(f"/api/svc/servers/test/{server.id}", headers=auth_headers())

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert Server.query.get(server.id).status == "online"


# ---------------------------------------------------------------------------
# E8 — приватный access-key (только под токеном + ownership)
# ---------------------------------------------------------------------------


def test_e8_get_access_key_returns_decrypted_private_key(client, svc_user):
    from app.services.ssh import keys as ssh_keys_service

    encryption_key = __import__("os").environ["ENCRYPTION_KEY"]
    plaintext_pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    encrypted = ssh_keys_service.encrypt_private_key(plaintext_pem, encryption_key)

    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=encrypted,
        fingerprint="fp4",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add(key)
    db.session.flush()
    server = Server(
        name="srv",
        ip_address="192.0.2.50",
        username="root",
        user_id=svc_user.id,
        ssh_port=22,
        access_key_id=key.id,
    )
    db.session.add(server)
    db.session.commit()

    response = client.get(f"/api/svc/servers/{server.id}/access-key", headers=auth_headers())

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["private_key"] == plaintext_pem


def test_e8_get_access_key_foreign_server_allowed(client, svc_user, other_user):
    """
    B0.1: фильтр владельца в /api/svc снят. Сервер другого пользователя
    теперь обрабатывается служебной учёткой (а не отклоняется с 404).
    """
    from app.services.ssh import keys as ssh_keys_service

    encryption_key = __import__("os").environ["ENCRYPTION_KEY"]
    plaintext_pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    encrypted = ssh_keys_service.encrypt_private_key(plaintext_pem, encryption_key)

    key = SSHKey(
        name="foreign-key",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=encrypted,
        fingerprint="fp-foreign",
        key_type="rsa",
        user_id=other_user.id,
    )
    db.session.add(key)
    db.session.flush()
    server = Server(
        name="not-mine",
        ip_address="192.0.2.60",
        username="root",
        user_id=other_user.id,
        ssh_port=22,
        access_key_id=key.id,
    )
    db.session.add(server)
    db.session.commit()

    response = client.get(f"/api/svc/servers/{server.id}/access-key", headers=auth_headers())
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["private_key"] == plaintext_pem


# ---------------------------------------------------------------------------
# E6 — категории в списке серверов (FIX B0.2)
# ---------------------------------------------------------------------------


def test_e6_server_with_categories_returns_names(client, svc_user):
    server = Server(
        name="cat-srv", ip_address="192.0.2.70", username="root", user_id=svc_user.id, ssh_port=22
    )
    prod = ServerCategory(name="prod")
    dev = ServerCategory(name="dev")
    db.session.add_all([server, prod, dev])
    server.categories.append(prod)
    server.categories.append(dev)
    db.session.commit()

    response = client.get("/api/svc/servers", headers=auth_headers())
    assert response.status_code == 200
    servers = response.get_json()["servers"]
    assert len(servers) == 1
    assert sorted(servers[0]["categories"]) == ["dev", "prod"]


def test_e6_server_without_categories_returns_empty_list(client, svc_user):
    server = Server(
        name="no-cat-srv",
        ip_address="192.0.2.71",
        username="root",
        user_id=svc_user.id,
        ssh_port=22,
    )
    db.session.add(server)
    db.session.commit()

    response = client.get("/api/svc/servers", headers=auth_headers())
    assert response.status_code == 200
    servers = response.get_json()["servers"]
    assert len(servers) == 1
    assert "categories" in servers[0]
    assert servers[0]["categories"] == []


# ---------------------------------------------------------------------------
# E9 — активные раскатки ключей (FIX B0.2)
# ---------------------------------------------------------------------------


def test_e9_returns_active_deployment(client, svc_user):
    server = Server(
        name="srv", ip_address="192.0.2.80", username="root", user_id=svc_user.id, ssh_port=22
    )
    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"x",
        fingerprint="fp-e9-active",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add_all([server, key])
    db.session.flush()
    deployment = KeyDeployment(ssh_key_id=key.id, server_id=server.id, deployed_by=svc_user.id)
    db.session.add(deployment)
    db.session.commit()

    response = client.get("/api/svc/key-deployments", headers=auth_headers())
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    deployments = data["deployments"]
    assert len(deployments) == 1
    assert deployments[0]["key_id"] == key.id
    assert deployments[0]["server_id"] == server.id
    assert deployments[0]["deployed_at"]


def test_e9_excludes_revoked_deployment(client, svc_user):
    from datetime import datetime, timezone

    server = Server(
        name="srv", ip_address="192.0.2.81", username="root", user_id=svc_user.id, ssh_port=22
    )
    key = SSHKey(
        name="k",
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=b"x",
        fingerprint="fp-e9-revoked",
        key_type="rsa",
        user_id=svc_user.id,
    )
    db.session.add_all([server, key])
    db.session.flush()
    revoked = KeyDeployment(
        ssh_key_id=key.id,
        server_id=server.id,
        deployed_by=svc_user.id,
        revoked_at=datetime.now(timezone.utc),
    )
    db.session.add(revoked)
    db.session.commit()

    response = client.get("/api/svc/key-deployments", headers=auth_headers())
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["deployments"] == []


def test_e9_without_token_returns_401(client, svc_user):
    response = client.get("/api/svc/key-deployments")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# CSRF-exempt: /api/svc/* принимает POST без CSRF-токена даже когда CSRF включён
# ---------------------------------------------------------------------------


def test_post_svc_bypasses_csrf_protection(monkeypatch):
    """Отдельный app с ВКЛЮЧЁННЫМ CSRF-протектом (в отличие от других тестов),
    чтобы доказать, что именно csrf.exempt на blueprint пропускает POST, а не то,
    что CSRF был выключен глобально.

    Нельзя использовать create_app("testing") — оно форсирует WTF_CSRF_ENABLED=False.
    Поэтому переключаем DATABASE_URL на :memory: через переменную окружения ДО
    create_app() (create_app читает os.environ прямо в SQLALCHEMY_DATABASE_URI,
    т.е. до db.init_app() — единственный безопасный момент для смены на :memory:,
    см. комментарий у фикстуры app() выше)."""
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    csrf_app = create_app()
    csrf_app.config["SERVICE_ACCOUNT_TOKEN"] = SERVICE_TOKEN
    # WTF_CSRF_ENABLED сознательно не выключаем — проверяем именно blueprint-exempt.

    with csrf_app.app_context():
        db.create_all()
        user = User(username="pass-manager-svc")
        user.set_password("x")
        db.session.add(user)
        db.session.commit()

        client = csrf_app.test_client()

        with patch("app.routes.api_svc.ssh_keys.generate_ssh_key") as mock_gen, patch(
            "app.routes.api_svc.ssh_keys.get_fingerprint"
        ) as mock_fp, patch("app.routes.api_svc.ssh_keys.encrypt_private_key") as mock_enc:
            mock_gen.return_value = ("pem", "ssh-rsa AAAA...")
            mock_fp.return_value = "fp-csrf"
            mock_enc.return_value = b"blob"

            response = client.post(
                "/api/svc/keys/generate",
                json={"name": "no-csrf-key", "key_type": "rsa"},
                headers=auth_headers(),
                # никакого X-CSRFToken заголовка и csrf cookie — намеренно
            )

        assert response.status_code == 200
        assert response.get_json()["success"] is True

        db.session.remove()
        db.drop_all()


# ---------------------------------------------------------------------------
# E10 — приватный ключ по key_id (только ключи svc-аккаунта)
# ---------------------------------------------------------------------------


def _make_svc_key(user, fingerprint, plaintext_pem=None, name="k"):
    """Создаёт SSHKey под заданным пользователем с зашифрованным приватным PEM."""
    from app.services.ssh import keys as ssh_keys_service

    encryption_key = __import__("os").environ["ENCRYPTION_KEY"]
    if plaintext_pem is None:
        plaintext_pem = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
    encrypted = ssh_keys_service.encrypt_private_key(plaintext_pem, encryption_key)
    key = SSHKey(
        name=name,
        public_key="ssh-rsa AAAA...",
        private_key_encrypted=encrypted,
        fingerprint=fingerprint,
        key_type="rsa",
        user_id=user.id,
    )
    db.session.add(key)
    db.session.commit()
    return key, plaintext_pem


def test_e10_get_private_key_returns_decrypted_private_key(client, svc_user):
    key, plaintext_pem = _make_svc_key(svc_user, fingerprint="fp-e10-own")

    response = client.get(f"/api/svc/keys/{key.id}/private", headers=auth_headers())

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["private_key"] == plaintext_pem


def test_e10_foreign_key_returns_404(client, svc_user, other_user):
    """Чужой ключ (владелец — другой пользователь) — 404, private_key ни в каком виде."""
    key, _ = _make_svc_key(other_user, fingerprint="fp-e10-foreign")

    response = client.get(f"/api/svc/keys/{key.id}/private", headers=auth_headers())

    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert "private_key" not in data


def test_e10_nonexistent_key_returns_404(client, svc_user):
    response = client.get("/api/svc/keys/999999/private", headers=auth_headers())

    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert "private_key" not in data


def test_e10_access_is_logged(client, svc_user):
    """Каждое обращение к E10 обязано попасть в журнал (add_log, с key_id)."""
    key, _ = _make_svc_key(svc_user, fingerprint="fp-e10-log")

    response = client.get(f"/api/svc/keys/{key.id}/private", headers=auth_headers())
    assert response.status_code == 200

    log_entry = Log.query.filter_by(action="svc_get_private_key", target=str(key.id)).first()
    assert log_entry is not None


# ---------------------------------------------------------------------------
# E11 — приватный ключ в формате PuTTY (.ppk) по key_id
# ---------------------------------------------------------------------------


def test_e11_get_private_key_ppk_converts_decrypted_private_key(client, svc_user):
    key, plaintext_pem = _make_svc_key(svc_user, fingerprint="fp-e11-own")

    with patch("app.routes.api_svc.ssh_keys.convert_private_key_to_ppk") as mock_convert:
        mock_convert.return_value = b"PuTTY-User-Key-File-3: ssh-rsa\n"

        response = client.get(f"/api/svc/keys/{key.id}/private.ppk", headers=auth_headers())

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["private_key_ppk"].startswith("PuTTY-User-Key-File")
    mock_convert.assert_called_once_with(plaintext_pem)


def test_e11_foreign_key_returns_404_without_conversion(client, svc_user, other_user):
    key, _ = _make_svc_key(other_user, fingerprint="fp-e11-foreign")

    with patch("app.routes.api_svc.ssh_keys.convert_private_key_to_ppk") as mock_convert:
        response = client.get(f"/api/svc/keys/{key.id}/private.ppk", headers=auth_headers())

    assert response.status_code == 404
    assert response.get_json()["success"] is False
    mock_convert.assert_not_called()


def test_e11_puttygen_unavailable_returns_500(client, svc_user):
    key, _ = _make_svc_key(svc_user, fingerprint="fp-e11-puttygen")
    error_message = "Утилита puttygen недоступна на сервере"

    with patch("app.routes.api_svc.ssh_keys.convert_private_key_to_ppk") as mock_convert:
        mock_convert.side_effect = RuntimeError(error_message)

        response = client.get(f"/api/svc/keys/{key.id}/private.ppk", headers=auth_headers())

    assert response.status_code == 500
    data = response.get_json()
    assert data["success"] is False
    assert error_message in data["message"]
