# Архитектура SSH-модуля

## 1. Общая структура

- **`app/services/ssh/connection.py`**: Низкоуровневый класс `SSHConnection` (paramiko wrapper).
- **`app/services/ssh/operations.py`**: Атомарные операции (`deploy_key`, `revoke_key`, `exec_command`).
- **`app/services/ssh/server_manager.py`**: Управление серверами (`init`, `test connection`).
- **`app/services/ssh/keys.py`**: Утилиты для ключей (`keygen`, `encrypt`).
- **`app/services/deployment_service.py`**: Бизнес-логика развертывания (БД + SSH).

## 2. Поток данных (Data Flow)

`Route` -> `Service` -> `Operations` -> `SSHConnection` -> `Server`

## 3. Примеры использования (кратко)

### Как развернуть ключ
Используется `app/services/deployment_service.py`.

### Как проверить сервер
Используется `app/services/ssh/server_manager.py`.

## 4. Служебный контракт `/api/svc` (Track C)

Тонкий blueprint для pass-manager — автоматизация онбординга серверов. Существующие
session-маршруты (`/api/*`) **не тронуты**; сервис-слой добавлен сбоку и переиспользует
ту же бизнес-логику (`_provision_server_with_verified_key_auth`, `deployment_service`,
`key_service.decrypt_access_key`).

### Аутентификация
- `login_manager.request_loader` (`app/__init__.py`) принимает **только**
  `Authorization: Bearer <SERVICE_ACCOUNT_TOKEN>` и **только** для путей `/api/svc/*`
  (path-check). При совпадении токена (`secrets.compare_digest`) `current_user` =
  служебный `pass-manager-svc`.
- `@bp.before_request` в `app/routes/api_svc.py` дополнительно требует
  `current_user.username == "pass-manager-svc"`, иначе `401`. Это закрывает fallback:
  без токена Flask-Login иначе взял бы session-пользователя, и залогиненный в браузере
  человек попал бы на `/api/svc` как он сам.
- Blueprint `@csrf.exempt` (машинный клиент, без CSRF-cookie); слушать только на
  `127.0.0.1` (nginx/gunicorn, не код).

### Почему так
Не переписываем `current_user`-scoping существующих маршрутов (риск сломать prod). Всем
владеет один сервис-user `pass-manager-svc`; политика доступа (кто какой сервер видит)
живёт в pass-manager, не здесь.

### Endpoints (E1–E8)
Полный список — в `README.md` → «Service Blueprint (`/api/svc`)». Свойства: E1
(`servers/add`) идемпотентен по `bootstrap_request_id`; E4 (`keys/deploy`) идемпотентен по
активному `KeyDeployment`; E8 (`servers/<id>/access-key`) отдаёт приватный per-server
root-ключ (Fernet-decrypt) — только под токеном и с проверкой ownership.

Миграции `/api/svc` (`bootstrap_request_id`, `ssh_keys.description`) идемпотентны
(проверка колонки через `inspect` перед `add_column`) — безопасны на проде, где часть
колонок уже могла появиться из-за дрейфа схемы.
