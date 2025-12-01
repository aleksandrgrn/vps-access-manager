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
