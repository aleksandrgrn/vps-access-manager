# SSH operations (deploy, revoke, etc.)
import logging
from typing import Any, Dict, List

from app.services.ssh.connection import SSHConnection
from app.services.ssh.keys import validate_ssh_public_key

logger = logging.getLogger(__name__)


def deploy_key_to_server(server, key, connection: SSHConnection) -> Dict[str, Any]:
    """
    Развёртывает публичный ключ на сервере через SSHConnection.

    Args:
        server: Объект сервера с параметрами подключения
        key: Публичный ключ (строка)
        connection: Активное SSH-соединение

    Returns:
        Dict[str, Any]: {'success': bool, 'message': str, 'error_type': str (optional)}
    """
    if not validate_ssh_public_key(key):
        logger.error(f"Невалидный ключ для сервера {server.name}")
        return {
            "success": False,
            "message": "Невалидный формат публичного ключа",
            "error_type": "invalid_key",
        }

    try:
        # Создаем директорию ~/.ssh с правами
        success, _, stderr = connection.execute("mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=15)
        if not success:
            logger.error(f"Ошибка создания ~/.ssh на сервере {server.name}: {stderr}")
            return {
                "success": False,
                "message": f"Ошибка создания ~/.ssh: {stderr}",
                "error_type": "mkdir_failed",
            }

        # Проверяем, есть ли ключ в authorized_keys
        success, authorized_keys, _ = connection.execute(
            "cat ~/.ssh/authorized_keys || echo ''", timeout=10
        )
        if key.strip() in authorized_keys:
            logger.info(f"Ключ уже присутствует на сервере {server.name}")

            return {"success": True, "message": "Ключ уже установлен", "status": "skipped"}

        # Добавляем ключ
        escaped_key = key.strip().replace("'", "'\\''")
        cmd = f"echo '{escaped_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        success, _, stderr = connection.execute(cmd, timeout=15)

        if success:
            logger.info(f"Ключ успешно добавлен на сервер {server.name}")

            return {"success": True, "message": "Ключ успешно добавлен", "status": "deployed"}
        else:
            logger.error(f"Ошибка добавления ключа на сервер {server.name}: {stderr}")
            return {
                "success": False,
                "message": f"Ошибка добавления ключа: {stderr}",
                "error_type": "append_failed",
            }
    except Exception as e:
        logger.error(f"Исключение при добавлении ключа на сервер {server.name}: {e}")
        return {
            "success": False,
            "message": f"Ошибка: {str(e)}",
            "error_type": "exception",
        }


def revoke_key_from_server(server, key, connection: SSHConnection) -> Dict[str, Any]:
    """
    Отзывает публичный ключ с сервера через SSHConnection.

    Args:
        server: Объект сервера
        key: Публичный ключ
        connection: Активное SSH-соединение

    Returns:
        Dict[str, Any]: {'success': bool, 'message': str, 'error_type': str (optional)}
    """
    if not validate_ssh_public_key(key):
        logger.error(f"Невалидный ключ для отзыва на сервере {server.name}")
        return {
            "success": False,
            "message": "Невалидный формат ключа",
            "error_type": "invalid_key",
        }

    try:
        # Создаём backup authorized_keys
        connection.execute(
            "cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak || true", timeout=10
        )

        # Читаем содержимое authorized_keys
        success, content, _ = connection.execute(
            "cat ~/.ssh/authorized_keys || echo ''", timeout=10
        )
        if not success:
            return {
                "success": False,
                "message": "Не удалось прочитать authorized_keys",
                "error_type": "read_failed",
            }

        lines = content.strip().split("\n")
        key_stripped = key.strip()
        new_lines = [line for line in lines if key_stripped not in line.strip()]

        if len(new_lines) == len(lines):
            return {
                "success": False,
                "message": "Ключ не найден в authorized_keys",
                "error_type": "key_not_found",
            }

        new_content = "\n".join(new_lines)
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"

        escaped_content = new_content.replace("'", "'\\''")
        cmd = (
            f"echo -n '{escaped_content}' > ~/.ssh/authorized_keys "
            "&& chmod 600 ~/.ssh/authorized_keys"
        )
        success, _, stderr = connection.execute(cmd, timeout=15)

        if success:
            logger.info(f"Ключ успешно отозван на сервере {server.name}")
            return {"success": True, "message": "Ключ успешно отозван"}
        else:
            # Восстанавливаем backup
            connection.execute(
                "mv ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys || true", timeout=10
            )
            logger.error(f"Ошибка при отзыве ключа на сервере {server.name}: {stderr}")
            return {
                "success": False,
                "message": f"Ошибка при обновлении authorized_keys: {stderr}",
                "error_type": "write_failed",
            }
    except Exception as e:
        logger.error(f"Исключение при отзыве ключа на сервере {server.name}: {e}")
        return {
            "success": False,
            "message": f"Ошибка: {str(e)}",
            "error_type": "exception",
        }


def verify_key_deployed(server, key, connection: SSHConnection) -> bool:
    """
    Проверяет наличие ключа на сервере.

    Args:
        server: Объект сервера
        key: Публичный ключ
        connection: Активное SSH-соединение

    Returns:
        bool: True если ключ найден
    """
    try:
        success, content, _ = connection.execute(
            "cat ~/.ssh/authorized_keys || echo ''", timeout=10
        )
        if not success:
            return False
        return key.strip() in content
    except Exception as e:
        logger.error(f"Ошибка при проверке ключа на сервере {server.name}: {e}")
        return False


def bulk_deploy_keys(servers: List, keys: List) -> Dict:
    """
    Массовое параллельное развёртывание ключей.

    Args:
        servers: Список серверов
        keys: Список ключей

    Returns:
        Dict с результатами
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = {"deployed": [], "skipped": [], "failed": [], "total": len(servers) * len(keys)}

    def deploy_task(server, key):
        conn = None
        try:
            conn = SSHConnection(server.ip_address, server.ssh_port, server.username)
            success, error = conn.connect_with_key(server.private_key, server)
            if not success:
                return server, key, False, error

            deploy_result = deploy_key_to_server(server, key, conn)
            conn.close()
            return server, key, deploy_result["success"], deploy_result
        except Exception as e:
            if conn:
                conn.close()
            return server, key, False, str(e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for server in servers:
            for key in keys:
                futures.append(executor.submit(deploy_task, server, key))

        for future in as_completed(futures):
            server, key, success, result_data = future.result()

            # result_data может быть строкой (если ошибка в deploy_task)
            # или словарем (от deploy_key_to_server)
            message = (
                result_data if isinstance(result_data, str) else result_data.get("message", "")
            )
            status = result_data.get("status", "") if isinstance(result_data, dict) else ""

            if success:
                if status == "skipped":
                    results["skipped"].append(
                        {"server_id": server.id, "server_name": server.name, "reason": message}
                    )
                    logger.info(f"Ключ пропущен (уже есть): сервер {server.name}")
                else:
                    results["deployed"].append(
                        {"server_id": server.id, "server_name": server.name, "message": message}
                    )
                    logger.info(f"Ключ успешно развернут: сервер {server.name}")
            else:
                results["failed"].append(
                    {"server_id": server.id, "server_name": server.name, "error": message}
                )
                logger.error(f"Ошибка развертывания ключа на сервере {server.name}: {message}")

    return results
