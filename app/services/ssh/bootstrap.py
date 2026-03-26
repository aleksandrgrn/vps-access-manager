"""SSH bootstrap orchestration for verified key-based server onboarding."""

from __future__ import annotations

import logging
import shlex
import time
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Tuple, cast

from app.services.ssh.connection import SSHConnection
from app.services.ssh.keys import validate_ssh_public_key

logger = logging.getLogger(__name__)

_SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"


def bootstrap_server_access(
    *,
    host: str,
    port: int,
    bootstrap_username: str,
    password: str,
    public_key: str,
    private_key: str,
    requires_legacy_ssh: bool,
    openssh_version: str,
    server_name: Optional[str] = None,
) -> Dict[str, object]:
    """Bootstrap root key access via root or sudo-capable bootstrap account."""

    password_connection = SSHConnection(host, port, bootstrap_username)

    try:
        connected, error = password_connection.connect_with_password(password)
        if not connected:
            return _failure(
                "password_connection_failed", error or "Не удалось подключиться по паролю"
            )

        executor, privilege_error = _build_root_executor(
            connection=password_connection,
            bootstrap_username=bootstrap_username,
            password=password,
        )
        if executor is None:
            return _failure(
                "root_access_unavailable",
                privilege_error or "Для настройки root-доступа требуются права root/sudo",
            )

        deploy_result = _deploy_root_public_key(
            executor=executor,
            public_key=public_key,
            server_name=server_name or host,
        )
        if not deploy_result.get("success"):
            return {
                "success": False,
                "error_type": deploy_result.get("error_type", "deploy_failed"),
                "message": deploy_result.get("message", "Не удалось развернуть SSH ключ"),
            }

        verify_result = _verify_key_login(
            host=host,
            port=port,
            username="root",
            private_key=private_key,
            requires_legacy_ssh=requires_legacy_ssh,
            openssh_version=openssh_version,
        )
        if verify_result["success"]:
            return {
                "success": True,
                "verified": True,
                "remediated": False,
                "target_username": "root",
                "message": "Вход по ключу подтверждён",
            }

        remediation_result = _conditionally_remediate_sshd_config(
            executor=executor,
            key_type=_public_key_type(public_key),
            initial_verify_error=str(verify_result["message"]),
        )
        if not remediation_result["success"]:
            return remediation_result

        reverify_result = _verify_key_login(
            host=host,
            port=port,
            username="root",
            private_key=private_key,
            requires_legacy_ssh=requires_legacy_ssh,
            openssh_version=openssh_version,
        )
        if reverify_result["success"]:
            return {
                "success": True,
                "verified": True,
                "remediated": True,
                "target_username": "root",
                "message": "Вход по ключу подтверждён после корректировки sshd_config",
            }

        rollback_error = _rollback_sshd_changes(
            cast(Callable[[str, int], Tuple[bool, str, str]], remediation_result["executor"]),
            str(remediation_result["backup_path"]),
        )
        message = (
            "Вход по ключу не подтверждён после корректировки sshd_config: "
            f"{reverify_result['message']}"
        )
        if rollback_error:
            message = f"{message}. Ошибка rollback: {rollback_error}"

        return _failure("verification_failed", message)
    finally:
        password_connection.close()


def _verify_key_login(
    *,
    host: str,
    port: int,
    username: str,
    private_key: str,
    requires_legacy_ssh: bool,
    openssh_version: str,
) -> Dict[str, object]:
    """Verify key auth using a brand-new SSH session."""

    connection = SSHConnection(host, port, username)
    server_ref = SimpleNamespace(
        requires_legacy_ssh=requires_legacy_ssh,
        openssh_version=openssh_version,
    )

    try:
        connected, error = connection.connect_with_key(private_key, server_obj=server_ref)
        if not connected:
            return _failure("verification_failed", error or "Вход по ключу не удался")

        executed, _, stderr = connection.execute("true", timeout=10)
        if not executed:
            return _failure(
                "verification_failed",
                stderr or "Вход по ключу установлен, но сессия не проходит проверку",
            )

        return {"success": True, "message": "Вход по ключу подтверждён"}
    finally:
        connection.close()


def _conditionally_remediate_sshd_config(
    *,
    executor: Callable[[str, int], Tuple[bool, str, str]],
    key_type: str,
    initial_verify_error: str,
) -> Dict[str, object]:
    """Normalize main sshd_config to the product-approved remediation set."""

    _ = key_type
    _ = initial_verify_error

    directives = _build_remediation_directives()

    apply_result = _apply_sshd_directives(executor, directives)
    if apply_result["success"]:
        return {
            "success": True,
            "backup_path": apply_result["backup_path"],
            "executor": executor,
            "directives": directives,
        }

    return _failure(
        "sshd_remediation_failed",
        f"Не удалось безопасно скорректировать sshd_config: {apply_result['message']}",
    )


def _build_root_executor(
    *,
    connection: SSHConnection,
    bootstrap_username: str,
    password: str,
) -> Tuple[Optional[Callable[[str, int], Tuple[bool, str, str]]], Optional[str]]:
    """Return an executor that applies commands as root."""

    if bootstrap_username == "root":
        return lambda command, timeout=20: connection.execute(command, timeout=timeout), None

    success, _, stderr = connection.execute("sudo -n true", timeout=10)
    if success:
        return (
            lambda command, timeout=20: connection.execute(
                f"sudo -n sh -c {shlex.quote(command)}", timeout=timeout
            ),
            None,
        )

    password_success, _, password_stderr = connection.execute(
        f"printf %s {shlex.quote(password)} | sudo -S -p '' true",
        timeout=10,
    )
    if password_success:
        return (
            lambda command, timeout=20: connection.execute(
                f"printf %s {shlex.quote(password)} | sudo -S -p '' sh -c {shlex.quote(command)}",
                timeout=timeout,
            ),
            None,
        )

    error_message = stderr or password_stderr or "Нет прав root/sudo для изменения sshd_config"
    return None, (
        "Вход по ключу для root не может быть настроен: " f"нужны права root/sudo ({error_message})"
    )


def _deploy_root_public_key(
    *,
    executor: Callable[[str, int], Tuple[bool, str, str]],
    public_key: str,
    server_name: str,
) -> Dict[str, object]:
    """Deploy the generated public key into /root/.ssh/authorized_keys."""

    if not validate_ssh_public_key(public_key):
        return _failure("invalid_key", "Невалидный формат публичного ключа")

    mkdir_success, _, mkdir_stderr = executor(
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh",
        20,
    )
    if not mkdir_success:
        return _failure(
            "mkdir_failed",
            f"Не удалось подготовить /root/.ssh на {server_name}: {mkdir_stderr}",
        )

    read_success, existing_keys, read_stderr = executor(
        "cat /root/.ssh/authorized_keys 2>/dev/null || echo ''",
        20,
    )
    if not read_success:
        return _failure(
            "read_failed",
            f"Не удалось прочитать /root/.ssh/authorized_keys: {read_stderr}",
        )

    if public_key.strip() in existing_keys:
        return {"success": True, "message": "Ключ уже установлен для root", "status": "skipped"}

    escaped_key = public_key.strip().replace("'", "'\\''")
    append_success, _, append_stderr = executor(
        (
            f"echo '{escaped_key}' >> /root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys"
        ),
        20,
    )
    if not append_success:
        return _failure(
            "append_failed",
            f"Не удалось добавить ключ root: {append_stderr}",
        )

    return {"success": True, "message": "Ключ успешно установлен для root", "status": "deployed"}


def _build_remediation_directives() -> List[str]:
    return [
        "PermitRootLogin yes",
        "PasswordAuthentication yes",
        "PubkeyAuthentication yes",
        "PubkeyAcceptedAlgorithms +ssh-rsa",
        "PubkeyAcceptedKeyTypes +ssh-rsa",
    ]


def _apply_sshd_directives(
    executor: Callable[[str, int], Tuple[bool, str, str]], directives: List[str]
) -> Dict[str, object]:
    backup_path = f"sshd_config.backup.{int(time.time() * 1000)}"
    path_success, stdout, stderr = executor("mktemp -t sshd_config.backup.XXXXXXXXXX", 20)
    if not path_success:
        return _failure(
            "sshd_remediation_failed", stderr or "Не удалось создать временный backup sshd_config"
        )

    if stdout.strip():
        backup_path = stdout.strip()

    success, _, stderr = executor(
        f"cp {_SSHD_CONFIG_PATH} {shlex.quote(backup_path)}",
        20,
    )
    if not success:
        return _failure(
            "sshd_remediation_failed", stderr or "Не удалось создать backup sshd_config"
        )

    read_success, current_config, read_stderr = executor(f"cat {_SSHD_CONFIG_PATH}", 20)
    if not read_success:
        return _failure(
            "sshd_remediation_failed",
            read_stderr or "Не удалось прочитать основной sshd_config",
        )

    normalized_config = _normalize_main_sshd_config(current_config, directives)
    write_success, _, write_stderr = executor(
        _build_write_config_command(_SSHD_CONFIG_PATH, normalized_config),
        20,
    )
    if not write_success:
        _rollback_sshd_changes(executor, backup_path)
        return _failure(
            "sshd_remediation_failed", write_stderr or "Не удалось обновить sshd_config"
        )

    validate_success, _, validate_stderr = executor(f"sshd -t -f {_SSHD_CONFIG_PATH}", 20)
    if not validate_success:
        _rollback_sshd_changes(executor, backup_path)
        return _failure(
            "sshd_remediation_failed",
            validate_stderr or "Проверка sshd_config завершилась ошибкой",
        )

    reload_success, _, reload_stderr = executor(_reload_sshd_command(), 30)
    if not reload_success:
        rollback_error = _rollback_sshd_changes(executor, backup_path)
        message = reload_stderr or "Не удалось перезагрузить sshd"
        if rollback_error:
            message = f"{message}. Ошибка rollback: {rollback_error}"
        return _failure("sshd_remediation_failed", message)

    return {"success": True, "backup_path": backup_path}


def _rollback_sshd_changes(
    executor: Callable[[str, int], Tuple[bool, str, str]], backup_path: str
) -> Optional[str]:
    restore_success, _, restore_stderr = executor(
        f"cp {shlex.quote(backup_path)} {_SSHD_CONFIG_PATH}", 20
    )
    if not restore_success:
        return restore_stderr or "Не удалось восстановить sshd_config"

    reload_success, _, reload_stderr = executor(_reload_sshd_command(), 30)
    if not reload_success:
        return reload_stderr or "Не удалось перезагрузить sshd после rollback"

    return None


def _reload_sshd_command() -> str:
    return (
        "if command -v systemctl >/dev/null 2>&1; then "
        "systemctl reload sshd || systemctl reload ssh || "
        "systemctl restart sshd || systemctl restart ssh; "
        "else service sshd reload || service ssh reload || "
        "service sshd restart || service ssh restart; fi"
    )


def _public_key_type(public_key: str) -> str:
    return public_key.strip().split()[0] if public_key.strip() else "unknown"


def _normalize_main_sshd_config(current_config: str, directives: List[str]) -> str:
    managed_keys = {
        "permitrootlogin",
        "passwordauthentication",
        "pubkeyauthentication",
    }
    managed_keys.update(directive.split()[0].lower() for directive in directives)

    normalized_lines: List[str] = []
    for line in current_config.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            normalized_lines.append(line)
            continue

        directive_name = stripped.split(None, 1)[0].lower()
        if directive_name == "include" and "sshd_config.d" in stripped.lower():
            normalized_lines.append(f"# {line}")
            continue

        if directive_name in managed_keys:
            normalized_lines.append(f"# {line}")
            continue

        normalized_lines.append(line)

    if normalized_lines and normalized_lines[-1].strip():
        normalized_lines.append("")

    normalized_lines.append("# vps-manager ssh bootstrap remediation")
    normalized_lines.extend(directives)
    normalized_lines.append("")
    return "\n".join(normalized_lines)


def _build_write_config_command(path: str, content: str) -> str:
    heredoc_tag = "__VPS_MANAGER_SSHD_CONFIG__"
    return f"cat > {path} <<'{heredoc_tag}'\n{content}{heredoc_tag}\n"


def _failure(error_type: str, message: str) -> Dict[str, object]:
    logger.warning("SSH bootstrap failure [%s]: %s", error_type, message)
    return {"success": False, "error_type": error_type, "message": message}
