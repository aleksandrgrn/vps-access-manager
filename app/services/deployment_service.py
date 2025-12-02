"""
Deployment Service

Encapsulates business logic for deploying and revoking SSH keys.
Removes dependency on Flask context (request, flash) and handles DB updates.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from app import db
from app.models import KeyDeployment, Server, SSHKey
from app.services.key_service import decrypt_access_key, revoke_key_from_all_servers
from app.services.ssh.connection import ssh_connection
from app.services.ssh.operations import deploy_key_to_server, revoke_key_from_server
from app.utils import add_log

logger = logging.getLogger(__name__)


def deploy_key_to_servers(user_id: int, key_id: int, server_ids: List[int]) -> Dict[str, Any]:
    """
    Deploy an SSH key to multiple servers.

    Args:
        user_id: ID of the user performing the action.
        key_id: ID of the SSH key to deploy.
        server_ids: List of server IDs to deploy to.

    Returns:
        Dict containing success status, message, and detailed results.
    """
    # 1. Validate inputs
    if not key_id or not server_ids:
        return {
            "success": False,
            "message": "key_id and server_ids are required",
            "error_type": "missing_parameters",
        }

    # 2. Get and validate key
    key = SSHKey.query.get(key_id)
    if not key:
        return {
            "success": False,
            "message": "Key not found",
            "error_type": "key_not_found",
        }

    if key.user_id != user_id:
        return {
            "success": False,
            "message": "Access denied to this key",
            "error_type": "access_denied",
        }

    logger.info(
        f"[DEPLOY_SERVICE_START] Deploying key {key.name} (id={key.id}) "
        f"to {len(server_ids)} servers by user {user_id}"
    )

    results = []
    success_count = 0
    failed_count = 0

    # 3. Iterate over servers
    for server_id in server_ids:
        try:
            server_id = int(server_id)
            server = Server.query.get(server_id)

            if not server:
                results.append(
                    {
                        "server_id": server_id,
                        "success": False,
                        "error": "Server not found",
                        "error_type": "server_not_found",
                    }
                )
                failed_count += 1
                continue

            if server.user_id != user_id:
                results.append(
                    {
                        "server_id": server_id,
                        "server_name": server.name,
                        "success": False,
                        "error": "Access denied to this server",
                        "error_type": "access_denied",
                    }
                )
                failed_count += 1
                continue

            # Check for existing active deployment
            existing_deployment = KeyDeployment.query.filter_by(
                ssh_key_id=key_id, server_id=server_id, revoked_at=None
            ).first()

            if existing_deployment:
                results.append(
                    {
                        "server_id": server_id,
                        "server_name": server.name,
                        "success": False,
                        "error": "Key already deployed on this server",
                        "error_type": "already_deployed",
                    }
                )
                failed_count += 1
                continue

            # Check access key
            if not server.access_key:
                results.append(
                    {
                        "server_id": server_id,
                        "server_name": server.name,
                        "success": False,
                        "error": "Server has no access key configured",
                        "error_type": "missing_access_key",
                    }
                )
                failed_count += 1
                continue

            # Decrypt access key
            decrypt_result = decrypt_access_key(server.access_key)
            if not decrypt_result["success"]:
                logger.error(
                    f"[DEPLOY_SERVICE_DECRYPT_FAIL] {server.name}: {decrypt_result['message']}"
                )
                results.append(
                    {
                        "server_id": server_id,
                        "server_name": server.name,
                        "success": False,
                        "error": f"Decryption error: {decrypt_result['message']}",
                        "error_type": "decryption_error",
                    }
                )
                failed_count += 1
                continue

            # Perform SSH deployment
            logger.info(f"[DEPLOY_SERVICE_SSH] Deploying to {server.name}")
            logger.error(f"DEBUG_DEPLOY: key_id={key.id}, public_key='{key.public_key}'")
            with ssh_connection(
                host=server.ip_address,
                port=server.ssh_port,
                username=server.username,
                private_key=decrypt_result["private_key"],
                server_obj=server,
            ) as conn:
                deploy_result = deploy_key_to_server(server, key.public_key, conn)

            if deploy_result["success"]:
                # Update DB only on success
                try:
                    deployment = KeyDeployment(
                        ssh_key_id=key_id,
                        server_id=server_id,
                        deployed_by=user_id,
                        deployed_at=datetime.now(timezone.utc),
                    )
                    db.session.add(deployment)
                    db.session.commit()

                    logger.info(f"[DEPLOY_SERVICE_SUCCESS] Key deployed to {server.name}")
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": True,
                            "message": f"Key successfully deployed to {server.name}",
                        }
                    )
                    success_count += 1

                except Exception as db_error:
                    db.session.rollback()
                    logger.error(f"[DEPLOY_SERVICE_DB_ERROR] {str(db_error)}")
                    results.append(
                        {
                            "server_id": server_id,
                            "server_name": server.name,
                            "success": False,
                            "error": f"SSH success, but DB error: {str(db_error)}",
                            "error_type": "database_error",
                        }
                    )
                    failed_count += 1
            else:
                logger.warning(f"[DEPLOY_SERVICE_FAILED] {server.name}: {deploy_result['message']}")
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
                    "error": "Invalid server ID format",
                    "error_type": "invalid_server_id",
                }
            )
            failed_count += 1

        except Exception as e:
            logger.error(f"[DEPLOY_SERVICE_EXCEPTION] Server {server_id}: {str(e)}")
            results.append(
                {
                    "server_id": server_id,
                    "success": False,
                    "error": str(e),
                    "error_type": "exception",
                }
            )
            failed_count += 1

    # Log operation
    add_log(
        "deploy_key",
        target=key.name,
        details={
            "servers": len(server_ids),
            "success": success_count,
            "failed": failed_count,
            "user_id": user_id,
        },
    )

    return {
        "success": True,
        "message": f"Deployment complete: {success_count} success, {failed_count} failed",
        "success_count": success_count,
        "failed_count": failed_count,
        "results": results,
    }


def revoke_deployment_by_id(user_id: int, deployment_id: int) -> Dict[str, Any]:
    """
    Revoke a specific key deployment by its ID.

    Args:
        user_id: ID of the user performing the action.
        deployment_id: ID of the KeyDeployment to revoke.

    Returns:
        Dict with success status and details.
    """
    logger.info(f"[REVOKE_SERVICE_START] Revoking deployment {deployment_id} by user {user_id}")

    deployment = KeyDeployment.query.get(deployment_id)
    if not deployment:
        return {
            "success": False,
            "message": "Deployment not found",
            "error_type": "not_found",
        }

    if deployment.revoked_at:
        return {
            "success": False,
            "message": "Key already revoked",
            "error_type": "already_revoked",
        }

    key_to_revoke = deployment.ssh_key
    server = deployment.server

    # Check access
    if key_to_revoke.user_id != user_id:
        return {
            "success": False,
            "message": "Access denied to this key",
            "error_type": "access_denied",
        }

    if not server.access_key:
        return {
            "success": False,
            "message": "Server has no access key configured",
            "server": server.name,
            "error_type": "missing_access_key",
        }

    # Decrypt access key
    decrypt_result = decrypt_access_key(server.access_key)
    if not decrypt_result["success"]:
        logger.error(f"[REVOKE_SERVICE_DECRYPT_FAIL] {decrypt_result['message']}")
        add_log(
            "revoke_key_decrypt_failed",
            target=key_to_revoke.name,
            details={"server": server.name, "error": decrypt_result["message"]},
        )
        return {
            "success": False,
            "message": f"Decryption error: {decrypt_result['message']}",
            "server": server.name,
            "error_type": "decryption_error",
        }

    private_key = decrypt_result["private_key"]

    # Perform SSH revocation
    try:
        with ssh_connection(
            host=server.ip_address,
            port=server.ssh_port,
            username=server.username,
            private_key=private_key,
            server_obj=server,
        ) as conn:
            revoke_result = revoke_key_from_server(server, key_to_revoke.public_key, conn)
    except Exception as ssh_error:
        logger.error(f"[REVOKE_SERVICE_SSH_EXCEPTION] {str(ssh_error)}")
        add_log(
            "revoke_key_exception",
            target=key_to_revoke.name,
            details={"server": server.name, "error": str(ssh_error)},
        )
        return {
            "success": False,
            "message": f"SSH error: {str(ssh_error)}",
            "server": server.name,
            "error_type": "ssh_exception",
        }

    if not revoke_result["success"]:
        logger.warning(f"[REVOKE_SERVICE_SSH_FAILED] {revoke_result['message']}")
        add_log(
            "revoke_key_failed",
            target=key_to_revoke.name,
            details={
                "server": server.name,
                "error": revoke_result.get("message", "Unknown error"),
            },
        )
        return {
            "success": False,
            "message": f"Failed to revoke key: {revoke_result['message']}",
            "server": server.name,
            "error_type": revoke_result.get("error_type", "ssh_error"),
        }

    # Update DB on success
    try:
        deployment.revoked_at = datetime.now(timezone.utc)
        deployment.revoked_by = user_id
        db.session.commit()

        logger.info(f"[REVOKE_SERVICE_SUCCESS] Key {key_to_revoke.name} revoked from {server.name}")
        add_log(
            "revoke_key",
            target=key_to_revoke.name,
            details={"server": server.name, "result": "success"},
        )

        return {
            "success": True,
            "message": "Key successfully revoked from VPS",
            "server": server.name,
            "ip": server.ip_address,
        }

    except Exception as db_error:
        db.session.rollback()
        logger.error(f"[REVOKE_SERVICE_DB_ERROR] {str(db_error)}")
        return {
            "success": False,
            "message": f"Database error: {str(db_error)}",
            "details": "SSH operation succeeded, but DB update failed",
            "server": server.name,
            "error_type": "database_error",
        }


def revoke_key_from_server_by_ids(user_id: int, key_id: int, server_id: int) -> Dict[str, Any]:
    """
    Revoke a key from a specific server using IDs.
    Finds the active deployment and calls revoke_deployment_by_id logic.

    Args:
        user_id: ID of the user.
        key_id: ID of the SSH key.
        server_id: ID of the server.

    Returns:
        Dict with result.
    """
    logger.info(f"[REVOKE_SERVICE_BY_IDS] key_id={key_id}, server_id={server_id}, user={user_id}")

    key_to_revoke = SSHKey.query.get(key_id)
    server = Server.query.get(server_id)

    if not key_to_revoke or not server:
        return {"success": False, "message": "Key or Server not found", "error_type": "not_found"}

    if key_to_revoke.user_id != user_id:
        return {"success": False, "message": "Access denied", "error_type": "access_denied"}

    # Find active deployment
    deployment = KeyDeployment.query.filter_by(
        ssh_key_id=key_id, server_id=server_id, revoked_at=None
    ).first()

    if not deployment:
        return {
            "success": False,
            "message": "Active deployment not found",
            "error_type": "deployment_not_found",
        }

    # Reuse the logic by ID
    return revoke_deployment_by_id(user_id, deployment.id)


def revoke_key_globally(user_id: int, key_id: int) -> Dict[str, Any]:
    """
    Revoke a key from ALL servers where it is currently deployed.

    Args:
        user_id: ID of the user.
        key_id: ID of the SSH key.

    Returns:
        Dict with bulk results.
    """
    logger.info(f"[REVOKE_SERVICE_GLOBAL] key_id={key_id}, user={user_id}")

    key_to_revoke = SSHKey.query.get(key_id)
    if not key_to_revoke:
        return {"success": False, "message": "Key not found", "error_type": "not_found"}

    if key_to_revoke.user_id != user_id:
        return {"success": False, "message": "Access denied", "error_type": "access_denied"}

    # Find all active deployments
    active_deployments = KeyDeployment.query.filter_by(ssh_key_id=key_id, revoked_at=None).all()

    if not active_deployments:
        return {
            "success": True,
            "message": "No active deployments found",
            "total": 0,
            "completed": 0,
            "failed": 0,
        }

    # Collect servers and access keys
    servers = []
    access_keys = {}

    for deployment in active_deployments:
        server = Server.query.get(deployment.server_id)
        if server and server.access_key:
            servers.append(server)
            access_keys[server.id] = server.access_key
        else:
            logger.warning(
                f"[REVOKE_SERVICE_SKIP] Server {deployment.server_id} missing or no access key"
            )

    if not servers:
        return {
            "success": False,
            "message": "No valid servers found for revocation",
            "error_type": "no_servers",
        }

    # Perform bulk revocation
    bulk_result = revoke_key_from_all_servers(key_to_revoke, servers, access_keys)

    # Update DB for successful results
    for result in bulk_result["results"]:
        if result["success"]:
            server_match = next((s for s in servers if s.name == result["server_name"]), None)
            if server_match:
                deployment = KeyDeployment.query.filter_by(
                    ssh_key_id=key_id, server_id=server_match.id, revoked_at=None
                ).first()

                if deployment:
                    deployment.revoked_at = datetime.now(timezone.utc)
                    deployment.revoked_by = user_id

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"[REVOKE_SERVICE_GLOBAL_DB_ERROR] {str(e)}")
        # Note: We still return the bulk result, but maybe with a warning?
        # The SSH part succeeded, so we should probably report that.

    add_log(
        "revoke_key_bulk",
        target=key_to_revoke.name,
        details={
            "total": len(servers),
            "success_count": bulk_result["success_count"],
            "failed_count": bulk_result["failed_count"],
            "user_id": user_id,
        },
    )

    return {
        "success": True,
        "message": f"Revoked from {bulk_result['success_count']} servers",
        "total": len(servers),
        "completed": bulk_result["success_count"],
        "failed": bulk_result["failed_count"],
        "results": bulk_result["results"],
    }
