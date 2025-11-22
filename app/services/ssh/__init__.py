"""
SSH Services Package

Exposes the public API for SSH operations.
"""

from .connection import connect_with_password, parse_openssh_version, test_connection
from .keys import (
    decrypt_private_key,
    encrypt_private_key,
    generate_ssh_key,
    get_fingerprint,
    validate_ssh_public_key,
)
from .operations import (
    deploy_key,
    deploy_key_to_multiple_servers,
    deploy_key_with_password,
    initialize_server,
    revoke_key,
    revoke_key_from_all_servers,
    revoke_key_from_single_server,
)
