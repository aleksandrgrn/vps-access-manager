from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.services.ssh.keys import convert_private_key_to_ppk, get_puttygen_path, get_secure_temp_dir


def test_get_puttygen_path_from_env_existing_file(tmp_path, monkeypatch):
    """Should return configured absolute puttygen path when executable exists."""
    puttygen = tmp_path / "puttygen"
    puttygen.write_text("#!/bin/sh\n", encoding="utf-8")
    puttygen.chmod(0o700)
    monkeypatch.setenv("PUTTYGEN_PATH", str(puttygen))

    assert get_puttygen_path() == str(puttygen)


def test_convert_private_key_to_ppk_success(tmp_path):
    """Should convert private key and return PPK bytes."""
    private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    fake_ppk = b"PuTTY-User-Key-File-3: ssh-rsa\n"
    puttygen_path = tmp_path / "puttygen"
    puttygen_path.write_text("#!/bin/sh\n", encoding="utf-8")
    puttygen_path.chmod(0o700)

    def fake_run(command, capture_output, text, timeout, check):
        output_path = Path(command[-1])
        output_path.write_bytes(fake_ppk)
        return Mock(returncode=0, stdout="", stderr="")

    with patch("app.services.ssh.keys.get_secure_temp_dir", return_value=str(tmp_path)), patch(
        "app.services.ssh.keys.subprocess.run", side_effect=fake_run
    ):
        result = convert_private_key_to_ppk(private_key, str(puttygen_path))

    assert result == fake_ppk


def test_convert_private_key_to_ppk_raises_on_empty_key(tmp_path):
    """Should reject empty private key before subprocess call."""
    puttygen_path = tmp_path / "puttygen"
    puttygen_path.write_text("#!/bin/sh\n", encoding="utf-8")
    puttygen_path.chmod(0o700)

    with pytest.raises(ValueError, match="Приватный ключ пуст"):
        convert_private_key_to_ppk("   ", str(puttygen_path))


def test_convert_private_key_to_ppk_raises_on_failed_conversion(tmp_path):
    """Should raise runtime error on puttygen non-zero exit."""
    private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    puttygen_path = tmp_path / "puttygen"
    puttygen_path.write_text("#!/bin/sh\n", encoding="utf-8")
    puttygen_path.chmod(0o700)

    with patch("app.services.ssh.keys.get_secure_temp_dir", return_value=str(tmp_path)), patch(
        "app.services.ssh.keys.subprocess.run"
    ) as mock_run:
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="conversion failed")

        with pytest.raises(RuntimeError, match="conversion failed"):
            convert_private_key_to_ppk(private_key, str(puttygen_path))


def test_get_secure_temp_dir_prefers_env(monkeypatch, tmp_path):
    """Should prefer configured temp dir for sensitive operations."""
    monkeypatch.setenv("PPK_TEMP_DIR", str(tmp_path))

    assert get_secure_temp_dir() == str(tmp_path)


def test_get_secure_temp_dir_rejects_relative_path(monkeypatch):
    """Should reject relative temp dir paths for secrets handling."""
    monkeypatch.setenv("PPK_TEMP_DIR", "tmp/unsafe")

    with pytest.raises(RuntimeError, match="абсолютным путём"):
        get_secure_temp_dir()
