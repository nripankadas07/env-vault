"""Tests for the env-vault encryption engine and .env parser."""

from __future__ import annotations

import pytest
from pathlib import Path

from cryptography.fernet import InvalidToken

from env_vault.vault import Vault, parse_env, serialize_env


# ââ .env parser tests ââââââââââââââââââââââââââââââââââââââââââââââââ


class TestParseEnv:
    """Tests for .env file parsing."""

    def test_basic_key_value(self) -> None:
        content = "DB_HOST=localhost\nDB_PORT=5432\n"
        env = parse_env(content)
        assert env == {"DB_HOST": "localhost", "DB_PORT": "5432"}

    def test_quoted_values(self) -> None:
        content = 'SECRET="my secret value"\nOTHER=\'single quoted\'\n'
        env = parse_env(content)
        assert env["SECRET"] == "my secret value"
        assert env["OTHER"] == "single quoted"

    def test_comments_and_blank_lines(self) -> None:
        content = "# This is a comment\n\nKEY=value\n\n# Another comment\n"
        env = parse_env(content)
        assert env == {"KEY": "value"}

    def test_inline_comments(self) -> None:
        content = "HOST=localhost # the host\n"
        env = parse_env(content)
        assert env["HOST"] == "localhost"

    def test_empty_value(self) -> None:
        content = "EMPTY=\n"
        env = parse_env(content)
        assert env["EMPTY"] == ""

    def test_value_with_equals(self) -> None:
        content = "URL=postgres://user:pass@host/db?opt=1\n"
        env = parse_env(content)
        assert env["URL"] == "postgres://user:pass@host/db?opt=1"


class TestSerializeEnv:
    """Tests for serializing env dicts back to .env format."""

    def test_basic_serialization(self) -> None:
        env = {"B_KEY": "val2", "A_KEY": "val1"}
        result = serialize_env(env)
        assert result == "A_KEY=val1\nB_KEY=val2\n"

    def test_values_with_spaces_are_quoted(self) -> None:
        env = {"KEY": "has spaces"}
        result = serialize_env(env)
        assert result == 'KEY="has spaces"\n'


# ââ Vault encryption/decryption tests âââââââââââââââââââââââââââââââ


class TestVaultEncryptDecrypt:
    """Tests for the core encrypt/decrypt cycle."""

    def test_round_trip(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "test.vault")
        original = "DB_HOST=localhost\nSECRET=hunter2\n"
        password = "test-password-123"

        encrypted = vault.encrypt(original, password)
        decrypted = vault.decrypt(encrypted, password)
        assert decrypted == original

    def test_wrong_password_fails(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "test.vault")
        original = "KEY=value\n"
        encrypted = vault.encrypt(original, "correct-password")

        with pytest.raises(InvalidToken):
            vault.decrypt(encrypted, "wrong-password")

    def test_invalid_format_raises(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "test.vault")
        with pytest.raises(ValueError, match="Invalid vault file format"):
            vault.decrypt(b"not-a-vault-file", "password")

    def test_encrypted_data_starts_with_magic(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "test.vault")
        encrypted = vault.encrypt("KEY=val\n", "pw")
        assert encrypted.startswith(Vault.MAGIC)


class TestVaultFileOperations:
    """Tests for file-based encrypt/decrypt."""

    def test_encrypt_and_decrypt_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=sk-abc123\nDEBUG=true\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "mypassword")

        assert vault.path.exists()
        assert vault.path.stat().st_size > 0

        output = tmp_path / ".env.decrypted"
        content = vault.decrypt_file("mypassword", output)
        assert "API_KEY=sk-abc123" in content
        assert output.read_text() == content

    def test_get_single_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("HOST=localhost\nPORT=8080\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "pw")

        assert vault.get("pw", "HOST") == "localhost"
        assert vault.get("pw", "PORT") == "8080"
        assert vault.get("pw", "MISSING") is None

    def test_set_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("HOST=localhost\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "pw")
        vault.set("pw", "NEW_KEY", "new_value")

        assert vault.get("pw", "NEW_KEY") == "new_value"
        assert vault.get("pw", "HOST") == "localhost"

    def test_remove_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("A=1\nB=2\nC=3\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "pw")

        assert vault.remove("pw", "B") is True
        assert vault.get("pw", "B") is None
        assert vault.get("pw", "A") == "1"
        assert vault.get("pw", "C") == "3"

    def test_remove_missing_key_returns_false(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("A=1\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "pw")

        assert vault.remove("pw", "MISSING") is False

    def test_list_keys(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("ZEBRA=z\nAPPLE=a\nMIDDLE=m\n")

        vault = Vault(tmp_path / ".env.vault")
        vault.encrypt_file(env_file, "pw")

        keys = vault.list_keys("pw")
        assert keys == ["APPLE", "MIDDLE", "ZEBRA"]
