"""Core encryption/decryption engine for .env files."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def parse_env(content: str) -> Dict[str, str]:
    """Parse a .env file content into a dictionary.

    Handles:
    - KEY=VALUE pairs
    - Quoted values (single and double quotes, stripped)
    - Comments (lines starting with #)
    - Blank lines (ignored)
    - Inline comments after unquoted values
    """
    env: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Handle quoted values
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        else:
            # Strip inline comments for unquoted values
            if " #" in value:
                value = value[: value.index(" #")].rstrip()

        env[key] = value
    return env


def serialize_env(env: Dict[str, str]) -> str:
    """Serialize an env dictionary back to .env format."""
    lines: list[str] = []
    for key in sorted(env.keys()):
        value = env[key]
        # Quote values containing spaces or special characters
        if any(c in value for c in (" ", "#", "'", '"', "\n")):
            value = f'"{value}"'
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


class Vault:
    """Encrypted .env file manager.

    Encrypts .env files using Fernet symmetric encryption with a
    password-derived key (PBKDF2-HMAC-SHA256).

    Attributes:
        path: Path to the encrypted vault file (.env.vault).
    """

    MAGIC = b"ENVVAULT1"  # File format identifier
    SALT_SIZE = 16

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def encrypt(self, env_content: str, password: str) -> bytes:
        """Encrypt .env content and return the vault bytes.

        Args:
            env_content: Raw .env file content.
            password: Encryption password.

        Returns:
            Encrypted vault bytes (includes magic header, salt, and ciphertext).
        """
        salt = os.urandom(self.SALT_SIZE)
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(env_content.encode("utf-8"))
        return self.MAGIC + salt + ciphertext

    def decrypt(self, vault_data: bytes, password: str) -> str:
        """Decrypt vault bytes and return the original .env content.

        Args:
            vault_data: Encrypted vault bytes.
            password: Decryption password.

        Returns:
            Decrypted .env file content.

        Raises:
            ValueError: If the vault format is invalid or magic header is wrong.
            InvalidToken: If the password is incorrect.
        """
        if not vault_data.startswith(self.MAGIC):
            raise ValueError("Invalid vault file format â missing magic header.")
        offset = len(self.MAGIC)
        salt = vault_data[offset : offset + self.SALT_SIZE]
        ciphertext = vault_data[offset + self.SALT_SIZE :]
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(ciphertext).decode("utf-8")

    def encrypt_file(self, env_path: str | Path, password: str) -> Path:
        """Encrypt a .env file and write the vault file.

        Args:
            env_path: Path to the .env file to encrypt.
            password: Encryption password.

        Returns:
            Path to the written vault file.
        """
        env_path = Path(env_path)
        content = env_path.read_text(encoding="utf-8")
        vault_data = self.encrypt(content, password)
        self.path.write_bytes(vault_data)
        return self.path

    def decrypt_file(self, password: str, output_path: Optional[str | Path] = None) -> str:
        """Decrypt the vault file and optionally write the result.

        Args:
            password: Decryption password.
            output_path: If provided, write the decrypted content to this path.

        Returns:
            Decrypted .env content.
        """
        vault_data = self.path.read_bytes()
        content = self.decrypt(vault_data, password)
        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")
        return content

    def get(self, password: str, key: str) -> Optional[str]:
        """Get a single value from the encrypted vault.

        Args:
            password: Decryption password.
            key: The environment variable name.

        Returns:
            The value, or None if the key is not found.
        """
        content = self.decrypt_file(password)
        env = parse_env(content)
        return env.get(key)

    def set(self, password: str, key: str, value: str) -> None:
        """Set a single value in the encrypted vault.

        Args:
            password: Decryption password (used to decrypt, modify, and re-encrypt).
            key: The environment variable name.
            value: The new value.
        """
        content = self.decrypt_file(password)
        env = parse_env(content)
        env[key] = value
        new_content = serialize_env(env)
        vault_data = self.encrypt(new_content, password)
        self.path.write_bytes(vault_data)

    def remove(self, password: str, key: str) -> bool:
        """Remove a key from the encrypted vault.

        Args:
            password: Decryption password.
            key: The environment variable name to remove.

        Returns:
            True if the key was found and removed, False otherwise.
        """
        content = self.decrypt_file(password)
        env = parse_env(content)
        if key not in env:
            return False
        del env[key]
        new_content = serialize_env(env)
        vault_data = self.encrypt(new_content, password)
        self.path.write_bytes(vault_data)
        return True

    def list_keys(self, password: str) -> list[str]:
        """List all keys in the encrypted vault.

        Args:
            password: Decryption password.

        Returns:
            Sorted list of environment variable names.
        """
        content = self.decrypt_file(password)
        env = parse_env(content)
        return sorted(env.keys())
