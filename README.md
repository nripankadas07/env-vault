# env-vault

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)

Encrypted `.env` file manager. Encrypt your environment secrets with a password, then decrypt, query, and modify individual keys â all without exposing plaintext files.

## Features

- **Password-based encryption** â uses PBKDF2-HMAC-SHA256 key derivation with Fernet (AES-128-CBC)
- **File-level encrypt/decrypt** â encrypt an entire `.env` file into a `.env.vault` binary
- **Key-level operations** â get, set, and remove individual keys without decrypting to disk
- **Robust .env parser** â handles quoted values, inline comments, blank lines, and edge cases
- **CLI interface** â encrypt, decrypt, get, set, remove, and list keys from the terminal
- **Safe round-trips** â encrypted vault preserves all keys/values through encrypt-decrypt cycles

## Installation

```bash
pip install -e .
```

Or install from source:

```bash
git clone https://github.com/nripankadas07/env-vault.git
cd env-vault
pip install -e ".[dev]"
```

## Usage

### Encrypt a .env file

```bash
env-vault encrypt .env -o .env.vault
# Prompts for password (with confirmation)
```

### Decrypt back to plaintext

```bash
# Print to stdout
env-vault decrypt .env.vault

# Write to file
env-vault decrypt .env.vault -o .env.decrypted
```

### Get a single key

```bash
env-vault get .env.vault API_KEY
# Prints: sk-abc123
```

### Set a key

```bash
env-vault set .env.vault NEW_KEY new_value
```

### Remove a key

```bash
env-vault rm .env.vault OLD_KEY
```

### List all keys

```bash
env-vault keys .env.vault
# Prints:
# API_KEY
# DATABASE_URL
# SECRET
```

### As a Library

```python
from env_vault import Vault

vault = Vault(".env.vault")

# Encrypt
vault.encrypt_file(".env", password="my-secret-password")

# Decrypt
content = vault.decrypt_file("my-secret-password")

# Get/set/remove individual keys
api_key = vault.get("my-secret-password", "API_KEY")
vault.set("my-secret-password", "NEW_KEY", "value")
vault.remove("my-secret-password", "OLD_KEY")

# List all keys
keys = vault.list_keys("my-secret-password")
```

## API Reference

### `Vault(path)`

Create a vault instance pointing to an encrypted vault file.

### `vault.encrypt(content, password) -> bytes`

Encrypt raw `.env` content string and return vault bytes.

### `vault.decrypt(vault_data, password) -> str`

Decrypt vault bytes and return the original `.env` content.

### `vault.encrypt_file(env_path, password) -> Path`

Encrypt a `.env` file on disk and write the vault file.

### `vault.decrypt_file(password, output_path=None) -> str`

Decrypt the vault file. Optionally write the result to `output_path`.

### `vault.get(password, key) -> Optional[str]`

Get a single value from the encrypted vault.

### `vault.set(password, key, value) -> None`

Set a key-value pair in the encrypted vault.

### `vault.remove(password, key) -> bool`

Remove a key from the vault. Returns True if found and removed.

### `vault.list_keys(password) -> list[str]`

List all keys in the vault (sorted).

## Architecture

```
src/env_vault/
  __init__.py     # Package exports
  vault.py        # Core encryption engine + .env parser
  cli.py          # Click-based CLI with subcommands
```

The vault file format is: `ENVVAULT1` magic header (9 bytes) + random salt (16 bytes) + Fernet ciphertext. The key is derived from the password using PBKDF2-HMAC-SHA256 with 480,000 iterations, making brute-force attacks impractical.

## Security Notes

- Uses `cryptography` library (OpenSSL-backed) for all crypto operations
- PBKDF2 with 480,000 iterations follows OWASP recommendations
- Each encryption uses a fresh random salt â encrypting the same file twice produces different ciphertext
- Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256)
- Passwords are never stored â only the derived key is used transiently

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT License â Copyright 2024 Nripanka Das
