"""Command-line interface for env-vault."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from env_vault.vault import Vault, parse_env, serialize_env


@click.group()
@click.version_option()
def main() -> None:
    """Encrypted .env file manager.

    Encrypt, decrypt, and manage environment secrets safely.
    """


@main.command()
@click.argument("env_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output vault file path (default: <env_file>.vault).",
)
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
def encrypt(env_file: Path, output: Path | None, password: str) -> None:
    """Encrypt a .env file into a vault."""
    vault_path = output or Path(str(env_file) + ".vault")
    vault = Vault(vault_path)
    vault.encrypt_file(env_file, password)
    click.echo(f"Encrypted {env_file} -> {vault_path}")


@main.command()
@click.argument("vault_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output .env file path (default: stdout).",
)
@click.option("--password", "-p", prompt=True, hide_input=True)
def decrypt(vault_file: Path, output: Path | None, password: str) -> None:
    """Decrypt a vault back to a .env file."""
    vault = Vault(vault_file)
    try:
        content = vault.decrypt_file(password, output)
    except Exception as exc:
        click.echo(f"Decryption failed: {exc}", err=True)
        sys.exit(1)

    if output:
        click.echo(f"Decrypted {vault_file} -> {output}")
    else:
        click.echo(content, nl=False)


@main.command("get")
@click.argument("vault_file", type=click.Path(exists=True, path_type=Path))
@click.argument("key")
@click.option("--password", "-p", prompt=True, hide_input=True)
def get_key(vault_file: Path, key: str, password: str) -> None:
    """Get a single value from the vault."""
    vault = Vault(vault_file)
    try:
        value = vault.get(password, key)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if value is None:
        click.echo(f"Key '{key}' not found.", err=True)
        sys.exit(1)
    click.echo(value)


@main.command("set")
@click.argument("vault_file", type=click.Path(exists=True, path_type=Path))
@click.argument("key")
@click.argument("value")
@click.option("--password", "-p", prompt=True, hide_input=True)
def set_key(vault_file: Path, key: str, value: str, password: str) -> None:
    """Set a key-value pair in the vault."""
    vault = Vault(vault_file)
    try:
        vault.set(password, key, value)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Set {key} in {vault_file}")


@main.command("rm")
@click.argument("vault_file", type=click.Path(exists=True, path_type=Path))
@click.argument("key")
@click.option("--password", "-p", prompt=True, hide_input=True)
def remove_key(vault_file: Path, key: str, password: str) -> None:
    """Remove a key from the vault."""
    vault = Vault(vault_file)
    try:
        removed = vault.remove(password, key)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if removed:
        click.echo(f"Removed {key} from {vault_file}")
    else:
        click.echo(f"Key '{key}' not found.", err=True)
        sys.exit(1)


@main.command("keys")
@click.argument("vault_file", type=click.Path(exists=True, path_type=Path))
@click.option("--password", "-p", prompt=True, hide_input=True)
def list_keys(vault_file: Path, password: str) -> None:
    """List all keys in the vault."""
    vault = Vault(vault_file)
    try:
        keys = vault.list_keys(password)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if not keys:
        click.echo("Vault is empty.")
    else:
        for key in keys:
            click.echo(key)
