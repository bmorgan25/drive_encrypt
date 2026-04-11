"""
Entry point for the CLI.
"""

import click

from commands.encrypt_cmd import encrypt_cmd
from commands.decrypt_cmd import decrypt_cmd


@click.group()
def cli() -> None:
    """
    SecureDrive — zero-knowledge local encryption for Google Drive.

    Files are encrypted locally with AES-256-GCM before leaving your machine.
    Your passphrase never leaves your device.
    """
    pass


cli.add_command(encrypt_cmd)
cli.add_command(decrypt_cmd)


if __name__ == "__main__":
    cli()
