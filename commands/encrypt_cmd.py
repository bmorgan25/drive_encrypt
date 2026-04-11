"""
CLI command for encrypting a file using SecureDrive.
"""

import getpass
import click

from fileio.fileio import encrypt_file, FileIOError
from crypto.crypto import DecryptionError


@click.command(name="encrypt")
@click.argument(
    "input_file", type=click.Path(exists=True, file_okay=True, dir_okay=False)
)
@click.option(
    "--output-dir",
    "-o",
    default="encrypted",
    show_default=True,
    help="Directory to write the encrypted .enc file into.",
)
def encrypt_cmd(input_file: str, output_dir: str) -> None:
    """
    Encrypt a file and write the result to the output directory.

    INPUT_FILE is the path to the file you want to encrypt.
    The encrypted output will be written as INPUT_FILE.enc in --output-dir.
    """
    click.echo(f"  File   : {input_file}")
    click.echo(f"  Output : {output_dir}")
    click.echo("")

    # Prompt for passphrase twice to catch typos.
    passphrase = getpass.getpass("Enter passphrase: ")

    if not passphrase:
        click.echo("Error: Passphrase cannot be empty.", err=True)
        raise SystemExit(1)

    confirm = getpass.getpass("Confirm passphrase: ")

    if passphrase != confirm:
        click.echo("Error: Passphrases do not match.", err=True)
        raise SystemExit(1)

    # Encrypt and write to disk
    try:
        click.echo("Encrypting...")
        output_path = encrypt_file(input_file, passphrase, output_dir)
        click.echo(
            click.style(f"Done. Encrypted file written to: {output_path}", fg="green")
        )

    except FileIOError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        raise SystemExit(1)
