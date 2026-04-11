"""
CLI command for decrypting a file using SecureDrive.
"""

import getpass
import click

from fileio.fileio import decrypt_file, FileIOError
from crypto.crypto import DecryptionError, InvalidFileError


@click.command(name="decrypt")
@click.argument(
    "input_file", type=click.Path(exists=True, file_okay=True, dir_okay=False)
)
@click.option(
    "--output-dir",
    "-o",
    default="decrypted",
    show_default=True,
    help="Directory to write the decrypted file into.",
)
def decrypt_cmd(input_file: str, output_dir: str) -> None:
    """
    Decrypt a .enc file and write the result to the output directory.

    INPUT_FILE is the path to the .enc file you want to decrypt.
    The decrypted output will be written under its original filename in --output-dir.
    """
    click.echo(f"  File   : {input_file}")
    click.echo(f"  Output : {output_dir}")
    click.echo("")

    # Decrypt only needs the passphrase once — no confirmation prompt.
    passphrase = getpass.getpass("Enter passphrase: ")

    if not passphrase:
        click.echo("Error: Passphrase cannot be empty.", err=True)
        raise SystemExit(1)

    try:
        click.echo("Decrypting...")
        output_path = decrypt_file(input_file, passphrase, output_dir)
        click.echo(
            click.style(f"Done. Decrypted file written to: {output_path}", fg="green")
        )

    except InvalidFileError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        click.echo("Is this a SecureDrive encrypted file?", err=True)
        raise SystemExit(1)

    except DecryptionError:
        # Intentionally vague avoid leaking information to an attacker.
        click.echo(
            click.style(
                "Error: Decryption failed. The passphrase may be incorrect or "
                "the file may be corrupted.",
                fg="red",
            ),
            err=True,
        )
        raise SystemExit(1)

    except FileIOError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        raise SystemExit(1)
