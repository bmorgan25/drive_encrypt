import os

from crypto.crypto import encrypt_data, decrypt_data, DecryptionError, InvalidFileError


class FileIOError(Exception):
    """
    Raised when a file operation fails — file not found, permission denied,
    disk full, etc. Wraps OSError so callers only need to handle one exception
    type from this module.
    """

    pass


ENCRYPTED_EXTENSION = ".enc"


def encrypt_file(input_path: str, passphrase: str, output_dir: str = ".") -> str:
    """
    Read a plaintext file, encrypt it, and write the result to output_dir.
    (e.g. taxes.pdf → taxes.pdf.enc)

    Args:
        input_path: Path to the plaintext file to encrypt.
        passphrase: The user's passphrase. Never stored or logged.
        output_dir: Directory to write the .enc file into. Defaults to
                    the current working directory.

    Returns:
        The full path to the written .enc file.

    Raises:
        FileIOError:  If the input file cannot be read, the output directory
                      cannot be created, or the output file cannot be written.
        ValueError:   If input_path does not point to a file.
    """
    # Validate input path
    if not os.path.exists(input_path):
        raise FileIOError(f"Input file not found: {input_path!r}")

    if not os.path.isfile(input_path):
        raise FileIOError(f"Input path is not a file: {input_path!r}")

    # Read the plaintext file
    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()
    except OSError as e:
        raise FileIOError(f"Could not read input file {input_path!r}: {e}") from e

    # Extract the filename to store in the encrypted payload
    filename = os.path.basename(input_path)

    # Encrypt using crypto.py
    enc_bytes = encrypt_data(plaintext, filename, passphrase)

    # Create the output directory if it doesn't already exist.
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        raise FileIOError(
            f"Could not create output directory {output_dir!r}: {e}"
        ) from e

    # Output filename: original filename + .enc extension.
    output_filename = filename + ENCRYPTED_EXTENSION
    output_path = os.path.join(output_dir, output_filename)

    # Write the encrypted file
    try:
        with open(output_path, "wb") as f:
            f.write(enc_bytes)
    except OSError as e:
        raise FileIOError(f"Could not write encrypted file {output_path!r}: {e}") from e

    return output_path


def decrypt_file(input_path: str, passphrase: str, output_dir: str = ".") -> str:
    """
    Read an encrypted .enc file, decrypt it, and write the plaintext to output_dir.

    Args:
        input_path: Path to the .enc file to decrypt.
        passphrase: The passphrase used when the file was encrypted.
        output_dir: Directory to write the decrypted file into. Defaults to
                    the current working directory.

    Returns:
        The full path to the written plaintext file.

    Raises:
        FileIOError:      If the input file cannot be read or output cannot
                          be written.
        InvalidFileError: If the file is not a valid SecureDrive encrypted file.
        DecryptionError:  If the passphrase is wrong or the file is corrupted.
        ValueError:       If input_path does not point to a file.
    """
    # Validate input path
    if not os.path.exists(input_path):
        raise FileIOError(f"Input file not found: {input_path!r}")

    if not os.path.isfile(input_path):
        raise FileIOError(f"Input path is not a file: {input_path!r}")

    # Read the encrypted file
    try:
        with open(input_path, "rb") as f:
            enc_bytes = f.read()
    except OSError as e:
        raise FileIOError(f"Could not read encrypted file {input_path!r}: {e}") from e

    # Decrypt the file
    filename, plaintext = decrypt_data(enc_bytes, passphrase)

    # Prepare the output path
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        raise FileIOError(
            f"Could not create output directory {output_dir!r}: {e}"
        ) from e

    output_path = os.path.join(output_dir, filename)

    # Prevent overwriting an existing file
    if os.path.exists(output_path):
        raise FileIOError(
            f"Output file already exists: {output_path!r}. "
            f"Move or rename it before decrypting."
        )

    # Write the decrypted file
    try:
        with open(output_path, "wb") as f:
            f.write(plaintext)
    except OSError as e:
        raise FileIOError(f"Could not write decrypted file {output_path!r}: {e}") from e

    return output_path
