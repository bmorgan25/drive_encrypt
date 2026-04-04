import os
import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Current drive_encrypt version
VERSION = 0x01

# Magic bytes
MAGIC = b"DREN"

# 128-bit salt fed to Argon2id
SALT_SIZE = 16
# 256-bit AES key derived from the passphrase
KEY_SIZE = 32
# 96-bit nonce for AES-GCM
NONCE_SIZE = 12
# 128-bit GCM authentication tag
TAG_SIZE = 16

# These values follow OWASP's current minimum recommendations.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB in KB
ARGON2_PARALLELISM = 4


class DecryptionError(Exception):
    """
    Raised when decryption fails. This covers two cases:
      1. Wrong passphrase — the derived key won't match, so GCM auth fails.
      2. Corrupted ciphertext — the auth tag won't verify.
    We intentionally use a single exception for both cases to avoid leaking
    information about *why* decryption failed.
    """

    pass


class InvalidFileError(Exception):
    """
    Raised when the file header is malformed — wrong magic bytes, unsupported
    version, or a truncated file. Distinct from DecryptionError so callers
    can give a clearer error message (e.g. "this isn't an encrypted file").
    """

    pass


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key using Argon2id.

    Args:
        passphrase: The user's plaintext passphrase.
        salt:       A random 16-byte salt. Must be unique per encryption
                    operation. Not secret — stored in the file header.

    Returns:
        A 32-byte key suitable for AES-256.
    """

    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes... Got {len(salt)}")

    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,  # Type.ID = Argon2id
    )

    return key


def encrypt_data(plaintext: bytes, filename: str, passphrase: str) -> bytes:
    """
    Encrypt plaintext bytes and return the full encrypted payload,
    including the header containing all metadata needed for decryption.

    Args:
        plaintext:  Raw bytes of the file to encrypt.
        filename:   Original filename (stored encrypted inside the payload).
        passphrase: The user's passphrase.

    Returns:
        A bytes object containing the full header + ciphertext.
    """

    # Generate fresh random salt and nonce for this encryption operation.
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(passphrase, salt)

    # Encode the filename and build the inner payload
    filename_bytes = filename.encode("utf-8")
    inner_payload = struct.pack(">Q", len(filename_bytes)) + filename_bytes + plaintext

    # Encrypt the plaintext with AES-256-GCM.
    aesgcm = AESGCM(key)
    # returns a 16 byte auth tag
    ciphertext_with_tag = aesgcm.encrypt(nonce, inner_payload, None)

    # Split the ciphertext and tag
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]

    # Build the binary header
    header = MAGIC + struct.pack(">B", VERSION) + salt + nonce + tag

    return header + ciphertext


def decrypt_data(enc_bytes: bytes, passphrase: str) -> tuple[str, bytes]:
    """
    Decrypt an ecrypted payload

    """

    # Validatation

    min_header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE + 8 + 8

    if len(enc_bytes) < min_header_size:
        raise InvalidFileError("File is too short to be a valid encrypted file.")

    if enc_bytes[:4] != MAGIC:
        raise InvalidFileError(
            f"Unrecognized file format. Expected magic bytes {MAGIC!r}, "
            f"got {enc_bytes[:4]!r}. Is this a drive_encrypt encrypted file?"
        )

    version = struct.unpack(">B", enc_bytes[4:5])[0]
    if version != VERSION:
        raise InvalidFileError(
            f"Unsupported file version {version}. This tool supports version {VERSION}."
        )

    # Parse header fields at their known offsets
    offset = 5  # Magic (4) + Version (1)

    salt = enc_bytes[offset : offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = enc_bytes[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    tag = enc_bytes[offset : offset + TAG_SIZE]
    offset += TAG_SIZE

    ciphertext = enc_bytes[offset:]

    # Re-derive the key and decrypt
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        inner_payload = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        raise DecryptionError(
            "Decryption failed. The passphrase may be incorrect, or the file "
            "may be corrupted."
        )

    # Inner layout: filename_length (8) | filename (N) | plaintext (M)
    inner_offset = 0
    (filename_len,) = struct.unpack(
        ">Q", inner_payload[inner_offset : inner_offset + 8]
    )
    inner_offset += 8

    if inner_offset + filename_len > len(inner_payload):
        raise InvalidFileError(
            "Decrypted payload is malformed (filename length out of bounds)."
        )

    filename = inner_payload[inner_offset : inner_offset + filename_len].decode("utf-8")
    inner_offset += filename_len

    plaintext = inner_payload[inner_offset:]

    return filename, plaintext
