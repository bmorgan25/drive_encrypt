import os
import struct
import pytest

from crypto.crypto import (
    MAGIC,
    VERSION,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    derive_key,
    encrypt_data,
    decrypt_data,
    DecryptionError,
    InvalidFileError,
)


PASSPHRASE = "correct-horse-battery-staple-river-moon"
FILENAME = "secret_document.pdf"
PLAINTEXT = b"This is a sensitive document. Handle with care."


# Happy Path
class TestHappyPath:

    def test_basic_round_trip(self):
        """Encrypting then decrypting returns the original plaintext."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        recovered_filename, recovered_plaintext = decrypt_data(enc, PASSPHRASE)

        assert recovered_plaintext == PLAINTEXT

    def test_filename_preserved(self):
        """The original filename survives the round trip intact."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        recovered_filename, _ = decrypt_data(enc, PASSPHRASE)

        assert recovered_filename == FILENAME

    def test_output_is_bytes(self):
        """encrypt_data returns a bytes object."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        assert isinstance(enc, bytes)

    def test_ciphertext_does_not_contain_plaintext(self):
        """
        The encrypted output should not contain the plaintext anywhere —
        a basic sanity check that encryption actually happened.
        """
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        assert PLAINTEXT not in enc

    def test_ciphertext_does_not_contain_filename(self):
        """The original filename should not appear in plaintext in the output."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        assert FILENAME.encode("utf-8") not in enc

    def test_multiple_round_trips(self):
        """Encrypt and decrypt several different files without interference."""
        files = [
            (b"File one contents", "file1.txt"),
            (b"File two contents", "file2.txt"),
            (b"File three contents", "file3.txt"),
        ]
        for plaintext, filename in files:
            enc = encrypt_data(plaintext, filename, PASSPHRASE)
            recovered_filename, recovered_plaintext = decrypt_data(enc, PASSPHRASE)
            assert recovered_plaintext == plaintext
            assert recovered_filename == filename


# Passphrase Handling
class TestPassphrase:

    def test_wrong_passphrase_raises(self):
        """A wrong passphrase must raise DecryptionError, never return garbage."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)

        with pytest.raises(DecryptionError):
            decrypt_data(enc, "wrong-passphrase")

    def test_similar_passphrase_raises(self):
        """A passphrase differing by one character must fail decryption."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        similar = PASSPHRASE[:-1]  # remove last character

        with pytest.raises(DecryptionError):
            decrypt_data(enc, similar)

    def test_empty_passphrase_encrypts_and_decrypts(self):
        """
        An empty passphrase is technically valid (though inadvisable).
        The crypto layer should not forbid it — that's a UX concern for the CLI.
        """
        enc = encrypt_data(PLAINTEXT, FILENAME, "")
        _, recovered = decrypt_data(enc, "")
        assert recovered == PLAINTEXT

    def test_empty_passphrase_wrong_key_raises(self):
        """Encrypting with empty passphrase, decrypting with non-empty must fail."""
        enc = encrypt_data(PLAINTEXT, FILENAME, "")

        with pytest.raises(DecryptionError):
            decrypt_data(enc, "not-empty")

    def test_unicode_passphrase(self):
        """Passphrases with non-ASCII unicode characters should work correctly."""
        unicode_passphrase = "pässwörд-секрет-日本語"
        enc = encrypt_data(PLAINTEXT, FILENAME, unicode_passphrase)
        _, recovered = decrypt_data(enc, unicode_passphrase)
        assert recovered == PLAINTEXT

    def test_unicode_passphrase_wrong_key_raises(self):
        """A unicode passphrase with a similar but different value must fail."""
        unicode_passphrase = "pässwörд-секрет-日本語"
        enc = encrypt_data(PLAINTEXT, FILENAME, unicode_passphrase)

        with pytest.raises(DecryptionError):
            decrypt_data(enc, "passw0rd")

    def test_whitespace_passphrase(self):
        """Passphrases with spaces and tabs should round-trip correctly."""
        spaced = "   leading and trailing spaces   "
        enc = encrypt_data(PLAINTEXT, FILENAME, spaced)
        _, recovered = decrypt_data(enc, spaced)
        assert recovered == PLAINTEXT


# File Integrity (Tamper Detection)
class TestFileIntegrity:

    def test_bit_flip_in_ciphertext_raises(self):
        """
        Flipping a single bit anywhere in the ciphertext must cause decryption
        to fail. This validates that GCM authentication is working.
        """
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        tampered = bytearray(enc)

        # Flip a bit near the end of the file (well into the ciphertext region)
        tampered[-1] ^= 0x01

        with pytest.raises(DecryptionError):
            decrypt_data(bytes(tampered), PASSPHRASE)

    def test_bit_flip_in_tag_raises(self):
        """Flipping a bit in the GCM auth tag must cause decryption to fail."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        tampered = bytearray(enc)

        # The tag lives at offset 33 (after magic + version + salt + nonce)
        tag_offset = 4 + 1 + SALT_SIZE + NONCE_SIZE
        tampered[tag_offset] ^= 0xFF

        with pytest.raises(DecryptionError):
            decrypt_data(bytes(tampered), PASSPHRASE)

    def test_bit_flip_in_salt_raises(self):
        """
        Flipping a bit in the salt changes the derived key, which means
        decryption will produce the wrong key and fail auth.
        """
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        tampered = bytearray(enc)

        # Salt starts at offset 5 (after magic + version)
        tampered[5] ^= 0x01

        with pytest.raises(DecryptionError):
            decrypt_data(bytes(tampered), PASSPHRASE)

    def test_truncated_file_raises(self):
        """A file truncated to half its size must raise InvalidFileError."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        truncated = enc[: len(enc) // 2]

        with pytest.raises((InvalidFileError, DecryptionError)):
            decrypt_data(truncated, PASSPHRASE)

    def test_empty_input_raises(self):
        """Passing empty bytes must raise InvalidFileError."""
        with pytest.raises(InvalidFileError):
            decrypt_data(b"", PASSPHRASE)

    def test_random_bytes_raises(self):
        """Passing random bytes that aren't an encrypted file must raise InvalidFileError."""
        with pytest.raises(InvalidFileError):
            decrypt_data(os.urandom(256), PASSPHRASE)

    def test_plaintext_file_raises(self):
        """Passing a plaintext file (not encrypted) must raise InvalidFileError."""
        with pytest.raises(InvalidFileError):
            decrypt_data(PLAINTEXT, PASSPHRASE)


# Header Validation
class TestHeaderValidation:

    def test_wrong_magic_bytes_raises(self):
        """A file with wrong magic bytes must raise InvalidFileError."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        bad_magic = b"XXXX" + enc[4:]

        with pytest.raises(InvalidFileError):
            decrypt_data(bad_magic, PASSPHRASE)

    def test_magic_bytes_present_in_output(self):
        """The encrypted output must start with the magic bytes."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        assert enc[:4] == MAGIC

    def test_version_byte_present_in_output(self):
        """The version byte at offset 4 must match VERSION."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        version = struct.unpack(">B", enc[4:5])[0]
        assert version == VERSION

    def test_unsupported_version_raises(self):
        """A file with a version number we don't recognize must raise InvalidFileError."""
        enc = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        bad_version = enc[:4] + struct.pack(">B", 99) + enc[5:]

        with pytest.raises(InvalidFileError):
            decrypt_data(bad_version, PASSPHRASE)


# Determinism and Uniqueness
class TestDeterminism:

    def test_same_input_produces_different_ciphertext(self):
        """
        Encrypting the same plaintext twice must produce different ciphertext
        each time, because a fresh random salt and nonce are generated per call.
        This prevents pattern analysis across files.
        """
        enc1 = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        enc2 = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)

        assert enc1 != enc2

    def test_different_salts_produce_different_keys(self):
        """
        The same passphrase with two different salts must produce different keys.
        This is the whole point of the salt.
        """
        salt1 = os.urandom(SALT_SIZE)
        salt2 = os.urandom(SALT_SIZE)

        key1 = derive_key(PASSPHRASE, salt1)
        key2 = derive_key(PASSPHRASE, salt2)

        assert key1 != key2

    def test_same_passphrase_and_salt_produces_same_key(self):
        """
        Derivation must be deterministic: the same passphrase + salt always
        produces the same key. This is what makes decryption possible.
        """
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key(PASSPHRASE, salt)
        key2 = derive_key(PASSPHRASE, salt)

        assert key1 == key2

    def test_both_encryptions_still_decrypt_correctly(self):
        """Even though ciphertext differs each time, both must decrypt correctly."""
        enc1 = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)
        enc2 = encrypt_data(PLAINTEXT, FILENAME, PASSPHRASE)

        _, pt1 = decrypt_data(enc1, PASSPHRASE)
        _, pt2 = decrypt_data(enc2, PASSPHRASE)

        assert pt1 == PLAINTEXT
        assert pt2 == PLAINTEXT


# Boundary Conditions
class TestBoundaryConditions:

    def test_empty_file_round_trip(self):
        """An empty file (0 bytes) must encrypt and decrypt without error."""
        enc = encrypt_data(b"", FILENAME, PASSPHRASE)
        _, recovered = decrypt_data(enc, PASSPHRASE)
        assert recovered == b""

    def test_single_byte_file(self):
        """A single-byte file must round-trip correctly."""
        enc = encrypt_data(b"\x00", FILENAME, PASSPHRASE)
        _, recovered = decrypt_data(enc, PASSPHRASE)
        assert recovered == b"\x00"

    def test_binary_file_round_trip(self):
        """Binary data (e.g. a PDF or image) must survive the round trip intact."""
        binary_data = os.urandom(4096)
        enc = encrypt_data(binary_data, "photo.jpg", PASSPHRASE)
        _, recovered = decrypt_data(enc, PASSPHRASE)
        assert recovered == binary_data

    def test_large_file_round_trip(self):
        """A 1 MB file must encrypt and decrypt correctly."""
        large_data = os.urandom(1024 * 1024)  # 1 MB
        enc = encrypt_data(large_data, "large_file.bin", PASSPHRASE)
        _, recovered = decrypt_data(enc, PASSPHRASE)
        assert recovered == large_data

    def test_unicode_filename_round_trip(self):
        """Filenames with non-ASCII characters must survive the round trip."""
        unicode_filename = "机密文件_тайный_документ.pdf"
        enc = encrypt_data(PLAINTEXT, unicode_filename, PASSPHRASE)
        recovered_filename, _ = decrypt_data(enc, PASSPHRASE)
        assert recovered_filename == unicode_filename

    def test_long_filename_round_trip(self):
        """A filename at the typical filesystem limit (255 chars) must work."""
        long_filename = "a" * 251 + ".txt"  # 255 chars total
        enc = encrypt_data(PLAINTEXT, long_filename, PASSPHRASE)
        recovered_filename, _ = decrypt_data(enc, PASSPHRASE)
        assert recovered_filename == long_filename

    def test_filename_with_spaces_and_symbols(self):
        """Filenames with spaces, dots, and special characters must round-trip."""
        filename = "My Secret Doc (2024) - FINAL v2.pdf"
        enc = encrypt_data(PLAINTEXT, filename, PASSPHRASE)
        recovered_filename, _ = decrypt_data(enc, PASSPHRASE)
        assert recovered_filename == filename


# Key Derivation Validation
class TestKeyDerivation:

    def test_derived_key_is_correct_length(self):
        """derive_key must return exactly KEY_SIZE (32) bytes."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key(PASSPHRASE, salt)
        assert len(key) == KEY_SIZE

    def test_derived_key_is_bytes(self):
        """derive_key must return a bytes object."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key(PASSPHRASE, salt)
        assert isinstance(key, bytes)

    def test_wrong_salt_size_raises(self):
        """Passing a salt of the wrong size must raise ValueError."""
        bad_salt = os.urandom(8)  # too short

        with pytest.raises(ValueError):
            derive_key(PASSPHRASE, bad_salt)

    def test_key_is_not_passphrase(self):
        """The derived key must not be a simple encoding of the passphrase."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key(PASSPHRASE, salt)
        assert key != PASSPHRASE.encode("utf-8")

    def test_argon2_parameters_are_at_minimum_owasp(self):
        """
        Validate that the Argon2id parameters meet OWASP minimums.
        This test acts as a guard against accidentally weakening params
        during development.
        """
        assert ARGON2_TIME_COST >= 2, "time_cost below OWASP minimum of 2"
        assert ARGON2_MEMORY_COST >= 19456, "memory_cost below OWASP minimum of 19 MB"
        assert ARGON2_PARALLELISM >= 1, "parallelism must be at least 1"
        assert KEY_SIZE == 32, "KEY_SIZE must be 32 bytes for AES-256"
        assert SALT_SIZE >= 16, "SALT_SIZE must be at least 16 bytes"
        assert NONCE_SIZE == 12, "NONCE_SIZE must be 12 bytes for AES-GCM"
