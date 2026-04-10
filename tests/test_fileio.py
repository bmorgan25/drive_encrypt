import os
import pytest

from fileio.fileio import (
    encrypt_file,
    decrypt_file,
    ENCRYPTED_EXTENSION,
    FileIOError,
)
from crypto.crypto import DecryptionError, InvalidFileError


PASSPHRASE = "correct-horse-battery-staple-river-moon"
PLAINTEXT = b"Sensitive document contents. Do not share."
FILENAME = "secret.txt"


@pytest.fixture
def plaintext_file(tmp_path):
    """Write a plaintext file to a temp directory and return its path."""
    file_path = tmp_path / FILENAME
    file_path.write_bytes(PLAINTEXT)
    return str(file_path)


@pytest.fixture
def encrypted_file(tmp_path, plaintext_file):
    """Encrypt a plaintext file and return the path to the .enc file."""
    enc_dir = str(tmp_path / "encrypted")
    return encrypt_file(plaintext_file, PASSPHRASE, enc_dir)


# Encrypt File
class TestEncryptFile:

    def test_returns_output_path(self, plaintext_file, tmp_path):
        """encrypt_file returns the path to the written .enc file."""
        out_dir = str(tmp_path / "out")
        result = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        assert isinstance(result, str)

    def test_output_file_exists(self, plaintext_file, tmp_path):
        """The .enc file must actually exist on disk after encryption."""
        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        assert os.path.isfile(out_path)

    def test_output_has_enc_extension(self, plaintext_file, tmp_path):
        """The output file must end with the .enc extension."""
        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        assert out_path.endswith(ENCRYPTED_EXTENSION)

    def test_output_filename_based_on_input(self, plaintext_file, tmp_path):
        """Output filename must be the original filename + .enc."""
        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        assert os.path.basename(out_path) == FILENAME + ENCRYPTED_EXTENSION

    def test_output_is_not_plaintext(self, plaintext_file, tmp_path):
        """The .enc file must not contain the original plaintext."""
        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        enc_bytes = open(out_path, "rb").read()
        assert PLAINTEXT not in enc_bytes

    def test_output_does_not_contain_filename(self, plaintext_file, tmp_path):
        """The .enc file must not expose the original filename in plaintext."""
        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        enc_bytes = open(out_path, "rb").read()
        assert FILENAME.encode() not in enc_bytes

    def test_creates_output_directory(self, plaintext_file, tmp_path):
        """encrypt_file must create the output directory if it doesn't exist."""
        out_dir = str(tmp_path / "new" / "nested" / "dir")
        assert not os.path.exists(out_dir)
        encrypt_file(plaintext_file, PASSPHRASE, out_dir)
        assert os.path.isdir(out_dir)

    def test_encrypting_same_file_twice_produces_different_output(
        self, plaintext_file, tmp_path
    ):
        """
        Two encryptions of the same file must produce different ciphertext
        due to fresh random salt and nonce each time.
        """
        out1 = str(tmp_path / "out1")
        out2 = str(tmp_path / "out2")
        path1 = encrypt_file(plaintext_file, PASSPHRASE, out1)
        path2 = encrypt_file(plaintext_file, PASSPHRASE, out2)
        assert open(path1, "rb").read() != open(path2, "rb").read()

    def test_binary_file(self, tmp_path):
        """Binary files (e.g. images, PDFs) must encrypt without error."""
        binary_data = os.urandom(2048)
        bin_path = str(tmp_path / "photo.jpg")
        open(bin_path, "wb").write(binary_data)

        out_dir = str(tmp_path / "out")
        out_path = encrypt_file(bin_path, PASSPHRASE, out_dir)
        assert os.path.isfile(out_path)


# Decrypt File
class TestDecryptFile:

    def test_returns_output_path(self, encrypted_file, tmp_path):
        """decrypt_file returns the path to the written plaintext file."""
        out_dir = str(tmp_path / "decrypted")
        result = decrypt_file(encrypted_file, PASSPHRASE, out_dir)
        assert isinstance(result, str)

    def test_output_file_exists(self, encrypted_file, tmp_path):
        """The decrypted file must actually exist on disk."""
        out_dir = str(tmp_path / "decrypted")
        out_path = decrypt_file(encrypted_file, PASSPHRASE, out_dir)
        assert os.path.isfile(out_path)

    def test_decrypted_contents_match_original(self, encrypted_file, tmp_path):
        """The decrypted file contents must exactly match the original plaintext."""
        out_dir = str(tmp_path / "decrypted")
        out_path = decrypt_file(encrypted_file, PASSPHRASE, out_dir)
        assert open(out_path, "rb").read() == PLAINTEXT

    def test_original_filename_recovered(self, encrypted_file, tmp_path):
        """The decrypted file must be written under the original filename."""
        out_dir = str(tmp_path / "decrypted")
        out_path = decrypt_file(encrypted_file, PASSPHRASE, out_dir)
        assert os.path.basename(out_path) == FILENAME

    def test_wrong_passphrase_raises(self, encrypted_file, tmp_path):
        """A wrong passphrase must raise DecryptionError."""
        out_dir = str(tmp_path / "decrypted")
        with pytest.raises(DecryptionError):
            decrypt_file(encrypted_file, "wrong-passphrase", out_dir)

    def test_creates_output_directory(self, encrypted_file, tmp_path):
        """decrypt_file must create the output directory if it doesn't exist."""
        out_dir = str(tmp_path / "new" / "nested" / "dir")
        assert not os.path.exists(out_dir)
        decrypt_file(encrypted_file, PASSPHRASE, out_dir)
        assert os.path.isdir(out_dir)

    def test_non_encrypted_file_raises(self, plaintext_file, tmp_path):
        """Passing a plaintext file to decrypt_file must raise InvalidFileError."""
        out_dir = str(tmp_path / "decrypted")
        with pytest.raises(InvalidFileError):
            decrypt_file(plaintext_file, PASSPHRASE, out_dir)


# Overwrite Guard
class TestOverwriteGuard:

    def test_raises_if_output_file_exists(self, encrypted_file, tmp_path):
        """
        decrypt_file must raise FileIOError if the output file already exists,
        to prevent accidental data loss from silent overwrites.
        """
        out_dir = str(tmp_path / "decrypted")
        os.makedirs(out_dir, exist_ok=True)

        # Pre-create a file at the would-be output path
        conflict_path = os.path.join(out_dir, FILENAME)
        open(conflict_path, "wb").write(b"existing content")

        with pytest.raises(FileIOError, match="already exists"):
            decrypt_file(encrypted_file, PASSPHRASE, out_dir)

    def test_existing_file_not_overwritten(self, encrypted_file, tmp_path):
        """The existing file must remain untouched after the FileIOError."""
        out_dir = str(tmp_path / "decrypted")
        os.makedirs(out_dir, exist_ok=True)

        existing_content = b"do not touch me"
        conflict_path = os.path.join(out_dir, FILENAME)
        open(conflict_path, "wb").write(existing_content)

        with pytest.raises(FileIOError):
            decrypt_file(encrypted_file, PASSPHRASE, out_dir)

        # File must still have its original content
        assert open(conflict_path, "rb").read() == existing_content


# Input Validation
class TestInputValidation:

    def test_encrypt_missing_file_raises(self, tmp_path):
        """encrypt_file must raise FileIOError for a nonexistent input path."""
        with pytest.raises(FileIOError, match="not found"):
            encrypt_file(str(tmp_path / "ghost.txt"), PASSPHRASE, str(tmp_path))

    def test_decrypt_missing_file_raises(self, tmp_path):
        """decrypt_file must raise FileIOError for a nonexistent input path."""
        with pytest.raises(FileIOError, match="not found"):
            decrypt_file(str(tmp_path / "ghost.enc"), PASSPHRASE, str(tmp_path))

    def test_encrypt_directory_as_input_raises(self, tmp_path):
        """Passing a directory path to encrypt_file must raise FileIOError."""
        with pytest.raises(FileIOError, match="not a file"):
            encrypt_file(str(tmp_path), PASSPHRASE, str(tmp_path / "out"))

    def test_decrypt_directory_as_input_raises(self, tmp_path):
        """Passing a directory path to decrypt_file must raise FileIOError."""
        with pytest.raises(FileIOError, match="not a file"):
            decrypt_file(str(tmp_path), PASSPHRASE, str(tmp_path / "out"))


# Full Round Trip via Disk
class TestRoundTrip:

    def test_full_round_trip(self, tmp_path):
        """Encrypt to disk then decrypt from disk — contents and filename match."""
        # Write original file
        original = tmp_path / "report.pdf"
        original.write_bytes(PLAINTEXT)

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        enc_path = encrypt_file(str(original), PASSPHRASE, enc_dir)
        dec_path = decrypt_file(enc_path, PASSPHRASE, dec_dir)

        assert open(dec_path, "rb").read() == PLAINTEXT
        assert os.path.basename(dec_path) == "report.pdf"

    def test_round_trip_binary_file(self, tmp_path):
        """Binary files survive a full encrypt → decrypt cycle intact."""
        binary_data = os.urandom(4096)
        original = tmp_path / "photo.jpg"
        original.write_bytes(binary_data)

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        enc_path = encrypt_file(str(original), PASSPHRASE, enc_dir)
        dec_path = decrypt_file(enc_path, PASSPHRASE, dec_dir)

        assert open(dec_path, "rb").read() == binary_data

    def test_round_trip_unicode_filename(self, tmp_path):
        """Files with unicode filenames survive a full round trip."""
        unicode_name = "机密文件.txt"
        original = tmp_path / unicode_name
        original.write_bytes(PLAINTEXT)

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        enc_path = encrypt_file(str(original), PASSPHRASE, enc_dir)
        dec_path = decrypt_file(enc_path, PASSPHRASE, dec_dir)

        assert os.path.basename(dec_path) == unicode_name
        assert open(dec_path, "rb").read() == PLAINTEXT

    def test_round_trip_empty_file(self, tmp_path):
        """An empty file survives a full round trip."""
        original = tmp_path / "empty.txt"
        original.write_bytes(b"")

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        enc_path = encrypt_file(str(original), PASSPHRASE, enc_dir)
        dec_path = decrypt_file(enc_path, PASSPHRASE, dec_dir)

        assert open(dec_path, "rb").read() == b""

    def test_multiple_files_round_trip(self, tmp_path):
        """Multiple files can be encrypted and decrypted independently."""
        files = {
            "doc1.txt": b"Document one",
            "doc2.txt": b"Document two",
            "doc3.txt": b"Document three",
        }

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        for name, content in files.items():
            original = tmp_path / name
            original.write_bytes(content)
            enc_path = encrypt_file(str(original), PASSPHRASE, enc_dir)
            dec_path = decrypt_file(enc_path, PASSPHRASE, dec_dir)
            assert open(dec_path, "rb").read() == content
