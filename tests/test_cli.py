import os
import pytest
from unittest.mock import patch
from click.testing import CliRunner

from main import cli


PASSPHRASE = "correct-horse-battery-staple-river-moon"
PLAINTEXT = b"Top secret document contents."
FILENAME = "secret.txt"


@pytest.fixture
def runner():
    """Click CLI test runner — captures output and exit codes."""
    return CliRunner()


@pytest.fixture
def plaintext_file(tmp_path):
    """Write a plaintext file to a temp dir and return its path."""
    path = tmp_path / FILENAME
    path.write_bytes(PLAINTEXT)
    return str(path)


@pytest.fixture
def encrypted_file(tmp_path, plaintext_file):
    """Encrypt a file via the CLI and return the path to the .enc output."""
    runner = CliRunner()
    enc_dir = str(tmp_path / "encrypted")

    with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
        result = runner.invoke(
            cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
        )

    assert result.exit_code == 0, result.output
    return os.path.join(enc_dir, FILENAME + ".enc")


# Encrypt Command
class TestEncryptCommand:

    def test_encrypt_happy_path(self, runner, plaintext_file, tmp_path):
        """Successful encryption exits with code 0."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert result.exit_code == 0

    def test_encrypt_output_file_created(self, runner, plaintext_file, tmp_path):
        """The .enc file must exist on disk after a successful encrypt."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            runner.invoke(cli, ["encrypt", plaintext_file, "--output-dir", enc_dir])
        assert os.path.isfile(os.path.join(enc_dir, FILENAME + ".enc"))

    def test_encrypt_success_message(self, runner, plaintext_file, tmp_path):
        """A success message must appear in output on successful encryption."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert "Done" in result.output

    def test_encrypt_shows_input_and_output(self, runner, plaintext_file, tmp_path):
        """The command must display the input file and output directory."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert plaintext_file in result.output
        assert enc_dir in result.output

    def test_encrypt_mismatched_passphrases(self, runner, plaintext_file, tmp_path):
        """Mismatched passphrase confirmation must exit with code 1."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=[PASSPHRASE, "wrong-confirm"]):
            result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert result.exit_code == 1
        assert "do not match" in result.output.lower()

    def test_encrypt_empty_passphrase(self, runner, plaintext_file, tmp_path):
        """An empty passphrase must exit with code 1."""
        enc_dir = str(tmp_path / "encrypted")
        with patch("getpass.getpass", side_effect=["", ""]):
            result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert result.exit_code == 1
        assert "empty" in result.output.lower()

    def test_encrypt_nonexistent_input_file(self, runner, tmp_path):
        """Passing a nonexistent file must exit with a non-zero code."""
        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            result = runner.invoke(cli, ["encrypt", str(tmp_path / "ghost.txt")])
        assert result.exit_code != 0

    def test_encrypt_default_output_dir(self, runner, plaintext_file, tmp_path):
        """Omitting --output-dir uses 'encrypted' as the default."""
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        try:
            with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
                result = runner.invoke(cli, ["encrypt", plaintext_file])
            assert result.exit_code == 0
            assert os.path.isfile(
                os.path.join(tmp_path, "encrypted", FILENAME + ".enc")
            )
        finally:
            os.chdir(original_dir)


# Decrypt Command
class TestDecryptCommand:

    def test_decrypt_happy_path(self, runner, encrypted_file, tmp_path):
        """Successful decryption exits with code 0."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            result = runner.invoke(
                cli, ["decrypt", encrypted_file, "--output-dir", dec_dir]
            )
        assert result.exit_code == 0

    def test_decrypt_output_file_created(self, runner, encrypted_file, tmp_path):
        """The decrypted file must exist on disk after a successful decrypt."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            runner.invoke(cli, ["decrypt", encrypted_file, "--output-dir", dec_dir])
        assert os.path.isfile(os.path.join(dec_dir, FILENAME))

    def test_decrypt_contents_match_original(self, runner, encrypted_file, tmp_path):
        """The decrypted file contents must match the original plaintext."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            runner.invoke(cli, ["decrypt", encrypted_file, "--output-dir", dec_dir])
        assert open(os.path.join(dec_dir, FILENAME), "rb").read() == PLAINTEXT

    def test_decrypt_success_message(self, runner, encrypted_file, tmp_path):
        """A success message must appear in output on successful decryption."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            result = runner.invoke(
                cli, ["decrypt", encrypted_file, "--output-dir", dec_dir]
            )
        assert "Done" in result.output

    def test_decrypt_wrong_passphrase(self, runner, encrypted_file, tmp_path):
        """A wrong passphrase must exit with code 1 and show an error."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value="wrong-passphrase"):
            result = runner.invoke(
                cli, ["decrypt", encrypted_file, "--output-dir", dec_dir]
            )
        assert result.exit_code == 1

    def test_decrypt_wrong_passphrase_no_output_file(
        self, runner, encrypted_file, tmp_path
    ):
        """No output file must be written when decryption fails."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value="wrong-passphrase"):
            runner.invoke(cli, ["decrypt", encrypted_file, "--output-dir", dec_dir])
        assert not os.path.isfile(os.path.join(dec_dir, FILENAME))

    def test_decrypt_invalid_file(self, runner, plaintext_file, tmp_path):
        """Passing a non-.enc file must exit with code 1."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            result = runner.invoke(
                cli, ["decrypt", plaintext_file, "--output-dir", dec_dir]
            )
        assert result.exit_code == 1

    def test_decrypt_empty_passphrase(self, runner, encrypted_file, tmp_path):
        """An empty passphrase must exit with code 1."""
        dec_dir = str(tmp_path / "decrypted")
        with patch("getpass.getpass", return_value=""):
            result = runner.invoke(
                cli, ["decrypt", encrypted_file, "--output-dir", dec_dir]
            )
        assert result.exit_code == 1

    def test_decrypt_default_output_dir(self, runner, encrypted_file, tmp_path):
        """Omitting --output-dir uses 'decrypted' as the default."""
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        try:
            with patch("getpass.getpass", return_value=PASSPHRASE):
                result = runner.invoke(cli, ["decrypt", encrypted_file])
            assert result.exit_code == 0
            assert os.path.isfile(os.path.join(tmp_path, "decrypted", FILENAME))
        finally:
            os.chdir(original_dir)


# CLI Structure
class TestCLIStructure:

    def test_help_exits_zero(self, runner):
        """--help must exit with code 0."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_help_shows_commands(self, runner):
        """--help must list the encrypt and decrypt commands."""
        result = runner.invoke(cli, ["--help"])
        assert "encrypt" in result.output
        assert "decrypt" in result.output

    def test_encrypt_help(self, runner):
        """encrypt --help must exit with code 0 and show usage."""
        result = runner.invoke(cli, ["encrypt", "--help"])
        assert result.exit_code == 0
        assert "INPUT_FILE" in result.output

    def test_decrypt_help(self, runner):
        """decrypt --help must exit with code 0 and show usage."""
        result = runner.invoke(cli, ["decrypt", "--help"])
        assert result.exit_code == 0
        assert "INPUT_FILE" in result.output

    def test_unknown_command(self, runner):
        """An unknown command must exit with a non-zero code."""
        result = runner.invoke(cli, ["unknowncmd"])
        assert result.exit_code != 0


# Full Round Trip via CLI
class TestCLIRoundTrip:

    def test_full_round_trip(self, runner, plaintext_file, tmp_path):
        """Encrypt then decrypt via CLI produces byte-identical output."""
        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
            enc_result = runner.invoke(
                cli, ["encrypt", plaintext_file, "--output-dir", enc_dir]
            )
        assert enc_result.exit_code == 0

        enc_path = os.path.join(enc_dir, FILENAME + ".enc")
        with patch("getpass.getpass", return_value=PASSPHRASE):
            dec_result = runner.invoke(
                cli, ["decrypt", enc_path, "--output-dir", dec_dir]
            )
        assert dec_result.exit_code == 0

        recovered = open(os.path.join(dec_dir, FILENAME), "rb").read()
        assert recovered == PLAINTEXT

    def test_round_trip_multiple_files(self, runner, tmp_path):
        """Multiple files can be encrypted and decrypted independently via CLI."""
        files = {
            "report.txt": b"Annual report contents",
            "notes.txt": b"Private notes",
        }

        enc_dir = str(tmp_path / "encrypted")
        dec_dir = str(tmp_path / "decrypted")

        for name, content in files.items():
            file_path = str(tmp_path / name)
            open(file_path, "wb").write(content)

            with patch("getpass.getpass", side_effect=[PASSPHRASE, PASSPHRASE]):
                runner.invoke(cli, ["encrypt", file_path, "--output-dir", enc_dir])

            enc_path = os.path.join(enc_dir, name + ".enc")
            with patch("getpass.getpass", return_value=PASSPHRASE):
                runner.invoke(cli, ["decrypt", enc_path, "--output-dir", dec_dir])

            recovered = open(os.path.join(dec_dir, name), "rb").read()
            assert recovered == content
