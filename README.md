# SecureDrive

Zero-knowledge local encryption for Google Drive. Files are encrypted on your machine before they ever leave it — Google Drive only ever sees ciphertext.

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| 1 | Local encrypt / decrypt CLI | ✅ Complete |
| 2 | Google Drive integration | 🔜 Up next |
| 3 | Desktop UI | 🔜 Planned |

---

## Security Design

- **Passphrase never stored.** It is fed into Argon2id at runtime to derive a 32-byte AES-256 key. The key exists only in memory during an encrypt or decrypt operation.
- **Fresh salt and nonce per operation.** Encrypting the same file twice with the same passphrase produces completely different ciphertext each time, preventing pattern analysis.
- **AES-256-GCM** provides both confidentiality (encryption) and integrity (authentication tag). A wrong passphrase or corrupted file will always raise an exception — garbage data is never silently returned.
- **Filename encryption.** The original filename is stored inside the encrypted payload, not in the file header. It is never readable without the correct passphrase.

### Key Derivation — Argon2id Parameters

| Parameter | Value | Purpose |
|---|---|---|
| `time_cost` | 3 | CPU work factor |
| `memory_cost` | 64 MB | Kills GPU-based brute force |
| `parallelism` | 4 | Threads used internally |
| `hash_length` | 32 bytes | Output size = AES-256 key |
| `salt_length` | 16 bytes | Randomly generated per file |

---

## File Format

### Outer file (plaintext header + ciphertext)

```
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size   Field                                        │
│ ──────────────────────────────────────────────────────────  │
│ 0       4      Magic bytes: b"SDRV"                         │
│ 4       1      Version byte: 0x01                           │
│ 5       16     Salt (random, generated per encryption)      │
│ 21      12     Nonce / IV (random, generated per encryption)│
│ 33      16     GCM authentication tag                       │
│ 49      M      Ciphertext (encrypts inner payload below)    │
└─────────────────────────────────────────────────────────────┘
```

### Inner payload (encrypted — not readable without passphrase)

```
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size   Field                                        │
│ ──────────────────────────────────────────────────────────  │
│ 0       8      Filename length (big-endian uint64)          │
│ 8       N      Original filename (UTF-8 encoded)            │
│ 8+N     M      File plaintext                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
secure_drive/
├── main.py                  # CLI entry point
├── conftest.py              # Pytest root marker
├── requirements.txt
├── crypto/
│   ├── __init__.py
│   └── crypto.py            # Argon2id key derivation + AES-256-GCM encrypt/decrypt
├── fileio/
│   ├── __init__.py
│   └── fileio.py            # Disk I/O — reading/writing plaintext and .enc files
├── commands/
│   ├── __init__.py
│   ├── encrypt_cmd.py       # `encrypt` CLI command
│   └── decrypt_cmd.py       # `decrypt` CLI command
└── tests/
    ├── __init__.py
    ├── test_crypto.py
    ├── test_fileio.py
    └── test_cli.py
```

---

## Setup

**Requirements:** Python 3.10+

```bash
# Clone the repo
git clone https://github.com/yourusername/secure_drive.git
cd secure_drive

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**`requirements.txt`**
```
argon2-cffi
cryptography
click
pytest
```

---

## Usage

### Encrypt a file

```bash
python main.py encrypt path/to/file.pdf
```

Writes the encrypted file to `encrypted/file.pdf.enc` by default.

```bash
# Specify a custom output directory
python main.py encrypt path/to/file.pdf --output-dir my_encrypted_files/
```

### Decrypt a file

```bash
python main.py decrypt encrypted/file.pdf.enc
```

Writes the decrypted file to `decrypted/` under its original filename by default.

```bash
# Specify a custom output directory
python main.py decrypt encrypted/file.pdf.enc --output-dir my_decrypted_files/
```

### Help

```bash
python main.py --help
python main.py encrypt --help
python main.py decrypt --help
```

---

## Running Tests

```bash
pytest tests/ -v
```

All three test modules run together. Tests use temporary directories and never touch your real files.

---

## Important Notes

**`.enc` files are binary — do not open them in a text editor.** Tools like vim may silently append a newline or modify bytes on save, which will corrupt the file and cause decryption to fail. To inspect an encrypted file safely, use a hex viewer:

```bash
xxd encrypted/file.pdf.enc | head -20
```

You should see the `SDRV` magic bytes at the start:
```
00000000  53 44 52 56 01 ...
          S  D  R  V  version
```

**If you forget your passphrase, your data is unrecoverable.** There is no password reset. Store your passphrase somewhere safe — a password manager or written down in a physically secure location.

---

## Threat Model

| Threat | Protected? |
|---|---|
| Google Drive breach — ciphertext stolen | ✅ Yes — useless without passphrase |
| Filename / metadata exposure in Drive | ✅ Yes — filename is encrypted in payload |
| Brute-force against weak passphrase | ⚠️ Partial — Argon2id slows attacks significantly, but a weak passphrase is still a risk |
| Attacker with access to your unlocked machine | ❌ No — they can run the tool directly |
| Forgotten passphrase | ❌ No — data is permanently unrecoverable |