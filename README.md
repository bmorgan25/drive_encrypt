# drive_encrypt

Design:
  - Passphrase is never stored anywhere. It is fed into Argon2id at
    runtime to derive a 32-byte AES-256 key.
  - Every encrypt operation generates a fresh random salt and nonce,
    so encrypting the same file twice with the same passphrase produces
    completely different ciphertext each time.
  - AES-256-GCM provides both confidentiality (encryption) and
    integrity (authentication tag). A wrong passphrase or corrupted
    file will raise an exception — it will never silently return
    garbage data.

File format produced by encrypt_data():
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
 
  Inner payload (encrypted, not visible without passphrase):
```
  ┌─────────────────────────────────────────────────────────────┐
  │ Offset  Size   Field                                        │
  │ ──────────────────────────────────────────────────────────  │
  │ 0       8      Filename length (big-endian uint64)          │
  │ 8       N      Original filename (UTF-8 encoded)            │
  │ 8+N     M      File plaintext                               │
  └─────────────────────────────────────────────────────────────┘
 ```
  The filename is part of the encrypted payload, so it is never
  readable without the correct passphrase.