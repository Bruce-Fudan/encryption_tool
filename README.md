# AES-256-GCM Encryption Tool

A lightweight, fully offline text/file encryption tool.
Protect what you send before you send it.


## What it does
- Encrypt / decrypt **text** (Base64 output, easy to paste anywhere)
- Encrypt / decrypt **files** of any type, streaming for large files
- Two KDFs: **Argon2id** (default, recommended) and **PBKDF2** (legacy)
- AES-256-GCM with authentication tag — any tampering is detected

## What it does NOT do
- No network access. No telemetry. No accounts.

Everything happens locally on your machine.

## Requirements
- Python 3.9+
- `pip install -r requirements.txt`

## Usage
```bash
python aes_gcm_tool.py
