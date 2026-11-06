# password-manager

A simple command-line password manager written in Python, built for a university lab assignment.

Entries (login + password) are stored locally in an encrypted vault file (`vault.json` by default). The vault is protected by a master password, which is never stored in plain text:

- The master password is verified using a salted PBKDF2-HMAC-SHA256 hash.
- A separate key, derived from the master password with its own salt, is used with Fernet (AES-based) symmetric encryption to encrypt/decrypt each stored entry.
- Master-password input is hidden (via `getpass`), never echoed to the terminal.

## Requirements

- Python >= 3.10
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync
```

## Usage

Create a new vault (asks for a new master password):

```bash
uv run password-manager --init
```

Running `--init` again on an existing vault lets you reset the master password: it will ask for the current password first, then the new one.

Unlock the vault and open the interactive menu (add / list / get / delete entries):

```bash
uv run password-manager --unlock
```

Generate a random password without touching the vault:

```bash
uv run password-manager --generate --length 20
```

Use a custom vault file location:

```bash
uv run password-manager --unlock --path my-vault.json
```

## Development

Run the linter, formatter check, type checker and tests:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src tests
uv run pytest
```

## Project structure

```
src/password_manager/
    crypto.py      # hashing, key derivation, encryption/decryption
    generator.py    # random password generator
    core.py         # PasswordManager: vault state, CRUD operations, persistence
    cli.py          # argparse CLI and interactive menu
tests/              # pytest tests for crypto, generator and core
```
