import base64
import json
from pathlib import Path

from password_manager import crypto


class VaultExistsError(Exception):
    """Raised when --init is attempted on an existing vault without the current password"""


class VaultLockedError(Exception):
    """Raised when an operation requires the vault to be unlocked first"""


class PasswordManager:
    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path
        self.key: bytes | None = None
        self.entries: dict[str, dict[str, str]] = {}
        self.salt_master: bytes | None = None
        self.salt_key: bytes | None = None
        self.hash_master: bytes | None = None

    @property
    def is_initialized(self) -> bool:
        """Check for the existence of a file at the specified path"""
        return self.storage_path.exists()

    @property
    def is_unlocked(self) -> bool:
        """Check if the manager is unblocked"""
        return self.key is not None

    def unlock(self, master_password: str) -> bool:
        with self.storage_path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        salt_master = base64.b64decode(raw["salt_master"])
        salt_key = base64.b64decode(raw["salt_key"])

        hash_master = base64.b64decode(raw["hash_master"])

        if not crypto.verify_master_password(master_password, salt_master, hash_master):
            return False
        self.key = crypto.derive_fernet_key(master_password, salt_key)
        self.salt_master = salt_master
        self.salt_key = salt_key
        self.hash_master = hash_master

        for name, record in raw["entries"].items():
            self.entries[name] = {
                "login": crypto.decrypt(record["login"], self.key),
                "password": crypto.decrypt(record["password"], self.key),
            }
        return True

    