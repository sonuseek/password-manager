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

    def _persist(self) -> None:
        if self.key is None:
            raise VaultLockedError("Cannot persist while locked.")
        if self.salt_master is None or self.salt_key is None or self.hash_master is None:
            raise VaultLockedError("Cannot persist while locked.")

        encrypted_entries = {}
        for name, record in self.entries.items():
            encrypted_entries[name] = {
                "login": crypto.encrypt(record["login"], self.key),
                "password": crypto.encrypt(record["password"], self.key),
            }
        payload = {
            "salt_master": base64.b64encode(self.salt_master).decode("ascii"),
            "salt_key": base64.b64encode(self.salt_key).decode("ascii"),
            "hash_master": base64.b64encode(self.hash_master).decode("ascii"),
            "entries": encrypted_entries,
        }
        with self.storage_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def init_master(self, new_password: str, *, current_password: str | None = None) -> None:
        if self.is_initialized:
            if current_password is None:
                raise VaultExistsError("Vault already exists; pass current_password to confirm.")
            if not crypto.verify_master_password(current_password, self.salt_master, self.hash_master):
                raise VaultExistsError("current_password does not match the existing vault")
            
        self.salt_master = crypto.generate_salt()
        self.salt_key = crypto.generate_salt()
        self.hash_master = crypto.hash_master_password(new_password, self.salt_master)
        self.key = crypto.derive_fernet_key(new_password, self.salt_key)
        self.entries = {}
        self._persist()
    