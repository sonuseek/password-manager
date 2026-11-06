from pathlib import Path

import pytest

from password_manager.core import PasswordManager, VaultLockedError


def test_init_unlock_and_crud_cycle(tmp_path: Path) -> None:
    storage_path = tmp_path / "vault.json"
    manager = PasswordManager(storage_path)

    manager.init_master("master-pass")
    assert storage_path.exists()

    manager2 = PasswordManager(storage_path)
    assert manager2.unlock("master-pass") is True
    assert manager2.unlock("wrong-pass") is False

    manager2.add_entry("github", "sofya", "qwerty123")
    assert manager2.list_entries() == ["github"]
    assert manager2.get_entry("github") == {"login": "sofya", "password": "qwerty123"}

    manager2.delete_entry("github")
    assert manager2.list_entries() == []


def test_add_entry_requires_unlock(tmp_path: Path) -> None:
    manager = PasswordManager(tmp_path / "vault.json")
    with pytest.raises(VaultLockedError):
        manager.add_entry("github", "sofya", "qwerty123")
