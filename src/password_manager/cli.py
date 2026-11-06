import argparse
import getpass
from pathlib import Path

from password_manager.core import PasswordManager, VaultExistsError
from password_manager.generator import generate_password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-manager",
        description="A simple password manager.",
    )
    parser.add_argument("--init", action="store_true", 
                        help="Create a new vault (or reset an existing one)."
    )
    parser.add_argument("--unlock", action="store_true", 
                        help="Unlock the vault and open the menu."
    )
    parser.add_argument("--generate", action="store_true", 
                        help="Generate a random password and exit."
    )
    parser.add_argument("--length", type=int, default=16, 
                        help="Length of generated password."
    )
    parser.add_argument("--path", type=Path, default=Path("vault.json"), 
                        help="Path to the vault file."
    )
    return parser


def run_init(manager: PasswordManager) -> None:
    if manager.is_initialized:
        current = getpass.getpass("Current master password: ")
        new = getpass.getpass("New master password: ")
        try:
            manager.init_master(new, current_password=current)
        except VaultExistsError as exc:
            print(f"Error: {exc}")
            return
    else:
        new = getpass.getpass("Set a new master password: ")
        manager.init_master(new)
    print("Vault initialized.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.generate:
        print(generate_password(args.length))
        return

    manager = PasswordManager(args.path)

    if args.init:
        run_init(manager)
        return