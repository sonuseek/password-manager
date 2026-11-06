import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet


def generate_salt() -> bytes:
    """Return a new cryptographically random salt"""
    return os.urandom(16)


def hash_master_password(password: str, salt: bytes) -> bytes:
    """Return a hash master password"""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 390_000, dklen=32)


def verify_master_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Check password"""
    return hmac.compare_digest(hash_master_password(password, salt), expected_hash)


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Generate a master key"""
    raw_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 390_000, dklen=32)
    return base64.urlsafe_b64encode(raw_key)


def encrypt(plaintext: str, key: bytes) -> str:
    """Encryption password"""
    fernet = Fernet(key)
    plaintext_bytes = plaintext.encode("utf-8")
    token = fernet.encrypt(plaintext_bytes)
    return token.decode()


def decrypt(token: str, key: bytes) -> str:
    """Decryption password"""
    fernet = Fernet(key)
    token_bytes = token.encode("utf-8")
    plaintext_bytes = fernet.decrypt(token_bytes)
    return plaintext_bytes.decode()
