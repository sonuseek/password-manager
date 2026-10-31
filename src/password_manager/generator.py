import secrets
import string


def generate_password(length: int = 16) -> str:
    """Generate a random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ""
    for _ in range (length):
        password = password + secrets.choice(alphabet)
    return password