from password_manager import crypto


def test_verify_master_password_correct_and_incorrect() -> None:
    salt = crypto.generate_salt()
    password_hash = crypto.hash_master_password("mypassword123", salt)

    assert crypto.verify_master_password("mypassword123", salt, password_hash) is True
    assert crypto.verify_master_password("wrongpassword", salt, password_hash) is False


def test_encrypt_decrypt_roundtrip() -> None:
    key = crypto.derive_fernet_key("somepassword", crypto.generate_salt())
    plaintext = "my-secret-value"

    token = crypto.encrypt(plaintext, key)
    assert crypto.decrypt(token, key) == plaintext
