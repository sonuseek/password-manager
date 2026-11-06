from password_manager.generator import generate_password


def test_generate_password_length() -> None:
    password = generate_password(20)
    assert len(password) == 20


def test_generate_password_is_random() -> None:
    assert generate_password(16) != generate_password(16)
