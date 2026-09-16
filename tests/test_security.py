import bcrypt

from app.core.security import verify_password


def test_verify_password_accepts_spring_compatible_bcrypt_hash() -> None:
    hashed = bcrypt.hashpw(b"Senha123!", bcrypt.gensalt(rounds=4)).decode()
    assert verify_password("Senha123!", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_password_accepts_2y_prefix() -> None:
    hashed = bcrypt.hashpw(b"Senha123!", bcrypt.gensalt(rounds=4)).decode()
    hashed_2y = "$2y$" + hashed[4:]
    assert verify_password("Senha123!", hashed_2y) is True


def test_verify_password_rejects_invalid_hash() -> None:
    assert verify_password("Senha123!", "not-a-bcrypt-hash") is False
