import bcrypt

# Generate an ephemeral timing-only bcrypt hash at process start instead of
# storing a hash-shaped literal in source control. It is never tied to a user.
_DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"timing-only", bcrypt.gensalt(rounds=10)).decode()


def _normalize_bcrypt_prefix(encoded_password: str) -> str:
    """Normalize Spring-compatible $2y$ hashes for the Python bcrypt library."""
    if encoded_password.startswith("$2y$"):
        return "$2b$" + encoded_password[4:]
    return encoded_password


def verify_password(raw_password: str, encoded_password: str) -> bool:
    """Verify legacy Spring bcrypt hashes without generating a new credential."""
    try:
        password_bytes = raw_password.encode("utf-8")
        encoded_bytes = _normalize_bcrypt_prefix(encoded_password).encode("utf-8")
        return bcrypt.checkpw(password_bytes, encoded_bytes)
    except (ValueError, TypeError):
        return False


def burn_dummy_password_check(raw_password: str) -> None:
    """Keep missing-user requests closer to the cost of a real login attempt."""
    verify_password(raw_password, _DUMMY_BCRYPT_HASH)
