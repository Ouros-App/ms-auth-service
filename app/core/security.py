import bcrypt


# Valid public bcrypt hash generated only for missing-user timing work.
# It is not tied to any Ouros account and carries no secret.
_DUMMY_BCRYPT_HASH = "$2y$10$RQdEwwOeMY0qJtHGr2Aec.zs8DqgBCpb3dNFPmbvTARxWRv6RF3HO"


def _normalize_bcrypt_prefix(encoded_password: str) -> str:
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
