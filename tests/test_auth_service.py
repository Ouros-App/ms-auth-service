import asyncio

import bcrypt
import pytest
from pydantic import SecretStr

from app.core.errors import AmbiguousIdentityError, InvalidCredentialsError
from app.models.identity import AccountType, StoredIdentity
from app.schemas.auth import CredentialVerificationRequest
from app.services.auth_service import AuthService


class FakeRepository:
    """Minimal identity repository double used by AuthService tests."""

    def __init__(self, identities: list[StoredIdentity]) -> None:
        """Store deterministic identities and track repository calls."""
        self.identities = identities
        self.calls: list[tuple[str, AccountType | None]] = []
        self.external_calls: list[tuple[AccountType, int]] = []

    async def find_by_email(
        self,
        email: str,
        account_type: AccountType | None = None,
    ) -> list[StoredIdentity]:
        """Return configured identities while recording normalized arguments."""
        self.calls.append((email, account_type))
        return self.identities

    async def find_by_external_id(
        self,
        account_type: AccountType,
        database_id: int,
    ) -> StoredIdentity | None:
        """Return the matching configured identity by stable business key."""
        self.external_calls.append((account_type, database_id))
        for identity in self.identities:
            if (
                identity.account_type is account_type
                and identity.database_id == database_id
            ):
                return identity
        return None


def make_identity(
    password: str = "Senha123!",
    *,
    account_type: AccountType = AccountType.FARM_OWNER,
    database_id: int = 10,
) -> StoredIdentity:
    """Build one stored identity with a cheap bcrypt hash for tests."""
    password_hash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt(rounds=4),
    ).decode()
    return StoredIdentity(
        database_id=database_id,
        email="User@Example.COM",
        password_hash=password_hash,
        account_type=account_type,
        name="Usuário Teste",
        farm_id=9 if account_type is AccountType.FARM_OWNER else None,
        enterprise_id=(
            7 if account_type is AccountType.COMPANY_EMPLOYEE else None
        ),
        first_access=True if account_type is AccountType.FARM_OWNER else None,
    )


def make_request(
    password: str = "Senha123!",
    account_type: AccountType | None = None,
) -> CredentialVerificationRequest:
    """Build a normalized credential-verification request for tests."""
    return CredentialVerificationRequest(
        email=" USER@example.com ",
        password=SecretStr(password),
        account_type=account_type,
    )


def test_valid_credentials_return_identity_without_password() -> None:
    """Return business identity data without exposing the stored password hash."""
    repository = FakeRepository([make_identity()])
    service = AuthService(repository)  # type: ignore[arg-type]

    response = asyncio.run(service.verify_credentials(make_request()))

    assert response.authenticated is True
    assert response.identity.id == 10
    assert response.identity.email == "User@Example.COM"
    assert response.identity.realm_role == "farm_owner"
    assert response.identity.farm_id == 9
    assert not hasattr(response.identity, "password_hash")
    assert repository.calls == [("user@example.com", None)]


def test_wrong_password_is_rejected() -> None:
    """Reject a known identity when the supplied password does not match."""
    service = AuthService(FakeRepository([make_identity()]))  # type: ignore[arg-type]
    request = make_request("wrong-password")

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(service.verify_credentials(request))


def test_unknown_user_is_rejected() -> None:
    """Reject a request when no identity exists for the supplied email."""
    service = AuthService(FakeRepository([]))  # type: ignore[arg-type]
    request = make_request()

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(service.verify_credentials(request))


def test_account_type_is_forwarded_to_repository() -> None:
    """Forward an optional account-type hint to identity lookup."""
    repository = FakeRepository(
        [make_identity(account_type=AccountType.COMPANY_EMPLOYEE)]
    )
    service = AuthService(repository)  # type: ignore[arg-type]

    asyncio.run(
        service.verify_credentials(
            make_request(account_type=AccountType.COMPANY_EMPLOYEE)
        )
    )

    assert repository.calls == [
        ("user@example.com", AccountType.COMPANY_EMPLOYEE)
    ]


def test_multiple_matching_accounts_require_account_type() -> None:
    """Require disambiguation when one credential matches multiple identities."""
    first = make_identity(database_id=1)
    second = make_identity(
        account_type=AccountType.ADMIN,
        database_id=2,
    )
    service = AuthService(FakeRepository([first, second]))  # type: ignore[arg-type]
    request = make_request()

    with pytest.raises(AmbiguousIdentityError):
        asyncio.run(service.verify_credentials(request))


def test_lookup_identity_by_email_returns_normalized_identity() -> None:
    """Expose identity metadata without credential material to Keycloak."""
    repository = FakeRepository([make_identity(database_id=31)])
    service = AuthService(repository)  # type: ignore[arg-type]

    identity = asyncio.run(service.lookup_identity_by_email("user@example.com"))

    assert identity is not None
    assert identity.id == 31
    assert identity.realm_role == "farm_owner"


def test_lookup_identity_by_email_returns_none_when_missing() -> None:
    """Return no external identity when the email is unknown."""
    service = AuthService(FakeRepository([]))  # type: ignore[arg-type]

    identity = asyncio.run(service.lookup_identity_by_email("missing@example.com"))

    assert identity is None


def test_lookup_identity_by_email_rejects_ambiguous_accounts() -> None:
    """Refuse to federate one email that maps to multiple account records."""
    repository = FakeRepository([
        make_identity(database_id=1),
        make_identity(account_type=AccountType.ADMIN, database_id=2),
    ])
    service = AuthService(repository)  # type: ignore[arg-type]

    with pytest.raises(AmbiguousIdentityError):
        asyncio.run(service.lookup_identity_by_email("user@example.com"))


def test_lookup_identity_by_external_id_returns_identity() -> None:
    """Resolve the stable external key used in Keycloak federated user ids."""
    repository = FakeRepository([make_identity(database_id=44)])
    service = AuthService(repository)  # type: ignore[arg-type]

    identity = asyncio.run(
        service.lookup_identity_by_external_id(AccountType.FARM_OWNER, 44)
    )

    assert identity is not None
    assert identity.id == 44
    assert repository.external_calls == [(AccountType.FARM_OWNER, 44)]


def test_lookup_identity_by_external_id_returns_none_when_missing() -> None:
    """Return no identity when a federated business key no longer exists."""
    service = AuthService(FakeRepository([]))  # type: ignore[arg-type]

    identity = asyncio.run(
        service.lookup_identity_by_external_id(AccountType.ADMIN, 999)
    )

    assert identity is None
