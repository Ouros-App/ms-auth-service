import asyncio

import bcrypt
import pytest
from pydantic import SecretStr

from app.core.errors import AmbiguousIdentityError, InvalidCredentialsError
from app.models.identity import AccountType, StoredIdentity
from app.schemas.auth import CredentialVerificationRequest
from app.services.auth_service import AuthService


class FakeRepository:
    def __init__(self, identities: list[StoredIdentity]) -> None:
        self.identities = identities
        self.calls: list[tuple[str, AccountType | None]] = []

    async def find_by_email(
        self,
        email: str,
        account_type: AccountType | None = None,
    ) -> list[StoredIdentity]:
        self.calls.append((email, account_type))
        return self.identities


def make_identity(
    password: str = "Senha123!",
    *,
    account_type: AccountType = AccountType.FARM_OWNER,
    database_id: int = 10,
) -> StoredIdentity:
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
    return CredentialVerificationRequest(
        email=" USER@example.com ",
        password=SecretStr(password),
        account_type=account_type,
    )


def test_valid_credentials_return_identity_without_password() -> None:
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
    service = AuthService(FakeRepository([make_identity()]))  # type: ignore[arg-type]

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(service.verify_credentials(make_request("wrong-password")))


def test_unknown_user_is_rejected() -> None:
    service = AuthService(FakeRepository([]))  # type: ignore[arg-type]

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(service.verify_credentials(make_request()))


def test_account_type_is_forwarded_to_repository() -> None:
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
    first = make_identity(database_id=1)
    second = make_identity(
        account_type=AccountType.ADMIN,
        database_id=2,
    )
    service = AuthService(FakeRepository([first, second]))  # type: ignore[arg-type]

    with pytest.raises(AmbiguousIdentityError):
        asyncio.run(service.verify_credentials(make_request()))
