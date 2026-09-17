import asyncio

from app.core.errors import AmbiguousIdentityError, InvalidCredentialsError
from app.core.security import burn_dummy_password_check, verify_password
from app.models.identity import AccountType
from app.repositories.identity_repository import IdentityRepository
from app.schemas.auth import (
    CredentialVerificationRequest,
    CredentialVerificationResponse,
    IdentityResponse,
)


class AuthService:
    """Verify existing Ouros credentials without minting application tokens."""

    def __init__(self, repository: IdentityRepository) -> None:
        self._repository = repository

    async def verify_credentials(
        self,
        request: CredentialVerificationRequest,
    ) -> CredentialVerificationResponse:
        """Validate credentials and return exactly one normalized identity."""
        identities = await self._repository.find_by_email(
            request.email,
            request.account_type,
        )
        raw_password = request.password.get_secret_value()

        if not identities:
            await asyncio.to_thread(burn_dummy_password_check, raw_password)
            raise InvalidCredentialsError

        matches = []
        for identity in identities:
            is_match = await asyncio.to_thread(
                verify_password,
                raw_password,
                identity.password_hash,
            )
            if is_match:
                matches.append(identity)

        if not matches:
            raise InvalidCredentialsError
        if len(matches) > 1:
            raise AmbiguousIdentityError

        return CredentialVerificationResponse(
            identity=IdentityResponse.from_identity(matches[0])
        )

    async def lookup_identity_by_email(self, email: str) -> IdentityResponse | None:
        """Resolve one external identity without exposing credential material."""
        identities = await self._repository.find_by_email(email)
        if not identities:
            return None
        if len(identities) > 1:
            raise AmbiguousIdentityError
        return IdentityResponse.from_identity(identities[0])

    async def lookup_identity_by_external_id(
        self,
        account_type: AccountType,
        database_id: int,
    ) -> IdentityResponse | None:
        """Resolve the stable external identity used by Keycloak storage ids."""
        identity = await self._repository.find_by_external_id(
            account_type,
            database_id,
        )
        if identity is None:
            return None
        return IdentityResponse.from_identity(identity)
