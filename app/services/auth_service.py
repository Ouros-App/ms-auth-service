import asyncio

from app.core.errors import AmbiguousIdentityError, InvalidCredentialsError
from app.core.security import burn_dummy_password_check, verify_password
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
