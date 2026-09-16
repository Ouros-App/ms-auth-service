from app.core.errors import AmbiguousIdentityError, InvalidCredentialsError
from app.core.security import burn_dummy_password_check, verify_password
from app.repositories.identity_repository import IdentityRepository
from app.schemas.auth import (
    CredentialVerificationRequest,
    CredentialVerificationResponse,
    IdentityResponse,
)


class AuthService:
    def __init__(self, repository: IdentityRepository) -> None:
        self._repository = repository

    async def verify_credentials(
        self,
        request: CredentialVerificationRequest,
    ) -> CredentialVerificationResponse:
        identities = await self._repository.find_by_email(
            request.email,
            request.account_type,
        )
        raw_password = request.password.get_secret_value()

        if not identities:
            burn_dummy_password_check(raw_password)
            raise InvalidCredentialsError

        matches = [
            identity
            for identity in identities
            if verify_password(raw_password, identity.password_hash)
        ]

        if not matches:
            raise InvalidCredentialsError
        if len(matches) > 1:
            raise AmbiguousIdentityError

        return CredentialVerificationResponse(
            identity=IdentityResponse.from_identity(matches[0])
        )
