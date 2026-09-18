import httpx

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.schemas.auth import KeycloakTokenResponse, TokenLoginRequest


class KeycloakTokenBrokerUnavailable(RuntimeError):
    """Raised when the Keycloak password-grant broker cannot issue a token."""


class KeycloakTokenBroker:
    """Relay first-party password logins to Keycloak without minting local JWTs."""

    def __init__(self, settings: Settings) -> None:
        self._token_url = (
            f"{settings.keycloak_issuer_url.rstrip('/')}/protocol/openid-connect/token"
        )
        self._client_id = settings.keycloak_token_broker_client_id
        self._client_secret = settings.keycloak_token_broker_client_secret
        self._scope = settings.keycloak_token_broker_scope
        self._timeout_seconds = settings.keycloak_token_broker_timeout_seconds

    async def issue_password_token(
        self,
        credentials: TokenLoginRequest,
    ) -> KeycloakTokenResponse:
        """Request a Keycloak-minted token for one rate-limited login attempt."""
        if self._client_secret is None:
            raise KeycloakTokenBrokerUnavailable("broker client secret is not configured")

        form = {
            "grant_type": "password",
            "client_id": self._client_id,
            "client_secret": self._client_secret.get_secret_value(),
            "username": credentials.email,
            "password": credentials.password.get_secret_value(),
            "scope": self._scope,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(self._token_url, data=form)
        except httpx.HTTPError as exc:
            raise KeycloakTokenBrokerUnavailable("Keycloak token endpoint unavailable") from exc

        if response.status_code in {400, 401}:
            raise InvalidCredentialsError
        if response.status_code != 200:
            raise KeycloakTokenBrokerUnavailable("Keycloak token endpoint rejected request")

        try:
            return KeycloakTokenResponse.model_validate(response.json())
        except (ValueError, TypeError) as exc:
            raise KeycloakTokenBrokerUnavailable("invalid Keycloak token response") from exc
