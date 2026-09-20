import asyncio
from functools import lru_cache

import httpx
from jwt import InvalidTokenError, PyJWKClient, decode
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.schemas.auth import KeycloakTokenResponse, TokenLoginRequest

VALID_ACCOUNT_TYPES = {"farm_owner", "company_employee", "admin"}
REQUIRED_FIRST_PARTY_AUDIENCES = frozenset(
    {
        "ms-spring-api",
        "ms-telemetry-dashboard-service",
        "ms-ai-server",
        "ms-mcp-server-ouros-knowledge",
        "ms-mcp-server-ouros-knowledge-codemode",
    }
)


class KeycloakTokenBrokerUnavailable(RuntimeError):
    """Raised when the Keycloak password-grant broker cannot issue a valid token."""


@lru_cache(maxsize=8)
def _get_jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url, cache_keys=True, lifespan=300)


class KeycloakTokenBroker:
    """Relay first-party password logins and enforce the Ouros JWT contract."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._issuer = settings.keycloak_issuer_url.rstrip("/")
        self._token_url = f"{self._issuer}/protocol/openid-connect/token"
        self._jwks_url = (
            settings.keycloak_token_broker_jwks_url
            or f"{self._issuer}/protocol/openid-connect/certs"
        )
        self._client_id = settings.keycloak_token_broker_client_id
        self._client_secret = settings.keycloak_token_broker_client_secret
        self._scope = settings.keycloak_token_broker_scope
        self._timeout_seconds = settings.keycloak_token_broker_timeout_seconds
        self._expected_audiences = REQUIRED_FIRST_PARTY_AUDIENCES
        self._transport = transport

    def _validate_access_token_contract(self, token: str) -> dict:
        """Validate signature, issuer, audiences and signed business identity."""

        try:
            signing_key = _get_jwks_client(self._jwks_url).get_signing_key_from_jwt(token)
            claims = decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=list(self._expected_audiences),
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_aud": False,
                },
            )
        except (InvalidTokenError, PyJWKClientError, ValueError) as exc:
            raise KeycloakTokenBrokerUnavailable(
                "Keycloak issued an access token that failed local validation"
            ) from exc

        audiences = claims.get("aud")
        if isinstance(audiences, str):
            audience_set = {audiences}
        elif isinstance(audiences, list) and all(isinstance(item, str) for item in audiences):
            audience_set = set(audiences)
        else:
            audience_set = set()

        if not self._expected_audiences.issubset(audience_set):
            raise KeycloakTokenBrokerUnavailable(
                "Keycloak access token is missing required Ouros audiences"
            )

        if claims.get("azp") != self._client_id:
            raise KeycloakTokenBrokerUnavailable(
                "Keycloak access token was not issued to the official broker"
            )

        account_type = claims.get("account_type")
        database_id = claims.get("database_id")
        realm_access = claims.get("realm_access")
        roles = realm_access.get("roles") if isinstance(realm_access, dict) else None
        if (
            account_type not in VALID_ACCOUNT_TYPES
            or not isinstance(roles, list)
            or account_type not in roles
        ):
            raise KeycloakTokenBrokerUnavailable(
                "Keycloak access token is missing the signed Ouros account role"
            )

        if isinstance(database_id, bool):
            raise KeycloakTokenBrokerUnavailable("invalid database_id claim")
        if isinstance(database_id, int):
            numeric_id = database_id
        elif isinstance(database_id, str) and database_id.isascii() and database_id.isdecimal():
            numeric_id = int(database_id)
        else:
            raise KeycloakTokenBrokerUnavailable("invalid database_id claim")
        if numeric_id <= 0:
            raise KeycloakTokenBrokerUnavailable("invalid database_id claim")

        return claims

    async def issue_password_token(
        self,
        credentials: TokenLoginRequest,
    ) -> KeycloakTokenResponse:
        """Request and locally verify a Keycloak-minted user token."""
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
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(self._token_url, data=form)
        except httpx.HTTPError as exc:
            raise KeycloakTokenBrokerUnavailable("Keycloak token endpoint unavailable") from exc

        if response.status_code in {400, 401}:
            raise InvalidCredentialsError
        if response.status_code != 200:
            raise KeycloakTokenBrokerUnavailable("Keycloak token endpoint rejected request")

        try:
            token_response = KeycloakTokenResponse.model_validate(response.json())
        except (ValueError, TypeError) as exc:
            raise KeycloakTokenBrokerUnavailable("invalid Keycloak token response") from exc

        try:
            await asyncio.to_thread(
                self._validate_access_token_contract,
                token_response.access_token,
            )
        except PyJWKClientConnectionError as exc:
            raise KeycloakTokenBrokerUnavailable(
                "Keycloak signing keys are unavailable"
            ) from exc
        return token_response
