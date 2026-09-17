import asyncio
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from app.core.config import Settings


class ServiceAuthenticationError(RuntimeError):
    """Raised when an internal service bearer token cannot be trusted."""


class KeycloakServiceTokenVerifier:
    """Validate Keycloak service-account tokens for internal auth endpoints."""

    def __init__(self, settings: Settings) -> None:
        self._issuer = settings.keycloak_issuer_url.rstrip("/")
        self._audience = settings.keycloak_internal_audience
        self._client_id = settings.keycloak_internal_client_id
        self._jwk_client = PyJWKClient(
            f"{self._issuer}/protocol/openid-connect/certs",
            cache_keys=True,
            lifespan=300,
            timeout=3,
        )

    async def verify_authorization_header(
        self,
        authorization: str | None,
    ) -> dict[str, Any]:
        """Validate one Bearer token without blocking the ASGI event loop."""
        if authorization is None:
            raise ServiceAuthenticationError("missing bearer token")

        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token.strip():
            raise ServiceAuthenticationError("invalid bearer token")

        return await asyncio.to_thread(self._decode, token.strip())

    def _decode(self, token: str) -> dict[str, Any]:
        """Verify signature, issuer, audience, lifetime and authorized party."""
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (InvalidTokenError, PyJWKClientError) as exc:
            raise ServiceAuthenticationError("invalid service token") from exc

        if payload.get("azp") != self._client_id:
            raise ServiceAuthenticationError("unexpected authorized party")

        return payload
