import asyncio

import pytest

from app.core.config import Settings
from app.core.service_auth import (
    KeycloakServiceTokenVerifier,
    ServiceAuthenticationError,
)


def make_verifier() -> KeycloakServiceTokenVerifier:
    """Build the verifier without performing any network request."""
    return KeycloakServiceTokenVerifier(
        Settings(
            keycloak_issuer_url="https://keycloak.example/realms/ouros",
            keycloak_internal_audience="ms-auth-service-internal",
            keycloak_internal_client_id="keycloak-user-storage",
        )
    )


def test_missing_bearer_token_is_rejected() -> None:
    """Require an Authorization header on internal endpoints."""
    verifier = make_verifier()
    verification = verifier.verify_authorization_header(None)
    with pytest.raises(ServiceAuthenticationError):
        asyncio.run(verification)


def test_malformed_bearer_token_is_rejected() -> None:
    """Reject non-Bearer authorization schemes before JWKS lookup."""
    verifier = make_verifier()
    verification = verifier.verify_authorization_header("Basic abc")
    with pytest.raises(ServiceAuthenticationError):
        asyncio.run(verification)


def test_valid_bearer_shape_delegates_to_decoder() -> None:
    """Move blocking JWT/JWKS verification off the event loop."""
    verifier = make_verifier()
    verifier._decode = lambda token: {"token": token}  # type: ignore[method-assign]

    payload = asyncio.run(
        verifier.verify_authorization_header("Bearer synthetic.jwt.token")
    )

    assert payload == {"token": "synthetic.jwt.token"}
