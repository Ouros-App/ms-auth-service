import asyncio
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.core.config import Settings
from app.core.service_auth import (
    KeycloakServiceTokenVerifier,
    ServiceAuthenticationError,
)

ISSUER = "https://keycloak.example/realms/ouros"
AUDIENCE = "ms-auth-service-internal"
CLIENT_ID = "keycloak-user-storage"
KEY_ID = "test-signing-key"


def make_verifier() -> KeycloakServiceTokenVerifier:
    """Build the verifier with deterministic Keycloak trust settings."""
    return KeycloakServiceTokenVerifier(
        Settings(
            keycloak_issuer_url=ISSUER,
            keycloak_internal_audience=AUDIENCE,
            keycloak_internal_client_id=CLIENT_ID,
        )
    )


def make_signing_material():
    """Create an ephemeral RSA key and its public JWK for contract tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})
    return private_key, jwk


def wire_jwks(verifier: KeycloakServiceTokenVerifier, jwk: dict) -> None:
    """Serve a deterministic JWKS while exercising the real PyJWKClient path."""
    verifier._jwk_client.fetch_data = lambda: {"keys": [jwk]}  # type: ignore[method-assign]


def make_claims() -> dict:
    """Return a valid service-account JWT claim set."""
    now = datetime.now(UTC)
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "service-account-keycloak-user-storage",
        "azp": CLIENT_ID,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }


def sign_token(private_key, claims: dict, *, algorithm: str = "RS256") -> str:
    """Sign a token with a fixed key id for verifier tests."""
    key = private_key if algorithm == "RS256" else "x" * 64
    return jwt.encode(
        claims,
        key,
        algorithm=algorithm,
        headers={"kid": KEY_ID},
    )


def verify_token(
    verifier: KeycloakServiceTokenVerifier,
    token: str,
) -> dict:
    """Exercise the public async Bearer-validation entry point."""
    return asyncio.run(
        verifier.verify_authorization_header(f"Bearer {token}")
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


def test_valid_rs256_service_token_is_accepted() -> None:
    """Accept a signed token matching issuer, audience and service client."""
    verifier = make_verifier()
    private_key, jwk = make_signing_material()
    wire_jwks(verifier, jwk)

    payload = verify_token(verifier, sign_token(private_key, make_claims()))

    assert payload["sub"] == "service-account-keycloak-user-storage"
    assert payload["aud"] == AUDIENCE
    assert payload["azp"] == CLIENT_ID


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://wrong.example/realms/ouros"),
        ("aud", "wrong-audience"),
        ("azp", "other-service"),
    ],
)
def test_service_token_contract_rejects_wrong_claims(claim: str, value: str) -> None:
    """Reject identity-bound claims that do not match the managed client."""
    verifier = make_verifier()
    private_key, jwk = make_signing_material()
    wire_jwks(verifier, jwk)
    claims = make_claims()
    claims[claim] = value
    token = sign_token(private_key, claims)

    with pytest.raises(ServiceAuthenticationError):
        verify_token(verifier, token)


def test_expired_service_token_is_rejected() -> None:
    """Reject service credentials after their Keycloak lifetime ends."""
    verifier = make_verifier()
    private_key, jwk = make_signing_material()
    wire_jwks(verifier, jwk)
    claims = make_claims()
    claims["exp"] = datetime.now(UTC) - timedelta(seconds=1)
    token = sign_token(private_key, claims)

    with pytest.raises(ServiceAuthenticationError):
        verify_token(verifier, token)


def test_missing_required_subject_is_rejected() -> None:
    """Require a subject claim on the Keycloak service identity."""
    verifier = make_verifier()
    private_key, jwk = make_signing_material()
    wire_jwks(verifier, jwk)
    claims = make_claims()
    del claims["sub"]
    token = sign_token(private_key, claims)

    with pytest.raises(ServiceAuthenticationError):
        verify_token(verifier, token)


def test_non_rs256_service_token_is_rejected() -> None:
    """Keep the verifier pinned to Keycloak RSA signing tokens."""
    verifier = make_verifier()
    private_key, jwk = make_signing_material()
    wire_jwks(verifier, jwk)
    token = sign_token(private_key, make_claims(), algorithm="HS256")

    with pytest.raises(ServiceAuthenticationError):
        verify_token(verifier, token)


def test_jwks_refresh_is_bounded_and_signing_keys_have_no_unbounded_cache() -> None:
    """Keep unknown-kid refreshes throttled without a non-expiring key LRU."""
    verifier = make_verifier()

    assert verifier._jwk_client.cooldown_duration == 5
    assert not hasattr(verifier._jwk_client.get_signing_key, "cache_info")
