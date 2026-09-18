import asyncio

import httpx
import pytest

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.schemas.auth import TokenLoginRequest
from app.services.keycloak_token_broker import (
    KeycloakTokenBroker,
    KeycloakTokenBrokerUnavailable,
)


def make_settings(**overrides) -> Settings:
    """Build isolated broker settings without external dependencies."""
    values = {
        "database_url": "postgresql://unused",
        "redis_url": None,
        "keycloak_token_broker_client_secret": "broker-secret",
    }
    values.update(overrides)
    return Settings(**values)


def make_request() -> TokenLoginRequest:
    """Return one valid first-party password-login request."""
    return TokenLoginRequest(email="user@example.com", password="Senha123!")


def test_password_broker_relays_valid_keycloak_token() -> None:
    """Relay the response fields without creating a local JWT."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/protocol/openid-connect/token")
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert b"grant_type=password" in request.content
        return httpx.Response(
            200,
            json={
                "access_token": "keycloak-access-token",
                "expires_in": 600,
                "refresh_expires_in": 1800,
                "refresh_token": "keycloak-refresh-token",
                "token_type": "Bearer",
                "scope": "openid ouros-identity",
            },
        )

    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(handler),
    )
    response = asyncio.run(broker.issue_password_token(make_request()))
    assert response.access_token == "keycloak-access-token"
    assert response.token_type == "Bearer"


@pytest.mark.parametrize("status_code", [400, 401])
def test_password_broker_maps_rejected_grants_to_generic_credentials_error(
    status_code: int,
) -> None:
    """Treat Keycloak invalid-grant responses exactly like local failures."""
    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(status_code, json={"error": "invalid_grant"})
        ),
    )
    with pytest.raises(InvalidCredentialsError):
        asyncio.run(broker.issue_password_token(make_request()))


def test_password_broker_maps_keycloak_outage_to_unavailable() -> None:
    """Avoid leaking upstream status details to public callers."""
    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(502, json={"error": "upstream"})
        ),
    )
    with pytest.raises(KeycloakTokenBrokerUnavailable):
        asyncio.run(broker.issue_password_token(make_request()))


def test_password_broker_maps_transport_failure_to_unavailable() -> None:
    """Handle connection failures without exposing network diagnostics."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(KeycloakTokenBrokerUnavailable):
        asyncio.run(broker.issue_password_token(make_request()))


def test_password_broker_requires_its_client_secret() -> None:
    """Keep the broker disabled until the secret manager is configured."""
    broker = KeycloakTokenBroker(
        make_settings(keycloak_token_broker_client_secret=None),
    )
    with pytest.raises(KeycloakTokenBrokerUnavailable):
        asyncio.run(broker.issue_password_token(make_request()))


def test_password_broker_rejects_malformed_success_payload() -> None:
    """Fail closed when Keycloak returns an incomplete token document."""
    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )
    with pytest.raises(KeycloakTokenBrokerUnavailable):
        asyncio.run(broker.issue_password_token(make_request()))
