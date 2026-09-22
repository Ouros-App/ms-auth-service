import asyncio
from unittest.mock import Mock, patch

import httpx
import pytest

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.schemas.auth import TokenLoginRequest, TokenRefreshRequest
from app.services.keycloak_token_broker import (
    REQUIRED_FIRST_PARTY_AUDIENCES,
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


def test_broker_audiences_follow_delegated_mcp_boundary() -> None:
    """Require the exchange requester audience and reject direct Knowledge MCP access."""
    assert "ms-ai-server-mcp-exchange" in REQUIRED_FIRST_PARTY_AUDIENCES
    assert "ms-mcp-server-ouros-knowledge" not in REQUIRED_FIRST_PARTY_AUDIENCES


def test_refresh_broker_rotates_valid_keycloak_token() -> None:
    """Use the confidential broker secret to rotate a server-managed session."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/protocol/openid-connect/token")
        assert b"grant_type=refresh_token" in request.content
        assert b"refresh_token=old-refresh-token" in request.content
        assert b"client_secret=broker-secret" in request.content
        return httpx.Response(
            200,
            json={
                "access_token": "rotated-access-token",
                "expires_in": 600,
                "refresh_expires_in": 1800,
                "refresh_token": "rotated-refresh-token",
                "token_type": "Bearer",
                "scope": "openid ouros-identity",
            },
        )

    broker = KeycloakTokenBroker(
        make_settings(),
        transport=httpx.MockTransport(handler),
    )
    with patch.object(
        broker,
        "_validate_access_token_contract",
        return_value={"sub": "subject"},
    ):
        response = asyncio.run(
            broker.refresh_token(TokenRefreshRequest(refresh_token="old-refresh-token"))
        )

    assert response.access_token == "rotated-access-token"
    assert response.refresh_token == "rotated-refresh-token"


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
    with patch.object(
        broker,
        "_validate_access_token_contract",
        return_value={"sub": "subject"},
    ):
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



def test_broker_validates_full_ouros_token_contract() -> None:
    """Require every first-party audience plus the signed business identity."""
    broker = KeycloakTokenBroker(make_settings())
    signing_key = Mock(key="public-key")
    jwks = Mock()
    jwks.get_signing_key_from_jwt.return_value = signing_key
    audiences = [
        "ms-spring-api",
        "ms-telemetry-dashboard-service",
        "ms-ai-server",
        "ms-ai-server-mcp-exchange",
        "ms-mcp-server-ouros-knowledge-codemode",
    ]
    claims = {
        "sub": "keycloak-subject",
        "azp": "ms-auth-service-broker",
        "iss": "https://ouros-keycloak.discloud.app/realms/ouros",
        "aud": audiences,
        "iat": 1_700_000_000,
        "exp": 4_102_444_800,
        "database_id": 42,
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=jwks,
        ),
        patch(
            "app.services.keycloak_token_broker.decode",
            return_value=claims,
        ) as decoder,
    ):
        assert broker._validate_access_token_contract("signed-token") == claims

    jwks.get_signing_key_from_jwt.assert_called_once_with("signed-token")
    assert decoder.call_args.kwargs["algorithms"] == ["RS256"]
    assert decoder.call_args.kwargs["issuer"] == (
        "https://ouros-keycloak.discloud.app/realms/ouros"
    )


def test_broker_rejects_missing_resource_audience() -> None:
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "ms-auth-service-broker",
        "aud": ["ms-ai-server"],
        "database_id": 42,
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")


@pytest.mark.parametrize(
    "claims",
    [
        {
            "sub": "subject",
        "azp": "ms-auth-service-broker",
            "aud": [
                "ms-spring-api",
                "ms-telemetry-dashboard-service",
                "ms-ai-server",
                "ms-ai-server-mcp-exchange",
                "ms-mcp-server-ouros-knowledge-codemode",
            ],
            "database_id": 0,
            "account_type": "farm_owner",
            "realm_access": {"roles": ["farm_owner"]},
        },
        {
            "sub": "subject",
        "azp": "ms-auth-service-broker",
            "aud": [
                "ms-spring-api",
                "ms-telemetry-dashboard-service",
                "ms-ai-server",
                "ms-ai-server-mcp-exchange",
                "ms-mcp-server-ouros-knowledge-codemode",
            ],
            "database_id": 42,
            "account_type": "admin",
            "realm_access": {"roles": ["farm_owner"]},
        },
    ],
)
def test_broker_rejects_invalid_signed_business_identity(claims: dict) -> None:
    broker = KeycloakTokenBroker(make_settings())
    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")



def test_broker_rejects_wrong_authorized_party() -> None:
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "another-client",
        "aud": [
            "ms-spring-api",
            "ms-telemetry-dashboard-service",
            "ms-ai-server",
            "ms-ai-server-mcp-exchange",
            "ms-mcp-server-ouros-knowledge-codemode",
        ],
        "database_id": 42,
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")



def test_broker_rejects_non_string_account_type() -> None:
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "ms-auth-service-broker",
        "aud": [
            "ms-spring-api",
            "ms-telemetry-dashboard-service",
            "ms-ai-server",
            "ms-ai-server-mcp-exchange",
            "ms-mcp-server-ouros-knowledge-codemode",
        ],
        "database_id": 42,
        "account_type": [],
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")


def test_broker_rejects_invalid_audience_shape() -> None:
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "ms-auth-service-broker",
        "aud": {"ms-ai-server": True},
        "database_id": 42,
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")


def test_broker_accepts_numeric_database_id_encoded_as_string() -> None:
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "ms-auth-service-broker",
        "aud": [
            "ms-spring-api",
            "ms-telemetry-dashboard-service",
            "ms-ai-server",
            "ms-ai-server-mcp-exchange",
            "ms-mcp-server-ouros-knowledge-codemode",
        ],
        "database_id": "42",
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
    ):
        assert broker._validate_access_token_contract("signed-token") == claims



def test_broker_rejects_oversized_decimal_database_id() -> None:
    """Map Python's oversized decimal conversion failure to broker unavailability."""
    broker = KeycloakTokenBroker(make_settings())
    claims = {
        "sub": "subject",
        "azp": "ms-auth-service-broker",
        "aud": list(REQUIRED_FIRST_PARTY_AUDIENCES),
        "database_id": "9" * 5000,
        "account_type": "farm_owner",
        "realm_access": {"roles": ["farm_owner"]},
    }

    with (
        patch(
            "app.services.keycloak_token_broker._get_jwks_client",
            return_value=Mock(
                get_signing_key_from_jwt=Mock(return_value=Mock(key="public-key"))
            ),
        ),
        patch("app.services.keycloak_token_broker.decode", return_value=claims),
        pytest.raises(KeycloakTokenBrokerUnavailable),
    ):
        broker._validate_access_token_contract("signed-token")
