from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.main import create_app
from app.models.identity import AccountType
from app.schemas.auth import (
    CredentialVerificationResponse,
    IdentityResponse,
    KeycloakTokenResponse,
)
from app.services.keycloak_token_broker import KeycloakTokenBrokerUnavailable


class FakeDatabase:
    """Minimal readiness double for HTTP route tests."""

    def __init__(self, ready: bool = True) -> None:
        self.ready = ready

    async def connect(self) -> None:
        """Mirror the database interface without opening a connection."""
        return

    async def close(self) -> None:
        """Mirror the database interface without cleanup."""
        return

    async def ping(self) -> bool:
        """Return the configured readiness state."""
        return self.ready


class FakeAuthService:
    """Return one deterministic authenticated identity."""

    async def verify_credentials(self, _request):
        """Return a successful credential verification response."""
        return CredentialVerificationResponse(
            identity=IdentityResponse(
                id=1,
                email="user@example.com",
                account_type=AccountType.FARM_OWNER,
                realm_role="farm_owner",
                farm_id=42,
            )
        )


class FakeKeycloakTokenBroker:
    """Return deterministic Keycloak-issued tokens without network I/O."""

    @staticmethod
    def _response() -> KeycloakTokenResponse:
        return KeycloakTokenResponse(
            access_token="keycloak-signed-access-token",
            expires_in=600,
            refresh_expires_in=1800,
            refresh_token="keycloak-signed-refresh-token",
            token_type="Bearer",
            scope="openid ouros-identity",
        )

    async def issue_password_token(self, _request) -> KeycloakTokenResponse:
        return self._response()

    async def refresh_token(self, _request) -> KeycloakTokenResponse:
        return self._response()


class InvalidKeycloakTokenBroker:
    """Raise the same generic invalid-credential exception as Keycloak."""

    async def issue_password_token(self, _request) -> KeycloakTokenResponse:
        raise InvalidCredentialsError

    async def refresh_token(self, _request) -> KeycloakTokenResponse:
        raise InvalidCredentialsError


class UnavailableKeycloakTokenBroker:
    """Simulate a broker outage without exposing implementation details."""

    async def issue_password_token(self, _request) -> KeycloakTokenResponse:
        raise KeycloakTokenBrokerUnavailable("unavailable")

    async def refresh_token(self, _request) -> KeycloakTokenResponse:
        raise KeycloakTokenBrokerUnavailable("unavailable")


class _LegacyFakeKeycloakTokenBroker:
    async def issue_password_token(self, _request) -> KeycloakTokenResponse:
        return KeycloakTokenResponse(
            access_token="keycloak-signed-access-token",
            expires_in=600,
            refresh_expires_in=1800,
            refresh_token="keycloak-signed-refresh-token",
            token_type="Bearer",
            scope="openid ouros-identity",
        )


class RejectingAuthService:
    """Reject all credentials using the production domain exception."""

    async def verify_credentials(self, _request):
        """Raise the generic invalid-credentials error."""
        raise InvalidCredentialsError


def build_client(
    *,
    ready: bool = True,
    rejecting: bool = False,
    token_broker=None,
) -> TestClient:
    """Build an isolated app that never inherits CI Redis configuration."""
    settings = Settings(database_url="postgresql://unused", redis_url=None)
    database = FakeDatabase(ready=ready)
    auth_service = RejectingAuthService() if rejecting else FakeAuthService()
    token_broker = token_broker or FakeKeycloakTokenBroker()
    app = create_app(
        settings=settings,
        database=database,  # type: ignore[arg-type]
        auth_service=auth_service,  # type: ignore[arg-type]
        keycloak_token_broker=token_broker,  # type: ignore[arg-type]
    )
    return TestClient(app)


def test_health_is_liveness_only() -> None:
    """Keep liveness healthy when the database is unavailable."""
    with build_client(ready=False) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_checks_database() -> None:
    """Report dependency failure through readiness rather than liveness."""
    with build_client(ready=False) as client:
        response = client.get("/ready")
    assert response.status_code == 503


def test_verify_credentials_route() -> None:
    """Return the normalized identity on successful verification."""
    with build_client() as client:
        response = client.post(
            "/v1/auth/credentials/verify",
            json={"email": "user@example.com", "password": "Senha123!"},
        )
    assert response.status_code == 200
    assert response.json()["identity"]["id"] == 1


def test_verify_credentials_returns_generic_401() -> None:
    """Keep invalid credential responses generic."""
    with build_client(rejecting=True) as client:
        response = client.post(
            "/v1/auth/credentials/verify",
            json={"email": "user@example.com", "password": "wrong"},
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciais inválidas."}


def test_token_login_relays_a_keycloak_token() -> None:
    """Keep the official login endpoint simple for first-party clients."""
    with build_client() as client:
        response = client.post(
            "/v1/auth/token",
            json={"email": "user@example.com", "password": "Senha123!"},
        )
    assert response.status_code == 200
    assert response.json() == {
        "access_token": "keycloak-signed-access-token",
        "expires_in": 600,
        "refresh_expires_in": 1800,
        "refresh_token": "keycloak-signed-refresh-token",
        "token_type": "Bearer",
        "scope": "openid ouros-identity",
    }


def test_token_login_returns_generic_401_for_rejected_credentials() -> None:
    """Keep Keycloak's invalid-grant response free of account-enumeration detail."""
    with build_client(token_broker=InvalidKeycloakTokenBroker()) as client:
        response = client.post(
            "/v1/auth/token",
            json={"email": "user@example.com", "password": "wrong"},
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciais inválidas."}


def test_token_login_returns_503_when_broker_is_unavailable() -> None:
    """Do not leak Keycloak transport or client-secret diagnostics to callers."""
    with build_client(token_broker=UnavailableKeycloakTokenBroker()) as client:
        response = client.post(
            "/v1/auth/token",
            json={"email": "user@example.com", "password": "Senha123!"},
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "Autenticação temporariamente indisponível."}


def test_token_refresh_relays_rotated_keycloak_tokens() -> None:
    """Allow trusted backends to renew a user session without the password."""
    with build_client() as client:
        response = client.post(
            "/v1/auth/token/refresh",
            json={"refresh_token": "keycloak-signed-refresh-token"},
        )

    assert response.status_code == 200
    assert response.json()["access_token"] == "keycloak-signed-access-token"
    assert response.json()["refresh_token"] == "keycloak-signed-refresh-token"


def test_token_refresh_returns_401_for_expired_refresh_token() -> None:
    """Fail closed when Keycloak rejects an expired or revoked refresh token."""
    with build_client(token_broker=InvalidKeycloakTokenBroker()) as client:
        response = client.post(
            "/v1/auth/token/refresh",
            json={"refresh_token": "expired-refresh-token"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciais inválidas."}
