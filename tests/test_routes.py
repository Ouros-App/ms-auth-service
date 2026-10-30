from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import EmailOtpInvalidError, InvalidCredentialsError
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


class FakeEmailOtpService:
    """Deterministic native OTP service for route tests."""

    async def start(self, email: str):
        return SimpleNamespace(
            challenge_id="challenge-012345678901234567890123",
            expires_in=300,
            masked_email="u***@example.com",
            email=email,
        )

    async def verify(self, challenge_id: str, email: str, code: str) -> None:
        if challenge_id != "challenge-012345678901234567890123" or code != "123456":
            raise EmailOtpInvalidError
        assert email == "user@example.com"

    async def close(self) -> None:
        return


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
    email_otp_service=None,
    password_broker_enabled: bool = True,
    environment: str = "development",
    origins: str = "",
) -> TestClient:
    """Build an isolated app that never inherits CI Redis configuration."""
    settings = Settings(
        database_url="postgresql://unused",
        redis_url=None,
        environment=environment,
        ouros_web_allowed_origins=origins,
        keycloak_password_broker_enabled=password_broker_enabled,
    )
    database = FakeDatabase(ready=ready)
    auth_service = RejectingAuthService() if rejecting else FakeAuthService()
    token_broker = token_broker or FakeKeycloakTokenBroker()
    email_otp_service = email_otp_service or FakeEmailOtpService()
    app = create_app(
        settings=settings,
        database=database,  # type: ignore[arg-type]
        auth_service=auth_service,  # type: ignore[arg-type]
        keycloak_token_broker=token_broker,  # type: ignore[arg-type]
        email_otp_service=email_otp_service,  # type: ignore[arg-type]
    )
    return TestClient(app)


def test_web_session_login_refresh_and_logout() -> None:
    origin = {"Origin": "https://web.example.com"}
    with build_client(environment="production", origins="https://web.example.com/") as client:
        preflight = client.options("/v1/auth/web/token/refresh", headers={
            **origin, "Access-Control-Request-Method": "POST"
        })
        assert preflight.headers["access-control-allow-credentials"] == "true"
        login = client.post("/v1/auth/web/login/verify", headers=origin, json={
            "challenge_id": "challenge-012345678901234567890123",
            "email": "user@example.com", "password": "Senha123!", "code": "123456",
        })
        assert login.status_code == 200
        assert "refresh_token" not in login.json()
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "Secure" in login.headers["set-cookie"]
        assert "SameSite=none" in login.headers["set-cookie"]
        refresh = client.post("/v1/auth/web/token/refresh", headers=origin)
        assert refresh.status_code == 200
        assert "refresh_token" not in refresh.json()
        logout = client.post("/v1/auth/web/logout", headers=origin)
        assert logout.status_code == 204
        assert "Max-Age=0" in logout.headers["set-cookie"]
        assert client.post("/v1/auth/web/token/refresh", headers=origin).status_code == 401


def test_web_session_rejects_untrusted_origin_and_invalid_otp() -> None:
    with build_client() as client:
        assert client.post("/v1/auth/web/logout").status_code == 403
        assert client.post("/v1/auth/web/logout", headers={"Origin": "https://evil.example"}).status_code == 403
        response = client.post("/v1/auth/web/login/verify", headers={"Origin": "http://localhost:5173"}, json={
            "challenge_id": "challenge-012345678901234567890123",
            "email": "user@example.com", "password": "Senha123!", "code": "000000",
        })
        assert response.status_code == 401


def test_web_origin_configuration() -> None:
    assert Settings(environment="production", ouros_web_allowed_origins="").web_allowed_origins == []
    assert Settings(environment="development", ouros_web_allowed_origins="").web_allowed_origins == ["http://localhost:5173"]
    assert Settings(ouros_web_allowed_origins=" https://a.example/, ,https://b.example ").web_allowed_origins == ["https://a.example", "https://b.example"]


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


def test_native_login_sends_email_challenge_before_issuing_tokens() -> None:
    with build_client() as client:
        response = client.post(
            "/v1/auth/login/start",
            json={"email": "user@example.com", "password": "Senha123!"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "challenge_id": "challenge-012345678901234567890123",
        "expires_in": 300,
        "masked_email": "u***@example.com",
    }


def test_native_login_verifies_code_then_issues_keycloak_tokens() -> None:
    with build_client() as client:
        response = client.post(
            "/v1/auth/login/verify",
            json={
                "challenge_id": "challenge-012345678901234567890123",
                "email": "user@example.com",
                "password": "Senha123!",
                "code": "123456",
            },
        )

    assert response.status_code == 200
    assert response.json()["access_token"] == "keycloak-signed-access-token"


def test_native_login_rejects_invalid_email_code() -> None:
    with build_client() as client:
        response = client.post(
            "/v1/auth/login/verify",
            json={
                "challenge_id": "challenge-012345678901234567890123",
                "email": "user@example.com",
                "password": "Senha123!",
                "code": "000000",
            },
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Código inválido ou expirado."}


def test_native_login_survives_legacy_direct_login_cutover() -> None:
    with build_client(password_broker_enabled=False) as client:
        start = client.post(
            "/v1/auth/login/start",
            json={"email": "user@example.com", "password": "Senha123!"},
        )
        verify = client.post(
            "/v1/auth/login/verify",
            json={
                "challenge_id": "challenge-012345678901234567890123",
                "email": "user@example.com",
                "password": "Senha123!",
                "code": "123456",
            },
        )

    assert start.status_code == 200
    assert verify.status_code == 200


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


def test_token_login_is_hidden_after_password_broker_cutover() -> None:
    """Prevent Direct Grant from bypassing the interactive OTP browser flow."""
    with build_client(password_broker_enabled=False) as client:
        response = client.post(
            "/v1/auth/token",
            json={"email": "user@example.com", "password": "Senha123!"},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_token_refresh_remains_available_after_direct_login_cutover() -> None:
    """Silent refresh must not force users through password + OTP again."""
    with build_client(password_broker_enabled=False) as client:
        response = client.post(
            "/v1/auth/token/refresh",
            json={"refresh_token": "keycloak-signed-refresh-token"},
        )

    assert response.status_code == 200
    assert response.json()["access_token"] == "keycloak-signed-access-token"



def test_disabled_token_login_hides_malformed_json() -> None:
    """Return 404 before FastAPI parses a disabled legacy login body."""
    with build_client(password_broker_enabled=False) as client:
        response = client.post(
            "/v1/auth/token",
            content="{",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_disabled_direct_login_does_not_hide_refresh_validation() -> None:
    """Refresh stays public to the app, so malformed payloads are still validated."""
    with build_client(password_broker_enabled=False) as client:
        response = client.post(
            "/v1/auth/token/refresh",
            content="{",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 422


def test_token_refresh_returns_401_for_expired_refresh_token() -> None:
    """Fail closed when Keycloak rejects an expired or revoked refresh token."""
    with build_client(token_broker=InvalidKeycloakTokenBroker()) as client:
        response = client.post(
            "/v1/auth/token/refresh",
            json={"refresh_token": "expired-refresh-token"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciais inválidas."}
