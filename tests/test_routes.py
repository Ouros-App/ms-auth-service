from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import InvalidCredentialsError
from app.main import create_app
from app.models.identity import AccountType
from app.schemas.auth import CredentialVerificationResponse, IdentityResponse


class FakeDatabase:
    def __init__(self, ready: bool = True) -> None:
        self.ready = ready

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def ping(self) -> bool:
        return self.ready


class FakeAuthService:
    async def verify_credentials(self, _request):
        return CredentialVerificationResponse(
            identity=IdentityResponse(
                id=1,
                email="user@example.com",
                account_type=AccountType.FARM_OWNER,
                realm_role="farm_owner",
                farm_id=42,
            )
        )


class RejectingAuthService:
    async def verify_credentials(self, _request):
        raise InvalidCredentialsError


def build_client(*, ready: bool = True, rejecting: bool = False) -> TestClient:
    settings = Settings(database_url="postgresql://unused")
    database = FakeDatabase(ready=ready)
    auth_service = RejectingAuthService() if rejecting else FakeAuthService()
    app = create_app(
        settings=settings,
        database=database,  # type: ignore[arg-type]
        auth_service=auth_service,  # type: ignore[arg-type]
    )
    return TestClient(app)


def test_health_is_liveness_only() -> None:
    with build_client(ready=False) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_checks_database() -> None:
    with build_client(ready=False) as client:
        response = client.get("/ready")
    assert response.status_code == 503


def test_verify_credentials_route() -> None:
    with build_client() as client:
        response = client.post(
            "/v1/auth/credentials/verify",
            json={"email": "user@example.com", "password": "Senha123!"},
        )
    assert response.status_code == 200
    assert response.json()["identity"]["id"] == 1


def test_verify_credentials_returns_generic_401() -> None:
    with build_client(rejecting=True) as client:
        response = client.post(
            "/v1/auth/credentials/verify",
            json={"email": "user@example.com", "password": "wrong"},
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciais inválidas."}
