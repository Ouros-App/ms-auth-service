from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.models.identity import AccountType
from app.schemas.auth import CredentialVerificationResponse, IdentityResponse


class FakeDatabase:
    """Minimal database double for app lifespan wiring."""

    async def close(self) -> None:
        """Mirror production cleanup."""
        return

    async def ping(self) -> bool:
        """Keep readiness available in tests."""
        return True


class FakeServiceTokenVerifier:
    """Accept one deterministic service bearer token."""

    def __init__(self) -> None:
        self.headers: list[str | None] = []

    async def verify_authorization_header(self, authorization: str | None):
        """Record and validate the synthetic token."""
        from app.core.service_auth import ServiceAuthenticationError

        self.headers.append(authorization)
        if authorization != "Bearer internal-token":
            raise ServiceAuthenticationError("invalid")
        return {"azp": "keycloak-user-storage"}


class FakeAuthService:
    """Provide deterministic external identity operations."""

    @staticmethod
    def identity() -> IdentityResponse:
        """Return one farm-owner identity."""
        return IdentityResponse(
            id=12,
            email="user@example.com",
            account_type=AccountType.FARM_OWNER,
            realm_role="farm_owner",
            name="User Test",
            farm_id=7,
            first_access=False,
        )

    async def lookup_identity_by_email(self, _email: str):
        """Return the synthetic identity."""
        return self.identity()

    async def lookup_identity_by_external_id(
        self,
        _account_type: AccountType,
        _database_id: int,
    ):
        """Return the synthetic identity by stable id."""
        return self.identity()

    async def verify_credentials(self, _payload):
        """Return a successful credential verification."""
        return CredentialVerificationResponse(identity=self.identity())


def build_client() -> tuple[TestClient, FakeServiceTokenVerifier]:
    """Build an app with no network or external secret dependency."""
    verifier = FakeServiceTokenVerifier()
    app = create_app(
        settings=Settings(database_url="postgresql://unused", redis_url=None),
        database=FakeDatabase(),  # type: ignore[arg-type]
        auth_service=FakeAuthService(),  # type: ignore[arg-type]
        service_token_verifier=verifier,  # type: ignore[arg-type]
    )
    return TestClient(app), verifier


def test_internal_lookup_requires_service_token() -> None:
    """Reject callers that do not present the Keycloak service identity."""
    client, _verifier = build_client()
    with client:
        response = client.get(
            "/internal/v1/identities/by-email",
            params={"email": "user@example.com"},
        )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_internal_lookup_by_email() -> None:
    """Return normalized identity data to the trusted Keycloak SPI."""
    client, verifier = build_client()
    with client:
        response = client.get(
            "/internal/v1/identities/by-email",
            params={"email": "user@example.com"},
            headers={"Authorization": "Bearer internal-token"},
        )
    assert response.status_code == 200
    assert response.json()["id"] == 12
    assert response.json()["realm_role"] == "farm_owner"
    assert verifier.headers == ["Bearer internal-token"]


def test_internal_lookup_by_external_id() -> None:
    """Resolve the stable account-type and database-id storage key."""
    client, _verifier = build_client()
    with client:
        response = client.get(
            "/internal/v1/identities/farm_owner/12",
            headers={"Authorization": "Bearer internal-token"},
        )
    assert response.status_code == 200
    assert response.json()["farm_id"] == 7


def test_internal_credential_verification() -> None:
    """Verify credentials without exposing the public rate-limit path."""
    client, _verifier = build_client()
    with client:
        response = client.post(
            "/internal/v1/credentials/verify",
            headers={"Authorization": "Bearer internal-token"},
            json={
                "email": "user@example.com",
                "password": "test-password",
                "account_type": "farm_owner",
            },
        )
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
