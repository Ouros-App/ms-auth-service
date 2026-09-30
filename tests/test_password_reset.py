import asyncio
import secrets
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings
from app.core.errors import (
    AmbiguousIdentityError,
    EmailOtpUnavailable,
    PasswordResetOtpAttemptsExceededError,
    PasswordResetOtpInvalidError,
    PasswordResetSpringError,
    PasswordResetTokenInvalidError,
)
from app.main import create_app
from app.models.identity import AccountType, StoredIdentity
from app.schemas.auth import (
    PasswordResetConfirmRequest,
    PasswordResetStartRequest,
    PasswordResetVerifyRequest,
)
from app.services.email_otp import EmailOtpChallenge, EmailOtpService
from app.services.password_reset_service import PasswordResetService


def make_settings(**kwargs) -> Settings:
    defaults = {
        "database_url": "postgresql://test:test@localhost:5432/test",
        "redis_url": None,
        "ouros_email_otp_enabled": True,
        "ouros_email_otp_hmac_secret": SecretStr("test-hmac-secret-at-least-32-chars-long"),
        "ouros_smtp_host": "smtp.example.com",
        "ms_spring_api_url": "https://ms-spring-api.test",
        "spring_jwt_secret": SecretStr("test-spring-jwt-secret-at-least-32-chars"),
        "password_reset_jwt_secret": SecretStr("test-reset-jwt-secret-at-least-32-chars"),
        "password_reset_token_ttl_seconds": 600,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


class FakeIdentityRepo:
    def __init__(self, identities: list[StoredIdentity] | None = None) -> None:
        self.identities = identities or []

    async def find_by_email(self, email: str, account_type=None) -> list[StoredIdentity]:
        matches = [i for i in self.identities if i.email.lower() == email.lower()]
        if account_type is not None:
            matches = [i for i in matches if i.account_type == account_type]
        return matches

    async def find_by_external_id(self, account_type, database_id: int):
        for i in self.identities:
            if i.account_type == account_type and i.database_id == database_id:
                return i
        return None


class FakeEmailOtpServiceForReset:
    def __init__(self) -> None:
        self.challenges: dict[str, dict] = {}
        self.fail_send = False

    async def start_password_reset(self, email: str, account_type: str, database_id: int) -> EmailOtpChallenge:
        if self.fail_send:
            raise EmailOtpUnavailable("email delivery failed")
        challenge_id = "test-challenge-" + secrets.token_urlsafe(16)
        self.challenges[challenge_id] = {
            "email": email,
            "account_type": account_type,
            "database_id": database_id,
            "code": "123456",
            "attempts": 0,
        }
        return EmailOtpChallenge(
            challenge_id=challenge_id,
            expires_in=300,
            masked_email=EmailOtpService._mask_email(email),
        )

    async def verify_password_reset(self, challenge_id: str, email: str, code: str) -> dict:
        record = self.challenges.get(challenge_id)
        if not record or record["email"] != email:
            raise PasswordResetOtpInvalidError
        if record["attempts"] >= 5:
            raise PasswordResetOtpAttemptsExceededError
        if code != record["code"]:
            record["attempts"] += 1
            if record["attempts"] >= 5:
                raise PasswordResetOtpAttemptsExceededError
            raise PasswordResetOtpInvalidError
        return dict(record)

    async def close(self) -> None:
        pass


def test_service_start_reset_success_farm_owner():
    settings = make_settings()
    repo = FakeIdentityRepo(
        [
            StoredIdentity(
                database_id=10,
                email="produtor@fazenda.com.br",
                password_hash="hash",
                account_type=AccountType.FARM_OWNER,
            )
        ]
    )
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    response = asyncio.run(
        service.start_reset(
            PasswordResetStartRequest(email="produtor@fazenda.com.br")
        )
    )
    assert response.challenge_id.startswith("test-challenge-")
    assert response.masked_email == "p***@fazenda.com.br"
    assert response.expires_in == 300


def test_service_start_reset_success_company_employee():
    settings = make_settings()
    repo = FakeIdentityRepo(
        [
            StoredIdentity(
                database_id=25,
                email="func@empresa.com.br",
                password_hash="hash",
                account_type=AccountType.COMPANY_EMPLOYEE,
            )
        ]
    )
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    response = asyncio.run(
        service.start_reset(
            PasswordResetStartRequest(email="func@empresa.com.br")
        )
    )
    assert response.challenge_id.startswith("test-challenge-")
    assert response.masked_email == "f***@empresa.com.br"


def test_service_start_reset_nonexistent_email_returns_dummy():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    with patch("app.services.password_reset_service.burn_dummy_password_check") as mock_burn:
        response = asyncio.run(
            service.start_reset(
                PasswordResetStartRequest(email="naoexiste@fazenda.com.br")
            )
        )
        assert mock_burn.called
        assert len(response.challenge_id) > 20
        assert response.masked_email == "n***@fazenda.com.br"
        assert response.expires_in == 300
        # Check that no actual OTP was created
        assert len(otp_service.challenges) == 0


def test_service_start_reset_admin_account_returns_dummy():
    settings = make_settings()
    repo = FakeIdentityRepo(
        [
            StoredIdentity(
                database_id=1,
                email="admin@ouros.com.br",
                password_hash="hash",
                account_type=AccountType.ADMIN,
            )
        ]
    )
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    response = asyncio.run(
        service.start_reset(
            PasswordResetStartRequest(email="admin@ouros.com.br")
        )
    )
    assert response.masked_email == "a***@ouros.com.br"
    assert len(otp_service.challenges) == 0


def test_service_start_reset_ambiguous_identity_raises():
    settings = make_settings()
    repo = FakeIdentityRepo(
        [
            StoredIdentity(database_id=1, email="duplo@fazenda.com.br", password_hash="h1", account_type=AccountType.FARM_OWNER),
            StoredIdentity(database_id=2, email="duplo@fazenda.com.br", password_hash="h2", account_type=AccountType.COMPANY_EMPLOYEE),
        ]
    )
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    with pytest.raises(AmbiguousIdentityError):
        asyncio.run(service.start_reset(PasswordResetStartRequest(email="duplo@fazenda.com.br")))


def test_service_verify_code_success():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    otp_service.challenges["test-challenge-12345678901234567890"] = {
        "email": "user@fazenda.com.br",
        "account_type": "farm_owner",
        "database_id": 42,
        "code": "654321",
        "attempts": 0,
    }

    verify_resp = asyncio.run(
        service.verify_code(
            PasswordResetVerifyRequest(challenge_id="test-challenge-12345678901234567890", email="user@fazenda.com.br", code="654321")
        )
    )
    assert verify_resp.reset_token
    assert verify_resp.expires_in == 600

    # Decoded token verification
    claims = asyncio.run(service._verify_reset_token(verify_resp.reset_token))
    assert claims["sub"] == "user@fazenda.com.br"
    assert claims["account_type"] == "farm_owner"
    assert claims["database_id"] == 42
    assert claims["purpose"] == "password_reset"


def test_service_verify_code_invalid_raises():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    otp_service.challenges["test-challenge-12345678901234567890"] = {
        "email": "user@fazenda.com.br",
        "account_type": "farm_owner",
        "database_id": 42,
        "code": "654321",
        "attempts": 0,
    }

    with pytest.raises(PasswordResetOtpInvalidError):
        asyncio.run(
            service.verify_code(
                PasswordResetVerifyRequest(challenge_id="test-challenge-12345678901234567890", email="user@fazenda.com.br", code="000000")
            )
        )


def test_service_confirm_reset_success_farm_owner():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()

    recorded_requests = []
    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        if request.url.path == "/farm-owners/10" and request.method == "PATCH":
            return httpx.Response(200, json={"id": 10, "email": "produtor@fazenda.com.br"})
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = PasswordResetService(settings, repo, otp_service, http_client=mock_client)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    resp = asyncio.run(
        service.confirm_reset(
            PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
        )
    )
    assert resp.message == "Senha redefinida com sucesso."
    assert len(recorded_requests) == 1

    # Validate header and body sent to Spring
    request = recorded_requests[0]
    assert request.headers["authorization"].startswith("Bearer ")
    assert b"NovaSenhaForte@2026" in request.content


def test_service_confirm_reset_success_company_employee():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()

    recorded_requests = []
    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        if request.url.path == "/company-employees/88" and request.method == "PATCH":
            return httpx.Response(200, json={"id": 88, "email": "func@empresa.com.br"})
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = PasswordResetService(settings, repo, otp_service, http_client=mock_client)

    reset_token = service._mint_reset_token("func@empresa.com.br", "company_employee", 88)

    resp = asyncio.run(
        service.confirm_reset(
            PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
        )
    )
    assert resp.message == "Senha redefinida com sucesso."
    assert len(recorded_requests) == 1


def test_service_confirm_reset_replay_token_rejected():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": 10}))
    )
    service = PasswordResetService(settings, repo, otp_service, http_client=mock_client)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    # First use succeeds
    asyncio.run(
        service.confirm_reset(
            PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
        )
    )

    # Replay attempt fails
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(
            service.confirm_reset(
                PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
            )
        )


def test_service_confirm_reset_spring_error():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(500, text="Internal error"))
    )
    service = PasswordResetService(settings, repo, otp_service, http_client=mock_client)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    with pytest.raises(PasswordResetSpringError) as exc_info:
        asyncio.run(
            service.confirm_reset(
                PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
            )
        )
    assert exc_info.value.status_code == 502


# ---------------- API Route Integration Tests ----------------

class FakeDatabase:
    async def connect(self): pass
    async def close(self): pass
    async def ping(self): return True


def build_test_client(settings=None, identity_repo=None, otp_service=None, http_client=None):
    cfg = settings or make_settings()
    repo = identity_repo or FakeIdentityRepo(
        [
            StoredIdentity(
                database_id=10,
                email="produtor@fazenda.com.br",
                password_hash="hash",
                account_type=AccountType.FARM_OWNER,
            )
        ]
    )
    otp = otp_service or FakeEmailOtpServiceForReset()
    service = PasswordResetService(cfg, repo, otp, http_client=http_client)
    app = create_app(
        settings=cfg,
        database=FakeDatabase(),
        email_otp_service=otp,
        password_reset_service=service,
    )
    return TestClient(app), otp


def test_api_route_start_password_reset_success():
    client, _ = build_test_client()
    resp = client.post(
        "/v1/auth/password/reset/start",
        json={"email": "produtor@fazenda.com.br"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "challenge_id" in data
    assert data["masked_email"] == "p***@fazenda.com.br"
    assert data["expires_in"] == 300


def test_api_route_start_password_reset_dummy():
    client, _ = build_test_client()
    resp = client.post(
        "/v1/auth/password/reset/start",
        json={"email": "desconhecido@fazenda.com.br"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "challenge_id" in data
    assert data["masked_email"] == "d***@fazenda.com.br"


def test_api_route_start_password_reset_invalid_email():
    client, _ = build_test_client()
    resp = client.post(
        "/v1/auth/password/reset/start",
        json={"email": "invalid-email-format"},
    )
    assert resp.status_code == 422


def test_api_route_verify_password_reset_success():
    client, otp = build_test_client()
    # Populate a challenge
    otp.challenges["test-challenge-123456789012"] = {
        "email": "produtor@fazenda.com.br",
        "account_type": "farm_owner",
        "database_id": 10,
        "code": "123456",
        "attempts": 0,
    }

    resp = client.post(
        "/v1/auth/password/reset/verify",
        json={
            "challenge_id": "test-challenge-123456789012",
            "email": "produtor@fazenda.com.br",
            "code": "123456",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "reset_token" in data
    assert data["expires_in"] == 600


def test_api_route_verify_password_reset_invalid_code():
    client, otp = build_test_client()
    otp.challenges["test-challenge-123456789012"] = {
        "email": "produtor@fazenda.com.br",
        "account_type": "farm_owner",
        "database_id": 10,
        "code": "123456",
        "attempts": 0,
    }

    resp = client.post(
        "/v1/auth/password/reset/verify",
        json={
            "challenge_id": "test-challenge-123456789012",
            "email": "produtor@fazenda.com.br",
            "code": "999999",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Código inválido, incorreto ou expirado."


def test_api_route_verify_password_reset_attempts_exceeded():
    client, otp = build_test_client()
    otp.challenges["test-challenge-123456789012"] = {
        "email": "produtor@fazenda.com.br",
        "account_type": "farm_owner",
        "database_id": 10,
        "code": "123456",
        "attempts": 5,
    }

    resp = client.post(
        "/v1/auth/password/reset/verify",
        json={
            "challenge_id": "test-challenge-123456789012",
            "email": "produtor@fazenda.com.br",
            "code": "123456",
        },
    )
    assert resp.status_code == 429
    assert resp.json()["detail"] == "Número máximo de tentativas de digitação do código excedido."


def test_api_route_confirm_password_reset_success():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/farm-owners/10" and request.method == "PATCH":
            return httpx.Response(200, json={"id": 10, "email": "produtor@fazenda.com.br"})
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cfg = make_settings()
    otp = FakeEmailOtpServiceForReset()
    client, _ = build_test_client(settings=cfg, otp_service=otp, http_client=mock_client)

    service = PasswordResetService(cfg, FakeIdentityRepo([]), otp)
    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    resp = client.post(
        "/v1/auth/password/reset/confirm",
        json={
            "reset_token": reset_token,
            "new_password": "NovaSenhaForte@2026",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Senha redefinida com sucesso."


def test_api_route_confirm_password_reset_weak_password():
    client, _ = build_test_client()
    resp = client.post(
        "/v1/auth/password/reset/confirm",
        json={
            "reset_token": "some-token",
            "new_password": "weak",
        },
    )
    assert resp.status_code == 422


def test_api_route_confirm_password_reset_spring_error():
    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(502, text="Bad Gateway"))
    )
    cfg = make_settings()
    otp = FakeEmailOtpServiceForReset()
    client, _ = build_test_client(settings=cfg, otp_service=otp, http_client=mock_client)

    service = PasswordResetService(cfg, FakeIdentityRepo([]), otp)
    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    resp = client.post(
        "/v1/auth/password/reset/confirm",
        json={
            "reset_token": reset_token,
            "new_password": "NovaSenhaForte@2026",
        },
    )
    assert resp.status_code == 502
