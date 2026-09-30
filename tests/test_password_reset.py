import asyncio
import secrets
import time
from unittest.mock import patch

import httpx
import jwt
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

    req = PasswordResetStartRequest(email="duplo@fazenda.com.br")
    coro = service.start_reset(req)
    with pytest.raises(AmbiguousIdentityError):
        asyncio.run(coro)


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
    claims = service._verify_reset_token(verify_resp.reset_token)
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

    req = PasswordResetVerifyRequest(
        challenge_id="test-challenge-12345678901234567890",
        email="user@fazenda.com.br",
        code="000000",
    )
    coro = service.verify_code(req)
    with pytest.raises(PasswordResetOtpInvalidError):
        asyncio.run(coro)


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
    replay_req = PasswordResetConfirmRequest(
        reset_token=reset_token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_replay = service.confirm_reset(replay_req)
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(coro_replay)


def test_service_confirm_reset_spring_error():
    settings = make_settings()
    repo = FakeIdentityRepo([])
    otp_service = FakeEmailOtpServiceForReset()
    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(500, text="Internal error"))
    )
    service = PasswordResetService(settings, repo, otp_service, http_client=mock_client)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    err_req = PasswordResetConfirmRequest(
        reset_token=reset_token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_err = service.confirm_reset(err_req)
    with pytest.raises(PasswordResetSpringError) as exc_info:
        asyncio.run(coro_err)
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


class FakeAsyncRedis:
    def __init__(self, *, fail: str | None = None) -> None:
        self.data: dict[str, str] = {}
        self.closed = False
        self.fail = fail

    async def ping(self) -> bool:
        if self.fail == "ping":
            from redis.exceptions import RedisError
            raise RedisError("ping fail")
        return True

    async def exists(self, key: str) -> int:
        if self.fail == "exists":
            from redis.exceptions import RedisError
            raise RedisError("exists fail")
        return 1 if key in self.data else 0

    async def set(self, key: str, value: str, *, ex: int) -> None:
        if self.fail == "set":
            from redis.exceptions import RedisError
            raise RedisError("set fail")
        self.data[key] = value

    async def aclose(self) -> None:
        self.closed = True


def test_password_reset_service_close() -> None:
    service = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    fake_redis = FakeAsyncRedis()
    mock_http = httpx.AsyncClient()
    service._redis = fake_redis
    service._http_client = mock_http

    asyncio.run(service.close())
    assert fake_redis.closed
    assert service._redis is None
    assert mock_http.is_closed


def test_password_reset_default_secrets() -> None:
    cfg = Settings(
        database_url="postgresql://unused",
        password_reset_jwt_secret=None,
        ouros_email_otp_hmac_secret=None,
        spring_jwt_secret=None,
    )
    service = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert service._get_reset_jwt_secret() == "ouros-dev-password-reset-secret-key-32-chars-minimum"
    assert service._get_spring_jwt_secret() == "ouros-dev-spring-delegation-secret-key-32-chars-minimum"


def test_password_reset_invalid_tokens_and_roles() -> None:
    service = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset())

    # Invalid purpose
    bad_purpose_token = jwt.encode(
        {"sub": "u@f.com", "account_type": "farm_owner", "database_id": 1, "purpose": "login", "jti": "j1", "exp": int(time.time()) + 60, "iat": int(time.time())},
        service._get_reset_jwt_secret(),
        algorithm="HS256",
    )
    bad_req = PasswordResetConfirmRequest(
        reset_token=bad_purpose_token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_bad = service.confirm_reset(bad_req)
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(coro_bad)

    # Invalid token signature
    invalid_sig_req = PasswordResetConfirmRequest(
        reset_token="invalid.jwt.token",
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_invalid_sig = service.confirm_reset(invalid_sig_req)
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(coro_invalid_sig)

    # Invalid account_type (admin)
    admin_token = service._mint_reset_token("admin@f.com", "admin", 1)
    admin_req = PasswordResetConfirmRequest(
        reset_token=admin_token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_admin = service.confirm_reset(admin_req)
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(coro_admin)

    # Password complexity failure
    valid_token = service._mint_reset_token("u@f.com", "farm_owner", 1)
    weak_req = PasswordResetConfirmRequest.model_construct(
        reset_token=valid_token,
        new_password=SecretStr("fraca"),
    )
    coro_weak = service.confirm_reset(weak_req)
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(coro_weak)


def test_password_reset_spring_error_variants() -> None:
    # Spring 400 with invalid json body
    mock_client_400 = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(400, text="not json"))
    )
    service_400 = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset(), http_client=mock_client_400)
    token = service_400._mint_reset_token("u@f.com", "farm_owner", 1)
    req_400 = PasswordResetConfirmRequest(
        reset_token=token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_400 = service_400.confirm_reset(req_400)
    with pytest.raises(PasswordResetSpringError) as exc_400:
        asyncio.run(coro_400)
    assert exc_400.value.status_code == 400

    # Spring 404
    mock_client_404 = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(404))
    )
    service_404 = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset(), http_client=mock_client_404)
    req_404 = PasswordResetConfirmRequest(
        reset_token=token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_404 = service_404.confirm_reset(req_404)
    with pytest.raises(PasswordResetSpringError) as exc_404:
        asyncio.run(coro_404)
    assert exc_404.value.status_code == 404

    # Spring 401/403
    mock_client_401 = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(401))
    )
    service_401 = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset(), http_client=mock_client_401)
    req_401 = PasswordResetConfirmRequest(
        reset_token=token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_401 = service_401.confirm_reset(req_401)
    with pytest.raises(PasswordResetSpringError) as exc_401:
        asyncio.run(coro_401)
    assert exc_401.value.status_code == 502

    # Network connection error
    def network_error_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    mock_client_err = httpx.AsyncClient(transport=httpx.MockTransport(network_error_handler))
    service_err = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset(), http_client=mock_client_err)
    req_err = PasswordResetConfirmRequest(
        reset_token=token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_err = service_err.confirm_reset(req_err)
    with pytest.raises(PasswordResetSpringError) as exc_err:
        asyncio.run(coro_err)
    assert exc_err.value.status_code == 502


def test_password_reset_redis_blacklist_operations() -> None:
    from app.core.errors import PasswordResetUnavailable

    cfg = make_settings(redis_url="redis://localhost:6379/0")
    service = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    fake_redis = FakeAsyncRedis()

    with patch("redis.asyncio.Redis.from_url", return_value=fake_redis):
        # Initial blacklist check is False
        assert not asyncio.run(service._is_blacklisted("test-jti-1"))

        # Blacklist the token
        asyncio.run(service._blacklist_token("test-jti-1", 60))

        # Now blacklist check is True
        assert asyncio.run(service._is_blacklisted("test-jti-1"))

    # Test Redis ping error
    service_ping_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="ping")):
        coro_ping = service_ping_err._redis_client()
        with pytest.raises(PasswordResetUnavailable):
            asyncio.run(coro_ping)

    # Test Redis exists error
    service_exists_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="exists")):
        coro_exists = service_exists_err._is_blacklisted("some-jti")
        with pytest.raises(PasswordResetUnavailable):
            asyncio.run(coro_exists)

    # Test Redis set error
    service_set_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="set")):
        coro_set = service_set_err._blacklist_token("some-jti", 60)
        with pytest.raises(PasswordResetUnavailable):
            asyncio.run(coro_set)


def test_password_reset_memory_cleanup() -> None:
    service = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    service._blacklist_memory["expired-1"] = time.time() - 100
    service._blacklist_memory["valid-1"] = time.time() + 100

    service._cleanup_blacklist_memory(time.time())
    assert "expired-1" not in service._blacklist_memory
    assert "valid-1" in service._blacklist_memory


def test_api_route_start_password_reset_rate_limit_exceeded() -> None:
    client, _ = build_test_client()
    for _ in range(3):
        resp = client.post(
            "/v1/auth/password/reset/start",
            json={"email": "produtor@fazenda.com.br"},
        )
        assert resp.status_code == 200

    # 4th request from same client triggers rate limiting
    resp4 = client.post(
        "/v1/auth/password/reset/start",
        json={"email": "produtor@fazenda.com.br"},
    )
    assert resp4.status_code == 429

