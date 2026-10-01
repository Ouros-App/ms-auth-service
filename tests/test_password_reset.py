import asyncio
import secrets
import time
from unittest.mock import patch

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.errors import (
    EmailOtpUnavailable,
    PasswordResetOtpAttemptsExceededError,
    PasswordResetOtpInvalidError,
    PasswordResetTokenInvalidError,
    PasswordResetUnavailable,
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

    async def update_password(self, account_type, database_id: int, password_hash: str) -> bool:
        for idx, i in enumerate(self.identities):
            if i.account_type == account_type and i.database_id == database_id:
                # Update password_hash in identity
                self.identities[idx] = StoredIdentity(
                    database_id=i.database_id,
                    email=i.email,
                    password_hash=password_hash,
                    account_type=i.account_type,
                    name=i.name,
                    farm_id=i.farm_id,
                    enterprise_id=i.enterprise_id,
                    first_access=i.first_access,
                )
                return True
        return False



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

    response = asyncio.run(
        service.start_reset(PasswordResetStartRequest(email="naoexiste@fazenda.com.br"))
    )
    assert len(response.challenge_id) > 20
    assert response.masked_email == "n***@fazenda.com.br"
    assert response.expires_in == 300
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


def test_service_start_reset_ambiguous_identity_returns_dummy():
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
    response = asyncio.run(service.start_reset(req))
    assert len(response.challenge_id) > 20
    assert response.masked_email == "d***@fazenda.com.br"
    assert response.expires_in == 300
    assert not otp_service.challenges


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
    identity = StoredIdentity(
        database_id=10,
        email="produtor@fazenda.com.br",
        password_hash="old-hash",
        account_type=AccountType.FARM_OWNER,
    )
    repo = FakeIdentityRepo([identity])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 10)

    resp = asyncio.run(
        service.confirm_reset(
            PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
        )
    )
    assert resp.message == "Senha redefinida com sucesso."
    updated_user = asyncio.run(repo.find_by_external_id(AccountType.FARM_OWNER, 10))
    assert updated_user is not None
    assert updated_user.password_hash.startswith("$2b$12$")


def test_service_confirm_reset_success_company_employee():
    settings = make_settings()
    identity = StoredIdentity(
        database_id=88,
        email="func@empresa.com.br",
        password_hash="old-hash",
        account_type=AccountType.COMPANY_EMPLOYEE,
    )
    repo = FakeIdentityRepo([identity])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    reset_token = service._mint_reset_token("func@empresa.com.br", "company_employee", 88)

    resp = asyncio.run(
        service.confirm_reset(
            PasswordResetConfirmRequest(reset_token=reset_token, new_password=SecretStr("NovaSenhaForte@2026"))
        )
    )
    assert resp.message == "Senha redefinida com sucesso."
    updated_user = asyncio.run(repo.find_by_external_id(AccountType.COMPANY_EMPLOYEE, 88))
    assert updated_user is not None
    assert updated_user.password_hash.startswith("$2b$12$")


def test_service_confirm_reset_replay_token_rejected():
    settings = make_settings()
    identity = StoredIdentity(
        database_id=10,
        email="produtor@fazenda.com.br",
        password_hash="old-hash",
        account_type=AccountType.FARM_OWNER,
    )
    repo = FakeIdentityRepo([identity])
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

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


def test_service_confirm_reset_user_not_found_in_database():
    settings = make_settings()
    repo = FakeIdentityRepo([])  # empty repo
    otp_service = FakeEmailOtpServiceForReset()
    service = PasswordResetService(settings, repo, otp_service)

    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 999)

    err_req = PasswordResetConfirmRequest(
        reset_token=reset_token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    coro_err = service.confirm_reset(err_req)
    with pytest.raises(PasswordResetTokenInvalidError) as exc_info:
        asyncio.run(coro_err)
    assert "Usuário não encontrado" in str(exc_info.value)



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
    cfg = make_settings()
    identity = StoredIdentity(
        database_id=10,
        email="produtor@fazenda.com.br",
        password_hash="old-hash",
        account_type=AccountType.FARM_OWNER,
    )
    repo = FakeIdentityRepo([identity])
    otp = FakeEmailOtpServiceForReset()
    client, _ = build_test_client(settings=cfg, identity_repo=repo, otp_service=otp)

    service = PasswordResetService(cfg, repo, otp)
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
    updated_user = asyncio.run(repo.find_by_external_id(AccountType.FARM_OWNER, 10))
    assert updated_user is not None
    assert updated_user.password_hash.startswith("$2b$12$")


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


def test_api_route_confirm_password_reset_user_not_found():
    cfg = make_settings()
    repo = FakeIdentityRepo([])
    otp = FakeEmailOtpServiceForReset()
    client, _ = build_test_client(settings=cfg, identity_repo=repo, otp_service=otp)

    service = PasswordResetService(cfg, repo, otp)
    reset_token = service._mint_reset_token("produtor@fazenda.com.br", "farm_owner", 999)

    resp = client.post(
        "/v1/auth/password/reset/confirm",
        json={
            "reset_token": reset_token,
            "new_password": "NovaSenhaForte@2026",
        },
    )
    assert resp.status_code == 400
    assert "Usuário não encontrado" in resp.json()["detail"]



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

    async def set(self, key: str, value: str, *, ex: int, nx: bool) -> bool:
        if self.fail == "set":
            from redis.exceptions import RedisError
            raise RedisError("set fail")
        assert ex > 0
        assert nx is True
        if key in self.data:
            return False
        self.data[key] = value
        return True

    async def delete(self, key: str) -> None:
        if self.fail == "delete":
            from redis.exceptions import RedisError
            raise RedisError("delete fail")
        self.data.pop(key, None)

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


def test_password_reset_jwt_secret_fallbacks() -> None:
    # 1. When dedicated secret is provided, it is used
    cfg1 = make_settings(
        password_reset_jwt_secret=SecretStr("custom-reset-secret-with-at-least-32-chars"),
        ouros_email_otp_hmac_secret=SecretStr("fallback-hmac-secret-at-least-32-chars"),
    )
    svc1 = PasswordResetService(cfg1, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc1._get_reset_jwt_secret() == "custom-reset-secret-with-at-least-32-chars"

    # 2. When dedicated secret is absent, falls back to ouros_email_otp_hmac_secret
    cfg2 = make_settings(
        password_reset_jwt_secret=None,
        ouros_email_otp_hmac_secret=SecretStr("fallback-hmac-secret-at-least-32-chars"),
    )
    svc2 = PasswordResetService(cfg2, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc2._get_reset_jwt_secret() == "fallback-hmac-secret-at-least-32-chars"

    # 3. When dedicated secret and email otp hmac secret are absent, falls back to spring_jwt_secret
    cfg3 = make_settings(
        password_reset_jwt_secret=None,
        ouros_email_otp_enabled=False,
        ouros_email_otp_hmac_secret=None,
        spring_jwt_secret=SecretStr("fallback-spring-secret-at-least-32-chars"),
    )
    svc3 = PasswordResetService(cfg3, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc3._get_reset_jwt_secret() == "fallback-spring-secret-at-least-32-chars"

    # 4. When all secrets are absent, falls back to dev default key
    cfg4 = make_settings(
        password_reset_jwt_secret=None,
        ouros_email_otp_enabled=False,
        ouros_email_otp_hmac_secret=None,
        spring_jwt_secret=None,
    )
    svc4 = PasswordResetService(cfg4, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc4._get_reset_jwt_secret() == "ouros-dev-password-reset-secret-key-32-chars-minimum"


def test_password_reset_spring_secret_fallbacks() -> None:
    # 1. When spring_jwt_secret is provided, it is used
    cfg1 = make_settings(
        spring_jwt_secret=SecretStr("custom-spring-secret-at-least-32-chars"),
        password_reset_jwt_secret=SecretStr("fallback-reset-secret-at-least-32-chars"),
    )
    svc1 = PasswordResetService(cfg1, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc1._get_spring_jwt_secret() == "custom-spring-secret-at-least-32-chars"

    # 2. When spring_jwt_secret is absent, falls back to password_reset_jwt_secret
    cfg2 = make_settings(
        spring_jwt_secret=None,
        password_reset_jwt_secret=SecretStr("fallback-reset-secret-at-least-32-chars"),
    )
    svc2 = PasswordResetService(cfg2, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc2._get_spring_jwt_secret() == "fallback-reset-secret-at-least-32-chars"

    # 3. When spring_jwt_secret and password_reset_jwt_secret are absent, falls back to ouros_email_otp_hmac_secret
    cfg3 = make_settings(
        spring_jwt_secret=None,
        password_reset_jwt_secret=None,
        ouros_email_otp_hmac_secret=SecretStr("fallback-hmac-secret-at-least-32-chars"),
    )
    svc3 = PasswordResetService(cfg3, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc3._get_spring_jwt_secret() == "fallback-hmac-secret-at-least-32-chars"

    # 4. When all secrets are absent, falls back to dev default key
    cfg4 = make_settings(
        spring_jwt_secret=None,
        password_reset_jwt_secret=None,
        ouros_email_otp_enabled=False,
        ouros_email_otp_hmac_secret=None,
    )
    svc4 = PasswordResetService(cfg4, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    assert svc4._get_spring_jwt_secret() == "ouros-dev-spring-delegation-secret-key-32-chars-minimum"


@pytest.mark.parametrize("environment", ["production", "staging", "test", "development"])
def test_environment_allows_omitted_jwt_secrets(environment: str) -> None:
    cfg = make_settings(
        environment=environment,
        password_reset_jwt_secret=None,
        spring_jwt_secret=None,
    )
    assert cfg.password_reset_jwt_secret is None
    assert cfg.spring_jwt_secret is None


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


def test_password_reset_database_error_releases_token() -> None:
    class ErrorIdentityRepo(FakeIdentityRepo):
        async def update_password(self, account_type, database_id: int, password_hash: str) -> bool:
            raise RuntimeError("Database connection lost")

    service = PasswordResetService(make_settings(), ErrorIdentityRepo([]), FakeEmailOtpServiceForReset())
    token = service._mint_reset_token("u@f.com", "farm_owner", 1)
    req = PasswordResetConfirmRequest(
        reset_token=token,
        new_password=SecretStr("NovaSenhaForte@2026"),
    )
    with pytest.raises(RuntimeError, match="Database connection lost"):
        asyncio.run(service.confirm_reset(req))

    # Token should be released from blacklist on failure
    assert service._blacklist_memory.get(service._verify_reset_token(token)["jti"]) is None



def test_password_reset_redis_blacklist_operations() -> None:
    cfg = make_settings(redis_url="redis://localhost:6379/0")
    service = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    fake_redis = FakeAsyncRedis()

    with patch("redis.asyncio.Redis.from_url", return_value=fake_redis):
        asyncio.run(service._reserve_token("test-jti-1", 60))
        with pytest.raises(PasswordResetTokenInvalidError):
            asyncio.run(service._reserve_token("test-jti-1", 60))
        asyncio.run(service._release_token("test-jti-1"))
        asyncio.run(service._reserve_token("test-jti-1", 60))

    # Test Redis ping error
    service_ping_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="ping")):
        coro_ping = service_ping_err._redis_client()
        with pytest.raises(PasswordResetUnavailable):
            asyncio.run(coro_ping)

    # Test Redis delete error
    service_delete_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="delete")):
        coro_delete = service_delete_err._release_token("some-jti")
        with pytest.raises(PasswordResetUnavailable):
            asyncio.run(coro_delete)

    # Test Redis set error
    service_set_err = PasswordResetService(cfg, FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    with patch("redis.asyncio.Redis.from_url", return_value=FakeAsyncRedis(fail="set")):
        coro_set = service_set_err._reserve_token("some-jti", 60)
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



@pytest.mark.parametrize("password", ["ValidPass1!\n", "ValidPass1!\r\n", "Valid\nPass1!"])
def test_new_password_rejects_line_breaks(password):
    with pytest.raises(ValidationError):
        PasswordResetConfirmRequest(reset_token="token", new_password=password)

    service = PasswordResetService(make_settings(), FakeIdentityRepo([]), FakeEmailOtpServiceForReset())
    token = service._mint_reset_token("user@example.com", "farm_owner", 1)
    request = PasswordResetConfirmRequest.model_construct(
        reset_token=token, new_password=SecretStr(password)
    )
    with pytest.raises(PasswordResetTokenInvalidError):
        asyncio.run(service.confirm_reset(request))


def test_start_reset_otp_unavailable_returns_generic_response(caplog):
    identity = StoredIdentity(
        database_id=1, email="user@example.com", password_hash="unused",
        account_type=AccountType.FARM_OWNER,
    )
    otp = FakeEmailOtpServiceForReset()
    otp.fail_send = True
    service = PasswordResetService(make_settings(), FakeIdentityRepo([identity]), otp)
    response = asyncio.run(service.start_reset(PasswordResetStartRequest(email=identity.email)))
    assert len(response.challenge_id) > 20
    assert response.masked_email == "u***@example.com"
    assert response.expires_in == 300
    assert "password_reset_challenge_unavailable" in caplog.text


def test_concurrent_confirmations_only_update_once(reset_backend_url):
    async def run():
        entered_update = asyncio.Event()
        release_update = asyncio.Event()
        update_calls = []

        class SlowIdentityRepo(FakeIdentityRepo):
            async def update_password(self, account_type, database_id: int, password_hash: str) -> bool:
                update_calls.append((account_type, database_id, password_hash))
                entered_update.set()
                await release_update.wait()
                return await super().update_password(account_type, database_id, password_hash)

        identity = StoredIdentity(
            database_id=1, email="user@example.com", password_hash="old-hash",
            account_type=AccountType.FARM_OWNER,
        )
        repo = SlowIdentityRepo([identity])
        service = PasswordResetService(
            make_settings(redis_url=reset_backend_url),
            repo,
            FakeEmailOtpServiceForReset(),
        )
        request = PasswordResetConfirmRequest(
            reset_token=service._mint_reset_token("user@example.com", "farm_owner", 1),
            new_password="ValidPass1!",
        )
        first = asyncio.create_task(service.confirm_reset(request))
        try:
            await asyncio.wait_for(entered_update.wait(), timeout=2)
            # The first update remains in-flight while a competing confirmation runs.
            with pytest.raises(PasswordResetTokenInvalidError):
                await asyncio.wait_for(service.confirm_reset(request), timeout=2)
        finally:
            release_update.set()
            result = await first
            await service.close()
        assert result.message == "Senha redefinida com sucesso."
        assert len(update_calls) == 1

    asyncio.run(run())


def test_failed_update_releases_reservation_for_retry(reset_backend_url):
    async def run():
        update_calls = []

        class FailingFirstIdentityRepo(FakeIdentityRepo):
            async def update_password(self, account_type, database_id: int, password_hash: str) -> bool:
                update_calls.append((account_type, database_id, password_hash))
                if len(update_calls) == 1:
                    raise RuntimeError("database transient error")
                return await super().update_password(account_type, database_id, password_hash)

        identity = StoredIdentity(
            database_id=1, email="user@example.com", password_hash="old-hash",
            account_type=AccountType.FARM_OWNER,
        )
        repo = FailingFirstIdentityRepo([identity])
        service = PasswordResetService(
            make_settings(redis_url=reset_backend_url),
            repo,
            FakeEmailOtpServiceForReset(),
        )
        request = PasswordResetConfirmRequest(
            reset_token=service._mint_reset_token("user@example.com", "farm_owner", 1),
            new_password="ValidPass1!",
        )
        try:
            with pytest.raises(RuntimeError, match="database transient error"):
                await service.confirm_reset(request)
            # Second attempt succeeds because reservation was released on failure
            await service.confirm_reset(request)
            # Third attempt fails because token was successfully consumed and kept in blacklist
            with pytest.raises(PasswordResetTokenInvalidError):
                await service.confirm_reset(request)
            assert len(update_calls) == 2
        finally:
            await service.close()

    asyncio.run(run())

