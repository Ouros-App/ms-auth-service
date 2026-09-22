import asyncio
import smtplib
import time
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import EmailOtpInvalidError, EmailOtpUnavailable
from app.services.email_otp import EmailOtpService


class FakeRedis:
    def __init__(self, *, fail: str | None = None) -> None:
        self.fail = fail
        self.data: dict[str, str] = {}
        self.closed = False

    async def ping(self) -> bool:
        if self.fail == "ping":
            raise RedisError("ping failed")
        return True

    async def set(self, key: str, value: str, *, ex: int) -> None:
        if self.fail == "set":
            raise RedisError("set failed")
        assert ex > 0
        self.data[key] = value

    async def get(self, key: str) -> str | None:
        if self.fail == "get":
            raise RedisError("get failed")
        return self.data.get(key)

    async def delete(self, key: str) -> None:
        if self.fail == "delete":
            raise RedisError("delete failed")
        self.data.pop(key, None)

    async def aclose(self) -> None:
        self.closed = True


class FakeSmtp:
    def __init__(self) -> None:
        self.ehlo_calls = 0
        self.starttls_calls = 0
        self.login_args: tuple[str, str] | None = None
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        return None

    def ehlo(self) -> None:
        self.ehlo_calls += 1

    def starttls(self, *, context) -> None:
        assert context is not None
        self.starttls_calls += 1

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)

    def send_message(self, message) -> None:
        self.sent.append(message)


def make_settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql://unused",
        "redis_url": None,
        "ouros_email_otp_enabled": True,
        "ouros_email_otp_hmac_secret": "x" * 32,
        "ouros_smtp_host": "smtp.example.test",
        "ouros_smtp_auth": False,
        "ouros_smtp_starttls": False,
    }
    values.update(overrides)
    return Settings(**values)


def run_verify(
    service: EmailOtpService,
    challenge_id: str,
    email: str,
    code: str,
) -> None:
    asyncio.run(service.verify(challenge_id, email, code))


def test_email_otp_round_trip_uses_hmac_and_consumes_challenge() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=123456),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("User@Example.com"))
        run_verify(service, challenge.challenge_id, "user@example.com", "123456")

    assert challenge.expires_in == 300
    assert challenge.masked_email == "u***@example.com"

    verification = service.verify(
        challenge.challenge_id,
        "user@example.com",
        "123456",
    )
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)


def test_email_otp_rejects_wrong_code_without_consuming_first_attempt() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=654321),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    verification = service.verify(
        challenge.challenge_id,
        "user@example.com",
        "000000",
    )
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)

    run_verify(service, challenge.challenge_id, "user@example.com", "654321")


def test_email_otp_rejects_wrong_email() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=654321),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    verification = service.verify(
        challenge.challenge_id,
        "other@example.com",
        "654321",
    )
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)


def test_email_otp_locks_challenge_after_max_attempts() -> None:
    service = EmailOtpService(make_settings(ouros_email_otp_max_attempts=2))
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=111111),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    for _ in range(2):
        verification = service.verify(
            challenge.challenge_id,
            "user@example.com",
            "999999",
        )
        with pytest.raises(EmailOtpInvalidError):
            asyncio.run(verification)

    verification = service.verify(
        challenge.challenge_id,
        "user@example.com",
        "111111",
    )
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)


def test_email_otp_rejects_expired_challenge() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=222222),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    service._memory[challenge.challenge_id]["expires_at"] = int(time.time()) - 1
    verification = service.verify(
        challenge.challenge_id,
        "user@example.com",
        "222222",
    )
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)


def test_email_otp_rejects_corrupt_challenge_record() -> None:
    service = EmailOtpService(make_settings())
    challenge_id = "corrupt-challenge"
    service._memory[challenge_id] = {
        "email": "user@example.com",
        "expires_at": int(time.time()) + 300,
    }

    verification = service.verify(challenge_id, "user@example.com", "123456")
    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(verification)

    assert challenge_id not in service._memory


def test_email_otp_start_removes_challenge_when_delivery_fails() -> None:
    service = EmailOtpService(make_settings())
    with patch.object(
        service,
        "_send_email",
        side_effect=smtplib.SMTPException("smtp down"),
    ):
        operation = service.start("user@example.com")
        with pytest.raises(EmailOtpUnavailable):
            asyncio.run(operation)

    assert service._memory == {}


def test_email_otp_disabled_fails_closed() -> None:
    service = EmailOtpService(
        make_settings(
            ouros_email_otp_enabled=False,
            ouros_email_otp_hmac_secret=None,
            ouros_smtp_host=None,
        )
    )
    operation = service.start("user@example.com")
    with pytest.raises(EmailOtpUnavailable):
        asyncio.run(operation)


def test_code_digest_requires_hmac_secret() -> None:
    service = EmailOtpService(
        make_settings(
            ouros_email_otp_enabled=False,
            ouros_email_otp_hmac_secret=None,
        )
    )
    with pytest.raises(EmailOtpUnavailable):
        service._code_digest("challenge", "123456")


def test_memory_cleanup_removes_expired_and_malformed_records() -> None:
    service = EmailOtpService(make_settings())
    now = int(time.time())
    service._memory = {
        "expired": {"expires_at": now - 1},
        "malformed": {"expires_at": "not-an-int"},
        "valid": {"expires_at": now + 60},
    }

    service._cleanup_memory()

    assert set(service._memory) == {"valid"}


def test_mask_email_handles_invalid_shape() -> None:
    assert EmailOtpService._mask_email("not-an-email") == "***"


def test_redis_round_trip_persists_and_consumes_challenge() -> None:
    fake = FakeRedis()
    service = EmailOtpService(make_settings(redis_url="redis://example.test/0"))

    with (
        patch("app.services.email_otp.Redis.from_url", return_value=fake),
        patch("app.services.email_otp.secrets.randbelow", return_value=333333),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))
        assert fake.data
        run_verify(service, challenge.challenge_id, "user@example.com", "333333")
        asyncio.run(service.close())

    assert fake.data == {}
    assert fake.closed is True


def test_redis_client_connection_failure_is_generic() -> None:
    fake = FakeRedis(fail="ping")
    service = EmailOtpService(make_settings(redis_url="redis://example.test/0"))

    with patch("app.services.email_otp.Redis.from_url", return_value=fake):
        operation = service._redis_client()
        with pytest.raises(EmailOtpUnavailable):
            asyncio.run(operation)

    assert fake.closed is True


@pytest.mark.parametrize("operation_name", ["set", "get", "delete"])
def test_redis_operation_failure_is_generic(operation_name: str) -> None:
    fake = FakeRedis(fail=operation_name)
    service = EmailOtpService(make_settings(redis_url="redis://example.test/0"))
    service._redis = fake

    if operation_name == "set":
        operation = service._save(
            "challenge",
            {
                "email": "user@example.com",
                "code_digest": "digest",
                "attempts": 0,
                "expires_at": int(time.time()) + 300,
            },
            300,
        )
    elif operation_name == "get":
        operation = service._load("challenge")
    else:
        operation = service._delete("challenge")

    with pytest.raises(EmailOtpUnavailable):
        asyncio.run(operation)

    assert fake.closed is True
    assert service._redis is None


def test_redis_load_handles_missing_and_corrupt_payloads() -> None:
    fake = FakeRedis()
    service = EmailOtpService(make_settings(redis_url="redis://example.test/0"))
    service._redis = fake

    assert asyncio.run(service._load("missing")) is None

    key = service._KEY_PREFIX + "corrupt"
    fake.data[key] = "{"
    assert asyncio.run(service._load("corrupt")) is None
    assert key not in fake.data

    fake.data[key] = "[]"
    assert asyncio.run(service._load("corrupt")) is None


def test_smtp_starttls_and_auth_send_message() -> None:
    smtp = FakeSmtp()
    service = EmailOtpService(
        make_settings(
            ouros_smtp_auth=True,
            ouros_smtp_starttls=True,
            ouros_smtp_user="smtp-user",
            ouros_smtp_password="smtp-password",
        )
    )

    with patch("app.services.email_otp.smtplib.SMTP", return_value=smtp):
        service._send_email("user@example.com", "123456")

    assert smtp.ehlo_calls == 2
    assert smtp.starttls_calls == 1
    assert smtp.login_args == ("smtp-user", "smtp-password")
    assert len(smtp.sent) == 1
    raw_message = smtp.sent[0].as_string()
    assert "123456" in raw_message
    assert "#D8A23A" in raw_message
    assert "#171438" in raw_message
    assert "#010B13" in raw_message
    assert "#F2F5F7" in raw_message
    assert "font-family:Poppins,Arial,sans-serif" in raw_message
    assert "cid:ouros-logo" in raw_message
    assert "Content-ID: <ouros-logo>" in raw_message
    assert 'filename="ouros-logo.png"' in raw_message


def test_branded_email_keeps_plain_text_fallback() -> None:
    service = EmailOtpService(make_settings())

    message = service._build_email_message("user@example.com", "246810")
    plain_body = message.get_body(preferencelist=("plain",))
    html_body = message.get_body(preferencelist=("html",))

    assert plain_body is not None
    assert html_body is not None

    plain = plain_body.get_content()
    html = html_body.get_content()

    assert "Seu código de acesso Ouros é:" in plain
    assert "246810" in plain
    assert "Confirme que é você" in html
    assert "Segurança de acesso" in html
    assert "Ouros &bull; acesso protegido" in html


def test_smtp_ssl_send_message() -> None:
    smtp = FakeSmtp()
    service = EmailOtpService(
        make_settings(
            ouros_smtp_ssl=True,
            ouros_smtp_starttls=False,
        )
    )

    with patch("app.services.email_otp.smtplib.SMTP_SSL", return_value=smtp) as ctor:
        service._send_email("user@example.com", "987654")

    assert ctor.call_args.kwargs["context"] is not None
    assert len(smtp.sent) == 1


def test_smtp_missing_host_fails_closed() -> None:
    service = EmailOtpService(
        make_settings(
            ouros_email_otp_enabled=False,
            ouros_smtp_host=None,
        )
    )
    with pytest.raises(EmailOtpUnavailable):
        service._send_email("user@example.com", "123456")


def test_settings_reject_invalid_otp_and_smtp_combinations() -> None:
    invalid_settings = [
        {"ouros_smtp_starttls": True, "ouros_smtp_ssl": True},
        {
            "ouros_email_otp_enabled": True,
            "ouros_email_otp_hmac_secret": None,
            "ouros_smtp_host": "smtp.example.test",
        },
        {
            "ouros_email_otp_enabled": True,
            "ouros_email_otp_hmac_secret": "short",
            "ouros_smtp_host": "smtp.example.test",
        },
        {
            "ouros_email_otp_enabled": True,
            "ouros_email_otp_hmac_secret": "x" * 32,
            "ouros_smtp_host": None,
        },
        {
            "ouros_email_otp_enabled": True,
            "ouros_email_otp_hmac_secret": "x" * 32,
            "ouros_smtp_host": "smtp.example.test",
            "ouros_smtp_auth": True,
            "ouros_smtp_user": None,
            "ouros_smtp_password": None,
        },
    ]

    for values in invalid_settings:
        with pytest.raises(ValidationError):
            Settings(**values)


def test_long_lived_mobile_sessions_request_offline_access() -> None:
    settings = Settings()
    assert "offline_access" in settings.keycloak_token_broker_scope.split()
