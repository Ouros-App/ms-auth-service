import asyncio
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.core.errors import EmailOtpInvalidError
from app.services.email_otp import EmailOtpService


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


def test_email_otp_round_trip_uses_hmac_and_consumes_challenge() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=123456),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("User@Example.com"))
        asyncio.run(
            service.verify(
                challenge.challenge_id,
                "user@example.com",
                "123456",
            )
        )

    assert challenge.expires_in == 300
    assert challenge.masked_email == "u***@example.com"

    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(
            service.verify(
                challenge.challenge_id,
                "user@example.com",
                "123456",
            )
        )


def test_email_otp_rejects_wrong_code_without_consuming_first_attempt() -> None:
    service = EmailOtpService(make_settings())
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=654321),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(
            service.verify(
                challenge.challenge_id,
                "user@example.com",
                "000000",
            )
        )

    asyncio.run(
        service.verify(
            challenge.challenge_id,
            "user@example.com",
            "654321",
        )
    )


def test_email_otp_locks_challenge_after_max_attempts() -> None:
    service = EmailOtpService(make_settings(ouros_email_otp_max_attempts=2))
    with (
        patch("app.services.email_otp.secrets.randbelow", return_value=111111),
        patch.object(service, "_send_email"),
    ):
        challenge = asyncio.run(service.start("user@example.com"))

    for _ in range(2):
        with pytest.raises(EmailOtpInvalidError):
            asyncio.run(
                service.verify(
                    challenge.challenge_id,
                    "user@example.com",
                    "999999",
                )
            )

    with pytest.raises(EmailOtpInvalidError):
        asyncio.run(
            service.verify(
                challenge.challenge_id,
                "user@example.com",
                "111111",
            )
        )


def test_long_lived_mobile_sessions_request_offline_access() -> None:
    settings = Settings()
    assert "offline_access" in settings.keycloak_token_broker_scope.split()
