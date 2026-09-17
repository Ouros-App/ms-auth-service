import asyncio

import pytest
from starlette.requests import Request

from app.core.config import Settings
from app.core.errors import RateLimitExceeded
from app.core.rate_limit import RateLimiter


def make_request(ip: str = "203.0.113.10") -> Request:
    """Build a minimal request carrying a deterministic source address."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/auth/credentials/verify",
        "headers": [],
        "client": (ip, 12345),
    }
    return Request(scope)


def test_burst_limit_blocks_fourth_attempt() -> None:
    """Block the fourth attempt inside a three-request burst window."""
    settings = Settings(
        database_url="postgresql://unused",
        redis_url=None,
        auth_rate_limit_ip_burst=3,
        auth_rate_limit_ip_burst_window_seconds=10,
        auth_rate_limit_ip_per_minute=100,
        auth_rate_limit_ip_per_15_minutes=100,
        auth_rate_limit_email_per_15_minutes=100,
    )
    limiter = RateLimiter(settings)
    request = make_request()

    async def scenario() -> None:
        for _ in range(3):
            await limiter.check_credentials_attempt(request, "user@example.com")

        with pytest.raises(RateLimitExceeded) as error:
            await limiter.check_credentials_attempt(request, "user@example.com")

        assert error.value.retry_after >= 1

    asyncio.run(scenario())


def test_email_limit_is_shared_across_ips() -> None:
    """Normalize email counters independently from the request source IP."""
    settings = Settings(
        database_url="postgresql://unused",
        redis_url=None,
        auth_rate_limit_ip_burst=100,
        auth_rate_limit_ip_per_minute=100,
        auth_rate_limit_ip_per_15_minutes=100,
        auth_rate_limit_email_per_15_minutes=2,
    )
    limiter = RateLimiter(settings)

    async def scenario() -> None:
        await limiter.check_credentials_attempt(
            make_request("203.0.113.10"), "User@Example.com"
        )
        await limiter.check_credentials_attempt(
            make_request("203.0.113.11"), "user@example.com"
        )

        with pytest.raises(RateLimitExceeded):
            await limiter.check_credentials_attempt(
                make_request("203.0.113.12"), "USER@example.com"
            )

    asyncio.run(scenario())
