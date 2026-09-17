import asyncio

import pytest
from starlette.requests import Request

from app.core.config import Settings
from app.core.errors import RateLimitExceeded
from app.core.rate_limit import RateLimiter


def make_request(
    ip: str = "203.0.113.10",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    """Build a minimal request carrying a deterministic source address."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/auth/credentials/verify",
        "headers": headers or [],
        "client": (ip, 12345),
    }
    return Request(scope)


def make_settings(**overrides: object) -> Settings:
    """Build isolated rate-limit settings without inheriting CI Redis state."""
    values = {
        "database_url": "postgresql://unused",
        "redis_url": None,
        "auth_rate_limit_ip_burst": 3,
        "auth_rate_limit_ip_burst_window_seconds": 10,
        "auth_rate_limit_ip_per_minute": 100,
        "auth_rate_limit_ip_per_15_minutes": 100,
        "auth_rate_limit_email_per_15_minutes": 100,
    }
    values.update(overrides)
    return Settings(**values)


def test_burst_limit_blocks_fourth_attempt() -> None:
    """Block the fourth attempt inside a three-request burst window."""
    limiter = RateLimiter(make_settings())
    request = make_request()

    async def scenario() -> None:
        """Consume the burst allowance and assert throttling afterwards."""
        for _ in range(3):
            await limiter.check_credentials_attempt(request, "user@example.com")

        with pytest.raises(RateLimitExceeded) as error:
            await limiter.check_credentials_attempt(request, "user@example.com")

        assert error.value.retry_after >= 1

    asyncio.run(scenario())


def test_email_limit_is_shared_across_ips() -> None:
    """Normalize email counters independently from the request source IP."""
    limiter = RateLimiter(
        make_settings(
            auth_rate_limit_ip_burst=100,
            auth_rate_limit_email_per_15_minutes=2,
        )
    )
    first_request = make_request("203.0.113.10")
    second_request = make_request("203.0.113.11")
    blocked_request = make_request("203.0.113.12")

    async def scenario() -> None:
        """Exhaust one normalized email counter from multiple source addresses."""
        await limiter.check_credentials_attempt(first_request, "User@Example.com")
        await limiter.check_credentials_attempt(second_request, "user@example.com")

        with pytest.raises(RateLimitExceeded):
            await limiter.check_credentials_attempt(blocked_request, "USER@example.com")

    asyncio.run(scenario())


def test_client_ip_ignores_untrusted_forwarding_headers() -> None:
    """Use the ASGI peer address instead of spoofable raw proxy headers."""
    request = make_request(
        "203.0.113.50",
        headers=[
            (b"cf-connecting-ip", b"198.51.100.1"),
            (b"x-forwarded-for", b"198.51.100.2, 198.51.100.3"),
        ],
    )

    assert RateLimiter._client_ip(request) == "203.0.113.50"


def test_memory_fallback_prunes_expired_entries() -> None:
    """Remove expired fallback counters during periodic cleanup."""
    limiter = RateLimiter(make_settings())
    limiter._memory["expired"] = (1, 0.0)
    limiter._memory_operations = limiter._MEMORY_CLEANUP_INTERVAL - 1

    async def scenario() -> None:
        """Trigger periodic maintenance with one new fallback increment."""
        await limiter._increment("fresh", 60)

    asyncio.run(scenario())

    assert "expired" not in limiter._memory
    assert "fresh" in limiter._memory


def test_memory_fallback_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evict one fallback key when the configured memory bound is reached."""
    monkeypatch.setattr(RateLimiter, "_MEMORY_MAX_ENTRIES", 2)
    limiter = RateLimiter(make_settings())

    async def scenario() -> None:
        """Insert more unique keys than the temporary test bound permits."""
        await limiter._increment("first", 60)
        await limiter._increment("second", 120)
        await limiter._increment("third", 180)

    asyncio.run(scenario())

    assert len(limiter._memory) == 2
    assert "third" in limiter._memory


def test_missing_client_uses_stable_unknown_bucket() -> None:
    """Fall back to one deterministic bucket when ASGI omits a peer address."""
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/auth/credentials/verify",
            "headers": [],
            "client": None,
        }
    )

    assert RateLimiter._client_ip(request) == "unknown"
