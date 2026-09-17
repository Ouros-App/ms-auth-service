import asyncio
import hashlib
from dataclasses import dataclass
from time import monotonic

from fastapi import Request
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import RateLimitExceeded


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """One counter dimension and time window used by the auth limiter."""

    name: str
    limit: int
    window_seconds: int
    dimension: str


class RateLimiter:
    """Rate limit credential verification by source IP and normalized email.

    Redis is used when REDIS_URL is configured so counters are shared across
    replicas. Without Redis, or during a temporary Redis outage, the service
    falls back to an in-process limiter so credential verification is still
    protected on each running instance.
    """

    _REDIS_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
"""

    def __init__(self, settings: Settings) -> None:
        self._redis_url = settings.redis_url
        self._redis: Redis | None = None
        self._redis_lock = asyncio.Lock()
        self._memory: dict[str, tuple[int, float]] = {}
        self._memory_lock = asyncio.Lock()
        self._rules = (
            RateLimitRule(
                name="ip-burst",
                limit=settings.auth_rate_limit_ip_burst,
                window_seconds=settings.auth_rate_limit_ip_burst_window_seconds,
                dimension="ip",
            ),
            RateLimitRule(
                name="ip-minute",
                limit=settings.auth_rate_limit_ip_per_minute,
                window_seconds=60,
                dimension="ip",
            ),
            RateLimitRule(
                name="ip-fifteen-minutes",
                limit=settings.auth_rate_limit_ip_per_15_minutes,
                window_seconds=15 * 60,
                dimension="ip",
            ),
            RateLimitRule(
                name="email-fifteen-minutes",
                limit=settings.auth_rate_limit_email_per_15_minutes,
                window_seconds=15 * 60,
                dimension="email",
            ),
        )

    @property
    def distributed(self) -> bool:
        """Return whether this limiter is configured for shared Redis counters."""
        return self._redis_url is not None

    async def connect(self) -> None:
        """Connect to Redis when configured, allowing later retries after failure."""
        if self._redis_url is None or self._redis is not None:
            return

        async with self._redis_lock:
            if self._redis is not None:
                return
            client = Redis.from_url(self._redis_url, decode_responses=True)
            try:
                await client.ping()
            except (RedisError, OSError, TimeoutError):
                await client.aclose()
                raise
            self._redis = client

    async def close(self) -> None:
        """Close the Redis client when one is active."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def ping(self) -> bool:
        """Return whether the configured distributed limiter is reachable."""
        if self._redis_url is None:
            return True
        if self._redis is None:
            try:
                await self.connect()
            except (RedisError, OSError, TimeoutError):
                return False
        if self._redis is None:
            return False
        try:
            return bool(await self._redis.ping())
        except (RedisError, OSError, TimeoutError):
            return False

    async def check_credentials_attempt(
        self,
        request: Request,
        email: str,
    ) -> None:
        """Consume all configured counters and raise when any limit is exceeded."""
        ip = self._client_ip(request)
        dimensions = {
            "ip": self._digest(ip),
            "email": self._digest(email.strip().lower()),
        }

        longest_retry_after = 0
        for rule in self._rules:
            key = (
                "ouros:auth:rate-limit:"
                f"{rule.name}:{dimensions[rule.dimension]}"
            )
            count, retry_after = await self._increment(
                key,
                rule.window_seconds,
            )
            if count > rule.limit:
                longest_retry_after = max(longest_retry_after, retry_after)

        if longest_retry_after > 0:
            raise RateLimitExceeded(retry_after=longest_retry_after)

    async def _increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Increment a Redis counter, falling back to memory if Redis is unavailable."""
        if self._redis_url is not None and self._redis is None:
            try:
                await self.connect()
            except (RedisError, OSError, TimeoutError):
                pass

        if self._redis is not None:
            try:
                result = await self._redis.eval(
                    self._REDIS_SCRIPT,
                    1,
                    key,
                    window_seconds,
                )
                count = int(result[0])
                ttl = max(int(result[1]), 1)
                return count, ttl
            except (RedisError, OSError, TimeoutError):
                await self.close()

        now = monotonic()
        async with self._memory_lock:
            current = self._memory.get(key)
            if current is None or current[1] <= now:
                count = 1
                expires_at = now + window_seconds
            else:
                count = current[0] + 1
                expires_at = current[1]
            self._memory[key] = (count, expires_at)

        retry_after = max(int(expires_at - now), 1)
        return count, retry_after

    @staticmethod
    def _digest(value: str) -> str:
        """Hash rate-limit dimensions so raw emails and IPs are not stored as keys."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _client_ip(request: Request) -> str:
        """Resolve the originating address from the deployment proxy headers."""
        cloudflare_ip = request.headers.get("cf-connecting-ip")
        if cloudflare_ip:
            return cloudflare_ip.strip()

        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",", maxsplit=1)[0].strip()

        if request.client is not None:
            return request.client.host
        return "unknown"
