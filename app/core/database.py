from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import asyncpg

from app.core.config import Settings


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when the service starts without a database URL."""


class Database:
    """Small asyncpg wrapper with read-only connections by default."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: asyncpg.Pool | None = None

    @staticmethod
    async def _configure_connection(connection: asyncpg.Connection) -> None:
        await connection.execute("SET default_transaction_read_only = on")

    async def connect(self) -> None:
        if not self._settings.database_url:
            raise DatabaseNotConfiguredError("DATABASE_URL is required")

        self._pool = await asyncpg.create_pool(
            dsn=self._settings.database_url,
            min_size=self._settings.database_min_pool_size,
            max_size=self._settings.database_max_pool_size,
            command_timeout=self._settings.database_command_timeout_seconds,
            init=self._configure_connection,
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[asyncpg.Connection]:
        if self._pool is None:
            raise RuntimeError("Database pool is not initialized")

        async with self._pool.acquire() as connection:
            async with connection.transaction(readonly=True):
                yield connection

    async def ping(self) -> bool:
        try:
            async with self.connection() as connection:
                return await connection.fetchval("SELECT 1") == 1
        except (asyncpg.PostgresError, RuntimeError):
            return False
