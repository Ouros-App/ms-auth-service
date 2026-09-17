import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import asyncpg

from app.core.config import Settings


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when the service starts without a database URL."""


class Database:
    """Small asyncpg wrapper with lazy, read-only connections by default."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: asyncpg.Pool | None = None
        self._connect_lock = asyncio.Lock()

    @staticmethod
    async def _configure_connection(connection: asyncpg.Connection) -> None:
        """Force every pooled connection into read-only mode by default."""
        await connection.execute("SET default_transaction_read_only = on")

    async def connect(self) -> None:
        """Create the pool once, allowing callers to retry after outages."""
        if self._pool is not None:
            return
        if not self._settings.database_url:
            raise DatabaseNotConfiguredError("DATABASE_URL is required")

        async with self._connect_lock:
            if self._pool is not None:
                return
            self._pool = await asyncpg.create_pool(
                dsn=self._settings.database_url,
                min_size=self._settings.database_min_pool_size,
                max_size=self._settings.database_max_pool_size,
                command_timeout=self._settings.database_command_timeout_seconds,
                init=self._configure_connection,
            )

    async def close(self) -> None:
        """Close the pool when one has been created."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[asyncpg.Connection]:
        """Yield a read-only connection, reconnecting lazily when necessary."""
        if self._pool is None:
            await self.connect()

        pool = self._pool
        if pool is None:
            raise RuntimeError("Database pool is not initialized")

        async with pool.acquire() as connection, connection.transaction(readonly=True):
            yield connection

    async def ping(self) -> bool:
        """Return whether PostgreSQL is currently available."""
        try:
            async with self.connection() as connection:
                return await connection.fetchval("SELECT 1") == 1
        except (asyncpg.PostgresError, OSError, RuntimeError):
            return False
