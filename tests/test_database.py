import asyncio

from app.core.config import Settings
from app.core.database import Database


def test_ping_returns_false_for_malformed_database_dsn() -> None:
    """Treat an invalid DATABASE_URL as not-ready instead of raising HTTP 500."""
    database = Database(
        Settings(
            database_url="postgresql://user:password@localhost:not-a-port/ouros",
            redis_url=None,
        )
    )

    assert asyncio.run(database.ping()) is False
