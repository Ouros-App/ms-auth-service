import asyncio
from contextlib import asynccontextmanager

from app.models.identity import AccountType
from app.repositories.identity_repository import IdentityRepository


class FakeConnection:
    """Capture repository SQL calls and return deterministic normalized rows."""

    def __init__(self, row=None) -> None:
        self.row = row
        self.fetch_calls = []
        self.fetchrow_calls = []

    async def fetch(self, query, *args):
        """Return a list containing the configured row."""
        self.fetch_calls.append((query, args))
        return [] if self.row is None else [self.row]

    async def fetchrow(self, query, *args):
        """Return the configured row for a stable-id lookup."""
        self.fetchrow_calls.append((query, args))
        return self.row


class FakeDatabase:
    """Expose one fake connection through the repository context-manager API."""

    def __init__(self, connection: FakeConnection) -> None:
        self.connection_value = connection

    @asynccontextmanager
    async def connection(self):
        """Yield the configured fake connection."""
        yield self.connection_value


def make_row():
    """Return the normalized row shape emitted by identity SQL."""
    return {
        "database_id": 12,
        "email": "user@example.com",
        "password_hash": "$2b$12$placeholder",
        "account_type": "farm_owner",
        "name": "User",
        "farm_id": 7,
        "enterprise_id": None,
        "first_access": False,
    }


def test_find_by_email_maps_normalized_row() -> None:
    """Map the union query result into the StoredIdentity domain model."""
    connection = FakeConnection(make_row())
    repository = IdentityRepository(FakeDatabase(connection))  # type: ignore[arg-type]

    identities = asyncio.run(repository.find_by_email(" USER@EXAMPLE.COM "))

    assert len(identities) == 1
    assert identities[0].database_id == 12
    assert identities[0].account_type is AccountType.FARM_OWNER
    assert connection.fetch_calls[0][1] == ("user@example.com", None)


def test_find_by_external_id_uses_account_specific_query() -> None:
    """Resolve one farm-owner by stable account type and database id."""
    connection = FakeConnection(make_row())
    repository = IdentityRepository(FakeDatabase(connection))  # type: ignore[arg-type]

    identity = asyncio.run(
        repository.find_by_external_id(AccountType.FARM_OWNER, 12)
    )

    assert identity is not None
    assert identity.farm_id == 7
    assert connection.fetchrow_calls[0][1] == (12,)


def test_find_by_external_id_returns_none_for_missing_row() -> None:
    """Return None when the requested federated identity was deleted."""
    connection = FakeConnection()
    repository = IdentityRepository(FakeDatabase(connection))  # type: ignore[arg-type]

    identity = asyncio.run(
        repository.find_by_external_id(AccountType.ADMIN, 999)
    )

    assert identity is None
