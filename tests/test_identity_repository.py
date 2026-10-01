import asyncio
from contextlib import asynccontextmanager

from app.models.identity import AccountType
from app.repositories.identity_repository import IdentityRepository


class FakeConnection:
    """Capture repository SQL calls and return deterministic normalized rows."""

    def __init__(self, row=None, execute_result="UPDATE 1") -> None:
        self.row = row
        self.execute_result = execute_result
        self.fetch_calls = []
        self.fetchrow_calls = []
        self.execute_calls = []

    async def fetch(self, query, *args):
        """Return a list containing the configured row."""
        self.fetch_calls.append((query, args))
        return [] if self.row is None else [self.row]

    async def fetchrow(self, query, *args):
        """Return the configured row for a stable-id lookup."""
        self.fetchrow_calls.append((query, args))
        return self.row

    async def execute(self, query, *args):
        """Simulate an UPDATE query returning affected row string."""
        self.execute_calls.append((query, args))
        return self.execute_result



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


def test_update_password_executes_correct_sql() -> None:
    """Verify update_password calls database execute with password hash and id."""
    connection = FakeConnection(execute_result="UPDATE 1")
    repository = IdentityRepository(FakeDatabase(connection))  # type: ignore[arg-type]

    updated = asyncio.run(
        repository.update_password(AccountType.FARM_OWNER, 12, "$2b$12$newhash")
    )

    assert updated is True
    assert len(connection.execute_calls) == 1
    query, args = connection.execute_calls[0]
    assert "UPDATE public.farm_owners" in query
    assert args == ("$2b$12$newhash", 12)


def test_update_password_returns_false_when_no_rows_updated() -> None:
    """Return False when UPDATE 0 is returned by database."""
    connection = FakeConnection(execute_result="UPDATE 0")
    repository = IdentityRepository(FakeDatabase(connection))  # type: ignore[arg-type]

    updated = asyncio.run(
        repository.update_password(AccountType.COMPANY_EMPLOYEE, 99, "$2b$12$newhash")
    )

    assert updated is False

