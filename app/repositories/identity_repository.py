from app.core.database import Database
from app.models.identity import AccountType, StoredIdentity

_FIND_IDENTITIES_SQL = """
SELECT *
FROM (
    SELECT
        id::bigint AS database_id,
        email,
        password AS password_hash,
        'farm_owner'::text AS account_type,
        name,
        id_farm::bigint AS farm_id,
        NULL::bigint AS enterprise_id,
        first_access
    FROM public.farm_owners
    WHERE lower(email) = $1

    UNION ALL

    SELECT
        id::bigint AS database_id,
        email,
        password AS password_hash,
        'company_employee'::text AS account_type,
        name,
        NULL::bigint AS farm_id,
        id_enterprise::bigint AS enterprise_id,
        NULL::boolean AS first_access
    FROM public.company_employees
    WHERE lower(email) = $1

    UNION ALL

    SELECT
        id::bigint AS database_id,
        email,
        password AS password_hash,
        'admin'::text AS account_type,
        NULL::text AS name,
        NULL::bigint AS farm_id,
        NULL::bigint AS enterprise_id,
        NULL::boolean AS first_access
    FROM public.adms
    WHERE lower(email) = $1
) AS identities
WHERE $2::text IS NULL OR account_type = $2::text
ORDER BY account_type, database_id
"""


class IdentityRepository:
    """Read identities from the existing Ouros production tables."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def find_by_email(
        self,
        email: str,
        account_type: AccountType | None = None,
    ) -> list[StoredIdentity]:
        """Return identities whose normalized email matches the supplied value."""
        async with self._database.connection() as connection:
            rows = await connection.fetch(
                _FIND_IDENTITIES_SQL,
                email.strip().lower(),
                account_type.value if account_type else None,
            )

        return [
            StoredIdentity(
                database_id=row["database_id"],
                email=row["email"],
                password_hash=row["password_hash"],
                account_type=AccountType(row["account_type"]),
                name=row["name"],
                farm_id=row["farm_id"],
                enterprise_id=row["enterprise_id"],
                first_access=row["first_access"],
            )
            for row in rows
        ]
