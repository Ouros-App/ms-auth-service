from dataclasses import dataclass
from enum import StrEnum


class AccountType(StrEnum):
    FARM_OWNER = "farm_owner"
    COMPANY_EMPLOYEE = "company_employee"
    ADMIN = "admin"

    @property
    def realm_role(self) -> str:
        return {
            AccountType.FARM_OWNER: "farm_owner",
            AccountType.COMPANY_EMPLOYEE: "company_employee",
            AccountType.ADMIN: "admin",
        }[self]


@dataclass(frozen=True, slots=True)
class StoredIdentity:
    database_id: int
    email: str
    password_hash: str
    account_type: AccountType
    name: str | None = None
    farm_id: int | None = None
    enterprise_id: int | None = None
    first_access: bool | None = None
