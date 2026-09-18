from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator

from app.models.identity import AccountType, StoredIdentity


class CredentialVerificationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: SecretStr
    account_type: AccountType | None = None

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized.count("@") != 1 or " " in normalized:
            raise ValueError("invalid email")
        local_part, domain = normalized.split("@", maxsplit=1)
        if not local_part or not domain:
            raise ValueError("invalid email")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, value: SecretStr) -> SecretStr:
        length = len(value.get_secret_value())
        if length == 0 or length > 128:
            raise ValueError("password length must be between 1 and 128 characters")
        return value


class IdentityResponse(BaseModel):
    id: int
    email: str
    account_type: AccountType
    realm_role: str
    name: str | None = None
    farm_id: int | None = None
    enterprise_id: int | None = None
    first_access: bool | None = None

    @classmethod
    def from_identity(cls, identity: StoredIdentity) -> "IdentityResponse":
        return cls(
            id=identity.database_id,
            email=identity.email,
            account_type=identity.account_type,
            realm_role=identity.account_type.realm_role,
            name=identity.name,
            farm_id=identity.farm_id,
            enterprise_id=identity.enterprise_id,
            first_access=identity.first_access,
        )


class CredentialVerificationResponse(BaseModel):
    authenticated: Literal[True] = True
    identity: IdentityResponse


class TokenLoginRequest(BaseModel):
    """Credentials accepted by the official Keycloak token broker."""

    email: str = Field(min_length=3, max_length=255)
    password: SecretStr

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        return CredentialVerificationRequest.validate_email_shape(value)

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, value: SecretStr) -> SecretStr:
        return CredentialVerificationRequest.validate_password_length(value)


class KeycloakTokenResponse(BaseModel):
    """A user token minted by Keycloak and relayed without modification."""

    access_token: str = Field(min_length=1)
    expires_in: int = Field(gt=0)
    refresh_expires_in: int | None = Field(default=None, ge=0)
    refresh_token: str | None = None
    token_type: Literal["Bearer"]
    scope: str | None = None
