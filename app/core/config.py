from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "ouros-auth-service"
    app_version: str = "0.1.0"
    environment: str = "development"
    app_port: int = Field(default=8000, ge=1, le=65535)

    database_url: str | None = None
    database_min_pool_size: int = Field(default=1, ge=1)
    database_max_pool_size: int = Field(default=10, ge=1)
    database_command_timeout_seconds: float = Field(default=5.0, gt=0)

    redis_url: str | None = None
    auth_rate_limit_ip_burst: int = Field(default=3, ge=1)
    auth_rate_limit_ip_burst_window_seconds: int = Field(default=10, ge=1)
    auth_rate_limit_ip_per_minute: int = Field(default=5, ge=1)
    auth_rate_limit_ip_per_15_minutes: int = Field(default=20, ge=1)
    auth_rate_limit_email_per_15_minutes: int = Field(default=5, ge=1)

    keycloak_issuer_url: str = "https://ouros-keycloak.discloud.app/realms/ouros"
    keycloak_internal_audience: str = "ms-auth-service-internal"
    keycloak_internal_client_id: str = "keycloak-user-storage"

    keycloak_token_broker_client_id: str = "ms-auth-service-broker"
    keycloak_token_broker_client_secret: SecretStr | None = None
    keycloak_token_broker_scope: str = "openid ouros-identity"
    keycloak_token_broker_timeout_seconds: float = Field(default=5.0, gt=0)
    keycloak_token_broker_jwks_url: str | None = None
    keycloak_token_broker_expected_audiences: str = (
        "ms-spring-api|ms-telemetry-dashboard-service|ms-ai-server|"
        "ms-mcp-server-ouros-knowledge|ms-mcp-server-ouros-knowledge-codemode"
    )

    @model_validator(mode="after")
    def validate_pool_sizes(self) -> "Settings":
        if self.database_max_pool_size < self.database_min_pool_size:
            raise ValueError("DATABASE_MAX_POOL_SIZE must be >= DATABASE_MIN_POOL_SIZE")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
