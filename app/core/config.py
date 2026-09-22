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

    keycloak_password_broker_enabled: bool = True
    keycloak_token_broker_client_id: str = "ms-auth-service-broker"
    keycloak_token_broker_client_secret: SecretStr | None = None
    keycloak_token_broker_scope: str = "openid ouros-identity offline_access"
    keycloak_token_broker_timeout_seconds: float = Field(default=5.0, gt=0)
    keycloak_token_broker_jwks_url: str | None = None

    ouros_email_otp_enabled: bool = False
    ouros_email_otp_hmac_secret: SecretStr | None = None
    ouros_email_otp_ttl_seconds: int = Field(default=300, ge=60, le=900)
    ouros_email_otp_max_attempts: int = Field(default=5, ge=1, le=10)

    ouros_smtp_host: str | None = None
    ouros_smtp_port: int = Field(default=587, ge=1, le=65535)
    ouros_smtp_from: str = "no-reply@ouros.local"
    ouros_smtp_from_display_name: str = "Ouros"
    ouros_smtp_auth: bool = False
    ouros_smtp_starttls: bool = True
    ouros_smtp_ssl: bool = False
    ouros_smtp_user: str | None = None
    ouros_smtp_password: SecretStr | None = None
    ouros_smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=30)

    @model_validator(mode="after")
    def validate_pool_sizes(self) -> "Settings":
        if self.database_max_pool_size < self.database_min_pool_size:
            raise ValueError("DATABASE_MAX_POOL_SIZE must be >= DATABASE_MIN_POOL_SIZE")
        if self.ouros_smtp_starttls and self.ouros_smtp_ssl:
            raise ValueError("OUROS_SMTP_STARTTLS and OUROS_SMTP_SSL cannot both be true")
        if self.ouros_email_otp_enabled:
            if self.ouros_email_otp_hmac_secret is None:
                raise ValueError("OUROS_EMAIL_OTP_HMAC_SECRET is required when email OTP is enabled")
            if len(self.ouros_email_otp_hmac_secret.get_secret_value()) < 32:
                raise ValueError("OUROS_EMAIL_OTP_HMAC_SECRET must contain at least 32 characters")
            if not self.ouros_smtp_host:
                raise ValueError("OUROS_SMTP_HOST is required when email OTP is enabled")
            if self.ouros_smtp_auth and (
                not self.ouros_smtp_user or self.ouros_smtp_password is None
            ):
                raise ValueError(
                    "OUROS_SMTP_USER and OUROS_SMTP_PASSWORD are required when SMTP auth is enabled"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
