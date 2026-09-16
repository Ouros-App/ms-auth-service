from functools import lru_cache

from pydantic import Field, model_validator
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

    @model_validator(mode="after")
    def validate_pool_sizes(self) -> "Settings":
        if self.database_max_pool_size < self.database_min_pool_size:
            raise ValueError("DATABASE_MAX_POOL_SIZE must be >= DATABASE_MIN_POOL_SIZE")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
