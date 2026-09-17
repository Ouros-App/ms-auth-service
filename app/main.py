from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import Settings, get_settings
from app.core.database import Database
from app.core.errors import (
    AmbiguousIdentityError,
    InvalidCredentialsError,
    RateLimitExceeded,
)
from app.core.infisical import load_infisical_secrets
from app.core.rate_limit import RateLimiter
from app.repositories.identity_repository import IdentityRepository
from app.services.auth_service import AuthService


def create_app(
    settings: Settings | None = None,
    database: Database | None = None,
    auth_service: AuthService | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    if settings is None:
        load_infisical_secrets()
        get_settings.cache_clear()

    resolved_settings = settings or get_settings()
    resolved_database = database or Database(resolved_settings)
    resolved_auth_service = auth_service or AuthService(
        IdentityRepository(resolved_database)
    )
    resolved_rate_limiter = rate_limiter or RateLimiter(resolved_settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.database = resolved_database
        application.state.auth_service = resolved_auth_service
        application.state.rate_limiter = resolved_rate_limiter
        await resolved_database.connect()
        await resolved_rate_limiter.connect()
        try:
            yield
        finally:
            await resolved_rate_limiter.close()
            await resolved_database.close()

    application = FastAPI(
        title="Ouros Auth Service",
        version=resolved_settings.app_version,
        description=(
            "Central credential verification service for Ouros. "
            "Keycloak token issuance is intentionally outside M2."
        ),
        lifespan=lifespan,
    )

    @application.exception_handler(InvalidCredentialsError)
    async def invalid_credentials_handler(
        _request: Request,
        _exception: InvalidCredentialsError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Credenciais inválidas."},
        )

    @application.exception_handler(AmbiguousIdentityError)
    async def ambiguous_identity_handler(
        _request: Request,
        _exception: AmbiguousIdentityError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": (
                    "As credenciais correspondem a mais de uma conta. "
                    "Informe account_type."
                )
            },
        )

    @application.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(
        _request: Request,
        exception: RateLimitExceeded,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Muitas tentativas. Tente novamente mais tarde."},
            headers={"Retry-After": str(exception.retry_after)},
        )

    application.include_router(router)
    return application


app = create_app()
