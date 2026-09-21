from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api.internal_routes import router as internal_router
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
from app.core.service_auth import KeycloakServiceTokenVerifier
from app.repositories.identity_repository import IdentityRepository
from app.services.auth_service import AuthService
from app.services.keycloak_token_broker import (
    KeycloakTokenBroker,
    KeycloakTokenBrokerUnavailable,
)


def create_app(
    settings: Settings | None = None,
    database: Database | None = None,
    auth_service: AuthService | None = None,
    rate_limiter: RateLimiter | None = None,
    service_token_verifier: KeycloakServiceTokenVerifier | None = None,
    keycloak_token_broker: KeycloakTokenBroker | None = None,
) -> FastAPI:
    """Build the FastAPI application and wire its shared services."""
    if settings is None:
        load_infisical_secrets()
        get_settings.cache_clear()

    resolved_settings = settings or get_settings()
    resolved_database = database or Database(resolved_settings)
    resolved_auth_service = auth_service or AuthService(
        IdentityRepository(resolved_database)
    )
    resolved_rate_limiter = rate_limiter or RateLimiter(resolved_settings)
    resolved_keycloak_token_broker = keycloak_token_broker or KeycloakTokenBroker(
        resolved_settings
    )
    resolved_service_token_verifier = (
        service_token_verifier
        or KeycloakServiceTokenVerifier(resolved_settings)
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Expose dependencies without making liveness depend on their startup."""
        application.state.database = resolved_database
        application.state.auth_service = resolved_auth_service
        application.state.rate_limiter = resolved_rate_limiter
        application.state.service_token_verifier = resolved_service_token_verifier
        application.state.keycloak_token_broker = resolved_keycloak_token_broker
        application.state.settings = resolved_settings
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
            "M3 adds an authenticated bridge for Keycloak User Storage."
        ),
        lifespan=lifespan,
    )

    @application.exception_handler(KeycloakTokenBrokerUnavailable)
    async def keycloak_token_broker_unavailable_handler(
        _request: Request,
        _exception: KeycloakTokenBrokerUnavailable,
    ) -> JSONResponse:
        """Avoid leaking Keycloak or broker configuration details."""
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Autenticação temporariamente indisponível."},
        )

    @application.exception_handler(InvalidCredentialsError)
    async def invalid_credentials_handler(
        _request: Request,
        _exception: InvalidCredentialsError,
    ) -> JSONResponse:
        """Return a generic authentication failure without account enumeration."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Credenciais inválidas."},
        )

    @application.exception_handler(AmbiguousIdentityError)
    async def ambiguous_identity_handler(
        _request: Request,
        _exception: AmbiguousIdentityError,
    ) -> JSONResponse:
        """Request account-type disambiguation when multiple identities match."""
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
        """Return a standards-friendly retry hint for throttled login attempts."""
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Muitas tentativas. Tente novamente mais tarde."},
            headers={"Retry-After": str(exception.retry_after)},
        )

    application.include_router(router)
    application.include_router(internal_router)
    return application


app = create_app()
