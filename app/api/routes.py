from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.database import Database
from app.core.rate_limit import RateLimiter
from app.schemas.auth import (
    CredentialVerificationRequest,
    CredentialVerificationResponse,
)
from app.schemas.common import HealthResponse, ReadinessResponse
from app.services.auth_service import AuthService

router = APIRouter()


def get_auth_service(request: Request) -> AuthService:
    """Resolve the shared authentication service from application state."""
    return request.app.state.auth_service


def get_database(request: Request) -> Database:
    """Resolve the shared database wrapper from application state."""
    return request.app.state.database


def get_rate_limiter(request: Request) -> RateLimiter:
    """Resolve the shared credential rate limiter from application state."""
    return request.app.state.rate_limiter


AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
DatabaseDependency = Annotated[Database, Depends(get_database)]
RateLimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]


@router.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    """Expose minimal service metadata."""
    return {
        "service": "ouros-auth-service",
        "status": "running",
        "phase": "M2",
    }


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health() -> HealthResponse:
    """Return process liveness independently from external dependencies."""
    return HealthResponse()


@router.get("/ready", response_model=ReadinessResponse, tags=["health"])
async def ready(
    database: DatabaseDependency,
    rate_limiter: RateLimiterDependency,
) -> ReadinessResponse:
    """Return readiness only when required production dependencies are usable."""
    if not await database.ping():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not ready.",
        )
    if not await rate_limiter.ping():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter is not ready.",
        )
    return ReadinessResponse()


@router.post(
    "/v1/auth/credentials/verify",
    response_model=CredentialVerificationResponse,
    tags=["auth"],
    summary="Verify Ouros credentials",
)
async def verify_credentials(
    request: Request,
    payload: CredentialVerificationRequest,
    service: AuthServiceDependency,
    rate_limiter: RateLimiterDependency,
) -> CredentialVerificationResponse:
    """Rate limit and verify one credential attempt."""
    await rate_limiter.check_credentials_attempt(request, payload.email)
    return await service.verify_credentials(payload)
