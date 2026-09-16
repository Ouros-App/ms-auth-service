from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.database import Database
from app.schemas.auth import CredentialVerificationRequest, CredentialVerificationResponse
from app.schemas.common import HealthResponse, ReadinessResponse
from app.services.auth_service import AuthService


router = APIRouter()


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_database(request: Request) -> Database:
    return request.app.state.database


@router.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {
        "service": "ouros-auth-service",
        "status": "running",
        "phase": "M2",
    }


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health() -> HealthResponse:
    return HealthResponse()


@router.get("/ready", response_model=ReadinessResponse, tags=["health"])
async def ready(database: Database = Depends(get_database)) -> ReadinessResponse:
    if not await database.ping():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not ready.",
        )
    return ReadinessResponse()


@router.post(
    "/v1/auth/credentials/verify",
    response_model=CredentialVerificationResponse,
    tags=["auth"],
    summary="Verify legacy Ouros credentials",
)
async def verify_credentials(
    payload: CredentialVerificationRequest,
    service: AuthService = Depends(get_auth_service),
) -> CredentialVerificationResponse:
    return await service.verify_credentials(payload)
