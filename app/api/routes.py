from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import Settings
from app.core.database import Database
from app.core.rate_limit import RateLimiter
from app.schemas.auth import (
    CredentialVerificationRequest,
    CredentialVerificationResponse,
    KeycloakTokenResponse,
    NativeLoginStartResponse,
    NativeLoginVerifyRequest,
    TokenLoginRequest,
    TokenRefreshRequest,
)
from app.schemas.common import HealthResponse, ReadinessResponse
from app.services.auth_service import AuthService
from app.services.email_otp import EmailOtpService
from app.services.keycloak_token_broker import KeycloakTokenBroker

router = APIRouter()


def get_auth_service(request: Request) -> AuthService:
    """Resolve the shared authentication service from application state."""
    return request.app.state.auth_service


def get_token_broker(request: Request) -> KeycloakTokenBroker:
    """Resolve the Keycloak token broker from application state."""
    return request.app.state.keycloak_token_broker


def get_runtime_settings(request: Request) -> Settings:
    """Resolve immutable runtime settings from application state."""
    return request.app.state.settings


def get_database(request: Request) -> Database:
    """Resolve the shared database wrapper from application state."""
    return request.app.state.database


def get_rate_limiter(request: Request) -> RateLimiter:
    """Resolve the shared credential rate limiter from application state."""
    return request.app.state.rate_limiter


def get_email_otp_service(request: Request) -> EmailOtpService:
    """Resolve the shared native email-OTP service from application state."""
    return request.app.state.email_otp_service


AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
DatabaseDependency = Annotated[Database, Depends(get_database)]
RateLimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]
TokenBrokerDependency = Annotated[KeycloakTokenBroker, Depends(get_token_broker)]
EmailOtpDependency = Annotated[EmailOtpService, Depends(get_email_otp_service)]
SettingsDependency = Annotated[Settings, Depends(get_runtime_settings)]


def require_password_broker(settings: Settings) -> None:
    """Hide the legacy password broker after the PKCE + OTP cutover."""
    if not settings.keycloak_password_broker_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


@router.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    """Expose minimal service metadata."""
    return {
        "service": "ouros-auth-service",
        "status": "running",
        "phase": "M2",
    }


@router.get("/health", tags=["health"])
async def health() -> HealthResponse:
    """Return process liveness independently from external dependencies."""
    return HealthResponse()


@router.get("/ready", tags=["health"])
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


@router.post(
    "/v1/auth/login/start",
    tags=["auth"],
    summary="Start native Ouros login and send an email code",
)
async def start_native_login(
    request: Request,
    payload: TokenLoginRequest,
    service: AuthServiceDependency,
    rate_limiter: RateLimiterDependency,
    email_otp: EmailOtpDependency,
) -> NativeLoginStartResponse:
    """Verify the password first, then create a short-lived email challenge."""
    await rate_limiter.check_credentials_attempt(request, payload.email)
    verified = await service.verify_credentials(
        CredentialVerificationRequest(
            email=payload.email,
            password=payload.password,
        )
    )
    challenge = await email_otp.start(verified.identity.email)
    return NativeLoginStartResponse(
        challenge_id=challenge.challenge_id,
        expires_in=challenge.expires_in,
        masked_email=challenge.masked_email,
    )


@router.post(
    "/v1/auth/login/verify",
    tags=["auth"],
    summary="Verify email code and receive Keycloak tokens",
)
async def verify_native_login(
    payload: NativeLoginVerifyRequest,
    email_otp: EmailOtpDependency,
    token_broker: TokenBrokerDependency,
) -> KeycloakTokenResponse:
    """Complete native login without exposing a Keycloak UI to the client."""
    await email_otp.verify(payload.challenge_id, payload.email, payload.code)
    return await token_broker.issue_password_token(
        TokenLoginRequest(email=payload.email, password=payload.password)
    )


@router.post(
    "/v1/auth/token",
    tags=["auth"],
    summary="Log in and receive a Keycloak access token",
)
async def issue_keycloak_token(
    request: Request,
    payload: TokenLoginRequest,
    rate_limiter: RateLimiterDependency,
    token_broker: TokenBrokerDependency,
    settings: SettingsDependency,
) -> KeycloakTokenResponse:
    """Apply credential throttling and relay a Keycloak-minted user token."""
    require_password_broker(settings)
    await rate_limiter.check_credentials_attempt(request, payload.email)
    return await token_broker.issue_password_token(payload)


@router.post(
    "/v1/auth/token/refresh",
    tags=["auth"],
    summary="Refresh a Keycloak user token",
)
async def refresh_keycloak_token(
    payload: TokenRefreshRequest,
    token_broker: TokenBrokerDependency,
) -> KeycloakTokenResponse:
    """Rotate a long-lived first-party session without repeating email OTP."""
    return await token_broker.refresh_token(payload)
