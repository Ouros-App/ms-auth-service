from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.service_auth import (
    KeycloakServiceTokenVerifier,
    ServiceAuthenticationError,
)
from app.models.identity import AccountType
from app.schemas.auth import (
    CredentialVerificationRequest,
    CredentialVerificationResponse,
    IdentityResponse,
)
from app.services.auth_service import AuthService

router = APIRouter(
    prefix="/internal/v1",
    tags=["internal"],
    include_in_schema=False,
)


def get_auth_service(request: Request) -> AuthService:
    """Resolve the shared authentication service from application state."""
    return request.app.state.auth_service


def get_service_token_verifier(request: Request) -> KeycloakServiceTokenVerifier:
    """Resolve the Keycloak service-token verifier."""
    return request.app.state.service_token_verifier


AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
ServiceTokenVerifierDependency = Annotated[
    KeycloakServiceTokenVerifier,
    Depends(get_service_token_verifier),
]


async def require_keycloak_service(
    request: Request,
    verifier: ServiceTokenVerifierDependency,
) -> None:
    """Allow only the managed Keycloak user-storage service account."""
    try:
        await verifier.verify_authorization_header(
            request.headers.get("Authorization")
        )
    except ServiceAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


ServiceAuthDependency = Annotated[None, Depends(require_keycloak_service)]


@router.get("/identities/by-email")
async def lookup_identity_by_email(
    email: Annotated[str, Query(min_length=3, max_length=255)],
    service: AuthServiceDependency,
    _auth: ServiceAuthDependency,
) -> IdentityResponse:
    """Resolve one external identity for Keycloak username/email lookup."""
    identity = await service.lookup_identity_by_email(email)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity not found.",
        )
    return identity


@router.get("/identities/{account_type}/{database_id}")
async def lookup_identity_by_external_id(
    account_type: AccountType,
    database_id: int,
    service: AuthServiceDependency,
    _auth: ServiceAuthDependency,
) -> IdentityResponse:
    """Resolve the identity encoded in a Keycloak federated storage id."""
    identity = await service.lookup_identity_by_external_id(
        account_type,
        database_id,
    )
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity not found.",
        )
    return identity


@router.post("/credentials/verify")
async def verify_internal_credentials(
    payload: CredentialVerificationRequest,
    service: AuthServiceDependency,
    _auth: ServiceAuthDependency,
) -> CredentialVerificationResponse:
    """Verify a password for Keycloak without applying public-IP rate limits."""
    return await service.verify_credentials(payload)
