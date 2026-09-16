from fastapi import APIRouter

from app.schemas.common import HealthResponse, MessageResponse

router = APIRouter()


@router.get("/", response_model=MessageResponse)
def read_root() -> MessageResponse:
    return MessageResponse(message="FastAPI microservice is running")


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(status="ok")
