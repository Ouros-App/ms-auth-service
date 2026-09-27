from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


class AcceptingMetricsVerifier:
    async def verify_authorization_header(self, authorization: str | None):
        if authorization != "Bearer prometheus-token":
            from app.core.service_auth import ServiceAuthenticationError
            raise ServiceAuthenticationError("invalid")
        return {"azp": "ouros-prometheus"}


class FakeDatabase:
    async def close(self):
        return

    async def ping(self):
        return True


class FakeRateLimiter:
    async def close(self):
        return

    async def ping(self):
        return True


class FakeEmailOtpService:
    async def close(self):
        return


def build_metrics_client() -> TestClient:
    return TestClient(
        create_app(
            settings=Settings(database_url="postgresql://unused"),
            database=FakeDatabase(),  # type: ignore[arg-type]
            rate_limiter=FakeRateLimiter(),  # type: ignore[arg-type]
            email_otp_service=FakeEmailOtpService(),  # type: ignore[arg-type]
            metrics_token_verifier=AcceptingMetricsVerifier(),  # type: ignore[arg-type]
        )
    )


def test_metrics_requires_prometheus_service_token() -> None:
    with build_metrics_client() as client:
        missing = client.get("/metrics")
        accepted = client.get(
            "/metrics",
            headers={"Authorization": "Bearer prometheus-token"},
        )

    assert missing.status_code == 401
    assert accepted.status_code == 200
    assert accepted.headers["content-type"].startswith("text/plain")
    assert b"auth_service_http_requests_total" in accepted.content


def test_readiness_exports_dependency_state() -> None:
    with build_metrics_client() as client:
        assert client.get("/ready").status_code == 200
        metrics = client.get(
            "/metrics",
            headers={"Authorization": "Bearer prometheus-token"},
        )

    assert b'auth_service_dependency_ready{dependency="postgresql"} 1.0' in metrics.content
    assert b'auth_service_dependency_ready{dependency="rate_limiter"} 1.0' in metrics.content
