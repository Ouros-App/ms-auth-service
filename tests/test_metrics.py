from fastapi.testclient import TestClient

import pytest

from app.core.config import Settings
from app.core.metrics import metric_path
from app.core.service_auth import KeycloakServiceTokenVerifier
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


def test_metric_path_bounds_unknown_paths() -> None:
    assert metric_path("/health") == "/health"
    assert metric_path(
        "/internal/v1/identities/farm_owner/42"
    ) == "/internal/v1/identities/{account_type}/{database_id}"
    assert metric_path("/totally/random/attacker/value") == "{unknown}"


def test_metrics_identity_settings_reject_blank_values() -> None:
    with pytest.raises(ValueError, match="KEYCLOAK_METRICS_AUDIENCE"):
        Settings(keycloak_metrics_audience="   ")

    with pytest.raises(
        ValueError,
        match="METRICS_KEYCLOAK_AUTHORIZED_PARTY",
    ):
        Settings(metrics_keycloak_authorized_party="")


def test_service_verifier_does_not_fallback_for_explicit_blank_identity() -> None:
    settings = Settings()
    with pytest.raises(ValueError, match="must not be blank"):
        KeycloakServiceTokenVerifier(
            settings,
            audience="",
            client_id="ouros-prometheus",
        )
