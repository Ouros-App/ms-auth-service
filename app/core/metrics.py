import re

from prometheus_client import Counter, Gauge, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "auth_service_http_requests_total",
    "Total de requisicoes HTTP recebidas pelo auth service.",
    ("method", "route", "status"),
)
HTTP_DURATION = Histogram(
    "auth_service_http_request_duration_seconds",
    "Duracao das requisicoes HTTP do auth service em segundos.",
    ("method", "route"),
)
AUTH_OPERATIONS = Counter(
    "auth_service_operations_total",
    "Operacoes de autenticacao por resultado.",
    ("operation", "outcome"),
)
RATE_LIMIT_HITS = Counter(
    "auth_service_rate_limit_hits_total",
    "Total de requests bloqueadas pelo rate limiter.",
)
DEPENDENCY_READY = Gauge(
    "auth_service_dependency_ready",
    "Estado da dependencia no ultimo readiness check (1=ready, 0=down).",
    ("dependency",),
)

_KNOWN_METRIC_PATHS = {
    "/",
    "/health",
    "/ready",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/v1/auth/credentials/verify",
    "/v1/auth/login/start",
    "/v1/auth/login/verify",
    "/v1/auth/token",
    "/v1/auth/token/refresh",
    "/v1/auth/password/reset/start",
    "/v1/auth/password/reset/verify",
    "/v1/auth/password/reset/confirm",
    "/internal/v1/identities/by-email",
    "/internal/v1/credentials/verify",
}

_AUTH_OPERATIONS_BY_PATH = {
    ("POST", "/v1/auth/credentials/verify"): "credentials_verify",
    ("POST", "/v1/auth/login/start"): "login_start",
    ("POST", "/v1/auth/login/verify"): "login_verify",
    ("POST", "/v1/auth/token"): "token_issue",
    ("POST", "/v1/auth/token/refresh"): "token_refresh",
    ("POST", "/v1/auth/password/reset/start"): "password_reset_start",
    ("POST", "/v1/auth/password/reset/verify"): "password_reset_verify",
    ("POST", "/v1/auth/password/reset/confirm"): "password_reset_confirm",
}


def metric_path(path: str) -> str:
    """Return only bounded route templates suitable for metric labels."""
    if path in _KNOWN_METRIC_PATHS:
        return path
    if re.fullmatch(
        r"/internal/v1/identities/[^/]+/\d+",
        path,
    ):
        return "/internal/v1/identities/{account_type}/{database_id}"
    return "{unknown}"


def auth_operation(method: str, path: str) -> str | None:
    return _AUTH_OPERATIONS_BY_PATH.get((method.upper(), path))


def outcome_for_status(status_code: int) -> str:
    if status_code < 400:
        return "success"
    if status_code < 500:
        return "client_error"
    return "server_error"


def metrics_payload() -> bytes:
    return generate_latest()
