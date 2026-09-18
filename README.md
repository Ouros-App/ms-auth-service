# Ouros Auth Service

<!-- REPO-METADATA:START -->
<div align="center">

[![Repo Size](https://img.shields.io/github/repo-size/Ouros-App/ms-auth-service?style=flat-square&label=REPO%20SIZE)](https://github.com/Ouros-App/ms-auth-service)
[![Languages](https://img.shields.io/github/languages/count/Ouros-App/ms-auth-service?style=flat-square&label=LANGUAGES)](https://github.com/Ouros-App/ms-auth-service/languages)
[![Issues](https://img.shields.io/github/issues/Ouros-App/ms-auth-service?style=flat-square&label=ISSUES)](https://github.com/Ouros-App/ms-auth-service/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/Ouros-App/ms-auth-service?style=flat-square&label=PULL%20REQUESTS)](https://github.com/Ouros-App/ms-auth-service/pulls)

</div>
<!-- REPO-METADATA:END -->

Central authentication service for Ouros.

## Current milestone: M3 bridge

This service owns **credential verification against the production PostgreSQL identity tables** and exposes an authenticated internal bridge for the Keycloak User Storage provider. It still does not mint an Ouros JWT: Keycloak is the only issuer for the new user access and refresh tokens.

The public M2 contract remains unchanged so the existing Spring/mobile authentication path keeps working during migration. M3 adds only internal endpoints used by Keycloak.

### Supported identities

| Account type | Source table | Keycloak realm role |
| --- | --- | --- |
| `farm_owner` | `farm_owners` | `farm_owner` |
| `company_employee` | `company_employees` | `company_employee` |
| `admin` | `adms` | `admin` |

The password column stays in PostgreSQL for this migration phase. Existing Spring bcrypt hashes are verified in place and are never returned by the API.

## API

### Liveness

```http
GET /health
```

Returns `200` when the process is alive. It deliberately does not depend on PostgreSQL or Redis.

### Readiness

```http
GET /ready
```

Returns `200` only when PostgreSQL is usable and, when `REDIS_URL` is configured, the distributed rate-limit backend is reachable.

### Verify credentials

```http
POST /v1/auth/credentials/verify
Content-Type: application/json
```

```json
{
  "email": "user@example.com",
  "password": "plain-text-from-the-login-form"
}
```

`account_type` is optional. By default, the service detects the account type automatically by checking the supported identity tables and validating the supplied password against the matching candidates. If the same credentials match more than one identity, the request returns `409` and the client may retry with `account_type` to disambiguate.

Success:

```json
{
  "authenticated": true,
  "identity": {
    "id": 42,
    "email": "user@example.com",
    "account_type": "farm_owner",
    "realm_role": "farm_owner",
    "name": "Example User",
    "farm_id": 7,
    "enterprise_id": null,
    "first_access": false
  }
}
```

`identity.id` is the real `id` from the production database table and remains the business/database identifier used by the existing Ouros services. A future Keycloak subject identifier is a separate authentication identifier and must not replace or be confused with this database `id`.

Invalid email/password always returns the same generic `401` response.

## Rate limiting

Credential verification is rate limited before database password verification, reducing brute-force, credential-stuffing and bcrypt CPU-abuse risk.

Default limits for `POST /v1/auth/credentials/verify`:

```text
per IP:     3 attempts / 10 seconds
per IP:     5 attempts / minute
per IP:    20 attempts / 15 minutes
per email:  5 attempts / 15 minutes
```

Exceeded limits return `429 Too Many Requests` with a `Retry-After` header. Email and IP values are SHA-256 hashed before being used in rate-limit keys.

When `REDIS_URL` is configured, counters live in Redis and are shared across replicas. Without Redis, the service uses an in-process fallback so local development and single-instance deployments remain protected.

## Security properties

- Password hashes are read only for verification and never leave the service layer.
- Missing-user attempts still execute a bcrypt comparison to reduce trivial timing differences.
- Credential verification is rate limited before bcrypt verification.
- Database connections set `default_transaction_read_only=on` and each repository operation runs inside a read-only transaction.
- Production should also use a dedicated PostgreSQL role with only `SELECT` permission on the three identity tables. Application-level read-only mode is defense in depth, not a replacement for DB grants.
- The API does not log passwords and Pydantic represents the request password as `SecretStr`.
- No JWT is generated locally in this service.

## Keycloak User Storage bridge

The new authentication path is:

```text
mobile/web
  -> Keycloak Authorization Code + PKCE
  -> Ouros User Storage SPI
  -> Keycloak service-account JWT
  -> ms-auth-service /internal/v1/*
  -> legacy identity tables
  -> Keycloak access_token + refresh_token
```

The internal bridge supports lookup by normalized email, lookup by stable `account_type + database_id`, and password verification. Every internal request requires a short-lived Keycloak service token whose RS256 signature, issuer, audience, expiry and `azp` are verified locally against Keycloak JWKS.

`client_credentials` is used only to authenticate the Keycloak provider to this internal API. It never represents the logged-in human.

## Configuration and Infisical

Production runtime secrets are loaded from Infisical before Pydantic `Settings` is created. The bootstrap connection follows the Ouros Universal Auth convention used in deployment:

```dotenv
INFISICAL_SITE_URL=https://app.infisical.com
INFISICAL_CLIENT_ID=
INFISICAL_CLIENT_SECRET=
INFISICAL_PROJECT_ID=
INFISICAL_ENVIRONMENT=prod
INFISICAL_SECRET_PATH=/ms-auth-service
```

The service authenticates with `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET`, loads all secrets from `INFISICAL_SECRET_PATH`, and injects them into the process environment before application settings are parsed.

Application secrets inside `/ms-auth-service`:

```text
DATABASE_URL
REDIS_URL       # optional but recommended in production
```

So the production flow is:

```text
Discloud env
  -> Infisical Universal Auth bootstrap
  -> Infisical /ms-auth-service
  -> DATABASE_URL + optional REDIS_URL
  -> Pydantic Settings
  -> PostgreSQL + distributed rate limiter
```

If no Infisical bootstrap values are configured, the loader is skipped. This keeps local development and CI compatible with direct environment variables. A partial Infisical configuration fails fast instead of silently starting with missing secrets.

Additional runtime configuration:

```dotenv
APP_NAME=ouros-auth-service
KEYCLOAK_ISSUER_URL=https://ouros-keycloak.discloud.app/realms/ouros
KEYCLOAK_INTERNAL_AUDIENCE=ms-auth-service-internal
KEYCLOAK_INTERNAL_CLIENT_ID=keycloak-user-storage
APP_PORT=8000
DATABASE_MIN_POOL_SIZE=1
DATABASE_MAX_POOL_SIZE=10
DATABASE_COMMAND_TIMEOUT_SECONDS=5
AUTH_RATE_LIMIT_IP_BURST=3
AUTH_RATE_LIMIT_IP_BURST_WINDOW_SECONDS=10
AUTH_RATE_LIMIT_IP_PER_MINUTE=5
AUTH_RATE_LIMIT_IP_PER_15_MINUTES=20
AUTH_RATE_LIMIT_EMAIL_PER_15_MINUTES=5
```

Never commit production credentials.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Swagger UI is available at `/docs`.

## Tests

```bash
pytest
```

The suite covers successful and rejected public authentication, unknown-user timing work, account-type forwarding, ambiguous identities, bcrypt compatibility, Infisical loading, HTTP error behavior, rate limiting, internal identity lookup and the Keycloak service-JWT contract including issuer, audience, `azp`, expiry, required claims, signing algorithm and JWKS refresh behavior.

## Structure

```text
app/
├── api/
│   ├── routes.py
│   └── internal_routes.py
├── core/
│   ├── config.py
│   ├── database.py
│   ├── errors.py
│   ├── infisical.py
│   ├── rate_limit.py
│   ├── security.py
│   └── service_auth.py
├── models/identity.py
├── repositories/identity_repository.py
├── schemas/
│   ├── auth.py
│   └── common.py
├── services/auth_service.py
└── main.py
```

## Migration map

```text
M1  Keycloak + clients-as-code                 done
M2  central credential verification           done
M3  Keycloak User Storage bridge              this PR + ouros-keycloak PR #5
M4  telemetry validates Keycloak JWT           planned
M5+ remaining Ouros services                    planned
```

## License

MIT. See [LICENSE](LICENSE).

## Principais contribuidores

<!-- CONTRIBUTORS:START -->
- [@Nicolas25vlad](https://github.com/Nicolas25vlad)
<!-- CONTRIBUTORS:END -->


## Official Keycloak token login

`POST /v1/auth/token` is the official first-party login contract for Ouros applications that need a Keycloak JWT without a browser redirect. It keeps the legacy credential-verification endpoint unchanged.

```text
Web backend / mobile / trusted Ouros client
  -> ms-auth-service /v1/auth/token
  -> Keycloak token endpoint (confidential broker client)
  -> Keycloak User Storage
  -> ms-auth-service internal credential verification
  -> Keycloak-issued JWT returned to the caller
```

The service does not create, modify or sign JWTs. Keycloak remains the sole issuer, and all APIs continue validating its issuer, JWKS signature, expiry, audience and roles.

### Endpoint contract

```http
POST /v1/auth/token
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your-password"
}
```

Successful response (`200`):

```json
{
  "access_token": "<Keycloak JWT>",
  "expires_in": 600,
  "refresh_expires_in": 1800,
  "refresh_token": "<Keycloak refresh token>",
  "token_type": "Bearer",
  "scope": "openid ouros-identity"
}
```

Use the access token only over TLS:

```http
Authorization: Bearer <access_token>
```

The token includes the federated identity claims issued by Keycloak, including `database_id`, `account_type`, `farm_id` or `enterprise_id`, and the realm role. Consumers must not trust decoded claims without validating the JWT signature.

### Client integration rules

- **Web:** prefer a backend-for-frontend (BFF). Keep the refresh token server-side and expose an `HttpOnly`, `Secure`, `SameSite` session cookie to the browser.
- **Mobile:** store tokens only in the platform secure store (Android Keystore / iOS Keychain). Never use normal preferences or application logs.
- **Server-to-server:** use Client Credentials instead of this endpoint; no user password should be involved.
- **Public third-party integrations:** use Authorization Code + PKCE rather than the password broker.
- The endpoint is for first-party Ouros applications. Do not embed the broker client secret in web or mobile applications.

At present, token refresh must remain server-managed because the Keycloak broker client secret is intentionally unavailable to callers. A caller that cannot safely keep a refresh token should log in again when the access token expires.

### Errors and rate limits

| Status | Meaning | Safe client behavior |
| --- | --- | --- |
| `200` | Keycloak authenticated the user and minted a token. | Use the access token until `expires_in`. |
| `401` | Invalid credentials. The response is intentionally generic. | Show a generic login error. |
| `422` | Invalid request shape, email or password length. | Correct the request; do not retry automatically. |
| `429` | Too many credential attempts. | Respect the `Retry-After` header. |
| `503` | Keycloak is unavailable or the broker secret is absent. | Retry with backoff; do not expose internal diagnostics. |

`/v1/auth/token` shares the distributed Redis-backed credential limiter with `/v1/auth/credentials/verify`. Passwords, access tokens and refresh tokens must never be written to logs, analytics, error trackers or browser storage.

### Compatibility

| Endpoint | Status | Purpose |
| --- | --- | --- |
| `POST /v1/auth/credentials/verify` | Maintained | Existing credential verification flow; returns identity only. |
| `POST /v1/auth/token` | Official | First-party login broker; returns a Keycloak-issued token. |

### Required configuration

The Keycloak deployment must first reconcile the confidential client `ms-auth-service-broker` through the matching `ouros-keycloak` IaC change. Obtain or generate that client's secret in Keycloak and store it only in the `ms-auth-service` secret manager.

```dotenv
KEYCLOAK_ISSUER_URL=https://ouros-keycloak.discloud.app/realms/ouros
KEYCLOAK_TOKEN_BROKER_CLIENT_ID=ms-auth-service-broker
KEYCLOAK_TOKEN_BROKER_CLIENT_SECRET=<secret-from-keycloak>
KEYCLOAK_TOKEN_BROKER_SCOPE=openid ouros-identity
KEYCLOAK_TOKEN_BROKER_TIMEOUT_SECONDS=5
```

`KEYCLOAK_TOKEN_BROKER_CLIENT_ID`, `KEYCLOAK_TOKEN_BROKER_SCOPE` and `KEYCLOAK_TOKEN_BROKER_TIMEOUT_SECONDS` have safe defaults. `KEYCLOAK_TOKEN_BROKER_CLIENT_SECRET` is required only for `/v1/auth/token`; without it, the legacy endpoints still work and the token endpoint returns `503`.

### Rollout checklist

1. Merge and deploy the Keycloak IaC change that creates `ms-auth-service-broker` with Direct Access Grants enabled only for that confidential client.
2. Store the generated client secret in Infisical as `KEYCLOAK_TOKEN_BROKER_CLIENT_SECRET` for `ms-auth-service`.
3. Merge and deploy the `ms-auth-service` token-broker change.
4. Check `/ready` returns `200`.
5. Use a QA account to call `/v1/auth/token`; validate the returned JWT locally and call one protected API with it.
6. Verify invalid-password attempts return generic `401` and repeated attempts receive `429`.

Never commit a client secret or an example production token.
