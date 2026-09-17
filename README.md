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

## Current milestone: M2

This service currently owns **credential verification against the production PostgreSQL identity tables**. It does not mint an Ouros JWT yet.

That boundary is intentional: the old Spring API signs its own JWT after validating bcrypt passwords, while the target architecture uses Keycloak as the token issuer. M2 moves password validation out of application APIs without introducing a second homemade token format.

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

Returns `200` when the process is alive. It deliberately does not depend on PostgreSQL.

### Readiness

```http
GET /ready
```

Returns `200` only when the PostgreSQL connection is usable.

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

## Security properties

- Password hashes are read only for verification and never leave the service layer.
- Missing-user attempts still execute a bcrypt comparison to reduce trivial timing differences.
- Database connections set `default_transaction_read_only=on` and each repository operation runs inside a read-only transaction.
- Production should also use a dedicated PostgreSQL role with only `SELECT` permission on the three identity tables. Application-level read-only mode is defense in depth, not a replacement for DB grants.
- The API does not log passwords and Pydantic represents the request password as `SecretStr`.
- No JWT is generated locally in this service.

## Why M2 stops before token issuance

Keycloak `client_credentials` represents a service account, not the logged-in user. A user access token must be issued only after Keycloak can authenticate or trust the corresponding user identity. The next milestone will add that bridge deliberately rather than impersonating a user with a machine token.

The intended M3 contract is:

```text
mobile/web -> ms-auth-service -> credential authority -> Keycloak -> access + refresh token
```

The exact Keycloak credential-federation mechanism is kept outside this PR so password authority is not silently duplicated into Keycloak.

## Configuration and Infisical

Production runtime secrets are loaded from Infisical before Pydantic `Settings` is created. This service now follows the same Python pattern used by `ms-ai-server` and `ms-mcp-server-ouros-knowledge`: the platform provides the Infisical bootstrap variables, the SDK loads the path contents, and those secrets are injected into the process environment before the app settings are parsed.

The runtime bootstrap values are:

```dotenv
INFISICAL_HOST=https://app.infisical.com
INFISICAL_TOKEN=
INFISICAL_PROJECT_ID=
INFISICAL_ENV=prod
INFISICAL_PATH=/ms-auth-service
```

Application secrets belong in the configured Infisical path. For M2, the database connection should be stored there as:

```text
DATABASE_URL
```

So the production flow is:

```text
Discloud env
  -> INFISICAL_TOKEN + project/env/path
  -> Infisical /ms-auth-service
  -> DATABASE_URL
  -> Pydantic Settings
  -> PostgreSQL
```

If no Infisical bootstrap values are configured, the loader is skipped. This keeps local development and CI compatible with a direct `DATABASE_URL` environment variable. A partial Infisical configuration fails fast instead of silently starting with missing secrets.

Additional runtime configuration:

```dotenv
APP_NAME=ouros-auth-service
APP_PORT=8000
DATABASE_MIN_POOL_SIZE=1
DATABASE_MAX_POOL_SIZE=10
DATABASE_COMMAND_TIMEOUT_SECONDS=5
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

The suite covers successful and rejected authentication, unknown-user timing work, account-type forwarding, ambiguous identities, bcrypt compatibility, Infisical loading and HTTP error behavior.

## Structure

```text
app/
├── api/routes.py
├── core/
│   ├── config.py
│   ├── database.py
│   ├── errors.py
│   ├── infisical.py
│   └── security.py
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
M2  central credential verification           this service
M3  user access/refresh tokens from Keycloak   next
M4  telemetry validates Keycloak JWT           planned
M5+ remaining Ouros services                    planned
```

## License

MIT. See [LICENSE](LICENSE).

## Principais contribuidores

<!-- CONTRIBUTORS:START -->
- [@Nicolas25vlad](https://github.com/Nicolas25vlad)
<!-- CONTRIBUTORS:END -->
