import asyncio
import logging
import secrets
import time
import uuid

import httpx
import jwt
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import (
    EmailOtpUnavailable,
    PasswordResetSpringError,
    PasswordResetTokenInvalidError,
    PasswordResetUnavailable,
)
from app.models.identity import AccountType
from app.repositories.identity_repository import IdentityRepository
from app.schemas.auth import (
    CREDENTIAL_COMPLEXITY_PATTERN,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetStartRequest,
    PasswordResetStartResponse,
    PasswordResetVerifyRequest,
    PasswordResetVerifyResponse,
)
from app.services.email_otp import EmailOtpService

logger = logging.getLogger(__name__)


class PasswordResetService:
    """Orchestrates password reset challenges, token issuance, and Spring API updates."""

    _BLACKLIST_PREFIX = "ouros:auth:password-reset:blacklist:"
    _REDIS_SOCKET_TIMEOUT_SECONDS = 2.0

    def __init__(
        self,
        settings: Settings,
        identity_repository: IdentityRepository,
        email_otp_service: EmailOtpService,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._identity_repository = identity_repository
        self._email_otp_service = email_otp_service
        self._http_client = http_client
        self._redis_url = settings.redis_url
        self._redis: Redis | None = None
        self._redis_lock = asyncio.Lock()
        self._blacklist_memory: dict[str, float] = {}
        self._blacklist_lock = asyncio.Lock()

    async def close(self) -> None:
        """Release underlying Redis and HTTP client resources."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
        if self._http_client is not None:
            await self._http_client.aclose()

    def _get_reset_jwt_secret(self) -> str:
        for secret in (
            self._settings.password_reset_jwt_secret,
            self._settings.ouros_email_otp_hmac_secret,
            self._settings.spring_jwt_secret,
        ):
            if secret is not None and len(secret.get_secret_value()) >= 32:
                return secret.get_secret_value()
        for secret in (
            self._settings.password_reset_jwt_secret,
            self._settings.ouros_email_otp_hmac_secret,
            self._settings.spring_jwt_secret,
        ):
            if secret is not None and secret.get_secret_value():
                return secret.get_secret_value()
        return "ouros-dev-password-reset-secret-key-32-chars-minimum"

    def _get_spring_jwt_secret(self) -> str:
        for secret in (
            self._settings.spring_jwt_secret,
            self._settings.password_reset_jwt_secret,
            self._settings.ouros_email_otp_hmac_secret,
        ):
            if secret is not None and len(secret.get_secret_value()) >= 32:
                return secret.get_secret_value()
        for secret in (
            self._settings.spring_jwt_secret,
            self._settings.password_reset_jwt_secret,
            self._settings.ouros_email_otp_hmac_secret,
        ):
            if secret is not None and secret.get_secret_value():
                return secret.get_secret_value()
        return "ouros-dev-spring-delegation-secret-key-32-chars-minimum"

    async def start_reset(
        self,
        request: PasswordResetStartRequest,
    ) -> PasswordResetStartResponse:
        """Return generic challenge metadata regardless of account eligibility or delivery."""
        normalized_email = request.email.strip().lower()
        response = PasswordResetStartResponse(
            challenge_id=secrets.token_urlsafe(32),
            masked_email=EmailOtpService._mask_email(normalized_email),
            expires_in=self._settings.ouros_email_otp_ttl_seconds,
        )

        identities = await self._identity_repository.find_by_email(
            normalized_email,
            request.account_type,
        )

        valid_identities = [
            i
            for i in identities
            if i.account_type in (AccountType.FARM_OWNER, AccountType.COMPANY_EMPLOYEE)
        ]

        if len(valid_identities) != 1:
            return response

        identity = valid_identities[0]
        try:
            challenge = await self._email_otp_service.start_password_reset(
                identity.email,
                identity.account_type.value,
                identity.database_id,
            )
        except EmailOtpUnavailable:
            logger.warning("password_reset_challenge_unavailable")
            return response

        response.challenge_id = challenge.challenge_id
        return response

    async def verify_code(
        self,
        request: PasswordResetVerifyRequest,
    ) -> PasswordResetVerifyResponse:
        """Verify the OTP code and mint an ephemeral password reset token."""
        record = await self._email_otp_service.verify_password_reset(
            request.challenge_id,
            request.email,
            request.code,
        )

        email = str(record["email"])
        account_type = str(record["account_type"])
        database_id = int(record["database_id"])

        reset_token = self._mint_reset_token(
            email=email,
            account_type=account_type,
            database_id=database_id,
        )

        return PasswordResetVerifyResponse(
            reset_token=reset_token,
            expires_in=self._settings.password_reset_token_ttl_seconds,
        )

    async def confirm_reset(
        self,
        request: PasswordResetConfirmRequest,
    ) -> PasswordResetConfirmResponse:
        """Validate reset token, password rules, and delegate update to ms-spring-api."""
        claims = self._verify_reset_token(request.reset_token)

        jti = claims["jti"]
        raw_password = request.new_password.get_secret_value()
        if not CREDENTIAL_COMPLEXITY_PATTERN.fullmatch(raw_password):
            raise PasswordResetTokenInvalidError(
                "A senha deve ter entre 8 e 20 caracteres, incluindo pelo menos "
                "uma letra maiúscula, uma minúscula, um número e um caractere especial"
            )

        email = claims["sub"]
        account_type = claims["account_type"]
        database_id = int(claims["database_id"])

        delegation_jwt = self._mint_spring_delegation_jwt(
            email=email,
            account_type=account_type,
            database_id=database_id,
        )

        now = int(time.time())
        exp = int(claims["exp"])
        remaining_ttl = max(exp - now, 1)
        await self._reserve_token(jti, remaining_ttl)
        try:
            await self._call_spring_patch(
                account_type=account_type,
                database_id=database_id,
                new_password=raw_password,
                delegation_jwt=delegation_jwt,
            )
        except Exception:
            await self._release_token(jti)
            raise

        return PasswordResetConfirmResponse(message="Senha redefinida com sucesso.")

    def _mint_reset_token(
        self,
        email: str,
        account_type: str,
        database_id: int,
    ) -> str:
        """Mint a signed, short-lived JWT scoped solely to password reset."""
        now = int(time.time())
        payload = {
            "sub": email,
            "account_type": account_type,
            "database_id": database_id,
            "purpose": "password_reset",
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._settings.password_reset_token_ttl_seconds,
        }
        return jwt.encode(payload, self._get_reset_jwt_secret(), algorithm="HS256")

    def _verify_reset_token(self, token: str) -> dict[str, object]:
        """Verify signature, expiry and claims of the reset token."""
        try:
            claims = jwt.decode(
                token,
                self._get_reset_jwt_secret(),
                algorithms=["HS256"],
                options={
                    "require": ["sub", "account_type", "database_id", "purpose", "jti", "exp", "iat"],
                },
            )
        except (jwt.PyJWTError, ValueError) as exc:
            raise PasswordResetTokenInvalidError("Token de recuperação inválido ou expirado.") from exc

        if claims.get("purpose") != "password_reset":
            raise PasswordResetTokenInvalidError("Token de recuperação com finalidade inválida.")

        return claims

    def _mint_spring_delegation_jwt(
        self,
        email: str,
        account_type: str,
        database_id: int,
    ) -> str:
        """Mint a delegation JWT recognized by ms-spring-api JwtAuthFilter."""
        now = int(time.time())
        role = "FARM_OWNER" if account_type == "farm_owner" else "COMPANY_EMPLOYEE"
        payload = {
            "sub": email,
            "id": database_id,
            "role": role,
            "iat": now,
            "exp": now + 120,
        }
        return jwt.encode(payload, self._get_spring_jwt_secret(), algorithm="HS256")

    async def _call_spring_patch(
        self,
        account_type: str,
        database_id: int,
        new_password: str,
        delegation_jwt: str,
    ) -> None:
        """Execute PATCH on the corresponding ms-spring-api entity endpoint."""
        base_url = self._settings.ms_spring_api_url.rstrip("/")
        if account_type == "farm_owner":
            endpoint = f"{base_url}/farm-owners/{database_id}"
        elif account_type == "company_employee":
            endpoint = f"{base_url}/company-employees/{database_id}"
        else:
            raise PasswordResetTokenInvalidError("Tipo de conta inválido para redefinição.")

        headers = {
            "Authorization": f"Bearer {delegation_jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {"password": new_password}

        client = self._http_client or httpx.AsyncClient(
            timeout=self._settings.ms_spring_api_timeout_seconds
        )
        should_close_client = self._http_client is None

        try:
            response = await client.patch(
                endpoint,
                json=payload,
                headers=headers,
            )
        except (httpx.RequestError, OSError) as exc:
            logger.warning(
                "password_reset_spring_connection_error url=%s error=%s",
                endpoint,
                str(exc),
            )
            raise PasswordResetSpringError(
                "Não foi possível conectar ao serviço de atualização de senha.",
                status_code=502,
            ) from exc
        finally:
            if should_close_client:
                await client.aclose()

        if response.status_code == 200:
            return

        logger.warning(
            "password_reset_spring_response_failed status=%d url=%s body=%s",
            response.status_code,
            endpoint,
            response.text[:255],
        )

        if response.status_code == 400:
            try:
                body = response.json()
                detail = body.get("detail") if isinstance(body, dict) else None
            except ValueError:
                detail = None
            logger.warning("password_reset_spring_bad_request detail=%r", detail)
            raise PasswordResetSpringError(
                "Dados da requisição inválidos na API de negócio.", status_code=400
            )

        if response.status_code == 404:
            raise PasswordResetSpringError("Usuário não encontrado na API de negócio.", status_code=404)

        if response.status_code in (401, 403):
            raise PasswordResetSpringError("Falha de autorização na API de negócio.", status_code=502)

        raise PasswordResetSpringError(
            "Erro retornado pela API de negócio.",
            status_code=502,
        )

    async def _redis_client(self) -> Redis:
        if self._redis_url is None:
            raise PasswordResetUnavailable("Redis is not configured")
        if self._redis is not None:
            return self._redis

        async with self._redis_lock:
            if self._redis is not None:
                return self._redis
            client = Redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=self._REDIS_SOCKET_TIMEOUT_SECONDS,
                socket_timeout=self._REDIS_SOCKET_TIMEOUT_SECONDS,
            )
            try:
                await client.ping()
            except (RedisError, OSError) as exc:
                await client.aclose()
                raise PasswordResetUnavailable("Redis is unavailable") from exc
            self._redis = client
            return client

    async def _reserve_token(self, jti: str, ttl_seconds: int) -> None:
        """Atomically reserve a token before updating the password."""
        if self._redis_url is not None:
            client = await self._redis_client()
            try:
                reserved = await client.set(
                    self._BLACKLIST_PREFIX + jti, "1", nx=True, ex=max(ttl_seconds, 1)
                )
            except (RedisError, OSError) as exc:
                await self.close()
                raise PasswordResetUnavailable("Redis reservation failed") from exc
            if not reserved:
                raise PasswordResetTokenInvalidError("Token já utilizado ou inválido.")
            return

        now = time.time()
        async with self._blacklist_lock:
            self._cleanup_blacklist_memory(now)
            if jti in self._blacklist_memory:
                raise PasswordResetTokenInvalidError("Token já utilizado ou inválido.")
            self._blacklist_memory[jti] = now + ttl_seconds

    async def _release_token(self, jti: str) -> None:
        """Allow retry after a failed password update."""
        if self._redis_url is not None:
            client = await self._redis_client()
            try:
                await client.delete(self._BLACKLIST_PREFIX + jti)
            except (RedisError, OSError) as exc:
                await self.close()
                raise PasswordResetUnavailable("Redis reservation release failed") from exc
            return

        async with self._blacklist_lock:
            self._blacklist_memory.pop(jti, None)

    def _cleanup_blacklist_memory(self, now: float) -> None:
        expired = [
            k for k, exp in self._blacklist_memory.items() if exp <= now
        ]
        for k in expired:
            self._blacklist_memory.pop(k, None)
