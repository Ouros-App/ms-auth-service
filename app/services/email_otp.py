import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import smtplib
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import EmailOtpInvalidError, EmailOtpUnavailable

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EmailOtpChallenge:
    """Public metadata for one short-lived native login challenge."""

    challenge_id: str
    expires_in: int
    masked_email: str


class EmailOtpService:
    """Create and verify native email OTP challenges without storing passwords."""

    _KEY_PREFIX = "ouros:auth:email-otp:"
    _REDIS_SOCKET_TIMEOUT_SECONDS = 2.0

    def __init__(self, settings: Settings) -> None:
        self._enabled = settings.ouros_email_otp_enabled
        self._hmac_secret = settings.ouros_email_otp_hmac_secret
        self._ttl_seconds = settings.ouros_email_otp_ttl_seconds
        self._max_attempts = settings.ouros_email_otp_max_attempts
        self._redis_url = settings.redis_url
        self._redis: Redis | None = None
        self._redis_lock = asyncio.Lock()
        self._memory: dict[str, dict[str, object]] = {}
        self._memory_lock = asyncio.Lock()

        self._smtp_host = settings.ouros_smtp_host
        self._smtp_port = settings.ouros_smtp_port
        self._smtp_from = settings.ouros_smtp_from
        self._smtp_from_display_name = settings.ouros_smtp_from_display_name
        self._smtp_auth = settings.ouros_smtp_auth
        self._smtp_starttls = settings.ouros_smtp_starttls
        self._smtp_ssl = settings.ouros_smtp_ssl
        self._smtp_user = settings.ouros_smtp_user
        self._smtp_password = settings.ouros_smtp_password
        self._smtp_timeout_seconds = settings.ouros_smtp_timeout_seconds

    async def close(self) -> None:
        """Close the dedicated Redis client when one was opened."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def start(self, email: str) -> EmailOtpChallenge:
        """Create one challenge only after the caller has verified the password."""
        self._require_ready()

        normalized_email = email.strip().lower()
        challenge_id = secrets.token_urlsafe(32)
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires_at = int(time.time()) + self._ttl_seconds
        record: dict[str, object] = {
            "email": normalized_email,
            "code_digest": self._code_digest(challenge_id, code),
            "attempts": 0,
            "expires_at": expires_at,
        }

        await self._save(challenge_id, record, self._ttl_seconds)
        try:
            await asyncio.to_thread(self._send_email, normalized_email, code)
        except (OSError, smtplib.SMTPException) as exc:
            smtp_code = getattr(exc, "smtp_code", None)
            errno = getattr(exc, "errno", None)
            logger.warning(
                "email_otp_delivery_failed error_type=%s smtp_code=%s errno=%s",
                type(exc).__name__,
                smtp_code,
                errno,
            )
            await self._delete(challenge_id)
            raise EmailOtpUnavailable("email delivery failed") from exc

        return EmailOtpChallenge(
            challenge_id=challenge_id,
            expires_in=self._ttl_seconds,
            masked_email=self._mask_email(normalized_email),
        )

    async def verify(self, challenge_id: str, email: str, code: str) -> None:
        """Consume one valid OTP challenge and reject all other cases generically."""
        self._require_ready()

        record = await self._load(challenge_id)
        if record is None:
            raise EmailOtpInvalidError

        normalized_email = email.strip().lower()
        record_email = record.get("email")
        expires_at = record.get("expires_at")
        attempts = record.get("attempts")
        code_digest = record.get("code_digest")

        if (
            not isinstance(record_email, str)
            or not isinstance(expires_at, int)
            or not isinstance(attempts, int)
            or not isinstance(code_digest, str)
        ):
            await self._delete(challenge_id)
            raise EmailOtpInvalidError

        now = int(time.time())
        if expires_at <= now or attempts >= self._max_attempts:
            await self._delete(challenge_id)
            raise EmailOtpInvalidError

        submitted_digest = self._code_digest(challenge_id, code)
        email_matches = hmac.compare_digest(record_email, normalized_email)
        code_matches = hmac.compare_digest(code_digest, submitted_digest)

        if not (email_matches and code_matches):
            attempts += 1
            if attempts >= self._max_attempts:
                await self._delete(challenge_id)
            else:
                record["attempts"] = attempts
                await self._save(
                    challenge_id,
                    record,
                    max(expires_at - now, 1),
                )
            raise EmailOtpInvalidError

        await self._delete(challenge_id)

    def _require_ready(self) -> None:
        if not self._enabled:
            raise EmailOtpUnavailable("email OTP is disabled")
        if self._hmac_secret is None or not self._smtp_host:
            raise EmailOtpUnavailable("email OTP configuration is incomplete")

    def _code_digest(self, challenge_id: str, code: str) -> str:
        if self._hmac_secret is None:
            raise EmailOtpUnavailable("email OTP HMAC secret is not configured")
        key = self._hmac_secret.get_secret_value().encode()
        payload = f"{challenge_id}:{code}".encode()
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    async def _redis_client(self) -> Redis:
        if self._redis_url is None:
            raise EmailOtpUnavailable("Redis is not configured")
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
                raise EmailOtpUnavailable("Redis is unavailable") from exc
            self._redis = client
            return client

    async def _save(
        self,
        challenge_id: str,
        record: dict[str, object],
        ttl_seconds: int,
    ) -> None:
        if self._redis_url is not None:
            client = await self._redis_client()
            try:
                await client.set(
                    self._KEY_PREFIX + challenge_id,
                    json.dumps(record, separators=(",", ":")),
                    ex=max(ttl_seconds, 1),
                )
            except (RedisError, OSError) as exc:
                await self.close()
                raise EmailOtpUnavailable("Redis write failed") from exc
            return

        async with self._memory_lock:
            self._cleanup_memory()
            self._memory[challenge_id] = dict(record)

    async def _load(self, challenge_id: str) -> dict[str, object] | None:
        if self._redis_url is not None:
            client = await self._redis_client()
            try:
                raw = await client.get(self._KEY_PREFIX + challenge_id)
            except (RedisError, OSError) as exc:
                await self.close()
                raise EmailOtpUnavailable("Redis read failed") from exc
            if raw is None:
                return None
            try:
                data = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                await self._delete(challenge_id)
                return None
            return data if isinstance(data, dict) else None

        async with self._memory_lock:
            self._cleanup_memory()
            record = self._memory.get(challenge_id)
            return dict(record) if record is not None else None

    async def _delete(self, challenge_id: str) -> None:
        if self._redis_url is not None:
            client = await self._redis_client()
            try:
                await client.delete(self._KEY_PREFIX + challenge_id)
            except (RedisError, OSError) as exc:
                await self.close()
                raise EmailOtpUnavailable("Redis delete failed") from exc
            return

        async with self._memory_lock:
            self._memory.pop(challenge_id, None)

    def _cleanup_memory(self) -> None:
        now = int(time.time())
        expired = [
            challenge_id
            for challenge_id, record in self._memory.items()
            if not isinstance(record.get("expires_at"), int)
            or int(record["expires_at"]) <= now
        ]
        for challenge_id in expired:
            self._memory.pop(challenge_id, None)

    def _build_email_message(self, recipient: str, code: str) -> EmailMessage:
        """Build the branded multipart OTP email with an inline Ouros logo."""
        ttl_minutes = max(self._ttl_seconds // 60, 1)
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "ouros-logo.png"

        message = EmailMessage()
        message["Subject"] = f"{code} é seu código de acesso Ouros"
        message["From"] = formataddr(
            (self._smtp_from_display_name, self._smtp_from)
        )
        message["To"] = recipient
        message.set_content(
            "Seu código de acesso Ouros é:\n\n"
            f"{code}\n\n"
            f"Ele expira em {ttl_minutes} minuto(s).\n"
            "Nunca compartilhe este código. Se você não tentou entrar, "
            "ignore esta mensagem."
        )

        message.add_alternative(
            f"""<!doctype html>
<html lang="pt-BR">
  <body style="margin:0;padding:0;background:#010B13;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
      Seu código Ouros é {code}. Ele expira em {ttl_minutes} minuto(s).
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
      border="0" style="width:100%;background:#010B13;margin:0;padding:0;">
      <tr>
        <td align="center" style="padding:40px 16px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
            border="0"
            style="width:100%;max-width:600px;border-collapse:separate;">
            <tr>
              <td align="center" style="padding:0 0 28px 0;">
                <img src="cid:ouros-logo" alt="Ouros" width="220"
                  style="display:block;width:220px;max-width:80%;height:auto;border:0;">
              </td>
            </tr>

            <tr>
              <td style="background:#F2F5F7;border-radius:24px;overflow:hidden;">
                <div style="height:6px;line-height:6px;background:#D8A23A;">&nbsp;</div>

                <table role="presentation" width="100%" cellspacing="0"
                  cellpadding="0" border="0" style="width:100%;">
                  <tr>
                    <td style="padding:44px 44px 18px 44px;">
                      <div style="
                        display:inline-block;
                        font-family:Poppins,Arial,sans-serif;
                        font-size:12px;
                        font-weight:600;
                        letter-spacing:1.4px;
                        text-transform:uppercase;
                        color:#171438;
                        background:#E9E6F2;
                        border-radius:999px;
                        padding:8px 12px;">
                        Segurança de acesso
                      </div>

                      <h1 style="
                        margin:22px 0 12px 0;
                        font-family:Poppins,Arial,sans-serif;
                        font-size:30px;
                        line-height:1.12;
                        letter-spacing:-1.2px;
                        font-weight:700;
                        color:#010B13;">
                        Confirme que é você
                      </h1>

                      <p style="
                        margin:0;
                        font-family:Poppins,Arial,sans-serif;
                        font-size:16px;
                        line-height:1.65;
                        color:#4B4A58;">
                        Use o código abaixo para concluir seu acesso ao Ouros.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:12px 44px 18px 44px;">
                      <table role="presentation" width="100%" cellspacing="0"
                        cellpadding="0" border="0"
                        style="width:100%;background:#171438;border-radius:18px;">
                        <tr>
                          <td align="center" style="padding:28px 18px 24px 18px;">
                            <div style="
                              font-family:Poppins,Arial,sans-serif;
                              font-size:12px;
                              line-height:1;
                              font-weight:600;
                              letter-spacing:1.8px;
                              text-transform:uppercase;
                              color:#D8A23A;
                              margin-bottom:14px;">
                              Seu código
                            </div>

                            <div style="
                              font-family:'Courier New',Courier,monospace;
                              font-size:40px;
                              line-height:1;
                              font-weight:700;
                              letter-spacing:10px;
                              color:#F2F5F7;
                              white-space:nowrap;">
                              {code}
                            </div>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:4px 44px 42px 44px;">
                      <p style="
                        margin:0 0 18px 0;
                        font-family:Poppins,Arial,sans-serif;
                        font-size:14px;
                        line-height:1.6;
                        color:#656372;">
                        Este código expira em
                        <strong style="color:#010B13;">{ttl_minutes} minuto(s)</strong>.
                      </p>

                      <table role="presentation" width="100%" cellspacing="0"
                        cellpadding="0" border="0"
                        style="width:100%;border-top:1px solid #D9DCE0;">
                        <tr>
                          <td style="padding-top:20px;">
                            <p style="
                              margin:0;
                              font-family:Poppins,Arial,sans-serif;
                              font-size:12px;
                              line-height:1.6;
                              color:#777582;">
                              Nunca compartilhe este código. Se você não tentou
                              entrar no Ouros, pode ignorar esta mensagem com segurança.
                            </p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td align="center" style="padding:24px 20px 0 20px;">
                <p style="
                  margin:0;
                  font-family:Poppins,Arial,sans-serif;
                  font-size:12px;
                  line-height:1.6;
                  letter-spacing:.2px;
                  color:#9B99AA;">
                  Ouros &bull; acesso protegido
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>""",
            subtype="html",
        )

        html_part = message.get_payload()[-1]
        html_part.add_related(
            logo_path.read_bytes(),
            maintype="image",
            subtype="png",
            cid="<ouros-logo>",
            filename="ouros-logo.png",
            disposition="inline",
        )
        return message

    def _send_email(self, recipient: str, code: str) -> None:
        if not self._smtp_host:
            raise EmailOtpUnavailable("SMTP host is not configured")

        message = self._build_email_message(recipient, code)

        context = ssl.create_default_context()
        smtp_type = smtplib.SMTP_SSL if self._smtp_ssl else smtplib.SMTP
        kwargs = {
            "host": self._smtp_host,
            "port": self._smtp_port,
            "timeout": self._smtp_timeout_seconds,
        }
        if self._smtp_ssl:
            kwargs["context"] = context

        with smtp_type(**kwargs) as smtp:
            if not self._smtp_ssl:
                smtp.ehlo()
                if self._smtp_starttls:
                    smtp.starttls(context=context)
                    smtp.ehlo()
            if self._smtp_auth:
                if not self._smtp_user or self._smtp_password is None:
                    raise EmailOtpUnavailable("SMTP credentials are not configured")
                smtp.login(
                    self._smtp_user,
                    self._smtp_password.get_secret_value(),
                )
            smtp.send_message(message)

    @staticmethod
    def _mask_email(email: str) -> str:
        local, separator, domain = email.partition("@")
        if not separator:
            return "***"
        visible = local[:1] if local else ""
        return f"{visible}***@{domain}"
