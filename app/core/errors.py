class InvalidCredentialsError(Exception):
    """Raised when no account matches the supplied credentials."""


class AmbiguousIdentityError(Exception):
    """Raised when credentials match more than one legacy account."""


class RateLimitExceeded(Exception):
    """Raised when a credential verification rate limit is exceeded."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limit exceeded")
        self.retry_after = max(retry_after, 1)


class EmailOtpInvalidError(Exception):
    """Raised when an email OTP challenge is missing, expired or invalid."""


class EmailOtpUnavailable(Exception):
    """Raised when the email OTP subsystem cannot create or verify challenges."""


class PasswordResetOtpInvalidError(Exception):
    """Raised when a password reset OTP challenge is missing, expired or invalid."""


class PasswordResetOtpAttemptsExceededError(Exception):
    """Raised when max attempts for password reset OTP verification are exceeded."""


class PasswordResetTokenInvalidError(Exception):
    """Raised when a reset token is invalid, expired, or already used."""


class PasswordResetSpringError(Exception):
    """Raised when the Spring business API returns an error during password reset."""

    def __init__(self, detail: str = "Falha na comunicação com o serviço de atualização de senha.", status_code: int = 502) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class PasswordResetUnavailable(Exception):
    """Raised when the password reset subsystem is temporarily unavailable."""
