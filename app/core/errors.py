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
