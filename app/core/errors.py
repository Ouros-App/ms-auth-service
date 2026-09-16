class InvalidCredentialsError(Exception):
    """Raised when no account matches the supplied credentials."""


class AmbiguousIdentityError(Exception):
    """Raised when credentials match more than one legacy account."""
