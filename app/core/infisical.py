import os

from dotenv import load_dotenv
from infisical_sdk import InfisicalSDKClient

DEFAULT_INFISICAL_SITE_URL = "https://app.infisical.com"

_REQUIRED_INFISICAL_KEYS = (
    "INFISICAL_CLIENT_ID",
    "INFISICAL_CLIENT_SECRET",
    "INFISICAL_PROJECT_ID",
    "INFISICAL_ENVIRONMENT",
    "INFISICAL_SECRET_PATH",
)


def load_infisical_secrets() -> None:
    """Load runtime secrets from Infisical using Ouros Universal Auth."""

    load_dotenv(override=False)

    values = {key: os.getenv(key) for key in _REQUIRED_INFISICAL_KEYS}
    if not any(values.values()):
        return

    missing = [key for key, value in values.items() if not value]
    if missing:
        raise RuntimeError(
            "Configuração parcial do Infisical; faltando: " + ", ".join(missing)
        )

    client = InfisicalSDKClient(
        host=os.getenv("INFISICAL_SITE_URL", DEFAULT_INFISICAL_SITE_URL)
    )
    client.auth.universal_auth.login(
        client_id=values["INFISICAL_CLIENT_ID"],
        client_secret=values["INFISICAL_CLIENT_SECRET"],
    )

    response = client.secrets.list_secrets(
        project_id=values["INFISICAL_PROJECT_ID"],
        environment_slug=values["INFISICAL_ENVIRONMENT"],
        secret_path=values["INFISICAL_SECRET_PATH"],
        view_secret_value=True,
    )

    for secret in response.secrets:
        os.environ[secret.secretKey] = secret.secretValue
