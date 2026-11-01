import main
from app.main import app as app_instance


def test_main_module_exports_app() -> None:
    assert main.app is app_instance
