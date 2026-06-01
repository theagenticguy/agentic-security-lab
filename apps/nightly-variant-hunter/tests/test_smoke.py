def test_imports() -> None:
    from nightly_variant_hunter import __version__

    assert __version__ == "0.1.0"


def test_cli_app_exists() -> None:
    from nightly_variant_hunter.main import app, hunt

    assert app is not None
    assert callable(hunt)
