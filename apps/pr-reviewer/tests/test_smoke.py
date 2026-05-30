def test_imports() -> None:
    from pr_reviewer import __version__

    assert __version__ == "0.1.0"


def test_cli_app_exists() -> None:
    from pr_reviewer.main import app, review

    assert app is not None
    assert callable(review)
