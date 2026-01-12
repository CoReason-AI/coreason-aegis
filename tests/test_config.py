import pytest

from coreason_jules_automator.config import Settings


def test_defaults() -> None:
    settings = Settings()
    assert settings.llm_strategy == "api"
    assert settings.extensions_enabled == ["security", "code-review"]
    assert settings.max_retries == 5


def test_env_var_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIBE_LLM_STRATEGY", "local")
    monkeypatch.setenv("VIBE_MAX_RETRIES", "10")

    settings = Settings()
    assert settings.llm_strategy == "local"
    assert settings.max_retries == 10


def test_vibe_prefixed_secret_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test that VIBE_GITHUB_TOKEN overrides GITHUB_TOKEN and passes check_github_token's "v is not None" path
    monkeypatch.setenv("VIBE_GITHUB_TOKEN", "vibe_token")
    monkeypatch.setenv("GITHUB_TOKEN", "std_token")

    settings = Settings()
    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "vibe_token"


def test_secrets_validation_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake_gh_token")
    monkeypatch.setenv("GOOGLE_API_KEY", "fake_google_key")
    monkeypatch.setenv("OPENAI_API_KEY", "fake_openai_key")

    settings = Settings()
    settings.validate_secrets()

    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "fake_gh_token"
    assert settings.google_api_key is not None
    assert settings.google_api_key.get_secret_value() == "fake_google_key"


def test_secrets_validation_failure_github(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "fake_google_key")

    settings = Settings()
    with pytest.raises(ValueError, match="GITHUB_TOKEN is missing"):
        settings.validate_secrets()


def test_secrets_validation_failure_google(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake_gh_token")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    settings = Settings()
    with pytest.raises(ValueError, match="GOOGLE_API_KEY is missing"):
        settings.validate_secrets()


def test_api_strategy_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake_gh_token")
    monkeypatch.setenv("GOOGLE_API_KEY", "fake_google_key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    settings = Settings()
    # llm_strategy defaults to "api"
    with pytest.raises(ValueError, match="At least one API key"):
        settings.validate_secrets()


def test_secret_masking(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret_token_value")
    settings = Settings()

    assert "secret_token_value" not in repr(settings)
    assert "secret_token_value" not in str(settings.github_token)


def test_all_env_vars_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test all fallback validators
    monkeypatch.setenv("GITHUB_TOKEN", "gh")
    monkeypatch.setenv("GOOGLE_API_KEY", "g")
    monkeypatch.setenv("OPENAI_API_KEY", "o")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "d")
    monkeypatch.setenv("SSH_PRIVATE_KEY", "s")

    settings = Settings()

    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "gh"
    assert settings.google_api_key is not None
    assert settings.google_api_key.get_secret_value() == "g"
    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == "o"
    assert settings.deepseek_api_key is not None
    assert settings.deepseek_api_key.get_secret_value() == "d"
    assert settings.ssh_private_key is not None
    assert settings.ssh_private_key.get_secret_value() == "s"


def test_vibe_prefixed_all_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test all VIBE_ prefixed overrides
    monkeypatch.setenv("VIBE_GITHUB_TOKEN", "v_gh")
    monkeypatch.setenv("VIBE_GOOGLE_API_KEY", "v_g")
    monkeypatch.setenv("VIBE_OPENAI_API_KEY", "v_o")
    monkeypatch.setenv("VIBE_DEEPSEEK_API_KEY", "v_d")
    monkeypatch.setenv("VIBE_SSH_PRIVATE_KEY", "v_s")

    settings = Settings()

    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "v_gh"
    assert settings.google_api_key is not None
    assert settings.google_api_key.get_secret_value() == "v_g"
    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == "v_o"
    assert settings.deepseek_api_key is not None
    assert settings.deepseek_api_key.get_secret_value() == "v_d"
    assert settings.ssh_private_key is not None
    assert settings.ssh_private_key.get_secret_value() == "v_s"
