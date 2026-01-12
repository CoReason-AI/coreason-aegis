import os
from typing import List, Literal, Optional

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings for Vibe Runner.
    Uses environment variables with VIBE_ prefix.
    """

    model_config = SettingsConfigDict(env_prefix="VIBE_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Tunable Settings
    llm_strategy: Literal["local", "api"] = "api"
    extensions_enabled: List[str] = ["security", "code-review"]
    max_retries: int = 5

    # Secrets
    github_token: Optional[SecretStr] = None
    google_api_key: Optional[SecretStr] = None
    openai_api_key: Optional[SecretStr] = None
    deepseek_api_key: Optional[SecretStr] = None
    ssh_private_key: Optional[SecretStr] = None

    @field_validator("github_token", mode="before")
    @classmethod
    def check_github_token(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return os.getenv("GITHUB_TOKEN")
        return v

    @field_validator("google_api_key", mode="before")
    @classmethod
    def check_google_api_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return os.getenv("GOOGLE_API_KEY")
        return v

    @field_validator("openai_api_key", mode="before")
    @classmethod
    def check_openai_api_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return os.getenv("OPENAI_API_KEY")
        return v

    @field_validator("deepseek_api_key", mode="before")
    @classmethod
    def check_deepseek_api_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return os.getenv("DEEPSEEK_API_KEY")
        return v

    @field_validator("ssh_private_key", mode="before")
    @classmethod
    def check_ssh_private_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return os.getenv("SSH_PRIVATE_KEY")
        return v

    def validate_secrets(self) -> None:
        """
        Explicitly validate existence of critical secrets.
        """
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN is missing. It is required for gh CLI.")

        if not self.google_api_key:
            raise ValueError("GOOGLE_API_KEY is missing. It is required for gemini CLI.")

        if self.llm_strategy == "api":
            if not self.openai_api_key and not self.deepseek_api_key:
                # Assuming one of them is required if using API strategy
                # The spec says "Optional (required only if llm_strategy='api')" for both.
                # It's safer to require at least one.
                # However, to avoid over-engineering if the user only provides one,
                # I'll check if BOTH are missing.
                raise ValueError(
                    "At least one API key (OPENAI_API_KEY or DEEPSEEK_API_KEY) is required when llm_strategy='api'."
                )


settings = Settings()
