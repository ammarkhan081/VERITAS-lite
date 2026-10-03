"""Application settings loaded from environment variables and `.env`."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for VERITAS-lite."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    llm_provider: str = "openai"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    groq_api_key: str = ""

    orchestrator_model: str = "gpt-4o-mini"
    red_team_model: str = "gpt-4o-mini"
    blue_team_model: str = "gpt-4o"
    verifier_llm_model: str = "gpt-4o-mini"

    database_url: str = "./data/veritas.db"

    default_max_steps: int = 30
    default_max_tokens: int = 100000
    normal_task_threshold: float = Field(
        default=0.10,
        validation_alias="NORMAL_TASK_ACCURACY_THRESHOLD",
    )
    patch_rejection_max: int = 3

    environment_type: str = "custom_sut"
    agentdojo_suite: str = "workspace"

    secret_patterns: list[str] = Field(
        default_factory=lambda: ["SESSION_TOKEN", "API_KEY"]
    )

    log_level: str = "INFO"
    log_format: str = "json"

    api_host: str = "0.0.0.0"
    api_port: int = 8000


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance loaded from the environment."""
    return Settings()
