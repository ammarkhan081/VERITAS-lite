"""Shared, provider-agnostic LLM factory for VERITAS-lite agents."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.core.config import get_settings

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel


def get_llm(role: str) -> "BaseChatModel":
    """Create the configured chat model for one of the four agent roles.

    Provider packages are imported lazily so gate-only and verifier workflows
    do not require every supported provider integration to be installed.
    """
    settings = get_settings()
    model_map = {
        "orchestrator": settings.orchestrator_model,
        "red_team": settings.red_team_model,
        "blue_team": settings.blue_team_model,
        "verifier": settings.verifier_llm_model,
    }
    if role not in model_map:
        raise ValueError(f"Unknown LLM role {role!r}; expected one of {', '.join(model_map)}")

    provider = str(settings.llm_provider).lower().strip()
    model = model_map[role]
    setup_hint = "Set LLM_PROVIDER=openai|anthropic|groq and the corresponding API key in .env"
    try:
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=model, temperature=0.0, api_key=settings.openai_api_key)
        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model, temperature=0.0, api_key=settings.anthropic_api_key)
        if provider == "groq":
            from langchain_groq import ChatGroq
            return ChatGroq(model=model, temperature=0.0, api_key=settings.groq_api_key, max_retries=10, timeout=60.0)
    except ImportError as exc:
        raise ValueError(f"LLM provider package for {provider!r} is not installed. {setup_hint}") from exc
    except Exception as exc:
        raise ValueError(f"Could not configure the {provider!r} chat model for role {role!r}. {setup_hint}") from exc

    raise ValueError(f"Unsupported LLM provider {provider!r}. {setup_hint}")
