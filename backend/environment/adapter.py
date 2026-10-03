"""Shared environment contract and adapter factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from backend.schemas.models import Attack, PatchProposal, Trace

_ENVIRONMENT_TYPE_OVERRIDE: ContextVar[str | None] = ContextVar(
    "veritas_environment_type_override", default=None
)


class EnvironmentAdapter(ABC):
    """Interface used by campaign agents to execute tasks against a SUT."""

    @abstractmethod
    def run_task(self, task: str, attack: Attack | None, sut_config: dict) -> Trace:
        """Run a task, optionally injecting an attack, and return a complete trace."""

    @abstractmethod
    def apply_config(self, patch: PatchProposal, current_config: dict) -> dict:
        """Return a patched configuration without mutating ``current_config``."""

    @abstractmethod
    def reset(self) -> None:
        """Reset SUT state to its initial conditions."""


def get_environment_adapter() -> EnvironmentAdapter:
    """Create the adapter selected by ``ENVIRONMENT_TYPE``."""
    from backend.core.config import get_settings

    override = _ENVIRONMENT_TYPE_OVERRIDE.get()
    environment_type = str(override or get_settings().environment_type).strip().lower()
    if environment_type == "agentdojo":
        try:
            from backend.environment.agentdojo_env import AgentDojoAdapter
        except ImportError as exc:
            raise ImportError(
                "ENVIRONMENT_TYPE=agentdojo requires the Person 3 AgentDojo adapter."
            ) from exc
        return AgentDojoAdapter()
    if environment_type not in {"custom_sut", "custom"}:
        raise ValueError(
            f"Unsupported ENVIRONMENT_TYPE {environment_type!r}; "
            "choose 'custom_sut' or 'agentdojo'."
        )
    try:
        from backend.environment.custom_sut import CustomSUTAdapter
    except ImportError as exc:
        raise ImportError(
            "The custom SUT environment adapter could not be imported."
        ) from exc
    return CustomSUTAdapter()


@contextmanager
def environment_type_override(environment_type: str | None) -> Iterator[None]:
    """Select an environment for one campaign without changing process settings."""
    if not environment_type:
        yield
        return
    token = _ENVIRONMENT_TYPE_OVERRIDE.set(str(environment_type).strip().lower())
    try:
        yield
    finally:
        _ENVIRONMENT_TYPE_OVERRIDE.reset(token)
