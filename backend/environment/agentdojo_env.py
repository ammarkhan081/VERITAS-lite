"""AgentDojo adapter stub pending external Day 0 validation."""

from __future__ import annotations

import copy
import logging
from typing import Any

from backend.core.config import get_settings
from backend.environment.adapter import EnvironmentAdapter
from backend.schemas.models import Attack, PatchProposal, Trace

logger = logging.getLogger("veritas.environment.agentdojo")


class AgentDojoAdapter(EnvironmentAdapter):
    """Clear, upgradeable stub for an AgentDojo-backed environment."""

    def __init__(self) -> None:
        self._suite_name = get_settings().agentdojo_suite
        self._pipeline: Any | None = None
        self._current_defense: Any | None = None
        logger.warning(
            "AgentDojoAdapter is a stub. Set ENVIRONMENT_TYPE=custom_sut "
            "until AgentDojo Day 0 validation is complete."
        )

    def run_task(self, task: str, attack: Attack | None, sut_config: dict) -> Trace:
        """Raise a specific message until AgentDojo integration is validated."""
        raise NotImplementedError(
            "AgentDojoAdapter is not implemented. Complete the Day 0 validation "
            "checklist in HANDOFF_NOTES.md, then implement the AgentPipeline "
            "integration. Use ENVIRONMENT_TYPE=custom_sut for the current MVP."
        )

    def apply_config(self, patch: PatchProposal, current_config: dict) -> dict:
        """Return a copied config with the proposed changes merged at the top level."""
        updated = copy.deepcopy(current_config)
        change = getattr(patch, "change", {})
        if isinstance(patch, dict):
            change = patch.get("change", change)
        if isinstance(change, dict):
            updated.update(copy.deepcopy(change))
        return updated

    def reset(self) -> None:
        """Clear any future pipeline state without importing AgentDojo."""
        self._pipeline = None
        self._current_defense = None
