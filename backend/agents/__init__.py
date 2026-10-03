"""VERITAS-lite agent nodes, exposed through lazy imports."""

from importlib import import_module
from typing import Any

__all__ = [
    "get_llm",
    "node_orchestrator_initialize",
    "node_orchestrator_generate_report",
    "route_after_verify_attacks",
    "route_after_verify_post_patch",
    "node_red_team_generate_attacks",
    "node_red_team_execute_attacks",
    "node_red_team_retest_training",
    "node_red_team_retest_held_out",
    "node_blue_team_propose",
    "node_verifier_score_attacks",
    "node_verifier_score_post_patch",
]

_EXPORTS = {
    "get_llm": ("backend.agents.base", "get_llm"),
    "node_orchestrator_initialize": ("backend.agents.orchestrator", "node_orchestrator_initialize"),
    "node_orchestrator_generate_report": ("backend.agents.orchestrator", "node_orchestrator_generate_report"),
    "route_after_verify_attacks": ("backend.agents.orchestrator", "route_after_verify_attacks"),
    "route_after_verify_post_patch": ("backend.agents.orchestrator", "route_after_verify_post_patch"),
    "node_red_team_generate_attacks": ("backend.agents.red_team", "node_red_team_generate_attacks"),
    "node_red_team_execute_attacks": ("backend.agents.red_team", "node_red_team_execute_attacks"),
    "node_red_team_retest_training": ("backend.agents.red_team", "node_red_team_retest_training"),
    "node_red_team_retest_held_out": ("backend.agents.red_team", "node_red_team_retest_held_out"),
    "node_blue_team_propose": ("backend.agents.blue_team", "node_blue_team_propose"),
    "node_verifier_score_attacks": ("backend.agents.verifier", "node_verifier_score_attacks"),
    "node_verifier_score_post_patch": ("backend.agents.verifier", "node_verifier_score_post_patch"),
}


def __getattr__(name: str) -> Any:
    """Load an agent export only when a caller requests it."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, symbol_name = _EXPORTS[name]
    return getattr(import_module(module_name), symbol_name)
