"""Campaign StateGraph for VERITAS-lite.

This module assembles the closed loop::

    initialize -> normal baseline -> generate -> execute -> verify
      -> blue-team propose -> validate -> [human review] -> apply patch
      -> retest training -> retest held-out -> normal suite -> verify post-patch
      -> store regression -> report

Agent and evaluation nodes are implemented in ``backend.agents`` / ``backend.eval``
and collected in :mod:`backend.orchestration.graph_nodes`. Infrastructure nodes that
belong to the Orchestrator's control plane (patch validation, human review, patch
application, regression storage) and the deterministic routing functions live here.
"""

from __future__ import annotations

import threading
from typing import Any, Optional
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt

from backend.core.config import get_settings
from backend.core.trace_writer import write_log_event
from backend.memory.campaign_store import CampaignStore
from backend.memory.regression_store import RegressionStore
from backend.orchestration.graph_nodes import (
    node_blue_team_propose,
    node_execute_attacks,
    node_generate_attacks,
    node_generate_report,
    node_initialize_campaign,
    node_retest_held_out_attacks,
    node_retest_training_attacks,
    node_run_normal_baseline,
    node_run_normal_suite_post_patch,
    node_verify_attacks,
    node_verify_post_patch,
    route_after_verify_attacks,
    route_after_verify_post_patch,
)
from backend.schemas.models import (
    AttackFamily,
    CampaignState,
    PatchProposal,
    PatchType,
    RegressionTest,
    RiskLevel,
    utcnow_iso,
)

ALLOWED_PATCH_TYPES = {
    PatchType.CONFIG_CHANGE.value,
    PatchType.SANITIZATION_RULE.value,
    PatchType.PROMPT_GUARD.value,
    "config_change",
    "sanitization_rule",
    "prompt_guard",
}


_default_regression_store: Optional[RegressionStore] = None
_default_campaign_store: Optional[CampaignStore] = None


def get_regression_store() -> RegressionStore:
    """Return a shared or newly initialized RegressionStore instance."""
    global _default_regression_store
    if _default_regression_store is None:
        _default_regression_store = RegressionStore()
    return _default_regression_store


def get_campaign_store() -> CampaignStore:
    """Return a shared or newly initialized CampaignStore instance."""
    global _default_campaign_store
    if _default_campaign_store is None:
        _default_campaign_store = CampaignStore()
    return _default_campaign_store


# ============================================================================
# Infrastructure Nodes (Orchestrator control plane)
# ============================================================================


def node_validate_patch(state: CampaignState) -> dict:
    """Validate the proposed patch before routing it to auto-apply or human review.

    Structural safety (patch-type allow-list) is enforced in :func:`node_apply_patch`;
    risk-based routing is decided by :func:`route_after_validate_patch`.
    """
    return {"human_approved": False}


def node_human_review(state: CampaignState) -> dict:
    """Pause for human-in-the-loop review if patch risk is high."""
    proposal = state.get("patch_proposal", {})
    campaign_id = state.get("campaign_id", "")
    current_asr = state.get("asr_before", 0.0)

    try:
        approval = interrupt({
            "prompt": "Review the following patch proposal:",
            "proposal": proposal,
            "campaign_id": campaign_id,
            "current_asr": current_asr,
        })
    except RuntimeError:
        # Fallback when executed outside an active LangGraph runnable context (e.g. standalone test)
        approval = state.get("human_approved", True)

    interventions = state.get("human_interventions", 0) + 1
    write_log_event(
        "human_review",
        campaign_id,
        "human",
        {"approved": bool(approval), "interventions": interventions},
    )

    if approval:
        return {"human_approved": True, "human_interventions": interventions}
    return {"human_approved": False, "human_interventions": interventions}


def node_apply_patch(state: CampaignState) -> dict:
    """Validate patch proposal and apply configuration update to SUT."""
    campaign_id = state.get("campaign_id", "")
    patch_data = state.get("patch_proposal", {})

    if isinstance(patch_data, PatchProposal):
        patch_type = patch_data.type.value if hasattr(patch_data.type, "value") else str(patch_data.type)
        patch_id = patch_data.id
        change = patch_data.change
        patch_obj = patch_data
    elif isinstance(patch_data, dict):
        patch_type = patch_data.get("type", "")
        if hasattr(patch_type, "value"):
            patch_type = patch_type.value
        patch_id = patch_data.get("id") or f"patch-{uuid4()}"
        change = patch_data.get("change", {})
        target = patch_data.get("target", "sut_config")
        rationale = patch_data.get("rationale", "")
        risk_level = patch_data.get("risk_level", RiskLevel.LOW)
        if hasattr(risk_level, "value"):
            risk_level = RiskLevel(risk_level.value)
        else:
            risk_level = RiskLevel(risk_level) if risk_level in RiskLevel._value2member_map_ else RiskLevel.LOW
        patch_type_enum = (
            PatchType(patch_type)
            if patch_type in PatchType._value2member_map_
            else PatchType.CONFIG_CHANGE
        )
        patch_obj = PatchProposal(
            id=patch_id,
            type=patch_type_enum,
            target=target,
            change=change,
            rationale=rationale,
            risk_level=risk_level,
            requires_human_review=patch_data.get("requires_human_review", False),
        )
    else:
        patch_type = ""
        patch_id = f"patch-{uuid4()}"
        change = {}
        patch_obj = None

    if patch_type not in ALLOWED_PATCH_TYPES or not patch_obj:
        write_log_event(
            "patch_rejected",
            campaign_id,
            "orchestrator",
            {"patch_id": patch_id, "error": f"Disallowed patch type: {patch_type}"},
        )
        return {
            "phase": "patch",
            "error_message": f"Disallowed patch type: {patch_type}",
        }

    # The environment owns the semantics of each patch type (config merge,
    # input-filter registration, system-prompt guard), so it computes the new config.
    from backend.environment.adapter import get_environment_adapter

    updated_config = get_environment_adapter().apply_config(
        patch_obj, dict(state.get("sut_config", {}) or {})
    )

    campaign_store = get_campaign_store()
    try:
        campaign_store.save_patch(patch_obj, campaign_id)
    except Exception:
        pass
    campaign_store.update_patch_status(patch_id, "applied", applied_at=utcnow_iso())

    regression_store = get_regression_store()
    regression_store.mark_patch_applied(campaign_id)

    write_log_event(
        "patch_applied",
        campaign_id,
        "orchestrator",
        {"patch_id": patch_id, "change": change},
    )

    return {
        "sut_config": updated_config,
        "patches_applied": [patch_id],
        "phase": "retest",
    }


def node_store_regression(state: CampaignState) -> dict:
    """Store successful attack traces as permanent regression tests."""
    campaign_id = state.get("campaign_id", "")
    traces = state.get("traces", [])
    attack_batch = state.get("attack_batch", [])
    regression_store = get_regression_store()

    attack_map = {
        (a.id if hasattr(a, "id") else a.get("id")): a
        for a in attack_batch
        if (hasattr(a, "id") or isinstance(a, dict))
    }

    reg_ids: list[str] = []

    for trace in traces:
        gates = trace.gates_fired if hasattr(trace, "gates_fired") else trace.get("gates_fired", [])
        if not gates:
            continue

        # Gate fired check (failed gate check)
        attack_id = trace.attack_id if hasattr(trace, "attack_id") else trace.get("attack_id")
        task = trace.task if hasattr(trace, "task") else trace.get("task", "")
        tool_calls = trace.tool_calls if hasattr(trace, "tool_calls") else trace.get("tool_calls", [])

        matching_attack = attack_map.get(attack_id)
        if matching_attack:
            family = (
                matching_attack.family
                if hasattr(matching_attack, "family")
                else matching_attack.get("family", AttackFamily.DIRECT_INJECTION)
            )
            payload = (
                matching_attack.payload
                if hasattr(matching_attack, "payload")
                else matching_attack.get("payload", "")
            )
            injection_vector = (
                matching_attack.injection_vector
                if hasattr(matching_attack, "injection_vector")
                else matching_attack.get("injection_vector", "")
            )
            target_tool = (
                matching_attack.target_tool
                if hasattr(matching_attack, "target_tool")
                else matching_attack.get("target_tool", "")
            )
        else:
            family = AttackFamily.DIRECT_INJECTION
            payload = ""
            injection_vector = ""
            target_tool = ""

        evidence = {
            "gates_fired": [
                g.model_dump(mode="json") if hasattr(g, "model_dump") else g
                for g in gates
            ]
        }
        replay_info = {
            "task": task,
            "tool_calls": [
                tc.model_dump(mode="json") if hasattr(tc, "model_dump") else tc
                for tc in tool_calls
            ],
        }

        family_enum = AttackFamily(family.value) if hasattr(family, "value") else AttackFamily(family)
        reg_test = RegressionTest(
            campaign_id=campaign_id,
            attack_id=attack_id or f"atk-{uuid4()}",
            family=family_enum,
            payload=payload,
            injection_vector=injection_vector,
            target_tool=target_tool,
            evidence=evidence,
            replay_info=replay_info,
            sut_version=state.get("sut_descriptor", {}).get("version", "v1.0"),
            status="active",
        )
        regression_store.add_regression_test(reg_test)
        reg_ids.append(reg_test.id)

    write_log_event(
        "regression_tests_stored",
        campaign_id,
        "orchestrator",
        {"count": len(reg_ids), "ids": reg_ids},
    )
    return {"regression_tests_added": reg_ids}


# ============================================================================
# Routing Functions
# ============================================================================


def route_after_validate_patch(state: CampaignState) -> str:
    """Route after patch validation based on risk level and human review flag."""
    patch = state.get("patch_proposal", {})
    if isinstance(patch, PatchProposal):
        requires_human = patch.requires_human_review
        risk_level = patch.risk_level.value if hasattr(patch.risk_level, "value") else str(patch.risk_level)
    elif isinstance(patch, dict):
        requires_human = patch.get("requires_human_review", False)
        risk_level = patch.get("risk_level", RiskLevel.LOW)
        if hasattr(risk_level, "value"):
            risk_level = risk_level.value
    else:
        requires_human = False
        risk_level = "low"

    if requires_human or str(risk_level).lower() in ("high", RiskLevel.HIGH.value):
        return "human_required"
    return "auto_apply"


def route_after_human_review(state: CampaignState) -> str:
    """Route after human review based on approval decision."""
    if state.get("human_approved", False):
        return "apply_patch"
    return "blue_team_propose"


def route_after_patch_rejected(state: CampaignState) -> str:
    """Route after patch rejection to check rejection count against budget."""
    settings = get_settings()
    rejection_count = state.get("patch_rejection_count", 0)
    if rejection_count >= settings.patch_rejection_max:
        return "escalate"
    return "propose_new"


# ============================================================================
# Graph Builder
# ============================================================================


def build_campaign_graph(checkpointer: Optional[Any] = None) -> CompiledStateGraph:
    """Build and compile the VERITAS-lite campaign StateGraph.

    Args:
        checkpointer: Optional Checkpointer saver or context manager.

    Returns:
        CompiledStateGraph ready for execution or inspection.
    """
    builder = StateGraph(CampaignState)

    # Add all 15 nodes
    builder.add_node("initialize_campaign", node_initialize_campaign)
    builder.add_node("run_normal_baseline", node_run_normal_baseline)
    builder.add_node("generate_attacks", node_generate_attacks)
    builder.add_node("execute_attacks", node_execute_attacks)
    builder.add_node("verify_attacks", node_verify_attacks)
    builder.add_node("blue_team_propose", node_blue_team_propose)
    builder.add_node("validate_patch", node_validate_patch)
    builder.add_node("human_review", node_human_review)
    builder.add_node("apply_patch", node_apply_patch)
    builder.add_node("retest_training_attacks", node_retest_training_attacks)
    builder.add_node("retest_held_out_attacks", node_retest_held_out_attacks)
    builder.add_node("run_normal_suite_post_patch", node_run_normal_suite_post_patch)
    builder.add_node("verify_post_patch", node_verify_post_patch)
    builder.add_node("store_regression", node_store_regression)
    builder.add_node("generate_report", node_generate_report)

    # Add edges
    builder.add_edge(START, "initialize_campaign")
    builder.add_edge("initialize_campaign", "run_normal_baseline")
    builder.add_edge("run_normal_baseline", "generate_attacks")
    builder.add_edge("generate_attacks", "execute_attacks")
    builder.add_edge("execute_attacks", "verify_attacks")
    builder.add_conditional_edges("verify_attacks", route_after_verify_attacks, {
        "attack_succeeded": "blue_team_propose",
        "no_attack_budget": "generate_report",
        "no_attack_retry": "generate_attacks",
    })
    builder.add_edge("blue_team_propose", "validate_patch")
    builder.add_conditional_edges("validate_patch", route_after_validate_patch, {
        "human_required": "human_review",
        "auto_apply": "apply_patch",
    })
    builder.add_conditional_edges("human_review", route_after_human_review, {
        "apply_patch": "apply_patch",
        "blue_team_propose": "blue_team_propose",
    })
    builder.add_edge("apply_patch", "retest_training_attacks")
    builder.add_edge("retest_training_attacks", "retest_held_out_attacks")
    builder.add_edge("retest_held_out_attacks", "run_normal_suite_post_patch")
    builder.add_edge("run_normal_suite_post_patch", "verify_post_patch")
    builder.add_conditional_edges("verify_post_patch", route_after_verify_post_patch, {
        "patch_accepted": "store_regression",
        "patch_rejected_utility": "blue_team_propose",
        "patch_rejected_asr": "blue_team_propose",
    })
    # Handle patch rejection loop
    builder.add_conditional_edges("blue_team_propose", route_after_patch_rejected, {
        "propose_new": "validate_patch",  # when rejection_count < max
        "escalate": "generate_report",    # when rejection_count >= max (but only when re-entering after rejection)
    })
    builder.add_edge("store_regression", "generate_report")
    builder.add_edge("generate_report", END)

    if checkpointer is not None and hasattr(checkpointer, "__enter__") and not hasattr(checkpointer, "get_tuple"):
        checkpointer = checkpointer.__enter__()

    return builder.compile(checkpointer=checkpointer)


_global_checkpointer = None
_global_checkpointer_context = None
_checkpointer_lock = threading.Lock()

def get_compiled_graph() -> CompiledStateGraph:
    """Create a graph with durable PostgreSQL or local in-memory checkpoints."""
    global _global_checkpointer, _global_checkpointer_context
    if _global_checkpointer is None:
        with _checkpointer_lock:
            if _global_checkpointer is None:
                database_url = get_settings().database_url
                if database_url.startswith(("postgres://", "postgresql://")):
                    from langgraph.checkpoint.postgres import PostgresSaver

                    _global_checkpointer_context = PostgresSaver.from_conn_string(
                        database_url, pipeline=False
                    )
                    _global_checkpointer = _global_checkpointer_context.__enter__()
                    _global_checkpointer.setup()
                else:
                    _global_checkpointer = MemorySaver()
    return build_campaign_graph(checkpointer=_global_checkpointer)
