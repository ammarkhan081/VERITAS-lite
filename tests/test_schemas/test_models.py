"""Unit tests for Pydantic and TypedDict schemas in schemas/models.py."""

from __future__ import annotations

import hashlib
import operator
from typing import get_type_hints

import pytest

from backend.schemas.models import (
    Attack,
    AttackFamily,
    AttackPlan,
    AttackPool,
    AttackStatus,
    CampaignReport,
    CampaignRequest,
    CampaignState,
    CampaignStatus,
    FailureSummary,
    GateCode,
    GateResult,
    PatchApplicationResult,
    PatchProposal,
    PatchType,
    Phase,
    RegressionTest,
    RiskLevel,
    ToolCall,
    Trace,
    VerificationResult,
    utcnow_iso,
)


def test_enum_string_values() -> None:
    """Verify all enum values are lowercase strings with underscores."""
    assert AttackFamily.DIRECT_INJECTION.value == "direct_injection"
    assert AttackFamily.INDIRECT_INJECTION.value == "indirect_injection"
    assert AttackFamily.GOAL_HIJACK.value == "goal_hijack"

    assert AttackPool.TRAINING.value == "training"
    assert AttackPool.HELD_OUT.value == "held_out"

    assert AttackStatus.PENDING.value == "pending"
    assert AttackStatus.EXECUTED.value == "executed"
    assert AttackStatus.SUCCEEDED.value == "succeeded"
    assert AttackStatus.FAILED.value == "failed"

    assert PatchType.CONFIG_CHANGE.value == "config_change"
    assert PatchType.SANITIZATION_RULE.value == "sanitization_rule"
    assert PatchType.PROMPT_GUARD.value == "prompt_guard"

    assert RiskLevel.LOW.value == "low"
    assert RiskLevel.MEDIUM.value == "medium"
    assert RiskLevel.HIGH.value == "high"

    assert Phase.BASELINE.value == "baseline"
    assert Phase.ATTACK.value == "attack"
    assert Phase.VERIFY.value == "verify"
    assert Phase.PATCH.value == "patch"
    assert Phase.RETEST.value == "retest"
    assert Phase.HELD_OUT.value == "held_out"
    assert Phase.REPORT.value == "report"

    assert CampaignStatus.RUNNING.value == "running"
    assert CampaignStatus.COMPLETED.value == "completed"
    assert CampaignStatus.FAILED.value == "failed"

    assert GateCode.UNAUTHORIZED_TOOL.value == "unauthorized_tool"
    assert GateCode.ARGUMENT_POLICY.value == "argument_policy"
    assert GateCode.OUTPUT_SCHEMA.value == "output_schema"
    assert GateCode.INJECTION_MARKER.value == "injection_marker"
    assert GateCode.EXFILTRATION_PATTERN.value == "exfiltration_pattern"
    assert GateCode.NORMAL_REGRESSION.value == "normal_regression"
    assert GateCode.TRACE_COMPLETENESS.value == "trace_completeness"


def test_attack_payload_hash_auto_populated() -> None:
    """Verify Attack auto-populates payload_hash with the first 16 chars of sha256."""
    payload = "drop database veritas;"
    expected_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

    atk = Attack(
        campaign_id="campaign-1",
        family=AttackFamily.DIRECT_INJECTION,
        payload=payload,
        injection_vector="direct_prompt",
        target_tool="db_exec",
        task="execute db query",
    )

    assert atk.payload_hash == expected_hash
    assert len(atk.payload_hash) == 16
    assert atk.status == AttackStatus.PENDING
    assert atk.pool == AttackPool.TRAINING


def test_attack_model_dump_serialization() -> None:
    """Verify Attack.model_dump() serializes all fields cleanly."""
    atk = Attack(
        campaign_id="campaign-1",
        family=AttackFamily.INDIRECT_INJECTION,
        payload="test payload",
        injection_vector="search_result",
        target_tool="browser",
        task="search web",
    )
    dumped = atk.model_dump(mode="json")
    assert dumped["campaign_id"] == "campaign-1"
    assert dumped["family"] == "indirect_injection"
    assert dumped["payload"] == "test payload"
    assert dumped["injection_vector"] == "search_result"
    assert dumped["target_tool"] == "browser"
    assert dumped["payload_hash"] != ""
    assert "created_at" in dumped


def test_trace_has_tool_call() -> None:
    """Verify Trace.has_tool_call() identifies present and absent tool calls."""
    tr = Trace(
        campaign_id="campaign-1",
        phase=Phase.ATTACK,
        task="read file",
        tool_calls=[
            ToolCall(
                name="read_file",
                args={"path": "/etc/passwd"},
                timestamp=utcnow_iso(),
                call_index=0,
            )
        ],
    )
    assert tr.has_tool_call("read_file") is True
    assert tr.has_tool_call("write_file") is False


def test_trace_get_tool_calls() -> None:
    """Verify Trace.get_tool_calls() filters tool calls by name."""
    now = utcnow_iso()
    tc1 = ToolCall(name="bash", args={"cmd": "ls"}, timestamp=now, call_index=0)
    tc2 = ToolCall(name="bash", args={"cmd": "pwd"}, timestamp=now, call_index=1)
    tc3 = ToolCall(name="curl", args={"url": "http://x"}, timestamp=now, call_index=2)

    tr = Trace(
        campaign_id="campaign-1",
        phase=Phase.ATTACK,
        task="run commands",
        tool_calls=[tc1, tc2, tc3],
    )

    bash_calls = tr.get_tool_calls("bash")
    assert len(bash_calls) == 2
    assert [c.args["cmd"] for c in bash_calls] == ["ls", "pwd"]

    curl_calls = tr.get_tool_calls("curl")
    assert len(curl_calls) == 1
    assert tr.get_tool_calls("unknown") == []


def test_campaign_state_typed_dict_keys() -> None:
    """Verify CampaignState is a valid TypedDict containing all required fields."""
    hints = get_type_hints(CampaignState)
    required_keys = {
        "campaign_id",
        "phase",
        "sut_descriptor",
        "sut_config",
        "threat_model",
        "budget_max_steps",
        "budget_max_tokens",
        "step_count",
        "tokens_used",
        "attack_batch",
        "executed_attack_ids",
        "payload_hashes",
        "traces",
        "verifier_report",
        "asr_before",
        "asr_after",
        "asr_held_out_before",
        "asr_held_out_after",
        "normal_acc_before",
        "normal_acc_after",
        "patch_proposal",
        "patch_rejection_count",
        "patches_applied",
        "human_approved",
        "human_interventions",
        "regression_tests_added",
        "final_report",
        "error_message",
    }
    assert required_keys.issubset(hints.keys())


def test_annotated_list_reducer_concatenation() -> None:
    """Verify operator.add reducer pattern concatenates lists rather than overwriting."""
    reducer = operator.add
    list1 = ["atk-1", "atk-2"]
    list2 = ["atk-3"]
    assert reducer(list1, list2) == ["atk-1", "atk-2", "atk-3"]


def test_gate_result_all_gate_codes() -> None:
    """Verify GateResult instantiates and serializes with every GateCode."""
    for gate_code in GateCode:
        gr = GateResult(
            gate=gate_code,
            passed=True,
            evidence={"detail": f"Checked {gate_code.value}"},
            attack_id="atk-10",
        )
        dumped = gr.model_dump(mode="json")
        assert dumped["gate"] == gate_code.value
        assert dumped["passed"] is True
        assert dumped["attack_id"] == "atk-10"


def test_patch_proposal_defaults() -> None:
    """Verify PatchProposal default values and schema structure."""
    patch = PatchProposal(
        type=PatchType.PROMPT_GUARD,
        target="system_prompt",
        change={"rule": "strip injections"},
        rationale="protect from direct prompt injection",
    )
    assert patch.id.startswith("patch-")
    assert patch.requires_human_review is False
    assert patch.risk_level == RiskLevel.LOW
    assert patch.expected_gates_affected == []

    dumped = patch.model_dump(mode="json")
    assert dumped["type"] == "prompt_guard"
    assert dumped["risk_level"] == "low"


def test_campaign_report_serialization() -> None:
    """Verify CampaignReport serializes to dictionary cleanly."""
    rep = CampaignReport(
        campaign_id="campaign-42",
        duration_seconds=12.5,
        asr_before=0.85,
        asr_after=0.10,
        asr_held_out_before=0.80,
        asr_held_out_after=0.15,
        normal_acc_before=0.98,
        normal_acc_after=0.97,
        patches_applied=2,
        human_interventions=1,
        regression_tests_added=3,
        total_steps=18,
        violations=[{"gate": "injection_marker", "passed": False}],
        patches=[{"id": "patch-1"}],
        summary="Campaign completed successfully.",
    )
    dumped = rep.model_dump(mode="json")
    assert dumped["campaign_id"] == "campaign-42"
    assert dumped["patches_applied"] == 2
    assert dumped["violations"][0]["gate"] == "injection_marker"
    assert dumped["summary"] == "Campaign completed successfully."


def test_auxiliary_models_serialize() -> None:
    """Verify AttackPlan, PatchApplicationResult, and FailureSummary."""
    plan = AttackPlan(campaign_id="campaign-1", attacks=[], notes="plan notes")
    assert plan.model_dump()["notes"] == "plan notes"

    app_res = PatchApplicationResult(
        patch_id="patch-1",
        campaign_id="campaign-1",
        applied=True,
        sut_config={"k": "v"},
    )
    assert app_res.applied is True

    fs = FailureSummary(
        attack_family=AttackFamily.GOAL_HIJACK,
        gates_fired=["unauthorized_tool"],
        tool_violated="system_exec",
        violation_type="privilege_escalation",
        injection_vector="prompt",
    )
    assert fs.attack_family == AttackFamily.GOAL_HIJACK
