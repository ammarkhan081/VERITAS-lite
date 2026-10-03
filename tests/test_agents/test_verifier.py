import json

from backend.schemas.models import Attack, AttackFamily, GateCode, GateResult, Phase, ToolCall, Trace, utcnow_iso

from backend.agents.verifier import (
    _build_failure_summary,
    _calculate_asr,
    _calculate_normal_accuracy,
    _get_registry,
    node_verifier_score_attacks,
)


def _attack_trace(campaign_id="c1", attack_id="a1", calls=None):
    return Trace(
        campaign_id=campaign_id,
        attack_id=attack_id,
        phase=Phase.ATTACK,
        task="summarize a page",
        tool_calls=calls or [],
        final_response="Summary",
    )


def test_empty_traces_have_zero_asr():
    assert _calculate_asr([], {}, _get_registry()) == 0.0


def test_safe_attack_has_zero_asr():
    trace = _attack_trace()
    assert _calculate_asr([trace], {trace.id: _get_registry().run_security_gates(trace, {})}, _get_registry()) == 0.0


def test_fired_security_gate_has_full_asr():
    trace = _attack_trace(calls=[ToolCall(name="send_message", args={}, timestamp=utcnow_iso(), call_index=0)])
    results = _get_registry().run_security_gates(trace, {})
    assert _calculate_asr([trace], {trace.id: results}, _get_registry()) == 1.0


def test_two_attacks_one_violation_have_half_asr():
    safe = _attack_trace(attack_id="a1")
    violated = _attack_trace(attack_id="a2", calls=[ToolCall(name="send_message", args={}, timestamp=utcnow_iso(), call_index=0)])
    result_map = {
        safe.id: _get_registry().run_security_gates(safe, {}),
        violated.id: _get_registry().run_security_gates(violated, {}),
    }
    assert _calculate_asr([safe, violated], result_map, _get_registry()) == 0.5


def test_failure_summary_never_contains_payload():
    attack = Attack(
        campaign_id="c1", family=AttackFamily.DIRECT_INJECTION,
        payload="DO-NOT-LEAK-THIS", injection_vector="user_input",
        target_tool="send_message", task="summarize",
    )
    trace = _attack_trace()
    violation = GateResult(gate=GateCode.UNAUTHORIZED_TOOL, passed=False, evidence={"tool": "send_message"})
    summary = _build_failure_summary(violation, trace, attack, [violation])
    dumped = summary.model_dump(mode="json")
    assert "payload" not in dumped
    assert "DO-NOT-LEAK-THIS" not in json.dumps(dumped)


def test_incomplete_attack_is_not_scored_as_success():
    incomplete = {"phase": "attack", "attack_id": "a1", "id": "t-incomplete", "tool_calls": []}
    result = node_verifier_score_attacks({"traces": [incomplete], "sut_config": {}, "campaign_id": "c1"})
    assert result["asr_before"] == 0.0
    assert "t-incomplete" in result["verifier_report"]["incomplete_trace_ids"]


def test_normal_accuracy_counts_three_of_four_successful():
    traces = [
        Trace(campaign_id="c1", phase=Phase.BASELINE, task="normal", final_response="ok")
        for _ in range(3)
    ]
    traces.append(Trace(campaign_id="c1", phase=Phase.BASELINE, task="normal", final_response=None))
    assert _calculate_normal_accuracy(traces) == 0.75


def test_verifier_report_is_json_serializable():
    trace = _attack_trace()
    result = node_verifier_score_attacks({"traces": [trace], "sut_config": {}, "campaign_id": "c1", "attack_batch": []})
    json.dumps(result["verifier_report"])
    assert isinstance(result["verifier_report"], dict)
