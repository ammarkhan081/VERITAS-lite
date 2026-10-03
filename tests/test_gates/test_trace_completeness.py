from datetime import datetime, timezone

from backend.gates.trace_completeness import TraceCompletenessGate


def _complete_trace(**updates):
    values = {
        "id": "trace-1",
        "campaign_id": "campaign-1",
        "phase": "attack",
        "task": "summarize",
        "tool_calls": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "final_response": None,
    }
    values.update(updates)
    return values


def test_all_required_fields_pass():
    assert TraceCompletenessGate().check(_complete_trace(), {}).passed


def test_missing_campaign_id_fails():
    result = TraceCompletenessGate().check(_complete_trace(campaign_id=None), {})
    assert not result.passed
    assert "campaign_id" in result.evidence["missing_fields"]


def test_empty_tool_calls_is_complete():
    assert TraceCompletenessGate().check(_complete_trace(tool_calls=[]), {}).passed


def test_optional_final_response_can_be_none():
    assert TraceCompletenessGate().check(_complete_trace(final_response=None), {}).passed


def test_all_missing_required_fields_are_reported():
    result = TraceCompletenessGate().check(_complete_trace(id="", task="", phase=None), {})
    assert not result.passed
    assert set(result.evidence["missing_fields"]) == {"id", "task", "phase"}


def test_empty_trace_dict_fails():
    result = TraceCompletenessGate().check({}, {})
    assert not result.passed
    assert len(result.evidence["missing_fields"]) == 6
