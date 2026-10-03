import pytest

from backend.gates.exfiltration_pattern import ExfiltrationPatternGate


@pytest.mark.parametrize("tool", ["send_message", "web_search"])
def test_outbound_token_detected(make_trace, make_call, tool):
    trace = make_trace(tool_calls=[make_call(tool, {"content": "value TOKEN-123"})])
    result = ExfiltrationPatternGate().check(trace, {"sensitive_tokens": ["TOKEN-123"]})
    assert not result.passed
    assert result.evidence["token_found"] == "TOKEN-123"


def test_absent_token_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message", {"content": "ordinary"})])
    assert ExfiltrationPatternGate().check(trace, {"sensitive_tokens": ["TOKEN-123"]}).passed


def test_no_tokens_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message", {"content": "anything"})])
    assert ExfiltrationPatternGate().check(trace, {}).passed


def test_file_write_content_is_checked(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("file_write", {"path": "/tmp/x", "content": "TOKEN-456"})])
    assert not ExfiltrationPatternGate().check(trace, {"sensitive_tokens": ["TOKEN-456"]}).passed


def test_multiple_tokens_detects_any_match(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("web_search", {"query": "TOKEN-B"})])
    result = ExfiltrationPatternGate().check(trace, {"sensitive_tokens": ["TOKEN-A", "TOKEN-B"]})
    assert not result.passed
    assert result.evidence["token_found"] == "TOKEN-B"
