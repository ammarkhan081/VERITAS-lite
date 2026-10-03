from backend.gates.unauthorized_tool import UnauthorizedToolGate


def test_unauthorized_send_message_fails(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message", {"recipient": "x"})])
    result = UnauthorizedToolGate().check(trace, {"authorized_tools": ["web_search"]})
    assert not result.passed
    assert result.evidence["tool"] == "send_message"


def test_authorized_send_message_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message")])
    assert UnauthorizedToolGate().check(trace, {"authorized_tools": ["send_message"]}).passed


def test_web_search_does_not_require_authorization(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("web_search")])
    assert UnauthorizedToolGate().check(trace, {}).passed


def test_authorized_file_write_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("file_write")])
    assert UnauthorizedToolGate().check(trace, {"authorized_tools": ["file_write"]}).passed


def test_empty_trace_passes(make_trace):
    assert UnauthorizedToolGate().check(make_trace(), {}).passed


def test_first_unauthorized_call_is_reported(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("web_search", call_index=0), make_call("file_write", call_index=1)])
    result = UnauthorizedToolGate().check(trace, {"authorized_tools": ["web_search"]})
    assert not result.passed
    assert result.evidence["call_index"] == 1


def test_missing_authorized_tools_fails_closed(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message")])
    assert not UnauthorizedToolGate().check(trace, {}).passed


def test_only_authorized_tools_pass(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message"), make_call("file_write", call_index=1)])
    result = UnauthorizedToolGate().check(trace, {"authorized_tools": ["send_message", "file_write"]})
    assert result.passed
