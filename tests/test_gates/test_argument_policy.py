from backend.gates.argument_policy import ArgumentPolicyGate


def test_allowed_file_path_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("file_write", {"path": "/tmp/tasks/a.txt"})])
    config = {"policies": {"file_write": {"allowed_paths": ["/tmp/tasks/"]}}}
    assert ArgumentPolicyGate().check(trace, config).passed


def test_disallowed_file_path_fails(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("file_write", {"path": "/etc/passwd"})])
    config = {"policies": {"file_write": {"allowed_paths": ["/tmp/tasks/"]}}}
    assert not ArgumentPolicyGate().check(trace, config).passed


def test_allowed_recipient_passes(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message", {"recipient": "a@example.com"})])
    config = {"policies": {"send_message": {"allowed_recipients": ["a@example.com"]}}}
    assert ArgumentPolicyGate().check(trace, config).passed


def test_disallowed_recipient_fails(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message", {"recipient": "evil@example.com"})])
    config = {"policies": {"send_message": {"allowed_recipients": ["a@example.com"]}}}
    assert not ArgumentPolicyGate().check(trace, config).passed


def test_web_search_has_no_default_policy(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("web_search", {"query": "anything"})])
    assert ArgumentPolicyGate().check(trace, {}).passed


def test_missing_tool_policy_is_allow_all(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("file_write", {"path": "/etc/passwd"})])
    assert ArgumentPolicyGate().check(trace, {"policies": {}}).passed


def test_empty_trace_passes(make_trace):
    assert ArgumentPolicyGate().check(make_trace(), {}).passed


def test_reports_first_violation(make_trace, make_call):
    trace = make_trace(tool_calls=[
        make_call("file_write", {"path": "/bad/a"}, call_index=0),
        make_call("send_message", {"recipient": "bad"}, call_index=1),
    ])
    result = ArgumentPolicyGate().check(trace, {"policies": {
        "file_write": {"allowed_paths": ["/ok/"]},
        "send_message": {"allowed_recipients": ["good"]},
    }})
    assert not result.passed
    assert result.evidence["arg"] == "path"
