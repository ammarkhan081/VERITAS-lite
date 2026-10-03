from backend.schemas.models import GateCode

from backend.gates.registry import GateRegistry, SECURITY_GATES


def test_registry_has_all_seven_gates():
    assert len(GateRegistry()._gates) == 7


def test_run_all_returns_six_per_trace_results(make_trace):
    assert len(GateRegistry().run_all_gates(make_trace(), {})) == 6


def test_run_security_returns_four_results(make_trace):
    assert len(GateRegistry().run_security_gates(make_trace(), {})) == 4


def test_no_security_gate_fired_for_empty_results():
    assert not GateRegistry().any_security_gate_fired([])


def test_failing_security_result_is_recognized(make_trace, make_call):
    trace = make_trace(tool_calls=[make_call("send_message")])
    registry = GateRegistry()
    results = registry.run_security_gates(trace, {})
    assert any(result.gate in SECURITY_GATES and not result.passed for result in results)
    assert registry.any_security_gate_fired(results)


def test_security_set_contains_exactly_four_codes():
    assert SECURITY_GATES == {
        GateCode.UNAUTHORIZED_TOOL,
        GateCode.ARGUMENT_POLICY,
        GateCode.INJECTION_MARKER,
        GateCode.EXFILTRATION_PATTERN,
    }
