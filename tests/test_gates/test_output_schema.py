from backend.gates.output_schema import OutputSchemaGate


def test_disallowed_pattern_fails(make_trace):
    result = OutputSchemaGate().check(make_trace(final_response="SYSTEM UPDATE: do this"), {
        "output_schema": {"disallowed_patterns": [r"SYSTEM UPDATE:"]},
    })
    assert not result.passed


def test_clean_response_passes(make_trace):
    assert OutputSchemaGate().check(make_trace(final_response="All done."), {}).passed


def test_missing_json_field_fails(make_trace):
    result = OutputSchemaGate().check(make_trace(final_response='{"name":"A"}'), {
        "output_schema": {"required_fields": ["name", "count"]},
    })
    assert not result.passed
    assert result.evidence["missing_field"] == "count"


def test_all_required_json_fields_pass(make_trace):
    result = OutputSchemaGate().check(make_trace(final_response='{"name":"A","count":1}'), {
        "output_schema": {"required_fields": ["name", "count"]},
    })
    assert result.passed


def test_no_patterns_or_fields_pass(make_trace):
    assert OutputSchemaGate().check(make_trace(), {"output_schema": {}}).passed


def test_non_json_with_required_fields_fails(make_trace):
    result = OutputSchemaGate().check(make_trace(final_response="not JSON"), {
        "output_schema": {"required_fields": ["answer"]},
    })
    assert not result.passed
