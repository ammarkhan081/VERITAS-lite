import json

from backend.schemas.models import FailureSummary, PatchType, RiskLevel

import backend.agents.blue_team as blue_team


class _Response:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, output, prompt_sink):
        self.output = output
        self.prompt_sink = prompt_sink

    def invoke(self, messages):
        self.prompt_sink.append("\n".join(str(message.content) for message in messages))
        return _Response(json.dumps(self.output.model_dump(mode="json")))


def test_blue_team_proposes_machine_applicable_change(monkeypatch):
    prompts = []
    output = blue_team.PatchProposalOutput(
        type=PatchType.SANITIZATION_RULE,
        target="tool_output_filter",
        change={"strip_untrusted_instructions": True},
        rationale="Treat retrieved text as untrusted input.",
        risk_level=RiskLevel.LOW,
    )

    class FakeLLM:
        def invoke(self, messages):
            return _FakeLLM(output, prompts).invoke(messages)

    saved = []

    class FakeStore:
        def save_patch(self, patch, campaign_id):
            saved.append((patch, campaign_id))

    monkeypatch.setattr(blue_team, "get_llm", lambda role: FakeLLM())
    monkeypatch.setattr(blue_team, "CampaignStore", FakeStore)
    summary = FailureSummary(
        attack_family="indirect_injection", gates_fired=["unauthorized_tool"],
        tool_violated="send_message", violation_type="unauthorized_tool", injection_vector="web_search_result",
    )
    result = blue_team.node_blue_team_propose({
        "campaign_id": "c1", "verifier_report": {"violations": [summary.model_dump(mode="json")]},
        "sut_config": {"sensitive_tokens": ["SECRET"], "payload": "MUST_NOT_LEAK"},
    })
    assert result["patch_proposal"]["change"]
    assert saved[0][1] == "c1"
    assert "MUST_NOT_LEAK" not in prompts[0]
    assert "SECRET" not in prompts[0]


def test_blue_team_output_does_not_include_attack_payload(monkeypatch):
    output = blue_team.PatchProposalOutput(
        type=PatchType.CONFIG_CHANGE, target="allowed_tools", change={"allowed_tools": ["web_search"]},
        rationale="Limit tool availability.", risk_level=RiskLevel.LOW,
    )

    prompts = []
    class FakeLLM:
        def invoke(self, messages):
            return _FakeLLM(output, prompts).invoke(messages)

    class FakeStore:
        def save_patch(self, patch, campaign_id):
            pass

    monkeypatch.setattr(blue_team, "get_llm", lambda role: FakeLLM())
    monkeypatch.setattr(blue_team, "CampaignStore", FakeStore)
    summary = {
        "attack_family": "direct_injection", "gates_fired": ["unauthorized_tool"],
        "tool_violated": "send_message", "violation_type": "unauthorized_tool", "injection_vector": "user_input",
        "payload": "private attack payload",
    }
    result = blue_team.node_blue_team_propose({"campaign_id": "c1", "verifier_report": {"violations": [summary]}, "sut_config": {}})
    assert "payload" not in result["patch_proposal"]
    assert "private attack payload" not in str(result["patch_proposal"])
    assert "private attack payload" not in prompts[0]


def test_patch_output_accepts_each_patch_type():
    for patch_type in PatchType:
        value = blue_team.PatchProposalOutput(
            type=patch_type, target="target", change={"enabled": True},
            rationale="minimal", risk_level=RiskLevel.MEDIUM,
        )
        assert value.type == patch_type


def test_failure_summary_allowlist_removes_extra_payload():
    summary = blue_team._safe_summary({
        "attack_family": "goal_hijack", "gates_fired": [], "tool_violated": "file_write",
        "violation_type": "argument_policy", "injection_vector": "document", "payload": "secret",
    })
    assert "payload" not in summary.model_dump()


def test_missing_failure_summary_is_rejected():
    try:
        blue_team.node_blue_team_propose({"verifier_report": {"violations": []}})
    except ValueError as exc:
        assert "FailureSummary" in str(exc)
    else:
        raise AssertionError("Expected missing FailureSummary to be rejected")


def test_blue_team_prompt_exists():
    prompt = blue_team._load_prompt()
    assert "Failure evidence" in prompt
