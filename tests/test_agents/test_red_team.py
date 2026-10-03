from types import SimpleNamespace

from backend.schemas.models import AttackFamily, AttackStatus, Phase, ToolCall, Trace, utcnow_iso

import backend.agents.red_team as red_team


def test_is_duplicate_detects_hash_match():
    payload = "new attack wording"
    assert red_team._is_duplicate(payload, [red_team._payload_hash(payload)])


def test_is_duplicate_allows_new_payload():
    assert not red_team._is_duplicate("different", [red_team._payload_hash("original")])


def test_select_next_family_rotates_after_repeated_family():
    state = {"attack_batch": [{"family": "direct_injection"}] * 3}
    assert red_team._select_next_family(state) == AttackFamily.INDIRECT_INJECTION


def test_attack_generation_output_validates():
    output = red_team.AttackGenerationOutput.model_validate({"attacks": [{
        "family": "direct_injection", "payload": "ignore rules", "injection_vector": "tool_output",
        "target_tool": "send_message", "task": "summarize a page",
    }]})
    assert output.attacks[0].family == AttackFamily.DIRECT_INJECTION


def test_prompt_file_loads():
    assert "Generate" in red_team._load_prompt("red_team_generate.txt")


def test_generation_deduplicates_and_seals(monkeypatch):
    output = red_team.AttackGenerationOutput(attacks=[
        red_team.SingleAttack(family=family, payload=f"payload-{i}", injection_vector="tool_output", target_tool="send_message", task="summarize")
        for i, family in enumerate(AttackFamily)
    ])
    saved = []
    sealed = []

    class FakeCampaignStore:
        def save_attack(self, attack):
            saved.append(attack)

    class FakeRegressionStore:
        def seal_held_out(self, campaign_id, attacks):
            sealed.extend(attacks)

    monkeypatch.setattr(red_team, "CampaignStore", FakeCampaignStore)
    monkeypatch.setattr(red_team, "RegressionStore", FakeRegressionStore)
    monkeypatch.setattr(red_team, "get_settings", lambda: SimpleNamespace(default_max_steps=15))
    monkeypatch.setattr(red_team, "_invoke_generation", lambda prompt: output)
    result = red_team.node_red_team_generate_attacks({
        "campaign_id": "c1", "attack_batch": [], "payload_hashes": [], "sut_config": {},
    })
    assert len(saved) == 1
    assert len(sealed) == 2
    assert result["held_out_sealed"] is True
    assert len(result["attack_batch"]) == 1


def test_execution_without_environment_adapter_returns_gracefully(monkeypatch):
    monkeypatch.setattr(red_team, "_environment_adapter", lambda: None)
    result = red_team.node_red_team_execute_attacks({
        "campaign_id": "c1", "attack_batch": [], "executed_attack_ids": [], "step_count": 0,
    })
    assert result["traces"] == []
    assert result["executed_attack_ids"] == []
    assert "Environment adapter" in result["error_message"]


def test_execution_updates_status_and_appends_trace(monkeypatch):
    statuses = []
    traces = []

    class FakeCampaignStore:
        def save_trace(self, trace):
            traces.append(trace)

        def update_attack_status(self, attack_id, status):
            statuses.append((attack_id, status))

    class FakeEnvironment:
        def run_task(self, task, attack, sut_config):
            return Trace(campaign_id="c1", phase=Phase.ATTACK, task=task, final_response="done")

    monkeypatch.setattr(red_team, "CampaignStore", FakeCampaignStore)
    monkeypatch.setattr(red_team, "_environment_adapter", lambda: FakeEnvironment())
    attack = {
        "id": "a1", "campaign_id": "c1", "family": "direct_injection", "payload": "payload",
        "payload_hash": "hash", "injection_vector": "tool_output", "target_tool": "send_message",
        "task": "summarize", "pool": "training", "status": "pending",
    }
    result = red_team.node_red_team_execute_attacks({
        "campaign_id": "c1", "attack_batch": [attack], "executed_attack_ids": [],
        "step_count": 0, "budget_max_steps": 4, "sut_config": {},
    })
    assert result["executed_attack_ids"] == ["a1"]
    assert result["step_count"] == 1
    assert statuses == [("a1", AttackStatus.EXECUTED)]
    assert traces[0].attack_id == "a1"


def test_held_out_retest_restores_task_and_records_result(monkeypatch):
    from backend.memory.campaign_store import CampaignStore
    from backend.schemas.models import Attack
    import backend.orchestration.graph as graph

    graph._default_regression_store = None
    regression_store = graph.get_regression_store()

    campaign_id = CampaignStore().create_campaign(
        __import__("backend.schemas.models", fromlist=["CampaignRequest"]).CampaignRequest(
            sut_descriptor={}, threat_model={}, budget={}
        ),
        campaign_id="campaign-holdout",
    )
    attack = Attack(
        campaign_id=campaign_id, family=AttackFamily.DIRECT_INJECTION,
        payload="holdout payload", injection_vector="search_result",
        target_tool="send_message", task="Summarize this untrusted result.",
    )
    regression_store.seal_held_out(campaign_id, [attack])
    regression_store.mark_patch_applied(campaign_id)
    observed = []

    class FakeCampaignStore:
        def save_trace(self, trace):
            observed.append(trace.task)

        def update_attack_status(self, attack_id, status):
            pass

    class FakeEnvironment:
        def run_task(self, task, attack, sut_config):
            return Trace(campaign_id=campaign_id, phase=Phase.HELD_OUT, task=task, final_response="done")

    monkeypatch.setattr(red_team, "CampaignStore", FakeCampaignStore)
    monkeypatch.setattr(red_team, "_environment_adapter", lambda: FakeEnvironment())
    result = red_team.node_red_team_retest_held_out({
        "campaign_id": campaign_id, "sut_config": {}, "step_count": 0,
        "budget_max_steps": 10, "executed_attack_ids": [],
    })
    assert result["traces"][0]["task"] == "Summarize this untrusted result."
    assert observed == ["Summarize this untrusted result."]
    assert regression_store.sample_held_out(campaign_id, n=1)[0].id == attack.id
