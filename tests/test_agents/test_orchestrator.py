from types import SimpleNamespace

from backend.core.config import get_settings
from backend.memory.campaign_store import CampaignStore

import backend.agents.orchestrator as orchestrator


def test_attack_routing_success_retry_and_budget(monkeypatch):
    monkeypatch.setattr(orchestrator, "get_settings", lambda: SimpleNamespace(default_max_steps=5))
    assert orchestrator.route_after_verify_attacks({"verifier_report": {"asr": 0.1}, "step_count": 0, "budget_max_steps": 5}) == "attack_succeeded"
    assert orchestrator.route_after_verify_attacks({"verifier_report": {"asr": 0.0}, "step_count": 1, "budget_max_steps": 5}) == "no_attack_retry"
    assert orchestrator.route_after_verify_attacks({"verifier_report": {"asr": 0.0}, "step_count": 5, "budget_max_steps": 5}) == "no_attack_budget"


def test_post_patch_routing_rejects_utility_drop(monkeypatch):
    monkeypatch.setattr(orchestrator, "get_settings", lambda: SimpleNamespace(normal_task_threshold=0.1))
    state = {"asr_before": 0.8, "asr_after": 0.1, "normal_acc_before": 0.95,
             "verifier_report": {"asr": 0.1, "normal_task_accuracy": 0.7}}
    assert orchestrator.route_after_verify_post_patch(state) == "patch_rejected_utility"


def test_post_patch_routing_rejects_no_asr_improvement(monkeypatch):
    monkeypatch.setattr(orchestrator, "get_settings", lambda: SimpleNamespace(normal_task_threshold=0.1))
    state = {"asr_before": 0.5, "asr_after": 0.5, "normal_acc_before": 0.95,
             "verifier_report": {"asr": 0.5, "normal_task_accuracy": 0.95}}
    assert orchestrator.route_after_verify_post_patch(state) == "patch_rejected_asr"


def test_post_patch_routing_accepts_improved_safe_patch(monkeypatch):
    monkeypatch.setattr(orchestrator, "get_settings", lambda: SimpleNamespace(normal_task_threshold=0.1))
    state = {"asr_before": 0.8, "asr_after": 0.1, "normal_acc_before": 0.95,
             "verifier_report": {"asr": 0.1, "normal_task_accuracy": 0.92}}
    assert orchestrator.route_after_verify_post_patch(state) == "patch_accepted"


def test_initialize_creates_campaign_and_sensitive_tokens():
    state = {
        "campaign_id": "campaign-fixed", "sut_descriptor": {"name": "test", "config": {"tool": "x"}},
        "sut_config": {"tool": "x"}, "threat_model": {"families": ["direct_injection"]},
        "budget_max_steps": 8, "budget_max_tokens": 100,
    }
    result = orchestrator.node_orchestrator_initialize(state)
    assert result["phase"] == "baseline"
    assert result["campaign_id"] == "campaign-fixed"
    tokens = result["sut_config"]["sensitive_tokens"]
    assert len(tokens) == 3 and len(set(tokens)) == 3
    assert CampaignStore().get_campaign("campaign-fixed")["status"] == "running"


def test_generate_report_uses_campaign_report_schema():
    CampaignStore().create_campaign(
        __import__("backend.schemas.models", fromlist=["CampaignRequest"]).CampaignRequest(
            sut_descriptor={}, threat_model={}, budget={}
        ),
        campaign_id="campaign-report",
    )
    result = orchestrator.node_orchestrator_generate_report({
        "campaign_id": "campaign-report", "asr_before": 0.8, "asr_after": 0.1,
        "asr_held_out_before": 0.0, "asr_held_out_after": 0.2,
        "normal_acc_before": 0.9, "normal_acc_after": 0.88,
        "patches_applied": ["patch-1"], "regression_tests_added": ["reg-1"],
        "verifier_report": {"violations": []}, "step_count": 4,
    })
    assert result["phase"] == "report"
    assert result["final_report"]["asr_after"] == 0.1
    assert result["final_report"]["patches_applied"] == 1
    assert CampaignStore().get_campaign("campaign-report")["status"] == "completed"
