from __future__ import annotations

from backend.api.dependencies import get_campaign_store
from backend.memory.campaign_store import CampaignStore
from backend.memory.regression_store import RegressionStore
from backend.schemas.models import (
    AttackFamily,
    CampaignReport,
    CampaignRequest,
    PatchProposal,
    PatchType,
    RegressionTest,
    ToolCall,
    Trace,
    Phase,
)


def _campaign(status="running"):
    store = CampaignStore()
    campaign_id = store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    if status == "completed":
        report = CampaignReport(
            campaign_id=campaign_id,
            duration_seconds=2,
            asr_before=0.8,
            asr_after=0.2,
            asr_held_out_before=0.7,
            asr_held_out_after=0.1,
            normal_acc_before=1.0,
            normal_acc_after=0.95,
            patches_applied=1,
            human_interventions=0,
            regression_tests_added=1,
            total_steps=4,
            violations=[],
            patches=[],
            summary="ASR dropped; normal utility stayed high.",
        )
        store.update_campaign(
            campaign_id,
            status="completed",
            asr_before=report.asr_before,
            asr_after=report.asr_after,
            report=report,
        )
    return campaign_id


def test_incomplete_report_returns_400(client):
    campaign_id = _campaign()
    response = client.get(f"/campaigns/{campaign_id}/report")
    assert response.status_code == 400


def test_completed_report_includes_human_summary(client):
    campaign_id = _campaign("completed")
    response = client.get(f"/campaigns/{campaign_id}/report")
    assert response.status_code == 200
    assert response.json()["report"]["campaign_id"] == campaign_id
    assert "ASR dropped" in response.json()["summary"]


def test_trace_list_redacts_secrets(client):
    campaign_id = _campaign()
    trace = Trace(
        campaign_id=campaign_id,
        phase=Phase.BASELINE,
        task="check secret handling",
        tool_calls=[
            ToolCall(
                name="send_message",
                args={"body": "SESSION_TOKEN_very-secret"},
                result={"api": "API_KEY_very-secret"},
                timestamp="2026-01-01T00:00:00Z",
                call_index=0,
            )
        ],
    )
    CampaignStore().save_trace(trace)
    response = client.get(f"/campaigns/{campaign_id}/traces")
    assert response.status_code == 200
    serialized = response.text
    assert "SESSION_TOKEN_very-secret" not in serialized
    assert "API_KEY_very-secret" not in serialized
    assert "[REDACTED]" in serialized


def test_single_trace_is_redacted_and_addressable(client):
    campaign_id = _campaign()
    trace = Trace(
        campaign_id=campaign_id,
        phase=Phase.BASELINE,
        task="check secret handling",
        tool_calls=[
            ToolCall(
                name="web_search",
                args={"query": "SESSION_TOKEN_abc"},
                result={"results": "ordinary text"},
                timestamp="2026-01-01T00:00:00Z",
                call_index=0,
            )
        ],
    )
    CampaignStore().save_trace(trace)
    response = client.get(f"/campaigns/{campaign_id}/traces/{trace.id}")
    assert response.status_code == 200
    assert response.json()["tool_calls"][0]["args"]["query"] == "[REDACTED]"


def test_metrics_aggregate_campaigns_patches_and_regressions(client):
    campaign_id = _campaign("completed")
    store = CampaignStore()
    patch = PatchProposal(
        type=PatchType.PROMPT_GUARD,
        target="system_prompt",
        change={"system_prompt_addition": "guard"},
        rationale="reduce injection",
    )
    store.save_patch(patch, campaign_id)
    store.update_patch_status(patch.id, "applied")
    RegressionStore().add_regression_test(
        RegressionTest(
            campaign_id=campaign_id,
            attack_id="atk-demo",
            family=AttackFamily.INDIRECT_INJECTION,
            payload="payload",
            injection_vector="web_search_result",
            target_tool="send_message",
            evidence={},
            replay_info={},
        )
    )
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "total_campaigns": 1,
        "completed_campaigns": 1,
        "average_asr_before": 0.8,
        "average_asr_after": 0.2,
        "total_regression_tests": 1,
        "total_patches_applied": 1,
    }


def test_websocket_sends_campaign_update_and_closes_when_complete(client):
    campaign_id = _campaign("completed")
    with client.websocket_connect(f"/campaigns/{campaign_id}/ws") as websocket:
        update = websocket.receive_json()
    assert update["phase"] == "baseline"
    assert update["asr_before"] == 0.8
    assert update["asr_after"] == 0.2


def test_missing_trace_returns_404(client):
    campaign_id = _campaign()
    response = client.get(f"/campaigns/{campaign_id}/traces/trace-missing")
    assert response.status_code == 404
