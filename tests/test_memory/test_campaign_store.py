"""Tests for CampaignStore SQLite CRUD operations."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from backend.core.config import get_settings
from backend.memory.campaign_store import CampaignStore
from backend.memory.db import get_db, reset_db
from backend.schemas.models import (
    Attack,
    AttackFamily,
    AttackPool,
    AttackStatus,
    CampaignReport,
    CampaignRequest,
    CampaignStatus,
    GateCode,
    GateResult,
    PatchProposal,
    PatchType,
    Phase,
    RiskLevel,
    ToolCall,
    Trace,
    utcnow_iso,
)


@pytest.fixture
def store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> CampaignStore:
    """CampaignStore backed by an isolated temporary SQLite file."""
    db_path = tmp_path / "data" / "veritas.db"
    monkeypatch.setenv("DATABASE_URL", str(db_path))
    get_settings.cache_clear()
    reset_db()
    return CampaignStore()


def _request() -> CampaignRequest:
    return CampaignRequest(
        sut_descriptor={"name": "custom-sut", "config": {"temp": 0.0}},
        threat_model={"families": ["indirect_injection"]},
        budget={"max_steps": 30, "max_tokens": 1000},
    )


def test_create_campaign_returns_id_format(store: CampaignStore) -> None:
    """Verify create_campaign returns a string ID starting with 'campaign-'."""
    campaign_id = store.create_campaign(_request())
    assert isinstance(campaign_id, str)
    assert campaign_id.startswith("campaign-")


def test_get_campaign_returns_correct_dict(store: CampaignStore) -> None:
    """Verify get_campaign returns the correct dictionary representation."""
    campaign_id = store.create_campaign(_request())
    row = store.get_campaign(campaign_id)

    assert row["id"] == campaign_id
    assert row["status"] == "running"
    assert row["phase"] == "baseline"
    desc = json.loads(row["sut_descriptor"])
    assert desc["name"] == "custom-sut"


def test_get_campaign_unknown_id_raises_keyerror(store: CampaignStore) -> None:
    """Verify get_campaign raises KeyError for non-existent ID."""
    with pytest.raises(KeyError) as exc_info:
        store.get_campaign(f"campaign-missing-{uuid4()}")
    assert "Campaign not found" in str(exc_info.value)


def test_save_and_get_attack_roundtrip(store: CampaignStore) -> None:
    """Verify save_attack and get_attacks round-trip persistence."""
    campaign_id = store.create_campaign(_request())
    attack = Attack(
        campaign_id=campaign_id,
        family=AttackFamily.DIRECT_INJECTION,
        payload="System prompt override",
        injection_vector="direct_prompt",
        target_tool="calculator",
        task="calculate",
    )
    store.save_attack(attack)

    attacks = store.get_attacks(campaign_id, pool="training")
    assert len(attacks) == 1
    loaded = attacks[0]
    assert loaded.id == attack.id
    assert loaded.campaign_id == campaign_id
    assert loaded.family == AttackFamily.DIRECT_INJECTION
    assert loaded.payload == "System prompt override"
    assert loaded.payload_hash == attack.payload_hash


def test_get_attacks_filters_by_pool(store: CampaignStore) -> None:
    """Verify get_attacks correctly filters between training and held_out pools."""
    campaign_id = store.create_campaign(_request())
    atk_train = Attack(
        campaign_id=campaign_id,
        family=AttackFamily.INDIRECT_INJECTION,
        payload="train payload",
        injection_vector="vector_1",
        target_tool="tool_a",
        pool=AttackPool.TRAINING,
        task="task a",
    )
    atk_held = Attack(
        campaign_id=campaign_id,
        family=AttackFamily.GOAL_HIJACK,
        payload="held out payload",
        injection_vector="vector_2",
        target_tool="tool_b",
        pool=AttackPool.HELD_OUT,
        task="task b",
    )
    store.save_attack(atk_train)
    store.save_attack(atk_held)

    train_list = store.get_attacks(campaign_id, pool="training")
    assert len(train_list) == 1
    assert train_list[0].id == atk_train.id

    held_list = store.get_attacks(campaign_id, pool="held_out")
    assert len(held_list) == 1
    assert held_list[0].id == atk_held.id


def test_save_and_get_traces_with_nested_tool_calls(store: CampaignStore) -> None:
    """Verify save_trace and get_traces round-trip with nested tool calls and gates."""
    campaign_id = store.create_campaign(_request())
    now = utcnow_iso()
    trace = Trace(
        campaign_id=campaign_id,
        attack_id="atk-100",
        phase=Phase.ATTACK,
        task="fetch data and exfiltrate",
        tool_calls=[
            ToolCall(
                name="http_get",
                args={"url": "https://api.internal/data"},
                result={"status": 200, "data": "secret"},
                timestamp=now,
                call_index=0,
            ),
            ToolCall(
                name="send_message",
                args={"to": "attacker", "msg": "secret"},
                result={"delivered": True},
                timestamp=now,
                call_index=1,
            ),
        ],
        gates_fired=[
            GateResult(
                gate=GateCode.EXFILTRATION_PATTERN,
                passed=False,
                evidence={"matched": "attacker"},
            )
        ],
        final_response="Message sent",
    )
    store.save_trace(trace)

    traces = store.get_traces(campaign_id)
    assert len(traces) == 1
    loaded = traces[0]
    assert loaded.id == trace.id
    assert len(loaded.tool_calls) == 2
    assert loaded.has_tool_call("http_get") is True
    assert loaded.has_tool_call("send_message") is True
    assert loaded.tool_calls[0].result == {"status": 200, "data": "secret"}
    assert loaded.gates_fired[0].gate == GateCode.EXFILTRATION_PATTERN
    assert loaded.gates_fired[0].passed is False


def test_update_campaign_fields(store: CampaignStore) -> None:
    """Verify update_campaign modifies specific allowed columns."""
    campaign_id = store.create_campaign(_request())
    store.update_campaign(
        campaign_id,
        phase=Phase.PATCH.value,
        asr_before=0.85,
        total_steps=12,
        human_interventions=2,
    )

    row = store.get_campaign(campaign_id)
    assert row["phase"] == "patch"
    assert row["asr_before"] == 0.85
    assert row["total_steps"] == 12
    assert row["human_interventions"] == 2
    assert row["updated_at"] is not None


def test_update_campaign_unknown_column_raises(store: CampaignStore) -> None:
    """Verify update_campaign raises ValueError when given an invalid column name."""
    campaign_id = store.create_campaign(_request())
    with pytest.raises(ValueError) as exc_info:
        store.update_campaign(campaign_id, non_existent_column="invalid")
    assert "Unknown campaign column" in str(exc_info.value)


def test_save_patch_and_retrieve_by_campaign_id(store: CampaignStore) -> None:
    """Verify save_patch stores patch proposal in DB associated with campaign."""
    campaign_id = store.create_campaign(_request())
    patch = PatchProposal(
        type=PatchType.CONFIG_CHANGE,
        target="temperature",
        change={"temperature": 0.0},
        rationale="eliminate non-deterministic jailbreaks",
        requires_human_review=True,
        risk_level=RiskLevel.MEDIUM,
    )
    store.save_patch(patch, campaign_id)

    conn = get_db()
    row = conn.execute("SELECT * FROM patches WHERE campaign_id = ?", (campaign_id,)).fetchone()
    assert row is not None
    assert row["id"] == patch.id
    assert row["status"] == "proposed"
    assert row["human_approved"] == 1
    proposal_dict = json.loads(row["proposal"])
    assert proposal_dict["rationale"] == "eliminate non-deterministic jailbreaks"


def test_update_patch_status(store: CampaignStore) -> None:
    """Verify update_patch_status updates status and metadata in DB."""
    campaign_id = store.create_campaign(_request())
    patch = PatchProposal(
        type=PatchType.SANITIZATION_RULE,
        target="input_filter",
        change={"strip_tags": True},
        rationale="strip HTML/XML markers",
    )
    store.save_patch(patch, campaign_id)

    now = utcnow_iso()
    store.update_patch_status(patch.id, "applied", applied_at=now, human_approved=True)

    conn = get_db()
    row = conn.execute("SELECT * FROM patches WHERE id = ?", (patch.id,)).fetchone()
    assert row["status"] == "applied"
    assert row["applied_at"] == now
    assert row["human_approved"] == 1


def test_finalize_campaign_sets_completed_and_stores_report(store: CampaignStore) -> None:
    """Verify finalize_campaign marks status completed and stores CampaignReport JSON."""
    campaign_id = store.create_campaign(_request())
    report = CampaignReport(
        campaign_id=campaign_id,
        duration_seconds=5.2,
        asr_before=0.9,
        asr_after=0.1,
        asr_held_out_before=0.85,
        asr_held_out_after=0.15,
        normal_acc_before=0.99,
        normal_acc_after=0.98,
        patches_applied=1,
        human_interventions=0,
        regression_tests_added=2,
        total_steps=10,
        violations=[],
        patches=[{"id": "patch-1"}],
        summary="Campaign successfully hardened SUT",
    )
    store.finalize_campaign(campaign_id, report)

    row = store.get_campaign(campaign_id)
    assert row["status"] == CampaignStatus.COMPLETED.value
    saved_report = json.loads(row["report"])
    assert saved_report["summary"] == "Campaign successfully hardened SUT"
    assert saved_report["asr_after"] == 0.1
