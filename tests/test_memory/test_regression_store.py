"""Tests for RegressionStore held-out attack sealing, sampling, and regression test CRUD."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from backend.core.config import get_settings
from backend.memory.campaign_store import CampaignStore
from backend.memory.db import get_db, reset_db
from backend.memory.regression_store import RegressionStore
from backend.schemas.models import (
    Attack,
    AttackFamily,
    AttackPool,
    CampaignRequest,
    RegressionTest,
)


@pytest.fixture
def stores(tmp_path, monkeypatch: pytest.MonkeyPatch) -> tuple[CampaignStore, RegressionStore]:
    """Provide isolated CampaignStore and RegressionStore instances with a temp DB."""
    db_path = tmp_path / "data" / "veritas.db"
    monkeypatch.setenv("DATABASE_URL", str(db_path))
    get_settings.cache_clear()
    reset_db()
    return CampaignStore(), RegressionStore()


def _make_attack(campaign_id: str, payload: str = "test payload") -> Attack:
    return Attack(
        campaign_id=campaign_id,
        family=AttackFamily.INDIRECT_INJECTION,
        payload=payload,
        injection_vector="document_upload",
        target_tool="doc_reader",
        task="read doc",
    )


def test_seal_held_out_succeeds_once(stores: tuple[CampaignStore, RegressionStore]) -> None:
    """Verify seal_held_out successfully inserts held-out attacks for a campaign."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    attacks = [_make_attack(cid, "held_out_1"), _make_attack(cid, "held_out_2")]
    reg_store.seal_held_out(cid, attacks)

    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) AS n FROM held_out_attacks WHERE campaign_id = ?", (cid,)
    ).fetchone()["n"]
    assert count == 2


def test_seal_held_out_raises_valueerror_on_second_call(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify seal_held_out raises ValueError if called more than once for a campaign."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    attacks = [_make_attack(cid, "held_out_1")]
    reg_store.seal_held_out(cid, attacks)

    with pytest.raises(ValueError) as exc_info:
        reg_store.seal_held_out(cid, attacks)
    assert "already sealed" in str(exc_info.value)


def test_sample_held_out_raises_permission_error_before_patch(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify sample_held_out raises PermissionError before a patch is marked applied."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    attacks = [_make_attack(cid, "held_out_1")]
    reg_store.seal_held_out(cid, attacks)

    with pytest.raises(PermissionError) as exc_info:
        reg_store.sample_held_out(cid, n=1)
    assert "cannot be sampled before a patch is applied" in str(exc_info.value)


def test_sample_held_out_returns_correct_n_after_patch(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify sample_held_out returns requested number of attacks after patch is applied."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    attacks = [
        _make_attack(cid, "atk-1"),
        _make_attack(cid, "atk-2"),
        _make_attack(cid, "atk-3"),
    ]
    reg_store.seal_held_out(cid, attacks)

    reg_store.mark_patch_applied(cid)
    sampled = reg_store.sample_held_out(cid, n=2)

    assert len(sampled) == 2
    for atk in sampled:
        assert atk.campaign_id == cid
        assert atk.pool == AttackPool.HELD_OUT


def test_add_regression_test_and_list_roundtrip(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify add_regression_test persists test and list_regression_tests loads it."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    reg_test = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-{uuid4()}",
        family=AttackFamily.GOAL_HIJACK,
        payload="hijack goal payload",
        injection_vector="user_input",
        target_tool="admin_cli",
        evidence={"gate": "argument_policy", "passed": False},
        replay_info={"task": "admin reset", "tool_calls": []},
        sut_version="v1.0",
        patch_version="v1.1",
        status="active",
    )
    reg_store.add_regression_test(reg_test)

    tests = reg_store.list_regression_tests(status="active")
    assert len(tests) == 1
    loaded = tests[0]
    assert loaded.id == reg_test.id
    assert loaded.campaign_id == cid
    assert loaded.family == AttackFamily.GOAL_HIJACK
    assert loaded.evidence["gate"] == "argument_policy"
    assert loaded.replay_info["task"] == "admin reset"
    assert loaded.status == "active"


def test_mark_resolved_changes_status(stores: tuple[CampaignStore, RegressionStore]) -> None:
    """Verify mark_resolved updates test status from active to resolved."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    reg_test = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-{uuid4()}",
        family=AttackFamily.DIRECT_INJECTION,
        payload="test",
        injection_vector="input",
        target_tool="tool",
        evidence={},
        replay_info={},
        status="active",
    )
    reg_store.add_regression_test(reg_test)

    reg_store.mark_resolved(reg_test.id)

    conn = get_db()
    row = conn.execute("SELECT status FROM regression_tests WHERE id = ?", (reg_test.id,)).fetchone()
    assert row["status"] == "resolved"


def test_list_regression_tests_filters_active(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify list_regression_tests(status='active') filters out resolved tests."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    test_active = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-act-{uuid4()}",
        family=AttackFamily.DIRECT_INJECTION,
        payload="act",
        injection_vector="v",
        target_tool="t",
        evidence={},
        replay_info={},
        status="active",
    )
    test_resolved = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-res-{uuid4()}",
        family=AttackFamily.DIRECT_INJECTION,
        payload="res",
        injection_vector="v",
        target_tool="t",
        evidence={},
        replay_info={},
        status="resolved",
    )
    reg_store.add_regression_test(test_active)
    reg_store.add_regression_test(test_resolved)

    active_tests = reg_store.list_regression_tests(status="active")
    assert len(active_tests) == 1
    assert active_tests[0].id == test_active.id


def test_list_regression_tests_filters_resolved(
    stores: tuple[CampaignStore, RegressionStore],
) -> None:
    """Verify list_regression_tests(status='resolved') filters out active tests."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    test_active = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-act-{uuid4()}",
        family=AttackFamily.DIRECT_INJECTION,
        payload="act",
        injection_vector="v",
        target_tool="t",
        evidence={},
        replay_info={},
        status="active",
    )
    test_resolved = RegressionTest(
        campaign_id=cid,
        attack_id=f"atk-res-{uuid4()}",
        family=AttackFamily.DIRECT_INJECTION,
        payload="res",
        injection_vector="v",
        target_tool="t",
        evidence={},
        replay_info={},
        status="resolved",
    )
    reg_store.add_regression_test(test_active)
    reg_store.add_regression_test(test_resolved)

    resolved_tests = reg_store.list_regression_tests(status="resolved")
    assert len(resolved_tests) == 1
    assert resolved_tests[0].id == test_resolved.id


def test_record_held_out_result(stores: tuple[CampaignStore, RegressionStore]) -> None:
    """Verify record_held_out_result updates result JSON and executed_at timestamp in DB."""
    campaign_store, reg_store = stores
    cid = campaign_store.create_campaign(
        CampaignRequest(sut_descriptor={}, threat_model={}, budget={})
    )
    atk = _make_attack(cid, "held_out_for_result")
    reg_store.seal_held_out(cid, [atk])
    reg_store.mark_patch_applied(cid)

    result_data = {"blocked": True, "gate": "prompt_guard"}
    reg_store.record_held_out_result(cid, atk.id, result_data)

    conn = get_db()
    row = conn.execute(
        "SELECT result, executed_at FROM held_out_attacks WHERE id = ?", (atk.id,)
    ).fetchone()
    assert row["executed_at"] is not None
    assert json.loads(row["result"]) == result_data
