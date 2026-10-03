"""CRUD persistence for campaigns, attacks, traces, and patches."""

from __future__ import annotations

import json
import threading
from typing import Any
from uuid import uuid4

from backend.memory.db import get_db, init_db
from backend.schemas.models import (
    Attack,
    AttackFamily,
    AttackPool,
    AttackStatus,
    CampaignReport,
    CampaignRequest,
    CampaignStatus,
    GateResult,
    PatchProposal,
    Phase,
    ToolCall,
    Trace,
    utcnow_iso,
)

_CAMPAIGN_COLUMNS = {
    "status",
    "sut_descriptor",
    "threat_model",
    "config_snapshot",
    "phase",
    "asr_before",
    "asr_after",
    "asr_held_out_before",
    "asr_held_out_after",
    "normal_acc_before",
    "normal_acc_after",
    "total_steps",
    "total_tokens",
    "human_interventions",
    "report",
    "updated_at",
}

_PATCH_COLUMNS = {
    "status",
    "human_approved",
    "normal_acc_before",
    "normal_acc_after",
    "applied_at",
    "rejection_reason",
    "proposal",
}


def _json_dump(value: Any) -> str:
    """Serialize a value to JSON, converting Pydantic models when needed."""
    if hasattr(value, "model_dump"):
        return json.dumps(value.model_dump(mode="json"))
    return json.dumps(value)


class CampaignStore:
    """SQLite-backed store for campaign lifecycle records."""

    def __init__(self) -> None:
        """Initialize tables and a write lock."""
        init_db()
        self._lock = threading.Lock()

    def create_campaign(self, req: CampaignRequest, campaign_id: str | None = None) -> str:
        """Insert a new campaign row and return its ID.

        Args:
            req: Campaign request describing the SUT, threat model, and budget.
            campaign_id: Optional pre-assigned ID; a new ``campaign-<uuid>`` is generated if omitted.
        """
        campaign_id = campaign_id or f"campaign-{uuid4()}"
        created_at = utcnow_iso()
        config_snapshot = req.sut_descriptor.get("config", req.sut_descriptor)
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO campaigns (
                    id, created_at, status, sut_descriptor, threat_model,
                    config_snapshot, phase, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    created_at,
                    CampaignStatus.RUNNING.value,
                    json.dumps(req.sut_descriptor),
                    json.dumps(req.threat_model),
                    json.dumps(config_snapshot),
                    Phase.BASELINE.value,
                    created_at,
                ),
            )
            conn.commit()
        return campaign_id

    def get_campaign(self, campaign_id: str) -> dict:
        """Return a campaign row as a dict, or raise KeyError if missing."""
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Campaign not found: {campaign_id}")
        return dict(row)

    def delete_campaign_record(self, campaign_id: str) -> None:
        """Permanently remove a non-running campaign and its related records."""
        with self._lock:
            conn = get_db()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT status FROM campaigns WHERE id = ?", (campaign_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(f"Campaign not found: {campaign_id}")
                if row["status"] == CampaignStatus.RUNNING.value:
                    raise ValueError("Running campaigns must be stopped before deletion")

                for table in (
                    "traces",
                    "regression_tests",
                    "held_out_attacks",
                    "patches",
                    "attacks",
                ):
                    conn.execute(
                        f"DELETE FROM {table} WHERE campaign_id = ?", (campaign_id,)
                    )
                conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def update_campaign(self, campaign_id: str, **kwargs: Any) -> None:
        """Update allowed campaign columns and bump ``updated_at``."""
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in kwargs.items():
            if key not in _CAMPAIGN_COLUMNS:
                raise ValueError(f"Unknown campaign column: {key}")
            if isinstance(value, (dict, list)) or hasattr(value, "model_dump"):
                values.append(_json_dump(value))
            elif hasattr(value, "value"):
                values.append(value.value)
            else:
                values.append(value)
            assignments.append(f"{key} = ?")
        assignments.append("updated_at = ?")
        values.append(utcnow_iso())
        values.append(campaign_id)
        with self._lock:
            conn = get_db()
            conn.execute(
                f"UPDATE campaigns SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            conn.commit()

    def save_attack(self, attack: Attack) -> None:
        """Insert an attack row."""
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO attacks (
                    id, campaign_id, family, payload, injection_vector,
                    target_tool, task, pool, status, created_at, executed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack.id,
                    attack.campaign_id,
                    attack.family.value,
                    attack.payload,
                    attack.injection_vector,
                    attack.target_tool,
                    attack.task,
                    attack.pool.value,
                    attack.status.value,
                    attack.created_at,
                    attack.executed_at,
                ),
            )
            conn.commit()

    def get_attacks(self, campaign_id: str, pool: str = "training") -> list[Attack]:
        """Return attacks for a campaign filtered by pool."""
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM attacks WHERE campaign_id = ? AND pool = ?",
            (campaign_id, pool),
        ).fetchall()
        return [
            Attack(
                id=row["id"],
                campaign_id=row["campaign_id"],
                family=AttackFamily(row["family"]),
                payload=row["payload"],
                injection_vector=row["injection_vector"],
                target_tool=row["target_tool"],
                pool=AttackPool(row["pool"]),
                status=AttackStatus(row["status"]),
                task=row["task"] or "",
                created_at=row["created_at"],
                executed_at=row["executed_at"],
            )
            for row in rows
        ]

    def update_attack_status(self, attack_id: str, status: AttackStatus | str) -> None:
        """Update an attack's lifecycle status; stamps ``executed_at`` once it has run."""
        status_value = status.value if isinstance(status, AttackStatus) else AttackStatus(status).value
        executed_at = utcnow_iso() if status_value != AttackStatus.PENDING.value else None
        with self._lock:
            conn = get_db()
            conn.execute(
                "UPDATE attacks SET status = ?, executed_at = COALESCE(?, executed_at) WHERE id = ?",
                (status_value, executed_at, attack_id),
            )
            conn.commit()

    def save_trace(self, trace: Trace) -> None:
        """Insert a trace row, serializing tool calls and gate results as JSON."""
        tool_calls = json.dumps([tc.model_dump(mode="json") for tc in trace.tool_calls])
        gates_fired = json.dumps(
            [gr.model_dump(mode="json") for gr in getattr(trace, "gates_fired", [])]
        )
        phase = trace.phase.value if hasattr(trace.phase, "value") else str(trace.phase)
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO traces (
                    id, campaign_id, attack_id, phase, task, tool_calls,
                    final_response, gates_fired, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace.id,
                    trace.campaign_id,
                    trace.attack_id,
                    phase,
                    trace.task,
                    tool_calls,
                    trace.final_response,
                    gates_fired,
                    trace.created_at,
                ),
            )
            conn.commit()

    def get_traces(self, campaign_id: str) -> list[Trace]:
        """Return traces for a campaign with JSON fields deserialized."""
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM traces WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchall()
        traces: list[Trace] = []
        for row in rows:
            tool_calls = [ToolCall(**item) for item in json.loads(row["tool_calls"])]
            gates_raw = json.loads(row["gates_fired"] or "[]")
            gates_fired = [GateResult(**item) for item in gates_raw]
            traces.append(
                Trace(
                    id=row["id"],
                    campaign_id=row["campaign_id"],
                    attack_id=row["attack_id"],
                    phase=Phase(row["phase"]),
                    task=row["task"],
                    tool_calls=tool_calls,
                    final_response=row["final_response"],
                    gates_fired=gates_fired,
                    created_at=row["created_at"],
                )
            )
        return traces

    def save_patch(self, patch: PatchProposal, campaign_id: str) -> None:
        """Insert a proposed patch for a campaign."""
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO patches (id, campaign_id, proposal, status, human_approved)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    patch.id,
                    campaign_id,
                    json.dumps(patch.model_dump(mode="json")),
                    "proposed",
                    int(patch.requires_human_review),
                ),
            )
            conn.commit()

    def update_patch_status(self, patch_id: str, status: str, **kwargs: Any) -> None:
        """Update a patch status and any additional allowed columns."""
        assignments = ["status = ?"]
        values: list[Any] = [status]
        for key, value in kwargs.items():
            if key not in _PATCH_COLUMNS:
                raise ValueError(f"Unknown patch column: {key}")
            if isinstance(value, (dict, list)) or hasattr(value, "model_dump"):
                values.append(_json_dump(value))
            elif isinstance(value, bool):
                values.append(int(value))
            else:
                values.append(value)
            assignments.append(f"{key} = ?")
        values.append(patch_id)
        with self._lock:
            conn = get_db()
            conn.execute(
                f"UPDATE patches SET {', '.join(assignments)} WHERE id = ?",
                tuple(values),
            )
            conn.commit()

    def finalize_campaign(self, campaign_id: str, report: CampaignReport) -> None:
        """Mark a campaign completed and persist the final report JSON."""
        self.update_campaign(
            campaign_id,
            status=CampaignStatus.COMPLETED.value,
            report=report,
        )
