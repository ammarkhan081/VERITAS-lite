"""Regression tests and sealed held-out attack sampling."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from backend.memory.db import get_db, init_db, uses_postgres
from backend.schemas.models import (
    Attack,
    AttackFamily,
    AttackPool,
    RegressionTest,
    utcnow_iso,
)

logger = logging.getLogger(__name__)


class RegressionStore:
    """SQLite-backed store for regression tests and sealed held-out attacks."""

    def __init__(self) -> None:
        """Initialize tables, a write lock, and in-memory campaign flags."""
        init_db()
        self._lock = threading.Lock()
        self._sealed_campaigns: set[str] = set()
        self._patch_applied_campaigns: set[str] = set()

    def add_regression_test(self, test: RegressionTest) -> None:
        """Insert a regression test derived from a successful attack."""
        family = test.family.value if hasattr(test.family, "value") else str(test.family)
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO regression_tests (
                    id, campaign_id, attack_id, family, payload, injection_vector,
                    target_tool, evidence, replay_info, sut_version, patch_version,
                    created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    test.id,
                    test.campaign_id,
                    test.attack_id,
                    family,
                    test.payload,
                    test.injection_vector,
                    test.target_tool,
                    json.dumps(test.evidence),
                    json.dumps(test.replay_info),
                    test.sut_version,
                    test.patch_version,
                    test.created_at,
                    test.status,
                ),
            )
            conn.commit()

    def list_regression_tests(self, status: str = "active") -> list[RegressionTest]:
        """Return regression tests matching ``status``, deserializing JSON fields."""
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM regression_tests WHERE status = ?",
            (status,),
        ).fetchall()
        return [
            RegressionTest(
                id=row["id"],
                campaign_id=row["campaign_id"],
                attack_id=row["attack_id"],
                family=AttackFamily(row["family"]),
                payload=row["payload"],
                injection_vector=row["injection_vector"],
                target_tool=row["target_tool"],
                evidence=json.loads(row["evidence"]),
                replay_info=json.loads(row["replay_info"]),
                sut_version=row["sut_version"],
                patch_version=row["patch_version"],
                created_at=row["created_at"],
                status=row["status"],
            )
            for row in rows
        ]

    def seal_held_out(self, campaign_id: str, attacks: list[Attack]) -> None:
        """Seal held-out attacks once at campaign start before any execution."""
        with self._lock:
            conn = get_db()
            existing = conn.execute(
                "SELECT COUNT(*) AS n FROM held_out_attacks WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()["n"]
            if campaign_id in self._sealed_campaigns or existing > 0:
                raise ValueError(f"Held-out set already sealed for campaign {campaign_id}")

            sealed_at = utcnow_iso()
            for attack in attacks:
                conn.execute(
                    """
                    INSERT INTO held_out_attacks (
                        id, campaign_id, family, payload, injection_vector,
                        target_tool, task, sealed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attack.id,
                        campaign_id,
                        attack.family.value,
                        attack.payload,
                        attack.injection_vector,
                        attack.target_tool,
                        attack.task,
                        sealed_at,
                    ),
                )
            self._sealed_campaigns.add(campaign_id)
            conn.commit()

        logger.info(
            "held_out_sealed",
            extra={
                "event_type": "held_out_sealed",
                "campaign_id": campaign_id,
                "count": len(attacks),
                "sealed_at": sealed_at,
            },
        )

    def mark_patch_applied(self, campaign_id: str) -> None:
        """Allow held-out sampling after a patch has been applied to this campaign."""
        with self._lock:
            self._patch_applied_campaigns.add(campaign_id)
        logger.info(
            "patch_applied_for_held_out",
            extra={"campaign_id": campaign_id},
        )

    def sample_held_out(self, campaign_id: str, n: int) -> list[Attack]:
        """Return up to ``n`` sealed held-out attacks after a patch is applied."""
        if campaign_id not in self._patch_applied_campaigns:
            raise PermissionError(
                "Held-out attacks cannot be sampled before a patch is applied"
            )
        conn = get_db()
        rows = conn.execute(
            f"""
            SELECT * FROM held_out_attacks
            WHERE campaign_id = ?
            ORDER BY {"random()" if uses_postgres() else "RANDOM()"}
            LIMIT ?
            """,
            (campaign_id, n),
        ).fetchall()
        return [self._attack_from_held_out_row(row) for row in rows]

    def record_held_out_result(
        self, campaign_id: str, attack_id: str, result: dict
    ) -> None:
        """Record the post-patch execution result for a held-out attack."""
        with self._lock:
            conn = get_db()
            conn.execute(
                """
                UPDATE held_out_attacks
                SET result = ?, executed_at = ?
                WHERE campaign_id = ? AND id = ?
                """,
                (json.dumps(result), utcnow_iso(), campaign_id, attack_id),
            )
            conn.commit()

    def mark_resolved(self, regression_id: str) -> None:
        """Mark a regression test as resolved."""
        with self._lock:
            conn = get_db()
            conn.execute(
                "UPDATE regression_tests SET status = ? WHERE id = ?",
                ("resolved", regression_id),
            )
            conn.commit()

    def _attack_from_held_out_row(self, row: Any) -> Attack:
        """Reconstruct an Attack from a ``held_out_attacks`` row."""
        return Attack(
            id=row["id"],
            campaign_id=row["campaign_id"],
            family=AttackFamily(row["family"]),
            payload=row["payload"],
            injection_vector=row["injection_vector"],
            target_tool=row["target_tool"],
            pool=AttackPool.HELD_OUT,
            task=row["task"] or "",
            created_at=row["sealed_at"],
            executed_at=row["executed_at"],
        )
