"""Structured trace persistence and JSON event logging."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.memory.campaign_store import CampaignStore

from backend.schemas.models import Trace, utcnow_iso

logger = logging.getLogger("veritas.trace")


def write_trace(trace: Trace, store: CampaignStore) -> None:
    """Persist a trace and emit a DEBUG JSON log line."""
    store.save_trace(trace)
    logger.debug(
        json.dumps(
            {
                "event_type": "trace_written",
                "campaign_id": trace.campaign_id,
                "trace_id": trace.id,
                "attack_id": trace.attack_id,
                "phase": trace.phase.value if hasattr(trace.phase, "value") else str(trace.phase),
                "timestamp": utcnow_iso(),
            }
        )
    )


def write_log_event(event_type: str, campaign_id: str, agent: str, data: dict) -> None:
    """Write a structured JSON log event at INFO level."""
    record = {
        "event_type": event_type,
        "campaign_id": campaign_id,
        "agent": agent,
        "timestamp": utcnow_iso(),
        "data": data,
    }
    logger.info(json.dumps(record))
