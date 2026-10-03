"""Tests for budget tracking, secret redaction, and trace logging."""

from __future__ import annotations

import json
import logging

from backend.core.budget import BudgetTracker
from backend.core.config import get_settings
from backend.core.redactor import redact_dict, redact_trace
from backend.core.trace_writer import write_log_event, write_trace
from backend.schemas.models import Phase, ToolCall, Trace


class _FakeStore:
    def __init__(self) -> None:
        self.saved: list[Trace] = []

    def save_trace(self, trace: Trace) -> None:
        self.saved.append(trace)


def test_redactor_removes_session_token_from_tool_args() -> None:
    original = Trace(
        campaign_id="campaign-1",
        phase=Phase.ATTACK,
        task="search",
        tool_calls=[
            ToolCall(
                name="lookup",
                args={"token": "SESSION_TOKEN_XYZ", "q": "news"},
                result={"raw": "API_KEY=secret"},
                timestamp="2026-01-01T00:00:00Z",
                call_index=0,
            )
        ],
        final_response="leak SESSION_TOKEN_XYZ in text",
    )
    patterns = get_settings().secret_patterns
    redacted = redact_trace(original, patterns)

    dumped = json.dumps(redacted.model_dump(mode="json"))
    assert "SESSION_TOKEN_XYZ" not in dumped
    assert original.tool_calls[0].args["token"] == "SESSION_TOKEN_XYZ"
    assert redacted.tool_calls[0].args["token"] == "[REDACTED]"
    assert redacted.tool_calls[0].result is not None
    assert redacted.tool_calls[0].result["raw"] == "[REDACTED]"
    assert "[REDACTED]" in (redacted.final_response or "")
    assert redact_dict({"nested": {"k": "has API_KEY here"}}, patterns)["nested"]["k"] == "[REDACTED]"


def test_budget_charges_then_exhausts() -> None:
    tracker = BudgetTracker(max_steps=3, max_tokens=1000)
    assert tracker.charge_step() is True
    assert tracker.charge_step() is True
    assert tracker.charge_step() is True
    assert tracker.charge_step() is False
    assert tracker.is_exhausted() is True
    assert tracker.remaining_steps() == 0
    assert tracker.charge_tokens(1000) is True
    assert tracker.charge_tokens(1) is False
    summary = tracker.summary()
    assert summary["steps_used"] == 3
    assert summary["exhausted"] is True


def test_write_log_event_emits_json(caplog) -> None:
    caplog.set_level(logging.INFO, logger="veritas.trace")
    write_log_event("test_event", "campaign-1", "orchestrator", {"ok": True})
    assert "test_event" in caplog.text
    payload = json.loads(caplog.records[-1].getMessage())
    assert payload["campaign_id"] == "campaign-1"
    assert payload["agent"] == "orchestrator"

    caplog.set_level(logging.DEBUG, logger="veritas.trace")
    store = _FakeStore()
    trace = Trace(campaign_id="campaign-1", phase=Phase.BASELINE, task="normal")
    write_trace(trace, store)  # type: ignore[arg-type]
    assert store.saved[0].id == trace.id
