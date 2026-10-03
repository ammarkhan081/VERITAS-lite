"""Unit tests for core utilities: BudgetTracker, secret redaction, and logging."""

from __future__ import annotations

import copy
import json
import logging

import pytest

from backend.core.budget import BudgetTracker
from backend.core.config import get_settings
from backend.core.redactor import redact_dict, redact_string, redact_trace
from backend.core.trace_writer import write_log_event, write_trace
from backend.schemas.models import Phase, ToolCall, Trace


def test_redact_trace_replaces_secret_patterns() -> None:
    """Verify redact_trace replaces occurrences of secret patterns."""
    patterns = ["SESSION_TOKEN", "API_KEY"]
    trace = Trace(
        campaign_id="campaign-1",
        phase=Phase.ATTACK,
        task="search with SESSION_TOKEN_SECRET",
        tool_calls=[
            ToolCall(
                name="curl",
                args={"auth": "Bearer API_KEY_SECRET", "query": "hello"},
                result={"body": "user with SESSION_TOKEN_ABC"},
                timestamp="2026-01-01T00:00:00Z",
                call_index=0,
            )
        ],
        final_response="Output leaked API_KEY_XYZ",
    )

    redacted = redact_trace(trace, patterns)

    tool_args = redacted.tool_calls[0].args
    assert tool_args["auth"] == "[REDACTED]"
    assert tool_args["query"] == "hello"

    tool_res = redacted.tool_calls[0].result
    assert tool_res is not None
    assert tool_res["body"] == "[REDACTED]"

    assert "[REDACTED]" in (redacted.final_response or "")
    assert "API_KEY" not in (redacted.final_response or "")


def test_redact_trace_does_not_mutate_original_trace() -> None:
    """Verify redact_trace produces a new copy and does NOT mutate original trace."""
    patterns = ["SECRET_TOKEN"]
    original_args = {"token": "SECRET_TOKEN_12345", "param": "safe"}
    original_result = {"info": "contains SECRET_TOKEN_5678"}

    original = Trace(
        campaign_id="campaign-1",
        phase=Phase.ATTACK,
        task="run task",
        tool_calls=[
            ToolCall(
                name="exec",
                args=copy.deepcopy(original_args),
                result=copy.deepcopy(original_result),
                timestamp="2026-01-01T00:00:00Z",
                call_index=0,
            )
        ],
        final_response="Found SECRET_TOKEN",
    )

    redacted = redact_trace(original, patterns)

    # Verify original remains unchanged
    assert original.tool_calls[0].args["token"] == "SECRET_TOKEN_12345"
    assert original.tool_calls[0].result["info"] == "contains SECRET_TOKEN_5678"
    assert original.final_response == "Found SECRET_TOKEN"

    # Verify redacted has masked values
    assert redacted.tool_calls[0].args["token"] == "[REDACTED]"
    assert redacted.tool_calls[0].result["info"] == "[REDACTED]"
    assert redacted.final_response == "Found [REDACTED]"


def test_redact_dict_handles_nested_dicts() -> None:
    """Verify redact_dict recursively traverses and redacts nested dicts and lists."""
    patterns = ["PASSWORD", "API_KEY"]
    data = {
        "user": "alice",
        "creds": {
            "token": "API_KEY_9999",
            "details": {
                "hash": "PASSWORD_HASH_123",
                "safe_num": 42,
                "safe_bool": True,
            },
        },
        "tags": ["normal", "has API_KEY inside item"],
    }

    result = redact_dict(data, patterns)

    assert result["user"] == "alice"
    assert result["creds"]["token"] == "[REDACTED]"
    assert result["creds"]["details"]["hash"] == "[REDACTED]"
    assert result["creds"]["details"]["safe_num"] == 42
    assert result["creds"]["details"]["safe_bool"] is True
    assert result["tags"] == ["normal", "[REDACTED]"]


def test_budget_tracker_stops_at_max_steps() -> None:
    """Verify BudgetTracker charges steps up to max_steps and rejects further charges."""
    tracker = BudgetTracker(max_steps=2, max_tokens=1000)

    assert tracker.charge_step() is True
    assert tracker.remaining_steps() == 1
    assert tracker.is_exhausted() is False

    assert tracker.charge_step() is True
    assert tracker.remaining_steps() == 0
    assert tracker.is_exhausted() is True

    # Attempting to charge past max_steps returns False
    assert tracker.charge_step() is False
    assert tracker.remaining_steps() == 0
    assert tracker.is_exhausted() is True


def test_budget_tracker_is_exhausted_is_false_when_remaining() -> None:
    """Verify BudgetTracker.is_exhausted() is False as long as steps and tokens remain."""
    tracker = BudgetTracker(max_steps=10, max_tokens=500)

    assert tracker.is_exhausted() is False
    tracker.charge_step()
    tracker.charge_tokens(200)

    assert tracker.remaining_steps() == 9
    assert tracker.remaining_tokens() == 300
    assert tracker.is_exhausted() is False


def test_budget_tracker_summary_returns_correct_dict() -> None:
    """Verify BudgetTracker.summary() provides a correct snapshot."""
    tracker = BudgetTracker(max_steps=5, max_tokens=2000)
    tracker.charge_step()
    tracker.charge_step()
    tracker.charge_tokens(750)

    summary = tracker.summary()
    assert summary == {
        "steps_used": 2,
        "tokens_used": 750,
        "steps_remaining": 3,
        "tokens_remaining": 1250,
        "exhausted": False,
    }

    tracker.charge_tokens(1250)
    assert tracker.summary()["exhausted"] is True


def test_redact_string_helper() -> None:
    """Verify redact_string masks exact and substring secret occurrences."""
    patterns = ["SECRET"]
    assert redact_string("safe text", patterns) == "safe text"
    assert redact_string("my SECRET is out", patterns) == "my [REDACTED] is out"
    assert redact_string("SECRET", patterns) == "[REDACTED]"
