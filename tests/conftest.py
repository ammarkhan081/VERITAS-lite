"""Shared pytest fixtures for the VERITAS-lite test suite."""

from __future__ import annotations

import pytest

from backend.schemas.models import Phase, ToolCall, Trace, utcnow_iso


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    """Give every test its own SQLite file and fresh cached singletons."""
    from backend.api.dependencies import get_campaign_store, get_graph, get_regression_store
    from backend.core.config import get_settings
    from backend.memory.db import reset_db
    import backend.orchestration.graph as graph_module

    def _reset() -> None:
        reset_db()
        get_settings.cache_clear()
        get_campaign_store.cache_clear()
        get_regression_store.cache_clear()
        get_graph.cache_clear()
        graph_module._default_campaign_store = None
        graph_module._default_regression_store = None

    _reset()
    monkeypatch.setenv("DATABASE_URL", str(tmp_path / "veritas-test.db"))
    get_settings.cache_clear()
    yield
    _reset()


@pytest.fixture
def make_trace():
    """Create valid traces while allowing individual fields to be overridden."""

    def build(**overrides):
        values = {
            "campaign_id": "campaign-test",
            "phase": Phase.ATTACK,
            "task": "Summarize the search result.",
            "tool_calls": [],
            "final_response": "Done.",
        }
        values.update(overrides)
        return Trace(**values)

    return build


@pytest.fixture
def make_call():
    """Create a ToolCall with required timestamp and index fields."""

    def build(name="web_search", args=None, result=None, call_index=0):
        values = {
            "name": name,
            "args": args or {},
            "timestamp": utcnow_iso(),
            "call_index": call_index,
        }
        if result is not None:
            values["result"] = result
        return ToolCall(**values)

    return build
