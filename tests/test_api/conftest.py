"""Fixtures for HTTP API tests."""

from __future__ import annotations

import pytest


class DummyGraph:
    """Stand-in campaign graph so API tests never start a real LLM campaign."""

    async def ainvoke(self, command, config=None):
        return {"resumed": True}


@pytest.fixture
def client(isolated_database):
    """FastAPI test client with the campaign graph replaced by ``DummyGraph``."""
    from fastapi.testclient import TestClient

    from backend.api.dependencies import get_graph
    from backend.api.main import app

    app.dependency_overrides[get_graph] = DummyGraph
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
