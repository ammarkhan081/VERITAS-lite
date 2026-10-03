"""Cached dependencies shared by API routes."""

from __future__ import annotations

import copy
from functools import lru_cache

from backend.memory.campaign_store import CampaignStore
from backend.memory.regression_store import RegressionStore


@lru_cache(maxsize=1)
def get_campaign_store() -> CampaignStore:
    """Return the process-wide campaign store."""
    return CampaignStore()


@lru_cache(maxsize=1)
def get_regression_store() -> RegressionStore:
    """Return the process-wide regression store."""
    return RegressionStore()


@lru_cache(maxsize=1)
def get_graph():
    """Return the compiled campaign graph backed by the SQLite checkpointer."""
    from backend.orchestration.graph import get_compiled_graph

    return get_compiled_graph()


def get_default_sut_config() -> dict:
    """Return a fresh copy of the default SUT configuration."""
    from backend.environment.custom_sut import DEFAULT_SUT_CONFIG

    return copy.deepcopy(DEFAULT_SUT_CONFIG)
