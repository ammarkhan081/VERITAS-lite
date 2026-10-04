"""Request and response models for the VERITAS-lite HTTP API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class StartCampaignRequest(BaseModel):
    sut_descriptor: dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "custom_sut",
            "tools": ["web_search", "file_write", "send_message"],
        }
    )
    threat_model: dict[str, Any] = Field(
        default_factory=lambda: {
            "families": ["direct_injection", "indirect_injection", "goal_hijack"]
        }
    )
    budget: dict[str, Any] = Field(
        default_factory=lambda: {"max_steps": 20, "max_tokens": 50000}
    )
    human_policy: dict[str, Any] = Field(default_factory=dict)


class CampaignStatusResponse(BaseModel):
    campaign_id: str
    status: str
    phase: str
    asr_before: float | None = None
    asr_after: float | None = None
    normal_acc_before: float | None = None
    normal_acc_after: float | None = None
    step_count: int = 0
    created_at: str
    updated_at: str | None = None
    error_message: str | None = None


class ResumeRequest(BaseModel):
    approved: bool
    comment: str = ""
