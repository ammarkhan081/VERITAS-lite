"""Campaign report, trace, metrics, and live-update routes."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from backend.api.dependencies import get_campaign_store
from backend.core.config import get_settings
from backend.core.redactor import redact_trace
from backend.eval.metrics import generate_campaign_summary
from backend.memory.campaign_store import CampaignStore
from backend.memory.db import get_db
from backend.schemas.models import CampaignReport

router = APIRouter()
metrics_router = APIRouter()


def _get_campaign(campaign_id: str, store: CampaignStore) -> dict:
    try:
        return store.get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc


def _redacted_trace(trace, settings) -> dict:
    return redact_trace(trace, settings.secret_patterns).model_dump(mode="json")


@router.get("/{campaign_id}/report")
async def get_campaign_report(
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    campaign = _get_campaign(campaign_id, store)
    if campaign["status"] != "completed":
        raise HTTPException(status_code=400, detail="Campaign is not completed")
    raw_report = campaign.get("report")
    if isinstance(raw_report, str):
        try:
            raw_report = json.loads(raw_report)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail="Stored report is invalid") from exc
    if not raw_report:
        raise HTTPException(status_code=404, detail="Campaign report not found")
    report = CampaignReport.model_validate(raw_report)
    return {
        "report": report.model_dump(mode="json"),
        "summary": generate_campaign_summary(report),
    }


@router.get("/{campaign_id}/traces")
async def get_campaign_traces(
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    _get_campaign(campaign_id, store)
    settings = get_settings()
    traces = store.get_traces(campaign_id)
    return {"campaign_id": campaign_id, "traces": [_redacted_trace(t, settings) for t in traces]}


@router.get("/{campaign_id}/traces/{trace_id}")
async def get_campaign_trace(
    campaign_id: str,
    trace_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    _get_campaign(campaign_id, store)
    trace = next(
        (item for item in store.get_traces(campaign_id) if item.id == trace_id), None
    )
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return _redacted_trace(trace, get_settings())


@metrics_router.get("/metrics")
async def get_metrics(
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    connection = get_db()
    rows = connection.execute(
        "SELECT status, asr_before, asr_after FROM campaigns"
    ).fetchall()
    total = len(rows)
    completed = [row for row in rows if row["status"] == "completed"]
    asr_before_values = [float(row["asr_before"]) for row in rows if row["asr_before"] is not None]
    asr_after_values = [float(row["asr_after"]) for row in rows if row["asr_after"] is not None]
    regression_count = connection.execute(
        "SELECT COUNT(*) AS n FROM regression_tests"
    ).fetchone()["n"]
    patches_count = connection.execute(
        "SELECT COUNT(*) AS n FROM patches WHERE status = 'applied'"
    ).fetchone()["n"]
    return {
        "total_campaigns": total,
        "completed_campaigns": len(completed),
        "average_asr_before": (
            round(sum(asr_before_values) / len(asr_before_values), 4)
            if asr_before_values
            else 0.0
        ),
        "average_asr_after": (
            round(sum(asr_after_values) / len(asr_after_values), 4)
            if asr_after_values
            else 0.0
        ),
        "total_regression_tests": int(regression_count),
        "total_patches_applied": int(patches_count),
    }


@router.websocket("/{campaign_id}/ws")
async def campaign_websocket(
    websocket: WebSocket,
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> None:
    """Stream campaign metrics until it finishes or the client disconnects."""
    await websocket.accept()
    try:
        while True:
            try:
                campaign = store.get_campaign(campaign_id)
            except KeyError:
                await websocket.send_json({"error": "Campaign not found"})
                await websocket.close(code=4404)
                return
            await websocket.send_json(
                {
                    "phase": campaign.get("phase"),
                    "asr_before": campaign.get("asr_before"),
                    "asr_after": campaign.get("asr_after"),
                    "step_count": campaign.get("total_steps", 0),
                }
            )
            if campaign["status"] in {"completed", "failed", "cancelled"}:
                return
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
