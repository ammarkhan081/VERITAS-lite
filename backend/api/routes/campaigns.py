"""Campaign lifecycle API routes."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from langgraph.types import Command

from backend.api.dependencies import get_campaign_store, get_default_sut_config, get_graph
from backend.api.models import CampaignStatusResponse, ResumeRequest, StartCampaignRequest
from backend.memory.campaign_store import CampaignStore
from backend.memory.db import get_db
from backend.schemas.models import CampaignRequest

logger = logging.getLogger("veritas.api.campaigns")
router = APIRouter()
_CAMPAIGN_TASKS: dict[str, asyncio.Task] = {}


def _build_default_sut_config() -> dict:
    """Create a fresh default config with a per-campaign secret marker."""
    config = get_default_sut_config()
    config["sensitive_tokens"] = [f"SESSION_TOKEN_{uuid.uuid4()}"]
    return config


def _campaign_status(row: dict) -> CampaignStatusResponse:
    return CampaignStatusResponse(
        campaign_id=row["id"],
        status=row["status"],
        phase=row.get("phase") or "baseline",
        asr_before=row.get("asr_before"),
        asr_after=row.get("asr_after"),
        normal_acc_before=row.get("normal_acc_before"),
        normal_acc_after=row.get("normal_acc_after"),
        step_count=int(row.get("total_steps") or 0),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _initial_state(campaign_id: str, request: StartCampaignRequest) -> dict[str, Any]:
    sut_config = _build_default_sut_config()
    descriptor_config = request.sut_descriptor.get("config")
    if isinstance(descriptor_config, dict):
        from backend.environment.custom_sut import _deep_merge

        _deep_merge(sut_config, descriptor_config)
    if request.sut_descriptor.get("type"):
        sut_config["environment_type"] = request.sut_descriptor["type"]
    sut_config["campaign_id"] = campaign_id
    sut_config["tools"] = request.sut_descriptor.get(
        "tools", ["web_search", "file_write", "send_message"]
    )
    return {
        "campaign_id": campaign_id,
        "phase": "baseline",
        "sut_descriptor": request.sut_descriptor,
        "sut_config": sut_config,
        "threat_model": request.threat_model,
        "budget_max_steps": int(request.budget.get("max_steps", 20)),
        "budget_max_tokens": int(request.budget.get("max_tokens", 50000)),
        "step_count": 0,
        "tokens_used": 0,
        "attack_batch": [],
        "executed_attack_ids": [],
        "payload_hashes": [],
        "traces": [],
        "verifier_report": {},
        "asr_before": 0.0,
        "asr_after": 0.0,
        "asr_held_out_before": 0.0,
        "asr_held_out_after": 0.0,
        "normal_acc_before": 0.0,
        "normal_acc_after": 0.0,
        "patch_proposal": {},
        "patch_rejection_count": 0,
        "patches_applied": [],
        "human_approved": False,
        "human_interventions": 0,
        "regression_tests_added": [],
        "final_report": {},
        "error_message": "",
    }


async def _run_campaign_async(
    campaign_id: str,
    request: StartCampaignRequest,
    store: CampaignStore | None = None,
    graph: Any | None = None,
) -> None:
    """Run the configured LangGraph campaign in a background task."""
    store = store or get_campaign_store()
    current_task = asyncio.current_task()
    if current_task is not None:
        _CAMPAIGN_TASKS[campaign_id] = current_task
    try:
        graph = graph or get_graph()
        initial_state = _initial_state(campaign_id, request)
        config = {"configurable": {"thread_id": campaign_id}}
        from backend.environment.adapter import environment_type_override

        with environment_type_override(request.sut_descriptor.get("type")):
            async for update in graph.astream(
                initial_state, config=config, stream_mode="updates"
            ):
                if isinstance(update, dict) and "__interrupt__" in update:
                    store.update_campaign(campaign_id, status="paused", phase="patch")
                    logger.info("Campaign %s paused for human review", campaign_id)
                    return
                try:
                    row = store.get_campaign(campaign_id)
                except KeyError:
                    return
                if row["status"] == "cancelled":
                    return
                # LangGraph streams node deltas, so only update persisted fields present
                # in this chunk; the campaign store validates each column name.
                for node_update in update.values() if isinstance(update, dict) else []:
                    if not isinstance(node_update, dict):
                        continue
                    fields = {
                        key: node_update[key]
                        for key in (
                            "phase",
                            "asr_before",
                            "asr_after",
                            "asr_held_out_before",
                            "asr_held_out_after",
                            "normal_acc_before",
                            "normal_acc_after",
                            "total_steps",
                            "total_tokens",
                        )
                        if key in node_update
                    }
                    if "step_count" in node_update:
                        fields["total_steps"] = int(node_update["step_count"])
                    if "tokens_used" in node_update:
                        fields["total_tokens"] = int(node_update["tokens_used"])
                    if fields:
                        store.update_campaign(campaign_id, **fields)
    except asyncio.CancelledError:
        logger.info("Campaign %s was cancelled", campaign_id)
        try:
            store.update_campaign(campaign_id, status="cancelled")
        except Exception:
            logger.exception("Could not persist cancellation for campaign %s", campaign_id)
    except Exception as exc:
        logger.exception("Campaign %s failed", campaign_id)
        try:
            store.update_campaign(campaign_id, status="failed", phase="failed")
        except Exception:
            logger.exception("Could not persist failure for campaign %s", campaign_id)
    finally:
        _CAMPAIGN_TASKS.pop(campaign_id, None)


@router.post("", response_model=dict, status_code=202)
async def start_campaign(
    request: StartCampaignRequest,
    background_tasks: BackgroundTasks,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    """Create a campaign and schedule its graph execution after responding."""
    campaign_id = store.create_campaign(
        CampaignRequest(
            sut_descriptor=request.sut_descriptor,
            threat_model=request.threat_model,
            budget=request.budget,
            human_policy=request.human_policy,
        )
    )
    background_tasks.add_task(_run_campaign_async, campaign_id, request, store)
    return {"campaign_id": campaign_id, "status": "started"}


@router.get("")
async def list_campaigns(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    """List campaigns in reverse creation order with bounded pagination."""
    connection = get_db()
    offset = (page - 1) * limit
    rows = connection.execute(
        "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    total = connection.execute("SELECT COUNT(*) AS n FROM campaigns").fetchone()["n"]
    return {
        "campaigns": [_campaign_status(dict(row)).model_dump(mode="json") for row in rows],
        "page": page,
        "limit": limit,
        "total": total,
    }


@router.get("/{campaign_id}", response_model=CampaignStatusResponse)
async def get_campaign_status(
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> CampaignStatusResponse:
    try:
        row = store.get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc
    return _campaign_status(row)


@router.delete("/{campaign_id}")
async def cancel_campaign(
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    try:
        row = store.get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc
    if row["status"] != "running":
        raise HTTPException(status_code=400, detail="Only running campaigns can be cancelled")
    store.update_campaign(campaign_id, status="cancelled")
    running_task = _CAMPAIGN_TASKS.get(campaign_id)
    if running_task is not None and not running_task.done():
        running_task.cancel()
    return {"campaign_id": campaign_id, "status": "cancelled"}


@router.delete("/{campaign_id}/record")
async def delete_campaign_record(
    campaign_id: str,
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    """Permanently delete a finished campaign and its associated records."""
    try:
        store.delete_campaign_record(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"campaign_id": campaign_id, "deleted": True}


@router.post("/{campaign_id}/resume")
async def resume_campaign(
    campaign_id: str,
    body: ResumeRequest,
    store: CampaignStore = Depends(get_campaign_store),
    graph: Any = Depends(get_graph),
) -> dict:
    try:
        row = store.get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc
    if row["status"] != "paused":
        raise HTTPException(status_code=400, detail="Campaign is not paused for human review")
    store.update_campaign(campaign_id, status="running")
    config = {"configurable": {"thread_id": campaign_id}}
    descriptor = row.get("sut_descriptor", {})
    if isinstance(descriptor, str):
        try:
            descriptor = json.loads(descriptor)
        except json.JSONDecodeError:
            descriptor = {}
    environment_type = descriptor.get("type") if isinstance(descriptor, dict) else None
    try:
        from backend.environment.adapter import environment_type_override

        with environment_type_override(environment_type):
            await graph.ainvoke(Command(resume=body.approved), config=config)
    except Exception as exc:
        store.update_campaign(campaign_id, status="paused")
        logger.exception("Could not resume campaign %s", campaign_id)
        raise HTTPException(status_code=500, detail="Could not resume campaign") from exc
    return {"status": "resumed", "approved": body.approved}
