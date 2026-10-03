"""Blue-Team structured defense proposal with strict failure-summary isolation."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from backend.agents._utils import construct_model, enum_value, field_value, model_dump
from backend.agents.base import get_llm
from backend.memory.campaign_store import CampaignStore
from backend.schemas.models import CampaignState, FailureSummary, PatchProposal, PatchType, RiskLevel

logger = logging.getLogger(__name__)
PROMPT_DIR = Path(__file__).parent / "prompts"
SUMMARY_FIELDS = {
    "attack_family",
    "gates_fired",
    "tool_violated",
    "violation_type",
    "injection_vector",
}


class PatchProposalOutput(BaseModel):
    """Structured response schema for Blue-Team defense proposals."""

    type: PatchType
    target: str
    change: dict[str, Any]
    rationale: str
    risk_level: RiskLevel
    requires_human_review: bool = False
    expected_gates_affected: list[str] = Field(default_factory=list)


def _load_prompt() -> str:
    """Read the Blue-Team prompt from its dedicated prompt file."""
    return (PROMPT_DIR / "blue_team_propose.txt").read_text(encoding="utf-8")


def _safe_summary(value: Any) -> FailureSummary:
    """Rebuild the failure summary from an explicit allowlist of fields."""
    raw = field_value(value, "failure_summary", value)
    if isinstance(raw, FailureSummary):
        raw = model_dump(raw)
    if not isinstance(raw, dict):
        raise ValueError("Verifier violation must contain a structured FailureSummary")
    allowed = {key: raw[key] for key in SUMMARY_FIELDS if key in raw}
    if "attack_family" not in allowed:
        allowed["attack_family"] = "unknown"
    if "gates_fired" not in allowed:
        allowed["gates_fired"] = []
    if "tool_violated" not in allowed:
        allowed["tool_violated"] = "unknown"
    if "violation_type" not in allowed:
        allowed["violation_type"] = "unknown"
    if "injection_vector" not in allowed:
        allowed["injection_vector"] = "unknown"
    return FailureSummary(**allowed)


def _safe_config(config: dict[str, Any]) -> dict[str, Any]:
    """Remove campaign secrets and any payload-like fields before prompting."""
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: clean(item)
                for key, item in value.items()
                if str(key).lower() not in {"payload", "payloads", "sensitive_tokens", "secret", "secrets"}
            }
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    return clean(config)


def node_blue_team_propose(state: CampaignState) -> dict[str, Any]:
    """Propose and persist a minimal defense using only the safe failure summary."""
    # Prefer the original pre-patch verifier report which has attack violations.
    # On re-entry after patch rejection, verifier_report is overwritten by post-patch results.
    attack_report = state.get("attack_verifier_report") or state.get("verifier_report") or {}
    verifier_report = attack_report if attack_report.get("violations") else (state.get("verifier_report") or {})
    violations = verifier_report.get("violations", []) or []
    if not violations:
        raise ValueError("Blue-Team requires at least one verifier FailureSummary")
    summary = _safe_summary(violations[0])
    summary_data = model_dump(summary)
    prompt = _load_prompt().format(
        attack_family=enum_value(summary_data.get("attack_family", "unknown")),
        gates_fired=", ".join(map(str, summary_data.get("gates_fired", []))),
        tool_violated=summary_data.get("tool_violated", "unknown"),
        violation_type=summary_data.get("violation_type", "unknown"),
        injection_vector=summary_data.get("injection_vector", "unknown"),
        current_sut_config=json.dumps(_safe_config(state.get("sut_config", {}) or {}), sort_keys=True, default=str),
    )
    import re
    from langchain_core.messages import SystemMessage, HumanMessage
    llm = get_llm("blue_team")
    system = (
        "You are a security blue-team assistant. "
        "Always respond with valid JSON only — no extra text, no markdown. "
        "Your response must be a JSON object matching this schema: "
        '{"type": string, "target": string, "change": object, "rationale": string, '
        '"risk_level": string, "requires_human_review": bool, "expected_gates_affected": [string]}. '
        'Valid type values: config_change, sanitization_rule, prompt_guard. '
        'Valid risk_level values: low, medium, high.'
    )
    messages = [SystemMessage(content=system), HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    raw = response.content if hasattr(response, "content") else str(response)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0].strip()
    try:
        data = json.loads(raw)
        output = PatchProposalOutput.model_validate(data)
    except Exception:
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                output = PatchProposalOutput.model_validate(json.loads(match.group()))
            except Exception:
                raise ValueError(f"Blue-team LLM returned non-parseable output: {raw[:300]}")
        else:
            raise ValueError(f"Blue-team LLM returned non-parseable output: {raw[:300]}")

    proposal_data = {
        "id": str(uuid.uuid4()),
        "campaign_id": state.get("campaign_id", ""),
        "type": output.type,
        "target": output.target,
        "change": output.change,
        "rationale": output.rationale,
        "risk_level": output.risk_level,
        "requires_human_review": output.requires_human_review,
        "expected_gates_affected": output.expected_gates_affected,
    }
    proposal = construct_model(PatchProposal, proposal_data)
    store = CampaignStore()
    saver = getattr(store, "save_patch", None) or getattr(store, "save_patch_proposal", None)
    if not callable(saver):
        raise AttributeError("CampaignStore must provide save_patch() or save_patch_proposal()")
    from backend.agents._utils import call_supported

    call_supported(
        saver,
        {
            "campaign_id": state.get("campaign_id", ""),
            "proposal": proposal,
            "patch": proposal,
            "patch_proposal": proposal,
        },
        positional_fallback=(proposal,),
    )

    return {
        "patch_proposal": model_dump(proposal),
        "patch_rejection_count": int(state.get("patch_rejection_count", 0)),
    }
