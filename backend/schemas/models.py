"""Pydantic and TypedDict schemas shared by VERITAS-lite agents and APIs."""

from __future__ import annotations

import hashlib
import operator
from datetime import datetime
from enum import Enum
from typing import Annotated, Optional, TypedDict
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a Z suffix."""
    return datetime.utcnow().isoformat() + "Z"


class AttackFamily(str, Enum):
    """Attack taxonomy used by the red-team agent."""

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    GOAL_HIJACK = "goal_hijack"


class AttackPool(str, Enum):
    """Whether an attack is in the training pool or sealed held-out set."""

    TRAINING = "training"
    HELD_OUT = "held_out"


class AttackStatus(str, Enum):
    """Lifecycle status of a generated attack."""

    PENDING = "pending"
    EXECUTED = "executed"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class PatchType(str, Enum):
    """Kinds of defense the blue-team agent may propose."""

    CONFIG_CHANGE = "config_change"
    SANITIZATION_RULE = "sanitization_rule"
    PROMPT_GUARD = "prompt_guard"


class RiskLevel(str, Enum):
    """Risk classification for a proposed patch."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Phase(str, Enum):
    """Campaign phase names used in traces and reports."""

    BASELINE = "baseline"
    ATTACK = "attack"
    VERIFY = "verify"
    PATCH = "patch"
    RETEST = "retest"
    HELD_OUT = "held_out"
    REPORT = "report"


class CampaignStatus(str, Enum):
    """Overall campaign lifecycle status."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class GateCode(str, Enum):
    """Deterministic verifier gate identifiers."""

    UNAUTHORIZED_TOOL = "unauthorized_tool"
    ARGUMENT_POLICY = "argument_policy"
    OUTPUT_SCHEMA = "output_schema"
    INJECTION_MARKER = "injection_marker"
    EXFILTRATION_PATTERN = "exfiltration_pattern"
    NORMAL_REGRESSION = "normal_regression"
    TRACE_COMPLETENESS = "trace_completeness"


class ToolCall(BaseModel):
    """A single tool invocation recorded in a trace."""

    name: str
    args: dict
    result: Optional[dict] = None
    timestamp: str
    call_index: int
    error: Optional[str] = None


class Trace(BaseModel):
    """Execution trace for an attack or a normal-task run."""

    id: str = Field(default_factory=lambda: f"trace-{uuid4()}")
    campaign_id: str
    attack_id: Optional[str] = None
    phase: Phase
    task: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    final_response: Optional[str] = None
    gates_fired: list[GateResult] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: utcnow_iso())

    def has_tool_call(self, tool_name: str) -> bool:
        """Return True if this trace contains a call to ``tool_name``."""
        return any(call.name == tool_name for call in self.tool_calls)

    def get_tool_calls(self, tool_name: str) -> list[ToolCall]:
        """Return all tool calls in this trace whose name matches ``tool_name``."""
        return [call for call in self.tool_calls if call.name == tool_name]


class GateResult(BaseModel):
    """Outcome of a single deterministic or LLM verifier gate."""

    gate: GateCode
    passed: bool
    evidence: dict = Field(default_factory=dict)
    attack_id: Optional[str] = None


class Attack(BaseModel):
    """A generated attack payload bound to a campaign and target tool."""

    id: str = Field(default_factory=lambda: f"atk-{uuid4()}")
    campaign_id: str
    family: AttackFamily
    payload: str
    injection_vector: str
    target_tool: str
    pool: AttackPool = AttackPool.TRAINING
    status: AttackStatus = AttackStatus.PENDING
    task: str
    created_at: str = Field(default_factory=lambda: utcnow_iso())
    executed_at: Optional[str] = None
    payload_hash: str = ""

    def model_post_init(self, __context: object) -> None:
        """Populate ``payload_hash`` from a truncated SHA-256 of the payload."""
        if not self.payload_hash:
            self.payload_hash = hashlib.sha256(self.payload.encode()).hexdigest()[:16]


class AttackPlan(BaseModel):
    """Batch of attacks produced by the red-team agent for a campaign."""

    campaign_id: str
    attacks: list[Attack] = Field(default_factory=list)
    notes: str = ""


class VerificationResult(BaseModel):
    """Aggregated verifier output for a campaign phase."""

    campaign_id: str
    phase: Phase
    asr: float
    recovery_rate: float = 0.0
    normal_task_accuracy: float
    violations: list[GateResult] = Field(default_factory=list)
    gate_decisions: list[GateResult] = Field(default_factory=list)
    attacks_evaluated: int = 0
    attacks_succeeded: int = 0
    recommendation: str = "no_action"


class PatchProposal(BaseModel):
    """Defense change proposed by the blue-team agent."""

    id: str = Field(default_factory=lambda: f"patch-{uuid4()}")
    type: PatchType
    target: str
    change: dict
    rationale: str
    expected_gates_affected: list[str] = Field(default_factory=list)
    requires_human_review: bool = False
    risk_level: RiskLevel = RiskLevel.LOW


class PatchApplicationResult(BaseModel):
    """Result of applying or rejecting a patch on the SUT."""

    patch_id: str
    campaign_id: str
    applied: bool
    status: str = "applied"
    sut_config: dict = Field(default_factory=dict)
    error: Optional[str] = None
    applied_at: str = Field(default_factory=lambda: utcnow_iso())


class FailureSummary(BaseModel):
    """Sanitized failure description sent to the blue-team agent (not a full trace)."""

    attack_family: AttackFamily
    gates_fired: list[str]
    tool_violated: str
    violation_type: str
    injection_vector: str


class RegressionTest(BaseModel):
    """Permanent regression test derived from a successful attack."""

    id: str = Field(default_factory=lambda: f"reg-{uuid4()}")
    campaign_id: str
    attack_id: str
    family: AttackFamily
    payload: str
    injection_vector: str
    target_tool: str
    evidence: dict
    replay_info: dict
    sut_version: str = "v1.0"
    patch_version: Optional[str] = None
    created_at: str = Field(default_factory=lambda: utcnow_iso())
    status: str = "active"


class CampaignRequest(BaseModel):
    """Input required to start a new campaign."""

    sut_descriptor: dict
    threat_model: dict
    budget: dict
    human_policy: dict = Field(default_factory=dict)


class CampaignReport(BaseModel):
    """Final campaign summary stored after the loop completes."""

    campaign_id: str
    duration_seconds: float
    asr_before: float
    asr_after: float
    asr_held_out_before: float
    asr_held_out_after: float
    normal_acc_before: float
    normal_acc_after: float
    patches_applied: int
    human_interventions: int
    regression_tests_added: int
    total_steps: int
    violations: list[dict]
    patches: list[dict]
    summary: str = ""


class CampaignState(TypedDict):
    """LangGraph state for a VERITAS-lite campaign."""

    campaign_id: str
    phase: str
    sut_descriptor: dict
    sut_config: dict
    threat_model: dict
    budget_max_steps: int
    budget_max_tokens: int
    step_count: int
    tokens_used: int
    attack_batch: Annotated[list, operator.add]
    executed_attack_ids: Annotated[list, operator.add]
    payload_hashes: Annotated[list, operator.add]
    traces: Annotated[list, operator.add]
    verifier_report: dict
    asr_before: float
    asr_after: float
    asr_held_out_before: float
    asr_held_out_after: float
    normal_acc_before: float
    normal_acc_after: float
    patch_proposal: dict
    patch_rejection_count: int
    patches_applied: Annotated[list, operator.add]
    human_approved: bool
    human_interventions: int
    regression_tests_added: Annotated[list, operator.add]
    final_report: dict
    error_message: str

    # Written by the agent layer. LangGraph only persists declared keys, so every
    # key a node returns must be listed here.
    held_out_sealed: bool                 # Red-Team: held-out set sealed (exactly once)
    successful_attack_ids: list           # Verifier: latest successful attacks (overwrite, not append)
    attack_verifier_report: dict          # Verifier: pre-patch report kept for the final summary
    duration_seconds: float               # Orchestrator: wall-clock campaign duration
