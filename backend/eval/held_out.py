"""Post-patch evaluation against sealed held-out attacks."""

from __future__ import annotations

from typing import Any

from backend.core.trace_writer import write_trace
from backend.environment.adapter import get_environment_adapter
from backend.gates.registry import GateRegistry
from backend.memory.campaign_store import CampaignStore
from backend.memory.regression_store import RegressionStore
from backend.schemas.models import Phase

from backend.eval.metrics import calculate_asr


def _shared_regression_store() -> RegressionStore:
    """Use Person 1's graph singleton so its in-memory patch flag is respected."""
    try:
        from backend.orchestration.graph import get_regression_store

        return get_regression_store()
    except (ImportError, AttributeError):
        return RegressionStore()


def run_held_out_evaluation(
    campaign_id: str,
    sut_config: dict,
    regression_store: RegressionStore | None = None,
    environment: Any | None = None,
) -> dict:
    """Run up to three sealed attacks and report post-patch held-out ASR."""
    regression_store = regression_store or _shared_regression_store()
    environment = environment or get_environment_adapter()
    attacks = regression_store.sample_held_out(campaign_id, n=3)
    registry = GateRegistry()
    campaign_store = CampaignStore()
    traces: list[dict] = []
    succeeded = 0

    for attack in attacks:
        task = attack.task or "Search for recent AI news and summarize it"
        trace = environment.run_task(task=task, attack=attack, sut_config=sut_config)
        trace.phase = Phase.HELD_OUT
        trace.attack_id = attack.id
        trace.campaign_id = campaign_id
        results = registry.run_security_gates(trace, sut_config)
        attack_succeeded = registry.any_security_gate_fired(results)
        succeeded += int(attack_succeeded)
        trace.gates_fired = results
        write_trace(trace, campaign_store)
        regression_store.record_held_out_result(
            campaign_id,
            attack.id,
            {"attack_succeeded": attack_succeeded, "trace_id": trace.id},
        )
        traces.append(trace.model_dump(mode="json"))

    return {
        "asr_held_out_after": calculate_asr(succeeded, len(attacks)),
        "held_out_traces": traces,
    }
