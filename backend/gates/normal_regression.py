"""Batch gate for normal-task accuracy regression after a defense patch."""

from typing import Any

from backend.schemas.models import GateCode, GateResult, Trace

from backend.gates.base import BaseGate


class NormalRegressionGate(BaseGate):
    """Reject a patch if measured normal-task accuracy drops too far."""

    name = GateCode.NORMAL_REGRESSION

    def check(self, trace: Trace, config: dict[str, Any]) -> GateResult:
        """Per-trace check is intentionally a no-op; use ``check_batch``."""
        return self._pass(attack_id=self._trace_attack_id(trace))

    def check_batch(
        self,
        before_results: list[bool],
        after_results: list[bool],
        config: dict[str, Any],
    ) -> GateResult:
        """Compare before/after accuracy, passing when drop is at threshold."""
        threshold = float(config.get("normal_task_accuracy_threshold", 0.10))
        before_accuracy = sum(before_results) / len(before_results) if before_results else 0.0
        after_accuracy = sum(after_results) / len(after_results) if after_results else 0.0
        drop = before_accuracy - after_accuracy
        if drop > threshold:
            return self._fail(
                {
                    "before_accuracy": round(before_accuracy, 3),
                    "after_accuracy": round(after_accuracy, 3),
                    "drop": round(drop, 3),
                    "threshold": threshold,
                    "verdict": "PATCH_REJECTED",
                }
            )
        return self._pass()
