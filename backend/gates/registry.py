"""Registry for deterministic security, utility, and infrastructure gates."""

from typing import Any

from backend.schemas.models import GateCode, GateResult, Trace

from backend.gates.argument_policy import ArgumentPolicyGate
from backend.gates.base import BaseGate
from backend.gates.exfiltration_pattern import ExfiltrationPatternGate
from backend.gates.injection_marker import InjectionMarkerGate
from backend.gates.normal_regression import NormalRegressionGate
from backend.gates.output_schema import OutputSchemaGate
from backend.gates.trace_completeness import TraceCompletenessGate
from backend.gates.unauthorized_tool import UnauthorizedToolGate

SECURITY_GATES = frozenset(
    {
        GateCode.UNAUTHORIZED_TOOL,
        GateCode.ARGUMENT_POLICY,
        GateCode.INJECTION_MARKER,
        GateCode.EXFILTRATION_PATTERN,
    }
)
UTILITY_GATES = frozenset({GateCode.OUTPUT_SCHEMA, GateCode.NORMAL_REGRESSION})
INFRASTRUCTURE_GATES = frozenset({GateCode.TRACE_COMPLETENESS})


class GateRegistry:
    """Own a deterministic collection of gates and run the desired subset."""

    def __init__(self) -> None:
        self._gates: dict[GateCode, BaseGate] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the seven built-in gates in stable execution order."""
        for gate in (
            UnauthorizedToolGate(),
            ArgumentPolicyGate(),
            OutputSchemaGate(),
            InjectionMarkerGate(),
            ExfiltrationPatternGate(),
            NormalRegressionGate(),
            TraceCompletenessGate(),
        ):
            self.register(gate)

    def register(self, gate: BaseGate) -> None:
        """Register or replace a gate by its ``GateCode``."""
        self._gates[gate.name] = gate

    def run_all_gates(self, trace: Trace, config: dict[str, Any]) -> list[GateResult]:
        """Run all per-trace gates, excluding batch-only normal regression."""
        return [
            gate.check(trace, config)
            for code, gate in self._gates.items()
            if code != GateCode.NORMAL_REGRESSION
        ]

    def run_security_gates(self, trace: Trace, config: dict[str, Any]) -> list[GateResult]:
        """Run the four security gates used to calculate attack success rate."""
        return [
            self._gates[code].check(trace, config)
            for code in (
                GateCode.UNAUTHORIZED_TOOL,
                GateCode.ARGUMENT_POLICY,
                GateCode.INJECTION_MARKER,
                GateCode.EXFILTRATION_PATTERN,
            )
            if code in self._gates
        ]

    def any_security_gate_fired(self, results: list[GateResult]) -> bool:
        """Return whether any security gate result is a violation."""
        return any(not result.passed and result.gate in SECURITY_GATES for result in results)

    def run_normal_regression(
        self,
        before: list[bool],
        after: list[bool],
        config: dict[str, Any],
    ) -> GateResult:
        """Run the normal-task accuracy gate in batch mode."""
        gate = self._gates.get(GateCode.NORMAL_REGRESSION)
        if not isinstance(gate, NormalRegressionGate):
            raise RuntimeError("NormalRegressionGate is not registered")
        return gate.check_batch(before, after, config)
