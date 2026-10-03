"""Abstract base class shared by all deterministic gates."""

from abc import ABC, abstractmethod
from typing import Any

from backend.schemas.models import GateCode, GateResult, Trace


class BaseGate(ABC):
    """A gate returns PASS for safe behavior and FAIL for a detected issue."""

    name: GateCode

    @abstractmethod
    def check(self, trace: Trace, config: dict[str, Any]) -> GateResult:
        """Evaluate one trace against this gate's policy."""
        raise NotImplementedError

    def _fail(self, evidence: dict[str, Any], attack_id: str | None = None) -> GateResult:
        """Construct a failed gate result with structured evidence."""
        return GateResult(gate=self.name, passed=False, evidence=evidence, attack_id=attack_id)

    def _pass(self, attack_id: str | None = None) -> GateResult:
        """Construct a passed gate result."""
        return GateResult(gate=self.name, passed=True, evidence={}, attack_id=attack_id)

    @staticmethod
    def _value(obj: Any, key: str, default: Any = None) -> Any:
        """Read a field from either a Pydantic model or a mapping."""
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @classmethod
    def _trace_attack_id(cls, trace: Trace) -> str | None:
        return cls._value(trace, "attack_id")

    @classmethod
    def _tool_calls(cls, trace: Trace) -> list[Any]:
        return cls._value(trace, "tool_calls", []) or []
