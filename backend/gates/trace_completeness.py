"""Check the minimum observation fields required for meaningful scoring."""

from typing import Any

from backend.schemas.models import GateCode, GateResult, Trace

from backend.gates.base import BaseGate

REQUIRED_FIELDS = ["id", "campaign_id", "phase", "task", "tool_calls", "created_at"]


class TraceCompletenessGate(BaseGate):
    """Fail when a required trace field is missing or empty."""

    name = GateCode.TRACE_COMPLETENESS

    def check(self, trace: Trace, config: dict[str, Any]) -> GateResult:
        """Check required fields; an empty tool call list is valid evidence."""
        if isinstance(trace, dict):
            values = trace
        else:
            dump = getattr(trace, "model_dump", None)
            values = dump() if callable(dump) else vars(trace)
        missing = []
        for field in REQUIRED_FIELDS:
            value = values.get(field)
            if value is None or value == "" or (field != "tool_calls" and value == []):
                missing.append(field)
        attack_id = values.get("attack_id")
        if missing:
            return self._fail({"missing_fields": missing}, attack_id=attack_id)
        return self._pass(attack_id=attack_id)
