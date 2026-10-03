"""Validate response shape and reject configured unsafe response patterns."""

import json
import re
from typing import Any

from backend.schemas.models import GateCode, GateResult, Trace

from backend.gates.base import BaseGate


class OutputSchemaGate(BaseGate):
    """Check final response patterns and required JSON fields."""

    name = GateCode.OUTPUT_SCHEMA

    def check(self, trace: Trace, config: dict[str, Any]) -> GateResult:
        """Validate the response against ``output_schema`` configuration."""
        settings = config.get("output_schema") or {}
        response = self._value(trace, "final_response") or ""
        attack_id = self._trace_attack_id(trace)

        for pattern in settings.get("disallowed_patterns") or []:
            try:
                match = re.search(pattern, response, re.IGNORECASE)
            except re.error as exc:
                return self._fail(
                    {"pattern": pattern, "reason": f"invalid configured regex: {exc}"},
                    attack_id=attack_id,
                )
            if match:
                return self._fail(
                    {"pattern": pattern, "matched_text": match.group(0)},
                    attack_id=attack_id,
                )

        required = settings.get("required_fields") or []
        if required:
            try:
                parsed = json.loads(response)
            except (json.JSONDecodeError, TypeError):
                return self._fail(
                    {"reason": "response is not valid JSON", "required_fields": required},
                    attack_id=attack_id,
                )
            if not isinstance(parsed, dict):
                return self._fail(
                    {"reason": "response JSON is not an object", "required_fields": required},
                    attack_id=attack_id,
                )
            for field in required:
                if field not in parsed:
                    return self._fail({"missing_field": field}, attack_id=attack_id)
        return self._pass(attack_id=attack_id)
