"""Secret redaction for traces, dicts, and free-text strings."""

from __future__ import annotations

import re
from typing import Any

from backend.schemas.models import ToolCall, Trace


def redact_string(s: str, secret_patterns: list[str]) -> str:
    """Replace case-insensitive occurrences of each secret pattern with ``[REDACTED]``."""
    redacted = s
    for pattern in secret_patterns:
        if not pattern:
            continue
        redacted = re.sub(re.escape(pattern), "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def _contains_secret(value: str, secret_patterns: list[str]) -> bool:
    """Return True if ``value`` contains any secret pattern (case-insensitive)."""
    lowered = value.lower()
    return any(pattern.lower() in lowered for pattern in secret_patterns if pattern)


def _redact_value(value: Any, secret_patterns: list[str]) -> Any:
    """Recursively redact strings, dicts, and lists."""
    if isinstance(value, str):
        if _contains_secret(value, secret_patterns):
            return "[REDACTED]"
        return value
    if isinstance(value, dict):
        return redact_dict(value, secret_patterns)
    if isinstance(value, list):
        return [_redact_value(item, secret_patterns) for item in value]
    return value


def redact_dict(data: dict, secret_patterns: list[str]) -> dict:
    """Return a new dict with secret-bearing string values replaced by ``[REDACTED]``."""
    return {key: _redact_value(value, secret_patterns) for key, value in data.items()}


def redact_trace(trace: Trace, secret_patterns: list[str]) -> Trace:
    """Return a deep-copied trace with secrets removed from tool I/O and the final response."""
    redacted_calls: list[ToolCall] = []
    for call in trace.tool_calls:
        redacted_calls.append(
            call.model_copy(
                update={
                    "args": redact_dict(call.args, secret_patterns),
                    "result": (
                        redact_dict(call.result, secret_patterns)
                        if call.result is not None
                        else None
                    ),
                }
            )
        )
    final_response = trace.final_response
    if final_response is not None:
        final_response = redact_string(final_response, secret_patterns)
    return trace.model_copy(
        deep=True,
        update={"tool_calls": redacted_calls, "final_response": final_response},
    )
