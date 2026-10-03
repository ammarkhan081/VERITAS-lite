"""Small compatibility helpers for the Person 1 schema and store interfaces."""

from __future__ import annotations

import inspect
from enum import Enum
from typing import Any


def field_value(value: Any, name: str, default: Any = None) -> Any:
    """Read an attribute from a model or a key from a mapping."""
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def enum_value(value: Any) -> Any:
    """Convert an enum member to its underlying value."""
    return value.value if isinstance(value, Enum) else value


def model_dump(value: Any) -> Any:
    """Return recursively JSON-friendly model data."""
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except TypeError:
            return value.model_dump()
    if isinstance(value, dict):
        return {key: model_dump(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [model_dump(item) for item in value]
    return enum_value(value)


def construct_model(model_type: Any, values: dict[str, Any]) -> Any:
    """Construct a Pydantic model, omitting fields unknown to its schema."""
    fields = getattr(model_type, "model_fields", None)
    if fields is None:
        fields = getattr(model_type, "__fields__", None)
    supplied = {key: value for key, value in values.items() if fields is None or key in fields}
    return model_type(**supplied)


def enum_member(enum_type: Any, *names: str, default: Any = None) -> Any:
    """Return the first available named member from an enum-like type."""
    for name in names:
        if hasattr(enum_type, name):
            return getattr(enum_type, name)
    return default


def call_supported(method: Any, values: dict[str, Any], positional_fallback: tuple[Any, ...] = ()) -> Any:
    """Call a store method with only parameters supported by its signature."""
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(*positional_fallback)

    params = signature.parameters
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in params.values()):
        return method(**values)

    kwargs = {
        name: values[name]
        for name, parameter in params.items()
        if name in values
        and parameter.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    missing_required = [
        parameter
        for name, parameter in params.items()
        if name not in kwargs
        and parameter.default is inspect.Parameter.empty
        and parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if missing_required:
        if positional_fallback:
            return method(*positional_fallback)
        names = ", ".join(parameter.name for parameter in missing_required)
        raise TypeError(f"Cannot call {getattr(method, '__qualname__', method)!s}; missing required parameters: {names}")
    return method(**kwargs)


def with_model_updates(model: Any, **updates: Any) -> Any:
    """Return a model copy with fields updated, or update a mutable trace."""
    if isinstance(model, dict):
        return {**model, **updates}
    copier = getattr(model, "model_copy", None)
    if callable(copier):
        return copier(update=updates)
    for key, value in updates.items():
        setattr(model, key, value)
    return model
