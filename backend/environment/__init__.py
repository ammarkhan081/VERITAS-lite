"""Environment adapters for VERITAS-lite."""

from backend.environment.adapter import (
    EnvironmentAdapter,
    environment_type_override,
    get_environment_adapter,
)
from backend.environment.custom_sut import CustomSUTAdapter

__all__ = [
    "EnvironmentAdapter",
    "get_environment_adapter",
    "environment_type_override",
    "CustomSUTAdapter",
]
