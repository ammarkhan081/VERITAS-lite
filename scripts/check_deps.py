"""Verify that every VERITAS-lite backend package can be imported.

Usage:
    python scripts/check_deps.py
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

# Allow `python scripts/check_deps.py` from any working directory.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

MODULES = (
    "backend.schemas.models",
    "backend.core.config",
    "backend.memory.campaign_store",
    "backend.memory.regression_store",
    "backend.gates.registry",
    "backend.agents.orchestrator",
    "backend.agents.red_team",
    "backend.agents.blue_team",
    "backend.agents.verifier",
    "backend.environment.adapter",
    "backend.eval.normal_tasks",
    "backend.orchestration.graph",
    "backend.api.main",
)


def main() -> int:
    """Import each backend module and report any failures."""
    errors: list[str] = []
    for module in MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:  # noqa: BLE001 - report every failure, not just ImportError
            errors.append(f"{module}: {type(exc).__name__}: {exc}")

    if errors:
        print("MISSING OR BROKEN MODULES:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"All {len(MODULES)} backend modules import successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
