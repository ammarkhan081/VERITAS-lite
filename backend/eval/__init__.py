"""Evaluation suite and metrics for VERITAS-lite."""

from backend.eval.normal_tasks import (
    NORMAL_TASKS,
    node_run_normal_baseline,
    node_run_normal_suite_post_patch,
)

__all__ = [
    "NORMAL_TASKS",
    "node_run_normal_baseline",
    "node_run_normal_suite_post_patch",
]
