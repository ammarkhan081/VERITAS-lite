"""Agent and evaluation node registry for the campaign graph.

Collects the LangGraph node callables implemented by the agent layer
(:mod:`backend.agents`) and the evaluation layer (:mod:`backend.eval`) under the
node names used by :func:`backend.orchestration.graph.build_campaign_graph`.
"""

from backend.agents.blue_team import node_blue_team_propose
from backend.agents.orchestrator import (
    node_orchestrator_generate_report as node_generate_report,
    node_orchestrator_initialize as node_initialize_campaign,
    route_after_verify_attacks,
    route_after_verify_post_patch,
)
from backend.agents.red_team import (
    node_red_team_execute_attacks as node_execute_attacks,
    node_red_team_generate_attacks as node_generate_attacks,
    node_red_team_retest_held_out as node_retest_held_out_attacks,
    node_red_team_retest_training as node_retest_training_attacks,
)
from backend.agents.verifier import (
    node_verifier_score_attacks as node_verify_attacks,
    node_verifier_score_post_patch as node_verify_post_patch,
)
from backend.eval.normal_tasks import (
    node_run_normal_baseline,
    node_run_normal_suite_post_patch,
)

__all__ = [
    "node_initialize_campaign",
    "node_generate_report",
    "node_generate_attacks",
    "node_execute_attacks",
    "node_retest_training_attacks",
    "node_retest_held_out_attacks",
    "node_blue_team_propose",
    "node_verify_attacks",
    "node_verify_post_patch",
    "node_run_normal_baseline",
    "node_run_normal_suite_post_patch",
    "route_after_verify_attacks",
    "route_after_verify_post_patch",
]
