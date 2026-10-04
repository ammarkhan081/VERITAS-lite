"""Start and follow a VERITAS-lite campaign over the HTTP API.

Examples:
  python scripts/run_campaign.py
  python scripts/run_campaign.py --environment custom_sut --max-steps 10
  python scripts/run_campaign.py --config configs/default_config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import httpx


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a VERITAS-lite campaign")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument(
        "--environment", default="custom_sut", choices=["custom_sut", "agentdojo"]
    )
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--max-tokens", type=int, default=50000)
    parser.add_argument(
        "--families",
        nargs="+",
        default=["indirect_injection", "direct_injection", "goal_hijack"],
    )
    parser.add_argument("--config", type=Path, help="Optional YAML campaign settings")
    return parser.parse_args()


def _payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = {
        "sut_descriptor": {
            "type": args.environment,
            "tools": ["web_search", "file_write", "send_message"],
        },
        "threat_model": {"families": args.families},
        "budget": {"max_steps": args.max_steps, "max_tokens": args.max_tokens},
        "human_policy": {},
    }
    if args.config:
        import yaml

        with args.config.open("r", encoding="utf-8") as handle:
            custom = yaml.safe_load(handle) or {}
        if not isinstance(custom, dict):
            raise ValueError("Campaign YAML config must contain a mapping")
        for key in ("sut_descriptor", "threat_model", "budget", "human_policy"):
            if isinstance(custom.get(key), dict):
                payload[key].update(custom[key])
    return payload


async def _run(args: argparse.Namespace) -> int:
    base_url = args.api_url.rstrip("/")
    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        try:
            response = await client.post("/api/campaigns", json=_payload(args))
            response.raise_for_status()
        except httpx.HTTPError as exc:
            print(f"Could not start campaign: {exc}")
            return 1
        campaign_id = response.json()["campaign_id"]
        print(f"Started campaign {campaign_id}")

        while True:
            try:
                status_response = await client.get(f"/api/campaigns/{campaign_id}")
                status_response.raise_for_status()
            except httpx.HTTPError as exc:
                print(f"Could not read campaign status: {exc}")
                return 1
            status = status_response.json()
            print(
                f"{status['status']} | phase={status['phase']} | "
                f"steps={status['step_count']} | ASR={status.get('asr_before')}"
            )
            if status["status"] in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(5)

        if status["status"] == "completed":
            report_response = await client.get(f"/api/campaigns/{campaign_id}/report")
            if report_response.is_success:
                print(report_response.json().get("summary", "Campaign completed."))
            return 0
        print(f"Campaign ended with status: {status['status']}")
        return 1


def main() -> int:
    args = _arguments()
    if args.max_steps < 1 or args.max_tokens < 1:
        raise SystemExit("--max-steps and --max-tokens must be positive")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
