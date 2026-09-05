#!/usr/bin/env python3
"""Run the low-resource Ibex protocol-composition campaign."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.campaign import (  # noqa: E402
    load_ibex_campaign_config,
    run_ibex_campaign,
    run_ibex_local_smoke,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one single-worker, wave-free Ibex protocol campaign."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--duration-seconds", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--checkpoint-seconds", type=int)
    parser.add_argument(
        "--command",
        choices=("real", "local-smoke"),
        help="Select the supervised command mode (default: real).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--local-smoke", action="store_true")
    parser.add_argument("--max-restarts", type=int)
    return parser.parse_args()


def _default_output_dir(config_path: Path) -> Path:
    document = load_ibex_campaign_config(config_path, root=ROOT)
    configured = document.get("output_dir", "runs/ibex_protocol_campaign")
    if not isinstance(configured, str) or not configured:
        raise ValueError("output_dir:path-required")
    output = Path(configured)
    return output if output.is_absolute() else ROOT / output


def _print_summary(result: object) -> None:
    if not isinstance(result, dict):
        raise TypeError("campaign result must be a mapping")
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def main() -> int:
    args = parse_args()
    if args.local_smoke and args.command == "real":
        raise ValueError("configuration-mixed: --local-smoke conflicts with --command real")
    if args.local_smoke and args.command == "local-smoke":
        raise ValueError("configuration-mixed: --local-smoke is already selected")

    output_dir = args.output_dir or _default_output_dir(args.config)
    local_smoke = args.local_smoke or args.command == "local-smoke"
    common = {
        "duration_seconds": args.duration_seconds,
        "seed": args.seed,
        "checkpoint_seconds": args.checkpoint_seconds,
        "max_restarts": args.max_restarts,
        "dry_run": args.dry_run,
    }
    if local_smoke:
        result = run_ibex_local_smoke(args.config, output_dir, **common)
    else:
        result = run_ibex_campaign(args.config, output_dir, **common)
    _print_summary(result)
    return 2 if result.get("status") == "dependency-unavailable" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TypeError, ValueError) as error:
        print(f"configuration-error: {error}", file=sys.stderr)
        raise SystemExit(2)
