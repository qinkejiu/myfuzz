"""Small public command line for the source-backed SoC workflow."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_soc_campaigns import run_matrix  # noqa: E402


DEFAULT_MATRIX = ROOT / "configs/soc/matrix.json"
DEFAULT_SECONDS = 300
DEFAULT_SEED = 20260914
CHECK_MODULES = (
    "tests.integration.test_soc_rfuzz_live",
    "tests.integration.test_soc_rfuzz_build",
    "tests.integration.test_soc_campaign_matrix",
    "tests.protocols.test_soc_fabric_rtl",
    "tests.protocols.test_axi4_processor_memory_adapter_rtl",
    "tests.test_cli",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m myfuzz", description="MyFuzz SoC workflow")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="run fast correctness checks")
    for name, help_text in (
        ("preflight", "validate and plan the 32-task matrix"),
        ("run", "run the real 32-task RFuzz matrix"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
        command.add_argument("--seed", type=int, default=DEFAULT_SEED)
        if name == "run":
            command.add_argument("--client", required=True,
                                 help="official RFuzz client executable")
    return parser


def _check() -> int:
    environment = dict(os.environ)
    environment.pop("MYFUZZ_SOC_REAL", None)
    previous = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(SRC) + (os.pathsep + previous if previous else "")
    return subprocess.run(
        [sys.executable, "-m", "unittest", *CHECK_MODULES, "-v"],
        cwd=ROOT, env=environment, check=False,
    ).returncode


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "check":
        return _check()
    if args.command == "run" and os.environ.get("MYFUZZ_SOC_REAL") != "1":
        print("error: run requires MYFUZZ_SOC_REAL=1", file=sys.stderr)
        return 2
    try:
        result = run_matrix(
            args.matrix, args.output,
            seconds=args.seconds,
            seed=args.seed,
            preflight_only=args.command == "preflight",
            root=ROOT,
            client=getattr(args, "client", None),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result.get("status"),
        "tasks": result.get("tasks_planned"),
        "effective_seconds": result.get("effective_budget_seconds"),
    }, sort_keys=True, separators=(",", ":")))
    expected = "preflight-only" if args.command == "preflight" else "completed"
    return 0 if result.get("status") == expected else 2


if __name__ == "__main__":
    raise SystemExit(main())
