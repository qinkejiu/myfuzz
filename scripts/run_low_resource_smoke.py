from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.experiments import CONSERVATIVE_PROFILE
from myfuzz.integration import run_low_resource_smoke


_MIB = 1024 * 1024


def _positive_mib(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("memory size must be positive")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded MyFuzz low-resource smoke")
    parser.add_argument("--report", type=Path, help="optional persistent report path")
    parser.add_argument("--soft-memory-mib", type=_positive_mib)
    parser.add_argument("--hard-memory-mib", type=_positive_mib)
    args = parser.parse_args(argv)

    profile = CONSERVATIVE_PROFILE
    if args.soft_memory_mib is not None or args.hard_memory_mib is not None:
        profile = replace(
            profile,
            soft_memory_bytes=(
                profile.soft_memory_bytes
                if args.soft_memory_mib is None
                else args.soft_memory_mib * _MIB
            ),
            hard_memory_bytes=(
                profile.hard_memory_bytes
                if args.hard_memory_mib is None
                else args.hard_memory_mib * _MIB
            ),
        )

    result = run_low_resource_smoke(ROOT, report_path=args.report, profile=profile)
    policy = result["runtime_policy"]
    print(f"status={result['status']}")
    print(f"profile={result['profile']}")
    print(f"candidate_count={result['candidate_count']}")
    print(f"build_jobs={result['build_jobs']}")
    print(f"fuzz_jobs={result['fuzz_jobs']}")
    print(
        "memory_policy="
        f"{policy['soft_memory_bytes']}/{policy['hard_memory_bytes']} bytes, "
        f"token={policy['token_bytes']}"
    )
    if result["report_path"] is not None:
        print(f"report={result['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
