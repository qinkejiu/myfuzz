from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.experiments import CONSERVATIVE_PROFILE, ResourceProfile
from myfuzz.integration import run_low_resource_smoke


_MIB = 1024 * 1024
_SOFT_MEMORY_CEILING = CONSERVATIVE_PROFILE.soft_memory_bytes
_HARD_MEMORY_CEILING = CONSERVATIVE_PROFILE.hard_memory_bytes


def _positive_mib(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("memory size must be an integer") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("memory size must be positive")
    return parsed


def _override_profile(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> ResourceProfile:
    requested_soft = (
        _SOFT_MEMORY_CEILING
        if args.soft_memory_mib is None
        else args.soft_memory_mib * _MIB
    )
    requested_hard = (
        _HARD_MEMORY_CEILING
        if args.hard_memory_mib is None
        else args.hard_memory_mib * _MIB
    )
    if requested_soft >= requested_hard:
        parser.error("--soft-memory-mib must be less than --hard-memory-mib")

    effective_soft = min(requested_soft, _SOFT_MEMORY_CEILING)
    effective_hard = min(requested_hard, _HARD_MEMORY_CEILING)
    if effective_soft >= effective_hard:
        parser.error("effective memory limits must keep soft below hard")

    if args.soft_memory_mib is None and args.hard_memory_mib is None:
        return CONSERVATIVE_PROFILE
    return replace(
        CONSERVATIVE_PROFILE,
        soft_memory_bytes=effective_soft,
        hard_memory_bytes=effective_hard,
        token_bytes=min(CONSERVATIVE_PROFILE.token_bytes, effective_soft),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded MyFuzz low-resource smoke")
    parser.add_argument("--report", type=Path, help="optional persistent report path")
    parser.add_argument("--soft-memory-mib", type=_positive_mib)
    parser.add_argument("--hard-memory-mib", type=_positive_mib)
    args = parser.parse_args(argv)

    profile = _override_profile(parser, args)

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
