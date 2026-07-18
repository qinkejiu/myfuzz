#!/usr/bin/env python3
"""Build and run the frozen two-CPU, eight-IP AXI-Lite capability systems."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT = REPO_ROOT / "materials" / "capability" / "axi_lite"
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(ROOT))

from freeze_manifest import build_manifest  # noqa: E402
from myfuzz.builder.atomic_target import run_verilator_target  # noqa: E402
from myfuzz.builder.qualification import QualificationOracle  # noqa: E402
from myfuzz.builder.qualification_pipeline import (  # noqa: E402
    _layout_from_dict, build_qualification_case,
)
from myfuzz.builder.rawbits import write_rawbits_testcase  # noqa: E402


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--cycles", type=int)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    manifest_path = ROOT / "manifest.json"
    frozen = _read_json(manifest_path)
    regenerated = build_manifest()
    if frozen != regenerated:
        raise SystemExit("capability manifest is stale; run freeze_manifest.py and review the diff")

    experiment = frozen["experiment"]
    cycles = args.cycles or int(experiment["cycles"])
    seed = args.seed or int(experiment["seed"])
    oracle = QualificationOracle(
        manifest_path.resolve().as_posix(), str(frozen["manifest_digest"]), frozen,
    )
    output = args.output.resolve()
    case_reports = []
    for case in frozen["cases"]:
        build = build_qualification_case(oracle, str(case["id"]), output, jobs=args.jobs)
        layout = _layout_from_dict(
            _read_json(Path(build.target_dir) / "evidence/bit_layout.json")
        )
        rng = random.Random(seed)
        raw_cycles = tuple(rng.getrandbits(layout.cycle_width) for _ in range(cycles))
        testcase = write_rawbits_testcase(
            layout, raw_cycles, Path(build.case_dir) / "testcases", name=f"seed_{seed}",
        )
        runs = []
        for mode in ("raw", "constrained"):
            started = time.monotonic()
            run = run_verilator_target(
                build.target_dir, testcase["rawbits"], testcase["metadata"],
                Path(build.case_dir) / "runs", mode=mode,
                timeout_seconds=float(experiment["timeout_seconds"]),
            )
            runs.append({
                "mode": mode,
                "seconds": time.monotonic() - started,
                "cycles": cycles,
                "coverage_hit_offsets": run.report["coverage_hit_offsets"],
                "coverage_hit_point_ids": run.report["coverage_hit_point_ids"],
                "coverage_hit_count_by_cycle": run.report["coverage_hit_count_by_cycle"],
                "coverage_sha256": run.report["coverage_sha256"],
                "coverage_trace_sha256": run.report["coverage_trace_sha256"],
            })
        case_reports.append({
            "case_id": build.case_id, "cpu": case["cpu"], "ips": case["ips"],
            "coverage_point_count": build.coverage_width,
            "compile_seconds": build.compile_seconds, "runs": runs,
        })
    report = {
        "schema": "myfuzz.capability-report/v1",
        "status": "passed",
        "manifest_digest": frozen["manifest_digest"],
        "seed": seed,
        "cycles": cycles,
        "cases": case_reports,
    }
    report_path = output / "capability_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"], "case_count": len(case_reports),
        "ip_count_per_case": len(case_reports[0]["ips"]),
        "coverage_point_counts": {
            item["case_id"]: item["coverage_point_count"] for item in case_reports
        },
        "report": report_path.as_posix(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
