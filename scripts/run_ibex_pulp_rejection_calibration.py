#!/usr/bin/env python3
"""Run, replay or recheck the targeted online rejection calibration.

``run`` starts the same persistent Ibex + two PULP GPIO RFuzz session as
``scripts/run_ibex_pulp_online.py``, but the online decoder is the calibration
decoder: declared class configurations manufacture real refusals before any RTL
command, and one class stays uncertain because its case reached submit.  The
receipt journal is still written by the unchanged live path, and the calibration
report is recomputable from ``receipts.jsonl`` alone with ``verify``.

``replay`` is the online replay contract unchanged: saved admitted evidence is
re-executed against fresh RTL.

Exit codes: 0 satisfied, 1 usage/environment error, 2 replay mismatch or a
report that does not recompute, 3 a declared calibration class was not observed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.ibex_pulp_online import (  # noqa: E402
    replay_ibex_pulp_online_files,
)
from myfuzz.integration.ibex_pulp_rejection_calibration import (  # noqa: E402
    CALIBRATION_CLASS_ORDER, CALIBRATION_REPORT_NAME, DEFAULT_ARM_SLOTS,
    MAX_ARM_SLOTS, build_calibration_plan, calibration_manifest_plan,
    calibration_report_matches, make_ibex_pulp_rejection_calibration_runtime,
    recompute_calibration_report, write_calibration_report,
)
from myfuzz.integration.scenario_rfuzz_live import (  # noqa: E402
    run_scenario_rfuzz_live,
)


def _selection(text: str):
    """``all`` arms every class, ``none`` disables calibration explicitly."""
    if text == "all":
        return None
    if text == "none":
        return ()
    return tuple(part.strip() for part in text.split(","))


def _add_calibration_options(command) -> None:
    command.add_argument(
        "--classes", default="all",
        help="comma separated calibration class IDs, or 'all' (default) / "
             "'none' (calibration disabled); declared classes: "
             + ", ".join(CALIBRATION_CLASS_ORDER))
    command.add_argument(
        "--arm-slots", type=int, default=DEFAULT_ARM_SLOTS,
        help=f"consecutive slots one class may be armed for, 1..{MAX_ARM_SLOTS}")


def _verify(output: Path, report_path: Path | None) -> tuple[dict, int]:
    saved_path = (report_path if report_path is not None
                  else output / CALIBRATION_REPORT_NAME)
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    recomputed = recompute_calibration_report(output)
    plan_matches = (json.dumps(calibration_manifest_plan(output), sort_keys=True)
                    == json.dumps(saved.get("plan"), sort_keys=True))
    matches = calibration_report_matches(saved, recomputed) and plan_matches
    payload = {"matches": matches,
               "manifest_plan_matches_report": plan_matches,
               "complete": bool(recomputed.get("complete")),
               "unsatisfied": recomputed.get("unsatisfied"),
               "receipts": recomputed.get("receipts")}
    return payload, (0 if matches and payload["complete"] else 2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="start one calibrated RTL fuzz session")
    run.add_argument("--client-binary", type=Path, required=True)
    run.add_argument("--cache-dir", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--seconds", type=float, default=60.0)
    run.add_argument("--max-tests", type=int, default=10000)
    run.add_argument("--seed", type=int)
    run.add_argument("--run-id", default="ibex-pulp-rejection-calibration")
    run.add_argument("--cpu-retirement", action="store_true",
                     help="observe official RVFI with the authenticated Ibex wrapper")
    run.add_argument("--native-irq-receipts", action="store_true",
                     help="record parsed Ibex pre/post IRQ decisions; requires RVFI")
    run.add_argument("--gpio-consumption", action="store_true",
                     help="observe authenticated passive GPIO register consumption")
    run.add_argument("--compressed-trace", action="store_true",
                     help="save lossless indexed zlib event blocks")
    _add_calibration_options(run)
    replay = commands.add_parser("replay", help="compare saved evidence with fresh RTL")
    replay.add_argument("--cache-dir", type=Path, required=True)
    replay.add_argument("--plan", type=Path, required=True)
    replay.add_argument("--trace", type=Path, required=True)
    verify = commands.add_parser(
        "verify", help="recompute the calibration report from the saved journal")
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--report", type=Path,
                        help="saved calibration report (default: output/"
                             + CALIBRATION_REPORT_NAME + ")")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            plan = build_calibration_plan(classes=_selection(args.classes),
                                          arm_slots=args.arm_slots)
            if args.output.exists() or args.output.is_symlink():
                raise ValueError("output directory must be new")
            runtime = make_ibex_pulp_rejection_calibration_runtime(
                cache_dir=args.cache_dir, run_id=args.run_id, plan=plan,
                cpu_retirement=args.cpu_retirement,
                gpio_consumption=args.gpio_consumption,
                **({'native_irq_receipts': True}
                   if args.native_irq_receipts else {}))
            result = run_scenario_rfuzz_live(
                executor=runtime.executor, client_binary=args.client_binary,
                output_dir=args.output, duration_seconds=args.seconds,
                max_tests=args.max_tests, search_seed=args.seed,
                max_runs_per_batch=1, compressed_trace=args.compressed_trace)
            report = write_calibration_report(
                result.output_dir, plan=plan,
                plan_document=runtime.decoder.calibration_document()["plan"],
                runtime_state=runtime.decoder.calibration_state())
            print(json.dumps({
                "output_dir": str(result.output_dir), "tests": result.tests,
                "statuses": result.statuses,
                "elapsed_seconds": result.elapsed_seconds,
                "effective_search_seconds": result.effective_search_seconds,
                "calibration_complete": report["complete"],
                "calibration_unsatisfied": report["unsatisfied"],
                "calibration_classes": [
                    {"class_id": entry["class_id"],
                     "expected_code": entry["expected_code"],
                     "observed_count": entry["observed_count"],
                     "satisfied": entry["satisfied"]}
                    for entry in report["classes"]],
                "rejection_codes": report["receipts"]["by_code"],
                "uncertain_receipts": report["receipts"]["uncertain_receipts"],
                "calibration_report": str(
                    result.output_dir / CALIBRATION_REPORT_NAME)}, sort_keys=True))
            return 0 if report["complete"] else 3
        if args.command == "verify":
            payload, code = _verify(args.output, args.report)
            print(json.dumps(payload, sort_keys=True))
            return code
        comparison = replay_ibex_pulp_online_files(
            cache_dir=args.cache_dir, plan_path=args.plan, trace_path=args.trace)
        print(json.dumps({"matches": comparison.matches,
                          "first_difference": comparison.first_difference,
                          "difference_context": comparison.difference_context},
                         sort_keys=True))
        return 0 if comparison.matches else 2
    except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
        print(f"ibex-pulp-rejection-calibration-error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
