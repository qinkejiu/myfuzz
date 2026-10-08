#!/usr/bin/env python3
"""Measure one fresh Ibex + dual GPIO runtime per saved RFuzz input.

This is a startup-cost baseline. Its single-case sessions do not reproduce
the online campaign's persistent state or coverage trajectory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _baseline_record(row: object, *, where: str) -> dict:
    """Validate one saved cold-baseline input row; ``where`` locates it."""
    raw = row.get("online_raw_records_hex") if isinstance(row, dict) else None
    if (not isinstance(raw, list) or len(raw) != 1
            or not isinstance(raw[0], str) or len(raw[0]) != 16):
        raise ValueError(f"{where}: each cold baseline input needs one "
                         "eight-byte record")
    try:
        data = bytes.fromhex(raw[0])
    except ValueError as exc:
        raise ValueError(f"{where}: cold baseline record is not hexadecimal") from exc
    if len(data) != 8 or data.hex() != raw[0]:
        raise ValueError(f"{where}: cold baseline requires canonical eight-byte hex")
    weights = row.get("online_weights")
    if (not isinstance(weights, dict) or any(
            not isinstance(key, str) or not key or type(value) is not int
            or not 1 <= value <= 65536 for key, value in weights.items())):
        raise ValueError(f"{where}: cold baseline record has invalid online weights")
    return row


def load_records(path: Path, count: int | None = None, *,
                 allow_short: bool = False) -> list[dict]:
    """Load saved inputs for cold measurement.

    ``count=None`` loads every row. ``allow_short`` selects the truncated-window
    semantics used by per-case cold-run aggregation: a file with fewer rows than
    requested yields the rows it has instead of raising.
    """
    if count is not None and (type(count) is not int or count < 1):
        raise ValueError("count must be a positive integer")
    records = []
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if count is not None and len(records) == count:
                break
            where = f"{Path(path)}: line {number}"
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{where}: invalid JSON: {exc.msg}") from exc
            records.append(_baseline_record(row, where=where))
    if count is not None and not allow_short and len(records) != count:
        raise ValueError("receipts file has fewer records than requested")
    return records


def load_first_records(path: Path, count: int) -> list[dict]:
    if type(count) is not int or not 1 <= count <= 30:
        raise ValueError("count must be between 1 and at most 30")
    return load_records(path, count)


def measure_cold_cases(records: list[dict], runtime_factory: Callable[[int], object],
                       *, clock: Callable[[], float] = time.monotonic,
                       verify_replay: bool = False) -> list[dict]:
    results = []
    for index, row in enumerate(records):
        started = clock()
        runtime = runtime_factory(index)
        after_init = clock()
        case = None
        receipt = None
        trace = None
        error = None
        after_decode = None
        try:
            case = runtime.decoder.decode(
                bytes.fromhex(row["online_raw_records_hex"][0]),
                coverage_hints=row["online_weights"])
            after_decode = clock()
            receipt = runtime.session.submit_case(case)
            runtime.decoder.commit(case)
            after_execute = clock()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            if after_decode is None:
                after_decode = clock()
                after_execute = after_decode
            else:
                after_execute = clock()
        try:
            trace = runtime.session.finish()
            final_status = trace.status
        except Exception as exc:
            final_status = "finish_error"
            error = f"{type(exc).__name__}: {exc}" if error is None else error
        after_finish = clock()
        replay_result = None
        if verify_replay:
            replay_error = None
            if trace is None or error is not None:
                replay_error = "cold case has no complete reference trace"
            else:
                try:
                    comparison = runtime.replay(trace)
                    replay_result = {
                        "replay_matches": comparison.matches is True,
                        "replay_first_difference": comparison.first_difference,
                        "replay_verification_scope": comparison.verification_scope,
                    }
                except Exception as exc:
                    replay_error = f"{type(exc).__name__}: {exc}"
            after_replay = clock()
            replay_result = {**(replay_result or {
                "replay_matches": False, "replay_first_difference": None,
                "replay_verification_scope": None}),
                "replay_seconds": after_replay - after_finish,
                "replay_error": replay_error}
        selected = (case.source.action_id.rsplit(":", 1)[-1]
                    if case is not None else None)
        original = row.get("applied_sources")
        original_source = original[0] if isinstance(original, list) and original else None
        status = ("error" if error is not None else
                  "finding" if receipt is not None and receipt.violations else
                  final_status)
        result = {
            "index": index, "raw_hex": row["online_raw_records_hex"][0],
            "original_status": row.get("status"), "cold_status": status,
            "original_source": original_source, "cold_source": selected,
            "source_compatible": original_source == selected,
            "original_path": row.get("path_id"),
            "cold_path": case.path_id if case is not None else None,
            "path_compatible": case is not None and row.get("path_id") == case.path_id,
            "init_seconds": after_init - started,
            "decode_seconds": after_decode - after_init,
            "execute_seconds": after_execute - after_decode,
            "finish_seconds": after_finish - after_execute,
            "total_seconds": after_finish - started,
            "error": error,
        }
        if replay_result is not None:
            result.update(replay_result)
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", type=Path, default=ROOT /
                        "runs/ibex-pulp-online-20261006-600s/receipts.jsonl")
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--fresh-replay", action="store_true",
                        help="verify each cold case using a fresh RTL process")
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must be a new file")
    from myfuzz.integration.ibex_pulp_online import make_ibex_pulp_online_runtime

    records = load_first_records(args.receipts, args.count)
    started = time.monotonic()
    results = measure_cold_cases(
        records, lambda index: make_ibex_pulp_online_runtime(
            cache_dir=args.cache_dir, run_id=f"ibex-pulp-cold-{index}"),
        verify_replay=args.fresh_replay)
    document = {"schema_version": "ibex_pulp_cold_baseline.v1",
                "comparison_scope": "startup_cost_only_not_coverage_equivalence",
                "source_receipts": str(args.receipts), "case_count": len(results),
                "elapsed_seconds": time.monotonic() - started,
                "source_compatible_count": sum(row["source_compatible"] for row in results),
                "path_compatible_count": sum(row["path_compatible"] for row in results),
                "cases": results}
    if args.fresh_replay:
        document["fresh_replay_enabled"] = True
        document["fresh_replay_match_count"] = sum(
            row["replay_matches"] is True for row in results)
        document["fresh_replay_full_count"] = sum(
            row["replay_matches"] is True
            and row["replay_verification_scope"] == "full" for row in results)
        document["replay_seconds_total"] = sum(row["replay_seconds"] for row in results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output), "cases": len(results),
                      "elapsed_seconds": document["elapsed_seconds"],
                      "source_compatible_count": document["source_compatible_count"],
                      "path_compatible_count": document["path_compatible_count"],
                      **({"fresh_replay_full_count": document["fresh_replay_full_count"]}
                         if args.fresh_replay else {})},
                     sort_keys=True))
    return 0 if not args.fresh_replay or document["fresh_replay_full_count"] == len(results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
