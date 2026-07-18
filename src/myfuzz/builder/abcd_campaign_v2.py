"""Serial, paired A/B/C/D branch-coverage campaigns on fixed DUT-cycle budgets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import statistics
import subprocess
from typing import Mapping, Sequence

from .atomic_target import FIXED_CYCLE_RUNNER_SCHEMA
from .generated_experiment_v2 import (
    GENERATED_MODES, _checkpoints, _coverage_curve, _first_hits, _hit_counts,
    run_generated_bcd_seed,
)
from .input_model import InputValidationError


def coverage_point_catalog(abi: Mapping[str, object]) -> Mapping[str, object]:
    """Return a source-offset-independent experiment catalog."""
    points = sorted(
        (item for item in abi.get("points", ()) if item.get("included") is True),
        key=lambda item: int(item["offset"]),
    )
    if [int(item["offset"]) for item in points] != list(range(len(points))):
        raise InputValidationError("experiment coverage points must have dense ordered offsets")
    entries = tuple({
        "offset": int(item["offset"]),
        "point_id": str(item["point_id"]),
        "component_id": str(item.get("component_id", "")),
    } for item in points)
    payload = {"schema": "myfuzz.experiment-coverage-catalog/v1", "points": entries}
    return {**payload, "digest": _sha256(_canonical(payload))}


def run_abcd_campaign(
    baseline_target_dir: str | Path,
    generated_target_dir: str | Path,
    output_dir: str | Path,
    *,
    seeds: Sequence[int],
    cycles: int,
    checkpoints: Sequence[int] = (),
    minimum_valid_seeds: int = 10,
    timeout_seconds: float = 30.0,
) -> Mapping[str, object]:
    """Run paired seeds serially, excluding complete tuples on infrastructure failure."""
    if cycles <= 0 or minimum_valid_seeds < 10 or timeout_seconds <= 0:
        raise InputValidationError("A/B/C/D campaign dimensions are invalid")
    selected = tuple(seeds)
    if (len(selected) < minimum_valid_seeds or len(set(selected)) != len(selected)
            or any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in selected)):
        raise InputValidationError("A/B/C/D campaign seed pool is invalid")
    selected_checkpoints = _checkpoints(cycles, checkpoints)
    baseline = Path(baseline_target_dir).resolve(strict=True)
    generated = Path(generated_target_dir).resolve(strict=True)
    a_completion = _read_json(baseline / "completion_manifest.json")
    g_completion = _read_json(generated / "completion_manifest.json")
    if a_completion.get("runner_schema") != FIXED_CYCLE_RUNNER_SCHEMA:
        raise InputValidationError("scheme A requires the fixed DUT-cycle runner")
    if g_completion.get("runner_schema") != "myfuzz.generated-target-runner/v2":
        raise InputValidationError("schemes B/C/D require generated target runner v2")
    a_layout = _read_json(baseline / "evidence/bit_layout.json")
    a_abi = _read_json(baseline / "evidence/coverage_abi.json")
    g_abi = _read_json(generated / "evidence/coverage_abi.json")
    a_catalog = coverage_point_catalog(a_abi)
    g_catalog = coverage_point_catalog(g_abi)
    if a_catalog != g_catalog:
        raise InputValidationError("A and generated targets do not share the ordered coverage catalog")

    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"A/B/C/D campaign output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    valid: list[Mapping[str, object]] = []
    invalid: list[Mapping[str, object]] = []
    for seed in selected:
        if len(valid) >= minimum_valid_seeds:
            break
        seed_dir = output / f"seed_{seed}"
        seed_dir.mkdir()
        try:
            a_variant = _run_a(
                baseline, a_completion, a_layout, a_abi, seed_dir / "A_BASELINE",
                seed, cycles, selected_checkpoints, timeout_seconds,
            )
            generated_run = run_generated_bcd_seed(
                generated, seed_dir / "generated", seed=seed, cycles=cycles,
                checkpoints=selected_checkpoints, timeout_seconds=timeout_seconds,
            ).report
            valid.append({
                "seed": seed,
                "A_BASELINE": a_variant,
                **{str(item["mode"]): item for item in generated_run["variants"]},
                "generated_report": str(seed_dir / "generated/bcd_report.json"),
            })
        except Exception as exc:
            invalid.append({"seed": seed, "reason": str(exc), "tuple_excluded": True})
            _write_json(seed_dir / "tuple_status.json", {
                "schema": "myfuzz.abcd-tuple-status/v1", "status": "infrastructure_invalid",
                "seed": seed, "reason": str(exc),
            })
    if len(valid) < minimum_valid_seeds:
        report = _base_report(
            cycles, selected_checkpoints, a_completion, g_completion, a_catalog,
            valid, invalid, status="insufficient_valid_tuples",
        )
        _write_json(output / "abcd_campaign_report.json", report)
        raise InputValidationError(
            f"A/B/C/D campaign produced {len(valid)} valid tuples; {minimum_valid_seeds} required"
        )

    variant_names = ("A_BASELINE", *(name for name, _value in GENERATED_MODES))
    variants = {
        name: _aggregate(name, [item[name] for item in valid], [int(item["seed"]) for item in valid])
        for name in variant_names
    }
    report = {
        **_base_report(
            cycles, selected_checkpoints, a_completion, g_completion, a_catalog,
            valid, invalid, status="valid",
        ),
        "variants": variants,
        "paired_tuples": [{
            "seed": item["seed"],
            "A_BASELINE": item["A_BASELINE"],
            **{name: item[name] for name, _value in GENERATED_MODES},
        } for item in valid],
    }
    _write_json(output / "abcd_campaign_report.json", report)
    return report


def _run_a(
    target: Path,
    completion: Mapping[str, object],
    layout: Mapping[str, object],
    abi: Mapping[str, object],
    output: Path,
    seed: int,
    cycles: int,
    checkpoints: tuple[int, ...],
    timeout_seconds: float,
) -> Mapping[str, object]:
    output.mkdir()
    bytes_per_cycle = int(layout["bytes_per_cycle"])
    cycle_width = int(layout["cycle_width"])
    coverage_width = int(abi["width"])
    coverage_bytes = (coverage_width + 7) // 8
    rawbits = _a_rawbits(seed, cycles, bytes_per_cycle)
    rawbits_path = output / "baseline_a.rawbits"
    rawbits_path.write_bytes(rawbits)
    coverage = output / "coverage.bin"
    trace_path = output / "coverage_trace.bin"
    metrics_path = output / "metrics.json"
    command = [
        str(target / "bin/myfuzz_target"), str(rawbits_path), str(cycles), "0",
        str(coverage), str(trace_path), str(metrics_path),
    ]
    completed = subprocess.run(
        command, cwd=target, capture_output=True, text=True, timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise InputValidationError(
            f"scheme A failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    frozen = coverage.read_bytes()
    trace = trace_path.read_bytes()
    if len(frozen) != coverage_bytes or len(trace) != cycles * coverage_bytes:
        raise InputValidationError("scheme A returned invalid coverage sizes")
    if frozen != trace[-coverage_bytes:]:
        raise InputValidationError("scheme A bitmap was not frozen at the final measured edge")
    metrics = _read_json(metrics_path)
    if (metrics.get("schema") != "myfuzz.fixed-dut-cycle-metrics/v1"
            or int(metrics.get("dut_cycles", -1)) != cycles
            or int(metrics.get("accepted_records", -1)) + int(metrics.get("stall_cycles", -1)) != cycles):
        raise InputValidationError("scheme A returned invalid fixed-cycle metrics")
    hits = _hit_counts(trace, cycles, coverage_bytes)
    plateau_window = max(1, cycles // 10)
    plateau_start = max(0, cycles - plateau_window) - 1
    return {
        "mode": "A_BASELINE", "status": "valid", "rng_domain": "A",
        "rng_algorithm": "sha256-counter-v1", "rawbits_sha256": _sha256(rawbits),
        "target_digest": completion["target_digest"],
        "layout_digest": layout["digest"],
        "coverage_abi_digest": completion["coverage_abi_digest"],
        "accepted_records": int(metrics["accepted_records"]),
        "stall_cycles": int(metrics["stall_cycles"]),
        "unconsumed_records": int(metrics["unconsumed_records"]),
        "accepted_raw_bits": int(metrics["accepted_records"]) * cycle_width,
        "executed_operations": None,
        "operation_semantics": "not_applicable_direct_bit_drive",
        "throughput_records_per_cycle": int(metrics["accepted_records"]) / cycles,
        "final_coverage_hits": hits[-1], "coverage_points": coverage_width,
        "coverage_fraction": hits[-1] / coverage_width,
        "coverage_curve": _coverage_curve(trace, cycles, coverage_bytes, checkpoints),
        "coverage_auc_hits": sum(hits),
        "first_hit_cycle_by_offset": _first_hits(trace, cycles, coverage_bytes, coverage_width),
        "plateau_window_cycles": plateau_window,
        "plateau_gain": hits[-1] - (hits[plateau_start] if plateau_start >= 0 else 0),
        "coverage_sha256": _sha256(frozen), "coverage_trace_sha256": _sha256(trace),
    }


def _aggregate(name: str, values: Sequence[Mapping[str, object]], seeds: Sequence[int]) -> Mapping[str, object]:
    first_hits: dict[str, list[int]] = {}
    for value in values:
        for offset, cycle in value["first_hit_cycle_by_offset"].items():
            first_hits.setdefault(str(offset), []).append(int(cycle))
    numeric = (
        "final_coverage_hits", "coverage_auc_hits", "plateau_gain", "accepted_records",
        "stall_cycles", "unconsumed_records", "accepted_raw_bits",
    )
    result: dict[str, object] = {
        "mode": name, "seed_count": len(values), "coverage_points": values[0]["coverage_points"],
        "first_hit_cycle_distribution": dict(sorted(first_hits.items())),
        "coverage_curves": [
            {"seed": seed, "curve": value["coverage_curve"]}
            for seed, value in zip(seeds, values)
        ],
    }
    for field in numeric:
        items = [int(value[field]) for value in values]
        result[field] = items
        result[f"median_{field}"] = statistics.median(items)
    operations = [value.get("executed_operations") for value in values]
    result["executed_operations"] = operations
    if all(item is not None for item in operations):
        result["median_executed_operations"] = statistics.median(int(item) for item in operations)
    result["throughput_records_per_cycle"] = [
        int(value["accepted_records"]) / (int(value["accepted_records"]) + int(value["stall_cycles"]))
        for value in values
    ]
    result["median_throughput_records_per_cycle"] = statistics.median(
        result["throughput_records_per_cycle"]
    )
    return result


def _base_report(cycles, checkpoints, a_completion, g_completion, catalog, valid, invalid, *, status):
    return {
        "schema": "myfuzz.abcd-campaign/v2", "status": status,
        "execution": "serial_A_then_B_then_C_then_D", "branch_coverage_only": True,
        "cycles": cycles, "checkpoints": list(checkpoints),
        "valid_seeds": [item["seed"] for item in valid], "invalid_tuples": invalid,
        "rng_domains": {"A_BASELINE": "A", "B_C_D": "GENERATED"},
        "coverage_point_catalog": catalog,
        "targets": {
            "A_BASELINE": {
                "target_digest": a_completion["target_digest"],
                "runner_schema": a_completion["runner_schema"],
                "coverage_abi_digest": a_completion["coverage_abi_digest"],
            },
            "B_C_D": {
                "target_digest": g_completion["target_digest"],
                "runner_schema": g_completion["runner_schema"],
                "coverage_abi_digest": g_completion["coverage_abi_digest"],
                "soc_digest": g_completion.get("soc_digest"),
                "constraint_digest": g_completion.get("constraint_digest"),
                "boot_rom_sha256": g_completion.get("boot_rom_sha256"),
            },
        },
    }


def _a_rawbits(seed: int, cycles: int, bytes_per_cycle: int) -> bytes:
    output = bytearray()
    for cycle in range(cycles):
        block = bytearray()
        counter = 0
        while len(block) < bytes_per_cycle:
            block.extend(hashlib.sha256(
                b"myfuzz.baseline-a-rawbits/v1\0" + seed.to_bytes(8, "little")
                + cycle.to_bytes(8, "little") + counter.to_bytes(4, "little")
            ).digest())
            counter += 1
        output.extend(block[:bytes_per_cycle])
    return bytes(output)


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise InputValidationError(f"JSON artifact must contain an object: {path}")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
