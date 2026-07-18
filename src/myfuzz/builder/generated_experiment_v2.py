"""Paired, cycle-budgeted B/C/D execution and replay for one generated target."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
from typing import Mapping, Sequence

from .input_model import InputValidationError
from .rfuzz_campaign import _load_target_contract, _validate_generated_metrics


GENERATED_MODES = (
    ("B_GENERATED_RAW", 0),
    ("C_PROTOCOL_SAFE", 1),
    ("D_SCENARIO_CONSTRAINED", 2),
)


@dataclass(frozen=True)
class GeneratedBCDRun:
    output_dir: str
    report: Mapping[str, object]


@dataclass(frozen=True)
class GeneratedBCDCampaign:
    output_dir: str
    report: Mapping[str, object]


def run_generated_bcd_campaign(
    target_dir: str | Path,
    output_dir: str | Path,
    *,
    seeds: Sequence[int],
    cycles: int,
    checkpoints: Sequence[int] = (),
    timeout_seconds: float = 30.0,
) -> GeneratedBCDCampaign:
    """Run at least ten paired seeds serially and aggregate branch-only metrics."""
    if any(isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds):
        raise InputValidationError("generated B/C/D campaign seeds must be integers")
    selected = tuple(seeds)
    if len(selected) < 10 or len(set(selected)) != len(selected) or any(seed < 0 for seed in selected):
        raise InputValidationError("generated B/C/D campaign requires at least ten unique non-negative seeds")
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"generated campaign output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    runs = []
    for seed in selected:
        result = run_generated_bcd_seed(
            target_dir, output / f"seed_{seed}", seed=seed, cycles=cycles,
            checkpoints=checkpoints, timeout_seconds=timeout_seconds,
        )
        runs.append(result.report)
    tuple_keys = (
        "target_digest", "layout_digest", "soc_digest", "constraint_digest",
        "coverage_abi_digest", "boot_rom_sha256",
    )
    for key in tuple_keys:
        if len({run.get(key) for run in runs}) != 1:
            raise InputValidationError(f"generated campaign changed immutable tuple field {key}")
    variants = {}
    for mode, _value in GENERATED_MODES:
        values = [next(item for item in run["variants"] if item["mode"] == mode) for run in runs]
        first_hit_cycles: dict[str, list[int]] = {}
        for value in values:
            for offset, cycle in value["first_hit_cycle_by_offset"].items():
                first_hit_cycles.setdefault(str(offset), []).append(int(cycle))
        variants[mode] = {
            "seed_count": len(values),
            "coverage_points": values[0]["coverage_points"],
            "final_coverage_hits": [value["final_coverage_hits"] for value in values],
            "median_final_coverage_hits": statistics.median(
                int(value["final_coverage_hits"]) for value in values
            ),
            "coverage_auc_hits": [value["coverage_auc_hits"] for value in values],
            "median_coverage_auc_hits": statistics.median(
                int(value["coverage_auc_hits"]) for value in values
            ),
            "plateau_gain": [value["plateau_gain"] for value in values],
            "median_plateau_gain": statistics.median(
                int(value["plateau_gain"]) for value in values
            ),
            "first_hit_cycle_distribution": dict(sorted(first_hit_cycles.items())),
            "coverage_curves": [
                {"seed": run["seed"], "curve": value["coverage_curve"]}
                for run, value in zip(runs, values)
            ],
        }
    report = {
        "schema": "myfuzz.generated-bcd-campaign/v1",
        "status": "valid",
        "seeds": list(selected),
        "cycles": cycles,
        "execution": "serial",
        "branch_coverage_only": True,
        "shared_binary": True,
        "shared_ordered_input_bytes_per_seed": True,
        **{key: runs[0].get(key) for key in tuple_keys},
        "variants": variants,
        "runs": [str(Path(run["rawbits"]).parent / "bcd_report.json") for run in runs],
    }
    _write_json(output / "bcd_campaign_report.json", report)
    return GeneratedBCDCampaign(output.as_posix(), report)


def run_generated_bcd_seed(
    target_dir: str | Path,
    output_dir: str | Path,
    *,
    seed: int,
    cycles: int,
    checkpoints: Sequence[int] = (),
    timeout_seconds: float = 30.0,
) -> GeneratedBCDRun:
    """Run B, C, then D over one immutable v3 byte stream and target binary."""
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise InputValidationError("generated experiment seed must be a non-negative integer")
    if isinstance(cycles, bool) or not isinstance(cycles, int) or cycles <= 0:
        raise InputValidationError("generated experiment cycles must be positive")
    if timeout_seconds <= 0:
        raise InputValidationError("generated experiment timeout must be positive")
    selected_checkpoints = _checkpoints(cycles, checkpoints)
    target, completion, layout, abi = _load_target_contract(target_dir)
    if layout.get("schema") != "myfuzz.rawbits-layout/v3":
        raise InputValidationError("generated B/C/D experiment requires RawBits layout v3")
    if completion.get("runner_schema") != "myfuzz.generated-target-runner/v2":
        raise InputValidationError("generated B/C/D experiment requires the v2 cycle-budget runner")
    bytes_per_cycle = int(layout["bytes_per_cycle"])
    cycle_width = int(layout["cycle_width"])
    coverage_width = int(abi["width"])
    coverage_bytes = (coverage_width + 7) // 8
    rawbits = _generated_rawbits(seed, cycles, cycle_width, bytes_per_cycle)
    rawbits_sha256 = _sha256(rawbits)

    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"generated experiment output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    rawbits_path = output / "generated.rawbits"
    rawbits_path.write_bytes(rawbits)
    variants: list[Mapping[str, object]] = []
    try:
        for mode_name, mode_value in GENERATED_MODES:
            variants.append(_run_variant(
                target, completion, layout, rawbits_path, rawbits_sha256, output,
                mode_name, mode_value, seed, cycles, cycle_width, coverage_width,
                coverage_bytes, selected_checkpoints, timeout_seconds,
            ))
    except Exception:
        _write_json(output / "tuple_status.json", {
            "schema": "myfuzz.generated-bcd-tuple-status/v1",
            "status": "infrastructure_invalid",
            "seed": seed,
            "target_digest": completion["target_digest"],
            "rawbits_sha256": rawbits_sha256,
        })
        raise
    report = {
        "schema": "myfuzz.generated-bcd-run/v1",
        "status": "valid",
        "seed": seed,
        "cycles": cycles,
        "rng_domain": "GENERATED",
        "rng_algorithm": "sha256-counter-v1",
        "rawbits": rawbits_path.as_posix(),
        "rawbits_sha256": rawbits_sha256,
        "target_digest": completion["target_digest"],
        "layout_digest": layout["digest"],
        "soc_digest": completion.get("soc_digest"),
        "constraint_digest": completion.get("constraint_digest"),
        "coverage_abi_digest": completion["coverage_abi_digest"],
        "boot_rom_sha256": completion.get("boot_rom_sha256"),
        "shared_binary": True,
        "shared_ordered_input_bytes": True,
        "execution_order": [name for name, _value in GENERATED_MODES],
        "checkpoints": list(selected_checkpoints),
        "variants": variants,
    }
    _write_json(output / "bcd_report.json", report)
    return GeneratedBCDRun(output.as_posix(), report)


def replay_generated_variant(
    bundle_path: str | Path,
    output_dir: str | Path,
    *,
    timeout_seconds: float = 30.0,
) -> Mapping[str, object]:
    """Re-execute one saved variant bundle and require byte/metric/bitmap identity."""
    bundle = _read_json(Path(bundle_path).resolve(strict=True))
    if bundle.get("schema") != "myfuzz.generated-replay-bundle/v1":
        raise InputValidationError("generated replay bundle schema mismatch")
    target = Path(str(bundle["target_dir"])).resolve(strict=True)
    completion = _read_json(target / "completion_manifest.json")
    if completion.get("target_digest") != bundle.get("target_digest"):
        raise InputValidationError("generated replay target digest mismatch")
    rawbits = Path(str(bundle["rawbits"])).resolve(strict=True)
    if _sha256(rawbits.read_bytes()) != bundle.get("rawbits_sha256"):
        raise InputValidationError("generated replay RawBits digest mismatch")
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"generated replay output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    coverage = output / "coverage.bin"
    trace = output / "coverage_trace.bin"
    metrics = output / "metrics.json"
    command = [
        (target / "bin/myfuzz_target").as_posix(), rawbits.as_posix(),
        str(bundle["cycles"]), str(bundle["mode_value"]), coverage.as_posix(),
        trace.as_posix(), metrics.as_posix(),
    ]
    completed = subprocess.run(
        command, cwd=target, capture_output=True, text=True, timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise InputValidationError(
            f"generated replay failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    actual = {
        "coverage_sha256": _sha256(coverage.read_bytes()),
        "coverage_trace_sha256": _sha256(trace.read_bytes()),
        "metrics_sha256": _sha256(metrics.read_bytes()),
    }
    expected = bundle.get("expected")
    if not isinstance(expected, Mapping) or actual != dict(expected):
        raise InputValidationError("generated replay result differs from the frozen bundle")
    report = {
        "schema": "myfuzz.generated-replay-result/v1",
        "status": "reproduced",
        "bundle": Path(bundle_path).resolve().as_posix(),
        **actual,
    }
    _write_json(output / "replay_report.json", report)
    return report


def _run_variant(
    target: Path,
    completion: Mapping[str, object],
    layout: Mapping[str, object],
    rawbits: Path,
    rawbits_sha256: str,
    output: Path,
    mode_name: str,
    mode_value: int,
    seed: int,
    cycles: int,
    cycle_width: int,
    coverage_width: int,
    coverage_bytes: int,
    checkpoints: tuple[int, ...],
    timeout_seconds: float,
) -> Mapping[str, object]:
    mode_dir = output / mode_name
    mode_dir.mkdir()
    coverage = mode_dir / "coverage.bin"
    trace = mode_dir / "coverage_trace.bin"
    metrics_path = mode_dir / "metrics.json"
    command = [
        (target / "bin/myfuzz_target").as_posix(), rawbits.as_posix(), str(cycles),
        str(mode_value), coverage.as_posix(), trace.as_posix(), metrics_path.as_posix(),
    ]
    completed = subprocess.run(
        command, cwd=target, capture_output=True, text=True, timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise InputValidationError(
            f"generated variant {mode_name} failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    frozen = coverage.read_bytes()
    trace_bytes = trace.read_bytes()
    if len(frozen) != coverage_bytes or len(trace_bytes) != cycles * coverage_bytes:
        raise InputValidationError(f"generated variant {mode_name} returned invalid coverage sizes")
    if frozen != trace_bytes[-coverage_bytes:]:
        raise InputValidationError(f"generated variant {mode_name} froze a post-measurement bitmap")
    metrics = _read_json(metrics_path)
    _validate_generated_metrics(metrics, cycles)
    accepted = int(metrics["accepted_records"])
    bytes_per_cycle = int(layout["bytes_per_cycle"])
    tail = rawbits.read_bytes()[accepted * bytes_per_cycle:]
    curve = _coverage_curve(trace_bytes, cycles, coverage_bytes, checkpoints)
    hit_counts = _hit_counts(trace_bytes, cycles, coverage_bytes)
    first_hits = _first_hits(trace_bytes, cycles, coverage_bytes, coverage_width)
    plateau_window = max(1, cycles // 10)
    plateau_gain = hit_counts[-1] - hit_counts[max(0, cycles - plateau_window) - 1] if cycles > plateau_window else hit_counts[-1]
    metrics_sha256 = _sha256(metrics_path.read_bytes())
    bundle = {
        "schema": "myfuzz.generated-replay-bundle/v1",
        "target_dir": target.as_posix(),
        "target_digest": completion["target_digest"],
        "layout_digest": layout["digest"],
        "soc_digest": completion.get("soc_digest"),
        "constraint_digest": completion.get("constraint_digest"),
        "coverage_abi_digest": completion["coverage_abi_digest"],
        "boot_rom_sha256": completion.get("boot_rom_sha256"),
        "seed": seed,
        "cycles": cycles,
        "mode": mode_name,
        "mode_value": mode_value,
        "rawbits": rawbits.resolve().as_posix(),
        "rawbits_sha256": rawbits_sha256,
        "expected": {
            "coverage_sha256": _sha256(frozen),
            "coverage_trace_sha256": _sha256(trace_bytes),
            "metrics_sha256": metrics_sha256,
        },
    }
    bundle_path = mode_dir / "replay_bundle.json"
    _write_json(bundle_path, bundle)
    return {
        "mode": mode_name,
        "mode_value": mode_value,
        "status": "valid",
        "accepted_records": accepted,
        "acceptance_cycles": metrics["acceptance_cycles"],
        "stall_cycles": metrics["stall_cycles"],
        "executed_operations": metrics["executed_operations"],
        "operation_cycles": metrics["operation_cycles"],
        "unconsumed_records": metrics["unconsumed_records"],
        "unconsumed_tail_sha256": _sha256(tail),
        "teardown_cycles": metrics["teardown_cycles"],
        "accepted_raw_bits": accepted * cycle_width,
        "final_coverage_hits": hit_counts[-1],
        "coverage_points": coverage_width,
        "coverage_fraction": hit_counts[-1] / coverage_width,
        "coverage_curve": curve,
        "coverage_auc_hits": sum(hit_counts),
        "first_hit_cycle_by_offset": first_hits,
        "plateau_window_cycles": plateau_window,
        "plateau_gain": plateau_gain,
        "coverage_sha256": _sha256(frozen),
        "coverage_trace_sha256": _sha256(trace_bytes),
        "metrics_sha256": metrics_sha256,
        "replay_bundle": bundle_path.as_posix(),
    }


def _generated_rawbits(seed: int, cycles: int, cycle_width: int, bytes_per_cycle: int) -> bytes:
    output = bytearray()
    for cycle in range(cycles):
        block = bytearray()
        counter = 0
        while len(block) < bytes_per_cycle:
            block.extend(hashlib.sha256(
                b"myfuzz.generated-rawbits/v1\0"
                + seed.to_bytes(8, "little")
                + cycle.to_bytes(8, "little")
                + counter.to_bytes(4, "little")
            ).digest())
            counter += 1
        value = block[:bytes_per_cycle]
        if cycle_width % 8:
            value[-1] &= (1 << (cycle_width % 8)) - 1
        output.extend(value)
    return bytes(output)


def _checkpoints(cycles: int, values: Sequence[int]) -> tuple[int, ...]:
    if not values:
        values = (max(1, cycles // 4), max(1, cycles // 2), max(1, 3 * cycles // 4), cycles)
    result = tuple(sorted(set(int(value) for value in values)))
    if not result or result[-1] != cycles or any(value <= 0 or value > cycles for value in result):
        raise InputValidationError("generated experiment checkpoints must be in 1..cycles and include cycles")
    return result


def _hit_counts(trace: bytes, cycles: int, coverage_bytes: int) -> list[int]:
    return [
        sum(byte.bit_count() for byte in trace[index * coverage_bytes:(index + 1) * coverage_bytes])
        for index in range(cycles)
    ]


def _coverage_curve(
    trace: bytes, cycles: int, coverage_bytes: int, checkpoints: tuple[int, ...],
) -> list[Mapping[str, int]]:
    counts = _hit_counts(trace, cycles, coverage_bytes)
    return [{"cycle": cycle, "hits": counts[cycle - 1]} for cycle in checkpoints]


def _first_hits(trace: bytes, cycles: int, coverage_bytes: int, coverage_width: int) -> Mapping[str, int]:
    result: dict[str, int] = {}
    for cycle in range(cycles):
        bitmap = trace[cycle * coverage_bytes:(cycle + 1) * coverage_bytes]
        for bit in range(coverage_width):
            key = str(bit)
            if key not in result and bitmap[bit // 8] & (1 << (bit % 8)):
                result[key] = cycle + 1
    return result


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot read generated experiment JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputValidationError(f"generated experiment JSON must contain an object: {path}")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode() + b"\n")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
