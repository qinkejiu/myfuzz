#!/usr/bin/env python3
"""Run CVA6 scheme1 vs scheme4 for a resumable 10h comparison."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - for older remote Pythons.
    tomllib = None


SCHEMES = [
    {
        "scheme": "scheme1",
        "label": "scheme1_baseline",
        "config": "configs/designs/cva6/config.json",
        "reuse_out_dir": "runs/designs/cva6",
        "description": "Top-level CVA6 baseline with fully random top-level inputs.",
    },
    {
        "scheme": "scheme4",
        "label": "scheme4_lightweight_plus",
        "config": "configs/designs/cva6_lightweight_plus/config.json",
        "reuse_out_dir": "runs/designs/cva6_lightweight_plus",
        "description": "Top-level CVA6 with structured NoC/AXI, CV-X-IF, interrupt, and debug constraints.",
    },
]

CSV_FIELDS = [
    "sample_kind",
    "slice_index",
    "hour_index",
    "target_elapsed_wall_s",
    "timestamp",
    "elapsed_wall_s",
    "slice_elapsed_wall_s",
    "scheme",
    "label",
    "alive",
    "returncode",
    "pid",
    "cpu_set",
    "tests_total",
    "tests_per_s",
    "slice_tests_total",
    "slice_tests_per_s",
    "cycles_total",
    "cycles_per_s",
    "slice_cycles_total",
    "slice_cycles_per_s",
    "discoveries",
    "queue_entries",
    "common_covered",
    "common_total",
    "common_pct",
    "queue_union_common_covered",
    "queue_union_common_pct",
    "all_toml_covered",
    "all_toml_total",
    "all_toml_pct",
    "bitmap_len",
    "latest_source",
    "input_directory",
    "run_root",
    "out_dir",
    "runner_log",
]


def duration_label(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds}s"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def parse_toml_string_value(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1].replace('\\"', '"')
    return raw


def load_coverage_items(path: Path) -> list[dict]:
    if tomllib is not None:
        data = tomllib.load(path.open("rb"))
        return list(data.get("coverage", []))

    items: list[dict] = []
    current: dict | None = None
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if line == "[[coverage]]":
            if current is not None:
                items.append(current)
            current = {}
            continue
        if current is None or "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in {"index", "line", "column"}:
            try:
                current[key] = int(value)
            except ValueError:
                current[key] = value
        else:
            current[key] = parse_toml_string_value(value)
    if current is not None:
        items.append(current)
    return items


def coverage_toml_for(out_dir: Path, top: str) -> Path:
    harness_toml = out_dir / "harness" / f"{top}.rfuzz.toml"
    if harness_toml.exists():
        return harness_toml
    return out_dir / "instrumented" / f"{top}.toml"


def coverage_module(item: dict) -> str:
    human = str(item.get("human") or "")
    if human:
        return human.split()[0]
    signal = str(item.get("signal") or "")
    if signal:
        return signal.split(".")[0]
    return ""


def contiguous_groups(indices: list[int]) -> list[list[int]]:
    groups: list[list[int]] = []
    if not indices:
        return groups
    start = prev = indices[0]
    for index in indices[1:]:
        if index == prev + 1:
            prev = index
            continue
        groups.append([start, prev, prev - start + 1])
        start = prev = index
    groups.append([start, prev, prev - start + 1])
    return groups


def symlink_reuse_outputs(reuse_out_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for item in ["frontend.json", "instrumented", "harness", "server"]:
        src = reuse_out_dir / item
        dst = out_dir / item
        if not src.exists():
            raise FileNotFoundError(f"missing reusable output: {src}")
        if dst.exists() or dst.is_symlink():
            if dst.is_dir() and not dst.is_symlink():
                shutil.rmtree(dst)
            else:
                dst.unlink()
        dst.symlink_to(src.resolve())


def queue_has_entries(queue_dir: Path) -> bool:
    return queue_dir.exists() and any(queue_dir.glob("entry_*.json"))


def latest_previous_queue(root: Path, run_root: Path, label: str, slice_index: int) -> Path | None:
    for previous in range(slice_index - 1, -1, -1):
        queue = (
            root
            / "runs"
            / "managed_runs"
            / run_root.name
            / "slices"
            / f"slice_{previous:04d}"
            / "designs"
            / label
            / "queue"
        )
        if queue_has_entries(queue):
            return queue
    return None


def prepare_scheme(root: Path, run_root: Path, slice_index: int, scheme: dict, args: argparse.Namespace) -> dict:
    base_config_path = root / scheme["config"]
    base_config = load_json(base_config_path)
    top = str(base_config["top"])
    reuse_out_dir = root / scheme["reuse_out_dir"]
    server = reuse_out_dir / "server" / "server"
    if not server.exists() or not os.access(server, os.X_OK):
        raise FileNotFoundError(f"missing executable server: {server}")
    if not (reuse_out_dir / "harness").exists():
        raise FileNotFoundError(f"missing harness directory: {reuse_out_dir / 'harness'}")

    out_dir_rel = (
        Path("runs")
        / "managed_runs"
        / run_root.name
        / "slices"
        / f"slice_{slice_index:04d}"
        / "designs"
        / scheme["label"]
    )
    out_dir = root / out_dir_rel
    symlink_reuse_outputs(reuse_out_dir, out_dir)

    config = dict(base_config)
    config["name"] = f"{run_root.name}_slice_{slice_index:04d}_{scheme['label']}"
    config["out_dir"] = out_dir_rel.as_posix()
    fuzz = dict(config.get("fuzz") or {})
    fuzz["max_runs"] = int(args.max_runs)
    fuzz["crash_restarts"] = int(args.crash_restarts)
    fuzz["stop_on_crash"] = False
    fuzz["seed_cycles"] = int(args.seed_cycles)
    fuzz["max_cycles"] = max(int(fuzz.get("max_cycles", args.max_cycles) or args.max_cycles), int(args.seed_cycles))
    fuzz["server_count"] = 1
    fuzz["save_latest_every_runs"] = int(args.save_latest_every_runs)

    input_queue = None
    if not args.no_replay_previous_queue:
        input_queue = latest_previous_queue(root, run_root, scheme["label"], slice_index)
        if input_queue is not None:
            fuzz["input_directory"] = str(input_queue.relative_to(root))
    config["fuzz"] = fuzz

    config_path = run_root / "configs" / f"slice_{slice_index:04d}" / f"{scheme['label']}.json"
    write_json(config_path, config)

    toml_path = coverage_toml_for(out_dir, top)
    if not toml_path.exists():
        raise FileNotFoundError(f"missing coverage TOML: {toml_path}")

    return {
        **scheme,
        "top": top,
        "config_path": config_path,
        "out_dir": out_dir,
        "out_dir_rel": out_dir_rel.as_posix(),
        "reuse_out_dir_abs": reuse_out_dir,
        "toml_path": toml_path,
        "input_directory": input_queue,
    }


def compute_common_indices(prepared: list[dict], exclude_top_bits: int, exclude_module_label: str) -> dict:
    per_scheme: dict[str, set[int]] = {}
    all_toml_per_scheme: dict[str, set[int]] = {}
    coverage_counts: dict[str, dict] = {}
    for item in prepared:
        coverage = load_coverage_items(Path(item["toml_path"]))
        all_indices = {int(point["index"]) for point in coverage}
        if not all_indices:
            raise RuntimeError(f"no coverage indices found in {item['toml_path']}")
        coverage_width = max(all_indices) + 1
        if exclude_top_bits < 0 or exclude_top_bits >= coverage_width:
            raise ValueError(f"--exclude-top-bits={exclude_top_bits} is invalid for width {coverage_width}")

        excluded = set(range(coverage_width - exclude_top_bits, coverage_width))
        included = set(range(0, coverage_width - exclude_top_bits))
        label_excluded = {
            int(point["index"])
            for point in coverage
            if coverage_module(point) == exclude_module_label
        }
        per_scheme[item["scheme"]] = included
        all_toml_per_scheme[item["scheme"]] = set(range(coverage_width))
        coverage_counts[item["scheme"]] = {
            "toml": str(Path(item["toml_path"])),
            "coverage_total": coverage_width,
            "excluded_top_bits": exclude_top_bits,
            "excluded_actual_bit_count": len(excluded),
            "excluded_actual_bit_groups": contiguous_groups(sorted(excluded)),
            "included_count": len(included),
            "metadata_label_audit": {
                "module_label": exclude_module_label,
                "label_count": len(label_excluded),
                "label_index_groups": contiguous_groups(sorted(label_excluded)),
                "note": "Audit only. CVA6 comparison defaults to excluding 0 actual bits.",
            },
        }
    return {
        "common_indices": sorted(set.intersection(*per_scheme.values())),
        "all_toml_indices_union": sorted(set.union(*all_toml_per_scheme.values())),
        "coverage_counts": coverage_counts,
    }


def stats_number(stats: dict, group: str, field: str) -> float | None:
    value = stats.get(group)
    if not isinstance(value, dict):
        return None
    raw = value.get(field)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def discoveries(stats: dict) -> int:
    mutators = stats.get("mutators")
    if not isinstance(mutators, list):
        return 0
    total = 0
    for item in mutators:
        if isinstance(item, dict):
            total += int(item.get("discovery_count") or 0)
    return total


def load_latest_stats(queue_dir: Path) -> tuple[dict, str | None]:
    latest = queue_dir / "latest.json"
    if latest.exists():
        try:
            return load_json(latest), "latest.json"
        except json.JSONDecodeError:
            pass
    entries = sorted(queue_dir.glob("entry_*.json"))
    if entries:
        try:
            data = load_json(entries[-1])
            return dict(data.get("stats") or {}), entries[-1].name
        except json.JSONDecodeError:
            return {}, entries[-1].name
    return {}, None


def load_latest_batch_counts(out_dir: Path) -> tuple[int | None, int | None, str | None]:
    latest_batch = out_dir / "latest" / "latest_batch.json"
    if not latest_batch.exists():
        return None, None, None
    try:
        data = load_json(latest_batch)
    except json.JSONDecodeError:
        return None, None, "latest/latest_batch.json"
    tests = data.get("test_count")
    cycles = data.get("total_cycles")
    try:
        tests_i = int(tests) if tests is not None else None
    except (TypeError, ValueError):
        tests_i = None
    try:
        cycles_i = int(cycles) if cycles is not None else None
    except (TypeError, ValueError):
        cycles_i = None
    return tests_i, cycles_i, "latest/latest_batch.json"


def bitmap_covered_indices(bitmap: list, indices: set[int]) -> set[int]:
    covered: set[int] = set()
    for index in indices:
        if index < len(bitmap) and int(bitmap[index]) != 255:
            covered.add(index)
    return covered


def trace_covered_indices(trace: list, indices: set[int]) -> set[int]:
    covered: set[int] = set()
    for index in indices:
        if index < len(trace) and int(trace[index]) > 0:
            covered.add(index)
    return covered


def queue_covered_indices(queue_dir: Path, indices: set[int]) -> set[int]:
    covered: set[int] = set()
    stats, _source = load_latest_stats(queue_dir)
    bitmap = stats.get("bitmap") if isinstance(stats.get("bitmap"), list) else []
    covered.update(bitmap_covered_indices(bitmap, indices))
    for entry_path in sorted(queue_dir.glob("entry_*.json")):
        if len(covered) == len(indices):
            break
        try:
            data = load_json(entry_path)
        except json.JSONDecodeError:
            continue
        trace = data.get("trace_bits") or data.get("entry", {}).get("trace_bits") or []
        covered.update(trace_covered_indices(trace, indices - covered))
    return covered


def queue_entry_count(queue_dir: Path) -> int:
    return len(list(queue_dir.glob("entry_*.json")))


def slice_queue(root: Path, run_root: Path, slice_index: int, label: str) -> Path:
    return (
        root
        / "runs"
        / "managed_runs"
        / run_root.name
        / "slices"
        / f"slice_{slice_index:04d}"
        / "designs"
        / label
        / "queue"
    )


def cumulative_slice_stats(root: Path, run_root: Path, label: str, slice_index: int, current_queue: Path) -> dict:
    seen: set[Path] = set()
    tests_total = 0
    cycles_total = 0
    discoveries_total = 0
    queue_entries = 0
    bitmap_len = 0
    latest_sources: list[str] = []
    for index in range(slice_index + 1):
        queue_dir = slice_queue(root, run_root, index, label)
        if queue_dir in seen:
            continue
        seen.add(queue_dir)
        stats, source = load_latest_stats(queue_dir)
        if source is not None:
            latest_sources.append(f"slice_{index:04d}:{source}")
        tests = stats_number(stats, "tests_per_second", "global_numerator")
        cycles = stats_number(stats, "cycles_per_second", "global_numerator")
        if tests is None or int(tests) == 0:
            batch_tests, batch_cycles, batch_source = load_latest_batch_counts(queue_dir.parent)
            if batch_tests is not None and batch_tests > 0:
                tests = float(batch_tests)
                if batch_source is not None:
                    latest_sources.append(f"slice_{index:04d}:{batch_source}")
            if (cycles is None or int(cycles) == 0) and batch_cycles is not None:
                cycles = float(batch_cycles)
        tests_total += int(tests) if tests is not None else 0
        cycles_total += int(cycles) if cycles is not None else 0
        discoveries_total += discoveries(stats)
        queue_entries += queue_entry_count(queue_dir)
        bitmap = stats.get("bitmap") if isinstance(stats.get("bitmap"), list) else []
        bitmap_len = max(bitmap_len, len(bitmap))
    if current_queue not in seen:
        stats, source = load_latest_stats(current_queue)
        if source is not None:
            latest_sources.append(f"current:{source}")
        tests = stats_number(stats, "tests_per_second", "global_numerator")
        cycles = stats_number(stats, "cycles_per_second", "global_numerator")
        if tests is None or int(tests) == 0:
            batch_tests, batch_cycles, batch_source = load_latest_batch_counts(current_queue.parent)
            if batch_tests is not None and batch_tests > 0:
                tests = float(batch_tests)
                if batch_source is not None:
                    latest_sources.append(f"current:{batch_source}")
            if (cycles is None or int(cycles) == 0) and batch_cycles is not None:
                cycles = float(batch_cycles)
        tests_total += int(tests) if tests is not None else 0
        cycles_total += int(cycles) if cycles is not None else 0
        discoveries_total += discoveries(stats)
        queue_entries += queue_entry_count(current_queue)
        bitmap = stats.get("bitmap") if isinstance(stats.get("bitmap"), list) else []
        bitmap_len = max(bitmap_len, len(bitmap))
    return {
        "tests_total": tests_total,
        "cycles_total": cycles_total,
        "discoveries": discoveries_total,
        "queue_entries": queue_entries,
        "bitmap_len": bitmap_len,
        "latest_source": ";".join(latest_sources) if latest_sources else None,
    }


def cumulative_covered(
    root: Path,
    run_root: Path,
    label: str,
    slice_index: int,
    current_queue: Path,
    indices: list[int],
) -> set[int]:
    wanted = set(indices)
    covered: set[int] = set()
    seen: set[Path] = set()
    for index in range(slice_index + 1):
        queue_dir = slice_queue(root, run_root, index, label)
        if queue_dir in seen:
            continue
        seen.add(queue_dir)
        covered.update(queue_covered_indices(queue_dir, wanted - covered))
        if len(covered) == len(wanted):
            return covered
    if current_queue not in seen:
        covered.update(queue_covered_indices(current_queue, wanted - covered))
    return covered


def pct(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if denominator in (None, 0) or numerator is None:
        return None
    return 100.0 * float(numerator) / float(denominator)


def command_for_scheme(root: Path, info: dict, args: argparse.Namespace, cpu_set: str | None) -> list[str]:
    cmd = [
        "python3",
        "src/myfuzz/scripts/run_design_flow.py",
        "--config",
        str(Path(info["config_path"]).relative_to(root)),
        "--stage",
        "fuzz",
        "--jobs",
        "1",
        "--fuzz-seconds",
        str(args.slice_seconds),
    ]
    if args.nice is not None:
        cmd = ["nice", "-n", str(args.nice), *cmd]
    if cpu_set is not None:
        cmd = ["taskset", "-c", cpu_set, *cmd]
    if shutil.which("/usr/bin/time") or Path("/usr/bin/time").exists():
        cmd = ["/usr/bin/time", "-v", *cmd]
    return cmd


def choose_cpu_sets(count: int, requested: str | None) -> list[str | None]:
    if requested:
        sets = [part.strip() for part in requested.split(",") if part.strip()]
        if len(sets) != count:
            raise ValueError(f"--cpu-sets must contain exactly {count} comma-separated CPU sets")
        return sets
    if not shutil.which("taskset"):
        return [None] * count
    try:
        allowed = sorted(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    except AttributeError:
        allowed = list(range(os.cpu_count() or 0))
    if len(allowed) < count:
        return [None] * count
    return [str(index) for index in allowed[:count]]


def start_scheme(root: Path, run_root: Path, slice_index: int, info: dict, args: argparse.Namespace, cpu_set: str | None) -> dict:
    log_path = run_root / "logs" / f"slice_{slice_index:04d}_{info['label']}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("wb")
    cmd = command_for_scheme(root, info, args, cpu_set)
    log.write(("+ " + " ".join(cmd) + "\n").encode())
    log.flush()
    proc = subprocess.Popen(
        cmd,
        cwd=str(root),
        stdout=log,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    pid_path = run_root / "pids" / f"slice_{slice_index:04d}_{info['label']}.pid"
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(proc.pid) + "\n")
    return {
        **info,
        "cmd": cmd,
        "cpu_set": cpu_set,
        "proc": proc,
        "log_handle": log,
        "runner_log": log_path,
        "pid": proc.pid,
    }


def sample_scheme(
    root: Path,
    run_root: Path,
    run: dict,
    slice_index: int,
    started: float,
    completed_before_slice: int,
    hour_index: int,
    target_elapsed: int,
    sample_kind: str,
    indices: dict,
) -> dict:
    proc: subprocess.Popen = run["proc"]
    returncode = proc.poll()
    current_queue = Path(run["out_dir"]) / "queue"
    current_stats, _current_source = load_latest_stats(current_queue)
    common_indices = indices["common_indices"]
    all_indices = indices["all_toml_indices_union"]

    common_covered = cumulative_covered(
        root, run_root, run["label"], slice_index, current_queue, common_indices
    )
    all_covered = cumulative_covered(
        root, run_root, run["label"], slice_index, current_queue, all_indices
    )
    cumulative_stats = cumulative_slice_stats(root, run_root, run["label"], slice_index, current_queue)

    slice_tests = stats_number(current_stats, "tests_per_second", "global_numerator")
    slice_cycles = stats_number(current_stats, "cycles_per_second", "global_numerator")
    if slice_tests is None or int(slice_tests) == 0:
        batch_tests, batch_cycles, _batch_source = load_latest_batch_counts(Path(run["out_dir"]))
        if batch_tests is not None and batch_tests > 0:
            slice_tests = float(batch_tests)
        if (slice_cycles is None or int(slice_cycles) == 0) and batch_cycles is not None:
            slice_cycles = float(batch_cycles)
    elapsed_wall_s = completed_before_slice + int(time.time() - started)
    return {
        "sample_kind": sample_kind,
        "slice_index": slice_index,
        "hour_index": hour_index,
        "target_elapsed_wall_s": target_elapsed,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "elapsed_wall_s": elapsed_wall_s,
        "slice_elapsed_wall_s": int(time.time() - started),
        "scheme": run["scheme"],
        "label": run["label"],
        "alive": int(returncode is None),
        "returncode": returncode,
        "pid": run["pid"],
        "cpu_set": run["cpu_set"],
        "tests_total": cumulative_stats["tests_total"],
        "tests_per_s": stats_number(current_stats, "tests_per_second", "global"),
        "slice_tests_total": int(slice_tests) if slice_tests is not None else None,
        "slice_tests_per_s": stats_number(current_stats, "tests_per_second", "global"),
        "cycles_total": cumulative_stats["cycles_total"],
        "cycles_per_s": stats_number(current_stats, "cycles_per_second", "global"),
        "slice_cycles_total": int(slice_cycles) if slice_cycles is not None else None,
        "slice_cycles_per_s": stats_number(current_stats, "cycles_per_second", "global"),
        "discoveries": cumulative_stats["discoveries"],
        "queue_entries": cumulative_stats["queue_entries"],
        "common_covered": len(common_covered),
        "common_total": len(common_indices),
        "common_pct": pct(len(common_covered), len(common_indices)),
        "queue_union_common_covered": len(common_covered),
        "queue_union_common_pct": pct(len(common_covered), len(common_indices)),
        "all_toml_covered": len(all_covered),
        "all_toml_total": len(all_indices),
        "all_toml_pct": pct(len(all_covered), len(all_indices)),
        "bitmap_len": cumulative_stats["bitmap_len"],
        "latest_source": cumulative_stats["latest_source"],
        "input_directory": str(run["input_directory"]) if run.get("input_directory") else None,
        "run_root": str(run_root),
        "out_dir": str(run["out_dir"]),
        "runner_log": str(run["runner_log"]),
    }


def append_sample(run_root: Path, rows: list[dict]) -> None:
    csv_path = run_root / "hourly_common_coverage.csv"
    jsonl_path = run_root / "hourly_common_coverage.jsonl"
    write_header = not csv_path.exists()
    with csv_path.open("a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in CSV_FIELDS})
    with jsonl_path.open("a") as jsonl_file:
        for row in rows:
            jsonl_file.write(json.dumps(row, sort_keys=True) + "\n")


def sample_all(
    root: Path,
    run_root: Path,
    runs: list[dict],
    slice_index: int,
    started: float,
    completed_before_slice: int,
    hour_index: int,
    target_elapsed: int,
    sample_kind: str,
    indices: dict,
    append: bool = True,
) -> list[dict]:
    rows = [
        sample_scheme(
            root,
            run_root,
            run,
            slice_index,
            started,
            completed_before_slice,
            hour_index,
            target_elapsed,
            sample_kind,
            indices,
        )
        for run in runs
    ]
    if append:
        append_sample(run_root, rows)
    write_json(run_root / "latest_sample.json", {"rows": rows})
    return rows


def terminate_alive(runs: list[dict]) -> None:
    alive = [run for run in runs if run["proc"].poll() is None]
    for sig, delay in [(signal.SIGINT, 5), (signal.SIGTERM, 5), (signal.SIGKILL, 0)]:
        if not alive:
            return
        for run in alive:
            try:
                os.killpg(run["proc"].pid, sig)
            except ProcessLookupError:
                pass
        if delay:
            time.sleep(delay)
        alive = [run for run in runs if run["proc"].poll() is None]


def close_logs(runs: list[dict]) -> None:
    for run in runs:
        try:
            run["log_handle"].close()
        except Exception:
            pass


def wait_for_children(runs: list[dict], grace_seconds: int) -> None:
    deadline = time.time() + grace_seconds
    for run in runs:
        remaining = max(0.0, deadline - time.time())
        try:
            run["proc"].wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass
    terminate_alive(runs)


def max_completed_elapsed(run_root: Path, sample_interval: int) -> int:
    csv_path = run_root / "hourly_common_coverage.csv"
    if not csv_path.exists():
        return 0
    completed = 0
    with csv_path.open(newline="") as csv_file:
        for row in csv.DictReader(csv_file):
            try:
                hour_index = int(row.get("hour_index") or 0)
                target_elapsed = int(float(row.get("target_elapsed_wall_s") or 0))
            except ValueError:
                continue
            if hour_index >= 0 and target_elapsed > completed:
                completed = target_elapsed
    if sample_interval > 0:
        completed = (completed // sample_interval) * sample_interval
    return completed


def next_slice_index(run_root: Path) -> int:
    slices = run_root / "slices"
    if not slices.exists():
        return 0
    indexes: list[int] = []
    for child in slices.iterdir():
        if child.is_dir() and child.name.startswith("slice_"):
            try:
                indexes.append(int(child.name.split("_", 1)[1]))
            except ValueError:
                pass
    return (max(indexes) + 1) if indexes else 0


def resolve_run_root(root: Path, args: argparse.Namespace) -> tuple[str, Path, bool]:
    if args.run_root:
        run_root = Path(args.run_root).expanduser()
        if not run_root.is_absolute():
            run_root = root / run_root
        run_root = run_root.resolve()
        return run_root.name, run_root, run_root.exists()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{args.label}_{duration_label(args.seconds)}_{stamp}"
    return run_id, root / "runs" / "managed_runs" / run_id, False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--hours", type=int, default=10)
    parser.add_argument("--sample-interval", type=int, default=3600)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--label", default="cva6_scheme1_vs_scheme4_resume")
    parser.add_argument("--run-root", type=Path, help="Existing run root to resume, or a new explicit run root.")
    parser.add_argument("--exclude-top-bits", type=int, default=0)
    parser.add_argument("--exclude-module-label", default="cva6")
    parser.add_argument("--seed-cycles", type=int, default=5)
    parser.add_argument("--max-cycles", type=int, default=200)
    parser.add_argument("--max-runs", type=int, default=64)
    parser.add_argument("--crash-restarts", type=int, default=3)
    parser.add_argument("--save-latest-every-runs", type=int, default=256)
    parser.add_argument("--nice", type=int, default=5)
    parser.add_argument("--cpu-sets", help="Comma-separated CPU sets, one per scheme.")
    parser.add_argument("--final-grace-seconds", type=int, default=600)
    parser.add_argument("--no-replay-previous-queue", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.repo.resolve()
    if args.seconds is None:
        args.seconds = args.hours * args.sample_interval
    if args.seconds <= 0:
        raise ValueError("--seconds must be positive")
    if args.sample_interval <= 0:
        raise ValueError("--sample-interval must be positive")

    run_id, run_root, existed = resolve_run_root(root, args)
    run_root.mkdir(parents=True, exist_ok=True)
    (run_root / "runner.pid").write_text(str(os.getpid()) + "\n")

    completed_before_slice = max_completed_elapsed(run_root, args.sample_interval) if existed else 0
    if completed_before_slice >= args.seconds:
        print(f"ALREADY_COMPLETE {run_root}", flush=True)
        return 0
    slice_index = next_slice_index(run_root)
    args.slice_seconds = args.seconds - completed_before_slice

    prepared = [prepare_scheme(root, run_root, slice_index, scheme, args) for scheme in SCHEMES]
    indices = compute_common_indices(prepared, args.exclude_top_bits, args.exclude_module_label)
    cpu_sets = choose_cpu_sets(len(prepared), args.cpu_sets)

    manifest_path = run_root / "manifest.json"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    manifest.update({
        "run_id": run_id,
        "run_root": str(run_root),
        "created_at": manifest.get("created_at") or datetime.now().isoformat(timespec="seconds"),
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "target_duration_seconds": args.seconds,
        "sample_interval_seconds": args.sample_interval,
        "completed_before_this_slice_seconds": completed_before_slice,
        "current_slice_index": slice_index,
        "current_slice_seconds": args.slice_seconds,
        "coverage_metric": (
            "Cumulative union coverage over actual __vi_coverage bit indices common to scheme1 and scheme4. "
            f"CVA6 run excludes {args.exclude_top_bits} top MSB bits by default."
        ),
        "common_coverage_total": len(indices["common_indices"]),
        "coverage_counts": indices["coverage_counts"],
        "resource_controls": {
            "jobs": 1,
            "server_count": 1,
            "nice": args.nice,
            "cpu_sets": cpu_sets,
            "seed_cycles": args.seed_cycles,
            "max_cycles": args.max_cycles,
            "max_runs": args.max_runs,
            "crash_restarts": args.crash_restarts,
            "replay_previous_queue": not args.no_replay_previous_queue,
        },
    })
    slices = list(manifest.get("slices") or [])
    slices.append({
        "slice_index": slice_index,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "completed_before_slice_seconds": completed_before_slice,
        "planned_seconds": args.slice_seconds,
        "schemes": [],
    })
    manifest["slices"] = slices
    write_json(manifest_path, manifest)

    runs: list[dict] = []
    try:
        for info, cpu_set in zip(prepared, cpu_sets):
            run = start_scheme(root, run_root, slice_index, info, args, cpu_set)
            runs.append(run)
            slices[-1]["schemes"].append({
                "scheme": run["scheme"],
                "label": run["label"],
                "description": run["description"],
                "config": str(run["config_path"]),
                "out_dir": str(run["out_dir"]),
                "reuse_out_dir": str(run["reuse_out_dir_abs"]),
                "toml": str(run["toml_path"]),
                "input_directory": str(run["input_directory"]) if run.get("input_directory") else None,
                "runner_log": str(run["runner_log"]),
                "pid": run["pid"],
                "cpu_set": run["cpu_set"],
                "cmd": run["cmd"],
            })
        manifest["updated_at"] = datetime.now().isoformat(timespec="seconds")
        write_json(manifest_path, manifest)

        print(f"STARTED {run_id}", flush=True)
        print(f"RUN_ROOT {run_root}", flush=True)
        print(f"SLICE {slice_index}", flush=True)
        print(f"COMMON_TOTAL {len(indices['common_indices'])}", flush=True)
        print(f"COMPLETED_BEFORE_SLICE {completed_before_slice}", flush=True)
        print(f"SLICE_SECONDS {args.slice_seconds}", flush=True)

        started = time.time()
        if completed_before_slice == 0:
            sample_all(
                root, run_root, runs, slice_index, started, completed_before_slice,
                0, 0, "start", indices
            )
        else:
            sample_all(
                root, run_root, runs, slice_index, started, completed_before_slice,
                completed_before_slice // args.sample_interval,
                completed_before_slice,
                "resume_start",
                indices,
                append=False,
            )

        next_target = ((completed_before_slice // args.sample_interval) + 1) * args.sample_interval
        while next_target <= args.seconds:
            deadline = started + (next_target - completed_before_slice)
            while time.time() < deadline:
                if all(run["proc"].poll() is not None for run in runs):
                    break
                time.sleep(min(30.0, max(0.1, deadline - time.time())))
            sample_all(
                root, run_root, runs, slice_index, started, completed_before_slice,
                next_target // args.sample_interval,
                next_target,
                "hourly",
                indices,
            )
            if all(run["proc"].poll() is not None for run in runs):
                break
            next_target += args.sample_interval

        wait_for_children(runs, args.final_grace_seconds)
        final_rows = sample_all(
            root, run_root, runs, slice_index, started, completed_before_slice,
            -1, args.seconds, "final", indices
        )
        slices[-1]["ended_at"] = datetime.now().isoformat(timespec="seconds")
        slices[-1]["returncodes"] = {run["label"]: run["proc"].poll() for run in runs}
        manifest["updated_at"] = datetime.now().isoformat(timespec="seconds")
        manifest["latest_returncodes"] = slices[-1]["returncodes"]
        manifest["completed_target_elapsed_seconds"] = max_completed_elapsed(run_root, args.sample_interval)
        if manifest["completed_target_elapsed_seconds"] >= args.seconds:
            manifest["completed_at"] = datetime.now().isoformat(timespec="seconds")
        write_json(manifest_path, manifest)
        write_json(run_root / "summary.json", {"final_rows": final_rows, "manifest": manifest})
        return 0 if all((run["proc"].poll() or 0) == 0 for run in runs) else 1
    except KeyboardInterrupt:
        terminate_alive(runs)
        manifest["interrupted_at"] = datetime.now().isoformat(timespec="seconds")
        manifest["updated_at"] = manifest["interrupted_at"]
        manifest["completed_target_elapsed_seconds"] = max_completed_elapsed(run_root, args.sample_interval)
        write_json(manifest_path, manifest)
        raise
    finally:
        terminate_alive(runs)
        close_logs(runs)


if __name__ == "__main__":
    raise SystemExit(main())
