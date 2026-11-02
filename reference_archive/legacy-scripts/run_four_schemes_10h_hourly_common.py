#!/usr/bin/env python3
"""Run the four Ibex schemes concurrently and sample common coverage hourly."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
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
        "config": "configs/designs/ibex/config.json",
        "reuse_out_dir": "runs/designs/ibex",
        "description": "Top-level ibex_core baseline.",
    },
    {
        "scheme": "scheme2",
        "label": "scheme2_naive_decomposed",
        "config": "configs/designs/ibex_naive/config.json",
        "reuse_out_dir": "runs/designs/ibex_naive",
        "description": "True decomposed submodule harness without constraints.",
    },
    {
        "scheme": "scheme3",
        "label": "scheme3_constrained_decomposed",
        "config": "configs/designs/ibex_constrained/config.json",
        "reuse_out_dir": "runs/designs/ibex_constrained",
        "description": "True decomposed submodule harness with constraints.",
    },
    {
        "scheme": "scheme4",
        "label": "scheme4_lightweight",
        "config": "configs/designs/ibex_lightweight/config.json",
        "reuse_out_dir": "runs/designs/ibex_lightweight",
        "description": "Top-level ibex_core lightweight constrained harness.",
    },
]

CSV_FIELDS = [
    "hour_index",
    "target_elapsed_wall_s",
    "timestamp",
    "elapsed_wall_s",
    "scheme",
    "label",
    "alive",
    "returncode",
    "pid",
    "cpu_set",
    "tests_total",
    "tests_per_s",
    "cycles_total",
    "cycles_per_s",
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
    "run_root",
    "out_dir",
    "runner_log",
]


def duration_label(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds}s"


def load_json(path: Path) -> dict:
    with path.open() as infile:
        return json.load(infile)


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

    # Minimal fallback parser for the generated rfuzz TOML coverage blocks.
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


def prepare_scheme(root: Path, run_root: Path, scheme: dict, args: argparse.Namespace) -> dict:
    base_config_path = root / scheme["config"]
    base_config = load_json(base_config_path)
    top = str(base_config["top"])
    reuse_out_dir = root / scheme["reuse_out_dir"]
    server = reuse_out_dir / "server" / "server"
    if not server.exists() or not os.access(server, os.X_OK):
        raise FileNotFoundError(f"missing executable server: {server}")
    if not (reuse_out_dir / "harness").exists():
        raise FileNotFoundError(f"missing harness directory: {reuse_out_dir / 'harness'}")

    out_dir_rel = Path("runs") / "managed_runs" / run_root.name / "designs" / scheme["label"]
    out_dir = root / out_dir_rel
    symlink_reuse_outputs(reuse_out_dir, out_dir)

    config = dict(base_config)
    config["name"] = f"{run_root.name}_{scheme['label']}"
    config["out_dir"] = out_dir_rel.as_posix()
    fuzz = config.setdefault("fuzz", {})
    fuzz["max_runs"] = int(args.max_runs)
    fuzz["crash_restarts"] = int(args.crash_restarts)
    fuzz["stop_on_crash"] = False
    fuzz["seed_cycles"] = int(args.seed_cycles)
    fuzz["max_cycles"] = max(int(fuzz.get("max_cycles", args.max_cycles) or args.max_cycles), int(args.seed_cycles))
    fuzz["server_count"] = 1

    config_path = run_root / "configs" / f"{scheme['label']}.json"
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

        # RFuzz consumes __vi_coverage by vector bit index. In the Ibex top-level
        # concat, the top-local ibex_core coverage occupies the MSB slice.
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
                "note": "Audit only. Coverage rows are counted by actual __vi_coverage bit index, not by TOML human labels.",
            },
        }
    common_indices = sorted(set.intersection(*per_scheme.values()))
    all_toml_indices = sorted(set.union(*all_toml_per_scheme.values()))
    return {
        "common_indices": common_indices,
        "all_toml_indices_union": all_toml_indices,
        "coverage_counts": coverage_counts,
    }


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
        str(args.seconds),
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


def start_scheme(root: Path, run_root: Path, info: dict, args: argparse.Namespace, cpu_set: str | None) -> dict:
    log_path = run_root / "logs" / f"{info['label']}.log"
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
    (run_root / "pids" / f"{info['label']}.pid").parent.mkdir(parents=True, exist_ok=True)
    (run_root / "pids" / f"{info['label']}.pid").write_text(str(proc.pid) + "\n")
    return {
        **info,
        "cmd": cmd,
        "cpu_set": cpu_set,
        "proc": proc,
        "log_handle": log,
        "runner_log": log_path,
        "pid": proc.pid,
    }


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


def discoveries(stats: dict) -> int | None:
    mutators = stats.get("mutators")
    if not isinstance(mutators, list):
        return None
    total = 0
    for item in mutators:
        if isinstance(item, dict):
            total += int(item.get("discovery_count") or 0)
    return total


def queue_entry_count(queue_dir: Path) -> int:
    return len(list(queue_dir.glob("entry_*.json")))


def bitmap_point_count(bitmap: list, indices: list[int]) -> int:
    count = 0
    for index in indices:
        if index < len(bitmap) and int(bitmap[index]) != 255:
            count += 1
    return count


def queue_union_common_count(queue_dir: Path, indices: list[int]) -> int:
    wanted = set(indices)
    covered: set[int] = set()
    for entry_path in sorted(queue_dir.glob("entry_*.json")):
        try:
            data = load_json(entry_path)
        except json.JSONDecodeError:
            continue
        trace = data.get("trace_bits") or data.get("entry", {}).get("trace_bits") or []
        for index in wanted - covered:
            if index < len(trace) and int(trace[index]) > 0:
                covered.add(index)
        if len(covered) == len(wanted):
            break
    return len(covered)


def pct(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if denominator in (None, 0) or numerator is None:
        return None
    return 100.0 * float(numerator) / float(denominator)


def sample_scheme(run_root: Path, run: dict, elapsed: int, hour_index: int, target_elapsed: int, indices: dict) -> dict:
    proc: subprocess.Popen = run["proc"]
    returncode = proc.poll()
    queue_dir = Path(run["out_dir"]) / "queue"
    stats, latest_source = load_latest_stats(queue_dir)
    bitmap = stats.get("bitmap") if isinstance(stats.get("bitmap"), list) else []
    common_indices = indices["common_indices"]
    all_indices = indices["all_toml_indices_union"]
    common_covered = bitmap_point_count(bitmap, common_indices)
    all_toml_covered = bitmap_point_count(bitmap, all_indices)
    queue_union = queue_union_common_count(queue_dir, common_indices)
    tests_total = stats_number(stats, "tests_per_second", "global_numerator")
    cycles_total = stats_number(stats, "cycles_per_second", "global_numerator")
    row = {
        "hour_index": hour_index,
        "target_elapsed_wall_s": target_elapsed,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "elapsed_wall_s": elapsed,
        "scheme": run["scheme"],
        "label": run["label"],
        "alive": int(returncode is None),
        "returncode": returncode,
        "pid": run["pid"],
        "cpu_set": run["cpu_set"],
        "tests_total": int(tests_total) if tests_total is not None else None,
        "tests_per_s": stats_number(stats, "tests_per_second", "global"),
        "cycles_total": int(cycles_total) if cycles_total is not None else None,
        "cycles_per_s": stats_number(stats, "cycles_per_second", "global"),
        "discoveries": discoveries(stats),
        "queue_entries": queue_entry_count(queue_dir),
        "common_covered": common_covered,
        "common_total": len(common_indices),
        "common_pct": pct(common_covered, len(common_indices)),
        "queue_union_common_covered": queue_union,
        "queue_union_common_pct": pct(queue_union, len(common_indices)),
        "all_toml_covered": all_toml_covered,
        "all_toml_total": len(all_indices),
        "all_toml_pct": pct(all_toml_covered, len(all_indices)),
        "bitmap_len": len(bitmap),
        "latest_source": latest_source,
        "run_root": str(run_root),
        "out_dir": str(run["out_dir"]),
        "runner_log": str(run["runner_log"]),
    }
    return row


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


def sample_all(run_root: Path, runs: list[dict], started: float, hour_index: int, target_elapsed: int, indices: dict) -> list[dict]:
    elapsed = int(time.time() - started)
    rows = [sample_scheme(run_root, run, elapsed, hour_index, target_elapsed, indices) for run in runs]
    append_sample(run_root, rows)
    write_json(run_root / "latest_sample.json", {"rows": rows})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--hours", type=int, default=10)
    parser.add_argument("--sample-interval", type=int, default=3600)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--label", default="four_schemes_10h_common")
    parser.add_argument("--exclude-top-bits", type=int, default=56)
    parser.add_argument("--exclude-module-label", default="ibex_core")
    parser.add_argument("--seed-cycles", type=int, default=5)
    parser.add_argument("--max-cycles", type=int, default=200)
    parser.add_argument("--max-runs", type=int, default=64)
    parser.add_argument("--crash-restarts", type=int, default=3)
    parser.add_argument("--nice", type=int, default=5)
    parser.add_argument("--cpu-sets", help="Comma-separated CPU sets, one per scheme. Default pins schemes to CPUs 0..3 if taskset is available.")
    parser.add_argument("--final-grace-seconds", type=int, default=600)
    args = parser.parse_args()

    root = args.repo.resolve()
    if args.seconds is None:
        args.seconds = args.hours * args.sample_interval
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{args.label}_{duration_label(args.seconds)}_{stamp}"
    run_root = root / "runs" / "managed_runs" / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    (run_root / "runner.pid").write_text(str(os.getpid()) + "\n")

    prepared = [prepare_scheme(root, run_root, scheme, args) for scheme in SCHEMES]
    indices = compute_common_indices(prepared, args.exclude_top_bits, args.exclude_module_label)
    cpu_sets = choose_cpu_sets(len(prepared), args.cpu_sets)

    runs: list[dict] = []
    manifest = {
        "run_id": run_id,
        "run_root": str(run_root),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": args.seconds,
        "sample_interval_seconds": args.sample_interval,
        "hour_samples": args.hours,
        "coverage_metric": (
            "RFuzz cumulative valid bitmap point coverage over actual __vi_coverage bit indices "
            f"common to all schemes, excluding the top module MSB slice of {args.exclude_top_bits} bits; "
            "queue union is recorded as an audit metric."
        ),
        "common_coverage_total": len(indices["common_indices"]),
        "common_coverage_indices": indices["common_indices"],
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
            "exclude_top_bits": args.exclude_top_bits,
            "exclude_module_label_audit": args.exclude_module_label,
        },
        "schemes": [],
    }

    write_json(run_root / "manifest.json", manifest)

    try:
        for info, cpu_set in zip(prepared, cpu_sets):
            run = start_scheme(root, run_root, info, args, cpu_set)
            runs.append(run)
            manifest["schemes"].append({
                "scheme": run["scheme"],
                "label": run["label"],
                "description": run["description"],
                "config": str(run["config_path"]),
                "out_dir": str(run["out_dir"]),
                "reuse_out_dir": str(run["reuse_out_dir_abs"]),
                "toml": str(run["toml_path"]),
                "runner_log": str(run["runner_log"]),
                "pid": run["pid"],
                "cpu_set": run["cpu_set"],
                "cmd": run["cmd"],
            })
        manifest["started_at"] = datetime.now().isoformat(timespec="seconds")
        write_json(run_root / "manifest.json", manifest)

        print(f"STARTED {run_id}", flush=True)
        print(f"RUN_ROOT {run_root}", flush=True)
        print(f"COMMON_TOTAL {len(indices['common_indices'])}", flush=True)

        started = time.time()
        sample_all(run_root, runs, started, 0, 0, indices)

        target_count = max(1, args.seconds // args.sample_interval)
        for hour_index in range(1, target_count + 1):
            target_elapsed = min(hour_index * args.sample_interval, args.seconds)
            deadline = started + target_elapsed
            while time.time() < deadline:
                if all(run["proc"].poll() is not None for run in runs):
                    break
                time.sleep(min(30.0, max(0.1, deadline - time.time())))
            sample_all(run_root, runs, started, hour_index, target_elapsed, indices)
            if all(run["proc"].poll() is not None for run in runs):
                break

        wait_for_children(runs, args.final_grace_seconds)
        final_rows = sample_all(run_root, runs, started, -1, args.seconds, indices)
        manifest["ended_at"] = datetime.now().isoformat(timespec="seconds")
        manifest["returncodes"] = {run["label"]: run["proc"].poll() for run in runs}
        write_json(run_root / "manifest.json", manifest)
        write_json(run_root / "summary.json", {"final_rows": final_rows, "manifest": manifest})
        return 0 if all((run["proc"].poll() or 0) == 0 for run in runs) else 1
    except KeyboardInterrupt:
        terminate_alive(runs)
        raise
    finally:
        close_logs(runs)


if __name__ == "__main__":
    raise SystemExit(main())
