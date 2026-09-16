#!/usr/bin/env python3
"""Run deterministic RFuzz coverage pilots sequentially with resource sampling."""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Job:
    target: str
    scheme: str
    server: str
    toml: str
    coverage_total: int

    @property
    def name(self) -> str:
        return f"{self.target}_{self.scheme}"


JOBS = (
    Job("ibex_opentitan_real_ip", "baseline_direct_slice", "runs/designs/ibex_opentitan_real_ip_baseline_direct_slice/server/server", "runs/designs/ibex_opentitan_real_ip_baseline_direct_slice/server/ibex_opentitan_real_ip_top.rfuzz.toml", 3713),
    Job("ibex_opentitan_real_ip", "depaware_projection", "runs/designs/ibex_opentitan_real_ip_depaware_projection/server/server", "runs/designs/ibex_opentitan_real_ip_depaware_projection/server/ibex_opentitan_real_ip_top.rfuzz.toml", 3713),
    Job("rvx_multicomponent", "baseline_direct_slice", "runs/designs/rvx_multicomponent_baseline_direct_slice/server/server", "runs/designs/rvx_multicomponent_baseline_direct_slice/server/rvx.rfuzz.toml", 324),
    Job("rvx_multicomponent", "depaware_projection", "runs/designs/rvx_multicomponent_depaware_projection/server/server", "runs/designs/rvx_multicomponent_depaware_projection/server/rvx.rfuzz.toml", 324),
)


class CoverageAccumulator:
    def __init__(self, valid_width: int):
        self.valid_width = valid_width
        self.covered: set[int] = set()
        self.seen: set[Path] = set()
        self.processed_entries = 0

    def update(self, queue_dir: Path) -> int:
        for path in sorted(queue_dir.glob("entry_*.json")):
            if path in self.seen:
                continue
            try:
                trace = json.loads(path.read_text()).get("trace_bits", [])
            except (OSError, json.JSONDecodeError):
                continue
            self.covered.update(
                index for index, value in enumerate(trace[: self.valid_width]) if int(value) != 0
            )
            self.seen.add(path)
            self.processed_entries += 1
        return len(self.covered)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def stats_value(stats: dict, group: str, field: str) -> float | None:
    value = stats.get(group)
    if not isinstance(value, dict) or value.get(field) is None:
        return None
    try:
        return float(value[field])
    except (TypeError, ValueError):
        return None


def descendants(pid: int) -> set[int]:
    found = {pid}
    pending = [pid]
    while pending:
        current = pending.pop()
        path = Path(f"/proc/{current}/task/{current}/children")
        try:
            children = [int(value) for value in path.read_text().split()]
        except (OSError, ValueError):
            children = []
        for child in children:
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def rss_bytes(pids: set[int]) -> int:
    total_kib = 0
    for pid in pids:
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total_kib += int(line.split()[1])
                    break
        except (OSError, ValueError):
            pass
    return total_kib * 1024


def available_memory_bytes() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def clean_channel(server_id: int) -> None:
    channel = Path(f"/tmp/fpga/{server_id}")
    for name in ("tx.fifo", "rx.fifo"):
        path = channel / name
        if path.is_fifo():
            path.unlink()
    try:
        channel.rmdir()
    except OSError:
        pass
    channel.parent.mkdir(parents=True, exist_ok=True)


def stop_process(proc: subprocess.Popen, initial: signal.Signals = signal.SIGINT) -> int:
    if proc.poll() is None:
        proc.send_signal(initial)
    try:
        return proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.terminate()
    try:
        return proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.wait()


def snapshot(job: Job, queue: Path, accumulator: CoverageAccumulator, elapsed: int, server_pid: int, fuzzer_pid: int, peak_rss: int) -> tuple[dict, int]:
    covered = accumulator.update(queue)
    stats = read_json(queue / "latest.json")
    current_rss = rss_bytes(descendants(server_pid) | descendants(fuzzer_pid))
    peak_rss = max(peak_rss, current_rss)
    tests = stats_value(stats, "tests_per_second", "global_numerator")
    cycles = stats_value(stats, "cycles_per_second", "global_numerator")
    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": job.target,
        "scheme": job.scheme,
        "elapsed_seconds": elapsed,
        "covered": covered,
        "coverage_total": job.coverage_total,
        "coverage_pct": round(100.0 * covered / job.coverage_total, 6),
        "queue_entries": accumulator.processed_entries,
        "tests_total": int(tests) if tests is not None else None,
        "cycles_total": int(cycles) if cycles is not None else None,
        "rss_bytes": current_rss,
        "peak_rss_bytes": peak_rss,
        "memory_available_bytes": available_memory_bytes(),
    }
    return row, peak_rss


def run_job(root: Path, run_root: Path, job: Job, seconds: int, interval: int, fuzzer: Path, campaign_seed: int, server_id: int, samples: list[dict]) -> dict:
    job_root = run_root / job.name
    queue = job_root / "queue"
    queue.mkdir(parents=True)
    clean_channel(server_id)
    server_log = (job_root / "server.log").open("wb")
    fuzzer_log = (job_root / "fuzzer.log").open("wb")
    server = subprocess.Popen([str(root / job.server), str(server_id)], cwd=root, stdout=server_log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        channel = Path(f"/tmp/fpga/{server_id}")
        if (channel / "tx.fifo").is_fifo() and (channel / "rx.fifo").is_fifo():
            break
        if server.poll() is not None:
            raise RuntimeError(f"{job.name}: server exited before opening RFuzz channel")
        time.sleep(0.05)
    else:
        stop_process(server)
        raise RuntimeError(f"{job.name}: RFuzz channel timeout")

    fuzzer_proc = subprocess.Popen(
        [str(fuzzer), str(root / job.toml), "--output-directory", str(queue), "--server-id", str(server_id), "--seed-cycles", "5", "--campaign-seed", str(campaign_seed)],
        cwd=root,
        stdout=fuzzer_log,
        stderr=subprocess.STDOUT,
    )
    accumulator = CoverageAccumulator(job.coverage_total)
    started = time.monotonic()
    next_sample = 0
    peak_rss = 0
    try:
        while True:
            elapsed = int(time.monotonic() - started)
            if elapsed >= next_sample:
                row, peak_rss = snapshot(job, queue, accumulator, elapsed, server.pid, fuzzer_proc.pid, peak_rss)
                samples.append(row)
                append_sample(run_root, row)
                print(json.dumps(row, sort_keys=True), flush=True)
                next_sample += interval
            if elapsed >= seconds or fuzzer_proc.poll() is not None or server.poll() is not None:
                break
            time.sleep(min(1.0, max(0.05, next_sample - (time.monotonic() - started))))
    finally:
        fuzzer_rc = stop_process(fuzzer_proc)
        server_rc = stop_process(server)
        server_log.close()
        fuzzer_log.close()
    final, peak_rss = snapshot(job, queue, accumulator, int(time.monotonic() - started), server.pid, fuzzer_proc.pid, peak_rss)
    samples.append(final)
    append_sample(run_root, final)
    return {**final, "fuzzer_returncode": fuzzer_rc, "server_returncode": server_rc, "job_root": str(job_root)}


FIELDS = ("timestamp", "target", "scheme", "elapsed_seconds", "covered", "coverage_total", "coverage_pct", "queue_entries", "tests_total", "cycles_total", "rss_bytes", "peak_rss_bytes", "memory_available_bytes")


def append_sample(run_root: Path, row: dict) -> None:
    with (run_root / "samples.jsonl").open("a") as out:
        out.write(json.dumps(row, sort_keys=True) + "\n")
    csv_path = run_root / "samples.csv"
    write_header = not csv_path.exists()
    with csv_path.open("a", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow({field: row.get(field) for field in FIELDS})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--sample-interval", type=int, default=100)
    parser.add_argument("--campaign-seed", type=int, default=1)
    parser.add_argument("--server-id", type=int, default=0)
    parser.add_argument("--jobs", nargs="*", choices=[job.name for job in JOBS])
    parser.add_argument("--label", default="ibex_rvx_sequential_1h")
    args = parser.parse_args()
    root = args.repo.resolve()
    selected = [job for job in JOBS if not args.jobs or job.name in args.jobs]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_root = root / "runs" / "pilots" / f"{args.label}_{stamp}"
    run_root.mkdir(parents=True)
    fuzzer = root / "third_party/rfuzz/upstream/target/release/kfuzz"
    manifest = {"created_at": datetime.now().isoformat(timespec="seconds"), "seconds_per_job": args.seconds, "sample_interval_seconds": args.sample_interval, "campaign_seed": args.campaign_seed, "server_id": args.server_id, "execution": "strictly_sequential_within_this_process", "jobs": [job.__dict__ for job in selected]}
    (run_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    samples: list[dict] = []
    summaries = []
    for job in selected:
        summaries.append(run_job(root, run_root, job, args.seconds, args.sample_interval, fuzzer, args.campaign_seed, args.server_id, samples))
    summary = {"run_root": str(run_root), "completed_at": datetime.now().isoformat(timespec="seconds"), "results": summaries}
    (run_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
