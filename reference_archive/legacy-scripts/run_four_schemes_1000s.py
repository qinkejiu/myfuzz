#!/usr/bin/env python3
"""Run the four Ibex fuzzing schemes sequentially and summarize coverage."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


SCHEMES = [
    ("baseline", "ibex", "configs/designs/ibex/config.json"),
    ("naive", "ibex_naive", "configs/designs/ibex_naive/config.json"),
    ("constrained", "ibex_constrained", "configs/designs/ibex_constrained/config.json"),
    ("lightweight", "ibex_lightweight", "configs/designs/ibex_lightweight/config.json"),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def coverage_summary(queue_dir: Path) -> dict:
    entries = sorted(queue_dir.glob("entry_*.json"))
    if not entries:
        return {
            "queue_entries": 0,
            "last_entry": None,
            "input_bytes": 0,
            "covered": 0,
            "total": 0,
            "coverage_pct": 0.0,
        }
    last = entries[-1]
    data = load_json(last)
    entry = data.get("entry", data)
    trace = entry.get("trace_bits") or data.get("trace_bits") or []
    inputs = entry.get("inputs") or data.get("inputs") or []
    covered = sum(1 for value in trace if int(value) > 0)
    total = len(trace)
    return {
        "queue_entries": len(entries),
        "last_entry": last.name,
        "input_bytes": len(inputs),
        "covered": covered,
        "total": total,
        "coverage_pct": (covered / total * 100.0) if total else 0.0,
    }


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def run_scheme(root: Path, run_root: Path, seconds: int, scheme: tuple[str, str, str]) -> dict:
    label, design, config = scheme
    cfg = load_json(root / config)
    out_dir = root / cfg["out_dir"]
    log_path = run_root / f"{label}.log"
    start = datetime.now().isoformat(timespec="seconds")
    cmd = [
        sys.executable,
        "src/myfuzz/scripts/run_design_flow.py",
        "--config",
        config,
        "--stage",
        "fuzz",
        "--fuzz-seconds",
        str(seconds),
        "--jobs",
        "1",
    ]
    with log_path.open("wb") as log:
        log.write(("+ " + " ".join(cmd) + "\n").encode())
        log.flush()
        proc = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    end = datetime.now().isoformat(timespec="seconds")
    summary = coverage_summary(out_dir / "queue")
    result = {
        "label": label,
        "design": design,
        "config": config,
        "out_dir": str(out_dir.relative_to(root)),
        "log": str(log_path.relative_to(root)),
        "start": start,
        "end": end,
        "returncode": proc.returncode,
        **summary,
    }
    write_json(run_root / f"{label}.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=1000)
    parser.add_argument("--label", default="four_schemes_1000s")
    args = parser.parse_args()

    root = Path.cwd().resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_root = root / "runs" / "managed_runs" / f"{args.label}_{stamp}"
    run_root.mkdir(parents=True, exist_ok=True)
    (run_root / "runner.pid").write_text(str(__import__("os").getpid()) + "\n")

    manifest = {
        "label": args.label,
        "seconds": args.seconds,
        "start": datetime.now().isoformat(timespec="seconds"),
        "run_root": str(run_root.relative_to(root)),
        "schemes": [],
    }
    write_json(run_root / "manifest.json", manifest)

    exit_code = 0
    for scheme in SCHEMES:
        result = run_scheme(root, run_root, args.seconds, scheme)
        manifest["schemes"].append(result)
        write_json(run_root / "manifest.json", manifest)
        if result["returncode"] != 0:
            exit_code = result["returncode"]
            break
        time.sleep(1)

    manifest["end"] = datetime.now().isoformat(timespec="seconds")
    manifest["returncode"] = exit_code
    write_json(run_root / "manifest.json", manifest)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
