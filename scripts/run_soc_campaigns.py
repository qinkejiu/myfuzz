#!/usr/bin/env python3
"""Plan or run the bounded two-CPU/three-family SoC RFuzz matrix.

The default mode is an inexpensive preflight.  A real run is deliberately
serial, requires at least 300 seconds per task, and passes through
``run_soc_campaign`` so the official RFuzz opt-in and evidence rules cannot be
bypassed by this convenience CLI.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import os
from pathlib import Path
import sys
from typing import Any


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.soc_campaign import (  # noqa: E402
    preflight_soc_campaign,
    run_soc_campaign,
)


MATRIX_SCHEMA = "soc_matrix.v1"
RESULT_SCHEMA = "soc_campaign_matrix_result.v1"
MODES = ("cpu_only", "mmio_only", "mixed")


def _load_json(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"matrix/config must be a regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"matrix/config must be an object: {path}")
    return value


def load_matrix(path: Path) -> dict[str, object]:
    document = _load_json(Path(path).resolve())
    if document.get("schema_version") != MATRIX_SCHEMA:
        raise ValueError("matrix schema_version mismatch")
    cells = document.get("cells")
    cpus = document.get("cpus")
    families = document.get("families")
    modes = document.get("modes")
    if (not isinstance(cells, list) or not isinstance(cpus, list) or not isinstance(families, list)
            or not isinstance(modes, list) or tuple(modes) != MODES):
        raise ValueError("matrix cpus/families/cells/modes are malformed")
    if set(cpus) != {"ibex", "cva6"} or set(families) != {"opentitan", "pulp", "zipcpu"}:
        raise ValueError("matrix must contain the two CPUs and three families")
    if len(cells) != 8:
        raise ValueError("matrix must contain exactly eight cells")
    ids: set[str] = set()
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise ValueError("matrix cell must be an object")
        cell_id = cell.get("cell_id")
        if not isinstance(cell_id, str) or not cell_id or cell_id in ids:
            raise ValueError("matrix cell ids must be unique nonempty strings")
        ids.add(cell_id)
        if not isinstance(cell.get("config"), str) or not cell["config"]:
            raise ValueError(f"matrix cell config missing: {cell_id}")
        if cell.get("cpu") not in cpus:
            raise ValueError(f"matrix cell CPU is not declared: {cell_id}")
        if cell.get("family") not in (*families, "mixed"):
            raise ValueError(f"matrix cell family is not declared: {cell_id}")
        if cell.get("distinct_ip_count") not in (2, 3):
            raise ValueError(f"matrix cell distinct_ip_count is invalid: {cell_id}")
    return document


def plan_matrix_tasks(matrix: Mapping[str, object], *, seconds: int, seed: int) -> list[dict[str, object]]:
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
        raise ValueError("seconds must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    tasks: list[dict[str, object]] = []
    for cell in matrix["cells"]:
        cell_id = str(cell["cell_id"])
        for mode in MODES:
            tasks.append({
                "task_id": f"{cell_id}/{mode}", "cell_id": cell_id,
                "config": cell["config"], "cpu": cell["cpu"],
                "family": cell["family"], "mode": mode,
                "bias_off": False, "seconds": seconds, "seed": seed + len(tasks),
            })
        tasks.append({
            "task_id": f"{cell_id}/mixed-bias-off", "cell_id": cell_id,
            "config": cell["config"], "cpu": cell["cpu"],
            "family": cell["family"], "mode": "mixed",
            "bias_off": True, "seconds": seconds, "seed": seed + len(tasks),
        })
    if len(tasks) != 32:
        raise ValueError("matrix task expansion must produce 32 tasks")
    return tasks


def _task_config(root: Path, task: Mapping[str, object], *, matrix_path: Path,
                 client: str | None) -> dict[str, object]:
    cell_path = (root / str(task["config"])).resolve()
    cell = _load_json(cell_path)
    source_paths = [
        "configs/soc/sources.lock.json",
        cell_path.relative_to(root).as_posix(),
        f"configs/soc/families/{task['family']}.json" if task["family"] != "mixed" else "configs/soc/families/opentitan.json",
    ]
    if task["family"] == "mixed":
        source_paths.extend([
            "configs/soc/families/pulp.json", "configs/soc/families/zipcpu.json",
        ])
    result: dict[str, object] = {
        "config_id": task["task_id"], "cell_id": task["cell_id"],
        # The campaign builder is config-driven: it re-reads this exact cell
        # config (and its base profile) to plan, render and compile the cell.
        "cell_config": cell_path.relative_to(root).as_posix(),
        "cpu": cell.get("cpu", task["cpu"]),
        "families": cell.get("families", [task["family"]]),
        "peripherals": cell.get("peripherals", []),
        "mode": task["mode"], "seed": task["seed"],
        "duration_seconds": task["seconds"], "simulator": "verilator",
        "source_paths": source_paths,
        "client_binary": client,
        "seed_cycles": 5,
        "reset_contract": {
            "driver": True, "memory": True, "cpu": True,
            "peripherals": True, "irq": True, "coverage": True,
        },
        "matrix_path": str(matrix_path), "bias_off": task["bias_off"],
        "base_cell": cell,
    }
    if task["bias_off"]:
        result["bias_policy"] = "all source/target input bias disabled; same coverage universe"
    return result


def _source_lock_evidence(root: Path, config: Mapping[str, object]) -> list[dict[str, object]]:
    lock = _load_json(root / "configs/soc/sources.lock.json")
    records = {item.get("id"): item for item in lock.get("components", [])
               if isinstance(item, Mapping)}
    cell = config.get("base_cell", {})
    wanted = cell.get("source_locks", []) if isinstance(cell, Mapping) else []
    evidence = []
    for source_id in wanted:
        record = records.get(source_id)
        evidence.append({"id": source_id, "present": isinstance(record, Mapping),
                         "source_status": record.get("source_status") if isinstance(record, Mapping) else None})
    return evidence


def _replay_probe(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"status": "not-requested"}
    path = path.resolve()
    if not path.exists() or path.is_symlink():
        return {"status": "missing", "path": str(path)}
    if path.is_file():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"status": "invalid", "path": str(path)}
        return {"status": "available-not-executed", "path": str(path),
                "schema_version": document.get("schema_version") if isinstance(document, Mapping) else None,
                "execution": "rebuild/replay is a separate real-run step"}
    return {"status": "available-not-executed", "path": str(path),
            "manifest": (path / "manifest.json").is_file(),
            "execution": "rebuild/replay is a separate real-run step"}


def run_matrix(matrix_path: Path, output: Path, *, seconds: int, seed: int,
               preflight_only: bool, rebuild_replay: Path | None = None,
               root: Path = ROOT) -> dict[str, object]:
    matrix_path = Path(matrix_path).resolve()
    matrix = load_matrix(matrix_path)
    if not preflight_only and seconds < 300:
        raise ValueError("real matrix campaigns require at least 300 seconds per task")
    tasks = plan_matrix_tasks(matrix, seconds=seconds, seed=seed)
    output = Path(output).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("matrix output must be new")
    output.mkdir(parents=True)
    client = os.environ.get("MYFUZZ_RFuzz_CLIENT")
    manifest: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "status": "preflight-only" if preflight_only else "running",
        "matrix": str(matrix_path), "seed": seed, "seconds_per_task": seconds,
        "main_tasks": 24, "bias_off_tasks": 8, "tasks_planned": len(tasks),
        "effective_budget_seconds": 0 if preflight_only else seconds * len(tasks),
        "rebuild_replay": _replay_probe(rebuild_replay),
        "tasks": [], "unsupported": [],
    }
    for task in tasks:
        task_config = _task_config(root, task, matrix_path=matrix_path, client=client)
        evidence = _source_lock_evidence(root, task_config)
        task_dir = output / str(task["task_id"]).replace("/", "__")
        if preflight_only:
            preflight = preflight_soc_campaign(task_config, root=root, environment=os.environ)
            row = {**task, "status": "ready" if preflight["ready"] and all(item["present"] for item in evidence) else "unsupported",
                   "preflight": preflight, "source_lock_evidence": evidence}
        else:
            row_result = run_soc_campaign(task_config, task_dir, root=root, environment=os.environ,
                                          preflight_only=False)
            row = {**task, "status": row_result.get("status"), "result": row_result,
                   "source_lock_evidence": evidence}
        if row["status"] == "unsupported":
            manifest["unsupported"].append(task["task_id"])
        manifest["tasks"].append(row)
    if manifest["unsupported"]:
        manifest["status"] = "incomplete"
    elif preflight_only:
        manifest["status"] = "preflight-only"
    else:
        manifest["status"] = "completed" if all(row["status"] == "completed" for row in manifest["tasks"]) else "incomplete"
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    return manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan/run the source-backed SoC RFuzz matrix")
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260914)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--rebuild-replay", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = run_matrix(args.matrix, args.output, seconds=args.seconds, seed=args.seed,
                          preflight_only=args.preflight_only, rebuild_replay=args.rebuild_replay)
    print(json.dumps({key: manifest[key] for key in (
        "schema_version", "status", "tasks_planned", "main_tasks", "bias_off_tasks",
        "unsupported", "effective_budget_seconds", "rebuild_replay")},
        ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if manifest["status"] in {"preflight-only", "completed"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TypeError, ValueError) as error:
        print(f"configuration-error: {error}", file=sys.stderr)
        raise SystemExit(2)
