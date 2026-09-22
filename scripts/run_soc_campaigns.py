#!/usr/bin/env python3
"""Plan or run the bounded two-CPU/three-family SoC RFuzz matrix.

The default mode is an inexpensive preflight.  A real run is deliberately
serial, requires at least 300 seconds per task, and passes through
``run_soc_campaign`` so the official RFuzz opt-in and evidence rules cannot be
bypassed by this convenience CLI.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
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


def _config_cpu(config: Mapping[str, object]) -> object:
    cpu = config.get("cpu")
    return cpu.get("id") if isinstance(cpu, Mapping) else cpu


def _peripheral_ids(config: Mapping[str, object]) -> list[str]:
    peripherals = config.get("peripherals")
    if not isinstance(peripherals, list):
        raise ValueError("cell config peripherals must be an array")
    result: list[str] = []
    for item in peripherals:
        value = item.get("id") if isinstance(item, Mapping) else item
        if not isinstance(value, str) or not value:
            raise ValueError("cell config peripheral id is malformed")
        result.append(value)
    return result


def load_matrix(path: Path, *, root: Path = ROOT) -> dict[str, object]:
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
    if cpus.count("ibex") != 1 or cpus.count("cva6") != 1 or len(cpus) != 2:
        raise ValueError("matrix must contain the two CPUs exactly once")
    if (set(families) != {"opentitan", "pulp", "zipcpu"}
            or len(families) != 3):
        raise ValueError("matrix must contain the two CPUs and three families")
    if len(cells) != 8:
        raise ValueError("matrix must contain exactly eight cells")
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
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
        pairs.add((str(cell["cpu"]), str(cell["family"])))
    required = {(cpu, family) for cpu in ("ibex", "cva6")
                for family in ("opentitan", "pulp", "zipcpu")}
    mixed = {("ibex", "mixed"), ("cva6", "mixed")}
    if pairs != required | mixed:
        raise ValueError("matrix must contain six CPU/family cells and one mixed cell per CPU")

    root = Path(root).resolve()
    family_members: dict[str, set[str]] = {}
    for family in families:
        family_doc = _load_json(root / f"configs/soc/families/{family}.json")
        family_members[str(family)] = set(_peripheral_ids(family_doc))
    for cell in cells:
        cell_id = str(cell["cell_id"])
        config_path = (root / str(cell["config"])).resolve()
        try:
            config_path.relative_to(root)
        except ValueError as error:
            raise ValueError(f"matrix cell config escapes root: {cell_id}") from error
        config = _load_json(config_path)
        if config.get("cell_id", config.get("config_id")) != cell_id:
            raise ValueError(f"matrix cell config id mismatch: {cell_id}")
        if _config_cpu(config) != cell["cpu"]:
            raise ValueError(f"matrix cell config CPU mismatch: {cell_id}")
        config_families = config.get("families")
        expected_families = ([cell["family"]] if cell["family"] != "mixed"
                             else list(families))
        if (not isinstance(config_families, list)
                or set(config_families) != set(expected_families)
                or len(config_families) != len(expected_families)):
            raise ValueError(f"matrix cell config family mismatch: {cell_id}")
        peripherals = _peripheral_ids(config)
        if len(peripherals) != len(set(peripherals)):
            raise ValueError(f"matrix cell peripherals must be distinct: {cell_id}")
        if len(peripherals) != cell["distinct_ip_count"]:
            raise ValueError(f"matrix cell distinct_ip_count mismatch: {cell_id}")
        represented = {family for family, members in family_members.items()
                       if any(item in members for item in peripherals)}
        if represented != set(expected_families):
            raise ValueError(f"matrix cell peripheral families mismatch: {cell_id}")
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
        "seed_cycles": 5,
        "reset_contract": {
            "driver": True, "memory": True, "cpu": True,
            "peripherals": True, "irq": True, "coverage": True,
        },
        "matrix_path": str(matrix_path), "bias_off": task["bias_off"],
        "base_cell": cell,
    }
    # ``None`` means that the resolver should apply its documented
    # explicit -> environment -> repository-default precedence.  Do not
    # serialize an explicit null as ``client_binary``: the RFuzz toolchain
    # contract reserves that field for a non-empty executable path and a
    # JSON null would otherwise be (correctly) rejected as malformed.
    if client is not None:
        result["client_binary"] = client
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


def rebuild_replay_matrix(
    existing: Path, output: Path, *, matrix_path: Path,
    root: Path = ROOT,
    builder: Callable[..., object] | None = None,
    replayer: Callable[[object, Path], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Rebuild and replay every retained task in an existing matrix run."""
    existing = Path(existing).resolve()
    source_manifest = _load_json(existing / "manifest.json")
    if source_manifest.get("schema_version") != RESULT_SCHEMA:
        raise ValueError("rebuild/replay matrix schema_version mismatch")
    source_tasks = source_manifest.get("tasks")
    if not isinstance(source_tasks, list):
        raise ValueError("rebuild/replay matrix tasks are malformed")

    matrix_path = Path(matrix_path).resolve()
    matrix = load_matrix(matrix_path, root=root)
    seed = source_manifest.get("seed", 0)
    seconds = source_manifest.get("seconds_per_task", 300)
    tasks = plan_matrix_tasks(matrix, seconds=seconds, seed=seed)
    expected_ids = {task["task_id"] for task in tasks}
    source_ids = {row.get("task_id") for row in source_tasks if isinstance(row, Mapping)}
    if source_ids != expected_ids:
        raise ValueError("rebuild/replay task set does not match the matrix")

    output = Path(output).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("rebuild/replay output must be new")
    output.mkdir(parents=True)
    if builder is None:
        from myfuzz.integration.soc_builder import build_soc_campaign_artifact
        builder = build_soc_campaign_artifact
    if replayer is None:
        from myfuzz.integration.rfuzz_live import replay_corpus
        replayer = replay_corpus

    result: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "status": "running",
        "matrix": str(matrix_path),
        "seed": seed,
        "seconds_per_task": seconds,
        "main_tasks": 24,
        "bias_off_tasks": 8,
        "tasks_planned": len(tasks),
        "effective_budget_seconds": 0,
        "rebuild_replay": {"status": "running", "source": str(existing)},
        "tasks": [],
        "unsupported": [],
    }
    for task in tasks:
        task_id = str(task["task_id"])
        task_name = task_id.replace("/", "__")
        corpus = existing / task_name / "live/corpus"
        row: dict[str, object] = {**task, "status": "failed"}
        try:
            if not corpus.is_dir() or not any(corpus.glob("entry_*.json")):
                raise ValueError("retained corpus is missing or empty")
            config = _task_config(root, task, matrix_path=matrix_path, client=None)
            artifact = builder(config, output / task_name / "build")
            replay = replayer(artifact, corpus)
            if (not isinstance(replay, Mapping) or replay.get("status") != "passed"
                    or not isinstance(replay.get("entries"), int)
                    or replay["entries"] < 1):
                raise ValueError("rebuild/replay did not verify a retained entry")
            row.update(status="passed", replay=dict(replay))
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"[:4096]
        result["tasks"].append(row)
    complete = len(result["tasks"]) == 32 and all(
        row.get("status") == "passed" for row in result["tasks"])
    result["status"] = "completed" if complete else "incomplete"
    result["rebuild_replay"] = {
        "status": "passed" if complete else "failed",
        "source": str(existing),
        "tasks_passed": sum(row.get("status") == "passed" for row in result["tasks"]),
    }
    (output / "manifest.json").write_text(
        json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    return result


def run_matrix(matrix_path: Path, output: Path, *, seconds: int, seed: int,
               preflight_only: bool, rebuild_replay: Path | None = None,
               root: Path = ROOT, client: str | None = None) -> dict[str, object]:
    if rebuild_replay is not None:
        return rebuild_replay_matrix(
            rebuild_replay, output, matrix_path=matrix_path, root=root)
    matrix_path = Path(matrix_path).resolve()
    matrix = load_matrix(matrix_path, root=root)
    if not preflight_only and seconds < 300:
        raise ValueError("real matrix campaigns require at least 300 seconds per task")
    tasks = plan_matrix_tasks(matrix, seconds=seconds, seed=seed)
    output = Path(output).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("matrix output must be new")
    output.mkdir(parents=True)
    client = client or os.environ.get("MYFUZZ_RFuzz_CLIENT")
    manifest: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "status": "preflight-only" if preflight_only else "running",
        "matrix": str(matrix_path), "seed": seed, "seconds_per_task": seconds,
        "main_tasks": 24, "bias_off_tasks": 8, "tasks_planned": len(tasks),
        "effective_budget_seconds": 0,
        "rebuild_replay": _replay_probe(rebuild_replay),
        "tasks": [], "unsupported": [],
    }
    campaign_rebuilder: Callable[..., object] | None = None
    if not preflight_only:
        from myfuzz.integration.soc_builder import build_soc_campaign_artifact
        campaign_rebuilder = build_soc_campaign_artifact
    for task in tasks:
        task_config = _task_config(root, task, matrix_path=matrix_path, client=client)
        evidence = _source_lock_evidence(root, task_config)
        task_dir = output / str(task["task_id"]).replace("/", "__")
        if preflight_only:
            preflight = preflight_soc_campaign(task_config, root=root, environment=os.environ)
            # A preflight is an environment/capability report, not a live
            # campaign.  A missing pinned RFuzz installation is therefore
            # recorded as an environment-unavailable row rather than being
            # mislabelled as an unsupported SoC cell.  Structural source-lock
            # failures remain genuine unsupported rows.
            if not all(item["present"] for item in evidence):
                row_status = "unsupported"
            elif preflight["ready"]:
                row_status = "ready"
            else:
                row_status = "environment-unavailable"
            row = {**task, "status": row_status,
                   "preflight": preflight, "source_lock_evidence": evidence}
        else:
            row_result = run_soc_campaign(task_config, task_dir, root=root, environment=os.environ,
                                          preflight_only=False,
                                          rebuilder=campaign_rebuilder)
            row = {**task, "status": row_result.get("status"), "result": row_result,
                   "source_lock_evidence": evidence}
            measured = row_result.get("effective_fuzz_seconds", 0)
            replay = row_result.get("replay", {})
            accepted = (
                row["status"] in {"completed", "completed_with_client_termination"}
                and isinstance(measured, (int, float)) and not isinstance(measured, bool)
                and measured >= task["seconds"]
                and isinstance(replay, Mapping) and replay.get("status") == "passed"
                and isinstance(replay.get("entries"), int) and replay["entries"] > 0
            )
            row["acceptance_complete"] = accepted
            row["effective_fuzz_seconds"] = measured if accepted else 0
            if accepted:
                manifest["effective_budget_seconds"] += measured
        if row["status"] == "unsupported":
            manifest["unsupported"].append(task["task_id"])
        manifest["tasks"].append(row)
    if manifest["unsupported"]:
        manifest["status"] = "incomplete"
    elif preflight_only:
        manifest["status"] = "preflight-only"
    else:
        # An interrupted run that retained receipts, corpus and transport identity
        # is a completed task: the client's own shutdown path is the only thing
        # that failed, and the policy in soc_campaign records the reason.
        acceptable = {"completed", "completed_with_client_termination"}
        manifest["status"] = ("completed"
                              if all(row["status"] in acceptable
                                     and row.get("acceptance_complete") is True
                                     for row in manifest["tasks"])
                              else "incomplete")
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    return manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan/run the source-backed SoC RFuzz matrix")
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260914)
    parser.add_argument("--client")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--rebuild-replay", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = run_matrix(args.matrix, args.output, seconds=args.seconds, seed=args.seed,
                          preflight_only=args.preflight_only, rebuild_replay=args.rebuild_replay,
                          client=args.client)
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
