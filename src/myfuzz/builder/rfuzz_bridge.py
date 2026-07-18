"""RFUZZ metadata bridge for explicitly fuzz-enabled unknown inputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from myfuzz.rfuzz.input_generator import generate_and_write

from .planner import SystemPlan
from .unknown_ports import UnknownPortAction


LEGACY_RFUZZ_FORMAT = "legacy-v1"


def emit_rfuzz_metadata(
    plan: SystemPlan, output_dir: str | Path, *, format_version: str,
) -> dict[str, Any]:
    _require_legacy_format(format_version)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    mappings = [
        {
            "module": item.module,
            "port": item.port,
            "width": item.width,
            "action": "PIN_INJECT",
            "payload_bits": min(item.width, 6),
            "constraint": item.constraint,
            "reset_behavior": item.reset_behavior,
            "reason": item.reason,
            "source": item.evidence_source,
        }
        for item in plan.unknown_ports
        if item.action is UnknownPortAction.RFUZZ_DRIVE
    ]
    actions = [{"name": "WAIT", "encoding": "00xxxxxx"}]
    if mappings:
        actions.append({
            "name": "PIN_INJECT",
            "encoding": "10VVVVVV",
            "targets": [f"{item['module']}.{item['port']}" for item in mappings],
        })
    action_definitions = {
        "schema_version": 1,
        "actions": actions,
        "input_mappings": mappings,
    }
    transaction_plan = {
        "schema_version": 1,
        "regions": [
            {
                "component": item["module"],
                "port": item["port"],
                "width": item["width"],
                "kind": "rfuzz_input",
                "scenario_priority": 0,
            }
            for item in mappings
        ],
        "sequences": [],
    }
    _write_json(out / "action_definitions.json", action_definitions)
    _write_json(out / "transaction_plan.json", transaction_plan)
    result = {
        "metadata_dir": out.as_posix(),
        "fuzz_input_count": len(mappings),
        "mapped_bits": sum(item["width"] for item in mappings),
        "action_definitions": (out / "action_definitions.json").as_posix(),
        "transaction_plan": (out / "transaction_plan.json").as_posix(),
    }
    _update_generation_report(out, "rfuzz", result)
    return result


def generate_rfuzz_testcase(
    metadata_dir: str | Path,
    output_dir: str | Path,
    *,
    cycles: int = 1024,
    seed: int = 1,
    name: str = "rfuzz_seed",
    format_version: str,
) -> dict[str, str]:
    _require_legacy_format(format_version)
    return generate_and_write(
        Path(metadata_dir), Path(output_dir), cycles=cycles, seed=seed, name=name,
        format_version=format_version,
    )


def _require_legacy_format(format_version: str) -> None:
    if format_version != LEGACY_RFUZZ_FORMAT:
        raise ValueError(
            f"legacy RFUZZ action bridge requires format_version={LEGACY_RFUZZ_FORMAT!r}"
        )


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _update_generation_report(output_dir: Path, key: str, value: Any) -> None:
    path = output_dir / "generation_report.json"
    if not path.exists():
        return
    report = json.loads(path.read_text(encoding="utf-8"))
    report[key] = value
    for generated in ("action_definitions.json", "transaction_plan.json"):
        if generated not in report["generated_files"]:
            report["generated_files"].append(generated)
    _write_json(path, report)
