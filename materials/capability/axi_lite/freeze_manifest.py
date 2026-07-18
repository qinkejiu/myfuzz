#!/usr/bin/env python3
"""Freeze the scaled AXI-Lite capability-system inputs without network access."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[3]
MATERIALS_ROOT = REPO_ROOT / "materials"
ROOT = MATERIALS_ROOT / "capability" / "axi_lite"
FORMAL_ROOT = MATERIALS_ROOT / "qualification" / "axi_lite"
sys.path.insert(0, str(REPO_ROOT / "src"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: dict[str, object]) -> str:
    payload = dict(value)
    payload.pop("manifest_digest", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_manifest() -> dict[str, object]:
    formal = json.loads((FORMAL_ROOT / "oracle.json").read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in formal["candidates"]}
    ips = []
    for source_id in (
        "verilog_axi_ram", "verilog_axi_dp_ram", "pulp_axi_lite_regs",
        "pulp_axi_lite_lfsr",
    ):
        for instance_index in range(2):
            candidate = copy.deepcopy(by_id[source_id])
            candidate["id"] = f"{source_id}_{instance_index}"
            candidate["split"] = "capability"
            ips.append(candidate)
    case_names = ("picorv32_scale_system", "ultra_riscv_scale_system")
    cases = []
    for case_name in case_names:
        config = ROOT / "cases" / f"{case_name}.json"
        case_data = json.loads(config.read_text(encoding="utf-8"))
        cases.append({
            "id": case_data["id"], "split": case_data["split"],
            "cpu": case_data["cpu"], "ips": case_data["ips"],
            "manifest_hash": _sha(config), "expected_artifact_bytes": 80_000_000,
            "resource_budget": {
                "compile_seconds": 1200, "run_seconds": 120, "max_bytes": 900_000_000,
            },
        })
    manifest = {
        "schema": "myfuzz.capability-manifest/v1",
        "frozen_revision": "scaled-two-cpu-eight-ip-v1",
        "manifest_digest": "",
        "formal_oracle_digest": formal["oracle_digest"],
        "candidates": [
            by_id["picorv32_cpu"], by_id["ultra_riscv_cpu"],
            *ips,
        ],
        "cases": cases,
        "experiment": {"cycles": 64, "timeout_seconds": 120, "seed": 1},
    }
    manifest["manifest_digest"] = _digest(manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = ROOT / "manifest.json"
    rendered = json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale capability manifest: {output}", file=sys.stderr)
            return 1
        return 0
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
