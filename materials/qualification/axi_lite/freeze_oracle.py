#!/usr/bin/env python3
"""Create or check the offline, content-locked AXI-Lite qualification oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[3]
MATERIALS_ROOT = REPO_ROOT / "materials"
QUALIFICATION_ROOT = MATERIALS_ROOT / "qualification" / "axi_lite"
sys.path.insert(0, str(REPO_ROOT / "src"))

from myfuzz.builder.contracts import build_elaboration_manifest  # noqa: E402
from myfuzz.builder.qualification import compute_oracle_digest  # noqa: E402


UPSTREAMS = {
    "picorv32": {
        "source": "https://github.com/YosysHQ/picorv32.git",
        "revision": "87c89acc18994c8cf9a2311e871818e87d304568",
        "archive_sha256": "5795a2144f19a58507d2252e8377714ee9ce7c611341e6c29c448651f203e824",
        "submodules": [],
    },
    "ultra_riscv": {
        "source": "https://github.com/ultraembedded/riscv.git",
        "revision": "7ae6f803e30f78c6ea3121e73c3adf50ff912730",
        "archive_sha256": "52a7637048d3f6ed6d26b4733994429cacabc4ae62384ec614c17b5c6c4485df",
        "submodules": [],
    },
    "verilog_axi": {
        "source": "https://github.com/alexforencich/verilog-axi.git",
        "revision": "516bd5dadc3365b7f9e225d2af8fe0b8d804fe53",
        "archive_sha256": "1ab8b3f0320c3757d968f86cc79ad42968e378bab22d045a6cd8ca6c6a3b6676",
        "submodules": [],
    },
    "pulp_axi": {
        "source": "https://github.com/pulp-platform/axi.git",
        "revision": "e55ae2a7ee606ee3cfd4257f63982a971b704407",
        "archive_sha256": "6a304548026e5c4b4cc864ca89deace6d43a15dcecd795fb12df42138b55caac",
        "submodules": [],
    },
    "common_cells": {
        "source": "https://github.com/pulp-platform/common_cells.git",
        "revision": "9ca8a7655f741e7dd5736669a20a301325194c28",
        "archive_sha256": "5bdd5aba92c237097b681a1e82224830189d6941db6b594d2b03aab7803b0f5c",
        "submodules": [],
    },
}


QUALIFIED = (
    {
        "id": "picorv32_cpu", "kind": "cpu", "module": "picorv32_axil_cpu_wrapper",
        "family": "picorv32", "split": "development", "filelist": "picorv32_cpu.f",
        "address_width": 32, "parameters": {}, "clock": "clk", "reset": "resetn",
        "prefix": "m", "upstreams": ("picorv32",),
        "license_groups": (("ISC", "upstream/picorv32/COPYING",
                            ("upstream/picorv32/", "wrappers/picorv32_axil_cpu_wrapper.sv")),),
        "patches": ("wrappers/picorv32_axil_cpu_wrapper.sv",),
    },
    {
        "id": "verilog_axi_ram", "kind": "ip", "module": "verilog_axi_ram_wrapper",
        "family": "verilog_axi", "split": "development", "filelist": "verilog_axi_ram.f",
        "address_width": 16, "parameters": {"DATA_WIDTH": 32, "ADDR_WIDTH": 16},
        "clock": "clk", "reset": "reset", "prefix": "s", "upstreams": ("verilog_axi",),
        "license_groups": (("MIT", "upstream/verilog_axi/COPYING",
                            ("upstream/verilog_axi/", "wrappers/verilog_axi_ram_wrapper.sv")),),
        "patches": ("wrappers/verilog_axi_ram_wrapper.sv",),
    },
    {
        "id": "verilog_axi_dp_ram", "kind": "ip", "module": "verilog_axi_dp_ram_wrapper",
        "family": "verilog_axi", "split": "development", "filelist": "verilog_axi_dp_ram.f",
        "address_width": 12, "parameters": {}, "clock": "clk", "reset": "reset",
        "prefix": "s", "upstreams": ("verilog_axi",),
        "license_groups": (("MIT", "upstream/verilog_axi/COPYING",
                            ("upstream/verilog_axi/", "wrappers/verilog_axi_dp_ram_wrapper.sv")),),
        "patches": ("wrappers/verilog_axi_dp_ram_wrapper.sv",),
    },
    {
        "id": "ultra_riscv_cpu", "kind": "cpu", "module": "ultra_riscv_axil_cpu_wrapper",
        "family": "ultraembedded_riscv", "split": "holdout", "filelist": "ultra_riscv_cpu.f",
        "address_width": 32, "parameters": {}, "clock": "clk", "reset": "reset",
        "prefix": "m", "upstreams": ("ultra_riscv",),
        "license_groups": (("BSD-3-Clause", "upstream/ultraembedded_riscv/LICENSE",
                            ("upstream/ultraembedded_riscv/", "wrappers/ultra_riscv_axil_cpu_wrapper.sv")),),
        "patches": ("wrappers/ultra_riscv_axil_cpu_wrapper.sv",),
    },
    {
        "id": "pulp_axi_lite_regs", "kind": "ip", "module": "pulp_axi_lite_regs_wrapper",
        "family": "pulp_axi", "split": "holdout", "filelist": "pulp_axi_lite_regs.f",
        "address_width": 32, "parameters": {}, "clock": "clk", "reset": "resetn",
        "prefix": "s", "upstreams": ("pulp_axi", "common_cells"),
        "license_groups": (
            ("SHL-0.51", "upstream/pulp_axi/LICENSE",
             ("upstream/pulp_axi/", "wrappers/pulp_axi_lite_regs_wrapper.sv")),
            ("SHL-0.51", "upstream/common_cells/LICENSE", ("upstream/common_cells/",)),
        ),
        "patches": ("wrappers/pulp_axi_lite_regs_wrapper.sv",),
    },
    {
        "id": "pulp_axi_lite_lfsr", "kind": "ip", "module": "pulp_axi_lite_lfsr_wrapper",
        "family": "pulp_axi", "split": "holdout", "filelist": "pulp_axi_lite_lfsr.f",
        "address_width": 32, "parameters": {}, "clock": "clk", "reset": "resetn",
        "prefix": "s", "upstreams": ("pulp_axi", "common_cells"),
        "license_groups": (
            ("SHL-0.51", "upstream/pulp_axi/LICENSE",
             ("upstream/pulp_axi/", "wrappers/pulp_axi_lite_lfsr_wrapper.sv")),
            ("SHL-0.51", "upstream/common_cells/LICENSE", ("upstream/common_cells/",)),
        ),
        "patches": ("wrappers/pulp_axi_lite_lfsr_wrapper.sv",),
    },
)


REJECTED = (
    ("local_pulp_models", "ip", "pulp_axi_lite_regs_model", "local_behavioral_pulp_models",
     "rejected_local_pulp_models.f", "behavioral name-based model, not immutable native upstream RTL"),
    ("maxim_model", "ip", "maxim_max11100_adc_model", "local_maxim_models",
     "rejected_maxim_model.f", "serial ADC model has no AXI-Lite target interface"),
    ("axi_dma_model", "ip", "axi_dma_model", "local_axi_dma_models",
     "rejected_axi_dma_model.f", "behavioral placeholder has no complete AXI-Lite target interface"),
    ("ariane_model", "cpu", "ariane_core_model", "local_ariane_models",
     "rejected_ariane_model.f", "behavioral placeholder is not an independently elaborated native AXI-Lite CPU"),
    ("cva6_model", "cpu", "cva6_core_model", "local_cva6_models",
     "rejected_cva6_model.f", "behavioral placeholder is not an independently elaborated native AXI-Lite CPU"),
    ("probe_cpu", "cpu", "axi_lite_probe_cpu", "local_protocol_probe",
     "rejected_probe_cpu.f", "protocol exerciser is explicitly not a software-programmed CPU core"),
)


SEMANTICS = (
    "awvalid", "awready", "awaddr", "wvalid", "wready", "wdata", "wstrb", "bvalid",
    "bready", "bresp", "arvalid", "arready", "araddr", "rvalid", "rready", "rdata",
    "rresp",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(MATERIALS_ROOT.resolve()).as_posix()


def _content(path: Path) -> dict[str, object]:
    return {"path": _relative(path), "sha256": _sha(path), "size": path.stat().st_size}


def _sources(filelist: Path, module: str) -> list[dict[str, object]]:
    manifest = build_elaboration_manifest(
        top_module=module, filelists=(filelist,), allow_roots=(MATERIALS_ROOT,),
    )
    return [_content(Path(source.path)) for source in manifest.sources]


def _interface(spec: dict[str, object]) -> dict[str, str]:
    result = {"clock": str(spec["clock"]), "reset": str(spec["reset"])}
    result.update({semantic: f"{spec['prefix']}_{semantic}" for semantic in SEMANTICS})
    return result


def _qualified_candidate(spec: dict[str, object]) -> dict[str, object]:
    filelist = QUALIFICATION_ROOT / "cases" / str(spec["filelist"])
    sources = _sources(filelist, str(spec["module"]))
    dependencies = []
    if "pulp_axi" in spec["upstreams"]:
        for directory in (
            QUALIFICATION_ROOT / "upstream" / "pulp_axi" / "include",
            QUALIFICATION_ROOT / "upstream" / "common_cells" / "include",
        ):
            dependencies.extend(_content(path) for path in sorted(directory.rglob("*.svh")))
    material_paths = [str(item["path"]) for item in (*sources, *dependencies)]
    licenses = []
    for spdx, license_name, prefixes in spec["license_groups"]:
        license_path = QUALIFICATION_ROOT / str(license_name)
        applies_to = [name for name in material_paths if any(name.startswith(
            f"qualification/axi_lite/{prefix}") for prefix in prefixes)]
        licenses.append({
            "spdx": spdx, "path": _relative(license_path), "sha256": _sha(license_path),
            "redistribution": True, "applies_to": applies_to,
        })
    return {
        "id": spec["id"], "kind": spec["kind"], "module": spec["module"],
        "family": spec["family"], "split": spec["split"], "status": "qualified",
        "reason": "independently elaborates and exposes a complete supported AXI-Lite interface",
        "protocol": "axi_lite", "data_width": 32, "address_width": spec["address_width"],
        "parameters": spec["parameters"], "filelist": _relative(filelist),
        "filelist_sha256": _sha(filelist), "sources": sources, "dependencies": dependencies,
        "licenses": licenses,
        "provenance": {
            "upstreams": [UPSTREAMS[name] for name in spec["upstreams"]],
            "patches": [{"path": f"qualification/axi_lite/{name}",
                         "sha256": _sha(QUALIFICATION_ROOT / name)} for name in spec["patches"]],
        },
        "interface": _interface(spec),
    }


def _rejected_candidate(spec: tuple[str, ...]) -> dict[str, object]:
    identifier, kind, module, family, filelist_name, reason = spec
    filelist = QUALIFICATION_ROOT / "cases" / filelist_name
    sources = _sources(filelist, module)
    source_hash = str(sources[0]["sha256"])
    return {
        "id": identifier, "kind": kind, "module": module, "family": family,
        "split": "development", "status": "rejected", "reason": reason,
        "protocol": "axi_lite", "data_width": 32, "address_width": 32, "parameters": {},
        "filelist": _relative(filelist), "filelist_sha256": _sha(filelist), "sources": sources,
        "dependencies": [], "licenses": [],
        "provenance": {"upstreams": [{
            "source": "checked-in local historical material", "revision": source_hash,
            "archive_sha256": source_hash, "submodules": [],
        }], "patches": []},
        "interface": {},
    }


def build_oracle() -> dict[str, object]:
    candidates = [_qualified_candidate(spec) for spec in QUALIFIED]
    candidates.extend(_rejected_candidate(spec) for spec in REJECTED)
    qualified = [candidate for candidate in candidates if candidate["status"] == "qualified"]
    cpus = [candidate for candidate in qualified if candidate["kind"] == "cpu"]
    ips = [candidate for candidate in qualified if candidate["kind"] == "ip"]
    compatibility = []
    for cpu in cpus:
        for ip in ips:
            compatible = cpu["data_width"] == ip["data_width"] and cpu["split"] == ip["split"]
            compatibility.append({
                "cpu": cpu["id"], "ip": ip["id"], "compatible": compatible,
                "reason": "same split and equal data width" if compatible else "split isolation",
            })
    cases = []
    for name, expected_bytes in (("development_case", 4_000_000), ("holdout_case", 12_000_000)):
        config = QUALIFICATION_ROOT / "cases" / f"{name}.json"
        data = json.loads(config.read_text(encoding="utf-8"))
        cases.append({
            "id": data["id"], "split": data["split"], "cpu": data["cpu"], "ips": data["ips"],
            "manifest_hash": _sha(config), "expected_artifact_bytes": expected_bytes,
            "resource_budget": {"compile_seconds": 300, "run_seconds": 120,
                                "max_bytes": 200_000_000},
        })
    family_assignments = []
    for candidate in candidates:
        assignment = {"family": candidate["family"], "split": candidate["split"]}
        if assignment not in family_assignments:
            family_assignments.append(assignment)
    oracle = {
        "schema": "myfuzz.qualification-oracle/v1", "oracle_version": "1",
        "oracle_implementation_sha256": _sha(REPO_ROOT / "src/myfuzz/builder/qualification.py"),
        "frozen_revision": "slice-h-axi-lite-dataset-v1", "protocol": "axi_lite",
        "oracle_digest": "",
        "dataset": {
            "split_unit": "source_family", "policy": "frozen_family_assignments_v1",
            "development_percent": 80, "holdout_percent": 20,
            "family_assignments": family_assignments,
        },
        "candidates": candidates, "compatibility": compatibility, "cases": cases,
        "experiment": {
            "seeds": list(range(1, 11)), "cycles": 256, "timeout_seconds": 120,
            "early_cycle": 64, "entropy_matched": True,
            "coverage_reset": "fresh_process_per_run", "merge": "point_id_union",
            "censoring": "timeouts_and_resource_exhaustion_are_failures",
            "confidence_interval": "paired_bootstrap_95_percent", "confidence_level": 0.95,
            "bootstrap_resamples": 10000, "bootstrap_seed": 20260713,
            "determinism_check": "repeat_first_seed_byte_identical",
        },
    }
    oracle["oracle_digest"] = compute_oracle_digest(oracle)
    return oracle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if oracle.json is not current")
    args = parser.parse_args()
    output = QUALIFICATION_ROOT / "oracle.json"
    rendered = json.dumps(build_oracle(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale qualification oracle: {output}", file=sys.stderr)
            return 1
        return 0
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
