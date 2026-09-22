#!/usr/bin/env python3
"""Generate, render and independently audit a SoC from user profiles.

Inputs are a composition request and the component profiles it references.
Nothing is selected by component name: every connection, address, interrupt
source id and top-level port comes from the profile declarations, the protocol
and capability tables, and the elaborated RTL facts.

Example (from the repository root):

    PYTHONPATH=src:. python3 scripts/generate_soc.py \\
        --request examples/soc_generation/request.json \\
        --profile examples/soc_generation/profiles/novacore.json \\
        --profile examples/soc_generation/profiles/novauart.json \\
        --profile examples/soc_generation/profiles/novagpio.json \\
        --output runs/soc-generation/novacore-demo

Exit codes: 0 generated and audited clean, 1 the request cannot be composed,
2 the generated RTL failed the independent structure audit.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.composition.component_profile import (  # noqa: E402
    ComponentProfileError,
    load_component_profile,
    load_composition_request,
    profile_pin,
)
from myfuzz.composition.soc_composition import (  # noqa: E402
    CompositionError,
    build_composition,
    composition_document,
    composition_summary,
)
from myfuzz.composition.soc_profile_renderer import (  # noqa: E402
    SocRenderError,
    render_composition,
    source_list,
)
from myfuzz.composition.soc_structure_audit import (  # noqa: E402
    StructureAuditError,
    audit_structure,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--request", help="composition_request.v1 JSON file")
    parser.add_argument("--profile", action="append", default=[],
                        help="component_profile.v1 JSON file (repeat for each component)")
    parser.add_argument("--output", help="output directory for the generated SoC")
    parser.add_argument("--print-pin", metavar="PROFILE",
                        help="print the source-tree pin for one profile and exit without "
                             "needing --request/--output")
    parser.add_argument("--no-audit", action="store_true",
                        help="skip the independent structure audit (not recommended)")
    parser.add_argument("--drive-profile", default="cpu_execute",
                        help="declared bus-ownership profile from input_constraints.DRIVE_PROFILES "
                             "(cpu_execute, bfm_isolated, contention); bfm_isolated and "
                             "contention render the synthetic fuzz_mmio master")
    parser.add_argument("--base-dir", default=str(ROOT),
                        help="directory the profile source roots are relative to")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, document: object) -> None:
    _write(path, json.dumps(document, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    base_dir = Path(args.base_dir).resolve()
    if args.print_pin:
        profile = load_component_profile(args.print_pin)
        print(profile_pin(profile, base_dir=base_dir))
        return 0
    if not args.print_pin and (not args.request or not args.output or not args.profile):
        print("input-invalid: --request, --output and at least one --profile are required",
              file=sys.stderr)
        return 1
    profiles: dict[str, object] = {}
    try:
        for path in args.profile:
            profile = load_component_profile(path)
            profiles[path] = profile
            profiles.setdefault(profile.component_id, profile)
        request = load_composition_request(args.request, profiles=profiles)
    except ComponentProfileError as error:
        print(f"input-invalid: {error}", file=sys.stderr)
        return 1
    try:
        plan = build_composition(request, base_dir=base_dir,
                                 drive_profile=args.drive_profile)
    except (CompositionError, ComponentProfileError) as error:
        print(f"composition-failed: {error}", file=sys.stderr)
        return 1
    try:
        files = render_composition(plan)
        records = source_list(plan)
    except SocRenderError as error:
        print(f"render-failed: {error}", file=sys.stderr)
        return 1

    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    _write(output / "myfuzz_soc_top.sv", files["myfuzz_soc_top.sv"])
    source_paths = [item["path"] for item in records if item["role"] != "include_root"]
    include_roots = [item["path"] for item in records if item["role"] == "include_root"]
    _write(output / "sources.f", "".join(f"{path}\n" for path in source_paths))
    _write_json(output / "soc_composition.json", composition_document(plan))
    _write_json(output / "soc_spec.json", plan.spec)
    _write_json(output / "soc_plan.json", plan.plan)
    _write_json(output / "interrupt_plan.json", plan.interrupt_document)
    _write_json(output / "address_map.json", plan.plan["address_map"])
    _write_json(output / "raw_layout.json", plan.raw_layout)
    if plan.stimulus:
        # The compiled stimulus document is the single source of the synthetic
        # master's parameters and raw segment offsets; it is written next to the
        # plan it was compiled from.
        _write_json(output / "soc_stimulus.json", plan.stimulus)
    _write_json(output / "port_dispositions.json",
                composition_document(plan)["dispositions"])
    _write_json(output / "inputs.json", {
        "schema_version": "soc_generation_inputs.v1",
        "request": str(Path(args.request)),
        "profiles": {path: {"component_id": profile.component_id,
                            "revision": profile.source.revision}
                     for path, profile in sorted(profiles.items())},
        "base_dir": base_dir.as_posix(),
        "plan_hash": plan.plan_hash,
    })

    audit_status = "skipped"
    if not args.no_audit:
        try:
            result = audit_structure(plan, top_text=files["myfuzz_soc_top.sv"],
                                     source_files=source_paths,
                                     base_dir=base_dir,
                                     include_roots=include_roots)
        except StructureAuditError as error:
            print(f"audit-failed-to-run: {error}", file=sys.stderr)
            _write_json(output / "structure_audit.json",
                        {"schema_version": "soc_structure_audit.v1",
                         "summary": {"status": "unknown", "failed": 0, "passed": 0,
                                     "unknown": 1},
                         "error": str(error)})
            return 2
        _write_json(output / "structure_audit.json", result)
        audit_status = result["summary"]["status"]

    summary = composition_summary(plan)
    summary["audit"] = audit_status
    summary["output"] = output.as_posix()
    if not args.quiet:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if audit_status in ("pass", "skipped") else 2


if __name__ == "__main__":
    raise SystemExit(main())
