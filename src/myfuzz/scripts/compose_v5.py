#!/usr/bin/env python3
"""Qualify strict compose-v5 manifests and audit real target availability."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.compose_v5 import (  # noqa: E402
    audit_compose_v5_targets,
    build_compose_v5_abcd_scheme_plan_from_manifest,
    build_compose_v5_connection_plan_from_manifest,
    build_compose_v5_scheme_a_layout_from_manifest,
    discover_compose_v5_contracts,
    emit_compose_v5_scheme_a_flat_shell_from_manifest,
    emit_compose_v5_scheme_a_harness_bundle_from_manifest,
    load_compose_v5_manifest,
    qualify_compose_v5_manifest,
    write_compose_v5_json,
)
from myfuzz.builder.input_model import InputValidationError  # noqa: E402


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--allow-root", type=Path, action="append", default=[])
    parser.add_argument("--verify-elaboration", action="store_true")
    parser.add_argument("--frontend-library", type=Path)
    parser.add_argument("--output", type=Path, required=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    qualify = commands.add_parser("qualify", help="qualify one compose-v5 manifest")
    _common(qualify)
    qualify.add_argument("--manifest", type=Path, required=True)
    discover = commands.add_parser(
        "discover-contracts",
        help="run frontend-backed contract discovery for one compose-v5 manifest",
    )
    _common(discover)
    discover.add_argument("--manifest", type=Path, required=True)
    layout = commands.add_parser(
        "layout",
        help="build a scheme-A rawbits layout for one compose-v5 manifest",
    )
    _common(layout)
    layout.add_argument("--manifest", type=Path, required=True)
    flat_top = commands.add_parser(
        "flat-top",
        help="emit a scheme-A flat top for one compose-v5 manifest",
    )
    _common(flat_top)
    flat_top.add_argument("--manifest", type=Path, required=True)
    flat_top.add_argument("--module-name", default="compose_v5_scheme_a_flat_top")
    harness = commands.add_parser(
        "scheme-a-harness",
        help="emit scheme-A flat top plus rawbits harness for one compose-v5 manifest",
    )
    _common(harness)
    harness.add_argument("--manifest", type=Path, required=True)
    harness.add_argument("--flat-module-name", default="compose_v5_scheme_a_flat_top")
    harness.add_argument("--module-name", default="compose_v5_scheme_a_harness")
    scheme_plan = commands.add_parser(
        "scheme-plan",
        help="write the compose-v5 A/B/C/D bit-level scheme plan for one manifest",
    )
    _common(scheme_plan)
    scheme_plan.add_argument("--manifest", type=Path, required=True)
    scheme_plan.add_argument("--stall-inputs-before-escalation", type=int, default=256)
    connection_plan = commands.add_parser(
        "connection-plan",
        help="write the compose-v5 CPU-master connection/address/bridge plan for one manifest",
    )
    _common(connection_plan)
    connection_plan.add_argument("--manifest", type=Path, required=True)
    audit = commands.add_parser("audit", help="audit named target manifests")
    _common(audit)
    audit.add_argument(
        "--target", action="append", required=True, metavar="ID=MANIFEST",
        help="target identifier and manifest path; may be repeated",
    )
    return parser.parse_args(argv)


def _targets(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        target_id, separator, manifest = value.partition("=")
        if not separator or not target_id.strip() or not manifest.strip():
            raise InputValidationError(f"invalid --target {value!r}; expected ID=MANIFEST")
        if target_id in result:
            raise InputValidationError(f"duplicate --target id {target_id!r}")
        result[target_id] = Path(manifest)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    roots = args.allow_root or [args.project_root]
    if args.command == "qualify":
        manifest = load_compose_v5_manifest(args.manifest)
        report = qualify_compose_v5_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            verify_elaboration=args.verify_elaboration,
            frontend_library=args.frontend_library,
        )
        write_compose_v5_json(report, args.output)
        print(f"{report.digest} {'qualified' if report.eligible else 'rejected'} {args.output}")
        return 0 if report.eligible else 2
    if args.command == "discover-contracts":
        manifest = load_compose_v5_manifest(args.manifest)
        report = discover_compose_v5_contracts(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
        )
        write_compose_v5_json(report, args.output)
        print(f"{report.digest} {report.status} {args.output}")
        return 0 if report.status == "unique" else 2
    if args.command == "layout":
        manifest = load_compose_v5_manifest(args.manifest)
        layout = build_compose_v5_scheme_a_layout_from_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
        )
        write_compose_v5_json(layout, args.output)
        print(f"{layout.digest} layout {args.output}")
        return 0
    if args.command == "flat-top":
        manifest = load_compose_v5_manifest(args.manifest)
        emitted = emit_compose_v5_scheme_a_flat_shell_from_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
            module_name=args.module_name,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(emitted.rtl, encoding="utf-8")
        print(f"{emitted.module_name} flat-top {args.output}")
        return 0
    if args.command == "scheme-a-harness":
        manifest = load_compose_v5_manifest(args.manifest)
        bundle = emit_compose_v5_scheme_a_harness_bundle_from_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
            flat_module_name=args.flat_module_name,
            harness_module_name=args.module_name,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(bundle.rtl, encoding="utf-8")
        print(
            f"{bundle.harness.module_name} scheme-a-harness "
            f"{bundle.layout.record_width_bits}b {args.output}"
        )
        return 0
    if args.command == "scheme-plan":
        manifest = load_compose_v5_manifest(args.manifest)
        plan = build_compose_v5_abcd_scheme_plan_from_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
            stall_inputs_before_escalation=args.stall_inputs_before_escalation,
        )
        write_compose_v5_json(plan, args.output)
        print(f"{plan.digest} scheme-plan {args.output}")
        return 0
    if args.command == "connection-plan":
        manifest = load_compose_v5_manifest(args.manifest)
        plan = build_compose_v5_connection_plan_from_manifest(
            manifest,
            project_root=args.project_root,
            allow_roots=roots,
            frontend_library=args.frontend_library,
        )
        write_compose_v5_json(plan, args.output)
        print(f"{plan.digest} connection-plan {args.output}")
        return 0
    report = audit_compose_v5_targets(
        _targets(args.target),
        project_root=args.project_root,
        allow_roots=roots,
        verify_elaboration=args.verify_elaboration,
        frontend_library=args.frontend_library,
    )
    write_compose_v5_json(report, args.output)
    print(f"{report.digest} {'qualified' if report.all_eligible else 'ineligible'} {args.output}")
    return 0 if report.all_eligible else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InputValidationError as exc:
        raise SystemExit(f"compose-v5: {exc}") from exc
