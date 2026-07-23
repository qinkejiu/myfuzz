#!/usr/bin/env python3
"""Generate rfuzz TOML from myfuzz frontend and instrumentation manifests."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path


try:
    from myfuzz.harness.abi import manifest_ports
except ModuleNotFoundError:  # direct script execution without PYTHONPATH=src
    import sys

    sys.path.insert(0, Path(__file__).resolve().parents[2].as_posix())
    from myfuzz.harness.abi import manifest_ports


def quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def find_top_module(frontend: dict, top: str) -> dict:
    modules = frontend.get("modules", [])
    for module in modules:
        if module.get("name") == top or module.get("origName") == top:
            return module
    for module in modules:
        if module.get("top"):
            return module
    raise RuntimeError(f"Top module not found in frontend manifest: {top}")


def coverage_width(instrumentation: dict, top: str) -> int:
    for item in instrumentation.get("module_coverage", []):
        if item.get("module") == top and item.get("active"):
            return int(item.get("coverage_width", 0))
    return int(instrumentation.get("coverage_point_count", 0))


def strip_sv_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def parse_sv_int(value: str) -> int:
    value = value.strip().replace("_", "")
    if "'" not in value:
        return int(value, 0)
    _width, literal = value.split("'", 1)
    literal = literal.strip()
    if not literal:
        raise ValueError(f"invalid SystemVerilog literal: {value}")
    base = literal[0].lower()
    digits = literal[1:]
    if base == "h":
        return int(digits, 16)
    if base == "d":
        return int(digits, 10)
    if base == "b":
        return int(digits, 2)
    if base == "o":
        return int(digits, 8)
    return int(literal, 10)


def sv_range_width(range_text: str | None) -> int:
    if not range_text:
        return 1
    match = re.search(r"\[\s*([^:\]]+)\s*:\s*([^\]]+)\s*\]", range_text)
    if not match:
        return 1
    left = parse_sv_int(match.group(1))
    right = parse_sv_int(match.group(2))
    return abs(left - right) + 1


def resolve_optional(root: Path | None, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() and root is not None:
        path = root / path
    return path.resolve()


def manual_harness_input(harness_config: dict | None, root: Path | None = None) -> tuple[str, int] | None:
    if not isinstance(harness_config, dict):
        return None
    module = harness_config.get("manual_harness_module")
    harness = harness_config.get("manual_harness")
    if not module or not harness:
        return None
    input_name = str(harness_config.get("manual_harness_input", "rfuzz_input_bits"))
    text = strip_sv_comments(resolve_optional(root, str(harness)).read_text())
    pattern = re.compile(
        rf"\binput\b\s+(?:wire\s+|logic\s+|reg\s+)?(?P<range>\[[^\]]+\])?\s*"
        rf"{re.escape(input_name)}\b",
        flags=re.S,
    )
    match = pattern.search(text)
    if match is None:
        raise RuntimeError(
            f"Manual harness input {input_name!r} not found in module {module!r}: {harness}"
        )
    return input_name, sv_range_width(match.group("range"))


def candidate_ports(candidate_manifest: dict) -> dict[str, dict]:
    ports = manifest_ports(candidate_manifest)
    return {str(port["emitted_name"]): port for port in ports}


def validate_frontend_candidate_join(module: dict, top: str, candidate_manifest: dict | None) -> dict[str, dict]:
    if candidate_manifest is None:
        raise ValueError("validated candidate manifest is required for input selection")
    manifest_by_name = candidate_ports(candidate_manifest)
    candidate_top = candidate_manifest.get("top", {}).get("module") if isinstance(candidate_manifest.get("top"), dict) else None
    selected_names = {name for name in (module.get("name"), module.get("origName")) if isinstance(name, str) and name}
    if candidate_top not in selected_names:
        raise ValueError(
            f"candidate manifest top module {candidate_top!r} does not match selected frontend module {sorted(selected_names)!r}"
        )

    frontend_by_name: dict[str, dict] = {}
    for port in module.get("ports", []):
        name = port.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("frontend port name is required for candidate manifest mapping")
        if name in frontend_by_name:
            raise ValueError(f"duplicate frontend port name: {name}")
        frontend_by_name[name] = port

    for name, declared in manifest_by_name.items():
        frontend_port = frontend_by_name.get(name)
        if frontend_port is None:
            raise ValueError(f"candidate manifest port {name!r} is not present in frontend port mapping")
        if (
            declared["direction"] != str(frontend_port.get("direction", ""))
            or int(declared["width"]) != int(frontend_port.get("width", 1))
        ):
            raise ValueError(f"candidate manifest mapping mismatch for frontend port {name!r}")
    for name in frontend_by_name:
        if name not in manifest_by_name:
            raise ValueError(f"frontend port {name!r} is not bound in candidate manifest")
    return manifest_by_name


def should_fuzz_input(name: str, candidate_manifest: dict) -> bool:
    """Return the validated manifest disposition for one frontend port name."""
    port = candidate_ports(candidate_manifest).get(name)
    if port is None:
        raise ValueError(f"frontend input {name!r} is not bound in candidate manifest")
    if port["direction"] not in {"input", "inout"}:
        return False
    role = port.get("semantic_role")
    missing = object()
    fuzzable = port.get("fuzzable", port.get("fuzz_disposition", port.get("disposition", missing)))
    if fuzzable is missing:
        raise ValueError(f"fuzz disposition must be explicit for manifest port {name!r}")
    if isinstance(fuzzable, str):
        fuzzable = fuzzable in {"fuzz", "fuzzable", "enabled", "input"}
    if not isinstance(fuzzable, bool):
        raise ValueError(f"invalid fuzz disposition for manifest port {name!r}")
    return bool(fuzzable and role not in {"clock", "reset"})


def write_toml(
    frontend: dict,
    instrumentation: dict,
    top: str,
    out_path: Path,
    harness_config: dict | None = None,
    root: Path | None = None,
    candidate_manifest: dict | None = None,
) -> None:
    module = find_top_module(frontend, top)
    manifest_by_name = validate_frontend_candidate_join(module, top, candidate_manifest)
    coverage_port = instrumentation["coverage_port"]
    top_cov_width = coverage_width(instrumentation, top)
    points = list(instrumentation.get("coverage", []))
    if top_cov_width > len(points):
        for index in range(len(points), top_cov_width):
            points.append(
                {
                    "file": "",
                    "module": top,
                    "signal": f"{coverage_port}[{index}]",
                    "kind": "unknown",
                    "subtype": "padding",
                    "line": 0,
                    "column": 0,
                }
            )
    elif top_cov_width < len(points):
        points = points[:top_cov_width]

    timestamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    with out_path.open("w") as out:
        out.write("# Generated from myfuzz frontend and source instrumentation metadata.\n")
        out.write("[general]\n")
        out.write(f"filename = {quote(top)}\n")
        out.write('instrumented = "sources.f"\n')
        out.write(f"top = {quote(top)}\n")
        out.write(f"timestamp = {timestamp}\n\n")

        manual_input = manual_harness_input(harness_config, root)
        if manual_input is not None:
            name, width = manual_input
            out.write("[[input]]\n")
            out.write(f"name = {quote(name)}\n")
            out.write(f"width = {width}\n\n")
        else:
            for port in module.get("ports", []):
                name = str(port["name"])
                direction = str(port.get("direction", ""))
                if direction not in {"input", "inout"}:
                    continue
                if name == coverage_port:
                    continue
                declared = manifest_by_name.get(name)
                if declared is None:
                    raise ValueError(f"frontend input {name!r} is not bound in candidate manifest")
                if not should_fuzz_input(name, candidate_manifest):
                    continue
                out.write("[[input]]\n")
                out.write(f"name = {quote(name)}\n")
                out.write(f"width = {int(port.get('width', 1))}\n\n")

        out.write("[[port]]\n")
        out.write(f"name = {quote(coverage_port)}\n")
        out.write(f"width = {top_cov_width}\n\n")

        for index, point in enumerate(points):
            kind = str(point.get("kind", "branch"))
            subtype = str(point.get("subtype", "hit"))
            module_name = str(point.get("module", ""))
            signal = str(point.get("signal", ""))
            line = int(point.get("line") or 0)
            column = int(point.get("column") or 0)
            human = f"{module_name} {kind} {subtype} line {line}".strip()
            out.write("[[coverage]]\n")
            out.write(f"port = {quote(coverage_port)}\n")
            out.write(f"name = {quote(signal or f'{coverage_port}[{index}]')}\n")
            out.write(f"index = {index}\n")
            out.write(f"filename = {quote(str(point.get('file', '')))}\n")
            out.write(f"line = {line}\n")
            out.write(f"column = {column}\n")
            out.write(f"human = {quote(human)}\n")
            out.write('type = "expr"\n')
            out.write(f"subtype = {quote(subtype)}\n")
            out.write(f"signal = {quote(signal)}\n")
            if bool(point.get("fail", False)):
                out.write("fail = true\n")
            out.write("\n")


def generate_toml(
    frontend: dict,
    instrumentation: dict,
    top: str,
    out_path: Path,
    harness_config: dict | None = None,
    root: Path | None = None,
    candidate_manifest: dict | None = None,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_toml(frontend, instrumentation, top, out_path, harness_config, root, candidate_manifest)
    return out_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate rfuzz TOML without Verilator XML.")
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--instrumentation", required=True)
    parser.add_argument("--top", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    frontend = json.loads(Path(args.frontend).read_text())
    instrumentation = json.loads(Path(args.instrumentation).read_text())
    candidate_manifest = json.loads(Path(args.manifest).read_text())
    generate_toml(frontend, instrumentation, args.top, Path(args.out), candidate_manifest=candidate_manifest)
    print(f"Generated rfuzz TOML: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
