#!/usr/bin/env python3
"""Generate rfuzz TOML from myfuzz frontend and instrumentation manifests."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path


CLOCK_NAMES = {"clock", "clk", "clk_i"}
RESET_NAMES = {"reset", "rst", "rst_i", "reset_i"}
ACTIVE_LOW_RESET_NAMES = {"rst_n", "rst_ni", "reset_n", "reset_ni"}


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


def harness_name_set(harness_config: dict | None, key: str) -> set[str]:
    if not isinstance(harness_config, dict):
        return set()
    value = harness_config.get(key, [])
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def harness_constant_inputs(harness_config: dict | None) -> dict[str, str]:
    if not isinstance(harness_config, dict):
        return {}
    value = harness_config.get("constant_inputs", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(expr) for key, expr in value.items()}


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


def should_fuzz_input(name: str, harness_config: dict | None) -> bool:
    clock_ports = CLOCK_NAMES | harness_name_set(harness_config, "clock_ports")
    reset_ports = RESET_NAMES | harness_name_set(harness_config, "reset_ports")
    active_low_reset_ports = ACTIVE_LOW_RESET_NAMES | harness_name_set(harness_config, "active_low_reset_ports")
    excluded = harness_name_set(harness_config, "exclude_inputs")
    constants = set(harness_constant_inputs(harness_config))
    fuzz_inputs = harness_name_set(harness_config, "fuzz_inputs")
    if fuzz_inputs:
        return name in fuzz_inputs
    return name not in clock_ports | reset_ports | active_low_reset_ports | excluded | constants


def write_toml(
    frontend: dict,
    instrumentation: dict,
    top: str,
    out_path: Path,
    harness_config: dict | None = None,
    root: Path | None = None,
) -> None:
    module = find_top_module(frontend, top)
    coverage_port = instrumentation["coverage_port"]
    abi = instrumentation.get("coverage_abi")
    if isinstance(abi, dict):
        if abi.get("port_name") != coverage_port:
            raise RuntimeError("CoverageABI port does not match instrumentation coverage_port")
        top_cov_width = int(abi.get("width", 0))
        points = [point for point in abi.get("points", []) if point.get("included")]
        offsets = sorted(int(point["offset"]) for point in points)
        if offsets != list(range(top_cov_width)):
            raise RuntimeError("CoverageABI offsets do not exactly cover the top vector")
        points.sort(key=lambda point: int(point["offset"]))
    else:
        top_cov_width = coverage_width(instrumentation, top)
        points = list(instrumentation.get("coverage", []))
        if top_cov_width != len(points):
            raise RuntimeError("legacy coverage metadata width mismatch; padding is forbidden")

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
                if direction != "input":
                    continue
                if name == coverage_port:
                    continue
                if not should_fuzz_input(name, harness_config):
                    continue
                out.write("[[input]]\n")
                out.write(f"name = {quote(name)}\n")
                out.write(f"width = {int(port.get('width', 1))}\n\n")

        out.write("[[port]]\n")
        out.write(f"name = {quote(coverage_port)}\n")
        out.write(f"width = {top_cov_width}\n\n")

        for index, point in enumerate(points):
            index = int(point.get("offset", index))
            kind = str(point.get("kind", "branch"))
            subtype = str(point.get("subtype", "hit"))
            module_name = str(point.get("module", ""))
            signal = str(point.get("signal", point.get("point_id", "")))
            line = int(point.get("source_line", point.get("line", 0)) or 0)
            column = int(point.get("source_column", point.get("column", 0)) or 0)
            human = f"{module_name} {kind} {subtype} line {line}".strip()
            out.write("[[coverage]]\n")
            out.write(f"port = {quote(coverage_port)}\n")
            out.write(f"name = {quote(signal or f'{coverage_port}[{index}]')}\n")
            out.write(f"index = {index}\n")
            out.write(f"filename = {quote(str(point.get('source_file', point.get('file', ''))))}\n")
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
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_toml(frontend, instrumentation, top, out_path, harness_config, root)
    return out_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate rfuzz TOML without Verilator XML.")
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--instrumentation", required=True)
    parser.add_argument("--top", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    frontend = json.loads(Path(args.frontend).read_text())
    instrumentation = json.loads(Path(args.instrumentation).read_text())
    generate_toml(frontend, instrumentation, args.top, Path(args.out))
    print(f"Generated rfuzz TOML: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
