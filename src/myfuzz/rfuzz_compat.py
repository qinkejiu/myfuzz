"""Compatibility artifacts for the original RFuzz Verilator protocol."""

from __future__ import annotations

import os
import stat
from pathlib import Path


RFUZZ_VERILATOR_RELATIVE = Path(
    "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
)
RFUZZ_VERILATOR_BIN_RELATIVE = Path(
    "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator_bin"
)
RFUZZ_VERILATOR_ROOT_RELATIVE = Path(
    "third_party/rfuzz/upstream/.tools/apt-root/usr/share/verilator"
)
RFUZZ_VERILATOR_VERSION_PREFIX = "Verilator 5.020"


def resolve_rfuzz_verilator(repo_root: Path) -> str:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        raise ValueError("repo_root must be an absolute pathlib.Path")
    override = os.environ.get("MYFUZZ_SERVER_VERILATOR_BIN")
    if override:
        return override
    candidate = repo_root / RFUZZ_VERILATOR_RELATIVE
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError(
            "bundled RFuzz Verilator 5.020 is missing; set "
            "MYFUZZ_SERVER_VERILATOR_BIN to an explicitly validated executable"
        ) from error
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(candidate, os.X_OK)
    ):
        raise ValueError(
            "bundled RFuzz Verilator 5.020 is not an executable regular file; "
            "set MYFUZZ_SERVER_VERILATOR_BIN to an explicitly validated executable"
        )
    return candidate.resolve().as_posix()


def rfuzz_verilator_environment(
    repo_root: Path, verilator_bin: str
) -> dict[str, str] | None:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        raise ValueError("repo_root must be an absolute pathlib.Path")
    if not isinstance(verilator_bin, str) or not verilator_bin:
        raise ValueError("verilator_bin must be a non-empty string")
    bundled = (repo_root / RFUZZ_VERILATOR_RELATIVE).resolve()
    if Path(verilator_bin).resolve() != bundled:
        return None

    binary = repo_root / RFUZZ_VERILATOR_BIN_RELATIVE
    install_root = repo_root / RFUZZ_VERILATOR_ROOT_RELATIVE
    try:
        binary_metadata = binary.lstat()
        install_metadata = install_root.lstat()
    except OSError as error:
        raise ValueError(
            "bundled RFuzz Verilator 5.020 installation is incomplete"
        ) from error
    if (
        binary.is_symlink()
        or not stat.S_ISREG(binary_metadata.st_mode)
        or not os.access(binary, os.X_OK)
        or install_root.is_symlink()
        or not stat.S_ISDIR(install_metadata.st_mode)
    ):
        raise ValueError(
            "bundled RFuzz Verilator 5.020 installation is incomplete"
        )

    environment = os.environ.copy()
    environment["VERILATOR_ROOT"] = install_root.resolve().as_posix()
    environment["VERILATOR_BIN"] = "../../bin/verilator_bin"
    return environment


def validate_rfuzz_verilator_version(version: str) -> str:
    if not isinstance(version, str) or not version.startswith(RFUZZ_VERILATOR_VERSION_PREFIX):
        raise ValueError(
            f"native RFuzz requires Verilator 5.020; observed {version!r}"
        )
    return version


def _align(value: int, alignment: int) -> int:
    if value < 0:
        raise ValueError("width must be non-negative")
    return ((value + alignment - 1) // alignment) * alignment


def aligned_input_bytes(input_width: int) -> int:
    return _align((input_width + 7) // 8, 8)


def aligned_coverage_bytes(coverage_width: int) -> int:
    return _align(coverage_width + 2, 8) - 2


def render_adapter(
    *,
    top: str,
    manual_module: str,
    input_name: str,
    input_width: int,
    coverage_port: str,
    coverage_width: int,
) -> str:
    input_bytes = aligned_input_bytes(input_width)
    coverage_bytes = aligned_coverage_bytes(coverage_width)
    ports = [
        "    input logic clock",
        "    input logic reset",
        "    input logic io_meta_reset",
        *(f"    input logic [7:0] io_input_bytes_{index}" for index in range(input_bytes)),
        *(f"    output logic [7:0] io_coverage_bytes_{index}" for index in range(coverage_bytes)),
    ]
    lines = [
        f"module {top}_VHarness (",
        ",\n".join(ports),
        ");",
        f"    logic [{input_width - 1}:0] {input_name};",
        f"    logic [{coverage_width - 1}:0] {coverage_port};",
        "",
    ]
    for index in range(input_bytes):
        low = index * 8
        if low >= input_width:
            continue
        high = min(low + 7, input_width - 1)
        byte_high = high - low
        if byte_high == 7:
            rhs = f"io_input_bytes_{index}"
        else:
            rhs = f"io_input_bytes_{index}[{byte_high}:0]"
        lines.append(f"    assign {input_name}[{high}:{low}] = {rhs};")
    lines.extend(
        [
            "",
            f"    {manual_module} dut (",
            "        .clock(clock),",
            "        .reset(reset),",
            "        .io_meta_reset(io_meta_reset),",
            f"        .{input_name}({input_name}),",
            f"        .{coverage_port}({coverage_port})",
            "    );",
            "",
        ]
    )
    for index in range(coverage_bytes):
        value = f"{{7'b0, {coverage_port}[{index}]}}" if index < coverage_width else "8'b0"
        lines.append(f"    assign io_coverage_bytes_{index} = {value};")
    lines.extend(["", "endmodule", ""])
    return "\n".join(lines)


def render_augmented_toml(base_toml: str, *, coverage_width: int) -> str:
    result = base_toml.rstrip() + "\n\n"
    for index in range(coverage_width):
        result += (
            "[[counter]]\n"
            f'name = "coverage_{index}"\n'
            "width = 8\n"
            "max = 1\n"
            "scale = false\n"
            f"index = {index}\n"
            f"signal = {index}\n"
            "fail = false\n\n"
        )
    return result


def _toml_quote(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def render_rfuzz_toml(
    *,
    top: str,
    input_name: str,
    input_width: int,
    coverage_width: int,
    instrumentation: dict,
    timestamp: str,
) -> str:
    coverage_port = str(instrumentation.get("coverage_port", "__vi_coverage"))
    points = list(instrumentation.get("coverage", []))[:coverage_width]
    while len(points) < coverage_width:
        index = len(points)
        points.append(
            {
                "file": "",
                "module": top,
                "signal": f"{coverage_port}[{index}]",
                "line": 0,
                "column": 0,
                "kind": "unknown",
                "subtype": "padding",
            }
        )
    lines = [
        "# Generated by myfuzz.rfuzz_compat.",
        "[general]",
        f"filename = {_toml_quote(top)}",
        'instrumented = "sources.f"',
        f"top = {_toml_quote(top)}",
        f"timestamp = {timestamp}",
        "",
        "[[input]]",
        f"name = {_toml_quote(input_name)}",
        f"width = {input_width}",
        "",
    ]
    for index, point in enumerate(points):
        module = str(point.get("module", top))
        kind = str(point.get("kind", "branch"))
        subtype = str(point.get("subtype", "hit"))
        line = int(point.get("line") or 0)
        lines.extend(
            [
                "[[coverage]]",
                f"port = {_toml_quote(coverage_port)}",
                f"name = {_toml_quote(point.get('signal') or f'{coverage_port}[{index}]')}",
                f"index = {index}",
                f"filename = {_toml_quote(point.get('file', ''))}",
                f"line = {line}",
                f"column = {int(point.get('column') or 0)}",
                f"human = {_toml_quote(f'{module} {kind} {subtype} line {line}')}",
                "",
            ]
        )
    return render_augmented_toml("\n".join(lines), coverage_width=coverage_width)


def server_build_command(
    *,
    verilator: Path,
    flist: Path,
    manual_harness: Path,
    adapter: Path,
    top: str,
    out_dir: Path,
    rfuzz_verilator_dir: Path,
    extra_args: list[str],
) -> list[str]:
    object_dir = out_dir / "obj_dir"
    cflags = f"-I{rfuzz_verilator_dir} -I{out_dir} -DVL_USER_FINISH"
    return [
        str(verilator),
        "--cc",
        "--exe",
        "--build",
        "-j",
        "1",
        "--Mdir",
        str(object_dir),
        "--top-module",
        f"{top}_VHarness",
        "-Wno-fatal",
        *extra_args,
        "-f",
        str(flist),
        str(manual_harness),
        str(adapter),
        str(rfuzz_verilator_dir / "top.cpp"),
        str(rfuzz_verilator_dir / "fpga_queue.cpp"),
        "-CFLAGS",
        cflags,
        "-o",
        str(out_dir / "server"),
    ]


def render_dut_header(*, top: str, input_width: int, coverage_width: int) -> str:
    input_size = aligned_input_bytes(input_width)
    coverage_size = aligned_coverage_bytes(coverage_width)
    apply_lines = "\n".join(
        f"    top->io_input_bytes_{index} = input[{index}];" for index in range(input_size)
    )
    coverage_lines = "\n".join(
        f"    coverage[{index}] = top->io_coverage_bytes_{index};"
        for index in range(coverage_size)
    )
    return f"""// Generated by myfuzz.rfuzz_compat.
#ifndef DUT_CONF_HPP
#define DUT_CONF_HPP

#include <V{top}_VHarness.h>
#define TOP_TYPE V{top}_VHarness
#define TOPLEVEL_STR \"{top}\"

static constexpr size_t InputSize = {input_size};
static constexpr size_t CoverageSize = {coverage_size};

static inline void apply_input(TOP_TYPE* top, const uint8_t* input) {{
{apply_lines}
}}

static inline void read_coverage(TOP_TYPE* top, uint8_t* coverage) {{
{coverage_lines}
}}

#endif
"""
