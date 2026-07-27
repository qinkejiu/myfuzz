"""Native compatibility helpers for the fixed, vendored original RFuzz checkout."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat


ORIGINAL_TOP_CPP = Path("third_party/rfuzz/rfuzz_flow/verilator/top.cpp")
ORIGINAL_QUEUE_CPP = Path("third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.cpp")
ORIGINAL_QUEUE_HPP = Path("third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.hpp")


@dataclass(frozen=True, slots=True)
class CandidateSource:
    module: str
    ports: tuple[tuple[str, int], ...]
    dut_module: str
    dut_instance: str


@dataclass(frozen=True, slots=True)
class CoverageBinding:
    top: str
    signal: str
    width: int


@dataclass(frozen=True, slots=True)
class RawAbiFragment:
    path: Path
    source: Path
    module: str
    raw_width: int
    document: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class MaterializedHarness:
    raw_abi: RawAbiFragment
    wrapper: Path
    wrapper_module: str
    header: Path
    toml: Path
    metadata: Path
    coverage: CoverageBinding


def _strip_sv_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


def _sv_width(range_text: str | None) -> int:
    if range_text is None:
        return 1
    match = re.fullmatch(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", range_text)
    if match is None:
        raise ValueError(f"candidate input has unsupported width range {range_text!r}")
    return abs(int(match.group(1)) - int(match.group(2))) + 1


def validate_candidate_source(
    source: str,
    *,
    module: str,
    ports: Sequence[tuple[str, int]],
    dut_module: str,
    dut_instance: str = "dut",
) -> CandidateSource:
    """Validate the generated candidate before any hierarchical reference is emitted."""
    if not all(isinstance(value, str) and value for value in (source, module, dut_module, dut_instance)):
        raise ValueError("candidate source and module identifiers are required")
    text = _strip_sv_comments(source)
    declaration = re.search(
        rf"\bmodule\s+{re.escape(module)}\s*\((?P<header>.*?)\)\s*;",
        text,
        flags=re.S,
    )
    if declaration is None:
        raise ValueError(f"candidate module {module!r} is not declared")
    header = declaration.group("header")
    declarations = re.findall(
        r"\b(input|output|inout)\b\s+(?:wire\s+|logic\s+|reg\s+)?"
        r"(?P<range>\[\s*\d+\s*:\s*\d+\s*\])?\s*(?P<name>[A-Za-z_$][\w$]*)",
        header,
    )
    actual: list[tuple[str, int]] = []
    for direction, range_text, name in declarations:
        if direction != "input":
            raise ValueError("candidate must expose exact input ports and no other ports")
        actual.append((name, _sv_width(range_text or None)))
    expected = tuple(ports)
    if tuple(actual) != expected:
        raise ValueError(
            f"candidate exact input ports mismatch: expected {expected!r}, got {tuple(actual)!r}"
        )
    instance = re.search(
        rf"\b{re.escape(dut_module)}\s+{re.escape(dut_instance)}\s*\(", text
    )
    if instance is None:
        raise ValueError(
            f"candidate inner DUT instance must be {dut_module} {dut_instance}"
        )
    return CandidateSource(module, expected, dut_module, dut_instance)


def validate_coverage_binding(instrumentation: object, top: str) -> CoverageBinding:
    if not isinstance(instrumentation, Mapping):
        raise ValueError("instrumentation must be an object")
    signal = instrumentation.get("coverage_port")
    if not isinstance(signal, str) or re.fullmatch(r"[A-Za-z_$][\w$]*", signal) is None:
        raise ValueError("instrumentation coverage signal must be a SystemVerilog identifier")
    records = instrumentation.get("module_coverage")
    if not isinstance(records, list):
        raise ValueError("instrumentation module_coverage must be an array")
    selected = [
        record
        for record in records
        if isinstance(record, Mapping)
        and record.get("module") == top
        and record.get("active") is True
    ]
    if len(selected) != 1:
        raise ValueError(f"selected top {top!r} must have exactly one active module coverage record")
    width = selected[0].get("coverage_width")
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise ValueError("active module coverage width must be a positive integer")
    return CoverageBinding(top, signal, width)


def _aligned_bytes_for_bits(bits: int) -> int:
    if isinstance(bits, bool) or not isinstance(bits, int) or bits <= 0:
        raise ValueError("bit width must be a positive integer")
    byte_count = (bits + 7) // 8
    return ((byte_count + 7) // 8) * 8


def aligned_coverage_width(logical_width: int) -> int:
    """Return original RFuzz's physical coverage byte count."""
    return _aligned_bytes_for_bits(logical_width * 8 + 16) - 2


def wrapper_module_name(candidate: CandidateSource, coverage: CoverageBinding) -> str:
    digest = hashlib.sha256(
        f"{candidate.module}\0{candidate.ports!r}\0{coverage.top}\0{coverage.signal}\0{coverage.width}".encode()
    ).hexdigest()[:12]
    return f"myfuzz_original_rfuzz_{digest}"


def render_wrapper(candidate: CandidateSource, coverage: CoverageBinding, *, raw_width: int) -> str:
    if not isinstance(candidate, CandidateSource) or not isinstance(coverage, CoverageBinding):
        raise TypeError("wrapper rendering requires validated candidate and coverage bindings")
    if ("rfuzz_input_bits", raw_width) not in candidate.ports:
        raise ValueError("raw ABI width does not match validated candidate input")
    input_size = _aligned_bytes_for_bits(raw_width)
    physical_width = aligned_coverage_width(coverage.width)
    module = wrapper_module_name(candidate, coverage)
    input_ports = ",\n".join(
        f"    input logic [7:0] io_input_bytes_{index}" for index in range(input_size)
    )
    coverage_ports = ",\n".join(
        f"    output logic [7:0] io_coverage_bytes_{index}"
        for index in range(physical_width)
    )
    input_assignments = "\n".join(
        f"    assign aligned_input[{index * 8 + 7}:{index * 8}] = io_input_bytes_{index};"
        for index in range(input_size)
    )
    coverage_assignments = []
    for index in range(physical_width):
        if index < coverage.width:
            coverage_assignments.append(
                f"    assign io_coverage_bytes_{index} = "
                f"{{6'b0, seen_true[{index}], seen_false[{index}]}};"
            )
        else:
            coverage_assignments.append(f"    assign io_coverage_bytes_{index} = 8'b0;")
    return f"""module {module} (
    input logic clock,
    input logic reset,
    input logic io_meta_reset,
{input_ports},
{coverage_ports}
);
    logic [{input_size * 8 - 1}:0] aligned_input;
    logic [{coverage.width - 1}:0] seen_true;
    logic [{coverage.width - 1}:0] seen_false;
{input_assignments}

    {candidate.module} candidate (
        .clock(clock),
        .reset(reset),
        .io_meta_reset(io_meta_reset),
        .rfuzz_input_bits(aligned_input[{raw_width - 1}:0])
    );

    always_ff @(posedge clock) begin
        if (reset || io_meta_reset) begin
            seen_true <= '0;
            seen_false <= '0;
        end else begin
            seen_true <= seen_true | candidate.{candidate.dut_instance}.{coverage.signal};
            seen_false <= seen_false | ~candidate.{candidate.dut_instance}.{coverage.signal};
        end
    end

{chr(10).join(coverage_assignments)}
endmodule
"""


def render_dut_header(
    wrapper_module: str, *, raw_width: int, logical_coverage_width: int
) -> str:
    input_size = _aligned_bytes_for_bits(raw_width)
    coverage_size = aligned_coverage_width(logical_coverage_width)
    apply_lines = "\n".join(
        f"    top->io_input_bytes_{index} = input[{index}];" for index in range(input_size)
    )
    read_lines = "\n".join(
        f"    coverage[{index}] = top->io_coverage_bytes_{index};"
        for index in range(coverage_size)
    )
    return f"""#ifndef MYFUZZ_ORIGINAL_RFUZZ_DUT_HPP
#define MYFUZZ_ORIGINAL_RFUZZ_DUT_HPP
#include <cstddef>
#include <cstdint>
#include <V{wrapper_module}.h>
#define TOP_TYPE V{wrapper_module}
#define TOPLEVEL_STR \"{wrapper_module}\"
static constexpr std::size_t CoverageSize = {coverage_size};
static constexpr std::size_t InputSize = {input_size};
static inline void apply_input(TOP_TYPE* top, const std::uint8_t* input) {{
{apply_lines}
}}
static inline void read_coverage(TOP_TYPE* top, std::uint8_t* coverage) {{
{read_lines}
}}
#endif
"""


def augment_toml(base: str, logical_coverage_width: int) -> str:
    if not isinstance(base, str):
        raise TypeError("base TOML must be text")
    blocks = [base.rstrip(), ""]
    for index in range(logical_coverage_width):
        blocks.extend(
            (
                "[[counter]]",
                'name = "TF"',
                "width = 8",
                "max = 3",
                "scale = false",
                f"index = {index}",
                f"signal = {index}",
                "fail = false",
                "",
            )
        )
    return "\n".join(blocks)


def _regular_repository_file(root: Path, path: Path, label: str) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} must remain beneath the repository") from error
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError(f"{label} is missing: {candidate}") from error
    if not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return resolved


def select_raw_abi_fragment(root: Path, harness_dir: Path) -> RawAbiFragment:
    root = root.resolve()
    harness = harness_dir.resolve()
    try:
        harness.relative_to(root)
    except ValueError as error:
        raise ValueError("harness directory must remain beneath the repository") from error
    fragments = sorted(harness.glob("*.abi.json"))
    if len(fragments) != 1:
        raise ValueError("harness directory must contain exactly one raw ABI fragment")
    path = _regular_repository_file(root, fragments[0], "raw ABI fragment")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("raw ABI fragment must be valid JSON") from error
    if not isinstance(document, Mapping):
        raise ValueError("raw ABI fragment must be an object")
    source_name = document.get("source")
    module = document.get("module")
    raw_width = document.get("raw_width")
    if (
        not isinstance(source_name, str)
        or not source_name
        or Path(source_name).name != source_name
        or not isinstance(module, str)
        or not module
        or isinstance(raw_width, bool)
        or not isinstance(raw_width, int)
        or raw_width <= 0
    ):
        raise ValueError("raw ABI fragment source, module, and raw_width are required")
    source = _regular_repository_file(root, harness / source_name, "raw ABI source")
    if source.parent != harness:
        raise ValueError("raw ABI source must be in the selected harness directory")
    return RawAbiFragment(path, source, module, raw_width, document)


def build_server_command(
    root: Path,
    *,
    verilator_bin: str,
    wrapper_module: str,
    sources_file: Path,
    wrapper: Path,
    candidate_source: Path,
    dut_header: Path,
    server_dir: Path,
    extra_sources: Sequence[Path] = (),
    extra_cflags: Sequence[str] = (),
    extra_ldflags: Sequence[str] = (),
    verilator_args: Sequence[str] = (),
    cxx_opt: str = "-O3",
    verilator_opt: str = "-O3",
) -> list[str]:
    if not isinstance(verilator_bin, str) or not verilator_bin:
        raise ValueError("Verilator executable is required")
    sources = _regular_repository_file(root, sources_file, "instrumented source list")
    wrapper_path = _regular_repository_file(root, wrapper, "RFuzz wrapper")
    candidate_path = _regular_repository_file(root, candidate_source, "candidate harness")
    header = _regular_repository_file(root, dut_header, "RFuzz DUT header")
    top_cpp = _regular_repository_file(root, ORIGINAL_TOP_CPP, "original RFuzz top.cpp")
    queue_cpp = _regular_repository_file(root, ORIGINAL_QUEUE_CPP, "original RFuzz fpga_queue.cpp")
    _regular_repository_file(root, ORIGINAL_QUEUE_HPP, "original RFuzz fpga_queue.hpp")
    validated_extra = [
        _regular_repository_file(root, Path(path), "extra Verilator source")
        for path in extra_sources
    ]
    server = server_dir.resolve()
    try:
        server.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("server directory must remain beneath the repository") from error
    object_dir = server / "obj_dir"
    executable = server / "server"
    include_flags = f"-I{header.parent.as_posix()} -I{top_cpp.parent.as_posix()} {cxx_opt} -DVL_USER_FINISH -DVM_TRACE=0"
    command = [
        verilator_bin,
        "--cc",
        "--exe",
        "--build",
        "--build-jobs",
        "1",
        "--top-module",
        wrapper_module,
        "--Mdir",
        object_dir.as_posix(),
        "-o",
        executable.as_posix(),
        verilator_opt,
        "-f",
        sources.as_posix(),
        candidate_path.as_posix(),
        wrapper_path.as_posix(),
        top_cpp.as_posix(),
        queue_cpp.as_posix(),
        *(path.as_posix() for path in validated_extra),
        "-CFLAGS",
        " ".join((include_flags, *extra_cflags)).strip(),
        "-Wno-fatal",
    ]
    if extra_ldflags:
        command.extend(("-LDFLAGS", " ".join(extra_ldflags)))
    command.extend(str(argument) for argument in verilator_args)
    return command


def materialize_harness(
    root: Path,
    *,
    harness_dir: Path,
    base_toml: Path,
    instrumentation: object,
    top: str,
    expected_ports: Sequence[tuple[str, int]],
) -> MaterializedHarness:
    """Materialize all generated inputs consumed by the original RFuzz server/fuzzer."""
    raw_abi = select_raw_abi_fragment(root, harness_dir)
    base = _regular_repository_file(root, base_toml, "base RFuzz TOML")
    candidate = validate_candidate_source(
        raw_abi.source.read_text(encoding="utf-8"),
        module=raw_abi.module,
        ports=expected_ports,
        dut_module=top,
        dut_instance="dut",
    )
    coverage = validate_coverage_binding(instrumentation, top)
    module = wrapper_module_name(candidate, coverage)
    harness = harness_dir.resolve()
    wrapper = write_text_file(
        harness / "original_rfuzz_wrapper.sv",
        render_wrapper(candidate, coverage, raw_width=raw_abi.raw_width),
    )
    header = write_text_file(
        harness / "dut.hpp",
        render_dut_header(
            module,
            raw_width=raw_abi.raw_width,
            logical_coverage_width=coverage.width,
        ),
    )
    toml = write_text_file(
        harness / f"{top}.rfuzz.toml",
        augment_toml(base.read_text(encoding="utf-8"), coverage.width),
    )
    metadata = harness / "original_rfuzz.json"
    metadata.write_text(
        json.dumps(
            {
                "schema_version": "myfuzz.original_rfuzz.v1",
                "raw_abi": raw_abi.path.name,
                "candidate_source": raw_abi.source.name,
                "candidate_module": raw_abi.module,
                "raw_width": raw_abi.raw_width,
                "top": top,
                "coverage_signal": coverage.signal,
                "coverage_width": coverage.width,
                "physical_coverage_width": aligned_coverage_width(coverage.width),
                "wrapper": wrapper.name,
                "wrapper_module": module,
                "header": header.name,
                "toml": toml.name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return MaterializedHarness(raw_abi, wrapper, module, header, toml, metadata, coverage)


def load_materialized_harness(root: Path, harness_dir: Path) -> MaterializedHarness:
    """Reload and cross-check materialized files before invoking Verilator."""
    harness = harness_dir.resolve()
    raw_abi = select_raw_abi_fragment(root, harness)
    metadata_path = _regular_repository_file(
        root, harness / "original_rfuzz.json", "original RFuzz metadata"
    )
    try:
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("original RFuzz metadata must be valid JSON") from error
    expected = {
        "schema_version": "myfuzz.original_rfuzz.v1",
        "raw_abi": raw_abi.path.name,
        "candidate_source": raw_abi.source.name,
        "candidate_module": raw_abi.module,
        "raw_width": raw_abi.raw_width,
    }
    if not isinstance(document, Mapping) or any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("original RFuzz metadata does not match the selected raw ABI")
    top = document.get("top")
    signal = document.get("coverage_signal")
    width = document.get("coverage_width")
    physical = document.get("physical_coverage_width")
    module = document.get("wrapper_module")
    if (
        not isinstance(top, str)
        or not top
        or not isinstance(signal, str)
        or not signal
        or isinstance(width, bool)
        or not isinstance(width, int)
        or width <= 0
        or physical != aligned_coverage_width(width)
        or not isinstance(module, str)
        or not module
    ):
        raise ValueError("original RFuzz metadata has invalid coverage or wrapper binding")

    def bound_file(key: str, label: str) -> Path:
        name = document.get(key)
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError(f"original RFuzz metadata {key} must be a file name")
        return _regular_repository_file(root, harness / name, label)

    wrapper = bound_file("wrapper", "RFuzz wrapper")
    header = bound_file("header", "RFuzz DUT header")
    toml = bound_file("toml", "augmented RFuzz TOML")
    return MaterializedHarness(
        raw_abi,
        wrapper,
        module,
        header,
        toml,
        metadata_path,
        CoverageBinding(top, signal, width),
    )


def write_text_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


__all__ = [
    "CandidateSource",
    "CoverageBinding",
    "MaterializedHarness",
    "RawAbiFragment",
    "aligned_coverage_width",
    "augment_toml",
    "build_server_command",
    "load_materialized_harness",
    "materialize_harness",
    "render_dut_header",
    "render_wrapper",
    "select_raw_abi_fragment",
    "validate_candidate_source",
    "validate_coverage_binding",
    "wrapper_module_name",
    "write_text_file",
]
