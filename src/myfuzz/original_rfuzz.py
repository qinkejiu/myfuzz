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
ORIGINAL_FUZZER_HPP = Path("third_party/rfuzz/rfuzz_flow/verilator/fuzzer.hpp")
_SV_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_SV_MODULE_DECLARATION = re.compile(r"\bmodule\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")
_SV_ENDMODULE = re.compile(r"\bendmodule\b")


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
    direction: str = "output"


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


@dataclass(frozen=True, slots=True)
class _SourceGraph:
    source_list: Path
    source_files: tuple[Path, ...]
    include_dirs: tuple[Path, ...]
    file_hashes: Mapping[str, str]
    graph_hash: str


def _sv_syntax_mask(text: str) -> str:
    """Mask comments and strings while preserving source positions and newlines."""
    masked = list(text)
    index = 0
    state = "code"
    while index < len(text):
        character = text[index]
        if state == "code":
            if character == '"':
                masked[index] = " "
                state = "string"
            elif character == "/" and index + 1 < len(text) and text[index + 1] == "/":
                masked[index] = masked[index + 1] = " "
                index += 1
                state = "line-comment"
            elif character == "/" and index + 1 < len(text) and text[index + 1] == "*":
                masked[index] = masked[index + 1] = " "
                index += 1
                state = "block-comment"
        elif state == "string":
            if character == "\\" and index + 1 < len(text):
                masked[index] = " "
                index += 1
                if masked[index] != "\n":
                    masked[index] = " "
            elif character == '"':
                masked[index] = " "
                state = "code"
            elif character != "\n":
                masked[index] = " "
        elif state == "line-comment":
            if character == "\n":
                state = "code"
            else:
                masked[index] = " "
        else:
            if character == "*" and index + 1 < len(text) and text[index + 1] == "/":
                masked[index] = masked[index + 1] = " "
                index += 1
                state = "code"
            elif character != "\n":
                masked[index] = " "
        index += 1
    return "".join(masked)


def _sv_width(range_text: str | None) -> int:
    if range_text is None:
        return 1
    match = re.fullmatch(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", range_text)
    if match is None:
        raise ValueError(f"candidate input has unsupported width range {range_text!r}")
    return abs(int(match.group(1)) - int(match.group(2))) + 1


def _require_sv_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _SV_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SystemVerilog identifier")
    return value


def _module_declaration_end(text: str, start: int, label: str) -> int:
    depth = 0
    for index in range(start, len(text)):
        character = text[index]
        if character == "(":
            depth += 1
        elif character == ")":
            if depth == 0:
                raise ValueError(f"{label} has an unbalanced module declaration")
            depth -= 1
        elif character == ";" and depth == 0:
            return index
    raise ValueError(f"{label} declaration must end with a semicolon")


def _selected_module_scope(source: str, module: str, label: str) -> tuple[str, str]:
    """Return the selected module declaration and body, rejecting ambiguous scopes."""
    text = _sv_syntax_mask(source)
    declarations = [
        match for match in _SV_MODULE_DECLARATION.finditer(text) if match.group("name") == module
    ]
    if len(declarations) != 1:
        raise ValueError(f"{label} requires exactly one {label} declaration")

    declaration = declarations[0]
    declaration_end = _module_declaration_end(text, declaration.end(), label)
    body_start = declaration_end + 1
    endmodule = _SV_ENDMODULE.search(text, body_start)
    nested_module = _SV_MODULE_DECLARATION.search(text, body_start)
    if endmodule is None or (
        nested_module is not None and nested_module.start() < endmodule.start()
    ):
        raise ValueError(f"{label} must terminate with endmodule before another module declaration")
    return text[declaration.end() : declaration_end], text[body_start : endmodule.start()]


def has_unique_closed_sv_module(source: str, module: str, label: str) -> bool:
    """Return whether source contains the selected module as one closed scope."""
    module = _require_sv_identifier(module, label)
    text = _sv_syntax_mask(source)
    declarations = [
        match for match in _SV_MODULE_DECLARATION.finditer(text) if match.group("name") == module
    ]
    if not declarations:
        return False
    _selected_module_scope(source, module, label)
    return True


def _module_top_level_statements(body: str) -> list[str]:
    """Return semicolon-terminated module statements outside function/task bodies."""
    statements: list[str] = []
    start = 0
    scope_depth = 0
    index = 0
    token_pattern = re.compile(r"\b(function|task|endfunction|endtask)\b")
    while index < len(body):
        token = token_pattern.match(body, index)
        if token is not None:
            keyword = token.group(1)
            if keyword in {"function", "task"}:
                if scope_depth == 0:
                    start = token.start()
                scope_depth += 1
            elif scope_depth:
                scope_depth -= 1
                if scope_depth == 0:
                    # Discard the whole subprogram, including its formal ports.
                    start = token.end()
            index = token.end()
            continue
        if body[index] == ";" and scope_depth == 0:
            statements.append(body[start:index])
            start = index + 1
        index += 1
    return statements


def _split_top_level_commas(text: str, label: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{",
    }
    for index, character in enumerate(text):
        if character in depths:
            depths[character] += 1
        elif character in closing:
            opener = closing[character]
            if depths[opener] == 0:
                raise ValueError(f"{label} has unbalanced delimiters")
            depths[opener] -= 1
        elif character == "," and not any(depths.values()):
            parts.append(text[start:index].strip())
            start = index + 1
    if any(depths.values()):
        raise ValueError(f"{label} has unbalanced delimiters")
    parts.append(text[start:].strip())
    return parts


def _parse_ansi_port_segment(segment: str, label: str) -> tuple[str, str, int]:
    declaration = re.fullmatch(
        r"(?P<direction>input|output|inout)\s+"
        r"(?:(?:wire|logic|reg|bit|tri|tri0|tri1|uwire|wand|wor|supply0|supply1|signed)\s+)*"
        r"(?P<range>\[[^\[\]]+\]\s+)?"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)",
        segment.strip(),
    )
    if declaration is None:
        raise ValueError(f"{label} ANSI port declaration cannot be parsed: {segment!r}")
    return (
        declaration.group("direction"),
        declaration.group("name"),
        _sv_width(declaration.group("range").strip() if declaration.group("range") else None),
    )


def _parse_ansi_ports(header: str, label: str) -> list[tuple[str, str, int]]:
    value = header.strip()
    if not (value.startswith("(") and value.endswith(")")):
        raise ValueError(f"{label} must use an ANSI port header")
    inner = value[1:-1].strip()
    if not inner:
        return []
    segments = _split_top_level_commas(inner, label)
    if any(not segment for segment in segments):
        raise ValueError(f"{label} contains an empty ANSI port declaration")
    return [_parse_ansi_port_segment(segment, label) for segment in segments]


def validate_candidate_source(
    source: str,
    *,
    module: str,
    ports: Sequence[tuple[str, int]],
    dut_module: str,
    dut_instance: str = "dut",
) -> CandidateSource:
    """Validate the generated candidate before any hierarchical reference is emitted."""
    if not isinstance(source, str) or not source:
        raise ValueError("candidate source is required")
    module = _require_sv_identifier(module, "candidate module")
    dut_module = _require_sv_identifier(dut_module, "candidate DUT module")
    dut_instance = _require_sv_identifier(dut_instance, "candidate DUT instance")
    header, body = _selected_module_scope(source, module, "candidate module")
    try:
        declarations = _parse_ansi_ports(header, "candidate exact input ports")
    except ValueError as error:
        raise ValueError(f"candidate exact input ports cannot be parsed: {error}") from error
    actual: list[tuple[str, int]] = []
    for direction, name, width in declarations:
        if direction != "input":
            raise ValueError("candidate must expose exact input ports and no other ports")
        actual.append((name, width))
    expected = tuple(ports)
    if tuple(actual) != expected:
        raise ValueError(
            f"candidate exact input ports mismatch: expected {expected!r}, got {tuple(actual)!r}"
        )
    instance = re.search(
        rf"\b{re.escape(dut_module)}\s+{re.escape(dut_instance)}\s*\(", body
    )
    if instance is None:
        raise ValueError(
            f"candidate inner DUT instance must be {dut_module} {dut_instance}"
        )
    return CandidateSource(module, expected, dut_module, dut_instance)


def validate_coverage_binding(
    instrumentation: object, top: str, design_source: str | None = None
) -> CoverageBinding:
    if not isinstance(instrumentation, Mapping):
        raise ValueError("instrumentation must be an object")
    top = _require_sv_identifier(top, "selected top module")
    signal = instrumentation.get("coverage_port")
    signal = _require_sv_identifier(signal, "instrumentation coverage signal")
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
    if design_source is not None:
        if not isinstance(design_source, str):
            raise ValueError("selected top design source must be text")
        header, body = _selected_module_scope(
            design_source, top, "selected top coverage port"
        )
        port_pattern = (
            r"\b(?P<direction>input|output|inout)\b\s+"
            r"(?:(?:wire|logic|reg)\s+)?(?:signed\s+)?"
            rf"(?P<range>\[\s*\d+\s*:\s*\d+\s*\])?\s*"
            rf"{re.escape(signal)}\b"
        )
        ports = list(re.finditer(port_pattern, header))
        for statement in _module_top_level_statements(body):
            ports.extend(re.finditer(port_pattern, statement))
        if len(ports) != 1 or ports[0].group("direction") != "output":
            raise ValueError(f"selected top coverage port {signal!r} is not declared")
        actual_width = _sv_width(ports[0].group("range") or None)
        if actual_width != width:
            raise ValueError(
                f"selected top coverage port width {actual_width} does not match instrumentation width {width}"
            )
    return CoverageBinding(top, signal, width, "output")


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


def _regular_repository_directory(root: Path, path: Path, label: str) -> Path:
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
    if not stat.S_ISDIR(metadata.st_mode) or candidate.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink directory")
    return resolved


def _relative_repository_path(root: Path, path: Path, label: str) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"{label} must remain beneath the repository") from error


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _directory_file_hashes(root: Path, directory: Path, label: str) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*"), key=lambda value: value.as_posix()):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError(f"{label} cannot be inspected: {path}") from error
        if path.is_symlink():
            raise ValueError(f"{label} contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} contains a non-regular file: {path}")
        files.append(
            {
                "path": _relative_repository_path(root, path, label),
                "sha256": _sha256_file(path),
            }
        )
    return files


def _validated_source_graph(root: Path, sources_file: Path) -> _SourceGraph:
    root = root.resolve()
    source_list = _regular_repository_file(root, sources_file, "instrumented source list")
    try:
        lines = source_list.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("instrumented source list cannot be read") from error

    source_files: list[Path] = []
    include_dirs: list[Path] = []
    entries: list[dict[str, object]] = []
    file_hashes: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("//", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("+incdir+"):
            values = line[len("+incdir+") :].split("+")
            if any(not value for value in values):
                raise ValueError(f"source list entry line {line_number} has an empty +incdir+ path")
            for value in values:
                directory = _regular_repository_directory(
                    root,
                    source_list.parent / value,
                    "source list entry +incdir+ directory",
                )
                include_dirs.append(directory)
                directory_files = _directory_file_hashes(
                    root, directory, "source list entry +incdir+ directory"
                )
                for item in directory_files:
                    file_hashes[item["path"]] = item["sha256"]
                entries.append(
                    {
                        "kind": "include_dir",
                        "path": _relative_repository_path(root, directory, "source list entry"),
                        "files": directory_files,
                    }
                )
            continue
        if line.startswith("-"):
            raise ValueError(
                f"source list entry line {line_number} has unsupported option {line!r}"
            )
        if len(line.split()) != 1:
            raise ValueError(
                f"source list entry line {line_number} must contain one source path"
            )
        source = _regular_repository_file(
            root, source_list.parent / line, "source list entry"
        )
        source_files.append(source)
        source_hash = _sha256_file(source)
        relative = _relative_repository_path(root, source, "source list entry")
        file_hashes[relative] = source_hash
        entries.append({"kind": "source", "path": relative, "sha256": source_hash})

    document = {
        "source_list": _relative_repository_path(root, source_list, "instrumented source list"),
        "source_list_sha256": _sha256_file(source_list),
        "entries": entries,
    }
    graph_hash = "sha256:" + hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _SourceGraph(
        source_list,
        tuple(source_files),
        tuple(include_dirs),
        file_hashes,
        graph_hash,
    )


def source_list_entries(root: Path, sources_file: Path) -> tuple[Path, ...]:
    """Validate a Verilator source list and return every ordinary source entry."""
    return _validated_source_graph(root, sources_file).source_files


def source_graph_hash(root: Path, sources_file: Path) -> str:
    """Return a content hash for the source list and all files it exposes."""
    return _validated_source_graph(root, sources_file).graph_hash


def native_input_identity(
    root: Path,
    *,
    sources_file: Path,
    verilator_bin: str,
    verilator_version: str,
    extra_sources: Sequence[Path] = (),
    extra_cflags: Sequence[str] = (),
    extra_ldflags: Sequence[str] = (),
    verilator_args: Sequence[str] = (),
    cxx_opt: str = "-O3",
    verilator_opt: str = "-O3",
) -> str:
    """Return the content identity of every fixed input to the native RFuzz build."""
    if not isinstance(verilator_bin, str) or not verilator_bin:
        raise ValueError("Verilator executable is required for native input identity")
    if not isinstance(verilator_version, str) or not verilator_version:
        raise ValueError("Verilator version is required for native input identity")

    def text_sequence(values: Sequence[str], label: str) -> list[str]:
        if isinstance(values, (str, bytes)):
            raise ValueError(f"{label} must be a sequence")
        result = list(values)
        if any(not isinstance(value, str) for value in result):
            raise ValueError(f"{label} must contain strings")
        return result

    repository = root.resolve()
    source_graph = _validated_source_graph(repository, sources_file)
    fixed_sources: list[dict[str, str]] = []
    for relative in (
        ORIGINAL_TOP_CPP,
        ORIGINAL_QUEUE_CPP,
        ORIGINAL_QUEUE_HPP,
        ORIGINAL_FUZZER_HPP,
    ):
        path = _regular_repository_file(
            repository, relative, "original RFuzz native input"
        )
        fixed_sources.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256_file(path),
            }
        )

    extra_records: list[dict[str, str]] = []
    for value in extra_sources:
        path = _regular_repository_file(
            repository, Path(value), "extra Verilator source"
        )
        extra_records.append(
            {
                "path": _relative_repository_path(
                    repository, path, "extra Verilator source"
                ),
                "sha256": _sha256_file(path),
            }
        )

    document = {
        "schema_version": "myfuzz.original_rfuzz.native-input.v1",
        "source_graph_hash": source_graph.graph_hash,
        "fixed_sources": fixed_sources,
        "extra_sources": extra_records,
        "verilator": {
            "binary": verilator_bin,
            "version": verilator_version,
            "args": text_sequence(verilator_args, "verilator_args"),
            "opt": verilator_opt,
        },
        "cxx_opt": cxx_opt,
        "extra_cflags": text_sequence(extra_cflags, "extra_cflags"),
        "extra_ldflags": text_sequence(extra_ldflags, "extra_ldflags"),
        "command_binding": "single-worker-fixed.v2",
    }
    return "sha256:" + hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_sources_file(root: Path, sources_file: Path) -> tuple[Path, ...]:
    """Fail closed on unsupported or unsafe source-list input."""
    return source_list_entries(root, sources_file)


def select_raw_abi_fragment(root: Path, harness_dir: Path) -> RawAbiFragment:
    root = root.resolve()
    harness = _regular_repository_directory(root, harness_dir, "harness directory")
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
    arguments = tuple(str(argument) for argument in verilator_args)
    for argument in arguments:
        if (
            argument in {"-j", "--build-jobs"}
            or argument.startswith("-j") and argument[2:].isdigit()
            or argument.startswith("--build-jobs=")
        ):
            raise ValueError("verilator_args cannot override the single Verilator worker")
    fixed_options = (
        "--cc",
        "--exe",
        "--build",
        "--top-module",
        "--Mdir",
        "-o",
        "-f",
        "-CFLAGS",
        "-LDFLAGS",
    )
    for argument in arguments:
        if argument in fixed_options or any(
            argument.startswith(f"{option}=") for option in fixed_options
        ):
            raise ValueError(
                "verilator_args cannot override the fixed Verilator binding"
            )
    sources = _regular_repository_file(root, sources_file, "instrumented source list")
    source_graph = _validated_source_graph(root, sources)
    if not source_graph.source_files:
        raise ValueError("instrumented source list must contain at least one source list entry")
    wrapper_path = _regular_repository_file(root, wrapper, "RFuzz wrapper")
    candidate_path = _regular_repository_file(root, candidate_source, "candidate harness")
    header = _regular_repository_file(root, dut_header, "RFuzz DUT header")
    top_cpp = _regular_repository_file(root, ORIGINAL_TOP_CPP, "original RFuzz top.cpp")
    queue_cpp = _regular_repository_file(root, ORIGINAL_QUEUE_CPP, "original RFuzz fpga_queue.cpp")
    _regular_repository_file(root, ORIGINAL_QUEUE_HPP, "original RFuzz fpga_queue.hpp")
    _regular_repository_file(root, ORIGINAL_FUZZER_HPP, "original RFuzz fuzzer.hpp")
    validated_extra = [
        _regular_repository_file(root, Path(path), "extra Verilator source")
        for path in extra_sources
    ]
    server_candidate = server_dir if server_dir.is_absolute() else root / server_dir
    parent = server_candidate
    while True:
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            if parent == parent.parent:
                raise ValueError("server directory parent cannot be inspected")
            parent = parent.parent
            continue
        if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("server directory must be a regular non-symlink directory")
        if parent == parent.parent:
            break
        parent = parent.parent
    server = server_candidate.resolve()
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
    sources_file: Path,
    design_source: str,
) -> MaterializedHarness:
    """Materialize all generated inputs consumed by the original RFuzz server/fuzzer."""
    source_graph = _validated_source_graph(root, sources_file)
    if not source_graph.source_files:
        raise ValueError("instrumented source list must contain at least one source list entry")
    if not isinstance(design_source, str) or not design_source:
        raise ValueError("selected top design source is required")
    raw_abi = select_raw_abi_fragment(root, harness_dir)
    base = _regular_repository_file(root, base_toml, "base RFuzz TOML")
    candidate = validate_candidate_source(
        raw_abi.source.read_text(encoding="utf-8"),
        module=raw_abi.module,
        ports=expected_ports,
        dut_module=top,
        dut_instance="dut",
    )
    coverage = validate_coverage_binding(instrumentation, top, design_source)
    module = wrapper_module_name(candidate, coverage)
    harness = harness_dir.resolve()
    wrapper_path = harness / "original_rfuzz_wrapper.sv"
    header_path = harness / "dut.hpp"
    toml_path = harness / f"{top}.rfuzz.toml"
    metadata = harness / "original_rfuzz.json"
    for output in (wrapper_path, header_path, toml_path, metadata):
        _validate_generated_output(output)
    wrapper = write_text_file(
        wrapper_path,
        render_wrapper(candidate, coverage, raw_width=raw_abi.raw_width),
    )
    header = write_text_file(
        header_path,
        render_dut_header(
            module,
            raw_width=raw_abi.raw_width,
            logical_coverage_width=coverage.width,
        ),
    )
    toml = write_text_file(
        toml_path,
        augment_toml(base.read_text(encoding="utf-8"), coverage.width),
    )

    def file_hash(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    write_text_file(
        metadata,
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
                "candidate_source_hash": file_hash(raw_abi.source),
                "design_source_hash": "sha256:" + hashlib.sha256(design_source.encode("utf-8")).hexdigest(),
                "source_graph_hash": source_graph.graph_hash,
                "wrapper_hash": file_hash(wrapper),
                "header_hash": file_hash(header),
                "toml_hash": file_hash(toml),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    return MaterializedHarness(raw_abi, wrapper, module, header, toml, metadata, coverage)


def load_materialized_harness(
    root: Path,
    harness_dir: Path,
    *,
    instrumentation: object,
    sources_file: Path,
    design_source: str,
) -> MaterializedHarness:
    """Reload and cross-check materialized files before invoking Verilator."""
    source_graph = _validated_source_graph(root, sources_file)
    if not source_graph.source_files:
        raise ValueError("instrumented source list must contain at least one source list entry")
    if not isinstance(design_source, str) or not design_source:
        raise ValueError("selected top design source is required")
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
    current_design_hash = "sha256:" + hashlib.sha256(design_source.encode("utf-8")).hexdigest()
    if document.get("design_source_hash") != current_design_hash:
        raise ValueError("materialized design source hash does not match current design source")
    if document.get("source_graph_hash") != source_graph.graph_hash:
        raise ValueError("materialized source graph hash does not match current source graph")
    current_coverage = validate_coverage_binding(instrumentation, top, design_source)
    if current_coverage != CoverageBinding(top, signal, width, "output"):
        raise ValueError("materialized coverage binding does not match current instrumentation or coverage port")

    def bound_file(key: str, label: str) -> Path:
        name = document.get(key)
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError(f"original RFuzz metadata {key} must be a file name")
        return _regular_repository_file(root, harness / name, label)

    wrapper = bound_file("wrapper", "RFuzz wrapper")
    header = bound_file("header", "RFuzz DUT header")
    toml = bound_file("toml", "augmented RFuzz TOML")
    expected_hashes = {
        "candidate_source_hash": raw_abi.source,
        "wrapper_hash": wrapper,
        "header_hash": header,
        "toml_hash": toml,
    }
    for key, path in expected_hashes.items():
        expected_hash = document.get(key)
        if not isinstance(expected_hash, str) or expected_hash != "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(f"materialized {key} content hash does not match")
    return MaterializedHarness(
        raw_abi,
        wrapper,
        module,
        header,
        toml,
        metadata_path,
        CoverageBinding(top, signal, width),
    )


def _validate_generated_output(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ValueError(f"generated output cannot be inspected: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"generated output must be a regular non-symlink file: {path}")


def _validate_generated_parent(path: Path) -> None:
    parent = path.parent
    while True:
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            if parent == parent.parent:
                raise ValueError(f"generated output parent cannot be inspected: {parent}")
            parent = parent.parent
            continue
        except OSError as error:
            raise ValueError(f"generated output parent cannot be inspected: {parent}") from error
        if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"generated output parent must be a regular non-symlink directory: {parent}")
        if parent == parent.parent:
            break
        parent = parent.parent


def write_text_file(path: Path, content: str) -> Path:
    _validate_generated_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_generated_parent(path)
    _validate_generated_output(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("safe generated-file writes require O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o666)
    except OSError as error:
        raise ValueError(f"generated output must be a regular non-symlink file: {path}") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)
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
    "native_input_identity",
    "render_dut_header",
    "render_wrapper",
    "has_unique_closed_sv_module",
    "select_raw_abi_fragment",
    "source_graph_hash",
    "source_list_entries",
    "validate_sources_file",
    "validate_candidate_source",
    "validate_coverage_binding",
    "wrapper_module_name",
    "write_text_file",
]
