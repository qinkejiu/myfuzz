"""Build compose-v5 rawbits targets for four-scheme coverage campaigns."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Iterable, Mapping

from .compose_v5 import (
    ComposeV5Manifest,
    build_compose_v5_abcd_scheme_plan_from_manifest,
    emit_compose_v5_scheme_a_harness_bundle_from_manifest,
    emit_compose_v5_scheme_b_harness_bundle_from_manifest,
)
from .contracts import (
    ElaborationManifest,
    ManifestError,
    build_elaboration_manifest,
    canonical_json,
    content_digest,
)
from .input_model import InputValidationError
from .rawbits_v5 import RawBitsV5Layout


COMPOSE_V5_TARGET_ARTIFACT_SCHEMA = "myfuzz.compose-v5-target-artifact/v1"
COMPOSE_V5_TARGET_EXECUTION_SCHEMA = "myfuzz.compose-v5-target-execution/v1"


@dataclass(frozen=True)
class BuiltComposeV5Target:
    path: str
    topology: str
    harness_module_name: str
    layout_digest: str
    target_digest: str
    coverage_abi_digest: str
    coverage_width: int
    executable: str
    schema: str = COMPOSE_V5_TARGET_ARTIFACT_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_compose_v5_target_artifact(
    *,
    rtl_files: Iterable[str | Path],
    filelists: Iterable[str | Path] = (),
    allow_roots: Iterable[str | Path],
    harness_rtl: str,
    harness_module_name: str,
    layout: RawBitsV5Layout,
    output_dir: str | Path,
    topology: str,
    scheme_plan: Mapping[str, object] | None = None,
    verilator_bin: str = "verilator",
    jobs: int = 1,
    target_name: str = "myfuzz_target",
    force: bool = False,
) -> BuiltComposeV5Target:
    """Materialize a compose-v5 target executable from RTL plus generated harness.

    The executable contract is intentionally small: ``myfuzz_target RAWBITS
    LAYOUT_DIGEST RESULT_JSON``.  It drives the generated harness with the
    zero-padded v5 rawbit records, ORs the source-level branch coverage port,
    and emits the JSON result consumed by ``compose_v5_campaign.py``.
    """

    if not isinstance(layout, RawBitsV5Layout):
        raise InputValidationError("compose-v5 target build requires a RawBitsV5Layout")
    _identifier(harness_module_name, "compose-v5 target harness module")
    _text(harness_rtl, "compose-v5 target harness RTL")
    _text(topology, "compose-v5 target topology")
    _identifier(target_name, "compose-v5 target executable name")
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs <= 0:
        raise InputValidationError("compose-v5 target jobs must be a positive integer")

    output = Path(output_dir).resolve()
    if output.exists():
        if not force and any(output.iterdir()):
            raise InputValidationError(f"compose-v5 target output directory is not empty: {output}")
        if force:
            shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    roots = _resolved_roots(allow_roots)
    try:
        source_manifest = build_elaboration_manifest(
            top_module=harness_module_name,
            rtl_files=tuple(rtl_files),
            filelists=tuple(filelists),
            allow_roots=roots,
            tools={"verilator": verilator_bin},
        )
    except ManifestError as exc:
        raise InputValidationError(f"compose-v5 target source manifest failed: {exc}") from exc

    target_digest = content_digest({
        "schema": COMPOSE_V5_TARGET_ARTIFACT_SCHEMA,
        "topology": topology,
        "source_manifest_digest": source_manifest.digest,
        "harness_module_name": harness_module_name,
        "harness_sha256": _sha256_text(harness_rtl),
        "layout_digest": layout.digest,
        "scheme_plan_digest": content_digest(dict(scheme_plan)) if scheme_plan else "",
        "target_name": target_name,
    })

    source_root = output / "source_rtl"
    instrumented_root = output / "instrumented_rtl"
    build_root = output / "build"
    bin_root = output / "bin"
    evidence_root = output / "evidence"
    for directory in (source_root, build_root, bin_root, evidence_root):
        directory.mkdir(parents=True, exist_ok=True)

    copied_relatives, include_relatives = _copy_source_manifest(
        source_manifest,
        source_root=source_root,
        allow_roots=roots,
    )
    generated_relative = Path("__myfuzz_generated__") / "compose_v5_harness.sv"
    generated_path = source_root / generated_relative
    generated_path.parent.mkdir(parents=True, exist_ok=True)
    generated_path.write_text(harness_rtl, encoding="utf-8")
    copied_relatives.append(generated_relative)
    source_flist = source_root / "compose_v5_sources.f"
    source_flist.write_text(
        "".join(f"+incdir+{item.as_posix()}\n" for item in include_relatives)
        + "".join(f"{item.as_posix()}\n" for item in copied_relatives),
        encoding="utf-8",
    )

    from myfuzz.instrumentation.source_branch_instrumenter import instrument_project

    try:
        instrumentation = instrument_project(
            source_root,
            instrumented_root,
            flist=source_flist,
            signal_prefix="myfuzz_branch_cov",
            coverage_port="myfuzz_coverage",
            top_module=harness_module_name,
            force=True,
        )
    except SystemExit as exc:
        raise InputValidationError(f"compose-v5 target instrumentation failed: {exc}") from exc

    coverage_abi = _coverage_abi(instrumentation)
    driver_path = output / "driver.cpp"
    driver_path.write_text(
        _emit_driver(
            harness_module_name,
            layout,
            coverage_port=str(coverage_abi["port_name"]),
            coverage_width=int(coverage_abi["width"]),
            observe_width=_observe_width_from_harness(harness_rtl),
        ),
        encoding="utf-8",
    )

    command = [
        verilator_bin,
        "--cc",
        "--exe",
        "--build",
        "--sv",
        "-Wno-fatal",
        "--top-module",
        harness_module_name,
        "-Mdir",
        build_root.name,
        "-o",
        target_name,
        "-j",
        str(jobs),
        "-f",
        str(Path(instrumentation["instrumented_flist"]).resolve()),
        driver_path.name,
    ]
    completed = subprocess.run(command, cwd=output, capture_output=True, text=True)
    (output / "verilator.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "verilator.stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise InputValidationError(f"compose-v5 target Verilator build failed: {detail[-4000:]}")
    built_executable = build_root / target_name
    if not built_executable.is_file():
        raise InputValidationError("compose-v5 target Verilator did not produce executable")
    final_executable = bin_root / target_name
    shutil.copyfile(built_executable, final_executable)
    os.chmod(final_executable, 0o755)

    report = {
        "schema": COMPOSE_V5_TARGET_ARTIFACT_SCHEMA,
        "topology": topology,
        "target_digest": target_digest,
        "source_manifest_digest": source_manifest.digest,
        "harness_module_name": harness_module_name,
        "layout_digest": layout.digest,
        "coverage_abi_digest": str(coverage_abi["manifest_digest"]),
        "coverage_width": int(coverage_abi["width"]),
        "coverage_port": str(coverage_abi["port_name"]),
        "target_name": target_name,
        "executable_sha256": _sha256_file(final_executable),
    }
    _write_json(evidence_root / "rawbits_layout.json", layout.to_dict())
    _write_json(evidence_root / "source_elaboration_manifest.json", source_manifest.to_dict())
    _write_json(evidence_root / "instrumentation.json", instrumentation)
    _write_json(evidence_root / "coverage_abi.json", coverage_abi)
    _write_json(evidence_root / "target_generation_report.json", report)
    if scheme_plan is not None:
        _write_json(evidence_root / "scheme_plan.json", dict(scheme_plan))
    _write_json(output / "completion_manifest.json", report)

    return BuiltComposeV5Target(
        path=output.as_posix(),
        topology=topology,
        harness_module_name=harness_module_name,
        layout_digest=layout.digest,
        target_digest=target_digest,
        coverage_abi_digest=str(coverage_abi["manifest_digest"]),
        coverage_width=int(coverage_abi["width"]),
        executable=final_executable.as_posix(),
    )


def build_compose_v5_target_artifact_from_manifest(
    manifest: ComposeV5Manifest,
    *,
    project_root: str | Path,
    allow_roots: Iterable[str | Path] | None = None,
    scheme: str,
    output_dir: str | Path,
    frontend_library: str | Path | None = None,
    verilator_bin: str = "verilator",
    jobs: int = 1,
    target_name: str = "myfuzz_target",
    force: bool = False,
    stall_inputs_before_escalation: int = 256,
) -> BuiltComposeV5Target:
    """Generate and build the compose-v5 target for one comparison scheme.

    Scheme A builds the flat baseline target.  Schemes B/C/D share the
    generated-SoC target; their behavioral difference is the rawbits projection
    selected by the campaign runner.
    """

    if scheme not in {"A", "B", "C", "D"}:
        raise InputValidationError("compose-v5 target scheme must be A, B, C, or D")
    root = Path(project_root).resolve(strict=True)
    roots = tuple(allow_roots) if allow_roots is not None else (root,)
    source_files, source_filelists = _manifest_sources(manifest, root)
    if scheme == "A":
        bundle = emit_compose_v5_scheme_a_harness_bundle_from_manifest(
            manifest,
            project_root=root,
            allow_roots=roots,
            frontend_library=frontend_library,
        )
        return build_compose_v5_target_artifact(
            rtl_files=source_files,
            filelists=source_filelists,
            allow_roots=roots,
            harness_rtl=bundle.rtl,
            harness_module_name=bundle.harness.module_name,
            layout=bundle.layout,
            output_dir=output_dir,
            topology="scheme_a_flat_baseline",
            verilator_bin=verilator_bin,
            jobs=jobs,
            target_name=target_name,
            force=force,
        )

    bundle = emit_compose_v5_scheme_b_harness_bundle_from_manifest(
        manifest,
        project_root=root,
        allow_roots=roots,
        frontend_library=frontend_library,
    )
    scheme_plan = build_compose_v5_abcd_scheme_plan_from_manifest(
        manifest,
        project_root=root,
        allow_roots=roots,
        frontend_library=frontend_library,
        stall_inputs_before_escalation=stall_inputs_before_escalation,
    )
    return build_compose_v5_target_artifact(
        rtl_files=source_files,
        filelists=source_filelists,
        allow_roots=roots,
        harness_rtl=bundle.rtl,
        harness_module_name=bundle.harness.module_name,
        layout=bundle.layout,
        output_dir=output_dir,
        topology="scheme_bcd_generated_soc",
        scheme_plan=scheme_plan.to_dict(),
        verilator_bin=verilator_bin,
        jobs=jobs,
        target_name=target_name,
        force=force,
    )


def _copy_source_manifest(
    manifest: ElaborationManifest,
    *,
    source_root: Path,
    allow_roots: tuple[Path, ...],
) -> tuple[list[Path], list[Path]]:
    copied_sources: list[Path] = []
    for source in manifest.sources:
        path = Path(source.path).resolve(strict=True)
        relative = _relative_to_allowed_root(path, allow_roots)
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        copied_sources.append(relative)

    include_relatives: list[Path] = []
    for include in manifest.include_dirs:
        path = Path(include).resolve(strict=True)
        relative = _relative_to_allowed_root(path, allow_roots)
        destination = source_root / relative
        include_relatives.append(relative)
        if destination.exists():
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file():
                child_relative = child.relative_to(path)
                target = destination / child_relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(child, target)
    return copied_sources, include_relatives


def _emit_driver(
    module_name: str,
    layout: RawBitsV5Layout,
    *,
    coverage_port: str,
    coverage_width: int,
    observe_width: int,
) -> str:
    class_name = f"V{_cpp_identifier(module_name)}"
    raw_setter = _cpp_setter("rawbits_i", layout.record_width_bits)
    observe_reader = _cpp_reader("observe_o", observe_width, "bit")
    coverage_reader = _cpp_reader(coverage_port, coverage_width, "bit")
    clock_fields = tuple(field for field in layout.fields if field.kind == "clock")
    clock_names = ", ".join(_cpp_string(field.owner) for field in clock_fields)
    clock_offsets = ", ".join(str(field.offset) for field in clock_fields)
    clock_initials = ", ".join(str(field.initial_value) for field in clock_fields)
    expected_layout_digest = layout.digest
    return f'''#include "{class_name}.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

class Digest256 {{
 public:
  Digest256() : h{{0x6a09e667f3bcc909ULL, 0xbb67ae8584caa73bULL,
                   0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL}} {{}}
  void update_byte(uint8_t byte) {{
    for (int i = 0; i < 4; ++i) {{
      h[i] ^= uint64_t(byte) + uint64_t(i + 1) * 0x9e3779b97f4a7c15ULL;
      h[i] *= 0x100000001b3ULL + uint64_t(i) * 0x100000001b3ULL;
      h[i] ^= h[i] >> 32;
    }}
  }}
  void update_u64(uint64_t value) {{
    for (int i = 0; i < 8; ++i) update_byte(uint8_t((value >> (8 * i)) & 0xffU));
  }}
  void update(const std::vector<uint8_t>& data) {{
    update_u64(data.size());
    for (uint8_t byte : data) update_byte(byte);
  }}
  std::string hex() const {{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 4; ++i) out << std::setw(16) << h[i];
    return out.str();
  }}
 private:
  uint64_t h[4];
}};

static bool read_payload(const char* path, std::vector<uint8_t>* data) {{
  std::ifstream input(path, std::ios::binary);
  if (!input) return false;
  data->assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return !input.bad();
}}

static void set_rawbits({class_name}& top, const std::vector<uint8_t>& bytes, size_t base) {{
{raw_setter}
}}

static std::vector<uint8_t> read_observe({class_name}& top) {{
  std::vector<uint8_t> result(({observe_width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {observe_width}; ++bit) {{
    bool value = false;
{observe_reader}
    if (value) result[bit / 8] |= uint8_t(1U << (bit % 8));
  }}
  return result;
}}

static std::vector<uint8_t> read_coverage({class_name}& top) {{
  std::vector<uint8_t> result(({coverage_width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {coverage_width}; ++bit) {{
    bool value = false;
{coverage_reader}
    if (value) result[bit / 8] |= uint8_t(1U << (bit % 8));
  }}
  return result;
}}

static void or_coverage(std::vector<uint8_t>* total, const std::vector<uint8_t>& update) {{
  if (total->size() < update.size()) total->resize(update.size(), 0);
  for (size_t i = 0; i < update.size(); ++i) (*total)[i] |= update[i];
}}

static bool bit_at(const std::vector<uint8_t>& bytes, size_t base, size_t offset) {{
  const size_t bit = base * 8 + offset;
  return ((bytes[bit / 8] >> (bit % 8)) & 1U) != 0;
}}

static std::string bytes_hex(const std::vector<uint8_t>& bytes) {{
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) out << std::setw(2) << unsigned(byte);
  return out.str();
}}

static void write_edges(std::ostream& out, const uint64_t* counts) {{
  static const char* names[] = {{{clock_names if clock_names else '""'}}};
  constexpr size_t kClockCount = {len(clock_fields)};
  out << "{{";
  for (size_t i = 0; i < kClockCount; ++i) {{
    if (i) out << ",";
    out << "\\\"" << names[i] << "\\\":" << counts[i];
  }}
  out << "}}";
}}

static bool write_result(
    const char* path,
    size_t steps,
    size_t eval_count,
    const uint64_t* rising,
    const uint64_t* falling,
    const std::string& wire_digest,
    const std::vector<uint8_t>& coverage,
    bool settled,
    const char* failure
) {{
  Digest256 coverage_digest;
  coverage_digest.update(coverage);
  std::ofstream out(path);
  if (!out) return false;
  out << "{{\\n";
  out << "  \\"schema\\": \\"{COMPOSE_V5_TARGET_EXECUTION_SCHEMA}\\",\\n";
  out << "  \\"layout_digest\\": \\"{expected_layout_digest}\\",\\n";
  out << "  \\"steps\\": " << steps << ",\\n";
  out << "  \\"eval_count\\": " << eval_count << ",\\n";
  out << "  \\"rising_edges\\": ";
  write_edges(out, rising);
  out << ",\\n";
  out << "  \\"falling_edges\\": ";
  write_edges(out, falling);
  out << ",\\n";
  out << "  \\"wire_digest\\": \\"" << wire_digest << "\\",\\n";
  out << "  \\"coverage_digest\\": \\"" << coverage_digest.hex() << "\\",\\n";
  out << "  \\"coverage_hex\\": \\"" << bytes_hex(coverage) << "\\",\\n";
  out << "  \\"settled\\": " << (settled ? "true" : "false") << ",\\n";
  if (failure) out << "  \\"failure\\": \\"" << failure << "\\"\\n";
  else out << "  \\"failure\\": null\\n";
  out << "}}\\n";
  return bool(out);
}}

int main(int argc, char** argv) {{
  if (argc != 4) {{
    std::cerr << "usage: myfuzz_target RAWBITS LAYOUT_DIGEST RESULT_JSON\\n";
    return 2;
  }}
  if (std::string(argv[2]) != "{expected_layout_digest}") {{
    std::cerr << "layout digest mismatch\\n";
    return 3;
  }}
  std::vector<uint8_t> data;
  if (!read_payload(argv[1], &data)) {{
    std::cerr << "cannot read rawbits payload\\n";
    return 4;
  }}
  constexpr size_t kRecordBytes = {layout.record_width_bytes};
  const size_t steps = data.empty() ? 0 : ((data.size() + kRecordBytes - 1) / kRecordBytes);
  data.resize(steps * kRecordBytes, 0);

  {class_name} top;
  std::vector<uint8_t> coverage(({coverage_width} + 7) / 8, 0);
  Digest256 wire_digest;
  size_t eval_count = 0;
  static const size_t clock_offsets[] = {{{clock_offsets if clock_offsets else "0"}}};
  uint64_t rising[{max(1, len(clock_fields))}] = {{{", ".join("0" for _ in range(max(1, len(clock_fields))))}}};
  uint64_t falling[{max(1, len(clock_fields))}] = {{{", ".join("0" for _ in range(max(1, len(clock_fields))))}}};
  bool prior[{max(1, len(clock_fields))}] = {{{clock_initials if clock_initials else "false"}}};
  constexpr size_t kClockCount = {len(clock_fields)};

  for (size_t step = 0; step < steps; ++step) {{
    const size_t base = step * kRecordBytes;
    for (size_t index = 0; index < kClockCount; ++index) {{
      const bool current = bit_at(data, base, clock_offsets[index]);
      if (!prior[index] && current) ++rising[index];
      if (prior[index] && !current) ++falling[index];
      prior[index] = current;
    }}
    set_rawbits(top, data, base);
    std::vector<uint8_t> previous;
    std::vector<uint8_t> stable;
    bool have_previous = false;
    bool step_settled = false;
    for (int attempt = 0; attempt < 32; ++attempt) {{
      top.eval();
      ++eval_count;
      or_coverage(&coverage, read_coverage(top));
      std::vector<uint8_t> current = read_observe(top);
      if (have_previous && current == previous) {{
        stable = current;
        step_settled = true;
        break;
      }}
      previous = current;
      have_previous = true;
    }}
    if (!step_settled) {{
      wire_digest.update(previous);
      write_result(argv[3], step + 1, eval_count, rising, falling, wire_digest.hex(), coverage, false, "settle_limit");
      return 0;
    }}
    wire_digest.update(stable);
  }}

  return write_result(argv[3], steps, eval_count, rising, falling, wire_digest.hex(), coverage, true, nullptr) ? 0 : 5;
}}
'''


def _coverage_abi(instrumentation: Mapping[str, object]) -> Mapping[str, object]:
    value = instrumentation.get("coverage_abi")
    if not isinstance(value, Mapping):
        raise InputValidationError("compose-v5 target instrumentation did not produce CoverageABI")
    if value.get("schema") != "myfuzz.coverage-abi/v1":
        raise InputValidationError("compose-v5 target currently expects CoverageABI v1")
    width = value.get("width")
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise InputValidationError("compose-v5 target instrumentation produced no coverage points")
    port_name = value.get("port_name")
    if not isinstance(port_name, str) or not port_name:
        raise InputValidationError("compose-v5 target coverage port is missing")
    digest = value.get("manifest_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise InputValidationError("compose-v5 target coverage ABI digest is invalid")
    return value


def _observe_width_from_harness(rtl: str) -> int:
    import re

    pattern = re.compile(
        r"output\s+logic\s+(?:(?:\[\s*(\d+)\s*:\s*0\s*\])\s*)?observe_o\b",
        re.MULTILINE,
    )
    match = pattern.search(rtl)
    if not match:
        raise InputValidationError("compose-v5 target harness must expose observe_o")
    if match.group(1) is None:
        return 1
    return int(match.group(1)) + 1


def _manifest_sources(manifest: ComposeV5Manifest, root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    rtl_files: list[Path] = []
    filelists: list[Path] = []
    for source in manifest.sources:
        rtl_files.extend(root / item for item in source.rtl_files)
        filelists.extend(root / item for item in source.filelists)
    return tuple(rtl_files), tuple(filelists)


def _relative_to_allowed_root(path: Path, roots: tuple[Path, ...]) -> Path:
    matches: list[Path] = []
    for index, root in enumerate(roots):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        matches.append(Path(f"root{index}") / relative)
    if not matches:
        raise InputValidationError(f"compose-v5 target source escapes allow roots: {path}")
    return sorted(matches, key=lambda item: len(item.parts))[0]


def _resolved_roots(values: Iterable[str | Path]) -> tuple[Path, ...]:
    roots = tuple(sorted({Path(item).resolve(strict=True) for item in values}, key=str))
    if not roots:
        raise InputValidationError("compose-v5 target requires at least one allow root")
    return roots


def _cpp_setter(signal: str, width: int) -> str:
    if width <= 64:
        return "\n".join((
            "  uint64_t value = 0;",
            f"  for (size_t i = 0; i < {min((width + 7) // 8, 8)}; ++i) "
            "value |= uint64_t(bytes[base + i]) << (8 * i);",
            f"  top.{signal} = value;",
        ))
    words = (width + 31) // 32
    return "\n".join((
        f"  for (size_t word = 0; word < {words}; ++word) top.{signal}[word] = 0;",
        f"  for (size_t i = 0; i < {(width + 7) // 8}; ++i) "
        f"top.{signal}[i / 4] |= uint32_t(bytes[base + i]) << (8 * (i % 4));",
    ))


def _cpp_reader(signal: str, width: int, bit_name: str) -> str:
    if width <= 64:
        return f"    value = (uint64_t(top.{signal}) >> {bit_name}) & 1U;"
    return f"    value = (top.{signal}[{bit_name} / 32] >> ({bit_name} % 32)) & 1U;"


def _cpp_identifier(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in value)


def _cpp_string(value: str) -> str:
    return json.dumps(value)


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.isidentifier():
        raise InputValidationError(f"{path}: expected a simple identifier")
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputValidationError(f"{path}: expected non-empty text")
    return value


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value) + b"\n")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
