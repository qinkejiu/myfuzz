"""Content-addressed Verilator targets, RawBits replay, and cycle minimization."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable, Mapping

from .contracts import (
    ConstraintIR, CoverageABI, CoverageABIV2, ElaborationManifest, ResolvedFile,
)
from .harness import EmittedHarness
from .input_model import InputValidationError
from .rawbits import RawBitsLayout, RawBitsTestcase, load_rawbits_testcase, write_rawbits_testcase


TARGET_SCHEMA = "myfuzz.verilator-target/v1"
COMPLETION_SCHEMA = "myfuzz.target-completion/v1"
RUN_SCHEMA = "myfuzz.target-run/v1"
LEGACY_RUNNER_SCHEMA = "myfuzz.legacy-acceptance-runner/v1"
FIXED_CYCLE_RUNNER_SCHEMA = "myfuzz.fixed-dut-cycle-runner/v1"
_RUNNER_SCHEMAS = {LEGACY_RUNNER_SCHEMA, FIXED_CYCLE_RUNNER_SCHEMA}

_USER_EVIDENCE = (
    "original_soc_rtl",
    "rfuzz_config",
    "address_graph",
    "connection_graph",
    "port_bindings",
    "instrumentation_manifest",
    "generation_report",
)


@dataclass(frozen=True)
class BuiltTarget:
    path: str
    target_digest: str
    completion_manifest: str
    cached: bool


@dataclass(frozen=True)
class TargetRun:
    output_dir: str
    report: Mapping[str, object]


def build_verilator_target(
    output_parent: str | Path,
    *,
    manifest: ElaborationManifest,
    source_root: str | Path,
    harness: EmittedHarness,
    layout: RawBitsLayout,
    constraint_ir: ConstraintIR,
    coverage_abi: CoverageABI | CoverageABIV2,
    evidence: Mapping[str, object],
    verilator_bin: str = "verilator",
    jobs: int = 1,
    runner_schema: str = LEGACY_RUNNER_SCHEMA,
) -> BuiltTarget:
    """Build and atomically publish one self-contained, manifest-keyed target."""
    if jobs <= 0:
        raise InputValidationError("target jobs must be positive")
    if runner_schema not in _RUNNER_SCHEMAS:
        raise InputValidationError(f"unsupported target runner schema: {runner_schema}")
    if manifest.top_module == harness.module_name:
        raise InputValidationError("instrumented SoC and Harness top names must differ")
    if harness.layout_digest != layout.digest:
        raise InputValidationError("target Harness and RawBits layout digests differ")
    if constraint_ir.layout_digest != layout.digest or constraint_ir.cycle_width != layout.cycle_width:
        raise InputValidationError("target ConstraintIR and RawBits layout are incompatible")
    if coverage_abi.width <= 0 or len(coverage_abi.manifest_digest) != 64:
        raise InputValidationError("target CoverageABI is invalid")
    missing = sorted(set(_USER_EVIDENCE) - set(evidence))
    unknown = sorted(set(evidence) - set(_USER_EVIDENCE))
    if missing or unknown:
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(missing))
        if unknown:
            detail.append("unknown: " + ", ".join(unknown))
        raise InputValidationError("target evidence fields are invalid (" + "; ".join(detail) + ")")

    root = Path(source_root).resolve(strict=True)
    sources = _validated_sources(manifest, root)
    include_files = _validated_include_files(manifest, root)
    version = _tool_version(verilator_bin)
    evidence_payloads = {name: _artifact_bytes(evidence[name]) for name in _USER_EVIDENCE}
    descriptor = {
        "schema": TARGET_SCHEMA,
        "instrumented_manifest_digest": manifest.digest,
        "harness_sha256": _sha256(harness.rtl.encode()),
        "layout_digest": layout.digest,
        "constraint_ir_sha256": _sha256(_canonical(constraint_ir.to_dict())),
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width,
        "verilator_version": version,
        "jobs": jobs,
        "runner_schema": runner_schema,
        "source_files": [
            {"path": relative.as_posix(), "sha256": source.sha256, "size": source.size}
            for source, relative in sources
        ],
        "include_files": [
            {"path": relative.as_posix(), "sha256": _sha256(path.read_bytes()),
             "size": path.stat().st_size}
            for path, relative in include_files
        ],
        "evidence": {name: _sha256(value) for name, value in sorted(evidence_payloads.items())},
    }
    target_digest = _sha256(_canonical(descriptor))
    parent = Path(output_parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    final = parent / target_digest
    lock_path = parent / f".{target_digest}.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if final.exists():
            _validate_completed_target(final, target_digest)
            return BuiltTarget(final.as_posix(), target_digest,
                               (final / "completion_manifest.json").as_posix(), True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{target_digest}.tmp-", dir=parent))
        try:
            _materialize_target(
                temporary, descriptor, manifest, root, sources, include_files, harness, layout,
                constraint_ir, coverage_abi, evidence_payloads, verilator_bin, jobs,
                target_digest, runner_schema,
            )
            os.replace(temporary, final)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    return BuiltTarget(final.as_posix(), target_digest,
                       (final / "completion_manifest.json").as_posix(), False)


def run_verilator_target(
    target_dir: str | Path,
    data_path: str | Path,
    metadata_path: str | Path,
    output_parent: str | Path,
    *,
    mode: str,
    timeout_seconds: float = 30.0,
) -> TargetRun:
    """Strictly load and replay one RawBits v2 testcase in a fresh process."""
    if mode not in {"raw", "constrained"}:
        raise InputValidationError("target run mode must be 'raw' or 'constrained'")
    target = Path(target_dir).resolve(strict=True)
    completion = _read_json(target / "completion_manifest.json")
    _validate_completed_target(target, str(completion.get("target_digest", "")))
    layout = _layout_from_dict(_read_json(target / "evidence/bit_layout.json"))
    testcase = load_rawbits_testcase(layout, data_path, metadata_path)
    testcase_hash = _sha256(Path(data_path).read_bytes())
    run_key = _sha256(_canonical({
        "target_digest": completion["target_digest"], "testcase_sha256": testcase_hash,
        "metadata": dict(testcase.metadata), "mode": mode,
    }))
    parent = Path(output_parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    final = parent / run_key
    if final.exists():
        report = _read_json(final / "run_report.json")
        if report.get("run_digest") != run_key:
            raise InputValidationError(f"existing run directory is incompatible: {final}")
        return TargetRun(final.as_posix(), report)
    temporary = Path(tempfile.mkdtemp(prefix=f".{run_key}.tmp-", dir=parent))
    try:
        shutil.copyfile(Path(data_path), temporary / "testcase.rawbits")
        _write_json(temporary / "testcase.json", dict(testcase.metadata))
        coverage_path = temporary / "coverage.bin"
        trace_path = temporary / "coverage_trace.bin"
        command = [
            (target / "bin/myfuzz_target").as_posix(), Path(data_path).resolve().as_posix(),
            str(len(testcase.cycles)), "1" if mode == "constrained" else "0",
            coverage_path.as_posix(), trace_path.as_posix(),
        ]
        try:
            completed = subprocess.run(
                command, cwd=target, capture_output=True, text=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise InputValidationError(f"Verilator target timed out after {timeout_seconds}s") from exc
        if completed.returncode != 0:
            raise InputValidationError(
                f"Verilator target failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        coverage = coverage_path.read_bytes()
        expected_bytes = (int(completion["coverage_width"]) + 7) // 8
        if len(coverage) != expected_bytes:
            raise InputValidationError("Verilator target returned an invalid coverage payload size")
        trace = trace_path.read_bytes()
        if len(trace) != len(testcase.cycles) * expected_bytes:
            raise InputValidationError("Verilator target returned an invalid coverage trace size")
        hits = _coverage_hits(target, coverage)
        hit_count_by_cycle = [
            sum(byte.bit_count() for byte in trace[offset:offset + expected_bytes])
            for offset in range(0, len(trace), expected_bytes)
        ]
        report = {
            "schema": RUN_SCHEMA,
            "run_digest": run_key,
            "target_digest": completion["target_digest"],
            "testcase_sha256": testcase_hash,
            "layout_digest": layout.digest,
            "coverage_abi_digest": completion["coverage_abi_digest"],
            "mode": mode,
            "cycles": len(testcase.cycles),
            "coverage_sha256": _sha256(coverage),
            "coverage_hit_offsets": [item[0] for item in hits],
            "coverage_hit_point_ids": [item[1] for item in hits],
            "coverage_hit_count_by_cycle": hit_count_by_cycle,
            "coverage_trace_sha256": _sha256(trace),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        _write_json(temporary / "run_report.json", report)
        os.replace(temporary, final)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return TargetRun(final.as_posix(), report)


def rebuild_verilator_target_runner(
    source_target: str | Path,
    output_parent: str | Path,
    *,
    runner_schema: str,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> BuiltTarget:
    """Rebuild a completed target with only a different audited runner contract."""
    source = Path(source_target).resolve(strict=True)
    completion = _read_json(source / "completion_manifest.json")
    _validate_completed_target(source, str(completion.get("target_digest", "")))
    manifest_value = _read_json(source / "evidence/elaboration_manifest.json")
    manifest = ElaborationManifest(
        str(manifest_value["schema"]), str(manifest_value["stage"]),
        str(manifest_value["top_module"]), str(manifest_value["language"]),
        tuple(ResolvedFile(str(item["path"]), str(item["sha256"]), int(item["size"]))
              for item in manifest_value["sources"]),
        tuple(str(item) for item in manifest_value["include_dirs"]),
        tuple(str(item) for item in manifest_value["defines"]),
        tuple((str(item[0]), str(item[1])) for item in manifest_value["parameters"]),
        tuple((str(item[0]), str(item[1])) for item in manifest_value["tools"]),
        manifest_value.get("parent_digest"), str(manifest_value["digest"]),
    )
    roots = [Path(item.path) for item in manifest.sources]
    roots.extend(Path(item) for item in manifest.include_dirs)
    source_root = Path(os.path.commonpath([path.as_posix() for path in roots]))
    if source_root.is_file():
        source_root = source_root.parent

    layout = _layout_from_dict(_read_json(source / "evidence/bit_layout.json"))
    constraint_value = _read_json(source / "evidence/constraint_ir.json")
    constraint_ir = ConstraintIR(
        str(constraint_value["layout_digest"]), int(constraint_value["cycle_width"]),
        tuple(constraint_value["constraints"]), str(constraint_value["schema"]),
    )
    abi_value = _read_json(source / "evidence/coverage_abi.json")
    if abi_value.get("schema") == "myfuzz.coverage-abi/v2":
        coverage_abi: CoverageABI | CoverageABIV2 = CoverageABIV2(
            str(abi_value["catalog_digest"]), str(abi_value["port_name"]),
            int(abi_value["width"]), int(abi_value["epoch_width"]),
            tuple(abi_value["points"]), int(abi_value["transport_width"]),
            str(abi_value["writer"]), str(abi_value["sampling"]), str(abi_value["schema"]),
        )
    else:
        coverage_abi = CoverageABI(
            str(abi_value["manifest_digest"]), str(abi_value["port_name"]),
            int(abi_value["width"]), tuple(abi_value["points"]), str(abi_value["schema"]),
        )
    harness_rtl = (source / "rtl/generated_harness_top.sv").read_text(encoding="utf-8")
    module_match = re.search(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b", harness_rtl)
    if module_match is None:
        raise InputValidationError("frozen target harness has no module declaration")
    harness = EmittedHarness(module_match.group(1), harness_rtl, (), layout.digest)
    evidence = {}
    for name in _USER_EVIDENCE:
        candidates = tuple((source / "evidence").glob(f"{name}.*"))
        if len(candidates) != 1:
            raise InputValidationError(f"frozen target evidence field {name} is ambiguous or absent")
        evidence[name] = candidates[0].read_bytes()
    return build_verilator_target(
        output_parent, manifest=manifest, source_root=source_root, harness=harness,
        layout=layout, constraint_ir=constraint_ir, coverage_abi=coverage_abi,
        evidence=evidence, verilator_bin=verilator_bin, jobs=jobs,
        runner_schema=runner_schema,
    )


def minimize_rawbits_cycles(
    layout: RawBitsLayout,
    testcase: RawBitsTestcase,
    predicate: Callable[[RawBitsTestcase], bool],
) -> RawBitsTestcase:
    """Deterministically remove cycle chunks while preserving ``predicate``."""
    current = tuple(testcase.cycles)
    if not predicate(testcase):
        raise InputValidationError("minimization predicate does not hold for the original testcase")
    granularity = 2
    while current:
        chunk_size = (len(current) + granularity - 1) // granularity
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate_cycles = current[:start] + current[start + chunk_size:]
            candidate = RawBitsTestcase(candidate_cycles, {
                **dict(testcase.metadata), "cycles": len(candidate_cycles),
            })
            if predicate(candidate):
                current = candidate_cycles
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    _, metadata = _pack_for_metadata(layout, current)
    return RawBitsTestcase(current, metadata)


def write_minimized_rawbits(
    layout: RawBitsLayout, testcase: RawBitsTestcase, output_dir: str | Path, *, name: str,
) -> dict[str, str]:
    return write_rawbits_testcase(layout, testcase.cycles, output_dir, name=name)


def _materialize_target(
    output: Path,
    descriptor: Mapping[str, object],
    manifest: ElaborationManifest,
    source_root: Path,
    sources: list[tuple[object, Path]],
    include_files: list[tuple[Path, Path]],
    harness: EmittedHarness,
    layout: RawBitsLayout,
    constraint_ir: ConstraintIR,
    coverage_abi: CoverageABI | CoverageABIV2,
    evidence: Mapping[str, bytes],
    verilator_bin: str,
    jobs: int,
    target_digest: str,
    runner_schema: str,
) -> None:
    rtl_dir = output / "rtl"
    evidence_dir = output / "evidence"
    build_dir = output / "build"
    bin_dir = output / "bin"
    for directory in (rtl_dir, evidence_dir, build_dir, bin_dir):
        directory.mkdir(parents=True)
    copied_sources = []
    for source, relative in sources:
        destination = rtl_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(source.path), destination)
        copied_sources.append(destination)
    for path, relative in include_files:
        destination = rtl_dir / relative
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
    harness_path = rtl_dir / "generated_harness_top.sv"
    harness_path.write_text(harness.rtl, encoding="utf-8")
    filelist = output / "sources.f"
    filelist.write_text("\n".join(path.relative_to(output).as_posix()
                                    for path in (*copied_sources, harness_path)) + "\n", encoding="utf-8")

    _write_json(evidence_dir / "elaboration_manifest.json", manifest.to_dict())
    _write_json(evidence_dir / "bit_layout.json", asdict(layout))
    _write_json(evidence_dir / "constraint_ir.json", constraint_ir.to_dict())
    _write_json(evidence_dir / "coverage_abi.json", coverage_abi.to_dict())
    _write_json(evidence_dir / "target_generation_report.json", descriptor)
    for name, payload in evidence.items():
        (evidence_dir / f"{name}{_artifact_suffix(payload)}").write_bytes(payload)

    driver = output / "driver.cpp"
    driver.write_text(
        _emit_driver(harness.module_name, layout, coverage_abi, runner_schema),
        encoding="utf-8",
    )
    command = [
        verilator_bin, "--cc", "--exe", "--build", "-Wno-fatal", "--top-module",
        harness.module_name, "-Mdir", "build", "-o", "myfuzz_target",
        "-j", str(jobs),
    ]
    for include_dir in manifest.include_dirs:
        relative = Path(include_dir).resolve().relative_to(source_root)
        command.append(f"-I{(Path('rtl') / relative).as_posix()}")
    command.extend(f"-D{definition}" for definition in manifest.defines)
    command.extend(f"-G{name}={value}" for name, value in manifest.parameters)
    command.extend(path.relative_to(output).as_posix() for path in copied_sources)
    command.extend((harness_path.relative_to(output).as_posix(), driver.name))
    completed = subprocess.run(command, cwd=output, capture_output=True, text=True)
    (output / "verilator.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "verilator.stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise InputValidationError(
            f"Verilator target build failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    executable = build_dir / "myfuzz_target"
    if not executable.is_file():
        raise InputValidationError("Verilator completed without producing the target executable")
    shutil.copyfile(executable, bin_dir / "myfuzz_target")
    os.chmod(bin_dir / "myfuzz_target", 0o755)
    shutil.rmtree(build_dir)
    completion = {
        "schema": COMPLETION_SCHEMA,
        "target_digest": target_digest,
        "instrumented_manifest_digest": manifest.digest,
        "layout_digest": layout.digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width,
        "runner_schema": runner_schema,
        "executable_sha256": _sha256((bin_dir / "myfuzz_target").read_bytes()),
        "evidence_files": _tree_hashes(evidence_dir),
    }
    _write_json(output / "completion_manifest.json", completion)


def _emit_driver(
    module_name: str,
    layout: RawBitsLayout,
    coverage_abi: CoverageABI | CoverageABIV2,
    runner_schema: str = LEGACY_RUNNER_SCHEMA,
) -> str:
    raw_setter = _cpp_setter("raw_bits_i", layout.cycle_width, "value")
    coverage_reader = _cpp_reader("coverage_o", coverage_abi.width, "bit")
    digest_words = [
        int(layout.digest[index:index + 8], 16)
        for index in range(0, 64, 8)
    ][::-1]
    coverage_words = [
        int(coverage_abi.manifest_digest[index:index + 8], 16)
        for index in range(0, 64, 8)
    ][::-1]
    class_name = f"V{_cpp_identifier(module_name)}"
    epoch_initialization = "top.coverage_epoch_i = 1;" if isinstance(coverage_abi, CoverageABIV2) else ""
    if runner_schema == FIXED_CYCLE_RUNNER_SCHEMA:
        return _emit_fixed_cycle_driver(
            class_name, layout, coverage_abi, raw_setter, coverage_reader,
            digest_words, coverage_words, epoch_initialization,
        )
    if runner_schema != LEGACY_RUNNER_SCHEMA:
        raise InputValidationError(f"unsupported target runner schema: {runner_schema}")
    return f'''#include "{class_name}.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

static void tick({class_name}& top) {{
  top.clk_i = 0; top.eval();
  top.clk_i = 1; top.eval();
  top.clk_i = 0; top.eval();
}}

static void set_raw({class_name}& top, const std::vector<uint8_t>& bytes, size_t base) {{
{raw_setter}
}}

static void write_coverage({class_name}& top, std::ostream& output) {{
  std::vector<uint8_t> coverage(({coverage_abi.width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {coverage_abi.width}; ++bit) {{
    bool value = false;
{coverage_reader}
    if (value) coverage[bit / 8] |= uint8_t(1u << (bit % 8));
  }}
  output.write(reinterpret_cast<const char*>(coverage.data()), coverage.size());
}}

int main(int argc, char** argv) {{
  if (argc != 5 && argc != 6) {{ std::cerr << "usage: myfuzz_target RAWBITS CYCLES MODE COVERAGE [TRACE]\\n"; return 2; }}
  const size_t cycles = std::stoull(argv[2]);
  const bool constrained = std::stoi(argv[3]) != 0;
  std::ifstream input(argv[1], std::ios::binary);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), {{}});
  constexpr size_t bytes_per_cycle = {layout.bytes_per_cycle};
  if (input.bad() || data.size() != cycles * bytes_per_cycle) {{ std::cerr << "rawbits size mismatch\\n"; return 3; }}
  {class_name} top;
  top.harness_resetn_i = 0; top.start_i = 0; top.mode_constrained_i = constrained;
  {epoch_initialization}
  top.format_version_i = 2; top.raw_bits_valid_i = 0; top.end_i = 0;
  const uint32_t layout_digest[8] = {{{", ".join(f"0x{word:08x}u" for word in digest_words)}}};
  const uint32_t coverage_digest[8] = {{{", ".join(f"0x{word:08x}u" for word in coverage_words)}}};
  for (int i = 0; i < 8; ++i) {{ top.layout_digest_i[i] = layout_digest[i]; top.coverage_abi_digest_i[i] = coverage_digest[i]; }}
  tick(top); tick(top); top.harness_resetn_i = 1; top.start_i = 1; tick(top); top.start_i = 0;
  std::ofstream trace;
  if (argc == 6) trace.open(argv[5], std::ios::binary);
  size_t guard = 0;
  for (size_t cycle = 0; cycle < cycles; ++cycle) {{
    while (!top.raw_bits_ready_o) {{ if (++guard > cycles + 65536) return 4; tick(top); }}
    set_raw(top, data, cycle * bytes_per_cycle); top.raw_bits_valid_i = 1; tick(top); top.raw_bits_valid_i = 0;
    if (trace) write_coverage(top, trace);
  }}
  while (!top.raw_bits_ready_o) {{ if (++guard > cycles + 131072) return 5; tick(top); }}
  top.end_i = 1; tick(top); top.end_i = 0;
  while (!top.done_o) {{ if (++guard > cycles + 196608) return 6; tick(top); }}
  if (top.format_error_o || !top.coverage_valid_o) return 7;
  std::ofstream output(argv[4], std::ios::binary); write_coverage(top, output);
  return output && (argc != 6 || trace) ? 0 : 8;
}}
'''


def _emit_fixed_cycle_driver(
    class_name: str,
    layout: RawBitsLayout,
    coverage_abi: CoverageABI | CoverageABIV2,
    raw_setter: str,
    coverage_reader: str,
    digest_words: list[int],
    coverage_words: list[int],
    epoch_initialization: str,
) -> str:
    return f'''#include "{class_name}.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

static void tick({class_name}& top) {{
  top.clk_i = 0; top.eval();
  top.clk_i = 1; top.eval();
  top.clk_i = 0; top.eval();
}}

static bool measured_tick({class_name}& top) {{
  top.clk_i = 0; top.eval();
  const bool accepted = top.raw_bits_valid_i && top.raw_bits_ready_o;
  top.clk_i = 1; top.eval();
  top.clk_i = 0; top.eval();
  return accepted;
}}

static void set_raw({class_name}& top, const std::vector<uint8_t>& bytes, size_t base) {{
{raw_setter}
}}

static void write_coverage({class_name}& top, std::ostream& output) {{
  std::vector<uint8_t> coverage(({coverage_abi.width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {coverage_abi.width}; ++bit) {{
    bool value = false;
{coverage_reader}
    if (value) coverage[bit / 8] |= uint8_t(1u << (bit % 8));
  }}
  output.write(reinterpret_cast<const char*>(coverage.data()), coverage.size());
}}

int main(int argc, char** argv) {{
  if (argc < 5 || argc > 7) {{
    std::cerr << "usage: myfuzz_target RAWBITS DUT_CYCLES MODE COVERAGE [TRACE [METRICS]]\\n";
    return 2;
  }}
  const size_t cycles = std::stoull(argv[2]);
  const bool constrained = std::stoi(argv[3]) != 0;
  std::ifstream input(argv[1], std::ios::binary);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), {{}});
  constexpr size_t bytes_per_cycle = {layout.bytes_per_cycle};
  if (input.bad() || data.size() != cycles * bytes_per_cycle) {{
    std::cerr << "rawbits size mismatch\\n"; return 3;
  }}
  {class_name} top;
  top.harness_resetn_i = 0; top.start_i = 0; top.mode_constrained_i = constrained;
  {epoch_initialization}
  top.format_version_i = 2; top.raw_bits_valid_i = 0; top.end_i = 0;
  const uint32_t layout_digest[8] = {{{", ".join(f"0x{word:08x}u" for word in digest_words)}}};
  const uint32_t coverage_digest[8] = {{{", ".join(f"0x{word:08x}u" for word in coverage_words)}}};
  for (int i = 0; i < 8; ++i) {{
    top.layout_digest_i[i] = layout_digest[i];
    top.coverage_abi_digest_i[i] = coverage_digest[i];
  }}
  tick(top); tick(top); top.harness_resetn_i = 1; top.start_i = 1; tick(top); top.start_i = 0;

  std::ofstream trace;
  if (argc >= 6) trace.open(argv[5], std::ios::binary);
  size_t record = 0;
  size_t accepted = 0;
  size_t stalled = 0;
  for (size_t cycle = 0; cycle < cycles; ++cycle) {{
    if (record < cycles) {{
      set_raw(top, data, record * bytes_per_cycle);
      top.raw_bits_valid_i = 1;
    }} else {{
      top.raw_bits_valid_i = 0;
    }}
    if (measured_tick(top)) {{ ++record; ++accepted; }} else {{ ++stalled; }}
    if (trace) write_coverage(top, trace);
  }}

  // Freeze the measured result before end/drain activity can change coverage.
  std::ofstream output(argv[4], std::ios::binary);
  write_coverage(top, output);
  top.raw_bits_valid_i = 0;
  top.end_i = 1; tick(top); top.end_i = 0;
  size_t teardown = 0;
  while (!top.done_o) {{ if (++teardown > cycles + 196608) return 6; tick(top); }}
  if (top.format_error_o || !top.coverage_valid_o) return 7;
  if (argc == 7) {{
    std::ofstream metrics(argv[6]);
    metrics << "{{\\n"
            << "  \\"schema\\": \\"myfuzz.fixed-dut-cycle-metrics/v1\\",\\n"
            << "  \\"dut_cycles\\": " << cycles << ",\\n"
            << "  \\"accepted_records\\": " << accepted << ",\\n"
            << "  \\"stall_cycles\\": " << stalled << ",\\n"
            << "  \\"unconsumed_records\\": " << (cycles - record) << "\\n"
            << "}}\\n";
    if (!metrics) return 9;
  }}
  return output && (argc < 6 || trace) ? 0 : 8;
}}
'''


def _cpp_setter(signal: str, width: int, value_name: str) -> str:
    if width <= 64:
        lines = ["  uint64_t value = 0;"]
        lines.append(f"  for (size_t i = 0; i < {min((width + 7) // 8, 8)}; ++i) value |= uint64_t(bytes[base + i]) << (8 * i);")
        lines.append(f"  top.{signal} = value;")
        return "\n".join(lines)
    words = (width + 31) // 32
    return "\n".join([
        f"  for (size_t word = 0; word < {words}; ++word) top.{signal}[word] = 0;",
        f"  for (size_t i = 0; i < {(width + 7) // 8}; ++i) top.{signal}[i / 4] |= uint32_t(bytes[base + i]) << (8 * (i % 4));",
    ])


def _cpp_reader(signal: str, width: int, bit_name: str) -> str:
    if width <= 64:
        return f"    value = (uint64_t(top.{signal}) >> {bit_name}) & 1u;"
    return f"    value = (top.{signal}[{bit_name} / 32] >> ({bit_name} % 32)) & 1u;"


def _validated_sources(manifest: ElaborationManifest, root: Path) -> list[tuple[object, Path]]:
    result = []
    for source in manifest.sources:
        path = Path(source.path).resolve(strict=True)
        if not path.is_relative_to(root):
            raise InputValidationError(f"target source escapes source_root: {path}")
        payload = path.read_bytes()
        if len(payload) != source.size or _sha256(payload) != source.sha256:
            raise InputValidationError(f"target source changed after elaboration: {path}")
        result.append((source, path.relative_to(root)))
    if not result:
        raise InputValidationError("target manifest has no RTL sources")
    for include_dir in manifest.include_dirs:
        path = Path(include_dir).resolve(strict=True)
        if not path.is_relative_to(root):
            raise InputValidationError(f"target include directory escapes source_root: {path}")
    return result


def _validated_include_files(
    manifest: ElaborationManifest, root: Path,
) -> list[tuple[Path, Path]]:
    result: list[tuple[Path, Path]] = []
    seen: set[Path] = set()
    for include_dir in manifest.include_dirs:
        directory = Path(include_dir).resolve(strict=True)
        if not directory.is_relative_to(root):
            raise InputValidationError(f"target include directory escapes source_root: {directory}")
        if not directory.is_dir():
            raise InputValidationError(f"target include path is not a directory: {directory}")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise InputValidationError(f"target include tree contains a symlink: {path}")
            if path.is_file() and path not in seen:
                seen.add(path)
                result.append((path, path.relative_to(root)))
    return result


def _tool_version(executable: str) -> str:
    try:
        completed = subprocess.run([executable, "--version"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InputValidationError(f"cannot execute formal Verilator tool {executable!r}") from exc
    return completed.stdout.strip()


def _artifact_bytes(value: object) -> bytes:
    if isinstance(value, Path):
        if not value.is_file() or value.is_symlink():
            raise InputValidationError(f"target evidence path must be a regular non-symlink file: {value}")
        return value.read_bytes()
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, Mapping) or isinstance(value, (list, tuple)):
        return _canonical(value) + b"\n"
    raise InputValidationError(f"unsupported target evidence value: {type(value).__name__}")


def _artifact_suffix(payload: bytes) -> str:
    try:
        json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ".txt"
    return ".json"


def _validate_completed_target(path: Path, target_digest: str) -> None:
    completion_path = path / "completion_manifest.json"
    if not completion_path.is_file():
        raise InputValidationError(f"target is incomplete: {path}")
    value = _read_json(completion_path)
    if value.get("schema") != COMPLETION_SCHEMA or value.get("target_digest") != target_digest:
        raise InputValidationError(f"target completion manifest mismatch: {path}")
    executable = path / "bin/myfuzz_target"
    if not executable.is_file() or _sha256(executable.read_bytes()) != value.get("executable_sha256"):
        raise InputValidationError(f"target executable failed completion verification: {path}")
    evidence = value.get("evidence_files")
    if not isinstance(evidence, Mapping) or evidence != _tree_hashes(path / "evidence"):
        raise InputValidationError(f"target evidence failed completion verification: {path}")


def _coverage_hits(target: Path, coverage: bytes) -> list[tuple[int, str]]:
    abi = _read_json(target / "evidence/coverage_abi.json")
    by_offset = {
        int(point["offset"]): str(point["point_id"])
        for point in abi["points"] if point.get("included")
    }
    result = []
    for offset in range(int(abi["width"])):
        if coverage[offset // 8] & (1 << (offset % 8)):
            result.append((offset, by_offset[offset]))
    return result


def _layout_from_dict(value: Mapping[str, object]) -> RawBitsLayout:
    from .rawbits import RawBitsLayoutEntry
    entries = tuple(RawBitsLayoutEntry(**item) for item in value["entries"])
    return RawBitsLayout(
        entries, int(value["cycle_width"]), int(value["bytes_per_cycle"]),
        str(value["digest"]), str(value["schema"]), str(value["byte_order"]),
        str(value["bit_order"]), str(value["cycle_order"]),
    )


def _pack_for_metadata(layout: RawBitsLayout, cycles: tuple[int, ...]) -> tuple[bytes, dict[str, object]]:
    from .rawbits import pack_rawbits_cycles
    return pack_rawbits_cycles(layout, cycles)


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256(path.read_bytes())
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputValidationError(f"JSON artifact must contain an object: {path}")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode() + b"\n")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _cpp_identifier(value: str) -> str:
    return value
