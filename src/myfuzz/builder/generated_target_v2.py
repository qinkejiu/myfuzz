"""Content-addressed Verilator target for the unified RawBits v3 B/C/D harness."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping

from .atomic_target import (
    BuiltTarget,
    COMPLETION_SCHEMA,
    TARGET_SCHEMA,
    _canonical,
    _cpp_identifier,
    _cpp_reader,
    _cpp_setter,
    _sha256,
    _tool_version,
    _tree_hashes,
    _validate_completed_target,
    _validated_include_files,
    _validated_sources,
    _write_json,
)
from .contracts import CoverageABIV2, ElaborationManifest, TemporalConstraintIRV2
from .generated_harness_v2 import EmittedGeneratedHarnessV2
from .input_model import InputValidationError
from .rawbits_v3 import RawBitsV3Layout


def build_generated_verilator_target_v2(
    output_parent: str | Path,
    *,
    manifest: ElaborationManifest,
    source_root: str | Path,
    harness: EmittedGeneratedHarnessV2,
    layout: RawBitsV3Layout,
    temporal_ir: TemporalConstraintIRV2,
    coverage_abi: CoverageABIV2,
    boot_rom_hex: str | Path | None = None,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> BuiltTarget:
    """Build one immutable v3 target without changing the legacy A/v2 target path."""
    if jobs <= 0:
        raise InputValidationError("generated target jobs must be positive")
    if manifest.top_module == harness.module_name:
        raise InputValidationError("instrumented SoC and generated Harness top names must differ")
    if layout.schema != "myfuzz.rawbits-layout/v3":
        raise InputValidationError("generated target requires RawBits layout v3")
    if harness.layout_digest != layout.digest:
        raise InputValidationError("generated target Harness and RawBits layout digests differ")
    if harness.soc_digest != temporal_ir.soc_digest:
        raise InputValidationError("generated target Harness and Temporal SoC digests differ")
    if harness.constraint_digest != temporal_ir.digest:
        raise InputValidationError("generated target Harness and Temporal constraint digests differ")
    if temporal_ir.rawbits_layout_digest != layout.digest:
        raise InputValidationError("generated target Temporal and RawBits layout digests differ")
    if harness.coverage_abi_digest != coverage_abi.manifest_digest:
        raise InputValidationError("generated target Harness and Coverage ABI digests differ")
    if coverage_abi.width <= 0 or len(coverage_abi.manifest_digest) != 64:
        raise InputValidationError("generated target Coverage ABI is invalid")

    root = Path(source_root).resolve(strict=True)
    sources = _validated_sources(manifest, root)
    include_files = _validated_include_files(manifest, root)
    rom = _validated_boot_rom(boot_rom_hex)
    version = _tool_version(verilator_bin)
    descriptor = {
        "schema": TARGET_SCHEMA,
        "runner_schema": "myfuzz.generated-target-runner/v2",
        "instrumented_manifest_digest": manifest.digest,
        "harness_sha256": _sha256(harness.rtl.encode()),
        "layout_digest": layout.digest,
        "soc_digest": harness.soc_digest,
        "constraint_digest": temporal_ir.digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width,
        "boot_rom_sha256": None if rom is None else _sha256(rom.read_bytes()),
        "verilator_version": version,
        "jobs": jobs,
        "source_files": [
            {"path": relative.as_posix(), "sha256": source.sha256, "size": source.size}
            for source, relative in sources
        ],
        "include_files": [
            {"path": relative.as_posix(), "sha256": _sha256(path.read_bytes()),
             "size": path.stat().st_size}
            for path, relative in include_files
        ],
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
            return BuiltTarget(
                final.as_posix(), target_digest,
                (final / "completion_manifest.json").as_posix(), True,
            )
        temporary = Path(tempfile.mkdtemp(prefix=f".{target_digest}.tmp-", dir=parent))
        try:
            _materialize_generated_target(
                temporary, descriptor, manifest, root, sources, include_files, harness,
                layout, temporal_ir, coverage_abi, rom, verilator_bin, jobs, target_digest,
            )
            os.replace(temporary, final)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    return BuiltTarget(
        final.as_posix(), target_digest, (final / "completion_manifest.json").as_posix(), False,
    )


def _materialize_generated_target(
    output: Path,
    descriptor: Mapping[str, object],
    manifest: ElaborationManifest,
    source_root: Path,
    sources: list[tuple[object, Path]],
    include_files: list[tuple[Path, Path]],
    harness: EmittedGeneratedHarnessV2,
    layout: RawBitsV3Layout,
    temporal_ir: TemporalConstraintIRV2,
    coverage_abi: CoverageABIV2,
    boot_rom: Path | None,
    verilator_bin: str,
    jobs: int,
    target_digest: str,
) -> None:
    rtl_dir = output / "rtl"
    evidence_dir = output / "evidence"
    build_dir = output / "build"
    bin_dir = output / "bin"
    for directory in (rtl_dir, evidence_dir, build_dir, bin_dir):
        directory.mkdir(parents=True)
    copied_sources: list[Path] = []
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
    (output / "sources.f").write_text(
        "\n".join(path.relative_to(output).as_posix()
                  for path in (*copied_sources, harness_path)) + "\n",
        encoding="utf-8",
    )
    if boot_rom is not None:
        shutil.copyfile(boot_rom, output / "boot_rom.hex")

    _write_json(evidence_dir / "elaboration_manifest.json", manifest.to_dict())
    _write_json(evidence_dir / "bit_layout.json", layout.to_dict())
    _write_json(evidence_dir / "temporal_constraint_ir.json", temporal_ir.to_dict())
    _write_json(evidence_dir / "coverage_abi.json", coverage_abi.to_dict())
    _write_json(evidence_dir / "target_generation_report.json", descriptor)

    driver = output / "driver.cpp"
    driver.write_text(_emit_generated_driver(harness.module_name, layout, temporal_ir, coverage_abi), encoding="utf-8")
    command = [
        verilator_bin, "--cc", "--exe", "--build", "-Wno-fatal", "--top-module",
        harness.module_name, "-Mdir", "build", "-o", "myfuzz_target", "-j", str(jobs),
    ]
    for include_dir in manifest.include_dirs:
        relative = Path(include_dir).resolve().relative_to(source_root)
        command.append(f"-I{(Path('rtl') / relative).as_posix()}")
    command.extend(f"-D{definition}" for definition in manifest.defines)
    command.extend(f"-G{name}={value}" for name, value in manifest.parameters)
    if boot_rom is not None:
        command.append('-GBOOT_ROM_HEX_FILE="boot_rom.hex"')
    command.extend(path.relative_to(output).as_posix() for path in copied_sources)
    command.extend((harness_path.relative_to(output).as_posix(), driver.name))
    completed = subprocess.run(command, cwd=output, capture_output=True, text=True)
    (output / "verilator.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "verilator.stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise InputValidationError(
            f"generated Verilator target build failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    executable = build_dir / "myfuzz_target"
    if not executable.is_file():
        raise InputValidationError("Verilator completed without producing the generated target executable")
    shutil.copyfile(executable, bin_dir / "myfuzz_target")
    os.chmod(bin_dir / "myfuzz_target", 0o755)
    shutil.rmtree(build_dir)
    completion = {
        "schema": COMPLETION_SCHEMA,
        "target_digest": target_digest,
        "instrumented_manifest_digest": manifest.digest,
        "layout_digest": layout.digest,
        "soc_digest": harness.soc_digest,
        "constraint_digest": temporal_ir.digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width,
        "boot_rom_sha256": None if boot_rom is None else _sha256(boot_rom.read_bytes()),
        "runner_schema": "myfuzz.generated-target-runner/v2",
        "executable_sha256": _sha256((bin_dir / "myfuzz_target").read_bytes()),
        "evidence_files": _tree_hashes(evidence_dir),
    }
    _write_json(output / "completion_manifest.json", completion)


def _emit_generated_driver(
    module_name: str,
    layout: RawBitsV3Layout,
    temporal_ir: TemporalConstraintIRV2,
    coverage_abi: CoverageABIV2,
) -> str:
    raw_setter = _cpp_setter("raw_bits_i", layout.cycle_width, "value")
    frozen_reader = _cpp_reader("coverage_o", coverage_abi.width, "bit")
    live_reader = _cpp_reader("coverage_live_o", coverage_abi.width, "bit")
    digests = {
        "layout": ("layout_digest_i", layout.digest),
        "soc": ("soc_digest_i", temporal_ir.soc_digest),
        "constraint": ("constraint_digest_i", temporal_ir.digest),
        "coverage": ("coverage_abi_digest_i", coverage_abi.manifest_digest),
    }
    digest_declarations = []
    digest_assignments = []
    for name, (port, digest) in digests.items():
        words = [int(digest[index:index + 8], 16) for index in range(0, 64, 8)][::-1]
        digest_declarations.append(
            f'  const uint32_t {name}_digest[8] = {{{", ".join(f"0x{word:08x}u" for word in words)}}};'
        )
        digest_assignments.append(f"top.{port}[i] = {name}_digest[i];")
    class_name = f"V{_cpp_identifier(module_name)}"
    return f'''#include "{class_name}.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void tick({class_name}& top) {{
  top.clk_i = 0; top.eval();
  top.clk_i = 1; top.eval();
  top.clk_i = 0; top.eval();
}}

static void set_raw({class_name}& top, const std::vector<uint8_t>& bytes, size_t base) {{
{raw_setter}
}}

static void write_frozen_coverage({class_name}& top, std::ostream& output) {{
  std::vector<uint8_t> coverage(({coverage_abi.width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {coverage_abi.width}; ++bit) {{
    bool value = false;
{frozen_reader}
    if (value) coverage[bit / 8] |= uint8_t(1u << (bit % 8));
  }}
  output.write(reinterpret_cast<const char*>(coverage.data()), coverage.size());
}}

static void write_live_coverage({class_name}& top, std::ostream& output) {{
  std::vector<uint8_t> coverage(({coverage_abi.width} + 7) / 8, 0);
  for (size_t bit = 0; bit < {coverage_abi.width}; ++bit) {{
    bool value = false;
{live_reader}
    if (value) coverage[bit / 8] |= uint8_t(1u << (bit % 8));
  }}
  output.write(reinterpret_cast<const char*>(coverage.data()), coverage.size());
}}

int main(int argc, char** argv) {{
  if (argc < 5 || argc > 7) {{
    std::cerr << "usage: myfuzz_target RAWBITS CYCLES MODE COVERAGE [TRACE|-] [METRICS]\\n"; return 2;
  }}
  const size_t cycles = std::stoull(argv[2]);
  const int mode = std::stoi(argv[3]);
  if (mode < 0 || mode > 2) {{ std::cerr << "mode must be 0, 1, or 2\\n"; return 3; }}
  std::ifstream input(argv[1], std::ios::binary);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), {{}});
  constexpr size_t bytes_per_cycle = {layout.bytes_per_cycle};
  if (input.bad() || data.size() != cycles * bytes_per_cycle) {{
    std::cerr << "rawbits size mismatch\\n"; return 4;
  }}
  {class_name} top;
  top.harness_resetn_i = 0; top.start_i = 0; top.mode_i = mode;
  top.coverage_epoch_i = 1; top.format_version_i = 3;
  top.raw_bits_valid_i = 0; top.end_i = 0;
{chr(10).join(digest_declarations)}
  for (int i = 0; i < 8; ++i) {{ {' '.join(digest_assignments)} }}
  tick(top); tick(top); top.harness_resetn_i = 1;
  top.start_i = 1; tick(top); top.start_i = 0;

  std::ofstream trace;
  if (argc >= 6 && std::string(argv[5]) != "-") trace.open(argv[5], std::ios::binary);
  size_t record = 0;
  size_t stall_cycles = 0;
  std::vector<size_t> acceptance_cycles;
  std::vector<size_t> operation_cycles;
  for (size_t measured_cycle = 0; measured_cycle < cycles; ++measured_cycle) {{
    const bool accepted = record < cycles && top.raw_bits_ready_o;
    if (record < cycles && !top.raw_bits_ready_o) ++stall_cycles;
    if (record < cycles) set_raw(top, data, record * bytes_per_cycle);
    top.raw_bits_valid_i = accepted;
    tick(top);
    top.raw_bits_valid_i = 0;
    if (accepted) {{ acceptance_cycles.push_back(measured_cycle); ++record; }}
    if (top.control_accepted_o) operation_cycles.push_back(measured_cycle);
    if (trace) write_live_coverage(top, trace);
  }}

  top.raw_bits_valid_i = 0;
  top.end_i = 1; tick(top); top.end_i = 0;
  size_t teardown = 0;
  while (!top.done_o) {{
    if (++teardown > 196608) {{ std::cerr << "teardown timeout\\n"; return 5; }}
    tick(top);
  }}
  if (top.format_error_o || top.runtime_error_o || !top.coverage_valid_o) {{
    std::cerr << "harness completion error: format=" << int(top.format_error_o)
              << " runtime=" << int(top.runtime_error_o)
              << " coverage_valid=" << int(top.coverage_valid_o)
              << " accepted_records=" << record
              << " executed_operations=" << operation_cycles.size()
              << " teardown_cycles=" << teardown << "\\n";
    return 6;
  }}
  std::ofstream output(argv[4], std::ios::binary);
  write_frozen_coverage(top, output);
  if (argc == 7) {{
    std::ofstream metrics(argv[6]);
    metrics << "{{\\\"schema\\\":\\\"myfuzz.generated-target-metrics/v1\\\","
            << "\\\"measured_cycles\\\":" << cycles << ","
            << "\\\"accepted_records\\\":" << record << ","
            << "\\\"stall_cycles\\\":" << stall_cycles << ","
            << "\\\"unconsumed_records\\\":" << (cycles - record) << ","
            << "\\\"executed_operations\\\":" << operation_cycles.size() << ","
            << "\\\"teardown_cycles\\\":" << teardown << ","
            << "\\\"acceptance_cycles\\\":[";
    for (size_t i = 0; i < acceptance_cycles.size(); ++i) {{
      if (i) metrics << ','; metrics << acceptance_cycles[i];
    }}
    metrics << "],\\\"operation_cycles\\\":[";
    for (size_t i = 0; i < operation_cycles.size(); ++i) {{
      if (i) metrics << ','; metrics << operation_cycles[i];
    }}
    metrics << "]}}\\n";
    if (!metrics) return 7;
  }}
  return output && (argc < 6 || std::string(argv[5]) == "-" || trace) ? 0 : 8;
}}
'''


def _validated_boot_rom(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    path = Path(value).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise InputValidationError("generated target boot ROM must be a regular non-symlink file")
    return path
