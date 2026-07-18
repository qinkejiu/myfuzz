"""Content-addressed Verilator target for a RawBits v4 protocol harness."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Callable, Mapping

from .atomic_target import (
    BuiltTarget, _canonical, _cpp_identifier, _cpp_reader, _cpp_setter, _sha256,
    _tool_version, _tree_hashes, _validated_include_files,
    _validated_sources, _write_json,
)
from .contracts import CoverageABIV2, ElaborationManifest
from .controller_v4 import (
    TargetExecutionResultV4, canonical_protocol_legality_rules_v4,
)
from .cpu_semantic_v4 import (
    CpuExecutionProfile, build_rv32i_boot_image_v4,
    decode_program_fragment_records_v4,
)
from .environment_v4 import (
    EnvironmentPlanV4, EnvironmentReplayLimitsV4, validate_environment_replay_v4,
)
from .generated_harness_v4 import EmittedHarnessV4
from .input_model import InputValidationError
from .process_monitor_v4 import TargetProcessTimeoutV4, run_polled_process_v4
from .rawbits_v4 import (
    RawBitsV4Lane, RawBitsV4Layout, RawBitsV4Limits, RawBitsV4Submode,
    decode_rawbits_v4_testcase, rawbits_v4_layout_from_dict,
)


TARGET_SCHEMA_V4 = "myfuzz.verilator-target/v4"
COMPLETION_SCHEMA_V4 = "myfuzz.verilator-target-completion/v4"
RUNNER_SCHEMA_V4 = "myfuzz.generated-target-runner/v4"


@dataclass(frozen=True)
class GeneratedTargetReplayContextV4:
    transport_sha256: str
    coverage_epoch: int
    environment_replay: bytes | None
    result: TargetExecutionResultV4


def build_protocol_verilator_target_v4(
    output_parent: str | Path,
    *,
    manifest: ElaborationManifest,
    source_root: str | Path,
    harness: EmittedHarnessV4,
    coverage_abi: CoverageABIV2,
    limits: RawBitsV4Limits = RawBitsV4Limits(),
    environment_plan: EnvironmentPlanV4 | None = None,
    environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
    cpu_profile: CpuExecutionProfile | None = None,
    verilator_bin: str = "verilator",
    jobs: int = 1,
    campaign_address_windows: tuple[tuple[str, int, int], ...] = (),
) -> BuiltTarget:
    if jobs != 1:
        raise InputValidationError("v4 protocol target requires exactly one Verilator build job")
    if manifest.top_module == harness.module_name:
        raise InputValidationError("instrumented v4 SoC and protocol Harness top names must differ")
    if harness.coverage_abi_digest != coverage_abi.manifest_digest:
        raise InputValidationError("v4 harness and coverage ABI digests differ")
    if coverage_abi.epoch_width != 64:
        raise InputValidationError("v4 protocol target currently requires an exact 64-bit coverage epoch")
    cpu_lane_enabled = any(
        lane.lane == RawBitsV4Lane.CPU_SEMANTIC.name for lane in harness.layout.lanes
    )
    if cpu_lane_enabled and cpu_profile is None:
        raise InputValidationError("v4 CPU lane target requires a CPU execution profile")
    if cpu_profile is not None and (not cpu_lane_enabled or not harness.boot_rom_parameter):
        raise InputValidationError("v4 CPU target requires a CPU lane and boot ROM capable SoC")
    for name in (
        "max_logical_records", "max_chunk_payload_bytes", "max_testcase_bytes",
    ):
        if getattr(limits, name) > (1 << 64) - 1:
            raise InputValidationError(f"v4 protocol target {name} exceeds its 64-bit runtime domain")
    external_inputs = sorted(port.name for port in harness.environment_ports if port.direction == "input")
    if external_inputs and environment_plan is None:
        raise InputValidationError(
            "v4 protocol target requires an explicit environment driver for external input(s): "
            + ", ".join(external_inputs)
        )
    if environment_plan is not None:
        _validate_environment_plan(harness, environment_plan)
    environment_limits.__post_init__()
    campaign_windows = _validate_campaign_address_windows(campaign_address_windows)
    legality_rules = canonical_protocol_legality_rules_v4(dict(harness.legality_rules))
    if not legality_rules:
        raise InputValidationError("v4 protocol harness lacks legality rule evidence")
    root = Path(source_root).resolve(strict=True)
    sources = _validated_sources(manifest, root)
    includes = _validated_include_files(manifest, root)
    descriptor = {
        "schema": TARGET_SCHEMA_V4, "runner_schema": RUNNER_SCHEMA_V4,
        "instrumented_manifest_digest": manifest.digest,
        "harness_sha256": _sha256(harness.rtl.encode()),
        "layout_digest": harness.layout.digest, "soc_digest": harness.soc_digest,
        "protocol_profile_digest": harness.protocol_profile_digest,
        "protocol_legality_rules": legality_rules,
        "cpu_profile_digest": None if cpu_profile is None else cpu_profile.digest,
        "cpu_state_domain_digest": None if cpu_profile is None else cpu_profile.state_domain.digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width, "coverage_epoch_width": coverage_abi.epoch_width,
        "rawbits_limits": {
            "max_chunks": limits.max_chunks,
            "max_logical_records": limits.max_logical_records,
            "max_chunk_payload_bytes": limits.max_chunk_payload_bytes,
            "max_testcase_bytes": limits.max_testcase_bytes,
        },
        "environment_plan_digest": None if environment_plan is None else environment_plan.digest,
        "environment_replay_required": bool(
            environment_plan is not None and environment_plan.requires_replay
        ),
        "environment_replay_limits": {
            "max_records": environment_limits.max_records,
            "max_payload_bytes": environment_limits.max_payload_bytes,
        },
        "campaign_address_windows": [
            {"name": name, "base": base, "size": size}
            for name, base, size in campaign_windows
        ],
        "verilator_version": _tool_version(verilator_bin), "jobs": jobs,
        "source_files": [{"path": relative.as_posix(), "sha256": source.sha256, "size": source.size}
                         for source, relative in sources],
        "include_files": [{"path": relative.as_posix(), "sha256": _sha256(path.read_bytes()), "size": path.stat().st_size}
                          for path, relative in includes],
    }
    digest = _sha256(_canonical(descriptor))
    parent = Path(output_parent).resolve(); parent.mkdir(parents=True, exist_ok=True)
    final = parent / digest
    with (parent / f".{digest}.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if final.exists():
            _validate_completed_target_v4(final, digest)
            return BuiltTarget(final.as_posix(), digest, (final / "completion_manifest.json").as_posix(), True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.tmp-", dir=parent))
        try:
            _materialize(
                temporary, descriptor, manifest, root, sources, includes, harness,
                coverage_abi, limits, environment_plan, environment_limits,
                cpu_profile, verilator_bin, digest,
            )
            os.replace(temporary, final)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    return BuiltTarget(final.as_posix(), digest, (final / "completion_manifest.json").as_posix(), False)


def run_protocol_verilator_target_v4(
    target_dir: str | Path,
    transport: bytes,
    *,
    layout_digest: str,
    coverage_abi: CoverageABIV2,
    coverage_epoch: int,
    environment_plan: EnvironmentPlanV4 | None = None,
    environment_replay: bytes | None = None,
    environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
    cpu_profile: CpuExecutionProfile | None = None,
    timeout_seconds: float = 30.0,
    poll_callback: Callable[[], None] | None = None,
    poll_interval_seconds: float = 1.0,
) -> TargetExecutionResultV4:
    """Replay one fully framed testcase and return coverage plus a wire-trace digest."""
    if not isinstance(transport, bytes) or not transport:
        raise InputValidationError("v4 target replay transport must be non-empty bytes")
    if isinstance(coverage_epoch, bool) or not 0 <= coverage_epoch < 1 << 64:
        raise InputValidationError("v4 target replay epoch must be an unsigned 64-bit integer")
    environment_limits.__post_init__()
    target = Path(target_dir).resolve(strict=True)
    try:
        completion = json.loads((target / "completion_manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError("v4 target replay completion manifest is unreadable") from exc
    target_digest = str(completion.get("target_digest", ""))
    _validate_completed_target_v4(target, target_digest)
    if completion.get("layout_digest") != layout_digest:
        raise InputValidationError("v4 target replay layout digest mismatch")
    if completion.get("coverage_abi_digest") != coverage_abi.manifest_digest:
        raise InputValidationError("v4 target replay coverage ABI digest mismatch")
    expected_cpu_profile = completion.get("cpu_profile_digest")
    if (None if cpu_profile is None else cpu_profile.digest) != expected_cpu_profile:
        raise InputValidationError("v4 target replay CPU profile digest mismatch")
    if completion.get("environment_replay_limits") != {
        "max_records": environment_limits.max_records,
        "max_payload_bytes": environment_limits.max_payload_bytes,
    }:
        raise InputValidationError("v4 target replay environment limits mismatch")
    expected_environment_digest = completion.get("environment_plan_digest")
    if environment_plan is None:
        if expected_environment_digest is not None:
            raise InputValidationError("v4 target replay requires its environment plan")
        if environment_replay is not None:
            raise InputValidationError("v4 target replay received an undeclared environment sidecar")
    else:
        environment_plan.__post_init__()
        if environment_plan.digest != expected_environment_digest:
            raise InputValidationError("v4 target replay environment plan digest mismatch")
        if environment_plan.requires_replay:
            if environment_replay is None:
                raise InputValidationError("v4 target replay requires environment replay bytes")
            validate_environment_replay_v4(
                environment_plan, environment_replay, limits=environment_limits,
            )
        elif environment_replay is not None:
            raise InputValidationError("constant-only v4 environment cannot consume replay bytes")
    with tempfile.TemporaryDirectory(prefix="myfuzz-v4-replay-") as directory:
        work = Path(directory)
        input_path = work / "transport.v4"
        coverage_path = work / "coverage.bin"
        result_path = work / "result.json"
        trace_path = work / "wire-trace.bin"
        environment_path = work / "environment.v4"
        input_path.write_bytes(transport)
        frozen_layout = rawbits_v4_layout_from_dict(
            json.loads((target / "evidence/bit_layout.json").read_text(encoding="utf-8"))
        )
        testcase = decode_rawbits_v4_testcase(frozen_layout, transport)
        cpu_steps = 0
        if testcase.lane == RawBitsV4Lane.CPU_SEMANTIC.name:
            if cpu_profile is None:
                raise InputValidationError("v4 CPU semantic replay requires its CPU profile")
            if testcase.submode != RawBitsV4Submode.PROGRAM_FRAGMENT.value:
                raise InputValidationError("v4 CPU SEMANTIC_OPS loader is not implemented")
            fragment = decode_program_fragment_records_v4(
                frozen_layout, testcase.records, cpu_profile,
            )
            cpu_steps = fragment.max_steps
            (work / "boot_rom.hex").write_text(
                build_rv32i_boot_image_v4(cpu_profile, fragment).hex_text,
                encoding="ascii",
            )
        command = [
            target / "bin/myfuzz_target", input_path, coverage_path, result_path,
            str(coverage_epoch), trace_path,
        ]
        if expected_cpu_profile is not None:
            command.append(str(cpu_steps))
        if environment_replay is not None:
            environment_path.write_bytes(environment_replay)
            command.append(environment_path)
        try:
            completed = run_polled_process_v4(
                command, cwd=work, timeout_seconds=timeout_seconds,
                poll_callback=poll_callback,
                poll_interval_seconds=poll_interval_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TargetProcessTimeoutV4(
                f"v4 protocol target replay timed out after {timeout_seconds}s"
            ) from exc
        if completed.returncode:
            failure = TargetProcessTimeoutV4 if completed.returncode in {14, 15} else InputValidationError
            raise failure(
                f"v4 protocol target replay failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        coverage_bitmap = coverage_path.read_bytes()
        if len(coverage_bitmap) != (coverage_abi.width + 7) // 8:
            raise InputValidationError("v4 protocol target replay returned invalid coverage size")
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InputValidationError("v4 protocol target replay result is unreadable") from exc
        if result.get("schema") != "myfuzz.target-execution-result/v4":
            raise InputValidationError("v4 protocol target replay result schema mismatch")
        trace = trace_path.read_bytes()
        if not trace or len(trace) % 32:
            raise InputValidationError("v4 protocol target replay wire trace is malformed")
        return TargetExecutionResultV4(
            coverage_bitmap,
            str(result.get("observed_classification")),
            result.get("violation_rule"),
            result.get("violation_cycle"),
            _sha256(trace),
            (),
            int(result.get("dut_cycles", 0)),
            len(trace) // 32,
            int(result.get("logical_records", 0)),
            int(result.get("accepted_records", 0)),
            int(result.get("record_stall_cycles", 0)),
        )


class GeneratedTargetServerV4:
    """Validated controller-to-binary adapter with monotonic coverage epochs."""

    def __init__(
        self,
        target_dir: str | Path,
        *,
        layout: RawBitsV4Layout,
        coverage_abi: CoverageABIV2,
        first_coverage_epoch: int = 1,
        limits: RawBitsV4Limits = RawBitsV4Limits(),
        environment_plan: EnvironmentPlanV4 | None = None,
        environment_replay_for: Callable[[object], bytes] | None = None,
        environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
        cpu_profile: CpuExecutionProfile | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if isinstance(first_coverage_epoch, bool) or not 1 <= first_coverage_epoch < 1 << 64:
            raise InputValidationError("generated v4 server first coverage epoch is invalid")
        if environment_plan is not None:
            environment_plan.__post_init__()
        if bool(environment_plan is not None and environment_plan.requires_replay) != bool(
            environment_replay_for is not None
        ):
            raise InputValidationError(
                "generated v4 server replay-driven environment requires exactly one provider"
            )
        self.target_dir = Path(target_dir).resolve(strict=True)
        try:
            completion = json.loads(
                (self.target_dir / "completion_manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise InputValidationError("generated v4 server completion manifest is unreadable") from exc
        self.target_digest = str(completion.get("target_digest", ""))
        _validate_completed_target_v4(self.target_dir, self.target_digest)
        if completion.get("layout_digest") != layout.digest:
            raise InputValidationError("generated v4 server layout digest mismatch")
        if completion.get("coverage_abi_digest") != coverage_abi.manifest_digest:
            raise InputValidationError("generated v4 server coverage ABI digest mismatch")
        if completion.get("cpu_profile_digest") != (
            None if cpu_profile is None else cpu_profile.digest
        ):
            raise InputValidationError("generated v4 server CPU profile digest mismatch")
        self.legality_rules = canonical_protocol_legality_rules_v4(
            completion.get("protocol_legality_rules")
        )
        if not self.legality_rules:
            raise InputValidationError("generated v4 server lacks legality rule evidence")
        try:
            rule_evidence = json.loads(
                (self.target_dir / "evidence/protocol_legality_rules.json").read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise InputValidationError(
                "generated v4 server legality rule evidence is unreadable"
            ) from exc
        if (
            rule_evidence.get("schema") != "myfuzz.protocol-legality-rules/v4"
            or rule_evidence.get("protocol_profile_digest")
            != completion.get("protocol_profile_digest")
            or canonical_protocol_legality_rules_v4(rule_evidence.get("rules"))
            != self.legality_rules
        ):
            raise InputValidationError(
                "generated v4 server legality rule evidence mismatch"
            )
        self.layout = layout
        self.coverage_abi = coverage_abi
        self.coverage_epoch = first_coverage_epoch
        self.limits = limits
        self.environment_plan = environment_plan
        self.environment_replay_for = environment_replay_for
        self.environment_limits = environment_limits
        self.cpu_profile = cpu_profile
        self.timeout_seconds = timeout_seconds
        self._last_replay_context: GeneratedTargetReplayContextV4 | None = None

    def handle(self, transport: bytes) -> bytes:
        return self.handle_result(transport).coverage_bitmap

    def handle_result(
        self,
        transport: bytes,
        *,
        poll_callback: Callable[[], None] | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> TargetExecutionResultV4:
        self._last_replay_context = None
        testcase = decode_rawbits_v4_testcase(self.layout, transport, limits=self.limits)
        if self.coverage_epoch >= 1 << 64:
            raise InputValidationError("generated v4 server coverage epoch is exhausted")
        sidecar = (
            None if self.environment_replay_for is None
            else self.environment_replay_for(testcase)
        )
        coverage_epoch = self.coverage_epoch
        result = run_protocol_verilator_target_v4(
            self.target_dir, transport, layout_digest=self.layout.digest,
            coverage_abi=self.coverage_abi, coverage_epoch=self.coverage_epoch,
            environment_plan=self.environment_plan, environment_replay=sidecar,
            environment_limits=self.environment_limits,
            cpu_profile=self.cpu_profile,
            timeout_seconds=self.timeout_seconds,
            poll_callback=poll_callback,
            poll_interval_seconds=poll_interval_seconds,
        )
        self._last_replay_context = GeneratedTargetReplayContextV4(
            hashlib.sha256(transport).hexdigest(), coverage_epoch, sidecar, result,
        )
        self.coverage_epoch += 1
        return result

    def replay_context_for(self, transport: bytes) -> GeneratedTargetReplayContextV4:
        context = self._last_replay_context
        if (
            context is None
            or context.transport_sha256 != hashlib.sha256(transport).hexdigest()
        ):
            raise InputValidationError("generated v4 replay context does not match transport")
        return context


def _materialize(
    output: Path, descriptor: Mapping[str, object], manifest: ElaborationManifest,
    root: Path, sources, includes, harness: EmittedHarnessV4, coverage: CoverageABIV2,
    limits: RawBitsV4Limits, environment: EnvironmentPlanV4 | None,
    environment_limits: EnvironmentReplayLimitsV4,
    cpu_profile: CpuExecutionProfile | None, verilator: str, target_digest: str,
) -> None:
    rtl = output / "rtl"; evidence = output / "evidence"; build = output / "build"; binary = output / "bin"
    for directory in (rtl, evidence, build, binary): directory.mkdir(parents=True)
    copied = []
    for source, relative in sources:
        destination = rtl / relative; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(source.path), destination); copied.append(destination)
    for path, relative in includes:
        destination = rtl / relative
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
    harness_path = rtl / "generated_harness_v4.sv"; harness_path.write_text(harness.rtl, encoding="utf-8")
    _write_json(evidence / "elaboration_manifest.json", manifest.to_dict())
    _write_json(evidence / "bit_layout.json", harness.layout.to_dict())
    _write_json(evidence / "coverage_abi.json", coverage.to_dict())
    _write_json(evidence / "protocol_legality_rules.json", {
        "schema": "myfuzz.protocol-legality-rules/v4",
        "protocol_profile_digest": harness.protocol_profile_digest,
        "rules": descriptor["protocol_legality_rules"],
    })
    if environment is not None:
        _write_json(evidence / "environment_plan.json", environment.to_dict())
    if cpu_profile is not None:
        _write_json(evidence / "cpu_execution_profile.json", cpu_profile.to_dict())
    _write_json(evidence / "target_generation_report.json", descriptor)
    driver = output / "driver.cpp"
    driver.write_text(
        _emit_driver(
            harness, coverage, limits, environment, environment_limits, cpu_profile,
        ),
        encoding="utf-8",
    )
    command = [verilator, "--cc", "--exe", "--build", "-Wno-fatal", "--top-module", harness.module_name,
               "-Mdir", "build", "-o", "myfuzz_target", "-j", "1"]
    for include_dir in manifest.include_dirs:
        relative = Path(include_dir).resolve().relative_to(root)
        command.append(f"-I{(Path('rtl') / relative).as_posix()}")
    command.extend(f"-D{definition}" for definition in manifest.defines)
    command.extend(f"-G{name}={value}" for name, value in manifest.parameters)
    if cpu_profile is not None:
        command.append('-GBOOT_ROM_HEX_FILE="boot_rom.hex"')
    command.extend(path.relative_to(output).as_posix() for path in copied)
    command.extend((harness_path.relative_to(output).as_posix(), driver.name))
    completed = subprocess.run(command, cwd=output, capture_output=True, text=True)
    (output / "verilator.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "verilator.stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode:
        raise InputValidationError(f"v4 Verilator target build failed: {completed.stderr.strip() or completed.stdout.strip()}")
    executable = build / "myfuzz_target"
    if not executable.is_file():
        raise InputValidationError("Verilator did not produce the v4 target executable")
    shutil.copyfile(executable, binary / "myfuzz_target"); os.chmod(binary / "myfuzz_target", 0o755)
    shutil.rmtree(build)
    completion = {
        "schema": COMPLETION_SCHEMA_V4, "runner_schema": RUNNER_SCHEMA_V4,
        "target_digest": target_digest, "instrumented_manifest_digest": manifest.digest,
        "layout_digest": harness.layout.digest, "soc_digest": harness.soc_digest,
        "protocol_profile_digest": harness.protocol_profile_digest,
        "protocol_legality_rules": descriptor["protocol_legality_rules"],
        "cpu_profile_digest": None if cpu_profile is None else cpu_profile.digest,
        "cpu_state_domain_digest": None if cpu_profile is None else cpu_profile.state_domain.digest,
        "rawbits_limits": {
            "max_chunks": limits.max_chunks,
            "max_logical_records": limits.max_logical_records,
            "max_chunk_payload_bytes": limits.max_chunk_payload_bytes,
            "max_testcase_bytes": limits.max_testcase_bytes,
        },
        "environment_plan_digest": None if environment is None else environment.digest,
        "environment_replay_required": bool(environment is not None and environment.requires_replay),
        "environment_replay_limits": {
            "max_records": environment_limits.max_records,
            "max_payload_bytes": environment_limits.max_payload_bytes,
        },
        "campaign_address_windows": descriptor["campaign_address_windows"],
        "coverage_abi_digest": coverage.manifest_digest, "coverage_width": coverage.width,
        "executable_sha256": _sha256((binary / "myfuzz_target").read_bytes()),
        "evidence_files": _tree_hashes(evidence),
    }
    _write_json(output / "completion_manifest.json", completion)


def _validate_campaign_address_windows(
    windows: tuple[tuple[str, int, int], ...],
) -> tuple[tuple[str, int, int], ...]:
    canonical = tuple(sorted(windows))
    if len({name for name, _base, _size in canonical}) != len(canonical):
        raise InputValidationError("v4 campaign address window names must be unique")
    for name, base, size in canonical:
        if not name:
            raise InputValidationError("v4 campaign address window name is empty")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (base, size)):
            raise InputValidationError("v4 campaign address window bounds must be integers")
        if base < 0 or size <= 0 or base + size > 1 << 64:
            raise InputValidationError("v4 campaign address window is outside the 64-bit domain")
    return canonical


def _emit_driver(
    harness: EmittedHarnessV4, coverage: CoverageABIV2, limits: RawBitsV4Limits,
    environment: EnvironmentPlanV4 | None,
    environment_limits: EnvironmentReplayLimitsV4,
    cpu_profile: CpuExecutionProfile | None,
) -> str:
    layout = harness.layout; width = layout.record_width_bytes * 8
    setter = _cpp_setter("record_i", width, "value")
    reader = _cpp_reader("coverage_o", coverage.width, "bit")
    snapshot_reader = _cpp_reader("wire_snapshot_o", 256, "bit")
    digest_words = lambda value: [int(value[index:index + 8], 16) for index in range(0, 64, 8)][::-1]
    layout_words = digest_words(layout.digest); soc_words = digest_words(harness.soc_digest)
    coverage_words = digest_words(coverage.manifest_digest)
    prefix = ",".join(str(value) for value in bytes.fromhex(layout.digest[:16]))
    masks = []
    cases = []
    for lane in layout.lanes:
        for submode_name, mask in lane.submode_used_masks:
            symbol = f"mask_{RawBitsV4Lane[lane.lane].value}_{RawBitsV4Submode[submode_name].value}"
            data = mask.to_bytes(layout.record_width_bytes, "little")
            masks.append(f"static const uint8_t {symbol}[RECORD_BYTES]={{{','.join(str(item) for item in data)}}};")
            cases.append(f"if(lane=={RawBitsV4Lane[lane.lane].value}&&submode=={RawBitsV4Submode[submode_name].value})return {symbol};")
    class_name = f"V{_cpp_identifier(harness.module_name)}"
    environment_required = environment is not None and environment.requires_replay
    cpu_execution_enabled = cpu_profile is not None
    cpu_max_steps = 0 if cpu_profile is None else cpu_profile.state_domain.max_steps
    constant_assignments = []
    environment_setters = []
    environment_calls = []
    environment_padding_checks = []
    environment_record_bytes = 0 if environment is None else environment.replay_record_width_bytes
    environment_prefix = ""
    if environment is not None:
        environment_prefix = ",".join(str(value) for value in bytes.fromhex(environment.digest[:16]))
        for binding in environment.inputs:
            if binding.mode == "constant":
                constant_assignments.extend(
                    _cpp_constant_assignment(binding.port_name, binding.width, binding.constant_value)
                )
        for index, field in enumerate(environment.replay_fields):
            function = f"set_environment_{index}"
            field_setter = _cpp_setter(field.port_name, field.width, "environment")
            environment_setters.append(
                f"static void {function}({class_name}&top,const std::vector<uint8_t>&bytes,size_t base){{{field_setter}}}"
            )
            environment_calls.append(
                f"{function}(top,bytes,base+{field.offset_bits // 8});"
            )
            if field.width % 8:
                invalid_mask = (~((1 << (field.width % 8)) - 1)) & 0xFF
                environment_padding_checks.append(
                    f"for(uint64_t r=0;r<environment_count;++r)if(environment_transport[64+r*{environment_record_bytes}+{field.offset_bits // 8 + field.storage_bytes - 1}]&{invalid_mask}u)return 25;"
                )
    environment_parse = ""
    if environment_required:
        environment_argument = 7 if cpu_execution_enabled else 6
        environment_parse = f''' const uint8_t environment_prefix[8]={{{environment_prefix}}};std::ifstream environment_input(argv[{environment_argument}],std::ios::binary);std::vector<uint8_t>environment_transport((std::istreambuf_iterator<char>(environment_input)),{{}});
 if(environment_input.bad()||environment_transport.size()<64||environment_transport.size()>64ull+{environment_limits.max_payload_bytes}ull)return 21;
 const uint8_t environment_magic[8]={{'M','Y','F','E','N','V','4',0}};for(int i=0;i<8;++i)if(environment_transport[i]!=environment_magic[i])return 23;
 if(u16(environment_transport,8)!=4||u16(environment_transport,10)!=64||u32(environment_transport,12)!={environment.replay_record_width_bits}u||u32(environment_transport,16)!={environment_record_bytes}u||u32(environment_transport,60)!=crc32(environment_transport.data(),60))return 23;
 environment_count=u64(environment_transport,20);const uint64_t environment_payload=u64(environment_transport,36);for(int i=0;i<8;++i)if(environment_transport[28+i]!=environment_prefix[i])return 24;for(int i=44;i<60;++i)if(environment_transport[i])return 24;
 if(!environment_count||environment_count>{environment_limits.max_records}ull||environment_count>{environment_limits.max_payload_bytes}ull/{environment_record_bytes}ull||environment_payload!=environment_count*{environment_record_bytes}ull||environment_payload>{environment_limits.max_payload_bytes}ull||environment_transport.size()!=64ull+environment_payload)return 24;
 {''.join(environment_padding_checks)}environment_records.assign(environment_transport.begin()+64,environment_transport.end());'''
    return f'''#include "{class_name}.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
constexpr size_t HEADER_BYTES=64,RECORD_BYTES={layout.record_width_bytes};
constexpr bool ENVIRONMENT_REPLAY_REQUIRED={'true' if environment_required else 'false'};
constexpr bool CPU_EXECUTION_ENABLED={'true' if cpu_execution_enabled else 'false'};
constexpr uint64_t CPU_MAX_STEPS={cpu_max_steps}ull;
{chr(10).join(masks)}
{chr(10).join(environment_setters)}
static uint32_t u32(const std::vector<uint8_t>&d,size_t p){{return uint32_t(d[p])|(uint32_t(d[p+1])<<8)|(uint32_t(d[p+2])<<16)|(uint32_t(d[p+3])<<24);}}
static uint16_t u16(const std::vector<uint8_t>&d,size_t p){{return uint16_t(d[p])|(uint16_t(d[p+1])<<8);}}
static uint64_t u64(const std::vector<uint8_t>&d,size_t p){{return uint64_t(u32(d,p))|(uint64_t(u32(d,p+4))<<32);}}
static uint32_t crc32(const uint8_t*p,size_t n){{uint32_t c=0xffffffffu;for(size_t i=0;i<n;++i){{c^=p[i];for(int j=0;j<8;++j)c=(c>>1)^(0xedb88320u&uint32_t(-int(c&1)));}}return c^0xffffffffu;}}
static bool decimal_u64(const char*text,uint64_t&value){{if(!text||!*text)return false;value=0;for(const char*p=text;*p;++p){{if(*p<'0'||*p>'9')return false;const uint64_t digit=uint64_t(*p-'0');if(value>(~uint64_t(0)-digit)/10)return false;value=value*10+digit;}}return true;}}
static const uint8_t* used_mask(uint8_t lane,uint8_t submode){{{''.join(cases)}return nullptr;}}
static void append_snapshot({class_name}&top,std::vector<uint8_t>&trace){{for(size_t bit=0;bit<256;++bit){{bool value=false;{snapshot_reader}if(value)trace[trace.size()-32+bit/8]|=uint8_t(1u<<(bit%8));}}}}
static bool drive_environment({class_name}&top,const std::vector<uint8_t>&bytes,uint64_t&index,uint64_t count){{{''.join(constant_assignments)}if(ENVIRONMENT_REPLAY_REQUIRED){{if(index>=count)return false;const size_t base=index*{environment_record_bytes};{''.join(environment_calls)}++index;}}return true;}}
static bool tick({class_name}&top,std::vector<uint8_t>*trace,const std::vector<uint8_t>&environment,uint64_t&environment_index,uint64_t environment_count){{if(!drive_environment(top,environment,environment_index,environment_count))return false;top.clk_i=0;top.eval();top.clk_i=1;top.eval();if(trace){{trace->resize(trace->size()+32,0);append_snapshot(top,*trace);}}top.clk_i=0;top.eval();return true;}}
static void set_record({class_name}&top,const std::vector<uint8_t>&bytes,size_t base){{{setter}}}
static void write_coverage({class_name}&top,std::ostream&out){{std::vector<uint8_t>data(({coverage.width}+7)/8,0);for(size_t bit=0;bit<{coverage.width};++bit){{bool value=false;{reader}if(value)data[bit/8]|=uint8_t(1u<<(bit%8));}}out.write(reinterpret_cast<const char*>(data.data()),data.size());}}
int main(int argc,char**argv){{
 const int expected_cpu_argc=ENVIRONMENT_REPLAY_REQUIRED?8:7;
 if((CPU_EXECUTION_ENABLED&&argc!=expected_cpu_argc)||(!CPU_EXECUTION_ENABLED&&(argc<4||argc>7||(ENVIRONMENT_REPLAY_REQUIRED&&argc!=7)||(!ENVIRONMENT_REPLAY_REQUIRED&&argc==7)))){{std::cerr<<"usage: myfuzz_target TRANSPORT COVERAGE RESULT_JSON [EPOCH] [WIRE_TRACE] [CPU_STEPS] [ENVIRONMENT]\\n";return 2;}}
 Verilated::commandArgs(argc,argv);
 std::ifstream input(argv[1],std::ios::binary);std::vector<uint8_t>transport((std::istreambuf_iterator<char>(input)),{{}});if(input.bad()||transport.empty()||transport.size()>{limits.max_testcase_bytes}ull)return 3;
 const uint8_t expected_prefix[8]={{{prefix}}};std::vector<uint8_t>records;size_t cursor=0;uint8_t lane=0,submode=0;uint64_t testcase=0,total_records=0,chunk=0;bool final_seen=false;
 while(cursor<transport.size()){{if(final_seen||cursor+64>transport.size())return 4;const size_t h=cursor;
  const uint8_t magic[8]={{'M','Y','F','Z','V','4',0,0}};for(int i=0;i<8;++i)if(transport[h+i]!=magic[i])return 5;
  if(u16(transport,h+8)!=4||u16(transport,h+10)!=64||u32(transport,h+60)!=crc32(&transport[h],60))return 6;
  for(int i=0;i<8;++i)if(transport[h+52+i]||transport[h+44+i]!=expected_prefix[i])return 7;
  uint8_t l=transport[h+12],s=transport[h+13];uint16_t flags=u16(transport,h+14);uint64_t id=u64(transport,h+16);uint32_t ci=u32(transport,h+24),bits=u32(transport,h+28),bytes=u32(transport,h+32),count=u32(transport,h+36),payload=u32(transport,h+40);
  const uint64_t expected_payload=uint64_t(count)*RECORD_BYTES;
  if(!used_mask(l,s)||bits!={layout.record_width_bits}||bytes!=RECORD_BYTES||!count||count>65535||payload!=expected_payload||payload>{limits.max_chunk_payload_bytes}ull||cursor+64ull+payload>transport.size())return 8;
  if(chunk==0){{lane=l;submode=s;testcase=id;}}else if(l!=lane||s!=submode||id!=testcase)return 9;if(ci!=chunk++)return 10;
  total_records+=count;if(chunk>{limits.max_chunks}ull||total_records>{limits.max_logical_records}ull)return 18;
  if(flags==1)final_seen=true;else if(flags!=2)return 11;cursor+=64;const uint8_t*mask=used_mask(l,s);
  for(uint32_t r=0;r<count;++r){{for(size_t b=0;b<RECORD_BYTES;++b){{uint8_t value=transport[cursor+r*RECORD_BYTES+b];if(value&uint8_t(~mask[b]))return 12;records.push_back(value);}}}}cursor+=payload;
 }}if(!final_seen||cursor!=transport.size())return 13;
 std::vector<uint8_t>environment_records;uint64_t environment_count=0,environment_index=0;{environment_parse}
 uint64_t cpu_steps=0;if(CPU_EXECUTION_ENABLED&&!decimal_u64(argv[6],cpu_steps))return 26;if((lane==4&&(!CPU_EXECUTION_ENABLED||!cpu_steps||cpu_steps>CPU_MAX_STEPS))||(lane!=4&&cpu_steps))return 26;
 {class_name} top;std::vector<uint8_t>wire_trace;std::vector<uint8_t>*trace=argc>=6?&wire_trace:nullptr;top.harness_resetn_i=0;top.start_i=0;top.end_i=0;top.record_valid_i=0;{('top.cpu_execute_i=0;' if cpu_execution_enabled else '')}top.lane_i=lane;top.submode_i=submode;top.coverage_epoch_i=argc>=5?std::stoull(argv[4]):1;
 const uint32_t ld[8]={{{','.join(f'0x{x:08x}u' for x in layout_words)}}},sd[8]={{{','.join(f'0x{x:08x}u' for x in soc_words)}}},cd[8]={{{','.join(f'0x{x:08x}u' for x in coverage_words)}}};for(int i=0;i<8;++i){{top.layout_digest_i[i]=ld[i];top.soc_digest_i[i]=sd[i];top.coverage_abi_digest_i[i]=cd[i];}}
 if(!tick(top,trace,environment_records,environment_index,environment_count)||!tick(top,trace,environment_records,environment_index,environment_count))return 21;top.harness_resetn_i=1;top.start_i=1;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;top.start_i=0;size_t guard=0,dut_cycles=0,record_stall_cycles=0,accepted_records=0;
 for(size_t base=0;base<records.size();base+=RECORD_BYTES){{while(!top.record_ready_o){{if(++guard>1000000)return 14;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;++record_stall_cycles;}}set_record(top,records,base);top.record_valid_i=1;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;if(!top.record_consumed_o)return 19;++accepted_records;top.record_valid_i=0;}}
 {('if(lane==4){top.cpu_execute_i=1;while(!top.cpu_ready_o){if(++guard>1050000)return 27;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;}for(uint64_t step=0;step<cpu_steps;++step){if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;}}' if cpu_execution_enabled else '')}
 top.end_i=1;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;top.end_i=0;while(!top.done_o){{if(++guard>1100000)return 15;if(!tick(top,trace,environment_records,environment_index,environment_count))return 21;++dut_cycles;}}if(environment_index!=environment_count)return 22;
 if(top.format_error_o||top.runtime_error_o||!top.coverage_valid_o)return 16;std::ofstream cov(argv[2],std::ios::binary);write_coverage(top,cov);
 const bool violation=top.violation_rule_o!=0;std::string classification=lane==1?"raw":(lane==2?(violation?"adversarial":"protocol_valid"):(lane==4?"cpu_semantic":"adversarial"));std::ofstream result(argv[3]);result<<"{{\\\"schema\\\":\\\"myfuzz.target-execution-result/v4\\\",\\\"observed_classification\\\":\\\""<<classification<<"\\\",\\\"violation_rule\\\":";if(violation)result<<unsigned(top.violation_rule_o);else result<<"null";result<<",\\\"violation_cycle\\\":";if(violation)result<<uint64_t(top.violation_cycle_o);else result<<"null";result<<",\\\"dut_cycles\\\":"<<dut_cycles<<",\\\"logical_records\\\":"<<total_records<<",\\\"accepted_records\\\":"<<accepted_records<<",\\\"record_stall_cycles\\\":"<<record_stall_cycles<<"}}\\n";
 if(argc>=6){{std::ofstream trace_out(argv[5],std::ios::binary);trace_out.write(reinterpret_cast<const char*>(wire_trace.data()),wire_trace.size());if(!trace_out)return 20;}}
 return cov&&result?0:17;
}}
'''


def _validate_environment_plan(
    harness: EmittedHarnessV4, plan: EnvironmentPlanV4,
) -> None:
    plan.__post_init__()
    if len(plan.digest) != 64:
        raise InputValidationError("v4 target environment plan must have a content digest")
    if plan.soc_digest != harness.soc_digest:
        raise InputValidationError("v4 target environment plan SoC digest mismatch")
    if plan.protocol_profile_digest != harness.protocol_profile_digest:
        raise InputValidationError("v4 target environment plan protocol profile digest mismatch")
    expected_inputs = tuple(sorted(
        (port.name, port.width) for port in harness.environment_ports
        if port.direction == "input"
    ))
    expected_outputs = tuple(sorted(
        (port.name, port.width) for port in harness.environment_ports
        if port.direction == "output"
    ))
    unsupported = sorted(
        port.name for port in harness.environment_ports
        if port.direction not in {"input", "output"}
    )
    if unsupported:
        raise InputValidationError(
            "v4 target environment plan cannot handle port direction(s): "
            + ", ".join(unsupported)
        )
    actual_inputs = tuple((item.port_name, item.width) for item in plan.inputs)
    actual_outputs = tuple((item.port_name, item.width) for item in plan.observed_outputs)
    if actual_inputs != expected_inputs:
        raise InputValidationError("v4 target environment input bindings do not match harness ports")
    if actual_outputs != expected_outputs:
        raise InputValidationError("v4 target environment observations do not match harness ports")


def _cpp_constant_assignment(name: str, width: int, value: int | None) -> list[str]:
    if value is None:
        raise InputValidationError(f"v4 environment constant {name} has no value")
    if width <= 64:
        return [f"top.{name}=0x{value:x}ull;"]
    return [
        f"top.{name}[{word}]=0x{(value >> (word * 32)) & 0xFFFFFFFF:08x}u;"
        for word in range((width + 31) // 32)
    ]


def _validate_completed_target_v4(path: Path, target_digest: str) -> None:
    completion_path = path / "completion_manifest.json"
    if not completion_path.is_file():
        raise InputValidationError(f"v4 target is incomplete: {path}")
    try:
        value = json.loads(completion_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"v4 target completion manifest is unreadable: {path}") from exc
    if value.get("schema") != COMPLETION_SCHEMA_V4 or value.get("target_digest") != target_digest:
        raise InputValidationError(f"v4 target completion manifest mismatch: {path}")
    executable = path / "bin/myfuzz_target"
    if not executable.is_file() or _sha256(executable.read_bytes()) != value.get("executable_sha256"):
        raise InputValidationError(f"v4 target executable failed completion verification: {path}")
    evidence = value.get("evidence_files")
    if not isinstance(evidence, Mapping) or evidence != _tree_hashes(path / "evidence"):
        raise InputValidationError(f"v4 target evidence failed completion verification: {path}")
