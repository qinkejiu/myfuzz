"""Fresh-run offline SoC component-defect confirmation.

The verifier binds build files by content, re-runs the SoCs, and recompiles a
declarative standalone fixture before upgrading the known component fault.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from copy import deepcopy
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, replace
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .soc_composition import CompositionPlan, build_composition
from .soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    REPLAY_AGREEMENT,
    UNDIAGNOSED,
    EvidencePackage,
    classify_boundary,
    compare_replay_results,
    identity_mismatches,
    replay_package,
    recorded_build_identity,
)
from .soc_runtime import RUNTIME_SCHEMA, RunResult, RuntimeBuild, build_profile_runtime, run_sample
from .soc_structure_audit import FAIL, PASS, audit_structure


@dataclass(frozen=True, slots=True)
class IsolationFixture:
    testbench: Path
    top_module: str
    marker: str
    source_name: str


@dataclass(frozen=True, slots=True)
class OfflineConfirmation:
    status: str
    reason: str
    evidence: Mapping[str, object]


def record_offline_confirmation(package: EvidencePackage,
                                result: OfflineConfirmation) -> EvidencePackage:
    """Snapshot a verifier result, without authenticating its Python origin.

    Confirmation remains conditional on the trusted specification and fixture.
    A constructed/deserialized result has no special authority; validating this
    record checks only integrity. Fresh proof requires rerunning the verifier.
    """
    report = {"schema_version": "soc_offline_confirmation.v1",
              "validation_scope": "record-integrity-only",
              "status": result.status, "reason": result.reason,
              "evidence": deepcopy(dict(result.evidence))}
    report["report_hash"] = "sha256:" + hashlib.sha256(canonical_bytes(report)).hexdigest()
    return replace(package, attribution={**dict(package.attribution),
                                         "offline_confirmation": report})


def validate_offline_confirmation(package: EvidencePackage) -> tuple[str, str]:
    """Check serialized record integrity; never certify an external execution."""
    report = package.attribution.get("offline_confirmation")
    if not isinstance(report, Mapping):
        return UNDIAGNOSED, "confirmation-record-missing"
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    if report.get("report_hash") != "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest():
        return UNDIAGNOSED, "confirmation-record-hash-mismatch"
    if report.get("schema_version") != "soc_offline_confirmation.v1" or \
            report.get("validation_scope") != "record-integrity-only" or \
            not isinstance(report.get("evidence"), Mapping):
        return UNDIAGNOSED, "confirmation-record-schema-mismatch"
    boundary, _ = classify_boundary(package)
    return boundary, "record-integrity-only"


def file_hash(path: Path) -> str:
    """Return the SHA-256 identity of the bytes currently stored at *path*."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _isolation_observation(stdout: str, marker: str, side: str) -> dict[str, int]:
    """Extract the one bounded fixture observation from a simulator transcript."""
    lines = [line for line in stdout.splitlines() if line.startswith(marker)]
    if not lines:
        raise ValueError(f"isolation-{side}-marker-missing")
    if len(lines) != 1:
        raise ValueError(f"isolation-{side}-marker-duplicate")
    fields: dict[str, str] = {}
    for part in lines[0][len(marker):].strip().split():
        if "=" not in part:
            raise ValueError(f"isolation-{side}-marker-malformed")
        key, value = part.split("=", 1)
        if key in fields:
            raise ValueError(f"isolation-{side}-marker-malformed")
        fields[key] = value
    bits, mosi = fields.get("bits"), fields.get("mosi")
    if (bits is None or mosi is None or not re.fullmatch(r"[0-9]+", bits)
            or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", mosi)):
        raise ValueError(f"isolation-{side}-marker-malformed")
    return {"bits": int(bits, 10), "mosi": int(mosi, 16)}


def run_isolation(fixture: IsolationFixture, *, baseline_source: Path,
                  mutant_source: Path, output_dir: Path,
                  timeout_seconds: int) -> Mapping[str, object]:
    """Compile and execute the declarative APB fixture against both RTL versions."""
    iverilog = shutil.which("iverilog")
    vvp = shutil.which("vvp")
    if not iverilog or not vvp:
        raise OSError("isolation-tool-missing")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Read every compiler input once.  The evidence hashes below therefore name
    # precisely the bytes consumed by both independent compiler invocations,
    # rather than mutable caller paths.
    fixture_bytes = Path(fixture.testbench).read_bytes()
    baseline_bytes = Path(baseline_source).read_bytes()
    mutant_bytes = Path(mutant_source).read_bytes()

    def execute(side: str, source: Path, testbench: Path) -> dict[str, object]:
        executable = output_dir / f"isolation-{side}"
        try:
            compile_result = subprocess.run(
                [iverilog, "-g2012", "-s", fixture.top_module, "-o", str(executable),
                 str(testbench), str(source)],
                shell=False, capture_output=True, text=True, check=False,
                timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(f"isolation-{side}-timeout") from error
        if compile_result.returncode:
            raise ValueError(f"isolation-{side}-compile-failed")
        try:
            run_result = subprocess.run(
                [vvp, str(executable)], shell=False, capture_output=True, text=True,
                check=False, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(f"isolation-{side}-timeout") from error
        if run_result.returncode:
            raise ValueError(f"isolation-{side}-run-failed")
        return {"observation": _isolation_observation(run_result.stdout, fixture.marker, side),
                "compile_returncode": compile_result.returncode,
                "run_returncode": run_result.returncode}

    with tempfile.TemporaryDirectory(prefix="isolation-input-", dir=output_dir) as temporary:
        snapshot_dir = Path(temporary)
        fixture_snapshot = snapshot_dir / ("fixture" + Path(fixture.testbench).suffix)
        baseline_snapshot = snapshot_dir / ("baseline-source" + Path(baseline_source).suffix)
        mutant_snapshot = snapshot_dir / ("mutant-source" + Path(mutant_source).suffix)
        fixture_snapshot.write_bytes(fixture_bytes)
        baseline_snapshot.write_bytes(baseline_bytes)
        mutant_snapshot.write_bytes(mutant_bytes)
        return {
            "baseline": execute("baseline", baseline_snapshot, fixture_snapshot),
            "mutant": execute("mutant", mutant_snapshot, fixture_snapshot),
            "fixture_hash": "sha256:" + hashlib.sha256(fixture_bytes).hexdigest(),
            "baseline_source_hash": "sha256:" + hashlib.sha256(baseline_bytes).hexdigest(),
            "mutant_source_hash": "sha256:" + hashlib.sha256(mutant_bytes).hexdigest(),
        }


def _source_bytes(build: RuntimeBuild, base_dir: Path) -> tuple[dict[str, str], tuple[str, ...]]:
    """Rehash a source closure and identify build records that have drifted."""
    current: dict[str, str] = {}
    drift: list[str] = []
    recorded = dict(build.source_hashes)
    for source in build.sources:
        name = str(source)
        path = Path(name)
        resolved = path if path.is_absolute() else base_dir / path
        if not resolved.is_file():
            raise ValueError(f"source-missing:{name}")
        actual = file_hash(resolved)
        current[name] = actual
        if recorded.get(name) != actual:
            drift.append(name)
    return current, tuple(drift)


def build_differential(baseline: RuntimeBuild, mutant: RuntimeBuild, *,
                       base_dir: Path | None = None) -> Mapping[str, object]:
    """Compare build artifacts from their current bytes, never caller claims."""
    root = Path.cwd() if base_dir is None else Path(base_dir)
    baseline_sources, baseline_drift = _source_bytes(baseline, root)
    mutant_sources, mutant_drift = _source_bytes(mutant, root)
    baseline_hashes = Counter(baseline_sources.values())
    mutant_hashes = Counter(mutant_sources.values())
    return {
        "top_equal": file_hash(baseline.top_path) == file_hash(mutant.top_path),
        "testbench_equal": (file_hash(baseline.testbench_path) ==
                            file_hash(mutant.testbench_path)),
        "boot_equal": _boot_hash(baseline) == _boot_hash(mutant),
        "removed_source_hashes": tuple(sorted((baseline_hashes - mutant_hashes).elements())),
        "added_source_hashes": tuple(sorted((mutant_hashes - baseline_hashes).elements())),
        "baseline_source_hashes": baseline_sources,
        "mutant_source_hashes": mutant_sources,
        "baseline_source_drift": baseline_drift,
        "mutant_source_drift": mutant_drift,
        **{side + "_build_hashes": {
            "top": file_hash(build.top_path),
            "testbench": file_hash(build.testbench_path),
            "boot_image": _boot_hash(build),
            "executable": file_hash(build.executable),
        } for side, build in (("baseline", baseline), ("mutant", mutant))},
    }


def _boot_hash(build: RuntimeBuild) -> str:
    return "none" if build.boot_image is None else file_hash(Path(build.boot_image))


def _same_build_abi(baseline: RuntimeBuild, mutant: RuntimeBuild) -> str | None:
    if baseline.raw_width != mutant.raw_width:
        return "raw-width"
    if baseline.slots != mutant.slots:
        return "slots"
    try:
        baseline_record = recorded_build_identity(baseline)
        mutant_record = recorded_build_identity(mutant)
    except Exception as error:  # the evidence module gives a stable diagnostic
        return f"build-record:{error}"
    if baseline_record["layout_hash"] != mutant_record["layout_hash"]:
        return "layout"
    if baseline_record["plan_hash"] != mutant_record["plan_hash"]:
        return "build-record"
    return None


def _runtime_identity_problem(package: EvidencePackage, mutant: RuntimeBuild) -> str | None:
    """Return the first absent, malformed, or stale runtime binding field."""
    identity = package.identity if isinstance(package.identity, Mapping) else {}
    runtime = identity.get("runtime")
    if not isinstance(runtime, Mapping):
        return "runtime:missing" if runtime is None else "runtime:malformed"

    saved_width = runtime.get("raw_width")
    if saved_width is None:
        return "runtime.raw_width:missing"
    if type(saved_width) is not int:
        return "runtime.raw_width:malformed"
    if saved_width != mutant.raw_width:
        return f"runtime.raw_width:saved={saved_width}:build={mutant.raw_width}"

    saved_hashes = runtime.get("source_hashes")
    if saved_hashes is None:
        return "runtime.source_hashes:missing"
    if not isinstance(saved_hashes, Mapping):
        return "runtime.source_hashes:malformed"
    if any(not isinstance(name, str) for name in saved_hashes):
        return "runtime.source_hashes:malformed"
    saved = dict(saved_hashes)
    expected = {str(name): value for name, value in mutant.source_hashes.items()}
    if (any(not isinstance(value, str) or not value.startswith("sha256:")
            or len(value) != len("sha256:") + 64 for value in saved.values())
            or saved != expected):
        return "runtime.source_hashes:mismatch"
    for field_name, expected_value in (
            ("schema_version", RUNTIME_SCHEMA),
            ("sources", list(mutant.sources)),
            ("boot_image_policy", mutant.boot_image_policy)):
        if runtime.get(field_name) != expected_value:
            return f"runtime.{field_name}:mismatch"
    return None


def _criterion_problem(package: EvidencePackage, criterion: Mapping[str, object]) -> str | None:
    if not isinstance(criterion, Mapping) or not criterion.get("independent_of_profile"):
        return "independent-criterion-missing"
    text = criterion.get("specification_text")
    stated_hash = criterion.get("specification_hash")
    if not isinstance(text, str) or not text or not isinstance(stated_hash, str) or \
            stated_hash != "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest():
        return "independent-criterion-hash"
    anomaly = package.anomaly if isinstance(package.anomaly, Mapping) else {}
    if str(criterion.get("criterion_id", "")) != str(anomaly.get("criterion", "")):
        return "independent-criterion-id"
    if criterion.get("expected") != anomaly.get("expected") or \
            criterion.get("observed") != anomaly.get("observed"):
        return "independent-criterion-observation"
    return None


def spi_wire_verdict(result: RunResult) -> tuple[str, object, object]:
    """Read MOSI verdicts from the independent SPI wire-check schema."""
    if not isinstance(result.peer_oracle, Mapping):
        return "not_assessed", None, None
    checks = result.peer_oracle.get("checks", ())
    if not isinstance(checks, (list, tuple)) or any(not isinstance(item, Mapping)
                                                    for item in checks):
        return "not_assessed", None, None
    matches = [item for item in checks if item.get("check_id") == "spi-transfer-wire"]
    if len(matches) != 1:
        return "not_assessed", None, None
    check = matches[0]
    expected = check.get("expected")
    observed = check.get("observed")
    if (not isinstance(expected, Mapping) or not isinstance(observed, Mapping)
            or not isinstance(expected.get("mosi"), list)
            or not isinstance(observed.get("mosi"), list)
            or not isinstance(expected.get("miso"), list)
            or not isinstance(observed.get("miso"), list)):
        return "not_assessed", None, None
    return str(check.get("status")), expected["mosi"], observed["mosi"]


def _run_problem(result: object, side: str) -> tuple[str, str] | None:
    """Classify invalid reruns without treating an unavailable tool as evidence."""
    if not isinstance(result, RunResult):
        return UNDIAGNOSED, f"{side}-rerun-result-invalid"
    if result.status != "OK":
        return UNDIAGNOSED, f"{side}-rerun-failed:{result.status}"
    if result.requests_truncated or any(bool(item.get("truncated"))
                                        for item in result.peer_wire_status):
        return COMPONENT_CANDIDATE, f"{side}-run-incomplete"
    return None


def _audit_summary(audit: Mapping[str, object]) -> Mapping[str, object]:
    summary = audit.get("summary")
    return dict(summary) if isinstance(summary, Mapping) else {}


def _fresh_evidence(*, baseline: RuntimeBuild, mutant: RuntimeBuild,
                    baseline_result: RunResult, mutant_result: RunResult,
                    replay: object, baseline_audit: Mapping[str, object],
                    mutant_audit: Mapping[str, object]) -> dict[str, object]:
    """Keep compact, freshly-derived records instead of caller-provided verdicts."""
    return {
        "baseline_top_hash": file_hash(baseline.top_path),
        "mutant_top_hash": file_hash(mutant.top_path),
        "baseline_run": baseline_result.document(),
        "mutant_run": mutant_result.document(),
        "mutant_replay": replay.document() if hasattr(replay, "document") else {},
        "baseline_structure_audit": _audit_summary(baseline_audit),
        "mutant_structure_audit": _audit_summary(mutant_audit),
    }


def _tool_failure_evidence(differential: Mapping[str, object], error: Exception) -> dict[str, object]:
    """Preserve diagnostics as evidence without making a reason environment-dependent."""
    return {**differential, "offline_rerun_error": {
        "type": type(error).__name__, "detail": str(error)}}


def _changed_source(build: RuntimeBuild, source_hash: str, source_name: str,
                    base_dir: Path) -> Path:
    """Find the one component file by its freshly verified bytes, not a caller path."""
    matches = [str(name) for name, digest in build.source_hashes.items()
               if digest == source_hash and source_name in Path(str(name)).stem]
    if len(matches) != 1:
        raise ValueError("isolation-source-not-unique")
    path = Path(matches[0])
    resolved = path if path.is_absolute() else base_dir / path
    if not resolved.is_file():
        raise ValueError("isolation-source-missing")
    if file_hash(resolved) != source_hash:
        raise ValueError("isolation-source-hash-drift")
    return resolved


def _single_byte(value: object) -> int | None:
    """Bridge the one-byte isolation fixture to the one-byte wire-oracle list."""
    if isinstance(value, list) and len(value) == 1 and type(value[0]) is int:
        value = value[0]
    if type(value) is int and 0 <= value <= 0xff:
        return value
    return None


_BUILD_METADATA = ("raw_width", "slots", "observations", "peer_slots",
                   "peer_observations", "peer_wires", "spi_wire_contracts",
                   "cpu_data_sources", "boot_image_policy", "build_hash")


def _plan_identity_problem(plan: CompositionPlan, baseline: RuntimeBuild,
                           mutant: RuntimeBuild, package: EvidencePackage,
                           *, base_dir: Path | None = None) -> str | None:
    if not isinstance(plan, CompositionPlan):
        return "plan-invalid"
    layout = plan.raw_layout.get("layout_hash")
    if not isinstance(plan.plan_hash, str) or not plan.plan_hash or not isinstance(layout, str) or not layout:
        return "plan-invalid"
    for side, build in (("baseline", baseline), ("mutant", mutant)):
        recorded = recorded_build_identity(build)
        if recorded["plan_hash"] != plan.plan_hash:
            return "plan_hash"
        if recorded["layout_hash"] != layout:
            return "layout_hash"
    identity = package.identity
    if identity.get("plan_hash") != plan.plan_hash:
        return "package.plan_hash"
    if identity.get("layout_hash") != layout:
        return "package.layout_hash"
    return _derived_plan_problem(plan, Path.cwd() if base_dir is None else base_dir)


def _derived_plan_problem(plan: CompositionPlan, base_dir: Path) -> str | None:
    # Stored plan_hash omits some audit inputs. Recreate every derived field
    # from the authoritative request/profiles, including future dataclass fields.
    expected = build_composition(plan.request, base_dir=base_dir,
                                 drive_profile=plan.drive_profile)
    for field in fields(CompositionPlan):
        if getattr(plan, field.name) != getattr(expected, field.name):
            return "derived-plan:" + field.name
    return None


def _build_metadata_problem(original: RuntimeBuild, rebuilt: RuntimeBuild,
                            side: str) -> str | None:
    for field_name in _BUILD_METADATA:
        if getattr(original, field_name) != getattr(rebuilt, field_name):
            return f"{side}-rebuilt-{field_name}-mismatch"
    if original.sources != rebuilt.sources:
        return f"{side}-rebuilt-sources-mismatch"
    if dict(original.source_hashes) != dict(rebuilt.source_hashes):
        return f"{side}-rebuilt-source_hashes-mismatch"
    for field_name in ("top", "testbench", "boot_image"):
        original_path = (original.top_path if field_name == "top" else
                         original.testbench_path if field_name == "testbench" else original.boot_image)
        rebuilt_path = (rebuilt.top_path if field_name == "top" else
                        rebuilt.testbench_path if field_name == "testbench" else rebuilt.boot_image)
        original_hash = "none" if original_path is None else file_hash(original_path)
        rebuilt_hash = "none" if rebuilt_path is None else file_hash(rebuilt_path)
        if original_hash != rebuilt_hash:
            return f"{side}-rebuilt-{field_name}-mismatch"
    return None


def _include_manifest(roots: Sequence[Path]) -> dict[str, str]:
    """Bounded, fail-closed inventory; not an immutable compiler input snapshot.

    Reject symlinks and special files rather than traversing outside declared
    roots. Pre/post comparisons detect observed drift, not a change restored
    between observations. Compiler wrappers must declare their include roots.
    """
    manifest: dict[str, str] = {}
    entries = 0
    total_bytes = 0
    for root in roots:
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("include-symlink:" + str(root))
        if not root.is_dir():
            raise ValueError("include-root-missing:" + str(root))
        pending = [root]
        while pending:
            directory = pending.pop()
            if directory.is_symlink():
                raise ValueError("include-symlink:" + str(directory))
            manifest[str(directory)] = "directory"
            with os.scandir(directory) as children:
                for child in children:
                    entries += 1
                    if entries > 100000:
                        raise ValueError("include-entry-limit")
                    mode = child.stat(follow_symlinks=False).st_mode
                    if stat.S_ISDIR(mode):
                        pending.append(Path(child.path))
                    elif stat.S_ISREG(mode):
                        digest = hashlib.sha256()
                        # O_NOFOLLOW also rejects a file swapped for a symlink
                        # after scandir; O_NONBLOCK prevents a swapped FIFO hang.
                        descriptor = os.open(child.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(descriptor, "rb") as source:
                            before = os.fstat(source.fileno())
                            if not stat.S_ISREG(before.st_mode):
                                raise ValueError("include-special-file:" + child.path)
                            size = 0
                            while chunk := source.read(1024 * 1024):
                                size += len(chunk)
                                total_bytes += len(chunk)
                                if size > 64 * 1024 * 1024 or total_bytes > 512 * 1024 * 1024:
                                    raise ValueError("include-size-limit")
                                digest.update(chunk)
                            after = os.fstat(source.fileno())
                        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError("include-read-drift:" + child.path)
                        manifest[child.path] = "sha256:" + digest.hexdigest()
                    else:
                        raise ValueError("include-symlink-or-special-file:" + child.path)
    return dict(sorted(manifest.items()))


def _rebuild_pair(plan: CompositionPlan, baseline: RuntimeBuild, mutant: RuntimeBuild,
                  *, base_dir: Path, output_dir: Path, timeout_seconds: int,
                  verilator: str | None, include_roots: Sequence[str] = (),
                  ) -> tuple[RuntimeBuild, RuntimeBuild, Mapping[str, object]]:
    tool = verilator or shutil.which("verilator")
    if not tool:
        raise OSError("runtime-tool-missing")
    resolved_tool = Path(tool).resolve()
    if not resolved_tool.is_file():
        raise OSError("runtime-tool-missing")
    tool_record = {"path": resolved_tool.as_posix(), "sha256": file_hash(resolved_tool)}
    roots = {Path(base_dir / item).absolute() for item in include_roots}
    for instance in plan.instances:
        source = instance.profile.source
        roots.update((base_dir / source.source_root / item).absolute()
                     for item in source.include_roots)
    roots = tuple(sorted(roots))
    include_manifest = _include_manifest(roots)
    tool_record["include_manifest"] = {
        "scope": "declared-roots-pre-post-drift-check-not-immutable-snapshot",
        "roots": [str(root) for root in roots],
        "entries": len(include_manifest),
        "sha256": "sha256:" + hashlib.sha256(canonical_bytes(include_manifest)).hexdigest(),
    }
    rebuilt: list[RuntimeBuild] = []
    for side, original in (("baseline", baseline), ("mutant", mutant)):
        if _include_manifest(roots) != include_manifest:
            raise ValueError(f"{side}-include-input-drift")
        expected_sources, drift = _source_bytes(original, base_dir)
        if drift:
            raise ValueError(f"{side}-source-drift:{drift[0]}")
        top_hash = file_hash(original.top_path)
        boot_hash = _boot_hash(original)
        rebuilt.append(build_profile_runtime(
            plan, output_dir=output_dir / side, base_dir=base_dir,
            top_text=original.top_path.read_text(encoding="utf-8"),
            sources=original.sources,
            boot_image=(None if original.boot_image_policy ==
                        "explicit_empty_image_no_program_loaded" else original.boot_image),
            timeout_seconds=timeout_seconds, verilator=resolved_tool.as_posix(),
            spi_wire_contracts=original.spi_wire_contracts))
        if _include_manifest(roots) != include_manifest:
            raise ValueError(f"{side}-include-input-drift")
        current_sources, post_drift = _source_bytes(original, base_dir)
        if post_drift or current_sources != expected_sources or \
                file_hash(original.top_path) != top_hash or _boot_hash(original) != boot_hash:
            raise ValueError(f"{side}-build-input-drift")
        if file_hash(resolved_tool) != tool_record["sha256"]:
            raise ValueError("runtime-tool-drift")
    return rebuilt[0], rebuilt[1], tool_record


def _confirm_component_offline_impl(
        package: EvidencePackage, *, plan: CompositionPlan, baseline: RuntimeBuild,
        mutant: RuntimeBuild, fixture: IsolationFixture, criterion: Mapping[str, object],
        base_dir: Path, include_roots: Sequence[str] = (), timeout_seconds: int = 600,
        verilator: str | None = None, rebuild_dir: Path,
) -> OfflineConfirmation:
    """Confirm only a fresh SoC and standalone-fixture reproduction."""
    boundary, reason = classify_boundary(package)
    if boundary != COMPONENT_CANDIDATE:
        return OfflineConfirmation(boundary, reason, {})

    mismatches = identity_mismatches(package, mutant)
    if mismatches:
        return OfflineConfirmation(UNDIAGNOSED, "mutant-identity:" + mismatches[0], {})
    runtime_problem = _runtime_identity_problem(package, mutant)
    if runtime_problem is not None:
        return OfflineConfirmation(UNDIAGNOSED, "mutant-identity:" + runtime_problem, {})
    abi_problem = _same_build_abi(baseline, mutant)
    if abi_problem is not None:
        return OfflineConfirmation(UNDIAGNOSED, "build-identity:" + abi_problem, {})
    if package.schema_version != "soc_failure_evidence.v1":
        return OfflineConfirmation(UNDIAGNOSED, "evidence-schema-unsupported", {})
    try:
        differential = build_differential(baseline, mutant, base_dir=base_dir)
    except (OSError, ValueError) as error:
        return OfflineConfirmation(UNDIAGNOSED, "build-files:" + str(error), {})
    for side in ("baseline", "mutant"):
        drift = differential[f"{side}_source_drift"]
        if drift:
            return OfflineConfirmation(UNDIAGNOSED, f"{side}-source-drift:{drift[0]}",
                                       differential)
    if not differential["top_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "generated-top-changed", differential)
    if not differential["testbench_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "testbench-changed", differential)
    if not differential["boot_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "boot-image-changed", differential)
    removed = differential["removed_source_hashes"]
    added = differential["added_source_hashes"]
    if len(removed) != 1 or len(added) != 1:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "source-differential-not-single", differential)
    criterion_problem = _criterion_problem(package, criterion)
    if criterion_problem is not None:
        return OfflineConfirmation(COMPONENT_CANDIDATE, criterion_problem, differential)
    if criterion.get("criterion_id") != "spi-mosi-byte":
        return OfflineConfirmation(COMPONENT_CANDIDATE,
                                   "unsupported-criterion:" + str(criterion.get("criterion_id")),
                                   differential)
    try:
        plan_problem = _plan_identity_problem(plan, baseline, mutant, package, base_dir=base_dir)
    except (OSError, ValueError) as error:
        return OfflineConfirmation(UNDIAGNOSED, "plan-identity:" + str(error), differential)
    if plan_problem:
        return OfflineConfirmation(UNDIAGNOSED, "plan-identity:" + plan_problem, differential)
    if len(package.samples) != 1 or len(package.results) != 1:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "offline-evidence-count", differential)
    try:
        replay = replay_package(package, mutant, timeout_seconds=timeout_seconds)
        fresh_baseline, fresh_mutant, tool_record = _rebuild_pair(
            plan, baseline, mutant, base_dir=base_dir, output_dir=rebuild_dir,
            timeout_seconds=timeout_seconds, verilator=verilator, include_roots=include_roots)
        for side, original, fresh in (("baseline", baseline, fresh_baseline),
                                      ("mutant", mutant, fresh_mutant)):
            problem = _build_metadata_problem(original, fresh, side)
            if problem:
                return OfflineConfirmation(UNDIAGNOSED, problem, differential)
        differential = {**differential, "rebuild_tool": tool_record,
                        "original_baseline_executable_provenance":
                        "unverified-not-used-for-differential",
                        "rebuilt_baseline_build_hashes": {
                            "top": file_hash(fresh_baseline.top_path),
                            "testbench": file_hash(fresh_baseline.testbench_path),
                            "boot_image": _boot_hash(fresh_baseline),
                            "executable": file_hash(fresh_baseline.executable)},
                        "rebuilt_mutant_build_hashes": {
                            "top": file_hash(fresh_mutant.top_path),
                            "testbench": file_hash(fresh_mutant.testbench_path),
                            "boot_image": _boot_hash(fresh_mutant),
                            "executable": file_hash(fresh_mutant.executable)}}
        baseline_result = run_sample(fresh_baseline, package.sample(), timeout_seconds=timeout_seconds)
        mutant_result = run_sample(fresh_mutant, package.sample(), timeout_seconds=timeout_seconds)
        baseline_audit = audit_structure(
            plan, top_text=fresh_baseline.top_path.read_text(encoding="utf-8"),
            source_files=fresh_baseline.sources, base_dir=base_dir, include_roots=include_roots)
        mutant_audit = audit_structure(
            plan, top_text=fresh_mutant.top_path.read_text(encoding="utf-8"),
            source_files=fresh_mutant.sources, base_dir=base_dir, include_roots=include_roots)
    except (OSError, ValueError, TimeoutError) as error:
        return OfflineConfirmation(UNDIAGNOSED, "offline-rerun-tool-failure",
                                   _tool_failure_evidence(differential, error))

    baseline_problem = _run_problem(baseline_result, "baseline")
    if baseline_problem is not None:
        return OfflineConfirmation(*baseline_problem, differential)
    mutant_problem = _run_problem(mutant_result, "mutant")
    if mutant_problem is not None:
        return OfflineConfirmation(*mutant_problem, differential)
    for side, audit in (("baseline", baseline_audit), ("mutant", mutant_audit)):
        if not isinstance(audit, Mapping) or _audit_summary(audit).get("status") not in (PASS, FAIL):
            return OfflineConfirmation(UNDIAGNOSED, f"{side}-structure-audit-invalid",
                                       differential)
    evidence = {**differential, "criterion": deepcopy(dict(criterion)), **_fresh_evidence(
        baseline=fresh_baseline, mutant=fresh_mutant, baseline_result=baseline_result,
        mutant_result=mutant_result, replay=replay, baseline_audit=baseline_audit,
        mutant_audit=mutant_audit)}
    if getattr(replay, "status", None) != REPLAY_AGREEMENT:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "replay-not-agreement", evidence)
    if _audit_summary(baseline_audit).get("status") == FAIL:
        return OfflineConfirmation(COMPOSITION_DEFECT, "baseline-structure-audit-failed", evidence)
    if _audit_summary(mutant_audit).get("status") == FAIL:
        return OfflineConfirmation(COMPOSITION_DEFECT, "mutant-structure-audit-failed", evidence)
    rebuilt_replay = compare_replay_results(package.results, (mutant_result,))
    evidence["rebuilt_mutant_replay"] = rebuilt_replay.document()
    if rebuilt_replay.status != REPLAY_AGREEMENT:
        return OfflineConfirmation(COMPONENT_CANDIDATE,
                                   "rebuilt-mutant-replay-not-agreement", evidence)
    if baseline_result.requests != mutant_result.requests or \
            baseline_result.peer_applied != mutant_result.peer_applied:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "cpu-peer-records-differ", evidence)
    baseline_status, baseline_expected, baseline_observed = spi_wire_verdict(baseline_result)
    mutant_status, mutant_expected, mutant_observed = spi_wire_verdict(mutant_result)
    if baseline_status != "pass":
        return OfflineConfirmation(COMPONENT_CANDIDATE,
                                   "baseline-spi-wire:" + baseline_status, evidence)
    if mutant_status != "mismatch":
        return OfflineConfirmation(COMPONENT_CANDIDATE,
                                   "mutant-spi-wire:" + mutant_status, evidence)
    if baseline_expected != criterion.get("expected") or \
            baseline_observed != criterion.get("expected") or \
            mutant_expected != criterion.get("expected"):
        return OfflineConfirmation(COMPONENT_CANDIDATE, "spi-criterion-observation", evidence)
    anomaly = package.anomaly if isinstance(package.anomaly, Mapping) else {}
    if mutant_observed != anomaly.get("observed"):
        return OfflineConfirmation(COMPONENT_CANDIDATE, "mutant-spi-observed", evidence)
    fixture_path = Path(fixture.testbench)
    fixture_path = fixture_path if fixture_path.is_absolute() else base_dir / fixture_path
    if not fixture_path.is_file():
        return OfflineConfirmation(UNDIAGNOSED, "isolation-fixture-missing", evidence)
    evidence = {**evidence, "fixture_top_module": fixture.top_module,
                "fixture_marker": fixture.marker}
    expected_byte = _single_byte(criterion.get("expected"))
    observed_byte = _single_byte(criterion.get("observed"))
    if expected_byte is None or observed_byte is None or expected_byte == observed_byte:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "isolation-criterion-not-single-byte", evidence)
    try:
        baseline_source = _changed_source(baseline, removed[0], fixture.source_name, base_dir)
        mutant_source = _changed_source(mutant, added[0], fixture.source_name, base_dir)
        isolation = run_isolation(
            IsolationFixture(fixture_path, fixture.top_module, fixture.marker, fixture.source_name),
            baseline_source=baseline_source, mutant_source=mutant_source,
            output_dir=rebuild_dir / "isolation", timeout_seconds=timeout_seconds)
    except TimeoutError as error:
        return OfflineConfirmation(UNDIAGNOSED, str(error), evidence)
    except OSError as error:
        return OfflineConfirmation(UNDIAGNOSED, "isolation-tool-failure",
                                   {**evidence, "isolation_error": str(error)})
    except ValueError as error:
        return OfflineConfirmation(COMPONENT_CANDIDATE, str(error), evidence)
    snapshot_fixture_hash = isolation.get("fixture_hash") if isinstance(isolation, Mapping) else None
    if not isinstance(snapshot_fixture_hash, str) or not snapshot_fixture_hash.startswith("sha256:"):
        return OfflineConfirmation(UNDIAGNOSED, "isolation-result-invalid", evidence)
    snapshot_baseline_hash = isolation.get("baseline_source_hash") if isinstance(isolation, Mapping) else None
    snapshot_mutant_hash = isolation.get("mutant_source_hash") if isinstance(isolation, Mapping) else None
    if not isinstance(snapshot_baseline_hash, str) or not isinstance(snapshot_mutant_hash, str):
        return OfflineConfirmation(UNDIAGNOSED, "isolation-result-invalid", evidence)
    evidence = {**evidence, "fixture_hash": snapshot_fixture_hash,
                "isolation_baseline_source_hash": snapshot_baseline_hash,
                "isolation_mutant_source_hash": snapshot_mutant_hash,
                "isolation": isolation}
    if snapshot_baseline_hash != removed[0] or snapshot_mutant_hash != added[0]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "isolation-source-hash-drift", evidence)
    try:
        baseline_observation = isolation["baseline"]["observation"]
        mutant_observation = isolation["mutant"]["observation"]
        baseline_mosi = baseline_observation["mosi"]
        mutant_mosi = mutant_observation["mosi"]
        baseline_bits = baseline_observation["bits"]
        mutant_bits = mutant_observation["bits"]
    except (KeyError, TypeError):
        return OfflineConfirmation(UNDIAGNOSED, "isolation-result-invalid", evidence)
    if type(baseline_bits) is not int or type(mutant_bits) is not int or \
            baseline_bits != 8 or mutant_bits != 8:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "isolation-bits-invalid", evidence)
    if baseline_mosi != expected_byte:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "isolation-baseline-observation", evidence)
    if mutant_mosi != observed_byte:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "isolation-mutant-observation", evidence)
    return OfflineConfirmation("component_confirmed", "offline-isolation-confirmed", evidence)


def confirm_component_offline(
        package: EvidencePackage, *, plan: CompositionPlan, baseline: RuntimeBuild,
        mutant: RuntimeBuild, fixture: IsolationFixture, criterion: Mapping[str, object],
        base_dir: Path, include_roots: Sequence[str] = (), timeout_seconds: int = 600,
        verilator: str | None = None,
) -> OfflineConfirmation:
    """Run confirmation with disposable, separate SoC reconstruction directories."""
    with tempfile.TemporaryDirectory(prefix="soc-offline-rebuild-") as temporary:
        return _confirm_component_offline_impl(
            package, plan=plan, baseline=baseline, mutant=mutant, fixture=fixture,
            criterion=criterion, base_dir=base_dir, include_roots=include_roots,
            timeout_seconds=timeout_seconds, verilator=verilator,
            rebuild_dir=Path(temporary))


__all__ = ["IsolationFixture", "OfflineConfirmation", "build_differential",
           "confirm_component_offline", "file_hash", "run_isolation", "spi_wire_verdict",
           "record_offline_confirmation", "validate_offline_confirmation"]
