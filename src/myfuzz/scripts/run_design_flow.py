#!/usr/bin/env python3
"""Run the myfuzz source-instrumentation-to-rfuzz flow for one design config."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
SRC_ROOT = REPO_ROOT / "src"
RFUZZ_ROOT = REPO_ROOT / "third_party" / "rfuzz"
if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())
if RFUZZ_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, RFUZZ_ROOT.as_posix())
if SRC_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, SRC_ROOT.as_posix())
if SCRIPT_DIR.as_posix() not in sys.path:
    sys.path.insert(0, SCRIPT_DIR.as_posix())

from myfuzz.scripts.composition_api import generate_compositions, write_composition_facts
from myfuzz.scripts.frontend_api import default_frontend_library, run_frontend_manifest
from myfuzz.scripts.source_only_frontend import run_source_only_frontend
from myfuzz.contracts import content_hash as contract_content_hash
from scripts.source_branch_instrumenter import instrument_project
from frontend_manifest_to_rfuzz_toml import (
    coverage_records,
    find_top_module,
    generate_toml,
    validate_frontend_candidate_join,
)
from myfuzz.harness import HarnessArtifact, StaticPolicyParameters, build_harness
from myfuzz.harness.abi import control_declarations
from myfuzz.original_rfuzz import (
    aligned_coverage_width,
    build_server_command,
    has_unique_closed_sv_module,
    load_materialized_harness,
    materialize_harness,
    native_input_identity,
    source_list_entries,
    write_text_file,
)
from myfuzz.rfuzz_compat import (
    resolve_rfuzz_verilator,
    validate_rfuzz_verilator_version,
)


STAGES = ["frontend", "composition", "instrument", "toml", "harness", "server", "fuzz"]
HARNESS_MODES = {"flat_direct", "candidate_direct", "candidate_depaware", "candidate_static"}
ORIGINAL_RFUZZ_FPGA_DIR = Path("/tmp/fpga")
ORIGINAL_RFUZZ_LOCK = Path("/tmp/myfuzz-original-rfuzz.lock")
SEEDED_FUZZER_RELATIVE = Path("third_party/rfuzz/upstream/target/release/kfuzz")


def coverage_universe_from_instrumentation(
    instrumentation: object,
    top: str | None = None,
) -> tuple[dict[str, object], ...]:
    if not isinstance(instrumentation, Mapping):
        raise ValueError("instrumentation must be an object")
    count = instrumentation.get("coverage_point_count")
    source_records = instrumentation.get("coverage")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("coverage_point_count must be a non-negative integer")
    if not isinstance(source_records, list):
        raise ValueError("instrumentation coverage must be an array")
    if count != len(source_records):
        raise ValueError("coverage_point_count does not match coverage records")
    selected_top = top
    if selected_top is None:
        selected_top = ""
    if not isinstance(selected_top, str):
        raise ValueError("selected top must be a string")
    records = (
        coverage_records(dict(instrumentation), selected_top)
        if selected_top
        else list(source_records)
    )

    file_ids: dict[str, int] = {}
    identities: set[str] = set()
    points: list[dict[str, object]] = []
    for index, value in enumerate(records):
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise ValueError(f"instrumentation coverage[{index}] must be an object")
        record = dict(value)
        identity = contract_content_hash(record)
        if identity in identities:
            raise ValueError("instrumentation coverage contains duplicate derived identities")
        identities.add(identity)
        filename = record.get("file")
        line = record.get("line")
        column = record.get("column", 0)
        padding = record.get("subtype") == "padding"
        if padding:
            if filename != "" or line != 0 or record.get("module") != selected_top:
                raise ValueError(f"instrumentation coverage[{index}] has invalid padding metadata")
            filename = f"<propagated:{selected_top}>"
            line = index + 1
        elif not isinstance(filename, str) or not filename:
            raise ValueError(f"instrumentation coverage[{index}].file is required")
        if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
            raise ValueError(f"instrumentation coverage[{index}].line must be positive")
        if isinstance(column, bool) or not isinstance(column, int) or column < 0:
            raise ValueError(f"instrumentation coverage[{index}].column must be non-negative")
        component_id = record.get("component_id", 1)
        if isinstance(component_id, bool) or not isinstance(component_id, int) or component_id <= 0:
            raise ValueError(f"instrumentation coverage[{index}].component_id must be positive")
        role = record.get("component_role", record.get("module", record.get("kind")))
        if not isinstance(role, str) or not role:
            raise ValueError(f"instrumentation coverage[{index}] has no component role")
        file_id = file_ids.setdefault(filename, len(file_ids) + 1)
        points.append({
            "point_id": index + 1,
            "stable_source_id": identity,
            "component_id": component_id,
            "component_role": role,
            "source": {"file_id": file_id, "line": line, "column": column},
        })
    return tuple(points)


def covered_point_ids_from_bitmap(
    points: object,
    bitmap: object,
) -> tuple[int, ...]:
    if not isinstance(points, (list, tuple)) or not isinstance(bitmap, (list, tuple)):
        raise ValueError("coverage points and bitmap must be arrays")
    logical_width = len(points)
    permitted_widths = {logical_width}
    if logical_width:
        permitted_widths.add(aligned_coverage_width(logical_width))
    if len(bitmap) not in permitted_widths:
        raise ValueError("RFuzz bitmap width does not match coverage point count")
    for index, value in enumerate(bitmap):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
            raise ValueError(f"RFuzz bitmap[{index}] must be a byte")
    covered: list[int] = []
    for index, (point, value) in enumerate(zip(points, bitmap[:logical_width])):
        if not isinstance(point, Mapping):
            raise ValueError(f"coverage points[{index}] must be an object")
        point_id = point.get("point_id")
        if isinstance(point_id, bool) or not isinstance(point_id, int) or point_id <= 0:
            raise ValueError(f"coverage points[{index}].point_id must be positive")
        if value != 255:
            covered.append(point_id)
    return tuple(covered)


def rfuzz_measurements(
    statistics: object,
    points: object,
) -> dict[str, object]:
    if not isinstance(statistics, Mapping):
        raise ValueError("RFuzz statistics must be an object")
    if not isinstance(points, (list, tuple)):
        raise ValueError("coverage points must be an array")

    def numerator(field: str) -> int:
        record = statistics.get(field)
        if not isinstance(record, Mapping):
            raise ValueError(f"RFuzz statistics {field} must be an object")
        value = record.get("global_numerator")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
            or not float(value).is_integer()
        ):
            raise ValueError(f"RFuzz statistics {field}.global_numerator is invalid")
        return int(value)

    runtime = statistics.get("runtime")
    if not isinstance(runtime, Mapping):
        raise ValueError("RFuzz statistics runtime must be an object")
    seconds = runtime.get("secs")
    nanos = runtime.get("nanos")
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, int)
        or seconds < 0
        or isinstance(nanos, bool)
        or not isinstance(nanos, int)
        or not 0 <= nanos < 1_000_000_000
    ):
        raise ValueError("RFuzz statistics runtime is invalid")
    bitmap = statistics.get("bitmap")
    covered = covered_point_ids_from_bitmap(points, bitmap)
    return {
        "elapsed_seconds": seconds + nanos / 1_000_000_000,
        "tests_executed": numerator("tests_per_second"),
        "cycles_executed": numerator("cycles_per_second"),
        "coverage_point_count": len(points),
        "covered_point_ids": list(covered),
    }


def load_rfuzz_measurements(
    path: Path,
    points: object,
    started_ns: int,
) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ValueError("RFuzz statistics are missing") from error
    except OSError as error:
        raise ValueError("RFuzz statistics must be a regular file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("RFuzz statistics must be a regular file")
        if metadata.st_mtime_ns < started_ns:
            raise ValueError("RFuzz statistics are stale")
        if metadata.st_size > 1024 * 1024:
            raise ValueError("RFuzz statistics exceed the size limit")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            statistics = json.load(stream)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("RFuzz statistics must be valid JSON") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return rfuzz_measurements(statistics, points)


def fuzz_result_document(
    job_id: str,
    artifact_id: str,
    execution_result: dict[str, object],
    statistics_path: Path,
    points: object,
    started_ns: int,
) -> dict[str, object]:
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("--job-id is required for a fuzz result document")
    if not isinstance(artifact_id, str):
        raise ValueError("--server-artifact-id is required for a fuzz result document")
    failures = execution_result.get("failure_reasons")
    resource_terminated = (
        failures.get("resource_terminated")
        if isinstance(failures, dict)
        else None
    )
    if resource_terminated == 1:
        return {
            "kind": "fuzz-resource",
            "job_id": job_id,
            "artifact_id": artifact_id,
            **execution_result,
        }
    measurements = load_rfuzz_measurements(statistics_path, points, started_ns)
    return {
        "kind": "fuzz",
        "job_id": job_id,
        "artifact_id": artifact_id,
        **measurements,
        **execution_result,
    }


def rfuzz_fifos_ready(fpga_dir: Path, server_ids: tuple[str, ...]) -> bool:
    for server_id in server_ids:
        for name in ("tx.fifo", "rx.fifo"):
            try:
                mode = (fpga_dir / server_id / name).lstat().st_mode
            except FileNotFoundError:
                return False
            if not stat.S_ISFIFO(mode):
                return False
    return True


def original_rfuzz_server_ids(
    paths: Mapping[str, Path], server_count: int, *, attempt: int, pid: int | None = None
) -> tuple[str, ...]:
    if not isinstance(paths, Mapping) or not isinstance(server_count, int) or server_count <= 0:
        raise ValueError("RFuzz server identity inputs are invalid")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
        raise ValueError("RFuzz attempt must be positive")
    process_id = os.getpid() if pid is None else pid
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise ValueError("RFuzz process identity must be positive")
    identity_path = paths.get("server") or paths.get("out_dir")
    if not isinstance(identity_path, Path):
        raise ValueError("RFuzz server identity path is required")
    digest = hashlib.sha256(identity_path.resolve().as_posix().encode("utf-8")).hexdigest()[:12]
    return tuple(
        f"myfuzz-{digest}-{process_id}-{attempt}-{index}"
        for index in range(server_count)
    )


def _validate_rfuzz_fpga_dir(fpga_dir: Path, *, create: bool = False) -> Path:
    if not isinstance(fpga_dir, Path) or not fpga_dir.is_absolute():
        raise ValueError("RFuzz FPGA directory must be an absolute path")
    try:
        metadata = fpga_dir.lstat()
    except FileNotFoundError:
        if not create:
            return fpga_dir
        fpga_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        metadata = fpga_dir.lstat()
    except OSError as error:
        raise ValueError("RFuzz FPGA directory cannot be inspected") from error
    if fpga_dir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("RFuzz FPGA directory must be a regular non-symlink directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("RFuzz FPGA directory must be owned by the current user")
    try:
        os.chmod(fpga_dir, 0o700)
    except OSError as error:
        raise ValueError("RFuzz FPGA directory permissions cannot be secured") from error
    return fpga_dir


@contextmanager
def _original_rfuzz_runtime():
    """Serialize access to the vendored fuzzer's hard-coded global FIFO root."""
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(ORIGINAL_RFUZZ_LOCK, flags, 0o600)
    except OSError as error:
        raise ValueError("cannot open the original RFuzz runtime lock") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("original RFuzz runtime lock must be a regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("original RFuzz runtime lock must be owned by the current user")
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as error:
            raise ValueError("original RFuzz runtime lock permissions cannot be secured") from error
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        fpga_dir = _validate_rfuzz_fpga_dir(ORIGINAL_RFUZZ_FPGA_DIR, create=True)
        yield fpga_dir
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_original_rfuzz_server_id(server_id: str) -> None:
    if not isinstance(server_id, str) or not re.fullmatch(
        r"myfuzz-[0-9a-f]{12}-[0-9]+-[0-9]+-[0-9]+", server_id
    ):
        raise ValueError("RFuzz server identity is invalid")


def rfuzz_endpoints_absent(fpga_dir: Path, server_ids: tuple[str, ...]) -> bool:
    if not isinstance(fpga_dir, Path) or not isinstance(server_ids, tuple):
        raise ValueError("RFuzz FIFO cleanup inputs are invalid")
    _validate_rfuzz_fpga_dir(fpga_dir)
    for server_id in server_ids:
        _validate_original_rfuzz_server_id(server_id)
        try:
            (fpga_dir / server_id).lstat()
        except FileNotFoundError:
            continue
        return False
    return True


def cleanup_original_rfuzz_endpoints(
    fpga_dir: Path, server_ids: tuple[str, ...]
) -> bool:
    if not isinstance(fpga_dir, Path) or not isinstance(server_ids, tuple):
        raise ValueError("RFuzz FIFO cleanup inputs are invalid")
    _validate_rfuzz_fpga_dir(fpga_dir)
    for server_id in server_ids:
        _validate_original_rfuzz_server_id(server_id)
        endpoint = fpga_dir / server_id
        if endpoint.is_symlink():
            endpoint.unlink()
        elif endpoint.exists():
            if not endpoint.is_dir():
                endpoint.unlink()
            else:
                shutil.rmtree(endpoint)
    try:
        fpga_dir.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        pass
    return rfuzz_endpoints_absent(fpga_dir, server_ids)


def result_json_path(root: Path, value: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("repository root must be absolute")
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("result path must be beneath the repository")
    raw = Path(value)
    destination = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("result path must be beneath the repository") from error
    return destination


def repo_root() -> Path:
    return REPO_ROOT


def rfuzz_flow_root(root: Path) -> Path:
    return root / "third_party" / "rfuzz" / "rfuzz_flow"


def rfuzz_upstream_root(root: Path) -> Path:
    return root / "third_party" / "rfuzz" / "upstream"


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def load_config(path: Path) -> dict:
    with path.open() as infile:
        return json.load(infile)


def resolve(root: Path, value: str) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(value)))
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def default_server_verilator(root: Path) -> str:
    return resolve_rfuzz_verilator(root)


def probe_verilator_version(verilator_bin: str, cwd: Path) -> str:
    if not isinstance(verilator_bin, str) or not verilator_bin:
        raise ValueError("Verilator executable is required")
    try:
        completed = subprocess.run(
            [verilator_bin, "--version"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("cannot determine the Verilator version") from error
    if completed.returncode != 0:
        raise ValueError("cannot determine the Verilator version")
    version = completed.stdout.strip().splitlines()
    if not version or not version[0]:
        raise ValueError("Verilator did not report a version")
    return validate_rfuzz_verilator_version(version[0])


def frontend_mode(cfg: dict) -> str:
    frontend_cfg = cfg.get("frontend", {})
    if isinstance(frontend_cfg, dict):
        return str(frontend_cfg.get("mode", "verilator"))
    return str(frontend_cfg or "verilator")


def stage_frontend(root: Path, cfg: dict, paths: dict, frontend_library: Path | None) -> dict:
    paths["out_dir"].mkdir(parents=True, exist_ok=True)
    if frontend_mode(cfg) == "source_only":
        return run_source_only_frontend(root, cfg, paths, write_debug_json=True)
    return run_frontend_manifest(
        root,
        cfg,
        paths,
        frontend_library=frontend_library,
        write_debug_json=True,
    )


def stage_composition(
    root: Path,
    cfg: dict,
    paths: dict,
    frontend_library: Path | None,
) -> dict[str, object]:
    """Materialize frontend facts and generate deterministic A candidates."""
    raw = cfg.get("composition")
    if not isinstance(raw, Mapping):
        raise ValueError("composition:configuration-required")

    config_value = raw.get("config", raw.get("declarations"))
    if not isinstance(config_value, str) or not config_value or "\0" in config_value:
        raise ValueError("composition.config:required")
    config_path = resolve(root, config_value)

    top_k = raw.get("top_k", 3)
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
        raise ValueError("composition.top_k:positive-integer-required")

    output_value = raw.get("out_dir")
    if output_value is None:
        output_path = paths["composition"]
    elif isinstance(output_value, str) and output_value and "\0" not in output_value:
        output_path = resolve(root, output_value)
    else:
        raise ValueError("composition.out_dir:path-required")

    frontend_value = raw.get("frontend_facts", raw.get("frontend"))
    if frontend_value is None:
        frontend_path = paths["composition_frontend"]
        write_composition_facts(config_path, frontend_path, frontend_library=frontend_library)
    elif isinstance(frontend_value, str) and frontend_value and "\0" not in frontend_value:
        frontend_path = resolve(root, frontend_value)
    else:
        raise ValueError("composition.frontend_facts:path-required")

    summary = generate_compositions(
        config_path,
        frontend_path,
        top_k,
        output_path,
        frontend_library=frontend_library,
    )
    candidates = summary.get("candidates", [])
    count = len(candidates) if isinstance(candidates, list) else 0
    print(f"Generated composition candidates: {count}")
    print(f"Composition output: {output_path}")
    return summary


def stage_instrument(root: Path, cfg: dict, paths: dict, frontend_manifest: dict) -> dict:
    instrumentation_cfg = cfg.get("instrumentation", {})
    instrumented = paths["instrumented"]
    manifest = instrument_project(
        paths["project_root"],
        instrumented,
        flist=paths["flist"],
        frontend_manifest=frontend_manifest,
        frontend_json=paths["frontend_json"],
        top_module=cfg["top"],
        settings=instrumentation_cfg,
        coverage_port=instrumentation_cfg.get("coverage_port", cfg.get("coverage_port", "__vi_coverage")),
        signal_prefix=instrumentation_cfg.get("signal_prefix", cfg.get("signal_prefix", "__vi_branch_cov")),
        force=True,
    )
    shutil.copy2(instrumented / "instrumented_sources.f", instrumented / "sources.f")
    print(f"Instrumented HDL files: {manifest['file_count']}")
    print(f"Coverage points: {manifest['coverage_point_count']}")
    return manifest


def validate_candidate_manifest(candidate_manifest: object) -> dict:
    if not isinstance(candidate_manifest, dict):
        raise ValueError("candidate manifest must be an object")
    if candidate_manifest.get("schema_version") != "candidate_manifest.v1":
        raise ValueError("candidate manifest schema_version must be candidate_manifest.v1")
    candidate_id = candidate_manifest.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate_manifest.v1 candidate_id must be a non-empty string")
    if not isinstance(candidate_manifest.get("top_port_abi"), list):
        raise ValueError("candidate_manifest.v1 top_port_abi must be an array")
    if not isinstance(candidate_manifest.get("coverage_universe"), list):
        raise ValueError("candidate_manifest.v1 coverage_universe must be an array")
    return candidate_manifest


def build_configured_harness(
    manifest: object,
    cfg: Mapping[str, object],
    mode: str,
) -> HarnessArtifact:
    if mode != "candidate_static":
        return build_harness(manifest, mode)
    static = cfg.get("static_projection")
    if not isinstance(static, Mapping):
        raise ValueError("candidate_static requires static_projection config")
    declarations = static.get("declarations")
    parameters = static.get("parameters")
    if not isinstance(declarations, Mapping) or not isinstance(parameters, Mapping):
        raise ValueError("static_projection requires declarations and parameters")
    typed = StaticPolicyParameters(
        parameters.get("direct_ratio"),
        parameters.get("event_rarity"),
        parameters.get("legal_set_strength"),
        parameters.get("mutual_exclusion"),
    )
    return build_harness(
        manifest,
        mode,
        static_declarations=declarations,
        static_parameters=typed,
    )


def _artifact_module_name(artifact: HarnessArtifact) -> str:
    declaration = artifact.source_text.splitlines()[0].split()
    if len(declaration) < 2 or declaration[0] != "module":
        raise ValueError("generated harness source has no module declaration")
    return declaration[1]


def write_candidate_harness_artifact(paths: dict, artifact: HarnessArtifact) -> tuple[Path, Path]:
    harness_dir = Path(paths["harness"])
    harness_dir.mkdir(parents=True, exist_ok=True)
    source_path = harness_dir / f"{artifact.mode}.sv"
    fragment_path = harness_dir / f"{artifact.mode}.abi.json"
    write_text_file(source_path, artifact.source_text)
    fragment = artifact.manifest_fragment()
    fragment.update(source=source_path.name, module=_artifact_module_name(artifact))
    write_json(fragment_path, fragment)
    return source_path, fragment_path


def harness_config_for_artifact(cfg: dict, artifact: HarnessArtifact, source_path: Path, fragment_path: Path) -> dict:
    value = cfg.get("harness", {})
    harness_cfg = dict(value) if isinstance(value, dict) else {}
    harness_cfg.update(
        candidate_mode=artifact.mode,
        manual_harness=source_path.resolve().as_posix(),
        manual_harness_module=_artifact_module_name(artifact),
        manual_harness_input="rfuzz_input_bits",
        raw_width=artifact.raw_width,
        raw_abi_hash=artifact.abi.abi_hash,
        raw_abi_manifest=fragment_path.resolve().as_posix(),
    )
    return harness_cfg


def original_rfuzz_candidate_ports(
    candidate_manifest: Mapping[str, object], raw_width: int
) -> tuple[tuple[str, int], ...]:
    controls = control_declarations(candidate_manifest)
    reset = controls.get("reset")
    if "clock" not in controls or reset is None or reset.get("io_meta_reset") is not True:
        raise ValueError(
            "original RFuzz requires clock, reset, and explicit io_meta_reset candidate controls"
        )
    return (
        ("clock", 1),
        ("reset", 1),
        ("io_meta_reset", 1),
        ("rfuzz_input_bits", raw_width),
    )


def stage_toml(
    root: Path,
    cfg: dict,
    paths: dict,
    frontend_manifest: dict,
    instrumentation: dict,
    candidate_manifest: dict,
    candidate_mode: str,
) -> None:
    manifest = validate_candidate_manifest(candidate_manifest)
    frontend_module = find_top_module(frontend_manifest, cfg["top"])
    validate_frontend_candidate_join(frontend_module, cfg["top"], manifest)
    artifact = build_configured_harness(manifest, cfg, candidate_mode)
    source_path, fragment_path = write_candidate_harness_artifact(paths, artifact)
    harness_cfg = harness_config_for_artifact(cfg, artifact, source_path, fragment_path)
    generate_toml(
        frontend_manifest,
        instrumentation,
        cfg["top"],
        paths["toml"],
        harness_cfg,
        root=root,
        candidate_manifest=candidate_manifest,
    )
    print(f"Generated rfuzz TOML: {paths['toml']}")


def selected_instrumented_top_source(
    root: Path, paths: Mapping[str, Path], instrumentation: Mapping[str, object], top: str
) -> str:
    instrumented = paths.get("instrumented")
    if not isinstance(instrumented, Path):
        raise ValueError("instrumented source directory is required for coverage validation")
    source_list = instrumented / "sources.f"
    source_files = source_list_entries(root, source_list)
    for candidate in source_files:
        try:
            source = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ValueError(f"instrumented source list entry cannot be read: {candidate}") from None
        if has_unique_closed_sv_module(source, top, "selected top module"):
            return source
    raise ValueError(f"selected top module {top!r} is absent from instrumented sources")


def stage_harness(
    root: Path,
    cfg: dict,
    paths: dict,
    server_bin: str,
    frontend_manifest: dict,
    instrumentation: dict,
    candidate_manifest: dict,
    candidate_mode: str,
) -> HarnessArtifact:
    manifest = validate_candidate_manifest(candidate_manifest)
    frontend_module = find_top_module(frontend_manifest, cfg["top"])
    validate_frontend_candidate_join(frontend_module, cfg["top"], manifest)
    artifact = build_configured_harness(manifest, cfg, candidate_mode)
    source_path, fragment_path = write_candidate_harness_artifact(paths, artifact)
    del server_bin
    design_source = selected_instrumented_top_source(root, paths, instrumentation, cfg["top"])
    generated = materialize_harness(
        root,
        harness_dir=paths["harness"],
        base_toml=paths["toml"],
        instrumentation=instrumentation,
        top=cfg["top"],
        expected_ports=original_rfuzz_candidate_ports(manifest, artifact.raw_width),
        sources_file=paths["instrumented"] / "sources.f",
        design_source=design_source,
    )
    print(f"Generated harness: {generated.wrapper}")
    print(f"Generated augmented TOML: {generated.toml}")
    print(f"Generated raw ABI: {fragment_path}")
    return artifact

def stage_server(
    root: Path, cfg: dict, paths: dict, server_bin: str, jobs: str
) -> dict[str, object]:
    server_cfg = cfg.get("server", {}) if isinstance(cfg.get("server", {}), dict) else {}
    del jobs
    sources_file = paths["instrumented"] / "sources.f"
    instrumentation_path = paths["instrumented"] / "instrumentation.json"
    try:
        instrumentation = json.loads(instrumentation_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("instrumentation evidence must be valid JSON before server build") from error
    design_source = selected_instrumented_top_source(root, paths, instrumentation, cfg["top"])
    generated = load_materialized_harness(
        root,
        paths["harness"],
        instrumentation=instrumentation,
        sources_file=sources_file,
        design_source=design_source,
    )
    if generated.coverage.top != cfg["top"]:
        raise ValueError("materialized original RFuzz top does not match selected design top")
    extra_sources = tuple(
        resolve(root, str(source))
        for source in server_cfg.get("extra_verilator_sources", [])
    )
    extra_cflags = tuple(str(flag) for flag in server_cfg.get("extra_cflags", []))
    extra_ldflags = tuple(str(flag) for flag in server_cfg.get("extra_ldflags", []))
    verilator_args = tuple(str(arg) for arg in cfg.get("verilator_args", []))
    cxx_opt = str(server_cfg.get("cxx_opt", "-O3"))
    verilator_opt = str(server_cfg.get("verilator_opt", "-O3"))
    input_identity: str | None = None
    verilator_version: str | None = None
    expected_identity = cfg.get("native_rfuzz_input_identity")
    if expected_identity is not None:
        if not isinstance(expected_identity, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", expected_identity
        ) is None:
            raise ValueError("native_rfuzz_input_identity must be a canonical SHA-256 identity")
        verilator_version = probe_verilator_version(server_bin, root)
        declared_version = cfg.get("native_rfuzz_verilator_version")
        if declared_version is not None and declared_version != verilator_version:
            raise ValueError("native RFuzz Verilator version does not match the planned identity")
        input_identity = native_input_identity(
            root,
            sources_file=sources_file,
            verilator_bin=server_bin,
            verilator_version=verilator_version,
            extra_sources=extra_sources,
            extra_cflags=extra_cflags,
            extra_ldflags=extra_ldflags,
            verilator_args=verilator_args,
            cxx_opt=cxx_opt,
            verilator_opt=verilator_opt,
        )
        if input_identity != expected_identity:
            raise ValueError("native RFuzz input identity does not match the planned identity")
    validate_output_parent(paths["server"] / "server")
    paths["server"].mkdir(parents=True, exist_ok=True)
    cmd = build_server_command(
        root,
        verilator_bin=server_bin,
        wrapper_module=generated.wrapper_module,
        sources_file=paths["instrumented"] / "sources.f",
        wrapper=generated.wrapper,
        candidate_source=generated.raw_abi.source,
        dut_header=generated.header,
        server_dir=paths["server"],
        extra_sources=extra_sources,
        extra_cflags=extra_cflags,
        extra_ldflags=extra_ldflags,
        verilator_args=verilator_args,
        cxx_opt=cxx_opt,
        verilator_opt=verilator_opt,
    )
    result = run_monitored_command(
        cmd,
        cwd=root,
        hard_memory_bytes=cfg.get("hard_memory_bytes"),
    )
    if result["returncode"] != 0 and not result["resource_terminated"]:
        raise subprocess.CalledProcessError(int(result["returncode"]), cmd)
    if input_identity is not None and not result["resource_terminated"]:
        write_json(
            paths["server"] / "build-input.json",
            {
                "schema_version": "myfuzz.original_rfuzz.build-input.v1",
                "artifact_id": cfg.get("server_artifact_id", ""),
                "input_identity": input_identity,
                "verilator_version": verilator_version,
            },
        )
        result = dict(result)
        result["input_identity"] = input_identity
        result["verilator_version"] = verilator_version
    return result


def seeded_fuzzer_path(root: Path) -> Path:
    """Return the explicit campaign-seeded fuzzer profile used by experiments."""
    return root.resolve() / SEEDED_FUZZER_RELATIVE


def _validate_fuzzer_executable(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is missing: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise ValueError(f"{label} must be a regular executable non-symlink file: {path}")
    return path


def build_fuzzer(root: Path, cfg: Mapping[str, object] | None = None) -> Path:
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg, Mapping) else {}
    if not isinstance(fuzz_cfg, Mapping):
        fuzz_cfg = {}
    declared = fuzz_cfg.get("fuzzer_path")
    if declared is not None:
        if (
            not isinstance(declared, str)
            or Path(declared).is_absolute()
            or Path(declared).as_posix() != SEEDED_FUZZER_RELATIVE.as_posix()
        ):
            raise ValueError(
                "fuzz.fuzzer_path must explicitly select the repository campaign-seed fuzzer"
            )
        return _validate_fuzzer_executable(
            seeded_fuzzer_path(root), "campaign-seed fuzzer"
        )

    fuzzer_dir = rfuzz_flow_root(root) / "fuzzer"
    fuzzer = fuzzer_dir / "target" / "release" / "kfuzz"
    if fuzzer.exists():
        return _validate_fuzzer_executable(fuzzer, "vendored kfuzz")
    run(["cargo", "build", "--release"], cwd=fuzzer_dir)
    if not fuzzer.exists():
        raise FileNotFoundError(fuzzer)
    return _validate_fuzzer_executable(fuzzer, "vendored kfuzz")


def terminate_process(proc: subprocess.Popen, timeout: int = 5) -> int | None:
    group_id = proc.pid

    def signal_tree(sig: int) -> bool:
        try:
            os.killpg(group_id, sig)
            return True
        except ProcessLookupError:
            return False

    def group_alive() -> bool:
        try:
            os.killpg(group_id, 0)
            return True
        except ProcessLookupError:
            return False

    owns_group = proc.poll() is not None

    if proc.poll() is None:
        try:
            group = os.getpgid(proc.pid)
            if group == proc.pid:
                owns_group = True
                signal_tree(signal.SIGTERM)
            else:
                proc.terminate()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                group = os.getpgid(proc.pid)
                if group == proc.pid:
                    signal_tree(signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            proc.wait()
    if owns_group:
        signal_tree(signal.SIGTERM)
        deadline = time.monotonic() + timeout
        while group_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        if group_alive():
            signal_tree(signal.SIGKILL)
    return proc.returncode


def interrupt_process(proc: subprocess.Popen, timeout: int = 5) -> int | None:
    """Ask kfuzz to flush its final snapshot before the hard stop."""
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return terminate_process(proc, timeout=timeout)
    return proc.returncode


def terminate_processes(procs: list[subprocess.Popen], timeout: int = 5) -> int | None:
    result: int | None = None
    for proc in procs:
        rc = terminate_process(proc, timeout=timeout)
        if result is None or (result == 0 and rc not in (None, 0)):
            result = rc
    return result


class _ProcessTreeMonitor:
    def __init__(self, processes: list[subprocess.Popen], hard_memory_bytes: int | None) -> None:
        self.processes = list(processes)
        self.hard_memory_bytes = hard_memory_bytes
        self.peak_rss_bytes = 0
        self.resource_terminated = False

    def observe(self) -> bool:
        roots = {process.pid for process in self.processes}
        parents: dict[int, int] = {}
        rss: dict[int, int] = {}
        page_size = os.sysconf("SC_PAGE_SIZE")
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                suffix = (entry / "stat").read_text().rpartition(")")[2].split()
                pid = int(entry.name)
                parents[pid] = int(suffix[1])
                rss[pid] = int(suffix[21]) * page_size
            except (FileNotFoundError, IndexError, OSError, ValueError):
                continue
        selected = set(roots)
        changed = True
        while changed:
            changed = False
            for pid, parent in parents.items():
                if parent in selected and pid not in selected:
                    selected.add(pid)
                    changed = True
        current = sum(rss.get(pid, 0) for pid in selected)
        self.peak_rss_bytes = max(self.peak_rss_bytes, current)
        if (
            self.hard_memory_bytes is not None
            and current >= self.hard_memory_bytes
            and not self.resource_terminated
        ):
            self.resource_terminated = True
            terminate_processes(self.processes)
        return self.resource_terminated


def run_monitored_command(
    cmd: list[str],
    *,
    cwd: Path,
    hard_memory_bytes: int | None,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    print("+ " + " ".join(cmd), flush=True)
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    monitor = _ProcessTreeMonitor([process], hard_memory_bytes)
    while process.poll() is None:
        monitor.observe()
        if monitor.resource_terminated:
            break
        time.sleep(0.05)
    monitor.observe()
    returncode = process.wait()
    terminate_process(process, timeout=1)
    return {
        "returncode": returncode,
        "peak_rss_bytes": max(1, monitor.peak_rss_bytes),
        "resource_terminated": monitor.resource_terminated,
    }


def first_returncode(procs: list[subprocess.Popen]) -> tuple[int | None, int | None]:
    first_seen: tuple[int | None, int | None] = (None, None)
    for index, proc in enumerate(procs):
        rc = proc.poll()
        if rc not in (None, 0):
            return index, rc
        if rc is not None and first_seen[1] is None:
            first_seen = (index, rc)
    return first_seen


def copy_if_exists(src: Path, dst: Path) -> bool:
    if src.exists():
        validate_output_parent(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        validate_output_parent(dst)
        validate_output_file(dst)
        shutil.copy2(src, dst)
        return True
    return False


def validate_output_parent(path: Path) -> None:
    """Reject symlinked output parents before creating missing descendants."""
    parent = path.parent
    while True:
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            if parent == parent.parent:
                raise ValueError(f"output parent cannot be inspected: {parent}")
            parent = parent.parent
            continue
        except OSError as error:
            raise ValueError(f"output parent cannot be inspected: {parent}") from error
        if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                f"output parent must be a regular non-symlink directory: {parent}"
            )
        if parent == parent.parent:
            break
        parent = parent.parent


def validate_output_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ValueError(f"output file cannot be inspected: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"output file must be a regular non-symlink file: {path}")


def write_json(path: Path, data: dict) -> None:
    validate_output_file(path)
    validate_output_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_output_parent(path)
    validate_output_file(path)
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        validate_output_file(path)
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def fuzz_server_count(cfg: dict) -> int:
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg.get("fuzz", {}), dict) else {}
    raw_count = fuzz_cfg.get("server_count", 1)
    if isinstance(raw_count, bool) or not isinstance(raw_count, int):
        raise ValueError("fuzz.server_count must be exactly one server")
    count = raw_count
    if count != 1:
        raise ValueError("fuzz.server_count must be exactly one server")
    return count


def next_crash_dir(crash_root: Path) -> Path:
    crash_root.mkdir(parents=True, exist_ok=True)
    existing = []
    for child in crash_root.iterdir():
        if child.is_dir() and child.name.startswith("crash_"):
            try:
                existing.append(int(child.name.split("_", 1)[1]))
            except ValueError:
                pass
    return crash_root / f"crash_{(max(existing) + 1) if existing else 1:06d}"


def queue_has_entries(queue_dir: Path) -> bool:
    return queue_dir.exists() and any(queue_dir.glob("entry_*.json"))


def load_replay_input_set(path: Path) -> set[tuple[int, ...]]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return set()
    candidates: list[list[int]] = []
    if isinstance(data.get("inputs"), list):
        candidates.append(data["inputs"])
    if isinstance(data.get("entry"), dict) and isinstance(data["entry"].get("inputs"), list):
        candidates.append(data["entry"]["inputs"])
    if isinstance(data.get("tests"), list):
        for test in data["tests"]:
            if isinstance(test, dict) and isinstance(test.get("inputs"), list):
                candidates.append(test["inputs"])
    return {tuple(int(value) & 0xff for value in item) for item in candidates}


def copy_queue_without_crash_inputs(src: Path, dst: Path, crash_jsons: list[Path]) -> bool:
    if not queue_has_entries(src):
        return False
    crash_inputs: set[tuple[int, ...]] = set()
    for path in crash_jsons:
        crash_inputs.update(load_replay_input_set(path))
    shutil.rmtree(dst, ignore_errors=True)
    dst.mkdir(parents=True, exist_ok=True)
    copied = 0
    for entry in sorted(src.glob("entry_*.json")):
        try:
            data = json.loads(entry.read_text())
            inputs = data.get("entry", {}).get("inputs", [])
            key = tuple(int(value) & 0xff for value in inputs)
        except (json.JSONDecodeError, TypeError, ValueError):
            key = ()
        if key and key in crash_inputs:
            continue
        shutil.copy2(entry, dst / f"entry_{copied:04d}.json")
        copied += 1
    return copied > 0


def _queue_entry_sort_key(path: Path) -> int:
    match = re.fullmatch(r"entry_(\d+)\.json", path.name)
    return int(match.group(1)) if match is not None else -1


def write_reproduce_script(
    path: Path,
    root: Path,
    cfg_path: Path,
    replay_input: Path,
    *,
    server_path: Path | None = None,
    fuzzer_path: Path | None = None,
    queue_snapshot: Path | None = None,
    server_id: str | None = None,
) -> None:
    root = root.resolve()
    config: Mapping[str, object] | None = None
    if server_path is None or fuzzer_path is None:
        config = load_config(cfg_path)
    if server_path is None:
        assert config is not None
        server_path = resolve(root, str(config["out_dir"])) / "server" / "server"
    if fuzzer_path is None:
        assert config is not None
        fuzz_cfg = config.get("fuzz", {}) if isinstance(config.get("fuzz", {}), Mapping) else {}
        declared = fuzz_cfg.get("fuzzer_path")
        fuzzer_path = (
            resolve(root, str(declared))
            if isinstance(declared, str)
            else rfuzz_flow_root(root) / "fuzzer" / "target" / "release" / "kfuzz"
        )
    if queue_snapshot is None:
        queue_snapshot = replay_input.parent / "queue_snapshot"
    if server_id is None:
        server_id = "myfuzz-000000000000-1-1-0"
    _validate_original_rfuzz_server_id(server_id)
    script = f'''#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys
import time

ROOT = Path({str(root)!r})
SERVER = Path({str(server_path.resolve())!r})
FUZZER = Path({str(fuzzer_path.resolve())!r})
CONFIG = Path({str(cfg_path.resolve())!r})
QUEUE_SNAPSHOT = Path({str(queue_snapshot.resolve())!r})
REPLAY_QUEUE = Path({str((replay_input.parent / "replay_queue").resolve())!r})
SERVER_ID = {server_id!r}
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.scripts.run_design_flow import (
    _original_rfuzz_runtime,
    cleanup_original_rfuzz_endpoints,
    rfuzz_fifos_ready,
    terminate_processes,
)

if REPLAY_QUEUE.exists():
    raise SystemExit(f"refusing to overwrite existing replay queue: {{REPLAY_QUEUE}}")
if not QUEUE_SNAPSHOT.is_dir():
    raise SystemExit(f"queue snapshot is missing: {{QUEUE_SNAPSHOT}}")
config = json.loads(CONFIG.read_text(encoding="utf-8"))
toml = SERVER.parent.parent / "harness" / (config["top"] + ".rfuzz.toml")
REPLAY_QUEUE.mkdir(mode=0o700)
processes = []
with _original_rfuzz_runtime() as fpga_dir:
    process = subprocess.Popen([str(SERVER), SERVER_ID], cwd=SERVER.parent, start_new_session=True)
    processes.append(process)
    try:
        deadline = time.time() + 20
        while not rfuzz_fifos_ready(fpga_dir, (SERVER_ID,)):
            if process.poll() is not None:
                raise RuntimeError("server exited before FIFO creation")
            if time.time() >= deadline:
                raise TimeoutError("timed out waiting for RFuzz FIFOs")
            time.sleep(0.1)
        subprocess.run(
            [str(FUZZER), str(toml), "--output-directory", str(REPLAY_QUEUE),
             "--input-directory", str(QUEUE_SNAPSHOT), "--server-id", SERVER_ID],
            cwd=SERVER.parent,
            check=True,
        )
    finally:
        terminate_processes(processes)
        cleanup_original_rfuzz_endpoints(fpga_dir, (SERVER_ID,))
'''
    write_text_file(path, script)
    path.chmod(0o755)


def archive_crash(
    root: Path,
    cfg: dict,
    cfg_path: Path,
    paths: dict,
    attempt: int,
    reason: str,
    returncode: int | None,
    server_returncode: int | None,
    server_log: Path,
    fuzzer_log: Path,
    *,
    fuzzer_path: Path | None = None,
    server_id: str | None = None,
) -> Path:
    crash_dir = next_crash_dir(paths["out_dir"] / "crashes")
    crash_dir.mkdir(parents=True, exist_ok=True)

    copied_latest_stats = copy_if_exists(paths["queue"] / "latest.json", crash_dir / "latest_stats.json")
    copy_if_exists(server_log, crash_dir / "server.log")
    for extra_server_log in sorted(server_log.parent.glob("server_*.log")):
        copy_if_exists(extra_server_log, crash_dir / extra_server_log.name)
    copy_if_exists(fuzzer_log, crash_dir / "kfuzz.log")
    latest_entry: Path | None = None
    if paths["queue"].exists():
        shutil.copytree(paths["queue"], crash_dir / "queue_snapshot", dirs_exist_ok=True)
        entries = sorted(paths["queue"].glob("entry_*.json"), key=_queue_entry_sort_key)
        if entries:
            latest_entry = entries[-1]
            copy_if_exists(latest_entry, crash_dir / "latest_entry.json")

    crash_input = crash_dir / "crash_input.json"
    if latest_entry is not None:
        try:
            entry_document = json.loads(latest_entry.read_text(encoding="utf-8"))
            inputs = entry_document.get("entry", {}).get("inputs")
            if not isinstance(inputs, list) or any(
                isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255
                for value in inputs
            ):
                raise ValueError
            write_json(crash_input, {"inputs": inputs})
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
            crash_input.unlink(missing_ok=True)
    replay_input = crash_input if crash_input.exists() else None

    metadata = {
        "kind": "myfuzz_crash",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "attempt": attempt,
        "reason": reason,
        "fuzzer_returncode": returncode,
        "server_returncode": server_returncode,
        "top": cfg["top"],
        "config": str(cfg_path),
        "out_dir": str(paths["out_dir"]),
        "latest_stats_saved": copied_latest_stats,
        "latest_entry_saved": latest_entry is not None,
        "crash_input": str(crash_input) if crash_input.exists() else None,
        "queue_snapshot_saved": (crash_dir / "queue_snapshot").exists(),
        "replay_input": str(replay_input) if replay_input is not None else None,
        "reproduce_script": (
            str(crash_dir / "reproduce.sh")
            if replay_input is not None and (crash_dir / "queue_snapshot").is_dir()
            else None
        ),
        "server_path": str(paths["server"] / "server"),
        "fuzzer_path": str(fuzzer_path) if fuzzer_path is not None else None,
        "server_id": server_id,
    }
    write_json(crash_dir / "metadata.json", metadata)
    if replay_input is not None and (crash_dir / "queue_snapshot").is_dir():
        write_reproduce_script(
            crash_dir / "reproduce.sh",
            root,
            cfg_path,
            replay_input,
            server_path=paths["server"] / "server",
            fuzzer_path=fuzzer_path,
            queue_snapshot=crash_dir / "queue_snapshot",
            server_id=server_id,
        )
    print(f"Archived crash: {crash_dir}", flush=True)
    return crash_dir


def _vendor_latest_counts(queue_dir: Path) -> tuple[int, int] | None:
    """Read the vendored queue snapshot without treating missing data as progress."""
    latest = queue_dir / "latest.json"
    try:
        metadata = latest.lstat()
        if latest.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return None
        document = json.loads(latest.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, Mapping):
        return None

    def count(field: str) -> int | None:
        record = document.get(field)
        value = record.get("global_numerator") if isinstance(record, Mapping) else None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not math.isfinite(float(value)) or value < 0 or int(value) != value:
            return None
        return int(value)

    tests = count("tests_per_second")
    cycles = count("cycles_per_second")
    if tests is None or cycles is None:
        return None
    return tests, cycles


def _is_seeded_fuzzer(path: Path) -> bool:
    expected = SEEDED_FUZZER_RELATIVE.as_posix()
    return path.is_absolute() and path.as_posix().endswith("/" + expected)


def _validate_vendored_fuzz_config(
    fuzz_cfg: Mapping[str, object], fuzzer: Path | None = None
) -> None:
    seeded = fuzzer is not None and _is_seeded_fuzzer(fuzzer)
    unsupported = sorted(
        key
        for key in (
            "save_latest_every_runs",
            "test_buffer_size",
            "coverage_buffer_size",
            "buffer_count",
        )
        if key in fuzz_cfg
    )
    if unsupported:
        raise ValueError(
            "vendored kfuzz does not support fuzz configuration fields: "
            + ", ".join(unsupported)
        )
    if "fuzzer_path" in fuzz_cfg:
        declared = fuzz_cfg["fuzzer_path"]
        if (
            not seeded
            or not isinstance(declared, str)
            or Path(declared).as_posix() != SEEDED_FUZZER_RELATIVE.as_posix()
        ):
            raise ValueError(
                "fuzz.fuzzer_path must explicitly select the campaign-seed fuzzer"
            )
    if "seed" in fuzz_cfg:
        if not seeded:
            raise ValueError(
                "seeded fuzzing requires the explicit campaign-seed fuzzer and --campaign-seed"
            )
        seed = fuzz_cfg["seed"]
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("fuzz.seed must be a non-negative integer")
    for key in ("max_cycles", "max_runs"):
        if key in fuzz_cfg:
            value = fuzz_cfg[key]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"fuzz.{key} must be a positive integer")


def _run_fuzz_attempt(
    root: Path,
    cfg: dict,
    cfg_path: Path,
    paths: dict,
    fuzzer: Path,
    seconds: int | None,
    attempt: int,
    resume_queue: Path | None,
    fpga_dir: Path,
) -> tuple[str, int | None, int | None, Path | None, bool, int, bool]:
    queue_dir = paths["queue"]
    attempt_dir = paths["out_dir"] / "attempts" / f"attempt_{attempt:04d}"
    server_count = fuzz_server_count(cfg)
    server_ids = original_rfuzz_server_ids(
        paths, server_count, attempt=attempt
    )
    cleanup_original_rfuzz_endpoints(fpga_dir, server_ids)
    shutil.rmtree(queue_dir, ignore_errors=True)
    attempt_dir.mkdir(parents=True, exist_ok=True)
    _validate_rfuzz_fpga_dir(fpga_dir, create=True)

    env = os.environ.copy()
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg.get("fuzz", {}), dict) else {}
    _validate_vendored_fuzz_config(fuzz_cfg, fuzzer)

    server = paths["server"] / "server"
    toml = paths["harness"] / f"{cfg['top']}.rfuzz.toml"
    server_id_arg = server_ids[0]
    server_log = attempt_dir / "server.log"
    server_logs = [
        attempt_dir / ("server.log" if index == 0 else f"server_{index}.log")
        for index in range(server_count)
    ]
    fuzzer_log = attempt_dir / "kfuzz.log"

    server_procs: list[subprocess.Popen] = []
    hard_memory = cfg.get("hard_memory_bytes")
    if isinstance(hard_memory, bool) or (
        hard_memory is not None and (not isinstance(hard_memory, int) or hard_memory <= 0)
    ):
        raise ValueError("hard_memory_bytes must be a positive integer")
    monitor = _ProcessTreeMonitor(server_procs, hard_memory)
    try:
        for server_id, log_path in zip(server_ids, server_logs):
            print(f"+ {server} {server_id}", flush=True)
            with log_path.open("wb") as server_out:
                server_process = subprocess.Popen(
                    [server.as_posix(), server_id],
                    cwd=paths["out_dir"],
                    env=env,
                    stdout=server_out,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                server_procs.append(server_process)
                monitor.processes.append(server_process)
        ready: set[str] = set()
        deadline = time.time() + 20
        while time.time() < deadline and len(ready) < server_count:
            if monitor.observe():
                return "resource", None, terminate_processes(server_procs), None, False, monitor.peak_rss_bytes, True
            for server_id, proc in zip(server_ids, server_procs):
                if proc.poll() is not None:
                    archive = archive_crash(
                        root, cfg, cfg_path, paths, attempt, f"server_{server_id}_exited_before_fifo",
                        None, proc.returncode, server_log, fuzzer_log,
                        fuzzer_path=fuzzer, server_id=server_id_arg,
                    )
                    return "infra", None, proc.returncode, archive, False, monitor.peak_rss_bytes, False
                if rfuzz_fifos_ready(fpga_dir, (server_id,)):
                    ready.add(server_id)
            time.sleep(0.1)
        if len(ready) < server_count:
            server_rc = terminate_processes(server_procs)
            archive = archive_crash(
                root, cfg, cfg_path, paths, attempt, "fifo_timeout",
                None, server_rc, server_log, fuzzer_log,
                fuzzer_path=fuzzer, server_id=server_id_arg,
            )
            return "infra", None, server_rc, archive, False, monitor.peak_rss_bytes, False

        cmd = [
            fuzzer.as_posix(),
            toml.as_posix(),
            "--output-directory",
            queue_dir.as_posix(),
            "--server-id",
            server_id_arg,
        ]
        if bool(fuzz_cfg.get("random", False)):
            cmd.append("--random")
        if bool(fuzz_cfg.get("skip_deterministic", False)):
            cmd.append("--skip-deterministic")
        if bool(fuzz_cfg.get("skip_non_deterministic", False)):
            cmd.append("--skip-non-deterministic")
        if "jqf_level" in fuzz_cfg:
            jqf_level = int(fuzz_cfg["jqf_level"])
            if jqf_level not in (0, 1, 2):
                raise ValueError("fuzz.jqf_level must be 0, 1, or 2")
            cmd.extend(["--jqf-level", str(jqf_level)])
        if "seed_cycles" in fuzz_cfg:
            seed_cycles = int(fuzz_cfg["seed_cycles"])
            if seed_cycles <= 0:
                raise ValueError("fuzz.seed_cycles must be positive")
            cmd.extend(["--seed-cycles", str(seed_cycles)])
        if "seed" in fuzz_cfg:
            cmd.extend(["--campaign-seed", str(fuzz_cfg["seed"])])
        if resume_queue is not None and queue_has_entries(resume_queue):
            cmd.extend(["--input-directory", resume_queue.as_posix()])
        if seconds is not None:
            budget_label = f"wall-seconds={seconds}"
        elif "max_cycles" in fuzz_cfg:
            budget_label = f"cycles={fuzz_cfg['max_cycles']}"
        else:
            budget_label = f"runs={fuzz_cfg['max_runs']}"
        print("+ " + " ".join([f"myfuzz-budget({budget_label})", *cmd]), flush=True)
        with fuzzer_log.open("wb") as fuzzer_out:
            fuzzer_proc = subprocess.Popen(
                cmd,
                cwd=paths["out_dir"],
                env=env,
                stdout=fuzzer_out,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            monitor.processes.append(fuzzer_proc)
            attempt_deadline = None if seconds is None else time.time() + seconds
            while True:
                if monitor.observe():
                    return "resource", fuzzer_proc.returncode, terminate_processes(server_procs), None, True, monitor.peak_rss_bytes, True
                fuzzer_rc = fuzzer_proc.poll()
                server_index, server_rc = first_returncode(server_procs)
                if fuzzer_rc is not None:
                    break
                if server_rc is not None:
                    fuzzer_rc = terminate_process(fuzzer_proc)
                    archive = archive_crash(
                        root, cfg, cfg_path, paths, attempt, f"server_{server_index}_exited_during_fuzz",
                        fuzzer_rc, server_rc, server_log, fuzzer_log,
                        fuzzer_path=fuzzer, server_id=server_id_arg,
                    )
                    return "infra", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
                latest_counts = _vendor_latest_counts(queue_dir)
                if latest_counts is not None:
                    tests_executed, cycles_executed = latest_counts
                    cycle_limit = fuzz_cfg.get("max_cycles")
                    run_limit = fuzz_cfg.get("max_runs")
                    if cycle_limit is not None and cycles_executed >= cycle_limit:
                        stop_reason = "max_cycles_budget"
                    elif run_limit is not None and tests_executed >= run_limit:
                        stop_reason = "max_runs_budget"
                    else:
                        stop_reason = None
                    if stop_reason is not None:
                        fuzzer_rc = interrupt_process(fuzzer_proc)
                        server_rc = terminate_processes(server_procs)
                        monitor.observe()
                        if fuzzer_rc != 0:
                            archive = archive_crash(
                                root, cfg, cfg_path, paths, attempt,
                                f"{stop_reason}_termination_failed",
                                fuzzer_rc, server_rc, server_log, fuzzer_log,
                                fuzzer_path=fuzzer, server_id=server_id_arg,
                            )
                            return "infra", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
                        return "ok", fuzzer_rc, server_rc, None, True, monitor.peak_rss_bytes, False
                if attempt_deadline is not None and time.time() >= attempt_deadline:
                    fuzzer_rc = interrupt_process(fuzzer_proc)
                    server_rc = terminate_processes(server_procs)
                    monitor.observe()
                    if fuzzer_rc != 0:
                        archive = archive_crash(
                            root, cfg, cfg_path, paths, attempt,
                            "fuzzer_timeout_termination_failed",
                            fuzzer_rc, server_rc, server_log, fuzzer_log,
                            fuzzer_path=fuzzer, server_id=server_id_arg,
                        )
                        return "infra", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
                    return "ok", fuzzer_rc, server_rc, None, True, monitor.peak_rss_bytes, False
                time.sleep(0.2)

        _, server_rc = first_returncode(server_procs)
        if fuzzer_rc == 0 and (server_rc is None or server_rc == 0):
            server_rc = terminate_processes(server_procs)
            monitor.observe()
            return "ok", fuzzer_rc, server_rc, None, True, monitor.peak_rss_bytes, False
        server_rc = terminate_processes(server_procs)
        archive = archive_crash(
            root, cfg, cfg_path, paths, attempt, "fuzzer_failed",
            fuzzer_rc, server_rc, server_log, fuzzer_log,
            fuzzer_path=fuzzer, server_id=server_id_arg,
        )
        monitor.observe()
        return "infra", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
    finally:
        terminate_processes(server_procs)
        cleanup_original_rfuzz_endpoints(fpga_dir, server_ids)


def run_fuzz_attempt(
    root: Path,
    cfg: dict,
    cfg_path: Path,
    paths: dict,
    fuzzer: Path,
    seconds: int | None,
    attempt: int,
    resume_queue: Path | None,
) -> tuple[str, int | None, int | None, Path | None, bool, int, bool]:
    with _original_rfuzz_runtime() as fpga_dir:
        return _run_fuzz_attempt(
            root,
            cfg,
            cfg_path,
            paths,
            fuzzer,
            seconds,
            attempt,
            resume_queue,
            fpga_dir,
        )


def validate_fuzz_artifact(root: Path, cfg: Mapping[str, object], paths: Mapping[str, Path]) -> None:
    """Reload the selected build artifact and attest its native inputs before fuzzing."""
    artifact_id = cfg.get("server_artifact_id")
    if artifact_id is None:
        return
    if not isinstance(artifact_id, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", artifact_id
    ) is None:
        raise ValueError("server_artifact_id must be a canonical SHA-256 identity")

    server = paths["server"] / "server"
    try:
        server_metadata = server.lstat()
    except OSError as error:
        raise ValueError("selected RFuzz server artifact is missing") from error
    if server.is_symlink() or not stat.S_ISREG(server_metadata.st_mode) or not os.access(server, os.X_OK):
        raise ValueError("selected RFuzz server artifact must be a regular executable")

    instrumentation_path = paths["instrumented"] / "instrumentation.json"
    try:
        instrumentation_metadata = instrumentation_path.lstat()
        if instrumentation_path.is_symlink() or not stat.S_ISREG(instrumentation_metadata.st_mode):
            raise ValueError("artifact instrumentation evidence must be a regular file")
        instrumentation = json.loads(instrumentation_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("artifact instrumentation evidence must be valid JSON") from error
    design_source = selected_instrumented_top_source(
        root, dict(paths), instrumentation, str(cfg["top"])
    )
    load_materialized_harness(
        root,
        paths["harness"],
        instrumentation=instrumentation,
        sources_file=paths["instrumented"] / "sources.f",
        design_source=design_source,
    )

    sidecar = paths["server"] / "build-input.json"
    try:
        sidecar_metadata = sidecar.lstat()
        if sidecar.is_symlink() or not stat.S_ISREG(sidecar_metadata.st_mode):
            raise ValueError("RFuzz build input sidecar must be a regular file")
        document = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("RFuzz build input sidecar must be valid JSON") from error
    if not isinstance(document, Mapping):
        raise ValueError("RFuzz build input sidecar must be an object")
    if document.get("schema_version") != "myfuzz.original_rfuzz.build-input.v1":
        raise ValueError("RFuzz build input sidecar schema is invalid")
    if document.get("artifact_id") != artifact_id:
        raise ValueError("RFuzz build input sidecar artifact identity does not match")
    recorded_identity = document.get("input_identity")
    if not isinstance(recorded_identity, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", recorded_identity
    ) is None:
        raise ValueError("RFuzz build input sidecar identity is invalid")
    expected_identity = cfg.get("native_rfuzz_input_identity")
    if expected_identity is not None and recorded_identity != expected_identity:
        raise ValueError("RFuzz build input sidecar identity does not match the plan")

    server_cfg = cfg.get("server", {}) if isinstance(cfg.get("server", {}), Mapping) else {}
    extra_sources = tuple(
        resolve(root, str(source))
        for source in server_cfg.get("extra_verilator_sources", [])
    )
    extra_cflags = tuple(str(flag) for flag in server_cfg.get("extra_cflags", []))
    extra_ldflags = tuple(str(flag) for flag in server_cfg.get("extra_ldflags", []))
    verilator_args = tuple(str(arg) for arg in cfg.get("verilator_args", []))
    cxx_opt = str(server_cfg.get("cxx_opt", "-O3"))
    verilator_opt = str(server_cfg.get("verilator_opt", "-O3"))
    verilator_bin = str(cfg.get("native_rfuzz_verilator_bin", default_server_verilator(root)))
    verilator_version = probe_verilator_version(verilator_bin, root)
    declared_version = cfg.get("native_rfuzz_verilator_version")
    if declared_version is not None and declared_version != verilator_version:
        raise ValueError("artifact Verilator version does not match the planned identity")
    current_identity = native_input_identity(
        root,
        sources_file=paths["instrumented"] / "sources.f",
        verilator_bin=verilator_bin,
        verilator_version=verilator_version,
        extra_sources=extra_sources,
        extra_cflags=extra_cflags,
        extra_ldflags=extra_ldflags,
        verilator_args=verilator_args,
        cxx_opt=cxx_opt,
        verilator_opt=verilator_opt,
    )
    if current_identity != recorded_identity:
        raise ValueError("selected RFuzz artifact native inputs changed after the build")


def stage_fuzz(
    root: Path,
    cfg: dict,
    cfg_path: Path,
    paths: dict,
    seconds: int | None,
) -> dict[str, object]:
    validate_fuzz_artifact(root, cfg, paths)
    fuzzer = build_fuzzer(root, cfg)
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg.get("fuzz", {}), dict) else {}
    if seconds is None and not any(
        key in fuzz_cfg for key in ("max_cycles", "max_runs")
    ):
        raise ValueError("fuzz requires a wall-time, cycle, or run budget")
    max_restarts = int(fuzz_cfg.get("crash_restarts", cfg.get("crash_restarts", 3)))
    stop_on_crash = bool(fuzz_cfg.get("stop_on_crash", cfg.get("stop_on_crash", False)))
    resume_queue: Path | None = None
    if fuzz_cfg.get("input_directory"):
        resume_queue = resolve(root, str(fuzz_cfg["input_directory"]))
    crashes: list[str] = []
    deadline = None if seconds is None else time.time() + seconds

    for attempt in range(1, max_restarts + 2):
        remaining = None if deadline is None else max(1, int(deadline - time.time()))
        if deadline is not None and time.time() >= deadline:
            raise RuntimeError(
                f"fuzz time budget exhausted after {len(crashes)} crash restart(s)"
            )
        outcome = run_fuzz_attempt(
            root, cfg, cfg_path, paths, fuzzer, remaining, attempt, resume_queue,
        )
        status, fuzzer_rc, server_rc, crash_dir = outcome[:4]
        handshake = bool(outcome[4]) if len(outcome) > 4 else status == "ok"
        peak_rss = int(outcome[5]) if len(outcome) > 5 else 1
        resource_terminated = bool(outcome[6]) if len(outcome) > 6 else False
        attempt_ids = original_rfuzz_server_ids(
            paths, fuzz_server_count(cfg), attempt=attempt
        )
        with _original_rfuzz_runtime() as fpga_dir:
            cleanup = rfuzz_endpoints_absent(fpga_dir, attempt_ids)
        if resource_terminated:
            return {
                "peak_rss_bytes": max(1, peak_rss),
                "server_returncode": server_rc if server_rc is not None else -15,
                "fuzzer_returncode": fuzzer_rc if fuzzer_rc is not None else -15,
                "handshake_succeeded": handshake,
                "fifo_cleanup_succeeded": cleanup,
                "crash_restart_count": len(crashes),
                "failure_reasons": {
                    "dut_crash": 0, "resource_terminated": 1,
                },
            }
        if status == "infra":
            raise RuntimeError(
                f"fuzz infrastructure failure on attempt {attempt}; "
                f"fuzzer_returncode={fuzzer_rc}, server_returncode={server_rc}, "
                f"evidence={crash_dir}"
            )
        if status == "ok":
            if crashes:
                print(f"Fuzz completed after {len(crashes)} crash restart(s).", flush=True)
            return {
                "peak_rss_bytes": max(1, peak_rss),
                "server_returncode": server_rc if server_rc is not None else 0,
                "fuzzer_returncode": fuzzer_rc if fuzzer_rc is not None else 0,
                "handshake_succeeded": handshake,
                "fifo_cleanup_succeeded": cleanup,
                "crash_restart_count": len(crashes),
                "failure_reasons": {
                    "dut_crash": len(crashes), "resource_terminated": 0,
                },
            }
        if crash_dir is not None:
            crashes.append(crash_dir.as_posix())
        if stop_on_crash or attempt > max_restarts:
            raise RuntimeError(
                f"fuzz crashed after attempt {attempt}; "
                f"fuzzer_returncode={fuzzer_rc}, server_returncode={server_rc}, "
                f"crashes={crashes}"
            )
        candidate_resume = crash_dir / "queue_snapshot" if crash_dir is not None else None
        resume_queue = None
        if candidate_resume is not None and queue_has_entries(candidate_resume):
            filtered = crash_dir / "resume_queue"
            crash_jsons = [crash_dir / "crash_input.json", crash_dir / "crash_batch.json"]
            if copy_queue_without_crash_inputs(candidate_resume, filtered, crash_jsons):
                resume_queue = filtered
        print(f"Restarting fuzz after crash ({attempt}/{max_restarts}); resume_queue={resume_queue}", flush=True)
    raise RuntimeError("fuzz stage exhausted without a terminal result")


def selected_stages(stage: str) -> list[str]:
    if stage == "all":
        return STAGES
    return [stage]


def artifact_flow_paths(paths: dict[str, Path], artifact_id: str | None) -> dict[str, Path]:
    if artifact_id is None:
        return paths
    if re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None:
        raise ValueError("server artifact ID must be a canonical SHA-256 identity")
    root = paths["out_dir"] / "server_artifacts" / artifact_id.removeprefix("sha256:")
    selected = dict(paths)
    selected.update({
        "toml": root / "instrumented" / paths["toml"].name,
        "harness": root / "harness",
        "server": root / "server",
        "queue": root / "queue",
    })
    return selected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run myfuzz design flow.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--stage", choices=["all", *STAGES], default="all")
    parser.add_argument("--frontend-library")
    parser.add_argument("--manifest", "--candidate-manifest", dest="manifest")
    parser.add_argument("--candidate-mode", choices=sorted(HARNESS_MODES), default=None)
    parser.add_argument("--server-artifact-id")
    parser.add_argument("--server-input-identity")
    parser.add_argument("--server-verilator-bin")
    parser.add_argument("--jobs", default=os.environ.get("MYFUZZ_JOBS", "1"))
    parser.add_argument("--fuzz-seconds", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--max-cycles", type=int)
    parser.add_argument("--hard-memory-bytes", type=int)
    parser.add_argument("--job-id")
    parser.add_argument("--result-json")
    parser.add_argument("--force", action=argparse.BooleanOptionalAction, default=False)
    return parser.parse_args()


def select_candidate_mode(cli_mode: str | None, cfg: dict) -> str:
    harness_cfg = cfg.get("harness", {}) if isinstance(cfg.get("harness"), dict) else {}
    configured = cfg.get("candidate_mode", harness_cfg.get("candidate_mode"))
    mode = cli_mode or configured or "candidate_direct"
    if mode not in HARNESS_MODES:
        raise ValueError(f"unknown candidate mode: {mode}")
    return str(mode)


def main() -> int:
    root = repo_root()
    args = parse_args()
    cfg_path = resolve(root, args.config)
    cfg = load_config(cfg_path)
    fuzz_seconds_arg = getattr(args, "fuzz_seconds", None)
    seed_arg = getattr(args, "seed", None)
    max_cycles_arg = getattr(args, "max_cycles", None)
    hard_memory_arg = getattr(args, "hard_memory_bytes", None)
    server_artifact_id = getattr(args, "server_artifact_id", None)
    server_input_identity = getattr(args, "server_input_identity", None)
    if server_input_identity is not None and re.fullmatch(
        r"sha256:[0-9a-f]{64}", server_input_identity
    ) is None:
        raise ValueError("--server-input-identity must be a canonical SHA-256 identity")
    if fuzz_seconds_arg is not None and fuzz_seconds_arg <= 0:
        raise ValueError("--fuzz-seconds must be positive")
    if hard_memory_arg is not None and hard_memory_arg <= 0:
        raise ValueError("--hard-memory-bytes must be positive")
    if (
        seed_arg is not None
        or max_cycles_arg is not None
        or hard_memory_arg is not None
        or server_artifact_id is not None
        or server_input_identity is not None
    ):
        if seed_arg is not None and seed_arg < 0:
            raise ValueError("--seed must be non-negative")
        if max_cycles_arg is not None and max_cycles_arg <= 0:
            raise ValueError("--max-cycles must be positive")
        cfg = dict(cfg)
        fuzz_cfg = cfg.get("fuzz", {})
        cfg["fuzz"] = dict(fuzz_cfg) if isinstance(fuzz_cfg, dict) else {}
        if seed_arg is not None:
            cfg["fuzz"]["seed"] = seed_arg
        if max_cycles_arg is not None:
            cfg["fuzz"]["max_cycles"] = max_cycles_arg
        if hard_memory_arg is not None:
            cfg["hard_memory_bytes"] = hard_memory_arg
        if server_artifact_id is not None:
            cfg["server_artifact_id"] = server_artifact_id
        if server_input_identity is not None:
            cfg["native_rfuzz_input_identity"] = server_input_identity
    manifest_arg = getattr(args, "manifest", None) or cfg.get("candidate_manifest")
    candidate_manifest = None
    if manifest_arg:
        candidate_manifest = load_config(resolve(root, str(manifest_arg)))
    candidate_mode = select_candidate_mode(getattr(args, "candidate_mode", None), cfg)
    out_dir = resolve(root, cfg["out_dir"])
    stages = selected_stages(args.stage)
    if args.force and "frontend" in stages and out_dir.exists():
        shutil.rmtree(out_dir)
    elif args.force and out_dir.exists() and args.stage != "all":
        print(f"--force for stage {args.stage} keeps existing flow outputs; remove {out_dir} or run --stage frontend --force to restart.", flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "out_dir": out_dir,
        "project_root": resolve(root, cfg["project_root"]),
        "flist": resolve(root, cfg["flist"]),
        "frontend_json": out_dir / "frontend.json",
        "composition": out_dir / "composition",
        "composition_frontend": out_dir / "composition_hdl_facts.json",
        "instrumented": out_dir / "instrumented",
        "toml": out_dir / "instrumented" / f"{cfg['top']}.toml",
        "harness": out_dir / "harness",
        "server": out_dir / "server",
        "queue": out_dir / "queue",
    }
    paths = artifact_flow_paths(paths, server_artifact_id)
    frontend_library = resolve(root, args.frontend_library) if args.frontend_library else default_frontend_library(root)
    server_bin = (
        args.server_verilator_bin
        or cfg.get("native_rfuzz_verilator_bin")
        or default_server_verilator(root)
    )
    if cfg.get("native_rfuzz_input_identity") is not None or server_artifact_id is not None:
        cfg = dict(cfg)
        cfg["native_rfuzz_verilator_bin"] = server_bin
    result_path = (
        result_json_path(root, args.result_json)
        if getattr(args, "result_json", None) is not None
        else None
    )
    if result_path is not None and args.stage not in {"server", "fuzz"}:
        raise ValueError("--result-json requires exactly the server or fuzz stage")

    frontend_manifest = None
    instrumentation = None
    if "frontend" in stages:
        frontend_manifest = stage_frontend(root, cfg, paths, frontend_library)
    if "composition" in stages:
        stage_composition(root, cfg, paths, frontend_library)
    if "instrument" in stages:
        if frontend_manifest is None:
            frontend_manifest = json.loads(paths["frontend_json"].read_text())
        instrumentation = stage_instrument(root, cfg, paths, frontend_manifest)
    if "toml" in stages:
        if frontend_manifest is None:
            frontend_manifest = json.loads(paths["frontend_json"].read_text())
        if instrumentation is None:
            instrumentation = json.loads((paths["instrumented"] / "instrumentation.json").read_text())
        if candidate_manifest is None:
            raise ValueError("validated candidate manifest path is required for TOML generation")
        stage_toml(root, cfg, paths, frontend_manifest, instrumentation, candidate_manifest, candidate_mode)
    if "harness" in stages:
        if frontend_manifest is None:
            frontend_manifest = json.loads(paths["frontend_json"].read_text())
        if instrumentation is None:
            instrumentation = json.loads(
                (paths["instrumented"] / "instrumentation.json").read_text()
            )
        if candidate_manifest is None:
            raise ValueError("validated candidate manifest path is required for harness generation")
        stage_harness(
            root,
            cfg,
            paths,
            server_bin,
            frontend_manifest,
            instrumentation,
            candidate_manifest,
            candidate_mode,
        )
    if "server" in stages:
        if server_artifact_id is not None:
            if frontend_manifest is None:
                frontend_manifest = json.loads(paths["frontend_json"].read_text())
            if instrumentation is None:
                instrumentation = json.loads(
                    (paths["instrumented"] / "instrumentation.json").read_text()
                )
            if candidate_manifest is None:
                raise ValueError("validated candidate manifest path is required for server generation")
            stage_toml(
                root,
                cfg,
                paths,
                frontend_manifest,
                instrumentation,
                candidate_manifest,
                candidate_mode,
            )
            stage_harness(
                root,
                cfg,
                paths,
                server_bin,
                frontend_manifest,
                instrumentation,
                candidate_manifest,
                candidate_mode,
            )
        build_result = stage_server(root, cfg, paths, server_bin, args.jobs)
        if result_path is not None:
            server_path = paths["server"] / "server"
            build_document = {
                "kind": "build",
                "artifact_id": server_artifact_id or "",
                "server_path": server_path.resolve().relative_to(root.resolve()).as_posix(),
                "server_exists": server_path.is_file(),
                "peak_rss_bytes": build_result["peak_rss_bytes"],
                "resource_terminated": build_result["resource_terminated"],
            }
            if build_result.get("input_identity") is not None:
                build_document["input_identity"] = build_result["input_identity"]
            if build_result.get("verilator_version") is not None:
                build_document["verilator_version"] = build_result["verilator_version"]
            write_json(result_path, build_document)
    if "fuzz" in stages:
        fuzz_seconds = fuzz_seconds_arg
        if fuzz_seconds is None and max_cycles_arg is None:
            fuzz_seconds = 5
        started_ns = time.time_ns()
        execution_result = stage_fuzz(root, cfg, cfg_path, paths, fuzz_seconds)
        if result_path is not None:
            instrumentation_document = json.loads(
                (paths["instrumented"] / "instrumentation.json").read_text()
            )
            points = coverage_universe_from_instrumentation(
                instrumentation_document, cfg["top"]
            )
            document = fuzz_result_document(
                args.job_id,
                server_artifact_id,
                execution_result,
                paths["queue"] / "latest.json",
                points,
                started_ns,
            )
            write_json(result_path, document)

    print(f"myfuzz output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
