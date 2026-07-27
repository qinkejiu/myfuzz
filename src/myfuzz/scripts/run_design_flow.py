#!/usr/bin/env python3
"""Run the myfuzz source-instrumentation-to-rfuzz flow for one design config."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
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
    find_top_module,
    generate_toml,
    validate_frontend_candidate_join,
)
from myfuzz.harness import HarnessArtifact, StaticPolicyParameters, build_harness


STAGES = ["frontend", "composition", "instrument", "toml", "harness", "server", "fuzz"]
HARNESS_MODES = {"flat_direct", "candidate_direct", "candidate_depaware", "candidate_static"}


def coverage_universe_from_instrumentation(
    instrumentation: object,
) -> tuple[dict[str, object], ...]:
    if not isinstance(instrumentation, Mapping):
        raise ValueError("instrumentation must be an object")
    count = instrumentation.get("coverage_point_count")
    records = instrumentation.get("coverage")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("coverage_point_count must be a non-negative integer")
    if not isinstance(records, list):
        raise ValueError("instrumentation coverage must be an array")
    if count != len(records):
        raise ValueError("coverage_point_count does not match coverage records")

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
        if not isinstance(filename, str) or not filename:
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
    if len(points) != len(bitmap):
        raise ValueError("RFuzz bitmap width does not match coverage point count")
    covered: list[int] = []
    for index, (point, value) in enumerate(zip(points, bitmap)):
        if not isinstance(point, Mapping):
            raise ValueError(f"coverage points[{index}] must be an object")
        point_id = point.get("point_id")
        if isinstance(point_id, bool) or not isinstance(point_id, int) or point_id <= 0:
            raise ValueError(f"coverage points[{index}].point_id must be positive")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
            raise ValueError(f"RFuzz bitmap[{index}] must be a byte")
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
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("RFuzz statistics are missing") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("RFuzz statistics must be a regular file")
    if metadata.st_mtime_ns < started_ns:
        raise ValueError("RFuzz statistics are stale")
    if metadata.st_size > 1024 * 1024:
        raise ValueError("RFuzz statistics exceed the size limit")
    try:
        statistics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("RFuzz statistics must be valid JSON") from error
    return rfuzz_measurements(statistics, points)


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
    env = os.environ.get("MYFUZZ_SERVER_VERILATOR_BIN")
    if env:
        return env
    installed = rfuzz_upstream_root(root) / ".tools" / "verilator-5.042-install" / "bin" / "verilator"
    if installed.exists():
        return installed.as_posix()
    return "verilator"


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
    source_path.write_text(artifact.source_text)
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


def rfuzz_harness_api():
    from rfuzz_flow.tools.verilog_instrumentation.generate_rfuzz_harness import (
        generate_harness_files,
        load_toml,
        top_ports_from_frontend_manifest,
        validate_harness,
    )

    return generate_harness_files, load_toml, top_ports_from_frontend_manifest, validate_harness


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


def stage_harness(
    root: Path,
    cfg: dict,
    paths: dict,
    server_bin: str,
    frontend_manifest: dict,
    candidate_manifest: dict,
    candidate_mode: str,
) -> HarnessArtifact:
    manifest = validate_candidate_manifest(candidate_manifest)
    frontend_module = find_top_module(frontend_manifest, cfg["top"])
    validate_frontend_candidate_join(frontend_module, cfg["top"], manifest)
    artifact = build_configured_harness(manifest, cfg, candidate_mode)
    source_path, fragment_path = write_candidate_harness_artifact(paths, artifact)
    generate_harness_files, load_toml, top_ports_from_frontend_manifest, validate_harness = rfuzz_harness_api()
    conf = load_toml(paths["toml"])
    ports = top_ports_from_frontend_manifest(frontend_manifest, cfg["top"])
    harness_cfg = harness_config_for_artifact(cfg, artifact, source_path, fragment_path)
    harness_path, augmented_toml = generate_harness_files(
        conf,
        ports,
        cfg["top"],
        paths["harness"],
        harness_cfg,
    )
    if bool(harness_cfg.get("validate", False)):
        validate_harness(
            server_bin,
            paths["toml"].parent,
            (paths["instrumented"] / "sources.f").resolve(),
            harness_path,
            cfg["top"],
            cfg.get("verilator_args", []),
        )
    else:
        print("Skipped harness lint validation; set harness.validate=true to enable it.")
    print(f"Generated harness: {harness_path}")
    print(f"Generated augmented TOML: {augmented_toml}")
    print(f"Generated raw ABI: {fragment_path}")
    return artifact

def stage_server(
    root: Path, cfg: dict, paths: dict, server_bin: str, jobs: str
) -> dict[str, object]:
    server_cfg = cfg.get("server", {}) if isinstance(cfg.get("server", {}), dict) else {}
    cmd = [
        sys.executable,
        (rfuzz_flow_root(root) / "tools" / "verilog_instrumentation" / "build_rfuzz_server.py").as_posix(),
        "--project-dir",
        paths["instrumented"].as_posix(),
        "--harness-dir",
        paths["harness"].as_posix(),
        "--top",
        cfg["top"],
        "--out-dir",
        paths["server"].as_posix(),
        "--verilator-bin",
        server_bin,
        "--jobs",
        jobs,
        f"--cxx-opt={server_cfg.get('cxx_opt', '-O3')}",
        f"--verilator-opt={server_cfg.get('verilator_opt', '-O3')}",
    ]
    for source in server_cfg.get("extra_verilator_sources", []):
        cmd.append(f"--extra-source={resolve(root, str(source)).as_posix()}")
    for flag in server_cfg.get("extra_cflags", []):
        cmd.append(f"--extra-cflag={str(flag)}")
    for flag in server_cfg.get("extra_ldflags", []):
        cmd.append(f"--extra-ldflag={str(flag)}")
    if bool(server_cfg.get("parallel_verilator_build", False)):
        cmd.append("--parallel-verilator-build")
    for arg in cfg.get("verilator_args", []):
        cmd.append(f"--verilator-arg={arg}")
    result = run_monitored_command(
        cmd,
        cwd=root,
        hard_memory_bytes=cfg.get("hard_memory_bytes"),
    )
    if result["returncode"] != 0 and not result["resource_terminated"]:
        raise subprocess.CalledProcessError(int(result["returncode"]), cmd)
    return result


def build_fuzzer(root: Path) -> Path:
    fuzzer_dir = rfuzz_flow_root(root) / "fuzzer"
    fuzzer = fuzzer_dir / "target" / "release" / "kfuzz"
    if fuzzer.exists():
        return fuzzer
    run(["cargo", "build", "--release"], cwd=fuzzer_dir)
    if not fuzzer.exists():
        raise FileNotFoundError(fuzzer)
    return fuzzer


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
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    return False


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
    count = int(fuzz_cfg.get("server_count", 1))
    if count <= 0:
        raise ValueError("fuzz.server_count must be positive")
    if count > 256:
        raise ValueError("fuzz.server_count must be <= 256")
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


def write_reproduce_script(path: Path, root: Path, cfg_path: Path, replay_input: Path) -> None:
    script = f"""#!/usr/bin/env bash
set -euo pipefail
cd {root}

out_dir="$(python3 - <<'PY'
import json, pathlib
cfg=json.load(open({str(cfg_path)!r}))
print(pathlib.Path(cfg["out_dir"]))
PY
)"
export RFUZZ_FPGA_DIR="${{RFUZZ_FPGA_DIR:-$out_dir/fpga_replay}}"
replay_queue="$(dirname {str(replay_input)!r})/replay_queue"
rm -rf "$RFUZZ_FPGA_DIR"
rm -rf "$replay_queue"
mkdir -p "$RFUZZ_FPGA_DIR"

server="$(python3 - <<'PY'
import json, pathlib
cfg=json.load(open({str(cfg_path)!r}))
out=pathlib.Path(cfg["out_dir"])
print(out / "server" / "server")
PY
)"
top="$(python3 - <<'PY'
import json
cfg=json.load(open({str(cfg_path)!r}))
print(cfg["top"])
PY
)"
toml="$(python3 - <<'PY'
import json, pathlib
cfg=json.load(open({str(cfg_path)!r}))
out=pathlib.Path(cfg["out_dir"])
print(out / "harness" / (cfg["top"] + ".rfuzz.toml"))
PY
)"
fuzzer="third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz"

"$server" 0 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 200); do
  [ -p "$RFUZZ_FPGA_DIR/0/tx.fifo" ] && break
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "server exited before FIFO creation" >&2
    exit 1
  fi
  sleep 0.1
done

"$fuzzer" "$toml" --output-directory "$replay_queue" --replay-input {str(replay_input)!r} --server-id 0
"""
    path.write_text(script)
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
    latest_input: Path,
    latest_batch: Path,
    server_log: Path,
    fuzzer_log: Path,
) -> Path:
    crash_dir = next_crash_dir(paths["out_dir"] / "crashes")
    crash_dir.mkdir(parents=True, exist_ok=True)

    copied_latest = copy_if_exists(latest_input, crash_dir / "latest_input.json")
    copied_batch = copy_if_exists(latest_batch, crash_dir / "latest_batch.json")
    copy_if_exists(server_log, crash_dir / "server.log")
    for extra_server_log in sorted(server_log.parent.glob("server_*.log")):
        copy_if_exists(extra_server_log, crash_dir / extra_server_log.name)
    copy_if_exists(fuzzer_log, crash_dir / "kfuzz.log")
    if paths["queue"].exists():
        shutil.copytree(paths["queue"], crash_dir / "queue_snapshot", dirs_exist_ok=True)

    crash_input = crash_dir / "crash_input.json"
    if copied_latest:
        shutil.copy2(crash_dir / "latest_input.json", crash_input)
    crash_batch = crash_dir / "crash_batch.json"
    if copied_batch:
        shutil.copy2(crash_dir / "latest_batch.json", crash_batch)
    replay_input = crash_batch if crash_batch.exists() else crash_input

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
        "latest_input_saved": copied_latest,
        "latest_batch_saved": copied_batch,
        "crash_input": str(crash_input) if crash_input.exists() else None,
        "crash_batch": str(crash_batch) if crash_batch.exists() else None,
        "queue_snapshot_saved": (crash_dir / "queue_snapshot").exists(),
        "replay_input": str(replay_input) if replay_input.exists() else None,
        "reproduce_script": str(crash_dir / "reproduce.sh") if replay_input.exists() else None,
    }
    write_json(crash_dir / "metadata.json", metadata)
    if replay_input.exists():
        write_reproduce_script(crash_dir / "reproduce.sh", root, cfg_path, replay_input)
    print(f"Archived crash: {crash_dir}", flush=True)
    return crash_dir


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
    fpga_dir = paths["out_dir"] / "fpga"
    queue_dir = paths["queue"]
    latest_dir = paths["out_dir"] / "latest"
    attempt_dir = paths["out_dir"] / "attempts" / f"attempt_{attempt:04d}"
    shutil.rmtree(fpga_dir, ignore_errors=True)
    shutil.rmtree(queue_dir, ignore_errors=True)
    shutil.rmtree(latest_dir, ignore_errors=True)
    attempt_dir.mkdir(parents=True, exist_ok=True)
    fpga_dir.mkdir(parents=True, exist_ok=True)
    latest_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["RFUZZ_FPGA_DIR"] = fpga_dir.as_posix()
    latest_input = latest_dir / "latest_input.json"
    latest_batch = latest_dir / "latest_batch.json"
    env["RFUZZ_LATEST_INPUT"] = latest_input.as_posix()
    env["RFUZZ_LATEST_BATCH"] = latest_batch.as_posix()
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg.get("fuzz", {}), dict) else {}
    for cfg_key, env_key in (
        ("seed", "RFUZZ_SEED"),
        ("max_cycles", "RFUZZ_MAX_CYCLES"),
        ("max_runs", "RFUZZ_MAX_RUNS"),
        ("save_latest_every_runs", "RFUZZ_SAVE_LATEST_EVERY_RUNS"),
        ("test_buffer_size", "RFUZZ_TEST_BUFFER_SIZE"),
        ("coverage_buffer_size", "RFUZZ_COVERAGE_BUFFER_SIZE"),
        ("buffer_count", "RFUZZ_BUFFER_COUNT"),
    ):
        if cfg_key in fuzz_cfg:
            env[env_key] = str(fuzz_cfg[cfg_key])

    server = paths["server"] / "server"
    toml = paths["harness"] / f"{cfg['top']}.rfuzz.toml"
    server_count = fuzz_server_count(cfg)
    server_ids = [str(index) for index in range(server_count)]
    server_id_arg = ",".join(server_ids)
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
    try:
        ready: set[str] = set()
        deadline = time.time() + 20
        while time.time() < deadline and len(ready) < server_count:
            if monitor.observe():
                return "resource", None, terminate_processes(server_procs), None, False, monitor.peak_rss_bytes, True
            for server_id, proc in zip(server_ids, server_procs):
                if proc.poll() is not None:
                    archive = archive_crash(
                        root, cfg, cfg_path, paths, attempt, f"server_{server_id}_exited_before_fifo",
                        None, proc.returncode, latest_input, latest_batch, server_log, fuzzer_log,
                    )
                    return "crash", None, proc.returncode, archive, False, monitor.peak_rss_bytes, False
                if rfuzz_fifos_ready(fpga_dir, (server_id,)):
                    ready.add(server_id)
            time.sleep(0.1)
        if len(ready) < server_count:
            server_rc = terminate_processes(server_procs)
            archive = archive_crash(
                root, cfg, cfg_path, paths, attempt, "fifo_timeout",
                None, server_rc, latest_input, latest_batch, server_log, fuzzer_log,
            )
            return "crash", None, server_rc, archive, False, monitor.peak_rss_bytes, False

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
        if resume_queue is not None and queue_has_entries(resume_queue):
            cmd.extend(["--input-directory", resume_queue.as_posix()])
        budget_label = (
            f"wall-seconds={seconds}"
            if seconds is not None
            else f"cycles={fuzz_cfg['max_cycles']}"
        )
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
                        fuzzer_rc, server_rc, latest_input, latest_batch, server_log, fuzzer_log,
                    )
                    return "crash", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
                if attempt_deadline is not None and time.time() >= attempt_deadline:
                    fuzzer_rc = terminate_process(fuzzer_proc)
                    server_rc = terminate_processes(server_procs)
                    monitor.observe()
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
            fuzzer_rc, server_rc, latest_input, latest_batch, server_log, fuzzer_log,
        )
        monitor.observe()
        return "crash", fuzzer_rc, server_rc, archive, True, monitor.peak_rss_bytes, False
    finally:
        terminate_processes(server_procs)


def stage_fuzz(
    root: Path,
    cfg: dict,
    cfg_path: Path,
    paths: dict,
    seconds: int | None,
) -> dict[str, object]:
    fuzzer = build_fuzzer(root)
    fuzz_cfg = cfg.get("fuzz", {}) if isinstance(cfg.get("fuzz", {}), dict) else {}
    if seconds is None and "max_cycles" not in fuzz_cfg:
        raise ValueError("fuzz requires a wall-time or cycle budget")
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
        shutil.rmtree(paths["out_dir"] / "fpga", ignore_errors=True)
        cleanup = not (paths["out_dir"] / "fpga").exists()
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
    if fuzz_seconds_arg is not None and fuzz_seconds_arg <= 0:
        raise ValueError("--fuzz-seconds must be positive")
    if hard_memory_arg is not None and hard_memory_arg <= 0:
        raise ValueError("--hard-memory-bytes must be positive")
    if seed_arg is not None or max_cycles_arg is not None or hard_memory_arg is not None:
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
    server_artifact_id = getattr(args, "server_artifact_id", None)
    paths = artifact_flow_paths(paths, server_artifact_id)
    frontend_library = resolve(root, args.frontend_library) if args.frontend_library else default_frontend_library(root)
    server_bin = args.server_verilator_bin or default_server_verilator(root)
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
        if candidate_manifest is None:
            raise ValueError("validated candidate manifest path is required for harness generation")
        stage_harness(root, cfg, paths, server_bin, frontend_manifest, candidate_manifest, candidate_mode)
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
                candidate_manifest,
                candidate_mode,
            )
        build_result = stage_server(root, cfg, paths, server_bin, args.jobs)
        if result_path is not None:
            server_path = paths["server"] / "server"
            write_json(result_path, {
                "kind": "build",
                "artifact_id": server_artifact_id or "",
                "server_path": server_path.resolve().relative_to(root.resolve()).as_posix(),
                "server_exists": server_path.is_file(),
                "peak_rss_bytes": build_result["peak_rss_bytes"],
                "resource_terminated": build_result["resource_terminated"],
            })
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
            points = coverage_universe_from_instrumentation(instrumentation_document)
            latest = paths["queue"] / "latest.json"
            measurements = load_rfuzz_measurements(latest, points, started_ns)
            if not isinstance(args.job_id, str) or not args.job_id:
                raise ValueError("--job-id is required for a fuzz result document")
            if not isinstance(server_artifact_id, str):
                raise ValueError("--server-artifact-id is required for a fuzz result document")
            document = {
                "kind": "fuzz",
                "job_id": args.job_id,
                "artifact_id": server_artifact_id,
                **measurements,
                **execution_result,
            }
            write_json(result_path, document)

    print(f"myfuzz output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
