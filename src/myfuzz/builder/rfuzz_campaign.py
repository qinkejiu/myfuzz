"""Bridge completed RawBits targets to the upstream RFUZZ shared-memory protocol."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from typing import Mapping

from .input_model import InputValidationError


RFUZZ_INPUT_MAGIC = 0x19931993
RFUZZ_COVERAGE_MAGIC = 0x73537353
_RFUZZ_MODES = {
    "myfuzz.rawbits-layout/v2": {"raw": 0, "constrained": 1},
    "myfuzz.rawbits-layout/v3": {
        "generated_raw": 0, "protocol_safe": 1, "scenario_constrained": 2,
    },
}


@dataclass(frozen=True)
class RFuzzGeometry:
    raw_bytes_per_cycle: int
    aligned_input_bytes: int
    coverage_points: int
    coverage_payload_bytes: int
    coverage_item_bytes: int

    def __post_init__(self) -> None:
        if self.raw_bytes_per_cycle <= 0 or self.coverage_points <= 0:
            raise InputValidationError("RFUZZ geometry requires non-empty input and coverage")
        if self.aligned_input_bytes < self.raw_bytes_per_cycle or self.aligned_input_bytes % 8:
            raise InputValidationError("RFUZZ input size must be 64-bit aligned")
        if self.coverage_item_bytes != self.coverage_payload_bytes + 2:
            raise InputValidationError("RFUZZ coverage item must include the 16-bit cycle count")
        if self.coverage_item_bytes % 8:
            raise InputValidationError("RFUZZ coverage item must be 64-bit aligned")


@dataclass(frozen=True)
class RFuzzInputTest:
    cycles: int
    rawbits: bytes
    ignored_padding_nonzero_bytes: int


@dataclass(frozen=True)
class RFuzzConformanceRun:
    output_dir: str
    report: Mapping[str, object]


@dataclass(frozen=True)
class RFuzzCampaignRun:
    output_dir: str
    report: Mapping[str, object]


def rfuzz_geometry(cycle_width: int, coverage_points: int) -> RFuzzGeometry:
    if isinstance(cycle_width, bool) or not isinstance(cycle_width, int) or cycle_width <= 0:
        raise InputValidationError("RFUZZ cycle width must be a positive integer")
    if isinstance(coverage_points, bool) or not isinstance(coverage_points, int) or coverage_points <= 0:
        raise InputValidationError("RFUZZ coverage point count must be a positive integer")
    raw_bytes = (cycle_width + 7) // 8
    aligned_input = _align(raw_bytes, 8)
    coverage_item = _align(coverage_points + 2, 8)
    return RFuzzGeometry(raw_bytes, aligned_input, coverage_points, coverage_item - 2,
                         coverage_item)


def emit_rfuzz_toml(target_dir: str | Path, output_path: str | Path) -> Mapping[str, object]:
    """Emit the exact byte-counter configuration consumed by upstream kfuzz."""
    target, completion, layout, abi = _load_target_contract(target_dir)
    geometry = rfuzz_geometry(int(layout["cycle_width"]), int(abi["width"]))
    elaboration = _read_json(target / "evidence/elaboration_manifest.json")
    top_module = elaboration.get("top_module")
    if not isinstance(top_module, str) or not top_module:
        raise InputValidationError("RFUZZ target elaboration manifest has no top module")
    points = sorted(
        (point for point in abi["points"] if point.get("included")),
        key=lambda point: int(point["offset"]),
    )
    if [int(point["offset"]) for point in points] != list(range(geometry.coverage_points)):
        raise InputValidationError("RFUZZ requires a dense included Coverage ABI")
    lines = [
        "[general]",
        f"filename = {_toml_string('evidence/coverage_abi.json')}",
        f"instrumented = {_toml_string(completion['target_digest'])}",
        f"top = {_toml_string(top_module)}",
        "timestamp = 1970-01-01T00:00:00Z",
        "",
        "[[input]]",
        "name = \"raw_bits_lsb0\"",
        f"width = {int(layout['cycle_width'])}",
    ]
    for point in points:
        offset = int(point["offset"])
        point_id = str(point["point_id"])
        component = str(point.get("component_id", "unknown"))
        source_line = int(point.get("source_line", 0))
        human = ".".join(filter(None, (
            component, str(point.get("module", "")), str(point.get("kind", "")),
            str(point.get("subtype", "")),
        )))
        lines.extend((
            "", "[[coverage]]", f"port = {_toml_string(str(abi['port_name']))}",
            f"name = {_toml_string(point_id)}", f"index = {offset}",
            f"filename = {_toml_string(component)}", f"line = {source_line}",
            "column = 0", f"human = {_toml_string(human)}",
            "", "[[counter]]", f"name = {_toml_string(point_id)}", "width = 8",
            "max = 1", "scale = false", f"index = {offset}", f"signal = {offset}",
            "fail = false",
        ))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "schema": "myfuzz.rfuzz-config/v1",
        "target_dir": target.as_posix(),
        "target_digest": completion["target_digest"],
        "layout_digest": layout["digest"],
        "coverage_abi_digest": completion["coverage_abi_digest"],
        "geometry": asdict(geometry),
        "toml": output.resolve().as_posix(),
        "toml_sha256": _sha256(output.read_bytes()),
    }


def parse_rfuzz_input_buffer(payload: bytes, geometry: RFuzzGeometry) -> tuple[int, tuple[RFuzzInputTest, ...]]:
    if len(payload) < 16:
        raise InputValidationError("RFUZZ input buffer is shorter than its header")
    magic, buffer_id, test_count, reserved0, reserved1, reserved2 = struct.unpack_from(
        ">IIHHHH", payload, 0,
    )
    if magic != RFUZZ_INPUT_MAGIC:
        raise InputValidationError("RFUZZ input buffer magic mismatch")
    if (reserved0, reserved1, reserved2) != (0, 0, 0):
        raise InputValidationError("RFUZZ input buffer reserved fields must be zero")
    offset = 16
    tests = []
    for _ in range(test_count):
        if offset + 8 > len(payload):
            raise InputValidationError("RFUZZ input buffer ends before a test header")
        cycles = struct.unpack_from(">Q", payload, offset)[0]
        offset += 8
        if cycles <= 0 or cycles > 0xFFFF:
            raise InputValidationError("RFUZZ testcase cycle count is outside 1..65535")
        padded_size = cycles * geometry.aligned_input_bytes
        if offset + padded_size > len(payload):
            raise InputValidationError("RFUZZ input buffer ends inside a testcase")
        padded = payload[offset:offset + padded_size]
        offset += padded_size
        raw = bytearray()
        ignored_nonzero = 0
        for cycle in range(cycles):
            base = cycle * geometry.aligned_input_bytes
            raw.extend(padded[base:base + geometry.raw_bytes_per_cycle])
            ignored_nonzero += sum(
                byte != 0 for byte in padded[
                    base + geometry.raw_bytes_per_cycle:base + geometry.aligned_input_bytes
                ]
            )
        tests.append(RFuzzInputTest(cycles, bytes(raw), ignored_nonzero))
    return buffer_id, tuple(tests)


def encode_rfuzz_coverage_buffer(
    buffer_id: int, results: tuple[tuple[int, bytes], ...], geometry: RFuzzGeometry,
) -> bytes:
    output = bytearray(struct.pack(">II", RFUZZ_COVERAGE_MAGIC, buffer_id))
    for cycles, bitset in results:
        if cycles <= 0 or cycles > 0xFFFF:
            raise InputValidationError("RFUZZ coverage cycle count is outside 1..65535")
        expected = (geometry.coverage_points + 7) // 8
        if len(bitset) != expected:
            raise InputValidationError("target coverage bitset size does not match RFUZZ geometry")
        counters = bytearray(geometry.coverage_payload_bytes)
        for point in range(geometry.coverage_points):
            counters[point] = 1 if bitset[point // 8] & (1 << (point % 8)) else 0
        output.extend(struct.pack(">H", cycles))
        output.extend(counters)
    return bytes(output)


def run_rfuzz_conformance_smoke(
    target_dir: str | Path,
    output_dir: str | Path,
    *,
    kfuzz_bin: str | Path,
    mode: str,
    campaign_seed: int = 1,
    seed_cycles: int = 2,
    timeout_seconds: float = 20.0,
) -> RFuzzConformanceRun:
    """Prove one real upstream kfuzz/shared-memory/target round trip."""
    _validate_known_mode(mode, "conformance")
    if isinstance(campaign_seed, bool) or not isinstance(campaign_seed, int) or campaign_seed < 0:
        raise InputValidationError("RFUZZ campaign seed must be a non-negative integer")
    if isinstance(seed_cycles, bool) or not isinstance(seed_cycles, int) or seed_cycles <= 0:
        raise InputValidationError("RFUZZ seed cycle count must be positive")
    if timeout_seconds <= 0:
        raise InputValidationError("RFUZZ conformance timeout must be positive")

    target, completion, layout, _ = _load_target_contract(target_dir)
    _mode_value(mode, str(layout["schema"]))
    kfuzz = Path(kfuzz_bin).resolve(strict=True)
    if not kfuzz.is_file() or not os.access(kfuzz, os.X_OK):
        raise InputValidationError(f"RFUZZ kfuzz binary is not executable: {kfuzz}")
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"RFUZZ conformance output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    config_path = output / "rfuzz.toml"
    config_report = emit_rfuzz_toml(target, config_path)
    event_log = output / "events.jsonl"
    server_id = f"myfuzz-{os.getpid()}-{completion['target_digest'][:12]}-{mode}"
    fifo_dir = Path("/tmp/fpga") / server_id
    kfuzz_output = output / "kfuzz-output"
    server_stdout = output / "server.stdout.log"
    server_stderr = output / "server.stderr.log"
    kfuzz_stdout = output / "kfuzz.stdout.log"
    kfuzz_stderr = output / "kfuzz.stderr.log"
    source_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
        source_root.as_posix(), environment.get("PYTHONPATH", ""),
    )))
    server_command = [
        sys.executable, "-m", "myfuzz.builder.rfuzz_campaign", "serve", target.as_posix(),
        "--mode", mode, "--server-id", server_id, "--log", event_log.as_posix(),
        "--testcase-timeout", str(timeout_seconds),
    ]
    kfuzz_command = [
        kfuzz.as_posix(), config_path.as_posix(), "--output-directory", kfuzz_output.as_posix(),
        "--server-id", server_id, "--campaign-seed", str(campaign_seed),
        "--seed-cycles", str(seed_cycles), "--skip-deterministic", "--skip-non-deterministic",
    ]
    started = time.monotonic()
    server = None
    fuzzer = None
    try:
        with server_stdout.open("wb") as server_out, server_stderr.open("wb") as server_err:
            server = subprocess.Popen(
                server_command, cwd=target, env=environment, stdout=server_out, stderr=server_err,
            )
            _wait_for_server(fifo_dir, server, timeout_seconds)
            with kfuzz_stdout.open("wb") as kfuzz_out, kfuzz_stderr.open("wb") as kfuzz_err:
                fuzzer = subprocess.Popen(
                    kfuzz_command, cwd=output, stdout=kfuzz_out, stderr=kfuzz_err,
                )
                _wait_for_event(event_log, server, fuzzer, timeout_seconds)
                fuzzer.send_signal(signal.SIGINT)
                try:
                    fuzzer.wait(timeout=min(5.0, timeout_seconds))
                except subprocess.TimeoutExpired as exc:
                    raise InputValidationError("upstream kfuzz did not stop after SIGINT") from exc
            try:
                server.wait(timeout=min(5.0, timeout_seconds))
            except subprocess.TimeoutExpired as exc:
                raise InputValidationError("RFUZZ target server did not stop after kfuzz exit") from exc
        if fuzzer.returncode != 0:
            raise InputValidationError(f"upstream kfuzz exited with status {fuzzer.returncode}")
        if server.returncode != 0:
            raise InputValidationError(f"RFUZZ target server exited with status {server.returncode}")
        events = _read_events(event_log)
        report = {
            "schema": "myfuzz.rfuzz-conformance-run/v1",
            "target_digest": completion["target_digest"],
            "coverage_abi_digest": completion["coverage_abi_digest"],
            "mode": mode,
            "campaign_seed": campaign_seed,
            "seed_cycles": seed_cycles,
            "event_count": len(events),
            "first_event": events[0],
            "elapsed_seconds": time.monotonic() - started,
            "config": dict(config_report),
            "commands": {"server": server_command, "kfuzz": kfuzz_command},
        }
        _write_json(output / "conformance_report.json", report)
        return RFuzzConformanceRun(output.as_posix(), report)
    finally:
        fuzzer_pid = fuzzer.pid if fuzzer is not None else None
        for process in (fuzzer, server):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if fuzzer_pid is not None:
            _remove_shm_created_by(fuzzer_pid)
        if fifo_dir.exists():
            shutil.rmtree(fifo_dir, ignore_errors=True)


def run_rfuzz_timed_campaign(
    target_dir: str | Path,
    output_dir: str | Path,
    *,
    kfuzz_bin: str | Path,
    mode: str,
    wall_seconds: float,
    campaign_seed: int = 1,
    seed_cycles: int = 4,
    checkpoints: tuple[float, ...] = (1, 2, 5, 10, 30, 60),
    startup_timeout_seconds: float = 20.0,
    shutdown_timeout_seconds: float = 10.0,
) -> RFuzzCampaignRun:
    """Run one bounded mutation campaign and clean up all process-owned IPC resources."""
    _validate_known_mode(mode, "campaign")
    if isinstance(campaign_seed, bool) or not isinstance(campaign_seed, int) or campaign_seed < 0:
        raise InputValidationError("RFUZZ campaign seed must be a non-negative integer")
    if isinstance(seed_cycles, bool) or not isinstance(seed_cycles, int) or seed_cycles <= 0:
        raise InputValidationError("RFUZZ seed cycle count must be positive")
    if wall_seconds <= 0 or startup_timeout_seconds <= 0 or shutdown_timeout_seconds <= 0:
        raise InputValidationError("RFUZZ campaign timeouts must be positive")
    if any(value <= 0 for value in checkpoints) or tuple(sorted(set(checkpoints))) != checkpoints:
        raise InputValidationError("RFUZZ checkpoints must be unique, positive, and increasing")

    target, completion, layout, _ = _load_target_contract(target_dir)
    _mode_value(mode, str(layout["schema"]))
    kfuzz = Path(kfuzz_bin).resolve(strict=True)
    if not kfuzz.is_file() or not os.access(kfuzz, os.X_OK):
        raise InputValidationError(f"RFUZZ kfuzz binary is not executable: {kfuzz}")
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"RFUZZ campaign output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    config_path = output / "rfuzz.toml"
    config_report = emit_rfuzz_toml(target, config_path)
    event_log = output / "events.jsonl"
    stop_file = output / "stop.requested"
    server_id = (
        f"myfuzz-{os.getpid()}-{time.time_ns()}-{completion['target_digest'][:8]}-{mode}"
    )
    fifo_dir = Path("/tmp/fpga") / server_id
    kfuzz_output = output / "kfuzz-output"
    server_stdout = output / "server.stdout.log"
    server_stderr = output / "server.stderr.log"
    kfuzz_stdout = output / "kfuzz.stdout.log"
    kfuzz_stderr = output / "kfuzz.stderr.log"
    source_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
        source_root.as_posix(), environment.get("PYTHONPATH", ""),
    )))
    server_command = [
        sys.executable, "-m", "myfuzz.builder.rfuzz_campaign", "serve", target.as_posix(),
        "--mode", mode, "--server-id", server_id, "--log", event_log.as_posix(),
        "--stop-file", stop_file.as_posix(),
        "--testcase-timeout", str(shutdown_timeout_seconds),
    ]
    kfuzz_command = [
        kfuzz.as_posix(), config_path.as_posix(), "--output-directory", kfuzz_output.as_posix(),
        "--server-id", server_id, "--campaign-seed", str(campaign_seed),
        "--seed-cycles", str(seed_cycles),
    ]
    server = None
    fuzzer = None
    fuzzer_pid = None
    samples: list[dict[str, object]] = []
    shutdown_started = None
    forced_server_kill = False
    try:
        with server_stdout.open("wb") as server_out, server_stderr.open("wb") as server_err:
            server = subprocess.Popen(
                server_command, cwd=target, env=environment, stdout=server_out, stderr=server_err,
            )
            _wait_for_server(fifo_dir, server, startup_timeout_seconds)
            with kfuzz_stdout.open("wb") as kfuzz_out, kfuzz_stderr.open("wb") as kfuzz_err:
                fuzzer = subprocess.Popen(
                    kfuzz_command, cwd=output, stdout=kfuzz_out, stderr=kfuzz_err,
                )
                fuzzer_pid = fuzzer.pid
                campaign_started = time.monotonic()
                sample_times = tuple(value for value in checkpoints if value < wall_seconds)
                for checkpoint in sample_times:
                    _wait_for_campaign_time(
                        campaign_started + checkpoint, server, fuzzer,
                    )
                    samples.append(_campaign_sample(checkpoint, event_log))

                _wait_for_campaign_time(campaign_started + wall_seconds, server, fuzzer)
                endpoint_bytes = event_log.stat().st_size if event_log.is_file() else 0
                shutdown_started = time.monotonic()
                stop_file.touch()
                fuzzer.terminate()
                samples.append(_campaign_sample(wall_seconds, event_log, endpoint_bytes))
                try:
                    fuzzer.wait(timeout=shutdown_timeout_seconds)
                except subprocess.TimeoutExpired:
                    fuzzer.kill()
                    fuzzer.wait()
                try:
                    server.wait(timeout=shutdown_timeout_seconds)
                except subprocess.TimeoutExpired:
                    forced_server_kill = True
                    server.kill()
                    server.wait()

        if fuzzer.returncode not in {-signal.SIGTERM, -signal.SIGKILL}:
            raise InputValidationError(f"upstream kfuzz exited unexpectedly with status {fuzzer.returncode}")
        if server.returncode != 0:
            raise InputValidationError(f"RFUZZ target server exited with status {server.returncode}")
        if forced_server_kill:
            raise InputValidationError("RFUZZ target server did not honor the campaign stop request")
        events = _read_events(event_log)
        endpoint = samples[-1]
        report = {
            "schema": "myfuzz.rfuzz-campaign-run/v1",
            "target_digest": completion["target_digest"],
            "coverage_abi_digest": completion["coverage_abi_digest"],
            "mode": mode,
            "campaign_seed": campaign_seed,
            "seed_cycles": seed_cycles,
            "wall_seconds": wall_seconds,
            "event_count": endpoint["event_count"],
            "coverage_points_hit": endpoint["coverage_points_hit"],
            "coverage_points_total": endpoint["coverage_points_total"],
            "checkpoints": samples,
            "recorded_event_count": len(events),
            "shutdown_seconds": time.monotonic() - shutdown_started,
            "forced_server_kill": forced_server_kill,
            "fuzzer_returncode": fuzzer.returncode,
            "server_returncode": server.returncode,
            "config": dict(config_report),
            "commands": {"server": server_command, "kfuzz": kfuzz_command},
        }
        _write_json(output / "campaign_report.json", report)
        return RFuzzCampaignRun(output.as_posix(), report)
    finally:
        stop_file.touch(exist_ok=True)
        for process in (fuzzer, server):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if fuzzer_pid is not None:
            _remove_shm_created_by(fuzzer_pid)
        if fifo_dir.exists():
            shutil.rmtree(fifo_dir, ignore_errors=True)


class RFuzzTargetServer:
    """Serve upstream kfuzz buffers by running one isolated target process per testcase."""

    def __init__(
        self, target_dir: str | Path, *, mode: str, server_id: str,
        log_path: str | Path, testcase_timeout_seconds: float = 30.0,
        stop_path: str | Path | None = None,
    ) -> None:
        _validate_known_mode(mode, "target")
        if not server_id or "/" in server_id or server_id in {".", ".."}:
            raise InputValidationError("RFUZZ server id must be one path component")
        self.target, self.completion, self.layout, self.abi = _load_target_contract(target_dir)
        self.geometry = rfuzz_geometry(int(self.layout["cycle_width"]), int(self.abi["width"]))
        self.mode_value = _mode_value(mode, str(self.layout["schema"]))
        self.mode = mode
        self.server_id = server_id
        self.log_path = Path(log_path).resolve()
        self.stop_path = Path(stop_path).resolve() if stop_path is not None else None
        self.testcase_timeout_seconds = testcase_timeout_seconds
        self._union = bytearray((self.geometry.coverage_points + 7) // 8)
        self._test_index = 0
        self._started = time.monotonic()
        self._shared_memory_ids: set[int] = set()

    def serve(self) -> None:
        fifo_dir = Path("/tmp/fpga") / self.server_id
        fifo_dir.mkdir(parents=True, exist_ok=False)
        tx_path, rx_path = fifo_dir / "tx.fifo", fifo_dir / "rx.fifo"
        os.mkfifo(tx_path)
        os.mkfifo(rx_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f"myfuzz-rfuzz-{self.server_id}-"))
        try:
            with tx_path.open("wb", buffering=0) as tx, rx_path.open("rb", buffering=0) as rx:
                while True:
                    ids = _read_exact_or_eof(rx, 8)
                    if ids is None:
                        break
                    input_id, coverage_id = struct.unpack("<II", ids)
                    self._shared_memory_ids.update((input_id, coverage_id))
                    if self._stop_requested():
                        break
                    input_ptr = _attach_shm(input_id)
                    coverage_ptr = _attach_shm(coverage_id)
                    stop_requested = False
                    try:
                        input_size = _shm_size(input_id)
                        payload = ctypes.string_at(input_ptr, input_size)
                        buffer_id, tests = parse_rfuzz_input_buffer(payload, self.geometry)
                        results = []
                        for test in tests:
                            if self._stop_requested():
                                stop_requested = True
                                break
                            results.append(self._run_test(test, work))
                        if self._stop_requested():
                            stop_requested = True
                        if not stop_requested:
                            encoded = encode_rfuzz_coverage_buffer(
                                buffer_id, tuple(results), self.geometry,
                            )
                            if len(encoded) > _shm_size(coverage_id):
                                raise InputValidationError("RFUZZ coverage shared memory is too small")
                            ctypes.memmove(coverage_ptr, encoded, len(encoded))
                    finally:
                        _detach_shm(input_ptr)
                        _detach_shm(coverage_ptr)
                    if stop_requested:
                        break
                    try:
                        tx.write(struct.pack("<II", coverage_id, input_id))
                    except BrokenPipeError:
                        break
        finally:
            shutil.rmtree(work, ignore_errors=True)
            for shm_id in self._shared_memory_ids:
                _remove_shm(shm_id)
            for path in (tx_path, rx_path):
                path.unlink(missing_ok=True)
            fifo_dir.rmdir()

    def _stop_requested(self) -> bool:
        return self.stop_path is not None and self.stop_path.exists()

    def _run_test(self, test: RFuzzInputTest, work: Path) -> tuple[int, bytes]:
        rawbits = work / "testcase.rawbits"
        coverage = work / "coverage.bin"
        metrics_path = work / "metrics.json"
        rawbits.write_bytes(test.rawbits)
        started = time.monotonic()
        command = [
            (self.target / "bin/myfuzz_target").as_posix(), rawbits.as_posix(),
            str(test.cycles), str(self.mode_value), coverage.as_posix(),
        ]
        if self.layout["schema"] == "myfuzz.rawbits-layout/v3":
            command.extend(("-", metrics_path.as_posix()))
        try:
            completed = subprocess.run(
                command, cwd=self.target, capture_output=True, text=True,
                timeout=self.testcase_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise InputValidationError(
                f"RFUZZ target testcase timed out after {self.testcase_timeout_seconds}s"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise InputValidationError(
                f"RFUZZ target testcase failed with exit code {completed.returncode}: {detail}"
            )
        bitset = coverage.read_bytes()
        expected = (self.geometry.coverage_points + 7) // 8
        if len(bitset) != expected:
            raise InputValidationError("RFUZZ target returned an invalid coverage bitset")
        metrics = None
        if self.layout["schema"] == "myfuzz.rawbits-layout/v3":
            metrics = _read_json(metrics_path)
            _validate_generated_metrics(metrics, test.cycles)
        previous = sum(byte.bit_count() for byte in self._union)
        for index, byte in enumerate(bitset):
            self._union[index] |= byte
        cumulative = sum(byte.bit_count() for byte in self._union)
        event = {
            "schema": "myfuzz.rfuzz-campaign-event/v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": time.monotonic() - self._started,
            "test_index": self._test_index,
            "cycles": test.cycles,
            "mode": self.mode,
            "testcase_sha256": _sha256(test.rawbits),
            "runtime_seconds": time.monotonic() - started,
            "hit_count": sum(byte.bit_count() for byte in bitset),
            "new_point_count": cumulative - previous,
            "cumulative_hit_count": cumulative,
            "coverage_point_count": self.geometry.coverage_points,
            "ignored_alignment_padding_nonzero_bytes": test.ignored_padding_nonzero_bytes,
        }
        if metrics is not None:
            accepted = int(metrics["accepted_records"])
            tail = test.rawbits[accepted * self.geometry.raw_bytes_per_cycle:]
            event.update({
                "accepted_records": accepted,
                "acceptance_cycles": metrics["acceptance_cycles"],
                "stall_cycles": metrics["stall_cycles"],
                "executed_operations": metrics["executed_operations"],
                "operation_cycles": metrics["operation_cycles"],
                "unconsumed_records": metrics["unconsumed_records"],
                "unconsumed_tail_sha256": _sha256(tail),
                "teardown_cycles": metrics["teardown_cycles"],
            })
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(event, sort_keys=True, ensure_ascii=True) + "\n")
            log.flush()
        self._test_index += 1
        return test.cycles, bitset


def _load_target_contract(target_dir: str | Path) -> tuple[Path, dict[str, object], dict[str, object], dict[str, object]]:
    target = Path(target_dir).resolve(strict=True)
    completion = _read_json(target / "completion_manifest.json")
    if completion.get("schema") != "myfuzz.target-completion/v1":
        raise InputValidationError("RFUZZ target completion manifest schema mismatch")
    executable = target / "bin/myfuzz_target"
    if not executable.is_file() or _sha256(executable.read_bytes()) != completion.get("executable_sha256"):
        raise InputValidationError("RFUZZ target executable digest mismatch")
    layout = _read_json(target / "evidence/bit_layout.json")
    abi = _read_json(target / "evidence/coverage_abi.json")
    if layout.get("schema") not in _RFUZZ_MODES:
        raise InputValidationError("RFUZZ target requires RawBits layout v2 or v3")
    if abi.get("schema") != "myfuzz.coverage-abi/v2":
        raise InputValidationError("RFUZZ target requires Coverage ABI v2")
    if completion.get("coverage_width") != abi.get("width"):
        raise InputValidationError("RFUZZ target coverage width mismatch")
    return target, completion, layout, abi


def _validate_known_mode(mode: str, context: str) -> None:
    known = {item for modes in _RFUZZ_MODES.values() for item in modes}
    if mode not in known:
        raise InputValidationError(
            f"RFUZZ {context} mode must be one of: {', '.join(sorted(known))}"
        )


def _mode_value(mode: str, layout_schema: str) -> int:
    modes = _RFUZZ_MODES.get(layout_schema)
    if modes is None or mode not in modes:
        expected = "" if modes is None else ", ".join(sorted(modes))
        raise InputValidationError(
            f"RFUZZ mode {mode!r} is incompatible with {layout_schema}; expected: {expected}"
        )
    return modes[mode]


def _validate_generated_metrics(value: Mapping[str, object], cycles: int) -> None:
    if value.get("schema") != "myfuzz.generated-target-metrics/v1":
        raise InputValidationError("generated target metrics schema mismatch")
    integer_fields = (
        "measured_cycles", "accepted_records", "stall_cycles", "unconsumed_records",
        "executed_operations", "teardown_cycles",
    )
    if any(isinstance(value.get(name), bool) or not isinstance(value.get(name), int)
           or int(value[name]) < 0 for name in integer_fields):
        raise InputValidationError("generated target metrics contain an invalid counter")
    if int(value["measured_cycles"]) != cycles:
        raise InputValidationError("generated target metrics measured-cycle mismatch")
    if int(value["accepted_records"]) + int(value["unconsumed_records"]) != cycles:
        raise InputValidationError("generated target metrics record accounting mismatch")
    for field in ("acceptance_cycles", "operation_cycles"):
        items = value.get(field)
        if not isinstance(items, list) or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0 or item >= cycles
            for item in items
        ):
            raise InputValidationError(f"generated target metrics {field} are invalid")
        if items != sorted(set(items)):
            raise InputValidationError(f"generated target metrics {field} are not ordered and unique")
    if len(value["acceptance_cycles"]) != int(value["accepted_records"]):
        raise InputValidationError("generated target metrics acceptance count mismatch")
    if len(value["operation_cycles"]) != int(value["executed_operations"]):
        raise InputValidationError("generated target metrics operation count mismatch")


def _shm_size(shm_id: int) -> int:
    path = Path("/proc/sysvipc/shm")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise InputValidationError("cannot inspect SysV shared memory sizes") from exc
    if not lines:
        raise InputValidationError("SysV shared memory table is empty")
    columns = lines[0].split()
    try:
        id_index, size_index = columns.index("shmid"), columns.index("size")
    except ValueError as exc:
        raise InputValidationError("unknown SysV shared memory table format") from exc
    for line in lines[1:]:
        values = line.split()
        if int(values[id_index]) == shm_id:
            return int(values[size_index])
    raise InputValidationError(f"SysV shared memory id is missing: {shm_id}")


def _attach_shm(shm_id: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
    libc.shmat.restype = ctypes.c_void_p
    pointer = libc.shmat(shm_id, None, 0)
    if pointer == ctypes.c_void_p(-1).value:
        raise InputValidationError(f"cannot attach SysV shared memory {shm_id}: errno {ctypes.get_errno()}")
    return int(pointer)


def _detach_shm(pointer: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.shmdt.argtypes = (ctypes.c_void_p,)
    libc.shmdt.restype = ctypes.c_int
    if libc.shmdt(ctypes.c_void_p(pointer)) != 0:
        raise InputValidationError(f"cannot detach SysV shared memory: errno {ctypes.get_errno()}")


def _remove_shm(shm_id: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.shmctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    libc.shmctl.restype = ctypes.c_int
    if libc.shmctl(shm_id, 0, None) != 0 and ctypes.get_errno() not in {22, 43}:
        raise InputValidationError(
            f"cannot remove SysV shared memory {shm_id}: errno {ctypes.get_errno()}"
        )


def _remove_shm_created_by(creator_pid: int) -> None:
    path = Path("/proc/sysvipc/shm")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise InputValidationError("cannot inspect SysV shared memory owners") from exc
    if not lines:
        return
    columns = lines[0].split()
    try:
        id_index, creator_index = columns.index("shmid"), columns.index("cpid")
    except ValueError as exc:
        raise InputValidationError("unknown SysV shared memory table format") from exc
    for line in lines[1:]:
        values = line.split()
        if int(values[creator_index]) == creator_pid:
            _remove_shm(int(values[id_index]))


def _read_exact_or_eof(stream: object, size: int) -> bytes | None:
    output = bytearray()
    while len(output) < size:
        chunk = stream.read(size - len(output))
        if not chunk:
            if not output:
                return None
            raise InputValidationError("RFUZZ FIFO closed inside a token")
        output.extend(chunk)
    return bytes(output)


def _wait_for_server(fifo_dir: Path, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise InputValidationError(f"RFUZZ target server exited with status {process.returncode}")
        if (fifo_dir / "tx.fifo").exists() and (fifo_dir / "rx.fifo").exists():
            return
        time.sleep(0.01)
    raise InputValidationError("RFUZZ target server did not create its FIFOs")


def _wait_for_event(
    event_log: Path,
    server: subprocess.Popen[bytes],
    fuzzer: subprocess.Popen[bytes],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if event_log.is_file() and event_log.stat().st_size:
            return
        if server.poll() is not None:
            raise InputValidationError(f"RFUZZ target server exited with status {server.returncode}")
        if fuzzer.poll() is not None:
            raise InputValidationError(f"upstream kfuzz exited with status {fuzzer.returncode}")
        time.sleep(0.01)
    raise InputValidationError("RFUZZ conformance smoke produced no coverage event")


def _wait_for_campaign_time(
    deadline: float, server: subprocess.Popen[bytes], fuzzer: subprocess.Popen[bytes],
) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        if server.poll() is not None:
            raise InputValidationError(f"RFUZZ target server exited with status {server.returncode}")
        if fuzzer.poll() is not None:
            raise InputValidationError(f"upstream kfuzz exited with status {fuzzer.returncode}")
        time.sleep(min(0.01, remaining))


def _campaign_sample(
    wall_seconds: float, event_log: Path, byte_limit: int | None = None,
) -> dict[str, object]:
    events = _read_available_events(event_log, byte_limit)
    if not events:
        return {
            "wall_seconds": wall_seconds, "event_count": 0,
            "coverage_points_hit": 0, "coverage_points_total": 0,
        }
    event = events[-1]
    return {
        "wall_seconds": wall_seconds,
        "event_count": len(events),
        "coverage_points_hit": event["cumulative_hit_count"],
        "coverage_points_total": event["coverage_point_count"],
    }


def _read_available_events(path: Path, byte_limit: int | None = None) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    with path.open("rb") as stream:
        payload = stream.read() if byte_limit is None else stream.read(byte_limit)
    lines = payload.splitlines(keepends=True)
    events = []
    for line in lines:
        if not line.endswith(b"\n"):
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or value.get("schema") != "myfuzz.rfuzz-campaign-event/v1":
            raise InputValidationError("RFUZZ event log contains an invalid event")
        events.append(value)
    return events


def _read_events(path: Path) -> list[dict[str, object]]:
    events = _read_available_events(path)
    if not events:
        raise InputValidationError("RFUZZ event log is empty")
    return events


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot read RFUZZ target artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputValidationError(f"RFUZZ target artifact must be an object: {path}")
    return value


def _write_json(path: Path, value: Mapping[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a completed myfuzz target to upstream kfuzz")
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit-config")
    emit.add_argument("target_dir")
    emit.add_argument("output")
    serve = subparsers.add_parser("serve")
    serve.add_argument("target_dir")
    serve.add_argument(
        "--mode", choices=tuple(sorted({item for modes in _RFUZZ_MODES.values() for item in modes})),
        required=True,
    )
    serve.add_argument("--server-id", required=True)
    serve.add_argument("--log", required=True)
    serve.add_argument("--stop-file")
    serve.add_argument("--testcase-timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.command == "emit-config":
        print(json.dumps(emit_rfuzz_toml(args.target_dir, args.output), indent=2, sort_keys=True))
    else:
        RFuzzTargetServer(
            args.target_dir, mode=args.mode, server_id=args.server_id, log_path=args.log,
            testcase_timeout_seconds=args.testcase_timeout, stop_path=args.stop_file,
        ).serve()


if __name__ == "__main__":
    main()
