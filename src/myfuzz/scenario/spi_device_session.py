"""Persistent local process for one pinned OpenTitan SPI Device RTL instance."""

from __future__ import annotations

import atexit
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping
import uuid

from .identity import bundle_identity, toolchain_identity
from .protocol_io import (BoundedLineReader, LocalCommandDeadlineExceeded,
                          end_local_process, read_local_reply, read_startup_ready,
                          write_local_command)


ROOT = Path(__file__).resolve().parents[3]
_BUILD_DIRECTORY: Path | None = None
_LOCAL_SOURCES = (
    "src/myfuzz/protocols/rtl/beat_to_tlul.sv",
    "configs/peripherals/opentitan_spi_device/closure_wrapper.sv",
    "src/myfuzz/scenario/rtl/local_opentitan_spi_device.sv",
    "src/myfuzz/scenario/rtl/local_opentitan_spi_device_main.cpp",
)
_COMMAND_HEADER = "src/myfuzz/scenario/rtl/local_command_replay.h"
_MAX_STALE_REPLIES = 8
_SPI_HALF_PERIOD = 8


def _binary() -> Path:
    global _BUILD_DIRECTORY
    if _BUILD_DIRECTORY is not None:
        return _BUILD_DIRECTORY / "obj_dir/Vlocal_opentitan_spi_device"
    verilator = shutil.which("verilator")
    if verilator is None:
        raise RuntimeError("Verilator is required for the OpenTitan SPI Device session")
    profile = json.loads((ROOT / "configs/peripherals/opentitan_spi_device/component_profile.json")
                         .read_text())
    source = profile["source"]
    source_root = ROOT / source["root"]
    directory = Path(tempfile.mkdtemp(prefix="myfuzz-ot-spi-device-"))
    obj = directory / "obj_dir"
    command = [verilator, "--cc", "--exe", "--build", "-j", "1",
               "--Mdir", str(obj), "--top-module", "local_opentitan_spi_device",
               "-Wno-fatal", "-Wno-WIDTH", "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
    command.extend("-I" + str(source_root / include)
                   for include in source["include_roots"])
    command.extend(str(source_root / name) for name in source["files"])
    command.extend(str(ROOT / name) for name in _LOCAL_SOURCES)
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=300)
        if result.returncode:
            raise RuntimeError("OpenTitan SPI Device build failed:\n" +
                               (result.stdout + result.stderr)[-6000:])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _BUILD_DIRECTORY = directory
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return obj / "Vlocal_opentitan_spi_device"


class OpenTitanSpiDeviceSession:
    """One SPI Device and its SPI and TL-UL state across a testcase."""

    max_local_ticks_per_step = 1
    max_local_ticks_per_register_access = 805

    def __init__(self) -> None:
        self._line_reader = BoundedLineReader()
        self._process: subprocess.Popen[str] | None = None
        self._case_id: str | None = None
        self._wire_execution = ""
        self._command_sequence = 0
        self._tick_base = 0
        self.local_ticks = 0
        self._sck = 0
        self._csb = 1
        self._sd_i = 0
        self._last_result: dict[str, int] = {"sd_o": 0, "sd_en": 0, "irq": 0,
                                             "rdata": 0, "error": 0}

    def prepare_local(self) -> None:
        _binary()

    def identity_document(self) -> dict:
        profile_path = ROOT / "configs/peripherals/opentitan_spi_device/component_profile.json"
        profile = json.loads(profile_path.read_text())
        source = profile["source"]
        source_root = ROOT / source["root"]
        paths = (profile_path, *(source_root / name for name in source["files"]),
                 *(ROOT / name for name in _LOCAL_SOURCES), ROOT / _COMMAND_HEADER)
        return {"sources": bundle_identity(ROOT, paths),
                "revision": source["revision"],
                "toolchain": toolchain_identity()}

    def begin_case(self, testcase_id: str) -> None:
        if self._process is not None or not testcase_id:
            raise ValueError("SPI Device testcase can begin exactly once")
        self._case_id = testcase_id
        self.local_ticks = 0
        self._tick_base = 0
        self._wire_execution = uuid.uuid4().hex
        self._command_sequence = 0
        self._sck, self._csb, self._sd_i = 0, 1, 0
        self._last_result = {"sd_o": 0, "sd_en": 0, "irq": 0,
                             "rdata": 0, "error": 0}
        self._line_reader.reset()
        self._process = subprocess.Popen((str(_binary()),), cwd=ROOT,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL,
                                         text=True, bufsize=1)
        try:
            ready = (read_startup_ready(self._line_reader, self._process.stdout)
                     if self._process.stdout is not None else "")
        except LocalCommandDeadlineExceeded:
            self._process.kill()
            self.end_case()
            raise
        if ready != "READY":
            self._process.kill()
            self.end_case()
            raise RuntimeError("OpenTitan SPI Device process did not initialize")

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan SPI Device process is not running")
        testcase_id = self._case_id
        previous_ticks = self.local_ticks
        self.end_case()
        self.begin_case(testcase_id)
        self._tick_base = previous_ticks
        self.local_ticks = previous_ticks
        return {"cancelled_responses": 0}

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        return int(self._csb == 0 or self._last_result["irq"] != 0)

    def begin_quiesce(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan SPI Device process is not running")

    def _command(self, *, valid: bool = False, write: bool = False,
                 address: int = 0, data: int = 0, be: int = 15,
                 cycles: int = 1) -> dict[str, int]:
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("OpenTitan SPI Device process is not running")
        if self._sck not in (0, 1) or self._csb not in (0, 1) \
                or not 0 <= self._sd_i < 16 or not 0 <= address < (1 << 32) \
                or not 0 <= data < (1 << 32) or not 0 <= be < 16 \
                or not 0 <= cycles <= 100000:
            raise ValueError("SPI Device command field is out of range")
        fields = (self._sck, self._csb, self._sd_i, int(valid), int(write),
                  address, data, be, cycles)
        self._command_sequence += 1
        sequence = self._command_sequence
        write_local_command(proc.stdin, "CMD " + self._wire_execution + " "
                            + f"{sequence:x} " + " ".join(
                                f"{field:x}" for field in fields) + "\n")
        stale_count = 0
        while True:
            line = read_local_reply(self, proc.stdout)
            if not line:
                raise RuntimeError("lost_reply: OpenTitan SPI Device stdout EOF")
            answer = line.strip().split()
            if len(answer) < 2 or answer[0] != "RESULT":
                raise RuntimeError("OpenTitan SPI Device process error: " + " ".join(answer))
            if answer[1] == self._wire_execution:
                break
            stale_count += 1
            if stale_count > _MAX_STALE_REPLIES:
                raise RuntimeError("stale_execution: OpenTitan SPI Device reply limit exceeded")
        if len(answer) != 9 or int(answer[2], 16) != sequence:
            raise RuntimeError("OpenTitan SPI Device process error: " + " ".join(answer))
        sd_o, sd_en, irq, readback, error, ticks = (
            int(item, 16) for item in answer[3:])
        if not 0 <= sd_o < 16 or not 0 <= sd_en < 16 or not 0 <= irq < 256 \
                or error not in (0, 1) or self._tick_base + ticks < self.local_ticks:
            raise RuntimeError("OpenTitan SPI Device invalid native observation")
        self.local_ticks = self._tick_base + ticks
        self._last_result = {"sd_o": sd_o, "sd_en": sd_en, "irq": irq,
                             "rdata": readback, "error": error}
        return dict(self._last_result)

    def drive_pins(self, sck: int, csb: int, mosi: int, cycles: int = 1) -> dict[str, int]:
        if sck not in (0, 1) or csb not in (0, 1) or mosi not in (0, 1):
            raise ValueError("SPI Device mode-0 pins must be bits")
        self._sck, self._csb, self._sd_i = sck, csb, mosi
        return self._command(cycles=cycles)

    def transfer_bytes(self, data: bytes, read_count: int = 0) -> bytes:
        """Clock an MSB-first mode-0 frame and return bytes after the command."""
        if not isinstance(data, bytes) or not data:
            raise ValueError("SPI Device transfer requires command bytes")
        if not 0 <= read_count <= 4096:
            raise ValueError("SPI Device read count is out of range")
        if self._csb == 0:
            raise RuntimeError("SPI Device transfer already has CS asserted")
        received = bytearray()
        self.drive_pins(0, 0, 0, _SPI_HALF_PERIOD)
        try:
            for sent in data + bytes(read_count):
                value = 0
                for shift in range(7, -1, -1):
                    bit = (sent >> shift) & 1
                    self.drive_pins(0, 0, bit, _SPI_HALF_PERIOD)
                    observed = self.drive_pins(1, 0, bit, _SPI_HALF_PERIOD)
                    miso = ((observed["sd_o"] >> 1) & 1) if observed["sd_en"] & 2 else 0
                    value = (value << 1) | miso
                received.append(value)
            self.drive_pins(0, 0, 0, _SPI_HALF_PERIOD)
        finally:
            self.drive_pins(0, 1, 0, _SPI_HALF_PERIOD)
        return bytes(received[len(data):])

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        unexpected = set(inputs) - {"spi_sck_i", "spi_csb_i", "spi_sd_i"}
        if unexpected:
            raise ValueError(f"undeclared SPI Device inputs: {sorted(unexpected)}")
        sck = int(inputs.get("spi_sck_i", self._sck))
        csb = int(inputs.get("spi_csb_i", self._csb))
        sd_i = int(inputs.get("spi_sd_i", self._sd_i))
        if sck not in (0, 1) or csb not in (0, 1) or not 0 <= sd_i < 16:
            raise ValueError("SPI Device input pin is out of range")
        self._sck, self._csb, self._sd_i = sck, csb, sd_i
        return self._command(cycles=1)

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        result = self._command(valid=True, write=True, address=0x40000000 + offset,
                               data=value, be=be, cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan SPI Device write error at {offset:#x}")

    def read_register(self, offset: int) -> int:
        result = self._command(valid=True, write=False, address=0x40000000 + offset,
                               cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan SPI Device read error at {offset:#x}")
        return result["rdata"]

    def end_case(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            end_local_process(proc)
        finally:
            self._process = None
