"""Persistent local process for one pinned OpenTitan SPI Host RTL instance."""

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
    "src/myfuzz/scenario/rtl/local_opentitan_spi_host.sv",
    "src/myfuzz/scenario/rtl/local_opentitan_spi_host_main.cpp",
)
_COMMAND_HEADER = "src/myfuzz/scenario/rtl/local_command_replay.h"
_MAX_STALE_REPLIES = 8


def _binary() -> Path:
    global _BUILD_DIRECTORY
    if _BUILD_DIRECTORY is not None:
        return _BUILD_DIRECTORY / "obj_dir/Vlocal_opentitan_spi_host"
    verilator = shutil.which("verilator")
    if verilator is None:
        raise RuntimeError("Verilator is required for the OpenTitan SPI Host session")
    profile = json.loads((ROOT / "configs/peripherals/opentitan_spi_host/component_profile.json")
                         .read_text())
    source = profile["source"]
    source_root = ROOT / source["root"]
    directory = Path(tempfile.mkdtemp(prefix="myfuzz-ot-spi-host-"))
    obj = directory / "obj_dir"
    command = [verilator, "--cc", "--exe", "--build", "-j", "1",
               "--Mdir", str(obj), "--top-module", "local_opentitan_spi_host",
               "-Wno-fatal", "-Wno-WIDTH", "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
    command.extend("-I" + str(source_root / include)
                   for include in source["include_roots"])
    command.extend(str(source_root / name) for name in source["files"])
    command.extend(str(ROOT / name) for name in _LOCAL_SOURCES)
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=300)
        if result.returncode:
            raise RuntimeError("OpenTitan SPI Host build failed:\n" +
                               (result.stdout + result.stderr)[-6000:])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _BUILD_DIRECTORY = directory
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return obj / "Vlocal_opentitan_spi_host"


class OpenTitanSpiHostSession:
    """One real Host with its local TL-UL and SPI timing across a testcase.

    A peer, when attached, owns MISO. Every local RTL tick reports real Host
    pins to the peer and receives the next legal SPI input before the next tick.
    """

    max_local_ticks_per_step = 1
    max_local_ticks_per_register_access = 205

    def __init__(self) -> None:
        self._line_reader = BoundedLineReader()
        self._process: subprocess.Popen[str] | None = None
        self._peer = None
        self._spi_sd_i = 0
        self._case_id: str | None = None
        self.local_ticks = 0
        self._tick_base = 0
        self._wire_execution = ""
        self._command_sequence = 0
        self._transfer_pending = False

    def prepare_local(self) -> None:
        _binary()

    def identity_document(self) -> dict:
        profile_path = ROOT / "configs/peripherals/opentitan_spi_host/component_profile.json"
        profile = json.loads(profile_path.read_text())
        source = profile["source"]
        source_root = ROOT / source["root"]
        paths = (profile_path, *(source_root / name for name in source["files"]),
                 *(ROOT / name for name in _LOCAL_SOURCES), ROOT / _COMMAND_HEADER,
                 ROOT / "src/myfuzz/scenario/spi_peer.py")
        return {"sources": bundle_identity(ROOT, paths),
                "revision": source["revision"],
                "toolchain": toolchain_identity()}

    def attach_peer(self, peer: object) -> None:
        if self._process is not None:
            raise ValueError("SPI peer must be attached before testcase start")
        if not hasattr(peer, "sd_i") or not callable(getattr(peer, "observe", None)):
            raise TypeError("SPI peer must expose sd_i and observe")
        self._peer = peer
        self._spi_sd_i = int(peer.sd_i)

    def begin_case(self, testcase_id: str) -> None:
        if self._process is not None or not testcase_id:
            raise ValueError("SPI Host testcase can begin exactly once")
        self._case_id = testcase_id
        self._wire_execution = uuid.uuid4().hex
        self._command_sequence = 0
        self._transfer_pending = False
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
            raise RuntimeError("OpenTitan SPI Host process did not initialize")

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan SPI Host process is not running")
        testcase_id = self._case_id
        self.end_case()
        self._tick_base = self.local_ticks
        if self._peer is not None:
            self._peer.reset_case()
            self._spi_sd_i = int(self._peer.sd_i)
        else:
            self._spi_sd_i = 0
        self.begin_case(testcase_id)
        return {"cancelled_responses": 0}

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        return int(self._transfer_pending)

    def begin_quiesce(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan SPI Host process is not running")

    def _observe_tick(self, answer: list[str], proc: subprocess.Popen[str]) -> None:
        if len(answer) != 9 or proc.stdin is None:
            raise RuntimeError("OpenTitan SPI Host invalid tick observation")
        sck, sck_en, csb, csb_en, sd_out, sd_en, native_pending, ticks = (
            int(item, 16) for item in answer[1:])
        if sck not in (0, 1) or sck_en not in (0, 1) \
                or csb not in (0, 1) or csb_en not in (0, 1) or not 0 <= sd_out < 16 \
                or not 0 <= sd_en < 16 or native_pending not in (0, 1) \
                or self._tick_base + ticks < self.local_ticks:
            raise RuntimeError("OpenTitan SPI Host invalid native pin observation")
        self.local_ticks = self._tick_base + ticks
        self._transfer_pending = bool(native_pending)
        pad_sck = sck if sck_en else 0
        pad_csb = csb if csb_en else 1
        pad_mosi = (sd_out & 1) if (sd_en & 1) else 0
        if self._peer is not None:
            self._peer.observe(sck=pad_sck, csb=pad_csb, mosi=pad_mosi)
            self._spi_sd_i = int(self._peer.sd_i)
        write_local_command(proc.stdin, f"DRIVE {self._spi_sd_i:x}\n")

    def _command(self, *, valid: bool = False, write: bool = False,
                 address: int = 0, data: int = 0, be: int = 15,
                 cycles: int = 1) -> dict[str, int]:
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("OpenTitan SPI Host process is not running")
        if not 0 <= self._spi_sd_i < 16 or not 0 <= address < (1 << 32) \
                or not 0 <= data < (1 << 32) or not 0 <= be < 16 \
                or not 0 <= cycles <= 100000:
            raise ValueError("SPI Host command field is out of range")
        command = (self._spi_sd_i, int(valid), int(write), address, data, be, cycles)
        self._command_sequence += 1
        sequence = self._command_sequence
        write_local_command(proc.stdin, "CMD " + self._wire_execution + " "
                            + f"{sequence:x} " + " ".join(
                                f"{field:x}" for field in command) + "\n")
        stale_count = 0
        while True:
            line = read_local_reply(self, proc.stdout)
            if not line:
                raise RuntimeError("lost_reply: OpenTitan SPI Host stdout EOF")
            answer = line.strip().split()
            if answer and answer[0] == "TICK":
                self._observe_tick(answer, proc)
                continue
            if len(answer) < 2 or answer[0] != "RESULT":
                raise RuntimeError("OpenTitan SPI Host process error: " + " ".join(answer))
            if answer[1] == self._wire_execution:
                break
            stale_count += 1
            if stale_count > _MAX_STALE_REPLIES:
                raise RuntimeError("stale_execution: OpenTitan SPI Host reply limit exceeded")
        if len(answer) != 15 or int(answer[2], 16) != sequence:
            raise RuntimeError("OpenTitan SPI Host process error: " + " ".join(answer))
        sck, sck_en, csb, csb_en, sd_out, sd_en, irq_event, irq_error, \
            native_pending, readback, error, ticks = (
                int(item, 16) for item in answer[3:])
        if native_pending not in (0, 1):
            raise RuntimeError("OpenTitan SPI Host pending observation is invalid")
        lifetime_ticks = self._tick_base + ticks
        if lifetime_ticks < self.local_ticks:
            raise RuntimeError("OpenTitan SPI Host local tick count moved backwards")
        self.local_ticks = lifetime_ticks
        self._transfer_pending = bool(native_pending)
        return {"sck": sck, "sck_en": sck_en, "csb": csb, "csb_en": csb_en,
                "sd_out": sd_out, "sd_en": sd_en, "irq_event": irq_event,
                "irq_error": irq_error, "native_pending": native_pending,
                "rdata": readback, "error": error}

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        unexpected = set(inputs) - {"spi_sd_i"}
        if unexpected:
            raise ValueError(f"undeclared SPI Host inputs: {sorted(unexpected)}")
        if self._peer is not None and "spi_sd_i" in inputs:
            raise ValueError("bound SPI Host MISO cannot be overwritten")
        self._spi_sd_i = int(inputs.get("spi_sd_i", self._spi_sd_i))
        return self._command(cycles=1)

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        result = self._command(valid=True, write=True, address=0x40000000 + offset,
                               data=value, be=be, cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan SPI Host write error at {offset:#x}")

    def read_register(self, offset: int) -> int:
        result = self._command(valid=True, write=False, address=0x40000000 + offset,
                               cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan SPI Host read error at {offset:#x}")
        return result["rdata"]

    def end_case(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            end_local_process(proc)
        finally:
            self._process = None
