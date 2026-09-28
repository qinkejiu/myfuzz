"""Persistent process session for one pinned OpenTitan UART RTL instance."""

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
    "src/myfuzz/composition/rtl/soc_opentitan_uart_target.sv",
    "src/myfuzz/scenario/rtl/local_opentitan_uart.sv",
    "src/myfuzz/scenario/rtl/local_opentitan_uart_main.cpp",
)
_COMMAND_HEADER = "src/myfuzz/scenario/rtl/local_command_replay.h"
_MAX_STALE_REPLIES = 8


def _binary() -> Path:
    global _BUILD_DIRECTORY
    if _BUILD_DIRECTORY is not None:
        return _BUILD_DIRECTORY / "obj_dir/Vlocal_opentitan_uart"
    verilator = shutil.which("verilator")
    if verilator is None:
        raise RuntimeError("Verilator is required for the OpenTitan UART session")
    profile = json.loads((ROOT / "configs/peripherals/opentitan_uart/component_profile.json")
                         .read_text())
    source = profile["source"]
    source_root = ROOT / source["root"]
    directory = Path(tempfile.mkdtemp(prefix="myfuzz-ot-uart-"))
    obj = directory / "obj_dir"
    command = [verilator, "--cc", "--exe", "--build", "-j", "1",
               "--Mdir", str(obj), "--top-module", "local_opentitan_uart",
               "-Wno-fatal", "-Wno-WIDTH", "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
    command.extend("-I" + str(source_root / include)
                   for include in source["include_roots"])
    command.extend(str(source_root / name) for name in source["files"])
    command.extend(str(ROOT / name) for name in _LOCAL_SOURCES)
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=300)
        if result.returncode:
            raise RuntimeError("OpenTitan UART build failed:\n" +
                               (result.stdout + result.stderr)[-6000:])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _BUILD_DIRECTORY = directory
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return obj / "Vlocal_opentitan_uart"


class OpenTitanUartSession:
    """One local UART clock domain, reset once at testcase start.

    ``step_local`` accepts the external RX level. Register transactions must
    arrive from the declared upstream source and return real TL-UL results.
    """

    max_local_ticks_per_step = 1
    max_local_ticks_per_register_access = 5

    def prepare_local(self) -> None:
        """Build the pinned RTL executable before testcase wall accounting."""
        _binary()

    def __init__(self) -> None:
        self._line_reader = BoundedLineReader()
        self._process: subprocess.Popen[str] | None = None
        self._uart_rx = 1
        self._case_id: str | None = None
        self.local_ticks = 0
        self._tick_base = 0
        self._wire_execution = ""
        self._command_sequence = 0
        self._tx_idle = 1
        self._tx_settle_until = 0

    def identity_document(self) -> dict:
        profile_path = ROOT / "configs/peripherals/opentitan_uart/component_profile.json"
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
            raise ValueError("UART testcase can begin exactly once")
        self._case_id = testcase_id
        self._wire_execution = uuid.uuid4().hex
        self._command_sequence = 0
        self._tx_idle = 1
        self._tx_settle_until = 0
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
            raise RuntimeError("OpenTitan UART process did not initialize")

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan UART process is not running")
        testcase_id = self._case_id
        self.end_case()
        self._uart_rx = 1
        self._tick_base = self.local_ticks
        self.begin_case(testcase_id)
        return {"cancelled_responses": 0}

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        return int(not self._tx_idle or self.local_ticks < self._tx_settle_until)

    def begin_quiesce(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("OpenTitan UART process is not running")

    def _command(self, *, valid: bool = False, write: bool = False,
                 address: int = 0, data: int = 0, be: int = 15,
                 cycles: int = 1) -> dict[str, int]:
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("OpenTitan UART process is not running")
        if self._uart_rx not in (0, 1) or not 0 <= address < (1 << 32) \
                or not 0 <= data < (1 << 32) or not 0 <= be < 16 \
                or not 0 <= cycles <= 100000:
            raise ValueError("UART command field is out of range")
        command = (self._uart_rx, int(valid), int(write), address, data, be, cycles)
        self._command_sequence += 1
        sequence = self._command_sequence
        write_local_command(proc.stdin, "CMD " + self._wire_execution + " "
                            + f"{sequence:x} " + " ".join(
                                f"{field:x}" for field in command) + "\n")
        for stale_count in range(_MAX_STALE_REPLIES + 1):
            line = read_local_reply(self, proc.stdout)
            if not line:
                raise RuntimeError("lost_reply: OpenTitan UART stdout EOF")
            answer = line.strip().split()
            if len(answer) < 2 or answer[0] != "RESULT":
                raise RuntimeError("OpenTitan UART process error: " + " ".join(answer))
            if answer[1] == self._wire_execution:
                break
            if stale_count == _MAX_STALE_REPLIES:
                raise RuntimeError("stale_execution: OpenTitan UART reply limit exceeded")
        if len(answer) != 11 or int(answer[2], 16) != sequence:
            raise RuntimeError("OpenTitan UART process error: " + " ".join(answer))
        tx, irq, tx_done, tx_watermark, tx_idle, readback, error, ticks = (
            int(item, 16) for item in answer[3:])
        if tx_idle not in (0, 1):
            raise RuntimeError("OpenTitan UART tx_idle observation is invalid")
        lifetime_ticks = self._tick_base + ticks
        if lifetime_ticks < self.local_ticks:
            raise RuntimeError("OpenTitan UART local tick count moved backwards")
        if self._tx_idle == 0 and tx_idle == 1:
            # The UART raises the registered TX_DONE event after TX turns
            # idle. Let real RTL run through that local pipeline.
            self._tx_settle_until = lifetime_ticks + 2
        self.local_ticks = lifetime_ticks
        self._tx_idle = tx_idle
        return {"uart_tx": tx, "irq": irq, "tx_done": tx_done,
                "tx_watermark": tx_watermark, "tx_idle": tx_idle,
                "rdata": readback, "error": error}

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        unexpected = set(inputs) - {"uart_rx"}
        if unexpected:
            raise ValueError(f"undeclared UART inputs: {sorted(unexpected)}")
        self._uart_rx = inputs.get("uart_rx", self._uart_rx)
        return self._command(cycles=1)

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        result = self._command(valid=True, write=True, address=0x40000000 + offset,
                               data=value, be=be, cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan UART write error at {offset:#x}")

    def read_register(self, offset: int) -> int:
        result = self._command(valid=True, write=False, address=0x40000000 + offset,
                               cycles=1)
        if result["error"]:
            raise RuntimeError(f"OpenTitan UART read error at {offset:#x}")
        return result["rdata"]

    def end_case(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            end_local_process(proc)
        finally:
            self._process = None
