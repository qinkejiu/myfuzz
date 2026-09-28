"""Independent pinned CVA6 session with host-owned persistent memory beats."""

from __future__ import annotations

import atexit
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping
import uuid

from myfuzz.composition.cva6_source_closure import resolve_cva6_source_closure

from .ledger import TransactionKey, TransactionLedger
from .identity import bundle_identity, toolchain_identity
from .memory import PersistentMemory
from .memory_service import MemoryService
from .protocol_io import (BoundedLineReader, LocalCommandDeadlineExceeded,
                          end_local_process, read_local_reply, read_startup_ready,
                          write_local_command)
from .router import DataflowRouter


ROOT = Path(__file__).resolve().parents[3]
_BUILD_DIRECTORY: Path | None = None
_LOCAL_SOURCES = (
    "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv",
    "src/myfuzz/protocols/rtl/processor_memory_backend.sv",
    "src/myfuzz/composition/rtl/soc_cva6_beat_core.sv",
    "src/myfuzz/scenario/rtl/local_cva6_cpu.sv",
    "src/myfuzz/scenario/rtl/local_cva6_cpu_main.cpp",
)
_COMMAND_HEADER = "src/myfuzz/scenario/rtl/local_command_replay.h"
_MAX_STALE_REPLIES = 8


def _binary() -> Path:
    global _BUILD_DIRECTORY
    if _BUILD_DIRECTORY is not None:
        return _BUILD_DIRECTORY / "obj_dir/Vlocal_cva6_cpu"
    verilator = shutil.which("verilator")
    if verilator is None:
        raise RuntimeError("Verilator is required for the CVA6 CPU session")
    closure = resolve_cva6_source_closure(ROOT)
    directory = Path(tempfile.mkdtemp(prefix="myfuzz-cva6-cpu-"))
    obj = directory / "obj_dir"
    command = [verilator, "--cc", "--exe", "--build", "-j", "1", "--Mdir", str(obj),
               "--top-module", "local_cva6_cpu", "-Wno-fatal", "-Wno-WIDTH",
               "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
    command.extend("-I" + str(ROOT / include) for include in closure["include_dirs"])
    command.extend("+define+" + define for define in closure["defines"])
    command.extend(str(ROOT / source) for source in closure["source_files"])
    command.extend(str(ROOT / name) for name in _LOCAL_SOURCES)
    try:
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               timeout=900)
        if built.returncode:
            raise RuntimeError("CVA6 build failed:\n" +
                               (built.stdout + built.stderr)[-10000:])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _BUILD_DIRECTORY = directory
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return obj / "Vlocal_cva6_cpu"


class Cva6CpuSession:
    """Advance CVA6's real AXI4 adapter/backend one local cycle per command."""

    max_transaction_events_per_step = 1  # One unified accepted AXI request.
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 1

    def prepare_local(self) -> None:
        """Build the pinned RTL executable before testcase wall accounting."""
        _binary()

    def __init__(self, *, memory: PersistentMemory,
                 router: DataflowRouter | None = None,
                 defer_mmio: bool = False) -> None:
        if not isinstance(defer_mmio, bool):
            raise ValueError("defer_mmio must be boolean")
        if defer_mmio and router is None:
            raise ValueError("deferred MMIO requires a router")
        self._line_reader = BoundedLineReader()
        self.memory = memory
        self.router = router
        self.defer_mmio = defer_mmio
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self.service = MemoryService(memory, TransactionLedger())
        self._process: subprocess.Popen[str] | None = None
        self._pending: tuple[int, int, int] | None = None
        self._queued_mmio = False
        self._testcase_id = ""
        self._sequence = 0
        self.reset_epoch = 0
        self._quiescing = False
        self.local_ticks = 0
        self.memory_write_count = 0
        self.memory_read_count = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self._wire_execution = ""
        self._command_sequence = 0

    def identity_document(self) -> dict:
        closure = resolve_cva6_source_closure(ROOT)
        paths = (*(ROOT / name for name in closure["source_files"]),
                 *(ROOT / name for name in _LOCAL_SOURCES), ROOT / _COMMAND_HEADER)
        return {"sources": bundle_identity(ROOT, paths),
                "include_dirs": closure["include_dirs"],
                "defines": closure["defines"],
                "toolchain": toolchain_identity(),
                "defer_mmio": self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        if self._process is not None or not testcase_id:
            raise ValueError("CVA6 testcase can begin exactly once")
        self._testcase_id = testcase_id
        self._wire_execution = uuid.uuid4().hex
        self._command_sequence = 0
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
            raise RuntimeError("CVA6 process did not initialize")

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("CVA6 process is not running")
        cancelled = int(self._pending is not None) + int(self._queued_mmio)
        cancelled_targets = (self.router.cancel_for_ledger(self.service.ledger)
                             if self.router is not None else ())
        if self._queued_mmio and len(cancelled_targets) != 1:
            raise RuntimeError("queued MMIO request was not cancelled")
        testcase_id = self._testcase_id
        self.end_case()
        self._pending = None
        self._queued_mmio = False
        self._sequence = 0
        self.reset_epoch += 1
        self._quiescing = False
        self.begin_case(testcase_id)
        return {"cancelled_responses": cancelled,
                "cancelled_target_requests": tuple(str(key)
                                                   for key in cancelled_targets)}

    @property
    def pending_responses(self) -> int:
        return int(self._pending is not None) + int(self._queued_mmio)

    def begin_quiesce(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("CVA6 process is not running")
        self._quiescing = True

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if set(inputs) - {"irq"}:
            raise ValueError("undeclared CVA6 input")
        irq = inputs.get("irq", 0)
        if isinstance(irq, bool) or not isinstance(irq, int) or not 0 <= irq < 4:
            raise ValueError("CVA6 irq input is out of range")
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("CVA6 process is not running")
        pending = self._pending
        values = (irq, int(pending is None and not getattr(self, "_queued_mmio", False)
                           and not self._quiescing), int(pending is not None),
                  pending[0] if pending else 0, pending[1] if pending else 0)
        self._command_sequence += 1
        sequence = self._command_sequence
        write_local_command(proc.stdin, "CMD " + self._wire_execution + " "
                            + f"{sequence:x} " + " ".join(
                                f"{value:x}" for value in values) + "\n")
        for stale_count in range(_MAX_STALE_REPLIES + 1):
            line = read_local_reply(self, proc.stdout)
            if not line:
                raise RuntimeError("lost_reply: CVA6 stdout EOF")
            reply = line.strip().split()
            if len(reply) < 2 or reply[0] != "RESULT":
                raise RuntimeError("CVA6 process error: " + " ".join(reply))
            if reply[1] == self._wire_execution:
                break
            if stale_count == _MAX_STALE_REPLIES:
                raise RuntimeError("stale_execution: CVA6 reply limit exceeded")
        if (len(reply) != 10 or int(reply[2], 16) != sequence
                or int(reply[-1], 16) != sequence):
            raise RuntimeError("CVA6 process error: " + " ".join(reply))
        req, write, address, wdata, be, rspready = (int(x, 16) for x in reply[3:-1])
        response_consumed = int(pending is not None and bool(rspready))
        response_rdata = pending[0] if response_consumed else 0
        response_source_sequence = pending[2] if response_consumed else 0
        if pending is not None and rspready:
            self._pending = None
        if (req and pending is None and not getattr(self, "_queued_mmio", False)
                and not self._quiescing):
            self._sequence += 1
            key = TransactionKey("local-execution", self._testcase_id, "cva6", self.reset_epoch,
                                 "unified", self._sequence)
            if self.router is not None and self.router.owns(address):
                if self.defer_mmio:
                    def completed(response: tuple[int, int]) -> None:
                        self._pending = (response[0], response[1],
                                         key.source_sequence)
                        self._queued_mmio = False
                        if write:
                            self.mmio_write_count += 1
                        else:
                            self.mmio_read_count += 1

                    fresh = self.router.enqueue(
                        self.service.ledger, key, address=address,
                        write=bool(write), wdata=wdata, be=be, beat_bytes=8,
                        callback=completed)
                    if not fresh:
                        raise RuntimeError("CVA6 accepted a duplicate MMIO request")
                    self._queued_mmio = True
                else:
                    response = self.router.transact(
                        self.service.ledger, key, address=address,
                        write=bool(write), wdata=wdata, be=be, beat_bytes=8)
                    self._pending = (response[0], response[1],
                                     key.source_sequence)
                    if write:
                        self.mmio_write_count += 1
                    else:
                        self.mmio_read_count += 1
            elif write:
                self.service.write(key, address, wdata, width_bytes=8,
                                   byte_enable=be)
                self._pending = (0, 0, key.source_sequence)
                self.memory_write_count += 1
            else:
                snapshot = self.service.read(key, address, width_bytes=8)
                self._pending = (snapshot.value, 0, key.source_sequence)
                self.memory_read_count += 1
        self.local_ticks += 1
        self.memory.advance_step()
        return {"req_valid": req, "write": write, "addr": address,
                "wdata": wdata, "be": be,
                "response_consumed": response_consumed,
                "response_rdata": response_rdata,
                "response_source_epoch": self.reset_epoch if response_consumed else 0,
                "response_source_sequence": response_source_sequence}

    def end_case(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            end_local_process(proc)
        finally:
            self._process = None
