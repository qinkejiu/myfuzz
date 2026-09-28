"""Independent source-backed Ibex session with host-owned persistent memory."""

from __future__ import annotations

import atexit
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping
import uuid

from .contracts import ProtocolEnvironmentError
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
    "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
    "src/myfuzz/composition/rtl/soc_ibex_beat_core.sv",
    "src/myfuzz/scenario/rtl/local_ibex_cpu.sv",
    "src/myfuzz/scenario/rtl/local_ibex_cpu_main.cpp",
)
_COMMAND_HEADER = "src/myfuzz/scenario/rtl/local_command_replay.h"
_MAX_STALE_REPLIES = 8


def _binary() -> Path:
    global _BUILD_DIRECTORY
    if _BUILD_DIRECTORY is not None:
        return _BUILD_DIRECTORY / "obj_dir/Vlocal_ibex_cpu"
    verilator = shutil.which("verilator")
    if verilator is None:
        raise RuntimeError("Verilator is required for the Ibex CPU session")
    profile = json.loads((ROOT / "configs/cpus/ibex/component_profile.json").read_text())
    source = profile["source"]
    source_root = ROOT / source["root"]
    directory = Path(tempfile.mkdtemp(prefix="myfuzz-ibex-cpu-"))
    obj = directory / "obj_dir"
    command = [verilator, "--cc", "--exe", "--build", "-j", "1", "--Mdir", str(obj),
               "--top-module", "local_ibex_cpu", "-Wno-fatal", "-Wno-WIDTH",
               "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
    command.extend("-I" + str(source_root / include)
                   for include in source["include_roots"])
    command.extend(str(source_root / name) for name in source["files"])
    command.extend(str(ROOT / name) for name in _LOCAL_SOURCES)
    try:
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               timeout=600)
        if built.returncode:
            raise RuntimeError("Ibex build failed:\n" +
                               (built.stdout + built.stderr)[-8000:])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _BUILD_DIRECTORY = directory
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return obj / "Vlocal_ibex_cpu"


class IbexCpuSession:
    """Advance one Ibex clock at a time; serve only accepted real OBI requests."""

    max_transaction_events_per_step = 2  # Instruction and data OBI channels.
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 1  # Only the data OBI channel reaches MMIO.

    def prepare_local(self) -> None:
        """Build the pinned RTL executable before testcase wall accounting."""
        _binary()

    def __init__(self, *, memory: PersistentMemory,
                 router: DataflowRouter, defer_mmio: bool = False) -> None:
        if not isinstance(defer_mmio, bool):
            raise ValueError("defer_mmio must be boolean")
        self._line_reader = BoundedLineReader()
        self.memory = memory
        self.router = router
        self.defer_mmio = defer_mmio
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self.service = MemoryService(memory, TransactionLedger())
        self._process: subprocess.Popen[str] | None = None
        self._pending_instr: tuple[int, int, int] | None = None
        self._pending_data: tuple[int, int, int] | None = None
        self._queued_mmio = False
        self._sequences = {"instr": 0, "data": 0}
        self._testcase_id = ""
        self.reset_epoch = 0
        self._quiescing = False
        self.local_ticks = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self.memory_write_count = 0
        self._wire_execution = ""
        self._command_sequence = 0

    def identity_document(self) -> dict:
        profile_path = ROOT / "configs/cpus/ibex/component_profile.json"
        profile = json.loads(profile_path.read_text())
        source = profile["source"]
        source_root = ROOT / source["root"]
        paths = (profile_path, *(source_root / name for name in source["files"]),
                 *(ROOT / name for name in _LOCAL_SOURCES), ROOT / _COMMAND_HEADER)
        return {"sources": bundle_identity(ROOT, paths),
                "revision": source["revision"],
                "toolchain": toolchain_identity(),
                "defer_mmio": self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        if self._process is not None or not testcase_id:
            raise ValueError("Ibex testcase can begin exactly once")
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
        if ready != "READY 3":
            self._process.kill()
            self.end_case()
            raise RuntimeError(f"Ibex did not reset into machine mode: {ready}")

    def _key(self, channel: str) -> TransactionKey:
        self._sequences[channel] += 1
        return TransactionKey("local-execution", self._testcase_id, "ibex", self.reset_epoch,
                              channel, self._sequences[channel])

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("Ibex process is not running")
        cancelled = (int(self._pending_instr is not None)
                     + int(self._pending_data is not None)
                     + int(self._queued_mmio))
        cancelled_targets = self.router.cancel_for_ledger(self.service.ledger)
        if self._queued_mmio and len(cancelled_targets) != 1:
            raise RuntimeError("queued MMIO request was not cancelled")
        testcase_id = self._testcase_id
        self.end_case()
        self._pending_instr = None
        self._pending_data = None
        self._queued_mmio = False
        self._sequences = {"instr": 0, "data": 0}
        self.reset_epoch += 1
        self._quiescing = False
        self.begin_case(testcase_id)
        return {"cancelled_responses": cancelled,
                "cancelled_target_requests": tuple(str(key)
                                                   for key in cancelled_targets)}

    @property
    def pending_responses(self) -> int:
        return (int(self._pending_instr is not None)
                + int(self._pending_data is not None)
                + int(self._queued_mmio))

    def begin_quiesce(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("Ibex process is not running")
        self._quiescing = True

    def _serve(self, channel: str, write: int, address: int,
               wdata: int, be: int) -> tuple[int, int, int] | None:
        key = self._key(channel)
        if channel == "instr" and write:
            raise RuntimeError("Ibex instruction port attempted a write")
        if self.router.owns(address):
            if channel == "instr":
                raise RuntimeError("Ibex fetched instruction from GPIO MMIO")
            if self.defer_mmio:
                def completed(response: tuple[int, int]) -> None:
                    self._pending_data = (response[0], response[1],
                                          key.source_sequence)
                    self._queued_mmio = False
                    if write:
                        self.mmio_write_count += 1
                    else:
                        self.mmio_read_count += 1

                fresh = self.router.enqueue(self.service.ledger, key,
                                            address=address, write=bool(write),
                                            wdata=wdata, be=be, beat_bytes=4,
                                            callback=completed)
                if not fresh:
                    raise RuntimeError("Ibex accepted a duplicate MMIO request")
                self._queued_mmio = True
                return None
            result = self.router.transact(self.service.ledger, key,
                                          address=address, write=bool(write),
                                          wdata=wdata, be=be, beat_bytes=4)
            if write:
                self.mmio_write_count += 1
            else:
                self.mmio_read_count += 1
            return result[0], result[1], key.source_sequence
        if write:
            self.service.write(key, address, wdata, width_bytes=4, byte_enable=be)
            self.memory_write_count += 1
            return 0, 0, key.source_sequence
        value = self.service.read(key, address, width_bytes=4).value
        return value, 0, key.source_sequence

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if set(inputs) - {"irq"}:
            raise ValueError("undeclared Ibex input")
        irq = inputs.get("irq", 0)
        if isinstance(irq, bool) or not isinstance(irq, int) or not 0 <= irq < 4:
            raise ValueError("Ibex irq input is out of range")
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("Ibex process is not running")
        ipending, dpending = self._pending_instr, self._pending_data
        values = (irq, int(ipending is None and not self._quiescing), int(ipending is not None),
                  ipending[0] if ipending else 0, ipending[1] if ipending else 0,
                  int(dpending is None and not getattr(self, "_queued_mmio", False)
                      and not self._quiescing),
                  int(dpending is not None),
                  dpending[0] if dpending else 0, dpending[1] if dpending else 0)
        self._command_sequence += 1
        sequence = self._command_sequence
        write_local_command(proc.stdin, "CMD " + self._wire_execution + " "
                            + f"{sequence:x} " + " ".join(
                                f"{value:x}" for value in values) + "\n")
        for stale_count in range(_MAX_STALE_REPLIES + 1):
            line = read_local_reply(self, proc.stdout)
            if not line:
                raise RuntimeError("lost_reply: Ibex stdout EOF")
            reply = line.strip().split()
            if reply[:2] == ["ERROR", "protocol_environment"]:
                if (len(reply) < 6 or reply[2] != self._wire_execution
                        or int(reply[3], 16) != sequence):
                    raise RuntimeError("Ibex protocol error identity is invalid")
                self.local_ticks = max(self.local_ticks, int(reply[4], 16))
                raise ProtocolEnvironmentError(" ".join(reply[5:]))
            if len(reply) < 2 or reply[0] != "RESULT":
                raise RuntimeError("Ibex process error: " + " ".join(reply))
            if reply[1] == self._wire_execution:
                break
            if stale_count == _MAX_STALE_REPLIES:
                raise RuntimeError("stale_execution: Ibex reply limit exceeded")
        if (len(reply) != 18 or int(reply[2], 16) != sequence
                or int(reply[-1], 16) != sequence):
            raise RuntimeError("Ibex process error: " + " ".join(reply))
        (ireq, iwrite, iaddr, iwdata, ibe, irspready,
         dreq, dwrite, daddr, dwdata, dbe, drspready,
         irq_masked_pre, irq_taken_pre) = (int(x, 16) for x in reply[3:-1])
        if irq_masked_pre not in (0, 1) or irq_taken_pre not in (0, 1):
            raise RuntimeError("Ibex returned invalid IRQ observation")
        if ipending is not None and irspready:
            self._pending_instr = None
        data_rsp_consumed = int(dpending is not None and bool(drspready))
        data_rsp_rdata = dpending[0] if data_rsp_consumed else 0
        data_rsp_source_epoch = self.reset_epoch if data_rsp_consumed else 0
        data_rsp_source_sequence = dpending[2] if data_rsp_consumed else 0
        if dpending is not None and drspready:
            self._pending_data = None
        if ireq and ipending is None and not self._quiescing:
            self._pending_instr = self._serve("instr", iwrite, iaddr, iwdata, ibe)
        if (dreq and dpending is None and not getattr(self, "_queued_mmio", False)
                and not self._quiescing):
            self._pending_data = self._serve("data", dwrite, daddr, dwdata, dbe)
        self.local_ticks += 1
        self.memory.advance_step()
        return {"instr_req_valid": ireq, "instr_addr": iaddr,
                "data_req_valid": dreq, "data_write": dwrite,
                "data_addr": daddr, "data_wdata": dwdata, "data_be": dbe,
                "data_rsp_consumed": data_rsp_consumed,
                "data_rsp_rdata": data_rsp_rdata,
                "data_rsp_source_epoch": data_rsp_source_epoch,
                "data_rsp_source_sequence": data_rsp_source_sequence,
                "irq_masked_pre": irq_masked_pre,
                "irq_taken_pre": irq_taken_pre}

    def end_case(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            end_local_process(proc)
        finally:
            self._process = None
