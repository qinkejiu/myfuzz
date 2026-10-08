"""Reset-free Ibex and real OpenTitan UART online source declarations."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness import GeneratedOpentitanUartSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import (
    UART_REGISTER_WRITES_BY_OFFSET, uart_register_write_denial)

from .batch import BatchAdvance
from .dependency import DependencyRule
from .genome import MemoryImage, ScenarioGenome
from .ibex_pulp_dual_source import ROOT, RVFI_CPU_PROFILE, _artifact
from .memory import MemoryRegion, PersistentMemory
from .online_case_decoder import (CandidateDisposition, OnlineCaseDecoder,
                                  OnlineDependencyGraph,
                                  OnlineDependencySource, OnlineSource)
from .ownership import InputField, InputOwner, compile_ownership
from .rejection_codes import Rejection, RejectionCode, RejectionError, reject
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .rv32i_sources import (MmioWindow, Rv32iInstruction, fragment_bytes,
                           mmio_write_fragment)
from .session_runtime import OnlineInstruction
from .runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract


UART_BASE = 0x40000000
#: The UART aperture the Router declares for this peripheral (profile
#: ``address.window_size``).  Writes outside it belong to another device.
UART_APERTURE_SIZE = 0x1000
RESULT_ADDRESS = 0x20000
CPU_PROFILE = "configs/cpus/ibex_obi_local/component_profile.json"
UART_PROFILE = "configs/peripherals/opentitan_uart_local/component_profile.json"
UART_FIFO_PROFILE = "configs/peripherals/opentitan_uart_fifo_local/component_profile.json"

#: RV32I store funct3 selects the real lane byte enable of the MMIO write.
_STORE_WRITES = {0: ("SB", 1), 1: ("SH", 3), 2: ("SW", 15)}

# The real local UART peer uses 32 clocks/bit and requires 17 idle bits before
# each 8N1 frame. Advance that UART-local interval without clocking Ibex.
UART_CLOCKS_PER_BIT = 32
UART_IDLE_BITS = 17
UART_FRAME_BITS = 10
UART_RX_SETTLE_TICKS = 50
UART_RX_READY_TICKS = ((UART_IDLE_BITS + UART_FRAME_BITS)
                       * UART_CLOCKS_PER_BIT + UART_RX_SETTLE_TICKS + 2)
UART_CPU_FRAGMENT_TICKS = 96
UART_ISR_CPU_TICKS = 320


def uart_online_advances(kind: str) -> tuple[BatchAdvance, ...]:
    paired = BatchAdvance(("uart", "cpu"))
    uart_only = BatchAdvance(("uart",))
    if kind == "cpu":
        return (paired,) * UART_CPU_FRAGMENT_TICKS
    if kind == "rx":
        return ((uart_only,) * UART_RX_READY_TICKS
                + (paired,) * UART_ISR_CPU_TICKS)
    if kind == "warmup":
        return ((paired,) * UART_CPU_FRAGMENT_TICKS
                + (uart_only,) * (UART_RX_READY_TICKS - UART_CPU_FRAGMENT_TICKS)
                + (paired,) * UART_ISR_CPU_TICKS)
    raise ValueError("unknown UART online advance kind")


def _ownership():
    return compile_ownership(
        (InputField("cpu", "irq", 1), InputField("uart", "uart_rx_byte", 8)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "uart.uart_rx_watermark"),
         InputOwner("uart", "uart_rx_byte", 0, 8, "source", "external_uart_rx_byte")))


def make_ibex_uart_online_factory(cache_dir: Path, *, cpu_retirement: bool = False,
                                  uart_fifo: bool = False,
                                  memory_commit: bool = False,
                                  memory_readback: bool = False):
    """Render source-locked harnesses once; each call creates fresh RTL state."""
    if type(cpu_retirement) is not bool:
        raise ValueError('cpu_retirement must be boolean')
    if type(uart_fifo) is not bool:
        raise ValueError('uart_fifo must be boolean')
    if type(memory_commit) is not bool or memory_commit and not (cpu_retirement and uart_fifo):
        raise ValueError('memory_commit requires CPU retirement and UART FIFO probes')
    if type(memory_readback) is not bool or memory_readback and not memory_commit:
        raise ValueError('memory_readback requires live memory commits')
    cpu_artifact = _artifact(RVFI_CPU_PROFILE if cpu_retirement else CPU_PROFILE, "cpu")
    uart_artifact = _artifact(UART_FIFO_PROFILE if uart_fifo else UART_PROFILE, "uart")
    cache_dir = Path(cache_dir)

    def factory() -> ScenarioRunner:
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x10000, 0x30000),),
            initialization_seed=47, max_initialized_bytes=0x30000)
        uart = GeneratedOpentitanUartSession(
            uart_artifact, base_dir=ROOT, cache_dir=cache_dir,
            source=None, cpu_routed_mode=True)
        router = DataflowRouter((DeviceWindow("uart", UART_BASE, 0x1000, uart),))
        cpu = GeneratedCve2Session(
            cpu_artifact, base_dir=ROOT, cache_dir=cache_dir,
            memory=memory, router=router, defer_mmio=True,
            native_irq_receipts=cpu_retirement and uart_fifo,
            memory_commit_receipts=memory_commit,
            memory_readback_receipts=memory_readback)
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "uart": uart}, ownership=_ownership(),
            bindings=(Binding("uart", "uart_rx_watermark", "cpu", "irq", 1),))
        if cpu_retirement and uart_fifo:
            runner.configure_controlled_irq_bootstrap(make_ibex_uart_online_bootstrap(
                memory_readback=memory_readback))
        return runner

    return factory


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _csrrs(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _jal(pc: int, destination: int) -> int:
    offset = destination - pc
    if offset % 2 or not -(1 << 20) <= offset < 1 << 20:
        raise ValueError("online UART instruction slot exceeds JAL reach")
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 |
            ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 | 0x6f)


def _image(image_id: str, address: int, words) -> MemoryImage:
    return MemoryImage(image_id, "cpu", address,
                       b"".join(word.to_bytes(4, "little") for word in words).hex())


@dataclass(frozen=True)
class IbexUartOnlineBootstrap:
    template: ScenarioGenome
    instruction_start: int
    instruction_end: int

    @property
    def instruction_count(self) -> int:
        return (self.instruction_end - self.instruction_start) // 4


@dataclass(frozen=True)
class UartTargetWrite:
    """One real MMIO write a decoded instruction fragment would issue."""

    operation: str
    address: int
    value: int
    byte_enable: int


def _sign_extend_12(bits: int) -> int:
    return bits - 0x1000 if bits & 0x800 else bits


def instruction_mmio_writes(data: bytes) -> tuple[UartTargetWrite, ...]:
    """Resolve every MMIO store one generated RV32I fragment would issue.

    Only the template this decoder emits is evaluated: ``LUI``/``ADDI``
    materialize a register, and a store delivers that register with the lane
    byte enable its own funct3 declares.  The resolved write keeps the whole
    data register and that strobe, exactly as the Router forwards them, so the
    target's declared register field judges the enabled lane bytes and nothing
    else -- the same rule the runtime refusal applies.  A fragment that is not
    whole words, a store width outside the admitted subset, or a store whose
    address or data the same fragment never materializes is refused fail-closed
    instead of being guessed to be legal.
    """
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) % 4:
        reject(RejectionCode.DECODE_MALFORMED_RECORD,
               "instruction fragment must be a nonempty sequence of words",
               "instruction.fragment",
               length=(len(data) if isinstance(data, (bytes, bytearray)) else data))
    registers: dict[int, int | None] = {}
    writes: list[UartTargetWrite] = []
    for index in range(0, len(data), 4):
        word = int.from_bytes(data[index:index + 4], "little")
        opcode = word & 0x7F
        destination = (word >> 7) & 0x1F
        if opcode == 0x37:  # LUI
            registers[destination] = word & 0xFFFFF000
            continue
        if opcode == 0x13 and (word >> 12) & 7 == 0:  # ADDI
            base = registers.get((word >> 15) & 0x1F)
            immediate = _sign_extend_12((word >> 20) & 0xFFF)
            registers[destination] = (None if base is None
                                      else (base + immediate) & 0xFFFFFFFF)
            continue
        if opcode == 0x67 or opcode == 0x6F or opcode == 0x17:
            # JALR/JAL/AUIPC write a position-dependent or unknown value.
            registers[destination] = None
            continue
        if opcode in (0x03, 0x13, 0x33, 0x73):
            # Loads, non-ADDI immediates, register operations and CSR reads
            # overwrite their destination with a value this fragment does not
            # determine.
            registers[destination] = None
            continue
        if opcode != 0x23:  # STORE
            continue
        funct3 = (word >> 12) & 7
        if funct3 not in _STORE_WRITES:
            reject(RejectionCode.ISA_DISALLOWED_OPERATION,
                   "store width is outside the admitted RV32I subset",
                   "instruction.fragment",
                   instruction=word.to_bytes(4, "little").hex())
        operation, byte_enable = _STORE_WRITES[funct3]
        base = registers.get((word >> 15) & 0x1F)
        value = registers.get((word >> 20) & 0x1F)
        if base is None or value is None:
            reject(RejectionCode.MMIO_WINDOW_DENIED,
                   "store target is not materialized by this fragment",
                   "mmio.address", reason="store_target_unresolved",
                   fragment=bytes(data).hex())
        offset = ((word >> 25) << 5) | ((word >> 7) & 0x1F)
        writes.append(UartTargetWrite(operation, (base + offset) & 0xFFFFFFFF,
                                      value, byte_enable))
    return tuple(writes)


def uart_write_rejection(write: UartTargetWrite) -> Rejection | None:
    """Classify one real target write against the declared UART write contract.

    The three declared fields of the session's ``write_register`` are reported
    separately: an offset outside the declared register map is a denied window,
    a strobe the register does not declare is a bad width, and the register word
    the enabled lanes really write, outside the declared field, is a bad stored
    value.  Only the enabled lanes are judged, because the pinned target writes
    exactly those (``be=1`` writes lane 0 alone).  A write outside the UART
    aperture belongs to another declared device and is left to the Router.
    """
    if type(write) is not UartTargetWrite:
        reject(RejectionCode.DECODE_MALFORMED_RECORD,
               "target write must be a resolved MMIO store", "mmio.operation")
    offset = write.address - UART_BASE
    if not 0 <= offset < UART_APERTURE_SIZE:
        return None
    denial = uart_register_write_denial(offset, write.value, write.byte_enable)
    if denial is None:
        return None
    rule = UART_REGISTER_WRITES_BY_OFFSET.get(offset)
    detail = {"address": write.address, "offset": offset,
              "operation": write.operation}
    if denial == "register":
        return Rejection(RejectionCode.MMIO_WINDOW_DENIED, "mmio.address",
                         {**detail, "declared_offsets": sorted(
                             UART_REGISTER_WRITES_BY_OFFSET)})
    if denial == "byte_enable":
        return Rejection(RejectionCode.MMIO_BAD_WIDTH, "mmio.width",
                         {**detail, "register": rule.name,
                          "byte_enable": write.byte_enable,
                          "declared_byte_enables": list(rule.byte_enables)})
    return Rejection(RejectionCode.FIELD_BAD_IMMEDIATE, "mmio.value",
                     {**detail, "register": rule.name, "value": write.value,
                      "byte_enable": write.byte_enable,
                      "enabled_value": rule.written_value(
                          write.value, write.byte_enable),
                      "declared_values": rule.declared_values})


def uart_fragment_rejection(data: bytes) -> Rejection | None:
    """Refuse one decoded instruction fragment the UART target does not support.

    A fragment whose real write cannot even be resolved is refused with the
    resolver's own fail-closed rejection.
    """
    try:
        writes = instruction_mmio_writes(data)
    except RejectionError as error:
        return error.rejection
    for write in writes:
        rejection = uart_write_rejection(write)
        if rejection is not None:
            return rejection
    return None


def uart_case_rejection(case) -> Rejection | None:
    """Refuse one decoded case whose real target writes are unsupported.

    Every instruction fragment the candidate would materialize is resolved from
    its own bytes; support instructions count too, because they occupy the same
    reserved slot.  A case with no MMIO store is never refused here.
    """
    fragments = []
    if isinstance(getattr(case, "source", None), OnlineInstruction):
        fragments.append(case.source)
    fragments.extend(getattr(case, "support_instructions", ()))
    for fragment in fragments:
        try:
            data = bytes.fromhex(fragment.data_hex)
        except (TypeError, ValueError):
            reject(RejectionCode.DECODE_MALFORMED_RECORD,
                   "decoded instruction fragment is not hex words",
                   "instruction.fragment", address=fragment.address)
        rejection = uart_fragment_rejection(data)
        if rejection is not None:
            return rejection
    return None


class UartOnlineCaseDecoder(OnlineCaseDecoder):
    """Keep CPU mutations inside the UART TXDATA and fixed-ISR contract."""

    def document(self) -> dict:
        document = super().document()
        document["uart_local_schedule"] = {
            "schema_version": "ibex_uart_local_schedule.v1",
            "clocks_per_bit": UART_CLOCKS_PER_BIT,
            "idle_bits": UART_IDLE_BITS,
            "frame_bits": UART_FRAME_BITS,
            "rx_settle_ticks": UART_RX_SETTLE_TICKS,
            "cpu_fragment_ticks": UART_CPU_FRAGMENT_TICKS,
            "isr_cpu_ticks": UART_ISR_CPU_TICKS,
            "rx_ready_ticks": UART_RX_READY_TICKS,
        }
        return document

    def decode_candidate(self, raw: bytes, *, coverage_hints=None
                         ) -> tuple[object, CandidateDisposition]:
        """Decode one candidate and refuse unsupported target writes first.

        The declared window and operation set make the fragment legal for the
        decoder, but the UART target additionally declares which register
        writes it supports: offset, byte-enable strobe and register word.  The
        real store the fragment would issue is resolved from its own bytes, so
        a candidate the session would refuse on arrival becomes a clean
        ``candidate_rejection.v1`` refusal before any RTL command.
        """
        case, disposition = super().decode_candidate(
            raw, coverage_hints=coverage_hints)
        if case is None:
            return case, disposition
        rejection = uart_case_rejection(case)
        if rejection is None:
            return case, disposition
        # No command was issued for this fragment: the refusal consumes no
        # reservation, so the refused case is not the current proposal either.
        self._proposal = None
        return None, CandidateDisposition("rejected", "decode_rejected", None,
                                          rejection)

    def decode(self, raw: bytes, *, coverage_hints=None):
        case = super().decode(raw, coverage_hints=coverage_hints)
        if not isinstance(case.source, OnlineInstruction):
            case = replace(case, advances=uart_online_advances("rx"))
            self._proposal = case
            return case
        choice = raw[3] % 4 if len(raw) > 3 else 0
        byte = raw[4] if len(raw) > 4 else 0
        if choice == 0:
            words = (Rv32iInstruction("NOP"),)
        elif choice == 1:
            immediate = int.from_bytes(raw[4:7], "little") & 0xfffff
            words = (Rv32iInstruction("LUI", rd=10, immediate=immediate),)
        elif choice == 2:
            immediate = int.from_bytes(raw[4:6], "little") & 0xfff
            immediate = immediate - 0x1000 if immediate & 0x800 else immediate
            words = (Rv32iInstruction("ADDI", rd=10, rs1=10,
                                      immediate=immediate),)
        else:
            words = mmio_write_fragment(
                "SB" if self._uart_wdata_byte_store else "SW",
                UART_BASE + 0x1c, byte,
                windows=self.windows, base_register=1, data_register=2)
        source = replace(case.source, data_hex=fragment_bytes(words).hex())
        if source.address + len(source.data) > self.instruction_end:
            source = replace(case.source, data_hex=fragment_bytes(
                (Rv32iInstruction("NOP"),)).hex())
        case = replace(case, source=source,
                       advances=uart_online_advances("cpu"))
        self._proposal = case
        # The same pre-RTL write gate guards direct decode callers: a store the
        # UART target does not declare may never be proposed for admission.
        rejection = uart_case_rejection(case)
        if rejection is not None:
            self._proposal = None
            raise RejectionError(
                f"UART candidate write refused: {rejection.code}@{rejection.pointer}",
                rejection)
        return case


def make_ibex_uart_online_bootstrap(*, instruction_start: int = 0x11000,
                                    instruction_end: int = 0x20000,
                                    memory_readback: bool = False
                                    ) -> IbexUartOnlineBootstrap:
    if (type(instruction_start) is not int or type(instruction_end) is not int
            or instruction_start % 4 or instruction_end % 4
            or not 0x11000 <= instruction_start < instruction_end <= 0x20000):
        raise ValueError("UART online instructions must fit before result RAM")
    if type(memory_readback) is not bool:
        raise ValueError('memory_readback must be boolean')
    main = [
        _lui(1, 0x40000),
        _lui(2, 0x80000), _addi(2, 2, 3), _sw(2, 1, 0x10),
        _addi(2, 0, 2), _sw(2, 1, 0x04),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
    ]
    main.append(_jal(0x10080 + len(main) * 4, instruction_start))
    isr = [*((0x00000013,) * (62 if memory_readback else 64))]
    if memory_readback:
        isr.extend((_lui(5, 0x20), _lw(6, 5, 0)))
    isr.extend((_lw(4, 1, 0x00), _lw(3, 1, 0x18),
           _lui(5, 0x20), _sw(3, 5, 0), _sw(4, 5, 4), 0x30200073))
    template = ScenarioGenome(
        testcase_id="ibex-uart-online-stream", direction="MULTI_COMPONENT_CHAIN",
        path_id="ibex-uart-dual-source-stream", schedule_order=("uart", "cpu"),
        max_steps=2400, actions=(), initial_images=(
            _image("cpu.main", 0x10080, main),
            _image("cpu.isr", 0x1012c, isr),
            MemoryImage("cpu.result", "cpu", RESULT_ADDRESS,
                        "0000000000000000")))
    return IbexUartOnlineBootstrap(template, instruction_start, instruction_end)


def make_ibex_uart_online_decoder(*, bootstrap: IbexUartOnlineBootstrap,
                                   uart_wdata_byte_store: bool = False
                                  ) -> OnlineCaseDecoder:
    if type(uart_wdata_byte_store) is not bool:
        raise ValueError('UART WDATA byte store opt-in must be boolean')
    cpu_id, rx_id = "cpu.online_instruction", "uart.external_rx_byte"
    cpu_path, rx_path = "cpu_to_uart_tx", "uart_rx_to_cpu"
    graph = OnlineDependencyGraph(
        sources=(
            OnlineDependencySource(cpu_id, "instruction", "cpu", ("CPU_TO_IP",)),
            OnlineDependencySource(rx_id, "source", "uart", ("IP_TO_CPU",),
                                   port="uart_rx_byte", width=8)),
        rules=(
            DependencyRule("uart.tx_fifo", (cpu_id,), "PERSISTENT_STATE_RULE"),
            DependencyRule(cpu_path, ("uart.tx_fifo",), "EVENT_ORDER"),
            DependencyRule("uart.rx_frame", (rx_id,), "ENV_PRECONDITION"),
            DependencyRule("uart.rx_fifo", ("uart.rx_frame",), "PERSISTENT_STATE_RULE"),
            DependencyRule("uart.rx_watermark", ("uart.rx_fifo",), "EVENT_ORDER"),
            DependencyRule("cpu.uart_irq", ("uart.rx_watermark",), "EVENT_ORDER"),
            DependencyRule("uart.rx_fifo_read", ("cpu.uart_irq",), "EVENT_ORDER"),
            DependencyRule("cpu.uart_read", ("uart.rx_fifo_read",), "DATA_BINDING"),
            DependencyRule(rx_path, ("cpu.uart_read",), "EVENT_ORDER")))
    nodes = (
        RuntimeNode(cpu_id, 'cpu', 'logical'), RuntimeNode(rx_id, 'uart', 'physical', 'uart_rx_byte', 0, 8),
        RuntimeNode('uart.tx_fifo', 'uart', 'state'), RuntimeNode(cpu_path, 'uart', 'logical'),
        RuntimeNode('uart.rx_frame', 'uart', 'logical'), RuntimeNode('uart.rx_fifo', 'uart', 'state'),
        RuntimeNode('uart.rx_watermark', 'uart', 'physical', 'uart_rx_watermark', 0, 1),
        RuntimeNode('cpu.uart_irq', 'cpu', 'physical', 'irq', 0, 1),
        RuntimeNode('uart.rx_fifo_read', 'uart', 'logical'), RuntimeNode('cpu.uart_read', 'cpu', 'logical'),
        RuntimeNode(rx_path, 'cpu', 'logical'))
    edges = tuple(RuntimeEdgeContract(index, 0, 'mmio_route', 'cpu', 'uart', UART_BASE, 0x1000)
                  for index in (0, 6, 7)) + (RuntimeEdgeContract(5, 0, 'direct_binding'),)
    graph_hash = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    contract = RuntimePathContract(graph_hash, nodes, edges)
    decoder = UartOnlineCaseDecoder(
        sources=(
            OnlineSource(cpu_id, "instruction", "cpu", "CPU_TO_IP", cpu_path,
                         coverage_target_ids=("uart_tx_activity", "cpu_data_write")),
            OnlineSource(rx_id, "source", "uart", "IP_TO_CPU", rx_path,
                         port="uart_rx_byte", width=8,
                         coverage_target_ids=("uart_rx_irq", "cpu_uart_vector_fetch"))),
        graph=graph, runtime_contract=contract, ownership=_ownership(), schedule=bootstrap.template.schedule_order,
        flow_by_target={cpu_path: "F4", rx_path: "F5"},
        instruction_start=bootstrap.instruction_start,
        instruction_end=bootstrap.instruction_end,
        windows=(MmioWindow(UART_BASE + 0x1c, 1 if uart_wdata_byte_store else 4,
                            write_widths=(1,) if uart_wdata_byte_store else (4,)),),
        max_steps=bootstrap.template.max_steps, max_input_bytes=8,
        advance_rounds=UART_CPU_FRAGMENT_TICKS,
        allowed_mmio_operations=("SB",) if uart_wdata_byte_store else ("SW",),
        support_words=4)
    decoder._uart_wdata_byte_store = uart_wdata_byte_store
    return decoder
