"""UART online MMIO candidates are judged by the byte lanes they really write.

Real evidence: ``runs/p5-uart-gate-20261007-online`` stopped after three cases
on ``ValueError: unsupported UART register write`` (failure artifact
``failures/online_uncertain_effect_7b098af9_1_1_604caae5c07e4c77.json``).  The
candidate's own fragment ``37b1c30c13016100b7000040238e2000`` loads
``x2 = 0x0CC3B006`` and issues ``SB x2, 0x1c(x1)``, i.e. one enabled byte lane
(``be=1``) at the UART ``WDATA`` register.

The pinned target writes exactly the enabled lanes: ``tlul_adapter_reg.sv``
forwards ``a_data``/``a_mask`` unchanged, ``uart_reg_top.sv`` takes a ``DW(8)``
field from ``reg_wdata[7:0]``, and the P4 SB gate measured ``be=1`` delivering
the real serial byte ``0x0c``.  The declared ``WDATA`` field therefore judges
the enabled lane bytes, not the unused ones: the real failing candidate is
admitted and writes byte ``0x06``, while a whole-word write (``be=15``) whose
word leaves the eight-bit field is refused before any RTL command.

These tests use no RTL: offline harness stubs, the real decoder declarations and
one bare real session instance with a recording transport prove acceptance,
refusal, zero state change, and that the next slot is still accepted.
"""

from __future__ import annotations

import json

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.local_harness.opentitan_uart_session import (
    UART_REGISTER_WRITES, GeneratedOpentitanUartSession, enabled_write_mask,
    uart_register_write_denial, uart_register_write_supported)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_uart_online import (
    UART_BASE, UartTargetWrite, make_ibex_uart_online_bootstrap,
    make_ibex_uart_online_decoder)
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
from myfuzz.scenario.rejection_codes import Rejection, RejectionCode
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.rv32i_sources import (MmioWindow, Rv32iInstruction,
                                           fragment_bytes, mmio_write_fragment)
from myfuzz.scenario.session_runtime import ScenarioSession

#: The real record of slot 2 in runs/p5-uart-gate-20261007-online.
REAL_FAILURE_RAW = bytes.fromhex("000000c30c0106b0")
#: The exact fragment that record decoded to (online_case.source.data_hex).
REAL_FAILURE_FRAGMENT = bytes.fromhex("37b1c30c13016100b7000040238e2000")
#: x2 = LUI 0x0cc3b + ADDI 6; SB enables lane 0 only.
REAL_FAILURE_VALUE = 0x0CC3B006
#: The real write the fragment issues, and the byte lane 0 really receives.
REAL_FAILURE_WRITE = UartTargetWrite("SB", UART_BASE + 0x1C, REAL_FAILURE_VALUE, 1)
REAL_FAILURE_BYTE = REAL_FAILURE_VALUE & 0xFF

WDATA = UART_BASE + 0x1C
#: A whole-word write to the eight-bit field: the shipped decoder without the
#: ``--uart-wdata-byte-store`` opt-in declares exactly this SW shape.
WORD_WRITE_REJECTION = {
    "schema_version": "candidate_rejection.v1",
    "code": "field.bad_immediate",
    "pointer": "mmio.value",
    "detail": {"address": WDATA, "byte_enable": 15, "declared_values": [0, 255],
               "enabled_value": REAL_FAILURE_VALUE, "offset": 0x1C,
               "operation": "SW", "register": "WDATA", "value": REAL_FAILURE_VALUE},
}


class _OfflineHarness:
    """Offline local harness: records instructions and source actions only."""

    def __init__(self) -> None:
        self.accepted: list[tuple[int, bytes, str]] = []
        self.injected: list[tuple[str, int, int, int, str]] = []
        self.cases: list[str] = []
        self.slots: tuple[int, int] | None = None

    def begin_case(self, testcase_id: str) -> None:
        self.cases.append(testcase_id)

    def step_local(self, inputs):
        return {}

    def end_case(self) -> None:
        pass

    def declare_instruction_slots(self, address: int, count: int) -> None:
        self.slots = (address, count)

    def accept_instructions(self, address: int, data: bytes, *,
                            source_event_id: str) -> None:
        self.accepted.append((address, bytes(data), source_event_id))

    def admit_source_event(self, port: str, value: int, *, bit_offset: int,
                           width: int, action_id: str) -> None:
        self.injected.append((port, value, bit_offset, width, action_id))
        return None


def _uart_executor(*, uart_wdata_byte_store: bool = True):
    """Wire the real UART online decoder around offline harness stubs.

    The declarations match the real runtime: one Router window over the UART
    aperture, the watermark binding, the instruction reservation and the
    configured runtime paths.  No RTL command can run here.
    """
    bootstrap = make_ibex_uart_online_bootstrap()
    decoder = make_ibex_uart_online_decoder(
        bootstrap=bootstrap, uart_wdata_byte_store=uart_wdata_byte_store)
    sessions = {name: _OfflineHarness() for name in ("uart", "cpu")}
    sessions["cpu"].router = DataflowRouter(
        (DeviceWindow("uart", UART_BASE, 0x1000, sessions["uart"]),))
    template = ScenarioGenome(
        testcase_id="ibex-uart-gate-seed", direction="MULTI_COMPONENT_CHAIN",
        path_id="ibex-uart-dual-source-stream", schedule_order=("uart", "cpu"),
        max_steps=2400, actions=())
    runner = ScenarioRunner(
        sessions=sessions, ownership=decoder.ownership,
        bindings=(Binding("uart", "uart_rx_watermark", "cpu", "irq", 1),))
    session = ScenarioSession(template, runner, checker=lambda receipt: ())
    session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    targets = (
        CoverageTarget("uart_tx_activity", "uart", "serial_tx_count", 1, 1),
        CoverageTarget("uart_rx_irq", "uart", "uart_rx_watermark", 1, 1),
        CoverageTarget("cpu_uart_vector_fetch", "cpu", "instr_addr",
                       0xFFFFFFFF, 0x1012C),
        CoverageTarget("cpu_data_write", "cpu", "data_writes", 1, 1))
    executor = ScenarioRfuzzExecutor(
        run_id="uart-candidate-rejection", factory=lambda: runner, targets=targets,
        session=session, online_decoder=decoder)
    return executor, sessions, decoder


def _instruction_writes(fragment: bytes):
    from myfuzz.scenario.ibex_uart_online import instruction_mmio_writes
    return instruction_mmio_writes(fragment)


def _gate_fragment(fragment: bytes) -> Rejection | None:
    from myfuzz.scenario.ibex_uart_online import uart_fragment_rejection
    return uart_fragment_rejection(fragment)


def _gate_write(offset: int, value: int, byte_enable: int) -> Rejection | None:
    from myfuzz.scenario.ibex_uart_online import uart_write_rejection
    # RV32I store widths, plus a neutral label for strobes no store emits.
    operation = {1: "SB", 3: "SH", 15: "SW"}.get(byte_enable, "STORE")
    return uart_write_rejection(
        UartTargetWrite(operation, UART_BASE + offset, value, byte_enable))


def _runtime_write(offset: int, value: int, *, be: int):
    """Run the real session refusal on a bare instance, recording the transport.

    Only ``_access`` is replaced: the acceptance decision and the exact
    ``(write, offset, value, byte_enable)`` the real target would receive are
    the shipped ones.
    """
    session = object.__new__(GeneratedOpentitanUartSession)
    calls = []
    session._access = lambda write, offset_, value_, be_: calls.append(
        (write, offset_, value_, be_))
    session.write_register(offset, value, be=be)
    return calls


# --------------------------------------------------------------------------
# The real failing candidate is admitted and writes its one enabled byte
# --------------------------------------------------------------------------

def test_real_failure_candidate_is_admitted_as_a_lane_zero_byte_write():
    executor, sessions, _decoder = _uart_executor(uart_wdata_byte_store=True)
    executor.execute_batch(InputBatch(0, 8, ((REAL_FAILURE_RAW,),)))

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == "complete"
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert decision["candidate_disposition"] == "admitted"
    assert decision["candidate_disposition_reason"] == "rtl_case_committed"
    assert decision["committed"] is True
    assert decision["operator_id"] == "rv32i:LUI+ADDI+LUI+SB"
    assert decision["source_id"] == "cpu.online_instruction"
    # The very fragment the real run submitted reached the CPU harness.
    accepted = sessions["cpu"].accepted
    assert len(accepted) == 1 and accepted[0][1] == REAL_FAILURE_FRAGMENT
    assert len(executor.session.cases) == 1
    assert executor._session_stop_reason is None
    # It carries exactly one real target write: SB lane 0 at WDATA.
    write, = _instruction_writes(REAL_FAILURE_FRAGMENT)
    assert write == REAL_FAILURE_WRITE
    assert _gate_write(0x1C, write.value, write.byte_enable) is None
    assert enabled_write_mask(write.byte_enable) == 0xFF
    assert write.value & enabled_write_mask(write.byte_enable) == REAL_FAILURE_BYTE


def test_real_write_register_accepts_the_lane_zero_word_and_keeps_its_byte():
    """The runtime refusal accepts it and hands the target the same beat."""
    calls = _runtime_write(0x1C, REAL_FAILURE_VALUE, be=1)
    assert calls == [(True, 0x1C, REAL_FAILURE_VALUE, 1)]
    assert calls[0][2] & enabled_write_mask(calls[0][3]) == REAL_FAILURE_BYTE
    # Writes the old acceptance already admitted keep the same delivered beat.
    assert _runtime_write(0x1C, 0x0C, be=1) == [(True, 0x1C, 0x0C, 1)]
    assert _runtime_write(0x1C, 0x0C, be=15) == [(True, 0x1C, 0x0C, 15)]
    assert _runtime_write(0x10, 0x80000003, be=15) == [
        (True, 0x10, 0x80000003, 15)]
    # A whole word that leaves the eight-bit field is still refused.
    try:
        _runtime_write(0x1C, REAL_FAILURE_VALUE, be=15)
    except ValueError as error:
        assert "unsupported UART register write" in str(error)
    else:
        raise AssertionError("a whole-word write above 0xFF is not declared")


# --------------------------------------------------------------------------
# The whole-word write to the same field is still refused before any RTL
# --------------------------------------------------------------------------

def test_real_word_write_to_the_byte_field_is_refused_before_any_rtl_command():
    executor, sessions, decoder = _uart_executor(uart_wdata_byte_store=False)
    cursor = decoder.instruction_cursor
    events_before = executor.session.runner.events_since(0)
    ticks_before = dict(executor.session.runner.local_ticks)
    delivered = []
    executor.execute_batch(InputBatch(0, 8, ((REAL_FAILURE_RAW,),)),
                           on_receipt=delivered.append)

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == "input_invalid"
    assert receipt.rejection == WORD_WRITE_REJECTION
    assert set(receipt.rejection) == {"schema_version", "code", "pointer", "detail"}
    assert json.loads(json.dumps(receipt.rejection)) == receipt.rejection
    assert Rejection.from_document(receipt.rejection).code is (
        RejectionCode.FIELD_BAD_IMMEDIATE)
    assert decision["rejection"] == receipt.rejection
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "decode_rejected"
    assert decision["admitted_status"] == "not_admitted"
    assert decision["committed"] is False
    assert decision["case_id"] is None
    assert delivered == [receipt]
    # Nothing reached the harnesses or the session.
    assert all(session.accepted == [] for session in sessions.values())
    assert all(session.injected == [] for session in sessions.values())
    assert executor.session.cases == ()
    assert executor.session.runner.events_since(0) == events_before == ()
    assert dict(executor.session.runner.local_ticks) == ticks_before == {
        "cpu": 0, "uart": 0}
    assert receipt.total_local_ticks == 0
    assert receipt.online_case is None
    assert receipt.trace is None
    # The reservation and the decoder sequence are untouched, and the session
    # keeps running instead of stopping on an uncertain effect.
    assert decoder.instruction_cursor == cursor
    assert decoder._sequence == 0
    assert decoder._proposal is None
    assert executor._session_stop_reason is None
    assert executor.session._halt_reason is None


def test_refused_word_write_does_not_stop_the_next_slot():
    executor, sessions, decoder = _uart_executor(uart_wdata_byte_store=False)
    cursor = decoder.instruction_cursor
    nop_raw = bytes((0, 0, 0, 0, 0, 0, 0, 0))
    executor.execute_batch(InputBatch(1, 8, ((REAL_FAILURE_RAW,), (nop_raw,))),
                           on_receipt=lambda _receipt: None)

    refused, admitted = executor.receipts[-2:]
    assert refused.status == "input_invalid"
    assert refused.rejection == WORD_WRITE_REJECTION
    assert admitted.status == "complete"
    assert admitted.rejection is None
    assert len(executor.session.cases) == 1
    accepted = sessions["cpu"].accepted
    assert len(accepted) == 1
    instructions = accepted[0][1]
    assert instructions and len(instructions) % 4 == 0
    assert all(int.from_bytes(instructions[index:index + 4], "little")
               == 0x00000013 for index in range(0, len(instructions), 4))
    assert decoder.instruction_cursor == cursor + len(instructions)
    assert decoder._sequence == 1
    assert executor._session_stop_reason is None


# --------------------------------------------------------------------------
# The declared field judges the enabled lanes only
# --------------------------------------------------------------------------

def test_wdata_byte_writes_are_judged_by_their_enabled_lane():
    """be=1 writes lane 0 alone: any unused high byte is irrelevant."""
    for value in (0x00, 0x01, 0x7F, 0x80, 0xFF, 0x100, 0x0203B006,
                  REAL_FAILURE_VALUE, 0xFFFFFFFF):
        assert uart_register_write_supported(0x1C, value, 1), hex(value)
        assert _gate_write(0x1C, value, 1) is None, hex(value)


def test_wdata_word_writes_must_stay_inside_the_eight_bit_field():
    """be=15 writes every lane, so the whole word must fit the field."""
    for value in (0x00, 0x01, 0x0C, 0x7F, 0x80, 0xFF):
        assert uart_register_write_supported(0x1C, value, 15), hex(value)
        assert _gate_write(0x1C, value, 15) is None, hex(value)
    for value in (0x100, 0x203, REAL_FAILURE_VALUE, 0xFFFFFFFF):
        assert not uart_register_write_supported(0x1C, value, 15), hex(value)
        rejection = _gate_write(0x1C, value, 15)
        assert rejection is not None
        assert (rejection.code, rejection.pointer) == (
            RejectionCode.FIELD_BAD_IMMEDIATE, "mmio.value")
        assert rejection.document()["detail"]["enabled_value"] == value
    assert {rule.offset for rule in UART_REGISTER_WRITES} == {0x04, 0x10, 0x1C}
    wdata = next(rule for rule in UART_REGISTER_WRITES if rule.offset == 0x1C)
    assert (wdata.name, wdata.byte_enables, wdata.declared_values) == (
        "WDATA", (1, 15), [0, 255])


def test_runtime_write_register_and_the_gate_agree_on_the_same_grid():
    """One declaration, two consumers: acceptance never differs."""
    offsets = (0x00, 0x04, 0x08, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x30)
    byte_enables = (0, 1, 2, 3, 7, 15)
    values = (0, 1, 2, 6, 0xFF, 0x100, 0x203, 0x80000003, 0xFFFFFFFF)
    for offset in offsets:
        for byte_enable in byte_enables:
            for value in values:
                try:
                    _runtime_write(offset, value, be=byte_enable)
                except ValueError as error:
                    assert "unsupported UART register write" in str(error)
                    runtime_accepts = False
                else:
                    runtime_accepts = True
                gate_accepts = _gate_write(offset, value, byte_enable) is None
                assert runtime_accepts is gate_accepts, (
                    hex(offset), byte_enable, hex(value))
                assert runtime_accepts is uart_register_write_supported(
                    offset, value, byte_enable)


def test_unsupported_byte_enable_is_bad_width():
    # A halfword store enables lanes 0 and 1; WDATA declares 1 and 15 only.
    halfword = ((0x1C >> 5) << 25 | 2 << 20 | 1 << 15 | 1 << 12
                | (0x1C & 31) << 7 | 0x23)
    fragment = (b"".join(word.to_bytes(4, "little") for word in (
        0x00000137, 0x00C10113, 0x400000B7, halfword)))
    rejection = _gate_fragment(fragment)
    assert rejection is not None
    assert (rejection.code, rejection.pointer) == (
        RejectionCode.MMIO_BAD_WIDTH, "mmio.width")
    assert rejection.document()["detail"] == {
        "address": WDATA, "byte_enable": 3, "offset": 0x1C,
        "operation": "SH", "register": "WDATA", "declared_byte_enables": [1, 15]}


def test_unsupported_register_offset_is_window_denied():
    # STATUS (0x14) is declared read-only and is not a declared write register.
    fragment = fragment_bytes((
        Rv32iInstruction("LUI", rd=2, immediate=0),
        Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=1),
        Rv32iInstruction("LUI", rd=1, immediate=UART_BASE >> 12),
        Rv32iInstruction("SB", rs1=1, rs2=2, immediate=0x14)))
    rejection = _gate_fragment(fragment)
    assert rejection is not None
    assert (rejection.code, rejection.pointer) == (
        RejectionCode.MMIO_WINDOW_DENIED, "mmio.address")
    assert rejection.document()["detail"] == {
        "address": UART_BASE + 0x14, "offset": 0x14, "operation": "SB",
        "declared_offsets": [0x04, 0x10, 0x1C]}


def test_exact_value_register_reports_its_declared_words():
    """The other declared shape: a register that accepts exact words only."""
    fragment = fragment_bytes((
        Rv32iInstruction("LUI", rd=2, immediate=0),
        Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=7),
        Rv32iInstruction("LUI", rd=1, immediate=UART_BASE >> 12),
        Rv32iInstruction("SW", rs1=1, rs2=2, immediate=0x04)))
    rejection = _gate_fragment(fragment)
    assert rejection is not None
    assert (rejection.code, rejection.pointer) == (
        RejectionCode.FIELD_BAD_IMMEDIATE, "mmio.value")
    assert rejection.document()["detail"] == {
        "address": UART_BASE + 0x04, "byte_enable": 15, "enabled_value": 7,
        "offset": 0x04, "operation": "SW", "register": "INTR_ENABLE", "value": 7,
        "declared_values": [6, 2]}


# --------------------------------------------------------------------------
# Fail-closed resolution and the untouched RX path
# --------------------------------------------------------------------------

def test_store_without_a_resolved_target_is_refused_fail_closed():
    """A store the fragment never materializes may not be guessed as legal."""
    fragment = fragment_bytes((
        Rv32iInstruction("SB", rs1=1, rs2=2, immediate=0x1C),))
    rejection = _gate_fragment(fragment)
    assert rejection is not None
    assert (rejection.code, rejection.pointer) == (
        RejectionCode.MMIO_WINDOW_DENIED, "mmio.address")
    assert rejection.document()["detail"] == {
        "reason": "store_target_unresolved", "fragment": fragment.hex()}
    # A base register overwritten by a shift is no longer the loaded address.
    overwritten = fragment_bytes((
        Rv32iInstruction("LUI", rd=1, immediate=UART_BASE >> 12),
        Rv32iInstruction("SLLI", rd=1, rs1=1, immediate=3),
        Rv32iInstruction("LUI", rd=2, immediate=0),
        Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=1),
        Rv32iInstruction("SB", rs1=1, rs2=2, immediate=0x1C)))
    stale = _gate_fragment(overwritten)
    assert stale is not None
    assert stale.document()["detail"] == {
        "reason": "store_target_unresolved", "fragment": overwritten.hex()}


def test_fragment_outside_the_uart_aperture_is_left_to_the_router():
    """Another device's window is not this target's declaration to police."""
    fragment = fragment_bytes((
        Rv32iInstruction("LUI", rd=2, immediate=0),
        Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=1),
        Rv32iInstruction("LUI", rd=1, immediate=0x40001),
        Rv32iInstruction("SB", rs1=1, rs2=2, immediate=0x00)))
    assert _gate_fragment(fragment) is None


def test_uart_rx_source_case_is_unaffected_by_the_write_gate():
    """The other declared path still commits its own source case."""
    executor, sessions, _decoder = _uart_executor()
    raw = bytes((0, 1, 1, 0, 0x5A, 0, 0, 0))
    executor.execute_batch(InputBatch(2, 8, ((raw,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "complete"
    assert receipt.rejection is None
    assert receipt.online_case["source"]["kind"] == "source_event"
    assert sessions["uart"].injected[0][0] == "uart_rx_byte"
    assert executor._session_stop_reason is None


def test_refused_candidate_is_the_fragment_the_real_run_submitted():
    """The raw record and the judgement are tied to the saved failure artifact."""
    _executor, _sessions, decoder = _uart_executor()
    case, degradation, direct = OnlineCaseDecoder._decode_case(
        decoder, REAL_FAILURE_RAW,
        coverage_hints={"cpu.online_instruction": 104,
                        "uart.external_rx_byte": 104})
    assert (degradation, direct) == (None, True)
    assert case.source.data_hex == REAL_FAILURE_FRAGMENT.hex()
    assert case.source.address == 0x11000
    assert _instruction_writes(REAL_FAILURE_FRAGMENT) == (REAL_FAILURE_WRITE,)
    assert uart_register_write_supported(0x1C, REAL_FAILURE_VALUE, 1)
    assert uart_register_write_denial(0x1C, REAL_FAILURE_VALUE, 1) is None


def test_control_group_supported_byte_write_fragment_is_not_refused():
    """The P4-measured byte write shape passes the same gate."""
    for operation, byte_enable in (("SB", 1), ("SW", 15)):
        words = mmio_write_fragment(
            operation, WDATA, 0x0C,
            windows=(MmioWindow(WDATA, 1 if operation == "SB" else 4,
                                write_widths=(1,) if operation == "SB" else (4,)),),
            base_register=1, data_register=2)
        fragment = fragment_bytes(words)
        write, = _instruction_writes(fragment)
        assert (write.operation, write.address, write.value, write.byte_enable) \
            == (operation, WDATA, 0x0C, byte_enable)
        assert _gate_fragment(fragment) is None
