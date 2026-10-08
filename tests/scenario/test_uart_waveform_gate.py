"""UART 波形互斥的预接纳拒绝门（软件测试，不跑 RTL）。

背景：OpenTitan UART 会话逐位驱动排队的 RX 波形，其 `_access` 会拒绝与之重叠的
TL-UL 寄存器访问（`TL-UL access during serial source waveform is unsupported`）。
在线路径上这个拒绝发生在**已提交的 case 内部**，于是整个会话以 `uncertain_effect`
停机。本门把同一谓词提前到任何 RTL 命令之前：重叠的 CPU MMIO 候选成为一次不消耗
的 pre-RTL 拒绝，会话继续。

本文件覆盖：片段 MMIO 访问解码、窗口判定、会话谓词的精确复用、拒绝形状（可被
executor 记录为 source-action refusal）、以及"不重叠/非 CPU/非 MMIO 时不得拒绝"。
"""

from __future__ import annotations

import pytest

from myfuzz.scenario.rv32i_sources import (
    MmioWindow,
    fragment_bytes,
    mmio_access_fragment,
)
from myfuzz.scenario.source_actions import (
    SourceAction,
    SourceActionPrerequisiteError,
    TerminationObservation,
)
from myfuzz.scenario.uart_waveform_gate import (
    UART_WAVEFORM_CONFLICT_REASON,
    UartWaveformAdmissionGate,
    fragment_mmio_accesses,
)

UART_BASE = 0x40000000
WINDOW = (UART_BASE, 0x1000)


class _Session:
    """A session stub whose only job is the shipped overlap answer."""

    def __init__(self, conflict=None):
        self._conflict = conflict
        self.queries = 0

    def register_access_conflict(self):
        self.queries += 1
        return self._conflict


def _action(*, words: bytes, component: str = "cpu",
            action_id: str = "case-1:cpu.online_instruction") -> SourceAction:
    return SourceAction(
        action_id=action_id, kind="instruction", component=component,
        source_id="cpu.online_instruction", ownership="fuzzable", flow_id="F4",
        payload={"address": 0x11000, "words_hex": words.hex()},
        termination_observation=TerminationObservation("retirement",
                                                       f"rvfi:{action_id}"),
        local_step_budget=64)


def _uart_access_words() -> bytes:
    fragment = mmio_access_fragment("LW", UART_BASE + 0x18,
                                    windows=(MmioWindow(UART_BASE, 0x1000),),
                                    base_register=3, data_register=2)
    return fragment_bytes(fragment)


def test_fragment_accesses_are_decoded_from_the_words():
    words = _uart_access_words()
    accesses = fragment_mmio_accesses(words)
    assert accesses == ({"operation": "LW", "address": UART_BASE + 0x18,
                         "word_offset": 4},)


def test_fragment_without_an_access_yields_nothing():
    # A single ADDI: no LUI base, no load/store.
    assert fragment_mmio_accesses(bytes.fromhex("13000000")) == ()
    with pytest.raises(ValueError):
        fragment_mmio_accesses(bytes.fromhex("1300"))


def _word(value: int) -> bytes:
    return value.to_bytes(4, "little")


def test_a_store_offset_uses_the_s_type_immediate_not_the_i_type_one():
    """A store is an S-type word: imm[11:5] in 31:25 and imm[4:0] in 11:7.

    Reading a store as I-type (bits 31:20) folds ``rs2`` into the address and
    drops ``imm[4:0]``.  For the shipped UART TXDATA fragment
    (``LUI x1, 0x40000`` + ``SB x2, 0x1c(x1)``, word ``0x00208e23``) that
    produced ``0x40000002`` instead of the real ``UART_BASE + 0x1c``, i.e. an
    address that only accidentally stayed inside the declared window.  The
    assertions below pin the real encoding, decoded independently here.
    """
    store = 0x00208E23  # SB x2, 0x1c(x1)
    assert store & 0x7F == 0x23 and (store >> 12) & 0x7 == 0x0
    assert ((store >> 25) & 0x7F) << 5 == 0x000
    assert (store >> 7) & 0x1F == 0x1C
    assert (store >> 20) & 0xFFF == 0x002  # what the I-type reading saw
    accesses = fragment_mmio_accesses(_word(0x400000B7) + _word(store))
    assert accesses == ({"operation": "SB", "address": UART_BASE + 0x1C,
                         "word_offset": 4},)
    # A word store at offset 0 keeps its zero offset and must not pick up rs2.
    assert fragment_mmio_accesses(
        _word(0x400000B7) + _word(0x0020A023)) == (
        {"operation": "SW", "address": UART_BASE, "word_offset": 4},)
    # A negative store offset sign-extends from the S-type immediate.
    assert fragment_mmio_accesses(
        _word(0x400000B7) + _word(0xFE20AE23)) == (
        {"operation": "SW", "address": UART_BASE - 4, "word_offset": 4},)
    # The load shape is I-type and must keep decoding exactly as before.
    assert fragment_mmio_accesses(
        _word(0x400000B7) + _word(0x0180A183)) == (
        {"operation": "LW", "address": UART_BASE + 0x18, "word_offset": 4},)


def test_a_conflicting_uart_access_is_refused_before_any_rtl():
    session = _Session({"local_tick": 120, "horizon_tick": 128,
                        "source_start_tick": 100, "source_end_tick": 200})
    gate = UartWaveformAdmissionGate(session=session, window=WINDOW)
    action = _action(words=_uart_access_words())

    gate.register(action)
    with pytest.raises(SourceActionPrerequisiteError) as refusal:
        gate.require_case(object())

    evaluation = refusal.value.evaluation
    assert evaluation.reason == UART_WAVEFORM_CONFLICT_REASON
    missing, = evaluation.missing
    assert missing.kind == "transport_idle"
    assert missing.subject == {"transport": "uart_rx_waveform",
                               "local_tick": 120, "horizon_tick": 128}
    assert gate.document()["refusals"] == 1
    assert session.queries == 1


def test_the_same_candidate_is_admitted_when_no_waveform_is_in_flight():
    session = _Session(None)
    gate = UartWaveformAdmissionGate(session=session, window=WINDOW)
    action = _action(words=_uart_access_words())

    gate.register(action)
    gate.require_case(object())
    assert gate.evaluate(action).satisfied is True
    assert gate.document()["refusals"] == 0


def test_the_session_predicate_is_only_asked_for_an_in_window_access():
    """窗口外访问、非 CPU 组件与无 MMIO 的片段都不触碰会话谓词。"""
    other = mmio_access_fragment("LW", 0x50000000,
                                 windows=(MmioWindow(0x50000000, 0x1000),),
                                 base_register=3, data_register=2)
    cases = (
        _action(words=fragment_bytes(other)),          # outside the window
        _action(words=_uart_access_words(), component="gpio_b"),
        _action(words=bytes.fromhex("13000000")),      # no access at all
    )
    for action in cases:
        session = _Session({"local_tick": 1, "horizon_tick": 2})
        gate = UartWaveformAdmissionGate(session=session, window=WINDOW)
        gate.register(action)
        gate.require_case(object())
        assert session.queries == 0, action.action_id


def test_a_gate_without_the_session_query_is_refused():
    with pytest.raises(ValueError, match="register_access_conflict"):
        UartWaveformAdmissionGate(session=object(), window=WINDOW)
    with pytest.raises(ValueError, match="window"):
        UartWaveformAdmissionGate(session=_Session(), window=(0, 0))
