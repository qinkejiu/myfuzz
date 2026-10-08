"""The Ibex dual-source result slot can be partly written -- only on request.

P3's ``store_then_load`` criterion has three parts; two of them are already
measured on real Ibex + PULP GPIO artifacts (the exact cross-case version/value
join and the first-unknown-read reuse).  The third one,
``byte_enable_lane_selectivity``, was **not observed** in any of them: every RAM
write those runs recorded was a full-enable ``SW`` (``partial_byte_enable_writes
= 0``), so "a byte-enable covers only its own lane" could not be falsified.

This file pins the explicit, default-off opt-in that makes the missing
observation possible, and the evidence it must produce:

* the declared scope is exactly one address (``RESULT_ADDRESS`` = ``0x10000``),
  one operation (``SB``) and its four byte lanes, declared where
  ``result_slot_readback`` already declares the window; GPIO A PADOUT stays
  word-only and every other address/width/alignment keeps its shipped refusal
  code from ``scenario/rejection_codes.py``;
* off, not one declaration moves: the decoder document of the no-kwarg builder
  and of ``result_slot_byte_store=False`` is byte-identical, and the decode
  space contains no byte store at all;
* on, the change is exactly the declared window write widths and the declared
  operation -- nothing else in the decoder document moves;
* through the *real* ``PersistentMemory``/``MemoryService`` (CPU stub, no RTL),
  a one-lane store commits one enabled lane with its own version and writer and
  leaves the other lanes' versions and writers untouched, which is what the
  production P3 observer then reports as ``measured``/``met``;
* the negative: a read lane that claims the byte store's version without being
  enabled by it is counted as an adoption and the criterion fails.

No RTL is compiled, rendered, started or simulated anywhere in this file.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from myfuzz.integration import ibex_pulp_online as online
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_pulp_dual_source import (
    DUAL_SOURCE_MEMORY_REGIONS, RESULT_ADDRESS,
    RESULT_SLOT_BYTE_STORE_BYTE_LANES, RESULT_SLOT_BYTE_STORE_OPERATION,
    RESULT_SLOT_BYTE_STORE_SCHEMA_VERSION,
    RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS, RESULT_SLOT_WORD_ONLY_WRITE_WIDTHS,
    install_host_ram_commit_journal, instruction_words,
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
    result_slot_byte_store_declaration,
)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.online_case_decoder import (OnlineCaseDecoder,
                                                 OnlineInstruction)
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.p3_acceptance import _TraceObserver, _store_then_load
from myfuzz.scenario.rejection_codes import RejectionCode, RejectionError
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.rv32i_sources import (
    MmioWindow, decode_instruction_fragment, fragment_bytes,
    instruction_operator_id, mmio_write_fragment, mutate_mmio_access,
)
from myfuzz.scenario.session_runtime import ScenarioSession, _online_manifest

#: The one MMIO window this wiring already declared (GPIO A PADOUT, offset 12).
PADOUT_WINDOW = 0x4000100C
#: The real builder, captured before any test monkeypatches the module name, so
#: two runtimes built in one test never chain into each other.
_REAL_DECODER_BUILDER = online.make_ibex_pulp_dual_source_online_decoder
#: The declared lanes of the result-slot window, in lane order.
RESULT_LANES = tuple(RESULT_ADDRESS + lane
                     for lane in RESULT_SLOT_BYTE_STORE_BYTE_LANES)
#: The exact two-word proof prefix of a byte store: LUI x1, 0x10 materializes
#: the result-slot base inside the fragment itself.
LUI_RESULT_BASE = 0x000100B7
#: ISA facts this file recomputes instead of trusting a comment: the SB opcode,
#: its funct3, the LUI opcode and the ADDI funct3.
SB_OPCODE, SB_FUNCT3, LUI_OPCODE, ADDI_FUNCT3 = 0x23, 0, 0x37, 0


def _manifest_bytes(decoder) -> bytes:
    """The exact bytes ``run_scenario_rfuzz_live`` saves as the decoder manifest."""
    return json.dumps(decoder.document(), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _document(decoder) -> dict:
    return json.loads(_manifest_bytes(decoder))


def _shipped_decoder(*, byte_store: bool | None = None):
    """The Ibex online decoder of this wiring, with every option explicit."""
    kwargs = {"result_slot_readback": True}
    if byte_store is not None:
        kwargs["result_slot_byte_store"] = byte_store
    return make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(), **kwargs)


def _space(decoder) -> dict[int, str]:
    """The decoder's whole first-byte instruction space, as fragment hex.

    This is the production call ``online_case_decoder`` makes
    (``decode_instruction_fragment`` over the decoder's own declared windows and
    operations), so the sweep measures the shipped declaration, not a copy.
    """
    space = {}
    for choice in range(256):
        entropy = bytes((choice, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0x88, 0x99, 0xAA, 0xBB))
        space[choice] = fragment_bytes(decode_instruction_fragment(
            entropy, windows=decoder.windows,
            allowed_mmio_operations=decoder.allowed_mmio_operations)).hex()
    return space


def _byte_store_fragment(choice: int, lane_selector: int, *,
                         value: int = 0x0000005A, decoder=None) -> str:
    """One fragment the declared operation set produces for a fixed entropy."""
    decoder = _shipped_decoder(byte_store=True) if decoder is None else decoder
    entropy = bytes((choice, 0x00, lane_selector, 0x00, 0x00, 0x00, 0x00,
                     0x00, value & 0xFF, (value >> 8) & 0xFF,
                     (value >> 16) & 0xFF, (value >> 24) & 0xFF))
    return fragment_bytes(decode_instruction_fragment(
        entropy, windows=decoder.windows,
        allowed_mmio_operations=decoder.allowed_mmio_operations)).hex()


def _materialized_sb_address(words_hex: str) -> int | None:
    """The one SB effective address a fragment *proves*, recomputed locally.

    Same proof rule as the shipped ``materialized_lw_addresses``: a base
    register value may only be claimed when a ``LUI`` (optionally plus ``ADDI``)
    of the same fragment materialized it.  ``None`` means "not proven".
    """
    words = instruction_words(words_hex)
    if words is None:
        return None
    known: dict[int, int] = {}
    address = None
    for word in words:
        opcode, funct3 = word & 0x7F, (word >> 12) & 7
        rd, rs1 = (word >> 7) & 31, (word >> 15) & 31
        if word == 0x00000013:
            continue
        if opcode == LUI_OPCODE:
            if rd:
                known[rd] = ((word >> 12) & 0xFFFFF) << 12
            continue
        if opcode == 0x13 and funct3 == ADDI_FUNCT3:
            base = 0 if rs1 == 0 else known.get(rs1)
            immediate = (word >> 20) & 0xFFF
            immediate = immediate - 0x1000 if immediate & 0x800 else immediate
            if rd:
                if base is None:
                    known.pop(rd, None)
                else:
                    known[rd] = (base + immediate) & 0xFFFFFFFF
            continue
        if opcode == SB_OPCODE and funct3 == SB_FUNCT3:
            base = 0 if rs1 == 0 else known.get(rs1)
            immediate = ((word >> 25) << 5) | ((word >> 7) & 31)
            immediate = immediate - 0x1000 if immediate & 0x800 else immediate
            if base is None or address is not None:
                return None
            address = (base + immediate) & 0xFFFFFFFF
            continue
        return None
    return address


# ---------------------------------------------------------------------------
# The declaration: one address, one operation, its four declared lanes
# ---------------------------------------------------------------------------

def test_the_optin_declares_one_address_one_operation_and_its_lanes():
    declaration = result_slot_byte_store_declaration()
    assert declaration["schema_version"] == RESULT_SLOT_BYTE_STORE_SCHEMA_VERSION
    assert declaration["operation"] == RESULT_SLOT_BYTE_STORE_OPERATION == "SB"
    assert declaration["address"] == RESULT_ADDRESS == 0x10000
    assert declaration["byte_width"] == 1
    assert tuple(declaration["write_widths"]) == RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS
    assert [(row["lane"], row["address"]) for row in declaration["lanes"]] == \
        [(lane, RESULT_ADDRESS + lane)
         for lane in RESULT_SLOT_BYTE_STORE_BYTE_LANES]
    # The byte width is confined to the result slot: the wiring's other window
    # is declared word-only, so no device register can receive a byte store.
    assert declaration["word_only_windows"] == [PADOUT_WINDOW]
    assert declaration["not_proof_of"] == ["RTL byte-enable lane selectivity",
                                           "cross-case acceptance"]


def test_the_default_off_decoder_is_byte_for_byte_the_shipped_declaration():
    shipped = _shipped_decoder()
    explicit_off = _shipped_decoder(byte_store=False)
    assert _manifest_bytes(shipped) == _manifest_bytes(explicit_off)
    # The whole instruction space is the same bytes too: no entropy value
    # decodes differently, because no declaration the decoder reads moved.
    assert _space(shipped) == _space(explicit_off)
    assert shipped.allowed_mmio_operations == ("LW", "SW")
    # The frozen shipped window declaration: no write width was added to either
    # window, and no third window exists.
    assert _document(shipped)["mmio_windows"] == [
        {"base": PADOUT_WINDOW, "size": 4, "readable": True, "writable": True,
         "write_widths": [1, 4]},
        {"base": RESULT_ADDRESS, "size": 4, "readable": True, "writable": True,
         "write_widths": [1, 4]}]
    # The opt-in declaration is not smuggled into the default document.
    assert "result_slot_byte_store" not in _document(shipped)
    assert json.dumps(result_slot_byte_store_declaration(),
                      sort_keys=True) not in _manifest_bytes(shipped).decode()


def test_the_optin_changes_exactly_the_declared_window_and_operation():
    shipped, opted = _shipped_decoder(), _shipped_decoder(byte_store=True)
    before, after = _document(shipped), _document(opted)
    assert set(before) == set(after)
    assert {key for key in before if before[key] != after[key]} == {
        "mmio_windows", "allowed_mmio_operations"}
    assert before["allowed_mmio_operations"] == ["LW", "SW"]
    assert after["allowed_mmio_operations"] == ["LW", "SW", "SB"]
    assert after["mmio_windows"] == [
        {"base": PADOUT_WINDOW, "size": 4, "readable": True, "writable": True,
         "write_widths": list(RESULT_SLOT_WORD_ONLY_WRITE_WIDTHS)},
        {"base": RESULT_ADDRESS, "size": 4, "readable": True, "writable": True,
         "write_widths": list(RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS)}]
    # The two manifests really are different bytes, so the run identity of an
    # opted-in run cannot be mistaken for the shipped one.
    assert hashlib.sha256(_manifest_bytes(shipped)).digest() != \
        hashlib.sha256(_manifest_bytes(opted)).digest()


def test_the_opted_in_decoder_manifest_rebuilds_for_saved_run_replay():
    opted = _shipped_decoder(byte_store=True)
    rebuilt = OnlineCaseDecoder.from_document(json.loads(_manifest_bytes(opted)))
    assert rebuilt.from_document_replay_only is True
    assert rebuilt.trusted_for_search is False
    assert [window.write_widths for window in rebuilt.windows] == \
        [(4,), RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS]
    assert rebuilt.allowed_mmio_operations == ("LW", "SW", "SB")
    # ``from_document`` refuses any document its own rebuild does not reproduce
    # byte for byte, so equality here means the saved manifest is canonical.
    assert _manifest_bytes(rebuilt) == _manifest_bytes(opted)


def test_the_optin_refuses_a_missing_window_and_a_non_boolean_request():
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    with pytest.raises(ValueError,
                       match="requires the declared result slot window"):
        make_ibex_pulp_dual_source_online_decoder(
            bootstrap=bootstrap, result_slot_byte_store=True)
    for value in (1, 0, None, "yes", ()):
        with pytest.raises(ValueError, match="byte store must be boolean"):
            make_ibex_pulp_dual_source_online_decoder(
                bootstrap=bootstrap, result_slot_readback=True,
                result_slot_byte_store=value)
    # The shipped single-window declaration keeps its own boolean refusal.
    for value in (1, None, "yes"):
        with pytest.raises(ValueError, match="readback must be boolean"):
            make_ibex_pulp_dual_source_online_decoder(
                bootstrap=bootstrap, result_slot_readback=value)


# ---------------------------------------------------------------------------
# The decode space: one enabled lane of the result slot, and nothing else
# ---------------------------------------------------------------------------

def test_the_optin_produces_single_lane_stores_at_the_declared_addresses():
    opted = _shipped_decoder(byte_store=True)
    shipped = _shipped_decoder()
    found: dict[int, set[int]] = {}
    for choice in range(256):
        for lane_selector in range(4):
            data_hex = _byte_store_fragment(choice, lane_selector,
                                            value=0x11223344, decoder=opted)
            data = bytes.fromhex(data_hex)
            operations = instruction_operator_id(data)
            if "SB" not in operations:
                continue
            # The store template is exactly LUI/ADDI of the value into x2, LUI
            # of the result base into x1, then one SB through x1.
            assert operations == "rv32i:LUI+ADDI+LUI+SB"
            words = instruction_words(data_hex)
            assert len(words) == 4
            # LUI x2/ADDI x2 load the declared value, LUI x1 materializes the
            # result base inside the fragment, then one SB through x1 stores x2.
            assert words[2] == LUI_RESULT_BASE
            assert (words[-1] >> 15) & 31 == 1 and (words[-1] >> 20) & 31 == 2
            assert (words[-1] & 0x7F) == SB_OPCODE
            assert (words[-1] >> 12) & 7 == SB_FUNCT3
            address = _materialized_sb_address(data_hex)
            assert address in RESULT_LANES, hex(address or 0)
            lane = address - RESULT_ADDRESS
            found.setdefault(choice, set()).add(lane)
            # The lane is exactly the SB offset of the fragment (RV32I splits it
            # over imm[11:5] and imm[4:0]), and the value register still holds
            # the low byte the lane receives.
            immediate = ((words[-1] >> 25) << 5) | ((words[-1] >> 7) & 31)
            assert immediate == lane
            # x2 really holds the declared value, so the enabled lane receives
            # exactly that value's byte.
            addi = (words[1] >> 20) & 0xFFF
            addi = addi - 0x1000 if addi & 0x800 else addi
            assert (((words[0] >> 12) << 12) + addi) & 0xFFFFFFFF == 0x11223344
    assert found, "the opted-in operation set produced no byte store at all"
    # Every one-byte store of this declaration lands inside the four declared
    # lane addresses, and every declared lane is reachable.
    assert {address for lanes in found.values() for address in lanes} == \
        set(RESULT_SLOT_BYTE_STORE_BYTE_LANES)
    # The control: the shipped declaration's own space contains no byte store,
    # which is exactly why P3 could not observe the property before.
    for choice in range(256):
        for lane_selector in range(4):
            shipped_ops = instruction_operator_id(bytes.fromhex(
                _byte_store_fragment(choice, lane_selector, decoder=shipped)))
            assert "SB" not in shipped_ops


def test_the_online_decoder_proposes_byte_stores_only_to_the_result_slot():
    opted = _shipped_decoder(byte_store=True)
    shipped = _shipped_decoder()
    addresses: set[int] = set()
    for tail in range(256):
        raw = bytes(((tail * 7) & 0xFF, 0x11, 0x00, tail, 0x22, 0x33, 0x44,
                     0x55))
        case = opted.decode(raw)
        if not isinstance(case.source, OnlineInstruction):
            continue
        data = bytes.fromhex(case.source.data_hex)
        if "SB" not in instruction_operator_id(data):
            continue
        address = _materialized_sb_address(case.source.data_hex)
        assert address in RESULT_LANES, hex(address or 0)
        addresses.add(address)
        # A byte store candidate is never generated for the word-only window.
        assert address != PADOUT_WINDOW
    assert addresses, "the online decoder proposed no byte store case"
    # The shipped decoder proposes no byte store for the same inputs.
    for tail in range(256):
        raw = bytes(((tail * 7) & 0xFF, 0x11, 0x00, tail, 0x22, 0x33, 0x44,
                     0x55))
        case = shipped.decode(raw)
        if isinstance(case.source, OnlineInstruction):
            assert "SB" not in instruction_operator_id(
                bytes.fromhex(case.source.data_hex))


def test_every_declared_byte_store_address_is_inside_the_declared_window():
    opted = _shipped_decoder(byte_store=True)
    selected = set()
    for window_selector in range(256):
        for lane_selector in range(4):
            access = mutate_mmio_access(
                RESULT_SLOT_BYTE_STORE_OPERATION,
                bytes((window_selector, lane_selector, 0x00, 0x00)),
                windows=opted.windows, base_register=1, data_register=2)
            base, offset = access[0].immediate << 12, access[1].immediate
            selected.add(base + offset)
    assert selected == set(RESULT_LANES)
    assert PADOUT_WINDOW not in selected


# ---------------------------------------------------------------------------
# The declared scope keeps every other shipped refusal code
# ---------------------------------------------------------------------------

def _refusal(operation: str, address: int, *, value: int = 0) -> dict:
    with pytest.raises(RejectionError) as error:
        mmio_write_fragment(operation, address, value,
                            windows=_shipped_decoder(byte_store=True).windows,
                            base_register=1, data_register=2)
    return error.value.rejection.document()


def test_other_addresses_widths_alignments_and_operations_keep_their_codes():
    # A declared address whose window is word-only: the width is refused.
    assert _refusal("SB", PADOUT_WINDOW)["code"] == \
        RejectionCode.MMIO_BAD_WIDTH.value
    assert _refusal("SB", PADOUT_WINDOW)["pointer"] == "mmio.width"
    # A one-byte address outside the declared window.
    for address in (RESULT_ADDRESS + 4, RESULT_ADDRESS - 4, 0x0):
        assert _refusal("SB", address)["code"] == \
            RejectionCode.MMIO_OUT_OF_WINDOW.value
    # A word access that leaves the declared byte width where it stands: the
    # shipped alignment code still refuses it.
    assert _refusal("SW", RESULT_ADDRESS + 1)["code"] == \
        RejectionCode.FIELD_BAD_ALIGNMENT.value
    assert _refusal("SW", RESULT_ADDRESS + 1)["pointer"] == "mmio.address"
    # An operation outside the supported store set is never turned into a byte
    # store, not even at the declared address.
    for operation in ("SH", "LBU", "LW", "NOP"):
        assert _refusal(operation, RESULT_ADDRESS)["code"] == \
            RejectionCode.ISA_DISALLOWED_OPERATION.value
    # The positive control: the declared address and its declared lanes are the
    # only thing this opt-in accepts.
    for lane in RESULT_SLOT_BYTE_STORE_BYTE_LANES:
        access = mmio_write_fragment(
            RESULT_SLOT_BYTE_STORE_OPERATION, RESULT_ADDRESS + lane, 0x5A,
            windows=_shipped_decoder(byte_store=True).windows,
            base_register=1, data_register=2)
        assert access[-1].operation == "SB"
    # Every code above is a shipped code: the opt-in invents none.
    codes = {RejectionCode.MMIO_BAD_WIDTH, RejectionCode.MMIO_OUT_OF_WINDOW,
             RejectionCode.FIELD_BAD_ALIGNMENT,
             RejectionCode.ISA_DISALLOWED_OPERATION}
    assert codes <= set(RejectionCode)


def test_a_window_without_the_declared_byte_width_refuses_the_store():
    # The address alone is not the declaration: drop the one-byte width and the
    # same store is refused with the same code, which is what the shipped
    # declaration does today.
    word_only = (MmioWindow(PADOUT_WINDOW, 4, write_widths=(4,)),
                 MmioWindow(RESULT_ADDRESS, 4, write_widths=(4,)))
    with pytest.raises(RejectionError) as error:
        mmio_write_fragment("SB", RESULT_ADDRESS, 0x5A, windows=word_only,
                            base_register=1, data_register=2)
    assert error.value.rejection.code is RejectionCode.MMIO_BAD_WIDTH


# ---------------------------------------------------------------------------
# The real host-memory path: one enabled lane, its own version, the others kept
# ---------------------------------------------------------------------------

#: The byte lane the partial store below enables, and the byte it commits.
PARTIAL_LANE = 2
FULL_VALUE = 0x0A0B0C06
PARTIAL_BYTE = 0x5A


class _LaneCpu:
    """Offline CPU stub performing *real* host-memory transactions.

    One scripted action runs per step.  ``store`` is exactly the call
    ``GeneratedCve2Session._serve`` makes for a real OBI store beat: the beat
    address is word aligned and the byte-enable is the RTL's own strobe, so a
    one-lane ``SB`` reaches the service as ``width_bytes=4`` with a single
    enabled lane.  Nothing here renders, starts or simulates RTL.
    """

    def __init__(self, *, commit_stream: bool = True) -> None:
        self.memory = PersistentMemory(regions=DUAL_SOURCE_MEMORY_REGIONS,
                                       initialization_seed=37,
                                       max_initialized_bytes=0x20000)
        self.ledger = TransactionLedger()
        self.service = MemoryService(
            self.memory, self.ledger,
            commit_stream_capacity=256 if commit_stream else None)
        self.router = None
        self.script: list = []
        self.steps = 0
        self.testcase_id = ""
        self._sequence = 0
        self.last_snapshot = None

    def begin_case(self, testcase_id: str) -> None:
        self.testcase_id = testcase_id
        self._sequence = 0

    def identity_document(self) -> dict:
        """The stub's own declared service identity (no generated-CPU claim)."""
        return {"cpu_service_schema_version": "generated_obi_cpu_service.v1",
                "source_component": "cpu", "defer_mmio": True}

    def end_case(self) -> None:
        pass

    def step_local(self, inputs):
        self.steps += 1
        action = self.script.pop(0) if self.script else None
        if action is not None:
            action(self)
        return {}

    def _key(self) -> TransactionKey:
        self._sequence += 1
        return TransactionKey("execution-1", self.testcase_id, "cpu", 0,
                              "data", self._sequence)

    def store(self, address: int, value: int, byte_enable: int):
        return self.service.write(self._key(), address, value,
                                  width_bytes=4, byte_enable=byte_enable)

    def load(self, address: int):
        self.last_snapshot = self.service.read(self._key(), address,
                                               width_bytes=4)
        return self.last_snapshot


def _lane_runner(*, commit_stream: bool = True):
    """A real runner over the stub CPU, with the shipped commit journal."""
    cpu = _LaneCpu(commit_stream=commit_stream)
    runner = ScenarioRunner(sessions={"cpu": cpu},
                            ownership=compile_ownership((), ()), bindings=())
    journal = None
    if commit_stream:
        journal = install_host_ram_commit_journal(
            runner, component="cpu", service=cpu.service)
    runner.begin_test("result-slot-byte-store")
    cpu.script = [
        lambda cpu: cpu.store(RESULT_ADDRESS, FULL_VALUE, 0b1111),
        lambda cpu: cpu.store(RESULT_ADDRESS,
                              PARTIAL_BYTE << (8 * PARTIAL_LANE),
                              1 << PARTIAL_LANE),
        lambda cpu: cpu.load(RESULT_ADDRESS),
    ]
    return runner, cpu, journal


def _artifact_events(runner) -> list[dict]:
    """The runner's events as the saved artifact serializes them (JSON)."""
    return json.loads(json.dumps(list(runner.events_since(0))))


def test_a_real_partial_store_commits_one_lane_and_keeps_the_other_versions():
    runner, cpu, journal = _lane_runner()
    assert journal is not None
    for _ in range(3):
        runner.step("cpu")
    events = _artifact_events(runner)
    writes = [event for event in events if event.get("kind") == "memory_write"]
    commits = [event for event in events
               if event.get("kind") == "memory_write_commit"]
    reads = [event for event in events if event.get("kind") == "memory_read"]
    assert len(writes) == 2 and len(commits) == 2 and len(reads) == 1
    full, partial = writes
    # The real byte-enable of each commit: one full word, then one lane.
    assert (full["byte_enable"], full["width_bytes"], full["byte_offset"]) == \
        (0b1111, 4, 0)
    assert (partial["byte_enable"], partial["width_bytes"],
            partial["byte_offset"]) == (1 << PARTIAL_LANE, 4, 0)
    assert partial["memory_id"] == "ram" and partial["generation"] == 0
    assert partial["address"] == RESULT_ADDRESS
    # The authenticated commit receipt carries exactly the enabled lane.
    partial_commit = commits[1]["commit_document"]
    assert partial_commit["byte_enable"] == 1 << PARTIAL_LANE
    assert partial_commit["width_bytes"] == 4
    assert [cell["byte_offset"] for cell in
            partial_commit["enabled_byte_cells"]] == [PARTIAL_LANE]
    assert partial_commit["enabled_byte_cells"][0]["value"] == PARTIAL_BYTE
    # The later read snapshot carries one version and writer per lane: the
    # enabled lane is the partial store's, every other lane is still the full
    # store's.
    snapshot = cpu.last_snapshot
    assert snapshot.versions == tuple(
        tuple(partial["version"]) if lane == PARTIAL_LANE
        else tuple(full["version"]) for lane in range(4))
    assert snapshot.writer_event_ids == tuple(
        str(TransactionKey(**partial["transaction"])) if lane == PARTIAL_LANE
        else str(TransactionKey(**full["transaction"])) for lane in range(4))
    expected = bytearray(FULL_VALUE.to_bytes(4, "little"))
    expected[PARTIAL_LANE] = PARTIAL_BYTE
    assert snapshot.data == bytes(expected)
    # The negative claim this evidence forbids: no other lane of the read is the
    # byte store's version or writer, so "the byte store covered a lane it never
    # enabled" is false and must stay false.
    for lane in range(4):
        if lane == PARTIAL_LANE:
            continue
        assert snapshot.versions[lane] != tuple(partial["version"])
        assert snapshot.writer_event_ids[lane] != \
            str(TransactionKey(**partial["transaction"]))


def test_the_p3_lane_selectivity_keys_are_measured_and_met_on_real_records():
    runner, cpu, _ = _lane_runner()
    for _ in range(3):
        runner.step("cpu")
    observer = _TraceObserver()
    for event in _artifact_events(runner):
        observer.observe(event)
    memory = observer.memory_report()
    byte_enable = memory["byte_enable"]
    assert byte_enable["partial_byte_enable_writes"] > 0
    assert byte_enable["non_enabled_lane_checks"] > 0
    assert byte_enable["non_enabled_lane_adoptions"] == 0
    assert byte_enable["lane_selectivity"] == {
        "measured": True, "met": True, "reason": None}
    # One partially enabled four-byte store over a four-lane read: exactly the
    # three lanes it never enabled are checked, and none of them adopted it.
    assert byte_enable["non_enabled_lane_checks"] == 3
    # The exact P3 gate key this work exists for.
    item = _store_then_load({"available": True}, memory, [])
    part = item["evidence"]["parts"]["byte_enable_lane_selectivity"]
    assert (part["measured"], part["met"]) == (True, True)
    assert part["reason"] is None
    assert part["partial_byte_enable_writes"] == \
        byte_enable["partial_byte_enable_writes"]
    assert part["non_enabled_lane_checks"] == 3
    assert part["non_enabled_lane_adoptions"] == 0


def test_a_read_lane_claiming_the_byte_store_version_fails_the_criterion():
    """The negative: an unenabled lane carrying the store's pair is an adoption."""
    runner, _, _ = _lane_runner()
    for _step in range(3):
        runner.step("cpu")
    events = _artifact_events(runner)
    partial = next(event for event in events
                   if event.get("kind") == "memory_write"
                   and event["byte_enable"] == 1 << PARTIAL_LANE)
    forged = []
    for event in events:
        event = copy.deepcopy(event)
        if event.get("kind") == "memory_read" and len(event["versions"]) == 4:
            # Forge exactly the false claim: lane 1, which this store never
            # enabled, "was covered" by it, i.e. carries its version and writer.
            event["versions"][1] = list(partial["version"])
            event["writer_event_ids"][1] = str(
                TransactionKey(**partial["transaction"]))
        forged.append(event)
    observer = _TraceObserver()
    for event in forged:
        observer.observe(event)
    byte_enable = observer.memory_report()["byte_enable"]
    assert byte_enable["partial_byte_enable_writes"] > 0
    assert byte_enable["non_enabled_lane_checks"] == 3
    assert byte_enable["non_enabled_lane_adoptions"] == 1
    assert byte_enable["lane_selectivity"]["measured"] is True
    assert byte_enable["lane_selectivity"]["met"] is False
    assert "adopted the version" in byte_enable["lane_selectivity"]["reason"]
    part = _store_then_load({"available": True},
                            observer.memory_report(), [])["evidence"][
                                "parts"]["byte_enable_lane_selectivity"]
    assert (part["measured"], part["met"]) == (True, False)
    assert part["non_enabled_lane_adoptions"] == 1


# ---------------------------------------------------------------------------
# Wiring: the runtime and the frozen CLI forward the opt-in only when asked
# ---------------------------------------------------------------------------

def test_the_online_runtime_forwards_the_optin_only_when_it_is_set(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        online, "make_ibex_pulp_dual_source_factory",
        lambda *args, **kwargs: (lambda: None))
    monkeypatch.setattr(
        online, "make_pulp_dual_source_online_runtime",
        lambda **kwargs: captured.update(kwargs) or SimpleNamespace())
    online.make_ibex_pulp_online_runtime(
        cache_dir=Path("/tmp/result-slot-byte-store-no-rtl"), run_id="shipped")
    shipped = captured["decoder"]
    assert shipped.allowed_mmio_operations == ("LW", "SW")
    assert [window.write_widths for window in shipped.windows] == [(1, 4), (1, 4)]
    online.make_ibex_pulp_online_runtime(
        cache_dir=Path("/tmp/result-slot-byte-store-no-rtl"), run_id="optin",
        result_slot_byte_store=True)
    opted = captured["decoder"]
    assert opted.allowed_mmio_operations == ("LW", "SW", "SB")
    assert [window.write_widths for window in opted.windows] == \
        [(4,), RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS]
    with pytest.raises(ValueError,
                       match="result_slot_byte_store must be boolean"):
        online.make_ibex_pulp_online_runtime(
            cache_dir=Path("/tmp/result-slot-byte-store-no-rtl"), run_id="bad",
            result_slot_byte_store=1)


class _StopBeforeRtl(RuntimeError):
    """Sentinel: the recording session refuses before any local harness begins."""


class _RecordingSession:
    """Real runner, no RTL: records construction and refuses at ``begin``."""

    def __init__(self, template, runner, *, checker=None, prerequisite_gate=None):
        self.template, self.runner, self.checker = template, runner, checker
        self.prerequisite_gate = prerequisite_gate

    def declare_instruction_slots(self, component, address, count=1):
        pass

    def configure_runtime_paths(self, *args, **kwargs):
        pass

    def begin(self):
        raise _StopBeforeRtl("no RTL in a software test")

    def finish(self):
        pass


def _runtime_identity(monkeypatch, **kwargs):
    """Build one runtime over a real runner without rendering any harness."""
    recorded = {}

    def builder(**builder_kwargs):
        # The real builder as imported, so a second call in the same test (whose
        # monkeypatch replaces the first one) can never recurse into itself.
        recorded["decoder"] = _REAL_DECODER_BUILDER(**builder_kwargs)
        return recorded["decoder"]

    def factory(*args, **factory_kwargs):
        recorded["factory_kwargs"] = factory_kwargs
        cpu = _LaneCpu(commit_stream=False)
        runner = ScenarioRunner(sessions={"cpu": cpu},
                                ownership=compile_ownership((), ()),
                                bindings=())
        recorded["runner"] = runner
        return lambda: runner

    def session_factory(template, runner, **session_kwargs):
        recorded["session"] = _RecordingSession(template, runner,
                                                **session_kwargs)
        return recorded["session"]

    monkeypatch.setattr(online, "make_ibex_pulp_dual_source_online_decoder",
                        builder)
    monkeypatch.setattr(online, "make_ibex_pulp_dual_source_factory", factory)
    monkeypatch.setattr(online, "ScenarioSession", session_factory)
    with pytest.raises(_StopBeforeRtl):
        online.make_ibex_pulp_online_runtime(
            cache_dir=Path("/tmp/result-slot-byte-store-no-rtl"),
            run_id="identity", **kwargs)
    return recorded


def test_the_switch_moves_the_decoder_manifest_and_not_the_session_manifest(
        monkeypatch):
    shipped = _runtime_identity(monkeypatch)
    opted = _runtime_identity(monkeypatch, result_slot_byte_store=True)
    # The same wiring is built either way: the factory receives the same
    # keyword arguments, so nothing but the decoder declaration can move.
    assert shipped["factory_kwargs"] == opted["factory_kwargs"]
    # The session manifest identity of the CPU does not name the switch.
    assert _manifest_bytes(shipped["decoder"]) != _manifest_bytes(opted["decoder"])
    assert shipped["runner"].sessions["cpu"].identity_document() == \
        opted["runner"].sessions["cpu"].identity_document()
    assert _online_manifest(shipped["runner"], None) == \
        _online_manifest(opted["runner"], None)
    # Generated per run: the two runners are distinct objects with distinct
    # memories, so the equality above is a real equality, not one object twice.
    assert shipped["runner"] is not opted["runner"]
    assert shipped["runner"].sessions["cpu"] is not opted["runner"].sessions["cpu"]


def test_the_cli_forwards_the_byte_store_switch_only_when_it_is_asked():
    script = Path(__file__).resolve().parents[2] / "scripts/run_ibex_pulp_online.py"
    spec = importlib.util.spec_from_file_location("_result_slot_byte_store_cli",
                                                  script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    def run_cli(extra: list[str]) -> dict:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "new-run"
            result = Mock(output_dir=output, tests=1, statuses={},
                          elapsed_seconds=1, effective_search_seconds=1)
            with patch.object(cli, "make_ibex_pulp_online_runtime",
                              return_value=Mock()) as runtime, patch.object(
                    cli, "run_scenario_rfuzz_live", return_value=result), \
                    redirect_stdout(StringIO()):
                assert cli.main(["run", "--client-binary", "/tmp/client",
                                 "--cache-dir", "/tmp/cache",
                                 "--output", str(output),
                                 "--cpu-retirement", "--gpio-consumption",
                                 "--memory-commit", *extra]) == 0
            return runtime.call_args.kwargs

    # Default: the switch is not even passed, so the builder keeps its own
    # default and the decoder identity is the shipped one.
    assert "result_slot_byte_store" not in run_cli([])
    assert run_cli(["--result-slot-byte-store"])["result_slot_byte_store"] is True
