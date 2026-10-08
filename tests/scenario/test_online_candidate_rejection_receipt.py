"""Online receipts carry versioned ``candidate_rejection.v1`` refusals.

The online candidate path must classify a refusal before any RTL command: a
decode-time rejection reaches the receipt with its exact code, failing field
pointer and detail, while a post-submit outcome stays ``uncertain`` and never
gains a structured rejection. The legacy receipt keys keep their meaning, an
unclassified error keeps its old handling instead of inventing a code, and a
repeated slot returns the original receipt document unchanged.

Every case is built from offline stubs; no RTL runs here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import (ScenarioRfuzzExecutor,
                                               ScenarioRfuzzReceipt)
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
from myfuzz.scenario import rejection_codes as rc
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder, OnlineSource
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.rv32i_sources import (MmioWindow, mmio_access_fragment,
                                           validate_instruction_bytes)
from myfuzz.scenario.session_runtime import ScenarioSession


NOP_BYTES = b"\x13\x00\x00\x00"
WINDOW = MmioWindow(0x40000000, 0x1000)
READ_ONLY_WINDOW = MmioWindow(0x40000000, 0x1000, writable=False)
#: A NOP instruction selection: byte three chooses operation class zero.
NOP_RAW = bytes((0, 0, 0, 0, 0, 0, 0, 0))
#: Byte three chooses the MMIO operation class; four is SW in the three-op set.
MMIO_SW_RAW = bytes((0, 0, 0, 4, 0, 0, 0, 0))
#: Byte three selects operation class two, whose edit byte makes three words.
DEGRADED_RAW = bytes((0, 0, 0, 2, 0xC4, 0xFF, 0x0F, 7))
_CPU_TARGET = CoverageTarget("cpu.observed", "cpu", "observed", 1, 1)
_IP_TARGET = CoverageTarget("ip.observed", "ip", "observed", 1, 1)
#: The frozen catalog digest; an added or renamed code changes this value.
#: 35 codes -> 37 with isa.reserved_imm_bit and field.bad_shamt.
REJECTION_CATALOG_SHA256 = (
    "86d03337fa3955b18ea05429a1c0eaa8c3c5bb21a56332d02a6a390d7e560577")


class _OfflineCpu:
    """Offline CPU harness: records admitted slots and executes no RTL."""

    def __init__(self) -> None:
        self.accepted: list[tuple[int, bytes, str]] = []

    def begin_case(self, testcase_id: str) -> None:
        pass

    def step_local(self, inputs):
        return {"observed": 0}

    def end_case(self) -> None:
        pass

    def accept_instructions(self, address: int, data: bytes, *,
                            source_event_id: str) -> None:
        self.accepted.append((address, bytes(data), source_event_id))


def _online_executor(decoder: OnlineCaseDecoder, *, ownership, schedule,
                     path_id: str, targets):
    """Wire a real executor around offline harness stubs."""
    template = ScenarioGenome(testcase_id="receipt-seed", direction="IP_TO_IP",
                              path_id=path_id, schedule_order=tuple(schedule),
                              max_steps=64, actions=())
    sessions = {component: _OfflineCpu() for component in schedule}
    runner = ScenarioRunner(sessions=sessions, ownership=ownership, bindings=())
    session = ScenarioSession(template, runner, checker=lambda receipt: ())
    session.begin()
    executor = ScenarioRfuzzExecutor(run_id="online-receipt", factory=lambda: runner,
                                     targets=targets, session=session,
                                     online_decoder=decoder)
    return executor, sessions


def _instruction_executor(*, instruction_start: int = 0x1000,
                          instruction_end: int = 0x1004, windows=()):
    """One reserved online instruction slot and nothing else."""
    ownership = compile_ownership((), ())
    decoder = OnlineCaseDecoder(
        sources=(OnlineSource("cpu.it", "instruction", "cpu", "IP_TO_IP", "cpu",
                              coverage_target_ids=("cpu.observed",)),),
        ownership=ownership, schedule=("cpu",), instruction_start=instruction_start,
        instruction_end=instruction_end, windows=windows, advance_rounds=2,
        max_input_bytes=8)
    return _online_executor(decoder, ownership=ownership, schedule=("cpu",),
                            path_id="cpu", targets=(_CPU_TARGET,))


def _pin_executor():
    """One external pin source owned by its external producer."""
    ownership = compile_ownership(
        (InputField("ip", "pin", 1),),
        (InputOwner("ip", "pin", 0, 1, "source", "external"),))
    decoder = OnlineCaseDecoder(
        sources=(OnlineSource("ip.pin", "source", "ip", "IP_TO_IP", "ip",
                              port="pin", coverage_target_ids=("ip.observed",)),),
        ownership=ownership, schedule=("ip",), instruction_start=0,
        instruction_end=4, advance_rounds=2, max_input_bytes=8)
    return _online_executor(decoder, ownership=ownership, schedule=("ip",),
                            path_id="ip", targets=(_IP_TARGET,))


def _bound_pin_ownership():
    """The same pin, now owned by an upstream producer instead of a fuzzer."""
    return compile_ownership(
        (InputField("ip", "pin", 1),),
        (InputOwner("ip", "pin", 0, 1, "bound", "other.out"),))


def _caught(call):
    with pytest.raises(ValueError) as failure:
        call()
    rejection = rc.rejection_of(failure.value)
    assert rejection is not None, failure.value
    return rejection


# --------------------------------------------------------------------------
# Real decode refusals in the receipt: one per layer
# --------------------------------------------------------------------------

def _long_slot_refusal():
    """A slot carrying more than one admitted record is unbounded input."""
    executor, sessions = _instruction_executor()
    return executor, sessions, (NOP_RAW, NOP_RAW)


def _exhausted_reservation_refusal():
    """No source remains inside the reservation, so decode refuses first."""
    executor, sessions = _instruction_executor(instruction_start=0,
                                               instruction_end=0)
    return executor, sessions, (NOP_RAW,)


def _window_denied_refusal():
    """The only declared window is read-only, so a store cannot be built."""
    executor, sessions = _instruction_executor(windows=(READ_ONLY_WINDOW,))
    return executor, sessions, (MMIO_SW_RAW,)


def _bound_input_refusal():
    """A pin whose compiled owner became a producer instead of the fuzzer."""
    executor, sessions = _pin_executor()
    executor.online_decoder.ownership = _bound_pin_ownership()
    return executor, sessions, (bytes((0, 0, 0, 7, 0, 0, 0, 0)),)


DECODE_REFUSALS = (
    pytest.param(_long_slot_refusal, "decode.unbounded_input", "input.raw",
                 id="decode-unbounded-input"),
    pytest.param(_exhausted_reservation_refusal, "budget.exhausted",
                 "instruction.cursor", id="budget-exhausted"),
    pytest.param(_window_denied_refusal, "mmio.window_denied", "mmio.operation",
                 id="mmio-window-denied"),
    pytest.param(_bound_input_refusal, "ownership.bound_input", "source.port",
                 id="ownership-bound-input"),
)


@pytest.mark.parametrize("build,code,pointer", DECODE_REFUSALS)
def test_decode_refusal_reaches_the_receipt_with_code_and_pointer(build, code, pointer):
    executor, sessions, records = build()
    delivered = []
    before_cursor = executor.online_decoder.instruction_cursor
    executor.execute_batch(InputBatch(3, 8, (records,)),
                           on_receipt=delivered.append)

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    # The refusal is versioned, layered, and points at the failing field.
    assert receipt.status == "input_invalid"
    assert receipt.rejection is not None
    assert set(receipt.rejection) == {"schema_version", "code", "pointer", "detail"}
    assert receipt.rejection["schema_version"] == "candidate_rejection.v1"
    assert (receipt.rejection["code"], receipt.rejection["pointer"]) == (code, pointer)
    assert json.loads(json.dumps(receipt.rejection)) == receipt.rejection
    assert rc.Rejection.from_document(receipt.rejection).code.value == code
    assert delivered == [receipt]
    # The decision record carries the very same document.
    assert decision["rejection"] == receipt.rejection
    # Legacy keys keep their existing names and values.
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "decode_rejected"
    assert decision["admitted_status"] == "not_admitted"
    assert decision["committed"] is False
    assert decision["source_selection_reason"] is None
    assert decision["case_id"] is None
    # The refusal happened before any RTL command and consumed nothing.
    assert executor.session.cases == ()
    assert all(session.accepted == [] for session in sessions.values())
    assert executor.online_decoder.instruction_cursor == before_cursor
    assert executor.online_decoder._sequence == 0
    assert receipt.total_local_ticks == 0
    assert receipt.online_case is None
    assert receipt.trace is None
    assert executor._session_stop_reason is None


def test_rejection_codes_are_the_frozen_catalog():
    """The catalog grew to 37 codes; no existing code changed identity."""
    assert rc.rejection_code_catalog_sha256() == REJECTION_CATALOG_SHA256


# --------------------------------------------------------------------------
# Admitted candidates keep a null rejection
# --------------------------------------------------------------------------

def test_direct_and_weighted_selection_commit_without_a_rejection():
    # Byte two names a configured source directly only when it is in range.
    for selector, expected in ((0, "direct_source_byte"),
                               (3, "feedback_weighted_legal_source")):
        executor, sessions = _instruction_executor()
        executor.execute_batch(InputBatch(4 + selector, 8,
                                          ((bytes((0, 0, selector, 0, 0, 0, 0, 0)),),)))
        receipt = executor.receipts[-1]
        decision = executor.online_decisions[-1]
        assert receipt.status == "complete"
        assert receipt.rejection is None
        assert decision["rejection"] is None
        assert decision["source_selection_reason"] == expected
        assert decision["candidate_disposition"] == "admitted"
        assert decision["candidate_disposition_reason"] == "rtl_case_committed"
        assert decision["committed"] is True
        assert sessions["cpu"].accepted[0][1] == NOP_BYTES
        # Old keys and old receipt fields are still present, not renamed.
        assert {"candidate_disposition", "candidate_disposition_reason",
                "source_selection_reason", "rejection"} <= set(decision)
        assert {"raw_sha256", "status", "path_id", "online_case",
                "online_weights", "rejection"} <= set(asdict(receipt))


def test_degraded_fallback_is_admitted_and_not_a_rejection():
    """A fragment that does not fit degrades to a NOP, not to a refusal."""
    executor, sessions = _instruction_executor()
    executor.execute_batch(InputBatch(6, 8, ((DEGRADED_RAW,),)))
    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == "complete"
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert decision["candidate_disposition"] == "admitted"
    assert sessions["cpu"].accepted[0][1] == NOP_BYTES


# --------------------------------------------------------------------------
# Uncertainty is never written as a structured rejection
# --------------------------------------------------------------------------

@pytest.mark.parametrize("halted,status", ((False, "environment_error"),
                                           (True, "uncertain_effect")))
def test_submit_failure_stays_uncertain_without_a_rejection(halted, status):
    executor, _ = _instruction_executor()
    refusal = rc.Rejection(rc.RejectionCode.SLOT_MATERIALIZED, "memory.address",
                           {"occupant": "STORE"})

    def fail_after_attempt(case):
        if halted:
            executor.session._halt_reason = "uncertain_effect"
        raise rc.RejectionError("slot was materialized by a real read", refusal)

    with patch.object(executor.session, "submit_case",
                      side_effect=fail_after_attempt):
        executor.execute_batch(InputBatch(7, 8, ((NOP_RAW,),)))

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == status
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert decision["candidate_disposition"] == "uncertain"
    assert decision["candidate_disposition_reason"] == "rtl_submit_failed_or_partial"
    assert "materialized by a real read" in receipt.error


def test_commit_refusal_after_submit_is_uncertain_not_rejected():
    executor, sessions = _instruction_executor()

    def shrink_reservation(case, selected):
        # The submit already ran; the reservation changed before admission.
        executor.online_decoder.instruction_end = \
            executor.online_decoder.instruction_cursor

    with patch.object(executor, "_validate_online_runtime_selection",
                      side_effect=shrink_reservation):
        executor.execute_batch(InputBatch(8, 8, ((NOP_RAW,),)))

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert sessions["cpu"].accepted  # the case really reached the harness
    assert decision["candidate_disposition"] == "uncertain"
    assert decision["candidate_disposition_reason"] == "commit_after_submit_uncertain"
    assert decision["committed"] is False
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert receipt.status != "input_invalid"


def test_pre_submit_validation_failure_keeps_its_legacy_label_without_a_code():
    """No code covers this checkout, so no code may be invented for it."""
    executor, _ = _instruction_executor()
    with patch.object(executor, "_validate_online_runtime_selection",
                      side_effect=ValueError("selection rejected")):
        executor.execute_batch(InputBatch(9, 8, ((NOP_RAW,),)))
    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "pre_submit_validation_rejected"
    assert decision["rejection"] is None
    assert receipt.rejection is None
    assert receipt.status == "environment_error"


def test_unclassified_decode_error_keeps_input_invalid_without_a_code():
    executor, _ = _instruction_executor()
    with patch.object(executor.online_decoder, "decode_candidate",
                      side_effect=ValueError("decoder refused without a code")):
        executor.execute_batch(InputBatch(10, 8, ((NOP_RAW,),)))
    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == "input_invalid"
    assert "decoder refused without a code" in receipt.error
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "decode_rejected"


# --------------------------------------------------------------------------
# Repeated slots are idempotent
# --------------------------------------------------------------------------

def test_repeated_slot_returns_the_same_rejection_receipt():
    executor, _ = _instruction_executor(windows=(READ_ONLY_WINDOW,))
    batch = InputBatch(11, 8, ((MMIO_SW_RAW,),))
    first, second = [], []
    executor.execute_batch(batch, on_receipt=first.append)
    coverage = executor.execute_batch(batch, on_receipt=second.append)

    assert len(executor.receipts) == 1
    assert len(executor.online_decisions) == 1
    assert first == [executor.receipts[0]]
    assert second == [executor.receipts[0]]
    assert first[0] is second[0]
    assert first[0].rejection["code"] == "mmio.window_denied"
    assert first[0].rejection["pointer"] == "mmio.operation"
    assert json.dumps(asdict(first[0]), sort_keys=True) == \
        json.dumps(asdict(second[0]), sort_keys=True)
    assert coverage == (bytes(len(executor.targets)),)


# --------------------------------------------------------------------------
# Pre-change receipts still parse and replay
# --------------------------------------------------------------------------

def _legacy_row(raw: bytes) -> dict:
    """A receipt row exactly as a pre-change run wrote it."""
    row = {"raw_sha256": hashlib.sha256(raw).hexdigest(),
           "genome_sha256": "genome", "path_id": "path",
           "manifest_sha256": "manifest", "semantic_sha256": "semantic",
           "status": "complete", "total_local_ticks": 3, "coverage_hex": "00",
           "violations": []}
    assert not {"rejection", "candidate_decode_disposition"} & set(row)
    return row


class _StubReplayExecutor:
    """Replay stub returning the execution identity saved in the row."""

    def __init__(self, **kwargs):
        self.receipts: list[SimpleNamespace] = []

    def execute_batch(self, batch):
        self.receipts.append(SimpleNamespace(
            status="complete", genome_sha256="genome", path_id="path",
            manifest_sha256="manifest", semantic_sha256="semantic",
            total_local_ticks=3, coverage_hex="00", violations=()))


def _write_offline_bundle(output: Path, raw: bytes, rows: list[dict]) -> None:
    (output / "corpus").mkdir(parents=True)
    manifest = {"decoder": "stub"}
    (output / "decoder_manifest.json").write_text(json.dumps(manifest))
    (output / "report.json").write_text(json.dumps({
        "decoder_manifest_sha256": hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()}))
    (output / "targets.json").write_text(json.dumps([{
        "target_id": "target", "component": "cpu", "port": "irq",
        "mask": 1, "value": 1}]))
    (output / "corpus" / "entry_0000.json").write_text(json.dumps({
        "entry": {"inputs": list(raw)}}))
    (output / "receipts.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows))


@pytest.mark.parametrize("extra", (
    pytest.param({}, id="pre-change-row"),
    pytest.param({"rejection": None}, id="admitted-new-row"),
    pytest.param({"rejection": {
        "schema_version": "candidate_rejection.v1",
        "code": "mmio.window_denied", "pointer": "mmio.operation",
        "detail": {"operation": "SW"}}}, id="refused-new-row"),
))
def test_saved_receipt_rows_replay_with_or_without_the_new_keys(tmp_path, extra):
    raw = bytes(8)
    output = tmp_path / "run"
    _write_offline_bundle(output, raw, [{**_legacy_row(raw), **extra}])
    with patch("myfuzz.integration.scenario_rfuzz_replay."
               "GenomeRecordDecoder.from_document",
               return_value=SimpleNamespace(max_records=1)), \
            patch("myfuzz.integration.scenario_rfuzz_replay."
                  "ScenarioRfuzzExecutor", _StubReplayExecutor):
        result = replay_scenario_rfuzz_corpus(output, lambda: None)
    assert (result.total_entries, result.matched_entries,
            result.mismatches) == (1, 1, ())


# --------------------------------------------------------------------------
# The live receipt journal carries the same document
# --------------------------------------------------------------------------

def _run_mocked_live(executor: ScenarioRfuzzExecutor, root: Path,
                     records: tuple[bytes, ...]) -> list[dict]:
    """Drive the live transport with an offline endpoint and no subprocess."""
    binary = root / "client"
    binary.write_bytes(b"client")
    output = root / "run"
    endpoint = MagicMock()
    endpoint.directory = root / "fifo"
    endpoint.receive.side_effect = [(1, 2)]
    client = Mock(pid=123456789, returncode=0)
    client.poll.side_effect = [None, 0]
    batch = InputBatch(1, 8, (records,))

    def process(*args, on_receipt, **kwargs):
        executor.execute_batch(batch, on_receipt=on_receipt)
        return (1, 2)

    with patch("myfuzz.integration.scenario_rfuzz_live.FifoEndpoint") as endpoint_type, \
            patch("myfuzz.integration.scenario_rfuzz_live.subprocess.Popen",
                  return_value=client), \
            patch("myfuzz.integration.scenario_rfuzz_live.os.killpg"), \
            patch("myfuzz.integration.scenario_rfuzz_live._rfuzz_client_identity",
                  return_value={"binary_sha256":
                                hashlib.sha256(b"client").hexdigest()}), \
            patch.object(executor, "process_owned_pair", side_effect=process):
        endpoint_type.return_value.__enter__.return_value = endpoint
        run_scenario_rfuzz_live(executor=executor, client_binary=binary,
                                output_dir=output, duration_seconds=1,
                                max_tests=1)
    return [json.loads(line) for line in
            (output / "receipts.jsonl").read_text().splitlines()]


def test_live_receipt_journal_carries_the_structured_rejection(tmp_path):
    executor, _ = _instruction_executor(windows=(READ_ONLY_WINDOW,))
    rows = _run_mocked_live(executor, tmp_path, (MMIO_SW_RAW,))
    assert [row["status"] for row in rows] == ["input_invalid"]
    assert rows[0]["rejection"] == executor.receipts[0].rejection
    assert rows[0]["rejection"]["code"] == "mmio.window_denied"
    assert rows[0]["rejection"]["pointer"] == "mmio.operation"
    assert rows[0]["candidate_disposition"] == "rejected"
    assert rows[0]["candidate_disposition_reason"] == "decode_rejected"


def test_live_receipt_journal_keeps_a_null_rejection_for_an_admitted_case(tmp_path):
    # One extra reserved word keeps a mutation hint available after the commit.
    executor, _ = _instruction_executor(instruction_end=0x1008)
    rows = _run_mocked_live(executor, tmp_path, (NOP_RAW,))
    assert [row["status"] for row in rows] == ["complete"]
    assert "rejection" in rows[0]
    assert rows[0]["rejection"] is None
    assert rows[0]["candidate_disposition"] == "admitted"
    assert rows[0]["candidate_disposition_reason"] == "rtl_case_committed"
    assert rows[0]["source_selection_reason"] == "direct_source_byte"


# --------------------------------------------------------------------------
# Why isa.* and mmio.out_of_window cannot come from an online decode
# --------------------------------------------------------------------------

def test_online_instruction_decode_never_raises_isa_or_out_of_window_codes():
    """Decoded fragments stay inside the admitted set and their windows."""
    executor, _ = _instruction_executor(instruction_end=0x1020, windows=(WINDOW,))
    decoder = executor.online_decoder
    refused = set()
    for selector in range(256):
        for window_selector in range(0, 256, 17):
            for payload in (b"\x00\x00\x00", b"\xff\xff\xff", b"\x80\x40\x20"):
                raw = bytes((0, 0, 0, selector, window_selector, *payload))
                case, disposition = decoder.decode_candidate(raw)
                if disposition.disposition == "rejected":
                    refused.add(str(disposition.rejection.code))
                if case is not None:
                    # Raises if the decoder ever emits an unadmitted operation.
                    validate_instruction_bytes(case.source.data)
    assert "isa.disallowed_operation" not in refused
    assert "mmio.out_of_window" not in refused
    assert refused <= {"mmio.bad_width", "mmio.no_aligned_address",
                       "mmio.window_denied"}


def test_out_of_window_refusal_still_exists_for_an_explicit_address():
    """The code is real; only address mutation keeps the window consistent."""
    rejection = _caught(lambda: mmio_access_fragment(
        "LW", 0x50000000, windows=(WINDOW,), base_register=1, data_register=2))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.MMIO_OUT_OF_WINDOW, "mmio.address")


def test_bound_input_is_refused_before_any_candidate_or_receipt_exists():
    """The ownership layer refuses the configuration, not a decoded input."""
    with pytest.raises(ValueError) as failure:
        OnlineCaseDecoder(
            sources=(OnlineSource("ip.pin", "source", "ip", "IP_TO_IP", "ip",
                                  port="pin"),),
            ownership=_bound_pin_ownership(), schedule=("ip",),
            instruction_start=0, instruction_end=4)
    assert isinstance(failure.value, rc.RejectionError)
    rejection = rc.rejection_of(failure.value)
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.OWNERSHIP_BOUND_INPUT, "source.port")
    assert rc.Rejection.from_document(rejection.document()) == rejection


def test_pre_change_receipt_construction_still_works():
    """A caller that never passes the new field keeps the old default."""
    receipt = ScenarioRfuzzReceipt(
        run_id="legacy", buffer_id=1, slot=0, raw_sha256="r" * 64,
        genome_sha256=None, semantic_sha256=None, status="input_invalid",
        total_local_ticks=0, coverage_hex="00", violations=(),
        error="ValueError: legacy refusal", trace=None)
    assert receipt.rejection is None
    assert "rejection" in asdict(receipt)
