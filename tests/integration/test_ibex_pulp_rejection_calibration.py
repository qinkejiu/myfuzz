"""The rejection calibration runtime manufactures real refusals from declarations.

Each calibration class is a declared decoder configuration over the shipped
Ibex + dual PULP GPIO online profile: a tightened input bound, an already
consumed instruction reservation, an MMIO window that denies the admitted
operation, a window that cannot hold the admitted access, an ownership map
replaced after construction, and a reservation one word past the declared
online slots.  Every refusal is produced by the production decode, MMIO,
ownership or memory code; nothing rewrites decoder state, forges an RTL output,
or injects a receipt.

None of these cases starts Verilator: the local harnesses are offline stubs and
the persistent memory is the real pure-Python model.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from myfuzz.integration.ibex_pulp_rejection_calibration import (
    CALIBRATION_CLASS_ORDER, CALIBRATION_REPORT_NAME, DEFAULT_ARM_SLOTS,
    MAX_ARM_SLOTS, UNCERTAIN_CLASS_ID, CalibrationStep,
    RejectionCalibrationDecoder, build_calibration_plan,
    calibration_class_specs, calibration_report_from_rows,
    make_ibex_pulp_rejection_calibration_decoder,
    recompute_calibration_report, write_calibration_report,
)
from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.scenario import rejection_codes as rc
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import ScenarioSession

RECORD_BYTES = 8
#: Byte three selects the decoded operation class; value three is SW when the
#: calibration decoder admits only SW as an MMIO operation.
SW_RAW = bytes((0, 0, 0, 3, 0, 0, 0, 0))
#: Byte three zero selects the arithmetic class, which touches no MMIO window.
NOP_RAW = bytes(8)
CPU_MEMORY = MemoryRegion("cpu.ram", 0x10000, 0x40000)
TARGETS = (
    CoverageTarget("gpio_a_output_bit0", "gpio_a", "gpio_out", 1, 1),
    CoverageTarget("gpio_b_irq", "gpio_b", "irq", 1, 1),
    CoverageTarget("cpu_external_irq_vector_fetch", "cpu", "instr_addr",
                   0xffffffff, 0x1012c),
    CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),
)

#: The exact refusal each trusted manufacturing means makes reachable.  These
#: expectations are declared here, not read back from the implementation, so a
#: renamed or re-pointed code fails this file.
EXPECTED_REFUSALS = (
    ("decode_unbounded_input", "decode.unbounded_input", "input.raw"),
    ("budget_exhausted", "budget.exhausted", "instruction.cursor"),
    ("mmio_window_denied", "mmio.window_denied", "mmio.operation"),
    ("mmio_bad_width", "mmio.bad_width", "mmio.width"),
    ("mmio_no_aligned_address", "mmio.no_aligned_address", "mmio.windows"),
    ("ownership_bound_input", "ownership.bound_input", "source.port"),
    ("ownership_fixed_input", "ownership.fixed_input", "source.port"),
)
#: Classes whose refusal needs the decoded operation class to be MMIO.
MMIO_CLASSES = frozenset({"mmio_window_denied", "mmio_bad_width",
                          "mmio_no_aligned_address"})


class _OfflineCpu:
    """Offline CPU harness backed by the real persistent memory model."""

    def __init__(self, memory: PersistentMemory) -> None:
        self.memory = memory
        self.accepted: list[tuple[int, bytes, str]] = []
        self.cases: list[str] = []

    def begin_case(self, testcase_id: str) -> None:
        self.cases.append(testcase_id)

    def step_local(self, inputs):
        self.memory.advance_step()
        return {"observed": 0}

    def end_case(self) -> None:
        pass

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        self.memory.declare_instruction_slots(address, count)

    def accept_instructions(self, address: int, data: bytes, *,
                            source_event_id: str) -> None:
        # The real reservation model decides; this stub only forwards.
        self.memory.accept_instructions(address, data,
                                        source_event_id=source_event_id)
        self.accepted.append((address, bytes(data), source_event_id))


class _OfflineIp:
    """Offline routed-IP harness: steps locally and accepts no fuzz input."""

    def __init__(self) -> None:
        self.accepted: list[tuple[int, bytes, str]] = []

    def begin_case(self, testcase_id: str) -> None:
        pass

    def step_local(self, inputs):
        return {"observed": 0}

    def end_case(self) -> None:
        pass


def _offline_base(*, bootstrap=None):
    """The shipped profile declaration without a runtime path contract.

    The calibration classes act on declarations the profile itself carries
    (sources, ownership, MMIO windows, instruction reservation), so the offline
    harnesses below can exercise the very same class configurations without
    binding the real routers that only generated RTL harnesses provide.
    """
    from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
    profile = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    return OnlineCaseDecoder(
        sources=tuple(profile.sources), ownership=profile.ownership,
        schedule=tuple(profile.advances[0].schedule),
        instruction_start=profile.instruction_start,
        instruction_end=profile.instruction_end,
        instruction_cursor=profile.instruction_cursor,
        windows=tuple(profile.windows), advance_rounds=len(profile.advances),
        max_input_bytes=profile.max_input_bytes, graph=None,
        max_steps=profile.max_steps,
        allowed_mmio_operations=tuple(profile.allowed_mmio_operations),
        support_words=profile.support_words)


def _offline_executor(plan, *, bootstrap=None):
    """Wire the calibration decoder around offline harnesses and real memory."""
    bootstrap = (make_ibex_pulp_dual_source_stream_bootstrap()
                 if bootstrap is None else bootstrap)
    decoder = RejectionCalibrationDecoder(
        base=_offline_base(bootstrap=bootstrap), plan=plan)
    memory = PersistentMemory(regions=(CPU_MEMORY,), initialization_seed=0,
                              max_initialized_bytes=1 << 20)
    sessions = {"cpu": _OfflineCpu(memory), "gpio_a": _OfflineIp(),
                "gpio_b": _OfflineIp()}
    runner = ScenarioRunner(sessions=sessions, ownership=decoder.ownership,
                            bindings=())
    # The shipped runtime checks every admitted case with this checker, and it
    # never turns a missing stage into a DUT failure, so a calibrated run must
    # stay violation free.
    session = ScenarioSession(bootstrap.template, runner,
                              checker=IbexPulpOnlineChecker())
    session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    session.begin()
    executor = ScenarioRfuzzExecutor(
        run_id="rejection-calibration", factory=lambda: runner,
        targets=TARGETS, session=session, online_decoder=decoder)
    return executor, sessions, session, bootstrap


def _record(class_id: str) -> bytes:
    return SW_RAW if class_id in MMIO_CLASSES else NOP_RAW


def _declared_configuration(decoder: RejectionCalibrationDecoder,
                            class_id: str) -> dict:
    document = decoder.calibration_document()
    step = next(item for item in document["plan"] if item["class_id"] == class_id)
    return step["declared_configuration"]


def _pin8_owner(declared: dict) -> tuple[str, str]:
    owners = [owner for owner in declared["ownership"]["owners"]
              if (owner["component_id"], owner["port"], owner["bit_offset"],
                  owner["width"]) == ("gpio_b", "gpio_in", 8, 1)]
    assert len(owners) == 1
    return owners[0]["kind"], owners[0]["producer_ref"]


# --------------------------------------------------------------------------
# Every trusted configuration produces its exact code and pointer before RTL
# --------------------------------------------------------------------------

@pytest.mark.parametrize("class_id,code,pointer", EXPECTED_REFUSALS)
def test_trusted_configuration_refuses_with_its_exact_code_before_any_rtl(
        class_id, code, pointer):
    plan = build_calibration_plan(classes=(class_id,))
    executor, sessions, session, _ = _offline_executor(plan)
    events_before = executor.session.runner.event_count
    ticks_before = dict(executor.session.runner.local_ticks)
    cursor_before = executor.online_decoder.instruction_cursor
    delivered: list = []
    executor.execute_batch(InputBatch(3, RECORD_BYTES, ((_record(class_id),),)),
                           on_receipt=delivered.append)

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    assert receipt.status == "input_invalid"
    assert receipt.rejection is not None
    assert receipt.rejection["schema_version"] == "candidate_rejection.v1"
    assert (receipt.rejection["code"], receipt.rejection["pointer"]) == (code, pointer)
    assert rc.Rejection.from_document(receipt.rejection).code.value == code
    assert decision["rejection"] == receipt.rejection
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "decode_rejected"
    assert delivered == [receipt]
    # The refusal happened before any RTL command and consumed nothing.
    assert executor.session.runner.event_count == events_before
    assert dict(executor.session.runner.local_ticks) == ticks_before
    assert session.cases == ()
    assert all(harness.accepted == [] for harness in sessions.values())
    assert executor.online_decoder.instruction_cursor == cursor_before
    assert executor.online_decoder._sequence == 0
    assert receipt.total_local_ticks == 0
    assert receipt.online_case is None
    assert receipt.trace is None
    assert executor._session_stop_reason is None
    # The refusal comes from a declared configuration, not a rewritten state.
    spec = calibration_class_specs()[class_id]
    assert (spec.expected_code, spec.expected_pointer) == (code, pointer)
    assert spec.expected_disposition == "rejected"
    assert spec.expected_reason == "decode_rejected"
    assert spec.means
    _assert_trusted_declaration(class_id, _declared_configuration(
        executor.online_decoder, class_id))


def _assert_trusted_declaration(class_id: str, declared: dict) -> None:
    if class_id == "decode_unbounded_input":
        assert declared["max_input_bytes"] == 1
        assert declared["arriving_record_bytes"] == RECORD_BYTES
    elif class_id == "budget_exhausted":
        assert declared["instruction_cursor"] == declared["instruction_end"]
        assert declared["sources"] == ["cpu.online_instruction"]
    elif class_id == "mmio_window_denied":
        assert declared["allowed_mmio_operations"] == ["SW"]
        assert [window["readable"] for window in declared["mmio_windows"]] == [True]
        assert [window["writable"] for window in declared["mmio_windows"]] == [False]
    elif class_id == "mmio_bad_width":
        assert declared["allowed_mmio_operations"] == ["SW"]
        assert [window["writable"] for window in declared["mmio_windows"]] == [True]
        assert [window["write_widths"] for window in declared["mmio_windows"]] == [[1]]
    elif class_id == "mmio_no_aligned_address":
        assert declared["allowed_mmio_operations"] == ["SW"]
        assert [window["size"] for window in declared["mmio_windows"]] == [1]
        assert [window["write_widths"] for window in declared["mmio_windows"]] == [[4]]
    elif class_id == "ownership_bound_input":
        assert declared["sources"] == ["gpio_b.external_pin8"]
        assert declared["ownership_replaced_after_construction"] is True
        assert _pin8_owner(declared) == ("bound", "gpio_a.gpio_out")
    elif class_id == "ownership_fixed_input":
        assert declared["sources"] == ["gpio_b.external_pin8"]
        assert declared["ownership_replaced_after_construction"] is True
        assert _pin8_owner(declared) == ("fixed", "constant_zero")
    else:  # pragma: no cover - the parametrization above is exhaustive
        raise AssertionError(f"unexpected class {class_id}")


# --------------------------------------------------------------------------
# Uncertainty is reported as uncertain, never as a structured rejection
# --------------------------------------------------------------------------

def test_uncertain_class_is_submit_failure_not_a_rejection():
    plan = build_calibration_plan(classes=(UNCERTAIN_CLASS_ID,))
    executor, sessions, session, bootstrap = _offline_executor(plan)
    executor.execute_batch(InputBatch(4, RECORD_BYTES, ((NOP_RAW,),)))

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    # The case was decoded and submitted; the real memory reservation model then
    # refused the instruction admission, so no clean refusal can be claimed.
    assert session.cases != ()
    assert session.cases[-1].source.address == bootstrap.instruction_end
    assert sessions["cpu"].accepted == []
    assert "instruction bytes are outside declared online slots" in receipt.error
    assert session._halt_reason == "uncertain_effect"
    assert receipt.status == "uncertain_effect"
    assert receipt.rejection is None
    assert decision["rejection"] is None
    assert decision["candidate_disposition"] == "uncertain"
    assert decision["candidate_disposition_reason"] == "rtl_submit_failed_or_partial"
    assert decision["committed"] is False
    assert decision["admitted_status"] == "submit_failed_or_partial"
    spec = calibration_class_specs()[UNCERTAIN_CLASS_ID]
    assert (spec.expected_code, spec.expected_pointer) == (None, None)
    assert spec.expected_disposition == "uncertain"
    assert spec.expected_reason == "rtl_submit_failed_or_partial"
    declared = _declared_configuration(executor.online_decoder, UNCERTAIN_CLASS_ID)
    assert declared["instruction_start"] == bootstrap.instruction_end
    assert declared["declared_slot_region"] == {
        "start": bootstrap.instruction_start, "end": bootstrap.instruction_end,
        "count": bootstrap.instruction_count}


def test_uncertain_receipt_is_never_counted_as_a_structured_rejection(tmp_path):
    plan = build_calibration_plan(classes=(UNCERTAIN_CLASS_ID,))
    rows = [{"buffer_id": 5, "slot": 0, "raw_sha256": "a" * 64,
             "status": "uncertain_effect",
             "candidate_disposition": "uncertain",
             "candidate_disposition_reason": "rtl_submit_failed_or_partial",
             "rejection": None}]
    report = calibration_report_from_rows(rows, plan=plan)
    assert report["complete"] is True
    assert report["receipts"]["structured_rejections"] == 0
    assert report["receipts"]["uncertain_receipts"] == 1
    assert report["classes"][0]["observations"][0]["code"] is None
    assert report["classes"][0]["observations"][0]["disposition"] == "uncertain"

    # The same journal can never satisfy a rejection class.
    other = calibration_report_from_rows(
        rows, plan=build_calibration_plan(classes=("budget_exhausted",)))
    assert other["complete"] is False
    assert other["unsatisfied"] == ["budget_exhausted"]
    assert other["classes"][0]["observed_count"] == 0

    # A rejection row cannot satisfy the uncertain class either.
    reversed_rows = [{"buffer_id": 5, "slot": 1, "raw_sha256": "b" * 64,
                      "status": "input_invalid",
                      "candidate_disposition": "rejected",
                      "candidate_disposition_reason": "decode_rejected",
                      "rejection": {"schema_version": "candidate_rejection.v1",
                                    "code": "budget.exhausted",
                                    "pointer": "instruction.cursor",
                                    "detail": None}}]
    assert calibration_report_from_rows(
        reversed_rows, plan=plan)["complete"] is False
    assert calibration_report_from_rows(
        reversed_rows,
        plan=build_calibration_plan(classes=("budget_exhausted",)))["complete"] is True

    written = write_calibration_report(tmp_path, plan=plan, rows=rows)
    assert written["complete"] is True
    assert json.loads((tmp_path / CALIBRATION_REPORT_NAME).read_text()) == written
    (tmp_path / "receipts.jsonl").write_text("")
    assert recompute_calibration_report(tmp_path, plan=plan)["complete"] is False


# --------------------------------------------------------------------------
# Repeated slots are idempotent
# --------------------------------------------------------------------------

def test_repeated_slot_returns_the_same_rejection_receipt():
    plan = build_calibration_plan(classes=("mmio_window_denied",))
    executor, _, _, _ = _offline_executor(plan)
    batch = InputBatch(11, RECORD_BYTES, ((SW_RAW,),))
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
# Without a calibration plan the online path is unchanged
# --------------------------------------------------------------------------

def test_empty_plan_reproduces_the_base_online_decode_exactly():
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    base = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    decoder = make_ibex_pulp_rejection_calibration_decoder(plan=(),
                                                          bootstrap=bootstrap)
    assert decoder.calibration_document()["enabled"] is False
    assert decoder.calibration_document()["plan"] == []
    # The uncalibrated document is the shipped profile declaration, unchanged.
    assert {key: value for key, value in decoder.document().items()
            if key != "rejection_calibration"} == base.document()
    for raw in (NOP_RAW, SW_RAW, bytes((0, 0, 1, 5, 0x9a, 1, 3, 0x40))):
        base_case, base_disposition = base.decode_candidate(raw)
        case, disposition = decoder.decode_candidate(raw)
        assert asdict(case) == asdict(base_case)
        assert disposition.document() == base_disposition.document()
        assert decoder.commit_candidate(case).document() == \
            base.commit_candidate(base_case).document()
    assert decoder.instruction_cursor == base.instruction_cursor
    assert decoder._sequence == base._sequence


def test_calibrated_slots_never_collide_with_the_shipped_case_identities():
    """Co-existing decoders must not reuse a case identity in one session."""
    from myfuzz.integration.ibex_pulp_rejection_calibration import (
        IDENTITY_NAMESPACE_STEP, MAX_LIVE_TESTS,
    )
    assert IDENTITY_NAMESPACE_STEP > MAX_LIVE_TESTS
    plan = build_calibration_plan()
    executor, _, _, _ = _offline_executor(plan)
    executor.execute_batch(InputBatch(13, RECORD_BYTES,
                                      tuple((NOP_RAW,) for _ in range(12))))
    identifiers = [decision["case_id"] for decision in executor.online_decisions
                   if decision["case_id"] is not None]
    assert len(identifiers) == len(set(identifiers))
    offsets = [step["declared_configuration"]["case_identity_offset"]
               for step in executor.online_decoder.calibration_document()["plan"]]
    assert len(set(offsets)) == len(offsets)
    assert min(offsets) > 0
    state = executor.online_decoder.calibration_state()
    assert state["case_identities"] == len(set(identifiers))


def test_a_repeated_case_identity_fails_closed_instead_of_submitting_it():
    """A decode without commit is a caller error; it must not reach the session."""
    plan = build_calibration_plan(classes=("mmio_bad_width",))
    executor, sessions, session, _ = _offline_executor(plan)
    # Byte three zero is admitted by this class, so the same slot would carry
    # the same case identity twice.
    with pytest.raises(ValueError, match="case identity repeated"):
        executor.online_decoder.decode_candidate(NOP_RAW)
        executor.online_decoder.decode_candidate(NOP_RAW)
    assert session.cases == ()


def test_calibration_manifest_discloses_every_declared_class():
    plan = build_calibration_plan()
    decoder = make_ibex_pulp_rejection_calibration_decoder(plan=plan)
    document = decoder.calibration_document()
    assert document["schema_version"] == "rejection_calibration.v1"
    assert document["enabled"] is True
    assert [step["class_id"] for step in document["plan"]] == \
        list(CALIBRATION_CLASS_ORDER)
    assert {step["class_id"] for step in document["plan"]} == \
        {class_id for class_id, _, _ in EXPECTED_REFUSALS} | {UNCERTAIN_CLASS_ID}
    for step in document["plan"]:
        assert step["arm_slots"] == DEFAULT_ARM_SLOTS
        assert step["means"]
        assert step["declared_configuration"]
    assert decoder.document()["rejection_calibration"] == document


def test_the_shipped_profile_is_the_declared_calibration_subject():
    """The classes act on the shipped declaration; these are its identities."""
    from myfuzz.integration.ibex_pulp_rejection_calibration import (
        CPU_INSTRUCTION_SOURCE, EXTERNAL_PIN_SOURCE, PIN_FIELD,
    )
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    profile = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    instruction = [source for source in profile.sources
                   if source.kind == "instruction"]
    external = [source for source in profile.sources if source.kind == "source"]
    assert [source.source_id for source in instruction] == [CPU_INSTRUCTION_SOURCE]
    assert [source.source_id for source in external] == [EXTERNAL_PIN_SOURCE]
    assert (external[0].component, external[0].port, external[0].bit_offset) == \
        PIN_FIELD
    assert len(profile.windows) == 1 and profile.windows[0].writable
    assert profile.max_input_bytes == RECORD_BYTES
    assert profile.instruction_start < profile.instruction_end
    # The calibration decoder carries that very declaration to the live session.
    decoder = make_ibex_pulp_rejection_calibration_decoder(plan=())
    for attribute in ("sources", "windows", "instruction_start",
                      "instruction_end", "allowed_mmio_operations",
                      "max_input_bytes", "max_steps", "support_words"):
        assert getattr(decoder, attribute) == getattr(profile, attribute)
    assert decoder.sources == profile.sources
    assert decoder.runtime_contract == profile.runtime_contract
    assert decoder.runtime_paths == profile.runtime_paths
    assert decoder.graph.edge_document() == profile.graph.edge_document()
    assert decoder.ownership.document() == profile.ownership.document()
    assert decoder.document()["runtime_contract"] == profile.document()["runtime_contract"]
    # The executor's own preflight work over these objects is unchanged.
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    prepared = PreparedRuntimePathContract(decoder.graph, decoder.runtime_contract,
                                          decoder.runtime_paths)
    expected = PreparedRuntimePathContract(profile.graph, profile.runtime_contract,
                                          profile.runtime_paths)
    assert prepared.document() == expected.document()
    assert prepared.path_ids == expected.path_ids
    assert decoder.trusted_for_search is True
    for direction, path in decoder.runtime_paths:
        for source_id in path.source_ids:
            source = decoder.graph.sources[source_id]
            if source.kind != "source":
                continue
            assert decoder.ownership.mutation_source(
                source.component, source.port, source.bit_offset, source.width,
                direction=direction) == profile.ownership.mutation_source(
                    source.component, source.port, source.bit_offset,
                    source.width, direction=direction)


def test_a_class_disarms_once_its_declared_refusal_is_observed():
    plan = build_calibration_plan(classes=("budget_exhausted",
                                          UNCERTAIN_CLASS_ID))
    executor, _, _, _ = _offline_executor(plan)
    executor.execute_batch(InputBatch(12, RECORD_BYTES,
                                      ((NOP_RAW,), (NOP_RAW,), (NOP_RAW,))))
    state = executor.online_decoder.calibration_state()
    assert state["plan"][0]["class_id"] == "budget_exhausted"
    assert state["plan"][0]["slots_applied"] == 1
    assert state["plan"][0]["satisfied"] is True
    assert state["plan"][1]["class_id"] == UNCERTAIN_CLASS_ID
    # The calibrated refusal never stops the session; the uncertain class does.
    assert executor.receipts[0].rejection["code"] == "budget.exhausted"
    assert executor.receipts[1].rejection is None
    assert executor.online_decisions[-1]["candidate_disposition"] == "uncertain"
    assert len(executor.receipts) == 2
    assert executor._session_stop_reason == "uncertain_effect"


# --------------------------------------------------------------------------
# The declared kfuzz scenario sweep satisfies the whole plan
# --------------------------------------------------------------------------

def _scenario_client_records(*, search_seed: int, stage: int, count: int,
                             template: int = 0) -> tuple[bytes, ...]:
    """Mirror ``ScenarioDecisionMutator::apply`` of the kfuzz scenario client.

    ``third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/mutation/scenario.rs``
    writes byte three as ``decision & 255`` for a mutation index that advances by
    one per decision inside a stage, so one stage sweeps consecutive third bytes.
    """
    epoch = stage - 1
    epoch_offset = ((epoch * 0x85ebca6b) & 0xFFFFFFFF) ^ (
        ((epoch >> 32) * 0xc2b2ae35) & 0xFFFFFFFF)
    seed_offset = (((search_seed & 0xFFFFFFFF) * 0x9e3779b9) & 0xFFFFFFFF) ^ (
        (search_seed >> 32) & 0xFFFFFFFF)
    records = []
    for index in range(count):
        decision = (index + seed_offset + epoch_offset) & 0xFFFFFFFF
        record = bytearray(8)
        record[0] = template
        record[1] = 0
        record[2] = 0
        record[3] = decision & 0xFF
        record[4] = (decision // 16) & 0xFF
        record[5] = 2 if decision % 8 == 7 else 1
        record[6] = (decision // 32) & 0xF
        record[7] = (decision >> 8) & 0xFF
        records.append(bytes(record))
    return tuple(records)


def test_a_declared_client_sweep_satisfies_the_whole_default_plan():
    plan = build_calibration_plan()
    executor, _, _, _ = _offline_executor(plan)
    records = tuple(record
                    for stage in (1, 2, 3, 4)
                    for record in _scenario_client_records(
                        search_seed=11, stage=stage, count=24))
    executor.execute_batch(InputBatch(21, RECORD_BYTES,
                                      tuple((record,) for record in records)))
    state = executor.online_decoder.calibration_state()
    assert state["classes_armed"] == len(CALIBRATION_CLASS_ORDER)
    assert all(step["satisfied"] or step["handed_to_session"]
               for step in state["plan"]), state["plan"]
    assert state["plan"][-1]["handed_to_session"] is True
    report = calibration_report_from_rows(
        [{"buffer_id": 21, "slot": index, "raw_sha256": "0" * 64,
          "status": receipt.status,
          "candidate_disposition": decision["candidate_disposition"],
          "candidate_disposition_reason": decision["candidate_disposition_reason"],
          "rejection": receipt.rejection}
         for index, (receipt, decision) in enumerate(
             zip(executor.receipts, executor.online_decisions))],
        plan=plan)
    assert report["complete"] is True
    # The shipped checker saw no DUT violation, so the run never stopped early.
    assert all(receipt.violations == () for receipt in executor.receipts)
    assert all(receipt.status in ("complete", "input_invalid", "uncertain_effect")
               for receipt in executor.receipts)
    assert executor._session_stop_reason == "uncertain_effect"
    # Every MMIO class was reached by a record whose third byte selects SW.
    for entry in report["classes"]:
        if entry["class_id"] not in MMIO_CLASSES:
            continue
        for observation in entry["observations"]:
            assert records[observation["slot"]][3] % 4 == 3
        assert entry["observed_count"] >= 1


# --------------------------------------------------------------------------
# Illegal calibration configuration is refused
# --------------------------------------------------------------------------
@pytest.mark.parametrize("classes", (
    ("mmio_window_denied", "not_a_class"),
    ("not_a_class",),
    ("",),
    ("budget_exhausted", "budget_exhausted"),
    "mmio_bad_width",
    ("mmio_bad_width", 3),
    ("mmio_bad_width", None),
))
def test_illegal_class_selection_is_refused(classes):
    with pytest.raises(ValueError):
        build_calibration_plan(classes=classes)


@pytest.mark.parametrize("arm_slots", (0, -1, 1.0, True, "8",
                                       MAX_ARM_SLOTS + 1))
def test_illegal_arm_budget_is_refused(arm_slots):
    with pytest.raises(ValueError):
        build_calibration_plan(classes=("budget_exhausted",),
                               arm_slots=arm_slots)


def test_a_hand_built_plan_with_an_unknown_or_overlong_step_is_refused():
    base = make_ibex_pulp_dual_source_online_decoder(bootstrap=None)
    with pytest.raises(ValueError):
        CalibrationStep("not_a_class", 1)
    with pytest.raises(ValueError):
        CalibrationStep("budget_exhausted", MAX_ARM_SLOTS + 1)
    with pytest.raises(ValueError):
        RejectionCalibrationDecoder(base=base, plan=("budget_exhausted",))
    with pytest.raises(ValueError):
        RejectionCalibrationDecoder(
            base=base, plan=(CalibrationStep("budget_exhausted", 1),
                             CalibrationStep("budget_exhausted", 1)))


def test_report_recomputation_refuses_a_malformed_plan(tmp_path):
    with pytest.raises(ValueError):
        calibration_report_from_rows([], plan="all")
    with pytest.raises(ValueError):
        calibration_report_from_rows(
            [], plan=(CalibrationStep("not_a_class", 1),))
    with pytest.raises(ValueError):
        calibration_report_from_rows(
            [], plan=(CalibrationStep("budget_exhausted", 1),),
            plan_document=[{"class_id": "mmio_bad_width", "arm_slots": 1}])
    with pytest.raises(ValueError):
        recompute_calibration_report(tmp_path)
    (tmp_path / CALIBRATION_REPORT_NAME).write_text(
        json.dumps({"schema_version": "rejection_calibration_report.v1",
                    "plan": [{"class_id": "budget_exhausted"}]}) + "\n")
    with pytest.raises(ValueError):
        recompute_calibration_report(tmp_path)


# --------------------------------------------------------------------------
# A real live-receipt journal carries the calibrated refusals
# --------------------------------------------------------------------------

def _run_mocked_live(executor: ScenarioRfuzzExecutor, root: Path,
                     records: tuple[bytes, ...]) -> list[dict]:
    """Drive the live receipt journal with an offline endpoint and no subprocess."""
    binary = root / "client"
    binary.write_bytes(b"client")
    output = root / "run"
    endpoint = MagicMock()
    endpoint.directory = root / "fifo"
    endpoint.receive.side_effect = [(1, 2)]
    client = Mock(pid=123456789, returncode=0)
    client.poll.side_effect = [None, 0]
    # The kfuzz scenario client sends one eight-byte record per test.
    batch = InputBatch(1, RECORD_BYTES, tuple((record,) for record in records))

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
                                output_dir=output, duration_seconds=3600,
                                max_tests=32, max_runs_per_batch=1)
    rows = [json.loads(line) for line in
            (output / "receipts.jsonl").read_text().splitlines()]
    write_calibration_report(output, plan=executor.online_decoder.calibration_plan,
                             plan_document=executor.online_decoder
                             .calibration_document()["plan"],
                             runtime_state=executor.online_decoder.calibration_state())
    return rows


def test_live_journal_carries_every_calibrated_refusal(tmp_path):
    plan = build_calibration_plan()
    executor, _, _, _ = _offline_executor(plan)
    records = (NOP_RAW,          # decode.unbounded_input
               NOP_RAW,          # budget.exhausted
               NOP_RAW, SW_RAW,  # mmio.window_denied
               NOP_RAW, SW_RAW,  # mmio.bad_width
               NOP_RAW, SW_RAW,  # mmio.no_aligned_address
               NOP_RAW,          # ownership.bound_input
               NOP_RAW,          # ownership.fixed_input
               NOP_RAW)          # uncertain
    rows = _run_mocked_live(executor, tmp_path, records)

    codes = [row["rejection"]["code"] if row["rejection"] else None
             for row in rows]
    for class_id, code, pointer in EXPECTED_REFUSALS:
        assert code in codes, class_id
        row = next(item for item in rows
                   if item["rejection"] and item["rejection"]["code"] == code)
        assert row["rejection"]["pointer"] == pointer
        assert row["candidate_disposition"] == "rejected"
        assert row["candidate_disposition_reason"] == "decode_rejected"
    uncertain = next(row for row in rows
                     if row["candidate_disposition"] == "uncertain")
    assert uncertain["rejection"] is None
    assert uncertain["candidate_disposition_reason"] == "rtl_submit_failed_or_partial"
    assert uncertain["status"] == "uncertain_effect"

    report = recompute_calibration_report(tmp_path / "run")
    assert report["complete"] is True
    assert report["unsatisfied"] == []
    assert {step["class_id"] for step in report["plan"]} == \
        {class_id for class_id, _, _ in EXPECTED_REFUSALS} | {UNCERTAIN_CLASS_ID}
    for entry in report["classes"]:
        assert entry["satisfied"] is True, entry["class_id"]
        assert entry["observed_count"] >= 1
    assert report["receipts"]["total"] == len(rows)
    assert report["receipts"]["uncertain_receipts"] == 1
    assert set(report["receipts"]["by_code"]) == \
        {code for _, code, _ in EXPECTED_REFUSALS}
    # The recomputation from the journal alone equals the in-process report.
    written = json.loads((tmp_path / "run" / CALIBRATION_REPORT_NAME).read_text())
    assert written["classes"] == report["classes"]
    assert written["complete"] is True
    assert written["runtime_state"]["plan"][0]["class_id"] == \
        CALIBRATION_CLASS_ORDER[0]


def test_recomputed_report_detects_a_missing_class(tmp_path):
    plan = build_calibration_plan(classes=("budget_exhausted",
                                          UNCERTAIN_CLASS_ID))
    executor, _, _, _ = _offline_executor(plan)
    _run_mocked_live(executor, tmp_path, (NOP_RAW, NOP_RAW))
    report = recompute_calibration_report(tmp_path / "run",
                                         plan=build_calibration_plan())
    assert report["complete"] is False
    assert set(report["unsatisfied"]) == \
        {class_id for class_id, _, _ in EXPECTED_REFUSALS
         if class_id != "budget_exhausted"}


# --------------------------------------------------------------------------
# The command line refuses bad calibration selections
# --------------------------------------------------------------------------

def _cli():
    path = Path(__file__).resolve().parents[2] / "scripts" / \
        "run_ibex_pulp_rejection_calibration.py"
    spec = importlib.util.spec_from_file_location(
        "run_ibex_pulp_rejection_calibration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_refuses_bad_selections_and_a_missing_verify_target(tmp_path, capsys):
    cli = _cli()
    assert cli.main(["run", "--client-binary", str(tmp_path / "client"),
                     "--cache-dir", str(tmp_path / "cache"),
                     "--output", str(tmp_path / "out"),
                     "--classes", "mmio_bad_width,not_a_class"]) == 1
    assert "not_a_class" in capsys.readouterr().err
    assert cli.main(["verify", "--output", str(tmp_path / "missing")]) == 1
    assert cli.main(["run", "--client-binary", str(tmp_path / "client"),
                     "--cache-dir", str(tmp_path / "cache"),
                     "--output", str(tmp_path / "out"),
                     "--classes", "none", "--arm-slots", "0"]) == 1
    assert "arm" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_cli_verify_recomputes_a_saved_bundle(tmp_path, capsys):
    plan = build_calibration_plan(classes=("budget_exhausted",
                                          UNCERTAIN_CLASS_ID))
    executor, _, _, _ = _offline_executor(plan)
    _run_mocked_live(executor, tmp_path, (NOP_RAW, NOP_RAW))
    output = tmp_path / "run"
    cli = _cli()
    assert cli.main(["verify", "--output", str(output)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["matches"] is True
    assert payload["complete"] is True
    # A journal the saved report does not describe is reported, not accepted.
    (output / "receipts.jsonl").write_text("")
    assert cli.main(["verify", "--output", str(output)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["matches"] is False
