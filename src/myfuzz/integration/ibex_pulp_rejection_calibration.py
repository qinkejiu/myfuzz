"""Targeted rejection calibration for the Ibex + dual PULP GPIO online path.

The online candidate path classifies a refusal before any RTL command and the
live receipt journal persists it as ``candidate_rejection.v1``.  A refusal is
only evidence when a run can actually produce one, so this module declares
decoder configurations whose *real* decode, MMIO, ownership and memory code
refuses a real RFuzz slot.

What a calibration class is
---------------------------
A class is one :class:`CalibrationStep`: a stable class ID, the arm budget of
consecutive RFuzz slots the configuration may be applied to, the exact expected
refusal (``code``/``pointer``, or an ``uncertain`` disposition), and the trusted
manufacturing means.  :class:`RejectionCalibrationDecoder` is itself an
:class:`OnlineCaseDecoder` built from the shipped profile declaration; it hands
each slot to the class configuration that is currently armed and otherwise
delegates to the unchanged base path, so an exhausted or disabled plan behaves
exactly like the existing online path.

Manufacturing means (all configuration, never injection)
--------------------------------------------------------
Every class changes *declarations only*: the RFuzz client still chooses the raw
bytes, the decoder's own code still decides, and the receipt is written by the
unchanged live path.  Nothing synthesizes an RTL event, patches a decoder
method, or fabricates a receipt, and no state a decision reads (cursor,
reservation, ownership, window, budget, proposal) is rewritten to force an
outcome.  The one attribute this module sets on a constructed decoder is the
case-identity namespace described below, which no admission decision reads.

``decode_unbounded_input``
    The class decoder declares a one-byte input bound.  The shipped online path
    fixes that bound to one eight-byte RFuzz record, so this class deliberately
    declares a tighter bound than the arriving slot to exercise the real
    decode-layer refusal.  The *dispatcher* keeps the shipped eight-byte bound,
    which is the executor's own invariant; the tightened bound exists only on
    the per-slot calibration instance and is recorded in the run manifest.
``budget_exhausted``
    The class decoder declares the profile's CPU instruction source as its only
    source and declares its instruction reservation already consumed
    (``instruction_cursor == instruction_end``), so no source remains inside its
    declared admission bounds.
``mmio_window_denied``
    The class decoder declares the profile's MMIO window not writable (it stays
    readable) and admits only ``SW``, so a decoded store has no window that
    permits it.
``mmio_bad_width``
    The class decoder declares the profile window writable but supporting only
    one-byte writes while ``SW`` is the only admitted MMIO operation.
``mmio_no_aligned_address``
    The class decoder declares the profile window one byte long while declaring
    four-byte writes, so no aligned ``SW`` address exists inside it.
``ownership_bound_input`` / ``ownership_fixed_input``
    The class decoder declares only the profile's external PADIN pin source and
    *after construction* replaces its compiled ownership map with one where
    that pin bit is owned by a bound (respectively fixed) producer, so the real
    ownership consultation refuses the mutation.
``uncertain_submit_outside_slots``
    The class decoder declares its instruction reservation one word past the
    session's declared online instruction slots.  Decode admits the case, submit
    reaches the real session and reservation model, and the admission is
    refused there.  Because the case was already submitted, the executor must
    report ``uncertain`` with a null rejection instead of a clean refusal.

Determinism and slot accounting
-------------------------------
A class is armed for consecutive slots, and it disarms as soon as its declared
outcome is observed (or its arm budget is exhausted, which is reported as an
unsatisfied class rather than hidden).  The RFuzz scenario client sweeps its
declared mutation index, so within one client decision stage the record's third
byte takes consecutive values; any window of ``arm_slots`` slots therefore
contains a run of consecutive values long enough to select every operation
class the MMIO calibration classes admit.  The report is recomputable from
``receipts.jsonl`` alone with :func:`recompute_calibration_report`.

Two decoders co-exist in one session, and the live session keys receipts by
case identity, so each class decoder is given its own namespace
(:data:`IDENTITY_NAMESPACE_STEP`, larger than :data:`MAX_LIVE_TESTS`).  A
repeated case identity would corrupt the receipt journal, so the dispatcher
fails closed instead of submitting it.

Entry points
------------
:func:`build_calibration_plan` validates a selection into a plan,
:func:`make_ibex_pulp_rejection_calibration_decoder` builds the decoder over the
shipped declaration without any RTL,
:func:`make_ibex_pulp_rejection_calibration_runtime` starts the real session,
:func:`write_calibration_report` persists the report beside ``receipts.jsonl``
and :func:`recompute_calibration_report` recomputes it from that journal alone.
``scripts/run_ibex_pulp_rejection_calibration.py`` is the command line, and
``verify`` re-derives the report of a saved run without starting RTL.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path
import tempfile
from types import MappingProxyType

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ibex_pulp_dual_source import (
    DualSourceStreamBootstrap, make_ibex_pulp_dual_source_factory,
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.online_case_decoder import (
    CandidateDisposition, OnlineCaseDecoder, OnlineSource,
)
from myfuzz.scenario.ownership import (
    InputField, InputOwner, OwnershipMap, compile_ownership,
)
from myfuzz.scenario.rfuzz_decoder import RECORD_BYTES
from myfuzz.scenario.rv32i_sources import MmioWindow

from .ibex_pulp_online import make_pulp_dual_source_online_runtime

CALIBRATION_SCHEMA_VERSION = "rejection_calibration.v1"
CALIBRATION_REPORT_SCHEMA_VERSION = "rejection_calibration_report.v1"
#: Name of the report artifact the run writes beside ``receipts.jsonl``.
CALIBRATION_REPORT_NAME = "rejection_calibration.json"
#: Slots one class configuration may be applied to before it is a reported miss.
DEFAULT_ARM_SLOTS = 8
#: Upper bound on that budget, so a plan cannot arm a class forever.
MAX_ARM_SLOTS = 64
#: Class that must stay uncertain: the case reached submit and was refused.
UNCERTAIN_CLASS_ID = "uncertain_submit_outside_slots"
#: The shipped profile's source identities, used to narrow a class declaration.
CPU_INSTRUCTION_SOURCE = "cpu.online_instruction"
EXTERNAL_PIN_SOURCE = "gpio_b.external_pin8"
#: (component, port, bit_offset) of the profile's fuzzable external pin.
PIN_FIELD = ("gpio_b", "gpio_in", 8)
#: Declared reservation bytes per calibration class inside the profile region.
CALIBRATION_SLICE_BYTES = 0x100
#: A decoded fragment is at most four words; the uncertain slot needs room.
UNCERTAIN_FRAGMENT_BYTES = 16
#: Case-identity namespace step per class: the live session keys receipts by
#: case identity, so every co-existing decoder needs its own namespace.  The
#: live runner admits at most :data:`MAX_LIVE_TESTS` cases, so one step per
#: class keeps the shipped decoder's namespace disjoint from every class's.
IDENTITY_NAMESPACE_STEP = 1 << 20
#: ``run_scenario_rfuzz_live`` refuses a larger ``max_tests`` budget.
MAX_LIVE_TESTS = 100000
assert IDENTITY_NAMESPACE_STEP > MAX_LIVE_TESTS
#: Schema of one rejection calibration class specification.
CALIBRATION_CLASS_SCHEMA_VERSION = "rejection_calibration_class.v1"

#: The same four local coverage milestones the online runtime publishes.
PULP_DUAL_SOURCE_TARGETS = (
    CoverageTarget("gpio_a_output_bit0", "gpio_a", "gpio_out", 1, 1),
    CoverageTarget("gpio_b_irq", "gpio_b", "irq", 1, 1),
    CoverageTarget("cpu_external_irq_vector_fetch", "cpu", "instr_addr",
                   0xffffffff, 0x1012c),
    CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),
)


@dataclass(frozen=True)
class CalibrationClassSpec:
    """One declared calibration class and the refusal it must make reachable."""

    class_id: str
    expected_code: str | None
    expected_pointer: str | None
    expected_disposition: str
    expected_reason: str
    means: str

    def __post_init__(self) -> None:
        if not self.class_id or not self.means:
            raise ValueError("a calibration class needs an ID and its means")
        if self.expected_disposition not in ("rejected", "uncertain"):
            raise ValueError("a calibration class is a refusal or an uncertainty")
        if self.expected_disposition == "rejected" and (
                not self.expected_code or not self.expected_pointer):
            raise ValueError("a rejected class declares its code and pointer")
        if self.expected_disposition == "uncertain" and (
                self.expected_code is not None or self.expected_pointer is not None):
            raise ValueError("an uncertain class carries no structured rejection")

    def document(self) -> dict:
        return {"schema_version": CALIBRATION_CLASS_SCHEMA_VERSION,
                "class_id": self.class_id, "expected_code": self.expected_code,
                "expected_pointer": self.expected_pointer,
                "expected_disposition": self.expected_disposition,
                "expected_reason": self.expected_reason, "means": self.means}


_SPECS = (
    CalibrationClassSpec(
        "decode_unbounded_input", "decode.unbounded_input", "input.raw",
        "rejected", "decode_rejected",
        "the calibration decoder declares a one-byte input bound "
        "(max_input_bytes=1) while the RFuzz slot carries the declared "
        "eight-byte record, so the real online decode refuses the input bound "
        "before any RTL command"),
    CalibrationClassSpec(
        "budget_exhausted", "budget.exhausted", "instruction.cursor",
        "rejected", "decode_rejected",
        "the calibration decoder declares the profile CPU instruction source "
        "as its only source and declares its instruction reservation already "
        "consumed (instruction_cursor == instruction_end), so no source "
        "remains inside the declared admission bounds"),
    CalibrationClassSpec(
        "mmio_window_denied", "mmio.window_denied", "mmio.operation",
        "rejected", "decode_rejected",
        "the calibration decoder declares the profile MMIO window not writable "
        "(still readable) and admits only SW, so a decoded store finds no "
        "window that permits the operation"),
    CalibrationClassSpec(
        "mmio_bad_width", "mmio.bad_width", "mmio.width",
        "rejected", "decode_rejected",
        "the calibration decoder declares the profile window writable but "
        "supporting only one-byte writes while SW is the only admitted MMIO "
        "operation, so the store width is not declared by any window"),
    CalibrationClassSpec(
        "mmio_no_aligned_address", "mmio.no_aligned_address", "mmio.windows",
        "rejected", "decode_rejected",
        "the calibration decoder declares the profile window one byte long "
        "while declaring four-byte writes, so no aligned SW address exists "
        "inside the permitted window"),
    CalibrationClassSpec(
        "ownership_bound_input", "ownership.bound_input", "source.port",
        "rejected", "decode_rejected",
        "the calibration decoder declares only the profile external PADIN pin "
        "source and, after construction, replaces its compiled ownership map "
        "with one whose pin bit is owned by a bound producer"),
    CalibrationClassSpec(
        "ownership_fixed_input", "ownership.fixed_input", "source.port",
        "rejected", "decode_rejected",
        "the calibration decoder declares only the profile external PADIN pin "
        "source and, after construction, replaces its compiled ownership map "
        "with one whose pin bit is owned by a fixed producer"),
    CalibrationClassSpec(
        UNCERTAIN_CLASS_ID, None, None, "uncertain",
        "rtl_submit_failed_or_partial",
        "the calibration decoder declares its instruction reservation one word "
        "past the session's declared online slots: decode admits the case, the "
        "real session and reservation model refuses the instruction admission "
        "during submit, and the case was already submitted"),
)
_CLASS_SPECS = MappingProxyType({spec.class_id: spec for spec in _SPECS})
assert len(_CLASS_SPECS) == len(_SPECS), "calibration class IDs must be unique"
#: Declared class order; a default plan arms every class once, in this order.
CALIBRATION_CLASS_ORDER = tuple(spec.class_id for spec in _SPECS)


def calibration_class_specs() -> dict[str, CalibrationClassSpec]:
    """Return the declared calibration classes keyed by class ID."""
    return dict(_CLASS_SPECS)


@dataclass(frozen=True)
class CalibrationStep:
    """One class armed for at most ``arm_slots`` consecutive RFuzz slots."""

    class_id: str
    arm_slots: int = DEFAULT_ARM_SLOTS

    def __post_init__(self) -> None:
        if self.class_id not in _CLASS_SPECS:
            raise ValueError(f"unknown calibration class: {self.class_id!r}")
        if (type(self.arm_slots) is not int
                or not 1 <= self.arm_slots <= MAX_ARM_SLOTS):
            raise ValueError(
                f"calibration arm budget must be 1..{MAX_ARM_SLOTS} slots")

    def document(self) -> dict:
        return {"class_id": self.class_id, "arm_slots": self.arm_slots}


def build_calibration_plan(*, classes: Sequence[str] | None = None,
                           arm_slots: int = DEFAULT_ARM_SLOTS
                           ) -> tuple[CalibrationStep, ...]:
    """Validate one explicit calibration selection into an ordered plan.

    ``classes=None`` selects every declared class; an empty sequence is the
    explicit "calibration disabled" plan and keeps the existing online path.
    """
    if (type(arm_slots) is not int
            or not 1 <= arm_slots <= MAX_ARM_SLOTS):
        raise ValueError(
            f"calibration arm budget must be 1..{MAX_ARM_SLOTS} slots")
    if classes is None:
        selected: list[object] = list(CALIBRATION_CLASS_ORDER)
    elif isinstance(classes, (str, bytes)) or not isinstance(classes, Sequence):
        raise ValueError(
            "calibration classes must be a sequence of declared class IDs")
    else:
        selected = list(classes)
    plan: list[CalibrationStep] = []
    seen: set[str] = set()
    for class_id in selected:
        if not isinstance(class_id, str) or class_id not in _CLASS_SPECS:
            raise ValueError(f"unknown calibration class: {class_id!r}")
        if class_id in seen:
            raise ValueError(f"duplicate calibration class: {class_id!r}")
        seen.add(class_id)
        plan.append(CalibrationStep(class_id, arm_slots))
    return tuple(plan)


def _validated_steps(plan: object) -> tuple[CalibrationStep, ...]:
    """Refuse any plan that is not a duplicate-free tuple of declared steps."""
    if isinstance(plan, (str, bytes)) or not isinstance(plan, Sequence):
        raise ValueError("calibration plan must be a sequence of steps")
    steps: list[CalibrationStep] = []
    seen: set[str] = set()
    for step in plan:
        if not isinstance(step, CalibrationStep):
            raise ValueError("calibration plan entries must be CalibrationStep")
        if step.class_id in seen:
            raise ValueError(f"duplicate calibration class: {step.class_id!r}")
        seen.add(step.class_id)
        steps.append(step)
    return tuple(steps)


# --------------------------------------------------------------------------
# Per-class decoder configurations
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _CalibrationVariant:
    """One armed class configuration and the declarations that produced it."""

    index: int
    spec: CalibrationClassSpec
    arm_slots: int
    decoder: OnlineCaseDecoder
    declared_configuration: dict


def _decoder_arguments(base: OnlineCaseDecoder) -> dict:
    """The shipped declaration of the base decoder, ready to re-construct it."""
    return {
        "sources": tuple(base.sources),
        "ownership": base.ownership,
        "schedule": tuple(base.advances[0].schedule),
        "instruction_start": base.instruction_start,
        "instruction_end": base.instruction_end,
        "instruction_cursor": base.instruction_cursor,
        "windows": tuple(base.windows),
        "advance_rounds": len(base.advances),
        "max_input_bytes": base.max_input_bytes,
        "graph": base.graph,
        "max_steps": base.max_steps,
        "allowed_mmio_operations": tuple(base.allowed_mmio_operations),
        "support_words": base.support_words,
        "runtime_contract": base.runtime_contract,
        "flow_by_target": (None if base.flow_by_target is None
                           else dict(base.flow_by_target)),
        "source_actions": tuple(base.source_actions.values()),
    }


def _variant_decoder(base: OnlineCaseDecoder, **declared: object
                     ) -> OnlineCaseDecoder:
    """Construct one class decoder from the shipped declaration plus overrides.

    A class may narrow the declared source set; the flow categories and source
    action declarations of the shipped profile are then narrowed with it, so the
    class decoder still describes exactly one coherent declaration.
    """
    arguments = _decoder_arguments(base)
    arguments.update(declared)
    sources = arguments["sources"]
    if arguments["flow_by_target"] is not None:
        targets = {source.path_id for source in sources}
        arguments["flow_by_target"] = {
            target: flow for target, flow in arguments["flow_by_target"].items()
            if target in targets}
    declared_ids = {source.source_id for source in sources}
    arguments["source_actions"] = tuple(
        item for item in arguments["source_actions"]
        if item.source_id in declared_ids)
    return OnlineCaseDecoder(**arguments)


def _source_by_kind(base: OnlineCaseDecoder, kind: str) -> OnlineSource:
    """The declared profile source of one kind, or a fail-closed refusal."""
    matching = [source for source in base.sources if source.kind == kind]
    if len(matching) != 1:
        raise ValueError(
            f"calibration requires exactly one declared {kind!r} source")
    return matching[0]


def _reservation_slice(base: OnlineCaseDecoder, index: int,
                       arm_slots: int) -> tuple[int, int]:
    """One disjoint reservation slice per class, below the shipped region end."""
    size = max(CALIBRATION_SLICE_BYTES, UNCERTAIN_FRAGMENT_BYTES * (arm_slots + 1))
    end = base.instruction_end - index * size
    start = end - size
    if start < base.instruction_start:
        raise ValueError("calibration reservation slices exceed the profile region")
    return start, end


def asdict_window(window: MmioWindow) -> dict:
    """JSON-safe declaration of one MMIO window; tuples never leak as tuples."""
    if not isinstance(window, MmioWindow):
        raise ValueError("a window declaration requires an MmioWindow")
    return json.loads(json.dumps(asdict(window)))


def _decoder_declaration(decoder: OnlineCaseDecoder, **extra: object) -> dict:
    """JSON-safe declaration of an effective class configuration."""
    document = {
        "sources": [source.source_id for source in decoder.sources],
        "instruction_start": decoder.instruction_start,
        "instruction_end": decoder.instruction_end,
        "instruction_cursor": decoder.instruction_cursor,
        "max_input_bytes": decoder.max_input_bytes,
        "arriving_record_bytes": RECORD_BYTES,
        "allowed_mmio_operations": list(decoder.allowed_mmio_operations),
        "mmio_windows": [asdict_window(window) for window in decoder.windows],
        "ownership": decoder.ownership.document(),
    }
    document.update(extra)
    return json.loads(json.dumps(document, sort_keys=True))


def _replaced_owner(base: OnlineCaseDecoder, component: str, port: str,
                    bit_offset: int, width: int, kind: str,
                    producer_ref: str) -> OwnershipMap:
    """Recompile the shipped ownership map with one owner row replaced."""
    declaration = base.ownership.document()
    fields = tuple(InputField(row["component_id"], row["port"], row["width"])
                   for row in declaration["fields"])
    owners = []
    replaced = False
    for row in declaration["owners"]:
        if ((row["component_id"], row["port"]) == (component, port)
                and row["bit_offset"] == bit_offset and row["width"] == width):
            owners.append(InputOwner(component, port, bit_offset, width, kind,
                                     producer_ref))
            replaced = True
        else:
            owners.append(InputOwner(**row))
    if not replaced:
        raise ValueError("declared profile does not own the requested field bits")
    return compile_ownership(fields, tuple(owners))


def _declared_producer_ref(base: OnlineCaseDecoder, component: str, port: str,
                           kind: str) -> str:
    """The producer reference the shipped declaration uses in this field.

    The replacement never invents a producer: it reuses the exact reference the
    profile already declares for that owner kind inside the same input field.
    """
    refs = sorted({row["producer_ref"]
                   for row in base.ownership.document()["owners"]
                   if (row["component_id"], row["port"]) == (component, port)
                   and row["kind"] == kind})
    if len(refs) != 1:
        raise ValueError(
            f"the shipped declaration needs one {kind!r} producer in "
            f"{component}.{port}")
    return refs[0]


def _allocate_identity_namespace(decoder: OnlineCaseDecoder, offset: int) -> None:
    """Give one class decoder a disjoint case-identity namespace.

    A decoded case identity is ``online-<sequence>-<raw digest>``, so two
    decoders that share a sequence would collide on an identical slot and the
    session would refuse the second one.  The offset changes only that identity
    string: no admission, reservation, ownership, window or budget decision
    reads it, so no class refusal is manufactured or suppressed by it.
    """
    if type(offset) is not int or offset < 1:
        raise ValueError("case identity offset must be a positive integer")
    decoder._sequence = offset


def _build_variant(base: OnlineCaseDecoder, step: CalibrationStep,
                   index: int) -> _CalibrationVariant:
    """Construct the real decoder configuration of one declared class."""
    class_id = step.class_id
    instruction_source = _source_by_kind(base, "instruction")
    pin_source = _source_by_kind(base, "source")
    pin_field = {"component": pin_source.component, "port": pin_source.port,
                 "bit_offset": pin_source.bit_offset, "width": pin_source.width}
    if class_id == "decode_unbounded_input":
        decoder = _variant_decoder(base, max_input_bytes=1)
        declared = _decoder_declaration(decoder)
    elif class_id == "budget_exhausted":
        decoder = _variant_decoder(base, sources=(instruction_source,),
                                   instruction_cursor=base.instruction_end)
        declared = _decoder_declaration(decoder)
    elif class_id in ("mmio_window_denied", "mmio_bad_width",
                      "mmio_no_aligned_address"):
        if class_id == "mmio_window_denied":
            windows = tuple(replace(window, writable=False)
                            for window in base.windows)
        elif class_id == "mmio_bad_width":
            windows = tuple(replace(window, writable=True, write_widths=(1,))
                            for window in base.windows)
        else:
            windows = tuple(MmioWindow(window.base, 1,
                                       readable=window.readable, writable=True,
                                       write_widths=(4,))
                            for window in base.windows)
        start, end = _reservation_slice(base, index, step.arm_slots)
        decoder = _variant_decoder(base, sources=(instruction_source,),
                                   windows=windows,
                                   allowed_mmio_operations=("SW",),
                                   instruction_start=start, instruction_end=end,
                                   instruction_cursor=start)
        declared = _decoder_declaration(decoder)
    elif class_id in ("ownership_bound_input", "ownership_fixed_input"):
        kind = "bound" if class_id == "ownership_bound_input" else "fixed"
        producer = _declared_producer_ref(
            base, pin_field["component"], pin_field["port"], kind)
        decoder = _variant_decoder(base, sources=(pin_source,))
        # The declared replacement happens once, before any slot is decoded.
        decoder.ownership = _replaced_owner(
            base, pin_field["component"], pin_field["port"],
            pin_field["bit_offset"], pin_field["width"], kind, producer)
        declared = _decoder_declaration(
            decoder, ownership_replaced_after_construction=True)
    elif class_id == UNCERTAIN_CLASS_ID:
        start = base.instruction_end
        decoder = _variant_decoder(base, sources=(instruction_source,),
                                   instruction_start=start,
                                   instruction_end=start + UNCERTAIN_FRAGMENT_BYTES,
                                   instruction_cursor=start)
        declared = _decoder_declaration(decoder, declared_slot_region={
            "start": base.instruction_start, "end": base.instruction_end,
            "count": (base.instruction_end - base.instruction_start) // 4})
    else:  # pragma: no cover - CalibrationStep already refused this
        raise ValueError(f"unknown calibration class: {class_id!r}")
    offset = (index + 1) * IDENTITY_NAMESPACE_STEP
    _allocate_identity_namespace(decoder, offset)
    declared = {**declared, "case_identity_offset": offset}
    return _CalibrationVariant(index, _CLASS_SPECS[class_id], step.arm_slots,
                               decoder, declared)


def _matches_expectation(spec: CalibrationClassSpec,
                         disposition: CandidateDisposition) -> bool:
    """True when a real disposition is exactly the declared class outcome."""
    if disposition.disposition != spec.expected_disposition:
        return False
    if disposition.reason != spec.expected_reason:
        return False
    if spec.expected_disposition == "uncertain":
        return disposition.rejection is None
    rejection = disposition.rejection
    return (rejection is not None and str(rejection.code) == spec.expected_code
            and rejection.pointer == spec.expected_pointer)


class RejectionCalibrationDecoder(OnlineCaseDecoder):
    """The shipped online decoder with per-slot calibration classes armed.

    The instance is constructed from the shipped profile declaration, so its
    sources, ownership, runtime paths, reservation and manifest are the base
    decoder's.  While a class is armed, decode is delegated to that class's real
    decoder instance and the returned case, disposition and rejection are the
    class decoder's own values; commit and decision metadata are delegated to
    the decoder that produced the case.  A class that narrows its declared
    source set receives only the coverage hints of the sources it declares.
    With no armed class left, every call is the base decoder's.
    """

    def __init__(self, *, base: OnlineCaseDecoder,
                 plan: Sequence[CalibrationStep]) -> None:
        if not isinstance(base, OnlineCaseDecoder):
            raise ValueError("calibration requires a constructed online decoder")
        if base.from_document_replay_only:
            raise ValueError("a replay-only decoder cannot calibrate a live run")
        steps = _validated_steps(plan)
        super().__init__(**_decoder_arguments(base))
        self.calibration_plan = steps
        self._calibration_variants = tuple(
            _build_variant(base, step, index)
            for index, step in enumerate(steps))
        self._calibration_step_index = 0
        self._calibration_state = [
            {"class_id": step.class_id, "arm_slots": step.arm_slots,
             "slots_applied": 0, "satisfied": False, "exhausted": False,
             "handed_to_session": False, "satisfied_code": None,
             "satisfied_disposition": None}
            for step in steps]
        self._calibration_owners: dict[str, OnlineCaseDecoder] = {}
        self._calibration_case_ids: set[str] = set()

    # -- calibration bookkeeping -------------------------------------------

    def _active_calibration_variant(self) -> _CalibrationVariant | None:
        if self._calibration_step_index >= len(self._calibration_variants):
            return None
        return self._calibration_variants[self._calibration_step_index]

    def _note_case_owner(self, case_id: str, decoder: OnlineCaseDecoder) -> None:
        """Bind one decoded case identity to its decoder, refusing a repeat.

        Identities are allocated so a repeat cannot happen in a well-formed run;
        a repeat means a caller decoded twice without committing, which would
        make the live session refuse the second submission, so it fails closed
        here instead of corrupting the receipt journal.
        """
        if case_id in self._calibration_case_ids:
            raise ValueError(
                "calibrated case identity repeated inside one run: " + case_id)
        self._calibration_case_ids.add(case_id)
        self._calibration_owners[case_id] = decoder
        while len(self._calibration_owners) > 8:
            self._calibration_owners.pop(next(iter(self._calibration_owners)))

    def _note_calibration_slot(self, variant: _CalibrationVariant,
                               disposition: CandidateDisposition) -> None:
        state = self._calibration_state[variant.index]
        state["slots_applied"] += 1
        if variant.spec.expected_disposition == "uncertain":
            # Uncertainty is decided after submit, so this class hands its
            # admitted case to the session and is judged from the receipt.
            if disposition.disposition in ("admitted", "degraded"):
                state["handed_to_session"] = True
                self._calibration_step_index += 1
            elif state["slots_applied"] >= variant.arm_slots:
                state["exhausted"] = True
                self._calibration_step_index += 1
            return
        if _matches_expectation(variant.spec, disposition):
            state["satisfied"] = True
            state["satisfied_code"] = (None if disposition.rejection is None
                                       else str(disposition.rejection.code))
            state["satisfied_disposition"] = disposition.disposition
            self._calibration_step_index += 1
        elif state["slots_applied"] >= variant.arm_slots:
            # An unsatisfied class is reported, never hidden or retried forever.
            state["exhausted"] = True
            self._calibration_step_index += 1

    def calibration_document(self) -> dict:
        """Declared calibration plan and the configuration behind each class."""
        return {
            "schema_version": CALIBRATION_SCHEMA_VERSION,
            "enabled": bool(self._calibration_variants),
            "plan": [
                {**variant.spec.document(),
                 "arm_slots": variant.arm_slots,
                 "declared_configuration": variant.declared_configuration}
                for variant in self._calibration_variants],
        }

    def calibration_state(self) -> dict:
        """Runtime slot accounting per class; never the source of a claim."""
        return {"schema_version": CALIBRATION_SCHEMA_VERSION,
                "enabled": bool(self._calibration_variants),
                "plan": [dict(state) for state in self._calibration_state],
                "classes_armed": self._calibration_step_index,
                "case_identities": len(self._calibration_case_ids)}

    def document(self) -> dict:
        """The shipped declaration plus the declared calibration plan."""
        return {**super().document(),
                "rejection_calibration": self.calibration_document()}

    # -- delegation ---------------------------------------------------------

    def decode_candidate(self, raw: bytes, *,
                         coverage_hints: Mapping[str, int] | None = None
                         ) -> tuple[object, CandidateDisposition]:
        variant = self._active_calibration_variant()
        if variant is None:
            case, disposition = super().decode_candidate(
                raw, coverage_hints=coverage_hints)
            if case is not None:
                self._note_case_owner(case.case_id, self)
            return case, disposition
        # A class may narrow its declared source set; only hints for the sources
        # it declares are meaningful to it, and they are passed unchanged.
        hints = coverage_hints
        if coverage_hints is not None:
            declared_ids = {source.source_id for source in variant.decoder.sources}
            hints = {source_id: weight
                     for source_id, weight in coverage_hints.items()
                     if source_id in declared_ids}
        case, disposition = variant.decoder.decode_candidate(
            raw, coverage_hints=hints)
        if case is not None:
            self._note_case_owner(case.case_id, variant.decoder)
        self._note_calibration_slot(variant, disposition)
        return case, disposition

    def _owner_of(self, case) -> OnlineCaseDecoder | None:
        """The class decoder that produced a case, or None for this decoder."""
        owner = self._calibration_owners.get(getattr(case, "case_id", None))
        return None if owner is None or owner is self else owner

    def decision_metadata(self, case) -> dict:
        owner = self._owner_of(case)
        return (super() if owner is None else owner).decision_metadata(case)

    def source_action(self, case):
        owner = self._owner_of(case)
        return (super() if owner is None else owner).source_action(case)

    def commit_candidate(self, case) -> CandidateDisposition:
        owner = self._owner_of(case)
        self._calibration_owners.pop(getattr(case, "case_id", None), None)
        return (super() if owner is None else owner).commit_candidate(case)


def make_ibex_pulp_rejection_calibration_decoder(
        *, plan: Sequence[CalibrationStep],
        bootstrap: DualSourceStreamBootstrap | None = None
        ) -> RejectionCalibrationDecoder:
    """Build the calibration decoder over the shipped Ibex online declaration."""
    if bootstrap is None:
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    if not isinstance(bootstrap, DualSourceStreamBootstrap):
        raise ValueError("dual-source stream bootstrap is required")
    base = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    return RejectionCalibrationDecoder(base=base, plan=plan)


def make_ibex_pulp_rejection_calibration_runtime(
        *, cache_dir: Path, run_id: str, plan: Sequence[CalibrationStep],
        evidence_dir: Path | None = None, feedback_interval: int = 16,
        max_warmup_rounds: int = 1024, cpu_retirement: bool = False,
        gpio_consumption: bool = False, native_irq_receipts: bool = False):
    """Start the real Ibex + dual PULP GPIO session with calibrated decoding.

    This is the only entry point that starts RTL, and the only difference from
    the online runtime is the calibration plan handed to the decoder.
    """
    if type(gpio_consumption) is not bool:
        raise ValueError("gpio_consumption must be boolean")
    if type(native_irq_receipts) is not bool or (native_irq_receipts
                                                 and not cpu_retirement):
        raise ValueError("native IRQ receipts require explicit RVFI retirement")
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_rejection_calibration_decoder(bootstrap=bootstrap,
                                                          plan=plan)
    factory = make_ibex_pulp_dual_source_factory(
        Path(cache_dir), cpu_retirement=cpu_retirement,
        gpio_consumption=gpio_consumption,
        **({'native_irq_receipts': True} if native_irq_receipts else {}))
    return make_pulp_dual_source_online_runtime(
        bootstrap=bootstrap, decoder=decoder, factory=factory, run_id=run_id,
        evidence_dir=evidence_dir, feedback_interval=feedback_interval,
        max_warmup_rounds=max_warmup_rounds)


# --------------------------------------------------------------------------
# Recomputable report
# --------------------------------------------------------------------------

def _require_rows(rows: Iterable[Mapping]) -> list[dict]:
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Iterable):
        raise ValueError("calibration report requires journal rows")
    collected = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("calibration journal rows must be objects")
        collected.append(dict(row))
    return collected


def _observation(row: Mapping, rejection: object) -> dict:
    document = rejection if isinstance(rejection, Mapping) else None
    return {"buffer_id": row.get("buffer_id"), "slot": row.get("slot"),
            "raw_sha256": row.get("raw_sha256"), "status": row.get("status"),
            "disposition": row.get("candidate_disposition"),
            "disposition_reason": row.get("candidate_disposition_reason"),
            "code": None if document is None else document.get("code"),
            "pointer": None if document is None else document.get("pointer"),
            "error": row.get("error")}


def calibration_report_from_rows(rows: Iterable[Mapping], *,
                                 plan: Sequence[CalibrationStep],
                                 runtime_state: Mapping | None = None,
                                 plan_document: Sequence[Mapping] | None = None
                                 ) -> dict:
    """Recompute the calibration report from receipt journal rows alone.

    A rejection class is satisfied only by a receipt whose structured rejection
    carries the declared code *and* pointer with the declared disposition and
    reason; the uncertain class only by a receipt with no structured rejection
    at all.  Nothing here trusts the decoder's own slot accounting.

    ``plan_document`` is the decoder manifest's own plan disclosure; when it is
    absent the report states the plan implied by the requested steps.
    """
    steps = _validated_steps(plan)
    journal = _require_rows(rows)
    classes = []
    for step in steps:
        spec = _CLASS_SPECS[step.class_id]
        observations = []
        mismatched = 0
        for row in journal:
            rejection = row.get("rejection")
            if row.get("candidate_disposition") != spec.expected_disposition:
                continue
            if row.get("candidate_disposition_reason") != spec.expected_reason:
                continue
            if spec.expected_disposition == "uncertain":
                if rejection is not None:
                    continue
                observations.append(_observation(row, None))
                continue
            if not isinstance(rejection, Mapping):
                continue
            if rejection.get("code") != spec.expected_code:
                continue
            if rejection.get("pointer") != spec.expected_pointer:
                mismatched += 1
                continue
            observations.append(_observation(row, rejection))
        classes.append({
            "class_id": spec.class_id,
            "expected_code": spec.expected_code,
            "expected_pointer": spec.expected_pointer,
            "expected_disposition": spec.expected_disposition,
            "expected_reason": spec.expected_reason,
            "means": spec.means,
            "observed_count": len(observations),
            "satisfied": bool(observations),
            "pointer_mismatches": mismatched,
            "observations": observations,
        })
    by_code = Counter(str(row["rejection"]["code"]) for row in journal
                      if isinstance(row.get("rejection"), Mapping)
                      and isinstance(row["rejection"].get("code"), str))
    by_status = Counter(str(row.get("status")) for row in journal)
    uncertain_rows = [row for row in journal
                      if row.get("candidate_disposition") == "uncertain"
                      and row.get("rejection") is None]
    unsatisfied = [entry["class_id"] for entry in classes
                   if not entry["satisfied"]]
    if plan_document is None:
        steps_document = [
            {**step.document(),
             **{key: value for key, value in _CLASS_SPECS[step.class_id]
                .document().items() if key not in ("class_id", "schema_version")}}
            for step in steps]
    else:
        if (isinstance(plan_document, (str, bytes))
                or not isinstance(plan_document, Sequence)
                or any(not isinstance(row, Mapping) for row in plan_document)
                or [row.get("class_id") for row in plan_document]
                != [step.class_id for step in steps]
                or [row.get("arm_slots") for row in plan_document]
                != [step.arm_slots for step in steps]):
            raise ValueError("declared plan document disagrees with the plan")
        steps_document = [json.loads(json.dumps(dict(row), sort_keys=True))
                          for row in plan_document]
    return {
        "schema_version": CALIBRATION_REPORT_SCHEMA_VERSION,
        "enabled": bool(steps),
        "plan": steps_document,
        "receipts": {"total": len(journal),
                     "by_status": dict(sorted(by_status.items())),
                     "structured_rejections": sum(by_code.values()),
                     "uncertain_receipts": len(uncertain_rows),
                     "by_code": dict(sorted(by_code.items()))},
        "classes": classes,
        "unsatisfied": unsatisfied,
        "complete": not unsatisfied,
        "runtime_state": (None if runtime_state is None
                          else json.loads(json.dumps(dict(runtime_state)))),
    }


def read_receipt_rows(output_dir: Path) -> list[dict]:
    """Read the live receipt journal of one saved run."""
    path = Path(output_dir) / "receipts.jsonl"
    if not path.is_file():
        raise ValueError(f"calibration needs the saved journal {path.name}")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError as error:
            raise ValueError("saved receipt journal is not JSON lines") from error
    return rows


def _plan_from_saved_report(output_dir: Path) -> tuple[
        tuple[CalibrationStep, ...], list[dict]]:
    path = Path(output_dir) / CALIBRATION_REPORT_NAME
    if not path.is_file():
        raise ValueError("saved calibration report is required to name the plan")
    document = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict)
            or document.get("schema_version") != CALIBRATION_REPORT_SCHEMA_VERSION
            or not isinstance(document.get("plan"), list)):
        raise ValueError("saved calibration report is malformed")
    try:
        steps = tuple(CalibrationStep(row["class_id"], row["arm_slots"])
                      for row in document["plan"])
    except (KeyError, TypeError) as error:
        raise ValueError("saved calibration plan is malformed") from error
    return steps, document["plan"]


def recompute_calibration_report(output_dir: Path, *,
                                 plan: Sequence[CalibrationStep] | None = None
                                 ) -> dict:
    """Recompute the report of a saved run from its ``receipts.jsonl``.

    Without an explicit plan the saved report names the plan, and its declared
    plan documents are carried over unchanged; the manifest cross-check in the
    caller is what ties that plan to the run identity.
    """
    output_dir = Path(output_dir)
    plan_document = None
    if plan is None:
        plan, plan_document = _plan_from_saved_report(output_dir)
    return calibration_report_from_rows(read_receipt_rows(output_dir), plan=plan,
                                        plan_document=plan_document)


def write_calibration_report(output_dir: Path, *,
                             plan: Sequence[CalibrationStep],
                             rows: Iterable[Mapping] | None = None,
                             runtime_state: Mapping | None = None,
                             plan_document: Sequence[Mapping] | None = None) -> dict:
    """Write the calibration report beside the journal it was computed from."""
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        raise ValueError("calibration report needs an existing output directory")
    journal = read_receipt_rows(output_dir) if rows is None else _require_rows(rows)
    document = calibration_report_from_rows(journal, plan=plan,
                                            runtime_state=runtime_state,
                                            plan_document=plan_document)
    encoded = json.dumps(document, sort_keys=True, ensure_ascii=False,
                         allow_nan=False).encode("utf-8") + b"\n"
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=output_dir,
                                         prefix=".calibration-") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = Path(handle.name)
        os.replace(temporary_path, output_dir / CALIBRATION_REPORT_NAME)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return document


def calibration_report_matches(saved: Mapping, recomputed: Mapping) -> bool:
    """True when a recomputation from the journal reproduces the saved report.

    The declared plan is deliberately excluded: it is tied to the run identity
    by comparing the saved report's plan with the decoder manifest disclosure,
    not by comparing an artifact with itself.
    """
    if not isinstance(saved, Mapping) or not isinstance(recomputed, Mapping):
        raise ValueError("calibration comparison requires report documents")
    keys = ("classes", "unsatisfied", "complete", "receipts")
    return all(json.dumps(saved.get(key), sort_keys=True, default=str)
               == json.dumps(recomputed.get(key), sort_keys=True, default=str)
               for key in keys)


def calibration_manifest_plan(output_dir: Path) -> list[dict]:
    """The plan the saved run manifest discloses, for cross-checking a report."""
    path = Path(output_dir) / "decoder_manifest.json"
    if not path.is_file():
        raise ValueError("saved decoder manifest is missing")
    document = json.loads(path.read_text(encoding="utf-8"))
    calibration = (document.get("rejection_calibration")
                   if isinstance(document, dict) else None)
    if (not isinstance(calibration, dict)
            or calibration.get("schema_version") != CALIBRATION_SCHEMA_VERSION
            or not isinstance(calibration.get("plan"), list)):
        raise ValueError("saved decoder manifest discloses no calibration plan")
    return calibration["plan"]
