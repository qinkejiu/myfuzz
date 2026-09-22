"""Versioned input-constraint and ownership policy for a composed SoC.

This module compiles the declarative contracts (component profiles, the
generated plan, the raw-input layout) into one bounded rule record set.  It is
the compile-time half of the input design: it decides *who may write what, when*
and refuses combinations it cannot prove, while the online drivers (step 6) own
the real handshake state.

Four rule classes are kept apart on purpose, because collapsing them is how
input design silently becomes "make the DUT pass":

``environment_hard``
    Must hold whenever its condition holds; a violating sample is rejected.
``scenario_precondition``
    Limits one scenario's reachability (for example "the event arrives after
    enable"), never the component's whole legal behaviour.
``search_preference``
    Biases the search; it is never a legality proof.
``dut_assertion``
    A property the DUT must satisfy.  It is *not* something a repairer may edit;
    a violation stays an anomaly.

Ownership is explicit and versioned: ``cpu_execute`` (the CPU owns every
CPU-side input and the bus), ``bfm_isolated`` (the CPU is held and the synthetic
master owns the bus) and ``contention`` (both are real masters and the arbiter
decides).  The legacy mode strings keep their meaning; this policy adds an
explicit owner per bit instead of leaving it implied by a render parameter.

Legacy behaviour is untouched: nothing in ``harness/runtime_projection.py`` or
``harness/static_policy.py`` is modified or re-interpreted, and the frozen
"inactive gate zeroes the field" semantics are neither read nor redefined here.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from myfuzz.contracts import canonical_bytes

INPUT_CONSTRAINT_SCHEMA = "soc_input_constraints.v1"

RULE_CATEGORIES = (
    "environment_hard",
    "scenario_precondition",
    "search_preference",
    "dut_assertion",
)
PHASES = ("compile", "sample", "runtime")
OWNERS = ("environment", "cpu", "bfm", "dut")
FAILURE_CLASSES = (
    "constraint_conflict",
    "capability_unsupported",
    "sample_unsatisfiable",
    "solver_budget_exhausted",
    "driver_violation",
    "dut_violation",
    "observation_insufficient",
)

#: Versioned drive profiles.  ``legacy_modes`` records which stimulus mode the
#: profile corresponds to; the legacy strings are not reinterpreted, the profile
#: only makes the ownership they imply explicit.
DRIVE_PROFILES: dict[str, dict[str, object]] = {
    "cpu_execute": {
        "version": 1,
        "bus_owner": "cpu",
        "cpu_held_in_reset": False,
        "legacy_modes": ("cpu_only",),
        "statement": "the CPU executes and owns every bus access; the environment owns "
                     "only declared special inputs and external pins",
    },
    "bfm_isolated": {
        "version": 1,
        "bus_owner": "bfm",
        "cpu_held_in_reset": True,
        "legacy_modes": ("mmio_only",),
        "statement": "the CPU is held in reset and the synthetic beat master owns the bus; "
                     "no CPU execution is claimed",
    },
    "contention": {
        "version": 1,
        "bus_owner": "arbitrated",
        "cpu_held_in_reset": False,
        "legacy_modes": ("mixed",),
        "statement": "the CPU and the synthetic master are both real masters on one bus; "
                     "ownership of each accepted transaction follows the arbiter",
    },
}

#: Primitives this compiler understands.  Anything else is a capability gap, not
#: something to approximate.
SUPPORTED_PRIMITIVES = (
    "drive_cycle_value",
    "drive_reset_sampled",
    "drive_pulse",
    "drive_hold",
    "drive_constant",
    "observe_only",
    "value_range",
    "value_enum",
    "value_mask_align",
    "reachable_window",
)

#: Bounds on the compiled closure, so an unsolvable input is a diagnosed budget
#: exhaustion rather than an infinite loop.
MAX_RULES = 4096
MAX_CLOSURE_STEPS = 4096
MAX_RULE_STATE_BITS = 4096


class InputConstraintError(ValueError):
    """A rule set is ambiguous, over-budget, unsupported or double-driven."""


def _error(reason: str) -> None:
    raise InputConstraintError(reason)


@dataclass(frozen=True, slots=True)
class ConstraintRule:
    rule_id: str
    category: str
    owner: str
    primitive: str
    phase: str
    fields: tuple[str, ...]
    read_set: tuple[str, ...]
    write_set: tuple[str, ...]
    raw_bits: tuple[tuple[int, int], ...] = ()
    parameters: tuple[tuple[str, object], ...] = ()
    basis: str = ""
    state_bits: int = 0
    budget: int = 0
    failure_class: str = "constraint_conflict"
    checker: str = ""
    applies_in_modes: tuple[str, ...] = ()

    def document(self) -> dict[str, object]:
        record: dict[str, object] = {
            "rule_id": self.rule_id,
            "category": self.category,
            "owner": self.owner,
            "primitive": self.primitive,
            "phase": self.phase,
            "fields": list(self.fields),
            "read_set": list(self.read_set),
            "write_set": list(self.write_set),
            "basis": self.basis,
            "state_bits": self.state_bits,
            "budget": self.budget,
            "failure_class": self.failure_class,
            "checker": self.checker,
        }
        if self.raw_bits:
            record["raw_bits"] = [[lo, hi] for lo, hi in self.raw_bits]
        if self.parameters:
            record["parameters"] = [[str(name), value] for name, value in self.parameters]
        if self.applies_in_modes:
            record["applies_in_modes"] = list(self.applies_in_modes)
        return record

    def key(self) -> tuple:
        return (self.rule_id, self.category, self.owner, self.primitive, self.phase,
                tuple(self.fields), tuple(self.read_set), tuple(self.write_set),
                tuple(self.raw_bits), tuple((str(name), repr(value))
                                            for name, value in self.parameters),
                self.basis, self.state_bits, self.budget, self.failure_class,
                self.checker, tuple(self.applies_in_modes))


@dataclass(frozen=True, slots=True)
class InputConstraintPolicy:
    drive_profile: str
    profile_version: int
    bus_owner: str
    cpu_held_in_reset: bool
    legacy_modes: tuple[str, ...]
    rules: tuple[ConstraintRule, ...]
    layout_hash: str
    plan_hash: str
    closure: tuple[tuple[str, tuple[str, ...]], ...]
    cycles: tuple[tuple[str, ...], ...] = ()
    gaps: tuple[str, ...] = ()
    policy_hash: str = ""

    def rule(self, rule_id: str) -> ConstraintRule:
        for item in self.rules:
            if item.rule_id == rule_id:
                return item
        raise InputConstraintError(f"unknown-rule:{rule_id}")

    def environment_write_bits(self) -> set[tuple[str, int]]:
        """(field_id, bit) pairs the environment is allowed to drive."""
        result: set[tuple[str, int]] = set()
        for item in self.rules:
            if item.owner != "environment":
                continue
            for raw_lo, raw_hi in item.raw_bits:
                for bit in range(raw_lo, raw_hi + 1):
                    result.add(("__raw__", bit))
        return result


# ---------------------------------------------------------------------------
# compilation
# ---------------------------------------------------------------------------


def project_sample_values(policy: InputConstraintPolicy, raw: int, *, raw_width: int) -> int:
    """Project environment-owned sample fields; never operate on DUT signals.

    Valid values are preserved. Invalid values select deterministically from the
    intersection, without enumerating a potentially large integer interval.
    Runtime/structural rules remain obligations of their respective backends.
    """
    if not isinstance(policy, InputConstraintPolicy):
        _error("sample-policy-type")
    if type(raw_width) is not int or raw_width <= 0 or type(raw) is not int \
            or not 0 <= raw < (1 << raw_width):
        _error("sample-outside-raw-width")
    projected = raw
    occupied = 0
    for rule in policy.rules:
        if rule.phase != "sample" or rule.category == "dut_assertion":
            continue
        if rule.category not in ("environment_hard", "scenario_precondition"):
            continue  # Search preferences are not required legality constraints.
        if rule.owner != "environment" or rule.read_set or rule.state_bits:
            _error(f"sample-rule-not-applicable:{rule.rule_id}")
        if rule.applies_in_modes and not set(policy.legacy_modes) <= set(rule.applies_in_modes):
            _error(f"sample-rule-mode-not-applicable:{rule.rule_id}")
        if rule.primitive not in ("value_range", "value_enum", "value_mask_align"):
            _error(f"unsupported-sample-rule:{rule.rule_id}:{rule.primitive}")
        if len(rule.raw_bits) != 1 or len(rule.fields) != 1 \
                or rule.write_set != rule.fields:
            _error(f"sample-rule-binding-unsupported:{rule.rule_id}")
        lo, hi = rule.raw_bits[0]
        if not 0 <= lo <= hi < raw_width:
            _error(f"sample-field-outside-raw-width:{rule.rule_id}")
        limit = (1 << (hi - lo + 1)) - 1
        bits = limit << lo
        if occupied & bits:
            _error(f"sample-rule-overlap:{rule.rule_id}")
        occupied |= bits
        parameters = dict(rule.parameters)
        if len(parameters) != len(rule.parameters) or set(parameters) - {
                "low", "high", "values", "mask", "alignment"}:
            _error(f"unsupported-sample-parameters:{rule.rule_id}")
        required = {"value_range": {"low", "high"}, "value_enum": {"values"},
                    "value_mask_align": set()}[rule.primitive]
        if not required <= parameters.keys() or (rule.primitive == "value_mask_align"
                and not {"mask", "alignment"} & parameters.keys()):
            _error(f"missing-sample-parameters:{rule.rule_id}")
        if ("low" in parameters) != ("high" in parameters):
            _error(f"invalid-sample-range:{rule.rule_id}")
        low, high = parameters.get("low", 0), parameters.get("high", limit)
        mask, alignment = parameters.get("mask", limit), parameters.get("alignment", 1)
        if any(type(value) is not int for value in (low, high, mask, alignment)) \
                or not 0 <= low <= high <= limit or not 0 <= mask <= limit \
                or alignment <= 0 or alignment & (alignment - 1) or alignment > limit + 1:
            _error(f"invalid-sample-parameters:{rule.rule_id}")
        mask &= ~(alignment - 1)
        value = (projected >> lo) & limit

        def next_allowed(candidate: int) -> int:
            # Carry above the highest forbidden set bit; at most field-width
            # carries are possible, independent of the range's cardinality.
            while candidate & ~mask:
                shift = (candidate & ~mask).bit_length()
                candidate = ((candidate >> shift) + 1) << shift
                if candidate > high:
                    return candidate
            return candidate

        if "values" in parameters:
            values = parameters["values"]
            if not isinstance(values, (tuple, list)) or not values or any(
                    type(item) is not int or not 0 <= item <= limit for item in values):
                _error(f"invalid-sample-enum:{rule.rule_id}")
            allowed = sorted({item for item in values if low <= item <= high and not item & ~mask})
            if not allowed:
                _error(f"sample-unsatisfiable:{rule.rule_id}")
            replacement = value if value in allowed else allowed[value % len(allowed)]
        else:
            first = next_allowed(low)
            if first > high:
                _error(f"sample-unsatisfiable:{rule.rule_id}")
            if low <= value <= high and not value & ~mask:
                replacement = value
            elif rule.primitive == "value_mask_align":
                replacement = value & mask
                if not low <= replacement <= high:
                    replacement = first
            else:
                replacement = next_allowed(low + value % (high - low + 1))
                if replacement > high:
                    replacement = first
        projected = (projected & ~bits) | (replacement << lo)
    return projected


def _rule(document: Mapping[str, object]) -> ConstraintRule:
    parameters = tuple((str(pair[0]), pair[1])
                       for pair in document.get("parameters", []) if isinstance(pair, Sequence))
    raw_bits = tuple((int(pair[0]), int(pair[1]))
                     for pair in document.get("raw_bits", []) if isinstance(pair, Sequence))
    return ConstraintRule(
        rule_id=str(document["rule_id"]),
        category=str(document["category"]),
        owner=str(document["owner"]),
        primitive=str(document["primitive"]),
        phase=str(document["phase"]),
        fields=tuple(str(item) for item in document.get("fields", [])),
        read_set=tuple(str(item) for item in document.get("read_set", [])),
        write_set=tuple(str(item) for item in document.get("write_set", [])),
        raw_bits=raw_bits,
        parameters=parameters,
        basis=str(document.get("basis", "")),
        state_bits=int(document.get("state_bits", 0)),
        budget=int(document.get("budget", 0)),
        failure_class=str(document.get("failure_class", "constraint_conflict")),
        checker=str(document.get("checker", "")),
        applies_in_modes=tuple(str(item) for item in document.get("applies_in_modes", [])),
    )


def _validate_rule(rule: ConstraintRule) -> None:
    if rule.category not in RULE_CATEGORIES:
        _error(f"unknown-rule-category:{rule.rule_id}:{rule.category}")
    if rule.owner not in OWNERS:
        _error(f"unknown-rule-owner:{rule.rule_id}:{rule.owner}")
    if rule.phase not in PHASES:
        _error(f"unknown-rule-phase:{rule.rule_id}:{rule.phase}")
    if rule.primitive not in SUPPORTED_PRIMITIVES:
        _error(f"unsupported-primitive:{rule.rule_id}:{rule.primitive}")
    if rule.failure_class not in FAILURE_CLASSES:
        _error(f"unknown-failure-class:{rule.rule_id}:{rule.failure_class}")
    if not rule.write_set and rule.primitive not in ("observe_only", "reachable_window"):
        _error(f"rule-without-write-set:{rule.rule_id}")
    if rule.state_bits < 0 or rule.state_bits > MAX_RULE_STATE_BITS:
        _error(f"rule-state-out-of-bounds:{rule.rule_id}:{rule.state_bits}")
    if rule.budget < 0:
        _error(f"rule-budget-negative:{rule.rule_id}")
    if rule.category != "dut_assertion" and rule.owner == "dut" and rule.write_set:
        # A rule that modifies a DUT-owned value would let the environment edit
        # the component under test.  DUT assertions observe, they never write.
        _error(f"environment-writes-dut-value:{rule.rule_id}")
    for mode in rule.applies_in_modes:
        if mode not in ("cpu_only", "mmio_only", "mixed"):
            _error(f"unknown-rule-mode:{rule.rule_id}:{mode}")


def _special_inputs(layout: Mapping[str, object]) -> list[dict[str, object]]:
    """Special inputs from the layout, with a fallback for older documents."""
    explicit = layout.get("special_inputs")
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)) and explicit:
        return [dict(item) for item in explicit if isinstance(item, Mapping)]
    records: list[dict[str, object]] = []
    for entry in layout.get("fields", []):
        if not isinstance(entry, Mapping):
            continue
        constraint = entry.get("constraint")
        if not isinstance(constraint, Mapping) or not constraint.get("randomizable"):
            continue
        owner = str(entry.get("owner", ""))
        instance_id, _, port = owner.partition("::")
        binding = entry.get("binding")
        top_port = str(binding.get("port")) if isinstance(binding, Mapping) else ""
        records.append({
            "instance_id": instance_id,
            "port": port,
            "top_port": top_port,
            "field_id": str(entry.get("field_id", "")),
            "role": str(entry.get("role", "")),
            "width": int(entry.get("width", 1)),
            "raw_lo": int(entry.get("raw_lo", 0)),
            "raw_hi": int(entry.get("raw_hi", 0)),
            "strategy": "cycle_value",
            "basis": "input_layout.field.constraint.randomizable",
        })
    return records


def _drive_rule(entry: Mapping[str, object], *, profile: Mapping[str, object]) -> ConstraintRule:
    strategy = str(entry.get("strategy") or "cycle_value")
    primitive = {
        "cycle_value": "drive_cycle_value",
        "reset_sampled": "drive_reset_sampled",
        "pulse": "drive_pulse",
        "hold": "drive_hold",
    }.get(strategy)
    if primitive is None:
        _error(f"unsupported-drive-strategy:{entry.get('port')}:{strategy}")
    phase = "sample" if strategy in ("reset_sampled",) else "runtime"
    state_bits = 0
    if strategy == "reset_sampled":
        state_bits = int(entry.get("width", 1)) + 1
    elif strategy == "pulse":
        state_bits = int(entry.get("width", 1)) + 8
    elif strategy == "hold":
        state_bits = int(entry.get("width", 1)) + 1
    return _rule({
        "rule_id": f"drive:{entry['top_port']}",
        "category": "environment_hard",
        "owner": "environment",
        "primitive": primitive,
        "phase": phase,
        "fields": [str(entry["field_id"])],
        "read_set": [],
        "write_set": [str(entry["top_port"])],
        "raw_bits": [[int(entry["raw_lo"]), int(entry["raw_hi"])]],
        "parameters": [["strategy", strategy],
                       ["width", int(entry["width"])],
                       ["instance_id", str(entry["instance_id"])],
                       ["port", str(entry["port"])]],
        "basis": str(entry.get("basis", "")),
        "state_bits": state_bits,
        "budget": 1,
        "failure_class": "driver_violation",
        "checker": "soc_special_input_driver",
    })


def _value_rule(entry: Mapping[str, object]) -> ConstraintRule | None:
    constraint = entry.get("constraint")
    if not isinstance(constraint, Mapping):
        return None
    width = int(entry["width"])
    parameters: list[tuple[str, object]] = []
    primitive = None
    if "range" in constraint:
        low, high = (int(item) for item in constraint["range"])
        if low < 0 or high >= (1 << width):
            _error(f"range-outside-field-width:{entry['field_id']}:{low}..{high}:width={width}")
        primitive = "value_range"
        parameters.extend([("low", low), ("high", high)])
    if "enum" in constraint:
        values = [int(item) for item in constraint["enum"]]
        if any(value < 0 or value >= (1 << width) for value in values):
            _error(f"enum-outside-field-width:{entry['field_id']}")
        if primitive is not None and primitive != "value_enum":
            # Two value selectors on one field must be composable: their
            # intersection has to be provably non-empty, otherwise the rule set
            # cannot be satisfied and is rejected instead of silently narrowed.
            low, high = parameters[0][1], parameters[1][1]
            allowed = [value for value in values if low <= value <= high]
            if not allowed:
                _error(f"empty-constraint-intersection:{entry['field_id']}:range-enum")
        primitive = "value_enum"
        parameters.append(("values", tuple(sorted(values))))
    alignment = constraint.get("alignment")
    if "mask" in constraint:
        mask = constraint["mask"]
        if type(mask) is not int or not 0 <= mask < (1 << width):
            _error(f"mask-outside-field-width:{entry['field_id']}")
        primitive = primitive or "value_mask_align"
        parameters.append(("mask", mask))
    if alignment is not None:
        alignment = int(alignment)
        if alignment <= 0 or alignment & (alignment - 1):
            _error(f"invalid-alignment:{entry['field_id']}:{alignment}")
        if alignment > (1 << width):
            _error(f"alignment-outside-field-width:{entry['field_id']}:{alignment}")
        if "enum" in constraint:
            values = [int(item) for item in constraint["enum"]]
            if all(value % alignment for value in values):
                _error(f"empty-constraint-intersection:{entry['field_id']}:enum-alignment")
        primitive = primitive or "value_mask_align"
        parameters.append(("alignment", alignment))
    if primitive is None:
        return None
    return _rule({
        "rule_id": f"value:{entry['field_id']}",
        "category": "environment_hard",
        "owner": "environment",
        "primitive": primitive,
        "phase": "sample",
        "fields": [str(entry["field_id"])],
        "read_set": [],
        "write_set": [str(entry["field_id"])],
        "raw_bits": [[int(entry["raw_lo"]), int(entry["raw_hi"])]],
        "parameters": parameters,
        "basis": str(entry.get("evidence", "input_layout.constraint")),
        "state_bits": 0,
        "budget": 1,
        "failure_class": "sample_unsatisfiable",
        "checker": "harness.static_policy",
    })


def _observation_rule(entry: Mapping[str, object]) -> ConstraintRule:
    return _rule({
        "rule_id": f"observe:{entry['instance_id']}:{entry['port']}",
        "category": "dut_assertion",
        "owner": "dut",
        "primitive": "observe_only",
        "phase": "runtime",
        "fields": [],
        "read_set": [f"{entry['instance_id']}::{entry['port']}"],
        "write_set": [],
        "basis": str(entry.get("reason", "")),
        "budget": 1,
        "failure_class": "observation_insufficient",
        "checker": "soc_structure_audit.observation_outputs",
    })


def _window_rule(window: Mapping[str, object], *, profile: Mapping[str, object],
                 reachable: bool) -> ConstraintRule:
    bus_owner = str(profile["bus_owner"])
    owner = {"cpu": "cpu", "bfm": "bfm", "arbitrated": "environment"}[bus_owner]
    if not reachable:
        owner = "dut"
    parameters: list[list[object]] = [
        ["base", int(window["base"])], ["size", int(window["size"])],
        ["request_sources", tuple(str(item)
                                  for item in window.get("request_sources", []))],
        ["bus_owner", bus_owner],
    ]
    if bus_owner == "arbitrated":
        # Two real masters reach the same window; ownership of each accepted
        # transaction follows the arbiter, so the rule records both masters
        # instead of pretending one of them owns the window.
        parameters.append(["arbitrated_masters", ("cpu", "bfm")])
        parameters.append(["arbitration", "single_outstanding_request_response"])
    return _rule({
        "rule_id": f"window:{window['target_id']}",
        "category": "environment_hard",
        "owner": owner,
        "primitive": "reachable_window",
        "phase": "runtime",
        "fields": [],
        "read_set": [],
        "write_set": [],
        "parameters": tuple(parameters),
        "basis": "soc_plan.address_map.windows",
        "budget": 1,
        "failure_class": "constraint_conflict",
        "checker": "soc_structure_audit.controller_mmio",
    })


def _closure(rules: Sequence[ConstraintRule]) -> tuple[tuple[tuple[str, tuple[str, ...]], ...],
                                                        tuple[tuple[str, ...], ...]]:
    """Bounded transitive closure over field read/write sets.

    A rule depends on another when it reads a field the other writes.  The walk
    expands each producer's own read set, so a chain is followed to its end.  A
    cycle is *recorded* (a finite expansion of a cycle is legal) but the number
    of edge visits is bounded, so an unbounded fixpoint is reported as a budget
    exhaustion instead of looping.  The result is canonical, so declaration
    order cannot change the produced identity.
    """
    writes: dict[str, list[str]] = {}
    for item in rules:
        for name in item.write_set:
            writes.setdefault(name, []).append(item.rule_id)
    closure: dict[str, set[str]] = {}
    cycles: set[tuple[str, ...]] = set()
    steps = 0
    for item in rules:
        seen: set[str] = set()
        pending: list[tuple[str, tuple[str, ...]]] = [(name, (item.rule_id,))
                                                      for name in item.read_set]
        while pending:
            name, path = pending.pop()
            for producer in writes.get(name, []):
                steps += 1
                if steps > MAX_CLOSURE_STEPS:
                    _error(f"closure-budget-exhausted:{item.rule_id}")
                if producer in path:
                    cycles.add(tuple(sorted(set(path) | {producer})))
                    continue
                if producer in seen:
                    continue
                seen.add(producer)
                for later in rules:
                    if later.rule_id == producer:
                        pending.extend((field, path + (producer,))
                                       for field in later.read_set)
                        break
        closure[item.rule_id] = seen
    return (tuple((rule_id, tuple(sorted(seen))) for rule_id, seen in sorted(closure.items())),
            tuple(sorted(cycles)))


def compile_input_constraints(plan: object, *, drive_profile: str,
                              reachable_targets: Sequence[str] | None = None) -> InputConstraintPolicy:
    """Compile one versioned ownership + constraint policy for a composition plan."""
    if drive_profile not in DRIVE_PROFILES:
        _error(f"unknown-drive-profile:{drive_profile}")
    profile = DRIVE_PROFILES[drive_profile]
    layout = getattr(plan, "raw_layout", None)
    if not isinstance(layout, Mapping):
        _error("plan-raw-layout-missing")
    rules: list[ConstraintRule] = []

    for entry in _special_inputs(layout):
        rules.append(_drive_rule(entry, profile=profile))
    for entry in layout.get("fields", []):
        if not isinstance(entry, Mapping):
            continue
        value_rule = _value_rule(entry)
        if value_rule is not None:
            rules.append(value_rule)

    dut_driven: set[str] = set()
    for instance in getattr(plan, "instances", ()):
        for disposition in instance.dispositions:
            if disposition.disposition == "observe":
                rules.append(_observation_rule({
                    "instance_id": disposition.instance_id,
                    "port": disposition.port,
                    "reason": disposition.reason,
                }))
            elif disposition.disposition == "functional" and disposition.direction == "input":
                # The SoC itself drives this component input (clock, reset,
                # adapter- or controller-owned net).  The environment must never
                # be able to write it.
                dut_driven.add(f"{disposition.instance_id}::{disposition.port}")

    reachable = None if reachable_targets is None else set(reachable_targets)
    for window in getattr(plan, "plan", {}).get("address_map", {}).get("windows", []):
        rules.append(_window_rule(window, profile=profile,
                                  reachable=reachable is None
                                  or str(window["target_id"]) in reachable))

    if len(rules) > MAX_RULES:
        _error(f"rule-count-exceeds-bound:{len(rules)}>{MAX_RULES}")
    ordered = sorted(rules, key=lambda item: item.key())
    identifiers = [item.rule_id for item in ordered]
    if len(set(identifiers)) != len(identifiers):
        duplicates = sorted({name for name in identifiers if identifiers.count(name) > 1})
        _error(f"duplicate-rule-id:{','.join(duplicates)}")
    for item in ordered:
        _validate_rule(item)
    _check_single_driver(ordered, dut_driven=dut_driven)
    closure, cycles = _closure(ordered)
    gaps = _capability_gaps(profile)
    driven = tuple(sorted(dut_driven))
    payload = {
        "schema_version": INPUT_CONSTRAINT_SCHEMA,
        "drive_profile": drive_profile,
        "profile_version": int(profile["version"]),
        "bus_owner": str(profile["bus_owner"]),
        "cpu_held_in_reset": bool(profile["cpu_held_in_reset"]),
        "legacy_modes": list(profile["legacy_modes"]),
        "rules": [item.document() for item in ordered],
        "closure": [[rule_id, list(deps)] for rule_id, deps in closure],
        "cycles": [list(item) for item in cycles],
        "layout_hash": str(layout.get("layout_hash", "")),
        "plan_hash": str(getattr(plan, "plan_hash", "")),
        "gaps": list(gaps),
        "dut_driven": list(driven),
    }
    policy_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return InputConstraintPolicy(
        drive_profile=drive_profile,
        profile_version=int(profile["version"]),
        bus_owner=str(profile["bus_owner"]),
        cpu_held_in_reset=bool(profile["cpu_held_in_reset"]),
        legacy_modes=tuple(str(item) for item in profile["legacy_modes"]),
        rules=tuple(ordered),
        layout_hash=str(layout.get("layout_hash", "")),
        plan_hash=str(getattr(plan, "plan_hash", "")),
        closure=closure,
        cycles=cycles,
        gaps=gaps,
        policy_hash=policy_hash,
    )


def compile_rules(documents: Sequence[Mapping[str, object]], *, drive_profile: str,
                  layout_hash: str = "", plan_hash: str = "",
                  dut_driven: Sequence[str] = ()) -> InputConstraintPolicy:
    """Compile an explicit rule set with the same validation and identity rules.

    Used by the tests and by the later phases that build rules from a repair
    plan rather than from the composition layout.
    """
    if drive_profile not in DRIVE_PROFILES:
        _error(f"unknown-drive-profile:{drive_profile}")
    profile = DRIVE_PROFILES[drive_profile]
    if len(documents) > MAX_RULES:
        _error(f"rule-count-exceeds-bound:{len(documents)}>{MAX_RULES}")
    ordered = sorted((_rule(item) for item in documents), key=lambda item: item.key())
    identifiers = [item.rule_id for item in ordered]
    if len(set(identifiers)) != len(identifiers):
        duplicates = sorted({name for name in identifiers if identifiers.count(name) > 1})
        _error(f"duplicate-rule-id:{','.join(duplicates)}")
    for item in ordered:
        _validate_rule(item)
    _check_single_driver(ordered, dut_driven=set(dut_driven))
    closure, cycles = _closure(ordered)
    gaps = _capability_gaps(profile)
    payload = {
        "schema_version": INPUT_CONSTRAINT_SCHEMA,
        "drive_profile": drive_profile,
        "profile_version": int(profile["version"]),
        "bus_owner": str(profile["bus_owner"]),
        "cpu_held_in_reset": bool(profile["cpu_held_in_reset"]),
        "legacy_modes": list(profile["legacy_modes"]),
        "rules": [item.document() for item in ordered],
        "closure": [[rule_id, list(deps)] for rule_id, deps in closure],
        "cycles": [list(item) for item in cycles],
        "layout_hash": layout_hash,
        "plan_hash": plan_hash,
        "gaps": list(gaps),
        "dut_driven": sorted(dut_driven),
    }
    policy_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return InputConstraintPolicy(
        drive_profile=drive_profile,
        profile_version=int(profile["version"]),
        bus_owner=str(profile["bus_owner"]),
        cpu_held_in_reset=bool(profile["cpu_held_in_reset"]),
        legacy_modes=tuple(str(item) for item in profile["legacy_modes"]),
        rules=tuple(ordered),
        layout_hash=layout_hash,
        plan_hash=plan_hash,
        closure=closure,
        cycles=cycles,
        gaps=gaps,
        policy_hash=policy_hash,
    )


def _rule_modes(item: ConstraintRule) -> frozenset[str]:
    """The modes a rule applies in; an empty declaration means every mode."""
    return frozenset(item.applies_in_modes) or frozenset(("cpu_only", "mmio_only", "mixed"))


def _check_single_driver(rules: Sequence[ConstraintRule], *,
                         dut_driven: set[str] | None = None) -> None:
    """No bit may have two environment drivers in the same mode.

    Two rules that only ever apply in mutually exclusive modes are not a double
    driver; they are two scenario-specific drivers for the same bit, which is
    exactly what the scenario vocabulary exists for.
    """
    owners: dict[int, list[ConstraintRule]] = {}
    for item in rules:
        if item.owner != "environment":
            continue
        for raw_lo, raw_hi in item.raw_bits:
            for bit in range(raw_lo, raw_hi + 1):
                for previous in owners.get(bit, ()):
                    shared = _rule_modes(previous) & _rule_modes(item)
                    # A sample value repair feeds the one physical driver; it
                    # is not a second physical writer. Require identical field
                    # geometry, not merely two different phase labels.
                    stages = (previous, item)
                    value_stage = [rule for rule in stages if rule.phase == "sample"
                                   and rule.primitive in ("value_range", "value_enum", "value_mask_align")]
                    driver_stage = [rule for rule in stages if rule.phase == "runtime"
                                    and rule.primitive.startswith("drive_")]
                    if value_stage and driver_stage and previous.fields == item.fields \
                            and previous.raw_bits == item.raw_bits:
                        continue
                    if shared:
                        _error(f"duplicate-input-driver:raw-bit-{bit}:"
                               f"{previous.rule_id}+{item.rule_id}:"
                               f"modes={','.join(sorted(shared))}")
                owners.setdefault(bit, []).append(item)
    written = {name for item in rules if item.owner == "environment"
               for name in item.write_set}
    dut_owned = {name for item in rules if item.owner == "dut" for name in item.read_set}
    dut_owned |= set(dut_driven or ())
    overlap = sorted(written & dut_owned)
    if overlap:
        _error(f"environment-overrides-dut-value:{','.join(overlap)}")


def _capability_gaps(profile: Mapping[str, object]) -> tuple[str, ...]:
    gaps: list[str] = []
    if profile["bus_owner"] == "arbitrated":
        gaps.append(
            "mixed ownership runs two real masters on one single-outstanding fabric; "
            "concurrent and out-of-order behaviour is not covered")
    if profile["bus_owner"] == "bfm":
        gaps.append("with the CPU held in reset there is no CPU execution evidence in this mode")
    gaps.append(
        "the first-phase fabric allows one outstanding transaction, so serialised access "
        "reduces the concurrent states the components experience")
    return tuple(gaps)


def input_constraint_document(policy: InputConstraintPolicy, *,
                              provenance: Mapping[str, object] | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": INPUT_CONSTRAINT_SCHEMA,
        "policy_hash": policy.policy_hash,
        "drive_profile": policy.drive_profile,
        "profile_version": policy.profile_version,
        "bus_owner": policy.bus_owner,
        "cpu_held_in_reset": policy.cpu_held_in_reset,
        "legacy_modes": list(policy.legacy_modes),
        "layout_hash": policy.layout_hash,
        "plan_hash": policy.plan_hash,
        "rules": [item.document() for item in policy.rules],
        "closure": [[rule_id, list(deps)] for rule_id, deps in policy.closure],
        "cycles": [list(item) for item in policy.cycles],
        "summary": {
            "rules": len(policy.rules),
            "by_category": {
                category: sum(1 for item in policy.rules if item.category == category)
                for category in RULE_CATEGORIES
            },
            "by_owner": {
                owner: sum(1 for item in policy.rules if item.owner == owner)
                for owner in OWNERS
            },
            "environment_driven_bits": len(policy.environment_write_bits()),
        },
        "gaps": list(policy.gaps),
    }
    if provenance is not None:
        document["provenance"] = dict(provenance)
    return document


def rules_of(policy: InputConstraintPolicy, category: str) -> tuple[ConstraintRule, ...]:
    return tuple(item for item in policy.rules if item.category == category)


__all__ = [
    "DRIVE_PROFILES",
    "FAILURE_CLASSES",
    "INPUT_CONSTRAINT_SCHEMA",
    "MAX_CLOSURE_STEPS",
    "MAX_RULES",
    "PHASES",
    "RULE_CATEGORIES",
    "SUPPORTED_PRIMITIVES",
    "ConstraintRule",
    "InputConstraintError",
    "InputConstraintPolicy",
    "compile_input_constraints",
    "compile_rules",
    "input_constraint_document",
    "project_sample_values",
    "rules_of",
]
