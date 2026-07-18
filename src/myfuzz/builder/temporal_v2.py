"""Normative TemporalConstraintIR v2 validation and cycle reference evaluator."""

from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
from typing import Iterable, Mapping

from .contracts import TemporalConstraintIRV2, canonical_json, seal_contract
from .input_model import InputValidationError


PRIMITIVE_OPERANDS: Mapping[str, tuple[str, ...]] = {
    "STABLE_UNTIL": ("dst", "sample", "activate", "release", "width", "reset"),
    "VALID_READY": ("valid", "payload", "sample", "activate", "ready", "width", "reset_payload"),
    "PULSE_WIDTH": ("dst", "start", "cycles"),
    "HOLD_WHEN": ("dst", "sample", "hold", "width", "reset"),
    "UPDATE_ON": ("dst", "sample", "event", "width", "reset"),
    "DEPENDENCY": ("dst", "predicate", "true_value", "false_value", "width"),
    "BIT_MASK": ("dst", "sample", "mask", "width"),
    "SEQUENCE": ("state", "initial", "transitions", "terminal", "states"),
    "WAIT_UNTIL": ("activate", "predicate", "limit", "success", "expired"),
    "TIMEOUT": ("active", "clear", "limit", "fired"),
    "CHOICE_WEIGHT": ("dst", "raw_slice", "slice_width", "choices", "integer_weights", "width"),
    "FAULT_INJECT": ("dst", "enable", "kind", "value", "cycles", "width"),
    "RESET_SEQUENCE": ("domain", "start", "drain_limit", "isolate_limit", "assert_cycles",
                       "complete_limit", "drained", "isolated", "reset_done", "error",
                       "request", "force_isolate", "success", "failed"),
}
TEMPORAL_SPECIFICATION_DIGEST = hashlib.sha256(canonical_json({
    "schema": "myfuzz.temporal-constraint-semantics/v2",
    "operands": PRIMITIVE_OPERANDS,
    "edge_order": "registered_outputs_accept,dut_nba,settled_feedback,next_state",
})).hexdigest()


@dataclass(frozen=True)
class TemporalStep:
    cycle: int
    accept_index: int
    accepted: bool
    outputs: Mapping[str, object]
    runtime_error: bool


def build_temporal_constraint_ir_v2(
    *, rawbits_layout_digest: str, soc_digest: str,
    constraints: Iterable[Mapping[str, object]],
    fault_capable_sinks: Iterable[str] = (),
) -> TemporalConstraintIRV2:
    values = []
    for index, raw in enumerate(constraints):
        value = dict(raw)
        primitive = _text(value.get("primitive"), f"constraints[{index}].primitive").upper()
        if primitive not in PRIMITIVE_OPERANDS:
            raise InputValidationError(f"constraints[{index}].primitive: unsupported {primitive!r}")
        required = {"id", "primitive", "priority", "domain", *PRIMITIVE_OPERANDS[primitive]}
        unknown, missing = set(value) - required, required - set(value)
        if missing or unknown:
            entries, kind = (missing, "missing") if missing else (unknown, "unknown")
            raise InputValidationError(f"constraints[{index}]: {kind} field(s): {', '.join(sorted(entries))}")
        value["id"] = _text(value["id"], f"constraints[{index}].id")
        value["primitive"] = primitive
        value["priority"] = _nonnegative(value["priority"], f"constraints[{index}].priority")
        value["domain"] = _text(value["domain"], f"constraints[{index}].domain")
        _validate_operands(value, index, set(fault_capable_sinks))
        values.extend(_expand_reset_sequence(value) if primitive == "RESET_SEQUENCE" else (value,))
    ids = [str(value["id"]) for value in values]
    if len(ids) != len(set(ids)):
        raise InputValidationError("TemporalConstraintIR v2 IDs must be unique")
    priorities = [int(value["priority"]) for value in values if not value.get("internal_only")]
    if len(priorities) != len(set(priorities)):
        raise InputValidationError("TemporalConstraintIR v2 priorities must be unique")
    _validate_writers_and_dag(values)
    return seal_contract(TemporalConstraintIRV2(
        rawbits_layout_digest, soc_digest, TEMPORAL_SPECIFICATION_DIGEST,
        tuple(values), {"source": "normative-temporal-semantics/v2", "reset_macro_expanded": True},
    ))  # type: ignore[return-value]


class TemporalConstraintEvaluator:
    def __init__(self, ir: TemporalConstraintIRV2):
        if ir.specification_digest != TEMPORAL_SPECIFICATION_DIGEST:
            raise InputValidationError("TemporalConstraintIR v2 specification digest mismatch")
        self.rules = tuple(sorted(ir.constraints, key=lambda item: int(item["priority"])))
        self.outputs: dict[str, object] = {}
        self.state: dict[str, dict[str, object]] = {}
        self.runtime_error = False
        self.cycle = 0
        self.accept_index = 0
        self._reset_all()

    @property
    def raw_bits_ready(self) -> bool:
        return not self.runtime_error

    def step(self, inputs: Mapping[str, object], *, record_valid: bool = False,
             global_reset: bool = False, domain_resets: Iterable[str] = ()) -> TemporalStep:
        accepted = bool(record_valid and self.raw_bits_ready)
        if global_reset:
            self._reset_all()
            accepted = False
        else:
            reset_domains = set(domain_resets)
            for rule in self.rules:
                if str(rule["domain"]) in reset_domains:
                    self._reset_rule(rule)
            if not self.runtime_error:
                context: dict[str, object] = {**inputs, **self.outputs}
                stable_outputs = dict(self.outputs)
                stable_state = copy.deepcopy(self.state)
                for rule in self.rules:
                    if rule.get("internal_only") or str(rule["domain"]) in reset_domains:
                        continue
                    self._apply(rule, context, accepted)
                    context.update(self.outputs)
                    if self.runtime_error:
                        self.outputs = stable_outputs
                        self.state = stable_state
                        accepted = False
                        break
        result = TemporalStep(self.cycle, self.accept_index, accepted, dict(self.outputs), self.runtime_error)
        if accepted:
            self.accept_index += 1
        self.cycle += 1
        return result

    def _reset_all(self) -> None:
        self.outputs = {}
        self.state = {}
        self.runtime_error = False
        for rule in self.rules:
            if not rule.get("internal_only"):
                self._reset_rule(rule)

    def _reset_rule(self, rule: Mapping[str, object]) -> None:
        rid, primitive = str(rule["id"]), str(rule["primitive"])
        self.state[rid] = {"active": False, "count": 0, "remaining": 0, "isolated": False}
        if primitive in {"STABLE_UNTIL", "HOLD_WHEN", "UPDATE_ON"}:
            self.outputs[str(rule["dst"])] = int(rule["reset"])
        elif primitive == "VALID_READY":
            self.outputs[str(rule["valid"])] = 0; self.outputs[str(rule["payload"])] = int(rule["reset_payload"])
        elif primitive in {"PULSE_WIDTH", "FAULT_INJECT"}:
            self.outputs[str(rule["dst"])] = 0
        elif primitive in {"DEPENDENCY", "BIT_MASK"}:
            self.outputs[str(rule["dst"])] = 0
        elif primitive == "SEQUENCE":
            self.outputs[str(rule["state"])] = str(rule["initial"])
            if rule.get("macro") == "reset_sequence":
                for name in ("request", "force_isolate", "success", "failed"):
                    self.outputs[str(rule[name])] = 0
        elif primitive == "WAIT_UNTIL":
            self.outputs[str(rule["success"])] = 0; self.outputs[str(rule["expired"])] = 0
        elif primitive == "TIMEOUT":
            self.outputs[str(rule["fired"])] = 0
        elif primitive == "CHOICE_WEIGHT":
            self.outputs[str(rule["dst"])] = int(tuple(rule["choices"])[0])

    def _value(self, operand: object, context: Mapping[str, object]) -> object:
        # String operands are bit-level signal references. Unconnected inputs are
        # deterministic zeroes; literal textual values are never evaluated here.
        return context.get(operand, 0) if isinstance(operand, str) else operand

    def _apply(self, rule: Mapping[str, object], context: dict[str, object], accepted: bool) -> None:
        primitive, rid = str(rule["primitive"]), str(rule["id"]); state = self.state[rid]
        if primitive == "STABLE_UNTIL":
            release, activate = bool(self._value(rule["release"], context)), bool(self._value(rule["activate"], context))
            if state["active"]:
                if release: state["active"] = False
            elif activate and not release:
                self.outputs[str(rule["dst"])] = int(self._value(rule["sample"], context)); state["active"] = True
        elif primitive == "VALID_READY":
            valid = str(rule["valid"]); activate = bool(self._value(rule["activate"], context))
            if state["active"]:
                if activate: self.runtime_error = True; return
                if bool(self.outputs[valid]) and bool(self._value(rule["ready"], context)):
                    self.outputs[valid] = 0; state["active"] = False
            elif activate:
                self.outputs[str(rule["payload"])] = int(self._value(rule["sample"], context)); self.outputs[valid] = 1; state["active"] = True
        elif primitive == "PULSE_WIDTH":
            start, cycles = bool(self._value(rule["start"], context)), int(rule["cycles"]); dst = str(rule["dst"])
            if state["remaining"]:
                if start: self.runtime_error = True; return
                state["remaining"] = int(state["remaining"]) - 1; self.outputs[dst] = 1 if state["remaining"] else 0
            elif start and cycles:
                state["remaining"] = cycles; self.outputs[dst] = 1
        elif primitive == "HOLD_WHEN":
            if not bool(self._value(rule["hold"], context)): self.outputs[str(rule["dst"])] = int(self._value(rule["sample"], context))
        elif primitive == "UPDATE_ON":
            if bool(self._value(rule["event"], context)): self.outputs[str(rule["dst"])] = int(self._value(rule["sample"], context))
        elif primitive == "DEPENDENCY":
            choice = rule["true_value"] if bool(self._value(rule["predicate"], context)) else rule["false_value"]
            self.outputs[str(rule["dst"])] = int(self._value(choice, context))
        elif primitive == "BIT_MASK":
            self.outputs[str(rule["dst"])] = int(self._value(rule["sample"], context)) & int(rule["mask"])
        elif primitive == "WAIT_UNTIL":
            success, expired = str(rule["success"]), str(rule["expired"]); self.outputs[success] = 0; self.outputs[expired] = 0
            if not state["active"]:
                if bool(self._value(rule["activate"], context)): state["active"] = True; state["count"] = 0
            elif bool(self._value(rule["predicate"], context)):
                self.outputs[success] = 1; state["active"] = False; state["count"] = 0
            elif int(state["count"]) == int(rule["limit"]) - 1:
                self.outputs[expired] = 1; state["active"] = False; state["count"] = 0
            else: state["count"] = int(state["count"]) + 1
        elif primitive == "TIMEOUT":
            fired = str(rule["fired"]); self.outputs[fired] = 0
            if bool(self._value(rule["clear"], context)) or not bool(self._value(rule["active"], context)):
                state["count"] = 0
            elif int(state["count"]) < int(rule["limit"]):
                state["count"] = int(state["count"]) + 1
                if int(state["count"]) == int(rule["limit"]): self.outputs[fired] = 1
        elif primitive == "CHOICE_WEIGHT":
            if accepted:
                raw, width = int(self._value(rule["raw_slice"], context)), int(rule["slice_width"])
                weights, choices = tuple(rule["integer_weights"]), tuple(rule["choices"])
                bucket = raw * sum(int(item) for item in weights) // (1 << width); upper = 0
                for choice, weight in zip(choices, weights):
                    upper += int(weight)
                    if bucket < upper: self.outputs[str(rule["dst"])] = int(choice); break
        elif primitive == "FAULT_INJECT":
            dst = str(rule["dst"]); enable = bool(self._value(rule["enable"], context))
            if state["remaining"]:
                state["remaining"] = int(state["remaining"]) - 1
                self.outputs[dst] = int(rule["value"]) if state["remaining"] else 0
            elif enable:
                state["remaining"] = int(rule["cycles"]); self.outputs[dst] = int(rule["value"])
        elif primitive == "SEQUENCE":
            if rule.get("macro") == "reset_sequence": self._apply_reset_sequence(rule, context, state)
            else: self._apply_sequence(rule, context, state)

    def _apply_sequence(self, rule, context, state) -> None:
        current = str(self.outputs[str(rule["state"])]); candidates = []
        for transition in tuple(rule["transitions"]):
            if transition["from"] == current and bool(self._value(transition["guard"], context)):
                candidates.append(transition)
        if candidates:
            chosen = sorted(candidates, key=lambda item: int(item["priority"]))[0]
            self.outputs[str(rule["state"])] = str(chosen["to"])

    def _apply_reset_sequence(self, rule, context, state) -> None:
        state_name = str(rule["state"]); current = str(self.outputs[state_name]); state["count"] = int(state["count"]) + 1
        for name in ("success", "failed"): self.outputs[str(rule[name])] = 0
        self.outputs[str(rule["request"])] = int(current in {"DRAIN", "ISOLATE", "RESET"})
        self.outputs[str(rule["force_isolate"])] = int(current == "ISOLATE" or (current == "RESET" and state["isolated"]))
        error = bool(self._value(rule["error"], context))
        if current == "IDLE":
            state["count"] = 0; state["isolated"] = False
            if bool(self._value(rule["start"], context)): self.outputs[state_name] = "DRAIN"
        elif current == "DRAIN":
            if error: self.outputs[state_name] = "FAILED"
            elif bool(self._value(rule["drained"], context)): self.outputs[state_name] = "RESET"; state["count"] = 0
            elif int(state["count"]) >= int(rule["drain_limit"]): self.outputs[state_name] = "ISOLATE"; state["count"] = 0; state["isolated"] = True
        elif current == "ISOLATE":
            if error: self.outputs[state_name] = "FAILED"
            elif bool(self._value(rule["isolated"], context)): self.outputs[state_name] = "RESET"; state["count"] = 0
            elif int(state["count"]) >= int(rule["isolate_limit"]): self.outputs[state_name] = "FAILED"
        elif current == "RESET":
            if error: self.outputs[state_name] = "FAILED"
            elif int(state["count"]) >= int(rule["assert_cycles"]) and bool(self._value(rule["reset_done"], context)): self.outputs[state_name] = "DONE"
            elif int(state["count"]) >= int(rule["complete_limit"]): self.outputs[state_name] = "FAILED"
        elif current == "DONE": self.outputs[str(rule["success"])] = 1; self.outputs[state_name] = "IDLE"
        elif current == "FAILED": self.outputs[str(rule["failed"])] = 1; self.outputs[state_name] = "IDLE"


def _validate_operands(value: Mapping[str, object], index: int, fault_sinks: set[str]) -> None:
    primitive = str(value["primitive"])
    for field in ("width", "slice_width", "limit", "cycles", "drain_limit", "isolate_limit", "assert_cycles", "complete_limit"):
        if field in value:
            minimum = 0 if primitive == "PULSE_WIDTH" and field == "cycles" else 1
            number = _nonnegative(value[field], f"constraints[{index}].{field}")
            if number < minimum: raise InputValidationError(f"constraints[{index}].{field}: expected >= {minimum}")
    if primitive == "CHOICE_WEIGHT":
        choices, weights = tuple(value["choices"]), tuple(value["integer_weights"])
        if not choices or len(choices) != len(weights) or any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in weights):
            raise InputValidationError(f"constraints[{index}]: CHOICE_WEIGHT requires equal non-empty choices and positive weights")
    if primitive == "BIT_MASK":
        mask = _nonnegative(value["mask"], f"constraints[{index}].mask")
        if mask >= (1 << int(value["width"])):
            raise InputValidationError(f"constraints[{index}].mask: does not fit width")
    if primitive == "FAULT_INJECT" and str(value["dst"]) not in fault_sinks:
        raise InputValidationError(f"constraints[{index}].dst: not an external fault-capable sink")
    if primitive == "SEQUENCE":
        states, terminal = set(value["states"]), set(value["terminal"])
        if value["initial"] not in states or not terminal <= states: raise InputValidationError("SEQUENCE states are inconsistent")
        transitions = tuple(value["transitions"]); priorities = [item["priority"] for item in transitions]
        if len(priorities) != len(set(priorities)): raise InputValidationError("SEQUENCE transition priorities must be unique")


def _expand_reset_sequence(value: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    base = {key: item for key, item in value.items() if key not in {"primitive", "domain"}}
    sequence = {
        **base, "primitive": "SEQUENCE", "domain": value["domain"], "macro": "reset_sequence",
        "state": f"{value['id']}.state", "initial": "IDLE",
        "states": ("IDLE", "DRAIN", "ISOLATE", "RESET", "DONE", "FAILED"),
        "terminal": (), "transitions": (),
    }
    timeouts = tuple({
        "id": f"{value['id']}.{name}_timeout", "primitive": "TIMEOUT", "priority": int(value["priority"]) + offset,
        "domain": value["domain"], "active": f"{value['id']}.internal_{name}_active", "clear": 0,
        "limit": value[f"{name}_limit"], "fired": f"{value['id']}.internal_{name}_fired", "internal_only": True,
    } for offset, name in enumerate(("drain", "isolate", "complete"), start=1_000_000))
    return (sequence, *timeouts)


def _writers(value: Mapping[str, object]) -> tuple[str, ...]:
    primitive = str(value["primitive"])
    fields = {"VALID_READY": ("valid", "payload"), "WAIT_UNTIL": ("success", "expired"),
              "SEQUENCE": ("state",), "TIMEOUT": ("fired",)}.get(primitive, ("dst",))
    result = [str(value[field]) for field in fields if field in value]
    if primitive == "SEQUENCE" and value.get("macro") == "reset_sequence":
        result.extend(str(value[field]) for field in ("request", "force_isolate", "success", "failed"))
    return tuple(result)


def _validate_writers_and_dag(values: list[Mapping[str, object]]) -> None:
    owners = {}
    for value in values:
        if value.get("internal_only"): continue
        for output in _writers(value):
            if output in owners: raise InputValidationError(f"multiple writers for {output!r}: {owners[output]} and {value['id']}")
            owners[output] = value["id"]
    dependencies = {str(value["id"]): set() for value in values if not value.get("internal_only")}
    by_output = {output: str(owner) for output, owner in owners.items()}
    priorities = {
        str(value["id"]): int(value["priority"])
        for value in values if not value.get("internal_only")
    }
    priority_violations = []
    for value in values:
        if value.get("internal_only"): continue
        for operand in value.values():
            if isinstance(operand, str) and operand in by_output and by_output[operand] != value["id"]:
                producer = by_output[operand]
                consumer = str(value["id"])
                dependencies[consumer].add(producer)
                if priorities[producer] >= priorities[consumer]:
                    priority_violations.append((producer, consumer))
    remaining = dict(dependencies)
    while remaining:
        ready = {node for node, deps in remaining.items() if not deps & set(remaining)}
        if not ready: raise InputValidationError("TemporalConstraintIR v2 dependency cycle")
        for node in ready: remaining.pop(node)
    if priority_violations:
        producer, consumer = sorted(priority_violations)[0]
        raise InputValidationError(
            f"dependency priority violation: {producer!r} must execute before {consumer!r}"
        )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip(): raise InputValidationError(f"{path}: expected non-empty text")
    return value


def _nonnegative(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0: raise InputValidationError(f"{path}: expected a non-negative integer")
    return value
