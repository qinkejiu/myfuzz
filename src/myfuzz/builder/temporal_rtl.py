"""Synthesizable RTL emitter for canonical TemporalConstraintIR v2."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Mapping

from .contracts import TemporalConstraintIRV2
from .input_model import InputValidationError
from .temporal_v2 import TEMPORAL_SPECIFICATION_DIGEST, _writers


@dataclass(frozen=True)
class EmittedTemporalRTL:
    module_name: str
    rtl: str
    input_ports: Mapping[str, str]
    output_ports: Mapping[str, str]
    domain_reset_ports: Mapping[str, str]
    state_encodings: Mapping[str, Mapping[str, int]]


def emit_temporal_constraint_rtl(
    ir: TemporalConstraintIRV2, *, module_name: str = "myfuzz_temporal_constraints",
) -> EmittedTemporalRTL:
    """Emit a deterministic next-state machine from a validated v2 IR."""
    if ir.specification_digest != TEMPORAL_SPECIFICATION_DIGEST:
        raise InputValidationError("TemporalConstraintIR v2 specification digest mismatch")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("temporal RTL module_name is not a Verilog identifier")
    rules = tuple(sorted((rule for rule in ir.constraints if not rule.get("internal_only")),
                         key=lambda rule: int(rule["priority"])))
    output_widths, state_encodings = _output_metadata(rules)
    input_widths = _input_metadata(rules, output_widths)
    names = _PortNames()
    output_ports = {signal: names.make(f"out_{signal}") for signal in sorted(output_widths)}
    input_ports = {signal: names.make(f"in_{signal}") for signal in sorted(input_widths)}
    domain_reset_ports = {
        domain: names.make(f"domain_reset_{domain}")
        for domain in sorted({str(rule["domain"]) for rule in rules})
    }
    rule_names = {str(rule["id"]): names.make(f"rule_{rule['id']}") for rule in rules}

    def out(signal: object, *, nxt: bool = False) -> str:
        base = output_ports[str(signal)]
        return f"{base}_next" if nxt else base

    def expr(value: object) -> str:
        if isinstance(value, bool):
            return "1'b1" if value else "1'b0"
        if isinstance(value, int):
            return str(value)
        signal = str(value)
        if signal in output_ports:
            return out(signal, nxt=True)
        if signal in input_ports:
            return input_ports[signal]
        raise InputValidationError(f"unresolved TemporalConstraintIR signal {signal!r}")

    port_lines = ["input logic clk", "input logic rst_n", "input logic raw_bits_valid"]
    port_lines.extend(f"input logic {port}" for port in domain_reset_ports.values())
    port_lines.extend(_decl("input logic", port, input_widths[signal]) for signal, port in input_ports.items())
    port_lines.extend(_decl("output logic", port, output_widths[signal]) for signal, port in output_ports.items())
    port_lines.extend(("output logic raw_bits_ready", "output logic constraint_runtime_error"))
    lines = [f"module {module_name} (", "  " + ",\n  ".join(port_lines), ");", ""]

    for signal, port in output_ports.items():
        lines.append("  " + _decl("logic", f"{port}_next", output_widths[signal]) + ";")
    lines.append("  logic constraint_runtime_error_next;")
    for rule in rules:
        prefix = rule_names[str(rule["id"])]
        for suffix, width in _rule_state(rule).items():
            lines.append("  " + _decl("logic", f"{prefix}_{suffix}", width) + ";")
            lines.append("  " + _decl("logic", f"{prefix}_{suffix}_next", width) + ";")
    lines.extend(("", "  assign raw_bits_ready = ~constraint_runtime_error;", "", "  always_comb begin"))
    for port in output_ports.values():
        lines.append(f"    {port}_next = {port};")
    lines.append("    constraint_runtime_error_next = constraint_runtime_error;")
    for rule in rules:
        prefix = rule_names[str(rule["id"])]
        for suffix in _rule_state(rule):
            lines.append(f"    {prefix}_{suffix}_next = {prefix}_{suffix};")
    lines.append("")
    for rule in rules:
        reset_port = domain_reset_ports[str(rule["domain"])]
        lines.append(f"    if ({reset_port}) begin")
        lines.extend(f"      {item}" for item in _reset_statements(rule, out, rule_names, state_encodings))
        lines.append("    end else if (!constraint_runtime_error_next) begin")
        lines.extend(f"      {item}" for item in _apply_statements(rule, out, expr, rule_names, state_encodings))
        lines.append("    end")
    # A dynamic violation freezes all next-state values from this edge.
    lines.append("    if (constraint_runtime_error_next && !constraint_runtime_error) begin")
    for port in output_ports.values():
        lines.append(f"      {port}_next = {port};")
    for rule in rules:
        prefix = rule_names[str(rule["id"])]
        for suffix in _rule_state(rule):
            lines.append(f"      {prefix}_{suffix}_next = {prefix}_{suffix};")
    lines.extend(("    end", "  end", "", "  always_ff @(posedge clk) begin", "    if (!rst_n) begin"))
    for rule in rules:
        lines.extend(f"      {item}" for item in _reset_statements(rule, out, rule_names, state_encodings, sequential=True))
    lines.append("      constraint_runtime_error <= 1'b0;")
    lines.append("    end else begin")
    for port in output_ports.values():
        lines.append(f"      {port} <= {port}_next;")
    for rule in rules:
        prefix = rule_names[str(rule["id"])]
        for suffix in _rule_state(rule):
            lines.append(f"      {prefix}_{suffix} <= {prefix}_{suffix}_next;")
    lines.extend(("      constraint_runtime_error <= constraint_runtime_error_next;", "    end", "  end", "endmodule", ""))
    return EmittedTemporalRTL(module_name, "\n".join(lines), input_ports, output_ports,
                              domain_reset_ports, state_encodings)


class _PortNames:
    def __init__(self) -> None:
        self.used: set[str] = set()

    def make(self, source: str) -> str:
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", source)
        if not candidate or candidate[0].isdigit():
            candidate = "n_" + candidate
        base, index = candidate, 2
        while candidate in self.used:
            candidate = f"{base}_{index}"; index += 1
        self.used.add(candidate)
        return candidate


def _decl(kind: str, name: str, width: int) -> str:
    return f"{kind} {name}" if width == 1 else f"{kind} [{width - 1}:0] {name}"


def _bits(count: int) -> int:
    return max(1, math.ceil(math.log2(max(2, count))))


def _output_metadata(rules):
    widths: dict[str, int] = {}
    encodings: dict[str, Mapping[str, int]] = {}
    for rule in rules:
        primitive = str(rule["primitive"])
        if primitive == "VALID_READY":
            widths[str(rule["valid"])] = 1; widths[str(rule["payload"])] = int(rule["width"])
        elif primitive == "WAIT_UNTIL":
            widths[str(rule["success"])] = 1; widths[str(rule["expired"])] = 1
        elif primitive == "TIMEOUT":
            widths[str(rule["fired"])] = 1
        elif primitive == "SEQUENCE":
            states = tuple(str(item) for item in rule["states"])
            signal = str(rule["state"]); widths[signal] = _bits(len(states))
            encodings[signal] = {state: index for index, state in enumerate(states)}
            if rule.get("macro") == "reset_sequence":
                for field in ("request", "force_isolate", "success", "failed"):
                    widths[str(rule[field])] = 1
        else:
            widths[str(rule["dst"])] = int(rule.get("width", 1))
    return widths, encodings


def _input_metadata(rules, output_widths):
    widths: dict[str, int] = {}

    def add(value, width):
        if not isinstance(value, str) or value in output_widths:
            return
        old = widths.get(value)
        if old is not None and old != width:
            raise InputValidationError(f"TemporalConstraintIR signal {value!r} has conflicting widths {old} and {width}")
        widths[value] = width

    for rule in rules:
        primitive = str(rule["primitive"]); width = int(rule.get("width", 1))
        if primitive in {"STABLE_UNTIL", "HOLD_WHEN", "UPDATE_ON", "VALID_READY", "BIT_MASK"}: add(rule["sample"], width)
        if primitive == "DEPENDENCY":
            add(rule["predicate"], 1); add(rule["true_value"], width); add(rule["false_value"], width)
        for field in ("activate", "release", "ready", "start", "hold", "event", "predicate",
                      "active", "clear", "enable", "drained", "isolated", "reset_done", "error"):
            if field in rule: add(rule[field], 1)
        if primitive == "CHOICE_WEIGHT": add(rule["raw_slice"], int(rule["slice_width"]))
        if primitive == "SEQUENCE":
            for transition in rule["transitions"]: add(transition["guard"], 1)
    return widths


def _rule_state(rule):
    primitive = str(rule["primitive"])
    result: dict[str, int] = {}
    if primitive in {"STABLE_UNTIL", "VALID_READY", "WAIT_UNTIL"}: result["active"] = 1
    if primitive in {"PULSE_WIDTH", "FAULT_INJECT"}: result["remaining"] = 32
    if primitive in {"WAIT_UNTIL", "TIMEOUT"}: result["count"] = 32
    if primitive == "SEQUENCE" and rule.get("macro") == "reset_sequence":
        result["count"] = 32; result["isolated"] = 1
    return result


def _reset_statements(rule, out, rule_names, encodings, sequential=False):
    assign = "<=" if sequential else "="; suffix = "" if sequential else "_next"
    primitive = str(rule["primitive"]); prefix = rule_names[str(rule["id"])]; result = []
    def output(field, value): result.append(f"{out(rule[field])}{suffix} {assign} {value};")
    if primitive in {"STABLE_UNTIL", "HOLD_WHEN", "UPDATE_ON"}: output("dst", str(int(rule["reset"])))
    elif primitive == "VALID_READY": output("valid", "1'b0"); output("payload", str(int(rule["reset_payload"])))
    elif primitive in {"PULSE_WIDTH", "FAULT_INJECT", "DEPENDENCY", "BIT_MASK"}: output("dst", "'0")
    elif primitive == "WAIT_UNTIL": output("success", "1'b0"); output("expired", "1'b0")
    elif primitive == "TIMEOUT": output("fired", "1'b0")
    elif primitive == "CHOICE_WEIGHT": output("dst", str(int(tuple(rule["choices"])[0])))
    elif primitive == "SEQUENCE":
        state = str(rule["state"]); output("state", str(encodings[state][str(rule["initial"])]))
        if rule.get("macro") == "reset_sequence":
            for field in ("request", "force_isolate", "success", "failed"): output(field, "1'b0")
    for state_name in _rule_state(rule): result.append(f"{prefix}_{state_name}{suffix} {assign} '0;")
    return result


def _apply_statements(rule, out, expr, rule_names, encodings):
    p = str(rule["primitive"]); prefix = rule_names[str(rule["id"])]; result = []
    if p == "STABLE_UNTIL":
        result += [f"if ({prefix}_active_next) begin", f"  if ({expr(rule['release'])}) {prefix}_active_next = 1'b0;", "end else if (" + expr(rule["activate"]) + " && !" + expr(rule["release"]) + ") begin", f"  {out(rule['dst'], nxt=True)} = {expr(rule['sample'])};", f"  {prefix}_active_next = 1'b1;", "end"]
    elif p == "VALID_READY":
        result += [f"if ({prefix}_active_next) begin", f"  if ({expr(rule['activate'])}) constraint_runtime_error_next = 1'b1;", f"  else if ({out(rule['valid'], nxt=True)} && {expr(rule['ready'])}) begin", f"    {out(rule['valid'], nxt=True)} = 1'b0;", f"    {prefix}_active_next = 1'b0;", "  end", f"end else if ({expr(rule['activate'])}) begin", f"  {out(rule['payload'], nxt=True)} = {expr(rule['sample'])};", f"  {out(rule['valid'], nxt=True)} = 1'b1;", f"  {prefix}_active_next = 1'b1;", "end"]
    elif p == "PULSE_WIDTH":
        result += [f"if ({prefix}_remaining_next != 0) begin", f"  if ({expr(rule['start'])}) constraint_runtime_error_next = 1'b1;", "  else begin", f"    {prefix}_remaining_next = {prefix}_remaining_next - 1'b1;", f"    {out(rule['dst'], nxt=True)} = ({prefix}_remaining_next != 0);", "  end", f"end else if ({expr(rule['start'])} && {int(rule['cycles'])} != 0) begin", f"  {prefix}_remaining_next = {int(rule['cycles'])};", f"  {out(rule['dst'], nxt=True)} = 1'b1;", "end"]
    elif p == "HOLD_WHEN": result += [f"if (!{expr(rule['hold'])}) {out(rule['dst'], nxt=True)} = {expr(rule['sample'])};"]
    elif p == "UPDATE_ON": result += [f"if ({expr(rule['event'])}) {out(rule['dst'], nxt=True)} = {expr(rule['sample'])};"]
    elif p == "DEPENDENCY": result += [f"{out(rule['dst'], nxt=True)} = {expr(rule['predicate'])} ? {expr(rule['true_value'])} : {expr(rule['false_value'])};"]
    elif p == "BIT_MASK":
        width = int(rule["width"])
        result += [f"{out(rule['dst'], nxt=True)} = {expr(rule['sample'])} & {width}'h{int(rule['mask']):x};"]
    elif p == "WAIT_UNTIL":
        result += [f"{out(rule['success'], nxt=True)} = 1'b0;", f"{out(rule['expired'], nxt=True)} = 1'b0;", f"if (!{prefix}_active_next) begin", f"  if ({expr(rule['activate'])}) begin {prefix}_active_next = 1'b1; {prefix}_count_next = 0; end", f"end else if ({expr(rule['predicate'])}) begin", f"  {out(rule['success'], nxt=True)} = 1'b1; {prefix}_active_next = 1'b0; {prefix}_count_next = 0;", f"end else if ({prefix}_count_next == {int(rule['limit']) - 1}) begin", f"  {out(rule['expired'], nxt=True)} = 1'b1; {prefix}_active_next = 1'b0; {prefix}_count_next = 0;", f"end else {prefix}_count_next = {prefix}_count_next + 1'b1;"]
    elif p == "TIMEOUT":
        result += [f"{out(rule['fired'], nxt=True)} = 1'b0;", f"if ({expr(rule['clear'])} || !{expr(rule['active'])}) {prefix}_count_next = 0;", f"else if ({prefix}_count_next < {int(rule['limit'])}) begin", f"  {prefix}_count_next = {prefix}_count_next + 1'b1;", f"  if ({prefix}_count_next == {int(rule['limit'])}) {out(rule['fired'], nxt=True)} = 1'b1;", "end"]
    elif p == "CHOICE_WEIGHT":
        total = sum(int(item) for item in rule["integer_weights"]); upper = 0
        result.append("if (raw_bits_valid && raw_bits_ready) begin")
        for index, (choice, weight) in enumerate(zip(rule["choices"], rule["integer_weights"])):
            upper += int(weight); keyword = "if" if index == 0 else "else if"
            result.append(f"  {keyword} ((({expr(rule['raw_slice'])} * {total}) >> {int(rule['slice_width'])}) < {upper}) {out(rule['dst'], nxt=True)} = {int(choice)};")
        result.append("end")
    elif p == "FAULT_INJECT":
        result += [f"if ({prefix}_remaining_next != 0) begin", f"  {prefix}_remaining_next = {prefix}_remaining_next - 1'b1;", f"  {out(rule['dst'], nxt=True)} = ({prefix}_remaining_next != 0) ? {int(rule['value'])} : 0;", f"end else if ({expr(rule['enable'])}) begin", f"  {prefix}_remaining_next = {int(rule['cycles'])};", f"  {out(rule['dst'], nxt=True)} = {int(rule['value'])};", "end"]
    elif p == "SEQUENCE" and rule.get("macro") == "reset_sequence":
        result += _reset_macro_statements(rule, out, expr, prefix, encodings[str(rule["state"])])
    elif p == "SEQUENCE":
        state_out = out(rule["state"], nxt=True); encoding = encodings[str(rule["state"])]
        first = True
        for transition in sorted(rule["transitions"], key=lambda item: int(item["priority"])):
            keyword = "if" if first else "else if"; first = False
            result.append(f"{keyword} ({state_out} == {encoding[str(transition['from'])]} && {expr(transition['guard'])}) {state_out} = {encoding[str(transition['to'])]};")
    return result


def _reset_macro_statements(rule, out, expr, prefix, encoding):
    state = out(rule["state"], nxt=True); request = out(rule["request"], nxt=True)
    force = out(rule["force_isolate"], nxt=True); success = out(rule["success"], nxt=True); failed = out(rule["failed"], nxt=True)
    e = {name: encoding[name] for name in ("IDLE", "DRAIN", "ISOLATE", "RESET", "DONE", "FAILED")}
    return [
        f"{prefix}_count_next = {prefix}_count_next + 1'b1;", f"{success} = 1'b0;", f"{failed} = 1'b0;",
        f"{request} = ({state} == {e['DRAIN']} || {state} == {e['ISOLATE']} || {state} == {e['RESET']});",
        f"{force} = ({state} == {e['ISOLATE']} || ({state} == {e['RESET']} && {prefix}_isolated_next));",
        f"if ({state} == {e['IDLE']}) begin", f"  {prefix}_count_next = 0; {prefix}_isolated_next = 1'b0;", f"  if ({expr(rule['start'])}) {state} = {e['DRAIN']};", "end",
        f"else if ({state} == {e['DRAIN']}) begin", f"  if ({expr(rule['error'])}) {state} = {e['FAILED']};", f"  else if ({expr(rule['drained'])}) begin {state} = {e['RESET']}; {prefix}_count_next = 0; end", f"  else if ({prefix}_count_next >= {int(rule['drain_limit'])}) begin {state} = {e['ISOLATE']}; {prefix}_count_next = 0; {prefix}_isolated_next = 1'b1; end", "end",
        f"else if ({state} == {e['ISOLATE']}) begin", f"  if ({expr(rule['error'])}) {state} = {e['FAILED']};", f"  else if ({expr(rule['isolated'])}) begin {state} = {e['RESET']}; {prefix}_count_next = 0; end", f"  else if ({prefix}_count_next >= {int(rule['isolate_limit'])}) {state} = {e['FAILED']};", "end",
        f"else if ({state} == {e['RESET']}) begin", f"  if ({expr(rule['error'])}) {state} = {e['FAILED']};", f"  else if ({prefix}_count_next >= {int(rule['assert_cycles'])} && {expr(rule['reset_done'])}) {state} = {e['DONE']};", f"  else if ({prefix}_count_next >= {int(rule['complete_limit'])}) {state} = {e['FAILED']};", "end",
        f"else if ({state} == {e['DONE']}) begin {success} = 1'b1; {state} = {e['IDLE']}; end",
        f"else if ({state} == {e['FAILED']}) begin {failed} = 1'b1; {state} = {e['IDLE']}; end",
    ]
