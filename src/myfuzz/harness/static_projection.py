"""Purely combinational evaluation and SystemVerilog emission for static policies."""

from __future__ import annotations

from collections.abc import Mapping

from .abi import RawBitAbi, content_hash, control_declarations, manifest_ports
from .direct import HarnessArtifact, _constant, _identifier, _logic, candidate_id, coverage_id, top_content_hash
from .static_policy import StaticAction, StaticPolicyPlan


def _escaped_sv_identifier(value: object, fallback: str) -> str:
    return f"\\{_identifier(value, fallback)} "


def _parameter(action: StaticAction, name: str) -> int | str | tuple[int, ...]:
    return dict(action.parameters)[name]


def _tuple_parameter(action: StaticAction, name: str) -> tuple[int, ...]:
    value = _parameter(action, name)
    assert isinstance(value, tuple)
    return value


def _raw_bit(raw_value: int, bit: int | str | tuple[int, ...]) -> int:
    assert isinstance(bit, int)
    return (raw_value >> bit) & 1


def _fold(raw_value: int, action: StaticAction) -> int:
    parameter = "fold_bits" if action.kind == "rarity_fold" else "selector_bits"
    bits = _tuple_parameter(action, parameter)
    value = 0
    for index, bit in enumerate(bits):
        value |= _raw_bit(raw_value, bit) << index
    divisor_name = "rarity" if action.kind == "rarity_fold" else "direct_ratio"
    divisor = _parameter(action, divisor_name)
    assert isinstance(divisor, int)
    return value % divisor


def _apply_selection_or_entropy(
    action: StaticAction,
    projected_value: int,
    direct_value: int,
    raw_value: int,
    peer_values: Mapping[int, int],
) -> int:
    if action.kind == "mutual_exclusion":
        mode = _parameter(action, "mode")
        assert isinstance(mode, str)
        if mode == "none":
            return projected_value
        if mode == "one_hot":
            return projected_value if not any(peer_values.values()) else 0
        lower_priority_active = any(
            value
            for destination_id, value in peer_values.items()
            if destination_id < action.destination_id
        )
        return projected_value if not lower_priority_active else 0
    assert action.kind == "entropy_mix"
    return direct_value if _fold(raw_value, action) == 0 else projected_value


def _apply(
    action: StaticAction,
    projected_value: int,
    direct_value: int,
    raw_value: int,
    peer_values: Mapping[int, int],
) -> int:
    if action.kind == "mask_align":
        mask = _parameter(action, "mask")
        assert isinstance(mask, int)
        return projected_value & mask
    if action.kind == "legal_set":
        values = _tuple_parameter(action, "values")
        strength = _parameter(action, "strength")
        assert isinstance(strength, int)
        return values[(projected_value // strength) % len(values)]
    if action.kind == "dependency_gate":
        return projected_value if _raw_bit(raw_value, _parameter(action, "gate_bit")) else 0
    if action.kind == "rarity_fold":
        return int(_fold(raw_value, action) == 0)
    return _apply_selection_or_entropy(
        action,
        projected_value,
        direct_value,
        raw_value,
        peer_values,
    )


def _raw_values(abi: RawBitAbi, raw_value: int) -> dict[int, int]:
    values = {destination.destination_id: 0 for destination in abi.destinations}
    for use in abi.uses:
        width = use.raw_hi - use.raw_lo + 1
        values[use.destination_id] |= (
            (raw_value >> use.raw_lo) & ((1 << width) - 1)
        ) << use.destination_lo
    return values


def project_static_sample(plan: StaticPolicyPlan, raw_value: int) -> dict[int, int]:
    """Project one bounded raw sample without retaining temporal state."""
    if not isinstance(plan, StaticPolicyPlan):
        raise TypeError("plan must be StaticPolicyPlan")
    if isinstance(raw_value, bool) or not isinstance(raw_value, int) or not 0 <= raw_value < 1 << plan.raw_abi.raw_width:
        raise ValueError("raw_value must fit the static policy raw width")
    direct_values = _raw_values(plan.raw_abi, raw_value)
    values = dict(direct_values)
    widths = {destination.destination_id: destination.width for destination in plan.raw_abi.destinations}
    for action in plan.actions:
        destination_id = action.destination_id
        peer_values = {
            peer_id: values[peer_id]
            for peer_id in _tuple_parameter(action, "peer_ids")
        } if action.kind == "mutual_exclusion" else {}
        values[destination_id] = _apply(
            action,
            values[destination_id],
            direct_values[destination_id],
            raw_value,
            peer_values,
        ) & (
            (1 << widths[destination_id]) - 1
        )
    return values


def _raw_expression(abi: RawBitAbi, destination_id: int, width: int) -> str:
    pieces: list[str] = []
    for use in abi.uses:
        if use.destination_id != destination_id:
            continue
        source_width = use.raw_hi - use.raw_lo + 1
        high_padding = width - source_width - use.destination_lo
        terms = []
        if high_padding:
            terms.append("{%d{1'b0}}" % high_padding)
        terms.append(f"rfuzz_input_bits[{use.raw_hi}:{use.raw_lo}]")
        if use.destination_lo:
            terms.append("{%d{1'b0}}" % use.destination_lo)
        pieces.append(terms[0] if len(terms) == 1 else "{" + ", ".join(terms) + "}")
    assert pieces
    return pieces[0] if len(pieces) == 1 else " | ".join(pieces)


def _zero_extended(source: str, source_width: int, target_width: int) -> str:
    assert 0 < source_width <= target_width
    padding = target_width - source_width
    if not padding:
        return source
    return f"{{{{{padding}{{1'b0}}}}, ({source})}}"


def _folded_expression(bits: tuple[int, ...], divisor: int) -> str:
    source = "{" + ", ".join(f"rfuzz_input_bits[{bit}]" for bit in reversed(bits)) + "}"
    width = max(len(bits), divisor.bit_length())
    extended = _zero_extended(source, len(bits), width)
    return f"(({extended}) % {_constant(width, divisor)})"


def _selection_expression(
    action: StaticAction,
    source: str,
    direct: str,
    width: int,
    peer_sources: Mapping[int, str],
) -> str:
    if action.kind == "mutual_exclusion":
        mode = _parameter(action, "mode")
        assert isinstance(mode, str)
        if mode == "none":
            return source
        if mode == "one_hot":
            competing = tuple(peer_sources.values())
        else:
            competing = tuple(
                peer_source
                for destination_id, peer_source in peer_sources.items()
                if destination_id < action.destination_id
            )
        if not competing:
            return source
        active = " || ".join(f"(({peer}) != 0)" for peer in competing)
        return f"(({active}) ? {_constant(width, 0)} : ({source}))"
    bits = _tuple_parameter(action, "selector_bits")
    direct_ratio = _parameter(action, "direct_ratio")
    assert isinstance(direct_ratio, int)
    folded = _folded_expression(bits, direct_ratio)
    folded_width = max(len(bits), direct_ratio.bit_length())
    return f"(({folded}) == {_constant(folded_width, 0)} ? ({direct}) : ({source}))"


def _action_expression(
    action: StaticAction,
    source: str,
    direct: str,
    width: int,
    peer_sources: Mapping[int, str],
) -> str:
    if action.kind == "mask_align":
        mask = _parameter(action, "mask")
        assert isinstance(mask, int)
        return f"(({source}) & {_constant(width, mask)})"
    if action.kind == "legal_set":
        values = _tuple_parameter(action, "values")
        strength = _parameter(action, "strength")
        assert isinstance(strength, int)
        arithmetic_width = max(width, strength.bit_length(), len(values).bit_length())
        extended = _zero_extended(source, width, arithmetic_width)
        index_expression = (
            f"((({extended}) / {_constant(arithmetic_width, strength)}) "
            f"% {_constant(arithmetic_width, len(values))})"
        )
        choices = [
            _constant(width, value)
            for value in values
        ]
        expression = choices[-1]
        for index in range(len(choices) - 2, -1, -1):
            expression = (
                f"((({index_expression}) == {_constant(arithmetic_width, index)}) "
                f"? {choices[index]} : ({expression}))"
            )
        return expression
    if action.kind == "dependency_gate":
        bit = _parameter(action, "gate_bit")
        assert isinstance(bit, int)
        return f"(rfuzz_input_bits[{bit}] ? ({source}) : {_constant(width, 0)})"
    if action.kind == "rarity_fold":
        bits = _tuple_parameter(action, "fold_bits")
        rarity = _parameter(action, "rarity")
        assert isinstance(rarity, int)
        folded = _folded_expression(bits, rarity)
        folded_width = max(len(bits), rarity.bit_length())
        return f"(({folded}) == {_constant(folded_width, 0)})"
    return _selection_expression(action, source, direct, width, peer_sources)


def emit_static_projection(manifest: object, plan: StaticPolicyPlan) -> str:
    """Emit a candidate-static harness with only continuous assignments."""
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    if not isinstance(plan, StaticPolicyPlan):
        raise TypeError("plan must be StaticPolicyPlan")
    top = manifest.get("top")
    if not isinstance(top, Mapping) or not isinstance(top.get("module"), str) or not top["module"]:
        raise ValueError("manifest.top.module is required for generated port mapping")
    controls = control_declarations(manifest)
    clock = controls.get("clock")
    reset = controls.get("reset")
    has_io_meta_reset = bool(reset and reset.get("io_meta_reset") is True)
    header_ports: list[str] = []
    if clock is not None:
        header_ports.append("    input logic clock")
    if reset is not None:
        header_ports.append("    input logic reset")
        if has_io_meta_reset:
            header_ports.append("    input logic io_meta_reset")
    header_ports.append(f"    input logic [{plan.raw_abi.raw_width - 1}:0] rfuzz_input_bits")
    lines = [
        f"module myfuzz_candidate_static_{plan.plan_hash[:12]} (",
        *[f"{port}," if index + 1 < len(header_ports) else port for index, port in enumerate(header_ports)],
        ");",
        f"    // purely combinational static projection of {top['module']}",
    ]
    destinations = {destination.port_id: destination for destination in plan.raw_abi.destinations}
    destination_by_id = {
        destination.destination_id: destination
        for destination in plan.raw_abi.destinations
    }
    direct_expressions = {
        destination_id: _raw_expression(plan.raw_abi, destination_id, destination.width)
        for destination_id, destination in destination_by_id.items()
    }
    expressions = dict(direct_expressions)
    action_comments = {destination_id: [] for destination_id in destination_by_id}
    for action in plan.actions:
        destination_id = action.destination_id
        peer_sources = {
            peer_id: expressions[peer_id]
            for peer_id in _tuple_parameter(action, "peer_ids")
        } if action.kind == "mutual_exclusion" else {}
        expressions[destination_id] = _action_expression(
            action,
            expressions[destination_id],
            direct_expressions[destination_id],
            destination_by_id[destination_id].width,
            peer_sources,
        )
        action_comments[destination_id].append(action)
    ports = manifest_ports(manifest)
    for port in ports:
        port_id, width = port["port_id"], port["width"]
        signal = f"port_{port_id}"
        lines.append(_logic(width, signal))
        role = port.get("semantic_role")
        if role == "clock":
            active_level = controls["clock"]["active_level"]
            lines.append(f"    assign {signal} = {{{width}{{{'clock' if active_level == 1 else '~clock'}}}}};")
        elif role == "reset":
            active_level = controls["reset"]["active_level"]
            reset_expression = "reset | io_meta_reset" if has_io_meta_reset else "reset"
            expression = reset_expression if active_level == 1 else f"~({reset_expression})"
            lines.append(f"    assign {signal} = {expression};")
        elif port_id in destinations:
            destination = destinations[port_id]
            for action in action_comments[destination.destination_id]:
                if action.kind == "entropy_mix":
                    lines.append(f"    // direct sample branch for port {port_id}")
                else:
                    lines.append(f"    // action {action.action_id} {action.kind} for port {port_id}")
            lines.append(f"    assign {signal} = {expressions[destination.destination_id]};")
        elif port["direction"] in {"input", "inout"}:
            value = port.get("constant_value", port.get("reset_value"))
            assert isinstance(value, int)
            lines.append(f"    assign {signal} = {_constant(width, value)};")
    lines.append(f"    {_escaped_sv_identifier(top['module'], 'generated_top')} dut (")
    for index, port in enumerate(ports):
        comma = "," if index + 1 < len(ports) else ""
        pin = _escaped_sv_identifier(
            port.get("emitted_name"),
            f"port_{port['port_id']}",
        )
        lines.append(f"        .{pin}(port_{port['port_id']}){comma}")
    lines.extend(("    );", "endmodule"))
    return "\n".join(lines) + "\n"


def build_static_harness(manifest: object, plan: StaticPolicyPlan) -> HarnessArtifact:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    source = emit_static_projection(manifest, plan)
    return HarnessArtifact(
        mode="candidate_static",
        raw_width=plan.raw_abi.raw_width,
        coverage_universe_id=coverage_id(manifest),
        candidate_id=candidate_id(manifest),
        abi=plan.raw_abi,
        source_text=source,
        content_hash=content_hash({"source_text": source}),
        top_content_hash=top_content_hash(manifest),
        policy_plan_hash=plan.plan_hash,
    )


__all__ = ["build_static_harness", "emit_static_projection", "project_static_sample"]
