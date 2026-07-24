"""Dependency-aware protocol projection retaining the direct raw-bit ABI."""

from __future__ import annotations

from collections.abc import Mapping

from .abi import (
    RawBitAbi,
    build_raw_abi,
    content_hash,
    control_declarations,
    dependency_group_for_port,
    dependency_groups,
    manifest_ports,
    selected_ports,
)
from .direct import (
    HarnessArtifact,
    _constant,
    _logic,
    _sv_identifier,
    candidate_id,
    coverage_id,
    top_content_hash,
)
from .projection import ProjectionAction, ProjectionPlan, build_projection_plan


_BASE_COUNTERS = (
    "projection_rate",
    "protocol_event_count",
    "timeout_count",
    "violation_count",
    "no_progress_count",
)


def _retained(manifest: Mapping[str, object]):
    declared = frozenset(dependency_groups(manifest))
    values = manifest.get("retained_dependency_groups", manifest.get("retained_groups"))
    if values is None:
        return declared
    if not isinstance(values, (list, tuple)):
        raise ValueError("retained dependency groups must be an array")
    from .abi import _group

    retained = frozenset(_group(item) for item in values)
    if not retained <= declared:
        raise ValueError("retained dependency groups must belong to the static group set")
    return retained


def _legacy_plan(manifest: Mapping[str, object], direct_abi: RawBitAbi) -> ProjectionPlan:
    retained = _retained(manifest)
    records: list[dict[str, object]] = []
    for use, port in zip(direct_abi.uses, selected_ports(manifest)):
        group = dependency_group_for_port(port)
        if group is not None and group not in retained:
            records.append(
                {
                    "action_id": len(records),
                    "destination_id": use.destination_id,
                    "kind": "gate",
                    "category": "dependency_consistency",
                    "max_cycles": 1,
                }
            )
    return build_projection_plan(direct_abi, records)


def _same_geometry(left: RawBitAbi, right: RawBitAbi) -> bool:
    return left.destinations == right.destinations and tuple(
        (item.raw_lo, item.raw_hi, item.destination_id, item.destination_lo)
        for item in left.uses
    ) == tuple(
        (item.raw_lo, item.raw_hi, item.destination_id, item.destination_lo)
        for item in right.uses
    )


def _raw_slice(action: ProjectionAction, abi: RawBitAbi) -> str:
    use = next(item for item in abi.uses if item.destination_id == action.destination_id)
    return f"rfuzz_input_bits[{use.raw_hi}:{use.raw_lo}]"


def _projected_expression(
    action: ProjectionAction,
    abi: RawBitAbi,
    source: str | None = None,
) -> str:
    raw = _raw_slice(action, abi) if source is None else source
    if action.kind == "fold_xor" and action.value_width > 1:
        shift = (action.value_width + 1) // 2
        return f"({raw} ^ ({raw} >> {shift}))"
    if action.kind in {"gate", "delay_select"}:
        counter_lo = action.state_lo + action.value_width
        active_lo = counter_lo + action.counter_width
        held = f"projection_state[{action.state_lo} +: {action.value_width}]"
        if action.kind == "gate":
            return f"(projection_state[{active_lo}] ? {held} : ({raw}))"
        counter = f"projection_state[{counter_lo} +: {action.counter_width}]"
        return (
            f"((projection_state[{active_lo}] && ({counter} <= 1)) "
            f"? {held} : {_constant(action.value_width, 0)})"
        )
    return raw


def _action_expressions(
    plan: ProjectionPlan,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    inputs: dict[int, str] = {}
    outputs: dict[int, str] = {}
    final = {
        destination.destination_id: _raw_slice(
            next(
                action
                for action in plan.actions
                if action.destination_id == destination.destination_id
            ),
            plan.raw_abi,
        )
        for destination in plan.raw_abi.destinations
        if any(
            action.destination_id == destination.destination_id
            for action in plan.actions
        )
    }
    for action in plan.actions:
        source = final.get(action.destination_id, _raw_slice(action, plan.raw_abi))
        projected = _projected_expression(action, plan.raw_abi, source)
        inputs[action.action_id] = source
        outputs[action.action_id] = projected
        final[action.destination_id] = projected
    return inputs, outputs, final


def _condition_sum(conditions: list[tuple[str, int]]) -> str:
    if not conditions:
        return "64'd0"
    return " + ".join(
        f"(({condition}) ? 64'd{increment} : 64'd0)"
        for condition, increment in conditions
    )


def _emit_depaware(manifest: Mapping[str, object], plan: ProjectionPlan) -> str:
    top = manifest.get("top")
    if not isinstance(top, Mapping) or not isinstance(top.get("module"), str) or not top["module"]:
        raise ValueError("manifest.top.module is required for generated port mapping")
    controls = control_declarations(manifest)
    clock = controls.get("clock")
    reset = controls.get("reset")
    temporal = tuple(action for action in plan.actions if action.kind in {"gate", "delay_select"})
    if temporal and (clock is None or reset is None):
        raise ValueError("temporal protocol projection requires explicit clock and reset controls")

    has_io_meta_reset = bool(reset and reset.get("io_meta_reset") is True)
    header_ports: list[str] = []
    if clock is not None:
        header_ports.append("    input logic clock")
    if reset is not None:
        header_ports.append("    input logic reset")
        if has_io_meta_reset:
            header_ports.append("    input logic io_meta_reset")
    header_ports.append(f"    input logic [{plan.raw_abi.raw_width - 1}:0] rfuzz_input_bits")
    module_name = f"myfuzz_candidate_depaware_{plan.plan_hash.split(':')[-1][:12]}"
    lines = [
        f"module {module_name} (",
        *[
            f"{port}," if index + 1 < len(header_ports) else port
            for index, port in enumerate(header_ports)
        ],
        ");",
        f"    // protocol_projection of {top['module']} with bounded dependency-aware actions",
        f"    logic [{plan.max_state_bits - 1}:0] projection_state;",
    ]
    categories = tuple(sorted({action.category for action in plan.actions}))
    counters = _BASE_COUNTERS + tuple(f"correction_{category}" for category in categories)
    lines.extend(f"    logic [63:0] {counter};" for counter in counters)

    destinations = {item.port_id: item for item in plan.raw_abi.destinations}
    uses = {item.destination_id: item for item in plan.raw_abi.uses}
    actions_by_destination: dict[int, list[ProjectionAction]] = {}
    for action in plan.actions:
        actions_by_destination.setdefault(action.destination_id, []).append(action)
    action_inputs, action_outputs, final_expressions = _action_expressions(plan)
    ports = manifest_ports(manifest)
    for port in ports:
        port_id, width = port["port_id"], port["width"]
        signal = f"port_{port_id}"
        lines.append(_logic(width, signal))
        role = port.get("semantic_role")
        if role == "clock":
            active_level = controls["clock"]["active_level"]
            expression = "clock" if active_level == 1 else "~clock"
            lines.append(f"    assign {signal} = {{{width}{{{expression}}}}};")
        elif role == "reset":
            active_level = controls["reset"]["active_level"]
            reset_expression = "reset | io_meta_reset" if has_io_meta_reset else "reset"
            expression = reset_expression if active_level == 1 else f"~({reset_expression})"
            lines.append(f"    assign {signal} = {expression};")
        elif port_id in destinations:
            destination = destinations[port_id]
            use = uses[destination.destination_id]
            actions = actions_by_destination.get(destination.destination_id, ())
            expression = final_expressions.get(
                destination.destination_id,
                f"rfuzz_input_bits[{use.raw_hi}:{use.raw_lo}]",
            )
            if actions:
                for action in actions:
                    lines.append(
                        f"    // action {action.action_id} {action.kind} "
                        f"({action.category}) for port {port_id}"
                    )
            else:
                lines.append(f"    // direct projection for port {port_id}")
            lines.append(f"    assign {signal} = {expression};")
        elif port["direction"] in {"input", "inout"}:
            value = port.get("constant_value", port.get("reset_value"))
            assert isinstance(value, int)
            lines.append(f"    assign {signal} = {_constant(width, value)};")

    if clock is not None:
        reset_expression = "reset | io_meta_reset" if has_io_meta_reset else "reset"
        correction_conditions = {category: [] for category in categories}
        protocol_events: list[tuple[str, int]] = []
        timeouts: list[tuple[str, int]] = []
        violations: list[tuple[str, int]] = []
        no_progress: list[tuple[str, int]] = []
        for action in plan.actions:
            source = action_inputs[action.action_id]
            projected = action_outputs[action.action_id]
            changed = f"({projected}) != ({source})"
            if action.kind != "direct":
                correction_conditions[action.category].append((changed, 1))
            if action.kind == "fold_xor":
                protocol_events.append((changed, 1))
                continue
            if action.kind not in {"gate", "delay_select"}:
                continue
            counter_lo = action.state_lo + action.value_width
            active_lo = counter_lo + action.counter_width
            active = f"projection_state[{active_lo}]"
            remaining = f"projection_state[{counter_lo} +: {action.counter_width}]"
            expires = f"{active} && ({remaining} <= 1)"
            starts = f"!{active} && (({source}) != '0)"
            if action.kind == "gate":
                protocol_events.extend(((active, 1), (expires, 1), (starts, 1)))
                timeouts.append((expires, 1))
                violations.append((expires, 1))
                no_progress.append((expires, 1))
            else:
                protocol_events.extend(((active, 1), (starts, 1)))
                no_progress.extend(((active, 1), (starts, 1)))

        lines.extend(
            [
                "    always_ff @(posedge clock) begin",
                f"        if ({reset_expression}) begin",
                "            projection_state <= '0;",
                *[f"            {counter} <= '0;" for counter in counters],
                "        end else begin",
                "            projection_rate <= projection_rate + 1'b1;",
                f"            protocol_event_count <= protocol_event_count + {_condition_sum(protocol_events)};",
                f"            timeout_count <= timeout_count + {_condition_sum(timeouts)};",
                f"            violation_count <= violation_count + {_condition_sum(violations)};",
                f"            no_progress_count <= no_progress_count + {_condition_sum(no_progress)};",
                *[
                    f"            correction_{category} <= correction_{category} + "
                    f"{_condition_sum(correction_conditions[category])};"
                    for category in categories
                ],
            ]
        )
        for action in plan.actions:
            if action.kind not in {"gate", "delay_select"}:
                continue
            assert action.max_cycles is not None
            source = action_inputs[action.action_id]
            counter_lo = action.state_lo + action.value_width
            active_lo = counter_lo + action.counter_width
            counter_slice = f"projection_state[{counter_lo} +: {action.counter_width}]"
            lines.extend(
                [
                    f"            // action {action.action_id} {action.kind} state",
                    f"            if (projection_state[{active_lo}]) begin",
                    f"                if ({counter_slice} <= 1) begin",
                    f"                    projection_state[{action.state_lo} +: {action.value_width}] <= '0;",
                    f"                    projection_state[{active_lo}] <= 1'b0;",
                    f"                    {counter_slice} <= '0;",
                    "                end else begin",
                    f"                    {counter_slice} <= {counter_slice} - 1'b1;",
                    "                end",
                    f"            end else if (({source}) != '0) begin",
                    f"                projection_state[{action.state_lo} +: {action.value_width}] <= {source};",
                    f"                {counter_slice} <= {action.counter_width}'d{action.max_cycles};",
                    f"                projection_state[{active_lo}] <= 1'b1;",
                    "            end",
                ]
            )
        lines.extend(["        end", "    end"])
    else:
        lines.append("    assign projection_state = '0;")
        lines.extend(f"    assign {counter} = '0;" for counter in counters)

    lines.append(f"    {_sv_identifier(top['module'], 'generated_top')} dut (")
    for index, port in enumerate(ports):
        comma = "," if index + 1 < len(ports) else ""
        pin = _sv_identifier(port.get("emitted_name"), f"port_{port['port_id']}")
        lines.append(f"        .{pin}(port_{port['port_id']}){comma}")
    lines.extend(["    );", "endmodule"])
    return "\n".join(lines) + "\n"


def build_depaware(
    manifest: object,
    projection_plan: ProjectionPlan | None = None,
) -> HarnessArtifact:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    direct_abi = build_raw_abi(manifest)
    plan = projection_plan or _legacy_plan(manifest, direct_abi)
    if not _same_geometry(direct_abi, plan.raw_abi):
        raise ValueError("dependency-aware projection changed raw ABI geometry")
    source = _emit_depaware(manifest, plan)
    categories = tuple(sorted({action.category for action in plan.actions}))
    counters = _BASE_COUNTERS + tuple(f"correction_{category}" for category in categories)
    return HarnessArtifact(
        mode="candidate_depaware",
        raw_width=plan.raw_abi.raw_width,
        coverage_universe_id=coverage_id(manifest),
        candidate_id=candidate_id(manifest),
        abi=plan.raw_abi,
        source_text=source,
        content_hash=content_hash({"source_text": source}),
        top_content_hash=top_content_hash(manifest),
        counters=counters,
        projection_plan=plan,
    )
