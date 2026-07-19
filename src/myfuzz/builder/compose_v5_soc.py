"""Compose-v5 generated SoC and rawbits harness emission."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .compose_v5_connection import ComposeV5ConnectionPlan
from .input_model import InputValidationError, PortDirection
from .rawbits_v5 import RawBitsV5Layout
from .rtl_analysis import EvidenceState, RTLModule, RTLPort


_SV_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SAFE_PARAMETER_LITERAL = re.compile(
    r"-?(?:"
    r"\d[\d_]*"
    r"|"
    r"(?:\d[\d_]*)?'[sS]?[bBoOdDhH][0-9a-fA-F_xXzZ?]+"
    r"|"
    r"'[01xXzZ]"
    r")\Z"
)


@dataclass(frozen=True)
class EmittedComposeV5GeneratedSoc:
    module_name: str
    rtl: str
    external_inputs: tuple[Mapping[str, object], ...]
    observations: tuple[Mapping[str, object], ...]
    internal_assignments: tuple[Mapping[str, object], ...]
    instances: tuple[str, ...]
    observe_width: int
    connection_plan_digest: str


@dataclass(frozen=True)
class EmittedComposeV5GeneratedSocHarness:
    module_name: str
    soc_module_name: str
    rtl: str
    layout_digest: str
    rawbits_width: int
    observe_width: int
    input_bindings: tuple[Mapping[str, object], ...]
    unused_layout_owners: tuple[str, ...]


@dataclass(frozen=True)
class EmittedComposeV5GeneratedSocBundle:
    soc: EmittedComposeV5GeneratedSoc
    layout: RawBitsV5Layout
    harness: EmittedComposeV5GeneratedSocHarness
    rtl: str


def emit_compose_v5_generated_soc_top(
    component_modules: Mapping[str, RTLModule],
    connection_plan: ComposeV5ConnectionPlan,
    *,
    module_name: str = "compose_v5_generated_soc_top",
) -> EmittedComposeV5GeneratedSoc:
    """Emit the compose-v5 generated-SoC topology from role-backed interfaces.

    This emitter intentionally consumes the connection plan only.  It does not
    infer by module name, port name, or protocol alias.  In this first generated
    SoC slice, a CPU initiator request is structurally broadcast to all planned
    targets when no address signal role exists in the discovered contract.
    """

    _identifier(module_name, "compose-v5 generated SoC module name")
    if not isinstance(component_modules, Mapping) or not component_modules:
        raise InputValidationError("compose-v5 generated SoC requires component modules")
    if not isinstance(connection_plan, ComposeV5ConnectionPlan):
        raise InputValidationError("compose-v5 generated SoC requires a connection plan")
    if connection_plan.incomplete_reasons:
        raise InputValidationError(
            "compose-v5 generated SoC refuses incomplete connection plan: "
            + "; ".join(connection_plan.incomplete_reasons)
        )

    modules = tuple(
        _module(component_id, module)
        for component_id, module in sorted(component_modules.items())
    )
    module_ids = {item["instance"] for item in modules}
    plan_ids = {str(item["id"]) for item in connection_plan.components}
    if module_ids != plan_ids:
        raise InputValidationError("compose-v5 generated SoC component set does not match plan")

    signal_drivers: dict[str, str] = {}
    internal_assignments: list[dict[str, object]] = []
    ready_terms_by_source: dict[str, list[str]] = {}
    for edge in sorted(connection_plan.edges, key=lambda item: str(item["id"])):
        if edge.get("status") != "planned":
            raise InputValidationError(f"compose-v5 generated SoC edge {edge.get('id')!r} is not planned")
        source_interface = _interface(connection_plan, str(edge.get("source_interface")))
        target_interface = _interface(connection_plan, str(edge.get("target_interface")))
        edge_assignments, ready_owner, ready_expr = _edge_assignments(edge, source_interface, target_interface)
        for owner, expression, reason in edge_assignments:
            if owner in signal_drivers and signal_drivers[owner] != expression:
                raise InputValidationError(f"compose-v5 generated SoC multiple drivers for {owner}")
            signal_drivers[owner] = expression
            internal_assignments.append({
                "owner": owner,
                "expression": expression,
                "edge": edge["id"],
                "reason": reason,
            })
        ready_terms_by_source.setdefault(ready_owner, []).append(ready_expr)

    for owner, terms in sorted(ready_terms_by_source.items()):
        expression = _or_expr(tuple(sorted(set(terms))))
        if owner in signal_drivers and signal_drivers[owner] != expression:
            raise InputValidationError(f"compose-v5 generated SoC multiple drivers for {owner}")
        signal_drivers[owner] = expression
        internal_assignments.append({
            "owner": owner,
            "expression": expression,
            "edge": "broadcast_ready_merge",
            "reason": "merge target ready outputs for CPU-only-master broadcast handshake",
        })

    external_inputs: list[dict[str, object]] = []
    observations: list[dict[str, object]] = []
    observe_offset = 0
    instance_lines: list[str] = []
    signal_lines: list[str] = []
    assign_lines: list[str] = []

    for module in modules:
        for port in module["ports"]:
            owner = f"{module['instance']}.{port['name']}"
            signal = _wire_name(owner)
            direction = port["direction"]
            width = int(port["width"])
            if direction is PortDirection.INPUT and owner not in signal_drivers:
                external_inputs.append({
                    "owner": owner,
                    "top_port": signal,
                    "component": module["instance"],
                    "child_port": port["name"],
                    "width": width,
                    "reason": "not internally driven by generated connection graph",
                })
            else:
                signal_lines.append(f"  logic {_range(width)}{signal};")
            if direction is PortDirection.OUTPUT:
                observations.append({
                    "owner": owner,
                    "signal": signal,
                    "component": module["instance"],
                    "child_port": port["name"],
                    "offset": observe_offset,
                    "width": width,
                })
                observe_offset += width

    for owner, expression in sorted(signal_drivers.items()):
        assign_lines.append(f"  assign {_wire_name(owner)} = {expression};")
    observe_width = max(1, observe_offset)
    if observations:
        for observation in observations:
            assign_lines.append(
                f"  assign observe_o[{int(observation['offset'])} +: {int(observation['width'])}] = "
                f"{observation['signal']};"
            )
    else:
        assign_lines.append("  assign observe_o = 1'b0;")

    for module in modules:
        if module["parameters"]:
            instance_lines.extend((
                f"  {module['module_type']} #(",
                ",\n".join(f"    .{name}({value})" for name, value in module["parameters"]),
                f"  ) {module['instance']} (",
            ))
        else:
            instance_lines.append(f"  {module['module_type']} {module['instance']} (")
        instance_lines.append(",\n".join(
            f"    .{port['name']}({_wire_name(f'{module['instance']}.{port['name']}')})"
            for port in module["ports"]
        ))
        instance_lines.append("  );")

    port_lines = [
        f"  input logic {_range(int(item['width']))}{item['top_port']}"
        for item in external_inputs
    ]
    port_lines.append(f"  output logic [{observe_width - 1}:0] observe_o")
    lines = [
        f"module {module_name} (",
        ",\n".join(port_lines),
        ");",
        "  // compose-v5 generated SoC v1.",
        "  // Connections come from behavior-backed interface roles, not module/port-name tables.",
        "  // No address signal role is available in v1 discovery, so planned target requests are broadcast.",
        f"  localparam logic [255:0] CONNECTION_PLAN_DIGEST = 256'h{connection_plan.digest};",
        *signal_lines,
        *assign_lines,
        *instance_lines,
        "endmodule",
    ]
    return EmittedComposeV5GeneratedSoc(
        module_name=module_name,
        rtl="\n".join(lines) + "\n",
        external_inputs=tuple(external_inputs),
        observations=tuple(observations),
        internal_assignments=tuple(internal_assignments),
        instances=tuple(str(item["instance"]) for item in modules),
        observe_width=observe_width,
        connection_plan_digest=connection_plan.digest,
    )


def emit_compose_v5_generated_soc_rawbits_harness(
    soc: EmittedComposeV5GeneratedSoc,
    layout: RawBitsV5Layout,
    *,
    module_name: str = "compose_v5_generated_soc_harness",
) -> EmittedComposeV5GeneratedSocHarness:
    """Bind v5 rawbits to the generated SoC's remaining external inputs."""

    _identifier(module_name, "compose-v5 generated SoC harness module name")
    if not isinstance(soc, EmittedComposeV5GeneratedSoc):
        raise InputValidationError("compose-v5 generated SoC harness requires an emitted SoC")
    if not isinstance(layout, RawBitsV5Layout):
        raise InputValidationError("compose-v5 generated SoC harness requires a RawBitsV5Layout")

    layout_by_owner = {field.owner: field for field in layout.fields}
    input_bindings: list[dict[str, object]] = []
    used_layout_owners: set[str] = set()
    for external in soc.external_inputs:
        owner = str(external["owner"])
        try:
            field = layout_by_owner[owner]
        except KeyError as exc:
            raise InputValidationError(
                f"compose-v5 generated SoC harness missing rawbits field for {owner}"
            ) from exc
        if field.width != int(external["width"]):
            raise InputValidationError(f"compose-v5 generated SoC harness width mismatch for {owner}")
        used_layout_owners.add(owner)
        input_bindings.append({
            "owner": owner,
            "top_port": external["top_port"],
            "kind": field.kind,
            "offset": field.offset,
            "width": field.width,
        })

    unused = tuple(sorted(set(layout_by_owner) - used_layout_owners))
    signal_lines = [
        f"  logic {_range(int(item['width']))}{item['top_port']};"
        for item in soc.external_inputs
    ]
    assign_lines = [
        f"  localparam logic [255:0] EXPECTED_LAYOUT_DIGEST = 256'h{layout.digest};",
        f"  localparam logic [255:0] EXPECTED_SOC_PLAN_DIGEST = 256'h{soc.connection_plan_digest};",
    ]
    for binding in input_bindings:
        assign_lines.append(
            f"  assign {binding['top_port']} = rawbits_i[{int(binding['offset'])} +: {int(binding['width'])}];"
        )
    instance_lines = [
        f"    .{item['top_port']}({item['top_port']})"
        for item in soc.external_inputs
    ]
    instance_lines.append("    .observe_o(observe_o)")
    lines = [
        f"module {module_name} (",
        f"  input logic [{layout.record_width_bits - 1}:0] rawbits_i,",
        f"  output logic [{soc.observe_width - 1}:0] observe_o",
        ");",
        f"  localparam int RAWBITS_WIDTH = {layout.record_width_bits};",
        f"  localparam int OBSERVE_WIDTH = {soc.observe_width};",
        "  // Unused rawbits fields correspond to ports now driven by generated SoC connections.",
        *signal_lines,
        *assign_lines,
        f"  {soc.module_name} i_soc (",
        ",\n".join(instance_lines),
        "  );",
        "endmodule",
    ]
    return EmittedComposeV5GeneratedSocHarness(
        module_name=module_name,
        soc_module_name=soc.module_name,
        rtl="\n".join(lines) + "\n",
        layout_digest=layout.digest,
        rawbits_width=layout.record_width_bits,
        observe_width=soc.observe_width,
        input_bindings=tuple(input_bindings),
        unused_layout_owners=unused,
    )


def emit_compose_v5_generated_soc_harness_bundle(
    component_modules: Mapping[str, RTLModule],
    connection_plan: ComposeV5ConnectionPlan,
    layout: RawBitsV5Layout,
    *,
    soc_module_name: str = "compose_v5_generated_soc_top",
    harness_module_name: str = "compose_v5_generated_soc_harness",
) -> EmittedComposeV5GeneratedSocBundle:
    soc = emit_compose_v5_generated_soc_top(
        component_modules,
        connection_plan,
        module_name=soc_module_name,
    )
    harness = emit_compose_v5_generated_soc_rawbits_harness(
        soc,
        layout,
        module_name=harness_module_name,
    )
    return EmittedComposeV5GeneratedSocBundle(soc, layout, harness, soc.rtl + "\n" + harness.rtl)


def _edge_assignments(
    edge: Mapping[str, object],
    source_interface: Mapping[str, object],
    target_interface: Mapping[str, object],
) -> tuple[tuple[tuple[str, str, str], ...], str, str]:
    edge_id = str(edge["id"])
    source_valid = _single_signal(source_interface, role="request_valid", direction="output", edge_id=edge_id)
    target_valid = _single_signal(target_interface, role="request_valid", direction="input", edge_id=edge_id)
    source_ready = _single_signal(source_interface, role="request_ready", direction="input", edge_id=edge_id)
    target_ready = _single_signal(target_interface, role="request_ready", direction="output", edge_id=edge_id)
    assignments = [(
        str(target_valid["owner"]),
        _wire_name(str(source_valid["owner"])),
        "broadcast source request_valid to planned target request_valid",
    )]
    for source_payload, target_payload in _payload_pairs(source_interface, target_interface, edge_id=edge_id):
        assignments.append((
            str(target_payload["owner"]),
            _wire_name(str(source_payload["owner"])),
            "broadcast source payload to planned target payload",
        ))
    return tuple(assignments), str(source_ready["owner"]), _wire_name(str(target_ready["owner"]))


def _interface(plan: ComposeV5ConnectionPlan, interface_id: str) -> Mapping[str, object]:
    for item in plan.interfaces:
        if item.get("id") == interface_id:
            if item.get("status") != "unique":
                raise InputValidationError(f"compose-v5 generated SoC interface {interface_id!r} is not unique")
            return item
    raise InputValidationError(f"compose-v5 generated SoC missing interface {interface_id!r}")


def _single_signal(
    interface: Mapping[str, object],
    *,
    role: str,
    direction: str,
    edge_id: str,
) -> Mapping[str, object]:
    matches = tuple(
        item for item in interface.get("signals", ())
        if isinstance(item, Mapping)
        and item.get("role") == role
        and item.get("direction") == direction
    )
    if len(matches) != 1:
        raise InputValidationError(
            f"compose-v5 generated SoC edge {edge_id} requires one {direction} {role} signal"
        )
    width = matches[0].get("width")
    if width != 1:
        raise InputValidationError(
            f"compose-v5 generated SoC edge {edge_id} requires one-bit {role}"
        )
    return matches[0]


def _payload_pairs(
    source_interface: Mapping[str, object],
    target_interface: Mapping[str, object],
    *,
    edge_id: str,
) -> tuple[tuple[Mapping[str, object], Mapping[str, object]], ...]:
    source_payloads = tuple(sorted(
        (
            item for item in source_interface.get("signals", ())
            if isinstance(item, Mapping)
            and item.get("role") == "payload"
            and item.get("direction") == "output"
        ),
        key=lambda item: (int(item["width"]), str(item["port"])),
    ))
    target_payloads = tuple(sorted(
        (
            item for item in target_interface.get("signals", ())
            if isinstance(item, Mapping)
            and item.get("role") == "payload"
            and item.get("direction") == "input"
        ),
        key=lambda item: (int(item["width"]), str(item["port"])),
    ))
    if len(source_payloads) != len(target_payloads):
        raise InputValidationError(
            f"compose-v5 generated SoC edge {edge_id} payload signal count mismatch"
        )
    for source, target in zip(source_payloads, target_payloads):
        if source["width"] != target["width"]:
            raise InputValidationError(
                f"compose-v5 generated SoC edge {edge_id} payload width mismatch"
            )
    return tuple(zip(source_payloads, target_payloads))


def _module(component_id: str, module: RTLModule) -> dict[str, object]:
    _identifier(component_id, "compose-v5 generated SoC component id")
    if not isinstance(module, RTLModule):
        raise InputValidationError("compose-v5 generated SoC requires RTLModule values")
    _identifier(module.original_name, f"compose-v5 component {component_id} original module name")
    _identifier(module.name, f"compose-v5 component {component_id} analysis module name")
    if module.evidence.state is not EvidenceState.KNOWN:
        raise InputValidationError(f"compose-v5 component {component_id} module is not fully provable")
    ports = tuple(_port(component_id, port) for port in sorted(module.ports, key=lambda item: item.name))
    if not ports:
        raise InputValidationError(f"compose-v5 component {component_id} has no ports")
    parameters = tuple(
        (_identifier(name, f"compose-v5 component {component_id} parameter name"),
         _parameter_literal(value, f"compose-v5 component {component_id} parameter {name}"))
        for name, value in sorted(module.parameters)
    )
    return {
        "module_type": module.original_name,
        "instance": component_id,
        "ports": ports,
        "parameters": parameters,
    }


def _port(component_id: str, port: RTLPort) -> dict[str, object]:
    _identifier(port.name, f"compose-v5 component {component_id} port name")
    if port.direction is PortDirection.INOUT:
        raise InputValidationError(
            f"compose-v5 generated SoC rejects inout port {component_id}.{port.name}"
        )
    if port.direction not in {PortDirection.INPUT, PortDirection.OUTPUT}:
        raise InputValidationError(f"invalid direction for compose-v5 port {component_id}.{port.name}")
    if isinstance(port.width, bool) or not isinstance(port.width, int) or port.width <= 0:
        raise InputValidationError(f"compose-v5 port {component_id}.{port.name} has invalid width")
    if port.evidence.state is not EvidenceState.KNOWN:
        raise InputValidationError(
            f"compose-v5 port {component_id}.{port.name} is not fully provable"
        )
    return {"name": port.name, "direction": port.direction, "width": port.width}


def _wire_name(owner: str) -> str:
    component, separator, port = owner.partition(".")
    if not separator:
        raise InputValidationError(f"compose-v5 owner {owner!r} is not component.port")
    return f"{_identifier(component, 'compose-v5 owner component')}__{_identifier(port, 'compose-v5 owner port')}"


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SV_IDENTIFIER.fullmatch(value):
        raise InputValidationError(f"{path}: expected a simple Verilog identifier")
    return value


def _parameter_literal(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SAFE_PARAMETER_LITERAL.fullmatch(value):
        raise InputValidationError(f"{path}: expected a safe numeric Verilog parameter literal")
    return value


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def _or_expr(terms: tuple[str, ...]) -> str:
    if not terms:
        return "1'b0"
    if len(terms) == 1:
        return terms[0]
    return "(" + " | ".join(terms) + ")"
