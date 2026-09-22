"""Render a compilable SoC top from a validated composition plan.

The renderer consumes the plan and never decides connections: every wire it
emits comes from a resolved binding, a resolved adapter or a disposition entry.
Names are instance-unique and stable, so a failure in a later audit can be
traced back to one profile fact.

Layout of the generated top:

* the SoC clock and reset are top-level inputs;
* each CPU instance is the real component behind its resolved processor adapter;
* the adapters feed the shared ``soc_arbiter`` / ``soc_router`` fabric, whose
  parameters come from the fabric plan;
* a plan that declares a synthetic ``fuzz_mmio`` source gets that generator-owned
  master on its own arbiter lane, with exactly the ``soc_stimulus.v1``
  projection parameters, its raw fields exported at the recorded segment
  offsets, and - in ``bfm_isolated`` - the CPU held in reset by a rendered
  constant for the whole test;
* each memory region is a generic byte-image memory model;
* each peripheral is the real component behind its resolved target bridge,
  with the bridge's protocol-side roles bound to the profile's real ports;
* peripheral interrupt outputs are normalized and wired to the generic
  controller, whose notification drives the CPU's declared interrupt entry;
* a component whose profile declares an external interface that a peer model
  implements is instantiated with that peer (``soc_peer_plan``) instead of
  exporting the pins: the peer's own ports are connected to the component's real
  pins, its stimulus inputs become top-level inputs driven either by the profile
  runtime's event plan or by the RFuzz combined raw layout, and its counters and
  observations become top-level outputs so a run can report them;
* declared special inputs, external pins and observation outputs become
  top-level ports with a stable, instance-qualified name.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .soc_composition import (
    MEMORY_MODEL_32,
    MEMORY_MODEL_64,
    MEMORY_MODEL_SOURCE,
    SYNTHETIC_CLOCK_PORT,
    CompositionPlan,
    InstanceComposition,
)
from .soc_peer_plan import PeerPlan
from .soc_port_dispositions import (
    IRQ_NOTIFY_NET,
    DispositionEntry,
    MemberNode,
    aligned_segments,
    constant_expression,
    cpu_entry_expression,
    driven_net,
    exported_ports,
    member_tree,
    port_is_aggregated,
    port_segments,
    segment_expression,
    segment_net,
    top_port_name,
)

RENDER_SCHEMA = "soc_generated.v1"
TOP_MODULE = "myfuzz_soc_top"
DRIVER_MODULE = "soc_special_input_driver"
DRIVER_SOURCE = "src/myfuzz/protocols/rtl/soc_special_input_driver.sv"
STRATEGY_CODES = {"cycle_value": 0, "reset_sampled": 1, "pulse": 2, "hold": 3}

#: Reset conventions of the modules the renderer instantiates itself.  The beat
#: fabric and its adapters use an active-high synchronous reset; the byte-image
#: memory model uses an active-low asynchronous one.  Declaring them here keeps
#: the generated polarity a checked fact rather than an assumption.
FABRIC_RESET_CONTRACT = {"port": "reset", "polarity": "active_high"}
MEMORY_RESET_CONTRACT = {"port": "reset", "polarity": "active_low"}

#: The rendered structure that holds the CPU in reset for a whole test.  The
#: names are declared here so the independent audit re-reads exactly the net and
#: constant this renderer promises, and so a generated top that holds the CPU
#: without them is a structural failure rather than a silent difference.
CPU_HELD_CONSTANT = "CPU_HELD_IN_RESET"
CPU_RESET_NET = "cpu_reset"


class SocRenderError(ValueError):
    """The plan cannot be rendered without inventing a connection."""


def _error(reason: str) -> None:
    raise SocRenderError(reason)


def _literal(value: object) -> str:
    if isinstance(value, bool):
        return "1'b1" if value else "1'b0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if value.isidentifier() or value.isdigit():
            return value
        _error(f"unsafe-parameter-literal:{value}")
    _error(f"unsupported-parameter-literal:{value!r}")


def _packed(values: Sequence[int], width: int, slots: int) -> str:
    text = "".join(f"{int(value) & ((1 << width) - 1):0{width}b}"
                   for value in reversed(list(values)))
    return f"{slots * width}'b{text}"


def _logic(name: str, width: int, *, signed: bool = False) -> str:
    if width == 1:
        return f"logic{' signed' if signed else ''} {name};"
    return f"logic {'signed ' if signed else ''}[{width - 1}:0] {name};"


def _driven_net(entry: DispositionEntry) -> str:
    """The net the special-input driver produces (instance-unique)."""
    return driven_net(entry)


def _top_port(entry: DispositionEntry) -> str:
    """The exported top-level port of one disposition segment."""
    return top_port_name(entry)


def _signal(instance_id: str, name: str) -> str:
    return f"{instance_id}__{name}"


def _synthetic(plan: CompositionPlan) -> Mapping[str, object] | None:
    """The declared synthetic master, checked against the fabric's own source list.

    The renderer adds no master of its own: it only renders the one the plan
    declares, on the lane the plan recorded for it.
    """
    record = plan.synthetic
    if not record:
        return None
    source_id = str(record.get("source_id", ""))
    lane = next((int(source["index"]) for source in plan.plan["fabric"]["sources"]
                 if str(source["source_id"]) == source_id), None)
    if lane is None:
        _error(f"synthetic-source-not-in-fabric:{source_id}")
    if lane != int(record.get("lane", -1)):
        _error(f"synthetic-lane-mismatch:{source_id}:{record.get('lane')}!={lane}")
    return record


class _Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, text: str = "") -> None:
        self.lines.append(text)

    def add_all(self, lines: Sequence[str]) -> None:
        self.lines.extend(lines)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _adapter_roles(instance: InstanceComposition,
                   adapter: Mapping[str, object] | None) -> dict[str, dict]:
    """role -> the bridge-side net plus the component-side connection rule.

    The net is as wide as the bridge port, because the bridge defines the
    protocol width.  A narrower component port is connected through the
    narrowing the planner proved; the renderer never slices on its own.
    """
    if adapter is None:
        return {}
    role_widths = adapter.get("role_widths") or {}
    roles: dict[str, dict] = {}
    for item in adapter["target_side_ports"]:  # type: ignore[index]
        role = str(item["role"])
        binding = role_widths.get(role)
        if binding is None:
            _error(f"role-width-binding-missing:{instance.instance_id}:{role}")
        roles[role] = {
            "net": _signal(instance.instance_id, role),
            "width": int(binding["width"]),
            "mode": str(binding["mode"]),
            "component_port": str(binding["component_port"]),
            "component_width": int(binding.get("component_width", binding["width"])),
        }
    return roles


def _field_net(instance: InstanceComposition, port: str, role: str) -> str:
    """The net one bound role of a component is wired on.

    A whole-port role keeps ``{instance}__{port}``; a role that owns only part of
    its port (a struct member, or a slice of a vector) is qualified by its role,
    which is unique inside its endpoint.  The ledger's own segment naming is the
    single declaration of that rule, so the plan record, the renderer and the
    audit cannot drift apart.
    """
    for entry in instance.dispositions:
        if entry.port == port and entry.role == role:
            return segment_net(entry)
    return f"{instance.instance_id}__{port}"


def _cpu_adapter_roles(instance: InstanceComposition,
                       endpoints: Sequence[str]) -> dict[str, dict]:
    """endpoint -> role -> the CPU-side net for each declared master/entry field.

    The map is scoped by endpoint on purpose: a split-interface CPU exposes the
    same protocol role ids on two interfaces (OBI ``req``/``gnt``/``addr`` on both
    the instruction and the data port), so a flat role map would silently wire
    the instruction port to the data nets.  The nets themselves stay
    ``{instance}__{field.port}`` and are already port-unique.
    """
    roles: dict[str, dict] = {}
    for endpoint_id in endpoints:
        endpoint = instance.binding.endpoint(endpoint_id)
        scoped: dict[str, dict] = {}
        for field in endpoint.fields:
            scoped[field.role] = {
                "net": _field_net(instance, field.port, field.role),
                "width": field.width,
                "mode": "direct",
                "component_port": field.port,
                "component_width": field.width,
            }
        roles[endpoint_id] = scoped
    return roles


def _role_binding(roles: Mapping[str, object], entry: DispositionEntry) -> object:
    """Resolve a disposition's role in either a scoped or a flat role map."""
    scoped = roles.get(str(entry.endpoint_id))
    if isinstance(scoped, Mapping):
        found = scoped.get(str(entry.role))
        if found is not None:
            return found
    return roles.get(str(entry.role))


def _render_top(plan: CompositionPlan) -> str:
    soc_plan = plan.plan
    fabric = soc_plan["fabric"]
    parameters = fabric["rtl"]["parameters"]
    decode = sorted((dict(row) for row in fabric["decode"]["windows"]),
                    key=lambda row: (int(row["base"]), str(row["window_id"])))
    address_width = int(parameters["ADDRESS_WIDTH"])
    data_width = int(parameters["DATA_WIDTH"])
    num_sources = int(parameters["NUM_SOURCES"])
    num_targets = int(parameters["NUM_TARGETS"])
    source_id_width = max(1, (num_sources - 1).bit_length())
    target_id_width = max(1, (num_targets - 1).bit_length())
    max_windows = max(1, len(decode))
    instances = {item.instance_id: item for item in plan.instances}
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    cpu_contract = cpu_instance.profile.cpu
    assert cpu_contract is not None
    cpu_endpoints = list(cpu_contract.master_endpoints)
    if cpu_contract.irq_entry_endpoint is not None:
        # The interrupt entry is a functional port too: the controller drives it,
        # so the component is wired to a named net rather than to a literal.
        cpu_endpoints.append(cpu_contract.irq_entry_endpoint)
    routes = {int(route["route_id"]): route for route in soc_plan["processor_execution"]["routes"]}
    bindings = sorted(soc_plan["processor_execution"]["bindings"],
                      key=lambda item: str(item["source_id"]))
    cpu_roles = _cpu_adapter_roles(cpu_instance, cpu_endpoints)
    # A functional role may be driven by an expression rather than a named net.
    # The CPU's declared interrupt entry is the only such case, and inlining it
    # keeps the connection visible in the elaborated netlist instead of hiding
    # behind a continuous assignment the frontend may fold away.  The expression
    # is the interrupt plan's own record: the controller notification when a
    # controller exists, and the declared inactive level when the plan says the
    # entry is disabled by contract because no source is declared.
    direct: dict[str, dict[str, str]] = {}
    if cpu_contract.irq_entry_endpoint is not None and cpu_contract.irq_entry_role:
        entry = cpu_instance.binding.endpoint(cpu_contract.irq_entry_endpoint)
        field = next(item for item in entry.fields
                     if item.role == cpu_contract.irq_entry_role)
        expression = cpu_entry_expression(plan.interrupt_document)
        if expression is not None:
            direct[cpu_instance.instance_id] = {
                field.role: expression,
                f"{entry.endpoint_id}:{field.role}": expression,
            }
    peripheral_roles: dict[str, dict[str, str]] = {}
    for target_record in plan.target_records:
        if "instance_id" not in target_record:
            continue
        instance_id = str(target_record["instance_id"])
        adapter = target_record.get("resolved_adapter")
        roles = _adapter_roles(instances[instance_id],
                               adapter if isinstance(adapter, Mapping) else None)
        # Interrupt source outputs are functional too: they are normalized and
        # driven into the controller's source vector, so they get a named net.
        for source in plan.interrupt_plan.sources:
            if source.instance_id == instance_id:
                roles[source.role] = {
                    "net": _signal(instance_id, source.port),
                    "width": 1,
                    "mode": "direct",
                    "component_port": source.port,
                    "component_width": 1,
                }
        peripheral_roles[instance_id] = roles

    writer = _Writer()
    writer.add("// Generated by myfuzz automatic SoC composition. Do not edit.")
    writer.add(f"// request: {plan.request_id}")
    writer.add(f"// plan:    {plan.plan_hash}")
    writer.add(f"// raw-input layout: {plan.raw_layout.get('layout_hash', '<none>')}")
    writer.add(f"module {TOP_MODULE} (")
    ports: list[str] = ["    input  logic clk_i", "    input  logic rst_ni"]
    seen_ports: set[str] = set()
    for entry in sorted(exported_ports([entry for item in plan.instances
                                        for entry in item.dispositions]), key=_top_port):
        name = _top_port(entry)
        if name in seen_ports:
            continue
        seen_ports.add(name)
        direction = "input " if entry.direction == "input" else "output"
        width = entry.bit_hi - entry.bit_lo + 1
        shape = "logic" if width == 1 else f"logic [{width - 1}:0]"
        ports.append(f"    {direction} {shape} {name}")
    for entry in sorted((item for instance in plan.instances
                         for item in instance.dispositions
                         if item.disposition == "fuzz"), key=_top_port):
        width = entry.bit_hi - entry.bit_lo + 1
        shape = "logic" if width == 1 else f"logic [{width - 1}:0]"
        ports.append(f"    output {shape} {_top_port(entry)}__applied")
    synthetic = _synthetic(plan)
    # The synthetic master's raw fields are the *request*: they are exported at
    # the exact bit offsets the stimulus document records for the mmio segment,
    # so the environment drives the offer, not the driver's internal latches.
    for item in (synthetic or {}).get("raw_ports", []):
        width = int(item["width"])
        shape = "logic" if width == 1 else f"logic [{width - 1}:0]"
        ports.append(f"    input  {shape} {item['name']}")
    # Peer stimulus ports are exported once.  The profile runtime drives them
    # from a payload-carrying event plan; the RFuzz profile artifact drives the
    # same ports from per-cycle raw fields recorded by combined_input_layout.
    # Peer counters and observations are exported so a run can report what the
    # peer really did.
    for peer in plan.peers:
        for slot in peer.slots:
            for signal in slot.signals:
                shape = "logic" if signal.width == 1 else f"logic [{signal.width - 1}:0]"
                ports.append(f"    input  {shape} {signal.top_port}")
        for observation in peer.observations:
            shape = "logic" if observation.width == 1 \
                else f"logic [{observation.width - 1}:0]"
            ports.append(f"    output {shape} {observation.top_port}")
    writer.add(",\n".join(ports))
    writer.add(");")
    writer.add("  // fuzz ports: declared special inputs, driven by the environment under the")
    writer.add("  //   profile's declared strategy.  They are ordinary inputs, not random nets.")
    writer.add("  // external ports: exported non-MMIO pins, driven by the environment model.")
    writer.add("  // peer ports: request inputs and observation outputs of the peer models the")
    writer.add("  //   plan attached; an interface with a peer is *not* exported as pins.")
    writer.add("  // observe ports: exported component outputs, never driven by the SoC.")
    if synthetic:
        writer.add("  // synthetic-input ports: the generated MMIO master's raw fields, at the")
        writer.add("  //   offsets soc_stimulus.v1 records for its mmio segment; the master is")
        writer.add("  //   its own latch, so no driver stage sits in front of them.")
    writer.add("")
    writer.add(f"  localparam integer ADDRESS_WIDTH = {address_width};")
    writer.add(f"  localparam integer DATA_WIDTH = {data_width};")
    writer.add(f"  localparam integer NUM_SOURCES = {num_sources};")
    writer.add(f"  localparam integer NUM_TARGETS = {num_targets};")
    writer.add("  // Every reset connection is written with the polarity its module contract")
    writer.add("  // declares, so the generated expression is the evidence the audit re-reads:")
    writer.add("  // the beat fabric is active high (~rst_ni), the byte-image memory model is")
    writer.add("  // active low (rst_ni).")
    if synthetic and plan.cpu_held_in_reset:
        # The CPU reset is asserted for the whole test.  The constant is rendered
        # (not only recorded in metadata) so the audit can re-read the held level
        # from the elaborated structure, and the CPU connects to this wire.
        writer.add("  // bfm_isolated holds the CPU in reset for the whole test: the rendered")
        writer.add("  // constant is the hold, and the CPU reset port is driven by this wire.")
        writer.add(f"  localparam bit {CPU_HELD_CONSTANT} = 1;")
        writer.add(f"  wire {CPU_RESET_NET} = {_held_reset_driver(plan)};")
    writer.add("")

    # ---- per-instance functional nets -----------------------------------
    for instance in plan.instances:
        roles = cpu_roles if instance.kind == "cpu" \
            else peripheral_roles.get(instance.instance_id, {})
        declared: set[str] = set()
        lines: list[str] = []
        for entry in sorted(instance.dispositions, key=lambda item: (item.port, item.bit_lo)):
            if entry.disposition not in ("functional", "peer"):
                continue
            if entry.disposition == "peer":
                # A peer-bound pin is an ordinary internal net: the component and
                # the peer instance share it, and it is not exported.
                name, width = _signal(instance.instance_id, entry.port), entry.width
                if name in declared:
                    continue
                declared.add(name)
                lines.append("  " + _logic(name, width))
                continue
            if str(entry.role) in direct.get(instance.instance_id, {}):
                continue
            binding = _role_binding(roles, entry)
            if binding is not None:
                name, width = str(binding["net"]), int(binding["width"])
            else:
                # A role the plan binds no bridge to keeps its own segment net;
                # on a whole-port role that is the historical
                # ``{instance}__{port}`` name, and on a member it is
                # role-qualified so two members of one struct port cannot share
                # a net.
                name, width = segment_net(entry), entry.width
            if name in declared:
                continue
            declared.add(name)
            lines.append("  " + _logic(name, width))
        if lines:
            writer.add(f"  // {instance.instance_id} ({instance.top_module}) functional nets")
            writer.add_all(lines)
            writer.add("")

    # ---- special-input drivers ------------------------------------------
    writer.add("  // Declared special inputs.  The top-level port is the raw request; the")
    writer.add("  // driver applies the profile's declared strategy and is the single writer")
    writer.add("  // of the component input.")
    for instance in plan.instances:
        for entry in sorted(instance.dispositions,
                            key=lambda item: (item.port, item.bit_lo)):
            if entry.disposition != "fuzz":
                continue
            width = entry.bit_hi - entry.bit_lo + 1
            strategy = str(entry.strategy)
            code = STRATEGY_CODES.get(strategy)
            if code is None:
                _error(f"unsupported-drive-strategy:{entry.instance_id}:{entry.port}:{strategy}")
            parameters = dict(entry.drive)
            pulse_cycles = int(parameters.get("pulse_cycles", 1))
            min_gap = int(parameters.get("min_gap_cycles", 0))
            handshake = 1 if parameters.get("handshake") else 0
            writer.add("")
            writer.add(f"  {_logic(_driven_net(entry), width)}")
            writer.add(f"  {DRIVER_MODULE} #(.WIDTH({width}), .STRATEGY({code}), "
                       f".PULSE_CYCLES({pulse_cycles}), .PULSE_MIN_GAP({min_gap}), "
                       f".HOLD_ON_READY({handshake})) u_drive_{_top_port(entry)} (")
            writer.add(f"    .clk_i(clk_i), .rst_ni(rst_ni), .raw_i({_top_port(entry)}),")
            writer.add("    .update_i(1'b1), .hold_ready_i(1'b1), "
                       f".value_o({_driven_net(entry)}), .applied_o()")
            writer.add("  );")
            writer.add(f"  assign {_top_port(entry)}__applied = {_driven_net(entry)};")
            writer.add(f"  // {entry.instance_id}.{entry.port}: {strategy}, "
                       f"{entry.reason}")
    writer.add("")

    # ---- arbiter and router plumbing ------------------------------------
    writer.add("  // Arbiter lanes: one per declared CPU master interface.")
    writer.add(f"  logic [{num_sources - 1}:0] src_req_valid, src_req_ready, src_write;")
    writer.add(f"  logic [{num_sources - 1}:0] src_rsp_valid, src_rsp_ready, src_error;")
    writer.add(f"  logic [{num_sources - 1}:0][{address_width - 1}:0] src_addr;")
    writer.add(f"  logic [{num_sources - 1}:0][{data_width - 1}:0] src_wdata, src_rdata;")
    writer.add(f"  logic [{num_sources - 1}:0][{data_width // 8 - 1}:0] src_be;")
    writer.add("  logic fabric_req_valid, fabric_req_ready, fabric_write, fabric_instr;")
    writer.add(f"  logic [{address_width - 1}:0] fabric_addr;")
    writer.add(f"  logic [{data_width - 1}:0] fabric_wdata, fabric_rdata;")
    writer.add(f"  logic [{data_width // 8 - 1}:0] fabric_be;")
    writer.add(f"  logic [{source_id_width - 1}:0] fabric_source_id, fabric_rsp_source_id;")
    writer.add("  logic [7:0] fabric_transaction_id, fabric_rsp_transaction_id;")
    writer.add("  logic fabric_rsp_valid, fabric_rsp_ready, fabric_error, fabric_protocol_error;")
    writer.add(f"  logic [{num_targets - 1}:0] t_req_valid, t_req_ready, t_write;")
    writer.add(f"  logic [{num_targets - 1}:0][{address_width - 1}:0] t_addr;")
    writer.add(f"  logic [{num_targets - 1}:0][{data_width - 1}:0] t_wdata, t_rdata;")
    writer.add(f"  logic [{num_targets - 1}:0][{data_width // 8 - 1}:0] t_be;")
    writer.add(f"  logic [{num_targets - 1}:0] t_rsp_valid, t_rsp_ready, t_error;")
    writer.add("")

    # ---- CPU adapters ----------------------------------------------------
    for binding in bindings:
        source_id = str(binding["source_id"])
        lane = next((index for index, source in enumerate(fabric["sources"])
                     if str(source["source_id"]) == source_id), None)
        if lane is None:
            _error(f"cpu-lane-missing:{source_id}")
        route = routes[int(binding["route_id"])]
        master = next((item for item in plan.spec["masters"]
                       if str(item["source_id"]) == source_id), None)
        if master is None:
            _error(f"cpu-master-record-missing:{source_id}")
        endpoint = cpu_instance.binding.endpoint(str(master["port"]))
        adapter_ports = {str(item["role"]): str(item["adapter_port"])
                         for item in plan.cpu_adapter["source_ports"]}
        writer.add(f"  // {cpu_instance.instance_id} {master['port']} -> {binding['rtl_module']}")
        parameter_text = ", ".join(
            f".{name}({_literal(value)})" for name, value in
            sorted(route["parameters"].items(), key=lambda item: str(item[0])))
        # Keep the compact ``module #(.ADDRESS_WIDTH(...`` spelling used by
        # the generated-source contract.  Besides being easier to inspect, it
        # gives the independent audit/fault-injection tests a stable anchor
        # without changing the elaborated structure.
        writer.add(f"  {binding['rtl_module']} #({parameter_text})"
                   f" u_{cpu_instance.instance_id}_adapter_{lane} (")
        connections = ["    .clk_i(clk_i), .rst_ni(rst_ni)"]
        scoped = cpu_roles.get(str(master["port"]), {})
        for field in endpoint.fields:
            # The adapter's source pin is connected to the net the *role* owns:
            # on a whole-port role that is the historical
            # ``{instance}__{port}`` net, and on a member of a struct port it is
            # the role-qualified member net.  Connecting the whole struct net
            # instead lets the frontend silently extend it to each narrow pin.
            role_binding = scoped.get(field.role)
            net = (str(role_binding["net"]) if isinstance(role_binding, Mapping)
                   else _signal(cpu_instance.instance_id, field.port))
            connections.append(f"    .{adapter_ports[field.role]}({net})")
        connections.extend([
            f"    .req_valid_o(src_req_valid[{lane}])",
            f"    .req_ready_i(src_req_ready[{lane}])",
            f"    .req_write_o(src_write[{lane}])",
            f"    .req_addr_o(src_addr[{lane}])",
            f"    .req_wdata_o(src_wdata[{lane}])",
            f"    .req_be_o(src_be[{lane}])",
            f"    .rsp_valid_i(src_rsp_valid[{lane}])",
            f"    .rsp_ready_o(src_rsp_ready[{lane}])",
            f"    .rsp_rdata_i(src_rdata[{lane}])",
            f"    .rsp_error_i(src_error[{lane}])",
        ])
        writer.add(",\n".join(connections))
        writer.add("  );")
    writer.add("")
    for instance in [item for item in plan.instances if item.kind == "cpu"]:
        _render_component(writer, instance, cpu_roles,
                          direct.get(instance.instance_id, {}),
                          reset_override=CPU_RESET_NET if plan.cpu_held_in_reset else None)
    if synthetic:
        _render_synthetic_master(writer, plan, synthetic)
    writer.add("")
    for binding in plan.plan["processor_execution"]["bindings"]:
        source_id = str(binding["source_id"])
        lane = next((index for index, source in enumerate(fabric["sources"])
                     if str(source["source_id"]) == source_id), None)
        if lane is None:
            _error(f"cpu-lane-missing:{source_id}")
    writer.add(f"  // Instruction-lane flags are part of the arbiter request, so they are")
    writer.add(f"  // literal bits of the s_instr vector rather than separate assigns.")

    # ---- arbiter / router ------------------------------------------------
    writer.add("")
    writer.add(f"  soc_arbiter #(.NUM_SOURCES({num_sources}), .ADDRESS_WIDTH(ADDRESS_WIDTH),")
    writer.add(f"      .DATA_WIDTH(DATA_WIDTH), .SOURCE_ID_WIDTH({source_id_width}),")
    writer.add("      .TRANSACTION_ID_WIDTH(8)) u_soc_arbiter (")
    writer.add("    .clk(clk_i), .reset(~rst_ni), .s_req_valid(src_req_valid),")
    writer.add("    .s_req_ready(src_req_ready), .s_write(src_write), .s_addr(src_addr),")
    writer.add(f"    .s_wdata(src_wdata), .s_be(src_be), "
               f".s_instr({_lane_instruction_bits(plan, fabric)}),")
    writer.add("    .s_rsp_valid(src_rsp_valid), .s_rsp_ready(src_rsp_ready),")
    writer.add("    .s_rdata(src_rdata), .s_error(src_error), .req_valid(fabric_req_valid),")
    writer.add("    .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),")
    writer.add("    .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),")
    writer.add("    .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),")
    writer.add("    .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),")
    writer.add("    .rdata(fabric_rdata), .error(fabric_error),")
    writer.add("    .rsp_source_id(fabric_rsp_source_id),")
    writer.add("    .rsp_transaction_id(fabric_rsp_transaction_id),")
    writer.add("    .protocol_error(fabric_protocol_error)")
    writer.add("  );")
    executable = sum(1 << position for position, row in enumerate(decode)
                     if row["permissions"]["execute"])
    readable = sum(1 << position for position, row in enumerate(decode)
                   if row["permissions"]["read"])
    writable = sum(1 << position for position, row in enumerate(decode)
                   if row["permissions"]["write"])
    source_mask = sum(int(row["allowed_source_mask"]) << (position * num_sources)
                      for position, row in enumerate(decode))
    writer.add("")
    writer.add("  // Address router: the plan's own windows, permissions and source masks.")
    writer.add(f"  soc_router #(.RESET_CLEARS_TARGETS("
               f"{_literal(int(parameters.get('RESET_CLEARS_TARGETS', 0)))}),")
    writer.add("      .NUM_TARGETS(NUM_TARGETS), .ADDRESS_WIDTH(ADDRESS_WIDTH),")
    writer.add(f"      .DATA_WIDTH(DATA_WIDTH), .SOURCE_ID_WIDTH({source_id_width}),")
    writer.add("      .NUM_SOURCES(NUM_SOURCES), .TRANSACTION_ID_WIDTH(8),")
    writer.add(f"      .TARGET_ID_WIDTH({target_id_width}),")
    writer.add(f"      .MAX_WINDOWS({max_windows}), .NUM_WINDOWS({len(decode)}),")
    writer.add("      .WINDOW_BASE(%s),"
               % _packed([int(row["base"]) for row in decode], address_width, max_windows))
    writer.add("      .WINDOW_TARGET_BASE(%s),"
               % _packed([int(row["target_base"]) for row in decode], address_width, max_windows))
    writer.add("      .WINDOW_SIZE(%s),"
               % _packed([int(row["size"]) for row in decode], address_width, max_windows))
    writer.add("      .WINDOW_TARGET(%s),"
               % _packed([int(row["target_index"]) for row in decode], target_id_width, max_windows))
    writer.add(f"      .WINDOW_EXECUTABLE({max_windows}'b{executable:0{max_windows}b}),")
    writer.add(f"      .WINDOW_READABLE({max_windows}'b{readable:0{max_windows}b}),")
    writer.add(f"      .WINDOW_WRITABLE({max_windows}'b{writable:0{max_windows}b}),")
    writer.add(f"      .WINDOW_SOURCE_MASK({max_windows * num_sources}'b"
               f"{source_mask:0{max_windows * num_sources}b})")
    writer.add("  ) u_soc_router (")
    writer.add("    .clk(clk_i), .reset(~rst_ni), .req_valid(fabric_req_valid),")
    writer.add("    .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),")
    writer.add("    .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),")
    writer.add("    .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),")
    writer.add("    .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),")
    writer.add("    .rdata(fabric_rdata), .error(fabric_error),")
    writer.add("    .rsp_source_id(fabric_rsp_source_id),")
    writer.add("    .rsp_transaction_id(fabric_rsp_transaction_id),")
    writer.add("    .t_req_valid(t_req_valid), .t_req_ready(t_req_ready), .t_write(t_write),")
    writer.add("    .t_addr(t_addr), .t_wdata(t_wdata), .t_be(t_be),")
    writer.add("    .t_rsp_valid(t_rsp_valid), .t_rsp_ready(t_rsp_ready),")
    writer.add("    .t_rdata(t_rdata), .t_error(t_error), .selected_target(),")
    writer.add("    .stale_pending()")
    writer.add("  );")

    # ---- memory targets --------------------------------------------------
    policies = {str(region["physical_memory_id"]): str(region["initialization_policy"])
                for region in plan.spec["memory_regions"]}  # type: ignore[index]
    for target in fabric["targets"]:
        if target.get("backing_kind") != "memory":
            continue
        index = int(target["index"])
        rows = [row for row in decode if int(row["target_index"]) == index]
        if len(rows) != 1:
            _error(f"memory-window-count:{target['backing_id']}")
        row = rows[0]
        model = MEMORY_MODEL_32 if data_width == 32 else MEMORY_MODEL_64
        policy = policies.get(str(target["backing_id"]), "on_demand")
        load_image = 1 if policy in ("preload", "rom") else 0
        writer.add("")
        writer.add(f"  // Memory {target['backing_id']} ({model}) at "
                   f"0x{int(row['base']):08x} size 0x{int(row['size']):x}, "
                   f"initialization {policy}.")
        writer.add(f"  {model} #(.BASE_ADDR({int(row['base'])}), .BYTES({int(row['size'])}),")
        writer.add(f"      .LOAD_IMAGE({load_image})) u_mem_{index} (")
        writer.add("    .clock(clk_i), .reset(rst_ni), .flush(1'b0),")
        writer.add(f"    .req_valid(t_req_valid[{index}]), .req_ready(t_req_ready[{index}]),")
        writer.add(f"    .write(t_write[{index}]), .addr(t_addr[{index}]), "
                   f".wdata(t_wdata[{index}]),")
        writer.add(f"    .be(t_be[{index}]), .rsp_valid(t_rsp_valid[{index}]),")
        writer.add(f"    .rsp_ready(t_rsp_ready[{index}]), .rdata(t_rdata[{index}]),")
        writer.add(f"    .error(t_error[{index}])")
        writer.add("  );")

    # ---- peripheral targets ---------------------------------------------
    width_adapters = {int(item["target_index"]): item
                      for item in fabric.get("width_adapters", [])}
    narrowers = {int(item["target_index"]): item
                 for item in fabric.get("address_narrowers", [])}
    for target_record in plan.target_records:
        if "instance_id" not in target_record:
            continue
        instance = instances[str(target_record["instance_id"])]
        index = _target_index(fabric, str(target_record["target_id"]))
        if index in width_adapters:
            _error(f"width-adapter-rendering-unsupported:{instance.instance_id}")
        if index in narrowers:
            _error(f"address-narrower-rendering-unsupported:{instance.instance_id}")
        _render_peripheral(writer, instance, target_record, index,
                           peripheral_roles[instance.instance_id])

    # ---- interrupt controller -------------------------------------------
    _render_interrupts(writer, plan)

    # ---- peer models -----------------------------------------------------
    for peer in plan.peers:
        _render_peer(writer, plan, peer)

    writer.add("")
    writer.add("  // Constants and explicitly unconnected ports are disposition-ledger")
    writer.add("  // entries; only the constant values are materialised as literals.")
    writer.add("  logic unused_outputs;")
    writer.add("  assign unused_outputs = ^{fabric_rsp_source_id, "
               "fabric_rsp_transaction_id, fabric_protocol_error};")
    writer.add("endmodule")
    return writer.text()


def _lane_instruction_bits(plan: CompositionPlan, fabric: Mapping[str, object]) -> str:
    """The arbiter's instruction lane flags, computed from the bound routes."""
    functions: dict[int, str] = {}
    for binding in plan.plan["processor_execution"]["bindings"]:
        source_id = str(binding["source_id"])
        lane = next((index for index, source in enumerate(fabric["sources"])
                     if str(source["source_id"]) == source_id), None)
        if lane is None:
            _error(f"cpu-lane-missing:{source_id}")
        functions[lane] = str(binding["function"])
    bits = "".join("1" if functions.get(index) == "instruction_memory_master" else "0"
                   for index in range(len(fabric["sources"]) - 1, -1, -1))
    return f"{len(fabric['sources'])}'b{bits}"


def _target_index(fabric: Mapping[str, object], target_id: str) -> int:
    for row in fabric["decode"]["windows"]:  # type: ignore[index]
        if str(row["target_id"]) == target_id:
            return int(row["target_index"])
    _error(f"target-window-missing:{target_id}")


def _render_component(writer: _Writer, instance: InstanceComposition,
                      roles: Mapping[str, object],
                      direct: Mapping[str, str] | None = None,
                      reset_override: str | None = None) -> None:
    """Instantiate the real component with every port connected by disposition.

    ``reset_override`` replaces the instance's own reset expression (the plain
    SoC reset at the instance's declared polarity) with a rendered net; the CPU
    uses it to be held in reset for a whole test without changing any other port.
    """
    if instance.parameters:
        # The instance parameters are the declared configuration of this
        # instance and the same values its ports were elaborated with
        # (``soc_composition._check_elaborated_parameters``), so they are
        # rendered instead of being silently replaced by the module defaults.
        writer.add(f"  {instance.top_module} #(")
        writer.add("    " + ", ".join(f".{name}({_literal(value)})"
                                      for name, value in sorted(instance.parameters.items())))
        writer.add(f"  ) u_{instance.instance_id} (")
    else:
        writer.add(f"  {instance.top_module} u_{instance.instance_id} (")
    connections: list[str] = []
    grouped = port_segments(instance.dispositions)
    for port in sorted(grouped):
        entries = grouped[port]
        if not port_is_aggregated(entries):
            entry = entries[0]
            if entry.disposition == "unconnected":
                writer.add(f"    // {entry.port}[{entry.bit_hi}:{entry.bit_lo}]: left open per "
                           f"contract - {entry.reason}")
                continue
            connections.append(f"    .{port}({_entry_expression(instance, entry, roles, direct, reset_override)})")
            continue
        connections.append(f"    .{port}({_aggregate_expression(instance, port, entries, roles, direct, reset_override, writer)})")
    if not connections:
        writer.add("    // no ports")
    writer.add(",\n".join(connections))
    writer.add("  );")


def _entry_expression(instance: InstanceComposition, entry: DispositionEntry,
                      roles: Mapping[str, object],
                      direct: Mapping[str, str] | None,
                      reset_override: str | None) -> str:
    """The connection expression of exactly one disposition segment."""
    if entry.disposition == "unconnected":
        _error(f"unconnected-functional-port:{instance.instance_id}:{entry.port}:{entry.role}")
    if entry.disposition == "peer":
        # The net is shared with the peer instance the plan attached; the peer,
        # not the top, is the other end of this pin.
        return _signal(instance.instance_id, entry.port)
    if entry.disposition == "functional":
        expression = (direct or {}).get(f"{entry.endpoint_id}:{entry.role}")
        if expression is None:
            expression = (direct or {}).get(str(entry.role))
        if expression is not None:
            return expression
        binding = _role_binding(roles, entry)
        if binding is not None:
            net = str(binding["net"])
            mode = str(binding["mode"])
            if mode == "direct":
                return net
            if mode == "narrow_address":
                bits = int(binding.get("component_width", entry.width))
                # The bridge address is narrowed by the window the planner
                # proved; the slice is the role's own declared width.
                return f"{net}[{bits - 1}:0]"
            _error(f"unsupported-role-binding:{instance.instance_id}:{entry.port}:{mode}")
        if entry.role == "clock":
            return "clk_i"
        if entry.role == "reset":
            return reset_override if reset_override is not None else _reset_expression(instance)
        _error(f"unconnected-functional-port:{instance.instance_id}:{entry.port}:{entry.role}")
    if entry.disposition == "fuzz":
        # The top-level port is the *request*; the driver inside the SoC applies
        # the declared strategy and owns the component input.
        return _driven_net(entry)
    if entry.disposition in ("external", "observe"):
        return _top_port(entry)
    if entry.disposition == "constant":
        return constant_expression(entry)
    _error(f"unsupported-disposition:{instance.instance_id}:{entry.port}:{entry.disposition}")


def _aggregate_expression(instance: InstanceComposition, port: str,
                          entries: Sequence[DispositionEntry],
                          roles: Mapping[str, object],
                          direct: Mapping[str, str] | None,
                          reset_override: str | None,
                          writer: _Writer) -> str:
    """One connection that drives or observes every role of a multi-role port.

    A struct or array port is connected with a SystemVerilog assignment pattern
    whose members are the individual roles' nets; a plain vector port is
    connected with a concatenation of its slices, most significant first.  The
    adapter's lossless address narrowing is commented where it happens, exactly
    as it is for a whole-port connection.
    """
    fact = instance.binding.facts.port(port)
    members = tuple(getattr(fact, "members", ()))
    width = entries[0].width
    segments = aligned_segments(entries, members, width)
    # Assigning an integral expression to an enumerated struct member is not a
    # legal implicit conversion (IEEE 1800 6.19.3), so a member whose declared
    # type is an enum is cast to that type by name; the type comes from the
    # elaboration, not from a guess about the member's name.
    enum_types = {tuple(member.path): member.enum_type for member in members
                  if getattr(member, "enum_type", "")}
    expressions: dict[int, str] = {}
    for _low, _high, _path, entry in segments:
        expressions[id(entry)] = _entry_expression(instance, entry, roles, direct,
                                                   reset_override)
        if entry.disposition == "functional":
            binding = _role_binding(roles, entry)
            if isinstance(binding, Mapping) and str(binding.get("mode")) == "narrow_address":
                writer.add(f"    // {port}.{entry.role or ''}: lossless narrowing of the bridge "
                           f"address proved by the declared window")
    by_span = {(entry.bit_lo, entry.bit_hi): expressions[id(entry)]
               for _low, _high, _path, entry in segments}
    if not members:
        return "{" + ", ".join(expressions[id(entry)]
                               for _low, _high, _path, entry
                               in sorted(segments, key=lambda row: -row[1])) + "}"

    def render(node: MemberNode, path: tuple[str, ...]) -> str:
        covering = by_span.get((node.bit_lo, node.bit_hi))
        if covering is not None:
            return covering
        parts: list[str] = []
        for _high, item in node.items():
            if isinstance(item, MemberNode):
                parts.append(f"{item.name}: {render(item, path + (item.name,))}")
            else:
                leaf_path, low, high = item  # type: ignore[misc]
                leaf = by_span.get((low, high))
                if leaf is None:
                    _error(f"struct-port-segment-mismatch:{instance.instance_id}:{port}:"
                           f"{'.'.join(leaf_path)}")
                declared = enum_types.get(tuple(leaf_path))
                if declared:
                    leaf = f"{declared}'({leaf})"
                parts.append(f"{leaf_path[-1]}: {leaf}")
        if not parts:
            _error(f"struct-port-segment-mismatch:{instance.instance_id}:{port}:"
                   f"{'.'.join(path)}")
        return "'{" + ", ".join(parts) + "}"

    tree = member_tree(members, width)
    return render(tree, ())


def _reset_expression(instance: InstanceComposition) -> str:
    polarity = instance.binding.resets[0][0].polarity
    if polarity == "active_low":
        return "rst_ni"
    if polarity == "active_high":
        return "~rst_ni"
    _error(f"unsupported-reset-polarity:{polarity}")


def _held_reset_driver(plan: CompositionPlan) -> str:
    """The expression that asserts the CPU's declared reset for a whole test."""
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    polarity = cpu_instance.binding.resets[0][0].polarity
    if polarity == "active_low":
        return f"rst_ni & ~{CPU_HELD_CONSTANT}"
    if polarity == "active_high":
        return f"~rst_ni | {CPU_HELD_CONSTANT}"
    _error(f"unsupported-reset-polarity:{polarity}")


def _render_synthetic_master(writer: _Writer, plan: CompositionPlan,
                             synthetic: Mapping[str, object]) -> None:
    """Instantiate the declared synthetic master on its own arbiter lane.

    Every parameter is the compiled ``soc_stimulus.v1`` projection parameter, the
    raw ports are the top-level ports at the recorded segment offsets, the beat
    ports are the fields of the master's own declared protocol and the remaining
    outputs are the driver's counters.  The reset follows the module's declared
    contract; the clock is the SoC clock.  Nothing here is selected by a
    component or model name: the module, its source and its ports all come from
    the plan's synthetic record, which is itself derived from the stimulus
    document and the module's elaboration.
    """
    identifier = str(synthetic["instance_id"])
    lane = int(synthetic["lane"])
    module = str(synthetic["module"])
    parameters = synthetic["parameter_literals"]
    assert isinstance(parameters, Mapping)
    writer.add("")
    writer.add(f"  // Synthetic MMIO master {identifier}: the generator-owned {module}")
    writer.add(f"  //   ({synthetic['source']}) declared by drive profile "
               f"'{plan.drive_profile}',")
    writer.add(f"  //   compiled in mode '{synthetic['mode']}' with exactly the parameters the")
    writer.add("  //   soc_stimulus.v1 rtl_projection records, and wired to its own arbiter")
    writer.add(f"  //   lane {lane} ({synthetic['source_id']}).")
    for item in synthetic["observations"]:  # type: ignore[union-attr]
        writer.add("  " + _logic(str(item["name"]), int(item["width"])))
    parameter_text = ", ".join(f".{name}({value})"
                               for name, value in sorted(parameters.items()))
    writer.add(f"  {module} #({parameter_text}")
    writer.add(f"  ) u_{identifier} (")
    reset_contract = synthetic["reset_contract"]
    assert isinstance(reset_contract, Mapping)
    reset_expression = "~rst_ni" if str(reset_contract["polarity"]) == "active_high" else "rst_ni"
    connections = [f"    .{SYNTHETIC_CLOCK_PORT}(clk_i)",
                   f"    .{reset_contract['port']}({reset_expression})"]
    for item in synthetic["raw_ports"]:  # type: ignore[union-attr]
        connections.append(f"    .{item['port']}({item['name']})")
    for item in synthetic["beat_ports"]:  # type: ignore[union-attr]
        connections.append(f"    .{item['port']}(src_{item['port']}[{lane}])")
    for item in synthetic["observations"]:  # type: ignore[union-attr]
        connections.append(f"    .{item['port']}({item['name']})")
    writer.add(",\n".join(connections))
    writer.add("  );")


def _render_peer(writer: _Writer, plan: CompositionPlan, peer: PeerPlan) -> None:
    """Instantiate the peer model the plan bound to one declared interface.

    Nothing here is selected by a name: the module, its parameters and every
    connection come from the resolved ``PeerPlan`` record, whose role bindings
    name the component's own elaborated ports.  The peer's stimulus inputs are
    the top-level ports the event plan drives; its counters and observations are
    top-level outputs, so a run reports what the peer really did.
    """
    writer.add("")
    writer.add(f"  // Peer {peer.peer_id} ({peer.module}) bound to "
               f"{peer.instance_id}.{peer.endpoint_id} by its declared roles "
               f"{', '.join(f'{role}:{direction}' for role, direction in peer.roles)}.")
    writer.add(f"  //   {peer.reason}")
    for item in peer.parameters:
        writer.add(f"  //   parameter {item.name}={item.value}: {item.constraint}; {item.basis}")
    for item in peer.requirements:
        writer.add(f"  //   requires {item.component_parameter}={item.value}"
                   f" (>= {item.minimum}): {item.rationale}")
    for slot in peer.slots:
        ports = ", ".join(f"{signal.peer_port}<-{signal.top_port}" for signal in slot.signals)
        writer.add(f"  //   slot {slot.slot} ({slot.kind}, payload {slot.width} bits, "
                   f"min gap {slot.minimum_gap_cycles} cycles): {ports}")
    parameter_text = ", ".join(f".{item.name}({item.value})" for item in peer.parameters)
    writer.add(f"  {peer.module} #({parameter_text}")
    writer.add(f"  ) {peer.instance} (")
    connections = ["    .clk_i(clk_i), .rst_ni(rst_ni)"]
    for item in peer.bindings:
        # The component-side net is the plan's role binding, not a guessed name.
        connections.append(f"    .{item.peer_port}({_signal(peer.instance_id, item.component_port)})")
    for slot in peer.slots:
        for signal in slot.signals:
            connections.append(f"    .{signal.peer_port}({signal.top_port})")
    observed = {item.peer_port for item in peer.observations}
    for item in peer.observations:
        connections.append(f"    .{item.peer_port}({item.top_port})")
    # Every remaining output is deliberately left open: it is not part of the
    # plan's declared observation set, and an unconnected output never drives.
    writer.add(",\n".join(connections))
    writer.add("  );")
    writer.add(f"  // {peer.instance_id}.{peer.endpoint_id}: {len(peer.bindings)} role(s) bound, "
               f"{len(observed)} observation(s) exported, "
               f"{sum(1 for item in peer.observations if item.counter)} counter(s).")


def _render_peripheral(writer: _Writer, instance: InstanceComposition,
                       target_record: Mapping[str, object], index: int,
                       roles: Mapping[str, str]) -> None:
    adapter = target_record["resolved_adapter"]
    assert isinstance(adapter, Mapping)
    identifier = instance.instance_id
    writer.add("")
    writer.add(f"  // {identifier}: {instance.top_module} behind {adapter['rtl_module']} "
               f"({target_record['protocol'][0]}{target_record['protocol'][1]}), window "
               f"0x{int(target_record['window']['base']):08x}.")  # type: ignore[index]
    parameters = ", ".join(
        f".{item['name']}({_literal(item['value'])})" for item in adapter["parameters"])
    reset_port = str(adapter["reset"]["port"])
    reset_expression = "~rst_ni" if str(adapter["reset"]["polarity"]) == "active_high" \
        else "rst_ni"
    writer.add(f"  {adapter['rtl_module']} #({parameters}) u_{identifier}_adapter (")
    writer.add(f"    .clk(clk_i), .{reset_port}({reset_expression}),")
    writer.add(f"    .req_valid(t_req_valid[{index}]), .req_ready(t_req_ready[{index}]),")
    writer.add(f"    .write(t_write[{index}]), .addr(t_addr[{index}]), "
               f".wdata(t_wdata[{index}]), .be(t_be[{index}]),")
    writer.add(f"    .rsp_valid(t_rsp_valid[{index}]), .rsp_ready(t_rsp_ready[{index}]),")
    writer.add(f"    .rdata(t_rdata[{index}]), .error(t_error[{index}]),")
    role_connections = [f"    .{item['port']}({_signal(identifier, str(item['role']))})"
                        for item in adapter["target_side_ports"]]
    role_connections += [f"    .{item['port']}()" for item in adapter.get("unconnected_outputs", [])]
    writer.add(",\n".join(role_connections))
    writer.add("  );")
    writer.add("")
    _render_component(writer, instance, roles)


def _render_interrupts(writer: _Writer, plan: CompositionPlan) -> None:
    document = plan.interrupt_document
    controller = document["controller"]
    cpu_entry = document.get("cpu_entry")
    writer.add("")
    if not controller["present"]:
        writer.add("  // No interrupt source is declared, so no controller exists.  The CPU")
        writer.add("  // entry is held at its inactive level; the plan records the gap.")
        if cpu_entry is not None:
            value = "1'b0" if cpu_entry["polarity"] == "active_high" else "1'b1"
            signal = _signal(str(cpu_entry["instance_id"]), str(cpu_entry["port"]))
            writer.add(f"  //   entry net {signal} is held inactive by the constant "
                       f"connection in the component instantiation.")
            writer.add(f"  localparam logic {signal}_inactive = {value};")
        return
    sources = sorted(document["sources"], key=lambda item: int(item["source_id"]))
    converters = [item for item in sources
                  if str((item.get("normalizer") or {}).get("kind", "direct")) == "edge_detect"]
    writer.add(f"  // Interrupt sources: {len(sources)} normalized level inputs; source id k+1")
    writer.add("  // is controller bit k, listed most significant id first.  Polarity")
    writer.add("  // normalization is recorded per source and visible in the expression.")
    if converters:
        writer.add(f"  // {len(converters)} of them declare a held edge-shaped condition, so")
        writer.add("  // they pass through soc_irq_edge_detect first.  Polarity inversion happens")
        writer.add("  // BEFORE the detector, so the detector always sees an active-high signal")
        writer.add("  // whose idle level is 0 and emits one event per declared edge.")
    writer.add("  logic irq_notify;")
    expressions: list[str] = []
    for item in reversed(sources):
        source = _signal(str(item["instance_id"]), str(item["port"]))
        if int(item["bit"]) != 0:
            source = f"{source}[{int(item['bit'])}]"
        if item["polarity_inversion"]:
            source = f"~{source}"
        normalizer = item.get("normalizer") or {}
        if str(normalizer.get("kind", "direct")) == "edge_detect":
            net = f"irq_src_{int(item['source_id'])}"
            writer.add(f"  logic {net};")
            writer.add(f"  {normalizer.get('module', 'soc_irq_edge_detect')} #(")
            writer.add(f"      .EDGE({int(normalizer['edge_parameter'])}), "
                       f".PULSE_CYCLES({int(normalizer['pulse_cycles'])}), "
                       f".RESET_LEVEL({int(normalizer['reset_level'])})) u_{net} (")
            writer.add(f"    .clk_i(clk_i), .rst_ni(rst_ni), .raw_i({source}), .irq_o({net})")
            writer.add("  );")
            source = net
            writer.add(f"  //   source id {int(item['source_id'])}: "
                       f"{item['instance_id']}.{item['port']}[{int(item['bit'])}] "
                       f"({item['polarity']}, {item['trigger']}) -> {net} -> "
                       f"controller bit {int(item['controller_bit'])}")
        else:
            writer.add(f"  //   source id {int(item['source_id'])}: "
                       f"{item['instance_id']}.{item['port']}[{int(item['bit'])}] "
                       f"({item['polarity']}, {item['trigger']}) -> "
                       f"controller bit {int(item['controller_bit'])}")
        expressions.append(source)
    source_vector = expressions[0] if len(expressions) == 1 \
        else "{" + ", ".join(expressions) + "}"
    target_index = _target_index(plan.plan["fabric"], f"{controller['instance_id']}_win")
    parameters = controller["parameters"]
    latch_literal = str(controller.get("latch_mask_literal", ""))
    if latch_literal:
        writer.add("")
        writer.add("  // LATCH_MASK bit k marks controller bit k (source id k+1) as latched:")
        writer.add("  // its pending bit is set-dominant and cleared only by CLAIM, because the")
        writer.add("  // source declares a moment (a bounded pulse, possibly the output of")
        writer.add("  // soc_irq_edge_detect) rather than a state.  Every other source follows")
        writer.add("  // its own input level.")
        writer.add(f"  //   latched source ids: "
                   f"{controller.get('latched_source_ids') or 'none'}")
    writer.add("")
    writer.add(f"  {controller['module']} #(.NUM_SOURCES({int(parameters['NUM_SOURCES'])}),")
    writer.add(f"      .ADDRESS_WIDTH({int(parameters['ADDRESS_WIDTH'])}),")
    writer.add(f"      .LATCH_MASK({latch_literal or '1\'b0'})) u_irq_controller (")
    writer.add(f"    .clk_i(clk_i), .rst_ni(rst_ni), .source_i({source_vector}),")
    writer.add("    .irq_o(irq_notify),")
    writer.add(f"    .req_valid_i(t_req_valid[{target_index}]), "
               f".req_ready_o(t_req_ready[{target_index}]),")
    local_width = int(parameters["ADDRESS_WIDTH"])
    writer.add(f"    // The controller decodes a window-local offset; the low "
               f"{local_width} address bits are the proven lossless slice.")
    writer.add(f"    .req_write_i(t_write[{target_index}]), "
               f".req_addr_i(t_addr[{target_index}][{local_width - 1}:0]),")
    writer.add(f"    .req_wdata_i(t_wdata[{target_index}]), .req_be_i(t_be[{target_index}]),")
    writer.add(f"    .rsp_valid_o(t_rsp_valid[{target_index}]), "
               f".rsp_ready_i(t_rsp_ready[{target_index}]),")
    writer.add(f"    .rsp_rdata_o(t_rdata[{target_index}]), .rsp_error_o(t_error[{target_index}])")
    writer.add("  );")
    if cpu_entry is not None:
        writer.add(f"  // CPU entry {cpu_entry['endpoint_id']}:{cpu_entry['role']} "
                   f"({cpu_entry['semantics']}, {cpu_entry['polarity']}) is connected "
                   f"directly at the component instantiation.")


def render_composition(plan: CompositionPlan) -> dict[str, str]:
    """Return the generated file set for one composition plan."""
    if not isinstance(plan, CompositionPlan):
        _error("composition-plan-required")
    return {"myfuzz_soc_top.sv": _render_top(plan)}


def _declared_component_sources(instance: object) -> tuple[str, ...]:
    """The component's published source closure.

    A real CPU is a multi-file closure with package ordering and include roots;
    publishing only the file that declares the top module would make the
    published source list unusable for elaboration (and therefore for the
    independent audit).
    """
    profile = instance.profile  # type: ignore[attr-defined]
    root = profile.source.source_root
    facts = instance.binding.facts
    # A closure declared as a filelist publishes no explicit file list; the
    # elaboration's own record of what it read is then the only complete answer
    # (falling back to the files that declare ports would publish one file of a
    # 225-file closure and make the audit's re-elaboration impossible).
    files = (tuple(profile.source.files) or tuple(getattr(facts, "files", ()))
             or tuple(sorted({port.source_file for port in facts.ports})))
    # A declared *filelist* is walked (and hashed) as part of the closure, but it
    # is not an HDL compilation unit: publishing core/Flist.cva6 into the
    # compiler's source list makes the frontend parse it as SystemVerilog.  Only
    # the HDL units the elaboration actually reads are published, which is the
    # same rule the profile's own source crawler applies.
    from pathlib import Path as _Path

    from myfuzz.scripts.source_only_frontend import HDL_SUFFIXES

    return tuple(f"{root}/{name}" for name in files
                 if _Path(name).suffix in HDL_SUFFIXES)


def source_list(plan: CompositionPlan) -> list[dict[str, str]]:
    """Every file the generated top needs, with the role it plays."""
    records: list[dict[str, str]] = []

    def add(path: object, role: str, owner: str) -> None:
        if not isinstance(path, str) or not path:
            return
        if any(item["path"] == path and item["role"] == role for item in records):
            return
        records.append({"path": path, "role": role, "owner": owner})

    for path in plan.plan["fabric"]["rtl"]["sources"]:
        add(path, "soc_fabric", "soc_fabric")
    if any(entry.disposition == "fuzz"
           for instance in plan.instances for entry in instance.dispositions):
        add(DRIVER_SOURCE, "special_input_driver", "soc_top")
    if plan.synthetic:
        # The synthetic master is rendered from the plan's own record, so the
        # source the plan names is the one the closure must publish.
        add(str(plan.synthetic.get("source", "")), "synthetic_master",
            str(plan.synthetic.get("instance_id", "soc_top")))
    for peer in plan.peers:
        # A peer model is published the same way: the plan names the module and
        # the source, and the closure must contain the file it will elaborate.
        add(peer.source, "peer_model", peer.instance_id)
    if plan.interrupt_plan.present:
        add(plan.interrupt_plan.rtl_source, "interrupt_controller",
            str(plan.interrupt_plan.controller_instance_id))
        # An edge-detected source needs its converter in the closure too; the
        # module is named by the plan, so the published source is the one the
        # rendered instance actually elaborates.
        for item in plan.interrupt_plan.sources:
            if str(item.normalizer.get("kind", "direct")) == "edge_detect":
                add(str(item.normalizer.get("source", "")), "interrupt_normalizer",
                    str(item.normalizer.get("module", "")))
                break
    for route in plan.plan["processor_execution"]["routes"]:
        add(route.get("rtl_source"), "cpu_adapter", "cpu")
    for instance in plan.instances:
        for path in _declared_component_sources(instance):
            add(path, "component_source", instance.instance_id)
        for root in instance.profile.source.include_roots:
            records.append({"path": f"{instance.profile.source.source_root}/{root}",
                            "role": "include_root", "owner": instance.instance_id})
    for target in plan.target_records:
        if "instance_id" in target:
            instance = plan.instance(str(target["instance_id"]))
            for path in _declared_component_sources(instance):
                add(path, "component_source", instance.instance_id)
            adapter = target.get("resolved_adapter")
            if isinstance(adapter, Mapping):
                add(adapter.get("rtl_source"), "target_adapter", instance.instance_id)
    for target in plan.target_records:
        if "instance_id" not in target:
            add(MEMORY_MODEL_SOURCE, "memory_model", str(target["component_id"]))
    return records


__all__ = [
    "RENDER_SCHEMA",
    "SYSTEM_SOURCES",
    "TOP_MODULE",
    "SocRenderError",
    "render_composition",
    "source_list",
]
