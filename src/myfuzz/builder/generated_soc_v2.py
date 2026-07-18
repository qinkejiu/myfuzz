"""Generic SoCIR v2 consumer for one AXI-Lite CPU master."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .apb import ApbDecoderConfig, emit_apb_decoder, emit_axi_lite_to_apb_bridge
from .axi_lite import AxiLiteFabricConfig, emit_axi_lite_fabric
from .contracts import SoCIRV2
from .control_mailbox import ControlMailboxABI, build_control_mailbox_abi, emit_control_mailbox
from .control_plane import GeneratedControlPlane
from .input_model import InputValidationError
from .interrupt_mapper import emit_interrupt_mapper
from .reset_controller import emit_reset_controller
from .service_rtl import emit_system_service_target


@dataclass(frozen=True)
class SocExternalPort:
    name: str
    direction: str
    width: int
    kind: str = "boundary"
    selection_index: int | None = None
    action: str = ""


@dataclass(frozen=True)
class EmittedSocIRV2:
    module_name: str
    rtl: str
    fabric_slots: tuple[str, ...]
    address_windows: tuple[tuple[str, int, int, str], ...]
    external_ports: tuple[str, ...]
    soc_digest: str
    external_port_specs: tuple[SocExternalPort, ...]


def emit_soc_ir_v2(
    ir: SoCIRV2, *, module_name: str = "myfuzz_generated_soc_v2",
    control_plane: GeneratedControlPlane | None = None,
    rom_install_backend: Mapping[str, object] | None = None,
    boot_rom_words: int | None = None,
    boot_rom_load_base: int | None = None,
) -> EmittedSocIRV2:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("SoCIR v2 module_name must be a Verilog identifier")
    modules = {str(item["logical_id"]): item for item in ir.logical_modules}
    instances = {str(item["instance_id"]): item for item in ir.instances}
    bindings = tuple(ir.port_bindings)
    endpoints = tuple(ir.endpoints)
    by_endpoint = {str(item["endpoint_id"]): item for item in endpoints}
    reset_domains = tuple(ir.reset_domains)
    reset_domain_count = max(1, len(reset_domains))
    reset_select_width = max(1, (reset_domain_count - 1).bit_length())
    reset_signals = _reset_signals(ir, modules)
    protected_reset_mask = _protected_reset_mask(ir, modules)
    initiators = [item for item in endpoints if item["role"] == "initiator" and item["protocol"] == "axi_lite"]
    if len(initiators) != 1:
        raise InputValidationError(f"generated SoC requires one AXI-Lite initiator, found {len(initiators)}")
    targets = [item for item in endpoints if item["role"] == "target" and item["protocol"] in {"axi_lite", "apb3", "apb4"}]
    if not targets:
        raise InputValidationError("generated SoC requires at least one protocol target")
    views = {str(item["instance_id"]): item for item in ir.address_views}
    missing = sorted(set(str(item["instance_id"]) for item in targets) - set(views))
    if missing:
        raise InputValidationError("missing address view(s): " + ", ".join(missing))
    windows = tuple(sorted((str(item["instance_id"]), int(views[str(item["instance_id"])]["global_base"]),
                            int(views[str(item["instance_id"])]["size"]), str(item["protocol"]))
                           for item in targets))
    address_width = max(32, max((base + size).bit_length() for _name, base, size, _protocol in windows))
    slots = tuple(name for name, _base, _size, _protocol in windows)
    fabric_name = f"{module_name}_fabric"
    fabric = emit_axi_lite_fabric(AxiLiteFabricConfig(
        address_width, 32, len(windows), tuple(item[1] for item in windows), tuple(item[2] for item in windows),
    ), fabric_name)
    all_ports = _port_bindings(bindings)
    rom_loader = _rom_loader_plan(
        ir, all_ports, rom_install_backend, boot_rom_words, boot_rom_load_base,
    )
    logical_endpoint = {str(item["endpoint_id"]): item for item in endpoints}
    external = _external_ports(ir)
    mailbox_abi = None
    has_interrupt_mapper = any(str(item.get("kind")) == "interrupt_mapper" for item in ir.service_nodes)
    has_reset_controller = any(str(item.get("kind")) == "reset_controller" for item in ir.service_nodes)
    interrupt_wires, interrupt_signals = _interrupt_wiring(ir, has_interrupt_mapper)
    if control_plane is not None:
        if control_plane.control_ir.soc_digest != ir.digest:
            raise InputValidationError("control plane was not derived from this SoCIR")
        mailbox_abi = build_control_mailbox_abi(control_plane.control_ir, control_plane.layout)
        if not any(str(item.get("kind")) == "control_mailbox" for item in ir.service_nodes):
            raise InputValidationError("control plane requires a generated control_mailbox service")
    port_lines = ["  input logic clk", "  input logic resetn"]
    port_lines.extend(f"  {direction} logic {_vrange(width)}{name}" for name, direction, width in external)
    if mailbox_abi is not None:
        port_lines.extend((
            f"  input logic [{mailbox_abi.raw_width-1}:0] control_raw_bits",
            "  input logic control_start", "  output logic control_accepted",
            "  output logic control_done", "  output logic control_active",
            "  output logic [31:0] control_status", "  output logic [31:0] control_result",
        ))
    if has_interrupt_mapper:
        port_lines.append("  input logic [31:0] external_irq_sources")
    if has_reset_controller:
        port_lines.extend((
            f"  input logic [{reset_select_width-1}:0] reset_domain_select",
            "  input logic reset_domain_start", "  output logic reset_domain_busy",
            "  output logic reset_domain_done", "  output logic reset_domain_error",
            "  output logic [31:0] reset_epoch",
        ))
    has_boot_rom = any(str(item.get("kind")) == "boot_rom" for item in ir.service_nodes)
    module_head = (f"module {module_name} #(parameter BOOT_ROM_HEX_FILE=\"\") ("
                   if has_boot_rom else f"module {module_name} (")
    lines = [module_head, ",\n".join(port_lines), ");"]
    if has_reset_controller:
        lines.append(f"  wire [{reset_domain_count-1}:0] domain_reset_active;")
    lines.extend(interrupt_wires)
    lines.extend(_fabric_wires(len(windows), address_width))
    lines.extend(_rom_loader_wiring(rom_loader))
    lines.append(f"  {fabric_name} i_fabric(")
    lines.append(_fabric_connections())
    lines.append("  );")
    lines.extend(_apb_subsystems(windows))
    lines.extend(_service_instances(ir, windows, mailbox_abi, rom_loader))
    lines.extend(_module_wires_and_instances(
        ir, modules, instances, all_ports, logical_endpoint, windows, external, reset_signals,
        interrupt_signals, rom_loader,
    ))
    lines.append("endmodule")
    boundary_specs = _external_port_specs(ir, external)
    control_specs = () if mailbox_abi is None else (
        SocExternalPort("control_raw_bits", "input", mailbox_abi.raw_width, "control"),
        SocExternalPort("control_start", "input", 1, "control"),
        SocExternalPort("control_accepted", "output", 1, "control"),
        SocExternalPort("control_done", "output", 1, "control"),
        SocExternalPort("control_active", "output", 1, "control"),
        SocExternalPort("control_status", "output", 32, "control"),
        SocExternalPort("control_result", "output", 32, "control"),
    )
    environment_specs = (
        (SocExternalPort("external_irq_sources", "input", 32, "environment"),)
        if has_interrupt_mapper else ()
    )
    if has_reset_controller:
        environment_specs += (
            SocExternalPort("reset_domain_select", "input", reset_select_width, "environment"),
            SocExternalPort("reset_domain_start", "input", 1, "environment"),
            SocExternalPort("reset_domain_busy", "output", 1, "environment"),
            SocExternalPort("reset_domain_done", "output", 1, "environment"),
            SocExternalPort("reset_domain_error", "output", 1, "environment"),
            SocExternalPort("reset_epoch", "output", 32, "environment"),
        )
    specs = boundary_specs + control_specs + environment_specs
    return EmittedSocIRV2(module_name, "\n".join(lines) + "\n" + fabric + "\n" +
                         "\n".join(_backend_modules(ir, windows, mailbox_abi)) + "\n",
                         slots, windows, tuple(item.name for item in specs), ir.digest, specs)


def _port_bindings(bindings):
    result: dict[tuple[str, str], Mapping[str, object]] = {}
    for binding in bindings:
        key = (str(binding["instance_id"]), str(binding["physical_port"]))
        if key in result: raise InputValidationError(f"duplicate port binding {key[0]}.{key[1]}")
        result[key] = binding
    return result


def _external_ports(ir):
    result = []
    for decision in sorted(ir.unknown_port_decisions, key=lambda item: (str(item["instance_id"]), str(item["port"]))):
        key = str(decision["instance_id"]), str(decision["port"])
        action = str(decision["action"])
        if action in {"external_input", "rfuzz_drive", "constrained_random"}:
            result.append((f"ext_{_safe(key[0])}_{_safe(key[1])}", "input", int(decision["width"])))
        elif action == "observe":
            result.append((f"obs_{_safe(key[0])}_{_safe(key[1])}", "output", int(decision["width"])))
        elif action == "tieoff":
            continue
        else:
            raise InputValidationError(f"unsupported generated unknown-port action {action!r}")
    return tuple(result)


def _external_port_specs(ir, external):
    decisions = {
        (str(item["instance_id"]), str(item["port"])): item
        for item in ir.unknown_port_decisions
    }
    input_indices = {
        (str(item["instance_id"]), str(item["port"])): index
        for index, item in enumerate(
            boundary for boundary in ir.external_boundaries
            if str(boundary["direction"]) == "input"
        )
    }
    result = []
    for name, direction, width in external:
        match = None
        for key, decision in decisions.items():
            prefix = "obs" if direction == "output" else "ext"
            if name == f"{prefix}_{_safe(key[0])}_{_safe(key[1])}":
                match = (key, decision)
                break
        if match is None:
            raise InputValidationError(f"generated external port {name} has no unknown-port decision")
        key, decision = match
        result.append(SocExternalPort(
            name, direction, width, "boundary", input_indices.get(key), str(decision["action"]),
        ))
    return tuple(result)


def _fabric_wires(count, width):
    return [
        f"  wire [{width-1}:0] m_awaddr,m_araddr; wire [31:0] m_wdata,m_rdata; wire [3:0] m_wstrb; wire [1:0] m_bresp,m_rresp;",
        "  wire m_awvalid,m_awready,m_wvalid,m_wready,m_bvalid,m_bready,m_arvalid,m_arready,m_rvalid,m_rready;",
        f"  wire [{count-1}:0] s_awvalid,s_awready,s_wvalid,s_wready,s_bvalid,s_bready,s_arvalid,s_arready,s_rvalid,s_rready;",
        f"  wire [{count-1}:0][{width-1}:0] s_awaddr,s_araddr; wire [{count-1}:0][31:0] s_wdata,s_rdata; wire [{count-1}:0][3:0] s_wstrb; wire [{count-1}:0][1:0] s_bresp,s_rresp;",
    ]


def _fabric_connections():
    return """    .aclk(clk),.aresetn(resetn),
    .m_awaddr(m_awaddr),.m_awvalid(m_awvalid),.m_awready(m_awready),.m_wdata(m_wdata),.m_wstrb(m_wstrb),.m_wvalid(m_wvalid),.m_wready(m_wready),
    .m_bresp(m_bresp),.m_bvalid(m_bvalid),.m_bready(m_bready),.m_araddr(m_araddr),.m_arvalid(m_arvalid),.m_arready(m_arready),
    .m_rdata(m_rdata),.m_rresp(m_rresp),.m_rvalid(m_rvalid),.m_rready(m_rready),.s_awvalid(s_awvalid),.s_awaddr(s_awaddr),.s_awready(s_awready),
    .s_wvalid(s_wvalid),.s_wdata(s_wdata),.s_wstrb(s_wstrb),.s_wready(s_wready),.s_bvalid(s_bvalid),.s_bresp(s_bresp),.s_bready(s_bready),
    .s_arvalid(s_arvalid),.s_araddr(s_araddr),.s_arready(s_arready),.s_rvalid(s_rvalid),.s_rdata(s_rdata),.s_rresp(s_rresp),.s_rready(s_rready)"""


def _module_wires_and_instances(
    ir, modules, instances, all_ports, endpoints, windows, external, reset_signals,
    interrupt_signals, rom_loader,
):
    endpoint_by_instance = {key: value for key, value in endpoints.items()}
    out = []; slot_by_instance = {name: index for index, (name, _base, _size, _protocol) in enumerate(windows)}
    external_names = {name for name, _direction, _width in external}
    decisions = {(str(item["instance_id"]), str(item["port"])): item for item in ir.unknown_port_decisions}
    for name, module in sorted(modules.items()):
        if name not in instances: continue
        instance = str(instances[name]["instance_id"]); endpoint_map = {}
        for (owner, physical), binding in all_ports.items():
            if owner != instance: continue
            endpoint_id = binding.get("endpoint_id")
            semantic = str(binding.get("semantic", "")); signal = _signal_for_binding(
                instance, physical, semantic, endpoint_id, slot_by_instance, endpoint_by_instance,
                reset_signals, interrupt_signals, rom_loader,
            )
            if signal is None:
                signal = _external_signal(instance, physical, binding, external_names)
            endpoint_map[physical] = signal
        for (owner, physical), decision in decisions.items():
            if owner != instance or physical in endpoint_map: continue
            endpoint_map[physical] = _unknown_signal(owner, physical, decision, external_names)
        if not endpoint_map: continue
        parameters = module.get("parameters", {})
        module_type = str(module.get("rtl_module") or name)
        head = f"  {module_type}"
        if parameters:
            head += " #(" + ",".join(f".{_safe(str(key))}({_literal(value)})" for key, value in sorted(parameters.items())) + ")"
        out.append(head + f" i_{_safe(instance)}(")
        out.append(",\n".join(f"    .{physical}({signal})" for physical, signal in sorted(endpoint_map.items())))
        out.append("  );")
    return out


def _backend_modules(ir, windows, mailbox_abi):
    # Each APB target receives a real bridge and a one-entry decoder. The
    # decoder remains a separate backend module so a future contiguous APB
    # subsystem can replace this wiring without changing SoCIR.
    result = []
    for index, (name, _base, size, protocol) in enumerate(windows):
        if protocol not in {"apb3", "apb4"}: continue
        bridge_name = f"myfuzz_v2_bridge_{index}"; decoder_name = f"myfuzz_v2_decoder_{index}"
        result.append(emit_axi_lite_to_apb_bridge(module_name=bridge_name))
        result.append(emit_apb_decoder(ApbDecoderConfig(32, 32, (0,), (size,), protocol == "apb4"), decoder_name))
    services = {str(item["node_id"]): item for item in ir.service_nodes}
    for index, (name, _base, size, _protocol) in enumerate(windows):
        service = services.get(name)
        if service is None:
            continue
        if str(service.get("kind")) == "control_mailbox" and mailbox_abi is not None:
            result.append(emit_control_mailbox(mailbox_abi, module_name=f"myfuzz_v2_service_{index}"))
            continue
        if str(service.get("kind")) == "interrupt_mapper":
            result.append(emit_interrupt_mapper(module_name=f"myfuzz_v2_service_{index}"))
            continue
        if str(service.get("kind")) == "reset_controller":
            count = max(1, len(ir.reset_domains))
            result.append(emit_reset_controller(
                module_name=f"myfuzz_v2_service_{index}", domain_count=count,
                protected_mask=_protected_reset_mask(
                    ir, {str(item["logical_id"]): item for item in ir.logical_modules},
                ),
            ))
            continue
        result.append(emit_system_service_target(
            module_name=f"myfuzz_v2_service_{index}", size=size,
            read_only=str(service.get("kind")) == "boot_rom",
        ))
    return result


def _service_instances(ir, windows, mailbox_abi, rom_loader):
    services = {str(item["node_id"]): item for item in ir.service_nodes}
    result = []
    for slot, (name, _base, _size, protocol) in enumerate(windows):
        service = services.get(name)
        if service is None:
            continue
        if protocol != "axi_lite":
            raise InputValidationError(f"generated service {name} requires AXI-Lite")
        mailbox = str(service.get("kind")) == "control_mailbox" and mailbox_abi is not None
        interrupt_mapper = str(service.get("kind")) == "interrupt_mapper"
        reset_controller = str(service.get("kind")) == "reset_controller"
        parameter = " #(.HEX_FILE(BOOT_ROM_HEX_FILE))" if str(service.get("kind")) == "boot_rom" else ""
        control_start = "(control_start&&rom_install_ready)" if rom_loader is not None else "control_start"
        result += [
            f"  myfuzz_v2_service_{slot}{parameter} i_service_{slot}(",
            *( [f"    .raw_bits_i(control_raw_bits),.start_i({control_start}),.accepted_o(control_accepted),",
                "    .done_o(control_done),.active_o(control_active),.status_o(control_status),.result_o(control_result),"]
               if mailbox else [] ),
            *( ["    .irq_sources(external_irq_sources|internal_irq_sources),.cpu_irq(mapped_cpu_irq),"] if interrupt_mapper else [] ),
            *( ["    .request_start(reset_domain_start),.request_domain(reset_domain_select),",
                "    .reset_active(domain_reset_active),.request_busy(reset_domain_busy),",
                "    .request_done(reset_domain_done),.request_error(reset_domain_error),.epoch(reset_epoch),"]
               if reset_controller else [] ),
            f"    .clk(clk),.resetn(resetn),.s_awaddr(s_awaddr[{slot}]),.s_awvalid(s_awvalid[{slot}]),.s_awready(s_awready[{slot}]),",
            f"    .s_wdata(s_wdata[{slot}]),.s_wstrb(s_wstrb[{slot}]),.s_wvalid(s_wvalid[{slot}]),.s_wready(s_wready[{slot}]),",
            f"    .s_bresp(s_bresp[{slot}]),.s_bvalid(s_bvalid[{slot}]),.s_bready(s_bready[{slot}]),",
            f"    .s_araddr(s_araddr[{slot}]),.s_arvalid(s_arvalid[{slot}]),.s_arready(s_arready[{slot}]),",
            f"    .s_rdata(s_rdata[{slot}]),.s_rresp(s_rresp[{slot}]),.s_rvalid(s_rvalid[{slot}]),.s_rready(s_rready[{slot}]));",
        ]
    return result


def _apb_subsystems(windows):
    result = []
    for slot, (_name, _base, _size, protocol) in enumerate(windows):
        if protocol not in {"apb3", "apb4"}: continue
        prefix = f"apb_{slot}"
        result += [
            f"  wire {prefix}_psel,{prefix}_penable,{prefix}_pwrite,{prefix}_pready,{prefix}_pslverr;",
            f"  wire [31:0] {prefix}_paddr,{prefix}_pwdata,{prefix}_prdata; wire [3:0] {prefix}_pstrb;",
            f"  wire [0:0] {prefix}_m_psel,{prefix}_m_penable,{prefix}_m_pwrite,{prefix}_m_pready,{prefix}_m_pslverr;",
            f"  wire [0:0][31:0] {prefix}_m_paddr,{prefix}_m_pwdata,{prefix}_m_prdata; wire [0:0][3:0] {prefix}_m_pstrb;",
            f"  myfuzz_v2_bridge_{slot} i_bridge_{slot}(.clk(clk),.resetn(resetn),",
            f"    .s_awaddr(s_awaddr[{slot}]),.s_awvalid(s_awvalid[{slot}]),.s_awready(s_awready[{slot}]),",
            f"    .s_wdata(s_wdata[{slot}]),.s_wstrb(s_wstrb[{slot}]),.s_wvalid(s_wvalid[{slot}]),.s_wready(s_wready[{slot}]),",
            f"    .s_bresp(s_bresp[{slot}]),.s_bvalid(s_bvalid[{slot}]),.s_bready(s_bready[{slot}]),",
            f"    .s_araddr(s_araddr[{slot}]),.s_arvalid(s_arvalid[{slot}]),.s_arready(s_arready[{slot}]),",
            f"    .s_rdata(s_rdata[{slot}]),.s_rresp(s_rresp[{slot}]),.s_rvalid(s_rvalid[{slot}]),.s_rready(s_rready[{slot}]),",
            f"    .psel({prefix}_psel),.penable({prefix}_penable),.pwrite({prefix}_pwrite),.paddr({prefix}_paddr),.pwdata({prefix}_pwdata),.pstrb({prefix}_pstrb),",
            f"    .pready({prefix}_pready),.prdata({prefix}_prdata),.pslverr({prefix}_pslverr));",
            f"  myfuzz_v2_decoder_{slot} i_decoder_{slot}(.psel({prefix}_psel),.penable({prefix}_penable),.pwrite({prefix}_pwrite),",
            f"    .paddr({prefix}_paddr),.pwdata({prefix}_pwdata),.pstrb({prefix}_pstrb),.pready({prefix}_pready),.prdata({prefix}_prdata),.pslverr({prefix}_pslverr),",
            f"    .m_psel({prefix}_m_psel),.m_penable({prefix}_m_penable),.m_pwrite({prefix}_m_pwrite),.m_paddr({prefix}_m_paddr),",
            f"    .m_pwdata({prefix}_m_pwdata),.m_pstrb({prefix}_m_pstrb),.m_pready({prefix}_m_pready),.m_prdata({prefix}_m_prdata),.m_pslverr({prefix}_m_pslverr));",
        ]
    return result


def _signal_for_binding(
    instance, physical, semantic, endpoint_id, slot_by_instance, endpoint_by_instance,
    reset_signals, interrupt_signals, rom_loader,
):
    if semantic == "clock" or semantic.endswith(".clock"): return "clk"
    if semantic in {"reset_active_low", "resetn"} or semantic.endswith(".reset_active_low"):
        return reset_signals.get(instance, ("resetn", "!resetn"))[0]
    if semantic in {"reset_active_high", "reset"} or semantic.endswith(".reset_active_high"):
        return reset_signals.get(instance, ("resetn", "!resetn"))[1]
    if semantic == "cpu_execution_reset_active_high":
        if rom_loader is None or instance != rom_loader["instance_id"]:
            raise InputValidationError(
                f"{instance}.{physical}: CPU execution reset requires a ROM install backend"
            )
        domain_reset = reset_signals.get(instance, ("resetn", "!resetn"))[1]
        return f"({domain_reset}||!rom_install_ready)"
    if semantic.startswith("rom_loader."):
        if rom_loader is None or instance != rom_loader["instance_id"]:
            raise InputValidationError(f"{instance}.{physical}: ROM loader port has no matching backend")
        return f"rom_loader_{semantic.split('.', 1)[1]}"
    interrupt_signal = interrupt_signals.get((instance, physical))
    if interrupt_signal is not None:
        return interrupt_signal
    if endpoint_id is None: return None
    endpoint = endpoint_by_instance.get(str(endpoint_id)); protocol = str(endpoint["protocol"])
    role = str(endpoint["role"]); suffix = semantic.rsplit(".", 1)[-1]
    if protocol == "axi_lite":
        if role == "initiator": return {"awvalid":"m_awvalid","awready":"m_awready","awaddr":"m_awaddr","wvalid":"m_wvalid","wready":"m_wready","wdata":"m_wdata","wstrb":"m_wstrb","bvalid":"m_bvalid","bready":"m_bready","bresp":"m_bresp","arvalid":"m_arvalid","arready":"m_arready","araddr":"m_araddr","rvalid":"m_rvalid","rready":"m_rready","rdata":"m_rdata","rresp":"m_rresp"}.get(suffix)
        slot = slot_by_instance[instance]
        return {"awvalid":f"s_awvalid[{slot}]","awready":f"s_awready[{slot}]","awaddr":f"s_awaddr[{slot}]","wvalid":f"s_wvalid[{slot}]","wready":f"s_wready[{slot}]","wdata":f"s_wdata[{slot}]","wstrb":f"s_wstrb[{slot}]","bvalid":f"s_bvalid[{slot}]","bready":f"s_bready[{slot}]","bresp":f"s_bresp[{slot}]","arvalid":f"s_arvalid[{slot}]","arready":f"s_arready[{slot}]","araddr":f"s_araddr[{slot}]","rvalid":f"s_rvalid[{slot}]","rready":f"s_rready[{slot}]","rdata":f"s_rdata[{slot}]","rresp":f"s_rresp[{slot}]"}.get(suffix)
    if protocol in {"apb3", "apb4"}:
        slot = slot_by_instance[instance]; prefix = f"apb_{slot}_m_"
        return {"psel":f"{prefix}psel[0]","penable":f"{prefix}penable[0]","pwrite":f"{prefix}pwrite[0]",
                "paddr":f"{prefix}paddr[0]","pwdata":f"{prefix}pwdata[0]","pstrb":f"{prefix}pstrb[0]",
                "pready":f"{prefix}pready[0]","prdata":f"{prefix}prdata[0]","pslverr":f"{prefix}pslverr[0]"}.get(suffix)
    return None


_ROM_LOADER_PORTS = {
    "awvalid": ("input", 1), "awready": ("output", 1), "awaddr": ("input", 32),
    "awid": ("input", 4), "awlen": ("input", 8), "awburst": ("input", 2),
    "wvalid": ("input", 1), "wready": ("output", 1), "wdata": ("input", 32),
    "wstrb": ("input", 4), "wlast": ("input", 1), "bvalid": ("output", 1),
    "bready": ("input", 1), "bresp": ("output", 2), "bid": ("output", 4),
    "arvalid": ("input", 1), "arready": ("output", 1), "araddr": ("input", 32),
    "arid": ("input", 4), "arlen": ("input", 8), "arburst": ("input", 2),
    "rvalid": ("output", 1), "rready": ("input", 1), "rdata": ("output", 32),
    "rresp": ("output", 2), "rid": ("output", 4), "rlast": ("output", 1),
}


def _rom_loader_plan(ir, all_ports, backend, boot_rom_words, boot_rom_load_base):
    backend = {} if backend is None else backend
    kind = str(backend.get("kind", "external_rom"))
    annotated = {
        (instance, str(binding["semantic"]).split(".", 1)[1]): binding
        for (instance, _physical), binding in all_ports.items()
        if str(binding.get("semantic", "")).startswith("rom_loader.")
    }
    if kind == "external_rom":
        if annotated:
            raise InputValidationError("external_rom backend cannot consume rom_loader.* ports")
        return None
    if kind != "pre_reset_tcm_loader":
        raise InputValidationError(f"unsupported ROM install backend {kind!r}")
    if str(backend.get("loader_interface", "")) != "axi4_target_single_beat_32":
        raise InputValidationError("pre-reset TCM loader requires axi4_target_single_beat_32")
    if not isinstance(boot_rom_words, int) or boot_rom_words <= 0:
        raise InputValidationError("pre-reset TCM loader requires a positive boot_rom_words value")
    if not isinstance(boot_rom_load_base, int) or not 0 <= boot_rom_load_base < (1 << 32):
        raise InputValidationError("pre-reset TCM loader requires a 32-bit boot_rom_load_base")
    if boot_rom_load_base % 4:
        raise InputValidationError("pre-reset TCM loader boot_rom_load_base must be word aligned")
    cpu_ids = {
        str(item["logical_id"]) for item in ir.logical_modules if str(item.get("kind")) == "cpu"
    }
    owners = {owner for owner, _semantic in annotated}
    if len(cpu_ids) != 1 or owners != cpu_ids:
        raise InputValidationError("rom_loader.* ports must belong to the generated system's only CPU")
    instance = next(iter(cpu_ids))
    by_semantic = {semantic: binding for (owner, semantic), binding in annotated.items() if owner == instance}
    missing = sorted(set(_ROM_LOADER_PORTS) - set(by_semantic))
    extra = sorted(set(by_semantic) - set(_ROM_LOADER_PORTS))
    if missing or extra:
        details = []
        if missing: details.append("missing " + ", ".join(missing))
        if extra: details.append("unsupported " + ", ".join(extra))
        raise InputValidationError("incomplete rom_loader interface: " + "; ".join(details))
    for semantic, (direction, width) in _ROM_LOADER_PORTS.items():
        binding = by_semantic[semantic]
        if str(binding["direction"]) != direction or int(binding["width"]) != width:
            raise InputValidationError(
                f"rom_loader.{semantic} requires {direction}[{width}], got "
                f"{binding['direction']}[{binding['width']}]"
            )
    execution_resets = [
        binding for (owner, _physical), binding in all_ports.items()
        if owner == instance and str(binding.get("semantic")) == "cpu_execution_reset_active_high"
    ]
    if len(execution_resets) != 1:
        raise InputValidationError("pre-reset TCM loader requires one cpu_execution_reset_active_high port")
    return {"instance_id": instance, "words": boot_rom_words, "load_base": boot_rom_load_base}


def _rom_loader_wiring(plan):
    if plan is None:
        return []
    declarations = []
    for semantic, (_direction, width) in _ROM_LOADER_PORTS.items():
        declarations.append(f"  wire {_vrange(width)}rom_loader_{semantic};")
    declarations.extend((
        "  reg rom_install_start; reg rom_install_ready; reg rom_install_started;",
        "  wire rom_install_busy,rom_install_done,rom_install_error;",
        "  always @(posedge clk or negedge resetn) begin",
        "    if (!resetn) begin rom_install_start<=1'b0; rom_install_ready<=1'b0; rom_install_started<=1'b0; end",
        "    else begin",
        "      rom_install_start<=1'b0;",
        "      if (!rom_install_started) begin rom_install_start<=1'b1; rom_install_started<=1'b1; end",
        "      if (rom_install_done) rom_install_ready<=1'b1;",
        "      if (rom_install_error) rom_install_ready<=1'b0;",
        "    end",
        "  end",
        f"  myfuzz_level1_tcm_loader #(.WORDS({plan['words']}),.LOAD_BASE(32'h{plan['load_base']:08x}),.HEX_FILE(BOOT_ROM_HEX_FILE)) i_rom_loader(",
        "    .clk(clk),.reset(!resetn),.start(rom_install_start),.busy(rom_install_busy),.done(rom_install_done),.error(rom_install_error),",
        "    .awvalid(rom_loader_awvalid),.awready(rom_loader_awready),.awaddr(rom_loader_awaddr),.awid(rom_loader_awid),.awlen(rom_loader_awlen),.awburst(rom_loader_awburst),",
        "    .wvalid(rom_loader_wvalid),.wready(rom_loader_wready),.wdata(rom_loader_wdata),.wstrb(rom_loader_wstrb),.wlast(rom_loader_wlast),",
        "    .bvalid(rom_loader_bvalid),.bready(rom_loader_bready),.bresp(rom_loader_bresp),.bid(rom_loader_bid),",
        "    .arvalid(rom_loader_arvalid),.arready(rom_loader_arready),.araddr(rom_loader_araddr),.arid(rom_loader_arid),.arlen(rom_loader_arlen),.arburst(rom_loader_arburst),",
        "    .rvalid(rom_loader_rvalid),.rready(rom_loader_rready),.rdata(rom_loader_rdata),.rresp(rom_loader_rresp),.rid(rom_loader_rid),.rlast(rom_loader_rlast));",
    ))
    return declarations


def _interrupt_wiring(ir, has_interrupt_mapper):
    edges = tuple(ir.interrupt_edges)
    if edges and not has_interrupt_mapper:
        raise InputValidationError("interrupt edges require the generated interrupt_mapper service")
    if not has_interrupt_mapper:
        return (), {}
    lines = ["  wire [31:0] internal_irq_sources;", "  wire [31:0] mapped_cpu_irq;"]
    signals = {}
    terms = []
    sink_key = None
    for edge in edges:
        source = edge.get("source", {})
        sink = edge.get("sink", {})
        candidate_sink = (str(sink.get("instance_id", "")), str(sink.get("port", "")))
        if not all(candidate_sink):
            raise InputValidationError("interrupt edge has an incomplete sink")
        if int(sink.get("width", 0)) != 32:
            raise InputValidationError("generated interrupt mapper requires a 32-bit sink")
        if sink_key is None:
            sink_key = candidate_sink
            signals[sink_key] = "mapped_cpu_irq"
        elif candidate_sink != sink_key:
            raise InputValidationError("interrupt edges have multiple sinks")
        if str(source.get("kind")) != "internal":
            continue
        key = (str(source.get("instance_id", "")), str(source.get("port", "")))
        width = int(source.get("width", 0))
        offset = int(edge.get("mapper_offset", -1))
        if not all(key) or width <= 0 or offset < 0 or offset + width > 32:
            raise InputValidationError("interrupt edge does not fit the 32-bit mapper")
        if key in signals:
            raise InputValidationError(f"duplicate interrupt source {key[0]}.{key[1]}")
        wire = f"irq_source_{len(terms)}"
        lines.append(f"  wire {_vrange(width)}{wire};")
        signals[key] = wire
        extended = wire if width == 32 else f"{{{{{32-width}{{1'b0}}}},{wire}}}"
        terms.append(f"({extended} << {offset})")
    lines.append("  assign internal_irq_sources = " + (" | ".join(terms) if terms else "32'b0") + ";")
    return tuple(lines), signals


def _reset_signals(ir, modules):
    result = {}
    for index, domain in enumerate(ir.reset_domains):
        for member in domain.get("members", ()):
            result[str(member)] = (
                f"(resetn&&!domain_reset_active[{index}])",
                f"(!resetn||domain_reset_active[{index}])",
            )
    return result


def _protected_reset_mask(ir, modules):
    cpu_ids = {
        logical_id for logical_id, module in modules.items()
        if str(module.get("kind")) == "cpu"
    }
    mask = 0
    for index, domain in enumerate(ir.reset_domains):
        if cpu_ids.intersection(str(member) for member in domain.get("members", ())):
            mask |= 1 << index
    return mask


def _external_signal(instance, physical, binding, external_names):
    prefix = f"ext_{_safe(instance)}_{_safe(physical)}"; observe = f"obs_{_safe(instance)}_{_safe(physical)}"
    if prefix in external_names: return prefix
    if observe in external_names: return observe
    if str(binding["direction"]) == "input": return "'0"
    return observe


def _unknown_signal(instance, physical, decision, external_names):
    action = str(decision["action"]); ext = f"ext_{_safe(instance)}_{_safe(physical)}"; obs = f"obs_{_safe(instance)}_{_safe(physical)}"
    if action in {"external_input", "rfuzz_drive", "constrained_random"} and ext in external_names: return ext
    if action == "observe" and obs in external_names: return obs
    if action == "tieoff":
        text = str(decision.get("result", "")); return "1'b1" if text.endswith(" 1") else "'0"
    raise InputValidationError(f"cannot realize unknown port {instance}.{physical}: {action}")


def _safe(value): return re.sub(r"[^A-Za-z0-9_]", "_", value)
def _vrange(width): return "" if width == 1 else f"[{width-1}:0] "
def _literal(value): return "1'b1" if value is True else "1'b0" if value is False else str(value)
