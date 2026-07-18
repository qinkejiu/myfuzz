"""RawBits v4 verification SoC emission without changing the v2 compatibility path."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .axi_lite_fabric_v4 import AxiLiteFabricV4Capability, emit_axi_lite_fabric_v4
from .contracts import SoCIRV2
from .generated_soc_v2 import EmittedSocIRV2, SocExternalPort, emit_soc_ir_v2
from .control_plane import GeneratedControlPlane
from .input_model import InputValidationError


@dataclass(frozen=True)
class EmittedSocIRV4:
    module_name: str
    rtl: str
    fabric_slots: tuple[str, ...]
    address_windows: tuple[tuple[str, int, int, str], ...]
    external_port_specs: tuple[SocExternalPort, ...]
    soc_digest: str
    fabric_capability: AxiLiteFabricV4Capability
    schema: str = "myfuzz.generated-soc/v4"


_MASTER_SIGNALS = {
    "awvalid": ("input", 1), "awready": ("output", 1), "awaddr": ("input", None),
    "wvalid": ("input", 1), "wready": ("output", 1), "wdata": ("input", 32),
    "wstrb": ("input", 4), "bvalid": ("output", 1), "bready": ("input", 1),
    "bresp": ("output", 2), "arvalid": ("input", 1), "arready": ("output", 1),
    "araddr": ("input", None), "rvalid": ("output", 1), "rready": ("input", 1),
    "rdata": ("output", 32), "rresp": ("output", 2),
}


def emit_soc_ir_v4(
    ir: SoCIRV2,
    *,
    module_name: str = "myfuzz_generated_soc_v4",
    aw_depth: int = 4,
    w_depth: int = 4,
    ar_depth: int = 4,
    write_reorder_depth: int = 4,
    read_reorder_depth: int = 4,
    control_plane: GeneratedControlPlane | None = None,
    rom_install_backend: dict[str, object] | None = None,
    boot_rom_words: int | None = None,
    boot_rom_load_base: int | None = None,
) -> EmittedSocIRV4:
    """Emit a v4 SoC with testcase-locked CPU/trace ownership of one master port."""
    base = emit_soc_ir_v2(
        ir, module_name=module_name, control_plane=control_plane,
        rom_install_backend=rom_install_backend, boot_rom_words=boot_rom_words,
        boot_rom_load_base=boot_rom_load_base,
    )
    initiators = [item for item in ir.endpoints if item["protocol"] == "axi_lite" and item["role"] == "initiator"]
    if len(initiators) != 1:
        raise InputValidationError("v4 verification SoC requires exactly one AXI-Lite CPU initiator")
    initiator = initiators[0]
    semantics = {str(item["semantic"]) for item in initiator["signals"]}
    awprot_present = "axi_lite.awprot" in semantics
    arprot_present = "axi_lite.arprot" in semantics
    target_prot = {
        str(item["semantic"])
        for endpoint in ir.endpoints
        if endpoint["role"] == "target"
        for item in endpoint["signals"]
    }
    if "axi_lite.awprot" in target_prot and not awprot_present:
        raise InputValidationError("target exposes AWPROT but the CPU initiator does not")
    if "axi_lite.arprot" in target_prot and not arprot_present:
        raise InputValidationError("target exposes ARPROT but the CPU initiator does not")
    capability = AxiLiteFabricV4Capability(
        address_width=max(32, max(base_value + size for _name, base_value, size, _protocol in base.address_windows).bit_length()),
        data_width=32,
        slave_count=len(base.address_windows),
        bases=tuple(item[1] for item in base.address_windows),
        sizes=tuple(item[2] for item in base.address_windows),
        aw_depth=aw_depth, w_depth=w_depth, ar_depth=ar_depth,
        write_reorder_depth=write_reorder_depth,
        read_reorder_depth=read_reorder_depth,
        awprot_present=awprot_present,
        arprot_present=arprot_present,
    )
    rtl = _replace_fabric(base.rtl, module_name, capability)
    rtl = _add_master_boundary(rtl, ir, initiator, module_name, capability)
    signals = dict(_MASTER_SIGNALS)
    if capability.awprot_present:
        signals["awprot"] = ("input", 3)
    if capability.arprot_present:
        signals["arprot"] = ("input", 3)
    trace_specs = tuple(
        SocExternalPort(f"trace_{name}", direction, capability.address_width if width is None else width, "verification_master")
        for name, (direction, width) in signals.items()
    ) + (
        SocExternalPort("master_snapshot", "output", 256, "verification_master"),
        SocExternalPort("infrastructure_reset", "input", 1, "verification_master"),
        SocExternalPort("select_trace", "input", 1, "verification_master"),
        SocExternalPort("cpu_execute", "input", 1, "verification_master"),
        SocExternalPort("cpu_ready", "output", 1, "verification_master"),
        SocExternalPort("master_locked", "output", 1, "verification_master"),
        SocExternalPort("trace_selected", "output", 1, "verification_master"),
    )
    return EmittedSocIRV4(
        module_name, rtl, base.fabric_slots, base.address_windows,
        base.external_port_specs + trace_specs, base.soc_digest, capability,
    )


def _replace_fabric(rtl: str, module_name: str, capability: AxiLiteFabricV4Capability) -> str:
    fabric_name = f"{module_name}_fabric"
    start = rtl.rfind(f"module {fabric_name} ")
    if start < 0:
        raise InputValidationError("generated v2 SoC fabric module was not found")
    end = rtl.find("endmodule\n", start)
    if end < 0:
        raise InputValidationError("generated v2 SoC fabric module is unterminated")
    end += len("endmodule\n")
    return rtl[:start] + emit_axi_lite_fabric_v4(capability, fabric_name) + rtl[end:]


def _add_master_boundary(
    rtl: str, ir: SoCIRV2, initiator, module_name: str,
    capability: AxiLiteFabricV4Capability,
) -> str:
    address_width = capability.address_width
    port_lines = [
        "  input logic infrastructure_reset", "  input logic select_trace",
        "  input logic cpu_execute", "  output logic cpu_ready",
        "  output logic master_locked", "  output logic trace_selected",
        "  output logic [255:0] master_snapshot",
    ]
    signals = dict(_MASTER_SIGNALS)
    if capability.awprot_present:
        signals["awprot"] = ("input", 3)
    if capability.arprot_present:
        signals["arprot"] = ("input", 3)
    for name, (direction, width) in signals.items():
        actual_width = address_width if width is None else width
        vector = "" if actual_width == 1 else f"[{actual_width-1}:0] "
        port_lines.append(f"  {direction} logic {vector}trace_{name}")
    close = rtl.find("\n);")
    if close < 0:
        raise InputValidationError("generated v2 SoC top port list was not found")
    rtl = rtl[:close] + ",\n" + ",\n".join(port_lines) + rtl[close:]

    instance = str(initiator["instance_id"])
    marker = f" i_{_safe(instance)}(\n"
    marker_at = rtl.find(marker)
    if marker_at < 0:
        raise InputValidationError("generated CPU instance was not found")
    block_start = rtl.rfind("\n", 0, marker_at) + 1
    block_end = rtl.find("\n  );", marker_at)
    if block_end < 0:
        raise InputValidationError("generated CPU instance is unterminated")
    block_end += len("\n  );")
    block = rtl[block_start:block_end]
    cpu_bindings = [item for item in ir.port_bindings if str(item["instance_id"]) == instance]
    execution_reset = next((
        item for item in cpu_bindings
        if str(item.get("semantic")) == "cpu_execution_reset_active_high"
    ), None)
    execution_reset_expression = None
    for binding in cpu_bindings:
        semantic = str(binding.get("semantic", ""))
        suffix = semantic.rsplit(".", 1)[-1]
        if semantic.startswith("axi_lite.") and suffix in signals:
            physical = str(binding["physical_port"])
            block = re.sub(
                rf"\.{re.escape(physical)}\([^\n]*\)",
                f".{physical}(cpu_m_{suffix})",
                block,
                count=1,
            )
        if semantic in {"reset_active_low", "resetn"} or semantic.endswith(".reset_active_low"):
            physical = str(binding["physical_port"])
            replacement = "cpu_infrastructure_resetn" if execution_reset is not None else "cpu_resetn"
            block = _replace_port_connection(block, physical, replacement)
        if semantic in {"reset_active_high", "reset"} or semantic.endswith(".reset_active_high"):
            physical = str(binding["physical_port"])
            replacement = "cpu_infrastructure_reset" if execution_reset is not None else "cpu_reset"
            block = _replace_port_connection(block, physical, replacement)
        if semantic == "cpu_execution_reset_active_high":
            physical = str(binding["physical_port"])
            match = re.search(rf"\.{re.escape(physical)}\(([^\n]*)\)", block)
            if match is None:
                raise InputValidationError("generated CPU execution reset binding was not found")
            execution_reset_expression = match.group(1)
            block = block[:match.start()] + f".{physical}(cpu_execution_reset)" + block[match.end():]
    rtl = rtl[:block_start] + block + rtl[block_end:]

    snapshot_awprot = "m_awprot" if capability.awprot_present else "3'd0"
    snapshot_arprot = "m_arprot" if capability.arprot_present else "3'd0"
    declarations = [
        f"  wire [{address_width-1}:0] cpu_m_awaddr,cpu_m_araddr; wire [31:0] cpu_m_wdata,cpu_m_rdata; wire [3:0] cpu_m_wstrb; wire [1:0] cpu_m_bresp,cpu_m_rresp;",
        "  wire cpu_m_awvalid,cpu_m_awready,cpu_m_wvalid,cpu_m_wready,cpu_m_bvalid,cpu_m_bready,cpu_m_arvalid,cpu_m_arready,cpu_m_rvalid,cpu_m_rready;",
        "  wire cpu_infrastructure_resetn=resetn&&!trace_selected; wire cpu_infrastructure_reset=!cpu_infrastructure_resetn;",
        "  wire cpu_resetn=cpu_infrastructure_resetn&&cpu_execute; wire cpu_reset=!cpu_resetn;",
        "  always_ff @(posedge clk) begin if(infrastructure_reset) begin master_locked<=1'b0;trace_selected<=1'b0;end else if(!master_locked) begin master_locked<=1'b1;trace_selected<=select_trace;end end",
        "  assign m_awaddr=trace_selected?trace_awaddr:cpu_m_awaddr; assign m_awvalid=trace_selected?trace_awvalid:cpu_m_awvalid; assign cpu_m_awready=!trace_selected&&m_awready; assign trace_awready=trace_selected&&m_awready;",
        "  assign m_wdata=trace_selected?trace_wdata:cpu_m_wdata; assign m_wstrb=trace_selected?trace_wstrb:cpu_m_wstrb; assign m_wvalid=trace_selected?trace_wvalid:cpu_m_wvalid; assign cpu_m_wready=!trace_selected&&m_wready; assign trace_wready=trace_selected&&m_wready;",
        "  assign cpu_m_bvalid=!trace_selected&&m_bvalid; assign cpu_m_bresp=m_bresp; assign trace_bvalid=trace_selected&&m_bvalid; assign trace_bresp=m_bresp; assign m_bready=trace_selected?trace_bready:cpu_m_bready;",
        "  assign m_araddr=trace_selected?trace_araddr:cpu_m_araddr; assign m_arvalid=trace_selected?trace_arvalid:cpu_m_arvalid; assign cpu_m_arready=!trace_selected&&m_arready; assign trace_arready=trace_selected&&m_arready;",
        "  assign cpu_m_rvalid=!trace_selected&&m_rvalid; assign cpu_m_rdata=m_rdata; assign cpu_m_rresp=m_rresp; assign trace_rvalid=trace_selected&&m_rvalid; assign trace_rdata=m_rdata; assign trace_rresp=m_rresp; assign m_rready=trace_selected?trace_rready:cpu_m_rready;",
        f"  assign master_snapshot={{resetn,m_awvalid,m_awready,m_awaddr,{snapshot_awprot},m_wvalid,m_wready,m_wdata,m_wstrb,m_bvalid,m_bready,m_bresp,m_arvalid,m_arready,m_araddr,{snapshot_arprot},m_rvalid,m_rready,m_rdata,m_rresp}};",
    ]
    if execution_reset_expression is None:
        declarations.insert(3, "  assign cpu_ready=cpu_resetn;")
    else:
        declarations.insert(
            3,
            f"  wire cpu_execution_reset=({execution_reset_expression})||!cpu_execute; assign cpu_ready=cpu_infrastructure_resetn&&cpu_execute&&!cpu_execution_reset;",
        )
    if capability.awprot_present:
        declarations[0] += " wire [2:0] cpu_m_awprot;"
        declarations.insert(1, f"  wire [2:0] m_awprot; wire [{capability.slave_count-1}:0][2:0] s_awprot;")
        declarations.append("  assign m_awprot=trace_selected?trace_awprot:cpu_m_awprot;")
    if capability.arprot_present:
        declarations[0] += " wire [2:0] cpu_m_arprot;"
        declarations.insert(1, f"  wire [{capability.slave_count-1}:0][2:0] s_arprot; wire [2:0] m_arprot;")
        declarations.append("  assign m_arprot=trace_selected?trace_arprot:cpu_m_arprot;")
    fabric_marker = f"  {module_name}_fabric i_fabric("
    at = rtl.find(fabric_marker)
    if at < 0:
        raise InputValidationError("generated fabric instance was not found")
    fabric_block_end = rtl.find("\n  );", at)
    if fabric_block_end < 0:
        raise InputValidationError("generated v4 fabric instance is unterminated")
    fabric_block = rtl[at:fabric_block_end]
    if capability.awprot_present:
        fabric_block = fabric_block.replace(".m_awaddr(m_awaddr)", ".m_awprot(m_awprot),.s_awprot(s_awprot),.m_awaddr(m_awaddr)")
    if capability.arprot_present:
        fabric_block = fabric_block.replace(".m_araddr(m_araddr)", ".m_arprot(m_arprot),.s_arprot(s_arprot),.m_araddr(m_araddr)")
    rtl = rtl[:at] + "\n".join(declarations) + "\n" + fabric_block + rtl[fabric_block_end:]
    return _wire_target_protection(rtl, ir, capability)


def _replace_port_connection(block: str, physical_port: str, expression: str) -> str:
    token = f".{physical_port}("
    start = block.find(token)
    if start < 0:
        raise InputValidationError(
            f"generated CPU port binding was not found: {physical_port}"
        )
    depth = 1
    cursor = start + len(token)
    while cursor < len(block) and depth:
        if block[cursor] == "(":
            depth += 1
        elif block[cursor] == ")":
            depth -= 1
        cursor += 1
    if depth:
        raise InputValidationError(
            f"generated CPU port binding is unterminated: {physical_port}"
        )
    return block[:start] + f".{physical_port}({expression})" + block[cursor:]


def _wire_target_protection(rtl: str, ir: SoCIRV2, capability: AxiLiteFabricV4Capability) -> str:
    if not (capability.awprot_present or capability.arprot_present):
        return rtl
    ordered_views = sorted(
        (item for item in ir.address_views
         if any(str(endpoint["instance_id"]) == str(item["instance_id"]) and endpoint["role"] == "target"
                for endpoint in ir.endpoints)),
        key=lambda item: str(item["instance_id"]),
    )
    windows = {str(item["instance_id"]): index for index, item in enumerate(ordered_views)}
    for endpoint in ir.endpoints:
        if endpoint["role"] != "target":
            continue
        instance = str(endpoint["instance_id"])
        marker = f" i_{_safe(instance)}(\n"
        marker_at = rtl.find(marker)
        if marker_at < 0:
            continue
        block_start = rtl.rfind("\n", 0, marker_at) + 1
        block_end = rtl.find("\n  );", marker_at)
        if block_end < 0:
            continue
        block = rtl[block_start:block_end]
        slot = windows.get(instance)
        if slot is None:
            continue
        physical = {str(item["semantic"]): str(item["physical_port"]) for item in endpoint["signals"]}
        replacements = []
        if capability.awprot_present and "axi_lite.awprot" in physical:
            replacements.append((physical["axi_lite.awprot"], f"s_awprot[{slot}]"))
        if capability.arprot_present and "axi_lite.arprot" in physical:
            replacements.append((physical["axi_lite.arprot"], f"s_arprot[{slot}]"))
        if replacements:
            for port, signal in replacements:
                block, replaced = re.subn(
                    rf"\.{re.escape(port)}\([^\n)]*\)",
                    f".{port}({signal})",
                    block,
                    count=1,
                )
                if replaced != 1:
                    raise InputValidationError(
                        f"target protection port {instance}.{port} was not emitted exactly once"
                    )
            rtl = rtl[:block_start] + block + rtl[block_end:]
    return rtl


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)
