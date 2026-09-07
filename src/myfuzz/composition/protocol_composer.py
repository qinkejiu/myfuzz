"""Deterministic materialization of the first Ibex protocol composition target."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.protocols.catalog import ProtocolCatalog, load_protocol_catalog

from .ids import canonical_id
from .input_layout import input_layout_document
from .ir import canonical_ir_document, canonical_ir_hash
from .source_crawler import annotate_interfaces
from .protocol_manifest import (
    CompositionComponent,
    ProtocolCompositionManifest,
    load_protocol_composition,
    validate_protocol_composition,
)
from .registry import ComponentRegistry, default_component_registry


_TOP_MODULE = "ibex_protocol_composition_top"
_UPSTREAM_SOURCE_LIST = "third_party/rfuzz/upstream/ibex/sources.f"
_PROTOCOL_SOURCE_ROOT = "src/myfuzz/protocols/rtl"
_FIRST_STAGE_COMPONENT_TYPES = frozenset({"ram", "timer", "gpio", "uart", "spi"})


@dataclass(frozen=True, slots=True)
class _AdapterDefinition:
    kind: str
    bridge_module: str
    target_module: str
    bridge_source: str
    target_source: str


_ADAPTERS: dict[tuple[str, str], _AdapterDefinition] = {
    ("apb", "4"): _AdapterDefinition(
        "apb4",
        "apb4_mmio_bridge",
        "apb4_mmio_target",
        f"{_PROTOCOL_SOURCE_ROOT}/apb4_mmio_bridge.sv",
        f"{_PROTOCOL_SOURCE_ROOT}/apb4_mmio_target.sv",
    ),
    ("axi4-lite", "1"): _AdapterDefinition(
        "axi4-lite",
        "axi4_lite_mmio_bridge",
        "axi4_lite_mmio_target",
        f"{_PROTOCOL_SOURCE_ROOT}/axi4_lite_mmio_bridge.sv",
        f"{_PROTOCOL_SOURCE_ROOT}/axi4_lite_mmio_target.sv",
    ),
    ("tl-ul", "1"): _AdapterDefinition(
        "tl-ul",
        "tl_ul_mmio_bridge",
        "tl_ul_mmio_target",
        f"{_PROTOCOL_SOURCE_ROOT}/tl_ul_mmio_bridge.sv",
        f"{_PROTOCOL_SOURCE_ROOT}/tl_ul_mmio_target.sv",
    ),
}


@dataclass(frozen=True, slots=True)
class CompositionArtifact:
    """Files and deterministic hashes emitted for one protocol composition."""

    ir: Mapping[str, object]
    wrapper_path: Path
    source_list_path: Path
    content_hash: str
    source_hash: str


def _width(expression: str, *, address_width: int, data_width: int) -> int:
    """Evaluate the closed width expressions used by bundled protocol plugins."""
    names = {"address_width": address_width, "data_width": data_width}
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError as error:
        raise ValueError(f"protocol width expression is invalid: {expression}") from error

    def evaluate(current: ast.AST) -> int:
        if isinstance(current, ast.Constant) and isinstance(current.value, int) and not isinstance(current.value, bool):
            return current.value
        if isinstance(current, ast.Name) and current.id in names:
            return names[current.id]
        if isinstance(current, ast.BinOp) and isinstance(current.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Div)):
            left, right = evaluate(current.left), evaluate(current.right)
            if isinstance(current.op, ast.Add):
                return left + right
            if isinstance(current.op, ast.Sub):
                return left - right
            if isinstance(current.op, ast.Mult):
                return left * right
            if right <= 0 or left % right:
                raise ValueError(f"protocol width expression is non-integral: {expression}")
            return left // right
        raise ValueError(f"protocol width expression is unsupported: {expression}")

    result = evaluate(node)
    if result <= 0:
        raise ValueError(f"protocol width expression is not positive: {expression}")
    return result


def _manifest_document(manifest: ProtocolCompositionManifest) -> dict[str, object]:
    return {
        "schema_version": "protocol_composition.v1",
        "target": {
            "kind": manifest.target_kind,
            "base_config": manifest.base_config,
            "address_width": manifest.address_width,
            "data_width": manifest.data_width,
        },
        "components": [
            {
                "component_id": component.component_id,
                "component_type": component.component_type,
                "protocol": {"id": component.protocol_id, "version": component.protocol_version},
                "base": component.base,
                "size": component.size,
                "irq": component.irq,
                "parameters": dict(sorted(component.parameters.items())),
                "external_input": component.external_input,
            }
            for component in sorted(manifest.components, key=lambda item: item.component_id)
        ],
        "runtime": {
            "seed": manifest.seed,
            "duration_seconds": manifest.duration_seconds,
            "checkpoint_seconds": manifest.checkpoint_seconds,
        },
    }


def _adapter_for(component: CompositionComponent) -> _AdapterDefinition:
    try:
        return _ADAPTERS[(component.protocol_id, component.protocol_version)]
    except KeyError as error:
        raise ValueError(
            f"unsupported runtime adapter: {component.protocol_id}@{component.protocol_version}"
        ) from error


def _component_tag(component_id: str) -> str:
    """Create a collision-proof SV identifier without trusting user text."""
    readable = re.sub(r"[^A-Za-z0-9_]", "_", component_id)
    if not readable or readable[0].isdigit():
        readable = "component_" + readable
    return f"{readable}_{canonical_id('sv-component', component_id):016x}"


def _hex32(value: int) -> str:
    digits = f"{value & 0xFFFF_FFFF:08x}"
    return f"32'h{digits[:4]}_{digits[4:]}"


def _relative_source_files(
    manifest: ProtocolCompositionManifest,
    registry: ComponentRegistry,
) -> tuple[str, ...]:
    sources: set[str] = {_UPSTREAM_SOURCE_LIST}
    for component in manifest.components:
        registration = registry.require(component.component_type)
        sources.update(registration.source_files)
        adapter = _adapter_for(component)
        sources.add(adapter.bridge_source)
        sources.add(adapter.target_source)
    return tuple(sorted(sources))


def _effective_parameters(
    component: CompositionComponent,
    registry: ComponentRegistry,
) -> dict[str, int]:
    registration = registry.require(component.component_type)
    parameters = dict(registration.parameter_defaults)
    parameters.update(component.parameters)
    return dict(sorted(parameters.items()))


def _validate_first_stage_component_set(
    manifest: ProtocolCompositionManifest,
) -> None:
    component_types = [component.component_type for component in manifest.components]
    counts = {
        component_type: component_types.count(component_type)
        for component_type in set(component_types)
    }
    if set(component_types) != _FIRST_STAGE_COMPONENT_TYPES or any(
        counts.get(component_type, 0) != 1
        for component_type in _FIRST_STAGE_COMPONENT_TYPES
    ):
        details = ", ".join(
            f"{component_type}={counts.get(component_type, 0)}"
            for component_type in sorted(_FIRST_STAGE_COMPONENT_TYPES)
        )
        raise ValueError(
            "first-stage protocol composition requires exactly one of each "
            f"component type ({details})"
        )


def _validate_generation_sources(
    root: Path,
    manifest: ProtocolCompositionManifest,
    registry: ComponentRegistry,
) -> tuple[str, ...]:
    source_files = _relative_source_files(manifest, registry)
    for source in source_files:
        source_path = (root / source).resolve()
        if not source_path.is_file():
            failure_kind = (
                "missing-source-list"
                if source == _UPSTREAM_SOURCE_LIST
                else "missing-source-file"
            )
            raise ValueError(f"composition.source:{source}:{failure_kind}")
    return source_files


def _protocol_fields(
    component: CompositionComponent,
    catalog: ProtocolCatalog,
    manifest: ProtocolCompositionManifest,
) -> list[dict[str, object]]:
    plugin = catalog.require(component.protocol_id, component.protocol_version)
    return [
        {
            "field_id": field.field_id,
            "port_id": canonical_id("protocol-port", f"{component.component_id}:{field.field_id}"),
            "direction": field.direction,
            "width": _width(
                field.width_expression,
                address_width=manifest.address_width,
                data_width=manifest.data_width,
            ),
            "required": field.required,
            "runtime_required": field.runtime_required,
        }
        for field in plugin.fields
    ]


def _build_ir(
    manifest: ProtocolCompositionManifest,
    catalog: ProtocolCatalog,
    registry: ComponentRegistry,
) -> dict[str, object]:
    components = tuple(sorted(manifest.components, key=lambda item: item.component_id))
    source_files = _relative_source_files(manifest, registry)
    component_records: list[dict[str, object]] = []
    instances: list[dict[str, object]] = []
    endpoint_bindings: list[dict[str, object]] = []
    adapters: list[dict[str, object]] = []
    regions: list[dict[str, object]] = []
    for component in components:
        registration = registry.require(component.component_type)
        adapter = _adapter_for(component)
        component_numeric_id = canonical_id("component", component.component_id)
        endpoint_id = canonical_id("protocol-endpoint", component.component_id)
        adapter_id = canonical_id("protocol-adapter", component.component_id)
        parameters = _effective_parameters(component, registry)
        component_record = {
            "id": component_numeric_id,
            "component_id": component.component_id,
            "component_type": component.component_type,
            "module_name": registration.module_name,
            "protocol_id": component.protocol_id,
            "protocol_version": component.protocol_version,
            "base": component.base,
            "size": component.size,
            "irq": component.irq,
            "parameters": parameters,
            "external_input": component.external_input,
        }
        component_records.append(component_record)
        instances.append(
            {
                "id": component_numeric_id,
                "component_id": component.component_id,
                "module_name": registration.module_name,
                "parameters": parameters,
                "role": component.component_type,
            }
        )
        endpoint_bindings.append(
            {
                "endpoint_id": endpoint_id,
                "binding_id": canonical_id("protocol-binding", component.component_id),
                "component_id": component.component_id,
                "protocol_id": component.protocol_id,
                "version": component.protocol_version,
                "side": "device",
                "adapter_id": adapter_id,
                "adapter_kind": adapter.kind,
                "bridge_module": adapter.bridge_module,
                "target_module": adapter.target_module,
                "parameters": {},
                "fields": _protocol_fields(component, catalog, manifest),
            }
        )
        adapters.append(
            {
                "id": adapter_id,
                "adapter_id": adapter_id,
                "component_id": component.component_id,
                "source_endpoint_id": canonical_id("ibex-endpoint", "data-master"),
                "target_endpoint_id": endpoint_id,
                "kind": adapter.kind,
                "bridge_module": adapter.bridge_module,
                "target_module": adapter.target_module,
                "max_wait_cycles": 16,
            }
        )
        regions.append(
            {
                "id": canonical_id("address-region", component.component_id),
                "component_id": component.component_id,
                "base": component.base,
                "size": component.size,
                "end": component.base + component.size,
                "port_id": canonical_id("mmio-port", component.component_id),
                "provenance": "manifest",
            }
        )

    protocol_kinds = sorted({adapter["kind"] for adapter in adapters})
    external_ports = [
        {"port_id": canonical_id("top-port", "clk_i"), "name": "clk_i", "direction": "input", "width": 1, "semantic_role": "clock"},
        {"port_id": canonical_id("top-port", "rst_ni"), "name": "rst_ni", "direction": "input", "width": 1, "semantic_role": "reset"},
        {"port_id": canonical_id("top-port", "boot_addr_i"), "name": "boot_addr_i", "direction": "input", "width": 32, "semantic_role": "boot_address"},
        {"port_id": canonical_id("top-port", "hart_id_i"), "name": "hart_id_i", "direction": "input", "width": 32, "semantic_role": "hart_id"},
        {"port_id": canonical_id("top-port", "instr_seed_i"), "name": "instr_seed_i", "direction": "input", "width": 32, "semantic_role": "instruction_seed"},
        {"port_id": canonical_id("top-port", "data_seed_i"), "name": "data_seed_i", "direction": "input", "width": 32, "semantic_role": "data_seed"},
        {"port_id": canonical_id("top-port", "gpio_pins_i"), "name": "gpio_pins_i", "direction": "input", "width": 16, "semantic_role": "gpio"},
        {"port_id": canonical_id("top-port", "uart_rx_valid_i"), "name": "uart_rx_valid_i", "direction": "input", "width": 1, "semantic_role": "uart_rx_valid"},
        {"port_id": canonical_id("top-port", "uart_rx_data_i"), "name": "uart_rx_data_i", "direction": "input", "width": 8, "semantic_role": "uart_rx_data"},
        {"port_id": canonical_id("top-port", "spi_miso_valid_i"), "name": "spi_miso_valid_i", "direction": "input", "width": 1, "semantic_role": "spi_miso_valid"},
        {"port_id": canonical_id("top-port", "spi_miso_data_i"), "name": "spi_miso_data_i", "direction": "input", "width": 8, "semantic_role": "spi_miso_data"},
        {"port_id": canonical_id("top-port", "timer_tick_i"), "name": "timer_tick_i", "direction": "input", "width": 1, "semantic_role": "timer_tick"},
        {"port_id": canonical_id("top-port", "irq_fast_i"), "name": "irq_fast_i", "direction": "input", "width": 15, "semantic_role": "irq_fast"},
        {"port_id": canonical_id("top-port", "irq_software_i"), "name": "irq_software_i", "direction": "input", "width": 1, "semantic_role": "irq_software"},
        {"port_id": canonical_id("top-port", "irq_nm_i"), "name": "irq_nm_i", "direction": "input", "width": 1, "semantic_role": "irq_nm"},
        {"port_id": canonical_id("top-port", "debug_req_i"), "name": "debug_req_i", "direction": "input", "width": 1, "semantic_role": "debug"},
        {"port_id": canonical_id("top-port", "instr_err_i"), "name": "instr_err_i", "direction": "input", "width": 1, "semantic_role": "instr_error"},
        {"port_id": canonical_id("top-port", "data_err_i"), "name": "data_err_i", "direction": "input", "width": 1, "semantic_role": "data_error"},
        {"port_id": canonical_id("top-port", "fetch_enable_i"), "name": "fetch_enable_i", "direction": "input", "width": 4, "semantic_role": "fetch_enable"},
        {"port_id": canonical_id("top-port", "system_observe_o"), "name": "system_observe_o", "direction": "output", "width": 32, "semantic_role": "observation"},
        {"port_id": canonical_id("top-port", "ip_observe_o"), "name": "ip_observe_o", "direction": "output", "width": 32, "semantic_role": "observation"},
    ]
    document: dict[str, object] = {
        "schema_version": "composition_ir.v1",
        "composition_kind": "protocol_composition",
        "target": {
            "kind": manifest.target_kind,
            "base_config": manifest.base_config,
            "address_width": manifest.address_width,
            "data_width": manifest.data_width,
            "top_module": _TOP_MODULE,
        },
        "runtime": {
            "seed": manifest.seed,
            "duration_seconds": manifest.duration_seconds,
            "checkpoint_seconds": manifest.checkpoint_seconds,
        },
        "components": component_records,
        "instances": instances,
        "endpoint_bindings": endpoint_bindings,
        "adapters": adapters,
        "adapter_kinds": protocol_kinds,
        "address_regions": sorted(regions, key=lambda item: (int(item["base"]), str(item["component_id"]))),
        "clock_domains": [
            {
                "domain_id": canonical_id("clock-domain", "system"),
                "port_id": canonical_id("top-port", "clk_i"),
                "name": "system_clock",
                "active_level": "high",
                "synchronous": True,
            }
        ],
        "reset_domains": [
            {
                "domain_id": canonical_id("reset-domain", "system"),
                "port_id": canonical_id("top-port", "rst_ni"),
                "name": "system_reset",
                "active_level": "low",
                "synchronous": True,
            }
        ],
        "external_ports": external_ports,
        # Source paths belong to sources.f.  The IR carries only opaque source
        # IDs so it remains portable across checkout locations.
        "source_file_ids": [canonical_id("source-file", source) for source in source_files],
        "boot_rom": {
            "kind": "rv32i-loop",
            "entry": "boot_rom_instruction",
            "sequence": ["ram", "timer", "gpio", "uart", "spi", "ram"],
        },
        "diagnostics": {"errors": [], "warnings": []},
    }
    return canonical_ir_document(document)


def _common_signal_declarations(prefix: str) -> list[str]:
    return [
        f"logic {prefix}_req_ready;",
        f"logic {prefix}_rsp_valid;",
        f"logic [DATA_WIDTH-1:0] {prefix}_rsp_rdata;",
        f"logic {prefix}_rsp_error;",
        f"logic {prefix}_valid;",
        f"logic {prefix}_write;",
        f"logic [ADDRESS_WIDTH-1:0] {prefix}_addr;",
        f"logic [DATA_WIDTH-1:0] {prefix}_wdata;",
        f"logic [(DATA_WIDTH/8)-1:0] {prefix}_be;",
        f"logic [DATA_WIDTH-1:0] {prefix}_rdata;",
        f"logic {prefix}_ready;",
        f"logic {prefix}_error;",
        f"logic {prefix}_irq;",
    ]


def _protocol_signal_declarations(prefix: str, adapter: _AdapterDefinition) -> list[str]:
    if adapter.kind == "apb4":
        return [
            f"logic [ADDRESS_WIDTH-1:0] {prefix}_paddr;",
            f"logic [2:0] {prefix}_pprot;",
            f"logic {prefix}_psel;",
            f"logic {prefix}_penable;",
            f"logic {prefix}_pwrite;",
            f"logic [DATA_WIDTH-1:0] {prefix}_pwdata;",
            f"logic [(DATA_WIDTH/8)-1:0] {prefix}_pstrb;",
            f"logic {prefix}_pready;",
            f"logic [DATA_WIDTH-1:0] {prefix}_prdata;",
            f"logic {prefix}_pslverr;",
        ]
    if adapter.kind == "axi4-lite":
        return [
            f"logic [ADDRESS_WIDTH-1:0] {prefix}_awaddr;",
            f"logic [2:0] {prefix}_awprot;",
            f"logic {prefix}_awvalid;",
            f"logic {prefix}_awready;",
            f"logic [DATA_WIDTH-1:0] {prefix}_axi_wdata;",
            f"logic [(DATA_WIDTH/8)-1:0] {prefix}_wstrb;",
            f"logic {prefix}_wvalid;",
            f"logic {prefix}_wready;",
            f"logic [1:0] {prefix}_bresp;",
            f"logic {prefix}_bvalid;",
            f"logic {prefix}_bready;",
            f"logic [ADDRESS_WIDTH-1:0] {prefix}_araddr;",
            f"logic [2:0] {prefix}_arprot;",
            f"logic {prefix}_arvalid;",
            f"logic {prefix}_arready;",
            f"logic [DATA_WIDTH-1:0] {prefix}_axi_rdata;",
            f"logic [1:0] {prefix}_rresp;",
            f"logic {prefix}_rvalid;",
            f"logic {prefix}_rready;",
        ]
    return [
        f"logic {prefix}_a_valid;",
        f"logic {prefix}_a_ready;",
        f"logic [2:0] {prefix}_a_opcode;",
        f"logic [2:0] {prefix}_a_param;",
        f"logic [2:0] {prefix}_a_size;",
        f"logic [0:0] {prefix}_a_source;",
        f"logic [ADDRESS_WIDTH-1:0] {prefix}_a_address;",
        f"logic [(DATA_WIDTH/8)-1:0] {prefix}_a_mask;",
        f"logic [DATA_WIDTH-1:0] {prefix}_a_data;",
        f"logic {prefix}_a_corrupt;",
        f"logic {prefix}_d_valid;",
        f"logic {prefix}_d_ready;",
        f"logic [2:0] {prefix}_d_opcode;",
        f"logic [1:0] {prefix}_d_param;",
        f"logic [2:0] {prefix}_d_size;",
        f"logic [0:0] {prefix}_d_source;",
        f"logic [0:0] {prefix}_d_sink;",
        f"logic {prefix}_d_denied;",
        f"logic [DATA_WIDTH-1:0] {prefix}_d_data;",
        f"logic {prefix}_d_corrupt;",
    ]


def _bridge_instance(prefix: str, component: CompositionComponent, adapter: _AdapterDefinition) -> list[str]:
    region = f"region_{prefix}"
    lines = [
        f"{adapter.bridge_module} #(.ADDRESS_WIDTH(ADDRESS_WIDTH), .DATA_WIDTH(DATA_WIDTH), .MAX_WAIT_CYCLES(16)) u_{prefix}_bridge (",
        "    .clk_i(clk_i),",
        "    .rst_ni(rst_ni),",
        f"    .req_valid_i({region}),",
        "    .req_write_i(data_we),",
        "    .req_addr_i(data_addr),",
        "    .req_wdata_i(data_wdata),",
        "    .req_be_i(data_be),",
        f"    .req_ready_o({prefix}_req_ready),",
        f"    .rsp_valid_o({prefix}_rsp_valid),",
        "    .rsp_ready_i(1'b1),",
        f"    .rsp_rdata_o({prefix}_rsp_rdata),",
        f"    .rsp_error_o({prefix}_rsp_error),",
    ]
    if adapter.kind == "apb4":
        lines.extend([
            f"    .paddr_o({prefix}_paddr),",
            f"    .pprot_o({prefix}_pprot),",
            f"    .psel_o({prefix}_psel),",
            f"    .penable_o({prefix}_penable),",
            f"    .pwrite_o({prefix}_pwrite),",
            f"    .pwdata_o({prefix}_pwdata),",
            f"    .pstrb_o({prefix}_pstrb),",
            f"    .pready_i({prefix}_pready),",
            f"    .prdata_i({prefix}_prdata),",
            f"    .pslverr_i({prefix}_pslverr)",
        ])
    elif adapter.kind == "axi4-lite":
        lines.extend([
            f"    .awaddr_o({prefix}_awaddr),",
            f"    .awprot_o({prefix}_awprot),",
            f"    .awvalid_o({prefix}_awvalid),",
            f"    .awready_i({prefix}_awready),",
            f"    .wdata_o({prefix}_axi_wdata),",
            f"    .wstrb_o({prefix}_wstrb),",
            f"    .wvalid_o({prefix}_wvalid),",
            f"    .wready_i({prefix}_wready),",
            f"    .bresp_i({prefix}_bresp),",
            f"    .bvalid_i({prefix}_bvalid),",
            f"    .bready_o({prefix}_bready),",
            f"    .araddr_o({prefix}_araddr),",
            f"    .arprot_o({prefix}_arprot),",
            f"    .arvalid_o({prefix}_arvalid),",
            f"    .arready_i({prefix}_arready),",
            f"    .rdata_i({prefix}_axi_rdata),",
            f"    .rresp_i({prefix}_rresp),",
            f"    .rvalid_i({prefix}_rvalid),",
            f"    .rready_o({prefix}_rready)",
        ])
    else:
        lines.extend([
            f"    .a_valid_o({prefix}_a_valid),",
            f"    .a_ready_i({prefix}_a_ready),",
            f"    .a_opcode_o({prefix}_a_opcode),",
            f"    .a_param_o({prefix}_a_param),",
            f"    .a_size_o({prefix}_a_size),",
            f"    .a_source_o({prefix}_a_source),",
            f"    .a_address_o({prefix}_a_address),",
            f"    .a_mask_o({prefix}_a_mask),",
            f"    .a_data_o({prefix}_a_data),",
            f"    .a_corrupt_o({prefix}_a_corrupt),",
            f"    .d_valid_i({prefix}_d_valid),",
            f"    .d_ready_o({prefix}_d_ready),",
            f"    .d_opcode_i({prefix}_d_opcode),",
            f"    .d_param_i({prefix}_d_param),",
            f"    .d_size_i({prefix}_d_size),",
            f"    .d_source_i({prefix}_d_source),",
            f"    .d_sink_i({prefix}_d_sink),",
            f"    .d_denied_i({prefix}_d_denied),",
            f"    .d_data_i({prefix}_d_data),",
            f"    .d_corrupt_i({prefix}_d_corrupt)",
        ])
    lines.append(");")
    return lines


def _target_instance(prefix: str, adapter: _AdapterDefinition) -> list[str]:
    lines = [
        f"{adapter.target_module} #(.ADDRESS_WIDTH(ADDRESS_WIDTH), .DATA_WIDTH(DATA_WIDTH), .MAX_WAIT_CYCLES(16)) u_{prefix}_target (",
        "    .clk_i(clk_i),",
        "    .rst_ni(rst_ni),",
    ]
    if adapter.kind == "apb4":
        lines.extend([
            f"    .paddr_i({prefix}_paddr),",
            f"    .pprot_i({prefix}_pprot),",
            f"    .psel_i({prefix}_psel),",
            f"    .penable_i({prefix}_penable),",
            f"    .pwrite_i({prefix}_pwrite),",
            f"    .pwdata_i({prefix}_pwdata),",
            f"    .pstrb_i({prefix}_pstrb),",
            f"    .pready_o({prefix}_pready),",
            f"    .prdata_o({prefix}_prdata),",
            f"    .pslverr_o({prefix}_pslverr),",
        ])
    elif adapter.kind == "axi4-lite":
        lines.extend([
            f"    .awaddr_i({prefix}_awaddr),",
            f"    .awprot_i({prefix}_awprot),",
            f"    .awvalid_i({prefix}_awvalid),",
            f"    .awready_o({prefix}_awready),",
            f"    .wdata_i({prefix}_axi_wdata),",
            f"    .wstrb_i({prefix}_wstrb),",
            f"    .wvalid_i({prefix}_wvalid),",
            f"    .wready_o({prefix}_wready),",
            f"    .bresp_o({prefix}_bresp),",
            f"    .bvalid_o({prefix}_bvalid),",
            f"    .bready_i({prefix}_bready),",
            f"    .araddr_i({prefix}_araddr),",
            f"    .arprot_i({prefix}_arprot),",
            f"    .arvalid_i({prefix}_arvalid),",
            f"    .arready_o({prefix}_arready),",
            f"    .rdata_o({prefix}_axi_rdata),",
            f"    .rresp_o({prefix}_rresp),",
            f"    .rvalid_o({prefix}_rvalid),",
            f"    .rready_i({prefix}_rready),",
        ])
    else:
        lines.extend([
            f"    .a_valid_i({prefix}_a_valid),",
            f"    .a_ready_o({prefix}_a_ready),",
            f"    .a_opcode_i({prefix}_a_opcode),",
            f"    .a_param_i({prefix}_a_param),",
            f"    .a_size_i({prefix}_a_size),",
            f"    .a_source_i({prefix}_a_source),",
            f"    .a_address_i({prefix}_a_address),",
            f"    .a_mask_i({prefix}_a_mask),",
            f"    .a_data_i({prefix}_a_data),",
            f"    .a_corrupt_i({prefix}_a_corrupt),",
            f"    .d_valid_o({prefix}_d_valid),",
            f"    .d_ready_i({prefix}_d_ready),",
            f"    .d_opcode_o({prefix}_d_opcode),",
            f"    .d_param_o({prefix}_d_param),",
            f"    .d_size_o({prefix}_d_size),",
            f"    .d_source_o({prefix}_d_source),",
            f"    .d_sink_o({prefix}_d_sink),",
            f"    .d_denied_o({prefix}_d_denied),",
            f"    .d_data_o({prefix}_d_data),",
            f"    .d_corrupt_o({prefix}_d_corrupt),",
        ])
    lines.extend([
        f"    .valid_o({prefix}_valid),",
        f"    .write_o({prefix}_write),",
        f"    .addr_o({prefix}_addr),",
        f"    .wdata_o({prefix}_wdata),",
        f"    .be_o({prefix}_be),",
        f"    .rdata_i({prefix}_rdata),",
        f"    .ready_i({prefix}_ready),",
        f"    .error_i({prefix}_error)",
        ");",
    ])
    return lines


def _component_instance(
    prefix: str,
    component: CompositionComponent,
    registration_module: str,
    parameters: Mapping[str, int],
) -> list[str]:
    lines = [f"{registration_module}"]
    if component.component_type == "ram":
        words = int(parameters.get("WORDS", 64))
        lines[0] += f" #(.WORDS({words}))"
    lines[0] += f" u_{prefix}_component ("
    lines.extend([
        "    .clk_i(clk_i),",
        "    .rst_ni(rst_ni),",
        f"    .valid_i({prefix}_valid),",
        f"    .write_i({prefix}_write),",
        f"    .addr_i({prefix}_addr),",
        f"    .wdata_i({prefix}_wdata),",
    ])
    if component.component_type == "ram":
        lines.extend([
            f"    .be_i({prefix}_be),",
            "    .seed_i(data_seed_i),",
            f"    .rdata_o({prefix}_rdata),",
            f"    .state_o({prefix}_state)",
        ])
    elif component.component_type == "timer":
        lines.extend([
            "    .tick_i(timer_tick_i),",
            f"    .rdata_o({prefix}_rdata),",
            f"    .irq_o({prefix}_irq),",
            f"    .state_o({prefix}_state)",
        ])
    elif component.component_type == "gpio":
        lines.extend([
            "    .pins_i(gpio_pins_i),",
            f"    .rdata_o({prefix}_rdata),",
            f"    .irq_o({prefix}_irq),",
            f"    .state_o({prefix}_state)",
        ])
    elif component.component_type == "uart":
        lines.extend([
            "    .rx_valid_i(uart_rx_valid_i),",
            "    .rx_data_i(uart_rx_data_i),",
            f"    .rdata_o({prefix}_rdata),",
            f"    .irq_o({prefix}_irq),",
            f"    .state_o({prefix}_state)",
        ])
    else:
        lines.extend([
            "    .miso_valid_i(spi_miso_valid_i),",
            "    .miso_data_i(spi_miso_data_i),",
            f"    .rdata_o({prefix}_rdata),",
            f"    .irq_o({prefix}_irq),",
            f"    .state_o({prefix}_state)",
        ])
    lines.append(");")
    return lines


def _render_wrapper(
    manifest: ProtocolCompositionManifest,
    registry: ComponentRegistry,
) -> str:
    components = tuple(sorted(manifest.components, key=lambda item: item.component_id))
    prefixes = {component.component_id: _component_tag(component.component_id) for component in components}
    lines = [
        "// Deterministic Ibex protocol-composition wrapper.",
        "// The boot path is a legal RV32I access loop over all declared regions.",
        "module ibex_protocol_composition_top #(",
        "    parameter integer ADDRESS_WIDTH = 32,",
        "    parameter integer DATA_WIDTH = 32",
        ") (",
        "    input  logic                         clk_i,",
        "    input  logic                         rst_ni,",
        "    input  logic [31:0]                  boot_addr_i,",
        "    input  logic [31:0]                  hart_id_i,",
        "    input  logic [31:0]                  instr_seed_i,",
        "    input  logic [31:0]                  data_seed_i,",
        "    input  logic [15:0]                  gpio_pins_i,",
        "    input  logic                         uart_rx_valid_i,",
        "    input  logic [7:0]                   uart_rx_data_i,",
        "    input  logic                         spi_miso_valid_i,",
        "    input  logic [7:0]                   spi_miso_data_i,",
        "    input  logic                         timer_tick_i,",
        "    input  logic [14:0]                  irq_fast_i,",
        "    input  logic                         irq_software_i,",
        "    input  logic                         irq_nm_i,",
        "    input  logic                         debug_req_i,",
        "    input  logic                         instr_err_i,",
        "    input  logic                         data_err_i,",
        "    input  logic [3:0]                   fetch_enable_i,",
        "    output logic [31:0]                  system_observe_o,",
        "    output logic [31:0]                  ip_observe_o",
        ");",
        "",
        "    localparam logic [2:0] REGION_RAM   = 3'd0;",
        "    localparam logic [2:0] REGION_TIMER = 3'd1;",
        "    localparam logic [2:0] REGION_GPIO  = 3'd2;",
        "    localparam logic [2:0] REGION_UART  = 3'd3;",
        "    localparam logic [2:0] REGION_SPI   = 3'd4;",
        "",
    ]
    for component in components:
        type_name = component.component_type.upper()
        lines.extend([
            f"    localparam logic [ADDRESS_WIDTH-1:0] BASE_{type_name} = {_hex32(component.base)};",
            f"    localparam logic [ADDRESS_WIDTH-1:0] SIZE_{type_name} = {_hex32(component.size)};",
        ])
    lines.extend([
        "",
        "    logic [31:0] cycle_q;",
        "    logic instr_req;",
        "    logic instr_gnt;",
        "    logic instr_rvalid;",
        "    logic [31:0] instr_addr;",
        "    logic [31:0] instr_rdata;",
        "    logic [31:0] instr_ram_rdata;",
        "    logic [7:0] instr_ram_state;",
        "    logic [31:0] data_rdata;",
        "    logic data_gnt;",
        "    logic data_rvalid;",
        "    logic data_error;",
        "    logic data_req;",
        "    logic data_we;",
        "    logic [3:0] data_be;",
        "    logic [31:0] data_addr;",
        "    logic [31:0] data_wdata;",
        "    logic [2:0] data_region;",
        "    logic irq_external;",
        "    logic timer_irq;",
        "    logic [21:0] ic_tag_rdata [0:1];",
        "    logic [63:0] ic_data_rdata [0:1];",
        "",
        "    function automatic logic [31:0] boot_rom_instruction(input logic [ADDRESS_WIDTH-1:0] address);",
        "        begin",
        "            boot_rom_instruction = 32'h0000_0013; // addi x0, x0, 0",
        "            unique case (address[6:2])",
        "                5'd0:  boot_rom_instruction = 32'h0000_02b7; // lui x5, 0x00000: RAM",
        "                5'd1:  boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): RAM",
        "                5'd2:  boot_rom_instruction = 32'h8001_02b7; // lui x5, 0x80010: Timer",
        "                5'd3:  boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): Timer",
        "                5'd4:  boot_rom_instruction = 32'h8002_02b7; // lui x5, 0x80020: GPIO",
        "                5'd5:  boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): GPIO",
        "                5'd6:  boot_rom_instruction = 32'h8003_02b7; // lui x5, 0x80030: UART",
        "                5'd7:  boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): UART",
        "                5'd8:  boot_rom_instruction = 32'h8004_02b7; // lui x5, 0x80040: SPI",
        "                5'd9:  boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): SPI",
        "                5'd10: boot_rom_instruction = 32'h0000_02b7; // lui x5, 0x00000: RAM",
        "                5'd11: boot_rom_instruction = 32'h0002_a303; // lw x6, 0(x5): RAM",
        "                5'd12: boot_rom_instruction = 32'hfd1f_f06f; // jal x0, -48: loop",
        "                default: boot_rom_instruction = 32'h0000_0013; // addi x0, x0, 0",
        "            endcase",
        "        end",
        "    endfunction",
        "",
        "    function automatic logic address_in_region(",
        "        input logic [ADDRESS_WIDTH-1:0] address,",
        "        input logic [ADDRESS_WIDTH-1:0] base,",
        "        input logic [ADDRESS_WIDTH-1:0] size",
        "    );",
        "        logic [ADDRESS_WIDTH-1:0] offset;",
        "        begin",
        "            offset = address - base;",
        "            address_in_region = $unsigned(offset) < $unsigned(size);",
        "        end",
        "    endfunction",
        "",
        "    assign instr_gnt = instr_req;",
        "    assign instr_rvalid = instr_req;",
        "    assign instr_rdata = boot_rom_instruction(instr_addr);",
        "    assign ic_tag_rdata[0] = 22'h0;",
        "    assign ic_tag_rdata[1] = 22'h0;",
        "    assign ic_data_rdata[0] = 64'h0;",
        "    assign ic_data_rdata[1] = 64'h0;",
        "",
        "    always_ff @(posedge clk_i or negedge rst_ni) begin",
        "        if (!rst_ni) cycle_q <= 32'h0;",
        "        else cycle_q <= cycle_q + 32'h1;",
        "    end",
        "",
        "    always_comb begin",
        "        data_region = REGION_RAM;",
    ])
    for component in components:
        type_name = component.component_type.upper()
        region_name = {
            "ram": "REGION_RAM",
            "timer": "REGION_TIMER",
            "gpio": "REGION_GPIO",
            "uart": "REGION_UART",
            "spi": "REGION_SPI",
        }[component.component_type]
        lines.append(
            f"        if (address_in_region(data_addr, BASE_{type_name}, SIZE_{type_name})) data_region = {region_name};"
        )
    lines.extend([
        "    end",
        "",
    ])

    for component in components:
        prefix = prefixes[component.component_id]
        adapter = _adapter_for(component)
        lines.extend(_common_signal_declarations(prefix))
        lines.extend(_protocol_signal_declarations(prefix, adapter))
        lines.append(f"logic [7:0] {prefix}_state;")
        lines.append(f"logic region_{prefix};")
        lines.append("")
    # The fixed first-stage target has one component of each registered type.
    for component in components:
        prefix = prefixes[component.component_id]
        region_name = {
            "ram": "REGION_RAM",
            "timer": "REGION_TIMER",
            "gpio": "REGION_GPIO",
            "uart": "REGION_UART",
            "spi": "REGION_SPI",
        }[component.component_type]
        lines.append(f"    assign region_{prefix} = data_req && (data_region == {region_name});")
    lines.extend([
        "    assign data_gnt = data_req && (" + " || ".join(f"(region_{prefixes[item.component_id]} && {prefixes[item.component_id]}_req_ready)" for item in components) + ");",
        "",
    ])
    lines.extend([
        "    always_comb begin",
        "        data_rvalid = 1'b0;",
        "        data_rdata = '0;",
        "        data_error = 1'b0;",
    ])
    for component in components:
        prefix = prefixes[component.component_id]
        lines.extend([
            f"        if ({prefix}_rsp_valid) begin",
            "            data_rvalid = 1'b1;",
            f"            data_rdata = {prefix}_rsp_rdata;",
            f"            data_error = {prefix}_rsp_error;",
            "        end",
        ])
    lines.extend(["    end", ""])

    for component in components:
        prefix = prefixes[component.component_id]
        adapter = _adapter_for(component)
        lines.extend(_bridge_instance(prefix, component, adapter))
        lines.append("")
        lines.extend(_target_instance(prefix, adapter))
        lines.append("")
        registration = registry.require(component.component_type)
        lines.extend(
            _component_instance(
                prefix,
                component,
                registration.module_name,
                _effective_parameters(component, registry),
            )
        )
        lines.append("")
        lines.extend([
            f"    assign {prefix}_ready = 1'b1;",
            f"    assign {prefix}_error = data_err_i && {prefix}_valid;",
            "",
        ])

    ram_prefix = prefixes.get(next((item.component_id for item in components if item.component_type == "ram"), ""), "")
    if ram_prefix:
        ram_component = next(item for item in components if item.component_type == "ram")
        words = int(_effective_parameters(ram_component, registry).get("WORDS", 64))
        lines.extend([
            f"    ibex_mcip_ram #(.WORDS({words})) u_instr_ram (",
            "        .clk_i(clk_i),",
            "        .rst_ni(rst_ni),",
            "        .valid_i(instr_req),",
            "        .write_i(1'b0),",
            "        .addr_i(instr_addr),",
            "        .wdata_i(32'h0),",
            "        .be_i(4'h0),",
            "        .seed_i(instr_seed_i),",
            "        .rdata_o(instr_ram_rdata),",
            "        .state_o(instr_ram_state)",
            "    );",
            "",
        ])
    lines.extend([
        "    assign irq_external = " + " || ".join(
            f"{prefixes[item.component_id]}_irq"
            for item in components
            if item.component_type in {"gpio", "spi", "uart"}
        ) + ";",
        "    assign timer_irq = " + next(
            (f"{prefixes[item.component_id]}_irq" for item in components if item.component_type == "timer"),
            "1'b0",
        ) + ";",
        "",
        "    ibex_core #(",
        "        .PMPEnable(1'b0),",
        "        .SecureIbex(1'b0),",
        "        .RV32M(ibex_pkg::RV32MFast),",
        "        .RV32B(ibex_pkg::RV32BNone),",
        "        .WritebackStage(1'b0),",
        "        .ICache(1'b0),",
        "        .RegFileECC(1'b0),",
        "        .MemECC(1'b0)",
        "    ) u_ibex (",
        "        .clk_i(clk_i),",
        "        .rst_ni(rst_ni),",
        "        .hart_id_i(hart_id_i),",
        "        .boot_addr_i(boot_addr_i),",
        "        .instr_req_o(instr_req),",
        "        .instr_gnt_i(instr_gnt),",
        "        .instr_rvalid_i(instr_rvalid),",
        "        .instr_addr_o(instr_addr),",
        "        .instr_rdata_i(instr_rdata),",
        "        .instr_err_i(instr_err_i && instr_rvalid),",
        "        .data_req_o(data_req),",
        "        .data_gnt_i(data_gnt),",
        "        .data_rvalid_i(data_rvalid),",
        "        .data_we_o(data_we),",
        "        .data_be_o(data_be),",
        "        .data_addr_o(data_addr),",
        "        .data_wdata_o(data_wdata),",
        "        .data_rdata_i(data_rdata),",
        "        .data_err_i((data_err_i && data_rvalid) || (data_error && data_rvalid)),",
        "        .dummy_instr_id_o(),",
        "        .dummy_instr_wb_o(),",
        "        .rf_raddr_a_o(),",
        "        .rf_raddr_b_o(),",
        "        .rf_waddr_wb_o(),",
        "        .rf_we_wb_o(),",
        "        .rf_wdata_wb_ecc_o(),",
        "        .rf_rdata_a_ecc_i(data_seed_i),",
        "        .rf_rdata_b_ecc_i(instr_seed_i),",
        "        .ic_tag_req_o(),",
        "        .ic_tag_write_o(),",
        "        .ic_tag_addr_o(),",
        "        .ic_tag_wdata_o(),",
        "        .ic_tag_rdata_i(ic_tag_rdata),",
        "        .ic_data_req_o(),",
        "        .ic_data_write_o(),",
        "        .ic_data_addr_o(),",
        "        .ic_data_wdata_o(),",
        "        .ic_data_rdata_i(ic_data_rdata),",
        "        .ic_scr_key_valid_i(1'b0),",
        "        .ic_scr_key_req_o(),",
        "        .irq_software_i(irq_software_i),",
        "        .irq_timer_i(timer_irq),",
        "        .irq_external_i(irq_external),",
        "        .irq_fast_i(irq_fast_i),",
        "        .irq_nm_i(irq_nm_i),",
        "        .irq_pending_o(),",
        "        .debug_req_i(debug_req_i),",
        "        .crash_dump_o(),",
        "        .double_fault_seen_o(),",
        "        .alert_minor_o(),",
        "        .alert_major_internal_o(),",
        "        .alert_major_bus_o(),",
        "        .core_busy_o(),",
        "        .fetch_enable_i(fetch_enable_i)",
        "    );",
        "",
        "    assign system_observe_o = {",
        "        instr_req, instr_gnt, instr_rvalid, data_req, data_gnt, data_rvalid,",
        "        data_we, data_region, irq_external, irq_software_i, irq_nm_i, debug_req_i,",
        "        instr_addr[7:0], data_addr[7:0], cycle_q[1:0]",
        "    };",
        "    assign ip_observe_o = {",
        "        instr_ram_state, timer_irq, irq_external, data_error, cycle_q[20:0]",
        "    };",
        "",
        "endmodule",
        "",
    ])
    return "\n".join(lines)


def _render_source_list(
    manifest: ProtocolCompositionManifest,
    registry: ComponentRegistry,
    *,
    root: Path,
    wrapper_path: Path,
) -> str:
    relative_sources = _relative_source_files(manifest, registry)
    sources = [
        f"-f {(root / _UPSTREAM_SOURCE_LIST).resolve().as_posix()}",
        *[
            (root / source).resolve().as_posix()
            for source in relative_sources
            if source != _UPSTREAM_SOURCE_LIST
        ],
        wrapper_path.resolve().as_posix(),
    ]
    return "\n".join(sources) + "\n"


def _source_hash(wrapper_text: str, relative_sources: tuple[str, ...]) -> str:
    # semantic_source_hash validates the generated HDL before the combined
    # source manifest is hashed as canonical JSON.
    from .metadata import semantic_source_hash

    wrapper_hash = semantic_source_hash(wrapper_text, context="composition.wrapper")
    source_list_hash = content_hash(
        {"source_list": [*relative_sources, f"{_TOP_MODULE}.sv"]}
    )
    return content_hash({"wrapper_hash": wrapper_hash, "source_list_hash": source_list_hash})


def compose_protocol_composition(
    manifest: ProtocolCompositionManifest,
    output_dir: Path,
    *,
    root: Path,
    catalog: ProtocolCatalog | None = None,
    registry: ComponentRegistry | None = None,
) -> CompositionArtifact:
    """Validate and emit one deterministic protocol-composition artifact."""
    output = Path(output_dir).resolve()
    checkout_root = Path(root).resolve()
    selected_catalog = catalog or load_protocol_catalog(checkout_root / "src/myfuzz/protocols/plugins")
    selected_registry = registry or default_component_registry(checkout_root)
    validate_protocol_composition(manifest, selected_catalog, selected_registry)
    _validate_first_stage_component_set(manifest)
    relative_sources = _validate_generation_sources(
        checkout_root,
        manifest,
        selected_registry,
    )
    ir = _build_ir(manifest, selected_catalog, selected_registry)
    wrapper_text = _render_wrapper(manifest, selected_registry)
    output.mkdir(parents=True, exist_ok=True)
    wrapper_path = output / f"{_TOP_MODULE}.sv"
    source_list_path = output / "sources.f"
    source_list = _render_source_list(
        manifest,
        selected_registry,
        root=checkout_root,
        wrapper_path=wrapper_path,
    )
    wrapper_path.write_text(wrapper_text, encoding="utf-8")
    source_list_path.write_text(source_list, encoding="utf-8")
    return CompositionArtifact(
        ir=ir,
        wrapper_path=wrapper_path,
        source_list_path=source_list_path,
        content_hash=canonical_ir_hash(ir),
        source_hash=_source_hash(wrapper_text, relative_sources),
    )


def write_protocol_composition(
    manifest_path: Path,
    output_dir: Path,
    *,
    root: Path,
) -> dict[str, object]:
    """Load a manifest, generate files, and publish a path-bearing summary."""
    manifest_file = Path(manifest_path)
    manifest = load_protocol_composition(manifest_file)
    checkout_root = Path(root).resolve()
    catalog = load_protocol_catalog(checkout_root / "src/myfuzz/protocols/plugins")
    registry = default_component_registry(checkout_root)
    artifact = compose_protocol_composition(
        manifest,
        Path(output_dir),
        root=checkout_root,
        catalog=catalog,
        registry=registry,
    )
    manifest_hash = content_hash(_manifest_document(manifest))
    ir_path = artifact.wrapper_path.parent / "composition_ir.json"
    ir_path.write_text(json.dumps(artifact.ir, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "schema_version": str(artifact.ir["schema_version"]),
        "manifest_hash": manifest_hash,
        "content_hash": artifact.content_hash,
        "source_hash": artifact.source_hash,
        "ir_path": ir_path.as_posix(),
        "wrapper_path": artifact.wrapper_path.as_posix(),
        "source_list_path": artifact.source_list_path.as_posix(),
        "complete": True,
    }


def _generic_plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _generic_plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_generic_plain(item) for item in value]
    return value


def _generic_source(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"generic composition source escapes base_dir: {relative}") from error
    if not candidate.is_file():
        raise ValueError(f"generic composition source is missing: {relative}")
    return candidate


def _generic_port_records(
    plan: object, *, internal_ports: frozenset[str] = frozenset(), require_records: bool = True,
) -> tuple[dict[str, object], ...]:
    annotations = getattr(plan, "annotations", None)
    if not isinstance(annotations, Mapping):
        raise ValueError("generic composition plan annotations are invalid")
    endpoints = annotations.get("endpoints")
    if not isinstance(endpoints, list | tuple):
        raise ValueError("generic composition plan endpoints are invalid")
    records: dict[str, dict[str, object]] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping) or not isinstance(endpoint.get("endpoint_id"), str):
            raise ValueError("generic composition endpoint is invalid")
        for field in endpoint.get("fields", ()):
            if not isinstance(field, Mapping):
                raise ValueError("generic composition field is invalid")
            port, direction, width = field.get("port"), field.get("direction"), field.get("width")
            if (
                not isinstance(port, str) or not port
                or direction not in {"input", "output"}
                or isinstance(width, bool) or not isinstance(width, int) or width <= 0
            ):
                raise ValueError("generic composition field facts are invalid")
            if port in internal_ports:
                continue
            identity = f"{endpoint['endpoint_id']}:{field.get('role')}:{port}"
            existing = records.get(port)
            # Endpoints describe semantic views of the same source module.
            # Shared physical pins retain their first opaque binding; only
            # contradictory HDL facts constitute a conflict.
            opaque = existing["opaque_port"] if existing is not None else f"p_{canonical_id('generic-top-port', identity):016x}"
            record = {
                "source_port": port,
                "opaque_port": opaque,
                "direction": direction,
                "width": width,
                "signed": field.get("signed", False),
            }
            if existing is not None and existing != record:
                raise ValueError(f"generic composition port facts conflict: {port}")
            records[port] = record
    if require_records and not records:
        raise ValueError("generic composition has no source-backed ports")
    return tuple(sorted(records.values(), key=lambda item: str(item["opaque_port"])))


def _generic_source_top(plan: object, *, internal_ports: frozenset[str] = frozenset()) -> tuple[str, dict[str, dict[str, object]]]:
    ports = _generic_port_records(plan, internal_ports=internal_ports, require_records=False)
    description = getattr(plan, "interface_description", None)
    source = getattr(description, "source", None)
    top_module = getattr(source, "top_module", None)
    if not isinstance(top_module, str) or not top_module:
        raise ValueError("generic composition source top module is invalid")
    declarations: list[str] = []
    for record in ports:
        width = int(record["width"])
        shape = "logic" if width == 1 else f"logic {'signed ' if record['signed'] else ''}[{width - 1}:0]"
        signed = " signed" if record["signed"] and width == 1 else ""
        declarations.append(f"    {record['direction']} {shape}{signed} {record['opaque_port']}")
    return top_module, {str(record["source_port"]): record for record in ports}


def _render_generic_source_only_top(plan: object) -> str:
    top_module, ports = _generic_source_top(plan)
    declarations = []
    for record in sorted(ports.values(), key=lambda item: str(item["opaque_port"])):
        width = int(record["width"])
        shape = "logic" if width == 1 else f"logic {'signed ' if record['signed'] else ''}[{width - 1}:0]"
        signed = " signed" if record["signed"] and width == 1 else ""
        declarations.append(f"    {record['direction']} {shape}{signed} {record['opaque_port']}")
    instance = f"u_{canonical_id('generic-source-instance', top_module):016x}"
    connections = [f"        .{record['source_port']}({record['opaque_port']})" for record in sorted(ports.values(), key=lambda item: str(item["opaque_port"]))]
    return "\n".join([
        "// Generated from source-backed interface annotations. Do not edit.",
        "module generic_composition_top (",
        ",\n".join(declarations),
        ");",
        f"  {top_module} {instance} (",
        ",\n".join(connections),
        "  );",
        "endmodule",
        "",
    ])


def _sv_identifier(value: object, *, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", value) is None:
        raise ValueError(f"generic composition {context} is not a SystemVerilog identifier")
    return value


def _sv_logic(name: str, width: int, *, signed: bool = False) -> str:
    if width <= 0:
        raise ValueError("generic composition wire width is invalid")
    if width == 1:
        return f"logic{' signed' if signed else ''} {name}"
    return f"logic {'signed ' if signed else ''}[{width - 1}:0] {name}"


def _sv_literal(width: int, value: int) -> str:
    if width <= 0 or value < 0 or value >= 1 << width:
        raise ValueError("generic composition address literal is invalid")
    return f"{width}'h{value:x}"


def _generic_routes(plan: object) -> tuple[dict[str, object], ...]:
    """Validate the IR topology used by the name-independent renderer."""
    ir = getattr(plan, "ir", None)
    capabilities = getattr(plan, "capabilities", None)
    components = getattr(plan, "components", None)
    if not isinstance(ir, Mapping) or not isinstance(capabilities, tuple) or not isinstance(components, tuple):
        raise ValueError("generic composition topology is invalid")
    adapters = ir.get("adapters")
    regions = ir.get("address_regions")
    irq_routes = ir.get("irq_routes")
    bindings = ir.get("endpoint_bindings")
    if not isinstance(adapters, (tuple, list)) or not isinstance(regions, (tuple, list)) or not isinstance(irq_routes, (tuple, list)):
        raise ValueError("generic composition topology is missing")
    if not isinstance(bindings, (tuple, list)):
        raise ValueError("generic composition bindings are missing")
    irq_components = {
        item.get("component_id") for item in irq_routes
        if isinstance(item, Mapping) and item.get("field_id") == "irq"
    }
    by_component = {item.get("component_id"): item for item in components if isinstance(item, Mapping)}
    by_region = {item.get("component_id"): item for item in regions if isinstance(item, Mapping)}
    by_binding = {item.get("component_id"): item for item in bindings if isinstance(item, Mapping)}
    by_endpoint = {item.endpoint_id: item for item in capabilities}
    routes: list[dict[str, object]] = []
    for raw in adapters:
        if not isinstance(raw, Mapping):
            raise ValueError("generic composition adapter is invalid")
        component_id = raw.get("component_id")
        component, region, binding = by_component.get(component_id), by_region.get(component_id), by_binding.get(component_id)
        source = by_endpoint.get(raw.get("source_endpoint_id"))
        if not isinstance(component_id, str) or component is None or region is None or binding is None or source is None:
            raise ValueError("generic composition adapter binding is invalid")
        contract = raw.get("contract")
        control = binding.get("control")
        if not isinstance(contract, Mapping) or contract.get("mode") not in {"single_target_single_channel", "native_apb", "native_wishbone_classic"}:
            raise ValueError("generic composition adapter contract is unsupported")
        if not isinstance(control, Mapping) or set(control) != {"clock", "reset", "reset_semantics"}:
            raise ValueError("generic composition control binding is invalid")
        for role in ("clock", "reset"):
            item = control[role]
            if not isinstance(item, Mapping) or not isinstance(item.get("source_port"), str) or not isinstance(item.get("target_port"), str):
                raise ValueError(f"generic composition {role} binding is invalid")
        reset_semantics = control.get("reset_semantics")
        if reset_semantics not in (
            {"polarity": "active_low", "synchrony": "asynchronous"},
            {"polarity": "active_high", "synchrony": "asynchronous"},
            {"polarity": "active_low", "synchrony": "synchronous"},
            {"polarity": "active_high", "synchrony": "synchronous"},
        ):
            raise ValueError("generic composition reset semantics are unsupported")
        fields = raw.get("fields")
        if not isinstance(fields, (tuple, list)) or not fields:
            raise ValueError("generic composition adapter fields are invalid")
        source_fields = {field.role: field for field in source.fields}
        route_fields: list[dict[str, object]] = []
        for field in fields:
            if not isinstance(field, Mapping):
                raise ValueError("generic composition adapter field is invalid")
            field_id, target_port = field.get("field_id"), field.get("target_port")
            direction, width = field.get("direction"), field.get("width")
            source_field = source_fields.get(field_id)
            if (
                not isinstance(field_id, str) or source_field is None
                or not isinstance(target_port, str) or not isinstance(direction, str)
                or isinstance(width, bool) or not isinstance(width, int) or width != source_field.width
                or direction not in {"input", "output"}
            ):
                raise ValueError("generic composition adapter field binding is invalid")
            route_fields.append({
                "field_id": field_id, "source_port": source_field.port, "source_direction": source_field.direction,
                "target_port": target_port, "direction": direction, "width": width,
                "signed": source_field.signed, "address": field.get("address") is True,
                "irq_route": component_id in irq_components and field_id == "irq",
            })
        address_fields = [field for field in route_fields if field["address"]]
        if not address_fields:
            raise ValueError("generic composition adapter has no address field")
        base, size = region.get("base"), region.get("size")
        if (
            isinstance(base, bool) or not isinstance(base, int) or base < 0
            or isinstance(size, bool) or not isinstance(size, int) or size <= 0
        ):
            raise ValueError("generic composition address region is invalid")
        max_wait = raw.get("max_wait_cycles")
        if (
            isinstance(max_wait, bool) or not isinstance(max_wait, int) or not 1 <= max_wait <= 65_535
            or contract.get("max_wait_cycles") != max_wait
        ):
            raise ValueError("generic composition adapter bound is invalid")
        routes.append({
            "component_id": component_id, "module_name": component.get("module_name"),
            "parameters": component.get("parameters", {}), "fields": tuple(route_fields),
            "base": base, "size": size, "adapter_id": raw.get("adapter_id"),
            "max_wait_cycles": max_wait, "source_endpoint_id": source.endpoint_id,
            "contract": dict(contract), "control": {role: dict(value) for role, value in control.items()},
        })
    if len({route["source_endpoint_id"] for route in routes}) != len(routes):
        raise ValueError("generic composition adapter requires one target per source endpoint")
    return tuple(sorted(routes, key=lambda item: str(item["component_id"])))


def _route_tag(route: Mapping[str, object]) -> str:
    return f"{canonical_id('generic-render-route', str(route['component_id'])):016x}"


def _render_generic_adapter(route: Mapping[str, object]) -> str:
    if isinstance(route.get("contract"), Mapping) and route["contract"].get("mode") in {"native_apb", "native_wishbone_classic"}:
        from .generic_protocol_routes import render_native_adapter
        return render_native_adapter(route)
    tag = _route_tag(route)
    module = f"myfuzz_generic_adapter_{tag}"
    address_width = max(int(field["width"]) for field in route["fields"] if field["address"])
    max_wait = route["max_wait_cycles"]
    contract = route.get("contract")
    if isinstance(max_wait, bool) or not isinstance(max_wait, int) or not 1 <= max_wait <= 65_535:
        raise ValueError("generic composition adapter bound is invalid")
    if not isinstance(contract, Mapping):
        raise ValueError("generic composition adapter contract is invalid")
    control = route.get("control")
    if not isinstance(control, Mapping) or not isinstance(control.get("reset_semantics"), Mapping):
        raise ValueError("generic composition adapter reset semantics are unsupported")
    reset_semantics = control["reset_semantics"]
    polarity, synchrony = reset_semantics.get("polarity"), reset_semantics.get("synchrony")
    if polarity not in {"active_low", "active_high"} or synchrony not in {"synchronous", "asynchronous"}:
        raise ValueError("generic composition adapter reset semantics are unsupported")
    reset_event = "" if synchrony == "synchronous" else f" or {'negedge' if polarity == 'active_low' else 'posedge'} reset"
    reset_condition = "!reset" if polarity == "active_low" else "reset"
    valid_id, ready_id, error_id = (
        contract.get("request_field_id"), contract.get("response_field_id"), contract.get("error_field_id"),
    )
    if not all(isinstance(item, str) for item in (valid_id, ready_id, error_id)):
        raise ValueError("generic composition adapter handshake is invalid")
    by_id = {str(field["field_id"]): field for field in route["fields"]}
    if valid_id not in by_id or ready_id not in by_id or error_id not in by_id:
        raise ValueError("generic composition adapter handshake fields are missing")
    ports = ["    input logic clock", "    input logic reset", "    input logic component_select"]
    declarations: list[str] = [
        f"  localparam int unsigned MAX_WAIT_CYCLES = {max_wait};",
        "  typedef enum logic [1:0] { IDLE, WAIT_TARGET, RESPOND } state_t;",
        "  state_t state;",
        "  int unsigned wait_cycles;",
        "  logic timeout_error;",
    ]
    capture_request: list[str] = []
    capture_response: list[str] = []
    assignments: list[str] = []
    for field in route["fields"]:
        field_id = f"f_{canonical_id('generic-render-field', str(field['field_id'])):016x}"
        width, signed = int(field["width"]), bool(field["signed"])
        shape = _sv_logic(field_id, width, signed=signed).rsplit(" ", 1)[0]
        if field["direction"] == "input":
            ports.extend((f"    input {shape} source_{field_id}", f"    output {shape} target_{field_id}"))
            declarations.append(f"  {shape} request_{field_id};")
            expression = f"source_{field_id}"
            if field["address"]:
                expression = f"(source_{field_id} - ADDRESS_BASE)"
            capture_request.append(f"        request_{field_id} <= {expression};")
            if field["field_id"] == valid_id:
                assignments.append(f"  assign target_{field_id} = (state == WAIT_TARGET) ? request_{field_id} : '0;")
            else:
                assignments.append(f"  assign target_{field_id} = (state == WAIT_TARGET) ? request_{field_id} : '0;")
        else:
            ports.extend((f"    input {shape} target_{field_id}", f"    output {shape} response_{field_id}"))
            if field["field_id"] != ready_id:
                declarations.append(f"  {shape} response_{field_id}_latched;")
                capture_response.append(f"          response_{field_id}_latched <= target_{field_id};")
            if field["field_id"] == ready_id:
                assignments.append(f"  assign response_{field_id} = (state == RESPOND);")
            elif field["field_id"] == error_id:
                assignments.append(f"  assign response_{field_id} = (state == RESPOND) ? (timeout_error ? '1 : response_{field_id}_latched) : '0;")
            elif field["field_id"] == "irq":
                assignments.append(f"  assign response_{field_id} = target_{field_id};")
            else:
                assignments.append(f"  assign response_{field_id} = (state == RESPOND) ? response_{field_id}_latched : '0;")
    reset_assignments = []
    for field in route["fields"]:
        field_id = f"f_{canonical_id('generic-render-field', str(field['field_id'])):016x}"
        if field["direction"] == "input":
            reset_assignments.append(f"      request_{field_id} <= '0;")
        elif field["field_id"] not in {ready_id, "irq"}:
            reset_assignments.append(f"      response_{field_id}_latched <= '0;")
    return "\n".join([
        f"module {module} #(",
        f"    parameter logic [{address_width - 1}:0] ADDRESS_BASE = {_sv_literal(address_width, int(route['base']))}",
        ") (",
        ",\n".join(ports),
        ");",
        *declarations,
        f"  always_ff @(posedge clock{reset_event}) begin",
        f"    if ({reset_condition}) begin",
        "      state <= IDLE;",
        "      wait_cycles <= 0;",
        "      timeout_error <= 1'b0;",
        *reset_assignments,
        "    end else begin",
        "      case (state)",
        "        IDLE: if (component_select && source_" + f"f_{canonical_id('generic-render-field', valid_id):016x}" + ") begin",
        "          timeout_error <= 1'b0;",
        "          wait_cycles <= 0;",
        *capture_request,
        "          state <= WAIT_TARGET;",
        "        end",
        "        WAIT_TARGET: if (target_" + f"f_{canonical_id('generic-render-field', ready_id):016x}" + ") begin",
        *capture_response,
        "          state <= RESPOND;",
        "        end else if (wait_cycles + 1 >= MAX_WAIT_CYCLES) begin",
        "          timeout_error <= 1'b1;",
        "          state <= RESPOND;",
        "        end else wait_cycles <= wait_cycles + 1;",
        "        RESPOND: state <= IDLE;",
        "        default: state <= IDLE;",
        "      endcase",
        "    end",
        "  end",
        *assignments,
        "endmodule",
        "",
    ])


def _render_generic_top(plan: object) -> str:
    routes = _generic_routes(plan)
    if not routes:
        return _render_generic_source_only_top(plan)
    internal_ports = frozenset(
        str(field["source_port"]) for route in routes for field in route["fields"]
    )
    top_module, external_ports = _generic_source_top(plan, internal_ports=internal_ports)
    all_ports = _generic_port_records(plan)
    source_records = {str(record["source_port"]): record for record in all_ports}
    def source_signal(port: str) -> str:
        record = source_records.get(port)
        if record is None:
            raise ValueError("generic composition source signal is missing")
        return (
            f"source_{canonical_id('generic-render-source-port', port):016x}"
            if port in internal_ports else str(record["opaque_port"])
        )
    lines = ["// Generated from source-backed interface annotations. Do not edit.", "module generic_composition_top ("]
    declarations = []
    for record in sorted(external_ports.values(), key=lambda item: str(item["opaque_port"])):
        width = int(record["width"])
        shape = "logic" if width == 1 else f"logic {'signed ' if record['signed'] else ''}[{width - 1}:0]"
        signed = " signed" if record["signed"] and width == 1 else ""
        declarations.append(f"    {record['direction']} {shape}{signed} {record['opaque_port']}")
    lines.extend((",\n".join(declarations), ");"))
    for port in sorted(internal_ports):
        record = source_records.get(port)
        if record is None:
            raise ValueError("generic composition internal source port is missing")
        lines.append("  " + _sv_logic(f"source_{canonical_id('generic-render-source-port', port):016x}", int(record["width"]), signed=bool(record["signed"])) + ";")
    source_instance = f"u_{canonical_id('generic-source-instance', top_module):016x}"
    lines.extend((f"  {top_module} {source_instance} (",))
    source_connections = []
    for port, record in sorted(source_records.items()):
        signal = source_signal(port)
        source_connections.append(f"        .{_sv_identifier(port, context='source port')}({signal})")
    lines.extend((",\n".join(source_connections), "  );"))
    responses: dict[str, str] = {}
    irq_targets: dict[str, str] = {}
    for route in routes:
        tag = _route_tag(route)
        component_select = f"component_select_{tag}"
        terms = [
            f"(source_{canonical_id('generic-render-source-port', str(field['source_port'])):016x} >= {_sv_literal(int(field['width']), int(route['base']))} && source_{canonical_id('generic-render-source-port', str(field['source_port'])):016x} < {_sv_literal(int(field['width']), int(route['base']) + int(route['size']))})"
            for field in route["fields"] if field["address"]
        ]
        if len(terms) != 1:
            raise ValueError("generic composition adapter requires one address channel")
        lines.extend((f"  logic {component_select};", f"  assign {component_select} = " + terms[0] + ";"))
        for field in route["fields"]:
            field_tag = f"f_{canonical_id('generic-render-field', str(field['field_id'])):016x}"
            wire = f"component_{tag}_{field_tag}"
            lines.append("  " + _sv_logic(wire, int(field["width"]), signed=bool(field["signed"])) + ";")
        module_name = _sv_identifier(route["module_name"], context="component module")
        parameter_text = []
        if not isinstance(route["parameters"], Mapping):
            raise ValueError("generic composition component parameters are invalid")
        for name, value in sorted(route["parameters"].items()):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("generic composition component parameter is invalid")
            parameter_text.append(f".{_sv_identifier(name, context='component parameter')}({value})")
        instance = f"u_{canonical_id('generic-component-instance', str(route['component_id'])):016x}"
        lines.append(f"  {module_name}" + (" #(\n        " + ",\n        ".join(parameter_text) + "\n  )" if parameter_text else "") + f" {instance} (")
        component_connections = []
        for field in route["fields"]:
            field_tag = f"f_{canonical_id('generic-render-field', str(field['field_id'])):016x}"
            component_connections.append(f"        .{_sv_identifier(field['target_port'], context='component port')}(component_{tag}_{field_tag})")
        for role in ("clock", "reset"):
            control = route["control"][role]
            component_connections.append(
                f"        .{_sv_identifier(control['target_port'], context='component control port')}({source_signal(str(control['source_port']))})"
            )
        lines.extend((",\n".join(component_connections), "  );"))
        adapter_module = f"myfuzz_generic_adapter_{tag}"
        adapter_connections = [
            f"        .clock({source_signal(str(route['control']['clock']['source_port']))})",
            f"        .reset({source_signal(str(route['control']['reset']['source_port']))})",
            f"        .component_select({component_select})",
        ]
        for field in route["fields"]:
            field_tag = f"f_{canonical_id('generic-render-field', str(field['field_id'])):016x}"
            field_source_signal = source_signal(str(field["source_port"]))
            component_signal = f"component_{tag}_{field_tag}"
            if field["direction"] == "input":
                adapter_connections.extend((f"        .source_{field_tag}({field_source_signal})", f"        .target_{field_tag}({component_signal})"))
            else:
                response = f"response_{tag}_{field_tag}"
                lines.append("  " + _sv_logic(response, int(field["width"]), signed=bool(field["signed"])) + ";")
                adapter_connections.extend((f"        .target_{field_tag}({component_signal})", f"        .response_{field_tag}({response})"))
                if field["irq_route"]:
                    if str(field["source_port"]) in irq_targets:
                        raise ValueError("generic composition IRQ source has multiple targets")
                    irq_targets[str(field["source_port"])] = component_signal
                else:
                    if str(field["source_port"]) in responses:
                        raise ValueError("generic composition response source has multiple targets")
                    responses[str(field["source_port"])] = response
        lines.extend((f"  {adapter_module} u_{canonical_id('generic-adapter-instance', str(route['component_id'])):016x} (", ",\n".join(adapter_connections), "  );"))
    for port, wire in sorted(responses.items()):
        lines.append(f"  assign {source_signal(port)} = {wire};")
    for port, wire in sorted(irq_targets.items()):
        lines.append(f"  assign {source_signal(port)} = {wire};")
    lines.append("endmodule\n")
    lines.extend(_render_generic_adapter(route) for route in routes)
    return "\n".join(lines)


def _validate_generic_top(
    text: str, *, source_paths: tuple[Path, ...], include_paths: tuple[Path, ...] = (),
    define_options: tuple[str, ...] = (),
    top_path: Path | None = None,
) -> None:
    """Use the existing lightweight frontend boundary, with structural fallback."""
    from .metadata import semantic_source_hash

    semantic_source_hash(text, context="generic.composition.top")
    if not text.startswith("// Generated from source-backed interface annotations. Do not edit.\nmodule generic_composition_top "):
        raise ValueError("generic composition top structure is invalid")
    if text.count("module ") != text.count("endmodule") or text.count("module ") < 1:
        raise ValueError("generic composition top structure is invalid")
    if top_path is not None and shutil.which("verilator") is not None:
        result = subprocess.run(
             ["verilator", "--lint-only", "-Wno-fatal", "--sv", "--top-module", "generic_composition_top",
             *("-I" + path.as_posix() for path in include_paths),
             *define_options,
             *(path.as_posix() for path in source_paths), top_path.as_posix()],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError("generic composition lint failed: " + result.stderr.strip())


def _validate_generic_output_boundary(
    plan: object, output: Path, root: Path, source_paths: tuple[Path, ...],
) -> None:
    """Reject publication targets that could replace source evidence."""
    try:
        output.relative_to(root)
    except ValueError as error:
        raise ValueError("generic composition output is outside base_dir") from error
    if output == root:
        raise ValueError("generic composition output cannot be base_dir itself")
    description = getattr(plan, "interface_description", None)
    locator = getattr(description, "source", None)
    source_root = getattr(locator, "source_root", None)
    if not isinstance(source_root, str) or not source_root:
        raise ValueError("generic composition source root is invalid")
    protected = (root / source_root).resolve()
    protected_paths = (protected, *source_paths)
    for source in protected_paths:
        if output == source or output.is_relative_to(source) or source.is_relative_to(output):
            raise ValueError("generic composition output overlaps source evidence")


def _validate_generic_address_regions(ir: object) -> None:
    """Reject malformed or overlapping regions before any publication work."""
    if not isinstance(ir, Mapping):
        raise ValueError("generic composition address map is missing")
    raw_regions = ir.get("address_regions", ())
    if not isinstance(raw_regions, (tuple, list)):
        raise ValueError("generic composition address map is invalid")
    regions: list[tuple[int, int, str]] = []
    for index, region in enumerate(raw_regions):
        if not isinstance(region, Mapping):
            raise ValueError("generic composition address region is invalid")
        base = region.get("base")
        size = region.get("size")
        end = region.get("end")
        if (
            isinstance(base, bool) or not isinstance(base, int) or base < 0
            or isinstance(size, bool) or not isinstance(size, int) or size <= 0
            or isinstance(end, bool) or not isinstance(end, int)
            or end != base + size
        ):
            raise ValueError("generic composition address region is invalid")
        component_id = region.get("component_id", index)
        if not isinstance(component_id, (str, int)) or isinstance(component_id, bool):
            raise ValueError("generic composition address region is invalid")
        regions.append((base, end, str(component_id)))
    for index, (base, end, component_id) in enumerate(sorted(regions)):
        if index and base < sorted(regions)[index - 1][1]:
            previous = sorted(regions)[index - 1][2]
            raise ValueError(
                f"generic composition address-overlap:{previous}:{component_id}"
            )


def _generic_plan_reconstruction_document(plan: object) -> dict[str, object]:
    """All planner facts that the generic renderer is allowed to consume."""
    return {
        "annotations": _generic_plain(getattr(plan, "annotations", None)),
        "capabilities": [
            {
                "endpoint_id": endpoint.endpoint_id,
                "function": endpoint.function,
                "side": endpoint.side,
                "protocol": endpoint.protocol,
                "clock": endpoint.clock,
                "reset": endpoint.reset,
                "fields": [
                    (field.role, field.port, field.direction, field.width, field.signed,
                     None if field.source is None else (field.source.file, field.source.line, field.source.column),
                     field.evidence)
                    for field in endpoint.fields
                ],
                "timing": [
                    (timing.kind, timing.fields, timing.clock, timing.max_latency,
                     None if timing.source is None else (timing.source.file, timing.source.line, timing.source.column),
                     timing.evidence)
                    for timing in endpoint.timing
                ],
                "evidence": endpoint.evidence,
            }
            for endpoint in getattr(plan, "capabilities", ())
        ],
        "components": _generic_plain(getattr(plan, "components", None)),
        "matches": _generic_plain(getattr(plan, "matches", None)),
        "diagnostics": list(getattr(plan, "diagnostics", ())),
        "layout": _generic_plain(input_layout_document(getattr(plan, "layout"))),
        "ir": _generic_plain(getattr(plan, "ir", None)),
        "interface_annotation_hash": getattr(plan, "interface_annotation_hash", None),
        "composition_ir_hash": getattr(plan, "composition_ir_hash", None),
        "source_files": list(getattr(plan, "source_files", ())),
        "source_include_roots": list(getattr(plan, "source_include_roots", ())),
        "source_defines": list(getattr(plan, "source_defines", ())),
        "source_evidence_hash": getattr(plan, "source_evidence_hash", None),
    }


def _validate_generic_plan_freshness(plan: object, root: Path) -> object:
    """Rebuild all pinned records; neither plan IR nor cached evidence is authority."""
    from .auto import _generic_source_evidence_hash, plan_generic_composition

    capabilities = getattr(plan, "capabilities", None)
    protocol_catalog = getattr(plan, "protocol_catalog", None)
    request = getattr(plan, "request", None)
    component_catalog = getattr(plan, "component_catalog", None)
    if not isinstance(capabilities, tuple) or request is None or component_catalog is None:
        raise ValueError("generic composition plan reconstruction evidence is missing")
    if any(getattr(endpoint, "protocol", None) is not None for endpoint in capabilities) and protocol_catalog is None:
        raise ValueError("generic composition protocol catalog evidence is missing")
    try:
        source_files = tuple(getattr(plan, "source_files", ()))
        description = getattr(plan, "interface_description", None)
        locator = getattr(description, "source", None)
        if locator is None:
            raise ValueError("generic composition plan source locator is missing")
        current_source_hash = _generic_source_evidence_hash(
            root, source_files, locator,
        )
        expected = plan_generic_composition(
            request, base_dir=root, component_catalog=component_catalog,
            protocol_catalog=protocol_catalog,
        )
    except ValueError as error:
        raise ValueError("generic composition stale source evidence") from error
    if current_source_hash != getattr(plan, "source_evidence_hash", None):
        raise ValueError("generic composition plan reconstruction mismatch")
    if canonical_bytes(_generic_plan_reconstruction_document(plan)) != canonical_bytes(_generic_plan_reconstruction_document(expected)):
        raise ValueError("generic composition plan reconstruction mismatch")
    return expected


def _generic_source_list(plan: object, root: Path, output: Path, sources: tuple[Path, ...]) -> str:
    """Emit one output-directory-relative file list with its include context."""
    include_roots = getattr(plan, "source_include_roots", ())
    if not isinstance(include_roots, tuple):
        raise ValueError("generic composition source-list evidence is invalid")
    entries: list[str] = []
    for include_root in include_roots:
        if not isinstance(include_root, str):
            raise ValueError("generic composition source-list include root is invalid")
        include = (root / include_root).resolve()
        try:
            include.relative_to(root)
        except ValueError as error:
            raise ValueError("generic composition source-list include root escapes base_dir") from error
        if not include.is_dir():
            raise ValueError("generic composition source-list include root is missing")
        entries.append("+incdir+" + Path(os.path.relpath(include, output)).as_posix())
    defines = getattr(plan, "source_defines", ())
    if not isinstance(defines, tuple) or any(not isinstance(item, str) or not item.startswith("+define+") for item in defines):
        raise ValueError("generic composition source-list define evidence is invalid")
    entries.extend(defines)
    for source in sources:
        entries.append(Path(os.path.relpath(source, output)).as_posix())
    entries.append("generic_composition_top.sv")
    return "\n".join(entries) + "\n"


def _generic_include_paths(plan: object, root: Path) -> tuple[Path, ...]:
    """Resolve source-list include evidence once for lint and publication."""
    include_roots = getattr(plan, "source_include_roots", ())
    if not isinstance(include_roots, tuple):
        raise ValueError("generic composition source-list evidence is invalid")
    paths: list[Path] = []
    for include_root in include_roots:
        if not isinstance(include_root, str):
            raise ValueError("generic composition source-list include root is invalid")
        include = (root / include_root).resolve()
        try:
            include.relative_to(root)
        except ValueError as error:
            raise ValueError("generic composition source-list include root escapes base_dir") from error
        if not include.is_dir() or include.is_symlink():
            raise ValueError("generic composition source-list include root is missing")
        paths.append(include)
    return tuple(paths)


def _generic_define_options(plan: object) -> tuple[str, ...]:
    """Return preserved filelist macro directives for the HDL frontend."""
    defines = getattr(plan, "source_defines", ())
    if not isinstance(defines, tuple) or any(not isinstance(item, str) or not item.startswith("+define+") for item in defines):
        raise ValueError("generic composition source-list define evidence is invalid")
    return defines


def write_generic_composition(plan: object, output_dir: Path, *, base_dir: Path) -> dict[str, object]:
    """Publish a validated generic composition without risking existing output."""
    from .auto import GenericCompositionPlan

    if not isinstance(plan, GenericCompositionPlan) or not plan.complete:
        raise ValueError("generic composition plan is incomplete")
    _validate_generic_address_regions(getattr(plan, "ir", None))
    root = Path(base_dir).resolve()
    if not root.is_dir():
        raise ValueError("generic composition base_dir is missing")
    plan = _validate_generic_plan_freshness(plan, root)
    sources = tuple(_generic_source(root, source) for source in plan.source_files)
    output = Path(output_dir).resolve()
    _validate_generic_output_boundary(plan, output, root, sources)
    # POSIX has no portable atomic replacement for a non-empty directory.  A
    # backup/publish/restore sequence cannot prove recovery when the restore
    # itself fails, so reject all pre-existing destinations before staging.
    if output.exists():
        raise ValueError("generic composition existing output cannot be replaced safely")
    top_text = _render_generic_top(plan)
    output_parent = output.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    ir_payload = canonical_bytes(_generic_plain(plan.ir))
    layout_payload = canonical_bytes(_generic_plain(input_layout_document(plan.layout)))
    source_list = _generic_source_list(plan, root, output, sources)
    include_paths = _generic_include_paths(plan, root)
    stage: Path | None = Path(tempfile.mkdtemp(prefix=f".{output.name}.generic-", dir=output_parent))
    try:
        (stage / "composition_ir.json").write_bytes(ir_payload)
        (stage / "input_layout.json").write_bytes(layout_payload)
        (stage / "generic_composition_top.sv").write_text(top_text, encoding="utf-8")
        (stage / "sources.f").write_text(source_list, encoding="utf-8")
        _validate_generic_top(
            top_text, source_paths=sources, include_paths=include_paths,
            define_options=_generic_define_options(plan),
            top_path=stage / "generic_composition_top.sv",
        )
        # Re-read staged data before publishing; no destination file is touched
        # until every serialisation and renderer validation has succeeded.
        json.loads((stage / "composition_ir.json").read_text(encoding="utf-8"))
        json.loads((stage / "input_layout.json").read_text(encoding="utf-8"))
        os.replace(stage, output)
        stage = None
    finally:
        if stage is not None and stage.exists():
            for child in stage.iterdir():
                child.unlink()
            stage.rmdir()
    return {
        "schema_version": "composition_ir.v1",
        "interface_annotation_hash": plan.interface_annotation_hash,
        "composition_ir_hash": plan.composition_ir_hash,
        "layout_hash": plan.layout.layout_hash,
        "top_path": (output / "generic_composition_top.sv").as_posix(),
        "source_list_path": (output / "sources.f").as_posix(),
        "complete": True,
    }


__all__ = [
    "CompositionArtifact",
    "compose_protocol_composition",
    "write_generic_composition",
    "write_protocol_composition",
]
