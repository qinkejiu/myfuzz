"""Protocol-selected adapters for the generic processor memory boundary."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .processor_boundary import ProcessorMemoryBinding


class ProcessorAdapterError(ValueError):
    """Raised when a processor endpoint has no fully declared backend adapter."""


@dataclass(frozen=True, slots=True)
class ExtensionPolicy:
    role: str
    direction: str
    action: str
    width: int | None = None
    width_group: str | None = None
    width_of: str | None = None
    width_divisor: int = 1


@dataclass(frozen=True, slots=True)
class ProcessorAdapterDefinition:
    adapter_id: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    rtl_module: str
    rtl_source: str
    features: tuple[str, ...]
    extension_policies: tuple[ExtensionPolicy, ...]
    source_ports: tuple[tuple[str, str, str], ...]
    reset_polarity: str
    reset_synchrony: str
    parameter_values: tuple[tuple[str, int], ...] = ()


_AXI4_EXTENSION_POLICIES = tuple(sorted((
    ExtensionPolicy("awlock", "output", "reject-nonzero", width=1),
    ExtensionPolicy("awcache", "output", "accept-ignore", width=4),
    ExtensionPolicy("awprot", "output", "accept-ignore", width=3),
    ExtensionPolicy("awqos", "output", "accept-ignore", width=4),
    ExtensionPolicy("awregion", "output", "accept-ignore", width=4),
    ExtensionPolicy("awatop", "output", "reject-with-axi-completion", width=6),
    ExtensionPolicy("awuser", "output", "accept-ignore", width_group="user"),
    ExtensionPolicy("wuser", "output", "accept-ignore", width_group="user"),
    ExtensionPolicy("buser", "input", "drive-zero", width_group="user"),
    ExtensionPolicy("arlock", "output", "reject-nonzero", width=1),
    ExtensionPolicy("arcache", "output", "accept-ignore", width=4),
    ExtensionPolicy("arprot", "output", "accept-ignore", width=3),
    ExtensionPolicy("arqos", "output", "accept-ignore", width=4),
    ExtensionPolicy("arregion", "output", "accept-ignore", width=4),
    ExtensionPolicy("aruser", "output", "accept-ignore", width_group="user"),
    ExtensionPolicy("ruser", "input", "drive-zero", width_group="user"),
), key=lambda item: item.role))

_OBI_EXTENSION_POLICIES = (
    ExtensionPolicy("be", "output", "pass-byte-enable", width_of="wdata", width_divisor=8),
    ExtensionPolicy("error", "input", "propagate-backend-error", width=1),
)

_READY_VALID_EXTENSION_POLICIES = ()

# TL-UL user/integrity sidebands are optional in the generic processor
# contract.  They are protocol fields when a component declares them, but a
# legacy endpoint may omit them entirely.  The resolver adds their adapter
# ports only for the endpoint that actually declares the field; this keeps the
# published source-port map backward compatible for the minimal TL-UL fixture.
_TL_UL_EXTENSION_POLICIES = (
    ExtensionPolicy("a_user", "output", "pass-through"),
    ExtensionPolicy("d_user", "input", "pass-through"),
    ExtensionPolicy("d_error", "input", "propagate-backend-error", width=1),
)
_TL_UL_OPTIONAL_PORTS = {
    "a_user": ("a_user_i", "input"),
    "d_user": ("d_user_o", "output"),
    "d_error": ("d_error_o", "output"),
}

# Wishbone SEL is the byte enable, exactly as OBI's BE is: a master that has it
# passes it through, and a master that does not is projected onto a full byte
# enable rather than having a transfer size invented for it.
_WISHBONE_EXTENSION_POLICIES = (
    ExtensionPolicy("sel", "output", "pass-byte-enable", width_of="dat_w",
                    width_divisor=8),
)

# AXI4-Lite protection bits carry no information the beat backend can use, and
# the AXI4 adapter applies the same accept-and-ignore policy to its sidebands.
_AXI4_LITE_EXTENSION_POLICIES = tuple(sorted((
    ExtensionPolicy("awprot", "output", "accept-ignore", width=3),
    ExtensionPolicy("arprot", "output", "accept-ignore", width=3),
), key=lambda item: item.role))

_ADAPTERS = {
    ("axi4", "1"): ProcessorAdapterDefinition(
        adapter_id="axi4-to-processor-memory-beat",
        source_protocol=("axi4", "1"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="axi4_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv",
        features=(
            "single-outstanding",
            "single-beat",
            "independent-write-channels",
            "id-roundtrip",
            "partial-write",
            "error-response",
        ),
        extension_policies=_AXI4_EXTENSION_POLICIES,
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("awid", "awid_i", "input"), ("awaddr", "awaddr_i", "input"),
            ("awlen", "awlen_i", "input"), ("awsize", "awsize_i", "input"),
            ("awburst", "awburst_i", "input"), ("awlock", "awlock_i", "input"),
            ("awcache", "awcache_i", "input"), ("awprot", "awprot_i", "input"),
            ("awqos", "awqos_i", "input"), ("awregion", "awregion_i", "input"),
            ("awatop", "awatop_i", "input"), ("awuser", "awuser_i", "input"),
            ("awvalid", "awvalid_i", "input"), ("awready", "awready_o", "output"),
            ("wdata", "wdata_i", "input"), ("wstrb", "wstrb_i", "input"),
            ("wlast", "wlast_i", "input"), ("wuser", "wuser_i", "input"),
            ("wvalid", "wvalid_i", "input"), ("wready", "wready_o", "output"),
            ("bid", "bid_o", "output"), ("bresp", "bresp_o", "output"),
            ("buser", "buser_o", "output"), ("bvalid", "bvalid_o", "output"),
            ("bready", "bready_i", "input"), ("arid", "arid_i", "input"),
            ("araddr", "araddr_i", "input"), ("arlen", "arlen_i", "input"),
            ("arsize", "arsize_i", "input"), ("arburst", "arburst_i", "input"),
            ("arlock", "arlock_i", "input"), ("arcache", "arcache_i", "input"),
            ("arprot", "arprot_i", "input"), ("arqos", "arqos_i", "input"),
            ("arregion", "arregion_i", "input"), ("aruser", "aruser_i", "input"),
            ("arvalid", "arvalid_i", "input"), ("arready", "arready_o", "output"),
            ("rid", "rid_o", "output"), ("rdata", "rdata_o", "output"),
            ("rresp", "rresp_o", "output"), ("rlast", "rlast_o", "output"),
            ("ruser", "ruser_o", "output"), ("rvalid", "rvalid_o", "output"),
            ("rready", "rready_i", "input"),
        ),
    ),
    ("obi", "1"): ProcessorAdapterDefinition(
        adapter_id="obi-to-processor-memory-beat",
        source_protocol=("obi", "1"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="obi_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
        features=(
            "single-outstanding", "read-only-or-read-write", "grant-backpressure",
            "partial-write-when-byte-enable-present", "error-response",
        ),
        extension_policies=_OBI_EXTENSION_POLICIES,
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("req", "req_i", "input"), ("gnt", "gnt_o", "output"),
            ("addr", "addr_i", "input"), ("we", "we_i", "input"),
            ("wdata", "wdata_i", "input"), ("be", "be_i", "input"),
            ("rvalid", "rvalid_o", "output"), ("rdata", "rdata_o", "output"),
            ("error", "error_o", "output"),
        ),
    ),
    ("ready-valid-memory", "1"): ProcessorAdapterDefinition(
        adapter_id="ready-valid-to-processor-memory-beat",
        source_protocol=("ready-valid-memory", "1"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="ready_valid_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/ready_valid_processor_memory_adapter.sv",
        features=(
            "single-outstanding", "read-write", "partial-write",
            "error-response-zero", "bounded-completion",
        ),
        extension_policies=_READY_VALID_EXTENSION_POLICIES,
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("valid", "valid_i", "input"), ("ready", "ready_o", "output"),
            ("addr", "addr_i", "input"), ("wdata", "wdata_i", "input"),
            ("wstrb", "wstrb_i", "input"), ("rdata", "rdata_o", "output"),
        ),
    ),
    ("tl-ul", "1"): ProcessorAdapterDefinition(
        adapter_id="tl-ul-to-processor-memory-beat",
        source_protocol=("tl-ul", "1"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="tl_ul_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/tl_ul_processor_memory_adapter.sv",
        features=(
            "single-outstanding", "get", "put-full", "put-partial",
            "source-roundtrip", "denied-corrupt-error", "partial-write",
        ),
        # Optional user/integrity fields are added per binding by
        # ``resolve_processor_adapter``; the minimal TL-UL endpoint keeps the
        # historical empty extension-policy contract.
        extension_policies=(),
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("a_valid", "a_valid_i", "input"), ("a_ready", "a_ready_o", "output"),
            ("a_opcode", "a_opcode_i", "input"), ("a_param", "a_param_i", "input"),
            ("a_size", "a_size_i", "input"), ("a_source", "a_source_i", "input"),
            ("a_address", "a_address_i", "input"), ("a_mask", "a_mask_i", "input"),
            ("a_data", "a_data_i", "input"), ("a_corrupt", "a_corrupt_i", "input"),
            ("d_valid", "d_valid_o", "output"), ("d_ready", "d_ready_i", "input"),
            ("d_opcode", "d_opcode_o", "output"), ("d_param", "d_param_o", "output"),
            ("d_size", "d_size_o", "output"), ("d_source", "d_source_o", "output"),
            ("d_sink", "d_sink_o", "output"), ("d_denied", "d_denied_o", "output"),
            ("d_data", "d_data_o", "output"), ("d_corrupt", "d_corrupt_o", "output"),
        ),
    ),
    ("wishbone", "classic"): ProcessorAdapterDefinition(
        adapter_id="wishbone-to-processor-memory-beat",
        source_protocol=("wishbone", "classic"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="wishbone_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/wishbone_processor_memory_adapter.sv",
        features=(
            "single-outstanding",
            "single-beat",
            "cycle-strobe-held-until-completion",
            "partial-write-when-select-present",
            "error-response",
        ),
        extension_policies=_WISHBONE_EXTENSION_POLICIES,
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("cyc", "cyc_i", "input"), ("stb", "stb_i", "input"),
            ("we", "we_i", "input"), ("adr", "adr_i", "input"),
            ("dat_w", "dat_w_i", "input"), ("sel", "sel_i", "input"),
            ("stall", "stall_o", "output"), ("ack", "ack_o", "output"),
            ("err", "err_o", "output"), ("dat_r", "dat_r_o", "output"),
        ),
    ),
    ("axi4-lite", "1"): ProcessorAdapterDefinition(
        adapter_id="axi4-lite-to-processor-memory-beat",
        source_protocol=("axi4-lite", "1"),
        target_protocol=("processor-memory-beat", "1"),
        rtl_module="axi4_lite_processor_memory_adapter",
        rtl_source="src/myfuzz/protocols/rtl/axi4_lite_processor_memory_adapter.sv",
        features=(
            "single-outstanding",
            "single-beat",
            "independent-write-channels",
            "byte-enable",
            "error-response",
            "no-bursts",
            "no-ids",
        ),
        extension_policies=_AXI4_LITE_EXTENSION_POLICIES,
        reset_polarity="active_low",
        reset_synchrony="synchronous",
        source_ports=(
            ("awaddr", "awaddr_i", "input"), ("awprot", "awprot_i", "input"),
            ("awvalid", "awvalid_i", "input"), ("awready", "awready_o", "output"),
            ("wdata", "wdata_i", "input"), ("wstrb", "wstrb_i", "input"),
            ("wvalid", "wvalid_i", "input"), ("wready", "wready_o", "output"),
            ("bresp", "bresp_o", "output"), ("bvalid", "bvalid_o", "output"),
            ("bready", "bready_i", "input"), ("araddr", "araddr_i", "input"),
            ("arprot", "arprot_i", "input"), ("arvalid", "arvalid_i", "input"),
            ("arready", "arready_o", "output"), ("rdata", "rdata_o", "output"),
            ("rresp", "rresp_o", "output"), ("rvalid", "rvalid_o", "output"),
            ("rready", "rready_i", "input"),
        ),
    ),
}


def resolve_processor_adapter(
    memory: ProcessorMemoryBinding,
) -> ProcessorAdapterDefinition:
    """Resolve only from a declared protocol and validate every extension."""
    try:
        adapter = _ADAPTERS[memory.protocol]
    except KeyError as error:
        raise ProcessorAdapterError(
            f"unsupported-processor-adapter:{memory.protocol[0]}@{memory.protocol[1]}"
        ) from error
    optional_tl_roles = {
        field.role for field in memory.fields if field.role in _TL_UL_OPTIONAL_PORTS
    } if memory.protocol == ("tl-ul", "1") else set()
    effective_policies = (adapter.extension_policies if memory.protocol != ("tl-ul", "1")
                          else tuple(item for item in _TL_UL_EXTENSION_POLICIES
                                     if item.role in optional_tl_roles))
    policies = {item.role: item for item in effective_policies}
    source_port_records = list(adapter.source_ports)
    if memory.protocol == ("tl-ul", "1"):
        declared_roles = {field.role for field in memory.fields}
        source_port_records.extend(
            (role, port, direction)
            for role, (port, direction) in _TL_UL_OPTIONAL_PORTS.items()
            if role in declared_roles
        )
    source_ports = {role: (port, direction) for role, port, direction in source_port_records}
    if len(source_ports) != len(source_port_records):
        raise ProcessorAdapterError(f"adapter-source-port-duplicate:{adapter.adapter_id}")
    protocol_roles = set(source_ports) - set(policies)
    seen: set[str] = set()
    field_roles = {field.role for field in memory.fields}
    has_we = "we" in field_roles
    if memory.protocol == ("obi", "1"):
        has_wdata = "wdata" in field_roles
        if has_we != has_wdata:
            raise ProcessorAdapterError("obi-write-fields")
        if "be" in field_roles and not has_we:
            raise ProcessorAdapterError("obi-byte-enable-without-write")
        if "error" not in field_roles:
            raise ProcessorAdapterError("obi-error-field")
    grouped_widths: dict[str, set[int]] = {}
    for field in memory.fields:
        port_fact = source_ports.get(field.role)
        if port_fact is None:
            raise ProcessorAdapterError(f"unsupported-extension:{field.role}")
        expected_adapter_direction = "input" if field.direction == "output" else "output"
        if field.role in protocol_roles:
            if port_fact[1] != expected_adapter_direction:
                raise ProcessorAdapterError(f"adapter-source-direction:{field.role}")
            continue
        if field.role in seen:
            raise ProcessorAdapterError(f"invalid-extension:{field.role}")
        seen.add(field.role)
        policy = policies.get(field.role)
        if policy is None:
            raise ProcessorAdapterError(f"unsupported-extension:{field.role}")
        if field.direction != policy.direction:
            raise ProcessorAdapterError(f"extension-direction:{field.role}")
        if policy.width is not None and field.width != policy.width:
            raise ProcessorAdapterError(f"extension-width:{field.role}")
        if policy.width_of is not None:
            reference = next(
                (item for item in memory.fields if item.role == policy.width_of), None
            )
            if (reference is None or reference.width % policy.width_divisor != 0 or
                    field.width != reference.width // policy.width_divisor):
                raise ProcessorAdapterError(f"extension-width:{field.role}")
        if policy.width_group is not None:
            grouped_widths.setdefault(policy.width_group, set()).add(field.width)
        if port_fact[1] != expected_adapter_direction:
            raise ProcessorAdapterError(f"adapter-source-direction:{field.role}")
    for group, widths in grouped_widths.items():
        if len(widths) != 1:
            raise ProcessorAdapterError(f"extension-width-group:{group}")
    if memory.protocol == ("obi", "1"):
        return replace(adapter, parameter_values=(
            ("READ_ONLY", int(not has_we)),
            ("HAS_BE", int("be" in seen)),
            ("HAS_ERROR", 1),
        ))
    if memory.protocol == ("wishbone", "classic"):
        return replace(adapter, parameter_values=(
            ("READ_ONLY", int(not has_we)),
            ("HAS_SEL", int("sel" in seen)),
        ))
    if memory.protocol == ("tl-ul", "1") and len(source_port_records) != len(adapter.source_ports):
        # Keep the historical module's port list intact for legacy benches
        # that instantiate it with ``.*``.  Endpoints that actually declare
        # TL-UL sidebands use the explicit wrapper in the same RTL source;
        # this makes the optional contract real without breaking the minimal
        # adapter ABI.
        return replace(
            adapter,
            rtl_module="tl_ul_processor_memory_adapter_sideband",
            source_ports=tuple(source_port_records),
            extension_policies=effective_policies,
        )
    return adapter


__all__ = [
    "ExtensionPolicy",
    "ProcessorAdapterDefinition",
    "ProcessorAdapterError",
    "resolve_processor_adapter",
]
