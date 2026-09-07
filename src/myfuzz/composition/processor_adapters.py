"""Protocol-selected adapters for the generic processor memory boundary."""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class ProcessorAdapterDefinition:
    adapter_id: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    rtl_module: str
    rtl_source: str
    features: tuple[str, ...]
    extension_policies: tuple[ExtensionPolicy, ...]


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
    policies = {item.role: item for item in adapter.extension_policies}
    seen: set[str] = set()
    field_roles = {field.role for field in memory.fields}
    grouped_widths: dict[str, set[int]] = {}
    for field in memory.extension_fields:
        if field.role in seen or field.role not in field_roles:
            raise ProcessorAdapterError(f"invalid-extension:{field.role}")
        seen.add(field.role)
        policy = policies.get(field.role)
        if policy is None:
            raise ProcessorAdapterError(f"unsupported-extension:{field.role}")
        if field.direction != policy.direction:
            raise ProcessorAdapterError(f"extension-direction:{field.role}")
        if policy.width is not None and field.width != policy.width:
            raise ProcessorAdapterError(f"extension-width:{field.role}")
        if policy.width_group is not None:
            grouped_widths.setdefault(policy.width_group, set()).add(field.width)
    for group, widths in grouped_widths.items():
        if len(widths) != 1:
            raise ProcessorAdapterError(f"extension-width-group:{group}")
    return adapter


__all__ = [
    "ExtensionPolicy",
    "ProcessorAdapterDefinition",
    "ProcessorAdapterError",
    "resolve_processor_adapter",
]
