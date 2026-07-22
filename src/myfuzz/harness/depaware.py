"""Dependency-aware protocol projection retaining the direct ABI."""

from __future__ import annotations

from collections.abc import Mapping

from .abi import (
    RawBitAbi,
    RawBitUse,
    build_raw_abi,
    content_hash,
    dependency_group_for_port,
    dependency_groups,
    selected_ports,
)
from .direct import HarnessArtifact, candidate_id, coverage_id, emit_direct


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


def build_depaware(manifest: object) -> HarnessArtifact:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    direct_abi = build_raw_abi(manifest)
    retained = _retained(manifest)
    ports = selected_ports(manifest)
    uses = tuple(
        RawBitUse(
            use.raw_lo,
            use.raw_hi,
            use.destination_id,
            use.destination_lo,
            "direct" if dependency_group_for_port(port) is None or dependency_group_for_port(port) in retained else "gate",
            "dependency_retained" if dependency_group_for_port(port) is None or dependency_group_for_port(port) in retained else "dependency_removed",
        )
        for use, port in zip(direct_abi.uses, ports)
    )
    abi_document = {
        "raw_width": direct_abi.raw_width,
        "destinations": [
            {"destination_id": item.destination_id, "component_id": item.component_id, "port_id": item.port_id, "width": item.width}
            for item in direct_abi.destinations
        ],
        "uses": [
            {"raw_lo": item.raw_lo, "raw_hi": item.raw_hi, "destination_id": item.destination_id, "destination_lo": item.destination_lo, "action": item.action, "category": item.category}
            for item in uses
        ],
    }
    abi = RawBitAbi(direct_abi.raw_width, direct_abi.destinations, uses, content_hash(abi_document))
    abi.validate_total_use()
    gated = frozenset(
        port["port_id"]
        for port in ports
        if dependency_group_for_port(port) is not None and dependency_group_for_port(port) not in retained
    )
    source = emit_direct(manifest, "candidate_depaware", abi, gated_port_ids=gated)
    return HarnessArtifact("candidate_depaware", abi.raw_width, coverage_id(manifest), candidate_id(manifest), abi, source, content_hash({"source_text": source}))
