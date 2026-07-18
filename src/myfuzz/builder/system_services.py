"""Deterministically place generated runtime services around a SoCIR v2 design."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
from typing import Mapping

from .addressing import AddressIntent, allocate_addresses
from .contracts import CpuExecutionProfile, SoCIRV2, canonical_json, seal_contract
from .input_model import AddressMode, AddressRequest, InputValidationError


@dataclass(frozen=True)
class SystemServiceRegion:
    instance_id: str
    kind: str
    base: int
    size: int
    source: str
    coverage_scope: bool = False
    protocol: str = "axi_lite"


@dataclass(frozen=True)
class SystemServicePlan:
    cpu_id: str
    address_width: int
    reset_vector: int
    regions: tuple[SystemServiceRegion, ...]
    profile_digest: str
    digest: str

    def to_dict(self) -> Mapping[str, object]:
        return asdict(self)


_AUTO_SERVICES = (
    ("__myfuzz_data_ram", "data_ram", 0x10000, 0x10000),
    ("__myfuzz_operation_status", "operation_status", 0x1000, 0x1000),
    ("__myfuzz_interrupt_mapper", "interrupt_mapper", 0x1000, 0x1000),
    ("__myfuzz_reset_controller", "reset_controller", 0x1000, 0x1000),
    ("__myfuzz_epoch", "epoch", 0x1000, 0x1000),
)


def plan_system_services(
    soc_address_views: tuple[Mapping[str, object], ...],
    cpu_profile: CpuExecutionProfile,
) -> SystemServicePlan:
    """Place mandatory services without relying on any leaf module identity."""
    if cpu_profile.data_width != 32:
        raise InputValidationError("generated system services require a 32-bit CPU data width")
    address_width = cpu_profile.address_width
    intents = []
    for index, view in enumerate(soc_address_views):
        try:
            name = str(view["instance_id"])
            base = int(view["global_base"])
            size = int(view["size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError(f"SoC address view {index} is incomplete") from exc
        intents.append(AddressIntent(name, AddressRequest(AddressMode.FIXED, size, base, size)))

    fixed_services = (
        ("__myfuzz_boot_rom", "boot_rom", cpu_profile.rom_window),
        ("__myfuzz_control_mailbox", "control_mailbox", cpu_profile.mailbox_window),
        ("__myfuzz_watchdog", "watchdog", cpu_profile.watchdog_window),
    )
    for instance_id, _kind, window in fixed_services:
        intents.append(AddressIntent(instance_id, AddressRequest(
            AddressMode.FIXED, int(window["size"]), int(window["base"]), int(window["size"]),
        )))
    for instance_id, _kind, size, alignment in _AUTO_SERVICES:
        intents.append(AddressIntent(instance_id, AddressRequest(AddressMode.AUTO, size, None, alignment)))

    allocated = allocate_addresses(intents, address_width=address_width)
    by_name = {window.module: window for window in allocated.windows}
    regions = []
    for instance_id, kind, _window in fixed_services:
        window = by_name[instance_id]
        regions.append(SystemServiceRegion(instance_id, kind, window.base, window.size, window.source))
    for instance_id, kind, _size, _alignment in _AUTO_SERVICES:
        window = by_name[instance_id]
        regions.append(SystemServiceRegion(instance_id, kind, window.base, window.size, window.source))
    regions.sort(key=lambda item: (item.base, item.instance_id))

    rom = next(item for item in regions if item.kind == "boot_rom")
    if not rom.base <= cpu_profile.reset_vector < rom.base + rom.size:
        raise InputValidationError("CPU reset vector is outside the planned boot ROM")
    profile_payload = cpu_profile.to_dict()
    profile_digest = hashlib.sha256(canonical_json(profile_payload)).hexdigest()
    payload = {
        "cpu_id": cpu_profile.cpu_id,
        "address_width": address_width,
        "reset_vector": cpu_profile.reset_vector,
        "regions": [asdict(item) for item in regions],
        "profile_digest": profile_digest,
    }
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    return SystemServicePlan(
        cpu_profile.cpu_id, address_width, cpu_profile.reset_vector,
        tuple(regions), profile_digest, digest,
    )


def add_system_services_to_soc_ir(soc: SoCIRV2, plan: SystemServicePlan) -> SoCIRV2:
    """Return a new sealed SoCIR whose generated services are explicit nodes."""
    existing_ids = {
        *(str(item["instance_id"]) for item in soc.instances),
        *(str(item["node_id"]) for item in soc.service_nodes),
    }
    collisions = sorted(existing_ids.intersection(item.instance_id for item in plan.regions))
    if collisions:
        raise InputValidationError("generated service ID collision: " + ", ".join(collisions))
    existing_views = {str(item["instance_id"]): item for item in soc.address_views}
    for region in plan.regions:
        for name, view in existing_views.items():
            base = int(view["global_base"]); size = int(view["size"])
            if region.base < base + size and base < region.base + region.size:
                raise InputValidationError(
                    f"generated service {region.instance_id} overlaps SoC target {name}"
                )

    services = tuple(soc.service_nodes) + tuple({
        "node_id": item.instance_id,
        "kind": item.kind,
        "protocol": item.protocol,
        "coverage_scope": item.coverage_scope,
        "address": {"base": item.base, "size": item.size},
        "provenance": {"source": item.source, "service_plan_digest": plan.digest},
    } for item in plan.regions)
    endpoints = tuple(soc.endpoints) + tuple({
        "endpoint_id": f"{item.instance_id}.bus",
        "instance_id": item.instance_id,
        "protocol": item.protocol,
        "role": "target",
        "profile": "generated_service_axi_lite/v1",
        "signals": (),
        "provenance": {"source": "system_service_plan", "service_plan_digest": plan.digest},
    } for item in plan.regions)
    views = tuple(soc.address_views) + tuple({
        "instance_id": item.instance_id,
        "global_base": item.base,
        "size": item.size,
        "byte_address_unit": 1,
        "local_address_width": plan.address_width,
        "transform": "local = global - global_base",
        "preserved_offset_bits": 0,
        "alignment": item.size,
        "alias_policy": "reject",
        "provenance": {"source": item.source, "service_plan_digest": plan.digest},
    } for item in plan.regions)
    provenance = dict(soc.provenance)
    provenance["system_service_plan_digest"] = plan.digest
    augmented = replace(
        soc, service_nodes=services, endpoints=endpoints, address_views=views,
        provenance=provenance, digest="",
    )
    return seal_contract(augmented)  # type: ignore[return-value]
