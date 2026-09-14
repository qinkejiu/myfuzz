"""Deterministic Python plan for the P6 SoC arbiter/router fabric."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .processor_backend import (
    ProcessorBackendError,
    build_processor_backend,
    processor_backend_document,
)


class SocFabricError(ValueError):
    """The declared SoC cannot be represented by the current P6 RTL."""


_RTL_SOURCES = (
    "src/myfuzz/protocols/rtl/soc_arbiter.sv",
    "src/myfuzz/protocols/rtl/soc_router.sv",
    "src/myfuzz/protocols/rtl/mmio_width_adapter.sv",
)
_SOURCE_ORDER = {"cpu_instruction": 0, "cpu_data": 1, "cpu_unified": 2, "fuzz_mmio": 3}


def _integer(value: object, reason: str, *, positive: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value <= 0):
        raise SocFabricError(reason)
    return value


def _records(spec: Mapping[str, object], name: str) -> list[Mapping[str, object]]:
    value = spec.get(name)
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SocFabricError(f"{name}:type")
    if not all(isinstance(item, Mapping) for item in value):
        raise SocFabricError(f"{name}:item")
    return list(value)


def _permissions(value: object, default: Mapping[str, bool] | None = None) -> dict[str, bool]:
    if value is None and default is not None:
        return dict(default)
    if not isinstance(value, Mapping):
        raise SocFabricError("permissions")
    result = {name: value.get(name) for name in ("read", "write", "execute")}
    if not all(isinstance(flag, bool) for flag in result.values()):
        raise SocFabricError("permissions")
    return result  # type: ignore[return-value]


def build_soc_fabric(spec: Mapping[str, object], processor_execution: Mapping[str, object]) -> dict[str, object]:
    """Build a JSON-compatible plan matching the committed P6 RTL parameters.

    Per-target source filtering is encoded in the router's packed window mask.
    The configured wait limit is an external runtime-watchdog contract and is
    not advertised as RTL logic.
    """
    if not isinstance(spec, Mapping):
        raise SocFabricError("spec:type")
    masters = _records(spec, "masters")
    regions = _records(spec, "memory_regions")
    targets = _records(spec, "targets")
    resources = spec.get("resources", {})
    # A spec assertion is not physical reset-wiring proof.  A later validated
    # renderer/net-binding step may promote this only after checking the
    # router, every width adapter, and every downstream target share the reset.
    reset_scope_verified = False

    source_ids = [item.get("source_id") for item in masters]
    if any(not isinstance(item, str) or not item for item in source_ids) or len(set(source_ids)) != len(source_ids):
        raise SocFabricError("source-id")
    for master in masters:
        if master.get("kind") not in _SOURCE_ORDER:
            raise SocFabricError("master-kind")
        protocol = master.get("protocol")
        if (not isinstance(protocol, (list, tuple)) or len(protocol) != 2
                or not all(isinstance(part, str) and part for part in protocol)):
            raise SocFabricError("master-protocol")
    ordered_masters = sorted(masters, key=lambda item: (_SOURCE_ORDER[str(item["kind"])], str(item["source_id"])))
    cpu_masters = [item for item in ordered_masters if str(item.get("kind", "")).startswith("cpu_")]
    backend_regions = []
    for region in regions:
        base = _integer(region.get("base"), "address-region", positive=False)
        if base < 0:
            raise SocFabricError("address-region")
        _integer(region.get("size"), "address-region")
    sorted_regions = sorted(regions, key=lambda item: (item["base"], str(item.get("region_id", ""))))
    for index, region in enumerate(sorted_regions):
        base = _integer(region.get("base"), "address-region", positive=False)
        size = _integer(region.get("size"), "address-region")
        backend_regions.append({
            "region_id": index,
            "component_id": region.get("region_id", region.get("component_id")),
            "base": base,
            "size": size,
            "end": base + size,
            "address_width": cpu_masters[0].get("address_width") if cpu_masters else 32,
        })
    try:
        backend = processor_backend_document(build_processor_backend(processor_execution, backend_regions))
    except ProcessorBackendError as error:
        raise SocFabricError(str(error)) from error

    route_functions = {item["function"] for item in backend["initiators"]}
    cpu_kinds = {item.get("kind") for item in cpu_masters}
    if cpu_kinds == {"cpu_unified"}:
        expected = bool(route_functions & {"memory_master", "processor_memory_master"})
    else:
        expected = cpu_kinds == {"cpu_instruction", "cpu_data"} and route_functions == {
            "instruction_memory_master", "data_memory_master"
        }
    if not expected or len(cpu_masters) != len(backend["initiators"]):
        raise SocFabricError("cpu-route-shape")

    address_width = int(backend["widths"]["address"])
    data_width = int(backend["widths"]["data"])
    if data_width not in (32, 64):
        raise SocFabricError("fabric-data-width")
    for master in ordered_masters:
        if master.get("address_width") != address_width or master.get("data_width") != data_width:
            raise SocFabricError("master-width-mismatch")
        if master.get("kind") == "fuzz_mmio" and master.get("protocol") != ["processor-memory-beat", "1"]:
            raise SocFabricError("master-protocol")
    target_ids = [target.get("target_id") for target in targets]
    if (any(not isinstance(target_id, str) or not target_id for target_id in target_ids)
            or len(set(target_ids)) != len(target_ids)):
        raise SocFabricError("duplicate-target-id")
    all_sources = set(source_ids)
    for target in targets:
        requested = target.get("request_sources")
        if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)):
            raise SocFabricError("request-sources")
        if not set(requested).issubset(all_sources) or not requested:
            raise SocFabricError(f"request-sources:{target.get('target_id')}")

    region_by_window: dict[tuple[object, int, int], Mapping[str, object]] = {}
    for region in regions:
        region_by_window[(region.get("component_id"), int(region["base"]), int(region["size"]))] = region
    backing_keys: dict[str, tuple[str, str]] = {}
    window_rows: list[dict[str, object]] = []
    for target in targets:
        window = target.get("window")
        if not isinstance(window, Mapping):
            raise SocFabricError("target-window")
        base = _integer(window.get("base"), "target-window", positive=False)
        if base < 0:
            raise SocFabricError("target-window")
        size = _integer(window.get("size"), "target-window")
        if base + size > (1 << address_width):
            raise SocFabricError("address-overflow")
        region = region_by_window.get((target.get("component_id"), base, size))
        if region is not None:
            window_id = str(region.get("region_id"))
            backing = ("memory", str(region.get("physical_memory_id")))
            permissions = _permissions(region.get("permissions"))
        else:
            window_id = str(target.get("target_id"))
            backing = ("target", window_id)
            permissions = _permissions(target.get("permissions"), {"read": True, "write": True, "execute": False})
        backing_keys[window_id] = backing
        window_rows.append({"window_id": window_id, "target_id": str(target.get("target_id")),
                            "base": base, "size": size, "end": base + size,
                            "permissions": permissions,
                            "allowed_source_mask": sum(
                                1 << index for index, master in enumerate(ordered_masters)
                                if master["source_id"] in target["request_sources"]
                            )})
    window_rows.sort(key=lambda row: (int(row["base"]), str(row["window_id"])))
    for left, right in zip(window_rows, window_rows[1:]):
        if int(right["base"]) < int(left["end"]):
            raise SocFabricError("address-overlap")

    unique_backings = sorted(set(backing_keys.values()))
    backing_index = {value: index for index, value in enumerate(unique_backings)}
    for row in window_rows:
        row["target_index"] = backing_index[backing_keys[str(row["window_id"])]]
    canonical_memory_bases = {
        index: min(int(row["base"]) for row in window_rows if row["target_index"] == index)
        for index, backing in enumerate(unique_backings) if backing[0] == "memory"
    }
    for row in window_rows:
        row["target_base"] = canonical_memory_bases.get(int(row["target_index"]), int(row["base"]))

    width_adapters: list[dict[str, object]] = []
    targets_by_id = {str(target.get("target_id")): target for target in targets}
    for index, backing in enumerate(unique_backings):
        associated = [row for row in window_rows if row["target_index"] == index]
        target_widths = {targets_by_id[str(row["target_id"])].get("data_width") for row in associated}
        if len(target_widths) != 1:
            raise SocFabricError("target-width-mismatch")
        target_width = _integer(next(iter(target_widths)), "target-width")
        if target_width not in (32, 64):
            raise SocFabricError("target-width")
        if target_width == data_width:
            continue
        if (data_width, target_width) != (64, 32):
            raise SocFabricError("unsupported-width-conversion")
        policies = [targets_by_id[str(row["target_id"])].get("width_conversion", {}) for row in associated]
        if any(policy != policies[0] for policy in policies[1:]):
            raise SocFabricError("width-policy-mismatch")
        policy = targets_by_id[str(associated[0]["target_id"])].get("width_conversion", {})
        if not isinstance(policy, Mapping):
            raise SocFabricError("width-policy")
        write_policy = policy.get("spanning_write", "reject")
        read_policy = policy.get("spanning_read", "reject")
        if write_policy not in ("reject", "split_side_effect_free") or read_policy not in ("reject", "assemble_side_effect_free"):
            raise SocFabricError("width-policy")
        width_adapters.append({
            "target_index": index, "module": "mmio_width_adapter",
            "source": _RTL_SOURCES[2],
            "parameters": {"ADDRESS_WIDTH": address_width, "DATA_WIDTH": 64,
                           "PERIPHERAL_DATA_WIDTH": 32,
                           "ALLOW_SPANNING_WRITE_SPLIT": int(write_policy == "split_side_effect_free"),
                           "ALLOW_SPANNING_READ_ASSEMBLE": int(read_policy == "assemble_side_effect_free"),
                           "RESET_CLEARS_TARGETS": int(reset_scope_verified)},
        })

    sources = [{"index": index, "source_id": item["source_id"], "kind": item.get("kind"),
                "ingress_protocol": ["processor-memory-beat", "1"],
                "instruction": item.get("kind") == "cpu_instruction"}
               for index, item in enumerate(ordered_masters)]
    limits = resources.get("limits", {}) if isinstance(resources, Mapping) else {}
    configured_wait = limits.get("max_wait_cycles", backend["recovery"]["max_wait_cycles"])
    configured_wait = _integer(configured_wait, "max-wait-cycles")
    used_sources = list(_RTL_SOURCES[:2]) + ([_RTL_SOURCES[2]] if width_adapters else [])
    used_modules = ["soc_arbiter", "soc_router"] + (["mmio_width_adapter"] if width_adapters else [])
    packed_source_mask = sum(
        int(row["allowed_source_mask"]) << (index * len(sources))
        for index, row in enumerate(window_rows)
    )
    packed_target_bases = sum(
        int(row["target_base"]) << (index * address_width)
        for index, row in enumerate(window_rows)
    )
    return {
        "schema_version": "soc_fabric.v1",
        "sources": sources,
        "targets": [{"index": index, "backing_kind": key[0], "backing_id": key[1]}
                    for index, key in enumerate(unique_backings)],
        "decode": {"windows": window_rows, "unmapped": {"completion": "error", "side_effect": False}},
        "width_adapters": width_adapters,
        "rtl": {"modules": used_modules,
                "sources": used_sources,
                "parameters": {"NUM_SOURCES": len(sources), "NUM_TARGETS": len(unique_backings),
                               "ADDRESS_WIDTH": address_width, "DATA_WIDTH": data_width,
                               "MAX_WINDOWS": max(1, len(window_rows)), "NUM_WINDOWS": len(window_rows),
                               "WINDOW_SOURCE_MASK": packed_source_mask,
                               "WINDOW_TARGET_BASE": packed_target_bases,
                               "RESET_CLEARS_TARGETS": int(reset_scope_verified)}},
        "watchdog": {"max_wait_cycles": configured_wait, "enforcement": "external_runtime_watchdog",
                     "rtl_enforced": False, "on_expiry": "terminate_test_without_transaction_id_reuse"},
        "reset_recovery": {"router_late_response": "drain_required_without_verified_full_test_reset",
                           "full_test_reset": ("clears_quarantine" if reset_scope_verified else "drain_required"),
                           "scope_verified": reset_scope_verified,
                           "required_scope": "same_reset_must_clear_router_width_adapters_and_all_downstream_targets"},
        "processor_backend_hash": backend["backend_hash"],
    }


__all__ = ["SocFabricError", "build_soc_fabric"]
