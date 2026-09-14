"""Frozen, versioned contracts for the generated SoC.

Three documents are exchanged between the composition stages as versioned
JSON-compatible dict documents:

soc_spec.v1
    Source facts plus explicit semantics: components and their instances,
    memory regions, bus masters, targets (MMIO windows), interrupt routes,
    environment links, clock/reset resources, assumptions and provenance.
soc_plan.v1
    The spec bound to concrete instances, adapters, nets, the decoded address
    map, reset distribution, stimulus modes and per-target capability evidence.
soc_stimulus.v1
    The raw fuzz input layout, rule classes, consumption rules and reset
    semantics of exactly one of the three stimulus modes.

Every rejection is a SocContractError whose message starts with a stable,
parseable "<reason>:<json-pointer>" prefix.

Hash policy
-----------
soc_spec_hash and soc_plan_hash sort only schema collections declared
unordered (components, routes, nets, and similar identity-keyed sets). Ordered
arrays such as protocol tuples and typed parameter arrays retain their order.
Object key order never affects the digest.
"""
from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence

from myfuzz.contracts import canonical_bytes, content_hash

SOC_SPEC_SCHEMA = "soc_spec.v1"
SOC_PLAN_SCHEMA = "soc_plan.v1"
SOC_STIMULUS_SCHEMA = "soc_stimulus.v1"

#: The three stimulus modes; selected at test_begin only.
SOC_MODES = ("cpu_only", "mmio_only", "mixed")
COMPONENT_KINDS = ("cpu", "peripheral", "memory", "clock_reset")
MASTER_KINDS = ("cpu_instruction", "cpu_data", "cpu_unified", "fuzz_mmio")
INITIALIZATION_POLICIES = ("on_demand", "preload", "rom", "alias", "none")
RAW_SEGMENT_IDS = ("instruction", "mmio", "environment")

#: Which master kinds are used in which mode.  A CPU held in reset does not
#: drive anything in mmio_only and the synthetic master does not exist in
#: cpu_only.
KIND_MODES = {
    "cpu_instruction": ("cpu_only", "mixed"),
    "cpu_data": ("cpu_only", "mixed"),
    "cpu_unified": ("cpu_only", "mixed"),
    "fuzz_mmio": ("mmio_only", "mixed"),
}

CPU_MASTER_KINDS = ("cpu_instruction", "cpu_data", "cpu_unified")

_PROTOCOL_NAME = re.compile(r"[a-z][a-z0-9._-]*\Z")
_PROTOCOL_VERSION = re.compile(r"(?:[0-9]+(?:\.[0-9]+)*|classic)\Z")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")

# The full test reset clears every piece of test state; the CPU reset is kept
# separate so mmio_only can hold only the CPU in reset.
TEST_RESET_CLEARS = ("cpu", "memory", "peripheral", "driver", "irq", "coverage", "coverage_universe")


class SocContractError(ValueError):
    """Stable, parseable SoC contract failure: <reason>:<json-pointer>."""

    def __init__(self, reason: str, pointer: str = "") -> None:
        if not isinstance(reason, str) or not reason:
            raise ValueError("reason must be a non-empty string")
        self.reason = reason
        self.pointer = pointer or ""
        super().__init__(reason if not self.pointer else f"{reason}:{self.pointer}")


def _error(reason: str, pointer: str = "") -> None:
    raise SocContractError(reason, pointer)


def _escape(token: object) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _child(pointer: str, token: object) -> str:
    return f"{pointer}/{_escape(token)}" if pointer else _escape(token)


def _require(document: Mapping[str, object], pointer: str, fields: Sequence[str]) -> None:
    for field in fields:
        if field not in document:
            _error("missing-field", _child(pointer, field))


def _object(value: object, pointer: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error("invalid-field", pointer)
    return value


def _array(value: object, pointer: str) -> list:
    if not isinstance(value, list):
        _error("invalid-field", pointer)
    return value


def _string(value: object, pointer: str) -> str:
    if not isinstance(value, str) or not value:
        _error("invalid-field", pointer)
    return value


def _hash_string(value: object, pointer: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _error("invalid-field", pointer)
    return value


def _boolean(value: object, pointer: str) -> bool:
    if not isinstance(value, bool):
        _error("invalid-field", pointer)
    return value


def _integer(value: object, pointer: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _error("invalid-field", pointer)
    if minimum is not None and value < minimum:
        _error("invalid-field", pointer)
    if maximum is not None and value > maximum:
        _error("invalid-field", pointer)
    return value


def _positive_number(value: object, pointer: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        _error("invalid-field", pointer)
    return value


def _enum(value: object, pointer: str, choices: Sequence[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        _error("invalid-field", pointer)
    return value


def _text_list(value: object, pointer: str, *, nonempty: bool = False) -> list:
    items = _array(value, pointer)
    for index, item in enumerate(items):
        _string(item, _child(pointer, index))
    if nonempty and not items:
        _error("invalid-field", pointer)
    return items


def _unique_names(items: Sequence[object], pointer: str, key: str, reason: str) -> list[str]:
    seen: set[str] = set()
    for index, item in enumerate(items):
        record = _object(item, _child(pointer, index))
        _require(record, _child(pointer, index), (key,))
        name = _string(record[key], _child(_child(pointer, index), key))
        if name in seen:
            _error(reason, name)
        seen.add(name)
    return sorted(seen)


def _protocol(value: object, pointer: str) -> tuple[str, str]:
    items = _array(value, pointer)
    if len(items) != 2:
        _error("invalid-field", pointer)
    name = _string(items[0], _child(pointer, 0))
    version = _string(items[1], _child(pointer, 1))
    if _PROTOCOL_NAME.fullmatch(name) is None:
        _error("invalid-field", _child(pointer, 0))
    if _PROTOCOL_VERSION.fullmatch(version) is None:
        _error("invalid-field", _child(pointer, 1))
    return name, version


def _permissions(value: object, pointer: str) -> dict:
    record = _object(value, pointer)
    _require(record, pointer, ("read", "write", "execute"))
    return {
        "read": _boolean(record["read"], _child(pointer, "read")),
        "write": _boolean(record["write"], _child(pointer, "write")),
        "execute": _boolean(record["execute"], _child(pointer, "execute")),
    }


def _provenance(value: object, pointer: str) -> dict:
    record = _object(value, pointer)
    result: dict[str, str] = {}
    for key, item in record.items():
        result[str(key)] = _string(item, _child(pointer, key))
    return result


def _window(value: object, pointer: str) -> tuple[int, int]:
    record = _object(value, pointer)
    _require(record, pointer, ("base", "size"))
    base = _integer(record["base"], _child(pointer, "base"), minimum=0)
    size = _integer(record["size"], _child(pointer, "size"), minimum=1)
    return base, size


def _overlaps(base_a: int, size_a: int, base_b: int, size_b: int) -> bool:
    return base_a < base_b + size_b and base_b < base_a + size_a


# --------------------------------------------------------------------------
# soc_spec.v1
# --------------------------------------------------------------------------


def _validate_components(document: Mapping[str, object]) -> dict[str, dict]:
    components = _array(document["components"], "components")
    result: dict[str, dict] = {}
    for index, value in enumerate(components):
        pointer = _child("components", index)
        record = _object(value, pointer)
        _require(record, pointer, ("component_id", "kind", "source_lock", "top_module",
                                   "clock_domain", "reset_domain", "instances", "capability_evidence"))
        component_id = _string(record["component_id"], _child(pointer, "component_id"))
        _enum(record["kind"], _child(pointer, "kind"), COMPONENT_KINDS)
        _string(record["source_lock"], _child(pointer, "source_lock"))
        _string(record["top_module"], _child(pointer, "top_module"))
        _string(record["clock_domain"], _child(pointer, "clock_domain"))
        _string(record["reset_domain"], _child(pointer, "reset_domain"))
        _object(record["capability_evidence"], _child(pointer, "capability_evidence"))
        instances = _array(record["instances"], _child(pointer, "instances"))
        if not instances:
            _error("invalid-field", _child(pointer, "instances"))
        seen_instances: set[str] = set()
        for instance_index, instance_value in enumerate(instances):
            instance_pointer = _child(_child(pointer, "instances"), instance_index)
            instance = _object(instance_value, instance_pointer)
            _require(instance, instance_pointer, ("instance_id", "parameters"))
            instance_id = _string(instance["instance_id"], _child(instance_pointer, "instance_id"))
            _object(instance["parameters"], _child(instance_pointer, "parameters"))
            if instance_id in seen_instances:
                _error("duplicate-instance-id", instance_id)
            seen_instances.add(instance_id)
        if component_id in result:
            _error("duplicate-component-id", component_id)
        result[component_id] = record
    return result


def _validate_memory_regions(document: Mapping[str, object], components: Mapping[str, dict]) -> list[dict]:
    regions = _array(document["memory_regions"], "memory_regions")
    records: list[dict] = []
    seen: set[str] = set()
    for index, value in enumerate(regions):
        pointer = _child("memory_regions", index)
        record = _object(value, pointer)
        _require(record, pointer, ("region_id", "component_id", "base", "size", "permissions",
                                   "physical_memory_id", "initialization_policy"))
        region_id = _string(record["region_id"], _child(pointer, "region_id"))
        component_id = _string(record["component_id"], _child(pointer, "component_id"))
        if component_id not in components:
            _error("unknown-component-id", _child(pointer, "component_id"))
        base = _integer(record["base"], _child(pointer, "base"), minimum=0)
        size = _integer(record["size"], _child(pointer, "size"), minimum=1)
        permissions = _permissions(record["permissions"], _child(pointer, "permissions"))
        physical_id = _string(record["physical_memory_id"], _child(pointer, "physical_memory_id"))
        policy = _enum(record["initialization_policy"], _child(pointer, "initialization_policy"),
                       INITIALIZATION_POLICIES)
        if region_id in seen:
            _error("duplicate-region-id", region_id)
        seen.add(region_id)
        if policy == "rom" and permissions["write"]:
            _error("writable-rom", f"memory_regions/{region_id}")
        records.append({
            "region_id": region_id, "component_id": component_id, "base": base, "size": size,
            "permissions": permissions, "physical_memory_id": physical_id,
            "initialization_policy": policy, "pointer": pointer,
        })
    ordered = sorted(records, key=lambda item: (item["base"], item["region_id"]))
    for index in range(1, len(ordered)):
        previous = ordered[index - 1]
        current = ordered[index]
        if _overlaps(previous["base"], previous["size"], current["base"], current["size"]):
            _error("overlapping-memory-regions",
                   f"{previous['region_id']}+{current['region_id']}")
    # One region per physical memory is the primary: it carries the real
    # initialization policy and defines the byte range that memory occupies.
    # Every other region sharing the physical id must be declared an alias, must
    # lie inside the primary, and may differ in permissions - an execute-only
    # instruction view and a read/write data view of the same RAM is exactly what
    # this contract exists for - but it may not invent a second primary, may not
    # alias nothing, may not reach outside the memory, and may not make a ROM
    # writable.
    primaries: dict[str, dict] = {}
    for record in records:
        if record["base"] + record["size"] > 1 << 64:
            _error("address-out-of-range", f"memory_regions/{record['region_id']}")
        if record["initialization_policy"] == "alias":
            continue
        primary = primaries.get(record["physical_memory_id"])
        if primary is None:
            primaries[record["physical_memory_id"]] = record
            continue
        # A second view that is not declared an alias must be byte-for-byte the
        # same memory: same extent, same permissions, same initialization. Any
        # difference is a genuine conflict rather than a second view.
        if (record["size"] != primary["size"]
                or record["permissions"] != primary["permissions"]
                or record["initialization_policy"] != primary["initialization_policy"]):
            _error("conflicting-physical-memory", record["physical_memory_id"])
    for record in records:
        if record["initialization_policy"] != "alias":
            continue
        primary = primaries.get(record["physical_memory_id"])
        if primary is None:
            # "alias" must alias something; otherwise the enum hides a region
            # whose initialization nobody ever declared.
            _error("alias-without-primary", record["region_id"])
        if record["size"] > primary["size"]:
            _error("alias-larger-than-physical-memory", record["region_id"])
        if primary["initialization_policy"] == "rom" and record["permissions"]["write"]:
            _error("writable-rom", f"memory_regions/{record['region_id']}")
    return records


def _check_address_reach(masters: Sequence[dict], regions: Sequence[dict],
                         targets: Sequence[dict]) -> None:
    """Every region and window must be reachable by the widest declared master.

    A master narrower than an address it must drive would silently truncate the
    address, so the plan's address map has to fit the largest declared width.
    """
    limit = 1 << max(master["address_width"] for master in masters)
    for region in regions:
        if region["base"] + region["size"] > limit:
            _error("address-exceeds-master-width", f"memory_regions/{region['region_id']}")
    for target in targets:
        if target["base"] + target["size"] > limit:
            _error("address-exceeds-master-width", f"targets/{target['target_id']}")


def _validate_masters(document: Mapping[str, object], components: Mapping[str, dict]) -> list[dict]:
    masters = _array(document["masters"], "masters")
    records: list[dict] = []
    seen_sources: set[str] = set()
    seen_inputs: set[tuple[str, str]] = set()
    for index, value in enumerate(masters):
        pointer = _child("masters", index)
        record = _object(value, pointer)
        _require(record, pointer, ("source_id", "kind", "component_id", "port", "protocol",
                                   "data_width", "address_width", "test_modes"))
        source_id = _string(record["source_id"], _child(pointer, "source_id"))
        kind = _enum(record["kind"], _child(pointer, "kind"), MASTER_KINDS)
        component_id = _string(record["component_id"], _child(pointer, "component_id"))
        if component_id not in components:
            _error("unknown-component-id", _child(pointer, "component_id"))
        port = _string(record["port"], _child(pointer, "port"))
        protocol = _protocol(record["protocol"], _child(pointer, "protocol"))
        _integer(record["data_width"], _child(pointer, "data_width"), minimum=1)
        _integer(record["address_width"], _child(pointer, "address_width"), minimum=1)
        modes = _text_list(record["test_modes"], _child(pointer, "test_modes"), nonempty=True)
        if len(set(modes)) != len(modes):
            _error("duplicate-mode", _child(pointer, "test_modes"))
        for mode_index, mode in enumerate(modes):
            mode_pointer = _child(_child(pointer, "test_modes"), mode_index)
            _enum(mode, mode_pointer, SOC_MODES)
            if mode not in KIND_MODES[kind]:
                _error("mode-not-declared", mode_pointer)
        if source_id in seen_sources:
            _error("duplicate-source-id", source_id)
        seen_sources.add(source_id)
        input_key = (component_id, port)
        if input_key in seen_inputs:
            _error("duplicate-input-driver", f"{component_id}/{port}")
        seen_inputs.add(input_key)
        records.append({
            "source_id": source_id, "kind": kind, "component_id": component_id, "port": port,
            "protocol": protocol, "data_width": record["data_width"],
            "address_width": record["address_width"], "test_modes": list(modes), "pointer": pointer,
        })
    return records


def _validate_targets(document: Mapping[str, object], components: Mapping[str, dict],
                      masters: Sequence[dict]) -> list[dict]:
    targets = _array(document["targets"], "targets")
    source_ids = {master["source_id"] for master in masters}
    records: list[dict] = []
    seen_targets: set[str] = set()
    owners: dict[tuple[str, str], str] = {}
    for index, value in enumerate(targets):
        pointer = _child("targets", index)
        record = _object(value, pointer)
        _require(record, pointer, ("target_id", "component_id", "port", "protocol", "window",
                                   "request_sources", "response_owner", "byte_enable"))
        target_id = _string(record["target_id"], _child(pointer, "target_id"))
        component_id = _string(record["component_id"], _child(pointer, "component_id"))
        if component_id not in components:
            _error("unknown-component-id", _child(pointer, "component_id"))
        port = _string(record["port"], _child(pointer, "port"))
        protocol = _protocol(record["protocol"], _child(pointer, "protocol"))
        base, size = _window(record["window"], _child(pointer, "window"))
        if base + size > 1 << 64:
            _error("address-out-of-range", _child(pointer, "window"))
        if target_id in seen_targets:
            _error("duplicate-target-id", target_id)
        seen_targets.add(target_id)
        request_sources = _array(record["request_sources"], _child(pointer, "request_sources"))
        if not request_sources:
            _error("missing-target-requester", target_id)
        if len(set(request_sources)) != len(request_sources):
            # A duplicated requester would be counted twice by every arbitration
            # and adapter derivation downstream.
            _error("duplicate-target-requester", target_id)
        for source_index, source in enumerate(request_sources):
            source_pointer = _child(_child(pointer, "request_sources"), source_index)
            name = _string(source, source_pointer)
            if name not in source_ids:
                _error("unknown-source-id", name)
        response_owner = _string(record["response_owner"], _child(pointer, "response_owner"))
        if response_owner != "soc_fabric":
            _error("invalid-response-owner", target_id)
        byte_enable = _boolean(record["byte_enable"], _child(pointer, "byte_enable"))
        owner_key = (component_id, port)
        previous_owner = owners.get(owner_key)
        if previous_owner is not None and previous_owner != response_owner:
            _error("duplicate-response-driver", f"{component_id}/{port}")
        owners[owner_key] = response_owner
        records.append({
            "target_id": target_id, "component_id": component_id, "port": port, "protocol": protocol,
            "base": base, "size": size, "request_sources": list(request_sources),
            "response_owner": response_owner, "byte_enable": byte_enable, "pointer": pointer,
        })
    for index, target in enumerate(records):
        for other in records[index + 1:]:
            if _overlaps(target["base"], target["size"], other["base"], other["size"]):
                _error("overlapping-target-windows", f"{target['target_id']}+{other['target_id']}")
    regions = _array(document["memory_regions"], "memory_regions")
    for target in records:
        for index, region in enumerate(regions):
            region_record = _object(region, _child("memory_regions", index))
            if region_record["component_id"] == target["component_id"]:
                continue
            if _overlaps(target["base"], target["size"], region_record["base"], region_record["size"]):
                _error("overlapping-target-windows",
                       f"{target['target_id']}+{region_record['region_id']}")
    return records


def _validate_interrupt_routes(document: Mapping[str, object], components: Mapping[str, dict],
                               masters: Sequence[dict]) -> list[dict]:
    routes = _array(document["interrupt_routes"], "interrupt_routes")
    source_ids = {master["source_id"] for master in masters}
    records: list[dict] = []
    seen: set[str] = set()
    for index, value in enumerate(routes):
        pointer = _child("interrupt_routes", index)
        record = _object(value, pointer)
        _require(record, pointer, ("route_id", "source", "sink", "mask_ack"))
        route_id = _string(record["route_id"], _child(pointer, "route_id"))
        if route_id in seen:
            _error("duplicate-route-id", route_id)
        seen.add(route_id)
        source = _object(record["source"], _child(pointer, "source"))
        _require(source, _child(pointer, "source"), ("component_id", "signal", "trigger"))
        source_pointer = _child(pointer, "source")
        source_component = _string(source["component_id"], _child(source_pointer, "component_id"))
        if source_component not in components:
            _error("unknown-component-id", _child(source_pointer, "component_id"))
        signal = _string(source["signal"], _child(source_pointer, "signal"))
        trigger = _enum(source["trigger"], _child(source_pointer, "trigger"), ("level", "edge"))
        sink = _object(record["sink"], _child(pointer, "sink"))
        _require(sink, _child(pointer, "sink"), ("master_id", "irq"))
        sink_pointer = _child(pointer, "sink")
        master_id = _string(sink["master_id"], _child(sink_pointer, "master_id"))
        if master_id not in source_ids:
            _error("unknown-source-id", master_id)
        irq = _integer(sink["irq"], _child(sink_pointer, "irq"), minimum=0)
        mask_ack = _object(record["mask_ack"], _child(pointer, "mask_ack"))
        _require(mask_ack, _child(pointer, "mask_ack"), ("register", "semantics"))
        _string(mask_ack["register"], _child(_child(pointer, "mask_ack"), "register"))
        _string(mask_ack["semantics"], _child(_child(pointer, "mask_ack"), "semantics"))
        records.append({
            "route_id": route_id, "source_component": source_component, "signal": signal,
            "trigger": trigger, "master_id": master_id, "irq": irq, "pointer": pointer,
        })
    return records


def _validate_environment_links(document: Mapping[str, object],
                                components: Mapping[str, dict]) -> list[dict]:
    links = _array(document["environment_links"], "environment_links")
    records: list[dict] = []
    seen: set[str] = set()
    for index, value in enumerate(links):
        pointer = _child("environment_links", index)
        record = _object(value, pointer)
        _require(record, pointer, ("link_id", "component_id", "protocol", "parameters"))
        link_id = _string(record["link_id"], _child(pointer, "link_id"))
        if link_id in seen:
            _error("duplicate-link-id", link_id)
        seen.add(link_id)
        component_id = _string(record["component_id"], _child(pointer, "component_id"))
        if component_id not in components:
            _error("unknown-component-id", _child(pointer, "component_id"))
        protocol = _protocol(record["protocol"], _child(pointer, "protocol"))
        parameters = _object(record["parameters"], _child(pointer, "parameters"))
        other_domain = parameters.get("clock_domain")
        if other_domain is not None:
            _string(other_domain, _child(_child(pointer, "parameters"), "clock_domain"))
        records.append({
            "link_id": link_id, "component_id": component_id, "protocol": protocol,
            "other_clock_domain": other_domain, "pointer": pointer,
        })
    return records


def _validate_resources(document: Mapping[str, object], components: Mapping[str, dict],
                        link_ids: set[str]) -> dict:
    resources = _object(document["resources"], "resources")
    _require(resources, "resources", ("clock_domains", "resets", "clock_adapters", "limits"))
    clock_domains = _array(resources["clock_domains"], "resources/clock_domains")
    _unique_names(clock_domains, "resources/clock_domains", "name", "duplicate-clock-domain")
    for index, value in enumerate(clock_domains):
        pointer = _child("resources/clock_domains", index)
        record = _object(value, pointer)
        _require(record, pointer, ("name", "frequency_hz"))
        _string(record["name"], _child(pointer, "name"))
        _positive_number(record["frequency_hz"], _child(pointer, "frequency_hz"))
    resets = _array(resources["resets"], "resources/resets")
    _unique_names(resets, "resources/resets", "name", "duplicate-reset-id")
    reset_domains: set[str] = set()
    for index, value in enumerate(resets):
        pointer = _child("resources/resets", index)
        record = _object(value, pointer)
        _require(record, pointer, ("name", "domain", "polarity", "synchronous"))
        _string(record["name"], _child(pointer, "name"))
        reset_domains.add(_string(record["domain"], _child(pointer, "domain")))
        _enum(record["polarity"], _child(pointer, "polarity"), ("active_low", "active_high"))
        _boolean(record["synchronous"], _child(pointer, "synchronous"))
    adapters = _array(resources["clock_adapters"], "resources/clock_adapters")
    seen_adapters: set[str] = set()
    for index, value in enumerate(adapters):
        pointer = _child("resources/clock_adapters", index)
        record = _object(value, pointer)
        _require(record, pointer, ("adapter_id", "link_id"))
        adapter_id = _string(record["adapter_id"], _child(pointer, "adapter_id"))
        if adapter_id in seen_adapters:
            _error("duplicate-clock-adapter", adapter_id)
        seen_adapters.add(adapter_id)
        link_id = _string(record["link_id"], _child(pointer, "link_id"))
        if link_id not in link_ids:
            _error("unknown-clock-adapter-link", link_id)
    limits = _object(resources["limits"], "resources/limits")
    _require(limits, "resources/limits", ("build_timeout_s", "run_timeout_s", "rss_limit_mb",
                                          "cycles_per_sample"))
    for key in ("build_timeout_s", "run_timeout_s", "rss_limit_mb", "cycles_per_sample"):
        _positive_number(limits[key], _child("resources/limits", key))
    domains = {str(record["name"]) for record in clock_domains}
    for index, value in enumerate(_array(document["components"], "components")):
        component = _object(value, _child("components", index))
        if component["clock_domain"] not in domains:
            _error("unknown-clock-domain", _child(_child("components", index), "clock_domain"))
        if component["reset_domain"] not in reset_domains:
            _error("unknown-reset-domain", _child(_child("components", index), "reset_domain"))
    return {"clock_domains": clock_domains, "resets": resets, "clock_adapters": adapters,
            "limits": limits, "reset_domains": sorted(reset_domains)}


def _validate_assumptions(document: Mapping[str, object]) -> None:
    assumptions = _array(document["assumptions"], "assumptions")
    seen: set[str] = set()
    for index, value in enumerate(assumptions):
        pointer = _child("assumptions", index)
        record = _object(value, pointer)
        _require(record, pointer, ("assumption_id", "statement", "provenance"))
        assumption_id = _string(record["assumption_id"], _child(pointer, "assumption_id"))
        if assumption_id in seen:
            _error("duplicate-assumption-id", assumption_id)
        seen.add(assumption_id)
        _string(record["statement"], _child(pointer, "statement"))
        _string(record["provenance"], _child(pointer, "provenance"))


def _lock_ids(document: object) -> list[str] | None:
    """Normalise a lock document, a list of ids or a mapping of ids to facts."""
    if document is None:
        return None
    if isinstance(document, Mapping):
        components = document.get("components")
        if isinstance(components, list):
            return [
                _string(_object(item, _child("source_locks/components", index)).get("id"),
                        _child(_child("source_locks/components", index), "id"))
                for index, item in enumerate(components)
            ]
        return [_string(key, _child("source_locks", key)) for key in document]
    if isinstance(document, (list, tuple)):
        ids = []
        for index, item in enumerate(document):
            if isinstance(item, str):
                ids.append(_string(item, _child("source_locks", index)))
            elif isinstance(item, Mapping):
                ids.append(_string(item.get("id"), _child(_child("source_locks", index), "id")))
            else:
                _error("invalid-field", _child("source_locks", index))
        return ids
    _error("invalid-field", "source_locks")
    return None


def _check_modes(masters: Sequence[dict], test_modes: object) -> list[str] | None:
    if test_modes is None:
        return None
    modes = _text_list(test_modes, "test_modes", nonempty=True)
    for index, mode in enumerate(modes):
        _enum(mode, _child("test_modes", index), SOC_MODES)
    for master in masters:
        for mode in modes:
            if mode in KIND_MODES[master["kind"]] and mode not in master["test_modes"]:
                _error("mode-not-declared", _child(master["pointer"], "test_modes"))
    return list(modes)


def _check_cross_clock(components: Mapping[str, dict], masters: Sequence[dict], targets: Sequence[dict],
                       routes: Sequence[dict], links: Sequence[dict],
                       clock_adapters: Sequence[object]) -> None:
    adapter_links: set[str] = set()
    for index, item in enumerate(clock_adapters):
        record = _object(item, _child("resources/clock_adapters", index))
        adapter_links.add(str(record["link_id"]))
    domains = {component_id: component["clock_domain"] for component_id, component in components.items()}
    master_components = {master["source_id"]: master["component_id"] for master in masters}
    for target in targets:
        target_domain = domains[target["component_id"]]
        for source_id in target["request_sources"]:
            if domains[master_components[source_id]] != target_domain and target["target_id"] not in adapter_links:
                _error("cross-clock-without-adapter", target["target_id"])
    for route in routes:
        source_domain = domains[route["source_component"]]
        sink_domain = domains[master_components[route["master_id"]]]
        if source_domain != sink_domain and route["route_id"] not in adapter_links:
            _error("cross-clock-without-adapter", route["route_id"])
    for link in links:
        other = link["other_clock_domain"]
        if other is not None and other != domains[link["component_id"]] and link["link_id"] not in adapter_links:
            _error("cross-clock-without-adapter", link["link_id"])


def validate_soc_spec(spec: dict, *, test_modes: object = None, source_lock_ids: object = None) -> None:
    """Validate a soc_spec.v1 document or raise SocContractError.

    test_modes (or an optional spec["test_modes"]) pins the stimulus modes this
    SoC is used in; every master whose kind is used in such a mode must declare
    it.  source_lock_ids (or spec["source_locks"]) supplies the ids of
    configs/soc/sources.lock.json; when neither is given, lock membership
    cannot be checked and is skipped, otherwise every components[].source_lock
    must resolve.
    """
    document = _object(spec, "")
    _require(document, "", ("schema_version", "spec_id", "components", "memory_regions", "masters",
                            "targets", "interrupt_routes", "environment_links", "resources",
                            "assumptions", "provenance"))
    _enum(document["schema_version"], "schema_version", (SOC_SPEC_SCHEMA,))
    _string(document["spec_id"], "spec_id")
    components = _validate_components(document)
    if not components:
        # A SoC with no components, no master or no target cannot be built, and
        # accepting it here only moves the failure into an opaque later stage.
        _error("empty-collection", "components")
    regions = _validate_memory_regions(document, components)
    masters = _validate_masters(document, components)
    if not masters:
        _error("empty-collection", "masters")
    targets = _validate_targets(document, components, masters)
    if not targets:
        _error("empty-collection", "targets")
    _check_address_reach(masters, regions, targets)
    routes = _validate_interrupt_routes(document, components, masters)
    links = _validate_environment_links(document, components)
    link_ids = {target["target_id"] for target in targets}
    link_ids.update(route["route_id"] for route in routes)
    link_ids.update(link["link_id"] for link in links)
    resources = _validate_resources(document, components, link_ids)
    _validate_assumptions(document)
    _provenance(document["provenance"], "provenance")

    _check_cross_clock(components, masters, targets, routes, links, resources["clock_adapters"])

    embedded_locks = _lock_ids(document.get("source_locks"))
    if embedded_locks is None:
        _error("missing-source-locks", "source_locks")
    lock_sets = [(set(embedded_locks), "source_locks")]
    if source_lock_ids is not None:
        lock_sets.append((set(_lock_ids(source_lock_ids) or ()), "source_lock_ids"))
    for index, value in enumerate(_array(document["components"], "components")):
        record = _object(value, _child("components", index))
        for known, _origin in lock_sets:
            if record["source_lock"] not in known:
                _error("unknown-source-lock", _child(_child("components", index), "source_lock"))

    pinned = test_modes if test_modes is not None else document.get("test_modes")
    _check_modes(masters, pinned)


# --------------------------------------------------------------------------
# soc_plan.v1
# --------------------------------------------------------------------------


def validate_soc_plan(plan: dict) -> None:
    """Validate a soc_plan.v1 document or raise SocContractError."""
    document = _object(plan, "")
    _require(document, "", ("schema_version", "spec_id", "spec_hash", "processor_execution",
                            "fabric", "instances", "adapters", "nets", "net_drivers", "address_map",
                            "target_capabilities", "reset", "clock_domains", "stimulus",
                            "assumptions", "provenance"))
    _enum(document["schema_version"], "schema_version", (SOC_PLAN_SCHEMA,))
    _string(document["spec_id"], "spec_id")
    _hash_string(document["spec_hash"], "spec_hash")
    processor = _object(document["processor_execution"], "processor_execution")
    _require(processor, "processor_execution", ("routes", "bindings"))
    bindings = _array(processor["bindings"], "processor_execution/bindings")
    binding_sources: set[str] = set()
    for index, value in enumerate(bindings):
        pointer = _child("processor_execution/bindings", index)
        binding = _object(value, pointer)
        _require(binding, pointer, ("source_id", "kind", "status", "route_id"))
        source_id = _string(binding["source_id"], _child(pointer, "source_id"))
        if binding.get("status") != "bound" or binding.get("route_id") is None:
            _error("unbound-cpu-route", source_id)
        if source_id in binding_sources:
            _error("ambiguous-cpu-route", source_id)
        binding_sources.add(source_id)

    instances = _array(document["instances"], "instances")
    seen_instances: set[str] = set()
    for index, value in enumerate(instances):
        pointer = _child("instances", index)
        record = _object(value, pointer)
        _require(record, pointer, ("component_id", "instance_id", "top_module", "parameters"))
        _string(record["component_id"], _child(pointer, "component_id"))
        instance_id = _string(record["instance_id"], _child(pointer, "instance_id"))
        _string(record["top_module"], _child(pointer, "top_module"))
        _object(record["parameters"], _child(pointer, "parameters"))
        if instance_id in seen_instances:
            _error("duplicate-instance-id", instance_id)
        seen_instances.add(instance_id)

    adapters = _array(document["adapters"], "adapters")
    ingress_sources = {
        str(net["driver"]["source_id"])
        for net in _array(document["nets"], "nets")
        if isinstance(net, Mapping) and net.get("kind") == "master_ingress"
        and isinstance(net.get("driver"), Mapping) and "source_id" in net["driver"]
    }
    cpu_ingress_sources = {
        str(net["driver"]["source_id"])
        for net in _array(document["nets"], "nets")
        if isinstance(net, Mapping) and net.get("kind") == "master_ingress"
        and isinstance(net.get("driver"), Mapping)
        and net["driver"].get("kind") in CPU_MASTER_KINDS
    }
    if binding_sources != cpu_ingress_sources:
        _error("cpu-binding-mismatch", "processor_execution/bindings")
    fabric = _object(document["fabric"], "fabric")
    _require(fabric, "fabric", ("schema_version", "sources", "targets", "decode", "rtl",
                                "watchdog", "reset_recovery", "downstream_adapters",
                                "network", "source_manifest"))
    if fabric["schema_version"] != "soc_fabric.v1":
        _error("invalid-field", "fabric/schema_version")
    fabric_sources = _array(fabric["sources"], "fabric/sources")
    if [item.get("index") for item in fabric_sources] != list(range(len(fabric_sources))):
        _error("fabric-source-index-mismatch", "fabric/sources")
    if {str(item.get("source_id")) for item in fabric_sources} != ingress_sources:
        _error("fabric-source-mismatch", "fabric/sources")
    ingress_widths = {int(net["data_width"]) for net in document["nets"]
                      if isinstance(net, Mapping) and net.get("kind") == "master_ingress"}
    if len(ingress_widths) != 1:
        _error("fabric-width-mismatch", "fabric/sources")
    address_map = _object(document["address_map"], "address_map")
    windows = _array(address_map.get("windows"), "address_map/windows")
    plan_targets = {
        str(window["target_id"]) for window in windows
        if isinstance(window, Mapping) and "target_id" in window
    }
    fabric_decode = _object(fabric["decode"], "fabric/decode")
    fabric_windows = _array(fabric_decode.get("windows"), "fabric/decode/windows")
    if {str(item.get("target_id")) for item in fabric_windows} != plan_targets:
        _error("fabric-window-mismatch", "fabric/decode/windows")
    source_index = {str(item["source_id"]): int(item["index"]) for item in fabric_sources}
    address_windows_by_target = {str(item["target_id"]): item for item in windows}
    for item in fabric_windows:
        target_id = str(item.get("target_id"))
        canonical = address_windows_by_target[target_id]
        expected_mask = sum(1 << source_index[str(source)]
                            for source in canonical.get("request_sources", []))
        if (item.get("base") != canonical.get("base")
                or item.get("size") != canonical.get("size")
                or item.get("allowed_source_mask") != expected_mask):
            _error("fabric-window-mismatch", target_id)
    rtl = _object(fabric["rtl"], "fabric/rtl")
    parameters = _object(rtl.get("parameters"), "fabric/rtl/parameters")
    packed_mask = sum(int(item["allowed_source_mask"]) << (index * len(fabric_sources))
                      for index, item in enumerate(fabric_windows))
    if (parameters.get("NUM_SOURCES") != len(fabric_sources)
            or parameters.get("NUM_WINDOWS") != len(fabric_windows)
            or parameters.get("WINDOW_SOURCE_MASK") != packed_mask
            or parameters.get("DATA_WIDTH") != next(iter(ingress_widths))
            or parameters.get("RESET_CLEARS_TARGETS") != 0):
        _error("fabric-parameter-mismatch", "fabric/rtl/parameters")
    downstream = _array(fabric["downstream_adapters"], "fabric/downstream_adapters")
    fabric_targets = _array(fabric["targets"], "fabric/targets")
    if len(downstream) != len(fabric_targets):
        _error("fabric-adapter-mismatch", "fabric/downstream_adapters")
    target_capability_records = _object(document["target_capabilities"], "target_capabilities")
    if set(map(str, target_capability_records)) != plan_targets:
        _error("target-capability-mismatch", "target_capabilities")
    expected_downstream = []
    for physical in fabric_targets:
        target_index = physical.get("index")
        target_ids = sorted(str(window["target_id"]) for window in fabric_windows
                            if window.get("target_index") == target_index)
        modules = []
        for target_id in target_ids:
            capability_record = _object(target_capability_records[target_id],
                                        f"target_capabilities/{target_id}")
            adapter_record = _object(capability_record.get("fabric_adapter"),
                                     f"target_capabilities/{target_id}/fabric_adapter")
            modules.append(adapter_record.get("module"))
        if not modules or any(module != modules[0] or not isinstance(module, str) for module in modules):
            _error("fabric-adapter-mismatch", str(target_index))
        expected_downstream.append({"target_index": target_index, "target_ids": target_ids,
                                    "module": modules[0], "role": "shared_fabric_to_target"})
    if downstream != expected_downstream:
        _error("fabric-adapter-mismatch", "fabric/downstream_adapters")
    network = _object(fabric["network"], "fabric/network")
    if (sorted(network.get("ingress_nets", [])) != sorted(f"ingress:{source}" for source in ingress_sources)
            or sorted(network.get("target_nets", [])) != sorted(f"target:{target}" for target in plan_targets)):
        _error("fabric-network-mismatch", "fabric/network")
    manifest = _text_list(fabric["source_manifest"], "fabric/source_manifest", nonempty=True)
    expected_manifest = set(rtl.get("sources", []))
    expected_manifest.update(processor.get("adapter_sources", []))
    for target_id, value in target_capability_records.items():
        capability_record = _object(value, f"target_capabilities/{target_id}")
        adapter_record = _object(capability_record.get("fabric_adapter"),
                                 f"target_capabilities/{target_id}/fabric_adapter")
        if adapter_record.get("source"):
            expected_manifest.add(adapter_record["source"])
    if manifest != sorted(expected_manifest):
        _error("fabric-source-manifest-mismatch", "fabric/source_manifest")
    seen_adapters: set[str] = set()
    for index, value in enumerate(adapters):
        pointer = _child("adapters", index)
        record = _object(value, pointer)
        _require(record, pointer, ("adapter_id", "source_id", "target_id", "module"))
        adapter_id = _string(record["adapter_id"], _child(pointer, "adapter_id"))
        source_id = _string(record["source_id"], _child(pointer, "source_id"))
        target_id = _string(record["target_id"], _child(pointer, "target_id"))
        if source_id not in ingress_sources:
            _error("unknown-plan-source", source_id)
        if target_id not in plan_targets:
            _error("unknown-plan-target", target_id)
        _string(record["module"], _child(pointer, "module"))
        if adapter_id in seen_adapters:
            _error("duplicate-adapter-id", adapter_id)
        seen_adapters.add(adapter_id)
    expected_adapter_pairs = {
        (str(source_id), str(window["target_id"]))
        for window in windows if isinstance(window, Mapping)
        for source_id in window.get("request_sources", [])
    }
    actual_adapter_pairs = {(str(item["source_id"]), str(item["target_id"])) for item in adapters}
    if expected_adapter_pairs != actual_adapter_pairs:
        _error("adapter-binding-mismatch", "adapters")

    nets = _array(document["nets"], "nets")
    net_ids: list[str] = []
    target_nets: list[Mapping[str, object]] = []
    for index, value in enumerate(nets):
        pointer = _child("nets", index)
        record = _object(value, pointer)
        _require(record, pointer, ("net_id", "kind", "driver"))
        net_ids.append(_string(record["net_id"], _child(pointer, "net_id")))
        kind = _string(record["kind"], _child(pointer, "kind"))
        _object(record["driver"], _child(pointer, "driver"))
        if kind == "target_request":
            _require(record, pointer, ("sink", "response_driver", "response_routing"))
            sink = _object(record["sink"], _child(pointer, "sink"))
            target_id = _string(sink.get("target_id"), _child(_child(pointer, "sink"), "target_id"))
            response_driver = _object(record["response_driver"], _child(pointer, "response_driver"))
            if response_driver != {"role": "target", "target_id": target_id}:
                _error("response-driver-mismatch", _child(pointer, "response_driver"))
            if record["response_routing"] != "accepted_source":
                _error("response-routing-mismatch", _child(pointer, "response_routing"))
            target_nets.append(record)
    if len(net_ids) != len(set(net_ids)):
        _error("duplicate-net-id", "nets")

    drivers = _array(document["net_drivers"], "net_drivers")
    driver_ids: list[str] = []
    for index, value in enumerate(drivers):
        pointer = _child("net_drivers", index)
        record = _object(value, pointer)
        _require(record, pointer, ("net_id", "driver", "driver_count", "evidence"))
        net_id = _string(record["net_id"], _child(pointer, "net_id"))
        driver_ids.append(net_id)
        _object(record["driver"], _child(pointer, "driver"))
        count = _integer(record["driver_count"], _child(pointer, "driver_count"), minimum=0)
        evidence = _object(record["evidence"], _child(pointer, "evidence"))
        _require(evidence, _child(pointer, "evidence"), ("unique", "rules", "observed_drivers"))
        unique = _boolean(evidence["unique"], _child(_child(pointer, "evidence"), "unique"))
        observed = _integer(evidence["observed_drivers"],
                            _child(_child(pointer, "evidence"), "observed_drivers"), minimum=0)
        _text_list(evidence["rules"], _child(_child(pointer, "evidence"), "rules"), nonempty=True)
        if count != 1 or observed != 1 or not unique:
            _error("net-driver-mismatch", net_id)
        matching = next((net for net in nets if net["net_id"] == net_id), None)
        if matching is None or record["driver"] != matching["driver"]:
            _error("net-driver-mismatch", net_id)
    if sorted(driver_ids) != sorted(net_ids) or len(driver_ids) != len(set(driver_ids)):
        missing = sorted(set(net_ids).symmetric_difference(driver_ids))
        _error("net-driver-mismatch", ",".join(missing) if missing else "net_drivers")

    _require(address_map, "address_map", ("windows", "memory_regions", "unmapped"))
    seen_targets: set[str] = set()
    laid_out: list[tuple[int, int, str]] = []
    for index, value in enumerate(windows):
        pointer = _child("address_map/windows", index)
        record = _object(value, pointer)
        _require(record, pointer, ("target_id", "window", "byte_enable", "response_driver",
                                   "response_routing"))
        target_id = _string(record["target_id"], _child(pointer, "target_id"))
        if target_id in seen_targets:
            _error("duplicate-window", target_id)
        seen_targets.add(target_id)
        base, size = _window(record["window"], _child(pointer, "window"))
        _boolean(record["byte_enable"], _child(pointer, "byte_enable"))
        response_driver = _object(record["response_driver"], _child(pointer, "response_driver"))
        if response_driver != {"role": "target", "target_id": target_id}:
            _error("response-driver-mismatch", _child(pointer, "response_driver"))
        if record["response_routing"] != "accepted_source":
            _error("response-routing-mismatch", _child(pointer, "response_routing"))
        laid_out.append((base, size, target_id))
    if len(target_nets) != len(windows):
        _error("target-net-mismatch", "nets")
    nets_by_target: dict[str, list[Mapping[str, object]]] = {}
    for net in target_nets:
        sink = net["sink"]
        nets_by_target.setdefault(str(sink["target_id"]), []).append(net)
    for window in windows:
        target_id = str(window["target_id"])
        matches = nets_by_target.get(target_id, [])
        if len(matches) != 1:
            _error("target-net-mismatch", target_id)
        net = matches[0]
        sink = net["sink"]
        expected_driver = {"role": "fabric", "instance": "soc_fabric", "kind": "decoder"}
        if (net["net_id"] != f"target:{target_id}"
                or sink.get("component_id") != window.get("component_id")
                or sink.get("port") != window.get("port")
                or net["driver"] != expected_driver
                or sorted(net.get("request_sources", [])) != sorted(window.get("request_sources", []))):
            _error("target-net-mismatch", target_id)
    ordered = sorted(laid_out)
    for index, (base, size, target_id) in enumerate(ordered):
        for other_base, other_size, other_id in ordered[index + 1:]:
            if _overlaps(base, size, other_base, other_size):
                _error("overlapping-target-windows", f"{target_id}+{other_id}")
    for index, value in enumerate(_array(address_map["memory_regions"], "address_map/memory_regions")):
        pointer = _child("address_map/memory_regions", index)
        record = _object(value, pointer)
        _require(record, pointer, ("region_id", "component_id", "base", "size", "permissions",
                                   "physical_memory_id", "initialization_policy"))
        _window({"base": record["base"], "size": record["size"]}, pointer)
        _permissions(record["permissions"], _child(pointer, "permissions"))
        _enum(record["initialization_policy"], _child(pointer, "initialization_policy"),
              INITIALIZATION_POLICIES)
    unmapped = _object(address_map["unmapped"], "address_map/unmapped")
    _require(unmapped, "address_map/unmapped", ("behavior", "response", "side_effects"))
    if unmapped["behavior"] != "error":
        _error("invalid-field", "address_map/unmapped/behavior")

    capabilities = _object(document["target_capabilities"], "target_capabilities")
    if set(map(str, capabilities)) != plan_targets:
        _error("target-capability-mismatch", "target_capabilities")
    for target_id, value in capabilities.items():
        pointer = _child("target_capabilities", target_id)
        record = _object(value, pointer)
        _require(record, pointer, ("capabilities", "evidence", "data_width",
                                   "data_width_provenance", "declared_data_width",
                                   "capability_data_width", "width_conversion"))
        _object(record["capabilities"], _child(pointer, "capabilities"))
        _object(record["evidence"], _child(pointer, "evidence"))
        data_width = record.get("data_width")
        if isinstance(data_width, bool) or data_width not in (32, 64):
            _error("target-capability-mismatch", f"{target_id}:data_width")
        declared_width = record["declared_data_width"]
        capability_width = record["capability_data_width"]
        if capability_width != record["capabilities"].get("data_width"):
            _error("target-capability-mismatch", f"{target_id}:capability_data_width")
        for label, width in (("declared", declared_width), ("capability", capability_width)):
            if width is not None and (isinstance(width, bool) or width not in (32, 64)):
                _error("target-capability-mismatch", f"{target_id}:{label}_data_width")
        if declared_width is not None and capability_width is not None and declared_width != capability_width:
            _error("target-capability-mismatch", f"{target_id}:data_width")
        expected_provenance = ("soc_spec.targets" if declared_width is not None
                               else "target_contracts.capabilities")
        expected_width = declared_width if declared_width is not None else capability_width
        if record["data_width_provenance"] != expected_provenance or data_width != expected_width:
            _error("target-width-provenance-mismatch", target_id)
        policy = _object(record["width_conversion"], f"{pointer}/width_conversion")
        if set(policy) != {"spanning_write", "spanning_read"}:
            _error("target-width-policy-mismatch", target_id)
        if (policy["spanning_write"] not in ("reject", "split_side_effect_free")
                or policy["spanning_read"] not in ("reject", "assemble_side_effect_free")):
            _error("target-width-policy-mismatch", target_id)
        address_policy = address_windows_by_target[target_id].get("width_conversion")
        if address_policy != policy:
            _error("target-width-policy-mismatch", target_id)
    memory_regions = list(_array(address_map["memory_regions"], "address_map/memory_regions"))
    for item in fabric_windows:
        target_id = str(item["target_id"])
        matching_region = next((region for region in memory_regions
                                if region.get("component_id") == address_windows_by_target[target_id].get("component_id")
                                and region.get("base") == item.get("base")
                                and region.get("size") == item.get("size")), None)
        expected_permissions = (matching_region.get("permissions") if matching_region else {
            "read": bool(capabilities[target_id]["capabilities"].get("read")),
            "write": bool(capabilities[target_id]["capabilities"].get("write")),
            "execute": False,
        })
        if item.get("permissions") != expected_permissions:
            _error("fabric-permission-mismatch", target_id)

    # Reconstruct the complete helper document from independent canonical plan
    # facts.  This closes gaps where a self-consistent forged target index,
    # translation base, width-adapter policy, or packed parameter could pass a
    # collection of selective checks.
    from .soc_fabric import SocFabricError, build_soc_fabric

    canonical_masters = []
    for net in nets:
        if net.get("kind") != "master_ingress":
            continue
        driver = net["driver"]
        canonical_masters.append({
            "source_id": driver["source_id"], "kind": driver["kind"],
            "component_id": driver.get("component_id"), "port": driver.get("port"),
            "protocol": list(net["protocol"]), "data_width": net["data_width"],
            "address_width": net["address_width"],
        })
    canonical_targets = []
    canonical_widths = {int(master["address_width"]) for master in canonical_masters}
    canonical_address_width = canonical_widths.pop() if len(canonical_widths) == 1 else 0
    for window in windows:
        target_id = str(window["target_id"])
        capability = target_capability_records[target_id]
        entry = {
            "target_id": target_id, "component_id": window["component_id"],
            "window": {"base": window["base"], "size": window["size"]},
            "request_sources": list(window["request_sources"]),
            "data_width": capability["data_width"],
            "width_conversion": copy.deepcopy(capability.get("width_conversion", {})),
            "permissions": {"read": bool(capability["capabilities"].get("read")),
                            "write": bool(capability["capabilities"].get("write")),
                            "execute": False},
        }
        # Re-derive the narrowing width from the recorded capability facts, the
        # same way the planner did, rather than trusting a field the plan wrote.
        if canonical_address_width:
            from .target_adapters import build_target_record, resolve_address_narrowing

            narrowing = resolve_address_narrowing(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": canonical_address_width,
                 "data_width": capability["data_width"]},
                build_target_record(
                    {"capabilities": capability["capabilities"],
                     "evidence": capability.get("evidence", {})},
                    {"component_id": window["component_id"], "target_id": target_id,
                     "protocol": list(capability["protocol"]),
                     "window": {"base": window["base"], "size": window["size"]}},
                    capability["data_width"]),
            )
            if narrowing is not None:
                entry["fabric_address_width"] = int(narrowing["downstream_address_width"])
        canonical_targets.append(entry)
    canonical_spec = {
        "masters": canonical_masters,
        "memory_regions": copy.deepcopy(memory_regions),
        "targets": canonical_targets,
        "resources": {"limits": {}},
    }
    try:
        expected_fabric = build_soc_fabric(canonical_spec, processor)
    except (SocFabricError, ValueError) as error:
        _error("fabric-reconstruction-failed", str(error))
    expected_downstream = []
    for physical in expected_fabric["targets"]:
        target_ids = sorted(window["target_id"] for window in expected_fabric["decode"]["windows"]
                            if window["target_index"] == physical["index"])
        modules = [target_capability_records[target_id]["fabric_adapter"]["module"]
                   for target_id in target_ids]
        if not modules or any(module != modules[0] for module in modules[1:]):
            _error("fabric-adapter-mismatch", str(physical["index"]))
        expected_downstream.append({"target_index": physical["index"], "target_ids": target_ids,
                                    "module": modules[0], "role": "shared_fabric_to_target"})
    expected_fabric["downstream_adapters"] = expected_downstream
    expected_fabric["network"] = {
        "ingress_nets": [f"ingress:{source['source_id']}" for source in expected_fabric["sources"]],
        "target_nets": [f"target:{target_id}" for adapter in expected_downstream
                        for target_id in adapter["target_ids"]],
    }
    expected_sources = set(expected_fabric["rtl"]["sources"])
    expected_sources.update(processor.get("adapter_sources", []))
    expected_sources.update(record["fabric_adapter"].get("source")
                            for record in target_capability_records.values()
                            if record["fabric_adapter"].get("source"))
    expected_fabric["source_manifest"] = sorted(expected_sources)
    if fabric != expected_fabric:
        _error("fabric-reconstruction-mismatch", "fabric")

    reset = _object(document["reset"], "reset")
    _require(reset, "reset", ("cpu_reset", "test_reset", "distribution"))
    cpu_reset = _object(reset["cpu_reset"], "reset/cpu_reset")
    test_reset = _object(reset["test_reset"], "reset/test_reset")
    _require(cpu_reset, "reset/cpu_reset", ("name", "domain", "sinks"))
    _require(test_reset, "reset/test_reset", ("name", "domain", "sinks", "clears"))
    _string(cpu_reset["name"], "reset/cpu_reset/name")
    _string(test_reset["name"], "reset/test_reset/name")
    _string(cpu_reset["domain"], "reset/cpu_reset/domain")
    _string(test_reset["domain"], "reset/test_reset/domain")
    if cpu_reset["name"] == test_reset["name"]:
        _error("reset-not-separated", str(cpu_reset["name"]))
    cpu_sinks = set(_text_list(cpu_reset["sinks"], "reset/cpu_reset/sinks", nonempty=True))
    instance_kinds = {str(item["instance_id"]): item.get("kind") for item in instances}
    if not cpu_sinks <= set(instance_kinds) or any(instance_kinds[sink] != "cpu" for sink in cpu_sinks):
        _error("invalid-reset-owner", "reset/cpu_reset/sinks")
    test_sinks = set(_text_list(test_reset["sinks"], "reset/test_reset/sinks", nonempty=True))
    if test_sinks != set(instance_kinds):
        _error("invalid-reset-owner", "reset/test_reset/sinks")
    _text_list(test_reset["clears"], "reset/test_reset/clears", nonempty=True)
    distribution = _array(reset.get("distribution"), "reset/distribution")
    cpu_distributed = {str(item.get("sink")) for item in distribution
                       if isinstance(item, Mapping) and item.get("role") == "cpu"}
    test_distributed = {str(item.get("sink")) for item in distribution
                        if isinstance(item, Mapping) and item.get("role") == "test"}
    if cpu_distributed != cpu_sinks or test_distributed != test_sinks:
        _error("invalid-reset-owner", "reset/distribution")

    for index, value in enumerate(_array(document["clock_domains"], "clock_domains")):
        pointer = _child("clock_domains", index)
        record = _object(value, pointer)
        _require(record, pointer, ("name", "frequency_hz"))
        _string(record["name"], _child(pointer, "name"))
        _positive_number(record["frequency_hz"], _child(pointer, "frequency_hz"))

    stimulus = _object(document["stimulus"], "stimulus")
    _require(stimulus, "stimulus", ("mode_selection", "selected_mode", "available_modes", "modes"))
    if stimulus["mode_selection"] != "test_begin":
        _error("invalid-field", "stimulus/mode_selection")
    if stimulus["selected_mode"] is not None:
        _enum(stimulus["selected_mode"], "stimulus/selected_mode", SOC_MODES)
    for index, mode_name in enumerate(_text_list(stimulus["available_modes"],
                                                "stimulus/available_modes", nonempty=True)):
        _enum(mode_name, _child("stimulus/available_modes", index), SOC_MODES)
    modes = _object(stimulus["modes"], "stimulus/modes")
    _require(modes, "stimulus/modes", SOC_MODES)
    for mode in SOC_MODES:
        pointer = _child("stimulus/modes", mode)
        record = _object(modes[mode], pointer)
        _require(record, pointer, ("mode", "cpu_reset", "peripheral_reset", "test_reset", "participants"))
        if record["mode"] != mode:
            _error("invalid-field", _child(pointer, "mode"))
        cpu = _object(record["cpu_reset"], _child(pointer, "cpu_reset"))
        _require(cpu, _child(pointer, "cpu_reset"), ("held_in_reset_whole_test", "released_at"))
        held = _boolean(cpu["held_in_reset_whole_test"],
                        _child(_child(pointer, "cpu_reset"), "held_in_reset_whole_test"))
        if held != (mode == "mmio_only"):
            _error("mode-reset-mismatch", _child(pointer, "cpu_reset"))
        peripheral = _object(record["peripheral_reset"], _child(pointer, "peripheral_reset"))
        _boolean(peripheral.get("held_in_reset_whole_test"),
                 _child(_child(pointer, "peripheral_reset"), "held_in_reset_whole_test"))
        mode_reset = _object(record["test_reset"], _child(pointer, "test_reset"))
        _text_list(mode_reset.get("clears"), _child(_child(pointer, "test_reset"), "clears"), nonempty=True)
        _text_list(record["participants"], _child(pointer, "participants"))

    _validate_assumptions(document)
    _provenance(document["provenance"], "provenance")


# --------------------------------------------------------------------------
# soc_stimulus.v1
# --------------------------------------------------------------------------


def validate_soc_stimulus(stimulus: dict) -> None:
    """Validate a soc_stimulus.v1 document or raise SocContractError."""
    document = _object(stimulus, "")
    _require(document, "", ("schema_version", "plan_hash", "mode", "mode_selection", "raw_layout",
                            "rule_classes", "consumption", "reset_semantics", "provenance"))
    _enum(document["schema_version"], "schema_version", (SOC_STIMULUS_SCHEMA,))
    _hash_string(document["plan_hash"], "plan_hash")
    mode = _enum(document["mode"], "mode", SOC_MODES)
    selection = _object(document["mode_selection"], "mode_selection")
    _require(selection, "mode_selection", ("selected_at",))
    if selection["selected_at"] != "test_begin":
        _error("invalid-field", "mode_selection/selected_at")

    layout = _object(document["raw_layout"], "raw_layout")
    _require(layout, "raw_layout", ("version", "total_bits", "segments"))
    _string(layout["version"], "raw_layout/version")
    total_bits = _integer(layout["total_bits"], "raw_layout/total_bits", minimum=1)
    segments = _array(layout["segments"], "raw_layout/segments")
    if not segments:
        _error("invalid-field", "raw_layout/segments")
    seen_segments: set[str] = set()
    spans: list[tuple[int, int, str]] = []
    for index, value in enumerate(segments):
        pointer = _child("raw_layout/segments", index)
        record = _object(value, pointer)
        _require(record, pointer, ("segment_id", "base_bit", "bit_width", "fields"))
        segment_id = _enum(record["segment_id"], _child(pointer, "segment_id"), RAW_SEGMENT_IDS)
        if segment_id in seen_segments:
            _error("duplicate-segment", segment_id)
        seen_segments.add(segment_id)
        base_bit = _integer(record["base_bit"], _child(pointer, "base_bit"), minimum=0)
        bit_width = _integer(record["bit_width"], _child(pointer, "bit_width"), minimum=1)
        if base_bit + bit_width > total_bits:
            _error("invalid-field", _child(pointer, "bit_width"))
        spans.append((base_bit, bit_width, segment_id))
        fields = _array(record["fields"], _child(pointer, "fields"))
        if not fields:
            _error("invalid-field", _child(pointer, "fields"))
        seen_fields: set[str] = set()
        field_spans: list[tuple[int, int, str]] = []
        for field_index, field_value in enumerate(fields):
            field_pointer = _child(_child(pointer, "fields"), field_index)
            field = _object(field_value, field_pointer)
            _require(field, field_pointer, ("name", "lsb", "width", "role", "padding"))
            name = _string(field["name"], _child(field_pointer, "name"))
            if name in seen_fields:
                _error("duplicate-raw-field", name)
            seen_fields.add(name)
            lsb = _integer(field["lsb"], _child(field_pointer, "lsb"), minimum=0)
            width = _integer(field["width"], _child(field_pointer, "width"), minimum=1)
            _string(field["role"], _child(field_pointer, "role"))
            _boolean(field["padding"], _child(field_pointer, "padding"))
            if lsb + width > bit_width:
                _error("invalid-field", _child(field_pointer, "width"))
            field_spans.append((lsb, width, name))
        ordered_fields = sorted(field_spans)
        for field_index, (lsb, width, name) in enumerate(ordered_fields):
            for other_lsb, other_width, other_name in ordered_fields[field_index + 1:]:
                if _overlaps(lsb, width, other_lsb, other_width):
                    _error("overlapping-raw-fields", f"{name}+{other_name}")
    ordered_spans = sorted(spans)
    for index, (base_bit, bit_width, segment_id) in enumerate(ordered_spans):
        for other_base, other_width, other_id in ordered_spans[index + 1:]:
            if _overlaps(base_bit, bit_width, other_base, other_width):
                _error("overlapping-raw-segments", f"{segment_id}+{other_id}")

    rules = _array(document["rule_classes"], "rule_classes")
    if not rules:
        _error("invalid-field", "rule_classes")
    seen_rules: set[str] = set()
    for index, value in enumerate(rules):
        pointer = _child("rule_classes", index)
        record = _object(value, pointer)
        _require(record, pointer, ("rule_id", "class", "category", "enabled"))
        rule_id = _string(record["rule_id"], _child(pointer, "rule_id"))
        if rule_id in seen_rules:
            _error("duplicate-rule-id", rule_id)
        seen_rules.add(rule_id)
        _string(record["class"], _child(pointer, "class"))
        _enum(record["category"], _child(pointer, "category"), ("constraint", "bias"))
        _boolean(record["enabled"], _child(pointer, "enabled"))

    consumption = _array(document["consumption"], "consumption")
    consumed: set[str] = set()
    seen_consumption: set[tuple[str, str]] = set()
    for index, value in enumerate(consumption):
        pointer = _child("consumption", index)
        record = _object(value, pointer)
        _require(record, pointer, ("segment_id", "driver", "latch_policy", "busy_policy", "max_pending"))
        segment_id = _string(record["segment_id"], _child(pointer, "segment_id"))
        if segment_id not in seen_segments:
            _error("unknown-segment", segment_id)
        driver = _string(record["driver"], _child(pointer, "driver"))
        _string(record["latch_policy"], _child(pointer, "latch_policy"))
        _string(record["busy_policy"], _child(pointer, "busy_policy"))
        pending = _integer(record["max_pending"], _child(pointer, "max_pending"), minimum=1)
        if pending != 1:
            _error("invalid-field", _child(pointer, "max_pending"))
        if (segment_id, driver) in seen_consumption:
            _error("duplicate-consumption", f"{segment_id}:{driver}")
        seen_consumption.add((segment_id, driver))
        consumed.add(segment_id)
    for segment_id in sorted(seen_segments - consumed):
        _error("unconsumed-segment", segment_id)

    reset = _object(document["reset_semantics"], "reset_semantics")
    _require(reset, "reset_semantics", ("mode", "cpu_reset", "peripheral_reset", "test_reset"))
    if reset["mode"] != mode:
        _error("mode-reset-mismatch", "reset_semantics/mode")
    cpu_reset = _object(reset["cpu_reset"], "reset_semantics/cpu_reset")
    _require(cpu_reset, "reset_semantics/cpu_reset", ("held_in_reset_whole_test", "released_at"))
    held = _boolean(cpu_reset["held_in_reset_whole_test"],
                    "reset_semantics/cpu_reset/held_in_reset_whole_test")
    peripheral = _object(reset["peripheral_reset"], "reset_semantics/peripheral_reset")
    _require(peripheral, "reset_semantics/peripheral_reset", ("held_in_reset_whole_test", "released_at"))
    peripheral_held = _boolean(peripheral["held_in_reset_whole_test"],
                               "reset_semantics/peripheral_reset/held_in_reset_whole_test")
    if held != (mode == "mmio_only") or peripheral_held:
        _error("mode-reset-mismatch", f"reset_semantics/{mode}")
    test_reset = _object(reset["test_reset"], "reset_semantics/test_reset")
    _require(test_reset, "reset_semantics/test_reset", ("asserted_at", "clears"))
    _text_list(test_reset["asserted_at"], "reset_semantics/test_reset/asserted_at", nonempty=True)
    _text_list(test_reset["clears"], "reset_semantics/test_reset/clears", nonempty=True)

    _provenance(document["provenance"], "provenance")


# --------------------------------------------------------------------------
# deterministic hashing
# --------------------------------------------------------------------------


_UNORDERED_COLLECTION_PATHS = frozenset({
    ("source_locks",), ("components",), ("components", "*", "instances"),
    ("source_locks", "components"),
    ("memory_regions",), ("masters",), ("masters", "*", "test_modes"), ("targets",),
    ("targets", "*", "request_sources"), ("interrupt_routes",), ("environment_links",),
    ("resources", "clock_domains"), ("resources", "resets"), ("resources", "clock_adapters"),
    ("assumptions",), ("test_modes",), ("processor_execution", "adapter_sources"),
    ("processor_execution", "routes"), ("processor_execution", "bindings"), ("instances",),
    ("adapters",), ("nets",), ("net_drivers",), ("address_map", "windows"),
    ("address_map", "memory_regions"), ("reset", "cpu_reset", "resource_resets"),
    ("reset", "cpu_reset", "sinks"), ("reset", "cpu_reset", "held_in_reset_modes"),
    ("reset", "test_reset", "resource_resets"), ("reset", "test_reset", "sinks"),
    ("reset", "test_reset", "clears"), ("reset", "test_reset", "asserted_at"),
    ("reset", "distribution"), ("reset", "semantics", "cpu_reset_hold_modes"),
    ("clock_domains",), ("clock_domains", "*", "components"),
    ("clock_domains", "*", "instances"), ("clock_domains", "*", "crossing_adapters"),
    ("environment_links",), ("interrupt_routes",),
    ("environment_contract", "links"), ("environment_contract", "interrupt_routes"),
    ("stimulus", "available_modes"), ("stimulus", "modes", "*", "participants"),
    ("stimulus", "modes", "*", "test_reset", "clears"),
    ("stimulus", "modes", "*", "test_reset", "asserted_at"),
})


def _unordered(value: object, path: tuple[str, ...] = ()) -> object:
    """Canonicalise only collections whose schema declares order irrelevant."""
    if isinstance(value, Mapping):
        return {str(key): _unordered(item, path + (str(key),)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_unordered(item, path + (str(index),)) for index, item in enumerate(value)]
        schema_path = tuple("*" if token.isdigit() else token for token in path)
        return sorted(items, key=canonical_bytes) if schema_path in _UNORDERED_COLLECTION_PATHS else items
    return value


def soc_spec_hash(spec: dict) -> str:
    """Return the deterministic sha256:<hex> identity of a spec document."""
    return content_hash(_unordered(spec))


def soc_plan_hash(plan: dict) -> str:
    """Return the deterministic sha256:<hex> identity of a plan document.

    Every plan collection is unordered by construction, so the normalisation is
    order-independent for all of them.
    """
    return content_hash(_unordered(plan))


__all__ = [
    "COMPONENT_KINDS",
    "CPU_MASTER_KINDS",
    "INITIALIZATION_POLICIES",
    "KIND_MODES",
    "MASTER_KINDS",
    "RAW_SEGMENT_IDS",
    "SOC_MODES",
    "SOC_PLAN_SCHEMA",
    "SOC_SPEC_SCHEMA",
    "SOC_STIMULUS_SCHEMA",
    "TEST_RESET_CLEARS",
    "SocContractError",
    "soc_plan_hash",
    "soc_spec_hash",
    "validate_soc_plan",
    "validate_soc_spec",
    "validate_soc_stimulus",
]
