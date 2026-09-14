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
soc_spec_hash and soc_plan_hash treat every JSON array as an unordered multiset
(sorted by canonical encoding) and every object as a key-sorted mapping, then
reuse myfuzz.contracts.content_hash.  Permuting any list or reordering any
object key therefore cannot change a digest, while changing a protocol tuple,
an address, a permission, an initialization policy or a master/target binding
does.  "protocol" is the ordered pair [name, version]; validation pins that
order (a version is numeric or "classic" and never looks like a protocol name),
so multiset normalisation cannot merge two documents that mean different
things.
"""
from __future__ import annotations

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
    physical: dict[str, tuple] = {}
    for record in records:
        signature = (record["size"], tuple(sorted(record["permissions"].items())),
                     record["initialization_policy"])
        previous = physical.get(record["physical_memory_id"])
        if previous is not None and previous != signature:
            _error("conflicting-physical-memory", record["physical_memory_id"])
        physical[record["physical_memory_id"]] = signature
    return records


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
        if target_id in seen_targets:
            _error("duplicate-target-id", target_id)
        seen_targets.add(target_id)
        request_sources = _array(record["request_sources"], _child(pointer, "request_sources"))
        if not request_sources:
            _error("missing-target-requester", target_id)
        for source_index, source in enumerate(request_sources):
            source_pointer = _child(_child(pointer, "request_sources"), source_index)
            name = _string(source, source_pointer)
            if name not in source_ids:
                _error("unknown-source-id", name)
        response_owner = _string(record["response_owner"], _child(pointer, "response_owner"))
        if response_owner not in request_sources:
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
    _validate_memory_regions(document, components)
    masters = _validate_masters(document, components)
    targets = _validate_targets(document, components, masters)
    routes = _validate_interrupt_routes(document, components, masters)
    links = _validate_environment_links(document, components)
    link_ids = {target["target_id"] for target in targets}
    link_ids.update(route["route_id"] for route in routes)
    link_ids.update(link["link_id"] for link in links)
    resources = _validate_resources(document, components, link_ids)
    _validate_assumptions(document)
    _provenance(document["provenance"], "provenance")

    _check_cross_clock(components, masters, targets, routes, links, resources["clock_adapters"])

    locks = _lock_ids(source_lock_ids if source_lock_ids is not None else document.get("source_locks"))
    if locks is not None:
        known = set(locks)
        for index, value in enumerate(_array(document["components"], "components")):
            record = _object(value, _child("components", index))
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
                            "instances", "adapters", "nets", "net_drivers", "address_map",
                            "target_capabilities", "reset", "clock_domains", "stimulus",
                            "assumptions", "provenance"))
    _enum(document["schema_version"], "schema_version", (SOC_PLAN_SCHEMA,))
    _string(document["spec_id"], "spec_id")
    _hash_string(document["spec_hash"], "spec_hash")
    _object(document["processor_execution"], "processor_execution")

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
    seen_adapters: set[str] = set()
    for index, value in enumerate(adapters):
        pointer = _child("adapters", index)
        record = _object(value, pointer)
        _require(record, pointer, ("adapter_id", "source_id", "target_id", "module"))
        adapter_id = _string(record["adapter_id"], _child(pointer, "adapter_id"))
        _string(record["source_id"], _child(pointer, "source_id"))
        _string(record["target_id"], _child(pointer, "target_id"))
        _string(record["module"], _child(pointer, "module"))
        if adapter_id in seen_adapters:
            _error("duplicate-adapter-id", adapter_id)
        seen_adapters.add(adapter_id)

    nets = _array(document["nets"], "nets")
    net_ids: list[str] = []
    for index, value in enumerate(nets):
        pointer = _child("nets", index)
        record = _object(value, pointer)
        _require(record, pointer, ("net_id", "kind", "driver"))
        net_ids.append(_string(record["net_id"], _child(pointer, "net_id")))
        _string(record["kind"], _child(pointer, "kind"))
        _object(record["driver"], _child(pointer, "driver"))
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
    if sorted(driver_ids) != sorted(net_ids) or len(driver_ids) != len(set(driver_ids)):
        missing = sorted(set(net_ids).symmetric_difference(driver_ids))
        _error("net-driver-mismatch", ",".join(missing) if missing else "net_drivers")

    address_map = _object(document["address_map"], "address_map")
    _require(address_map, "address_map", ("windows", "memory_regions", "unmapped"))
    windows = _array(address_map["windows"], "address_map/windows")
    seen_targets: set[str] = set()
    laid_out: list[tuple[int, int, str]] = []
    for index, value in enumerate(windows):
        pointer = _child("address_map/windows", index)
        record = _object(value, pointer)
        _require(record, pointer, ("target_id", "window", "byte_enable"))
        target_id = _string(record["target_id"], _child(pointer, "target_id"))
        if target_id in seen_targets:
            _error("duplicate-window", target_id)
        seen_targets.add(target_id)
        base, size = _window(record["window"], _child(pointer, "window"))
        _boolean(record["byte_enable"], _child(pointer, "byte_enable"))
        laid_out.append((base, size, target_id))
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
    for target_id, value in capabilities.items():
        pointer = _child("target_capabilities", target_id)
        record = _object(value, pointer)
        _require(record, pointer, ("capabilities", "evidence"))
        _object(record["capabilities"], _child(pointer, "capabilities"))
        _object(record["evidence"], _child(pointer, "evidence"))

    reset = _object(document["reset"], "reset")
    _require(reset, "reset", ("cpu_reset", "test_reset"))
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
    _text_list(cpu_reset["sinks"], "reset/cpu_reset/sinks", nonempty=True)
    _text_list(test_reset["sinks"], "reset/test_reset/sinks", nonempty=True)
    _text_list(test_reset["clears"], "reset/test_reset/clears", nonempty=True)

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


def _unordered(value: object) -> object:
    """Normalise JSON so that list order and object key order never matter."""
    if isinstance(value, Mapping):
        return {str(key): _unordered(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_unordered(item) for item in value]
        return sorted(items, key=canonical_bytes)
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
