"""Bind a validated soc_spec.v1 to concrete instances, adapters and nets.

build_soc_plan is the only entry point.  It validates the spec before touching
it, resolves every target against the caller-supplied target_contracts, and
fails closed on anything it cannot prove:

* a target without a contract is missing-target-contract
* a contract without a partial_write capability is missing-target-capability
* a target that needs byte enables but cannot partially write is
  unsupported-partial-write
* a contract whose component/port/protocol disagrees with the spec is
  target-contract-mismatch
* a contract without an adapter module for a source is missing-adapter-module

The returned soc_plan.v1 document records bound instances, adapters, nets with
their single driver plus the evidence that proves uniqueness, the decoded
address map, reset distribution (CPU reset vs full test reset kept separate),
clock domains, per-target capability evidence copied verbatim from the
contracts, and the three stimulus modes with their reset semantics.  The plan
is validated again before it is returned, so an unvalidated document is never
handed to a renderer.
"""
from __future__ import annotations

import copy
from collections import Counter
from collections.abc import Mapping, Sequence

from myfuzz.composition.ids import canonical_id

from .soc_contracts import (
    CPU_MASTER_KINDS,
    KIND_MODES,
    SOC_MODES,
    SOC_PLAN_SCHEMA,
    TEST_RESET_CLEARS,
    SocContractError,
    soc_spec_hash,
    validate_soc_plan,
    validate_soc_spec,
)
from .soc_fabric import SocFabricError, build_soc_fabric

PROCESSOR_EXECUTION_SCHEMA = "processor_execution.v1"
FABRIC_INSTANCE = "soc_fabric"
TEST_RESET_NAME = "test_reset"

#: Which processor execution route functions may serve which master kind.
_CPU_ROUTE_FUNCTIONS = {
    "cpu_instruction": ("instruction_memory_master", "memory_master", "processor_memory_master"),
    "cpu_data": ("data_memory_master", "memory_master", "processor_memory_master"),
    "cpu_unified": ("memory_master", "processor_memory_master"),
}


def _error(reason: str, pointer: str = "") -> None:
    raise SocContractError(reason, pointer)


def _deep(value: object) -> object:
    return copy.deepcopy(value)


def _index_contracts(target_contracts: object) -> dict[str, dict]:
    if not isinstance(target_contracts, (list, tuple)):
        _error("invalid-target-contracts", "target_contracts")
    index: dict[str, dict] = {}
    for position, value in enumerate(target_contracts):
        pointer = f"target_contracts/{position}"
        if not isinstance(value, Mapping):
            _error("invalid-target-contract", pointer)
        if "target_id" not in value:
            _error("missing-field", f"{pointer}/target_id")
        target_id = value["target_id"]
        if not isinstance(target_id, str) or not target_id:
            _error("invalid-target-contract", f"{pointer}/target_id")
        if target_id in index:
            _error("duplicate-target-contract", target_id)
        index[target_id] = dict(value)
    return index


def _validate_contract(contract: Mapping[str, object], target: Mapping[str, object]) -> None:
    target_id = target["target_id"]
    for field in ("component_id", "port", "protocol"):
        if field not in contract:
            continue
        expected = target[field]
        actual = contract[field]
        if field == "protocol":
            expected = list(expected)
            actual = list(actual) if isinstance(actual, (list, tuple)) else actual
        if actual != expected:
            _error("target-contract-mismatch", f"{target_id}:{field}")
    capabilities = contract.get("capabilities")
    if not isinstance(capabilities, Mapping):
        _error("missing-target-capability", f"{target_id}:capabilities")
    if "partial_write" not in capabilities:
        _error("missing-target-capability", f"{target_id}:partial_write")
    if not isinstance(capabilities["partial_write"], bool):
        _error("invalid-target-capability", f"{target_id}:partial_write")
    if target["byte_enable"] and not capabilities["partial_write"]:
        _error("unsupported-partial-write", target_id)


def _adapter_module(contract: Mapping[str, object], target_id: str, source: Mapping[str, object]) -> tuple[str, str | None]:
    protocol_key = f"{source['protocol'][0]}@{source['protocol'][1]}"
    modules = contract.get("adapter_modules")
    module = None
    if isinstance(modules, Mapping) and protocol_key in modules:
        module = modules[protocol_key]
    if module is None:
        module = contract.get("adapter_module")
    if not isinstance(module, str) or not module:
        _error("missing-adapter-module", target_id)
    source_path = contract.get("adapter_source")
    if source_path is not None and (not isinstance(source_path, str) or not source_path):
        _error("invalid-target-contract", f"{target_id}:adapter_source")
    return module, source_path


def _fabric_adapter_module(contract: Mapping[str, object], target_id: str) -> tuple[str, str | None]:
    """Resolve the one adapter downstream of the normalized beat fabric."""
    modules = contract.get("adapter_modules")
    if isinstance(modules, Mapping):
        module = modules.get("processor-memory-beat@1")
        if not isinstance(module, str) or not module:
            _error("missing-fabric-adapter-module", target_id)
    else:
        module = contract.get("adapter_module")
        if not isinstance(module, str) or not module:
            _error("missing-fabric-adapter-module", target_id)
    source = contract.get("adapter_source")
    return module, source if isinstance(source, str) else None


def _width_conversion(value: object, target_id: str) -> dict[str, str]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping) or set(value) - {"spanning_write", "spanning_read"}:
        _error("invalid-width-conversion", target_id)
    write = value.get("spanning_write", "reject")
    read = value.get("spanning_read", "reject")
    if write not in ("reject", "split_side_effect_free"):
        _error("invalid-width-conversion", f"{target_id}:spanning_write")
    if read not in ("reject", "assemble_side_effect_free"):
        _error("invalid-width-conversion", f"{target_id}:spanning_read")
    return {"spanning_write": write, "spanning_read": read}


def _validate_processor_execution(execution: object) -> Mapping[str, object]:
    if not isinstance(execution, Mapping):
        _error("invalid-field", "processor_execution")
    if execution.get("schema_version") != PROCESSOR_EXECUTION_SCHEMA:
        _error("invalid-field", "processor_execution/schema_version")
    routes = execution.get("routes")
    if not isinstance(routes, list):
        _error("invalid-field", "processor_execution/routes")
    for position, route in enumerate(routes):
        pointer = f"processor_execution/routes/{position}"
        if not isinstance(route, Mapping):
            _error("invalid-field", pointer)
        for field in ("route_id", "function", "source_protocol", "target_protocol",
                      "adapter_id", "rtl_module", "rtl_source"):
            if field not in route:
                _error("missing-field", f"{pointer}/{field}")
    execution_hash = execution.get("execution_hash")
    if execution_hash is not None and not isinstance(execution_hash, str):
        _error("invalid-field", "processor_execution/execution_hash")
    return execution


def _build_instances(spec: Mapping[str, object]) -> list[dict]:
    instances: list[dict] = []
    for component in sorted(spec["components"], key=lambda item: item["component_id"]):
        for instance in sorted(component["instances"], key=lambda item: item["instance_id"]):
            instances.append({
                "component_id": component["component_id"],
                "instance_id": instance["instance_id"],
                "canonical_id": canonical_id("soc-instance",
                                             f"{component['component_id']}:{instance['instance_id']}"),
                "kind": component["kind"],
                "source_lock": component["source_lock"],
                "top_module": component["top_module"],
                "clock_domain": component["clock_domain"],
                "reset_domain": component["reset_domain"],
                "parameters": _deep(instance["parameters"]),
            })
    return instances


def _build_cpu_boundary(spec: Mapping[str, object], execution: Mapping[str, object]) -> dict:
    routes = sorted(execution.get("routes", []), key=lambda route: route["route_id"])
    bindings: list[dict] = []
    for master in sorted(spec["masters"], key=lambda item: item["source_id"]):
        if master["kind"] not in CPU_MASTER_KINDS:
            continue
        functions = _CPU_ROUTE_FUNCTIONS[master["kind"]]
        matches = [route for route in routes if route["function"] in functions]
        if not matches:
            _error("missing-cpu-route", master["source_id"])
        if len(matches) != 1:
            _error("ambiguous-cpu-route", master["source_id"])
        route = matches[0]
        widths = route.get("widths")
        if (list(route.get("source_protocol", [])) != list(master["protocol"])
                or not isinstance(widths, Mapping)
                or widths.get("address") != master["address_width"]
                or widths.get("data") != master["data_width"]
                or route.get("target_protocol") != ["processor-memory-beat", "1"]):
            _error("cpu-route-mismatch", master["source_id"])
        bindings.append({
                "source_id": master["source_id"],
                "kind": master["kind"],
                "function": route["function"],
                "route_id": route["route_id"],
                "adapter_id": route["adapter_id"],
                "rtl_module": route["rtl_module"],
                "rtl_source": route["rtl_source"],
                "reset_contract": _deep(route.get("reset_contract", {})),
                "backend_contract": _deep(route.get("backend_contract", {})),
                "status": "bound",
        })
    return {
        "schema_version": execution.get("schema_version"),
        "execution_hash": execution.get("execution_hash"),
        "adapter_sources": sorted(execution.get("adapter_sources", [])),
        "classification": _deep(execution.get("classification")),
        "routes": [_deep(route) for route in routes],
        "bindings": bindings,
    }


def _build_adapters(spec: Mapping[str, object], contracts: Mapping[str, Mapping[str, object]]) -> list[dict]:
    masters = {master["source_id"]: master for master in spec["masters"]}
    adapters: list[dict] = []
    for target in sorted(spec["targets"], key=lambda item: item["target_id"]):
        contract = contracts[target["target_id"]]
        for source_id in sorted(target["request_sources"]):
            source = masters[source_id]
            module, source_path = _adapter_module(contract, target["target_id"], source)
            adapters.append({
                "adapter_id": f"adapter:{source_id}:{target['target_id']}",
                "canonical_id": canonical_id("soc-target-adapter",
                                             f"{source_id}:{target['target_id']}"),
                "source_id": source_id,
                "target_id": target["target_id"],
                "component_id": target["component_id"],
                "port": target["port"],
                "role": "initiator_to_target",
                "source_protocol": list(source["protocol"]),
                "target_protocol": list(target["protocol"]),
                "module": module,
                "rtl_source": source_path,
                "data_width": source["data_width"],
                "parameters": _deep(contract.get("adapter_parameters", {})),
                "provenance": {"source": "target_contracts", "target_id": target["target_id"]},
            })
    return adapters


def _build_nets(spec: Mapping[str, object]) -> tuple[list[dict], list[dict]]:
    instance_domain = {instance["instance_id"]: component["clock_domain"]
                       for component in spec["components"] for instance in component["instances"]}
    nets: list[dict] = []
    drivers: list[dict] = []

    source_counts = Counter(master["source_id"] for master in spec["masters"])
    owner_counts: dict[tuple[str, str], set[str]] = {}
    for target in spec["targets"]:
        owner_counts.setdefault((target["component_id"], target["port"]), set()).add(target["response_owner"])
    route_counts = Counter(route["route_id"] for route in spec["interrupt_routes"])

    def add(net: dict, observed: int, rules: Sequence[str], subject: str) -> None:
        if observed != 1:
            _error(rules[0], subject)
        nets.append(net)
        drivers.append({
            "net_id": net["net_id"],
            "driver": _deep(net["driver"]),
            "driver_count": 1,
            "evidence": {
                "unique": True,
                "observed_drivers": observed,
                "rules": list(rules),
                "checked": subject,
            },
        })

    for master in sorted(spec["masters"], key=lambda item: item["source_id"]):
        net = {
            "net_id": f"ingress:{master['source_id']}",
            "canonical_id": canonical_id("soc-net", f"ingress:{master['source_id']}"),
            "kind": "master_ingress",
            "driver": {
                "role": "master",
                "source_id": master["source_id"],
                "kind": master["kind"],
                "component_id": master["component_id"],
                "port": master["port"],
            },
            "sink": {"role": "fabric", "instance": FABRIC_INSTANCE, "kind": "arbiter"},
            "protocol": list(master["protocol"]),
            "data_width": master["data_width"],
            "address_width": master["address_width"],
        }
        add(net, source_counts[master["source_id"]],
            ("duplicate-source-id", "duplicate-input-driver"), master["source_id"])

    for target in sorted(spec["targets"], key=lambda item: item["target_id"]):
        key = (target["component_id"], target["port"])
        net = {
            "net_id": f"target:{target['target_id']}",
            "canonical_id": canonical_id("soc-net", f"target:{target['target_id']}"),
            "kind": "target_request",
            "driver": {"role": "fabric", "instance": FABRIC_INSTANCE, "kind": "decoder"},
            "sink": {
                "role": "target",
                "target_id": target["target_id"],
                "component_id": target["component_id"],
                "port": target["port"],
            },
            "protocol": list(target["protocol"]),
            "window": {"base": target["window"]["base"], "size": target["window"]["size"]},
            "request_sources": sorted(target["request_sources"]),
            "response_driver": {"role": "target", "target_id": target["target_id"]},
            "response_routing": "accepted_source",
        }
        if len(owner_counts[key]) != 1:
            _error("duplicate-response-driver", f"{target['component_id']}/{target['port']}")
        add(net, 1, ("duplicate-input-driver", "duplicate-response-driver"),
            f"{target['component_id']}/{target['port']}")

    for route in sorted(spec["interrupt_routes"], key=lambda item: item["route_id"]):
        source = route["source"]
        net = {
            "net_id": f"interrupt:{route['route_id']}",
            "canonical_id": canonical_id("soc-net", f"interrupt:{route['route_id']}"),
            "kind": "interrupt",
            "driver": {
                "role": "interrupt_source",
                "component_id": source["component_id"],
                "signal": source["signal"],
                "trigger": source["trigger"],
            },
            "sink": {"role": "interrupt_sink", "master_id": route["sink"]["master_id"],
                     "irq": route["sink"]["irq"]},
            "mask_ack": _deep(route["mask_ack"]),
        }
        add(net, route_counts[route["route_id"]], ("duplicate-route-id",), route["route_id"])

    domain_counts = Counter(domain["name"] for domain in spec["resources"]["clock_domains"])
    for domain in sorted(spec["resources"]["clock_domains"], key=lambda item: item["name"]):
        net = {
            "net_id": f"clock:{domain['name']}",
            "canonical_id": canonical_id("soc-net", f"clock:{domain['name']}"),
            "kind": "clock",
            "driver": {"role": "clock_source", "domain": domain["name"],
                       "frequency_hz": domain["frequency_hz"]},
            "sinks": sorted(instance_id for instance_id, name in instance_domain.items()
                            if name == domain["name"]),
        }
        add(net, domain_counts[domain["name"]], ("duplicate-clock-domain",), domain["name"])

    reset_counts = Counter(reset["name"] for reset in spec["resources"]["resets"])
    for reset in sorted(spec["resources"]["resets"], key=lambda item: item["name"]):
        net = {
            "net_id": f"reset:{reset['name']}",
            "canonical_id": canonical_id("soc-net", f"reset:{reset['name']}"),
            "kind": "reset",
            "driver": {
                "role": "reset_source",
                "name": reset["name"],
                "domain": reset["domain"],
                "polarity": reset["polarity"],
                "synchronous": reset["synchronous"],
            },
            "sinks": sorted(instance["instance_id"] for component in spec["components"]
                            if component["reset_domain"] == reset["domain"]
                            for instance in component["instances"]),
        }
        add(net, reset_counts[reset["name"]], ("duplicate-reset-id",), reset["name"])
    return nets, drivers


def _crossing_domains(spec: Mapping[str, object]) -> dict[str, set[str]]:
    """Map every declared clock adapter to the two clock domains it joins."""
    by_component = {component["component_id"]: component["clock_domain"]
                    for component in spec["components"]}
    master_component = {master["source_id"]: master["component_id"] for master in spec["masters"]}
    targets = {target["target_id"]: target for target in spec["targets"]}
    routes = {route["route_id"]: route for route in spec["interrupt_routes"]}
    links = {link["link_id"]: link for link in spec["environment_links"]}
    result: dict[str, set[str]] = {}
    for adapter in spec["resources"]["clock_adapters"]:
        link_id = adapter["link_id"]
        domains: set[str] = set()
        if link_id in targets:
            target = targets[link_id]
            domains.add(by_component[target["component_id"]])
            domains.update(by_component[master_component[source]]
                           for source in target["request_sources"])
        elif link_id in routes:
            route = routes[link_id]
            domains.add(by_component[route["source"]["component_id"]])
            domains.add(by_component[master_component[route["sink"]["master_id"]]])
        else:
            link = links[link_id]
            domains.add(by_component[link["component_id"]])
            other = link["parameters"].get("clock_domain")
            if other:
                domains.add(other)
        result[adapter["adapter_id"]] = domains
    return result


def _build_reset(spec: Mapping[str, object], instances: Sequence[Mapping[str, object]]) -> dict:
    resets = sorted(spec["resources"]["resets"], key=lambda item: item["name"])
    cpu_components = {master["component_id"] for master in spec["masters"]
                      if master["kind"] in CPU_MASTER_KINDS}
    cpu_components.update(component["component_id"] for component in spec["components"]
                          if component["kind"] == "cpu")
    if not cpu_components:
        _error("missing-cpu-component", "components")
    by_id = {component["component_id"]: component for component in spec["components"]}
    cpu_domains = {by_id[component_id]["reset_domain"] for component_id in cpu_components}
    if len(cpu_domains) != 1:
        _error("ambiguous-cpu-reset-domain", ",".join(sorted(cpu_domains)))
    cpu_domain = cpu_domains.pop()
    cpu_resets = [reset for reset in resets if reset["domain"] == cpu_domain]
    if not cpu_resets:
        _error("unknown-reset-domain", cpu_domain)
    cpu_name = cpu_resets[0]["name"]
    if cpu_name == TEST_RESET_NAME:
        cpu_name = f"{cpu_name}_cpu"

    clock_reset = [component for component in spec["components"] if component["kind"] == "clock_reset"]
    if clock_reset:
        test_domain = clock_reset[0]["reset_domain"]
        derived_from = "clock_reset-component"
    else:
        others = sorted({reset["domain"] for reset in resets if reset["domain"] != cpu_domain})
        test_domain = others[0] if others else cpu_domain
        derived_from = "non-cpu-reset-domain" if others else "cpu-reset-domain"
    test_resets = [reset for reset in resets if reset["domain"] == test_domain]

    cpu_sinks = sorted(instance["instance_id"] for instance in instances
                       if instance["component_id"] in cpu_components
                       and by_id[instance["component_id"]]["kind"] == "cpu")
    test_sinks = sorted(instance["instance_id"] for instance in instances)
    distribution: list[dict] = []
    for instance in sorted(instances, key=lambda item: item["instance_id"]):
        for reset, role in ((cpu_resets[0], "cpu"), (test_resets[0] if test_resets else None, "test")):
            if reset is None:
                continue
            if role == "cpu" and instance["instance_id"] not in cpu_sinks:
                continue
            distribution.append({
                "reset": reset["name"],
                "domain": reset["domain"],
                "polarity": reset["polarity"],
                "synchronous": reset["synchronous"],
                "sink": instance["instance_id"],
                "role": role,
            })
    return {
        "cpu_reset": {
            "name": cpu_name,
            "signal": cpu_name,
            "domain": cpu_domain,
            "polarity": cpu_resets[0]["polarity"],
            "synchronous": cpu_resets[0]["synchronous"],
            "resource_resets": sorted(reset["name"] for reset in cpu_resets),
            "components": sorted(cpu_components),
            "sinks": cpu_sinks,
            "held_in_reset_modes": ["mmio_only"],
        },
        "test_reset": {
            "name": TEST_RESET_NAME,
            "signal": TEST_RESET_NAME,
            "domain": test_domain,
            "polarity": test_resets[0]["polarity"] if test_resets else "active_low",
            "synchronous": test_resets[0]["synchronous"] if test_resets else True,
            "resource_resets": sorted(reset["name"] for reset in test_resets),
            "sinks": test_sinks,
            "clears": list(TEST_RESET_CLEARS),
            "asserted_at": ["test_begin", "sample_begin"],
            "independent_of_cpu_reset": True,
            "derived_from": derived_from,
        },
        "distribution": distribution,
        "semantics": {
            "mode_selected_at": "test_begin",
            "cpu_reset_hold_modes": ["mmio_only"],
            "peripheral_reset": "released for the whole test in every mode",
            "full_test_reset": "clears all test state at test_begin and at each sample reset",
        },
    }


def _build_environment_contract(spec: Mapping[str, object]) -> dict:
    """Carry the explicit pin and IRQ contracts into the bound plan.

    The planner does not infer a pin from a component or signal name.  Keeping
    the validated records verbatim gives the environment driver and renderer a
    single source of truth for protocol parameters, trigger mode and mask/ack
    semantics.
    """
    links = sorted(
        (_deep(link) for link in spec["environment_links"]),
        key=lambda item: item["link_id"],
    )
    routes = sorted(
        (_deep(route) for route in spec["interrupt_routes"]),
        key=lambda item: item["route_id"],
    )
    return {
        "schema_version": "soc_environment_contract.v1",
        "links": links,
        "interrupt_routes": routes,
        "environment_driver": {
            "driver_id": "environment_pins",
            "ownership": "external_pins_only",
            "accepts_only_declared_links": True,
            "max_pending": 1,
        },
        "irq_router": {
            "module": "soc_irq_router",
            "capture": "per_source_pending",
            "claim": "priority_ordered",
            "completion": "explicit_complete",
            "simultaneous_sources": "retained_independently",
        },
        "provenance": {
            "links": "soc_spec.v1#/environment_links",
            "interrupt_routes": "soc_spec.v1#/interrupt_routes",
        },
    }


def _build_stimulus(spec: Mapping[str, object], test_mode: str | None) -> dict:
    pinned = spec.get("test_modes")
    available = list(pinned) if pinned else list(SOC_MODES)
    if test_mode is not None:
        if test_mode not in available:
            _error("mode-not-declared", test_mode)
        participants = [master["source_id"] for master in spec["masters"]
                        if test_mode in KIND_MODES[master["kind"]] and test_mode in master["test_modes"]]
        if not participants:
            _error("mode-not-declared", test_mode)
    modes: dict[str, dict] = {}
    for mode in SOC_MODES:
        participants = sorted(master["source_id"] for master in spec["masters"]
                              if mode in KIND_MODES[master["kind"]] and mode in master["test_modes"])
        unavailable = mode not in available
        modes[mode] = {
            "mode": mode,
            "available": not unavailable,
            "cpu_reset": {"held_in_reset_whole_test": mode == "mmio_only", "released_at": "test_begin"},
            "peripheral_reset": {"held_in_reset_whole_test": False, "released_at": "test_begin"},
            "test_reset": {"asserted_at": ["test_begin"], "clears": list(TEST_RESET_CLEARS),
                           "separate_from_cpu_reset": True},
            "participants": [] if unavailable else participants,
            "reset_semantics": (
                "cpu reset asserted for the whole test, peripherals released"
                if mode == "mmio_only"
                else "cpu reset released at test_begin"
            ),
        }
    return {
        "mode_selection": "test_begin",
        "selected_mode": test_mode,
        "available_modes": [mode for mode in SOC_MODES if mode in available],
        "modes": modes,
    }


def build_soc_plan(spec: dict, processor_execution: dict, target_contracts: list,
                   *, test_mode: str | None = None) -> dict:
    """Bind a validated spec to instances, adapters, nets and the address map.

    target_contracts is a list of per-target capability records produced by the
    source/capability lock (P1) and consumed again by target adapter resolution
    (P5).  Each record requires a target_id and a capabilities mapping with an
    explicit boolean partial_write; component_id, port and protocol, when
    present, must agree with the spec, and adapter_module (or adapter_modules
    keyed by source protocol) names the adapter module for this target.
    """
    validate_soc_spec(spec)
    execution = _validate_processor_execution(processor_execution)
    contracts = _index_contracts(target_contracts)

    for target in sorted(spec["targets"], key=lambda item: item["target_id"]):
        contract = contracts.get(target["target_id"])
        if contract is None:
            _error("missing-target-contract", target["target_id"])
        _validate_contract(contract, target)

    cpu_boundary = _build_cpu_boundary(spec, execution)
    fabric_spec = _deep(spec)
    effective_widths: dict[str, tuple[int, str]] = {}
    for target in fabric_spec["targets"]:
        contract = contracts[target["target_id"]]
        capability_width = contract["capabilities"].get("data_width")
        declared_width = target.get("data_width")
        if declared_width is None and capability_width is None:
            _error("missing-target-capability", f"{target['target_id']}:data_width")
        if declared_width is not None and capability_width is not None and declared_width != capability_width:
            _error("target-contract-mismatch", f"{target['target_id']}:data_width")
        effective_width = declared_width if declared_width is not None else capability_width
        provenance = "soc_spec.targets" if declared_width is not None else "target_contracts.capabilities"
        target["data_width"] = effective_width
        target["width_conversion"] = _width_conversion(target.get("width_conversion"), target["target_id"])
        effective_widths[target["target_id"]] = (effective_width, provenance)
        target["permissions"] = {
            "read": bool(contract["capabilities"].get("read")),
            "write": bool(contract["capabilities"].get("write")),
            "execute": False,
        }
    # Wait limits remain an external runtime concern.  Fabric construction is
    # canonicalized to the validated CPU backend capability, not an unrelated
    # caller resource hint that the plan validator cannot independently prove.
    if isinstance(fabric_spec.get("resources"), Mapping):
        fabric_spec["resources"] = dict(fabric_spec["resources"])
        fabric_spec["resources"]["limits"] = {}
    try:
        fabric = build_soc_fabric(fabric_spec, execution)
    except SocFabricError as error:
        _error("invalid-soc-fabric", str(error))

    instances = _build_instances(spec)
    adapters = _build_adapters(spec, contracts)
    nets, drivers = _build_nets(spec)
    crossings = _crossing_domains(spec)

    masters = {master["source_id"]: master for master in spec["masters"]}
    target_capabilities: dict[str, dict] = {}
    for target in sorted(spec["targets"], key=lambda item: item["target_id"]):
        contract = contracts[target["target_id"]]
        modules = {source_id: _adapter_module(contract, target["target_id"], masters[source_id])[0]
                   for source_id in target["request_sources"]}
        single = sorted(set(modules.values()))
        adapter = {
            "module": single[0] if len(single) == 1 else modules,
            "source": contract.get("adapter_source"),
        }
        fabric_module, fabric_source = _fabric_adapter_module(contract, target["target_id"])
        target_capabilities[target["target_id"]] = {
            "component_id": target["component_id"],
            "port": target["port"],
            "protocol": list(target["protocol"]),
            "byte_enable": target["byte_enable"],
            "data_width": effective_widths[target["target_id"]][0],
            "data_width_provenance": effective_widths[target["target_id"]][1],
            "declared_data_width": target.get("data_width"),
            "capability_data_width": contract["capabilities"].get("data_width"),
            "width_conversion": _width_conversion(target.get("width_conversion"), target["target_id"]),
            "adapter": adapter,
            "fabric_adapter": {"module": fabric_module, "source": fabric_source},
            "capabilities": _deep(contract["capabilities"]),
            "evidence": _deep(contract.get("evidence", {})),
            "provenance": {"source": "target_contracts", "target_id": target["target_id"]},
        }

    downstream_adapters = []
    for physical in fabric["targets"]:
        windows_for_target = [window for window in fabric["decode"]["windows"]
                              if window["target_index"] == physical["index"]]
        modules = [_fabric_adapter_module(contracts[window["target_id"]], window["target_id"])[0]
                   for window in windows_for_target]
        if not modules or any(module != modules[0] for module in modules[1:]):
            _error("shared-target-adapter-mismatch", physical["backing_id"])
        downstream_adapters.append({
            "target_index": physical["index"],
            "target_ids": sorted(window["target_id"] for window in windows_for_target),
            "module": modules[0],
            "role": "shared_fabric_to_target",
        })
    fabric["downstream_adapters"] = downstream_adapters
    fabric["network"] = {
        "ingress_nets": [f"ingress:{source['source_id']}" for source in fabric["sources"]],
        "target_nets": [f"target:{target_id}" for adapter in downstream_adapters
                        for target_id in adapter["target_ids"]],
    }
    fabric["source_manifest"] = sorted(set(
        list(fabric["rtl"]["sources"])
        + list(execution.get("adapter_sources", []))
        + [str(value["adapter"]["source"]) for value in target_capabilities.values()
           if value["adapter"]["source"]]
    ))

    spec_hash = soc_spec_hash(spec)
    plan = {
        "schema_version": SOC_PLAN_SCHEMA,
        "spec_id": spec["spec_id"],
        "spec_hash": spec_hash,
        "processor_execution": cpu_boundary,
        "fabric": fabric,
        "instances": instances,
        "adapters": adapters,
        "nets": nets,
        "net_drivers": drivers,
        "address_map": {
            "windows": [{
                "window_id": f"window:{target['target_id']}",
                "canonical_id": canonical_id("soc-address-window", target["target_id"]),
                "target_id": target["target_id"],
                "component_id": target["component_id"],
                "port": target["port"],
                "protocol": list(target["protocol"]),
                "window": {"base": target["window"]["base"], "size": target["window"]["size"]},
                "base": target["window"]["base"],
                "size": target["window"]["size"],
                "byte_enable": target["byte_enable"],
                "request_sources": sorted(target["request_sources"]),
                "width_conversion": _width_conversion(target.get("width_conversion"), target["target_id"]),
                "response_driver": {"role": "target", "target_id": target["target_id"]},
                "response_routing": "accepted_source",
            } for target in sorted(spec["targets"], key=lambda item: item["target_id"])],
            "memory_regions": [{
                "region_id": region["region_id"],
                "component_id": region["component_id"],
                "base": region["base"],
                "size": region["size"],
                "permissions": _deep(region["permissions"]),
                "physical_memory_id": region["physical_memory_id"],
                "initialization_policy": region["initialization_policy"],
            } for region in sorted(spec["memory_regions"], key=lambda item: item["region_id"])],
            "unmapped": {"behavior": "error", "response": "error_response", "side_effects": "none"},
            "decode": {
                "overlap_policy": "rejected-at-validation",
                "arbitration": "single-driver-per-target-port",
                "unmapped_policy": "explicit-error-no-side-effects",
            },
        },
        "target_capabilities": target_capabilities,
        "reset": _build_reset(spec, instances),
        # Keep the validated environment/IRQ ownership visible to downstream
        # stimulus and rendering stages; no pin or source is inferred here.
        "environment_links": _deep(spec["environment_links"]),
        "interrupt_routes": _deep(spec["interrupt_routes"]),
        "environment_contract": _build_environment_contract(spec),
        "clock_domains": [{
            "name": domain["name"],
            "canonical_id": canonical_id("soc-clock-domain", domain["name"]),
            "frequency_hz": domain["frequency_hz"],
            "components": sorted(component["component_id"] for component in spec["components"]
                                 if component["clock_domain"] == domain["name"]),
            "instances": sorted(instance["instance_id"] for instance in instances
                                if instance["clock_domain"] == domain["name"]),
            "crossing_adapters": sorted(adapter_id for adapter_id, domains in crossings.items()
                                         if domain["name"] in domains),
            "single_runtime_clock": len(spec["resources"]["clock_domains"]) == 1,
        } for domain in sorted(spec["resources"]["clock_domains"], key=lambda item: item["name"])],
        "stimulus": _build_stimulus(spec, test_mode),
        "assumptions": _deep(spec["assumptions"]),
        "provenance": dict(spec["provenance"], plan="soc_plan.v1", spec_hash=spec_hash),
    }
    plan["provenance"]["target_contracts"] = "caller-supplied capability records"
    validate_soc_plan(plan)
    return plan


__all__ = ["build_soc_plan"]
