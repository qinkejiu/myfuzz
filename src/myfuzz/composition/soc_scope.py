"""The explicit, machine-readable protocol and adapter scope of the composer.

``soc_composition.build_composition`` accepts exactly the combinations this
module declares as ``supported`` and raises a named refusal for every other
one.  The two halves are the same code: :func:`declared_scope_refusals` and
:func:`bound_scope_refusals` build their reason strings with the very builders
the scope record publishes, so the record cannot drift from what a caller sees.

The record (:func:`soc_adapter_scope`) is versioned by ``SOC_SCOPE_SCHEMA`` and
is plain JSON-compatible data:

* ``families``: one entry per (protocol family, side) pair, with the adapter
  block the composer really instantiates (empty for a side that has none).
* ``entries``: a flat list of feature claims.  Every entry is either
  ``supported`` (with the adapter, the audit check that proves the rendered
  wiring and the positive test) or ``refused`` (with the exact error string a
  caller sees for the documented fixture, its parameterised template and the
  code path that raises it).
* ``supported_topology``: the precise positive statement of what the composer
  supports today (clock domains, reset release, port directions, fabric lanes,
  debug, trace and the CPU input dispositions).  The clock-domain, reset,
  bidirectional-port, fabric-lane, debug-transport and CPU-input claims are
  entries in the same flat list, with ``family``/``side`` set to ``any``.

Nothing here decides anything by component or model name: every check reads a
declared profile fact (endpoint function, protocol, capability, port action,
reset binding) or the composition request.  ``trigger`` records name the
fixture and mutation the published ``error`` string was produced with, and
``tests/composition/test_soc_adapter_scope.py`` replays every one of them.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SOC_SCOPE_SCHEMA = "soc_adapter_scope.v1"
SUPPORTED = "supported"
REFUSED = "refused"

#: Endpoint functions that make an endpoint a bus master.
MASTER_FUNCTIONS = (
    "memory_master",
    "processor_memory_master",
    "instruction_memory_master",
    "data_memory_master",
)
#: Endpoint functions that make an endpoint an MMIO target.
TARGET_FUNCTIONS = ("mmio_slave", "memory_slave")

#: Capability keys whose declared value the composer cannot honour anywhere.
EXCLUSIVE_KEYS = ("exclusive_access", "exclusive", "lock", "locked")
CACHE_KEYS = ("cache_attributes", "cache", "attributes", "cacheable")
CDC_KEYS = ("cdc", "clock_domain_crossing", "async", "asynchronous_crossing")
BURST_KEYS = ("bursts", "burst")
TRANSACTION_ID_KEYS = ("transaction_ids", "ids", "multiple_ids", "out_of_order_ids")
RESET_SEQUENCE_KEYS = ("sequence", "sequence_after", "after", "depends_on", "release_order")

#: The byte-strobe role of each master protocol.  A profile that declares
#: ``byte_enable``/``partial_write`` without declaring this role would render an
#: adapter whose byte enable is tied to all-ones, turning a partial write into a
#: full-word write; that is refused instead.  A read-only master (one that
#: declares no write-enable role either) is not refused: it cannot write at all.
MASTER_STROBE_ROLES: dict[str, str] = {
    "obi": "be",
    "axi4": "wstrb",
    "axi4-lite": "wstrb",
    "tl-ul": "a_mask",
    "wishbone": "sel",
    "ready-valid": "wstrb",
}
#: The role that makes a master able to write at all.  ``None`` means the strobe
#: itself is the write channel, so a missing strobe already means read-only.
MASTER_WRITE_ROLES: dict[str, str | None] = {
    "obi": "we",
    "axi4": "wvalid",
    "axi4-lite": "wvalid",
    "tl-ul": "a_valid",
    "wishbone": "we",
    "ready-valid": None,
}

#: The declared CPU-input roles this composer understands.  A role in
#: ``REFUSED_CPU_INPUT_CLASSES`` is refused by name; every other CPU input is
#: classified by its declared disposition (constant / fuzz driver / functional).
CPU_INPUT_CLASSES: dict[str, tuple[str, ...]] = {
    "debug": ("debug", "debug_request", "debug_req", "debug_entry"),
    "fetch_enable": ("fetch_enable", "fetch_en"),
    "timer_interrupt": ("timer_interrupt", "machine_timer", "timer_irq", "timer"),
    "software_interrupt": ("software_interrupt", "machine_software", "software_irq", "software"),
    "trace": ("trace", "trace_valid", "instr_trace", "instruction_trace", "rvfi", "trace_port"),
}
REFUSED_CPU_INPUT_CLASSES = ("trace",)

#: The adapter blocks the composer really renders, per (family, side).
MASTER_ADAPTERS: dict[str, dict[str, str]] = {
    "obi": {
        "adapter_id": "obi-to-processor-memory-beat",
        "rtl_module": "obi_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
    "axi4": {
        "adapter_id": "axi4-to-processor-memory-beat",
        "rtl_module": "axi4_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
    "axi4-lite": {
        "adapter_id": "axi4-lite-to-processor-memory-beat",
        "rtl_module": "axi4_lite_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/axi4_lite_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
    "tl-ul": {
        "adapter_id": "tl-ul-to-processor-memory-beat",
        "rtl_module": "tl_ul_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/tl_ul_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
    "wishbone": {
        "adapter_id": "wishbone-to-processor-memory-beat",
        "rtl_module": "wishbone_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/wishbone_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
    "ready-valid": {
        "adapter_id": "ready-valid-to-processor-memory-beat",
        "rtl_module": "ready_valid_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/ready_valid_processor_memory_adapter.sv",
        "resolver": "processor_adapters.resolve_processor_adapter",
    },
}
#: Master families whose adapter block exists but does not pass the composer's
#: own fatal-warning frontend elaboration, so ``build_composition`` refuses them
#: by name instead of failing with the raw frontend error.  The record keeps the
#: adapter block above so the reason is traceable to the RTL.  Keyed by family
#: label; ``protocol_family`` maps a declared protocol to it.
REFUSED_MASTER_ADAPTERS: dict[str, str] = {
    "ready-valid": "ready_valid_processor_memory_adapter",
}

TARGET_ADAPTERS: dict[str, dict[str, str]] = {
    "apb3": {
        "adapter_id": "beat-to-apb3",
        "rtl_module": "beat_to_apb",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_apb.sv",
        "resolver": "target_adapters.resolve_target_adapter -> target_adapters._resolve_apb",
    },
    "apb4": {
        "adapter_id": "beat-to-apb4",
        "rtl_module": "beat_to_apb",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_apb.sv",
        "resolver": "target_adapters.resolve_target_adapter -> target_adapters._resolve_apb",
    },
    "tl-ul": {
        "adapter_id": "beat-to-tlul",
        "rtl_module": "beat_to_tlul",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_tlul.sv",
        "resolver": "target_adapters.resolve_target_adapter -> target_adapters._resolve_tlul",
    },
    "wishbone": {
        "adapter_id": "beat-to-wishbone-classic",
        "rtl_module": "beat_to_wishbone",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_wishbone.sv",
        "resolver": "target_adapters.resolve_target_adapter -> target_adapters._resolve_wishbone",
    },
}

#: The protocol families the scope record names, in record order, with the side
#: each one is really composed on.
FAMILIES: tuple[tuple[str, str, tuple[str, str]], ...] = (
    ("obi", "master", ("obi", "1")),
    ("obi", "target", ("obi", "1")),
    ("apb3", "target", ("apb", "3")),
    ("apb4", "target", ("apb", "4")),
    ("axi4-lite", "master", ("axi4-lite", "1")),
    ("axi4-lite", "target", ("axi4-lite", "1")),
    ("axi4", "master", ("axi4", "1")),
    ("axi4", "target", ("axi4", "1")),
    ("tl-ul", "master", ("tl-ul", "1")),
    ("tl-ul", "target", ("tl-ul", "1")),
    ("wishbone", "master", ("wishbone", "classic")),
    ("wishbone", "target", ("wishbone", "classic")),
    ("ready-valid", "master", ("ready-valid-memory", "1")),
    ("ready-valid", "target", ("ready-valid-memory", "1")),
)

#: The feature axes the record enumerates for every composed family.
FEATURES = (
    "data_width",
    "burst",
    "transaction_id",
    "multiple_outstanding",
    "byte_enable",
    "error_response",
    "exclusive_access",
    "cache_attributes",
)

DECLARED_PATH = "soc_composition.build_composition -> soc_scope.declared_scope_refusals"
BOUND_PATH = "soc_composition.build_composition -> soc_scope.bound_scope_refusals"
TARGET_ADAPTER_PATH = ("soc_composition._peripheral_target_adapter -> "
                       "target_adapters.resolve_target_adapter")
PROFILE_PATH = "component_profile._validate_request_consistency"
DISPOSITION_PATH = ("soc_composition.build_composition -> "
                    "soc_port_dispositions.build_port_dispositions -> PortDispositionError")

TEST_MODULE = "tests.composition.test_soc_adapter_scope"

#: Why the tl-ul *target* resolver refusals are published without a replay
#: trigger: the adapter and its refusals exist and are covered by the RTL-level
#: resolver tests, but no ``component_profile.v1`` in this checkout declares a
#: complete tl-ul target (the opentitan_* profiles declare no MMIO endpoint at
#: all), so ``build_composition`` cannot reach that path end to end.
_TLUL_EVIDENCE = ("resolver and RTL covered by tests/protocols/"
                  "test_soc_target_adapters_rtl.py; no component_profile in this "
                  "checkout declares a complete tl-ul target, so this resolver-path "
                  "refusal has no end-to-end replay")


# ---------------------------------------------------------------------------
# reason builders: the single source of the exact refusal strings
# ---------------------------------------------------------------------------


def _protocol(protocol: Sequence[str]) -> str:
    return f"{protocol[0]}@{protocol[1]}"


#: declared protocol -> the family label the scope record uses.
PROTOCOL_FAMILY: dict[tuple[str, str], str] = {
    (protocol[0], protocol[1]): family for family, _side, protocol in FAMILIES
}


def protocol_family(protocol: Sequence[str]) -> str:
    """The family label of a declared protocol, or the protocol name itself."""
    key = (str(protocol[0]), str(protocol[1])) if protocol else ("", "")
    return PROTOCOL_FAMILY.get(key, key[0])


def data_width_refusal(instance_id: str, endpoint_id: str, side: str,
                       protocol: Sequence[str], width: object) -> str:
    return (f"unsupported-{side}-data-width:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:{width}:only-32-bit-is-composed")


def master_contract_undeclared(instance_id: str, endpoint_id: str,
                               protocol: Sequence[str], capability: str) -> str:
    return (f"undeclared-master-contract:{instance_id}:{endpoint_id}:{_protocol(protocol)}:"
            f"{capability}:axi4-full-requires-the-declared-single-beat-"
            f"single-outstanding-contract")


def outstanding_refusal(instance_id: str, endpoint_id: str, side: str,
                        protocol: Sequence[str], value: object) -> str:
    return (f"unsupported-{side}-outstanding:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:max_outstanding={value}:only-1-is-composed")


def burst_refusal(instance_id: str, endpoint_id: str, side: str,
                  protocol: Sequence[str]) -> str:
    return (f"unsupported-{side}-burst:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:bursts-are-not-composed")


def transaction_id_refusal(instance_id: str, endpoint_id: str, side: str,
                           protocol: Sequence[str]) -> str:
    return (f"unsupported-{side}-transaction-id:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:multiple-or-out-of-order-ids-are-not-composed")


def exclusive_refusal(instance_id: str, endpoint_id: str, side: str,
                      protocol: Sequence[str]) -> str:
    return (f"unsupported-{side}-exclusive-access:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:exclusive-access-has-no-path-in-this-composer")


def cache_refusal(instance_id: str, endpoint_id: str, side: str,
                  protocol: Sequence[str]) -> str:
    return (f"unsupported-{side}-cache-attributes:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:cache-and-attribute-semantics-have-no-path-in-"
            f"this-composer")


def master_error_refusal(instance_id: str, endpoint_id: str,
                         protocol: Sequence[str]) -> str:
    return (f"unsupported-master-error-response:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:the-ready-valid-adapter-has-no-error-channel")


def master_adapter_refusal(instance_id: str, endpoint_id: str, protocol: Sequence[str],
                           module: str) -> str:
    return (f"unsupported-master-adapter:{instance_id}:{endpoint_id}:{_protocol(protocol)}:"
            f"adapter-{module}-does-not-pass-the-fatal-warning-frontend-elaboration")


def master_byte_enable_refusal(instance_id: str, endpoint_id: str, protocol: Sequence[str],
                               role: str) -> str:
    return (f"unsupported-master-byte-enable:{instance_id}:{endpoint_id}:"
            f"{_protocol(protocol)}:the-profile-declares-byte-enable-but-the-endpoint-"
            f"declares-no-{role}-role")


def crossing_refusal(instance_id: str, side: str, protocol: Sequence[str]) -> str:
    return (f"unsupported-clock-domain-crossing:{instance_id}:{side}:{_protocol(protocol)}:"
            f"cdc-declared-but-no-synchroniser-is-composed")


def route_crossing_refusal(source_id: str, source_domain: str, target_id: str,
                           target_domain: str) -> str:
    return (f"cross-domain-route:{source_id}:{source_domain}:{target_id}:{target_domain}:"
            f"no-synchroniser-is-composed")


def debug_transport_refusal(instance_id: str, endpoint_id: str) -> str:
    return (f"debug-transport-unsupported:{instance_id}:{endpoint_id}:"
            f"this-composer-builds-no-debug-transport")


def peripheral_master_refusal(instance_id: str, endpoint_id: str, function: str) -> str:
    return (f"fabric-master-lane-unavailable:{instance_id}:{endpoint_id}:{function}:"
            f"only-the-cpu-master-endpoints-and-the-generated-synthetic-master-own-"
            f"fabric-lanes")


def reset_sequence_profile_refusal(component_id: str, port: str, after: str) -> str:
    return (f"reset-sequence-unsupported:{component_id}:{port}:{after}:"
            f"only-one-simultaneously-released-reset-domain-is-composed")


def reset_sequence_request_refusal(request_id: str, order: Sequence[str]) -> str:
    return (f"reset-sequence-unsupported:{request_id}:"
            f"{','.join(str(item) for item in order)}:"
            f"only-one-simultaneously-released-reset-domain-is-composed")


def inout_port_refusal(port: str) -> str:
    return f"inout-port-unsupported:{port}:no-single-unambiguous-direction-is-declared"


def trace_input_refusal(instance_id: str, port: str, role: str) -> str:
    return f"trace-input-unsupported:{instance_id}:{port}:{role}:this-composer-captures-no-trace"


# ---------------------------------------------------------------------------
# declared-fact readers (this module never imports the composition layer)
# ---------------------------------------------------------------------------


def _capabilities(profile: object) -> Mapping[str, Any]:
    return dict(getattr(profile, "capabilities", {}) or {})


def _endpoints(profile: object) -> tuple[Any, ...]:
    return tuple(getattr(profile, "endpoints", ()) or ())


def _endpoint_protocol(endpoint: object) -> tuple[str, str]:
    protocol = getattr(endpoint, "protocol", None)
    if protocol is None:
        return ("", "")
    return (str(protocol[0]), str(protocol[1]))


def _endpoint_roles(endpoint: object) -> set[str]:
    return {str(getattr(field, "role", "")) for field in
            tuple(getattr(endpoint, "fields", ()) or ())}


def _first_declared(capabilities: Mapping[str, Any],
                    keys: Sequence[str]) -> tuple[str, Any] | None:
    for key in keys:
        if key in capabilities:
            return key, capabilities[key]
    return None


def _declared_true(capabilities: Mapping[str, Any], keys: Sequence[str]) -> bool:
    found = _first_declared(capabilities, keys)
    return found is not None and found[1] is True


def _reset_sequence(profile: object) -> list[tuple[str, str]]:
    """Declared reset ordering: ``(port, after)`` for every reset that has one."""
    declared: list[tuple[str, str]] = []
    for binding in tuple(getattr(profile, "resets", ()) or ()):
        for item in tuple(getattr(binding, "sequence_after", ()) or ()):
            declared.append((str(getattr(binding, "port", "")), str(item)))
    return declared


def declared_role(action: object) -> str | None:
    """The role a port action declares, or None."""
    role = getattr(action, "role", None)
    return None if role is None else str(role)


def cpu_input_class(role: object) -> str | None:
    """The declared CPU-input class of a profile role, or None."""
    if role is None:
        return None
    text = str(role).strip().lower()
    for name, vocabulary in CPU_INPUT_CLASSES.items():
        if text in vocabulary:
            return name
    return None


# ---------------------------------------------------------------------------
# stage 1: refusals that follow from the request and the declared profiles
# ---------------------------------------------------------------------------


def declared_scope_refusals(request: object) -> list[str]:
    """Every refusal that only needs the request and the declared profiles.

    These run before any component is bound, so a refused capability is named
    even when the profile's ports could not be bound at all.  The checks run in
    a fixed order, so a profile that breaks several rules at once produces a
    deterministic first reason.
    """
    refusals: list[str] = []
    request_sequence = tuple(getattr(request, "reset_sequence", ()) or ())
    if request_sequence:
        refusals.append(reset_sequence_request_refusal(
            str(getattr(request, "request_id", "")), request_sequence))

    for instance in sorted(request.instances(), key=lambda item: item.instance_id):
        instance_id = str(instance.instance_id)
        profile = instance.profile
        capabilities = _capabilities(profile)
        component_id = str(getattr(profile, "component_id", ""))

        for port, after in sorted(_reset_sequence(profile)):
            refusals.append(reset_sequence_profile_refusal(component_id, port, after))

        for endpoint in sorted(_endpoints(profile),
                               key=lambda item: str(getattr(item, "endpoint_id", ""))):
            function = str(getattr(endpoint, "function", ""))
            endpoint_id = str(getattr(endpoint, "endpoint_id", ""))
            protocol = _endpoint_protocol(endpoint)
            if function in MASTER_FUNCTIONS:
                refusals.extend(_master_contract_refusals(
                    instance_id, endpoint_id, protocol, capabilities,
                    _endpoint_roles(endpoint)))
            elif function in TARGET_FUNCTIONS:
                refusals.extend(_target_scope_refusals(
                    instance_id, endpoint_id, protocol, capabilities))
    return refusals


def _master_contract_refusals(instance_id: str, endpoint_id: str,
                              protocol: Sequence[str], capabilities: Mapping[str, Any],
                              roles: set[str]) -> list[str]:
    refusals: list[str] = []
    family = protocol_family(protocol)
    refused_module = REFUSED_MASTER_ADAPTERS.get(family)
    if refused_module is not None:
        # The whole family is refused.  A profile that additionally claims an
        # error channel gets the more specific refusal: that adapter has no
        # error output at all, which is why the claim can never be honoured.
        if capabilities.get("error_response") is True:
            return [master_error_refusal(instance_id, endpoint_id, protocol)]
        return [master_adapter_refusal(instance_id, endpoint_id, protocol, refused_module)]
    width = capabilities.get("data_width")
    if width is None:
        refusals.append(master_contract_undeclared(instance_id, endpoint_id, protocol,
                                                   "data_width"))
    elif width != 32:
        refusals.append(data_width_refusal(instance_id, endpoint_id, "master", protocol, width))
    outstanding = capabilities.get("max_outstanding")
    if family == "axi4":
        if outstanding is None:
            refusals.append(master_contract_undeclared(instance_id, endpoint_id, protocol,
                                                       "max_outstanding"))
        elif outstanding != 1:
            refusals.append(outstanding_refusal(instance_id, endpoint_id, "master", protocol,
                                                outstanding))
        bursts = capabilities.get("bursts")
        if bursts is None:
            refusals.append(master_contract_undeclared(instance_id, endpoint_id, protocol,
                                                       "bursts"))
        elif bursts is not False:
            refusals.append(burst_refusal(instance_id, endpoint_id, "master", protocol))
    else:
        if outstanding is not None and outstanding != 1:
            refusals.append(outstanding_refusal(instance_id, endpoint_id, "master", protocol,
                                                outstanding))
        found = _first_declared(capabilities, BURST_KEYS)
        if found is not None and found[1] is not False:
            refusals.append(burst_refusal(instance_id, endpoint_id, "master", protocol))
    found = _first_declared(capabilities, TRANSACTION_ID_KEYS)
    if found is not None and found[1] is not False:
        refusals.append(transaction_id_refusal(instance_id, endpoint_id, "master", protocol))
    if _declared_true(capabilities, EXCLUSIVE_KEYS):
        refusals.append(exclusive_refusal(instance_id, endpoint_id, "master", protocol))
    if _declared_true(capabilities, CACHE_KEYS):
        refusals.append(cache_refusal(instance_id, endpoint_id, "master", protocol))
    if _declared_true(capabilities, CDC_KEYS):
        refusals.append(crossing_refusal(instance_id, "master", protocol))
    strobe_role = MASTER_STROBE_ROLES.get(family)
    write_role = MASTER_WRITE_ROLES.get(family)
    if strobe_role is not None and (
            capabilities.get("byte_enable") is True
            or capabilities.get("partial_write") is True) and strobe_role not in roles:
        if write_role is None or write_role in roles:
            refusals.append(master_byte_enable_refusal(instance_id, endpoint_id, protocol,
                                                       strobe_role))
    return refusals


def _target_scope_refusals(instance_id: str, endpoint_id: str,
                           protocol: Sequence[str],
                           capabilities: Mapping[str, Any]) -> list[str]:
    refusals: list[str] = []
    width = capabilities.get("data_width")
    if width is not None and width != 32:
        refusals.append(data_width_refusal(instance_id, endpoint_id, "target", protocol, width))
    outstanding = capabilities.get("max_outstanding")
    if outstanding is not None and outstanding != 1:
        refusals.append(outstanding_refusal(instance_id, endpoint_id, "target", protocol,
                                            outstanding))
    found = _first_declared(capabilities, BURST_KEYS)
    if found is not None and found[1] is not False:
        refusals.append(burst_refusal(instance_id, endpoint_id, "target", protocol))
    found = _first_declared(capabilities, TRANSACTION_ID_KEYS)
    if found is not None and found[1] is not False:
        refusals.append(transaction_id_refusal(instance_id, endpoint_id, "target", protocol))
    if _declared_true(capabilities, EXCLUSIVE_KEYS):
        refusals.append(exclusive_refusal(instance_id, endpoint_id, "target", protocol))
    if _declared_true(capabilities, CACHE_KEYS):
        refusals.append(cache_refusal(instance_id, endpoint_id, "target", protocol))
    if _declared_true(capabilities, CDC_KEYS):
        refusals.append(crossing_refusal(instance_id, "target", protocol))
    return refusals


# ---------------------------------------------------------------------------
# stage 2: refusals that need the bound, disposed instances
# ---------------------------------------------------------------------------


def bound_scope_refusals(request: object, instances: Sequence[object]) -> list[str]:
    """Refusals over the bound structure: lanes, debug, trace and route domains.

    These run after every component has been bound and disposed, so a profile
    that also has a binding conflict is reported with that conflict first (the
    binding diagnostics are the more precise ones).  The request-level
    single-domain gate (``cross-domain-unsupported``) refuses a profile whose
    declared clock is foreign before any route is formed, so a composition that
    reaches this point has one domain and no route crosses it: the route-level
    check below is the second half of the same statement, it is what a future
    multi-domain request would hit first, and it is tested directly because the
    request-level gate makes it unreachable end to end today.
    """
    refusals: list[str] = []
    domains: list[tuple[str, str]] = []
    for instance in sorted(instances, key=lambda item: str(item.instance_id)):
        instance_id = str(instance.instance_id)
        profile = instance.profile
        kind = str(getattr(profile, "kind", ""))
        for endpoint in sorted(_endpoints(profile),
                               key=lambda item: str(getattr(item, "endpoint_id", ""))):
            function = str(getattr(endpoint, "function", ""))
            endpoint_id = str(getattr(endpoint, "endpoint_id", ""))
            if function == "debug_slave":
                refusals.append(debug_transport_refusal(instance_id, endpoint_id))
            elif function in MASTER_FUNCTIONS and kind != "cpu":
                refusals.append(peripheral_master_refusal(instance_id, endpoint_id, function))
        if kind == "cpu":
            for action in sorted(tuple(getattr(profile, "port_actions", ()) or ()),
                                 key=lambda item: str(getattr(item, "port", ""))):
                role = declared_role(action)
                if cpu_input_class(role) in REFUSED_CPU_INPUT_CLASSES:
                    refusals.append(trace_input_refusal(
                        instance_id, str(getattr(action, "port", "")), str(role)))
        clocks = tuple(getattr(getattr(instance, "binding", None), "clocks", ()) or ())
        domain = str(getattr(clocks[0][0], "domain", "")) if clocks else ""
        domains.append((instance_id, domain))
    cpu_id = str(getattr(request.cpu, "instance_id", ""))
    cpu_domain = next((domain for name, domain in domains if name == cpu_id), "")
    for instance_id, domain in domains:
        if domain and domain != cpu_domain:
            refusals.append(route_crossing_refusal(cpu_id, cpu_domain, instance_id, domain))
            # The public composer reports the first deterministic route
            # refusal.  Returning all foreign instances here made the direct
            # replay API disagree with the same fail-fast contract.
            break
    return refusals


# ---------------------------------------------------------------------------
# CPU input completeness record
# ---------------------------------------------------------------------------


def cpu_input_records(instance: object) -> list[dict[str, object]]:
    """One record per CPU input port, derived from the disposition ledger.

    The record states, for every input of a CPU instance, exactly who drives it
    and with what: a rendered constant literal, a ``soc_special_input_driver``
    instance named after the port, another functional net of the generated top,
    or the exported top-level port of an external interface.  The structural
    audit re-reads the elaborated netlist against this record, so the claim is
    checked rather than assumed.
    """
    if str(getattr(instance, "kind", "")) != "cpu":
        return []
    # Imported here: this module is itself imported while component_profile is
    # still initialising, so a module-level import of the ledger's naming helpers
    # would close the cycle.
    from .soc_port_dispositions import constant_expression, driven_net, top_port_name

    instance_id = str(instance.instance_id)
    declared_roles: dict[str, str] = {}
    for action in tuple(getattr(getattr(instance, "profile", None), "port_actions", ()) or ()):
        role = declared_role(action)
        if role is not None:
            declared_roles[str(getattr(action, "port", ""))] = role
    records: list[dict[str, object]] = []
    for entry in sorted(getattr(instance, "dispositions", ()) or (),
                        key=lambda item: (item.port, item.bit_lo)):
        if entry.direction != "input":
            continue
        role = entry.role or declared_roles.get(entry.port)
        width = entry.bit_hi - entry.bit_lo + 1
        span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
            f"[{entry.bit_hi}:{entry.bit_lo}]"
        record: dict[str, object] = {
            "instance_id": instance_id,
            "port": entry.port,
            "bits": {"lo": entry.bit_lo, "hi": entry.bit_hi},
            "width": width,
            "disposition": entry.disposition,
            "role": role,
            "class": cpu_input_class(role),
            "clock_domain": entry.clock_domain,
            "reset_domain": entry.reset_domain,
        }
        if entry.value is not None:
            record["value"] = entry.value
        if entry.strategy is not None:
            record["strategy"] = entry.strategy
        if entry.disposition == "constant":
            record["driver"] = "soc_top_constant"
            record["expected_net"] = f"{span}{constant_expression(entry)}"
            record["audit"] = "cpu_input_dispositions"
        elif entry.disposition == "fuzz":
            record["driver"] = "soc_special_input_driver"
            record["driver_cell"] = f"u_drive_{top_port_name(entry)}"
            record["expected_net"] = driven_net(entry)
            record["audit"] = "cpu_input_dispositions"
        elif entry.disposition == "external":
            record["driver"] = "soc_top_port"
            record["expected_net"] = top_port_name(entry)
            record["audit"] = "cpu_input_dispositions"
        elif entry.disposition == "functional" and entry.role == "clock":
            record["driver"] = "soc_clock"
            record["expected_net"] = "clk_i"
            record["audit"] = "cpu_input_dispositions"
        elif entry.disposition == "functional" and entry.role == "reset":
            record["driver"] = "soc_reset"
            record["audit"] = "cpu_reset_hold"
        elif entry.disposition == "functional":
            record["driver"] = "processor_adapter"
            record["audit"] = "cpu_adapter_wiring"
        elif entry.disposition == "peer":
            record["driver"] = f"peer:{entry.target}"
            record["audit"] = "peer_roles"
        else:
            record["driver"] = str(entry.disposition)
            record["audit"] = None
        records.append(record)
    return records


# ---------------------------------------------------------------------------
# the scope record
# ---------------------------------------------------------------------------


def _entry(*, family: str, side: str, protocol: Sequence[str], feature: str,
           status: str, condition: str, declaration: str | None = None,
           error: str | None = None, error_template: str | None = None,
           code_path: str | None = None, adapter: Mapping[str, str] | None = None,
           audit: str | None = None, test: str | None = None,
           composition_test: str | None = None,
           composition_evidence: str | None = None,
           replay_evidence: str | None = None,
           trigger: Mapping[str, object] | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "family": family,
        "side": side,
        "protocol": list(protocol),
        "feature": feature,
        "status": status,
        "condition": condition,
    }
    if declaration is not None:
        record["declaration"] = declaration
    if status == REFUSED:
        record["error"] = error
        record["error_template"] = error_template
        record["code_path"] = code_path
        if replay_evidence is not None:
            record["replay_evidence"] = replay_evidence
    else:
        record["adapter"] = dict(adapter or {})
        record["audit"] = audit
        record["test"] = test
        if composition_test is not None:
            record["composition_test"] = composition_test
        if composition_evidence is not None:
            record["composition_evidence"] = composition_evidence
    if trigger is not None:
        record["trigger"] = dict(trigger)
    return record


#: Fixture names the trigger records refer to.  Each names the instance,
#: endpoint and component the published ``error`` literal was rendered with.
MASTER_FIXTURE = {"instance": "cpu0", "endpoint": "core.bus", "component": "novacore"}
TARGET_FIXTURES: dict[str, dict[str, str]] = {
    "apb3": {"instance": "spi0", "endpoint": "spi.bus", "component": "pulp_spi"},
    "apb4": {"instance": "gpio0", "endpoint": "gpio.bus", "component": "novagpio"},
    "tl-ul": {"instance": "uart0", "endpoint": "uart.bus", "component": "opentitan_uart"},
    "wishbone": {"instance": "uart0", "endpoint": "uart.bus", "component": "novauart_link"},
}


def _master_feature_entries(family: str, protocol: Sequence[str]) -> list[dict[str, object]]:
    instance, endpoint = MASTER_FIXTURE["instance"], MASTER_FIXTURE["endpoint"]
    adapter = MASTER_ADAPTERS[family]
    positive = f"{TEST_MODULE}.MasterCompositionTests.test_{family.replace('-', '_')}_master_composes"
    trigger_fixture = f"{family}-master"
    entries: list[dict[str, object]] = [
        _entry(family=family, side="master", protocol=protocol, feature="data_width",
               status=SUPPORTED,
               condition="capabilities.data_width is 32, the width of the beat fabric",
               declaration="capabilities.data_width", adapter=adapter,
               audit="adapter_binding", test=positive,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "data_width",
                        "value": 32}),
        _entry(family=family, side="master", protocol=protocol, feature="data_width",
               status=REFUSED,
               condition="capabilities.data_width is anything but 32",
               declaration="capabilities.data_width",
               error=data_width_refusal(instance, endpoint, "master", protocol, 64),
               error_template=("unsupported-master-data-width:<instance>:<endpoint>:"
                               "<protocol>@<version>:<width>:only-32-bit-is-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "data_width", "value": 64}),
        _entry(family=family, side="master", protocol=protocol, feature="burst",
               status=REFUSED,
               condition="capabilities.bursts is declared true",
               declaration="capabilities.bursts",
               error=burst_refusal(instance, endpoint, "master", protocol),
               error_template=("unsupported-master-burst:<instance>:<endpoint>:"
                               "<protocol>@<version>:bursts-are-not-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "bursts"}),
        _entry(family=family, side="master", protocol=protocol, feature="transaction_id",
               status=REFUSED,
               condition="capabilities.transaction_ids (or ids/multiple_ids/out_of_order_ids) "
                         "is declared true",
               declaration="capabilities.transaction_ids|ids",
               error=transaction_id_refusal(instance, endpoint, "master", protocol),
               error_template=("unsupported-master-transaction-id:<instance>:<endpoint>:"
                               "<protocol>@<version>:multiple-or-out-of-order-ids-are-not-"
                               "composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "transaction_ids"}),
        _entry(family=family, side="master", protocol=protocol,
               feature="multiple_outstanding", status=SUPPORTED,
               condition="capabilities.max_outstanding is 1, the beat fabric's own "
                         "single-outstanding contract",
               declaration="capabilities.max_outstanding", adapter=adapter,
               audit="adapter_binding", test=positive,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "max_outstanding",
                        "value": 1}),
        _entry(family=family, side="master", protocol=protocol,
               feature="multiple_outstanding", status=REFUSED,
               condition="capabilities.max_outstanding is declared greater than 1",
               declaration="capabilities.max_outstanding",
               error=outstanding_refusal(instance, endpoint, "master", protocol, 2),
               error_template=("unsupported-master-outstanding:<instance>:<endpoint>:"
                               "<protocol>@<version>:max_outstanding=<value>:only-1-is-"
                               "composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "max_outstanding",
                        "value": 2}),
        _entry(family=family, side="master", protocol=protocol, feature="exclusive_access",
               status=REFUSED,
               condition="any exclusive/locked capability is declared true",
               declaration="capabilities.exclusive_access|exclusive|lock",
               error=exclusive_refusal(instance, endpoint, "master", protocol),
               error_template=("unsupported-master-exclusive-access:<instance>:<endpoint>:"
                               "<protocol>@<version>:exclusive-access-has-no-path-in-this-"
                               "composer"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "exclusive_access"}),
        _entry(family=family, side="master", protocol=protocol, feature="cache_attributes",
               status=REFUSED,
               condition="any cache/attribute capability is declared true",
               declaration="capabilities.cache_attributes|cache|attributes",
               error=cache_refusal(instance, endpoint, "master", protocol),
               error_template=("unsupported-master-cache-attributes:<instance>:<endpoint>:"
                               "<protocol>@<version>:cache-and-attribute-semantics-have-no-"
                               "path-in-this-composer"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "cache_attributes"}),
        _entry(family=family, side="master", protocol=protocol, feature="byte_enable",
               status=SUPPORTED,
               condition=f"the endpoint declares the {MASTER_STROBE_ROLES[family]} strobe role "
                         f"the {family} adapter consumes; a profile that declares byte_enable "
                         f"or partial_write without it is refused instead of rendering an "
                         f"all-ones byte enable",
               declaration="capabilities.byte_enable|partial_write",
               adapter=adapter, audit="adapter_binding", test=positive,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "byte_enable", "value": True}),
        _entry(family=family, side="master", protocol=protocol, feature="byte_enable",
               status=REFUSED,
               condition=(f"capabilities.byte_enable or capabilities.partial_write is declared "
                          f"true while the endpoint declares no "
                          f"{MASTER_STROBE_ROLES[family]} role"),
               declaration="capabilities.byte_enable|partial_write",
               error=master_byte_enable_refusal(instance, endpoint, protocol,
                                                MASTER_STROBE_ROLES[family]),
               error_template=("unsupported-master-byte-enable:<instance>:<endpoint>:"
                               "<protocol>@<version>:the-profile-declares-byte-enable-but-"
                               "the-endpoint-declares-no-<role>-role"),
               code_path=DECLARED_PATH,
               trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                        "mutation": "drop_endpoint_role",
                        "role": MASTER_STROBE_ROLES[family]}),
        _entry(family=family, side="master", protocol=protocol, feature="error_response",
               status=REFUSED if family == "ready-valid" else SUPPORTED,
               condition=("capabilities.error_response is declared true for a ready-valid "
                          "master: the ready-valid adapter has no error output at all"
                          if family == "ready-valid" else
                          f"the {family} adapter carries the protocol's own error channel "
                          f"and the profile's capabilities.error_response matches the "
                          f"declared endpoint"),
               declaration="capabilities.error_response",
               adapter=None if family == "ready-valid" else adapter,
               audit=None if family == "ready-valid" else "adapter_binding",
               test=None if family == "ready-valid" else positive,
               error=master_error_refusal(instance, endpoint, protocol)
               if family == "ready-valid" else None,
               error_template=("unsupported-master-error-response:<instance>:<endpoint>:"
                               "ready-valid-memory@1:the-ready-valid-adapter-has-no-error-"
                               "channel") if family == "ready-valid" else None,
               code_path=DECLARED_PATH if family == "ready-valid" else None,
               trigger=({"fixture": trigger_fixture, "fixture_request": "request.json",
                         "mutation": "capability", "capability": "error_response",
                         "value": True}
                        if family == "ready-valid" else
                        {"fixture": trigger_fixture, "fixture_request": "request.json",
                         "mutation": "capability", "capability": "error_response",
                         "value": True})),
    ]
    if family == "ready-valid":
        # The loss is real and is recorded, not hidden: the adapter's own feature
        # list carries "error-response-zero" and the generated top has no error
        # wire to the CPU.
        entries.append(_entry(
            family=family, side="master", protocol=protocol, feature="error_response",
            status=SUPPORTED,
            condition="capabilities.error_response is absent/false: the ready-valid adapter "
                      "is rendered with its declared error-response-zero contract, so a "
                      "fabric decode error or target rejection is NOT visible to this CPU",
            declaration="capabilities.error_response",
            adapter=adapter, audit="cpu_adapter_parameters",
            test=f"{TEST_MODULE}.MasterCompositionTests."
                 f"test_ready_valid_master_records_the_zero_error_response_loss",
            composition_evidence="plan.cpu_adapter.features contains error-response-zero",
            trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                     "mutation": "capability", "capability": "error_response",
                     "value": False},
        ))
    if family == "axi4":
        entries.extend([
            _entry(family=family, side="master", protocol=protocol,
                   feature="multiple_outstanding", status=REFUSED,
                   condition="an axi4 full master that does not declare "
                             "capabilities.max_outstanding at all",
                   declaration="capabilities.max_outstanding",
                   error=master_contract_undeclared(instance, endpoint, protocol,
                                                    "max_outstanding"),
                   error_template=("undeclared-master-contract:<instance>:<endpoint>:"
                                   "<protocol>@<version>:max_outstanding:axi4-full-requires-"
                                   "the-declared-single-beat-single-outstanding-contract"),
                   code_path=DECLARED_PATH,
                   trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                            "mutation": "remove_capability", "capability": "max_outstanding"}),
            _entry(family=family, side="master", protocol=protocol, feature="burst",
                   status=REFUSED,
                   condition="an axi4 full master that does not declare capabilities.bursts "
                             "false",
                   declaration="capabilities.bursts",
                   error=master_contract_undeclared(instance, endpoint, protocol, "bursts"),
                   error_template=("undeclared-master-contract:<instance>:<endpoint>:"
                                   "<protocol>@<version>:bursts:axi4-full-requires-the-"
                                   "declared-single-beat-single-outstanding-contract"),
                   code_path=DECLARED_PATH,
                   trigger={"fixture": trigger_fixture, "fixture_request": "request.json",
                            "mutation": "remove_capability", "capability": "bursts"}),
        ])
    return entries


def _target_feature_entries(family: str, protocol: Sequence[str]) -> list[dict[str, object]]:
    manifest = TARGET_FIXTURES[family]
    instance, endpoint, component = (manifest["instance"], manifest["endpoint"],
                                     manifest["component"])
    adapter = TARGET_ADAPTERS.get(family, {})
    fixture = f"{family}-target"
    composition_test = (f"{TEST_MODULE}.TargetCompositionTests."
                        f"test_{family.replace('-', '_')}_target_composes")
    missing = None
    if family == "tl-ul":
        missing = ("no component_profile in this checkout declares a complete tl-ul "
                   "mmio_slave endpoint (the opentitan_* profiles declare no MMIO "
                   "endpoint), so the resolver and RTL are covered by "
                   "tests/protocols/test_soc_target_adapters_rtl.py and no end-to-end "
                   "composition test exists")
    entries: list[dict[str, object]] = [
        _entry(family=family, side="target", protocol=protocol, feature="data_width",
               status=SUPPORTED,
               condition="capabilities.data_width is 32, the width of the beat fabric",
               declaration="capabilities.data_width", adapter=adapter,
               audit="adapter_binding",
               test=None if missing else composition_test,
               composition_evidence=missing,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "data_width", "value": 32}),
        _entry(family=family, side="target", protocol=protocol, feature="data_width",
               status=REFUSED,
               condition="capabilities.data_width is anything but 32",
               declaration="capabilities.data_width",
               error=data_width_refusal(instance, endpoint, "target", protocol, 64),
               error_template=("unsupported-target-data-width:<instance>:<endpoint>:"
                               "<protocol>@<version>:<width>:only-32-bit-is-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "data_width", "value": 64}),
        _entry(family=family, side="target", protocol=protocol, feature="burst",
               status=REFUSED,
               condition="capabilities.bursts is declared true",
               declaration="capabilities.bursts",
               error=burst_refusal(instance, endpoint, "target", protocol),
               error_template=("unsupported-target-burst:<instance>:<endpoint>:"
                               "<protocol>@<version>:bursts-are-not-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "bursts"}),
        _entry(family=family, side="target", protocol=protocol, feature="transaction_id",
               status=REFUSED,
               condition="capabilities.transaction_ids (or ids) is declared true",
               declaration="capabilities.transaction_ids|ids",
               error=transaction_id_refusal(instance, endpoint, "target", protocol),
               error_template=("unsupported-target-transaction-id:<instance>:<endpoint>:"
                               "<protocol>@<version>:multiple-or-out-of-order-ids-are-not-"
                               "composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "transaction_ids"}),
        _entry(family=family, side="target", protocol=protocol,
               feature="multiple_outstanding", status=SUPPORTED,
               condition="capabilities.max_outstanding is 1 or is not declared (the beat "
                         "target adapter is single-outstanding by construction)",
               declaration="capabilities.max_outstanding", adapter=adapter,
               audit="adapter_binding",
               test=None if missing else composition_test,
               composition_evidence=missing,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "max_outstanding",
                        "value": 1}),
        _entry(family=family, side="target", protocol=protocol,
               feature="multiple_outstanding", status=REFUSED,
               condition="capabilities.max_outstanding is declared greater than 1",
               declaration="capabilities.max_outstanding",
               error=outstanding_refusal(instance, endpoint, "target", protocol, 2),
               error_template=("unsupported-target-outstanding:<instance>:<endpoint>:"
                               "<protocol>@<version>:max_outstanding=<value>:only-1-is-"
                               "composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "max_outstanding",
                        "value": 2}),
        _entry(family=family, side="target", protocol=protocol, feature="exclusive_access",
               status=REFUSED,
               condition="any exclusive/locked capability is declared true",
               declaration="capabilities.exclusive_access|exclusive|lock",
               error=exclusive_refusal(instance, endpoint, "target", protocol),
               error_template=("unsupported-target-exclusive-access:<instance>:<endpoint>:"
                               "<protocol>@<version>:exclusive-access-has-no-path-in-this-"
                               "composer"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "exclusive_access"}),
        _entry(family=family, side="target", protocol=protocol, feature="cache_attributes",
               status=REFUSED,
               condition="any cache/attribute capability is declared true",
               declaration="capabilities.cache_attributes|cache|attributes",
               error=cache_refusal(instance, endpoint, "target", protocol),
               error_template=("unsupported-target-cache-attributes:<instance>:<endpoint>:"
                               "<protocol>@<version>:cache-and-attribute-semantics-have-no-"
                               "path-in-this-composer"),
               code_path=DECLARED_PATH,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "declared_true", "capability": "cache_attributes"}),
        _entry(family=family, side="target", protocol=protocol, feature="error_response",
               status=SUPPORTED,
               condition="capabilities.has_error is true: the adapter carries the target's "
                         "own error pin (HAS_PSLVERR/HAS_ERR=1); when it is false or absent "
                         "the adapter records error_source none/fabric and still returns its "
                         "own rejection and timeout errors on the beat response",
               declaration="capabilities.has_error", adapter=adapter,
               audit="adapter_binding",
               test=None if missing else composition_test,
               composition_evidence=missing,
               trigger={"fixture": fixture, "fixture_request": "request.json",
                        "mutation": "capability", "capability": "has_error", "value": True}),
    ]
    if family == "apb3":
        entries.append(_entry(
            family=family, side="target", protocol=protocol, feature="byte_enable",
            status=SUPPORTED,
            condition="capabilities.partial_write is false: APB3 has no PSTRB, the adapter "
                      "renders HAS_PSTRB=0/SUPPORTS_PARTIAL_WRITE=0 and answers a partial "
                      "write with a beat error response and zero APB transfers instead of "
                      "silently writing whole words",
            declaration="capabilities.partial_write", adapter=adapter,
            audit="adapter_binding",
            test=f"{TEST_MODULE}.TargetCompositionTests."
                 f"test_apb3_target_without_byte_strobes_records_the_local_rejection",
            trigger={"fixture": fixture, "fixture_request": "request.json",
                     "mutation": "capability", "capability": "partial_write", "value": False}))
        entries.append(_entry(
            family=family, side="target", protocol=protocol, feature="byte_enable",
            status=REFUSED,
            condition="capabilities.partial_write is declared true while the target has no "
                      "byte strobe (APB3 has no PSTRB) or declares byte_enable false",
            declaration="capabilities.partial_write",
            error=(f"target-adapter:{instance}:unsupported-target-capability:partial-write:"
                   f"{component}:apb3:byte_enable=False"),
            error_template=("target-adapter:<instance>:unsupported-target-capability:"
                            "partial-write:<component>:apb3:byte_enable=<byte_enable>"),
            code_path=TARGET_ADAPTER_PATH + " -> TargetAdapterError",
            trigger={"fixture": "pulp-spi-partial-write", "fixture_request":
                     "request-ibex-pulp-spi.json", "mutation": "capability",
                     "capability": "partial_write", "value": True}))
    else:
        entries.append(_entry(
            family=family, side="target", protocol=protocol, feature="byte_enable",
            status=SUPPORTED,
            condition="capabilities.partial_write is true together with a declared byte "
                      "strobe the adapter consumes; SUPPORTS_PARTIAL_WRITE=1 is rendered",
            declaration="capabilities.partial_write", adapter=adapter,
            audit="adapter_binding",
            test=None if missing else
            f"{TEST_MODULE}.TargetCompositionTests."
            f"test_{family.replace('-', '_')}_target_records_partial_write_support",
            composition_evidence=missing,
            trigger={"fixture": fixture, "fixture_request": "request.json",
                     "mutation": "capability", "capability": "partial_write", "value": True}))
        entries.append(_entry(
            family=family, side="target", protocol=protocol, feature="byte_enable",
            status=REFUSED,
            condition="capabilities.partial_write is declared true while the target declares "
                      "byte_enable false (or, for wishbone, sel_implemented false)",
            declaration="capabilities.partial_write",
            error=(f"target-adapter:{instance}:unsupported-target-capability:partial-write:"
                   f"{component}"
                   + (":apb4:byte_enable=False" if family == "apb4" else
                      ":byte_enable=False:sel_implemented=False" if family == "wishbone"
                      else ":byte_enable=False")),
            error_template=("target-adapter:<instance>:unsupported-target-capability:"
                            "partial-write:<component>"
                            + (":apb4:byte_enable=<byte_enable>" if family == "apb4" else
                               ":byte_enable=<byte_enable>:sel_implemented=<sel_implemented>"
                               if family == "wishbone" else
                               ":byte_enable=<byte_enable>")),
            code_path=TARGET_ADAPTER_PATH + " -> TargetAdapterError",
            # No component_profile in this checkout declares a complete tl-ul target, so
            # the resolver-path refusal for that family cannot be replayed end to end.
            trigger=None if family == "tl-ul" else
            {"fixture": fixture, "fixture_request": "request.json",
             "mutation": "capability", "capability": "partial_write", "value": True,
             "byte_enable": False,
             **({"sel_implemented": False} if family == "wishbone" else {})},
            replay_evidence=(_TLUL_EVIDENCE if family == "tl-ul" else None)))
    return entries


def _structural_entries() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = [
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="clock_domain", status=SUPPORTED,
               condition="one declared clock domain: every clock binding of every instance "
                         "equals request.clock.domain, so every route, interrupt source and "
                         "adapter is same-domain and no synchroniser is needed",
               declaration="clock.domain",
               adapter={"resolver": "component_profile._validate_request_consistency"},
               audit="clock_distribution",
               test="tests.composition.test_component_profile.CompositionRequestTests."
                    "test_cross_domain_component_is_rejected",
               trigger={"fixture": "novagpio-cross-domain", "fixture_request":
                        "request.json", "mutation": "foreign_clock_domain"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="clock_domain_crossing", status=REFUSED,
               condition="a route whose source and destination are in different declared "
                         "clock domains",
               declaration="clock.domain",
               error=route_crossing_refusal("cpu0", "core", "gpio0", "fast"),
               error_template=("cross-domain-route:<source>:<source_domain>:<target>:"
                               "<target_domain>:no-synchroniser-is-composed"),
               code_path=BOUND_PATH,
               trigger={"mutation": "route_domain", "source_domain": "core",
                        "target_domain": "fast"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="clock_domain_crossing", status=REFUSED,
               condition="an interrupt source whose declared clock domain is not the one "
                         "the controller samples in",
               declaration="interrupts[].clock_domain",
               error="cross-domain-interrupt-source:gpio0:other",
               error_template="cross-domain-interrupt-source:<instance>:<domain>",
               code_path="soc_interrupt_plan.build_interrupt_plan",
               trigger={"mutation": "interrupt_domain", "instance": "gpio0",
                        "domain": "other"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="clock_domain_crossing", status=REFUSED,
               condition="a profile whose declared clock domain differs from the request's, "
                         "or a profile/request that declares a cdc capability",
               declaration="clock.domain, capabilities.cdc|clock_domain_crossing|async",
               error="cross-domain-unsupported:gpio0:fast",
               error_template="cross-domain-unsupported:<instance>:<domain>",
               code_path=PROFILE_PATH,
               trigger={"fixture": "novagpio-cross-domain", "fixture_request": "request.json",
                        "mutation": "foreign_clock_domain"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="reset_topology", status=SUPPORTED,
               condition="one declared reset domain, one polarity and one synchrony for every "
                         "instance (request.reset.domain/polarity/synchronous equal to every "
                         "profile's reset binding), released simultaneously: every component "
                         "reset port is driven by rst_ni or ~rst_ni according to its declared "
                         "polarity, the only other legal expression being the CPU hold of a "
                         "bfm drive profile",
               declaration="reset.domain|polarity|synchronous",
               adapter={"resolver": "soc_profile_renderer._reset_expression"},
               audit="reset_topology",
               test=f"{TEST_MODULE}.StructuralCaseTests."
                    f"test_the_single_simultaneous_reset_domain_is_rendered_and_audited",
               trigger={"fixture": "novagpio", "fixture_request": "request.json",
                        "mutation": "capability", "capability": "reset_domain",
                        "value": "sys_rst"}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="reset_sequence",
               status=REFUSED,
               condition="a profile reset binding declares a release dependency "
                         "(after/sequence/depends_on/release_order)",
               declaration="resets[].after|sequence|depends_on|release_order",
               error=reset_sequence_profile_refusal("novagpio", "rst_ni", "cpu0"),
               error_template=("reset-sequence-unsupported:<component>:<port>:<after>:"
                               "only-one-simultaneously-released-reset-domain-is-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": "novagpio-reset-after", "fixture_request": "request.json",
                        "mutation": "reset_sequence_key", "key": "after", "value": "cpu0"}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="reset_sequence",
               status=REFUSED,
               condition="the composition request declares an ordered reset sequence",
               declaration="reset.sequence",
               error=reset_sequence_request_refusal("novacore-novauart-novagpio",
                                                    ["cpu0", "gpio0"]),
               error_template=("reset-sequence-unsupported:<request_id>:<order>:"
                               "only-one-simultaneously-released-reset-domain-is-composed"),
               code_path=DECLARED_PATH,
               trigger={"fixture": "novagpio", "fixture_request": "request.json",
                        "mutation": "request_reset_sequence", "value": ["cpu0", "gpio0"]}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="inout_port",
               status=REFUSED,
               condition="an elaborated component port is declared inout, so no single "
                         "driver direction can be assigned to it",
               declaration=None,
               error=("dispositions:t0:inout-port-unsupported:PAD:no-single-unambiguous-"
                      "direction-is-declared"),
               error_template=("dispositions:<instance>:inout-port-unsupported:<port>:"
                               "no-single-unambiguous-direction-is-declared"),
               code_path=DISPOSITION_PATH,
               trigger={"mutation": "inout_port", "port": "PAD"}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="master_lane",
               status=SUPPORTED,
               condition="the fabric lanes are exactly the CPU's declared master endpoints "
                         "(all resolved through one adapter module) plus, for a bfm/arbitrated "
                         "drive profile, one generated synthetic master",
               declaration="cpu.master_endpoints",
               adapter={"rtl_module": "soc_arbiter",
                        "resolver": "soc_composition._cpu_adapter"},
               audit="fabric_source_lanes",
               test="tests.integration.test_soc_assurance_acceptance."
                    "GenerationAcceptanceTests."
                    "test_generation_entry_point_publishes_a_complete_artifact_set",
               trigger={"fixture": "novacore", "fixture_request": "request-ibex.json",
                        "mutation": "capability", "capability": "master_lane", "value": 1}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="peripheral_master_endpoint", status=REFUSED,
               condition="a non-CPU instance declares a master endpoint: the fabric has no "
                         "lane for it and the renderer cannot drive its request channel",
               declaration="endpoints[].function in memory_master|processor_memory_master|"
                           "instruction_memory_master|data_memory_master on a peripheral",
               error=("fabric-master-lane-unavailable:uart0:uart.dma:memory_master:"
                      "only-the-cpu-master-endpoints-and-the-generated-synthetic-master-own-"
                      "fabric-lanes"),
               error_template=("fabric-master-lane-unavailable:<instance>:<endpoint>:"
                               "<function>:only-the-cpu-master-endpoints-and-the-generated-"
                               "synthetic-master-own-fabric-lanes"),
               code_path=DECLARED_PATH,
               trigger={"fixture": "novauart-dma", "fixture_request": "request.json",
                        "mutation": "peripheral_master_endpoint"}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="debug_transport",
               status=REFUSED,
               condition="any instance declares a debug_slave endpoint: no debug transport, "
                         "DMI or debug MMIO target is built",
               declaration="endpoints[].function == debug_slave",
               error=("debug-transport-unsupported:cpu0:core.debug:this-composer-builds-no-"
                      "debug-transport"),
               error_template=("debug-transport-unsupported:<instance>:<endpoint>:"
                               "this-composer-builds-no-debug-transport"),
               code_path=DECLARED_PATH,
               trigger={"fixture": "novacore-debug", "fixture_request": "request.json",
                        "mutation": "debug_endpoint"}),
        _entry(family="any", side="any", protocol=("any", "any"), feature="cpu_input_trace",
               status=REFUSED,
               condition="a CPU port action declares a trace role (trace, trace_valid, "
                         "instr_trace, instruction_trace, rvfi, trace_port)",
               declaration="port_actions[].role",
               error=("trace-input-unsupported:cpu0:fetch_enable_i:trace:this-composer-"
                      "captures-no-trace"),
               error_template=("trace-input-unsupported:<instance>:<port>:<role>:"
                               "this-composer-captures-no-trace"),
               code_path=DECLARED_PATH,
               trigger={"fixture": "novacore-trace-role", "fixture_request": "request.json",
                        "mutation": "cpu_trace_role"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="cpu_input_undisposed", status=REFUSED,
               condition="a CPU input that no declared disposition drives",
               declaration="port_actions[]",
               error="dispositions:cpu0:undisposed-port-bits:cpu0:fetch_enable_i:0:0",
               error_template="dispositions:<instance>:undisposed-port-bits:<instance>:<port>:<bits>",
               code_path=DISPOSITION_PATH,
               trigger={"fixture": "novacore-no-fetch-action",
                        "fixture_request": "request.json",
                        "mutation": "drop_cpu_port_action", "port": "fetch_enable_i"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="cpu_input_unconnected", status=REFUSED,
               condition="a CPU input declared unconnected: an input needs a driver, so the "
                         "ledger refuses it even when the action names a contract",
               declaration="port_actions[]",
               error="dispositions:cpu0:input-without-driver:cpu0:fetch_enable_i",
               error_template=("dispositions:<instance>:input-without-driver:<instance>:"
                               "<port>"),
               code_path=("soc_composition.build_composition -> soc_port_dispositions."
                          "_validate_coverage -> PortDispositionError"),
               trigger={"fixture": "novacore-unconnected-fetch",
                        "fixture_request": "request.json",
                        "mutation": "unconnected_cpu_input", "port": "fetch_enable_i"}),
        _entry(family="any", side="any", protocol=("any", "any"),
               feature="undeclared_target_capability", status=REFUSED,
               condition="a target capability key the adapter does not consume appears in "
                         "capabilities; a misspelled feature is refused rather than ignored",
               declaration="capabilities.<unknown>",
               error=("target-adapter:gpio0:unsupported-target-capability:unknown:novagpio:"
                      "magic_mode"),
               error_template=("target-adapter:<instance>:unsupported-target-capability:"
                               "unknown:<component>:<key>"),
               code_path=TARGET_ADAPTER_PATH + " -> TargetAdapterError",
               trigger={"fixture": "novagpio-unknown-capability",
                        "fixture_request": "request.json", "mutation": "unknown_capability",
                        "key": "magic_mode"}),
    ]
    return entries


def composed_side(family: str, side: str) -> bool:
    """Whether the composer really builds a route for this family and side."""
    if side == "master":
        return family in MASTER_ADAPTERS and family not in REFUSED_MASTER_ADAPTERS
    return family in TARGET_ADAPTERS


def _refused_master_adapter_entries(family: str, protocol: Sequence[str]
                                    ) -> list[dict[str, object]]:
    """Every feature of a master family whose adapter cannot be built."""
    module = REFUSED_MASTER_ADAPTERS[family]
    instance, endpoint = MASTER_FIXTURE["instance"], MASTER_FIXTURE["endpoint"]
    condition = (f"the {family} master adapter block ({module}) does not pass the "
                 f"composer's fatal-warning frontend elaboration, so no composition with "
                 f"a {family} master can be built")
    entries = []
    for feature in FEATURES:
        if feature == "error_response":
            entries.append(_entry(
                family=family, side="master", protocol=protocol, feature=feature,
                status=REFUSED,
                condition="a ready-valid master that declares capabilities.error_response "
                          "true: that adapter has no error output at all, so the claim can "
                          "never be honoured (and the family is refused in any case)",
                declaration="capabilities.error_response",
                error=master_error_refusal(instance, endpoint, protocol),
                error_template=("unsupported-master-error-response:<instance>:<endpoint>:"
                                "ready-valid-memory@1:the-ready-valid-adapter-has-no-error-"
                                "channel"),
                code_path=DECLARED_PATH,
                trigger={"fixture": f"{family}-master",
                         "fixture_request": "request.json",
                         "mutation": "declared_true", "capability": "error_response"},
            ))
            continue
        entries.append(_entry(
            family=family, side="master", protocol=protocol, feature=feature,
            status=REFUSED, condition=condition,
            declaration="endpoints[].protocol",
            error=master_adapter_refusal(instance, endpoint, protocol, module),
            error_template=("unsupported-master-adapter:<instance>:<endpoint>:"
                            "<protocol>@<version>:adapter-<module>-does-not-pass-the-"
                            "fatal-warning-frontend-elaboration"),
            code_path=DECLARED_PATH,
            trigger={"fixture": f"{family}-master",
                     "fixture_request": "request.json",
                     "mutation": "capability", "capability": "data_width", "value": 32},
        ))
    return entries


def soc_adapter_scope() -> dict[str, object]:
    """Return the versioned scope of the composer as plain data."""
    entries: list[dict[str, object]] = []
    for family, side, protocol in FAMILIES:
        if not composed_side(family, side):
            if family in REFUSED_MASTER_ADAPTERS and side == "master":
                entries.extend(_refused_master_adapter_entries(family, protocol))
            else:
                entries.append(_unsupported_side_entry(family, side, protocol))
            continue
        if side == "master":
            entries.extend(_master_feature_entries(family, protocol))
        else:
            entries.extend(_target_feature_entries(family, protocol))
    entries.extend(_structural_entries())
    refusals = [item for item in entries if item["status"] == REFUSED]
    supported = [item for item in entries if item["status"] == SUPPORTED]
    return {
        "schema_version": SOC_SCOPE_SCHEMA,
        "composer": {
            "entry_point": "myfuzz.composition.soc_composition.build_composition",
            "validator": "myfuzz.composition.soc_scope.declared_scope_refusals",
            "bound_validator": "myfuzz.composition.soc_scope.bound_scope_refusals",
            "error_type": "myfuzz.composition.soc_composition.CompositionError",
            "profile_error_type": ("myfuzz.composition.component_profile."
                                   "ComponentProfileError"),
            "test_module": TEST_MODULE,
        },
        "features": list(FEATURES),
        "families": [
            {"family": family, "side": side, "protocol": list(protocol),
             "composed": composed_side(family, side),
             "refused_adapter": REFUSED_MASTER_ADAPTERS.get(family) if side == "master"
             else None,
             "adapter": dict((MASTER_ADAPTERS if side == "master" else TARGET_ADAPTERS)
                             .get(family, {}))}
            for family, side, protocol in FAMILIES
        ],
        "supported_topology": {
            "clock_domains": "exactly one, request.clock.domain, shared by every instance",
            "clock_crossing": "refused: no synchroniser, no async FIFO, no CDC bridge",
            "reset": "exactly one reset domain, one polarity and one synchrony "
                     "(request.reset.*), released simultaneously; ordered or dependent "
                     "release is refused",
            "ports": "unidirectional only; an elaborated inout port is refused",
            "fabric_sources": "the CPU's declared master endpoints (one adapter module) "
                              "plus at most one generated synthetic master",
            "debug": "no debug transport is built; a debug_slave endpoint is refused",
            "trace": "no trace capture; a trace-role CPU input is refused",
            "cpu_inputs": "every CPU input has exactly one declared disposition: constant, "
                          "fuzz (soc_special_input_driver with a declared strategy), "
                          "external pin, clock/reset distribution, or a "
                          "processor-adapter/fabric/interrupt net",
        },
        "entries": entries,
        "refusals": refusals,
        "supported": supported,
    }


def _unsupported_side_entry(family: str, side: str, protocol: Sequence[str]
                            ) -> dict[str, object]:
    instance = "gpio0"
    if protocol[0] in ("obi", "axi4", "ready-valid-memory"):
        error = f"target-adapter:{instance}:not-a-target-protocol:{protocol[0]}"
        template = "target-adapter:<instance>:not-a-target-protocol:<protocol>"
    else:
        error = f"target-adapter:{instance}:unsupported-target-protocol:{protocol[0]}"
        template = "target-adapter:<instance>:unsupported-target-protocol:<protocol>"
    return _entry(
        family=family, side=side, protocol=protocol, feature="adapter", status=REFUSED,
        condition=(f"an endpoint declares {_protocol(protocol)} as a {side}: the beat fabric "
                   f"drives peripheral targets and is driven by CPU masters, so this side has "
                   f"no adapter at all"),
        declaration="endpoints[].protocol",
        error=error,
        error_template=template,
        code_path=TARGET_ADAPTER_PATH + " -> TargetAdapterError",
        trigger={"fixture": "novagpio-unsupported-target-protocol",
                 "fixture_request": "request.json",
                 "mutation": "target_protocol", "protocol": list(protocol)},
    )


__all__ = [
    "BURST_KEYS",
    "CACHE_KEYS",
    "CDC_KEYS",
    "CPU_INPUT_CLASSES",
    "EXCLUSIVE_KEYS",
    "FAMILIES",
    "FEATURES",
    "MASTER_ADAPTERS",
    "MASTER_FUNCTIONS",
    "MASTER_STROBE_ROLES",
    "REFUSED",
    "REFUSED_CPU_INPUT_CLASSES",
    "REFUSED_MASTER_ADAPTERS",
    "RESET_SEQUENCE_KEYS",
    "SOC_SCOPE_SCHEMA",
    "SUPPORTED",
    "TARGET_ADAPTERS",
    "TARGET_FUNCTIONS",
    "TRANSACTION_ID_KEYS",
    "bound_scope_refusals",
    "composed_side",
    "cpu_input_class",
    "cpu_input_records",
    "declared_scope_refusals",
    "inout_port_refusal",
    "soc_adapter_scope",
]
