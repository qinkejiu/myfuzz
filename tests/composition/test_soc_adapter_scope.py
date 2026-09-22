"""Item 9 and 10: the composer's declared adapter scope, refusals and positives.

Two things are asserted here:

1. ``soc_scope.soc_adapter_scope()`` is internally consistent.  Every
   ``refused`` entry's published ``error`` string is the one the composer really
   raises for the documented fixture and is replayed from the record's own
   ``trigger``; every ``supported`` entry names a positive test in this module
   (or an adapter plus an audit check) or records explicitly why no end-to-end
   composition test exists in this checkout.
2. The refusals themselves, one test per requirement: exact protocol/feature
   combinations, CDC, reset order, bidirectional ports, CPU inputs and
   peripheral master lanes.

Every fixture is a pinned input under ``configs/``, ``examples/`` or
``third_party/``; profile documents are mutated in memory only, never on disk.
"""
from __future__ import annotations

import copy
import importlib
import json
import shutil
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition import soc_scope
from myfuzz.composition.component_profile import (
    ComponentProfileError,
    PhysicalFacts,
    ProfileBinding,
    ResolvedEndpoint,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import CompositionError, build_composition
from myfuzz.composition.soc_port_dispositions import PortDispositionError, build_port_dispositions
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import FAIL, audit_structure
from myfuzz.composition.source_crawler import ElaboratedPortFact

from .soc_generation_fixture import ROOT, example_profiles

EXAMPLE = "examples/soc_generation/profiles"
CPU_KEY = f"{EXAMPLE}/novacore.json"
GPIO_KEY = f"{EXAMPLE}/novagpio.json"
UART_KEY = f"{EXAMPLE}/novauart.json"
LINK_KEY = f"{EXAMPLE}/novauart_link.json"
IBEX = "configs/cpus/ibex/component_profile.json"
PULP_SPI = "configs/peripherals/pulp_spi/component_profile.json"
DEFAULT_REQUEST = "examples/soc_generation/request.json"
PULP_REQUEST = "examples/soc_generation/request-ibex-pulp-spi.json"
TRACE_MODULE = "tests.composition.test_soc_adapter_scope"

SCOPE = soc_scope.soc_adapter_scope()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _document(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _request_document(path: str = DEFAULT_REQUEST) -> dict:
    return _document(path)


def _free_facts(document: dict) -> list[ElaboratedPortFact]:
    from myfuzz.composition.component_profile import elaborate_profile

    return list(elaborate_profile(load_component_profile(document),
                                 base_dir=ROOT).ports)


def _dispose_free_ports(document: dict) -> dict:
    """Dispose of exactly the ports a protocol variant leaves unbound.

    A protocol variant of a pinned component leaves the ports of the original
    interface unbound, which the disposition ledger refuses (correctly).  This
    helper adds an explicit constant/observe action for those ports only, so the
    variant exercises the adapter path and nothing else.
    """
    bound: set[str] = set()
    for endpoint in document.get("endpoints", []):
        for field in endpoint.get("fields", []):
            physical = field.get("physical")
            if physical:
                bound.add(physical["port"])
            else:
                bound.update(field.get("aliases", []))
    for binding in document.get("clocks", []) + document.get("resets", []):
        bound.add(binding["port"])
    actions = document.setdefault("port_actions", [])
    existing = {entry["port"] for entry in actions}
    for fact in _free_facts(document):
        if fact.name in bound or fact.name in existing:
            continue
        if fact.direction == "input":
            actions.append({"port": fact.name, "action": "constant", "value": 0,
                            "reason": "scope fixture: port is outside this variant's "
                                      "declared interface"})
        elif fact.direction == "output":
            actions.append({"port": fact.name, "action": "observe",
                            "reason": "scope fixture: port is outside this variant's "
                                      "declared interface"})
        else:
            raise AssertionError(f"unexpected inout fixture port {fact.name}")
    return document


#: One bindable field set per master protocol, mapped onto novacore's OBI pins.
MASTER_FIELDS: dict[str, list[dict[str, str]]] = {
    "obi": [
        {"role": "req", "aliases": ["obi_req_o"]},
        {"role": "gnt", "aliases": ["obi_gnt_i"]},
        {"role": "addr", "aliases": ["obi_addr_o"]},
        {"role": "we", "aliases": ["obi_we_o"]},
        {"role": "wdata", "aliases": ["obi_wdata_o"]},
        {"role": "be", "aliases": ["obi_be_o"]},
        {"role": "rvalid", "aliases": ["obi_rvalid_i"]},
        {"role": "rdata", "aliases": ["obi_rdata_i"]},
        {"role": "error", "aliases": ["obi_err_i"]},
    ],
    "axi4": [
        {"role": "awvalid", "aliases": ["obi_req_o"]},
        {"role": "awready", "aliases": ["obi_gnt_i"]},
        {"role": "wdata", "aliases": ["obi_wdata_o"]},
        {"role": "wstrb", "aliases": ["obi_be_o"]},
        {"role": "wvalid", "aliases": ["obi_we_o"]},
    ],
    "axi4-lite": [
        {"role": "awaddr", "aliases": ["obi_addr_o"]},
        {"role": "awvalid", "aliases": ["obi_req_o"]},
        {"role": "awready", "aliases": ["obi_gnt_i"]},
        {"role": "wdata", "aliases": ["obi_wdata_o"]},
        {"role": "wstrb", "aliases": ["obi_be_o"]},
        {"role": "wvalid", "aliases": ["obi_we_o"]},
        {"role": "rdata", "aliases": ["obi_rdata_i"]},
        {"role": "rvalid", "aliases": ["obi_rvalid_i"]},
    ],
    "tl-ul": [
        {"role": "a_valid", "aliases": ["obi_req_o"]},
        {"role": "a_ready", "aliases": ["obi_gnt_i"]},
        {"role": "a_source", "aliases": ["obi_we_o"]},
        {"role": "a_address", "aliases": ["obi_addr_o"]},
        {"role": "a_mask", "aliases": ["obi_be_o"]},
        {"role": "a_data", "aliases": ["obi_wdata_o"]},
        {"role": "d_valid", "aliases": ["obi_rvalid_i"]},
        {"role": "d_data", "aliases": ["obi_rdata_i"]},
        {"role": "d_corrupt", "aliases": ["obi_err_i"]},
    ],
    "wishbone": [
        {"role": "cyc", "aliases": ["obi_req_o"]},
        {"role": "we", "aliases": ["obi_we_o"]},
        {"role": "adr", "aliases": ["obi_addr_o"]},
        {"role": "dat_w", "aliases": ["obi_wdata_o"]},
        {"role": "sel", "aliases": ["obi_be_o"]},
        {"role": "ack", "aliases": ["obi_rvalid_i"]},
        {"role": "err", "aliases": ["obi_err_i"]},
        {"role": "dat_r", "aliases": ["obi_rdata_i"]},
    ],
    "ready-valid": [
        {"role": "valid", "aliases": ["obi_req_o"]},
        {"role": "ready", "aliases": ["obi_gnt_i"]},
        {"role": "addr", "aliases": ["obi_addr_o"]},
        {"role": "wdata", "aliases": ["obi_wdata_o"]},
        {"role": "wstrb", "aliases": ["obi_be_o"]},
        {"role": "rdata", "aliases": ["obi_rdata_i"]},
    ],
}
MASTER_PROTOCOL_VERSION = {"wishbone": "classic"}
#: The (protocol, version) a family is really declared with.
MASTER_PROTOCOL_NAME = {"ready-valid": "ready-valid-memory"}


def master_document(family: str) -> dict:
    """novacore re-declared with one master protocol the scope record names.

    ``ready-valid`` additionally declares ``error_response: false``: that adapter
    has no error channel at all, so claiming one is refused (see the matching
    scope entry) and the positive fixture states the truth.
    """
    document = _document(CPU_KEY)
    document["endpoints"][0]["protocol"] = [
        MASTER_PROTOCOL_NAME.get(family, family), MASTER_PROTOCOL_VERSION.get(family, "1")]
    document["endpoints"][0]["fields"] = copy.deepcopy(MASTER_FIELDS[family])
    document["capabilities"]["max_outstanding"] = 1
    if family == "axi4":
        document["capabilities"]["bursts"] = False
    if family == "ready-valid":
        document["capabilities"]["error_response"] = False
    return _dispose_free_ports(document)


WISHBONE_TARGET_FIELDS = [
    {"role": "cyc", "aliases": ["psel_i"]},
    {"role": "stb", "aliases": ["penable_i"]},
    {"role": "we", "aliases": ["pwrite_i"]},
    {"role": "adr", "aliases": ["paddr_i"]},
    {"role": "dat_w", "aliases": ["pwdata_i"]},
    {"role": "sel", "aliases": ["pstrb_i"]},
    {"role": "ack", "aliases": ["pready_o"]},
    {"role": "err", "aliases": ["pslverr_o"]},
    {"role": "dat_r", "aliases": ["prdata_o"]},
    {"role": "stall", "aliases": ["uart_tx_o"]},
]


def link_wishbone_document(**capability_changes) -> dict:
    """A wishbone MMIO target over the pinned novauart_link RTL."""
    document = _document(LINK_KEY)
    document["endpoints"] = [entry for entry in document["endpoints"]
                             if entry["endpoint_id"] == "link.irq"]
    document["endpoints"].append({
        "endpoint_id": "uart.bus", "function": "mmio_slave",
        "protocol": ["wishbone", "classic"],
        "fields": copy.deepcopy(WISHBONE_TARGET_FIELDS),
    })
    document["capabilities"].update({"has_address_port": True, "address_units": "byte",
                                     "sel_implemented": True,
                                     "wishbone_flavour": "classic"})
    document["capabilities"].update(capability_changes)
    document["port_actions"] = [entry for entry in document["port_actions"]
                                if entry["port"] != "uart_tx_o"]
    return _dispose_free_ports(document)


def apb3_document(**capability_changes) -> dict:
    """An APB3 target with no write strobe, over the pinned novagpio RTL."""
    document = _document(GPIO_KEY)
    document["endpoints"][0]["protocol"] = ["apb", "3"]
    document["endpoints"][0]["fields"] = [
        entry for entry in document["endpoints"][0]["fields"]
        if entry["role"] != "pstrb"]
    document["capabilities"].update({"byte_enable": False, "partial_write": False})
    document["capabilities"].update(capability_changes)
    document["port_actions"].append({
        "port": "pstrb_i", "action": "constant", "value": 0,
        "reason": "scope fixture: APB3 has no PSTRB; the RTL port is held inactive"})
    return document


def _first_input_role(protocol: list[str]) -> str:
    """A one-bit input role of the refused target protocol.

    The fixture must still bind, because a target protocol with no adapter is
    refused by the resolver, which runs after binding.
    """
    from myfuzz.composition.component_profile import (
        _protocol_field_directions,
        _protocol_field_widths,
    )

    key = (protocol[0], protocol[1])
    directions = _protocol_field_directions(key)
    widths = _protocol_field_widths(key, {"data_width": 32, "address_width": 12})
    return next(role for role, direction in sorted(directions.items())
                if direction == "input" and widths.get(role) == 1)


def unsupported_target_protocol_document(protocol: list[str]) -> dict:
    document = _document(GPIO_KEY)
    document["endpoints"] = [entry for entry in document["endpoints"]
                             if entry["endpoint_id"] == "gpio.bus"]
    document["endpoints"][0]["protocol"] = list(protocol)
    document["endpoints"][0]["fields"] = [{"role": _first_input_role(protocol),
                                           "aliases": ["psel_i"]}]
    document["interrupts"] = []
    return _dispose_free_ports(document)


def uart_dma_document() -> dict:
    """A peripheral that declares a bus-master endpoint over its own pins."""
    document = _document(UART_KEY)
    document["endpoints"] = [entry for entry in document["endpoints"]
                             if entry["endpoint_id"] != "uart.pins"]
    document["endpoints"].append({
        "endpoint_id": "uart.dma", "function": "memory_master", "protocol": ["obi", "1"],
        "fields": [{"role": "req", "aliases": ["uart_tx_o"]},
                   {"role": "gnt", "aliases": ["uart_rx_i"]}],
    })
    return document


def debug_document() -> dict:
    """A CPU that declares a debug transport endpoint."""
    document = _document(CPU_KEY)
    document["port_actions"] = [entry for entry in document["port_actions"]
                                if entry["port"] != "fetch_enable_i"]
    document["endpoints"].append({
        "endpoint_id": "core.debug", "function": "debug_slave", "protocol": ["apb", "3"],
        "fields": [{"role": "psel", "aliases": ["fetch_enable_i"]}],
    })
    return document


def trace_role_document() -> dict:
    document = _document(CPU_KEY)
    for entry in document["port_actions"]:
        if entry["port"] == "fetch_enable_i":
            entry["role"] = "trace"
    return document


def drop_action_document(port: str) -> dict:
    document = _document(CPU_KEY)
    document["port_actions"] = [entry for entry in document["port_actions"]
                                if entry["port"] != port]
    return document


def unconnected_document(port: str) -> dict:
    document = _document(CPU_KEY)
    document["port_actions"] = [entry for entry in document["port_actions"]
                                if entry["port"] != port]
    document["port_actions"].append({"port": port, "action": "unconnected",
                                     "reason": "scope fixture",
                                     "protocol": ["obi", "1"]})
    return document


def cross_domain_document() -> dict:
    document = _document(GPIO_KEY)
    document["clocks"][0]["domain"] = "fast"
    for interrupt in document.get("interrupts", []):
        interrupt["clock_domain"] = "fast"
    return document


def reset_after_document(after: str = "cpu0") -> dict:
    document = _document(GPIO_KEY)
    document["resets"][0]["after"] = after
    return document


def unknown_capability_document(key: str = "magic_mode") -> dict:
    document = _document(GPIO_KEY)
    document["capabilities"][key] = True
    return document


def tlul_target_document(**capability_changes) -> dict:
    """An unbindable tl-ul target: enough to reach the declared-scope checks.

    No pinned component declares a complete tl-ul target, so this fixture only
    exercises the declared-refusal stage, which runs before any port is bound.
    """
    document = _document(GPIO_KEY)
    document["endpoints"] = [entry for entry in document["endpoints"]
                             if entry["endpoint_id"] == "gpio.bus"]
    document["endpoints"][0]["endpoint_id"] = "uart.bus"
    document["endpoints"][0]["protocol"] = ["tl-ul", "1"]
    document["endpoints"][0]["fields"] = [{"role": "a_valid", "aliases": ["psel_i"]}]
    document["interrupts"] = []
    document["capabilities"].update(capability_changes)
    return document


def fetch_enable_fuzz_document() -> dict:
    """The real ibex profile with fetch_enable declared as a driven special input."""
    document = _document(IBEX)
    for entry in document["port_actions"]:
        if entry["port"] == "fetch_enable_i":
            entry.clear()
            entry.update({"port": "fetch_enable_i", "action": "fuzz",
                          "strategy": "reset_sampled",
                          "reason": "scope fixture: fetch_enable is offered to the "
                                    "environment as a declared special input"})
    return document


#: fixture name -> (profile documents keyed by the path the request references,
#:                  request document path)
FIXTURES: dict[str, tuple[dict[str, dict], str]] = {
    "novacore": ({CPU_KEY: _document(CPU_KEY)}, DEFAULT_REQUEST),
    "novagpio": ({GPIO_KEY: _document(GPIO_KEY)}, DEFAULT_REQUEST),
    "obi-master": ({CPU_KEY: master_document("obi")}, DEFAULT_REQUEST),
    "axi4-master": ({CPU_KEY: master_document("axi4")}, DEFAULT_REQUEST),
    "axi4-lite-master": ({CPU_KEY: master_document("axi4-lite")}, DEFAULT_REQUEST),
    "tl-ul-master": ({CPU_KEY: master_document("tl-ul")}, DEFAULT_REQUEST),
    "wishbone-master": ({CPU_KEY: master_document("wishbone")}, DEFAULT_REQUEST),
    "ready-valid-master": ({CPU_KEY: master_document("ready-valid")}, DEFAULT_REQUEST),
    "apb3-target": ({PULP_SPI: _document(PULP_SPI)}, PULP_REQUEST),
    "apb4-target": ({GPIO_KEY: _document(GPIO_KEY)}, DEFAULT_REQUEST),
    "tl-ul-target": ({UART_KEY: tlul_target_document()}, DEFAULT_REQUEST),
    "wishbone-target": ({UART_KEY: link_wishbone_document()}, DEFAULT_REQUEST),
    "novagpio-apb3": ({GPIO_KEY: apb3_document()}, DEFAULT_REQUEST),
    "novauart-dma": ({UART_KEY: uart_dma_document()}, DEFAULT_REQUEST),
    "novacore-debug": ({CPU_KEY: debug_document()}, DEFAULT_REQUEST),
    "novacore-trace-role": ({CPU_KEY: trace_role_document()}, DEFAULT_REQUEST),
    "novacore-no-fetch-action": ({CPU_KEY: drop_action_document("fetch_enable_i")},
                                 DEFAULT_REQUEST),
    "novacore-unconnected-fetch": ({CPU_KEY: unconnected_document("fetch_enable_i")},
                                   DEFAULT_REQUEST),
    "novagpio-unknown-capability": ({GPIO_KEY: unknown_capability_document()},
                                    DEFAULT_REQUEST),
    "novagpio-unsupported-target-protocol": ({GPIO_KEY: _document(GPIO_KEY)},
                                             DEFAULT_REQUEST),
    "novagpio-cross-domain": ({GPIO_KEY: cross_domain_document()}, DEFAULT_REQUEST),
    "novagpio-reset-after": ({GPIO_KEY: reset_after_document()}, DEFAULT_REQUEST),
    "pulp-spi-partial-write": ({PULP_SPI: _document(PULP_SPI)}, PULP_REQUEST),
}


def _primary(documents: dict[str, dict]) -> dict:
    return documents[next(iter(documents))]


def compose(documents: dict[str, dict], request_path: str = DEFAULT_REQUEST,
            request_document: dict | None = None):
    """Load one request against a mutated profile set and build the plan."""
    profiles = dict(example_profiles())
    request = request_document if request_document is not None \
        else _request_document(request_path)
    referenced = {request["cpu"]["profile"]} | {
        entry["profile"] for entry in request.get("peripherals", [])}
    for path in sorted(referenced | set(documents)):
        profiles[path] = load_component_profile(documents.get(path) or _document(path))
    loaded = load_composition_request(request, profiles=profiles)
    return build_composition(loaded, base_dir=ROOT)


def render_and_audit(plan) -> dict:
    """Render, then re-elaborate the published source list and audit it.

    Include roots are directories, so they are passed as ``include_roots``
    exactly as ``scripts/generate_soc.py`` does, never as source files.
    """
    text = render_composition(plan)["myfuzz_soc_top.sv"]
    records = source_list(plan)
    sources = [item["path"] for item in records if item["role"] != "include_root"]
    include_roots = [item["path"] for item in records if item["role"] == "include_root"]
    return audit_structure(plan, top_text=text, source_files=sources, base_dir=ROOT,
                           include_roots=include_roots)


# ---------------------------------------------------------------------------
# trigger replay
# ---------------------------------------------------------------------------


def _fixture_with_trigger(trigger: dict) -> tuple[dict[str, dict], str, dict]:
    """Build the documented fixture and apply the entry's trigger to it."""
    name = str(trigger["fixture"])
    documents, request_path = FIXTURES[name]
    documents = copy.deepcopy(documents)
    request_document = _request_document(request_path)
    mutation = str(trigger["mutation"])
    primary = _primary(documents)
    if name == "pulp-spi-partial-write":
        primary["capabilities"]["partial_write"] = True
    elif mutation == "capability":
        primary["capabilities"][str(trigger["capability"])] = trigger["value"]
        if "byte_enable" in trigger:
            primary["capabilities"]["byte_enable"] = trigger["byte_enable"]
        if "sel_implemented" in trigger:
            primary["capabilities"]["sel_implemented"] = trigger["sel_implemented"]
    elif mutation == "declared_true":
        primary["capabilities"][str(trigger["capability"])] = True
    elif mutation == "remove_capability":
        primary["capabilities"].pop(str(trigger["capability"]), None)
    elif mutation == "drop_endpoint_role":
        primary["endpoints"][0]["fields"] = [
            entry for entry in primary["endpoints"][0]["fields"]
            if entry["role"] != trigger["role"]]
        documents = {key: _dispose_free_ports(value) for key, value in documents.items()}
    elif mutation == "target_protocol":
        documents[GPIO_KEY] = unsupported_target_protocol_document(trigger["protocol"])
    elif mutation == "request_reset_sequence":
        request_document.setdefault("reset", {})["sequence"] = list(trigger["value"])
    return documents, request_path, request_document


def run_trigger(entry: dict) -> str:
    """Replay one scope entry's trigger and return the refusal string it produces."""
    trigger = entry["trigger"]
    if trigger["mutation"] in ("route_domain", "inout_port", "interrupt_domain"):
        return _SPECIAL_TRIGGERS[str(trigger["mutation"])](trigger)
    documents, request_path, request_document = _fixture_with_trigger(trigger)
    try:
        compose(documents, request_path, request_document)
    except (CompositionError, ComponentProfileError) as error:
        return str(error)
    raise AssertionError(f"the trigger for {entry['family']}/{entry['feature']} "
                         f"({entry['condition']}) was accepted instead of refused")


def _route_domain_trigger(trigger: dict) -> str:
    """The route-level CDC refusal over a bound instance with a foreign domain."""
    documents, request_path = FIXTURES["novacore"]
    plan = compose(copy.deepcopy(documents), request_path)
    instances = []
    for item in plan.instances:
        if item.kind == "cpu":
            instances.append(item)
            continue
        binding_record, field = item.binding.clocks[0]
        instances.append(replace(item, binding=replace(
            item.binding,
            clocks=((replace(binding_record, domain=str(trigger["target_domain"])), field),))))
    refusals = soc_scope.bound_scope_refusals(plan.request, instances)
    if not refusals:
        raise AssertionError("the route-level clock-domain check accepted a foreign domain")
    return refusals[0]


def _inout_trigger(trigger: dict) -> str:
    """The disposition-layer refusal of a port with no unambiguous direction.

    No pinned component in this checkout has an ``inout`` port (the profiles
    elaborate no bidirectional pin, and the one vendored pad cell does not pass
    the SystemVerilog frontend), so the refusal is exercised at the disposition
    layer whose contract is exactly "given these elaborated facts".  The legal
    unidirectional case is every other test in this module.
    """
    port = str(trigger["port"])
    fact = ElaboratedPortFact(name=port, direction="inout", width=1, signed=False,
                              source_file="fixture.sv", line=1, column=1, members=())
    facts = PhysicalFacts(top_module="fixture", ports=(fact,),
                          content_hash="sha256:" + "0" * 64, revision="sha256:" + "0" * 64)
    binding = ProfileBinding(
        component_id="fixture", kind="peripheral", facts=facts, endpoints=(),
        clocks=(), resets=(), binding_hash="sha256:" + "0" * 64)
    try:
        build_port_dispositions("t0", binding, clock_domain="core", reset_domain="sys_rst")
    except PortDispositionError as error:
        return f"dispositions:t0:{error}"
    raise AssertionError("an inout port was disposed instead of refused")


def _interrupt_domain_trigger(trigger: dict) -> str:
    """The interrupt-source CDC refusal, exercised on a real plan's bindings."""
    from myfuzz.composition.soc_interrupt_plan import (
        InterruptPlanError,
        InterruptSourceRequest,
        build_interrupt_plan,
    )

    plan = compose({}, DEFAULT_REQUEST)
    cpu = next(item for item in plan.instances if item.kind == "cpu")
    sources = []
    for instance in plan.instances:
        for source in instance.profile.interrupts:
            profile_source = replace(source, clock_domain=str(trigger["domain"])) \
                if instance.instance_id == trigger["instance"] else source
            sources.append((InterruptSourceRequest(
                instance_id=instance.instance_id,
                component_id=instance.component_id,
                endpoint_id=source.endpoint_id,
                role=source.role,
                declared_source_id=source.source_id,
                bit=source.bit,
            ), profile_source))
    try:
        build_interrupt_plan(
            sources=sources,
            bindings={item.instance_id: item.binding for item in plan.instances},
            cpu_instance_id=cpu.instance_id, cpu_binding=cpu.binding,
            cpu_profile=cpu.profile,
            address_width=int(cpu.profile.capabilities["address_width"]))
    except InterruptPlanError as error:
        return str(error)
    raise AssertionError("a cross-domain interrupt source was accepted")


_SPECIAL_TRIGGERS = {
    "route_domain": _route_domain_trigger,
    "inout_port": _inout_trigger,
    "interrupt_domain": _interrupt_domain_trigger,
}


# ---------------------------------------------------------------------------
# the record's own consistency
# ---------------------------------------------------------------------------


class ScopeRecordTests(unittest.TestCase):
    def test_the_record_is_versioned_and_covers_every_named_family(self) -> None:
        self.assertEqual(soc_scope.SOC_SCOPE_SCHEMA, SCOPE["schema_version"])
        families = {(item["family"], item["side"]) for item in SCOPE["families"]}
        for required in (("obi", "master"), ("obi", "target"), ("apb3", "target"),
                         ("apb4", "target"), ("axi4-lite", "master"),
                         ("axi4-lite", "target"), ("axi4", "master"), ("axi4", "target"),
                         ("tl-ul", "master"), ("tl-ul", "target"),
                         ("wishbone", "master"), ("wishbone", "target"),
                         ("ready-valid", "master"), ("ready-valid", "target")):
            self.assertIn(required, families)

    def test_every_feature_axis_is_recorded_for_every_composed_family(self) -> None:
        for family, side, _protocol in soc_scope.FAMILIES:
            if not soc_scope.composed_side(family, side):
                continue
            recorded = {entry["feature"] for entry in SCOPE["entries"]
                        if entry["family"] == family and entry["side"] == side}
            self.assertEqual(set(soc_scope.FEATURES), recorded,
                             f"{family}/{side}: {sorted(recorded)}")

    def test_every_refusal_publishes_an_exact_error_and_its_code_path(self) -> None:
        self.assertTrue(SCOPE["refusals"])
        for entry in SCOPE["refusals"]:
            with self.subTest(entry=f"{entry['family']}/{entry['side']}/{entry['feature']}"):
                self.assertTrue(entry.get("error"), entry)
                self.assertIn("<", str(entry.get("error_template")), entry)
                self.assertTrue(entry.get("code_path"), entry)
                self.assertEqual(soc_scope.REFUSED, entry["status"])

    def test_every_supported_entry_names_its_test_or_its_missing_evidence(self) -> None:
        module = importlib.import_module(TRACE_MODULE)
        for entry in SCOPE["supported"]:
            label = f"{entry['family']}/{entry['side']}/{entry['feature']}"
            with self.subTest(entry=label):
                self.assertTrue(entry.get("test") or entry.get("composition_evidence"),
                                entry)
                test = entry.get("test")
                if test and str(test).startswith(TRACE_MODULE):
                    parts = str(test).split(".")
                    self.assertEqual(5, len(parts), test)
                    owner = getattr(module, parts[3], None)
                    self.assertIsNotNone(owner, test)
                    self.assertTrue(callable(getattr(owner, parts[4], None)), test)
                if not entry.get("adapter"):
                    self.assertTrue(entry.get("composition_evidence"), entry)

    def test_every_refusal_is_replayable_from_its_own_trigger(self) -> None:
        """The record's reason string is the one the composer really raises."""
        self.assertTrue(SCOPE["refusals"])
        replayed = 0
        for entry in SCOPE["refusals"]:
            label = f"{entry['family']}/{entry['side']}/{entry['feature']}"
            with self.subTest(entry=label, error=entry["error"]):
                if not entry.get("trigger"):
                    # A refusal without a trigger must say why it cannot be
                    # replayed end to end; it is never silently unverified.
                    self.assertTrue(entry.get("replay_evidence"), entry)
                    continue
                self.assertEqual(entry["error"], run_trigger(entry))
                replayed += 1
        unreplayable = [entry for entry in SCOPE["refusals"] if not entry.get("trigger")]
        self.assertEqual(len(SCOPE["refusals"]) - len(unreplayable), replayed)
        self.assertTrue(unreplayable, "the tl-ul resolver refusal has no fixture")

    def test_the_supported_topology_is_stated_explicitly(self) -> None:
        topology = SCOPE["supported_topology"]
        for key in ("clock_domains", "clock_crossing", "reset", "ports",
                    "fabric_sources", "debug", "trace", "cpu_inputs"):
            self.assertIn(key, topology)
        self.assertIn("refused", topology["clock_crossing"])
        self.assertIn("simultaneously", topology["reset"])


# ---------------------------------------------------------------------------
# positive composition cases: every master family
# ---------------------------------------------------------------------------


class MasterCompositionTests(unittest.TestCase):
    """Every master protocol the scope record calls supported really composes."""

    def _compose_family(self, family: str):
        plan = compose({CPU_KEY: master_document(family)})
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("u_cpu0_adapter_0", text)
        return plan

    def test_obi_master_composes(self) -> None:
        plan = self._compose_family("obi")
        self.assertEqual("obi_processor_memory_adapter", plan.cpu_adapter["module"])

    def test_axi4_master_composes(self) -> None:
        plan = self._compose_family("axi4")
        self.assertEqual("axi4_processor_memory_adapter", plan.cpu_adapter["module"])
        route = plan.plan["processor_execution"]["routes"][0]
        self.assertEqual({"ADDRESS_WIDTH": 32, "DATA_WIDTH": 32}, route["parameters"])

    def test_axi4_lite_master_composes(self) -> None:
        plan = self._compose_family("axi4-lite")
        self.assertEqual("axi4_lite_processor_memory_adapter", plan.cpu_adapter["module"])

    def test_tl_ul_master_composes(self) -> None:
        plan = self._compose_family("tl-ul")
        self.assertEqual("tl_ul_processor_memory_adapter", plan.cpu_adapter["module"])

    def test_wishbone_master_composes(self) -> None:
        plan = self._compose_family("wishbone")
        self.assertEqual("wishbone_processor_memory_adapter", plan.cpu_adapter["module"])
        route = plan.plan["processor_execution"]["routes"][0]
        self.assertEqual(1, route["parameters"]["HAS_SEL"])

    def test_ready_valid_master_is_refused_because_its_adapter_fails_the_frontend(self) -> None:
        """The adapter block exists but does not pass the width cross-check.

        ``build_composition`` elaborates every CPU adapter with a fatal warning
        policy to width-check the declared roles; the ready-valid adapter raises
        ``WIDTHEXPAND`` at ``ready_valid_processor_memory_adapter.sv:81``
        (``wait_q + 1``), so no composition with it can be built.  The scope
        record refuses the family by name instead of letting the raw frontend
        error escape, and this test proves the underlying failure is real.
        """
        from myfuzz.composition.component_profile import (
            ComponentProfileError,
            elaborate_rtl_module,
        )

        with self.assertRaises(ComponentProfileError) as error:
            elaborate_rtl_module(
                base_dir=ROOT, source_root=".",
                top_module="ready_valid_processor_memory_adapter",
                files=["src/myfuzz/protocols/rtl/"
                       "ready_valid_processor_memory_adapter.sv"],
                parameters=(("ADDRESS_WIDTH", "32"), ("DATA_WIDTH", "32")))
        self.assertIn("elaboration-frontend-error", str(error.exception))
        self.assertIn("WIDTHEXPAND", str(error.exception))
        with self.assertRaises(CompositionError) as refused:
            self._compose_family("ready-valid")
        self.assertEqual(
            "unsupported-master-adapter:cpu0:core.bus:ready-valid-memory@1:"
            "adapter-ready_valid_processor_memory_adapter-does-not-pass-the-fatal-"
            "warning-frontend-elaboration", str(refused.exception))

    def test_the_rendered_adapter_is_the_one_the_plan_claims(self) -> None:
        """The audit re-reads the elaboration for every master family."""
        for family in ("obi", "axi4", "axi4-lite", "tl-ul", "wishbone"):
            with self.subTest(family=family):
                plan = compose({CPU_KEY: master_document(family)})
                result = render_and_audit(plan)
                findings = {item["check_id"]: item for item in result["findings"]}
                self.assertIn("adapter_binding", findings)
                self.assertEqual("pass", findings["adapter_binding"]["status"],
                                 findings["adapter_binding"])
                self.assertEqual("pass", result["summary"]["status"], result["findings"])
                cells = {str(cell["instance"]): str(cell["module"])
                         for cell in result["netlist"]["cells"]}
                self.assertTrue(cells["u_cpu0_adapter_0"].startswith(
                    plan.cpu_adapter["module"]), cells)


# ---------------------------------------------------------------------------
# positive composition cases: every target family
# ---------------------------------------------------------------------------


class TargetCompositionTests(unittest.TestCase):
    def test_apb4_target_records_partial_write_support(self) -> None:
        plan = compose({GPIO_KEY: _document(GPIO_KEY)})
        render_composition(plan)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "gpio0")
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual(1, parameters["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual([], list(adapter["unsupported"]))

    def test_apb4_target_composes(self) -> None:
        plan = compose({GPIO_KEY: _document(GPIO_KEY)})
        render_composition(plan)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "gpio0")
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual({"HAS_PSTRB": 1, "SUPPORTS_PARTIAL_WRITE": 1}, {
            key: parameters[key] for key in ("HAS_PSTRB", "SUPPORTS_PARTIAL_WRITE")})
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["adapter_binding"]["status"])

    def test_apb3_target_composes(self) -> None:
        plan = compose({GPIO_KEY: apb3_document()})
        render_composition(plan)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "gpio0")
        self.assertEqual({"protocol": "apb", "version": "3"},
                         dict(adapter["target_protocol"]))
        self.assertEqual("beat_to_apb", adapter["rtl_module"])
        self.assertEqual("pass", render_and_audit(plan)["summary"]["status"])

    def test_apb3_target_without_byte_strobes_records_the_local_rejection(self) -> None:
        """APB3 has no PSTRB: the adapter rejects a partial write, never widens it."""
        plan = compose({GPIO_KEY: apb3_document()})
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "gpio0")
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual(0, parameters["HAS_PSTRB"])
        self.assertEqual(0, parameters["SUPPORTS_PARTIAL_WRITE"])
        unsupported = {item["capability"]: item["reason"] for item in adapter["unsupported"]}
        self.assertIn("partial_write", unsupported)
        self.assertIn("rejected with an error response", unsupported["partial_write"])
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["adapter_binding"]["status"])
        self.assertEqual("pass", result["summary"]["status"])

    def test_wishbone_target_composes(self) -> None:
        plan = compose({UART_KEY: link_wishbone_document()})
        render_composition(plan)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "uart0")
        self.assertEqual("beat_to_wishbone", adapter["rtl_module"])
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual(1, parameters["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual("pass", render_and_audit(plan)["summary"]["status"])

    def test_wishbone_target_records_partial_write_support(self) -> None:
        plan = compose({UART_KEY: link_wishbone_document()})
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "uart0")
        self.assertEqual([], list(adapter["unsupported"]))
        self.assertEqual("target_pin", adapter["error_source"])

    def test_tl_ul_target_has_adapter_evidence_but_no_composition_fixture(self) -> None:
        """tl-ul target is recorded as supported with its missing evidence named."""
        entries = [item for item in SCOPE["supported"]
                   if item["family"] == "tl-ul" and item["side"] == "target"]
        self.assertTrue(entries)
        for entry in entries:
            self.assertIsNone(entry.get("composition_test"), entry)
            self.assertIn("no component_profile in this checkout",
                          str(entry.get("composition_evidence")))

    def test_the_real_pinned_apb3_peripheral_composes_with_the_real_cpu(self) -> None:
        """configs/cpus/ibex + configs/peripherals/pulp_spi, unmodified."""
        plan = compose({}, PULP_REQUEST)
        render_composition(plan)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "spi0")
        self.assertEqual("beat_to_apb", adapter["rtl_module"])
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual(0, parameters["HAS_PSTRB"])
        self.assertEqual(0, parameters["SUPPORTS_PARTIAL_WRITE"])

    def test_a_target_without_an_error_channel_keeps_its_adapter_error_path(self) -> None:
        """has_error=false is accepted; the adapter still returns its own errors.

        This is the behaviour the acceptance suite already pins
        (``test_a_missing_capability_is_refused_instead_of_guessed``): the
        capability is not guessed, the plan records ``error_source: none`` and
        the adapter's local rejection and timeout paths still set the beat error.
        """
        document = _document(UART_KEY)
        document["capabilities"].pop("has_error")
        plan = compose({UART_KEY: document})
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "uart0")
        self.assertEqual("none", adapter["error_source"])
        parameters = {item["name"]: item["value"] for item in adapter["parameters"]}
        self.assertEqual(0, parameters["HAS_PSLVERR"])
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["adapter_binding"]["status"])


# ---------------------------------------------------------------------------
# refusals, one test per requirement
# ---------------------------------------------------------------------------


class MasterScopeRefusalTests(unittest.TestCase):
    def _refused(self, document: dict, request_path: str = DEFAULT_REQUEST) -> str:
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: document}, request_path)
        return str(error.exception)

    def test_a_bursting_axi4_master_is_refused_by_name(self) -> None:
        document = master_document("axi4")
        document["capabilities"]["bursts"] = True
        self.assertEqual("unsupported-master-burst:cpu0:core.bus:axi4@1:bursts-are-not-composed",
                         self._refused(document))

    def test_an_axi4_master_with_transaction_ids_is_refused_by_name(self) -> None:
        document = master_document("axi4")
        document["capabilities"]["transaction_ids"] = True
        self.assertEqual(
            "unsupported-master-transaction-id:cpu0:core.bus:axi4@1:"
            "multiple-or-out-of-order-ids-are-not-composed", self._refused(document))

    def test_an_axi4_master_with_two_outstanding_is_refused_by_name(self) -> None:
        document = master_document("axi4")
        document["capabilities"]["max_outstanding"] = 2
        self.assertEqual(
            "unsupported-master-outstanding:cpu0:core.bus:axi4@1:max_outstanding=2:"
            "only-1-is-composed", self._refused(document))

    def test_an_axi4_master_without_the_declared_contract_is_refused(self) -> None:
        document = master_document("axi4")
        document["capabilities"].pop("max_outstanding")
        self.assertEqual(
            "undeclared-master-contract:cpu0:core.bus:axi4@1:max_outstanding:"
            "axi4-full-requires-the-declared-single-beat-single-outstanding-contract",
            self._refused(document))

    def test_a_64_bit_master_is_refused_by_name(self) -> None:
        document = _document(CPU_KEY)
        document["capabilities"]["data_width"] = 64
        self.assertEqual(
            "unsupported-master-data-width:cpu0:core.bus:obi@1:64:only-32-bit-is-composed",
            self._refused(document))

    def test_a_master_without_a_byte_strobe_is_refused_by_name(self) -> None:
        """byte_enable with no strobe role would render an all-ones enable."""
        document = _document(CPU_KEY)
        document["endpoints"][0]["fields"] = [
            entry for entry in document["endpoints"][0]["fields"] if entry["role"] != "be"]
        document = _dispose_free_ports(document)
        self.assertEqual(
            "unsupported-master-byte-enable:cpu0:core.bus:obi@1:the-profile-declares-"
            "byte-enable-but-the-endpoint-declares-no-be-role", self._refused(document))

    def test_a_read_only_master_without_a_strobe_is_accepted(self) -> None:
        """A read-only endpoint cannot write, so byte_enable is not a hole."""
        document = _document(CPU_KEY)
        document["endpoints"][0]["fields"] = [
            entry for entry in document["endpoints"][0]["fields"]
            if entry["role"] not in ("be", "we", "wdata")]
        document = _dispose_free_ports(document)
        plan = compose({CPU_KEY: document})
        route = plan.plan["processor_execution"]["routes"][0]
        self.assertEqual(1, route["parameters"]["READ_ONLY"])
        self.assertEqual(0, route["parameters"]["HAS_BE"])

    def test_exclusive_access_on_a_master_is_refused_by_name(self) -> None:
        document = _document(CPU_KEY)
        document["capabilities"]["exclusive_access"] = True
        self.assertEqual(
            "unsupported-master-exclusive-access:cpu0:core.bus:obi@1:"
            "exclusive-access-has-no-path-in-this-composer", self._refused(document))

    def test_cache_attributes_on_a_master_are_refused_by_name(self) -> None:
        document = _document(CPU_KEY)
        document["capabilities"]["cache_attributes"] = True
        self.assertEqual(
            "unsupported-master-cache-attributes:cpu0:core.bus:obi@1:"
            "cache-and-attribute-semantics-have-no-path-in-this-composer",
            self._refused(document))

    def test_an_error_channel_declared_on_a_ready_valid_master_is_refused(self) -> None:
        """The ready-valid adapter has no error output, so claiming one is refused.

        The family is refused for its adapter regardless; this claim gets the
        more specific reason because the adapter can never carry the error.
        """
        document = master_document("ready-valid")
        document["capabilities"]["error_response"] = True
        self.assertEqual(
            "unsupported-master-error-response:cpu0:core.bus:ready-valid-memory@1:"
            "the-ready-valid-adapter-has-no-error-channel", self._refused(document))


class TargetScopeRefusalTests(unittest.TestCase):
    def test_an_obi_target_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: unsupported_target_protocol_document(["obi", "1"])})
        self.assertEqual("target-adapter:gpio0:not-a-target-protocol:obi",
                         str(error.exception))

    def test_an_axi4_target_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: unsupported_target_protocol_document(["axi4", "1"])})
        self.assertEqual("target-adapter:gpio0:not-a-target-protocol:axi4",
                         str(error.exception))

    def test_an_axi4_lite_target_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: unsupported_target_protocol_document(["axi4-lite", "1"])})
        self.assertEqual("target-adapter:gpio0:unsupported-target-protocol:axi4-lite",
                         str(error.exception))

    def test_a_ready_valid_target_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: unsupported_target_protocol_document(
                ["ready-valid-memory", "1"])})
        self.assertEqual(
            "target-adapter:gpio0:not-a-target-protocol:ready-valid-memory",
            str(error.exception))

    def test_a_64_bit_target_is_refused_by_name(self) -> None:
        document = _document(GPIO_KEY)
        document["capabilities"]["data_width"] = 64
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: document})
        self.assertEqual(
            "unsupported-target-data-width:gpio0:gpio.bus:apb@4:64:only-32-bit-is-composed",
            str(error.exception))

    def test_an_apb3_partial_write_is_refused_with_the_resolver_reason(self) -> None:
        """The refusal comes from the target adapter, not from a new check."""
        document = _document(PULP_SPI)
        document["capabilities"]["partial_write"] = True
        with self.assertRaises(CompositionError) as error:
            compose({PULP_SPI: document}, PULP_REQUEST)
        self.assertEqual(
            "target-adapter:spi0:unsupported-target-capability:partial-write:pulp_spi:"
            "apb3:byte_enable=False", str(error.exception))

    def test_a_wishbone_partial_write_without_select_is_refused(self) -> None:
        document = link_wishbone_document(partial_write=True, byte_enable=False,
                                          sel_implemented=False)
        with self.assertRaises(CompositionError) as error:
            compose({UART_KEY: document})
        self.assertEqual(
            "target-adapter:uart0:unsupported-target-capability:partial-write:"
            "novauart_link:byte_enable=False:sel_implemented=False",
            str(error.exception))

    def test_exclusive_access_on_a_target_is_refused_by_name(self) -> None:
        document = _document(GPIO_KEY)
        document["capabilities"]["exclusive_access"] = True
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: document})
        self.assertEqual(
            "unsupported-target-exclusive-access:gpio0:gpio.bus:apb@4:"
            "exclusive-access-has-no-path-in-this-composer", str(error.exception))

    def test_cache_attributes_on_a_target_are_refused_by_name(self) -> None:
        document = _document(GPIO_KEY)
        document["capabilities"]["cache_attributes"] = True
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: document})
        self.assertEqual(
            "unsupported-target-cache-attributes:gpio0:gpio.bus:apb@4:"
            "cache-and-attribute-semantics-have-no-path-in-this-composer",
            str(error.exception))

    def test_an_undeclared_target_capability_is_refused_by_the_resolver(self) -> None:
        document = _document(GPIO_KEY)
        document["capabilities"]["magic_mode"] = True
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: document})
        self.assertEqual(
            "target-adapter:gpio0:unsupported-target-capability:unknown:novagpio:magic_mode",
            str(error.exception))


class StructuralRefusalTests(unittest.TestCase):
    def test_a_foreign_clock_domain_is_refused_at_the_request(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            compose({GPIO_KEY: cross_domain_document()})
        self.assertEqual("cross-domain-unsupported:gpio0:fast", str(error.exception))

    def test_a_route_across_clock_domains_is_refused_by_name(self) -> None:
        """The route-level half of the CDC statement, tested directly.

        The request-level single-domain gate makes a cross-domain route
        unreachable end to end today, so the route check is exercised with a
        bound instance whose declared domain really differs.
        """
        documents, request_path = FIXTURES["novacore"]
        plan = compose(copy.deepcopy(documents), request_path)
        instances = []
        for item in plan.instances:
            if item.kind == "cpu":
                instances.append(item)
                continue
            binding_record, field = item.binding.clocks[0]
            instances.append(replace(item, binding=replace(
                item.binding,
                clocks=((replace(binding_record, domain="fast"), field),))))
        refusals = soc_scope.bound_scope_refusals(plan.request, instances)
        self.assertTrue(refusals, "the route-level check accepted a foreign domain")
        for refusal in refusals:
            self.assertTrue(refusal.startswith("cross-domain-route:cpu0:core:"), refusal)
            self.assertTrue(refusal.endswith(":fast:no-synchroniser-is-composed"), refusal)
        self.assertIn("cross-domain-route:cpu0:core:gpio0:fast:no-synchroniser-is-composed",
                      refusals)

    def test_a_declared_reset_sequence_in_a_profile_is_refused(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({GPIO_KEY: reset_after_document()})
        self.assertEqual(
            "reset-sequence-unsupported:novagpio:rst_ni:cpu0:"
            "only-one-simultaneously-released-reset-domain-is-composed",
            str(error.exception))

    def test_a_declared_reset_sequence_in_the_request_is_refused(self) -> None:
        request = _request_document()
        request["reset"]["sequence"] = ["cpu0", "gpio0"]
        with self.assertRaises(CompositionError) as error:
            compose({}, DEFAULT_REQUEST, request)
        self.assertEqual(
            "reset-sequence-unsupported:novacore-novauart-novagpio:cpu0,gpio0:"
            "only-one-simultaneously-released-reset-domain-is-composed",
            str(error.exception))

    def test_a_reset_polarity_mismatch_is_still_refused(self) -> None:
        """The supported reset topology is one domain, one polarity, simultaneous."""
        document = _document(GPIO_KEY)
        document["resets"][0]["polarity"] = "active_high"
        with self.assertRaises(ComponentProfileError) as error:
            compose({GPIO_KEY: document})
        self.assertEqual("reset-polarity-mismatch:gpio0", str(error.exception))

    def test_a_bidirectional_port_is_refused_at_the_disposition_layer(self) -> None:
        reason = _inout_trigger({"port": "PAD"})
        self.assertEqual("dispositions:t0:inout-port-unsupported:PAD:"
                         "no-single-unambiguous-direction-is-declared", reason)


class StructuralCaseTests(unittest.TestCase):
    """The reset topology and the unidirectional port set, re-read from the RTL."""

    def test_the_single_simultaneous_reset_domain_is_rendered_and_audited(self) -> None:
        """One reset domain, released simultaneously, re-read from the netlist."""
        plan = compose({})
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["reset_topology"]["status"],
                         findings["reset_topology"])
        expected = findings["reset_topology"]["expected"]
        self.assertEqual("sys_rst", expected["reset_domain"])
        self.assertEqual("active_low", expected["polarity"])
        self.assertEqual(["rst_ni", "~rst_ni"], expected["nets"])
        # Every planned reset pin lands on one of the two legal nets.
        for subject, actual in findings["reset_topology"]["actual"].items():
            self.assertIn(actual.replace(" ", ""), ("rst_ni", "~rst_ni"), subject)

    def test_a_unidirectional_port_set_is_disposed_and_audited(self) -> None:
        """The legal case: every port of the example composition has one direction."""
        plan = compose({})
        for instance in plan.instances:
            for entry in instance.dispositions:
                self.assertIn(entry.direction, ("input", "output"))
        result = render_and_audit(plan)
        self.assertEqual("pass", result["summary"]["status"], result["findings"])
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["reset_topology"]["status"])

    def test_a_peripheral_master_endpoint_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({UART_KEY: uart_dma_document()})
        self.assertEqual(
            "fabric-master-lane-unavailable:uart0:uart.dma:memory_master:"
            "only-the-cpu-master-endpoints-and-the-generated-synthetic-master-own-"
            "fabric-lanes", str(error.exception))

    def test_the_cpu_master_lanes_are_composed_and_audited(self) -> None:
        """Ibex declares two master endpoints; both get a lane and an adapter."""
        plan = compose({}, "examples/soc_generation/request-ibex.json")
        sources = [str(item["source_id"]) for item in plan.plan["fabric"]["sources"]]
        self.assertEqual(["cpu_master0", "cpu_master1"], sources)
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["fabric_source_lanes"]["status"])
        self.assertEqual("pass", findings["response_ownership"]["status"])
        self.assertEqual("pass", findings["adapter_binding"]["status"])

    def test_a_debug_transport_endpoint_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: debug_document()})
        self.assertEqual(
            "debug-transport-unsupported:cpu0:core.debug:this-composer-builds-no-"
            "debug-transport", str(error.exception))

    def test_a_trace_role_cpu_input_is_refused_by_name(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: trace_role_document()})
        self.assertEqual(
            "trace-input-unsupported:cpu0:fetch_enable_i:trace:this-composer-captures-"
            "no-trace", str(error.exception))

    def test_an_undisposed_cpu_input_is_refused(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: drop_action_document("fetch_enable_i")})
        self.assertEqual("dispositions:cpu0:undisposed-port-bits:cpu0:fetch_enable_i:0:0",
                         str(error.exception))

    def test_an_unconnected_cpu_input_is_refused(self) -> None:
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: unconnected_document("fetch_enable_i")})
        self.assertEqual("dispositions:cpu0:input-without-driver:cpu0:fetch_enable_i",
                         str(error.exception))


# ---------------------------------------------------------------------------
# CPU input completeness, per input
# ---------------------------------------------------------------------------


def _cpu_input(plan, port: str) -> dict:
    return next(record for record in plan.cpu_inputs if record["port"] == port)


class CpuInputTests(unittest.TestCase):
    """debug, fetch_enable, timer, software and trace: one test each."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = compose({}, "examples/soc_generation/request-ibex.json")

    def test_debug_req_is_a_declared_constant_and_a_debug_endpoint_is_refused(self) -> None:
        record = _cpu_input(self.plan, "debug_req_i")
        self.assertEqual("constant", record["disposition"])
        self.assertEqual(0, record["value"])
        self.assertEqual("soc_top_constant", record["driver"])
        self.assertEqual("cpu_input_dispositions", record["audit"])
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: debug_document()})
        self.assertIn("debug-transport-unsupported", str(error.exception))

    def test_fetch_enable_is_the_declared_mubi_on_constant(self) -> None:
        record = _cpu_input(self.plan, "fetch_enable_i")
        self.assertEqual("constant", record["disposition"])
        self.assertEqual(5, record["value"])
        self.assertEqual("4'd5", record["expected_net"])

    def test_a_fuzz_declared_fetch_enable_is_driven_by_the_special_input_driver(self) -> None:
        plan = compose({IBEX: fetch_enable_fuzz_document()},
                       "examples/soc_generation/request-ibex.json")
        record = _cpu_input(plan, "fetch_enable_i")
        self.assertEqual("fuzz", record["disposition"])
        self.assertEqual("soc_special_input_driver", record["driver"])
        self.assertEqual("reset_sampled", record["strategy"])
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("u_drive_cpu0__fetch_enable_i", text)
        self.assertIn(".value_o(cpu0__fetch_enable_i__driven)", text)
        result = render_and_audit(plan)
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual("pass", findings["cpu_input_dispositions"]["status"],
                         findings["cpu_input_dispositions"])

    def test_timer_and_software_inputs_are_declared_constants(self) -> None:
        for port in ("irq_timer_i", "irq_software_i"):
            with self.subTest(port=port):
                record = _cpu_input(self.plan, port)
                self.assertEqual("constant", record["disposition"])
                self.assertEqual(0, record["value"])
                self.assertEqual("soc_top_constant", record["driver"])

    def test_the_declared_interrupt_entry_is_owned_by_the_controller(self) -> None:
        """The external entry is not a constant: the interrupt controller drives it."""
        record = _cpu_input(self.plan, "irq_external_i")
        self.assertEqual("functional", record["disposition"])
        self.assertEqual("processor_adapter", record["driver"])
        self.assertEqual("cpu_adapter_wiring", record["audit"])
        self.assertIsNone(record.get("expected_net"))

    def test_the_ibex_profile_declares_no_trace_input(self) -> None:
        """The real CPU has no trace port, so no trace claim is made."""
        ports = {str(record["port"]) for record in self.plan.cpu_inputs}
        self.assertNotIn("trace", " ".join(sorted(ports)))
        self.assertFalse([record for record in self.plan.cpu_inputs
                          if record.get("class") == "trace"])
        with self.assertRaises(CompositionError) as error:
            compose({CPU_KEY: trace_role_document()})
        self.assertIn("trace-input-unsupported", str(error.exception))

    def test_every_cpu_input_has_exactly_one_declared_driver(self) -> None:
        for record in self.plan.cpu_inputs:
            with self.subTest(port=record["port"]):
                self.assertTrue(record["driver"])
                self.assertIsNotNone(record["audit"])


# ---------------------------------------------------------------------------
# the new audit checks must be able to fail
# ---------------------------------------------------------------------------


class NewAuditCheckTests(unittest.TestCase):
    """Each new claim is re-read from the elaboration and can report a fault."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise unittest.SkipTest("verilator is not installed")
        cls.plan = compose({})
        cls.text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.sources = [item["path"] for item in source_list(cls.plan)]

    def audit(self, text: str) -> dict:
        return audit_structure(self.plan, top_text=text, source_files=self.sources,
                               base_dir=ROOT)

    def failures(self, text: str) -> list[str]:
        return [item["check_id"] for item in self.audit(text)["findings"]
                if item["status"] == FAIL]

    def mutate(self, old: str, new: str) -> str:
        self.assertIn(old, self.text)
        return self.text.replace(old, new)

    def test_the_new_checks_pass_on_the_generated_soc(self) -> None:
        result = self.audit(self.text)
        findings = {item["check_id"]: item for item in result["findings"]}
        for check_id in ("adapter_binding", "reset_topology", "cpu_input_dispositions"):
            self.assertIn(check_id, findings)
            self.assertEqual("pass", findings[check_id]["status"], findings[check_id])
        self.assertEqual("pass", result["summary"]["status"], result["findings"])

    def test_a_changed_adapter_parameter_is_detected(self) -> None:
        text = self.mutate(".SUPPORTS_PARTIAL_WRITE(1)", ".SUPPORTS_PARTIAL_WRITE(0)")
        self.assertIn("adapter_binding", self.failures(text))

    def test_a_changed_cpu_adapter_width_is_detected(self) -> None:
        text = self.mutate(".ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_BE(1)",
                           ".ADDRESS_WIDTH(16), .DATA_WIDTH(32), .HAS_BE(1)")
        self.assertIn("adapter_binding", self.failures(text))

    def test_a_second_reset_net_is_detected(self) -> None:
        """A delayed reset copy on one component is a reset order, not simultaneous."""
        text = self.mutate("    .pwrite_i(gpio0__pwrite),\n    .rst_ni(rst_ni)",
                           "    .pwrite_i(gpio0__pwrite),\n    .rst_ni(rst_ni_late)")
        text = text.replace("  localparam integer NUM_TARGETS",
                            "  wire rst_ni_late = rst_ni;\n  localparam integer NUM_TARGETS")
        self.assertIn("rst_ni_late", text)
        self.assertIn("reset_topology", self.failures(text))

    def test_a_component_reset_tied_inactive_is_detected(self) -> None:
        text = self.mutate("    .pwrite_i(gpio0__pwrite),\n    .rst_ni(rst_ni)",
                           "    .pwrite_i(gpio0__pwrite),\n    .rst_ni(1'b1)")
        self.assertIn("reset_topology", self.failures(text))

    def test_a_flipped_component_reset_is_detected(self) -> None:
        text = self.mutate("    .pwrite_i(gpio0__pwrite),\n    .rst_ni(rst_ni)",
                           "    .pwrite_i(gpio0__pwrite),\n    .rst_ni(~rst_ni)")
        self.assertIn("reset_topology", self.failures(text))

    def test_a_changed_cpu_input_constant_is_detected(self) -> None:
        text = self.mutate(".fetch_enable_i(1'd1)", ".fetch_enable_i(1'd0)")
        self.assertIn("cpu_input_dispositions", self.failures(text))

    def test_a_dropped_special_input_driver_is_detected(self) -> None:
        text = self.mutate(".value_o(cpu0__event_i__driven)", ".value_o()")
        self.assertIn("cpu_input_dispositions", self.failures(text))

    def test_a_changed_driver_strategy_is_detected(self) -> None:
        text = self.mutate(".WIDTH(4), .STRATEGY(0)", ".WIDTH(4), .STRATEGY(1)")
        self.assertIn("cpu_input_dispositions", self.failures(text))

    def test_a_swapped_special_input_lane_is_detected(self) -> None:
        text = self.mutate(".event_i(cpu0__event_i__driven)",
                           ".event_i(gpio0__pin_mode_i__driven)")
        self.assertIn("cpu_input_dispositions", self.failures(text))


if __name__ == "__main__":
    unittest.main()
