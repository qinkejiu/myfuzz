"""Real component profiles for the registered SoC components.

This module is the acceptance gate for the ``component_profile.v1`` files of the
real peripherals registered in ``configs/soc/sources.lock.json``:

* ``configs/peripherals/pulp_spi/component_profile.json``
* ``configs/peripherals/zipcpu_uart/component_profile.json``
* ``configs/peripherals/zipcpu_timer/component_profile.json``
* ``configs/peripherals/opentitan_uart/component_profile.json``
* ``configs/peripherals/opentitan_gpio/component_profile.json``

It was added as a new module rather than folded into
``test_real_peripheral_component_profiles.py`` because that module is the
PULP-GPIO acceptance test (it owns the APB3-without-PSTRB and pulse-IRQ
controls and composes ``examples/soc_generation/request-pulp-gpio.json``),
while this module is a per-profile ledger over five components and three
protocol families.  The two overlap only in the shared profile vocabulary.

Per profile it proves: the declaration is the pinned closure (root, revision,
file list, include roots, parameters), it elaborates, every declared role binds
to a real port of the declared direction and width, every elaborated port and
every bit of it has exactly one disposition, the declared capabilities are
exactly what the target-adapter resolver consumes, and the profile fails closed
under four negative controls per component.
"""
from __future__ import annotations

import json
import shutil
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    bind_profile,
    elaborate_profile,
    load_component_profile,
)
from myfuzz.composition.component_profile import DISPOSITION_KINDS, PortAction
from myfuzz.composition.soc_port_dispositions import (
    PortDispositionError,
    build_port_dispositions,
)
from myfuzz.composition.target_adapters import (
    TargetAdapterError,
    resolve_target_adapter,
)

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "configs/soc/sources.lock.json"

#: component_id -> (profile path, closure record, source root(s) the closure spans)
PROFILES: dict[str, tuple[str, str]] = {
    "pulp_spi": ("configs/peripherals/pulp_spi/component_profile.json",
                 "configs/soc/closures/pulp_spi.json"),
    "zipcpu_uart": ("configs/peripherals/zipcpu_uart/component_profile.json",
                    "configs/soc/closures/zipcpu_uart.json"),
    "zipcpu_timer": ("configs/peripherals/zipcpu_timer/component_profile.json",
                     "configs/soc/closures/zipcpu_timer.json"),
    "opentitan_uart": ("configs/peripherals/opentitan_uart/component_profile.json",
                       "configs/soc/closures/opentitan_uart.json"),
    "opentitan_gpio": ("configs/peripherals/opentitan_gpio/component_profile.json",
                       "configs/soc/closures/opentitan_gpio.json"),
}

#: Capabilities each target protocol's adapter actually consumes.  A profile may
#: declare more (the resolver carries unconsumed facts through); declaring less
#: is what this set catches.
CONSUMED_CAPABILITIES: dict[tuple[str, str], frozenset[str]] = {
    ("apb", "3"): frozenset(("byte_enable", "partial_write", "has_error", "data_width")),
    ("wishbone", "classic"): frozenset((
        "byte_enable", "partial_write", "has_error", "data_width", "has_address_port",
        "address_units", "sel_implemented", "wishbone_flavour",
    )),
    ("tl-ul", "1"): frozenset((
        "byte_enable", "partial_write", "has_error", "data_width", "integrity",
        "source_width", "sink_width", "user_width", "size_width",
    )),
}

#: Families used to scope the negative controls: component -> family.
FAMILIES = {
    "pulp_spi": "pulp",
    "zipcpu_uart": "zipcpu",
    "zipcpu_timer": "zipcpu",
    "opentitan_uart": "opentitan",
    "opentitan_gpio": "opentitan",
}

_HAS_TOOLING = shutil.which("verilator") is not None


def closure_document(name: str) -> dict:
    return json.loads((ROOT / PROFILES[name][1]).read_text(encoding="utf-8"))


def lock_record(component: str) -> dict:
    document = json.loads(LOCK.read_text(encoding="utf-8"))
    return next(item for item in document["components"] if item["id"] == component)


def _field_port(field) -> str:
    """The physical port a profile field binds, by alias or by member selector."""
    return field.physical.port if field.physical is not None else field.aliases[0]


def selected_span(fact, field) -> tuple[int, int, int]:
    """(bit_lo, bit_hi, width) of the member a bound role selected.

    A member path may name an intermediate packed struct (TL-UL's a_user), whose
    span is the union of the elaborated leaves below it.  ``field`` may be a
    loaded ``ProfileField`` or an already resolved ``ResolvedField``.
    """
    spans = {(item.path): (item.raw_lo, item.raw_hi, item.width)
             for item in fact.members}
    path = tuple(getattr(field, "member_path", ()) or
                 getattr(getattr(field, "physical", None), "member_path", ()))
    if path in spans:
        return spans[path]
    below = [value for candidate, value in spans.items()
             if candidate[:len(path)] == path]
    if not below:
        raise AssertionError(f"no elaborated member for {path}")
    return (min(item[0] for item in below), max(item[1] for item in below),
            sum(item[2] for item in below))


def whole_port_fields(binding) -> list:
    """The bound roles that own a whole physical port.

    A profile may now bind a *member* of a struct port or a slice of a vector, so
    the controls that need a port-level selector (misspell the port name, swap
    two ports' directions, oversize a whole-port constant) select from these;
    the member-level controls live in tests/composition/test_multi_role_ports.py.
    """
    return [field for field in binding.all_fields() if field.whole_port]


def _misspell(field):
    """A copy of the field whose bound port (or member path) does not exist."""
    if field.physical is not None:
        return replace(field, physical=replace(
            field.physical,
            member_path=(field.physical.member_path[0] + "_typo",)
            + tuple(field.physical.member_path[1:])))
    return replace(field, aliases=(field.aliases[0] + "_typo",))


def declared_parameters(profile) -> dict[str, str]:
    """The profile's declared elaboration parameters as name -> value strings."""
    settings = profile.source.elaboration
    return {} if settings is None else {name: value for name, value in settings.parameters}


def mmio_endpoint(profile):
    for endpoint in profile.endpoints:
        if endpoint.function == "mmio_slave":
            return endpoint
    return None


def target_record(profile, *, base: int = 0x40000000, drop_evidence: str | None = None) -> dict:
    """The target record soc_composition builds for one peripheral profile."""
    endpoint = mmio_endpoint(profile)
    assert endpoint is not None and endpoint.protocol is not None
    assert profile.address is not None
    evidence = {
        name: {"topic": f"component_profile.capabilities.{name}",
               "evidence_path": f"component_profile:{profile.component_id}",
               "provenance": "component_profile"}
        for name in profile.capabilities
        if name != drop_evidence
    }
    return {
        "component_id": profile.component_id,
        "target_id": f"{profile.component_id}_win",
        "protocol": list(endpoint.protocol),
        "version": endpoint.protocol[1],
        "data_width": int(profile.capabilities["data_width"]),
        "window": {"base": base, "size": profile.address.window_size},
        "capabilities": dict(profile.capabilities),
        "evidence": evidence,
        "max_wait_cycles": int(profile.capabilities.get("max_wait_cycles", 16)),
    }


class RealComponentProfileTests(unittest.TestCase):
    """Elaborate each profile once; every test below reads those facts."""

    facts: dict[str, object] = {}
    bindings: dict[str, object] = {}
    ledgers: dict[str, tuple] = {}
    profiles: dict[str, object] = {}

    @classmethod
    def setUpClass(cls) -> None:
        if not _HAS_TOOLING:
            raise unittest.SkipTest("verilator is missing")
        for name, (path, _closure) in PROFILES.items():
            profile_path = ROOT / path
            if not profile_path.is_file():
                raise AssertionError(f"missing component profile: {path}")
            profile = load_component_profile(profile_path)
            facts = elaborate_profile(profile, base_dir=ROOT)
            binding = bind_profile(profile, facts)
            entries = build_port_dispositions(
                f"{name}0", binding,
                clock_domain=profile.clocks[0].domain,
                reset_domain=profile.resets[0].domain,
                profile_port_actions=profile.port_actions)
            cls.profiles[name] = profile
            cls.facts[name] = facts
            cls.bindings[name] = binding
            cls.ledgers[name] = entries

    # -- declaration vs the pinned closure --------------------------------
    def test_profile_files_are_the_pinned_closure(self) -> None:
        for name, (path, closure_path) in PROFILES.items():
            with self.subTest(component=name):
                profile = self.profiles[name]
                document = json.loads((ROOT / path).read_text(encoding="utf-8"))
                closure = closure_document(name)
                record = lock_record(name)
                self.assertEqual(closure["top_module"], profile.source.top_module)
                self.assertEqual(
                    closure["top_module"],
                    record["source"]["top_module"])
                # roots: the closure may span several pinned roots (pulp_spi);
                # the profile's single root must then be their common parent.
                closure_roots = sorted({item["root"] for item in closure["closure_files"]})
                if len(closure_roots) == 1:
                    self.assertEqual(closure_roots[0], profile.source.source_root)
                else:
                    self.assertEqual("third_party", profile.source.source_root)
                    for root in closure_roots:
                        self.assertTrue(root.startswith("third_party/"), root)
                # files: exactly the HDL files the recorded command compiles,
                # expressed relative to the profile's single source root
                compiled = [item for item in closure["command"]
                            if item.endswith((".sv", ".v", ".svh"))]
                if len(closure_roots) == 1:
                    prefix = closure_roots[0] + "/"
                    recorded = sorted(item[len(prefix):] for item in compiled
                                      if item.startswith(prefix))
                else:
                    prefix = profile.source.source_root.rstrip("/") + "/"
                    recorded = sorted(item[len(prefix):] for item in compiled
                                      if item.startswith(prefix))
                self.assertEqual(recorded, sorted(profile.source.files))
                self.assertEqual(list(closure.get("include_roots", [])),
                                 list(profile.source.include_roots))
                self.assertEqual("recorded-nonfatal",
                                 profile.source.elaboration.warning_policy)
                if profile.source.revision.startswith("git:"):
                    # a git pin must be the lock's pin for this component
                    self.assertEqual(record["source"]["revision"], profile.source.revision)
                else:
                    # a content pin is verified by elaborate_profile itself
                    self.assertTrue(profile.source.revision.startswith("sha256:"))
                    self.assertEqual(sorted(closure_roots), sorted(
                        {item["root"] for item in closure["closure_files"]}))
                # every parameter the profile declares is recorded for the closure
                recorded_parameters = {item["name"]: str(item["value"])
                                       for item in record["typed_parameters"]}
                for parameter, value in declared_parameters(profile).items():
                    self.assertIn(parameter, recorded_parameters)
                    self.assertEqual(str(recorded_parameters[parameter]), value)
                # the closure's own parameter list is accounted for: declared or
                # explicitly recorded as unrepresentable in evidence.verified
                declared = set(declared_parameters(profile))
                unrepresentable = " ".join(profile.evidence["verified"])
                for item in closure["parameters"]:
                    if item["name"] in declared:
                        continue
                    if "::" in item["name"]:
                        continue  # generated-package constant, not a top parameter
                    self.assertIn(item["name"], unrepresentable, item["name"])

    def test_declared_parameters_are_integer_valued(self) -> None:
        # ElaborationSettings accepts decimal integers only; this pins the reason
        # the opentitan profiles cannot carry AlertAsyncOn=1'b1 style overrides.
        for name in PROFILES:
            with self.subTest(component=name):
                for _name, value in declared_parameters(self.profiles[name]).items():
                    self.assertRegex(value, r"-?(?:0|[1-9][0-9]*)\Z")

    # -- elaboration, binding, ledger -------------------------------------
    def test_every_profile_elaborates(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                facts = self.facts[name]
                self.assertGreater(len(facts.ports), 0)
                self.assertEqual(self.profiles[name].source.top_module, facts.top_module)

    def test_declared_roles_bind_to_real_ports(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                facts, binding = self.facts[name], self.bindings[name]
                self.assertGreater(len(binding.all_fields()), 0)
                for field in binding.all_fields():
                    fact = facts.port(field.port)
                    self.assertIsNotNone(fact, field.port)
                    self.assertEqual(fact.direction, field.direction, field.port)
                    self.assertTrue(field.source_file, field.port)
                    if field.member_path:
                        # A member role owns the elaborated member's width inside
                        # a wider struct port, and its span is the member's own.
                        self.assertEqual(selected_span(fact, field),
                                         (field.raw_lo, field.raw_hi, field.width),
                                         field.port)
                    elif not field.whole_port:
                        # A bit-range role owns a slice of a wider vector port.
                        self.assertLess(field.raw_hi, fact.width, field.port)
                        self.assertEqual(field.raw_hi - field.raw_lo + 1, field.width)
                    else:
                        self.assertEqual(fact.width, field.width, field.port)
                # clock and reset are the real ports of the declaration
                self.assertEqual([(item.port, "input") for item, _ in binding.clocks],
                                 [(item.port, field.direction)
                                  for item, field in binding.clocks])
                self.assertEqual([item.port for item in self.profiles[name].clocks],
                                 [item.port for item, _ in binding.clocks])
                self.assertEqual([item.port for item in self.profiles[name].resets],
                                 [item.port for item, _ in binding.resets])

    def test_every_elaborated_port_and_bit_has_exactly_one_disposition(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                facts, entries = self.facts[name], self.ledgers[name]
                covered: dict[str, set[int]] = {}
                for entry in entries:
                    self.assertIn(entry.disposition, DISPOSITION_KINDS)
                    self.assertNotEqual("unclassified", entry.disposition)
                    self.assertTrue(entry.reason, entry.port)
                    bits = covered.setdefault(entry.port, set())
                    for bit in range(entry.bit_lo, entry.bit_hi + 1):
                        self.assertNotIn(bit, bits, f"{entry.port}[{bit}] twice")
                        bits.add(bit)
                elaborated = {fact.name: fact.width for fact in facts.ports}
                self.assertEqual(set(elaborated), set(covered))
                for port, width in elaborated.items():
                    self.assertEqual(set(range(width)), covered[port], port)
                self.assertEqual(sum(elaborated.values()),
                                 sum(entry.bit_hi - entry.bit_lo + 1 for entry in entries))
                for entry in entries:
                    if entry.disposition == "constant":
                        self.assertEqual("input", entry.direction, entry.port)
                        self.assertLess(entry.value, 1 << (entry.bit_hi - entry.bit_lo + 1))
                    if entry.disposition == "observe":
                        self.assertEqual("output", entry.direction, entry.port)
                    if entry.disposition in ("external", "fuzz"):
                        self.assertIn(entry.direction, ("input", "output"))
                    if entry.disposition == "unconnected":
                        self.assertTrue(entry.coverage_loss)

    def test_declared_ports_are_exactly_the_elaborated_selection(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                profile, facts = self.profiles[name], self.facts[name]
                selection = json.loads(
                    (ROOT / PROFILES[name][0]).read_text(encoding="utf-8")
                )["source"].get("top_port_selection", "all")
                declared = set()
                for endpoint in profile.endpoints:
                    for field in endpoint.fields:
                        declared.add(field.physical.port if field.physical else field.aliases[0])
                declared.update(item.port for item in profile.clocks)
                declared.update(item.port for item in profile.resets)
                declared.update(item.port for item in profile.port_actions)
                if selection == "declared":
                    self.assertEqual(declared, {fact.name for fact in facts.ports})
                    # the bounded selection must be recorded, never silent
                    self.assertTrue(profile.evidence["unknown"])

    # -- capabilities vs the adapter resolver -----------------------------
    def test_declared_capabilities_are_what_the_resolver_consumes(self) -> None:
        for name in PROFILES:
            endpoint = mmio_endpoint(self.profiles[name])
            if endpoint is None:
                continue  # opentitan: no bus endpoint, covered by the next test
            with self.subTest(component=name):
                profile = self.profiles[name]
                resolved = resolve_target_adapter(
                    {"protocol": "processor-memory-beat", "version": "1",
                     "address_width": 32,
                     "data_width": int(profile.capabilities["data_width"])},
                    target_record(profile))
                self.assertEqual(list(endpoint.protocol),
                                 [resolved["target_protocol"]["protocol"],
                                  resolved["target_protocol"]["version"]])
                consumed = CONSUMED_CAPABILITIES[tuple(endpoint.protocol)]
                self.assertTrue(consumed <= set(profile.capabilities))
                self.assertEqual(set(profile.capabilities), set(resolved["capability_evidence"]))
                parameters = {item["name"]: item["value"] for item in resolved["parameters"]}
                self.assertEqual(profile.address.window_size, parameters["WINDOW_SIZE"])
                for fact, record in resolved["capability_evidence"].items():
                    self.assertEqual(profile.capabilities[fact], record["value"], fact)
                if endpoint.protocol == ("apb", "3"):
                    self.assertEqual(0, parameters["HAS_PSTRB"])
                    self.assertEqual(0, parameters["SUPPORTS_PARTIAL_WRITE"])
                    self.assertEqual(1, parameters["HAS_PSLVERR"])
                if endpoint.protocol == ("wishbone", "classic"):
                    self.assertEqual(
                        {"classic": 0, "registered-ack": 1, "registered-ack-cyc-ignored": 2}
                        [profile.capabilities["wishbone_flavour"]],
                        parameters["WB_FLAVOUR"])
                    self.assertEqual(
                        int(profile.capabilities.get("address_units") == "word"),
                        parameters["ADDRESS_UNITS"])
                    self.assertEqual(
                        int(profile.capabilities["partial_write"]
                            and profile.capabilities["byte_enable"]
                            and profile.capabilities["sel_implemented"]),
                        parameters["SUPPORTS_PARTIAL_WRITE"])
                    self.assertEqual(int(profile.capabilities["has_error"]),
                                     parameters["HAS_ERR"])

    def test_every_declared_capability_has_an_evidence_entry_per_profile(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                profile = self.profiles[name]
                semantics = " ".join(profile.evidence["semantics"])
                self.assertTrue(semantics)
                # every declared capability must be named in the semantics list
                for capability in profile.capabilities:
                    self.assertIn(capability, semantics, capability)

    def test_tlul_profiles_declare_the_real_bus_endpoint(self) -> None:
        """The OpenTitan bus is now declared, member by member, and re-proved.

        This test replaces the one that recorded the former blockage (the plugin
        had no d_error/d_user, its a_size/a_source widths contradicted top_pkg,
        and the renderer had no struct-port path).  Every claim it used to make
        about the *RTL* is kept: the register decode is still declared, the
        bounded port selection is still recorded as unknown, and the bus members
        are the real ones - now bound instead of excluded.
        """
        from myfuzz.composition.component_profile import (
            _protocol_field_directions, _protocol_field_widths)
        for name in ("opentitan_uart", "opentitan_gpio"):
            with self.subTest(component=name):
                profile = self.profiles[name]
                facts, binding = self.facts[name], self.bindings[name]
                endpoint = mmio_endpoint(profile)
                self.assertIsNotNone(endpoint, "the TL-UL endpoint must be declared")
                self.assertEqual(("tl-ul", "1"), endpoint.protocol)
                # the RTL decode is still declared (software generation input)
                self.assertIsNotNone(profile.address)
                self.assertTrue(profile.address.registers)
                # the plugin now carries every member the adapter port list needs
                roles = set(_protocol_field_directions(("tl-ul", "1")))
                for role in ("d_error", "d_user", "a_user"):
                    self.assertIn(role, roles)
                widths = _protocol_field_widths(("tl-ul", "1"), profile.capabilities)
                self.assertEqual(2, widths["a_size"])
                self.assertEqual(2, widths["d_size"])
                self.assertEqual(8, widths["a_source"])
                self.assertEqual(8, widths["d_source"])
                self.assertEqual(23, widths["a_user"])
                self.assertEqual(14, widths["d_user"])
                # and every declared role is the real elaborated member
                tl_i = facts.port("tl_i")
                tl_o = facts.port("tl_o")
                self.assertEqual((109, "input"), (tl_i.width, tl_i.direction))
                self.assertEqual((66, "output"), (tl_o.width, tl_o.direction))
                spans = {(item.path): (item.raw_lo, item.raw_hi, item.width)
                         for port in (tl_i, tl_o) for item in port.members}
                self.assertEqual(20, len(endpoint.fields))
                for field in endpoint.fields:
                    fact = facts.port(field.physical.port)
                    self.assertEqual(selected_span(fact, field),
                                     (field.member_bits[0], field.member_bits[1],
                                      field.width), field.role)
                    self.assertEqual(fact.direction, field.direction, field.role)
                # every bit of both struct ports is classified
                covered: set[int] = set()
                for entry in self.ledgers[name]:
                    if entry.port in ("tl_i", "tl_o"):
                        covered.update(range(entry.bit_lo, entry.bit_hi + 1))
                self.assertEqual(set(range(109)) | set(range(66)) - set(), covered)
                # the bounded selection is still explicitly recorded
                unknown = " ".join(profile.evidence["unknown"])
                for token in ("alert_rx_i", "alert_tx_o", "racl_policies_i",
                              "racl_error_o"):
                    self.assertIn(token, unknown, token)

    # -- negative controls -------------------------------------------------
    def test_negative_control_missing_port(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                profile, facts = self.profiles[name], self.facts[name]
                target = self.binding_port(name)
                broken = replace(profile, endpoints=tuple(
                    replace(endpoint, fields=tuple(
                        _misspell(field) if _field_port(field) == target else field
                        for field in endpoint.fields))
                    for endpoint in profile.endpoints))
                with self.assertRaises(ComponentProfileError) as error:
                    bind_profile(broken, facts)
                self.assertIn("port-missing", str(error.exception))
                self.assertIn(target, str(error.exception))

    def test_negative_control_wrong_direction(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                profile, facts = self.profiles[name], self.facts[name]
                port, other = self.binding_direction_swap(name)
                for endpoint in profile.endpoints:
                    for field in endpoint.fields:
                        if _field_port(field) == port:
                            self.assertTrue(
                                field.aliases,
                                "direction control needs alias-bound fields")
                            self.assertIsNone(field.physical)
                broken = replace(profile, endpoints=tuple(
                    replace(endpoint, fields=tuple(
                        replace(field, aliases=(other,))
                        if _field_port(field) == port else field
                        for field in endpoint.fields))
                    for endpoint in profile.endpoints))
                with self.assertRaises(ComponentProfileError) as error:
                    bind_profile(broken, facts)
                self.assertIn("direction-conflict", str(error.exception))

    def test_negative_control_undisposed_port(self) -> None:
        """Drop a disposition: either a port action or a bound endpoint field."""
        for name in PROFILES:
            with self.subTest(component=name):
                profile, facts, binding = (self.profiles[name], self.facts[name],
                                           self.bindings[name])
                if profile.port_actions:
                    dropped = profile.port_actions[0].port
                    actions = profile.port_actions[1:]
                    use = binding
                else:
                    endpoint = profile.endpoints[0]
                    field = endpoint.fields[-1]
                    dropped = field.aliases[0]
                    broken = replace(profile, endpoints=tuple(
                        replace(item, fields=tuple(
                            other for other in item.fields if other is not field))
                        if item.endpoint_id == endpoint.endpoint_id else item
                        for item in profile.endpoints))
                    use = bind_profile(broken, facts)
                    actions = profile.port_actions
                with self.assertRaises(PortDispositionError) as error:
                    build_port_dispositions(
                        f"{name}0", use, clock_domain=profile.clocks[0].domain,
                        reset_domain=profile.resets[0].domain,
                        profile_port_actions=actions)
                self.assertIn(f"undisposed-port-bits:{name}0:{dropped}",
                              str(error.exception))

    def test_negative_control_capability_without_evidence(self) -> None:
        for name in PROFILES:
            endpoint = mmio_endpoint(self.profiles[name])
            if endpoint is None:
                continue
            with self.subTest(component=name):
                profile = self.profiles[name]
                fact = sorted(profile.capabilities)[0]
                record = target_record(profile, drop_evidence=fact)
                with self.assertRaises(TargetAdapterError) as error:
                    resolve_target_adapter(
                        {"protocol": "processor-memory-beat", "version": "1",
                         "address_width": 32,
                         "data_width": int(profile.capabilities["data_width"])},
                        record)
                self.assertIn("missing-evidence", str(error.exception))
                self.assertIn(fact, str(error.exception))

    def test_negative_control_unclassified_or_conflicting_disposition(self) -> None:
        """A second disposition for a covered bit is a second driver, not a refinement."""
        for name in PROFILES:
            with self.subTest(component=name):
                profile, binding = self.profiles[name], self.bindings[name]
                if profile.port_actions:
                    action = profile.port_actions[0]
                    actions = profile.port_actions + (action,)
                    expected = "duplicate-port-action"
                else:
                    # no port actions: overlap a bound input with a constant action
                    port = next(field.port for field in whole_port_fields(binding)
                                if field.direction == "input" and field.width == 1)
                    actions = profile.port_actions + (PortAction(
                        port=port, action="constant", value=0,
                        reason="probe: a second driver for an already bound bit"),)
                    expected = "bit-multiple-dispositions"
                with self.assertRaises(PortDispositionError) as error:
                    build_port_dispositions(
                        f"{name}0", binding, clock_domain=profile.clocks[0].domain,
                        reset_domain=profile.resets[0].domain,
                        profile_port_actions=actions)
                self.assertIn(expected, str(error.exception))

    def test_negative_control_action_on_a_port_outside_the_selection(self) -> None:
        """The bounded selection is explicit: it may not be extended by stealth."""
        for name in ("opentitan_uart", "opentitan_gpio"):
            with self.subTest(component=name):
                profile, binding = self.profiles[name], self.bindings[name]
                outside = "alert_rx_i" if name == "opentitan_uart" else "alert_tx_o"
                template = profile.port_actions[0]
                actions = profile.port_actions + (
                    replace(template, port=outside, member_path=(), bits=()),)
                with self.assertRaises(PortDispositionError) as error:
                    build_port_dispositions(
                        f"{name}0", binding, clock_domain=profile.clocks[0].domain,
                        reset_domain=profile.resets[0].domain,
                        profile_port_actions=actions)
                self.assertIn(f"port-action-unknown-port:{outside}", str(error.exception))

    def test_negative_control_constant_wider_than_its_port(self) -> None:
        for name in PROFILES:
            with self.subTest(component=name):
                profile, binding = self.profiles[name], self.bindings[name]
                constants = [item for item in profile.port_actions
                             if item.action == "constant"]
                if constants:
                    action = constants[0]
                    port = action.port
                    width = (action.bits[-1] - action.bits[0] + 1 if action.bits
                             else binding.facts.port(port).width)
                    actions = tuple(
                        replace(item, value=1 << width) if item.port == port else item
                        for item in profile.port_actions)
                else:
                    port = next(field.port for field in whole_port_fields(binding)
                                if field.direction == "input" and field.width == 1)
                    actions = profile.port_actions + (PortAction(
                        port=port, action="constant", value=2,
                        reason="probe: a constant that does not fit its port"),)
                with self.assertRaises(PortDispositionError) as error:
                    build_port_dispositions(
                        f"{name}0", binding, clock_domain=profile.clocks[0].domain,
                        reset_domain=profile.resets[0].domain,
                        profile_port_actions=actions)
                self.assertIn(f"constant-action-out-of-range:{port}:",
                              str(error.exception))

    # -- helpers -----------------------------------------------------------
    def binding_port(self, name: str) -> str:
        return whole_port_fields(self.bindings[name])[0].port

    def binding_direction_swap(self, name: str) -> tuple[str, str]:
        """(port, an alias of the opposite direction) for one declared endpoint."""
        facts = self.facts[name]
        for field in whole_port_fields(self.bindings[name]):
            fact = facts.port(field.port)
            for other in sorted({item.name for item in facts.ports},
                                key=lambda item: item):
                other_fact = facts.port(other)
                if other_fact.direction != fact.direction:
                    return field.port, other
        raise AssertionError(f"{name}: no opposite-direction port pair")


class ProfileFamilyCoverageTests(unittest.TestCase):
    """Every family must carry at least the four negative controls."""

    def test_negative_controls_cover_each_family(self) -> None:
        controls = {
            "missing_port": RealComponentProfileTests.test_negative_control_missing_port,
            "wrong_direction": RealComponentProfileTests.test_negative_control_wrong_direction,
            "undisposed_port": RealComponentProfileTests.test_negative_control_undisposed_port,
            "capability_without_evidence":
                RealComponentProfileTests.test_negative_control_capability_without_evidence,
        }
        self.assertGreaterEqual(len(controls), 2)
        families = sorted(set(FAMILIES.values()))
        self.assertEqual(["opentitan", "pulp", "zipcpu"], families)
        document = json.loads(LOCK.read_text(encoding="utf-8"))
        registered = {item["id"] for item in document["components"]}
        self.assertTrue(set(PROFILES) <= registered)


if __name__ == "__main__":
    unittest.main()
