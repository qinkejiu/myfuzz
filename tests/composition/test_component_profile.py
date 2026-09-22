"""Step 2: unified component profiles bound to real elaborated RTL facts."""
from __future__ import annotations

import json
import unittest
from dataclasses import replace

from myfuzz.composition import component_profile as cp
from myfuzz.composition.component_profile import (
    ComponentProfileError,
    bind_profile,
    elaborate_profile,
    load_component_profile,
    load_composition_request,
    profile_pin,
)

from .soc_generation_fixture import EXAMPLE, PROFILE_NAMES, ROOT, example_profiles


def _load(name: str):
    return load_component_profile(EXAMPLE / "profiles" / f"{name}.json")


class ProfileLoadTests(unittest.TestCase):
    def test_profiles_load_with_the_declared_kinds_and_endpoints(self) -> None:
        core = _load("novacore")
        self.assertEqual("cpu", core.kind)
        self.assertEqual(["core.bus", "core.irq"],
                         sorted(endpoint.endpoint_id for endpoint in core.endpoints))
        self.assertEqual("riscv", core.cpu.family)
        self.assertEqual(65536, core.cpu.reset_vector)
        for name in ("novauart", "novagpio"):
            peripheral = _load(name)
            self.assertEqual("peripheral", peripheral.kind)
            self.assertTrue(peripheral.address.registers)
            self.assertTrue(peripheral.interrupts)

    def test_unknown_schema_kind_and_function_are_rejected(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novauart.json").read_text())
        for mutate, reason in (
            (lambda item: item.update(schema_version="component_profile.v2"), "schema"),
            (lambda item: item.update(kind="accelerator"), "kind"),
            (lambda item: item["endpoints"][0].update(function="magic_bus"), "function"),
        ):
            broken = json.loads(json.dumps(document))
            mutate(broken)
            with self.subTest(reason=reason):
                with self.assertRaises(ComponentProfileError):
                    load_component_profile(broken)

    def test_embedded_programs_are_rejected(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novagpio.json").read_text())
        document["port_actions"][0]["python"] = "lambda: 1"
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("profile-embedded-program", str(error.exception))

    def test_constant_action_requires_a_value_and_a_reason(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novagpio.json").read_text())
        document["port_actions"][0]["action"] = "constant"
        document["port_actions"][0].pop("strategy")
        with self.assertRaises(ComponentProfileError):
            load_component_profile(document)
        document["port_actions"][0]["value"] = 3
        document["port_actions"][0].pop("reason")
        with self.assertRaises(ComponentProfileError):
            load_component_profile(document)

    def test_unconnected_requires_a_contract_reference(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novagpio.json").read_text())
        document["port_actions"].append({"port": "pin_mode_i", "action": "unconnected",
                                         "reason": "not needed"})
        with self.assertRaises(ComponentProfileError):
            load_component_profile(document)

    def test_interrupt_prerequisite_requires_an_mmio_address_map(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novacore.json").read_text())
        document["endpoints"][1]["function"] = "interrupt_source"
        document["interrupts"] = [{
            "endpoint_id": "core.irq", "role": "external", "polarity": "active_high",
            "clock_domain": "core", "hold": "profile-declared level",
            "clear": "profile-declared clear", "prerequisites": [{
                "register": "CTRL", "offset": 0, "mask": 1,
                "reason": "must be enabled before the source can raise",
            }],
        }]
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("interrupt-prerequisites-require-address", str(error.exception))

    def test_interrupt_prerequisite_operation_is_closed_world(self) -> None:
        document = json.loads((EXAMPLE / "profiles/novauart.json").read_text())
        document["interrupts"][0]["prerequisites"] = [{
            "register": "CTRL", "offset": 0, "mask": 1,
            "reason": "enable receiver", "operation": "write_magic",
        }]
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("unsupported-interrupt-prerequisite-operation:write_magic",
                      str(error.exception))


class ProfileBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not cp.supervisor_available()[0]:
            # The direct path is exercised either way; both are the same
            # frontend contract, so the tests do not depend on which ran.
            pass

    def test_binding_resolves_every_role_to_a_real_port(self) -> None:
        profile = _load("novacore")
        facts = elaborate_profile(profile, base_dir=ROOT)
        binding = bind_profile(profile, facts)
        resolved = {field.role: field for field in binding.all_fields()}
        self.assertEqual("output", resolved["req"].direction)
        self.assertEqual("obi_req_o", resolved["req"].port)
        self.assertEqual("input", resolved["gnt"].direction)
        self.assertEqual(32, resolved["addr"].width)
        self.assertEqual("input", binding.clocks[0][1].direction)
        self.assertEqual("clk_i", binding.clocks[0][1].port)

    def test_direction_conflict_is_reported_not_repaired(self) -> None:
        """A profile that calls an input an output must fail, not be inverted."""
        profile = _load("novacore")
        facts = elaborate_profile(profile, base_dir=ROOT)
        endpoint = profile.endpoint("core.bus")
        broken_fields = tuple(
            replace(field, direction="input", aliases=("obi_req_o",))
            if field.role == "req" else field for field in endpoint.fields)
        broken = replace(profile, endpoints=tuple(
            replace(item, fields=broken_fields) if item.endpoint_id == "core.bus" else item
            for item in profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, facts)
        self.assertIn("direction-conflict", str(error.exception))
        self.assertIn("core.bus", str(error.exception))

    def test_unknown_port_and_wrong_width_are_reported(self) -> None:
        profile = _load("novacore")
        facts = elaborate_profile(profile, base_dir=ROOT)
        endpoint = profile.endpoint("core.bus")
        missing = replace(profile, endpoints=tuple(
            replace(item, fields=tuple(
                replace(field, aliases=("obi_address_typo_o",)) if field.role == "addr" else field
                for field in endpoint.fields)) if item.endpoint_id == "core.bus" else item
            for item in profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(missing, facts)
        self.assertIn("port-missing", str(error.exception))
        wrong = replace(profile, endpoints=tuple(
            replace(item, fields=tuple(
                replace(field, width=16) if field.role == "addr" else field
                for field in endpoint.fields)) if item.endpoint_id == "core.bus" else item
            for item in profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(wrong, facts)
        self.assertIn("binding-width-conflict", str(error.exception))

    def test_protocol_width_is_checked_independently_of_the_profile(self) -> None:
        """A port that disagrees with the protocol's declared role width fails."""
        profile = _load("novauart")
        facts = elaborate_profile(profile, base_dir=ROOT)
        endpoint = profile.endpoint("uart.bus")
        broken = replace(profile, endpoints=tuple(
            replace(item, fields=tuple(
                replace(field, direction=None, aliases=("uart_tx_o",))
                if field.role == "psel" else field
                for field in endpoint.fields)) if item.endpoint_id == "uart.bus" else item
            for item in profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, facts)
        self.assertIn("direction-conflict", str(error.exception))

    def test_source_pin_mismatch_is_reported(self) -> None:
        profile = _load("novagpio")
        broken = replace(profile, source=replace(profile.source, revision="sha256:" + "0" * 64))
        with self.assertRaises(ComponentProfileError) as error:
            elaborate_profile(broken, base_dir=ROOT)
        self.assertIn("content-hash-mismatch", str(error.exception))

    def test_all_example_profiles_bind(self) -> None:
        for name in PROFILE_NAMES:
            with self.subTest(profile=name):
                profile = _load(name)
                facts = elaborate_profile(profile, base_dir=ROOT)
                binding = bind_profile(profile, facts)
                self.assertTrue(binding.all_fields())
                self.assertTrue(binding.binding_hash.startswith("sha256:"))


class CompositionRequestTests(unittest.TestCase):
    def test_request_loads_and_keeps_two_instances_of_one_profile(self) -> None:
        request = load_composition_request(EXAMPLE / "request.json", profiles=example_profiles())
        identifiers = [item.instance_id for item in request.instances()]
        self.assertEqual(["cpu0", "gpio0", "uart0", "uart1"], sorted(identifiers))
        uart0 = next(item for item in request.peripherals if item.instance_id == "uart0")
        uart1 = next(item for item in request.peripherals if item.instance_id == "uart1")
        self.assertIs(uart0.profile, uart1.profile)
        self.assertIsNone(uart0.address)
        self.assertEqual(1073745920, uart1.address)

    def test_unknown_profile_reference_is_reported(self) -> None:
        document = json.loads((EXAMPLE / "request.json").read_text())
        document["peripherals"][0]["profile"] = "profiles/does-not-exist.json"
        with self.assertRaises(ComponentProfileError) as error:
            load_composition_request(document, profiles=example_profiles())
        self.assertIn("unknown-profile", str(error.exception))

    def test_duplicate_instance_and_writable_rom_are_rejected(self) -> None:
        document = json.loads((EXAMPLE / "request.json").read_text())
        document["peripherals"][1]["instance_id"] = "uart0"
        with self.assertRaises(ComponentProfileError):
            load_composition_request(document, profiles=example_profiles())
        document = json.loads((EXAMPLE / "request.json").read_text())
        document["memory"][0]["permissions"]["write"] = True
        with self.assertRaises(ComponentProfileError) as error:
            load_composition_request(document, profiles=example_profiles())
        self.assertIn("writable-rom", str(error.exception))

    def test_cross_domain_component_is_rejected(self) -> None:
        """The first phase is single-domain; a foreign clock domain must fail."""
        document = json.loads((EXAMPLE / "request.json").read_text())
        document["clock"]["domain"] = "fast"
        with self.assertRaises(ComponentProfileError) as error:
            load_composition_request(document, profiles=example_profiles())
        self.assertIn("cross-domain-unsupported", str(error.exception))

    def test_profile_pin_helper_matches_the_declared_revision(self) -> None:
        for name in PROFILE_NAMES:
            with self.subTest(profile=name):
                profile = _load(name)
                self.assertEqual(profile.source.revision, profile_pin(profile, base_dir=ROOT))


class RegisterDeclarationTests(unittest.TestCase):
    """The optional register declarations a generated program may rely on.

    ``reset_value``, ``writable_bits`` and ``clears_register`` are the only
    additions; each one is a declared fact with a validation rule, so a profile
    cannot use one to state something the generator would have to guess at.
    """

    def document(self) -> dict:
        return json.loads((EXAMPLE / "profiles/novagpio.json").read_text())

    def test_the_example_profiles_declare_them_as_real_facts(self) -> None:
        registers = {item.name: item for item in _load("novagpio").address.registers}
        self.assertEqual(0, registers["DATA_OUT"].reset_value)
        self.assertEqual(0xFF, registers["DATA_OUT"].writable_bits)
        self.assertEqual(1, registers["IRQ_EN"].writable_bits)
        self.assertEqual("IRQ_STATUS", registers["DATA_IN"].clears_register)
        self.assertIsNone(registers["IRQ_STATUS"].clears_register,
                          "no declared register proves a read of IRQ_STATUS clears it")
        # novagpio.sv clears irq_stat_q only on a DATA_IN access (a write at
        # :89, a read at :93), so a read of IRQ_STATUS clears nothing.  The
        # declaration has to say so: a read_clears here would be a fact about
        # the DUT that the RTL does not implement, and the generated software
        # would then try to verify it and record a false coverage gap.
        self.assertEqual("none", registers["IRQ_STATUS"].side_effect,
                         "IRQ_STATUS must declare the side effect novagpio.sv really has")
        uart = {item.name: item for item in _load("novauart").address.registers}
        self.assertEqual(0, uart["CTRL"].reset_value)
        self.assertEqual(0xFF, uart["CTRL"].writable_bits)
        self.assertEqual(1, uart["IRQ_STATUS"].writable_bits)
        self.assertEqual("IRQ_STATUS", uart["IRQ_STATUS"].clears_register)

    def test_a_reset_value_wider_than_the_register_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][0]["width"] = 8
        document["address"]["registers"][0]["reset_value"] = 0x100
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("register-reset-value-exceeds-width:DATA_OUT", str(error.exception))

    def test_writable_bits_wider_than_the_register_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][0]["width"] = 8
        document["address"]["registers"][0]["writable_bits"] = 0x1FF
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("register-writable-bits-exceed-width:DATA_OUT", str(error.exception))

    def test_empty_writable_bits_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][0]["writable_bits"] = 0
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("register-writable-bits-empty:DATA_OUT", str(error.exception))

    def test_writable_bits_on_a_read_only_register_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][2]["writable_bits"] = 1
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("writable-bits-on-read-only-register:DATA_IN", str(error.exception))

    def test_a_clearing_side_effect_without_a_probe_is_allowed(self) -> None:
        """No probe means "not observable", which the generator records as a gap.

        The case is constructed here rather than read out of the example
        profile: which of its registers carries an unobservable clearing side
        effect is a fact about the RTL, and it changes when the RTL does.  The
        schema rule under test is that such a declaration is *allowed*.
        """
        document = self.document()
        target = next(item for item in document["address"]["registers"]
                      if item["name"] == "IRQ_STATUS")
        target["side_effect"] = "read_clears"
        target.pop("clears_register", None)
        profile = load_component_profile(document)
        register = next(item for item in profile.address.registers
                        if item.name == "IRQ_STATUS")
        self.assertIsNone(register.clears_register)
        self.assertEqual("read_clears", register.side_effect)

    def test_a_probe_on_a_register_without_a_clearing_side_effect_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][0]["clears_register"] = "IRQ_STATUS"
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("clears-register-without-a-clearing-side-effect:DATA_OUT",
                      str(error.exception))

    def test_an_unknown_probe_is_refused(self) -> None:
        document = self.document()
        document["address"]["registers"][2]["clears_register"] = "NOT_A_REGISTER"
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("unknown-clears-register:DATA_IN:NOT_A_REGISTER", str(error.exception))

    def test_a_probe_must_be_readable(self) -> None:
        document = self.document()
        document["address"]["registers"][2]["clears_register"] = "IRQ_EN"
        document["address"]["registers"][3]["access"] = "wo"
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("clears-register-not-readable:DATA_IN:IRQ_EN", str(error.exception))

    def test_the_fields_survive_a_round_trip_through_the_profile(self) -> None:
        profile = load_component_profile(self.document())
        registers = {item.name: item for item in profile.address.registers}
        self.assertEqual((0, 0xFF, None),
                         (registers["DIR"].reset_value, registers["DIR"].writable_bits,
                          registers["DIR"].clears_register))


if __name__ == "__main__":
    unittest.main()
