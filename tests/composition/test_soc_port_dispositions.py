"""Step 3: every port and bit segment has exactly one recorded disposition."""
from __future__ import annotations

import unittest
from dataclasses import replace

from myfuzz.composition.component_profile import (
    PortAction,
    bind_profile,
    elaborate_profile,
    load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import (
    PortDispositionError,
    build_port_dispositions,
    disposition_summary,
    dispositions_document,
    exported_ports,
    fuzz_ports,
)

from .soc_generation_fixture import EXAMPLE, ROOT


def _binding(name: str):
    profile = load_component_profile(EXAMPLE / "profiles" / f"{name}.json")
    return profile, bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))


def _dispositions(instance_id: str, name: str):
    profile, binding = _binding(name)
    return profile, build_port_dispositions(
        instance_id, binding, clock_domain="core", reset_domain="sys_rst",
        profile_port_actions=profile.port_actions)


class DispositionCoverageTests(unittest.TestCase):
    def test_every_declared_port_gets_exactly_one_disposition(self) -> None:
        for instance_id, name in (("cpu0", "novacore"), ("uart0", "novauart"),
                                  ("gpio0", "novagpio")):
            with self.subTest(instance=instance_id):
                _profile, binding = _binding(name)
                entries = build_port_dispositions(
                    instance_id, binding, clock_domain="core", reset_domain="sys_rst",
                    profile_port_actions=_profile.port_actions)
                covered: dict[str, int] = {}
                for entry in entries:
                    covered[entry.port] = covered.get(entry.port, 0) + \
                        entry.bit_hi - entry.bit_lo + 1
                expected = {port.name: port.width for port in binding.facts.ports}
                self.assertEqual(expected, covered)

    def test_summary_counts_the_five_classes(self) -> None:
        profile, entries = _dispositions("novacore0", "novacore")
        summary = disposition_summary(entries)
        self.assertEqual(1, summary["fuzz"])
        self.assertEqual(2, summary["observe"])
        self.assertEqual(1, summary["constant"])
        self.assertGreater(summary["functional"], 0)

    def test_a_port_nobody_classified_is_rejected(self) -> None:
        """Removing a declaration must fail; an unclassified port is never generated."""
        profile, binding = _binding("novagpio")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("gpio0", binding, clock_domain="core",
                                    reset_domain="sys_rst", profile_port_actions=())
        self.assertIn("undisposed-port-bits", str(error.exception))
        self.assertIn("pin_mode_i", str(error.exception))

    def test_two_actions_for_one_bit_are_rejected(self) -> None:
        profile, binding = _binding("novagpio")
        first = PortAction(port="pin_mode_i", bits=(0, 1), action="fuzz",
                           strategy="cycle_value", reason="first claim")
        second = PortAction(port="pin_mode_i", bits=(1, 2), action="fuzz",
                            strategy="cycle_value", reason="overlapping claim")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("gpio0", binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=(first, second))
        self.assertIn("bit-multiple-dispositions", str(error.exception))

    def test_outputs_cannot_be_randomly_driven(self) -> None:
        profile, binding = _binding("novagpio")
        bad = PortAction(port="gpio_out_o", action="fuzz", strategy="cycle_value",
                         reason="wrong on purpose")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("gpio0", binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=(profile.port_actions[0], bad))
        self.assertIn("fuzz-action-on-non-input", str(error.exception))

    def test_constants_only_apply_to_inputs_and_must_fit(self) -> None:
        profile, binding = _binding("novacore")
        on_output = PortAction(port="status_o", action="constant", value=0,
                               reason="wrong on purpose")
        with self.assertRaises(PortDispositionError):
            build_port_dispositions("cpu0", binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=(*profile.port_actions, on_output))
        del on_output
        too_wide = PortAction(port="event_i", action="constant", value=1 << 8,
                              reason="wrong on purpose")
        without_fuzz = tuple(action for action in profile.port_actions
                             if action.port != "event_i")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("cpu0", binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=(*without_fuzz, too_wide))
        self.assertIn("constant-action-out-of-range", str(error.exception))

    def test_fuzz_requires_a_declared_drive_strategy(self) -> None:
        profile, entries = _dispositions("gpio0", "novagpio")
        fuzz = fuzz_ports(entries)
        self.assertEqual(["pin_mode_i"], [entry.port for entry in fuzz])
        self.assertEqual("cycle_value", fuzz[0].strategy)
        _profile, binding = _binding("novagpio")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions(
                "gpio0", binding, clock_domain="core", reset_domain="sys_rst",
                profile_port_actions=(replace(profile.port_actions[0], strategy=None),))
        self.assertIn("requires-drive-strategy", str(error.exception))


class PartialVectorTests(unittest.TestCase):
    """An 8-bit input whose other bits are unused must be recorded bit by bit."""

    def test_unused_bits_of_a_vector_are_covered_by_the_declared_disposition(self) -> None:
        profile, binding = _binding("novagpio")
        entries = build_port_dispositions(
            "gpio0", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=profile.port_actions)
        by_port = {entry.port: entry for entry in entries}
        self.assertEqual((0, 7), (by_port["gpio_in_i"].bit_lo, by_port["gpio_in_i"].bit_hi))
        self.assertEqual("external", by_port["gpio_in_i"].disposition)

    def test_a_partially_classified_vector_is_rejected(self) -> None:
        profile, binding = _binding("novagpio")
        partial = PortAction(port="pin_mode_i", bits=(0, 1), action="fuzz",
                             strategy="cycle_value", reason="only two bits on purpose")
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("gpio0", binding, clock_domain="core",
                                    reset_domain="sys_rst", profile_port_actions=(partial,))
        self.assertIn("undisposed-port-bits", str(error.exception))
        self.assertIn("2:2", str(error.exception))

    def test_disjoint_bit_actions_are_accepted_and_reported(self) -> None:
        profile, binding = _binding("novagpio")
        actions = (
            PortAction(port="pin_mode_i", bits=(0, 1), action="fuzz",
                       strategy="cycle_value", reason="two random bits"),
            PortAction(port="pin_mode_i", bits=(2,), action="constant", value=0,
                       reason="third bit is a defined constant"),
        )
        entries = build_port_dispositions("gpio0", binding, clock_domain="core",
                                          reset_domain="sys_rst", profile_port_actions=actions)
        spans = {(entry.bit_lo, entry.bit_hi): entry.disposition for entry in entries
                 if entry.port == "pin_mode_i"}
        self.assertEqual({(0, 1): "fuzz", (2, 2): "constant"}, spans)
        document = dispositions_document(entries)
        self.assertTrue(any(item["port"] == "pin_mode_i"
                            for item in document["coverage_losses"]))


class ExportTests(unittest.TestCase):
    def test_exports_are_fuzz_external_and_observe_only(self) -> None:
        for instance_id, name in (("cpu0", "novacore"), ("uart0", "novauart"),
                                  ("gpio0", "novagpio")):
            with self.subTest(instance=instance_id):
                _profile, entries = _dispositions(instance_id, name)
                for entry in exported_ports(entries):
                    self.assertIn(entry.disposition, ("fuzz", "external", "observe"))

    def test_external_pins_are_not_random_inputs(self) -> None:
        _profile, entries = _dispositions("uart0", "novauart")
        external = {entry.port: entry.disposition for entry in exported_ports(entries)}
        self.assertEqual({"uart_rx_i": "external", "uart_tx_o": "external"}, external)
        self.assertFalse(fuzz_ports(entries))

    def test_declared_constant_and_unconnected_port_are_recorded(self) -> None:
        _profile, entries = _dispositions("cpu0", "novacore")
        constant = [entry for entry in entries if entry.disposition == "constant"]
        self.assertEqual(1, len(constant))
        self.assertEqual(1, constant[0].value)
        self.assertTrue(constant[0].coverage_loss)
        self.assertIn("held at a fixed value", constant[0].coverage_loss)


if __name__ == "__main__":
    unittest.main()
