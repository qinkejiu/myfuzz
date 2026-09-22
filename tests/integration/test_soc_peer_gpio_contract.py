"""Task 3: the GPIO peer's electrical contract, one property at a time.

The GPIO peer claims four independent electrical behaviours - it samples the
value the peer drives, it presents the component's output value, it honours the
component's output enable (``dir``), and it resolves an undriven line to a
declared default level - plus a contention report whose error treatment is a
declared policy (``CONTENTION_IS_ERROR`` 0/1).  This module builds one positive
and at least one negative criterion per behaviour, in three layers:

1. **Pure (always run).**  ``myfuzz.composition.soc_peer_oracle.gpio_resolution``
   is the frozen Python reference.  Each test writes its own raw pin values and
   states the expected level by hand, so the expectation can never come from the
   generated RTL, from a peer counter or from the implementation under test.
   Refusals (a default level, contention policy, pin count or previous error
   outside the contract) are asserted by their exact reason string, so an
   approximation would be a failure rather than a silent rounding.
2. **Real RTL (``MYFUZZ_SOC_REAL=1``).**  The rendered, audited, compiled peer
   SoC of ``tests/integration/test_soc_peer_models.py::GpioPeerRuntimeTests`` is
   reused unchanged: this module only subclasses that fixture (it never edits
   it) and re-evaluates the *same* independent contract with the parameters the
   plan really declared.  Four configurations are run - the fixture's own
   ``(DEFAULT_INPUT_LEVEL=0, CONTENTION_IS_ERROR=1)``, each declaration changed
   on its own, and both changed at once - so both default levels and both
   contention policies have real-RTL evidence, not only the configuration the
   example request happens to ship.
3. **The bidirectional-pin boundary (always run).**  A real ``inout`` pad has no
   electrical resolution model in this generator, so it must be refused at
   generation time instead of being degraded into a random unidirectional line.
   This module asserts the *named* refusals that exist today
   (``inout-port-unsupported`` at the disposition/admission layer and
   ``fuzz-action-on-non-input`` / ``observe-action-on-non-output`` at the port
   action layer) against a real component's elaborated facts, and pins the PULP
   APB GPIO boundary: the pinned ``apb_gpio.sv`` declares no bidirectional port
   at all, and the GPIO peer is *refused* as an attachment to the PULP
   ``gpio.pins`` interface because that interface also declares ``padcfg`` and
   ``in_sync`` roles the electrical model does not implement.  Nothing in the
   generator is changed by this module; the finding is reported as it is.
"""
from __future__ import annotations

import json
import re
import unittest
import unittest.mock
from dataclasses import replace

from myfuzz.composition import soc_peer_oracle, soc_scope
from myfuzz.composition.component_profile import (
    PortAction,
    bind_profile,
    elaborate_profile,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import CompositionError, build_composition
from myfuzz.composition.soc_peer_oracle import PeerOracleError, gpio_resolution
from myfuzz.composition.soc_port_dispositions import (
    PortDispositionError,
    build_port_dispositions,
)

from tests.composition.soc_generation_fixture import ROOT
# The fixture module is imported as a module on purpose: binding its TestCase
# classes to names of this module would make the unittest loader collect (and
# rebuild) them here as well.
from tests.integration import test_soc_peer_models as peer_models

#: The fixture's own request reader, captured before any subclass patches it.
_ORIGINAL_PEER_REQUEST_DOCUMENT = peer_models.peer_request_document

#: The peer-models example SoC: the fixture this module's real-RTL half reuses.
PEER_PROFILE = "examples/soc_generation/profiles/novagpio.json"

#: The pinned PULP APB GPIO: the real bidirectional-pad boundary under test.
PULP_PROFILE = "configs/peripherals/pulp_gpio/component_profile.json"
PULP_REQUEST = "examples/soc_generation/request-pulp-gpio.json"
PULP_GPIO_RTL = "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv"
NOVA_CORE = "examples/soc_generation/profiles/novacore.json"


def gpio(**overrides: object) -> dict[str, int]:
    """``gpio_resolution`` with a minimal all-undriven 8-pin sample."""
    arguments: dict[str, object] = {
        "peer_drive_value": 0, "peer_drive_valid": 0,
        "component_out": 0, "component_dir": 0, "pins": 8,
        "default_input_level": 0, "contention_is_error": 0,
    }
    arguments.update(overrides)
    return gpio_resolution(**arguments)  # type: ignore[arg-type]


class GpioResolutionContractTests(unittest.TestCase):
    """Item 3.1: every electrical property, with its own positive and negative."""

    def test_gpio_resolution_is_the_published_independent_reference(self) -> None:
        self.assertIn("gpio_resolution", set(soc_peer_oracle.__all__))

    # -- input sampling ----------------------------------------------------

    def test_input_sampling_takes_the_peer_value_only_where_the_peer_drives(self) -> None:
        sample = gpio(peer_drive_value=0xA5, peer_drive_valid=0x0F)
        # Bits 0..3 are driven (0101), bits 4..7 are high impedance and carry
        # the declared default level 0.
        self.assertEqual(0x05, sample["resolved"])
        self.assertEqual(0, sample["contention"])
        self.assertEqual(0, sample["contention_error"])

    def test_input_sampling_ignores_a_peer_value_the_peer_does_not_enable(self) -> None:
        sample = gpio(peer_drive_value=0xFF, peer_drive_valid=0x00)
        # The peer names a value but enables no pin: every pin is high
        # impedance, so the value must not reach the line.
        self.assertEqual(0x00, sample["resolved"])
        self.assertNotEqual(0xFF, sample["resolved"])

    def test_input_sampling_masks_pins_the_declared_interface_does_not_have(self) -> None:
        driven = gpio(pins=4, peer_drive_value=0x0A, peer_drive_valid=0x0F,
                      default_input_level=1)
        self.assertEqual(0x0A, driven["resolved"])
        # valid/value bits above the declared width are outside the interface:
        # they must be dropped, not OR-ed onto the line.
        self.assertEqual(0x0F, gpio(pins=4, peer_drive_value=0xFF,
                                    peer_drive_valid=0xF0,
                                    default_input_level=1)["resolved"])
        self.assertEqual(0x00, gpio(pins=4, peer_drive_value=0xF0,
                                    peer_drive_valid=0x0F,
                                    default_input_level=0)["resolved"])

    # -- output value ------------------------------------------------------

    def test_output_value_is_the_component_value_where_the_component_drives(self) -> None:
        sample = gpio(component_out=0x5A, component_dir=0xFF)
        self.assertEqual(0x5A, sample["resolved"])
        self.assertEqual(0, sample["contention"])

    def test_output_value_is_absent_where_the_component_is_high_impedance(self) -> None:
        sample = gpio(component_out=0xFF, component_dir=0x00)
        # The output register alone is not a drive: without the direction bit
        # the pin is high impedance and takes the default level.
        self.assertEqual(0x00, sample["resolved"])
        self.assertNotEqual(0xFF, sample["resolved"])

    # -- output enable (dir) ----------------------------------------------

    def test_direction_enables_the_component_drive_bit_by_bit(self) -> None:
        # Low nibble enabled and driven high, high nibble high impedance.
        self.assertEqual(0x0F, gpio(component_out=0xFF, component_dir=0x0F,
                                    default_input_level=0)["resolved"])
        # Same enable, low drive, and a pulled-up default: exactly the disabled
        # bits keep the default level, so the enable is per bit.
        self.assertEqual(0xF0, gpio(component_out=0x00, component_dir=0x0F,
                                    default_input_level=1)["resolved"])

    def test_a_component_that_is_high_impedance_cannot_contend(self) -> None:
        sample = gpio(peer_drive_value=0xFF, peer_drive_valid=0xFF,
                      component_out=0x00, component_dir=0x00,
                      contention_is_error=1)
        # If dir were ignored, the component's 0x00 would be a drive and this
        # sample would be an all-pin contention resolved to 0.
        self.assertEqual(0xFF, sample["resolved"])
        self.assertEqual(0, sample["contention"])
        self.assertEqual(0, sample["contention_count"])
        self.assertEqual(0, sample["contention_error"])

    # -- default level -----------------------------------------------------

    def test_default_level_zero_is_the_level_of_an_undriven_pin(self) -> None:
        self.assertEqual(0x00, gpio(default_input_level=0)["resolved"])

    def test_default_level_one_is_the_level_of_an_undriven_pin(self) -> None:
        self.assertEqual(0xFF, gpio(default_input_level=1)["resolved"])
        # The default vector follows the declared width, it is not all ones.
        self.assertEqual(0x0F, gpio(pins=4, default_input_level=1)["resolved"])

    def test_a_driven_bit_is_never_replaced_by_the_default_level(self) -> None:
        # Both sides drive low on a pulled-up line: the drive wins.
        self.assertEqual(0xF0, gpio(component_out=0x00, component_dir=0x0F,
                                    default_input_level=1)["resolved"])
        self.assertEqual(0xF0, gpio(peer_drive_value=0x00, peer_drive_valid=0x0F,
                                    default_input_level=1)["resolved"])
        # A contested bit resolves to the contention level, also not the
        # default level.  The rule is per pin, so the bits nobody contends keep
        # their agreed value -- here the upper four pins stay pulled up.
        contended = gpio(peer_drive_value=0x0F, peer_drive_valid=0x0F,
                         component_out=0x00, component_dir=0x0F,
                         default_input_level=1, contention_is_error=1)
        self.assertEqual(0xF0, contended["resolved"])
        self.assertEqual(0x0F, contended["contention"])
        self.assertEqual(4, contended["contention_count"])

    def test_a_default_level_outside_the_contract_is_refused_by_name(self) -> None:
        for level in (2, -1, True):
            with self.assertRaises(PeerOracleError) as error:
                gpio(default_input_level=level)
            self.assertEqual("gpio-default-input-level-invalid",
                             str(error.exception), repr(level))

    # -- contention --------------------------------------------------------

    def test_an_opposite_drive_is_contention_and_never_a_winner(self) -> None:
        sample = gpio(peer_drive_value=0xAA, peer_drive_valid=0xFF,
                      component_out=0x55, component_dir=0xFF,
                      contention_is_error=1)
        self.assertEqual(0xFF, sample["contention"])
        self.assertEqual(0xFF, sample["contention_rise"])
        self.assertEqual(8, sample["contention_count"])
        self.assertEqual(1, sample["contention_error"])
        # The resolved level is the contention level, never either driver's
        # value and never X.
        self.assertEqual(0x00, sample["resolved"])
        self.assertNotIn(sample["resolved"], (0xAA, 0x55))

    def test_only_the_disagreeing_bits_are_flagged_as_contended(self) -> None:
        sample = gpio(peer_drive_value=0xAB, peer_drive_valid=0xFF,
                      component_out=0xAA, component_dir=0xFF)
        self.assertEqual(0x01, sample["contention"])
        self.assertEqual(1, sample["contention_count"])
        self.assertEqual(1, sample["contention_rise"].bit_count())

    def test_the_contract_resolves_a_partial_contention_per_pin(self) -> None:
        """The reference resolves per pin, exactly like the peer RTL.

        ``src/myfuzz/protocols/rtl/soc_gpio_peer.sv`` computes
        ``contended ? CONTENTION_LEVEL : agreed`` for each pin independently, and
        its declared contention level is zero, so a contended pin reads 0 while
        every other pin keeps its agreed value.  The reference used to zero the
        *whole* word as soon as any bit contended, which disagreed with the RTL
        on every partial contention; this test pins the corrected per-pin rule,
        and ``GpioDeclaredContractRuntimeTests`` checks the same expectation
        against the real peer.
        """
        partial = gpio(peer_drive_value=0xAB, peer_drive_valid=0xFF,
                       component_out=0xAA, component_dir=0xFF)
        # Only bit 0 contends, so only bit 0 is forced to the contention level and
        # the other seven keep the peer's value.
        self.assertEqual(0xAA, partial["resolved"])
        self.assertEqual(0x01, partial["contention"])
        # All-pin contention is the case where the two rules coincide.
        whole = gpio(peer_drive_value=0xAA, peer_drive_valid=0xFF,
                     component_out=0x55, component_dir=0xFF)
        self.assertEqual(0x00, whole["resolved"])
        self.assertEqual(0xFF, whole["contention"])

    def test_a_matching_drive_is_not_contention(self) -> None:
        sample = gpio(peer_drive_value=0x5A, peer_drive_valid=0xFF,
                      component_out=0x5A, component_dir=0xFF,
                      contention_is_error=1)
        self.assertEqual(0, sample["contention"])
        self.assertEqual(0, sample["contention_count"])
        self.assertEqual(0, sample["contention_error"])
        self.assertEqual(0x5A, sample["resolved"])
        self.assertNotEqual(0, sample["resolved"])

    def test_contention_policy_one_raises_the_sticky_error(self) -> None:
        sample = gpio(peer_drive_value=0x01, peer_drive_valid=0x01,
                      component_out=0x00, component_dir=0x01,
                      contention_is_error=1)
        self.assertEqual(0x01, sample["contention"])
        self.assertEqual(1, sample["contention_count"])
        self.assertEqual(1, sample["contention_error"])

    def test_contention_policy_zero_reports_the_contention_without_the_error(self) -> None:
        sample = gpio(peer_drive_value=0x01, peer_drive_valid=0x01,
                      component_out=0x00, component_dir=0x01,
                      contention_is_error=0)
        # The policy only decides the error flag: the contention itself is
        # still reported, so silence is never mistaken for agreement.
        self.assertEqual(0x01, sample["contention"])
        self.assertEqual(1, sample["contention_count"])
        self.assertEqual(0x00, sample["resolved"])
        self.assertEqual(0, sample["contention_error"])

    def test_an_error_from_an_earlier_sample_stays_under_policy_zero(self) -> None:
        sample = gpio(contention_is_error=0, previous_error=1)
        self.assertEqual(0, sample["contention"])
        self.assertEqual(1, sample["contention_error"])

    def test_a_persistent_contention_is_counted_once_per_rise(self) -> None:
        first = gpio(peer_drive_value=0x01, peer_drive_valid=0x01,
                     component_out=0x00, component_dir=0x01,
                     contention_is_error=1)
        second = gpio(peer_drive_value=0x01, peer_drive_valid=0x01,
                      component_out=0x00, component_dir=0x01,
                      contention_is_error=1,
                      previous_contention=first["contention"],
                      previous_error=first["contention_error"])
        self.assertEqual(1, first["contention_count"])
        self.assertEqual(0x01, second["contention"])
        self.assertEqual(0, second["contention_rise"])
        self.assertEqual(0, second["contention_count"])
        self.assertEqual(1, second["contention_error"])

    def test_a_contention_that_ended_is_no_longer_flagged(self) -> None:
        ended = gpio(component_out=0x00, component_dir=0x01,
                     contention_is_error=1, previous_contention=0x01,
                     previous_error=1)
        self.assertEqual(0, ended["contention"])
        self.assertEqual(0, ended["contention_rise"])
        self.assertEqual(0, ended["contention_count"])
        # ... while the error the earlier sample raised stays sticky.
        self.assertEqual(1, ended["contention_error"])

    def test_a_contention_policy_outside_the_contract_is_refused_by_name(self) -> None:
        for policy in (2, -1, True):
            with self.assertRaises(PeerOracleError) as error:
                gpio(contention_is_error=policy)
            self.assertEqual("gpio-contention-policy-invalid",
                             str(error.exception), repr(policy))

    # -- sample parameters outside the contract ----------------------------

    def test_a_pin_count_below_one_is_refused_by_name(self) -> None:
        for pins in (0, -1):
            with self.assertRaises(PeerOracleError) as error:
                gpio(pins=pins)
            self.assertEqual("gpio-pins-invalid", str(error.exception), repr(pins))

    def test_a_previous_error_outside_the_contract_is_refused_by_name(self) -> None:
        for previous in (2, -1, True):
            with self.assertRaises(PeerOracleError) as error:
                gpio(previous_error=previous)
            self.assertEqual("gpio-previous-error-invalid",
                             str(error.exception), repr(previous))


def pulp_declarations() -> dict[str, object]:
    """The pinned PULP GPIO profile and the module header of its pinned RTL."""
    profile = load_component_profile(ROOT / PULP_PROFILE)
    text = (ROOT / PULP_GPIO_RTL).read_text()
    start = text.index("module apb_gpio")
    header = text[start:text.index(");", start)]
    return {"profile": profile, "header": header,
            "pin_endpoint": next(item for item in profile.endpoints
                                 if item.endpoint_id == "gpio.pins")}


class GpioGenerationBoundaryTests(unittest.TestCase):
    """Item 3.3: a pin boundary without an electrical model is refused by name.

    The refusals below already exist in the generator; this module only asserts
    them (Task 3 adds no source check).  A real component's elaborated facts are
    used, so the refusal is exercised on the same objects the generator sees.
    """

    def novagpio(self):
        profile = load_component_profile(ROOT / PEER_PROFILE)
        facts = elaborate_profile(profile, base_dir=ROOT)
        return profile, facts, bind_profile(profile, facts)

    def ledger(self, profile, binding, actions=()):
        return build_port_dispositions(
            "gpio0", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=tuple(profile.port_actions) + tuple(actions))

    def test_the_bidirectional_port_refusal_is_published_with_its_reason(self) -> None:
        reason = soc_scope.inout_port_refusal("PAD")
        self.assertEqual(
            "inout-port-unsupported:PAD:no-single-unambiguous-direction-is-declared",
            reason)
        entry = next(item for item in soc_scope.soc_adapter_scope()["entries"]
                     if item["feature"] == "inout_port")
        self.assertEqual(soc_scope.REFUSED, entry["status"])
        self.assertEqual(f"dispositions:t0:{reason}", entry["error"])
        self.assertEqual("dispositions:<instance>:inout-port-unsupported:<port>:"
                         "no-single-unambiguous-direction-is-declared",
                         entry["error_template"])
        self.assertIn("soc_port_dispositions.build_port_dispositions", entry["code_path"])
        self.assertIn("PortDispositionError", entry["code_path"])
        self.assertEqual({"mutation": "inout_port", "port": "PAD"}, entry["trigger"])
        self.assertIn("no single driver direction", entry["condition"])

    def test_the_admission_layer_refuses_an_elaborated_inout_port(self) -> None:
        profile, facts, binding = self.novagpio()
        # Positive control: the component's real, unidirectional pin boundary is
        # admitted, so the refusal below is about the direction and nothing else.
        admitted = self.ledger(profile, binding)
        self.assertTrue(admitted)
        self.assertEqual(["external"], sorted({entry.disposition for entry in admitted
                                               if entry.endpoint_id == "gpio.pins"}))
        bidirectional_facts = replace(facts, ports=tuple(
            replace(fact, direction="inout") if fact.name == "gpio_in_i" else fact
            for fact in facts.ports))
        # The binding layer names a bidirectional pad by the role it was asked
        # for; the disposition ledger is what refuses it, before any render.
        bidirectional = bind_profile(profile, bidirectional_facts)
        with self.assertRaises(PortDispositionError) as error:
            self.ledger(profile, bidirectional)
        self.assertEqual(
            "inout-port-unsupported:gpio_in_i:no-single-unambiguous-direction-is-declared",
            str(error.exception))
        # The ambiguity was not resolved by guessing either: the field the
        # profile declared is still the input role it asked for, and no ledger
        # (and therefore no randomly driven pin) was produced for the port.
        declared_in = next(field for endpoint in bidirectional.endpoints
                           for field in endpoint.fields if field.port == "gpio_in_i")
        self.assertEqual("input", declared_in.direction)

    def test_an_output_port_cannot_be_degraded_into_a_driven_random_line(self) -> None:
        profile, _facts, binding = self.novagpio()
        random_drive = PortAction(
            port="gpio_out_o", action="fuzz", strategy="cycle_value",
            reason="negative control: the environment may not drive an output")
        with self.assertRaises(PortDispositionError) as error:
            self.ledger(profile, binding, (random_drive,))
        self.assertEqual("fuzz-action-on-non-input:gpio_out_o:output",
                         str(error.exception))
        # The mirror image: a component input is never turned into an observed
        # (undriven) line either.
        observed_input = PortAction(
            port="gpio_in_i", action="observe",
            reason="negative control: an input is not an observation point")
        with self.assertRaises(PortDispositionError) as error:
            self.ledger(profile, binding, (observed_input,))
        self.assertEqual("observe-action-on-non-output:gpio_in_i:input",
                         str(error.exception))


class PulpGpioInoutBoundaryTests(unittest.TestCase):
    """The PULP APB GPIO boundary: what is refused today, and what the gap is.

    The pinned PULP unit declares no ``inout`` port, so the disposition-layer
    refusal cannot be reached from it; the boundary it really has is three (plus
    two auxiliary) unidirectional pin ports.  An electrical peer is *not*
    silently attached to that boundary either: the attachment is refused by
    name because the interface also declares ``padcfg`` and ``in_sync``, roles
    the peer's electrical contract does not implement.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.declared = pulp_declarations()
        cls.profile = cls.declared["profile"]
        cls.profiles = {NOVA_CORE: load_component_profile(ROOT / NOVA_CORE),
                        PULP_PROFILE: cls.profile}
        cls.document = json.loads((ROOT / PULP_REQUEST).read_text())
        cls.plan = build_composition(
            load_composition_request(cls.document, profiles=cls.profiles), base_dir=ROOT)
        cls.gpio = next(item for item in cls.plan.instances
                        if item.instance_id == "gpio0")

    def request(self, document: dict):
        return load_composition_request(document, profiles=self.profiles)

    def test_the_pinned_pulp_rtl_declares_no_bidirectional_pad(self) -> None:
        header = str(self.declared["header"])
        self.assertNotIn("inout", header)
        port_directions = {"gpio_in": "input", "gpio_out": "output", "gpio_dir": "output",
                           "gpio_padcfg": "output", "gpio_in_sync": "output"}
        for port, direction in port_directions.items():
            declaration = next(line for line in header.splitlines()
                               if re.search(rf"\b{port}\b", line))
            self.assertRegex(declaration.strip(), rf"^{direction}\b", port)
        endpoint = self.declared["pin_endpoint"]
        self.assertEqual(("in", "out", "dir", "padcfg", "in_sync"),
                         tuple(field.role for field in endpoint.fields))
        self.assertEqual(("input", "output", "output", "output", "output"),
                         tuple(field.direction for field in endpoint.fields))
        # The roles bind exactly the pinned unidirectional ports, one each.
        self.assertEqual(tuple(port_directions),
                         tuple(str(field.aliases[0]) for field in endpoint.fields))

    def test_the_composed_pulp_boundary_has_one_direction_per_pin(self) -> None:
        entries = [entry for entry in self.gpio.dispositions
                   if entry.endpoint_id == "gpio.pins"]
        self.assertEqual({"in": "input", "out": "output", "dir": "output",
                          "padcfg": "output", "in_sync": "output"},
                         {entry.role: entry.direction for entry in entries})
        self.assertNotIn("inout", {entry.direction for entry in self.gpio.dispositions})
        self.assertEqual(len(entries), len({entry.port for entry in entries}))
        self.assertEqual({"external"}, {entry.disposition for entry in entries})
        # No peer was attached, and the reason is recorded instead of guessed.
        self.assertEqual((), tuple(item.instance_id for item in self.plan.peers))
        gap = next(item for item in self.plan.gaps
                   if item.startswith("gpio0.gpio.pins:"))
        self.assertIn("no peer model implements the declared roles", gap)
        self.assertIn("padcfg:output", gap)
        self.assertIn("in_sync:output", gap)
        self.assertIn("the environment drives them", gap)

    def test_the_electrical_gpio_peer_is_refused_as_a_pulp_pin_attachment(self) -> None:
        document = json.loads(json.dumps(self.document))
        document["peer_models"] = [{
            "instance_id": "gpio0", "endpoint_id": "gpio.pins", "attach": True,
            "parameters": {"DEFAULT_INPUT_LEVEL": 0, "CONTENTION_IS_ERROR": 1}}]
        with self.assertRaises(CompositionError) as error:
            build_composition(self.request(document), base_dir=ROOT)
        message = str(error.exception)
        self.assertIn("peer-attach:gpio0:gpio.pins", message)
        self.assertIn("peer-role-unsupported", message)
        for role in ("in:input", "out:output", "dir:output", "padcfg:output",
                     "in_sync:output"):
            self.assertIn(role, message)

    def test_the_profile_records_the_pad_electrical_model_as_absent(self) -> None:
        # The gap is declared by the profile itself, so nothing here needs a new
        # source check: structural generation provides no pad driver and no
        # bidirectional electrical model, and every pin stays exported.
        unknown = " ".join(str(item) for item in self.profile.evidence["unknown"])
        self.assertIn("Pad electrical behaviour and an external pin driver are not "
                      "provided by structural generation; all pins are exported.",
                      unknown)


# ---------------------------------------------------------------------------
# real RTL: the same contract, re-evaluated with what the plan declared
# ---------------------------------------------------------------------------


def gpio_contract_document(**parameters: int) -> dict:
    """The fixture's own request document with gpio0's peer parameters changed.

    The shipped example declares ``DEFAULT_INPUT_LEVEL=0`` and
    ``CONTENTION_IS_ERROR=1``; an electrical item is only covered when the other
    values are run as well, so the subclasses below re-run the same fixture
    build with one or both of them changed.  Nothing on disk is modified.
    """
    document = _ORIGINAL_PEER_REQUEST_DOCUMENT()
    for item in document["peer_models"]:
        if item["instance_id"] == "gpio0":
            item["parameters"].update({str(name): int(value)
                                       for name, value in parameters.items()})
    return document


class _GpioContractRuntimeScenarios:
    """Real-RTL scenarios whose expectation is the contract, never a counter.

    Every expected level below is produced by ``gpio_resolution()`` from the raw
    values this module writes (peer value/valid, component out/dir) and from the
    parameters the plan declared - never from the peer's own counters.
    """

    #: gpio0 peer parameters this class changes on top of the fixture's request.
    gpio_parameters: dict[str, int] = {}

    # Those two scenarios belong to the fixture module, which runs them with its
    # own expectations; this module re-derives the observations from
    # gpio_resolution() instead of running the same simulations twice.
    test_the_peer_drive_is_read_back_and_the_component_output_is_seen_by_the_peer = None
    test_an_opposite_drive_raises_the_pin_contention_flag = None

    @classmethod
    def setUpClass(cls) -> None:
        if not cls.gpio_parameters:
            super().setUpClass()
            return
        override = (lambda: gpio_contract_document(**cls.gpio_parameters))
        with unittest.mock.patch.object(peer_models, "peer_request_document", override):
            super().setUpClass()

    # -- the declared parameters and the contract --------------------------

    def declared_parameters(self) -> dict[str, int]:
        values = {str(name): int(value)
                  for name, value in self.plan.peer("gpio0").parameter_values.items()}
        for name in ("PINS", "DEFAULT_INPUT_LEVEL", "CONTENTION_IS_ERROR"):
            self.assertIn(name, values, sorted(values))
        return values

    def pins_mask(self) -> int:
        return (1 << self.declared_parameters()["PINS"]) - 1

    def default_vector(self) -> int:
        return self.pins_mask() if self.declared_parameters()["DEFAULT_INPUT_LEVEL"] else 0

    def contract(self, *, peer_value: int, peer_valid: int, out: int, direction: int,
                 previous_contention: int = 0, previous_error: int = 0) -> dict[str, int]:
        declared = self.declared_parameters()
        return gpio_resolution(
            peer_drive_value=peer_value, peer_drive_valid=peer_valid,
            component_out=out, component_dir=direction, pins=declared["PINS"],
            default_input_level=declared["DEFAULT_INPUT_LEVEL"],
            contention_is_error=declared["CONTENTION_IS_ERROR"],
            previous_contention=previous_contention, previous_error=previous_error)

    def assert_peer_contract(self, result, expected: dict[str, int], *,
                             direction: int, note: str) -> None:
        self.assertEqual(expected["resolved"],
                         self.observation(result, "gpio0__pin_value_o"), note)
        self.assertEqual(expected["contention"],
                         self.observation(result, "gpio0__contention_o"), note)
        self.assertEqual(expected["contention_count"],
                         self.observation(result, "gpio0__contention_count_o"), note)
        self.assertEqual(expected["contention_error"],
                         self.observation(result, "gpio0__contention_error_o"), note)
        self.assertEqual(direction, self.observation(result, "gpio0__direction_o"), note)

    # -- the tests ---------------------------------------------------------

    def test_the_plan_declares_the_parameters_this_class_asked_for(self) -> None:
        shipped = next(item for item in _ORIGINAL_PEER_REQUEST_DOCUMENT()["peer_models"]
                       if item["instance_id"] == "gpio0")["parameters"]
        shipped = {str(name): int(value) for name, value in shipped.items()}
        declared = self.declared_parameters()
        self.assertEqual(8, declared["PINS"], "the novagpio pin interface is 8 bits wide")
        for name, value in shipped.items():
            if name in {str(item) for item in self.gpio_parameters}:
                # This class asked for another value and the plan really carries
                # it: without this, a variant would silently re-run the shipped
                # configuration and claim evidence it does not have.
                self.assertEqual(int(self.gpio_parameters[name]), declared[name], name)
                self.assertNotEqual(value, declared[name],
                                    f"{name} was not changed from the shipped declaration")
                continue
            self.assertEqual(value, declared[name], name)

    def test_the_undriven_real_line_is_the_declared_default_level(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x00),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0x00),   # component high-Z
            60: ("gpio0_win", peer_models.GPIO_DATA_IN, 0, 0),  # read the line
        }, 120, request_id=901))
        expected = self.contract(peer_value=0, peer_valid=0, out=0x00, direction=0x00)
        self.assertEqual(self.default_vector(), expected["resolved"])
        self.assert_peer_contract(result, expected, direction=0x00,
                                  note="an undriven line must hold the declared default level")
        read = self.reads(result, "gpio0_win")[peer_models.GPIO_DATA_IN] & self.pins_mask()
        self.assertEqual(expected["resolved"], read,
                         "the component must sample the same level the peer resolved")
        # The level follows the declared parameter, it is not a fixed constant.
        self.assertNotEqual(read ^ self.pins_mask(), read)

    def test_a_partial_peer_drive_is_sampled_bit_by_bit_by_the_component(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x00),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0x00),   # component high-Z
            60: ("gpio0_win", peer_models.GPIO_DATA_IN, 0, 0),
        }, 140, events=(self.event("gpio0", "gpio.drive", 40, 0xA5 | (0x0F << 8)),),
            request_id=902))
        expected = self.contract(peer_value=0xA5, peer_valid=0x0F,
                                 out=0x00, direction=0x00)
        self.assert_peer_contract(result, expected, direction=0x00,
                                  note="peer value, drive enable and default must compose per pin")
        read = self.reads(result, "gpio0_win")[peer_models.GPIO_DATA_IN] & self.pins_mask()
        self.assertEqual(expected["resolved"], read)
        self.assertEqual(0x05, read & 0x0F, "the peer's driven bits carry its value")
        self.assertEqual(self.default_vector() & 0xF0, read & 0xF0,
                         "the peer's high-impedance bits carry the declared default")
        self.assertNotEqual(0xA5, read,
                            "the peer value must not be applied where the peer drives nothing")

    def test_the_real_component_drive_reaches_the_pin_with_its_direction(self) -> None:
        driven = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x5A),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
        }, 120, request_id=903))
        expected = self.contract(peer_value=0, peer_valid=0, out=0x5A, direction=0xFF)
        self.assert_peer_contract(driven, expected, direction=0xFF,
                                  note="the peer must present the component's output value")
        self.assertEqual(0x5A, self.observation(driven, "gpio0__pin_value_o"))
        # Negative: the output register without the direction bit is not a drive.
        idle = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x5A),
        }, 120, request_id=904))
        expected_idle = self.contract(peer_value=0, peer_valid=0,
                                      out=0x5A, direction=0x00)
        self.assert_peer_contract(idle, expected_idle, direction=0x00,
                                  note="DATA_OUT alone must not put a value on the pin")
        self.assertEqual(self.default_vector(),
                         self.observation(idle, "gpio0__pin_value_o"))
        self.assertNotEqual(0x5A, self.observation(idle, "gpio0__pin_value_o"))

    def test_the_real_direction_enables_the_component_drive_bit_by_bit(self) -> None:
        # The pair is chosen so that a peer that ignored dir per bit would fail
        # in either default-level configuration.
        high = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0xFF),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0x0F),
        }, 120, request_id=905))
        low = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x00),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0x0F),
        }, 120, request_id=906))
        for result, out in ((high, 0xFF), (low, 0x00)):
            expected = self.contract(peer_value=0, peer_valid=0, out=out, direction=0x0F)
            self.assert_peer_contract(result, expected, direction=0x0F,
                                      note="only the enabled bits may carry the component drive")

    def test_a_matching_drive_is_not_reported_as_contention(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x5A),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
        }, 200, events=(self.event("gpio0", "gpio.drive", 60, 0x5A | (0xFF << 8)),),
            request_id=907))
        expected = self.contract(peer_value=0x5A, peer_valid=0xFF,
                                 out=0x5A, direction=0xFF)
        self.assertEqual(0x5A, expected["resolved"])
        self.assertEqual(0, expected["contention"])
        self.assert_peer_contract(result, expected, direction=0xFF,
                                  note="two drivers with the same value agree, they do not contend")
        self.assertEqual(0, self.observation(result, "gpio0__contention_count_o"))
        self.assertEqual(0, self.observation(result, "gpio0__contention_error_o"))

    def test_an_all_pin_contention_resolves_to_the_contention_level(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x55),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
            140: ("gpio0_win", peer_models.GPIO_DATA_IN, 0, 0),
        }, 200, events=(self.event("gpio0", "gpio.drive", 60, 0xAA | (0xFF << 8)),),
            request_id=908))
        expected = self.contract(peer_value=0xAA, peer_valid=0xFF,
                                 out=0x55, direction=0xFF)
        self.assertEqual(self.pins_mask(), expected["contention"])
        self.assertEqual(8, expected["contention_count"])
        self.assertEqual(0x00, expected["resolved"],
                         "the contention level is a defined 0, never the peer's or the component's value")
        self.assert_peer_contract(result, expected, direction=0xFF,
                                  note="an opposite drive must be reported and resolved to the contention level")
        # Policy 1 raises the sticky error; policy 0 must not.
        self.assertEqual(self.declared_parameters()["CONTENTION_IS_ERROR"],
                         self.observation(result, "gpio0__contention_error_o"))
        self.assertEqual(0x00,
                         self.reads(result, "gpio0_win")[peer_models.GPIO_DATA_IN] & self.pins_mask(),
                         "the peripheral must see the contention level, not X")

    def test_a_persistent_contention_is_counted_once_per_pin(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x55),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
        }, 200, events=(self.event("gpio0", "gpio.drive", 60, 0xAA | (0xFF << 8)),
                        self.event("gpio0", "gpio.drive", 61, 0xAA | (0xFF << 8))),
            request_id=909))
        first = self.contract(peer_value=0xAA, peer_valid=0xFF, out=0x55, direction=0xFF)
        held = self.contract(peer_value=0xAA, peer_valid=0xFF, out=0x55, direction=0xFF,
                             previous_contention=first["contention"],
                             previous_error=first["contention_error"])
        self.assertEqual(8, first["contention_count"])
        self.assertEqual(0, held["contention_count"], "a held contention is not a new rise")
        self.assert_peer_contract(result, self.accumulated(first, held), direction=0xFF,
                                  note="a contention that persists is counted once per pin")

    def test_a_released_contention_follows_the_declared_error_policy(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0x55),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
        }, 220, events=(self.event("gpio0", "gpio.drive", 60, 0xAA | (0xFF << 8)),
                        self.event("gpio0", "gpio.drive", 120, 0x00)),
            request_id=910))
        first = self.contract(peer_value=0xAA, peer_valid=0xFF, out=0x55, direction=0xFF)
        released = self.contract(peer_value=0x00, peer_valid=0x00, out=0x55, direction=0xFF,
                                 previous_contention=first["contention"],
                                 previous_error=first["contention_error"])
        self.assertEqual(0, released["contention"], "the contention ended")
        self.assertEqual(0x55, released["resolved"], "the component drives the line again")
        self.assert_peer_contract(result, self.accumulated(first, released), direction=0xFF,
                                  note="a released contention must follow the declared policy")
        self.assertEqual(self.declared_parameters()["CONTENTION_IS_ERROR"],
                         self.observation(result, "gpio0__contention_error_o"),
                         "the sticky error must follow the declared CONTENTION_IS_ERROR policy")

    def test_a_partial_contention_is_resolved_per_pin_by_the_real_peer(self) -> None:
        """The reference and the peer agree on a *partial* contention.

        ``soc_gpio_peer.sv`` forces only the contended pin to the contention
        level and keeps the agreed value on every other pin, and
        ``gpio_resolution`` now states the same per-pin rule instead of zeroing
        the whole word.  This test is what keeps the two from drifting apart
        again: the reference no longer disagrees with the peer it judges, so the
        wire criterion may be assessed rather than excused.
        """
        result = self.run_sample(self.sample({
            4: ("gpio0_win", peer_models.GPIO_DATA_OUT, 1, 0xAA),
            20: ("gpio0_win", peer_models.GPIO_DIR, 1, 0xFF),
        }, 200, events=(self.event("gpio0", "gpio.drive", 60, 0xAB | (0xFF << 8)),),
            request_id=911))
        reference = self.contract(peer_value=0xAB, peer_valid=0xFF,
                                  out=0xAA, direction=0xFF)
        self.assertEqual(0x01, reference["contention"])
        # Bit 0 is the contended pin and carries the declared contention level 0;
        # bits 1..7 keep the peer's value.
        self.assertEqual(0xAA, reference["resolved"], "the reference is per pin")
        self.assertEqual(0x01, self.observation(result, "gpio0__contention_o"))
        self.assertEqual(1, self.observation(result, "gpio0__contention_count_o"))
        self.assertEqual(reference["resolved"],
                         self.observation(result, "gpio0__pin_value_o"),
                         "the peer must resolve a partial contention exactly as the reference does")
        self.assertEqual(self.declared_parameters()["CONTENTION_IS_ERROR"],
                         self.observation(result, "gpio0__contention_error_o"))

    def accumulated(self, *samples: dict[str, int]) -> dict[str, int]:
        """The end-of-run state a sequence of contract samples adds up to."""
        expected = dict(samples[-1])
        expected["contention_count"] = sum(int(item["contention_count"])
                                           for item in samples)
        return expected


class GpioDeclaredContractRuntimeTests(_GpioContractRuntimeScenarios,
                                       peer_models.GpioPeerRuntimeTests):
    """The fixture's own configuration: DEFAULT_INPUT_LEVEL=0, CONTENTION_IS_ERROR=1."""

    gpio_parameters: dict[str, int] = {}


class GpioDefaultHighRuntimeTests(_GpioContractRuntimeScenarios,
                                  peer_models.GpioPeerRuntimeTests):
    """The default level is a declaration: an undriven line really reads high."""

    gpio_parameters = {"DEFAULT_INPUT_LEVEL": 1}


class GpioContentionPolicyOffRuntimeTests(_GpioContractRuntimeScenarios,
                                          peer_models.GpioPeerRuntimeTests):
    """CONTENTION_IS_ERROR=0 still reports the contention, but raises no error."""

    gpio_parameters = {"CONTENTION_IS_ERROR": 0}


class GpioDefaultHighPolicyOffRuntimeTests(_GpioContractRuntimeScenarios,
                                           peer_models.GpioPeerRuntimeTests):
    """Both declarations changed at once: the items must not be coupled."""

    gpio_parameters = {"DEFAULT_INPUT_LEVEL": 1, "CONTENTION_IS_ERROR": 0}


if __name__ == "__main__":
    unittest.main()
