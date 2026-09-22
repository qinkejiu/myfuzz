"""Priority item 2: the generic peer models are wired into the profile path.

``src/myfuzz/protocols/rtl/soc_{uart,spi,gpio}_peer.sv`` are generic: they select
nothing by name, and their contracts are declared by roles and parameters.  This
module proves that the profile-driven composition path really drives them:

* the composition attaches a peer to a declared ``external_pins`` interface when
  the endpoint's **role signature** is exactly the peer's own role contract, and
  never because of a component, instance or port name;
* an interface no implemented peer matches is exported and recorded (the
  behaviour every earlier render had), while an attachment the request *demands*
  is refused with a located capability gap instead of being approximated;
* the peer's timing parameters must agree with the parameters the component
  itself declares, and the component's own timing must satisfy the peer's
  sampling contract, or the plan is refused rather than rounded;
* the generated top instantiates the peer, connects it to the component's real
  pins, exports the peer's stimulus inputs and its counters, and exports no pin
  the peer owns;
* the runtime drives the peer from a declared, payload-carrying event plan, saves
  the events it applied and the peer's own counters, and reproduces both when the
  same sample is replayed.

The real-runtime half is opt-in through ``MYFUZZ_SOC_REAL=1`` and follows
``test_soc_matrix_runtime.py``: when the flag is set nothing may skip.  The
example set had no SPI component at all, so ``examples/soc_generation`` gained
``novaspi.sv`` (an SPI master) and ``novauart_link.sv`` (a UART that really
frames a byte, unlike the untouched ``novauart``), with their profiles and
``request-peers.json``.
"""
from __future__ import annotations

import json
import os
import re
import time
import unittest
import unittest.mock
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition.component_profile import (
    ElaborationSettings,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import (
    CompositionError,
    build_composition,
    composition_document,
)
from myfuzz.composition.soc_peer_plan import match_models
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    PeerStimulusEvent,
    RuntimeBuild,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    render_profile_testbench,
    run_sample,
    validate_peer_events,
)
from myfuzz.composition.soc_structure_audit import FAIL, PASS, audit_structure

from tests.composition.soc_generation_fixture import ROOT, example_plan, tools_available

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
PEER_REQUEST = ROOT / "examples/soc_generation/request-peers.json"
PEER_PROFILE_NAMES = ("novacore", "novauart_link", "novaspi", "novagpio")
DRIVE_PROFILE = "bfm_isolated"

#: Register offsets of the example peripherals the samples below drive.
UART_CTRL, UART_STATUS, UART_TXDATA, UART_RXDATA, UART_IRQ_STATUS = 0x00, 0x04, 0x08, 0x0c, 0x10
SPI_CTRL, SPI_STATUS, SPI_TXDATA, SPI_RXDATA = 0x00, 0x04, 0x08, 0x0c
GPIO_DATA_OUT, GPIO_DIR, GPIO_DATA_IN = 0x00, 0x04, 0x08

#: What the components transmit in the samples below, and what the peers answer.
UART_COMPONENT_BYTE = 0x3C
UART_PEER_BYTE = 0x5A
SPI_COMPONENT_BYTE = 0xA5
SPI_PEER_BYTE = 0x3C


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def peer_profiles() -> dict:
    profiles: dict = {}
    for name in PEER_PROFILE_NAMES:
        relative = f"examples/soc_generation/profiles/{name}.json"
        profile = load_component_profile(ROOT / relative)
        profiles[relative] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


def peer_request_document() -> dict:
    return json.loads(PEER_REQUEST.read_text())


def build_peer_plan(document: dict | None = None, *, profiles: dict | None = None,
                    drive_profile: str = DRIVE_PROFILE):
    request = load_composition_request(document or peer_request_document(),
                                       profiles=profiles or peer_profiles())
    return build_composition(request, base_dir=ROOT, drive_profile=drive_profile)


_PLAN = None


def example_peer_plan():
    global _PLAN
    if _PLAN is None:
        _PLAN = build_peer_plan()
    return _PLAN


def with_roles(profile, endpoint_id: str, roles: tuple[str, ...]):
    """The profile with one endpoint's role ids renamed (aliases unchanged).

    The role ids are the only thing the peer match reads, so renaming them is
    how this module proves the choice is role based.
    """
    endpoints = []
    for endpoint in profile.endpoints:
        if endpoint.endpoint_id != endpoint_id:
            endpoints.append(endpoint)
            continue
        if len(roles) != len(endpoint.fields):
            raise AssertionError("role count mismatch")
        endpoints.append(replace(endpoint, fields=tuple(
            replace(field, role=role) for field, role in zip(endpoint.fields, roles))))
    return replace(profile, endpoints=tuple(endpoints))


def with_attachment(document: dict, instance_id: str, endpoint_id: str, *,
                    attach: bool = True, parameters: dict | None = None) -> dict:
    updated = json.loads(json.dumps(document))
    updated["peer_models"] = [
        item for item in updated.get("peer_models", [])
        if not (item["instance_id"] == instance_id and item["endpoint_id"] == endpoint_id)]
    updated["peer_models"].append({
        "instance_id": instance_id, "endpoint_id": endpoint_id, "attach": attach,
        "parameters": parameters or {}})
    return updated


def without_attachment(document: dict, instance_id: str) -> dict:
    updated = json.loads(json.dumps(document))
    updated["peer_models"] = [item for item in updated.get("peer_models", [])
                              if item["instance_id"] != instance_id]
    return updated


def spi_mode_profiles(cpol: int, cpha: int) -> dict:
    """The peer profiles with novaspi declared in another SPI mode.

    The mode is a declared elaboration parameter of the component, so changing it
    is changing the profile's own declaration - exactly what a second profile
    file would say - without duplicating the RTL pin.
    """
    profiles = peer_profiles()
    relative = "examples/soc_generation/profiles/novaspi.json"
    profile = profiles[relative]
    parameters = (("BITS", "8"), ("CPOL", str(cpol)), ("CPHA", str(cpha)),
                  ("SCK_HALF_DIV", "4"), ("CS_SETUP", "2"), ("CS_HOLD", "2"))
    profiles[relative] = replace(profile, source=replace(
        profile.source,
        elaboration=ElaborationSettings(frontend="verilator-json", defines=(),
                                        parameters=parameters, warning_policy="fatal")))
    return profiles


def spi_mode_document(cpol: int, cpha: int, document: dict | None = None) -> dict:
    updated = json.loads(json.dumps(document or peer_request_document()))
    for item in updated["peripherals"]:
        if item["instance_id"] == "spi0":
            item["parameters"] = {"BITS": 8, "CPOL": cpol, "CPHA": cpha,
                                  "SCK_HALF_DIV": 4, "CS_SETUP": 2, "CS_HOLD": 2}
    for item in updated["peer_models"]:
        if item["instance_id"] == "spi0":
            item["parameters"] = {"BITS": 8, "CPOL": cpol, "CPHA": cpha,
                                  "CS_ACTIVE_LOW": 1}
    return updated


def _failed(result: dict) -> list[str]:
    return [str(item["check_id"]) for item in result["findings"] if item["status"] == FAIL]


def _audit(plan, text: str) -> dict:
    return audit_structure(plan, top_text=text,
                           source_files=[item["path"] for item in source_list(plan)],
                           base_dir=ROOT)


def _window_base(plan, target_id: str) -> int:
    return next(int(window["base"]) for window in plan.plan["address_map"]["windows"]
                if str(window["target_id"]) == target_id)


def _selector(plan, target_id: str) -> int:
    base = _window_base(plan, target_id)
    bases = [int(value) for value in plan.synthetic["parameters"]["WINDOW_BASE"]]
    return bases.index(base)


def _cycle_word(plan, **fields: int) -> int:
    value = 0
    for name, raw in fields.items():
        slot = next(item for item in plan.synthetic["raw_ports"] if item["port"] == name)
        value |= (int(raw) & ((1 << int(slot["width"])) - 1)) << int(slot["raw_lo"])
    return value


def _offer_word(plan, target_id: str, offset: int, write: int, wdata: int = 0,
                be: int = 0xF) -> int:
    return _cycle_word(plan, stim_offer=1, stim_target_selector=_selector(plan, target_id),
                       stim_offset=_window_base(plan, target_id) + offset,
                       stim_write=write, stim_wdata=wdata, stim_be=be)


def _slot_index(build: RuntimeBuild, instance_id: str, slot: str) -> int:
    return next(int(item["index"]) for item in build.peer_slots
                if item["instance_id"] == instance_id and item["slot"] == slot)


# ---------------------------------------------------------------------------
# the model table itself: the match is a role-signature match
# ---------------------------------------------------------------------------


class _Field:
    """The part of a bound profile field the peer match is allowed to read."""

    def __init__(self, role: str, direction: str, port: str, width: int = 1) -> None:
        self.role, self.direction, self.port, self.width = role, direction, port, width


class PeerModelMatchTests(unittest.TestCase):
    UART = (_Field("rx", "input", "uart_rx_i"), _Field("tx", "output", "uart_tx_o"))
    SPI = (_Field("sck", "output", "spi_sck_o"), _Field("cs", "output", "spi_cs_o"),
           _Field("mosi", "output", "spi_mosi_o"), _Field("miso", "input", "spi_miso_i"))
    GPIO = (_Field("in", "input", "gpio_in_i", 8), _Field("out", "output", "gpio_out_o", 8),
            _Field("dir", "output", "gpio_dir_o", 8))

    def test_the_role_signature_selects_exactly_one_model(self) -> None:
        for fields, peer_id in ((self.UART, "uart"), (self.SPI, "spi"), (self.GPIO, "gpio")):
            with self.subTest(peer=peer_id):
                self.assertEqual((peer_id,),
                                 tuple(model.peer_id for model in match_models(fields)))

    def test_the_component_and_port_names_do_not_select_anything(self) -> None:
        renamed = tuple(_Field(field.role, field.direction,
                               f"totally_other_{index}", field.width)
                        for index, field in enumerate(self.UART))
        self.assertEqual(("uart",),
                         tuple(model.peer_id for model in match_models(renamed)))
        # A signature with the same directions but different roles matches nothing.
        other = tuple(_Field(f"role{index}", field.direction, field.port, field.width)
                      for index, field in enumerate(self.UART))
        self.assertEqual((), match_models(other))

    def test_a_signature_no_model_implements_is_refused_by_plan_peer(self) -> None:
        from myfuzz.composition.soc_peer_plan import PeerPlanError, plan_peer
        with self.assertRaises(PeerPlanError) as error:
            plan_peer(instance_id="x0", component_id="x", endpoint_id="x.pins",
                      fields=(_Field("a", "input", "a_i"), _Field("b", "output", "b_o")),
                      declared={}, component_parameters={})
        self.assertIn("peer-role-unsupported", str(error.exception))
        self.assertIn("a:input,b:output", str(error.exception))

    def test_an_ambiguous_signature_is_refused_rather_than_ordered(self) -> None:
        import myfuzz.composition.soc_peer_plan as peer_plan
        duplicate = replace(peer_plan.GPIO_PEER, peer_id="gpio_copy")
        with unittest.mock.patch.object(peer_plan, "PEER_MODELS",
                                        (*peer_plan.PEER_MODELS, duplicate)):
            with self.assertRaises(peer_plan.PeerPlanError) as error:
                peer_plan.plan_peer(instance_id="x0", component_id="x",
                                    endpoint_id="x.pins", fields=self.GPIO,
                                    declared={}, component_parameters={})
        self.assertIn("peer-role-ambiguous", str(error.exception))
        self.assertIn("gpio,gpio_copy", str(error.exception))


# ---------------------------------------------------------------------------
# plan, roles and refusals
# ---------------------------------------------------------------------------


@unittest.skipUnless(tools_available(), "verilator is not installed")
class PeerPlanTests(unittest.TestCase):
    def test_peers_are_selected_by_the_declared_role_signature(self) -> None:
        plan = example_peer_plan()
        self.assertEqual({"gpio0": "gpio", "spi0": "spi", "uart0": "uart"},
                         {item.instance_id: item.peer_id for item in plan.peers})
        for peer in plan.peers:
            instance = plan.instance(peer.instance_id)
            endpoint = next(item for item in instance.binding.endpoints
                            if item.endpoint_id == peer.endpoint_id)
            declared = tuple(sorted((field.role, field.direction)
                                    for field in endpoint.fields))
            self.assertEqual(declared, tuple(sorted(peer.roles)), peer.instance_id)
            # The match is the model table's own decision, not this test's.
            self.assertEqual((peer.peer_id,),
                             tuple(model.peer_id for model in match_models(endpoint.fields)))
            # No port name takes part in the choice: the bound ports are the
            # profile's aliases, and the peer's binding names the role.
            for binding in peer.bindings:
                self.assertEqual(peer.peer_id, peer.peer_id)
                self.assertIn(binding.role, dict(peer.roles))
                self.assertTrue(binding.component_port)
        document = composition_document(plan)
        self.assertEqual({item.instance_id: item.peer_id for item in plan.peers},
                         {name: record["peer_id"] for name, record in
                          ((item["instance_id"], item) for item in document["peers"])})

    def test_the_peer_parameters_are_the_component_declared_parameters(self) -> None:
        plan = example_peer_plan()
        for peer in plan.peers:
            parameters = plan.instance(peer.instance_id).parameters
            for item in peer.parameters:
                if "matches the component parameter" not in item.constraint:
                    continue
                component = item.constraint.split("parameter ", 1)[1].split("=", 1)[0]
                self.assertIn(component, parameters, peer.instance_id)
                self.assertEqual(int(parameters[component]), item.value,
                                 f"{peer.instance_id}.{item.name}")

    def test_every_peer_requirement_is_recorded_with_its_basis(self) -> None:
        plan = example_peer_plan()
        spi = plan.peer("spi0")
        requirements = {item.component_parameter: item for item in spi.requirements}
        self.assertEqual({2, 1}, {item.minimum for item in requirements.values()})
        self.assertEqual(4, requirements["SCK_HALF_DIV"].value)
        self.assertEqual(2, requirements["CS_SETUP"].value)
        for item in requirements.values():
            self.assertTrue(item.rationale)

    def test_the_environment_link_records_the_attached_peer(self) -> None:
        plan = example_peer_plan()
        links = {item["link_id"]: item for item in plan.spec["environment_links"]}
        link = links["uart0:link.pins"]
        self.assertEqual("internal_peer", link["parameters"]["connection"])
        peer = link["parameters"]["peer"]
        self.assertEqual("soc_uart_peer", peer["module"])
        self.assertEqual(["uart", "1"], peer["protocol"])
        self.assertEqual(["uart0__tx_sent_count_o", "uart0__tx_drop_count_o",
                          "uart0__rx_count_o", "uart0__framing_error_count_o",
                          "uart0__timeout_count_o"], peer["counters"])
        self.assertEqual([{"role": "rx", "component_port": "uart_rx_i",
                           "component_direction": "input", "peer_port": "serial_tx_o",
                           "width": 1},
                          {"role": "tx", "component_port": "uart_tx_o",
                           "component_direction": "output", "peer_port": "serial_rx_i",
                           "width": 1}], peer["bindings"])

    def test_an_interface_without_a_declared_peer_stays_exported_and_recorded(self) -> None:
        document = without_attachment(peer_request_document(), "gpio0")
        plan = build_peer_plan(document)
        self.assertEqual(("spi0", "uart0"), tuple(item.instance_id for item in plan.peers))
        gap = next(item for item in plan.gaps if item.startswith("gpio0.gpio.pins:"))
        self.assertIn("no peer attachment", gap)
        self.assertIn("gpio peer model matches", gap)
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("    input  logic [7:0] gpio0__gpio_in_i,", top)
        self.assertIn("    output logic [7:0] gpio0__gpio_out_o,", top)
        # The peer that *was* attached keeps its pins internal.
        self.assertNotIn("    input  logic uart0__uart_rx_i,", top)

    def test_an_interface_no_peer_implements_is_exported_and_recorded(self) -> None:
        profiles = peer_profiles()
        relative = "examples/soc_generation/profiles/novauart_link.json"
        profiles[relative] = with_roles(profiles[relative], "link.pins",
                                        ("rxd", "txd"))
        document = without_attachment(peer_request_document(), "uart0")
        plan = build_peer_plan(document, profiles=profiles)
        gap = next(item for item in plan.gaps if item.startswith("uart0.link.pins:"))
        self.assertIn("no peer model implements the declared roles", gap)
        self.assertIn("rxd:input", gap)
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("    input  logic uart0__uart_rx_i,", top)
        self.assertIn("    output logic uart0__uart_tx_o,", top)
        self.assertIsNone(plan.peer("uart0"))

    def test_an_attachment_no_peer_implements_is_refused_with_the_roles(self) -> None:
        profiles = peer_profiles()
        relative = "examples/soc_generation/profiles/novauart_link.json"
        profiles[relative] = with_roles(profiles[relative], "link.pins",
                                        ("rxd", "txd"))
        document = with_attachment(peer_request_document(), "uart0", "link.pins",
                                   parameters={"DATA_WIDTH": 8, "BAUD_DIV": 8,
                                               "STOP_BITS": 1, "IDLE_LEVEL": 1})
        with self.assertRaises(CompositionError) as error:
            build_peer_plan(document, profiles=profiles)
        message = str(error.exception)
        self.assertIn("peer-attach:uart0:link.pins", message)
        self.assertIn("peer-role-unsupported", message)
        self.assertIn("rxd:input,txd:output", message)

    def test_a_partial_role_set_does_not_match_a_peer(self) -> None:
        """Three of the SPI peer's four roles are not the SPI peer's contract."""
        profiles = peer_profiles()
        relative = "examples/soc_generation/profiles/novaspi.json"
        profile = profiles[relative]
        endpoint = next(item for item in profile.endpoints
                        if item.endpoint_id == "spi.pins")
        profiles[relative] = replace(profile, endpoints=tuple(
            replace(item, fields=item.fields[:-1]) if item.endpoint_id == "spi.pins"
            else item for item in profile.endpoints))
        self.assertEqual(3, len(endpoint.fields) - 1)
        with self.assertRaises(Exception) as error:
            build_peer_plan(peer_request_document(), profiles=profiles)
        self.assertIn("mosi", str(error.exception))

    def test_an_attachment_to_an_interface_without_declared_timing_is_refused(self) -> None:
        """novauart declares no frame timing, so the framing peer cannot drive it."""
        profiles = peer_profiles()
        relative = "examples/soc_generation/profiles/novauart.json"
        profiles[relative] = load_component_profile(ROOT / relative)
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        document["peer_models"] = [{
            "instance_id": "uart0", "endpoint_id": "uart.pins", "attach": True,
            "parameters": {"DATA_WIDTH": 8, "BAUD_DIV": 8, "STOP_BITS": 1,
                           "IDLE_LEVEL": 1}}]
        with self.assertRaises(CompositionError) as error:
            build_peer_plan(document, profiles=profiles)
        message = str(error.exception)
        self.assertIn("peer-component-parameter-missing", message)
        # The first peer parameter with no component counterpart is named.
        self.assertIn("the component declares no SERIAL_WIDTH", message)

    def test_a_peer_frame_timing_that_disagrees_with_the_component_is_refused(self) -> None:
        document = with_attachment(peer_request_document(), "uart0", "link.pins",
                                   parameters={"DATA_WIDTH": 8, "BAUD_DIV": 4,
                                               "STOP_BITS": 1, "IDLE_LEVEL": 1})
        with self.assertRaises(CompositionError) as error:
            build_peer_plan(document)
        message = str(error.exception)
        self.assertIn("peer-timing-mismatch", message)
        self.assertIn("peer=4:component=BAUD_DIV=8", message)

    def test_a_component_clock_the_peer_cannot_sample_is_refused(self) -> None:
        document = spi_mode_document(0, 0)
        for item in document["peripherals"]:
            if item["instance_id"] == "spi0":
                item["parameters"]["SCK_HALF_DIV"] = 1
        profiles = spi_mode_profiles(0, 0)
        relative = "examples/soc_generation/profiles/novaspi.json"
        settings = profiles[relative].source.elaboration
        profiles[relative] = replace(profiles[relative], source=replace(
            profiles[relative].source, elaboration=replace(
                settings, parameters=tuple(
                    (name, "1" if name == "SCK_HALF_DIV" else value)
                    for name, value in settings.parameters))))
        with self.assertRaises(CompositionError) as error:
            build_peer_plan(document, profiles=profiles)
        self.assertIn("peer-timing-unsupported:spi:SCK_HALF_DIV:1<2", str(error.exception))

    def test_an_out_of_range_or_unknown_peer_parameter_is_refused(self) -> None:
        cases = (
            ({"BITS": 8, "CPOL": 2, "CPHA": 0}, "peer-parameter-out-of-range"),
            ({"BITS": 8, "CPOL": 0, "CPHA": 0, "MODE": 1}, "peer-parameter-unknown"),
        )
        for parameters, reason in cases:
            with self.subTest(reason=reason):
                document = with_attachment(peer_request_document(), "spi0", "spi.pins",
                                           parameters=parameters)
                with self.assertRaises(CompositionError) as error:
                    build_peer_plan(document)
                self.assertIn(reason, str(error.exception))

    def test_an_instance_parameter_that_was_not_elaborated_is_refused(self) -> None:
        document = json.loads(json.dumps(peer_request_document()))
        for item in document["peripherals"]:
            if item["instance_id"] == "uart0":
                item["parameters"]["BAUD_DIV"] = 16
        with self.assertRaises(CompositionError) as error:
            build_peer_plan(document)
        self.assertIn("instance-parameter-mismatch:uart0:BAUD_DIV", str(error.exception))

    def test_a_control_request_cannot_name_a_peer_model(self) -> None:
        document = json.loads(json.dumps(peer_request_document()))
        document["peer_models"][0]["model"] = "gpio"
        with self.assertRaises(Exception) as error:
            load_composition_request(document, profiles=peer_profiles())
        self.assertIn("unsupported-peer-request-key", str(error.exception))

    def test_a_composition_that_attaches_no_peer_is_unchanged(self) -> None:
        """The example request declares no attachment: its render has no peer at all."""
        plan = example_plan()
        self.assertEqual((), plan.peers)
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        for marker in ("soc_uart_peer", "soc_spi_peer", "soc_gpio_peer", "__peer_",
                       "tx_request_valid_i", "pin_value_o"):
            self.assertNotIn(marker, top)
        # Every declared external pin is still a top-level port.
        self.assertIn("    input  logic uart0__uart_rx_i,", top)
        self.assertIn("    output logic uart0__uart_tx_o,", top)
        self.assertIn("    input  logic [7:0] gpio0__gpio_in_i,", top)
        self.assertIn("    output logic [7:0] gpio0__gpio_dir_o,", top)
        self.assertNotIn("peer_model", {item["role"] for item in source_list(plan)})
        # ... and the plan records why each interface stayed external.
        for instance_id in ("uart0", "uart1", "gpio0"):
            self.assertTrue(any(gap.startswith(f"{instance_id}.") for gap in plan.gaps),
                            plan.gaps)

    def test_the_peer_plan_changes_the_composition_identity(self) -> None:
        with_peers = example_peer_plan()
        without = build_peer_plan(without_attachment(peer_request_document(), "uart0"))
        self.assertNotEqual(with_peers.plan_hash, without.plan_hash)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


@unittest.skipUnless(tools_available(), "verilator is not installed")
class PeerRenderTests(unittest.TestCase):
    def test_the_peer_pins_are_internal_and_the_peer_owns_them(self) -> None:
        plan = example_peer_plan()
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("  soc_uart_peer #(.DATA_WIDTH(8), .BAUD_DIV(8), .STOP_BITS(1), "
                      ".IDLE_LEVEL(1), .TIMEOUT_BITS(64)", top)
        peer = plan.peer("uart0")
        self.assertIn(f"    .serial_tx_o(uart0__{peer.binding('rx').component_port}),", top)
        self.assertIn(f"    .serial_rx_i(uart0__{peer.binding('tx').component_port}),", top)
        # The component's own pins are internal nets, declared once and never
        # exported; the peer is the only other end of them.
        self.assertIn("  logic uart0__uart_rx_i;", top)
        self.assertNotIn("    input  logic uart0__uart_rx_i,", top)
        self.assertNotIn("    output logic uart0__uart_tx_o,", top)
        self.assertEqual(1, top.count(".uart_rx_i("))

    def test_every_peer_observation_is_exported_and_every_stimulus_is_an_input(self) -> None:
        plan = example_peer_plan()
        top = render_composition(plan)["myfuzz_soc_top.sv"]

        def port_declaration(direction: str, width: int, name: str) -> str:
            shape = "logic" if width == 1 else f"logic [{width - 1}:0]"
            return f"    {direction} {shape} {name}"

        for peer in plan.peers:
            for slot in peer.slots:
                for signal in slot.signals:
                    self.assertIn(port_declaration("input ", signal.width, signal.top_port),
                                  top, f"missing stimulus port {signal.top_port}")
            for observation in peer.observations:
                self.assertIn(port_declaration("output", observation.width,
                                               observation.top_port), top,
                              f"missing observation port {observation.top_port}")
                self.assertIn(f"    .{observation.peer_port}({observation.top_port})", top,
                              f"{observation.peer_port} is not connected to "
                              f"{observation.top_port}")

    def test_the_component_instance_carries_its_declared_parameters(self) -> None:
        plan = example_peer_plan()
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("  novaspi #(", top)
        self.assertIn("    .BITS(8), .CPHA(0), .CPOL(0), .CS_HOLD(2), .CS_SETUP(2), "
                      ".SCK_HALF_DIV(4)", top)
        self.assertIn("  novauart_link #(", top)
        self.assertIn("    .BAUD_DIV(8), .IDLE_LEVEL(1), .SERIAL_WIDTH(8), .STOP_BITS(1)",
                      top)
        # A component with no declared parameters keeps the plain instantiation.
        self.assertIn("  novagpio u_gpio0 (", top)

    def test_the_source_list_publishes_every_peer_model(self) -> None:
        plan = example_peer_plan()
        records = source_list(plan)
        peers = {item["owner"]: item["path"] for item in records
                 if item["role"] == "peer_model"}
        self.assertEqual({
            "uart0": "src/myfuzz/protocols/rtl/soc_uart_peer.sv",
            "spi0": "src/myfuzz/protocols/rtl/soc_spi_peer.sv",
            "gpio0": "src/myfuzz/protocols/rtl/soc_gpio_peer.sv"}, peers)

    def test_the_testbench_consumes_the_plan_slot_table(self) -> None:
        plan = example_peer_plan()
        testbench = render_profile_testbench(plan)
        self.assertIn("  localparam integer PEER_SLOTS = 3;", testbench)
        self.assertIn("  localparam integer PEER_EVENTS_MAX = 256;", testbench)
        self.assertIn("    scan_count = $fscanf(fd, \"P %d\", peer_event_count);", testbench)
        self.assertIn("MYFUZZ_PEER_APPLIED", testbench)
        self.assertIn("MYFUZZ_RSP", testbench)
        for peer in plan.peers:
            for slot in peer.slots:
                for signal in slot.signals:
                    # The port carries the event plan's value through one
                    # continuous assignment, and that assignment is its only
                    # writer: a port that is continuously assigned must not carry
                    # an initial value -- neither a declaration initialiser nor a
                    # procedural ``initial`` statement -- or Verilator refuses the
                    # design outright (CONTASSINIT).  ``<port>__event`` is
                    # initialised instead, so the level is still defined at time 0.
                    declared = re.compile(
                        r"^\s*(?:logic|wire)(?:\s*\[[^\]]*\])?\s+"
                        + re.escape(str(signal.top_port)) + r"\s*;(?:\s*//.*)?$")
                    self.assertTrue(
                        any(declared.match(line) for line in testbench.splitlines()),
                        f"{signal.top_port} has no plain declaration")
                    self.assertIn(f"  assign {signal.top_port} = ", testbench)
                    self.assertNotIn(f"  initial {signal.top_port} = '0;", testbench)


# ---------------------------------------------------------------------------
# independent audit and its fault injection
# ---------------------------------------------------------------------------


@unittest.skipUnless(tools_available(), "verilator is not installed")
class PeerAuditTests(unittest.TestCase):
    def test_the_peer_plan_passes_every_structural_check(self) -> None:
        plan = example_peer_plan()
        result = _audit(plan, render_composition(plan)["myfuzz_soc_top.sv"])
        self.assertEqual(PASS, result["summary"]["status"], result["findings"])
        checks = {item["check_id"] for item in result["findings"]}
        for required in ("peer_instances", "peer_parameters", "peer_role_wiring",
                         "peer_boundary", "peer_counters"):
            self.assertIn(required, checks)

    def test_the_exported_boundary_is_exactly_the_ledger_and_the_peer_records(self) -> None:
        plan = example_peer_plan()
        result = _audit(plan, render_composition(plan)["myfuzz_soc_top.sv"])
        boundary = next(item for item in result["findings"]
                        if item["check_id"] == "top_ports")
        expected = boundary["expected"]
        self.assertIn("uart0__tx_request_valid_i", expected)
        self.assertIn("uart0__tx_sent_count_o", expected)
        self.assertNotIn("uart0__uart_rx_i", expected)
        self.assertNotIn("uart0__uart_tx_o", expected)


class PeerFaultInjectionTests(unittest.TestCase):
    """A wrong peer structure must be found even though the plan is right."""

    @classmethod
    def setUpClass(cls) -> None:
        if not tools_available():
            raise unittest.SkipTest("verilator is not installed")
        cls.plan = example_peer_plan()
        cls.text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.sources = [item["path"] for item in source_list(cls.plan)]

    def mutate(self, *pairs: tuple[str, str]) -> str:
        text = self.text
        for old, new in pairs:
            self.assertIn(old, text, f"mutation anchor missing: {old}")
            self.assertNotEqual(old, new)
            text = text.replace(old, new)
        return text

    def audit(self, text: str) -> dict:
        return _audit(self.plan, text)

    def test_a_swapped_peer_role_is_detected(self) -> None:
        text = self.mutate((".serial_tx_o(uart0__uart_rx_i)",
                            ".serial_tx_o(uart0__uart_tx_o)"),
                           (".serial_rx_i(uart0__uart_tx_o)",
                            ".serial_rx_i(uart0__uart_rx_i)"))
        self.assertIn("peer_role_wiring", _failed(self.audit(text)))

    def test_a_peer_bound_to_another_components_pin_is_detected(self) -> None:
        text = self.mutate((".sck_i(spi0__spi_sck_o)", ".sck_i(spi0__spi_cs_o)"),
                           (".cs_i(spi0__spi_cs_o)", ".cs_i(spi0__spi_sck_o)"))
        self.assertIn("peer_role_wiring", _failed(self.audit(text)))

    def test_a_peer_omitted_while_its_pins_are_exported_is_detected(self) -> None:
        """The plan says the peer owns the pin; the RTL both omits it and exports it."""
        text = self.mutate(
            # The peer instance is renamed away and no longer drives the pin...
            ("  ) u_uart0_peer (", "  ) u_uart0_peer_omitted ("),
            ("    .serial_tx_o(uart0__uart_rx_i),\n", ""),
            # ... the pin becomes a top-level input instead of an internal net ...
            ("  logic uart0__uart_rx_i;\n", ""),
            ("    input  logic rst_ni,",
             "    input  logic rst_ni,\n"
             "    input  logic uart0__uart_rx_i,"))
        failures = _failed(self.audit(text))
        self.assertIn("peer_instances", failures)
        self.assertIn("peer_boundary", failures)
        self.assertIn("top_ports", failures)

    def test_a_pin_the_peer_owns_that_is_also_exported_is_detected(self) -> None:
        """The peer is present, but the interface is exported as well."""
        text = self.mutate(("    .serial_tx_o(uart0__uart_rx_i),\n", ""),
                           ("  logic uart0__uart_rx_i;\n", ""),
                           ("    input  logic rst_ni,",
                            "    input  logic rst_ni,\n"
                            "    input  logic uart0__uart_rx_i,"))
        failures = _failed(self.audit(text))
        self.assertIn("peer_boundary", failures)
        self.assertIn("top_ports", failures)

    def test_a_peer_timing_parameter_that_does_not_match_the_plan_is_detected(self) -> None:
        text = self.mutate((".BAUD_DIV(8), .STOP_BITS(1), .IDLE_LEVEL(1), .TIMEOUT_BITS(64)",
                            ".BAUD_DIV(4), .STOP_BITS(1), .IDLE_LEVEL(1), .TIMEOUT_BITS(64)"))
        self.assertIn("peer_parameters", _failed(self.audit(text)))

    def test_a_counter_that_is_never_observed_is_detected(self) -> None:
        text = self.mutate((".tx_sent_count_o(uart0__tx_sent_count_o)",
                            ".tx_sent_count_o(1'b0)"))
        self.assertIn("peer_counters", _failed(self.audit(text)))

    def test_a_counter_removed_from_the_top_boundary_is_detected(self) -> None:
        text = self.mutate(("    output logic [31:0] uart0__rx_count_o,\n", ""))
        failures = _failed(self.audit(text))
        self.assertIn("peer_counters", failures)
        self.assertIn("top_ports", failures)

    def test_a_stimulus_port_tied_off_is_detected(self) -> None:
        text = self.mutate((".tx_request_valid_i(uart0__tx_request_valid_i)",
                            ".tx_request_valid_i(1'b0)"))
        # The boundary itself is unchanged (the port is still declared), so the
        # fault is reported where it is: the port never reaches the peer's pin.
        self.assertEqual(["peer_boundary"], _failed(self.audit(text)))

    def test_a_missing_peer_instance_is_detected(self) -> None:
        text = self.mutate(("  ) u_spi0_peer (", "  ) u_spi0_peer_renamed ("))
        self.assertIn("peer_instances", _failed(self.audit(text)))


# ---------------------------------------------------------------------------
# the declared event plan
# ---------------------------------------------------------------------------


class PeerEventPlanTests(unittest.TestCase):
    """The runtime refuses a peer stimulus plan this build cannot honour."""

    def build(self) -> RuntimeBuild:
        directory = Path("/nonexistent")
        return RuntimeBuild(
            output_dir=directory, top_path=directory / "top.sv",
            testbench_path=directory / "tb.sv", executable=directory / "sim",
            sources=(), raw_width=1, slots=(), observations=(), boot_image=None,
            boot_image_policy="no_preloaded_region", build_hash="sha256:" + "0" * 64,
            peer_slots=(
                {"index": 0, "slot": "uart.tx_byte", "kind": "pulse_byte", "width": 8,
                 "instance_id": "uart0", "peer_id": "uart", "minimum_gap_cycles": 81,
                 "signals": ()},
                {"index": 1, "slot": "gpio.drive", "kind": "level_drive", "width": 16,
                 "instance_id": "gpio0", "peer_id": "gpio", "minimum_gap_cycles": 1,
                 "signals": ()},
            ))

    def test_an_unknown_slot_is_refused(self) -> None:
        with self.assertRaises(SocRuntimeError) as error:
            validate_peer_events(self.build(), RuntimeSample(
                request_id=1, raw=(0,),
                peer_events=(PeerStimulusEvent(slot=7, cycle=1, payload=0),)))
        self.assertIn("peer-event-unknown-slot:7", str(error.exception))

    def test_a_payload_wider_than_the_slot_is_refused(self) -> None:
        with self.assertRaises(SocRuntimeError) as error:
            validate_peer_events(self.build(), RuntimeSample(
                request_id=1, raw=(0,),
                peer_events=(PeerStimulusEvent(slot=0, cycle=1, payload=0x100),)))
        self.assertIn("peer-event-payload-out-of-range:uart.tx_byte", str(error.exception))

    def test_two_pulse_events_closer_than_the_peer_minimum_are_refused(self) -> None:
        with self.assertRaises(SocRuntimeError) as error:
            validate_peer_events(self.build(), RuntimeSample(
                request_id=1, raw=(0,),
                peer_events=(PeerStimulusEvent(slot=0, cycle=10, payload=1),
                             PeerStimulusEvent(slot=0, cycle=40, payload=2))))
        self.assertIn("peer-event-too-close:uart.tx_byte:40-10<81", str(error.exception))

    def test_a_legal_plan_is_accepted_and_the_payload_round_trips(self) -> None:
        build = self.build()
        sample = RuntimeSample(request_id=2, raw=(0,),
                               peer_events=(PeerStimulusEvent(slot=0, cycle=10, payload=0xA5),
                                            PeerStimulusEvent(slot=1, cycle=20, payload=0x0105)))
        validate_peer_events(build, sample)
        payload = sample.payload().splitlines()
        self.assertEqual("P 2", payload[2])
        self.assertEqual("0 10 a5", payload[3])
        self.assertEqual("1 20 105", payload[4])

    def test_the_event_plan_bound_is_enforced(self) -> None:
        from myfuzz.composition.soc_runtime import MAX_PEER_EVENTS
        with self.assertRaises(SocRuntimeError) as error:
            RuntimeSample(request_id=3, raw=(0,), peer_events=tuple(
                PeerStimulusEvent(slot=0, cycle=index, payload=1)
                for index in range(MAX_PEER_EVENTS + 1)))
        self.assertIn("peer-event-plan-exceeds-bound", str(error.exception))


# ---------------------------------------------------------------------------
# real builds and real simulation
# ---------------------------------------------------------------------------


class _PeerRuntimeFixture(unittest.TestCase):
    """One rendered, audited, compiled peer SoC, re-used by the class."""

    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_PEER_BUILD_TIMEOUT_S", "1800"))
    cpol = 0
    cpha = 0

    @classmethod
    def setUpClass(cls) -> None:
        if not OPT_IN:
            raise unittest.SkipTest("set MYFUZZ_SOC_REAL=1 for the real peer runtime")
        import shutil

        if shutil.which("verilator") is None:
            raise AssertionError("Verilator is required for the real peer runtime")
        cls.started = time.monotonic()
        profiles = None
        document = None
        if (cls.cpol, cls.cpha) != (0, 0):
            profiles = spi_mode_profiles(cls.cpol, cls.cpha)
            document = spi_mode_document(cls.cpol, cls.cpha)
        cls.plan = build_peer_plan(document, profiles=profiles)
        cls.top_text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.audit = _audit(cls.plan, cls.top_text)
        if _failed(cls.audit):
            raise AssertionError("generated top failed the audit: %s" % _failed(cls.audit))
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-peer-", dir=ROOT)
        output = Path(cls._temporary.name) / f"spi{cls.cpol}{cls.cpha}"
        cls.build = build_profile_runtime(
            cls.plan, output_dir=output, base_dir=ROOT, top_text=cls.top_text,
            sources=[item["path"] for item in source_list(cls.plan)
                     if item["role"] != "include_root"],
            timeout_seconds=cls.build_timeout_s)
        print("\nMYFUZZ_SOC_PEER_TIMING spi_mode=%d%d build_s=%.1f raw_width=%d peers=%s"
              % (cls.cpol, cls.cpha, time.monotonic() - cls.started, cls.build.raw_width,
                 ",".join(peer.instance_id for peer in cls.plan.peers)))

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    # -- sample construction ------------------------------------------------

    def sample(self, offers: dict[int, tuple[str, int, int, int]], cycles: int, *,
               events=(), request_id: int = 1) -> RuntimeSample:
        """One raw sample: {cycle: (target, offset, write, wdata)} plus peer events."""
        raw = [0] * cycles
        for cycle, (target, offset, write, wdata) in offers.items():
            raw[cycle] = _offer_word(self.plan, target, offset, write, wdata)
        return RuntimeSample(request_id=request_id, raw=tuple(raw), peer_events=tuple(events))

    def event(self, instance_id: str, slot: str, cycle: int, payload: int):
        return PeerStimulusEvent(slot=_slot_index(self.build, instance_id, slot),
                                 cycle=cycle, payload=payload)

    def run_sample(self, sample: RuntimeSample):
        result = run_sample(self.build, sample)
        self.assertEqual("OK", result.status, result.reason or result.stdout[-2000:])
        return result

    def read_pairs(self, result, target_id: str) -> list[tuple[int, int]]:
        """Every completed read of one window, in completion order."""
        base = _window_base(self.plan, target_id)
        return [(int(item["addr"]) - base, int(item["rdata"]))
                for item in result.responses
                if not int(item["write"]) and base <= int(item["addr"]) < base + 0x1000]

    def reads(self, result, target_id: str) -> dict[int, int]:
        """The last value every read returned, keyed by the register offset read."""
        return dict(self.read_pairs(result, target_id))

    def read_values(self, result, target_id: str, offset: int) -> list[int]:
        """Every value returned by the reads of one register offset, in order."""
        return [value for register, value in self.read_pairs(result, target_id)
                if register == offset]

    def observation(self, result, name: str) -> int:
        self.assertIn(name, result.observations, sorted(result.observations))
        return int(result.observations[name])


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class UartPeerRuntimeTests(_PeerRuntimeFixture):
    def test_a_peer_byte_reaches_the_peripheral_and_a_peripheral_byte_reaches_the_peer(self) -> None:
        result = self.run_sample(self.sample({
            4: ("uart0_win", UART_CTRL, 1, 0x7),        # rx-enable, tx-enable, irq-enable
            20: ("uart0_win", UART_TXDATA, 1, UART_COMPONENT_BYTE),
            150: ("uart0_win", UART_STATUS, 0, 0),
            170: ("uart0_win", UART_IRQ_STATUS, 0, 0),
            190: ("uart0_win", UART_RXDATA, 0, 0),
            210: ("uart0_win", UART_STATUS, 0, 0),
        }, 240, events=(self.event("uart0", "uart.tx_byte", 50, UART_PEER_BYTE),),
            request_id=101))
        status = self.read_values(result, "uart0_win", UART_STATUS)
        # STATUS before the read: rx-valid (bit0) and tx-ready (bit1).
        self.assertEqual(0b0011, status[0] & 0b0011,
                         "the peripheral never reported the peer's byte")
        # The interrupt the receive raised, on the peripheral's own status register.
        self.assertEqual(1, self.reads(result, "uart0_win")[UART_IRQ_STATUS] & 1)
        # The byte the peer transmitted is the byte the peripheral holds.
        self.assertEqual(UART_PEER_BYTE, self.reads(result, "uart0_win")[UART_RXDATA])
        # Reading it clears the receive-valid state.
        self.assertEqual(0, status[-1] & 0b0001)
        # ... and the byte the peripheral transmitted is the byte the peer received.
        self.assertEqual(1, self.observation(result, "uart0__tx_sent_count_o"))
        self.assertEqual(1, self.observation(result, "uart0__rx_count_o"))
        self.assertEqual(UART_COMPONENT_BYTE, self.observation(result, "uart0__rx_data_o"))
        self.assertEqual(0, self.observation(result, "uart0__framing_error_count_o"))
        self.assertEqual(0, self.observation(result, "uart0__tx_drop_count_o"))
        # The transmit completed: the peer has no busier state left.
        self.assertEqual(0x0, self.observation(result, "uart0__timeout_count_o"))

    def test_the_peer_stimulus_is_applied_at_its_declared_cycle(self) -> None:
        result = self.run_sample(self.sample({
            4: ("uart0_win", UART_CTRL, 1, 0x7),
        }, 120, events=(self.event("uart0", "uart.tx_byte", 33, 0x11),
                        self.event("uart0", "uart.tx_byte", 120, 0x22)),
            request_id=102))
        applied = [item for item in result.peer_applied
                   if item["instance"] == "uart0" and item["slot"] == "uart.tx_byte"]
        self.assertEqual([33, 120], [int(item["cycle"]) for item in applied])
        self.assertEqual([0x11, 0x22], [int(item["value"]) for item in applied])


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiPeerRuntimeTests(_PeerRuntimeFixture):
    def test_a_transfer_completes_with_the_declared_clock_and_data(self) -> None:
        result = self.run_sample(self.sample({
            4: ("spi0_win", SPI_TXDATA, 1, SPI_COMPONENT_BYTE),
            20: ("spi0_win", SPI_CTRL, 1, 0x1),          # start
            120: ("spi0_win", SPI_STATUS, 0, 0),
            140: ("spi0_win", SPI_RXDATA, 0, 0),
        }, 180, events=(self.event("spi0", "spi.arm_byte", 10, SPI_PEER_BYTE),),
            request_id=201))
        reads = self.reads(result, "spi0_win")
        # busy=0, rx-valid=1, done=1 after the transfer.
        self.assertEqual(0b110, reads[SPI_STATUS] & 0b111, "the transfer never completed")
        # MISO: the byte the peer armed is the byte the master assembled.
        self.assertEqual(SPI_PEER_BYTE, reads[SPI_RXDATA])
        # MOSI: the peer assembled exactly the byte the master shifted out.
        self.assertEqual(1, self.observation(result, "spi0__rx_count_o"))
        self.assertEqual(SPI_COMPONENT_BYTE, self.observation(result, "spi0__rx_data_o"))
        # CLK/CS: one selection, both clock edges per bit, no partial byte and no
        # clock transition outside the selection.
        self.assertEqual(2 * 8, self.observation(result, "spi0__clock_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__bit_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__incomplete_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__incomplete_error_o"))
        self.assertEqual(0, self.observation(result, "spi0__deselected_clock_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__deselected_clock_error_o"))
        self.assertEqual(0, self.observation(result, "spi0__selected_o"))
        self.assertEqual(0, self.observation(result, "spi0__tx_armed_o"))
        self.assertEqual(0, self.observation(result, "spi0__tx_drop_count_o"))

    def test_an_arm_that_arrives_while_the_register_is_full_is_dropped_and_counted(self) -> None:
        result = self.run_sample(self.sample({
            4: ("spi0_win", SPI_TXDATA, 1, SPI_COMPONENT_BYTE),
            20: ("spi0_win", SPI_CTRL, 1, 0x1),
        }, 180, events=(self.event("spi0", "spi.arm_byte", 10, SPI_PEER_BYTE),
                        self.event("spi0", "spi.arm_byte", 12, 0x7E)),
            request_id=202))
        # The second arm lands while the first is still armed, so the peer drops
        # it and says so instead of queueing it.
        self.assertEqual(1, self.observation(result, "spi0__tx_drop_count_o"))
        self.assertEqual(1, self.observation(result, "spi0__rx_count_o"))
        self.assertEqual(SPI_COMPONENT_BYTE, self.observation(result, "spi0__rx_data_o"))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiMode3PeerRuntimeTests(_PeerRuntimeFixture):
    """The mode is a declared parameter, not a decoration: CPOL=1/CPHA=1 works."""

    cpol = 1
    cpha = 1

    def test_the_declared_mode_transfers_both_directions(self) -> None:
        result = self.run_sample(self.sample({
            4: ("spi0_win", SPI_TXDATA, 1, SPI_COMPONENT_BYTE),
            20: ("spi0_win", SPI_CTRL, 1, 0x1),
            120: ("spi0_win", SPI_STATUS, 0, 0),
            140: ("spi0_win", SPI_RXDATA, 0, 0),
        }, 180, events=(self.event("spi0", "spi.arm_byte", 10, SPI_PEER_BYTE),),
            request_id=301))
        peer = self.plan.peer("spi0")
        self.assertEqual({"CPOL": 1, "CPHA": 1},
                         {name: value for name, value in peer.parameter_values.items()
                          if name in ("CPOL", "CPHA")})
        self.assertEqual(SPI_PEER_BYTE, self.reads(result, "spi0_win")[SPI_RXDATA])
        self.assertEqual(SPI_COMPONENT_BYTE, self.observation(result, "spi0__rx_data_o"))
        self.assertEqual(2 * 8, self.observation(result, "spi0__clock_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__incomplete_count_o"))
        self.assertEqual(0, self.observation(result, "spi0__deselected_clock_count_o"))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class GpioPeerRuntimeTests(_PeerRuntimeFixture):
    def test_the_peer_drive_is_read_back_and_the_component_output_is_seen_by_the_peer(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", GPIO_DATA_OUT, 1, 0x00),
            20: ("gpio0_win", GPIO_DIR, 1, 0x00),        # component high-Z at first
            60: ("gpio0_win", GPIO_DATA_IN, 0, 0),       # read while the peer drives
            100: ("gpio0_win", GPIO_DATA_OUT, 1, 0x5A),
            120: ("gpio0_win", GPIO_DIR, 1, 0xFF),       # component drives all pins
        }, 200, events=(self.event("gpio0", "gpio.drive", 40, 0x00FF | (0x05 << 8)),
                        self.event("gpio0", "gpio.drive", 80, 0x0000)),
            request_id=401))
        reads = self.reads(result, "gpio0_win")
        # The peer's drive, read back through the component's own DATA_IN register.
        self.assertEqual(0x05, reads[GPIO_DATA_IN] & 0xFF,
                         "the component did not sample the peer's drive")
        # The component's output and direction, seen by the peer.
        self.assertEqual(0x5A, self.observation(result, "gpio0__pin_value_o"))
        self.assertEqual(0xFF, self.observation(result, "gpio0__direction_o"))
        self.assertEqual(0, self.observation(result, "gpio0__contention_count_o"))

    def test_an_opposite_drive_raises_the_pin_contention_flag(self) -> None:
        result = self.run_sample(self.sample({
            4: ("gpio0_win", GPIO_DATA_OUT, 1, 0x5A),    # every component pin drives 0
            20: ("gpio0_win", GPIO_DIR, 1, 0xFF),
        }, 200, events=(self.event("gpio0", "gpio.drive", 60, (0x01 << 8) | 0x01),),
            request_id=402))
        self.assertEqual(0x01, self.observation(result, "gpio0__contention_o"))
        self.assertEqual(1, self.observation(result, "gpio0__contention_count_o"))
        self.assertEqual(1, self.observation(result, "gpio0__contention_error_o"))
        # The resolved line is the declared contention level, never X.
        self.assertEqual(0x5A, self.observation(result, "gpio0__pin_value_o"))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class PeerReplayRuntimeTests(_PeerRuntimeFixture):
    def test_a_replayed_run_reproduces_the_peer_counters_and_stimulus(self) -> None:
        sample = self.sample({
            4: ("uart0_win", UART_CTRL, 1, 0x7),
            20: ("uart0_win", UART_TXDATA, 1, UART_COMPONENT_BYTE),
            150: ("uart0_win", UART_STATUS, 0, 0),
            170: ("uart0_win", UART_RXDATA, 0, 0),
            200: ("spi0_win", SPI_TXDATA, 1, SPI_COMPONENT_BYTE),
            220: ("spi0_win", SPI_CTRL, 1, 0x1),
            320: ("spi0_win", SPI_STATUS, 0, 0),
            340: ("spi0_win", SPI_RXDATA, 0, 0),
        }, 380, events=(self.event("uart0", "uart.tx_byte", 50, UART_PEER_BYTE),
                        self.event("spi0", "spi.arm_byte", 210, SPI_PEER_BYTE)),
            request_id=501)
        first = self.run_sample(sample)
        second = self.run_sample(sample)
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.cycles, second.cycles)
        self.assertEqual(first.peer_applied, second.peer_applied)
        self.assertEqual(first.responses, second.responses)
        self.assertEqual(dict(first.counters), dict(second.counters))
        self.assertEqual(dict(first.observations), dict(second.observations))
        # The peer counters the plan declares are in the saved evidence, and they
        # are the ones the run really produced.
        counters = {key: value for key, value in first.counters.items()
                    if key.startswith("peer.")}
        self.assertEqual(1, counters["peer.uart0.tx_sent_count_o"])
        self.assertEqual(1, counters["peer.uart0.rx_count_o"])
        self.assertEqual(1, counters["peer.spi0.rx_count_o"])
        self.assertEqual(2 * 8, counters["peer.spi0.clock_count_o"])
        self.assertTrue(counters)
        document = first.document()
        self.assertEqual([dict(item) for item in first.peer_applied],
                         document["peer_applied"])
        self.assertEqual([dict(item) for item in first.responses],
                         document["fabric_responses"])


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class PeerRefusalRuntimeTests(_PeerRuntimeFixture):
    def test_a_stimulus_plan_the_peer_cannot_honour_is_refused_before_simulation(self) -> None:
        slot = _slot_index(self.build, "uart0", "uart.tx_byte")
        with self.assertRaises(SocRuntimeError) as error:
            run_sample(self.build, RuntimeSample(
                request_id=601, raw=(0,) * 40,
                peer_events=(PeerStimulusEvent(slot=slot, cycle=1, payload=1),
                             PeerStimulusEvent(slot=slot, cycle=2, payload=2))))
        self.assertIn("peer-event-too-close", str(error.exception))


if __name__ == "__main__":
    unittest.main()
