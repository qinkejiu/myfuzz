"""Real pinned Ibex (``ibex_top``) as a ``component_profile.v1``.

This module proves three things and refuses to prove a fourth:

* the profile loads, the pinned closure elaborates with verilator and every
  declared role binds to a real ``ibex_top`` port of the declared direction and
  width;
* the port-disposition ledger classifies every elaborated port *and every bit*
  of it, with constants that fit their port and observations that are real
  component outputs;
* the profile fails closed: a missing disposition, an out-of-range constant, a
  wrong action kind, a mis-declared binding and an action on a port the bounded
  elaboration does not select are all reported, never repaired.

It does *not* claim the composed SoC runs: the aggregate ``ram_cfg_icache_*``
ports of ``ibex_top`` are not representable by the current verilator-json port
extractor, so ``source.top_port_selection`` is ``declared`` and those four ports
are deliberately outside the elaboration.  The test asserts that this gap is
recorded in ``evidence.unknown`` rather than hidden.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    DISPOSITION_KINDS,
    ComponentProfileError,
    PortAction,
    bind_profile,
    elaborate_profile,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_port_dispositions import (
    PortDispositionError,
    build_port_dispositions,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "configs/cpus/ibex/component_profile.json"
OFFICIAL_PATH = ROOT / "configs/cpus/ibex/official_core_interface_description.json"
MATRIX_PATH = ROOT / "configs/soc/ibex-pulp.json"
SOURCE_ROOT = ROOT / "third_party/rfuzz/upstream/ibex"
REQUEST_PATH = ROOT / "examples/soc_generation/request-ibex.json"
UART_PATH = ROOT / "examples/soc_generation/profiles/novauart.json"
GPIO_PATH = ROOT / "examples/soc_generation/profiles/novagpio.json"

#: The four top-level aggregate ports the port extractor cannot represent, with
#: the shape the RTL declares for them.
AGGREGATE_PORTS = (
    "ram_cfg_icache_tag_i",
    "ram_cfg_icache_tag_o",
    "ram_cfg_icache_data_i",
    "ram_cfg_icache_data_o",
)

#: The ports the declared endpoints, the clock and the reset bind.
DECLARED_FUNCTIONAL_PORTS = frozenset((
    "clk_i", "rst_ni",
    "instr_req_o", "instr_gnt_i", "instr_addr_o", "instr_rvalid_i",
    "instr_rdata_i", "instr_err_i",
    "data_req_o", "data_gnt_i", "data_addr_o", "data_we_o", "data_wdata_o",
    "data_be_o", "data_rvalid_i", "data_rdata_i", "data_err_i",
    "irq_external_i",
))

#: Constants whose value is fixed by the RTL or by the project's own wrapper of
#: the same core (src/myfuzz/composition/rtl/soc_ibex_beat_core.sv).
EXPECTED_CONSTANTS = {
    "test_en_i": 0,
    "hart_id_i": 0,
    "boot_addr_i": 65536,
    "trvk_heap_base_addr_i": 0,
    "instr_rdata_intg_i": 0,
    "data_rdata_intg_i": 0,
    "data_tag_i": 0,
    "trvk_revbm_gnt_i": 0,
    "trvk_revbm_rvalid_i": 0,
    "trvk_revbm_rdata_i": 0,
    "trvk_revbm_rdata_intg_i": 0,
    "trvk_revbm_err_i": 0,
    "irq_software_i": 0,
    "irq_timer_i": 0,
    "irq_fast_i": 0,
    "irq_nm_i": 0,
    "scramble_key_valid_i": 0,
    "scramble_key_i": 0,
    "scramble_nonce_i": 0,
    "debug_req_i": 0,
    "cheriot_enable_i": 10,      # ibex_pkg::IbexMuBiOff = 4'b1010
    "fetch_enable_i": 5,         # ibex_pkg::IbexMuBiOn  = 4'b0101
    "mcounteren_writable_i": 5,  # ibex_pkg::IbexMuBiOn
    "scan_rst_ni": 1,
}

#: Outputs the SoC exports for passive monitoring only.  Each one is driven by
#: ibex_top itself (to a status value or to a constant in this parameterization).
EXPECTED_OBSERVES = frozenset((
    "alert_minor_o", "alert_major_internal_o", "alert_major_bus_o",
    "core_sleep_o", "crash_dump_o", "double_fault_seen_o",
    "data_wdata_intg_o", "data_tag_o",
    "trvk_revbm_req_o", "trvk_revbm_addr_o", "scramble_req_o",
    "lockstep_cmp_en_o",
    "data_req_shadow_o", "data_we_shadow_o", "data_be_shadow_o",
    "data_addr_shadow_o", "data_wdata_shadow_o", "data_wdata_intg_shadow_o",
    "instr_req_shadow_o", "instr_addr_shadow_o",
))

#: Instruction endpoint: read-only OBI.  role -> (port, direction, width)
INSTRUCTION_FIELDS = {
    "req": ("instr_req_o", "output", 1),
    "gnt": ("instr_gnt_i", "input", 1),
    "addr": ("instr_addr_o", "output", 32),
    "rvalid": ("instr_rvalid_i", "input", 1),
    "rdata": ("instr_rdata_i", "input", 32),
    "error": ("instr_err_i", "input", 1),
}

#: Data endpoint: read-write OBI with byte enables and an error response.
DATA_FIELDS = {
    "req": ("data_req_o", "output", 1),
    "gnt": ("data_gnt_i", "input", 1),
    "addr": ("data_addr_o", "output", 32),
    "we": ("data_we_o", "output", 1),
    "wdata": ("data_wdata_o", "output", 32),
    "be": ("data_be_o", "output", 4),
    "rvalid": ("data_rvalid_i", "input", 1),
    "rdata": ("data_rdata_i", "input", 32),
    "error": ("data_err_i", "input", 1),
}

_HAS_TOOLING = SOURCE_ROOT.is_dir() and shutil.which("verilator") is not None


class IbexProfileFixture(unittest.TestCase):
    """Elaborate the pinned Ibex closure once for every test in this module."""

    profile = None
    facts = None
    binding = None
    entries = None

    @classmethod
    def setUpClass(cls) -> None:
        if not _HAS_TOOLING:
            raise unittest.SkipTest(
                f"ibex checkout or verilator missing: {SOURCE_ROOT}")
        cls.profile = load_component_profile(PROFILE_PATH)
        cls.facts = elaborate_profile(cls.profile, base_dir=ROOT)
        cls.binding = bind_profile(cls.profile, cls.facts)
        cls.entries = build_port_dispositions(
            "ibex0", cls.binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=cls.profile.port_actions)

    def field(self, endpoint_id: str, role: str):
        return self.binding.field(endpoint_id, role)

    def entries_for(self, port: str):
        return tuple(entry for entry in self.entries if entry.port == port)

    def actions_without(self, port: str):
        return tuple(action for action in self.profile.port_actions
                     if action.port != port)

    def action(self, port: str):
        return next(action for action in self.profile.port_actions if action.port == port)


class ProfileDeclarationTests(IbexProfileFixture):
    def test_profile_loads_with_the_pinned_ibex_source(self) -> None:
        profile = self.profile
        self.assertEqual("ibex", profile.component_id)
        self.assertEqual("cpu", profile.kind)
        self.assertEqual("third_party/rfuzz/upstream/ibex", profile.source.source_root)
        self.assertEqual("ibex_top", profile.source.top_module)
        self.assertEqual("git:34b0705760ef3dfa00e99637432473d2be8f22f3",
                         profile.source.revision)
        document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        self.assertEqual("declared", document["source"]["top_port_selection"])
        self.assertIsNotNone(profile.cpu)
        self.assertEqual("riscv", profile.cpu.family)
        self.assertEqual(32, profile.cpu.xlen)
        self.assertEqual(["i", "m", "c"], list(profile.cpu.extensions))
        self.assertEqual(65536, profile.cpu.reset_vector)
        self.assertEqual(["processor.instruction", "processor.data"],
                         list(profile.cpu.master_endpoints))
        self.assertEqual("processor.interrupts", profile.cpu.irq_entry_endpoint)
        self.assertEqual("external", profile.cpu.irq_entry_role)
        self.assertEqual("active_high", profile.cpu.irq_entry_polarity)
        self.assertEqual("machine_external", profile.cpu.irq_semantics)
        self.assertEqual(32, profile.capability("address_width"))
        self.assertEqual(32, profile.capability("data_width"))
        self.assertEqual([("clk_i", "core")],
                         [(item.port, item.domain) for item in profile.clocks])
        self.assertEqual([("rst_ni", "sys_rst", "active_low", False)],
                         [(item.port, item.domain, item.polarity, item.synchronous)
                          for item in profile.resets])

    def test_closure_parameters_and_isa_match_the_official_tables(self) -> None:
        """The closure, the include roots and the parameters are the pinned ones."""
        profile = self.profile
        official = json.loads(OFFICIAL_PATH.read_text(encoding="utf-8"))["source"]
        self.assertEqual(official["files"], list(profile.source.files))
        self.assertEqual(official["include_roots"], list(profile.source.include_roots))
        declared = tuple((name, value)
                         for name, value in profile.source.elaboration.parameters)
        expected = tuple((item["name"], item["value"])
                         for item in official["elaboration"]["parameters"])
        self.assertEqual(sorted(expected), sorted(declared))
        self.assertEqual("recorded-nonfatal", profile.source.elaboration.warning_policy)
        # Every parameter is the decimal string of the value the existing Ibex
        # matrix config uses for the same core.
        matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))["cpu"]
        for name, value in declared:
            self.assertRegex(value, r"[0-9]+")
            self.assertEqual(int(matrix["parameters"][name]), int(value))
        self.assertEqual(matrix["reset_vector"], profile.cpu.reset_vector)
        self.assertEqual(sorted(item.upper() for item in matrix["extensions"]),
                         sorted(item.upper() for item in profile.cpu.extensions))

    def test_git_revision_is_the_real_checkout_head(self) -> None:
        """A ``git:`` pin that names a commit the checkout is not at is a lie."""
        if shutil.which("git") is None or not (SOURCE_ROOT / ".git").exists():
            self.skipTest("checkout is not a git working tree")
        result = subprocess.run(["git", "-C", SOURCE_ROOT.as_posix(), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(f"git:{result.stdout.strip()}", self.profile.source.revision)


class ProfileBindingTests(IbexProfileFixture):
    def test_bounded_elaboration_keeps_exactly_the_declared_ports(self) -> None:
        self.assertEqual("declared", self.facts.selection)
        # 62 of the 66 ports ibex_top declares: the four aggregate ports below
        # are the documented, unrepresentable rest.
        self.assertEqual(62, len(self.facts.ports))
        for name in AGGREGATE_PORTS:
            self.assertIsNone(self.facts.port(name))

    def test_declared_roles_bind_to_real_ports_of_the_right_shape(self) -> None:
        self.assertEqual(16, len(self.binding.all_fields()))
        for endpoint_id, expected in (("processor.instruction", INSTRUCTION_FIELDS),
                                      ("processor.data", DATA_FIELDS)):
            endpoint = self.binding.endpoint(endpoint_id)
            self.assertEqual(("obi", "1"), endpoint.protocol)
            self.assertEqual(expected, {field.role: (field.port, field.direction, field.width)
                                        for field in endpoint.fields})
            for field in endpoint.fields:
                fact = self.facts.port(field.port)
                self.assertIsNotNone(fact, field.port)
                self.assertEqual(fact.direction, field.direction)
                self.assertEqual(fact.width, field.width)
                self.assertEqual("rtl/ibex_top.sv", field.source_file)
        entry = self.binding.endpoint("processor.interrupts")
        self.assertEqual("interrupt_entry", entry.function)
        self.assertEqual(("irq_external_i", "input", 1),
                         (entry.fields[0].port, entry.fields[0].direction,
                          entry.fields[0].width))
        # The interrupt entry is the real machine-external bit of ibex_top.
        self.assertEqual("irq_external_i", self.binding.field("processor.interrupts",
                                                              "external").port)
        self.assertEqual([("clk_i", "input")],
                         [(field.port, field.direction)
                          for _binding, field in self.binding.clocks])
        self.assertEqual([("rst_ni", "input")],
                         [(field.port, field.direction)
                          for _binding, field in self.binding.resets])
        self.assertTrue(self.binding.binding_hash.startswith("sha256:"))

    def test_missing_port_and_reversed_binding_are_reported(self) -> None:
        broken = replace(self.profile, endpoints=tuple(
            replace(endpoint, fields=tuple(
                replace(field, aliases=("instr_address_typo_o",)) if field.role == "addr"
                else field for field in endpoint.fields))
            if endpoint.endpoint_id == "processor.instruction" else endpoint
            for endpoint in self.profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, self.facts)
        self.assertIn("port-missing", str(error.exception))
        self.assertIn("processor.instruction:addr", str(error.exception))

        reversed_binding = replace(self.profile, endpoints=tuple(
            replace(endpoint, fields=tuple(
                replace(field, aliases=("instr_gnt_i",)) if field.role == "req" else field
                for field in endpoint.fields))
            if endpoint.endpoint_id == "processor.instruction" else endpoint
            for endpoint in self.profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(reversed_binding, self.facts)
        self.assertIn("direction-conflict", str(error.exception))


class DispositionLedgerTests(IbexProfileFixture):
    def test_every_elaborated_port_and_bit_has_exactly_one_disposition(self) -> None:
        covered: dict[str, set[int]] = {}
        for entry in self.entries:
            self.assertIn(entry.disposition, DISPOSITION_KINDS)
            self.assertNotEqual("unclassified", entry.disposition)
            self.assertTrue(entry.reason, entry.port)
            bits = covered.setdefault(entry.port, set())
            for bit in range(entry.bit_lo, entry.bit_hi + 1):
                self.assertNotIn(bit, bits, f"{entry.port}[{bit}] classified twice")
                bits.add(bit)
        elaborated = {fact.name: fact.width for fact in self.facts.ports}
        self.assertEqual(set(elaborated), set(covered))
        for name, width in elaborated.items():
            self.assertEqual(set(range(width)), covered[name],
                             f"{name} has undisposed bits")
        # The ledger identity: covered bits equal the elaborated bit count.
        self.assertEqual(sum(elaborated.values()),
                         sum(entry.bit_hi - entry.bit_lo + 1 for entry in self.entries))

    def test_dispositions_are_the_declared_kinds_for_the_declared_ports(self) -> None:
        summary = Counter(entry.disposition for entry in self.entries)
        self.assertEqual({"functional": len(DECLARED_FUNCTIONAL_PORTS),
                          "constant": len(EXPECTED_CONSTANTS),
                          "observe": len(EXPECTED_OBSERVES)}, dict(summary))
        functional = {entry.port for entry in self.entries
                      if entry.disposition == "functional"}
        self.assertEqual(set(DECLARED_FUNCTIONAL_PORTS), functional)
        constant = {entry.port for entry in self.entries
                    if entry.disposition == "constant"}
        self.assertEqual(set(EXPECTED_CONSTANTS), constant)
        observed = {entry.port for entry in self.entries
                    if entry.disposition == "observe"}
        self.assertEqual(set(EXPECTED_OBSERVES), observed)
        # Constants drive inputs, observations are outputs, nothing is fuzzed or
        # left open: an unconstrained drive of this CPU would be a silent hole.
        for entry in self.entries:
            if entry.disposition == "constant":
                self.assertEqual("input", entry.direction, entry.port)
                self.assertEqual("const", entry.target)
            if entry.disposition == "observe":
                self.assertEqual("output", entry.direction, entry.port)
        self.assertFalse([entry for entry in self.entries
                          if entry.disposition in ("fuzz", "external", "unconnected")])

    def test_constant_values_fit_their_port_and_are_rtl_grounded(self) -> None:
        for port, value in EXPECTED_CONSTANTS.items():
            entry = self.entries_for(port)[0]
            self.assertEqual(value, entry.value, port)
            width = entry.bit_hi - entry.bit_lo + 1
            self.assertLess(entry.value, 1 << width, port)
            self.assertEqual(entry.width, width, port)  # whole-port action
        # boot_addr_i is the profile's own declared reset vector.
        self.assertEqual(self.profile.cpu.reset_vector, self.action("boot_addr_i").value)
        # The MuBi constants are the encodings ibex_pkg declares.
        self.assertEqual(0b1010, self.action("cheriot_enable_i").value)   # IbexMuBiOff
        self.assertEqual(0b0101, self.action("fetch_enable_i").value)     # IbexMuBiOn
        self.assertEqual(0b0101, self.action("mcounteren_writable_i").value)

    def test_aggregate_ports_are_recorded_as_unknown_not_silently_dropped(self) -> None:
        unknown = " ".join(self.profile.evidence["unknown"])
        for name in AGGREGATE_PORTS:
            self.assertIn(name, unknown)
        self.assertIn("cannot be represented by the current verilator-json port extractor",
                      unknown)
        self.assertIn("real coverage gap", unknown)


class FailClosedTests(IbexProfileFixture):
    def test_removing_a_port_action_leaves_undisposed_bits(self) -> None:
        """A port the ledger no longer classifies must be a hard error."""
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=self.actions_without("test_en_i"))
        self.assertIn("undisposed-port-bits:ibex0:test_en_i", str(error.exception))

    def test_constant_wider_than_its_port_is_rejected(self) -> None:
        oversized = replace(self.action("scan_rst_ni"), value=2)
        actions = tuple(oversized if action.port == "scan_rst_ni" else action
                        for action in self.profile.port_actions)
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                    reset_domain="sys_rst", profile_port_actions=actions)
        self.assertIn("constant-action-out-of-range:scan_rst_ni:2!<2", str(error.exception))

    def test_action_kind_and_direction_rules_fail_closed(self) -> None:
        cases = (
            (replace(self.action("test_en_i"), action="observe", value=None),
             "observe-action-on-non-output"),
            (replace(self.action("alert_minor_o"), action="fuzz", strategy="cycle_value"),
             "fuzz-action-on-non-input"),
        )
        for action, reason in cases:
            with self.subTest(reason=reason):
                actions = tuple(action if item.port == action.port else item
                                for item in self.profile.port_actions)
                with self.assertRaises(PortDispositionError) as error:
                    build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                            reset_domain="sys_rst",
                                            profile_port_actions=actions)
                self.assertIn(reason, str(error.exception))
        # ``unconnected`` is only legal with a contract reference, so a profile
        # that leaves a port open without naming the contract is rejected when it
        # is loaded, before any RTL is touched.
        document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        document["port_actions"] = [
            {"port": item["port"], "action": "unconnected", "reason": "probe: no contract"}
            if item["port"] == "test_en_i" else item
            for item in document["port_actions"]]
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("unconnected-requires-contract", str(error.exception))

    def test_action_on_an_unselected_aggregate_port_is_rejected(self) -> None:
        """The bounded selection is explicit: it may not be extended by stealth."""
        actions = self.profile.port_actions + (
            replace(self.action("test_en_i"), port="ram_cfg_icache_tag_i"),)
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                    reset_domain="sys_rst", profile_port_actions=actions)
        self.assertIn("port-action-unknown-port:ram_cfg_icache_tag_i",
                      str(error.exception))

    def test_duplicate_and_conflicting_actions_are_rejected(self) -> None:
        duplicate = self.profile.port_actions + (self.action("test_en_i"),)
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                    reset_domain="sys_rst", profile_port_actions=duplicate)
        self.assertIn("duplicate-port-action:test_en_i", str(error.exception))
        # A second action that covers a bit the whole-port action already covers
        # is a second driver for the same bit, not a refinement.
        overlapping = self.profile.port_actions + (
            PortAction(port="scan_rst_ni", action="constant", value=0, bits=(0,),
                       reason="probe: overlapping bit selector"),)
        with self.assertRaises(PortDispositionError) as error:
            build_port_dispositions("ibex0", self.binding, clock_domain="core",
                                    reset_domain="sys_rst",
                                    profile_port_actions=overlapping)
        self.assertIn("bit-multiple-dispositions:ibex0:scan_rst_ni[0]",
                      str(error.exception))


class CompositionRequestTests(unittest.TestCase):
    def test_request_composes_ibex_with_the_two_first_time_peripherals(self) -> None:
        profiles = {
            PROFILE_PATH.as_posix(): load_component_profile(PROFILE_PATH),
            UART_PATH.as_posix(): load_component_profile(UART_PATH),
            GPIO_PATH.as_posix(): load_component_profile(GPIO_PATH),
        }
        request = load_composition_request(REQUEST_PATH.as_posix(), profiles=profiles)
        self.assertEqual("ibex-novauart-novagpio", request.request_id)
        self.assertEqual("cpu0", request.cpu.instance_id)
        self.assertEqual("ibex", request.cpu.profile.component_id)
        self.assertEqual(["gpio0", "uart0"],
                         sorted(item.instance_id for item in request.peripherals))
        self.assertEqual({"novagpio", "novauart"},
                         {item.profile.component_id for item in request.peripherals})
        # Same memory / clock / reset / address-policy shape as request.json.
        reference = json.loads(
            (ROOT / "examples/soc_generation/request.json").read_text(encoding="utf-8"))
        candidate = json.loads(REQUEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(reference["memory"], candidate["memory"])
        self.assertEqual(reference["clock"], candidate["clock"])
        self.assertEqual(reference["reset"], candidate["reset"])
        self.assertEqual(reference["address_policy"], candidate["address_policy"])
        self.assertEqual(reference["test_modes"], candidate["test_modes"])
        self.assertEqual("core", request.clock_domain)
        self.assertEqual("sys_rst", request.reset_domain)
        self.assertEqual("active_low", request.reset_polarity)
        self.assertFalse(request.reset_synchronous)


if __name__ == "__main__":
    unittest.main()
