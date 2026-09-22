"""Real pinned CVA6 as a ``component_profile.v1`` over its packed AXI4 struct pair.

CVA6 packs its whole AXI4 master into two top-level *struct* ports -
``noc_req_o`` (AW + W + AR, 470 bits) and ``noc_resp_i`` (B + R, 210 bits) - so
one physical port carries 32 and 13 semantic roles respectively.  This module
proves:

* the profile is the pinned CVA6 closure (filelist, variables, nested repository
  pins, include roots) and it elaborates with all 13 top-level ports;
* every one of the 45 AXI4 roles binds to its own elaborated member, with the
  member's inclusive bit range declared and re-proved (a wrong offset is refused
  with ``member-offset-conflict``);
* the port-disposition ledger classifies every port and every one of the 8416
  elaborated bits, including the two bits of ``irq_i`` that are *not* the
  interrupt entry;
* the composition request reaches the composer, which refuses it with the
  declared adapter-scope diagnostic because that scope composes 32-bit masters
  only - the exact message is asserted, and no support is claimed.

It also records, as a *diagnostic*, what happens with only that one declared
policy bypassed: the plan builds, the two struct ports render as member-wise
assignment patterns (including CVA6's nested ``aw``/``b``/``r`` structs and the
TL-UL-style enum casts), the independent audit re-elaborates the 225-file
closure and passes, and the new ``struct_port_mapping`` check verifies the
member-to-net record.  The diagnostic is labelled as such: it is the evidence a
maintainer needs to decide whether to widen the declared scope, not a claim that
the composer supports a 64-bit master today.
"""
from __future__ import annotations

import json
import shutil
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    bind_profile,
    elaborate_profile,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.cva6_source_closure import resolve_cva6_source_closure
from myfuzz.composition.soc_composition import (
    CompositionError,
    build_composition,
)
from myfuzz.composition.soc_port_dispositions import (
    build_port_dispositions,
    port_segments,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import (
    FAIL,
    PASS,
    StructureAuditError,
    audit_structure,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "configs/cpus/cva6/component_profile.json"
REQUEST_PATH = ROOT / "examples/soc_generation/request-cva6.json"
SOURCE_ROOT = ROOT / "third_party/cva6_upstream_reference"
INTERFACE_PATH = ROOT / "configs/cpus/cva6/official_core_interface_description.json"

#: The 45 AXI4 roles the profile declares, split by the struct port they live in.
NOC_REQ_ROLES = frozenset((
    "awid", "awaddr", "awlen", "awsize", "awburst", "awlock", "awcache", "awprot",
    "awqos", "awregion", "awatop", "awuser", "awvalid", "wdata", "wstrb", "wlast",
    "wuser", "wvalid", "bready", "arid", "araddr", "arlen", "arsize", "arburst",
    "arlock", "arcache", "arprot", "arqos", "arregion", "aruser", "arvalid",
    "rready",
))
NOC_RESP_ROLES = frozenset((
    "awready", "arready", "wready", "bvalid", "bid", "bresp", "buser", "rvalid",
    "rid", "rdata", "rresp", "rlast", "ruser",
))
#: role -> (port, member path, bit_lo, bit_hi, width) as the pinned closure lays
#: them out.  The profile must agree with every one of these.
MEMBER_LAYOUT = {
    "awid": ("noc_req_o", ("aw", "id"), 466, 469, 4),
    "awaddr": ("noc_req_o", ("aw", "addr"), 402, 465, 64),
    "awuser": ("noc_req_o", ("aw", "user"), 303, 366, 64),
    "awvalid": ("noc_req_o", ("aw_valid",), 302, 302, 1),
    "wdata": ("noc_req_o", ("w", "data"), 238, 301, 64),
    "wstrb": ("noc_req_o", ("w", "strb"), 230, 237, 8),
    "rready": ("noc_req_o", ("r_ready",), 0, 0, 1),
    "awready": ("noc_resp_i", ("aw_ready",), 209, 209, 1),
    "bid": ("noc_resp_i", ("b", "id"), 202, 205, 4),
    "buser": ("noc_resp_i", ("b", "user"), 136, 199, 64),
    "ruser": ("noc_resp_i", ("r", "user"), 0, 63, 64),
    "d_error": None,
}

_HAS_TOOLING = (SOURCE_ROOT / "core" / "cva6.sv").is_file() and \
    shutil.which("verilator") is not None


@unittest.skipUnless(_HAS_TOOLING, "the pinned CVA6 checkout or verilator is missing")
class Cva6ProfileFixture(unittest.TestCase):
    """Elaborate and bind the pinned CVA6 closure once for the whole module."""

    profile = None
    facts = None
    binding = None
    entries = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_component_profile(PROFILE_PATH)
        cls.facts = elaborate_profile(cls.profile, base_dir=ROOT)
        cls.binding = bind_profile(cls.profile, cls.facts)
        cls.entries = build_port_dispositions(
            "cpu0", cls.binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=cls.profile.port_actions)


class ProfileDeclarationTests(Cva6ProfileFixture):
    def test_the_profile_is_the_pinned_cva6_filelist_closure(self) -> None:
        profile = self.profile
        self.assertEqual("cva6", profile.component_id)
        self.assertEqual("cpu", profile.kind)
        self.assertEqual("cva6", profile.source.top_module)
        self.assertEqual("third_party/cva6_upstream_reference", profile.source.source_root)
        self.assertEqual("git:2e1336dcff3d1a0b49fbe6282b97802f32ea32af",
                         profile.source.revision)
        self.assertEqual("core/Flist.cva6", profile.source.filelist)
        self.assertEqual((("CVA6_REPO_DIR", "."),
                          ("HPDCACHE_DIR", "core/cache_subsystem/hpdcache"),
                          ("TARGET_CFG", "cv64a6_imafdc_sv39")),
                         tuple(profile.source.filelist_variables))
        closure = resolve_cva6_source_closure(ROOT)
        self.assertEqual(closure["top_module"], profile.source.top_module)
        self.assertEqual(closure["root_revision"], profile.source.revision)
        self.assertEqual(
            [item[len(profile.source.source_root) + 1:] for item in closure["include_dirs"]],
            list(profile.source.include_roots))
        self.assertEqual(len(closure["source_files"]), 225)
        self.assertEqual([(item.path, item.revision)
                          for item in profile.source.repositories],
                         [(item["path"], item["revision"])
                          for item in closure["nested_repositories"]])

    def test_the_contract_is_rv64_with_one_unified_axi4_master(self) -> None:
        contract = self.profile.cpu
        self.assertEqual("riscv", contract.family)
        self.assertEqual(64, contract.xlen)
        self.assertEqual(["i", "m", "a", "f", "d", "c"], list(contract.extensions))
        self.assertEqual(65536, contract.reset_vector)
        self.assertEqual(["processor.memory.unified"], list(contract.master_endpoints))
        self.assertEqual("processor.interrupts", contract.irq_entry_endpoint)
        self.assertEqual("machine_external", contract.irq_entry_role)
        self.assertEqual(64, self.profile.capabilities["address_width"])
        self.assertEqual(64, self.profile.capabilities["data_width"])
        self.assertEqual(4, self.profile.capabilities["id_width"])
        self.assertEqual(64, self.profile.capabilities["user_width"])
        self.assertFalse(self.profile.capabilities["bursts"])

    def test_the_official_interface_document_is_the_same_45_roles(self) -> None:
        document = json.loads(INTERFACE_PATH.read_text(encoding="utf-8"))
        memory = next(endpoint for endpoint in document["endpoints"]
                      if endpoint.get("function") == "memory_master")
        declared = {field["role"]: (field["physical"]["port"],
                                    tuple(field["physical"]["member_path"]))
                    for field in memory["fields"] if "physical" in field}
        self.assertEqual(NOC_REQ_ROLES | NOC_RESP_ROLES, set(declared))
        endpoint = self.binding.endpoint("processor.memory.unified")
        self.assertEqual(declared, {field.role: (field.port, field.member_path)
                                    for field in endpoint.fields})

    def test_every_declared_role_is_a_pinned_axi4_adapter_source_port(self) -> None:
        from myfuzz.composition.processor_adapters import _ADAPTERS
        adapter = _ADAPTERS[("axi4", "1")]
        self.assertEqual(NOC_REQ_ROLES | NOC_RESP_ROLES,
                         {role for role, _port, _direction in adapter.source_ports})


class MemberLayoutTests(Cva6ProfileFixture):
    def test_all_thirteen_top_level_ports_are_elaborated(self) -> None:
        self.assertEqual(
            ["boot_addr_i", "clk_i", "cvxif_req_o", "cvxif_resp_i", "debug_req_i",
             "hart_id_i", "ipi_i", "irq_i", "noc_req_o", "noc_resp_i",
             "rst_ni", "rvfi_probes_o", "time_irq_i"],
            sorted(fact.name for fact in self.facts.ports))
        self.assertEqual("all", self.facts.selection)
        self.assertEqual(225, len(self.facts.files))

    def test_the_struct_ports_have_the_pinned_member_layout(self) -> None:
        for port, roles in (("noc_req_o", NOC_REQ_ROLES), ("noc_resp_i", NOC_RESP_ROLES)):
            fact = self.facts.port(port)
            spans = {member.path: (member.raw_lo, member.raw_hi, member.width)
                     for member in fact.members}
            self.assertEqual(len(roles), len(fact.members), port)
            for role in sorted(roles):
                expected = MEMBER_LAYOUT.get(role)
                if expected is None:
                    continue
                self.assertEqual(expected[0], port)
                self.assertEqual((expected[2], expected[3], expected[4]),
                                 spans[expected[1]], role)
            self.assertEqual(fact.width,
                             sum(member.width for member in fact.members), port)
        self.assertEqual(470, self.facts.port("noc_req_o").width)
        self.assertEqual(210, self.facts.port("noc_resp_i").width)

    def test_every_role_binds_to_its_declared_member_and_proves_the_span(self) -> None:
        endpoint = self.binding.endpoint("processor.memory.unified")
        self.assertEqual(NOC_REQ_ROLES | NOC_RESP_ROLES,
                         {field.role for field in endpoint.fields})
        for field in endpoint.fields:
            fact = self.facts.port(field.port)
            member = next(item for item in fact.members
                          if item.path == field.member_path)
            self.assertEqual((member.raw_lo, member.raw_hi, member.width),
                             (field.raw_lo, field.raw_hi, field.width), field.role)
            self.assertEqual(fact.direction, field.direction, field.role)
        self.assertEqual("output", self.facts.port("noc_req_o").direction)
        self.assertEqual("input", self.facts.port("noc_resp_i").direction)
        # Every host-to-device role lands on the output struct and every
        # device-to-host role on the input struct.
        for field in endpoint.fields:
            expected = "output" if field.port == "noc_req_o" else "input"
            self.assertEqual(expected, field.direction, field.role)

    def test_a_member_offset_the_elaboration_contradicts_is_refused(self) -> None:
        endpoint = self.profile.endpoint("processor.memory.unified")
        broken_fields = tuple(
            replace(field, member_bits=(field.member_bits[0] + 1, field.member_bits[1]))
            if field.role == "awid" else field for field in endpoint.fields)
        broken = replace(self.profile, endpoints=tuple(
            replace(item, fields=broken_fields) if item.endpoint_id == endpoint.endpoint_id
            else item for item in self.profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, self.facts)
        self.assertIn("member-offset-conflict:processor.memory.unified:awid:"
                      "noc_req_o.aw.id:[469:466]!=[469:467]", str(error.exception))

    def test_a_member_on_the_wrong_struct_port_is_refused(self) -> None:
        endpoint = self.profile.endpoint("processor.memory.unified")
        broken_fields = tuple(
            replace(field, physical=replace(field.physical, port="noc_resp_i"))
            if field.role == "awid" else field for field in endpoint.fields)
        broken = replace(self.profile, endpoints=tuple(
            replace(item, fields=broken_fields) if item.endpoint_id == endpoint.endpoint_id
            else item for item in self.profile.endpoints))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, self.facts)
        self.assertIn("member-missing:processor.memory.unified:awid:noc_resp_i.aw.id",
                      str(error.exception))

    def test_the_interrupt_entry_is_the_machine_external_bit_only(self) -> None:
        field = self.binding.field("processor.interrupts", "machine_external")
        self.assertEqual(("irq_i", 0, 0, 1), (field.port, field.raw_lo, field.raw_hi,
                                              field.width))
        self.assertEqual(2, field.port_width)
        self.assertFalse(field.whole_port)


class DispositionLedgerTests(Cva6ProfileFixture):
    def test_every_port_and_bit_of_the_closure_is_classified(self) -> None:
        covered: dict[str, set[int]] = {}
        for entry in self.entries:
            bits = covered.setdefault(entry.port, set())
            for bit in range(entry.bit_lo, entry.bit_hi + 1):
                self.assertNotIn(bit, bits, f"{entry.port}[{bit}] twice")
                bits.add(bit)
        elaborated = {fact.name: fact.width for fact in self.facts.ports}
        self.assertEqual(set(elaborated), set(covered))
        for name, width in elaborated.items():
            self.assertEqual(set(range(width)), covered[name], name)
        self.assertEqual(sum(elaborated.values()),
                         sum(entry.bit_hi - entry.bit_lo + 1 for entry in self.entries))
        self.assertEqual(8416, sum(elaborated.values()))

    def test_the_two_struct_ports_are_fully_covered_by_their_roles(self) -> None:
        for port, roles in (("noc_req_o", NOC_REQ_ROLES), ("noc_resp_i", NOC_RESP_ROLES)):
            entries = port_segments(self.entries)[port]
            self.assertEqual(roles, {entry.role for entry in entries})
            self.assertTrue(all(entry.disposition == "functional" for entry in entries))
            self.assertTrue(all(entry.width == self.facts.port(port).width
                                for entry in entries))
            self.assertEqual(self.facts.port(port).width,
                             sum(entry.bit_hi - entry.bit_lo + 1 for entry in entries))

    def test_every_remaining_port_has_exactly_one_disposition(self) -> None:
        declared = {entry.port: entry for entry in self.entries
                    if entry.port not in ("noc_req_o", "noc_resp_i")}
        self.assertEqual(
            {"clk_i", "rst_ni", "boot_addr_i", "hart_id_i", "irq_i", "ipi_i",
             "time_irq_i", "debug_req_i", "rvfi_probes_o", "cvxif_req_o",
             "cvxif_resp_i"},
            set(declared))
        self.assertEqual("constant", declared["boot_addr_i"].disposition)
        self.assertEqual(65536, declared["boot_addr_i"].value)
        self.assertEqual((1, 1), (declared["irq_i"].bit_lo, declared["irq_i"].bit_hi))
        self.assertEqual("unconnected", declared["rvfi_probes_o"].disposition)
        self.assertTrue(declared["rvfi_probes_o"].coverage_loss)
        self.assertEqual("observe", declared["cvxif_req_o"].disposition)
        self.assertEqual("constant", declared["cvxif_resp_i"].disposition)


class CompositionRequestTests(Cva6ProfileFixture):
    def request(self):
        profiles = {PROFILE_PATH.as_posix(): self.profile}
        return load_composition_request(REQUEST_PATH.as_posix(), profiles=profiles)

    def test_the_request_names_the_pinned_profile_and_a_single_mode(self) -> None:
        request = self.request()
        self.assertEqual("cva6-rom-ram", request.request_id)
        self.assertEqual("cva6", request.cpu.profile.component_id)
        self.assertEqual([], list(request.peripherals))
        self.assertEqual([("rom0", 65536, 32768), ("ram0", 2147483648, 65536)],
                         [(item.region_id, item.base, item.size)
                          for item in request.memory])
        self.assertEqual(["cpu_only"], list(request.test_modes))
        # boot_addr_i is the profile's declared reset vector and the ROM's base.
        self.assertEqual(next(item.value for item in self.profile.port_actions
                              if item.port == "boot_addr_i"),
                         request.memory[0].base)
        self.assertEqual(request.memory[0].base, self.profile.cpu.reset_vector)

    def test_the_composition_is_refused_by_the_declared_adapter_scope(self) -> None:
        """A 64-bit master is outside the scope the composer declares."""
        with self.assertRaises(CompositionError) as error:
            build_composition(self.request(), base_dir=ROOT)
        self.assertEqual(
            "unsupported-master-data-width:cpu0:processor.memory.unified:"
            "axi4@1:64:only-32-bit-is-composed", str(error.exception))


@unittest.skipUnless(_HAS_TOOLING, "the pinned CVA6 checkout or verilator is missing")
class Cva6DiagnosticCompositionTests(Cva6ProfileFixture):
    """What the pipeline does once the declared scope admits a 64-bit master.

    The composer's declared adapter scope refuses a 64-bit master by policy, so
    the product cannot compose this request.  This class runs the *same* pipeline
    with only that one policy check made permissive, to record what the rest of
    the pipeline actually does: it is evidence for the scope decision, not a
    claim that the composer supports a 64-bit master today.  Nothing here changes
    the shipped behaviour, and the refusal test above still pins the policy.
    """

    plan = None
    top = None
    _audit_result = None
    sources: list = []
    include_roots: list = []

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        import myfuzz.composition.soc_composition as soc_composition

        original = soc_composition._raise_scope_refusals
        soc_composition._raise_scope_refusals = lambda refusals: None
        try:
            request = load_composition_request(
                REQUEST_PATH.as_posix(),
                profiles={PROFILE_PATH.as_posix(): cls.profile})
            cls.plan = build_composition(request, base_dir=ROOT)
        finally:
            soc_composition._raise_scope_refusals = original
        cls.top = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        records = source_list(cls.plan)
        cls.sources = [item["path"] for item in records if item["role"] != "include_root"]
        cls.include_roots = [item["path"] for item in records
                             if item["role"] == "include_root"]

    def audit(self, text: str) -> dict:
        return audit_structure(self.plan, top_text=text, source_files=self.sources,
                               base_dir=ROOT, include_roots=self.include_roots)

    def findings(self) -> dict:
        if self.__class__._audit_result is None:
            self.__class__._audit_result = self.audit(self.top)
        result = self.__class__._audit_result
        assert isinstance(result, dict)
        return {item["check_id"]: item for item in result["findings"]}

    def test_the_two_struct_ports_render_as_member_wise_connections(self) -> None:
        self.assertIn(".noc_req_o('{aw: '{id: cpu0__noc_req_o__awid,", self.top)
        self.assertIn("user: cpu0__noc_req_o__awuser}, aw_valid: "
                      "cpu0__noc_req_o__awvalid,", self.top)
        self.assertIn("ar: '{id: cpu0__noc_req_o__arid,", self.top)
        self.assertIn(".noc_resp_i('{aw_ready: cpu0__noc_resp_i__awready,", self.top)
        self.assertIn("b: '{id: cpu0__noc_resp_i__bid, resp: cpu0__noc_resp_i__bresp, "
                      "user: cpu0__noc_resp_i__buser},", self.top)
        self.assertIn("r: '{id: cpu0__noc_resp_i__rid, data: cpu0__noc_resp_i__rdata,",
                      self.top)
        # One connection per port, not one per role.
        self.assertEqual(1, self.top.count(".noc_req_o("))
        self.assertEqual(1, self.top.count(".noc_resp_i("))
        self.assertEqual(1, self.top.count(".irq_i("))

    def test_the_irq_vector_is_a_held_bit_and_the_driven_entry(self) -> None:
        self.assertIn(".irq_i({1'd0, 1'b0})", self.top)

    def test_the_generated_soc_passes_the_independent_audit(self) -> None:
        result = self.audit(self.top)
        self.assertEqual(PASS, result["summary"]["status"],
                         [item for item in result["findings"]
                          if item["status"] != PASS])
        self.assertEqual(0, result["summary"]["failed"])

    def test_the_member_to_net_record_is_re_read_from_the_netlist(self) -> None:
        finding = self.findings()["struct_port_mapping"]
        self.assertEqual(PASS, finding["status"], finding["actual"])
        self.assertEqual([{"instance": "cpu0", "port": "cvxif_req_o", "members": 17,
                           "segments": 1, "leaves": ["cpu0__cvxif_req_o"]},
                          {"instance": "cpu0", "port": "cvxif_resp_i", "members": 14,
                           "segments": 1, "leaves": ["178'd0"]},
                          {"instance": "cpu0", "port": "irq_i", "members": 0,
                           "segments": 2, "leaves": ["1'd0", "1'b0"]},
                          {"instance": "cpu0", "port": "noc_req_o", "members": 32,
                           "segments": 32, "leaves": [
                               f"cpu0__noc_req_o__{role}" for role in (
                                   "awid", "awaddr", "awlen", "awsize", "awburst",
                                   "awlock", "awcache", "awprot", "awqos", "awregion",
                                   "awatop", "awuser", "awvalid", "wdata", "wstrb",
                                   "wlast", "wuser", "wvalid", "bready", "arid",
                                   "araddr", "arlen", "arsize", "arburst", "arlock",
                                   "arcache", "arprot", "arqos", "arregion", "aruser",
                                   "arvalid", "rready")]},
                          {"instance": "cpu0", "port": "noc_resp_i", "members": 13,
                           "segments": 13, "leaves": [
                               f"cpu0__noc_resp_i__{role}" for role in (
                                   "awready", "arready", "wready", "bvalid", "bid",
                                   "bresp", "buser", "rvalid", "rid", "rdata", "rresp",
                                   "rlast", "ruser")]},
                          {"instance": "cpu0", "port": "rvfi_probes_o", "members": 88,
                           "segments": 1, "leaves": []}],
                         finding["expected"])

    def test_every_cpu_adapter_pin_is_the_role_net_of_its_member(self) -> None:
        result = self.audit(self.top)
        finding = next(item for item in result["findings"]
                       if item["check_id"] == "cpu_adapter_wiring")
        self.assertEqual(PASS, finding["status"], finding["actual"])
        self.assertEqual("45 fields verified", finding["actual"])

    # -- fault injection -------------------------------------------------
    def mutate(self, old: str, new: str) -> str:
        self.assertIn(old, self.top, f"mutation anchor missing: {old}")
        self.assertNotEqual(old, new)
        return self.top.replace(old, new)

    def test_a_swapped_member_net_is_detected(self) -> None:
        text = self.mutate(
            "aw: '{id: cpu0__noc_req_o__awid, addr: cpu0__noc_req_o__awaddr,",
            "aw: '{id: cpu0__noc_req_o__awaddr, addr: cpu0__noc_req_o__awid,")
        result = self.audit(text)
        self.assertEqual(FAIL, result["summary"]["status"])
        failed = [item["check_id"] for item in result["findings"]
                  if item["status"] == FAIL]
        self.assertIn("struct_port_mapping", failed)
        self.assertIn("cpu_adapter_wiring", failed)

    def test_a_dropped_member_net_is_detected(self) -> None:
        text = self.mutate("strb: cpu0__noc_req_o__wstrb,",
                           "strb: cpu0__noc_req_o__wlast,")
        result = self.audit(text)
        self.assertEqual(FAIL, result["summary"]["status"])
        self.assertIn("struct_port_mapping",
                      [item["check_id"] for item in result["findings"]
                       if item["status"] == FAIL])

    def test_a_duplicated_member_net_is_detected(self) -> None:
        text = self.mutate("ar_valid: cpu0__noc_req_o__arvalid,",
                           "ar_valid: cpu0__noc_req_o__arid,")
        result = self.audit(text)
        self.assertEqual(FAIL, result["summary"]["status"])
        self.assertIn("struct_port_mapping",
                      [item["check_id"] for item in result["findings"]
                       if item["status"] == FAIL])

    def test_a_reordered_struct_connection_is_detected(self) -> None:
        """Swapping two whole sub-structs keeps every net but the wrong member."""
        text = self.mutate("b_ready: cpu0__noc_req_o__bready,",
                           "b_ready: cpu0__noc_req_o__rready,")
        result = self.audit(text)
        self.assertEqual(FAIL, result["summary"]["status"])
        self.assertIn("struct_port_mapping",
                      [item["check_id"] for item in result["findings"]
                       if item["status"] == FAIL])

    def test_the_audit_reports_the_elaborated_bits_it_re_read(self) -> None:
        netlist = self.audit(self.top)["netlist"]
        cell = next(item for item in netlist["cells"] if item["instance"] == "u_cpu0")
        self.assertEqual("cva6", cell["module"])
        ports = {item["name"]: item["width"] for item in netlist["ports"]}
        self.assertEqual(1, ports["clk_i"])


if __name__ == "__main__":
    unittest.main()
