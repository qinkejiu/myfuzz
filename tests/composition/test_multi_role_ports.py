"""Multi-role physical ports: struct members, bit slices and their assembly.

A ``component_profile.v1`` port used to carry exactly one semantic role.  A real
IP packs a whole bus into one struct port (CVA6's ``noc_req_o``/``noc_resp_i``,
OpenTitan's ``tl_i``/``tl_o``) and a real CPU splits one vector port across
several entries (CVA6's ``irq_i[0]`` is the machine-external entry and
``irq_i[1]`` is held inactive), so a profile may now declare several roles on one
port as long as each names its own bits.

This module is the unit-level acceptance for that vocabulary.  It needs no RTL:
the elaborated facts are built by hand, so every rule is exercised on exactly the
shape it is meant to refuse or accept.  The end-to-end proof on real RTL lives in
``test_opentitan_tlul_endpoint.py`` (a real OpenTitan TL-UL struct pair) and
``test_cva6_component_profile.py`` (the real CVA6 AXI4 struct pair).
"""
from __future__ import annotations

import unittest
from dataclasses import replace

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    PhysicalFacts,
    bind_profile,
    load_component_profile,
)
from myfuzz.composition.soc_composition import port_binding_records
from myfuzz.composition.soc_port_dispositions import (
    DispositionEntry,
    PortDispositionError,
    aligned_segments,
    build_port_dispositions,
    constant_expression,
    driven_net,
    member_tree,
    port_is_aggregated,
    port_segments,
    segment_expression,
    segment_net,
    top_port_name,
)
from myfuzz.composition.source_crawler import ElaboratedMemberFact, ElaboratedPortFact


def member(path: tuple[str, ...], width: int, low: int, high: int,
           enum_type: str = "") -> ElaboratedMemberFact:
    return ElaboratedMemberFact(path, width, low, high, False, "rtl/struct.sv", 1, 1,
                                enum_type)


#: A packed struct with a nested struct and a nested enum, packed most
#: significant member first: aw{id[3:0], addr[63:0]}, valid, user{rsp, data},
#: last - 84 bits, the layout the spans below are the proof of.
STRUCT_PORT = ElaboratedPortFact(
    "bus_o", "output", 84, False, "rtl/struct.sv", 10, 5,
    (member(("aw", "id"), 4, 80, 83, "bus_pkg::id_e"),
     member(("aw", "addr"), 64, 16, 79),
     member(("valid",), 1, 15, 15),
     member(("user", "rsp"), 7, 8, 14),
     member(("user", "data"), 7, 1, 7),
     member(("last",), 1, 0, 0)),
)

#: A plain vector input with declared slices.
VECTOR_PORT = ElaboratedPortFact("irq_i", "input", 3, False, "rtl/struct.sv", 20, 5)
CLK_PORT = ElaboratedPortFact("clk_i", "input", 1, False, "rtl/struct.sv", 30, 5)
RST_PORT = ElaboratedPortFact("rst_ni", "input", 1, False, "rtl/struct.sv", 31, 5)


def facts(*ports: ElaboratedPortFact) -> PhysicalFacts:
    """The declared ports plus the clock and reset every profile must bind."""
    return PhysicalFacts(top_module="struct_top",
                         ports=tuple(ports) + (CLK_PORT, RST_PORT),
                         content_hash="sha256:" + "0" * 64,
                         revision="sha256:" + "0" * 64)


def profile_document(**endpoint) -> dict:
    base = {
        "schema_version": "component_profile.v1",
        "component_id": "structy",
        "kind": "peripheral",
        "source": {
            "root": "rtl",
            "revision": "sha256:" + "0" * 64,
            "top_module": "struct_top",
            "files": ["struct.sv"],
        },
        "clocks": [{"port": "clk_i", "domain": "core", "frequency_hz": 50000000}],
        "resets": [{"port": "rst_ni", "domain": "sys_rst", "polarity": "active_low",
                    "synchronous": False}],
        "capabilities": {"data_width": 32, "partial_write": True},
        "address": {"window_size": 64, "alignment": 64, "registers": []},
        "endpoints": [{
            "endpoint_id": "dut.bus",
            "function": "external_pins",
            **endpoint,
        }],
    }
    return base


#: Every role of STRUCT_PORT, declared with its member path and proved bit range.
STRUCT_FIELDS = [
    {"role": "id", "direction": "output", "width": 4,
     "physical": {"port": "bus_o", "member_path": ["aw", "id"],
                  "bit_range": [80, 83]}},
    {"role": "addr", "direction": "output", "width": 64,
     "physical": {"port": "bus_o", "member_path": ["aw", "addr"],
                  "bit_range": [16, 79]}},
    {"role": "valid", "direction": "output", "width": 1,
     "physical": {"port": "bus_o", "member_path": ["valid"],
                  "bit_range": [15, 15]}},
    {"role": "user", "direction": "output", "width": 14,
     "physical": {"port": "bus_o", "member_path": ["user"],
                  "bit_range": [1, 14]}},
    {"role": "last", "direction": "output", "width": 1,
     "physical": {"port": "bus_o", "member_path": ["last"],
                  "bit_range": [0, 0]}},
]


def load(fields, *, extra_actions=(), function="external_pins", **endpoint) -> object:
    document = profile_document(fields=fields, function=function, **endpoint)
    if extra_actions:
        document["port_actions"] = list(extra_actions)
    return load_component_profile(document)


def ledger(profile, binding, *, actions=None, instance="dut0"):
    return build_port_dispositions(
        instance, binding, clock_domain="core", reset_domain="sys_rst",
        profile_port_actions=tuple(actions if actions is not None
                                   else profile.port_actions))


class SelectorVocabularyTests(unittest.TestCase):
    """The document vocabulary: a member path, a member proof, or a bit slice."""

    def test_a_member_role_carries_its_member_path_and_proved_span(self) -> None:
        profile = load(STRUCT_FIELDS)
        endpoint = profile.endpoints[0]
        self.assertEqual(5, len(endpoint.fields))
        field = next(item for item in endpoint.fields if item.role == "addr")
        self.assertEqual(("aw", "addr"), field.physical.member_path)
        self.assertEqual((16, 79), field.member_bits)
        self.assertIsNone(field.bit_range)

    def test_a_bit_slice_role_needs_one_alias_and_no_physical_selector(self) -> None:
        profile = load([{"role": "entry", "direction": "input", "aliases": ["irq_i"],
                         "bit_range": [1, 1]}])
        field = profile.endpoints[0].fields[0]
        self.assertEqual((1, 1), field.bit_range)
        self.assertIsNone(field.physical)

    def test_a_member_path_and_a_bit_slice_together_are_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load([{"role": "id", "direction": "output", "width": 4,
                   "bit_range": [88, 91],
                   "physical": {"port": "bus_o", "member_path": ["aw", "id"]}}])
        self.assertIn("profile-field-selector-ambiguous", str(error.exception))

    def test_a_member_proof_without_a_member_path_is_refused(self) -> None:
        # ``physical.bits`` is a proof of a *member's* offset, so a field that
        # declares an offset proof but no member path is a declaration error
        # rather than an offset that is silently dropped.
        with self.assertRaises(ValueError) as error:
            from myfuzz.composition.component_profile import ProfileField
            from myfuzz.composition.interface_description import PhysicalSelector
            ProfileField(role="id", width=4, member_bits=(0, 3))
        self.assertIn("member-bits-without-a-member-path", str(error.exception))
        self.assertIsNotNone(PhysicalSelector("bus_o", ("aw", "id")))

    def test_a_malformed_bit_range_is_refused(self) -> None:
        for span in ([3, 1], [-1, 2], [1], ["a", "b"]):
            with self.subTest(span=span):
                with self.assertRaises(ComponentProfileError) as error:
                    load([{"role": "entry", "direction": "input", "aliases": ["irq_i"],
                           "bit_range": span}])
                self.assertIn("invalid-profile-field", str(error.exception))


class PortOverlapTests(unittest.TestCase):
    """Load-time: two roles on one port are legal only on disjoint bits."""

    def test_disjoint_members_on_one_port_load(self) -> None:
        profile = load(STRUCT_FIELDS)
        self.assertEqual(1, len(profile.endpoints))

    def test_the_same_member_twice_is_a_duplicate_binding(self) -> None:
        fields = STRUCT_FIELDS + [dict(STRUCT_FIELDS[0], role="id_again")]
        with self.assertRaises(ComponentProfileError) as error:
            load(fields)
        self.assertIn("duplicate-port-binding:bus_o:", str(error.exception))

    def test_an_intermediate_member_overlaps_its_own_leaves(self) -> None:
        fields = STRUCT_FIELDS + [{"role": "aw", "direction": "output", "width": 68,
                                   "physical": {"port": "bus_o",
                                                "member_path": ["aw"]}}]
        with self.assertRaises(ComponentProfileError) as error:
            load(fields)
        self.assertIn("overlapping-port-binding:bus_o:", str(error.exception))
        self.assertIn("aw", str(error.exception))

    def test_overlapping_bit_slices_are_refused(self) -> None:
        fields = [{"role": "low", "direction": "input", "aliases": ["irq_i"],
                   "bit_range": [0, 1]},
                  {"role": "high", "direction": "input", "aliases": ["irq_i"],
                   "bit_range": [1, 1]}]
        with self.assertRaises(ComponentProfileError) as error:
            load(fields)
        self.assertIn("overlapping-port-binding:irq_i:"
                      "dut.bus:high+dut.bus:low", str(error.exception))

    def test_disjoint_bit_slices_load(self) -> None:
        profile = load([{"role": "low", "direction": "input", "aliases": ["irq_i"],
                         "bit_range": [0, 0]},
                        {"role": "high", "direction": "input", "aliases": ["irq_i"],
                         "bit_range": [1, 1]}])
        self.assertEqual(2, len(profile.endpoints[0].fields))


class MemberLayoutTests(unittest.TestCase):
    """Binding: the declared member is the elaborated member, offsets included."""

    def bind(self, fields, ports=(STRUCT_PORT, VECTOR_PORT)):
        profile = load(fields)
        return profile, bind_profile(profile, facts(*ports))

    def test_a_leaf_member_binds_its_elaborated_span(self) -> None:
        _profile, binding = self.bind(STRUCT_FIELDS)
        field = binding.field("dut.bus", "addr")
        self.assertEqual(("bus_o", ("aw", "addr"), 16, 79, 64),
                         (field.port, field.member_path, field.raw_lo, field.raw_hi,
                          field.width))
        self.assertEqual(84, field.port_width)
        self.assertFalse(field.whole_port)

    def test_an_intermediate_member_binds_the_union_of_its_leaves(self) -> None:
        _profile, binding = self.bind(STRUCT_FIELDS)
        field = binding.field("dut.bus", "user")
        self.assertEqual(("bus_o", ("user",), 1, 14, 14),
                         (field.port, field.member_path, field.raw_lo, field.raw_hi,
                          field.width))

    def test_a_declared_offset_the_elaboration_contradicts_is_refused(self) -> None:
        fields = [dict(STRUCT_FIELDS[1],
                       physical={"port": "bus_o", "member_path": ["aw", "addr"],
                                 "bit_range": [16, 78]})]
        with self.assertRaises(ComponentProfileError) as error:
            self.bind(fields + STRUCT_FIELDS[2:])
        self.assertIn("member-offset-conflict:dut.bus:addr:bus_o.aw.addr:"
                      "[79:16]!=[78:16]", str(error.exception))

    def test_a_member_the_struct_does_not_have_is_reported(self) -> None:
        fields = [{"role": "id", "direction": "output", "width": 4,
                   "physical": {"port": "bus_o", "member_path": ["aw", "identifier"]}}]
        with self.assertRaises(ComponentProfileError) as error:
            self.bind(fields + STRUCT_FIELDS[1:])
        self.assertIn("member-missing:dut.bus:id:bus_o.aw.identifier",
                      str(error.exception))

    def test_a_bit_slice_outside_its_port_is_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            self.bind([{"role": "entry", "direction": "input", "aliases": ["irq_i"],
                        "bit_range": [0, 3]}])
        self.assertIn("bit-range-outside-port:dut.bus:entry:irq_i:3>=width3",
                      str(error.exception))

    def test_a_member_of_the_wrong_direction_is_refused(self) -> None:
        fields = [{"role": "id", "direction": "input", "width": 4,
                   "physical": {"port": "bus_o", "member_path": ["aw", "id"]}}]
        with self.assertRaises(ComponentProfileError) as error:
            self.bind(fields + STRUCT_FIELDS[1:])
        self.assertIn("direction-conflict", str(error.exception))

    def test_a_second_endpoint_on_one_member_is_refused_at_load_time(self) -> None:
        document = profile_document(fields=STRUCT_FIELDS)
        document["endpoints"].append({
            "endpoint_id": "dut.other", "function": "external_pins",
            "fields": [{"role": "id", "direction": "output", "width": 4,
                        "physical": {"port": "bus_o", "member_path": ["aw", "id"]}}],
        })
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("duplicate-port-binding:bus_o:",
                      str(error.exception))

    def test_the_binding_refuses_a_duplicate_member_even_if_a_profile_says_so(self) -> None:
        """Defence in depth: the binding re-checks the per-bit claims itself."""
        profile = load(STRUCT_FIELDS)
        endpoint = profile.endpoints[0]
        duplicate = replace(endpoint, fields=endpoint.fields + (endpoint.fields[0],))
        broken = replace(profile, endpoints=(duplicate,))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, facts(STRUCT_PORT, VECTOR_PORT))
        self.assertIn("duplicate-physical-binding:bus_o:dut.bus:id+dut.bus:id",
                      str(error.exception))

    def test_the_binding_refuses_overlapping_bit_ranges(self) -> None:
        profile = load([{"role": "low", "direction": "input", "aliases": ["irq_i"],
                         "bit_range": [0, 1]}])
        endpoint = profile.endpoints[0]
        from myfuzz.composition.component_profile import ProfileField
        overlapping = ProfileField(role="high", direction="input", aliases=("irq_i",),
                                   bit_range=(1, 2))
        broken = replace(profile, endpoints=(
            replace(endpoint, fields=endpoint.fields + (overlapping,)),))
        with self.assertRaises(ComponentProfileError) as error:
            bind_profile(broken, facts(STRUCT_PORT, VECTOR_PORT))
        self.assertIn("overlapping-physical-binding:irq_i:[1:0]+dut.bus:high:[2:1]",
                      str(error.exception))


class LedgerCoverageTests(unittest.TestCase):
    """The whole-port coverage rule still holds, member by member."""

    def bind(self, fields, ports=(STRUCT_PORT,)):
        profile = load(fields)
        return profile, bind_profile(profile, facts(*ports))

    def test_every_member_role_gets_its_own_span_and_the_port_is_covered(self) -> None:
        profile, binding = self.bind(STRUCT_FIELDS, ports=(STRUCT_PORT,))
        entries = ledger(profile, binding)
        by_port = port_segments(entries)["bus_o"]
        covered = {bit for entry in by_port
                   for bit in range(entry.bit_lo, entry.bit_hi + 1)}
        self.assertEqual(set(range(84)), covered)
        self.assertEqual(84, sum(entry.bit_hi - entry.bit_lo + 1 for entry in by_port))
        self.assertEqual(84, entries[0].width)
        for entry in by_port:
            self.assertEqual(84, entry.width, "the recorded width is the port's")

    def test_a_partial_member_declaration_leaves_undisposed_bits(self) -> None:
        profile, binding = self.bind(STRUCT_FIELDS[:2] + [STRUCT_FIELDS[4]])
        with self.assertRaises(PortDispositionError) as error:
            ledger(profile, binding)
        self.assertIn("undisposed-port-bits:dut0:bus_o:15:1",
                      str(error.exception))

    def test_a_member_slice_and_a_constant_can_share_one_vector_port(self) -> None:
        from myfuzz.composition.component_profile import PortAction
        profile, binding = self.bind([
            {"role": "entry", "direction": "input", "aliases": ["irq_i"],
             "bit_range": [0, 0]}], ports=(VECTOR_PORT,))
        entries = ledger(profile, binding, actions=[
            PortAction(port="irq_i", action="constant", value=0, bits=(1, 2),
                       reason="the other two bits are held inactive")])
        by_role = {entry.role: entry for entry in entries}
        self.assertEqual((0, 0), (by_role["entry"].bit_lo, by_role["entry"].bit_hi))
        self.assertEqual([(1, 2)], [(entry.bit_lo, entry.bit_hi) for entry in entries
                                    if entry.disposition == "constant"])
        self.assertEqual({0, 1, 2}, {bit for entry in entries if entry.port == "irq_i"
                                     for bit in range(entry.bit_lo, entry.bit_hi + 1)})


class SegmentNamingTests(unittest.TestCase):
    """The net and top-port names the renderer, the plan and the audit share."""

    def entry(self, low, high, *, role="r", disposition="functional", width=8,
              value=None):
        return DispositionEntry(
            instance_id="dut0", component_id="structy", port="bus_o", bit_lo=low,
            bit_hi=high, direction="output", width=width, disposition=disposition,
            target="t", endpoint_id="dut.bus", role=role, value=value, strategy=None)

    def test_a_whole_port_segment_keeps_the_historical_name(self) -> None:
        whole = self.entry(0, 7)
        self.assertEqual("dut0__bus_o", segment_net(whole))
        self.assertEqual("dut0__bus_o", top_port_name(whole))
        self.assertEqual("dut0__bus_o__driven", driven_net(whole))
        self.assertFalse(port_is_aggregated((whole,)))

    def test_a_member_segment_is_role_qualified(self) -> None:
        part = self.entry(3, 5)
        self.assertEqual("dut0__bus_o__r", segment_net(part))
        self.assertEqual("dut0__bus_o_5_3", top_port_name(part))
        self.assertTrue(port_is_aggregated((part,)))
        self.assertTrue(port_is_aggregated((self.entry(0, 5), self.entry(6, 7))))

    def test_a_constant_segment_renders_its_own_width(self) -> None:
        constant = self.entry(3, 5, role=None, disposition="constant", value=5,
                              width=8)
        self.assertEqual("3'd5", constant_expression(constant))
        self.assertEqual("dut0__bus_o__constant_5_3", segment_net(constant))

    def test_the_plan_records_the_member_to_net_mapping(self) -> None:
        # An interrupt source is a *functional* role, so each member is wired to
        # the net of its own role rather than exported to the top boundary.
        profile = load(STRUCT_FIELDS, function="interrupt_source")
        binding = bind_profile(profile, facts(STRUCT_PORT))
        instance = type("Instance", (), {
            "instance_id": "dut0", "component_id": "structy", "binding": binding,
            "dispositions": ledger(profile, binding),
        })()
        records = port_binding_records(instance)
        by_port = {record["port"]: record for record in records}
        self.assertEqual({"bus_o"}, set(by_port))
        record = by_port["bus_o"]
        self.assertEqual(84, record["width"])
        self.assertEqual([("aw", "id"), ("aw", "addr"), ("valid",), ("user", "rsp"),
                          ("user", "data"), ("last",)],
                         [tuple(item["path"]) for item in record["members"]])
        self.assertEqual("bus_pkg::id_e", record["members"][0]["enum_type"])
        self.assertEqual([(80, 83), (16, 79), (15, 15), (1, 14), (0, 0)],
                         [(segment["bit_lo"], segment["bit_hi"])
                          for segment in record["segments"]])
        self.assertEqual(["dut0__bus_o__id", "dut0__bus_o__addr", "dut0__bus_o__valid",
                          "dut0__bus_o__user", "dut0__bus_o__last"],
                         [segment["expression"] for segment in record["segments"]])

    def test_a_group_segment_carries_the_whole_substruct(self) -> None:
        entry = self.entry(1, 14, role="user")
        self.assertEqual("dut0__bus_o__user", segment_net(entry))
        segments = aligned_segments(
            (self.entry(80, 83, role="id"), self.entry(16, 79, role="addr"),
             self.entry(15, 15, role="valid"), entry, self.entry(0, 0, role="last")),
            STRUCT_PORT.members, 84)
        # The whole user{...} group is one segment, so it is one leaf named by the
        # segment net rather than one leaf per integrity field.
        self.assertEqual([(80, 83, ("aw", "id")), (16, 79, ("aw", "addr")),
                          (15, 15, ("valid",)), (1, 14, ("user",)), (0, 0, ("last",))],
                         [(low, high, path) for low, high, path, _entry in segments])


class TreeAndAssemblyTests(unittest.TestCase):
    """The member tree and the segment order the rendered expression emits."""

    def entry(self, low, high, role, *, disposition="functional", value=None):
        return DispositionEntry(
            instance_id="dut0", component_id="structy", port="bus_o", bit_lo=low,
            bit_hi=high, direction="output", width=92, disposition=disposition,
            target="t", endpoint_id="dut.bus", role=role, value=value, strategy=None)

    def test_the_tree_rebuilds_the_nested_struct_in_span_order(self) -> None:
        tree = member_tree(STRUCT_PORT.members, 84)
        self.assertEqual(["aw", "user"], [child.name for child in tree.children])
        self.assertEqual([("aw", "id"), ("aw", "addr")],
                         [path for path, _low, _high in tree.children[0].leaves])
        self.assertEqual([("user", "rsp"), ("user", "data")],
                         [path for path, _low, _high in tree.children[1].leaves])
        # A plain member stays a leaf of the port itself, not a child node.
        self.assertEqual([("valid",), ("last",)],
                         [path for path, _low, _high in tree.leaves])
        # A node's items merge children and leaves by span, most significant first.
        self.assertEqual(["aw", "valid", "user", "last"],
                         [item.name if isinstance(item, object) and hasattr(item, "name")
                          else item[0][-1] for _high, item in tree.items()])

    def test_segments_tile_the_port_most_significant_first(self) -> None:
        entries = (self.entry(80, 83, "id"), self.entry(16, 79, "addr"),
                   self.entry(15, 15, "valid"), self.entry(1, 14, "user"),
                   self.entry(0, 0, "last"))
        segments = aligned_segments(entries, STRUCT_PORT.members, 84)
        self.assertEqual([(80, 83, ("aw", "id")), (16, 79, ("aw", "addr")),
                          (15, 15, ("valid",)), (1, 14, ("user",)),
                          (0, 0, ("last",))],
                         [(low, high, path) for low, high, path, _entry in segments])

    def test_a_slice_straddling_two_members_is_refused(self) -> None:
        # A slice from bit 7 to bit 16 covers the end of aw.addr, all of valid and
        # the top of user.rsp: it tiles the port but cannot be an assignment
        # pattern member, so it is refused instead of being reordered.
        entries = (self.entry(80, 83, "id"), self.entry(17, 79, "addr"),
                   self.entry(7, 16, "middle"), self.entry(0, 6, "rest"))
        with self.assertRaises(PortDispositionError) as error:
            aligned_segments(entries, STRUCT_PORT.members, 84)
        self.assertIn("struct-port-segment-mismatch:dut0:bus_o:",
                      str(error.exception))

    def test_a_gap_or_an_overlap_is_refused_by_name(self) -> None:
        gap = (self.entry(80, 83, "id"), self.entry(16, 79, "addr"),
               self.entry(15, 15, "valid"), self.entry(1, 14, "user"))
        with self.assertRaises(PortDispositionError) as error:
            aligned_segments(gap, STRUCT_PORT.members, 84)
        self.assertIn("port-segment-gap:dut0:bus_o:0", str(error.exception))
        overlap = (self.entry(79, 83, "id"), self.entry(16, 79, "addr"),
                   self.entry(15, 15, "valid"), self.entry(1, 14, "user"),
                   self.entry(0, 0, "last"))
        with self.assertRaises(PortDispositionError) as error:
            aligned_segments(overlap, STRUCT_PORT.members, 84)
        self.assertIn("port-segment-overlap:dut0:bus_o:[79:16]",
                      str(error.exception))

    def test_a_memberless_port_is_a_flat_concatenation(self) -> None:
        entries = (replace(self.entry(2, 2, "high"), width=3),
                   replace(self.entry(0, 1, "low"), width=3))
        segments = aligned_segments(entries, (), 3)
        self.assertEqual([(2, 2, ()), (0, 1, ())],
                         [(low, high, path) for low, high, path, _entry in segments])

    def test_a_constant_segment_is_a_literal_expression(self) -> None:
        constant = self.entry(0, 1, None, disposition="constant", value=3)
        self.assertEqual("2'd3", segment_expression(constant))
        self.assertEqual("2'd3", constant_expression(constant))
        self.assertIsNone(segment_expression(self.entry(
            0, 1, None, disposition="unconnected")))


class TlulVocabularyTests(unittest.TestCase):
    """The TL-UL plugin declares the members and widths the resolver needs."""

    def test_the_plugin_carries_every_tlul_member_the_adapter_drives(self) -> None:
        from myfuzz.composition.component_profile import (
            _protocol_field_directions, _protocol_field_widths)
        roles = _protocol_field_directions(("tl-ul", "1"))
        for role in ("a_user", "d_user", "d_error", "a_ready", "d_ready"):
            self.assertIn(role, roles)
        # Host-to-device fields are inputs of the peripheral target and
        # device-to-host fields are its outputs, including a_ready (which lives in
        # the response struct) and the integrity/error sidebands.
        self.assertEqual("input", roles["a_valid"])
        self.assertEqual("input", roles["d_ready"])
        self.assertEqual("output", roles["a_ready"])
        self.assertEqual("input", roles["a_user"])
        self.assertEqual("output", roles["d_user"])
        self.assertEqual("output", roles["d_error"])

    def test_the_protocol_widths_are_resolved_from_the_declared_capabilities(self) -> None:
        from myfuzz.composition.component_profile import _protocol_field_widths
        widths = _protocol_field_widths(("tl-ul", "1"), {
            "address_width": 32, "data_width": 32, "size_width": 2,
            "source_width": 8, "sink_width": 1, "user_width": 23,
            "d_user_width": 14,
        })
        self.assertEqual({"a_size": 2, "d_size": 2, "a_source": 8, "d_source": 8,
                          "a_user": 23, "d_user": 14, "a_address": 32, "a_data": 32,
                          "a_mask": 4, "d_error": 1},
                         {role: widths[role] for role in
                          ("a_size", "d_size", "a_source", "d_source", "a_user",
                           "d_user", "a_address", "a_data", "a_mask", "d_error")})

    def test_a_width_the_profile_does_not_declare_is_not_silently_guessed(self) -> None:
        from myfuzz.composition.component_profile import _protocol_field_widths
        widths = _protocol_field_widths(("tl-ul", "1"),
                                        {"address_width": 32, "data_width": 32})
        self.assertNotIn("a_size", widths)
        self.assertNotIn("a_source", widths)
        self.assertNotIn("a_user", widths)

    def test_the_declared_width_defaults_are_the_pinned_ones(self) -> None:
        from myfuzz.protocols.widths import (
            PROTOCOL_WIDTH_PARAMETER_DEFAULTS, compile_width_expression)
        self.assertEqual({"size_width": 2, "source_width": 8, "sink_width": 1,
                          "user_width": 23, "d_user_width": 14},
                         PROTOCOL_WIDTH_PARAMETER_DEFAULTS)
        self.assertEqual(2, compile_width_expression("size_width", {}))
        self.assertEqual(8, compile_width_expression("source_width", {}))
        self.assertEqual(4, compile_width_expression("data_width / 8",
                                                     {"data_width": 32}))


if __name__ == "__main__":
    unittest.main()
