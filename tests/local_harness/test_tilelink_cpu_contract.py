"""The declared BOOM CPU memory seam must bind exactly one TileLink contract.

``configs/cpus/boom/interface_description.json`` is the only real TileLink 1.0
declaration in this repository: the BOOM CPU-side seam.  Since the coherent
landing (commit 941d9be) it declares **one** endpoint, ``cpu.coherent_memory``
(39 A/B/C/D/E client roles, protocol ``["tilelink-coherent","1"]``); the split
``cpu.instruction_memory``/``cpu.data_memory`` pair this file used to read is
gone from the file, so assertions built on it can only fail.  The declaration
names roles and physical aliases only -- it deliberately leaves directions,
widths and signedness to the HDL crawler -- so this file supplies the published
``TL_COHERENT_SHAPE`` table for direction/width and takes role spelling and
physical-port aliases from the declaration itself.

These tests drive the *public* selector with the endpoint the declaration
describes, so a contract that no longer matches the real declaration fails
here.  Contract-only: no RTL is compiled, no runtime behaviour is claimed and no
DUT adherence is asserted.
"""
from __future__ import annotations

from dataclasses import replace
import importlib
import json
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import ResolvedEndpoint, ResolvedField
from myfuzz.local_harness.tilelink_coherent_fields import TL_COHERENT_SHAPE


ROOT = Path(__file__).resolve().parents[2]
BOOM_DECLARATION = ROOT / "configs" / "cpus" / "boom" / "interface_description.json"

# The declared seam is the coherent client, so the endpoint the contract is
# matched against is built from the declaration's roles/aliases plus the
# published shape table.  Both are pinned elsewhere (the plugin table and the
# derived ``BoomTile`` physical ports); this file only needs them to hand the
# selector a real endpoint instead of a hand-typed one.
_DECLARED_ENDPOINT = "cpu.coherent_memory"
_DECLARED_PROTOCOL = ("tilelink-coherent", "1")
_DECLARED_FUNCTION = "memory_master"
_DECLARED_ROLE_COUNT = 39
_CAPABILITIES = {"data_width": 64, "address_width": 32}


def registry():
    return importlib.import_module('myfuzz.local_harness.template_contracts')


def declaration() -> dict:
    return json.loads(BOOM_DECLARATION.read_text(encoding="utf-8"))


def declared(endpoint_id: str) -> dict:
    """The one declaration entry for ``endpoint_id``; fail loudly, not silently."""
    matches = [item for item in declaration()["endpoints"]
               if item["endpoint_id"] == endpoint_id]
    if len(matches) != 1:
        raise AssertionError(
            f"the declaration must publish exactly one {endpoint_id!r} endpoint, "
            f"found {len(matches)}: {[item['endpoint_id'] for item in declaration()['endpoints']]}")
    return matches[0]


def declared_roles(endpoint_id: str) -> set[str]:
    return {field["role"] for field in declared(endpoint_id)["fields"]}


def declared_aliases(endpoint_id: str) -> dict[str, str]:
    return {field["role"]: field["aliases"][0] for field in declared(endpoint_id)["fields"]}


def declared_endpoint(endpoint_id: str = _DECLARED_ENDPOINT) -> ResolvedEndpoint:
    """Resolve the declared roles into the record ``select_template_contract`` takes."""
    source = declared(endpoint_id)
    declared_role_set = {field["role"] for field in source["fields"]}
    missing = declared_role_set - set(TL_COHERENT_SHAPE)
    if missing or len(declared_role_set) != len(source["fields"]):
        raise AssertionError(
            f"declaration roles must be unique and covered by the published shape; "
            f"uncovered={sorted(missing)}")
    fields = []
    for field in source["fields"]:
        direction, width = TL_COHERENT_SHAPE[field["role"]]
        fields.append(ResolvedField(
            endpoint_id, field["role"], field["aliases"][0], (), direction,
            width, 0, width - 1, False, "BoomTile.sv", 1, width))
    return ResolvedEndpoint(endpoint_id, source["function"],
                            tuple(source["protocol"]), tuple(fields))


def contract():
    """The single registered TileLink coherent client contract."""
    matches = [item for item in registry().list_template_contracts()
               if item.template_id == "cpu.tilelink-coherent"]
    if len(matches) != 1:
        raise AssertionError(
            "exactly one cpu.tilelink-coherent contract must be registered, "
            f"found {[item.variant_id for item in matches]}")
    return matches[0]


class TileLinkCpuContractTests(unittest.TestCase):
    def test_declaration_publishes_the_coherent_seam_only(self):
        """The split instruction/data endpoints are gone; the seam is coherent."""
        published = [item["endpoint_id"] for item in declaration()["endpoints"]]
        self.assertEqual([_DECLARED_ENDPOINT], published)
        self.assertNotIn("cpu.instruction_memory", published)
        self.assertNotIn("cpu.data_memory", published)
        source = declared(_DECLARED_ENDPOINT)
        self.assertEqual(_DECLARED_FUNCTION, source["function"])
        self.assertEqual(list(_DECLARED_PROTOCOL), source["protocol"])
        self.assertEqual(_DECLARED_ROLE_COUNT, len(source["fields"]))
        # One role, one physical alias: the binding has nothing to disambiguate.
        roles = [field["role"] for field in source["fields"]]
        self.assertEqual(len(roles), len(set(roles)))
        self.assertTrue(all(len(field["aliases"]) == 1 for field in source["fields"]))

    def test_contract_role_vocabulary_is_the_declared_vocabulary(self):
        """The contract's roles must be exactly the declared roles, not invented."""
        item = contract()
        self.assertEqual(declared_roles(_DECLARED_ENDPOINT), set(item.required_roles))
        self.assertEqual(_DECLARED_ROLE_COUNT, len(item.required_roles))
        self.assertEqual((), item.optional_roles)
        self.assertEqual("cpu", item.side)
        self.assertEqual(_DECLARED_PROTOCOL, item.protocol)

    def test_declared_endpoint_selects_the_coherent_variant_uniquely(self):
        selected = registry().select_template_contract(
            declared_endpoint(), dict(_CAPABILITIES))
        self.assertEqual("cpu.tilelink-coherent", selected.contract.template_id)
        self.assertEqual("coherent-ab-cd-e-single-outstanding",
                         selected.contract.variant_id)
        document = selected.document()
        self.assertEqual(_DECLARED_ENDPOINT, document["binding"]["endpoint_id"])
        # The physical port names come from the declaration's own aliases.
        ports = {row["role"]: row["physical_port"]
                 for row in document["binding"]["roles"]}
        self.assertEqual(declared_aliases(_DECLARED_ENDPOINT), ports)
        self.assertEqual(64, document["binding"]["data_width"])
        self.assertEqual(32, document["binding"]["address_width"])
        self.assertFalse(document["runtime_effective"])
        self.assertFalse(document["dut_semantics_verified"])

    def test_each_other_shape_is_refused(self):
        """Fail closed: the declared shape is the only accepted shape."""
        source = declared_endpoint()
        missing = replace(source, fields=tuple(
            field for field in source.fields if field.role != "d_bits_denied"))
        unknown = replace(source, fields=source.fields + (
            ResolvedField(_DECLARED_ENDPOINT, "a_opcode", "a_opcode", (),
                          "output", 3, 0, 2, False, "BoomTile.sv", 1, 3),))
        reversed_directions = replace(source, fields=tuple(
            replace(field, direction="input" if field.direction == "output" else "output")
            for field in source.fields))
        wrong_opcode = replace(source, fields=tuple(
            replace(field, width=2, raw_lo=0, raw_hi=1, port_width=2)
            if field.role == "a_bits_opcode" else field for field in source.fields))
        wrong_data = replace(source, fields=tuple(
            replace(field, width=32, raw_lo=0, raw_hi=31, port_width=32)
            if field.role == "a_bits_data" else field for field in source.fields))
        wrong_mask = replace(source, fields=tuple(
            replace(field, width=4, raw_lo=0, raw_hi=3, port_width=4)
            if field.role == "a_bits_mask" else field for field in source.fields))
        wrong_address = replace(source, fields=tuple(
            replace(field, width=64, raw_lo=0, raw_hi=63, port_width=64)
            if field.role == "a_bits_address" else field for field in source.fields))
        for bad in (missing, unknown, reversed_directions, wrong_opcode, wrong_data,
                    wrong_mask, wrong_address):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                registry().select_template_contract(bad, dict(_CAPABILITIES))
        # The single-bit A/C/D/E handshake lines are checked too, not just width.
        reversed_valid = replace(source, fields=tuple(
            replace(field, direction="input" if field.direction == "output" else "output")
            if field.role == "a_valid" else field for field in source.fields))
        with self.assertRaises(ValueError):
            registry().select_template_contract(reversed_valid, dict(_CAPABILITIES))

    def test_coherent_client_is_not_the_tl_ul_target_contract(self):
        """``cpu.tilelink-coherent`` and ``target.tl-ul`` are different entries.

        TL-UL is derived from TileLink, so the two role *vocabularies* overlap
        by design (``a_valid``/``d_ready``/... exist on both sides).  What keeps
        them apart is the protocol/side pair, and that is what the selector
        enforces: neither is addressable as the other.
        """
        cpu = contract()
        target = next(item for item in registry().list_template_contracts()
                      if item.template_id == "target.tl-ul")
        self.assertNotEqual(cpu.template_id, target.template_id)
        self.assertEqual("cpu", cpu.side)
        self.assertEqual("target", target.side)
        self.assertEqual(_DECLARED_PROTOCOL, cpu.protocol)
        self.assertEqual(("tl-ul", "1"), target.protocol)
        self.assertNotEqual(cpu.protocol, target.protocol)
        self.assertLess(len(target.required_roles), len(cpu.required_roles))
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                declared_endpoint(), {}, template_id="target.tl-ul",
                template_version="1", variant_id="user-integrity")

    def test_retired_abstract_declaration_pair_is_gone_from_the_inventory(self):
        """The old four/five-role abstract pair is deleted, not merely refused.

        ``cpu.tilelink``/``declared-four-role`` and
        ``declared-five-role-write-capable`` were written against the removed
        split endpoints (protocol ``["tilelink","1"]``, roles
        address/request/read_data/response[/write_data]).  No declaration
        carries that shape since the coherent landing, so the two rows were
        deleted from the registry instead of staying in the inventory as
        permanently unreachable entries.  This test keeps the removal
        fail-closed: neither id, nor the ``tilelink`` 1.0 protocol, nor the
        abstract role vocabulary may come back by accident.
        """
        rows = registry().list_template_contracts()
        inventory = [(item.template_id, item.template_version, item.variant_id)
                     for item in rows]
        retired = [("cpu.tilelink", "1", "declared-four-role"),
                   ("cpu.tilelink", "1", "declared-five-role-write-capable")]
        for identity in retired:
            self.assertNotIn(identity, inventory)
        self.assertEqual([], [item.template_id for item in rows
                              if item.template_id == "cpu.tilelink"])
        self.assertEqual([], [item.protocol for item in rows
                              if tuple(item.protocol) == ("tilelink", "1")])
        # The abstract role vocabulary still belongs to no declared endpoint.
        abstract_roles = {"address", "request", "read_data", "response", "write_data"}
        self.assertEqual(5, len(abstract_roles))
        self.assertEqual(set(), abstract_roles & declared_roles(_DECLARED_ENDPOINT))
        # Fail closed: an explicit request for a retired identity cannot be
        # served, and it is refused as unregistered rather than matched by shape.
        for identity in retired:
            with self.subTest(identity=identity), self.assertRaises(ValueError) as refused:
                registry().select_template_contract(
                    declared_endpoint(), {}, template_id=identity[0],
                    template_version=identity[1], variant_id=identity[2])
            self.assertEqual("template-unregistered-selection", str(refused.exception))

    def test_limits_and_role_shapes_record_the_derived_vocabulary(self):
        item = contract()
        limits = dict(item.limits)
        # The role table is the bundled plugin, not a hand-typed transcription.
        self.assertEqual("src/myfuzz/protocols/plugins/tilelink-coherent.json",
                         limits["role_declaration"])
        self.assertEqual("tilelink_ab_cd_e_five_channel", limits["channel_vocabulary"])
        self.assertEqual((64,), limits["supported_data_widths"])
        self.assertEqual(1, limits["max_outstanding"])
        # The coherence claim is explicitly bounded to what the harness does.
        self.assertEqual("harness_never_probes_b_channel_stays_low",
                         limits["coherence_scope"])
        # Nothing may claim TileLink features the plugin never mentions.
        self.assertNotIn("ids", limits)
        self.assertNotIn("bursts", limits)
        shapes = item.document()["role_shapes"]
        self.assertEqual({"width": "address_width"}, shapes["a_bits_address"])
        self.assertEqual({"width": "data_width"}, shapes["a_bits_data"])
        self.assertEqual({"width": "data_width/8"}, shapes["a_bits_mask"])
        self.assertEqual({"width": 1}, shapes["a_valid"])
        self.assertEqual({"width": 3}, shapes["a_bits_opcode"])


class TileLinkCpuInventoryTests(unittest.TestCase):
    def test_coherent_entry_is_registered_once_with_distinct_identity(self):
        entries = [item for item in registry().list_template_contracts()
                   if item.template_id == "cpu.tilelink-coherent"]
        self.assertEqual(["coherent-ab-cd-e-single-outstanding"],
                         [item.variant_id for item in entries])
        self.assertEqual(_DECLARED_PROTOCOL, entries[0].protocol)
        self.assertEqual(_DECLARED_ROLE_COUNT, len(entries[0].required_roles))
        # Every inventory identity is unique and versioned; no absolute count is
        # pinned here on purpose (the registry total is owned by
        # ``test_template_contracts.test_inventory_versioned_frozen_and_no_runtime_claim``,
        # so adding an entry updates one file, not two).
        rows = registry().list_template_contracts()
        ids = [(item.template_id, item.template_version, item.variant_id)
               for item in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(item.template_version == "1" for item in rows))
        self.assertEqual(1, len([item for item in rows
                                 if item.protocol == _DECLARED_PROTOCOL]))


if __name__ == "__main__":
    unittest.main()
