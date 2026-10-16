"""CPU-side TileLink 1.0 contracts, derived from a real declaration.

The only real TileLink 1.0 declaration in this repository is the BOOM semantic
interface description (``configs/cpus/boom/interface_description.json``).  These
tests load that file and build the endpoints from the roles it declares, so a
contract that does not match the real declaration fails here.  Contract-only:
no RTL is compiled, no runtime behaviour is claimed and no DUT adherence is
asserted.
"""
from __future__ import annotations

from dataclasses import replace
import importlib
import json
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import ResolvedEndpoint, ResolvedField


ROOT = Path(__file__).resolve().parents[2]
BOOM_DECLARATION = ROOT / "configs" / "cpus" / "boom" / "interface_description.json"

# The declaration names roles only: it leaves directions, widths, signedness and
# hierarchy to the HDL crawler.  The test therefore supplies the master-side
# convention itself -- a TileLink master drives address/request (and write_data)
# towards the device and receives read_data/response back -- and the widths the
# declaration does not carry.  Only the role vocabulary comes from the file.
_HOST_ROLES = frozenset({"address", "request", "write_data"})
_WIDTHS = {"address": 64, "request": 1, "write_data": 64, "read_data": 64, "response": 1}
_A_B_C_D_E_CHANNEL_ROLES = frozenset((
    "a_valid", "a_ready", "a_opcode", "a_param", "a_size", "a_source", "a_address",
    "a_mask", "a_data", "a_user", "a_corrupt",
    "b_valid", "b_ready", "b_opcode", "b_param", "b_size", "b_source", "b_address",
    "b_mask", "b_data", "b_user", "b_corrupt",
    "c_valid", "c_ready", "c_opcode", "c_param", "c_size", "c_source", "c_address",
    "c_data", "c_user", "c_corrupt",
    "d_valid", "d_ready", "d_opcode", "d_param", "d_size", "d_source", "d_sink",
    "d_data", "d_user", "d_error", "d_corrupt",
    "e_valid", "e_ready", "e_sink",
))


def registry():
    return importlib.import_module('myfuzz.local_harness.template_contracts')


def declaration() -> dict:
    return json.loads(BOOM_DECLARATION.read_text(encoding="utf-8"))


def declared(endpoint_id: str) -> dict:
    return next(item for item in declaration()["endpoints"]
                if item["endpoint_id"] == endpoint_id)


def declared_roles(endpoint_id: str) -> set[str]:
    return {field["role"] for field in declared(endpoint_id)["fields"]}


def declared_aliases(endpoint_id: str) -> dict[str, str]:
    return {field["role"]: field["aliases"][0] for field in declared(endpoint_id)["fields"]}


def declared_endpoint(endpoint_id: str) -> ResolvedEndpoint:
    """Resolve the declared roles into the record ``select_template_contract`` takes."""
    source = declared(endpoint_id)
    fields = []
    for field in source["fields"]:
        role = field["role"]
        width = _WIDTHS[role]
        fields.append(ResolvedField(
            endpoint_id, role, field["aliases"][0], (),
            "output" if role in _HOST_ROLES else "input",
            width, 0, width - 1, False, "boom_tile.sv", 1, width))
    return ResolvedEndpoint(endpoint_id, source["function"],
                            tuple(source["protocol"]), tuple(fields))


def contract(variant_id: str):
    return next(item for item in registry().list_template_contracts()
                if (item.template_id, item.variant_id) == ("cpu.tilelink", variant_id))


class TileLinkCpuContractTests(unittest.TestCase):
    def test_role_vocabulary_is_copied_from_the_real_boom_declaration(self):
        """The contract's roles must be exactly the declared roles, not invented."""
        self.assertEqual({"address", "read_data", "request", "response"},
                         declared_roles("cpu.instruction_memory"))
        self.assertEqual({"address", "write_data", "read_data", "request", "response"},
                         declared_roles("cpu.data_memory"))
        self.assertEqual(declared_roles("cpu.instruction_memory"),
                         set(contract("declared-four-role").required_roles))
        self.assertEqual(declared_roles("cpu.data_memory"),
                         set(contract("declared-five-role-write-capable").required_roles))
        self.assertEqual(("tilelink", "1"), tuple(declared("cpu.data_memory")["protocol"]))

    def test_no_a_b_c_d_e_channel_is_smuggled_into_the_contract(self):
        """A five-channel protocol dump would stop matching the real declaration."""
        for variant in ("declared-four-role", "declared-five-role-write-capable"):
            with self.subTest(variant=variant):
                item = contract(variant)
                roles = set(item.required_roles) | set(item.optional_roles)
                self.assertFalse(roles & _A_B_C_D_E_CHANNEL_ROLES)
                self.assertEqual((), item.optional_roles)
                self.assertEqual("cpu", item.side)
                self.assertEqual(("tilelink", "1"), item.protocol)

    def test_declared_instruction_endpoint_selects_the_four_role_contract(self):
        selected = registry().select_template_contract(
            declared_endpoint("cpu.instruction_memory"),
            {"data_width": 64, "address_width": 64})
        self.assertEqual("cpu.tilelink", selected.contract.template_id)
        self.assertEqual("declared-four-role", selected.contract.variant_id)
        self.assertEqual(("address", "request"), selected.contract.host_to_device_roles)
        document = selected.document()
        self.assertEqual("cpu.instruction_memory", document["binding"]["endpoint_id"])
        # The physical port names come from the declaration's own aliases.
        ports = {row["role"]: row["physical_port"]
                 for row in document["binding"]["roles"]}
        self.assertEqual(declared_aliases("cpu.instruction_memory"), ports)
        self.assertFalse(document["runtime_effective"])
        self.assertFalse(document["dut_semantics_verified"])
        self.assertEqual(64, document["binding"]["data_width"])

    def test_declared_data_endpoint_selects_the_write_capable_variant(self):
        selected = registry().select_template_contract(
            declared_endpoint("cpu.data_memory"),
            {"data_width": 64, "address_width": 64})
        self.assertEqual("declared-five-role-write-capable", selected.contract.variant_id)
        self.assertEqual(("address", "request", "write_data"),
                         selected.contract.host_to_device_roles)
        self.assertNotEqual(contract("declared-four-role"),
                            selected.contract)

    def test_each_variant_refuses_the_other_real_endpoint(self):
        """The two declared shapes must not be interchangeable."""
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                declared_endpoint("cpu.instruction_memory"), {},
                template_id="cpu.tilelink", template_version="1",
                variant_id="declared-five-role-write-capable")
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                declared_endpoint("cpu.data_memory"), {},
                template_id="cpu.tilelink", template_version="1",
                variant_id="declared-four-role")

    def test_reversed_missing_unknown_direction_and_width_mismatches_refuse(self):
        """Fail closed: the declared shape is the only accepted shape."""
        source = declared_endpoint("cpu.instruction_memory")
        reversed_directions = replace(source, fields=tuple(
            replace(field, direction="input" if field.direction == "output" else "output")
            for field in source.fields))
        missing = replace(source, fields=tuple(
            field for field in source.fields if field.role != "response"))
        unknown = replace(source, fields=source.fields + (
            ResolvedField("cpu.instruction_memory", "a_opcode", "a_opcode", (),
                          "output", 3, 0, 2, False, "boom_tile.sv", 1, 3),))
        wrong_data = replace(source, fields=tuple(
            replace(field, width=24, raw_hi=23, port_width=24)
            if field.role == "read_data" else field for field in source.fields))
        wrong_address = replace(source, fields=tuple(
            replace(field, width=128, raw_hi=127, port_width=128)
            if field.role == "address" else field for field in source.fields))
        wrong_request_direction = replace(source, fields=tuple(
            replace(field, direction="input") if field.role == "request" else field
            for field in source.fields))
        for bad in (reversed_directions, missing, unknown, wrong_data, wrong_address,
                    wrong_request_direction):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                registry().select_template_contract(bad, {})
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                source, {"error_response": True})
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                declared_endpoint("cpu.data_memory"), {"byte_enable": True})

    def test_tilelink_cpu_is_not_the_target_tl_ul_entry(self):
        """``cpu.tilelink`` and ``target.tl-ul`` are different inventory entries."""
        cpu = contract("declared-four-role")
        target = next(item for item in registry().list_template_contracts()
                      if item.template_id == "target.tl-ul")
        self.assertNotEqual(cpu.template_id, target.template_id)
        self.assertEqual("cpu", cpu.side)
        self.assertEqual("target", target.side)
        self.assertEqual(("tilelink", "1"), cpu.protocol)
        self.assertEqual(("tl-ul", "1"), target.protocol)
        self.assertNotEqual(cpu.protocol, target.protocol)
        self.assertFalse(set(cpu.required_roles) & set(target.required_roles))
        # A TL-UL peripheral target is not a TileLink CPU endpoint, and the
        # TileLink CPU endpoint is not addressable as the TL-UL target.
        with self.assertRaises(ValueError):
            registry().select_template_contract(
                declared_endpoint("cpu.instruction_memory"), {},
                template_id="target.tl-ul", template_version="1",
                variant_id="user-integrity")

    def test_declared_vocabulary_limits_are_recorded_and_not_overclaimed(self):
        limits = dict(contract("declared-four-role").limits)
        self.assertEqual("configs/cpus/boom/interface_description.json",
                         limits["role_declaration"])
        self.assertEqual("declared_abstract_roles_only_no_a_b_c_d_e_mapping",
                         limits["channel_vocabulary"])
        self.assertEqual("not_declared_not_claimed", limits["undeclared_capability_policy"])
        self.assertIs(limits["byte_enable"], False)
        self.assertIs(limits["partial_write"], False)
        self.assertIs(limits["error_response"], False)
        self.assertEqual(1, limits["max_outstanding"])
        # Nothing may claim TileLink features the declaration never mentions.
        self.assertNotIn("coherence", limits)
        self.assertNotIn("bursts", limits)
        self.assertNotIn("ids", limits)


class TileLinkCpuInventoryTests(unittest.TestCase):
    def test_both_tilelink_entries_are_in_the_registry_with_distinct_identity(self):
        entries = [item for item in registry().list_template_contracts()
                   if item.template_id == "cpu.tilelink"]
        self.assertEqual(["declared-five-role-write-capable", "declared-four-role"],
                         sorted(item.variant_id for item in entries))
        self.assertEqual(2, len(entries))
        self.assertNotEqual(entries[0].identity_sha256, entries[1].identity_sha256)
        ids = [(item.template_id, item.template_version, item.variant_id)
               for item in registry().list_template_contracts()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(17, len(registry().list_template_contracts()))

    def test_declared_role_shapes_drive_the_width_checks(self):
        shapes = contract("declared-four-role").document()["role_shapes"]
        self.assertEqual({"width": "address_width"}, shapes["address"])
        self.assertEqual({"width": "data_width"}, shapes["read_data"])
        # The declaration carries no width for the abstract request/response
        # roles, so the contract must not invent one (no fixed 1-bit claim).
        self.assertEqual({"width": "source_defined", "max_width": 4096},
                         shapes["request"])
        self.assertEqual({"width": "source_defined", "max_width": 4096},
                         shapes["response"])


if __name__ == "__main__":
    unittest.main()
