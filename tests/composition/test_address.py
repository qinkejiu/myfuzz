from __future__ import annotations

import unittest

from myfuzz.composition.address import (
    AddressAllocationError,
    AddressError,
    AddressRegion,
    LocalRegion,
    allocate_regions,
    extract_local_regions,
)
from myfuzz.composition.declarations import ComponentDecl, DeclarationSet, PortDecl, ProtocolBinding, ProtocolFieldBinding
from myfuzz.composition.facts import HdlFacts, HdlModule, HdlPort


def facts_for(records: tuple[object, ...], *, components: tuple[tuple[int, int], ...] = ((101, 1), (202, 2)), role: str = "request.address") -> HdlFacts:
    modules = tuple(HdlModule(module_id, (port_id,), ()) for _, module_id in components for port_id in (module_id * 10 + 1,))
    ports = tuple(HdlPort(module_id * 10 + 1, module_id, "input", 32, False, role) for _, module_id in components)
    return HdlFacts(modules, ports, (("local_address_facts", records),))


def declarations_for(*, components: tuple[tuple[int, int], ...] = ((101, 1), (202, 2))) -> DeclarationSet:
    return DeclarationSet(
        tuple(
            ComponentDecl(
                component_id,
                module_id,
                "target",
                (PortDecl(module_id * 10 + 1, "request.address", True),),
                (ProtocolBinding(component_id * 10, "bus", "target", (ProtocolFieldBinding("request.address", module_id * 10 + 1),)),),
                (),
            )
            for component_id, module_id in components
        )
    )


class AddressAllocatorTests(unittest.TestCase):
    def test_extracts_only_explicitly_tied_local_address_facts(self) -> None:
        facts = facts_for(
            (
                {"address_field_port_id": 11, "offset": 0x20, "size": 4, "alignment": 4, "state_id": 7},
                {"offset": 0x80, "size": 8},
            )
        )
        regions = extract_local_regions(facts, declarations_for())

        self.assertEqual(len(regions), 1)
        self.assertEqual((regions[0].component_id, regions[0].port_id, regions[0].offset, regions[0].size), (101, 11, 0x20, 4))
        self.assertEqual(regions[0].alignment, 4)

    def test_custom_address_role_is_accepted_only_with_explicit_field_id(self) -> None:
        facts = facts_for(
            (
                {"address_field_port_id": 11, "offset": 0x10, "size": 4},
                {"port_id": 11, "offset": 0x20, "size": 4},
            ),
            role="bus.addr",
        )
        custom_declarations = DeclarationSet(
            tuple(
                ComponentDecl(
                    component.id,
                    component.module_id,
                    component.role,
                    (PortDecl(11 if component.module_id == 1 else 21, "bus.addr", True),),
                    (ProtocolBinding(component.id * 10, "bus", "target", (ProtocolFieldBinding("bus.addr", 11 if component.module_id == 1 else 21),)),),
                    (),
                )
                for component in declarations_for().components
            )
        )

        regions = extract_local_regions(facts, custom_declarations)

        self.assertEqual([(region.port_id, region.offset) for region in regions], [(11, 0x10)])

    def test_address_like_role_without_explicit_field_id_is_not_inferred(self) -> None:
        facts = facts_for(({"port_id": 11, "offset": 0, "size": 4},))

        self.assertEqual(extract_local_regions(facts, declarations_for()), ())

    def test_preserves_fixed_bases_and_allocates_non_overlapping_aligned_regions(self) -> None:
        regions = (
            LocalRegion(101, 11, 0, 0x100, 0x100, fixed_base=0x400),
            LocalRegion(202, 21, 0, 0x80, 0x80),
            LocalRegion(303, 31, 0, 0x80, 0x80),
        )
        allocated = allocate_regions(regions, {"address_width": 16})

        self.assertEqual(allocated[0].base, 0x400)
        self.assertEqual([(item.component_id, item.base, item.size) for item in allocated], [(101, 0x400, 0x100), (202, 0, 0x80), (303, 0x80, 0x80)])
        self.assertEqual(set(allocated), {AddressRegion(101, 11, 0x400, 0x100, 0, "fixed"), AddressRegion(202, 21, 0, 0x80, 0, "inferred"), AddressRegion(303, 31, 0x80, 0x80, 0, "inferred")})

    def test_applies_fixed_base_constraint_by_region_id(self) -> None:
        region = LocalRegion(101, 11, 0x20, 0x40, 0x40, region_id=7)

        allocated = allocate_regions((region,), {"address_width": 12, "fixed_bases": {7: 0x300}})

        self.assertEqual(allocated[0], AddressRegion(101, 11, 0x300, 0x40, 0x20, "fixed"))

    def test_equal_solutions_are_ordered_by_opaque_component_id(self) -> None:
        regions = (
            LocalRegion(900, 91, 0, 0x100, 0x100),
            LocalRegion(100, 81, 0, 0x100, 0x100),
        )
        allocated = allocate_regions(regions, {"address_width": 12})

        self.assertEqual([(item.component_id, item.base) for item in allocated], [(100, 0), (900, 0x100)])

    def test_local_offset_is_retained_in_absolute_region(self) -> None:
        region = LocalRegion(101, 11, 0x30, 0x10, 0x10)
        allocated = allocate_regions((region,), {"address_width": 12})

        self.assertEqual(allocated[0].base, 0)
        self.assertEqual(allocated[0].local_offset, 0x30)
        self.assertEqual(allocated[0].provenance, "inferred")

    def test_rejects_overflow_and_fixed_overlap_with_structured_conflicts(self) -> None:
        with self.assertRaises(AddressAllocationError) as overflow:
            allocate_regions((LocalRegion(101, 11, 0, 0x100, 0x100, fixed_base=0x1000),), {"address_width": 12})
        self.assertTrue(any(conflict.kind == "address_width" for conflict in overflow.exception.conflicts))

        with self.assertRaises(AddressAllocationError) as overlap:
            allocate_regions((LocalRegion(101, 11, 0, 0x100, 0x100, fixed_base=0), LocalRegion(202, 21, 0, 0x100, 0x100, fixed_base=0x80)), {"address_width": 12})
        self.assertTrue(any(conflict.kind == "overlap" for conflict in overlap.exception.conflicts))

    def test_rejects_malformed_regions_and_non_declared_alignment(self) -> None:
        with self.assertRaises(AddressError):
            LocalRegion(101, 11, -1, 4, 4)
        with self.assertRaises(AddressAllocationError) as invalid:
            allocate_regions((LocalRegion(101, 11, 0, 4, 3),), {"address_width": 12})
        self.assertTrue(any(conflict.kind == "alignment" for conflict in invalid.exception.conflicts))

    def test_extract_rejects_unknown_address_port_and_bad_size(self) -> None:
        bad_port_facts = facts_for(({"address_field_port_id": 99, "offset": 0, "size": 4},))
        with self.assertRaises(AddressError):
            extract_local_regions(bad_port_facts, declarations_for())

        bad_size_facts = facts_for(({"address_field_port_id": 11, "offset": 0, "size": 0},))
        with self.assertRaises(AddressError):
            extract_local_regions(bad_size_facts, declarations_for())


if __name__ == "__main__":
    unittest.main()
