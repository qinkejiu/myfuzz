"""Generic local-address extraction and deterministic region allocation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import canonical_bytes

from .declarations import DeclarationSet
from .facts import HdlFacts


class AddressError(ValueError):
    """Malformed address fact, declaration, or region input."""


@dataclass(frozen=True, slots=True)
class AddressConflict:
    kind: str
    component_ids: tuple[int, ...]
    detail: str


class AddressAllocationError(AddressError):
    """Raised when no address assignment satisfies the supplied constraints."""

    def __init__(self, conflicts: Sequence[AddressConflict]) -> None:
        self.conflicts = tuple(conflicts)
        detail = "; ".join(f"{item.kind}:{item.detail}" for item in self.conflicts) or "unsatisfiable address constraints"
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class LocalRegion:
    component_id: int
    port_id: int
    offset: int
    size: int
    alignment: int = 1
    fixed_base: int | None = None
    region_id: int | None = None
    provenance: str = "rtl"

    def __post_init__(self) -> None:
        _positive_id(self.component_id, "component_id")
        _positive_id(self.port_id, "port_id")
        if not isinstance(self.offset, int) or isinstance(self.offset, bool) or self.offset < 0:
            raise AddressError("offset:invalid")
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
            raise AddressError("size:invalid")
        if not isinstance(self.alignment, int) or isinstance(self.alignment, bool) or self.alignment <= 0:
            raise AddressError("alignment:invalid")
        if self.fixed_base is not None and (not isinstance(self.fixed_base, int) or isinstance(self.fixed_base, bool) or self.fixed_base < 0):
            raise AddressError("fixed_base:invalid")
        if self.region_id is not None:
            _positive_id(self.region_id, "region_id")


@dataclass(frozen=True, slots=True)
class AddressRegion:
    component_id: int
    port_id: int
    base: int
    size: int
    local_offset: int = 0
    provenance: str = "inferred"

    def __post_init__(self) -> None:
        _positive_id(self.component_id, "component_id")
        _positive_id(self.port_id, "port_id")
        if not isinstance(self.base, int) or isinstance(self.base, bool) or self.base < 0:
            raise AddressError("base:invalid")
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
            raise AddressError("size:invalid")
        if not isinstance(self.local_offset, int) or isinstance(self.local_offset, bool) or self.local_offset < 0:
            raise AddressError("local_offset:invalid")


_ADDRESS_FIELD_KEYS = frozenset(("address_field_port_id", "address_port_id"))


def _positive_id(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise AddressError(f"{path}:invalid-id")
    return value


def _nonnegative(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AddressError(f"{path}:invalid")
    return value


def _record_mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if isinstance(value, tuple):
        pairs: list[tuple[str, object]] = []
        for item in value:
            if not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str):
                return None
            pairs.append((item[0], item[1]))
        return dict(pairs)
    return None


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return tuple((str(key), _freeze(item)) for key, item in sorted(value.items(), key=lambda pair: str(pair[0])))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _fact_port_id(record: Mapping[str, object]) -> int | None:
    present = [_positive_id(record[key], key) for key in _ADDRESS_FIELD_KEYS if key in record]
    if len(present) > 1 and present[0] != present[1]:
        raise AddressError("local_address_facts:conflicting-address-field-ids")
    if present:
        return present[0]
    return None


def _validated_local_address_entries(facts: HdlFacts, declarations: DeclarationSet) -> tuple[tuple[LocalRegion, object], ...]:
    declarations.validate_against(facts)
    port_to_component: dict[int, int] = {}
    bound_field_ports: set[int] = set()
    for component in declarations.components:
        for port in component.ports:
            port_to_component[port.port_id] = component.id
        for binding in component.protocol_bindings:
            bound_field_ports.update(field.port_id for field in binding.fields)

    records = tuple(record for section, section_records in facts.structural_sections if section == "local_address_facts" for record in section_records)
    entries: list[tuple[LocalRegion, object]] = []
    for ordinal, raw_record in enumerate(records):
        frozen_record = _freeze(raw_record)
        record = _record_mapping(frozen_record)
        if record is None:
            raise AddressError(f"local_address_facts[{ordinal}]:type")
        port_id = _fact_port_id(record)
        if port_id is None:
            # Facts not tied to a declared address field are intentionally ignored.
            continue
        if port_id not in port_to_component:
            raise AddressError(f"local_address_facts[{ordinal}].port_id:unresolved-reference")
        if port_id not in bound_field_ports:
            raise AddressError(f"local_address_facts[{ordinal}].port_id:not-bound-protocol-field")
        offset = _nonnegative(record.get("offset", record.get("local_offset", 0)), f"local_address_facts[{ordinal}].offset")
        size_value = record.get("size", record.get("window_size"))
        if size_value is None:
            raise AddressError(f"local_address_facts[{ordinal}].size:missing")
        size = _positive_id(size_value, f"local_address_facts[{ordinal}].size")
        alignment = _positive_id(record.get("alignment", 1), f"local_address_facts[{ordinal}].alignment")
        fixed_base = record.get("fixed_base")
        if fixed_base is not None:
            fixed_base = _nonnegative(fixed_base, f"local_address_facts[{ordinal}].fixed_base")
        region_id = record.get("region_id", record.get("state_id"))
        if region_id is not None:
            region_id = _positive_id(region_id, f"local_address_facts[{ordinal}].region_id")
        entries.append((LocalRegion(port_to_component[port_id], port_id, offset, size, alignment, fixed_base, region_id, "rtl"), frozen_record))
    return tuple(sorted(entries, key=lambda item: canonical_bytes(item[1])))


def extract_local_regions_with_evidence(facts: HdlFacts, declarations: DeclarationSet) -> tuple[tuple[LocalRegion, ...], tuple[object, ...]]:
    """Return validated local windows and canonical source-fact evidence."""
    entries = _validated_local_address_entries(facts, declarations)
    return tuple(item[0] for item in entries), tuple(item[1] for item in entries)


def extract_local_regions(facts: HdlFacts, declarations: DeclarationSet) -> tuple[LocalRegion, ...]:
    """Extract local windows only when a fact references an explicit address field."""
    regions, _ = extract_local_regions_with_evidence(facts, declarations)
    return tuple(sorted(regions, key=lambda item: (item.component_id, item.port_id, item.offset, item.size, item.region_id or 0)))


def _constraint_value(constraints: object, *keys: str, default: object = None) -> object:
    if isinstance(constraints, Mapping):
        for key in keys:
            if key in constraints:
                return constraints[key]
    else:
        for key in keys:
            if hasattr(constraints, key):
                return getattr(constraints, key)
    return default


def _alignment_allowed(alignment: int, declared: set[int]) -> bool:
    return alignment & (alignment - 1) == 0 or alignment in declared


def _intervals_overlap(base: int, size: int, occupied: Sequence[tuple[int, int, int]]) -> tuple[int, int, int] | None:
    end = base + size
    for other_base, other_end, other_index in occupied:
        if base < other_end and other_base < end:
            return other_base, other_end, other_index
    return None


def _aligned(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _candidate_bases(region: LocalRegion, occupied: Sequence[tuple[int, int, int]], limit: int, address_limit: int) -> tuple[int, ...]:
    starts = [0]
    # Every collision can advance directly to the end of the occupied interval;
    # this enumerates all meaningful first-fit boundaries without scanning a
    # potentially 64-bit address space.
    for base, end, _ in sorted(occupied):
        starts.extend((base, end))
    starts = sorted({_aligned(start, region.alignment) for start in starts if start <= address_limit})
    candidates: list[int] = []
    for start in starts:
        current = start
        while current + region.size <= address_limit and len(candidates) < limit:
            overlap = _intervals_overlap(current, region.size, occupied)
            if overlap is None:
                candidates.append(current)
                break
            current = _aligned(overlap[1], region.alignment)
    return tuple(dict.fromkeys(candidates))


def allocate_regions(regions: Sequence[LocalRegion], constraints: object) -> tuple[AddressRegion, ...]:
    """Allocate fixed and inferred regions with bounded deterministic backtracking."""
    if not isinstance(regions, Sequence) or isinstance(regions, (str, bytes)):
        raise AddressError("regions:type")
    normalized = tuple(regions)
    width_value = _constraint_value(constraints, "address_width", "address_width_bits", default=64)
    width = _positive_id(width_value, "address_width")
    if width > 64:
        raise AddressError("address_width:unsupported")
    address_limit = 1 << width
    global_alignment_value = _constraint_value(constraints, "alignment", default=1)
    global_alignment = _positive_id(global_alignment_value, "alignment")
    declared_values = _constraint_value(constraints, "declared_alignments", "allowed_alignments", "alignments", default=())
    if not isinstance(declared_values, Sequence) or isinstance(declared_values, (str, bytes)):
        raise AddressError("declared_alignments:type")
    declared_alignments = {_positive_id(value, "declared_alignments") for value in declared_values}
    max_nodes = _positive_id(_constraint_value(constraints, "backtrack_limit", "max_backtracks", default=4096), "backtrack_limit")
    candidate_limit = _positive_id(_constraint_value(constraints, "candidate_limit", default=128), "candidate_limit")
    fixed_bases = _constraint_value(constraints, "fixed_bases", default={})
    if not isinstance(fixed_bases, Mapping):
        raise AddressError("fixed_bases:type")

    effective: list[LocalRegion] = []
    conflicts: list[AddressConflict] = []
    for region in normalized:
        if not isinstance(region, LocalRegion):
            raise AddressError("regions:item-type")
        alignment = max(region.alignment, global_alignment)
        explicit_base = region.fixed_base
        fixed_keys: tuple[object, ...] = (
            *((region.region_id, str(region.region_id)) if region.region_id is not None else ()),
            region.component_id,
            str(region.component_id),
            region.port_id,
            str(region.port_id),
        )
        for key in fixed_keys:
            if explicit_base is None and key in fixed_bases:
                explicit_base = _nonnegative(fixed_bases[key], "fixed_bases.base")
                break
        if not _alignment_allowed(alignment, declared_alignments):
            conflicts.append(AddressConflict("alignment", (region.component_id,), f"alignment {alignment} is not power-of-two or declared"))
        effective.append(LocalRegion(region.component_id, region.port_id, region.offset, region.size, alignment, explicit_base, region.region_id, region.provenance))
    if conflicts:
        raise AddressAllocationError(conflicts)

    ordered = tuple(sorted(enumerate(effective), key=lambda pair: (pair[1].fixed_base is None, pair[1].component_id, pair[1].port_id, pair[1].offset, pair[0])))
    occupied: list[tuple[int, int, int]] = []
    assigned: dict[int, int] = {}
    for index, region in ordered:
        if region.fixed_base is None:
            continue
        base = region.fixed_base
        if base % region.alignment:
            conflicts.append(AddressConflict("alignment", (region.component_id,), f"fixed base {base} is not aligned"))
        if base + region.size > address_limit:
            conflicts.append(AddressConflict("address_width", (region.component_id,), f"fixed region ends at {base + region.size}, limit is {address_limit}"))
        overlap = _intervals_overlap(base, region.size, occupied)
        if overlap is not None:
            conflicts.append(AddressConflict("overlap", (region.component_id, effective[overlap[2]].component_id), f"fixed region overlaps region index {overlap[2]}"))
        occupied.append((base, base + region.size, index))
        assigned[index] = base
    if conflicts:
        raise AddressAllocationError(tuple(conflicts))

    mutable = tuple((index, region) for index, region in ordered if region.fixed_base is None)
    nodes = 0

    def search(position: int, current: list[tuple[int, int, int]]) -> bool:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            return False
        if position == len(mutable):
            return True
        index, region = mutable[position]
        for base in _candidate_bases(region, current, candidate_limit, address_limit):
            assigned[index] = base
            current.append((base, base + region.size, index))
            if search(position + 1, current):
                return True
            current.pop()
            assigned.pop(index, None)
        return False

    if not search(0, occupied[:]):
        raise AddressAllocationError((AddressConflict("unsatisfiable", tuple(region.component_id for _, region in mutable), "bounded search found no non-overlapping assignment"),))

    result: list[AddressRegion] = []
    for index, region in enumerate(effective):
        base = assigned[index]
        result.append(AddressRegion(region.component_id, region.port_id, base, region.size, region.offset, "fixed" if region.fixed_base is not None else "inferred"))
    return tuple(sorted(result, key=lambda item: (item.component_id, item.port_id, item.base, item.local_offset)))


__all__ = [
    "AddressAllocationError",
    "AddressConflict",
    "AddressError",
    "AddressRegion",
    "LocalRegion",
    "allocate_regions",
    "extract_local_regions_with_evidence",
    "extract_local_regions",
]
