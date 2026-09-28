"""Compile exclusive bit ownership for DUT inputs.

The map describes which bits may be mutated. A direction chooses among the
declared sources elsewhere; it cannot turn a bound bit into a source.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


_KINDS = frozenset(("source", "bound", "fixed"))
_DIRECTIONS = frozenset(("CPU_TO_IP", "IP_TO_CPU", "IP_TO_IP",
                         "CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP",
                         "MULTI_COMPONENT_CHAIN"))


@dataclass(frozen=True)
class InputField:
    component_id: str
    port: str
    width: int

    def __post_init__(self) -> None:
        if not self.component_id or not self.port:
            raise ValueError("component_id and port must be nonempty")
        if isinstance(self.width, bool) or not isinstance(self.width, int) or self.width < 1:
            raise ValueError("input width must be positive")


@dataclass(frozen=True)
class InputOwner:
    component_id: str
    port: str
    bit_offset: int
    width: int
    kind: str
    producer_ref: str

    def __post_init__(self) -> None:
        if not self.component_id or not self.port or not self.producer_ref:
            raise ValueError("owner identity and producer_ref must be nonempty")
        if self.kind not in _KINDS:
            raise ValueError("unknown input owner kind")
        if (isinstance(self.bit_offset, bool) or not isinstance(self.bit_offset, int)
                or self.bit_offset < 0 or isinstance(self.width, bool)
                or not isinstance(self.width, int) or self.width < 1):
            raise ValueError("owner bit range is invalid")


class OwnershipMap:
    def __init__(self, bits: dict[tuple[str, str], tuple[InputOwner, ...]]) -> None:
        self._bits = bits

    def document(self) -> dict:
        """Stable source/binding identity for corpus and replay manifests."""
        fields = [{"component_id": component, "port": port, "width": len(bits)}
                  for (component, port), bits in sorted(self._bits.items())]
        owners = sorted({owner for bits in self._bits.values() for owner in bits},
                        key=lambda owner: (owner.component_id, owner.port,
                                           owner.bit_offset, owner.width,
                                           owner.kind, owner.producer_ref))
        return {"fields": fields, "owners": [asdict(owner) for owner in owners]}

    def mutation_source(self, component_id: str, port: str, bit_offset: int,
                        width: int, *, direction: str) -> str:
        if direction not in _DIRECTIONS:
            raise ValueError("unknown mutation direction")
        bits = self._bits.get((component_id, port))
        if bits is None:
            raise ValueError("undeclared input field")
        if (isinstance(bit_offset, bool) or not isinstance(bit_offset, int)
                or bit_offset < 0 or isinstance(width, bool)
                or not isinstance(width, int) or width < 1
                or bit_offset + width > len(bits)):
            raise ValueError("mutation range exceeds input field")
        selected = bits[bit_offset:bit_offset + width]
        for owner in selected:
            if owner.kind != "source":
                raise ValueError(f"{owner.kind} input cannot be mutated")
        producers = {owner.producer_ref for owner in selected}
        if len(producers) != 1:
            raise ValueError("mutation spans multiple fuzzable sources")
        return next(iter(producers))

    def field_width(self, component_id: str, port: str) -> int:
        bits = self._bits.get((component_id, port))
        if bits is None:
            raise ValueError("undeclared input field")
        return len(bits)

    def binding_producer(self, component_id: str, port: str,
                         bit_offset: int, width: int) -> str:
        bits = self._bits.get((component_id, port))
        if bits is None or bit_offset < 0 or width < 1 or bit_offset + width > len(bits):
            raise ValueError("binding range exceeds input field")
        selected = bits[bit_offset:bit_offset + width]
        if any(owner.kind != "bound" for owner in selected):
            raise ValueError("route target is not bound input")
        producers = {owner.producer_ref for owner in selected}
        if len(producers) != 1:
            raise ValueError("route target has multiple producers")
        return next(iter(producers))


def compile_ownership(fields: tuple[InputField, ...],
                      owners: tuple[InputOwner, ...]) -> OwnershipMap:
    if not isinstance(fields, tuple) or not isinstance(owners, tuple):
        raise ValueError("fields and owners must be tuples")
    bits: dict[tuple[str, str], list[InputOwner | None]] = {}
    for field in fields:
        if not isinstance(field, InputField):
            raise ValueError("fields must contain InputField records")
        key = (field.component_id, field.port)
        if key in bits:
            raise ValueError("duplicate input field")
        bits[key] = [None] * field.width
    for owner in owners:
        if not isinstance(owner, InputOwner):
            raise ValueError("owners must contain InputOwner records")
        key = (owner.component_id, owner.port)
        if key not in bits:
            raise ValueError("owner references undeclared input field")
        field_bits = bits[key]
        if owner.bit_offset + owner.width > len(field_bits):
            raise ValueError("owner exceeds input width")
        for index in range(owner.bit_offset, owner.bit_offset + owner.width):
            if field_bits[index] is not None:
                raise ValueError("input ownership overlap")
            field_bits[index] = owner
    if any(owner is None for field_bits in bits.values() for owner in field_bits):
        raise ValueError("input has unclassified bits")
    return OwnershipMap({key: tuple(field_bits) for key, field_bits in bits.items()})
