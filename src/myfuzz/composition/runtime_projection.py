"""Stateless layout constraints for live simulation; protocol FSMs stay in RTL.

Projection order is mask, finite-value selection or range/alignment mapping,
instruction legality, inactive-gate zeroing, then raw-layout reconstruction.
Inactive gate zeroing deliberately overrides field constraints, including enums
whose declared active values do not contain zero.
"""
import hashlib
from dataclasses import replace

from myfuzz.contracts import canonical_bytes

from .input_layout import InputLayout
from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
from myfuzz.isa.transducer import RiscvInstructionTransducer


class RuntimeProjector:
    def __init__(self, layout: InputLayout, *, isa: IsaContract | None = None,
                 require_compiler_provenance: bool = False):
        if not isinstance(layout, InputLayout):
            raise ValueError("runtime projection requires layout")
        # Validate and project the same detached snapshot. Mutable constraint
        # sequences are copied so callers cannot change a running campaign.
        fields = []
        for field in layout.fields:
            if field.width != field.raw_hi - field.raw_lo + 1:
                raise ValueError("runtime field width must equal raw slice width")
            constraint = dict(field.constraint)
            if isinstance(constraint.get("range"), (list, tuple)):
                constraint["range"] = tuple(constraint["range"])
            if isinstance(constraint.get("enum"), (list, tuple)):
                constraint["enum"] = tuple(constraint["enum"])
            fields.append(replace(field, constraint=constraint))
        layout = replace(layout, fields=tuple(fields))
        layout.to_raw_abi()
        self.layout = layout
        self.provider = RiscvInstructionProvider(isa) if isa is not None else None
        self.instruction_transducer = (
            RiscvInstructionTransducer(isa)
            if isa is not None and isa.supports_legal_instruction_validation
            else None
        )
        self._constraint_candidates: dict[str, tuple[int, ...]] = {}
        by_id = {field.field_id: field for field in layout.fields}
        if len(by_id) != len(layout.fields):
            raise ValueError("duplicate runtime field")
        for field in layout.fields:
            if field.dependency_group is not None:
                raise ValueError("unbound runtime dependency group")
            if set(field.constraint) - {
                "range", "alignment", "enum", "mask", "randomizable", "gated_by", "byte_enable_width"
            }:
                raise ValueError("unsupported runtime constraint")
            if field.encoding not in {"bits", "raw_instruction", "riscv_imc"}:
                raise ValueError("unsupported runtime encoding")
            if require_compiler_provenance and field.member_path and "compiler_elaboration" not in set(field.evidence):
                raise ValueError("packed runtime binding lacks compiler provenance")
            if "randomizable" in field.constraint and type(field.constraint["randomizable"]) is not bool:
                raise ValueError("runtime randomizable must be boolean")
            if field.encoding == "riscv_imc":
                # Repairing an opcode cannot also promise arbitrary numeric bounds
                # or zero-on-invalid gating; those require an intersection solver.
                semantic_constraints = set(field.constraint) - {"randomizable"}
                if semantic_constraints or field.signed:
                    raise ValueError("unsupported instruction constraint intersection")
                if self.provider is None or not isa.supports_legal_instruction_validation or field.width not in (16, 32):
                    raise ValueError("missing implemented instruction contract")
                if field.width == 16 and ("C" not in isa.extensions or isa.instruction_alignment != 2):
                    raise ValueError("compressed instruction contract mismatch")
            alignment = field.constraint.get("alignment", 1)
            if type(alignment) is not int or alignment < 1 or alignment & (alignment - 1) or alignment > 1 << field.width:
                raise ValueError("invalid runtime alignment")
            mask = field.constraint.get("mask")
            if mask is not None and (
                type(mask) is not int or mask < 0 or mask >= 1 << field.width
            ):
                raise ValueError("invalid runtime mask")
            bounds = field.constraint.get("range")
            if bounds is not None:
                minimum = -(1 << (field.width - 1)) if field.signed else 0
                maximum = (1 << (field.width - 1)) - 1 if field.signed else (1 << field.width) - 1
                if not isinstance(bounds, (list, tuple)) or len(bounds) != 2 or any(type(v) is not int for v in bounds):
                    raise ValueError("invalid runtime range")
                if not minimum <= bounds[0] <= bounds[1] <= maximum or any(v % alignment for v in bounds):
                    raise ValueError("runtime range/alignment conflict")
            enum = field.constraint.get("enum")
            if enum is not None:
                if (
                    not isinstance(enum, (list, tuple))
                    or not enum
                    or any(type(value) is not int for value in enum)
                    or len(set(enum)) != len(enum)
                ):
                    raise ValueError("invalid runtime enum")
                minimum = -(1 << (field.width - 1)) if field.signed else 0
                maximum = (1 << (field.width - 1)) - 1 if field.signed else (1 << field.width) - 1
                if any(value < minimum or value > maximum for value in enum):
                    raise ValueError("runtime enum outside field width")
                if any(value % alignment for value in enum):
                    raise ValueError("runtime enum/alignment conflict")
                if bounds is not None and any(not bounds[0] <= value <= bounds[1] for value in enum):
                    raise ValueError("runtime enum/range conflict")
                if mask is not None:
                    field_mask = (1 << field.width) - 1
                    if any((value & field_mask) & ~mask for value in enum):
                        raise ValueError("runtime enum/mask conflict")
                self._constraint_candidates[field.field_id] = tuple(enum)
            if mask is not None and bounds is not None:
                span = (bounds[1] - bounds[0]) // alignment
                if span > 1_000_000:
                    raise ValueError("runtime range/mask intersection is not bounded")
                candidates = tuple(
                    bounds[0] + index * alignment
                    for index in range(span + 1)
                    if (((bounds[0] + index * alignment) & ((1 << field.width) - 1)) & ~mask) == 0
                )
                if not candidates:
                    raise ValueError("runtime range/mask conflict")
                self._constraint_candidates[field.field_id] = candidates
            gate = field.constraint.get("gated_by")
            if gate is not None and (gate not in by_id or by_id[gate].width != 1 or by_id[gate].role != "valid" or by_id[gate].owner != field.owner or field.role == "valid"):
                raise ValueError("invalid runtime gate")
            if gate is not None and bounds is not None and not bounds[0] <= 0 <= bounds[1]:
                raise ValueError("runtime gate/range conflict")
            be = field.constraint.get("byte_enable_width")
            if be is not None and (type(be) is not int or be != field.width):
                raise ValueError("invalid byte enable constraint")
            if field.role == "byte_enable":
                data = by_id.get(f"{field.owner}:data")
                if data is None or data.width % 8 or field.width != data.width // 8:
                    raise ValueError("byte-enable/data width mismatch")
                if be is not None and be != data.width // 8:
                    raise ValueError("byte-enable/data width mismatch")
            elif be is not None:
                raise ValueError("byte-enable constraint requires byte-enable field")
        self._validate_port_bindings()
        modes = {
            "legal" if field.encoding == "riscv_imc" else "raw"
            for field in layout.fields
            if field.role == "instruction"
        }
        self.instruction_modes = tuple(sorted(modes))
        self.instruction_mode = (
            next(iter(self.instruction_modes)) if len(self.instruction_modes) == 1
            else "mixed" if self.instruction_modes else "none"
        )
        self._constraint_document = self._build_constraint_document()
        self.constraint_hash = "sha256:" + hashlib.sha256(
            canonical_bytes(self._constraint_document)
        ).hexdigest()

    def _build_constraint_document(self) -> dict[str, object]:
        fields = []
        for field in self.layout.fields:
            constraint = {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in sorted(field.constraint.items())
            }
            fields.append({
                "field_id": field.field_id,
                "role": field.role,
                "width": field.width,
                "raw_lo": field.raw_lo,
                "raw_hi": field.raw_hi,
                "encoding": field.encoding,
                "signed": field.signed,
                "constraint": constraint,
                "port": field.port,
                "member_path": list(field.member_path),
                "port_raw_lo": field.port_raw_lo,
                "port_raw_hi": field.port_raw_hi,
                "port_width": field.port_width,
            })
        return {
            "schema_version": "runtime_constraints.v2",
            "layout_hash": self.layout.layout_hash,
            "instruction_mode": self.instruction_mode,
            "isa_contract": None if self.provider is None else {
                "xlen": self.provider.contract.xlen,
                "extensions": list(self.provider.contract.extensions),
                "privilege_modes": list(self.provider.contract.privilege_modes),
                "instruction_alignment": self.provider.contract.instruction_alignment,
            },
            "projection_order": [
                "mask",
                "finite_selection_or_range_alignment",
                "instruction_legality",
                "inactive_gate_zero",
                "raw_reconstruction",
            ],
            "gating_semantics": "inactive_zero_overrides_field_constraints",
            "fields": fields,
        }

    def _validate_port_bindings(self) -> None:
        by_port = {}
        for field in self.layout.fields:
            if not field.port:
                continue
            coordinates = (field.port_raw_lo, field.port_raw_hi, field.port_width)
            if field.member_path:
                if any(type(value) is not int for value in coordinates):
                    raise ValueError("packed runtime binding is incomplete")
                assert field.port_raw_lo is not None and field.port_raw_hi is not None
                assert field.port_width is not None
                if (field.port_raw_lo < 0 or field.port_raw_hi < field.port_raw_lo or
                        field.port_raw_hi >= field.port_width or
                        field.port_raw_hi - field.port_raw_lo + 1 != field.width):
                    raise ValueError("packed runtime binding has invalid range")
            elif any(value is not None for value in coordinates):
                raise ValueError("packed runtime binding lacks member path")
            by_port.setdefault(field.port, []).append(field)
        for port, fields in by_port.items():
            members = [field for field in fields if field.member_path]
            if members and len(members) != len(fields):
                raise ValueError(f"packed runtime binding mixes whole port: {port}")
            if not members:
                if len(fields) != 1:
                    raise ValueError(f"runtime port binding is duplicated: {port}")
                continue
            widths = {field.port_width for field in members}
            if len(widths) != 1:
                raise ValueError(f"packed runtime binding has inconsistent width: {port}")
            width = next(iter(widths))
            assert width is not None
            cursor = 0
            for field in sorted(members, key=lambda item: item.port_raw_lo):
                assert field.port_raw_lo is not None and field.port_raw_hi is not None
                if field.port_raw_lo != cursor:
                    raise ValueError(f"packed runtime binding is incomplete or overlapping: {port}")
                cursor = field.port_raw_hi + 1
            if cursor != width:
                raise ValueError(f"packed runtime binding is incomplete: {port}")

    def project(self, raw: int) -> int:
        if type(raw) is not int or not 0 <= raw < 1 << self.layout.raw_width:
            raise ValueError("raw sample outside layout")
        values = {}
        for field in self.layout.fields:
            mask = (1 << field.width) - 1
            source = (raw >> field.raw_lo) & mask
            constraint = field.constraint
            source_mask = constraint.get("mask")
            if source_mask is not None:
                source &= source_mask
            enum = constraint.get("enum")
            alignment = field.constraint.get("alignment", 1)
            bounds = field.constraint.get("range")
            if enum is not None:
                candidates = self._constraint_candidates[field.field_id]
                value = candidates[source % len(candidates)]
            elif bounds is not None and source_mask is not None:
                candidates = self._constraint_candidates[field.field_id]
                value = candidates[source % len(candidates)]
            else:
                value = source
                if field.signed and value & (1 << (field.width - 1)):
                    value -= 1 << field.width
                if bounds is None:
                    value = (value // alignment) * alignment
                else:
                    lo, hi = bounds
                    value = lo + (((value - lo) // alignment) % ((hi - lo) // alignment + 1)) * alignment
            value &= mask
            if field.encoding == "riscv_imc":
                assert self.instruction_transducer is not None
                selector = value >> max(0, field.width - self.instruction_transducer.selector_width)
                value = self.instruction_transducer.repair(
                    selector,
                    value,
                    width=field.width,
                ).word
            values[field.field_id] = value
        result = 0
        for field in self.layout.fields:
            gate = field.constraint.get("gated_by")
            value = values[field.field_id] if gate is None or values[gate] else 0
            result |= value << field.raw_lo
        return result

    def project_ports(self, raw: int) -> dict[str, int]:
        """Project one RFuzz word and rebuild each physical DUT input port."""
        projected = self.project(raw)
        ports: dict[str, int] = {}
        for field in self.layout.fields:
            if not field.port:
                raise ValueError(f"runtime field has no physical port: {field.field_id}")
            value = (projected >> field.raw_lo) & ((1 << field.width) - 1)
            if field.member_path:
                assert field.port_raw_lo is not None
                ports[field.port] = ports.get(field.port, 0) | (value << field.port_raw_lo)
            else:
                ports[field.port] = value
        return ports


def project_word(layout: InputLayout, raw: int, *, isa: IsaContract | None = None) -> int:
    return RuntimeProjector(layout, isa=isa).project(raw)
