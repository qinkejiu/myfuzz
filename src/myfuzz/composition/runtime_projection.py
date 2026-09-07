"""Stateless layout constraints for live simulation; protocol FSMs stay in RTL."""
from dataclasses import replace

from .input_layout import InputLayout
from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider


class RuntimeProjector:
    def __init__(self, layout: InputLayout, *, isa: IsaContract | None = None):
        if not isinstance(layout, InputLayout):
            raise ValueError("runtime projection requires layout")
        # Validate and project the same detached snapshot. Range is the only
        # supported nested constraint; all other validated values are scalars.
        fields = []
        for field in layout.fields:
            if field.width != field.raw_hi - field.raw_lo + 1:
                raise ValueError("runtime field width must equal raw slice width")
            constraint = dict(field.constraint)
            if isinstance(constraint.get("range"), (list, tuple)):
                constraint["range"] = tuple(constraint["range"])
            fields.append(replace(field, constraint=constraint))
        layout = replace(layout, fields=tuple(fields))
        layout.to_raw_abi()
        self.layout = layout
        self.provider = RiscvInstructionProvider(isa) if isa is not None else None
        by_id = {field.field_id: field for field in layout.fields}
        if len(by_id) != len(layout.fields):
            raise ValueError("duplicate runtime field")
        for field in layout.fields:
            if field.dependency_group is not None:
                raise ValueError("unbound runtime dependency group")
            if set(field.constraint) - {"range", "alignment", "gated_by", "byte_enable_width"}:
                raise ValueError("unsupported runtime constraint")
            if field.encoding not in {"bits", "raw_instruction", "riscv_imc"}:
                raise ValueError("unsupported runtime encoding")
            if field.encoding == "riscv_imc":
                # Repairing an opcode cannot also promise arbitrary numeric bounds
                # or zero-on-invalid gating; those require an intersection solver.
                if field.constraint or field.signed:
                    raise ValueError("unsupported instruction constraint intersection")
                if self.provider is None or not isa.supports_legal_instruction_validation or field.width not in (16, 32):
                    raise ValueError("missing implemented instruction contract")
                if field.width == 16 and ("C" not in isa.extensions or isa.instruction_alignment != 2):
                    raise ValueError("compressed instruction contract mismatch")
            alignment = field.constraint.get("alignment", 1)
            if type(alignment) is not int or alignment < 1 or alignment & (alignment - 1) or alignment > 1 << field.width:
                raise ValueError("invalid runtime alignment")
            bounds = field.constraint.get("range")
            if bounds is not None:
                minimum = -(1 << (field.width - 1)) if field.signed else 0
                maximum = (1 << (field.width - 1)) - 1 if field.signed else (1 << field.width) - 1
                if not isinstance(bounds, (list, tuple)) or len(bounds) != 2 or any(type(v) is not int for v in bounds):
                    raise ValueError("invalid runtime range")
                if not minimum <= bounds[0] <= bounds[1] <= maximum or any(v % alignment for v in bounds):
                    raise ValueError("runtime range/alignment conflict")
            gate = field.constraint.get("gated_by")
            if gate is not None and (gate not in by_id or by_id[gate].width != 1 or by_id[gate].role != "valid" or by_id[gate].owner != field.owner or field.role == "valid"):
                raise ValueError("invalid runtime gate")
            if gate is not None and bounds is not None and not bounds[0] <= 0 <= bounds[1]:
                raise ValueError("runtime gate/range conflict")
            be = field.constraint.get("byte_enable_width")
            if be is not None and (type(be) is not int or be != field.width):
                raise ValueError("invalid byte enable constraint")

    def project(self, raw: int) -> int:
        if type(raw) is not int or not 0 <= raw < 1 << self.layout.raw_width:
            raise ValueError("raw sample outside layout")
        values = {}
        for field in self.layout.fields:
            mask = (1 << field.width) - 1
            value = (raw >> field.raw_lo) & mask
            if field.signed and value & (1 << (field.width - 1)):
                value -= 1 << field.width
            alignment = field.constraint.get("alignment", 1)
            bounds = field.constraint.get("range")
            if bounds is None:
                value = (value // alignment) * alignment
            else:
                lo, hi = bounds
                value = lo + (((value - lo) // alignment) % ((hi - lo) // alignment + 1)) * alignment
            value &= mask
            if field.encoding == "riscv_imc" and not self.provider.is_legal_word(value, compressed=field.width == 16):
                value = 0x0001 if field.width == 16 else 0x00000013  # architectural NOP
            values[field.field_id] = value
        result = 0
        for field in self.layout.fields:
            gate = field.constraint.get("gated_by")
            value = values[field.field_id] if gate is None or values[gate] else 0
            result |= value << field.raw_lo
        return result


def project_word(layout: InputLayout, raw: int, *, isa: IsaContract | None = None) -> int:
    return RuntimeProjector(layout, isa=isa).project(raw)
