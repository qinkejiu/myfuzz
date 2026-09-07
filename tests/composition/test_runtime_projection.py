from dataclasses import replace
import unittest
from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
from myfuzz.composition import runtime_projection


class RuntimeProjectionTests(unittest.TestCase):
    def test_declared_width_must_equal_raw_slice_width(self):
        field = LayoutField("a", "e", "data", 8, 0, 3, "bits", {"range": [16, 28]})
        adjacent = LayoutField("b", "e", "status", 4, 4, 7, "bits", {})
        for width, fields in ((4, (field,)), (8, (field, adjacent))):
            with self.subTest(raw_width=width):
                layout = InputLayout("input_layout.v1", width, fields, "id")
                # Legal for the generic ABI, but not for an in-place projector:
                # previously project(0) returned 26, spilling beyond bits 0..3.
                layout.to_raw_abi()
                with self.assertRaisesRegex(ValueError, "width.*slice"):
                    runtime_projection.RuntimeProjector(layout)

    def test_projection_preserves_adjacent_field_bits(self):
        fields = (
            LayoutField("a", "e", "data", 4, 0, 3, "bits", {"range": [0, 12], "alignment": 4}),
            LayoutField("b", "e", "status", 4, 4, 7, "bits", {}),
        )
        projector = runtime_projection.RuntimeProjector(InputLayout("input_layout.v1", 8, fields, "id"))
        for raw in range(256):
            projected = projector.project(raw)
            self.assertLess(projected, 256)
            self.assertEqual(projected >> 4, raw >> 4)
            self.assertEqual(projected & 15, (raw & 15) // 4 * 4)

    def test_caller_range_mutation_does_not_change_validated_projection(self):
        bounds = [0, 8]
        field = LayoutField("a", "e", "data", 8, 0, 7, "bits", {"range": bounds, "alignment": 4})
        layout = InputLayout("input_layout.v1", 8, (field,), "id")
        projector = runtime_projection.RuntimeProjector(layout)
        before = tuple(projector.project(raw) for raw in range(256))
        bounds[:] = [1, 9]
        # Previously returned 9 for raw zero, violating validated alignment.
        self.assertEqual(projector.project(0), 0)
        self.assertEqual(tuple(projector.project(raw) for raw in range(256)), before)
        self.assertEqual(layout.fields[0].constraint["range"], [1, 9])
        self.assertEqual(projector.layout.fields[0].constraint["range"], (0, 8))
        with self.assertRaises(TypeError):
            projector.layout.fields[0].constraint["range"][0] = 1
        with self.assertRaises(TypeError):
            projector.layout.fields[0].constraint["alignment"] = 1

    def test_conflicting_constraints_are_rejected_before_projection(self):
        valid = LayoutField("v", "e", "valid", 1, 0, 0, "bits", {})
        data = LayoutField("d", "e", "data", 32, 1, 32, "bits", {})
        cases = (
            replace(data, owner="other", constraint={"gated_by":"v"}),
            replace(data, constraint={"gated_by":"v", "range":[1,8]}),
            replace(data, encoding="riscv_imc", constraint={"alignment":4}),
            replace(data, encoding="riscv_imc", constraint={"gated_by":"v"}),
            replace(data, encoding="riscv_imc", constraint={"range":[0,8]}),
        )
        for field in cases:
            with self.subTest(field=field), self.assertRaises(ValueError):
                runtime_projection.RuntimeProjector(InputLayout("input_layout.v1",33,(valid,field),"id"),
                    isa=IsaContract(32,("I",)))

    def test_range_alignment_signedness_and_gate_share_declared_layout(self):
        fields=(LayoutField("e:valid","e","valid",1,0,0,"bits",{}),
                LayoutField("e:address","e","address",8,1,8,"bits",{"range":[16,28],"alignment":4}),
                LayoutField("e:ready","e","ready",1,9,9,"bits",{"gated_by":"e:valid"}),
                LayoutField("e:data","e","data",8,10,17,"bits",{"range":[-8,7]},signed=True))
        layout=InputLayout("input_layout.v1",18,fields,"identity")
        result=runtime_projection.project_word(layout,(255<<1)|(1<<9)|(255<<10))
        self.assertEqual((result>>1)&255,28)
        self.assertEqual((result>>9)&1,0)
        self.assertEqual((result>>10)&255,255)

    def test_instruction_legality_is_isa_driven_and_raw_mode_is_explicit(self):
        for width,extensions in ((16,("I","C")),(32,("I","M"))):
            with self.subTest(width=width):
                isa=IsaContract(32,extensions,instruction_alignment=2 if width==16 else 4)
                field=LayoutField("i","e","instruction",width,0,width-1,"riscv_imc",{})
                layout=InputLayout("input_layout.v1",width,(field,),"id")
                result=runtime_projection.project_word(layout,0,isa=isa)
                self.assertTrue(RiscvInstructionProvider(isa).is_legal_word(result,compressed=width==16))
                self.assertEqual(runtime_projection.project_word(layout,result,isa=isa),result)
                raw=replace(layout,fields=(replace(field,encoding="raw_instruction"),))
                self.assertEqual(runtime_projection.project_word(raw,0),0)

    def test_unbound_dependency_or_unknown_constraint_fails_closed(self):
        base=LayoutField("a","e","data",8,0,7,"bits",{})
        for field in (replace(base,dependency_group="unbound"),replace(base,constraint={"unknown":1}),
                      replace(base,encoding="riscv_imc"),replace(base,constraint={"gated_by":"missing"})):
            with self.subTest(field=field),self.assertRaises(ValueError):
                runtime_projection.project_word(InputLayout("input_layout.v1",8,(field,),"id"),0)
