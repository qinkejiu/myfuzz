from dataclasses import replace
import unittest
from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
from myfuzz.composition import runtime_projection


class RuntimeProjectionTests(unittest.TestCase):
    def test_projected_fields_reconstruct_compiler_proven_packed_input(self):
        fields = (
            LayoutField("e:ready", "e", "ready", 1, 0, 0, "bits", {},
                        port="rsp_bundle", member_path=("ready",),
                        port_raw_lo=32, port_raw_hi=32, port_width=33),
            LayoutField("e:data", "e", "data", 32, 1, 32, "bits", {"range": [4, 12], "alignment": 4},
                        port="rsp_bundle", member_path=("data",),
                        port_raw_lo=0, port_raw_hi=31, port_width=33),
        )
        projector = runtime_projection.RuntimeProjector(
            InputLayout("input_layout.v1", 33, fields, "packed")
        )
        projected = projector.project((1 << 0) | (15 << 1))
        ports = projector.project_ports((1 << 0) | (15 << 1))

        self.assertEqual(12, (projected >> 1) & 0xffffffff)
        self.assertEqual((1 << 32) | 12, ports["rsp_bundle"])

    def test_packed_runtime_binding_must_be_complete_and_nonoverlapping(self):
        base = LayoutField("e:a", "e", "data", 4, 0, 3, "bits", {},
                           port="bundle", member_path=("a",),
                           port_raw_lo=0, port_raw_hi=3, port_width=8)
        cases = (
            (base,),
            (base, replace(base, field_id="e:b", role="status", raw_lo=4, raw_hi=7,
                           member_path=("b",), port_raw_lo=3, port_raw_hi=6)),
            (base, replace(base, field_id="e:b", role="status", raw_lo=4, raw_hi=7,
                           member_path=("b",), port_raw_lo=4, port_raw_hi=7, port_width=9)),
        )
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, "packed runtime"):
                runtime_projection.RuntimeProjector(
                    InputLayout("input_layout.v1", sum(f.width for f in fields), fields, "bad")
                )
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

    def test_legal_instruction_projection_retains_diverse_rfuzz_operations(self):
        isa = IsaContract(32, ("I", "M"))
        field = LayoutField("i", "e", "instruction", 32, 0, 31, "riscv_imc", {})
        layout = InputLayout("input_layout.v1", 32, (field,), "diverse-instructions")
        projector = runtime_projection.RuntimeProjector(layout, isa=isa)
        provider = RiscvInstructionProvider(isa)

        projected = tuple(
            projector.project((selector << 24) | 0x0055_AA00)
            for selector in range(256)
        )

        self.assertTrue(all(provider.is_legal_word(word) for word in projected))
        self.assertGreaterEqual(len(set(projected)), 10)
        self.assertEqual(
            projected,
            tuple(
                projector.project((selector << 24) | 0x0055_AA00)
                for selector in range(256)
            ),
        )

    def test_unbound_dependency_or_unknown_constraint_fails_closed(self):
        base=LayoutField("a","e","data",8,0,7,"bits",{})
        for field in (replace(base,dependency_group="unbound"),replace(base,constraint={"unknown":1}),
                      replace(base,encoding="riscv_imc"),replace(base,constraint={"gated_by":"missing"})):
            with self.subTest(field=field),self.assertRaises(ValueError):
                runtime_projection.project_word(InputLayout("input_layout.v1",8,(field,),"id"),0)

    def test_enum_and_mask_constraints_are_applied_before_reconstruction(self):
        fields = (
            LayoutField("e:enum", "e", "enum", 4, 0, 3, "bits", {"enum": [1, 4, 7]},
                        port="enum_port"),
            LayoutField("e:mask", "e", "mask", 4, 4, 7, "bits", {"mask": 0b1010},
                        port="mask_port"),
        )
        projector = runtime_projection.RuntimeProjector(InputLayout("input_layout.v1", 8, fields, "id"))

        self.assertEqual(1, projector.project(0) & 0xF)
        self.assertEqual(4, projector.project(1) & 0xF)
        self.assertEqual(7, projector.project(2) & 0xF)
        self.assertEqual(1, projector.project(3) & 0xF)
        self.assertEqual(0b1010, (projector.project(0xF0) >> 4) & 0xF)

    def test_byte_enable_constraint_matches_same_owner_data_width(self):
        valid = LayoutField("e:valid", "e", "valid", 1, 0, 0, "bits", {})
        data = LayoutField("e:data", "e", "data", 32, 1, 32, "bits", {})
        byte_enable = LayoutField("e:byte_enable", "e", "byte_enable", 4, 33, 36, "bits",
                                  {"byte_enable_width": 4})
        runtime_projection.RuntimeProjector(
            InputLayout("input_layout.v1", 37, (valid, data, byte_enable), "id")
        )
        invalid = replace(byte_enable, width=8, raw_hi=40,
                          constraint={"byte_enable_width": 8})
        with self.assertRaisesRegex(ValueError, "byte-enable.*data"):
            runtime_projection.RuntimeProjector(
                InputLayout("input_layout.v1", 41, (valid, data, invalid), "id")
            )

    def test_instruction_mode_and_constraint_hash_are_explicit(self):
        raw_layout = InputLayout(
            "input_layout.v1", 32,
            (LayoutField("e:instruction", "e", "instruction", 32, 0, 31,
                         "raw_instruction", {}, port="instruction"),),
            "raw",
        )
        raw_projector = runtime_projection.RuntimeProjector(raw_layout)
        self.assertEqual("raw", raw_projector.instruction_mode)
        self.assertTrue(raw_projector.constraint_hash.startswith("sha256:"))

        isa = IsaContract(32, ("I",))
        legal_layout = replace(raw_layout, fields=(replace(raw_layout.fields[0], encoding="riscv_imc"),))
        legal_projector = runtime_projection.RuntimeProjector(legal_layout, isa=isa)
        self.assertEqual("legal", legal_projector.instruction_mode)
        self.assertNotEqual(raw_projector.constraint_hash, legal_projector.constraint_hash)

    def test_raw_instruction_mode_accepts_an_unimplemented_isa_contract(self):
        field = LayoutField(
            "i", "e", "instruction", 32, 0, 31, "raw_instruction", {},
        )
        layout = InputLayout("input_layout.v1", 32, (field,), "raw-unimplemented-isa")
        isa = IsaContract(64, ("I", "A"))

        projector = runtime_projection.RuntimeProjector(layout, isa=isa)

        self.assertEqual(projector.project(0x0200_00B3), 0x0200_00B3)

    def test_constraint_hash_binds_complete_isa_contract(self):
        field = LayoutField(
            "i", "e", "instruction", 32, 0, 31, "riscv_imc", {},
        )
        layout = InputLayout("input_layout.v1", 32, (field,), "isa-bound")
        contracts = (
            IsaContract(32, ("I",)),
            IsaContract(64, ("I",)),
            IsaContract(32, ("I", "M")),
            IsaContract(32, ("I",), privilege_modes=("M", "U")),
            IsaContract(32, ("I",), instruction_alignment=2),
        )
        projectors = tuple(
            runtime_projection.RuntimeProjector(layout, isa=contract)
            for contract in contracts
        )

        self.assertEqual(len(contracts), len({item.constraint_hash for item in projectors}))
        self.assertEqual(
            {
                "xlen": 32,
                "extensions": ["I"],
                "privilege_modes": ["M"],
                "instruction_alignment": 4,
            },
            projectors[0]._constraint_document["isa_contract"],
        )

    def test_instruction_randomizable_is_metadata_and_direct_values_are_boolean(self):
        base = LayoutField("i", "e", "instruction", 32, 0, 31, "riscv_imc", {})
        layout = InputLayout("input_layout.v1", 32, (base,), "randomizable")
        isa = IsaContract(32, ("I",))
        for value in (False, True):
            with self.subTest(value=value):
                field = replace(base, constraint={"randomizable": value})
                projector = runtime_projection.RuntimeProjector(
                    replace(layout, fields=(field,)), isa=isa,
                )
                self.assertTrue(
                    RiscvInstructionProvider(isa).is_legal_word(projector.project(0))
                )
        for value in (0, 1, None, "true"):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError, "randomizable.*boolean"
            ):
                runtime_projection.RuntimeProjector(
                    replace(layout, fields=(replace(base, constraint={"randomizable": value}),)),
                    isa=isa,
                )

    def test_finite_candidates_are_cached_during_initialization(self):
        fields = (
            LayoutField("enum", "e", "enum", 8, 0, 7, "bits", {"enum": [1, 3, 7]}),
            LayoutField(
                "range-mask", "e", "data", 8, 8, 15, "bits",
                {"range": [0, 252], "alignment": 4, "mask": 0b10101100},
            ),
        )
        projector = runtime_projection.RuntimeProjector(
            InputLayout("input_layout.v1", 16, fields, "cached")
        )
        enum_candidates = projector._constraint_candidates["enum"]
        range_mask_candidates = projector._constraint_candidates["range-mask"]

        for raw in range(256):
            projector.project(raw | (raw << 8))

        self.assertIs(enum_candidates, projector._constraint_candidates["enum"])
        self.assertIs(
            range_mask_candidates, projector._constraint_candidates["range-mask"]
        )
        self.assertEqual((1, 3, 7), enum_candidates)
        self.assertTrue(range_mask_candidates)

    def test_inactive_gate_zero_overrides_nonzero_enum(self):
        fields = (
            LayoutField("valid", "e", "valid", 1, 0, 0, "bits", {}),
            LayoutField(
                "data", "e", "data", 3, 1, 3, "bits",
                {"enum": [1, 3, 7], "gated_by": "valid"},
            ),
        )
        projector = runtime_projection.RuntimeProjector(
            InputLayout("input_layout.v1", 4, fields, "gated-enum")
        )

        self.assertEqual(0, projector.project(0b1110))
        self.assertEqual(7, projector.project(0b0101) >> 1)
        self.assertEqual(
            "inactive_zero_overrides_field_constraints",
            projector._constraint_document["gating_semantics"],
        )
