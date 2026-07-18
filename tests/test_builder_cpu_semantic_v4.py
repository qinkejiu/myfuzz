import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AxiLiteV4Capability, CpuExecutionProfile, CpuMemoryRegion, CpuStateDomain,
    InputValidationError, ProgramFragmentIR, RawBitsV4Lane, RawBitsV4Submode,
    build_axi_lite_v4_layout, build_cpu_semantic_v4_layout,
    build_mmio_smoke_program_fragment_v4,
    build_rv32i_boot_image_v4, cpu_execution_profile_v4_from_dict,
    decode_program_fragment_records_v4,
    encode_program_fragment_records_v4, materialize_program_fragment_v4,
    picorv32_semantic_profile, ultra_riscv_semantic_profile,
)


def _profile():
    domain = CpuStateDomain(
        xlen=32, gpr_writable_mask=(1 << 32) - 2, csr_masks={"mstatus": 0xFFFF},
        csr_addresses={"mstatus": 0x300},
        privilege_modes=("M",), pc_base=0x1000, pc_size=0x1000,
        trap_vector_base=0x2000, trap_vector_size=0x100,
        memory_regions=(
            CpuMemoryRegion("loader", 0, 0x1000, "rx", 0),
            CpuMemoryRegion("ram", 0x1000, 0x4000, "rwx", 0),
        ),
        max_steps=32, loader="fixture-loader", reset_values={"x0": 0, "pc": 0},
    )
    return CpuExecutionProfile("fixture", ("RV32I",), (), domain, "mailbox", "direct", "sync")


class CpuSemanticV4Test(unittest.TestCase):
    def test_mmio_smoke_fragment_is_profile_driven_and_round_trips(self):
        for profile in (picorv32_semantic_profile(), ultra_riscv_semantic_profile()):
            fragment = build_mmio_smoke_program_fragment_v4(
                profile,
                (("low", 0x20000000, 0x1000), ("high", 0xFFFFF800, 0x800)),
            )
            self.assertEqual(ProgramFragmentIR.decode(fragment.encode(profile), profile), fragment)
            self.assertEqual(fragment.words[:4], (
                0x05A00313, 0x200002B7, 0x0062A023, 0x0002A383,
            ))
            self.assertEqual(fragment.words[-1], 0x0000006F)
            self.assertEqual(fragment.profile_digest, profile.digest)

    def test_mmio_smoke_fragment_rejects_ambiguous_windows(self):
        profile = picorv32_semantic_profile()
        with self.assertRaisesRegex(InputValidationError, "unique"):
            build_mmio_smoke_program_fragment_v4(
                profile, (("duplicate", 0x20000000, 0x1000),) * 2,
            )
        with self.assertRaisesRegex(InputValidationError, "aligned"):
            build_mmio_smoke_program_fragment_v4(
                profile, (("unaligned", 0x20000002, 0x1000),),
            )

    def test_domain_and_fragment_round_trip_is_canonical(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x00000013, 0x00100073), entry_pc=0x1000, registers={1: 7},
            csrs={"mstatus": 1}, memory={"ram": ((4, 0xAA),)}, privilege="M",
            trap_vector=0x2000, max_steps=8, profile_digest=profile.digest,
        )
        encoded = fragment.encode(profile)
        decoded = ProgramFragmentIR.decode(encoded, profile)
        self.assertEqual(decoded, fragment)
        self.assertEqual(decoded.encode(profile), encoded)

    def test_unrealizable_state_is_rejected(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x13,), entry_pc=0x9000, registers={}, csrs={}, memory={}, privilege="M",
            trap_vector=0x2000, max_steps=1, profile_digest=profile.digest,
        )
        with self.assertRaises(InputValidationError):
            fragment.encode(profile)

    def test_profile_loader_and_program_image_are_generic_and_digest_bound(self):
        profile = _profile()
        loaded = cpu_execution_profile_v4_from_dict(profile.to_dict())
        self.assertEqual(loaded, profile)
        fragment = ProgramFragmentIR(
            words=(0x00000013, 0x00100073), entry_pc=0x1000, registers={1: 7},
            csrs={"mstatus": 1}, memory={"ram": ((0x100, 0xAA),)}, privilege="M",
            trap_vector=0x2000, max_steps=8, profile_digest=profile.digest,
        )
        image = materialize_program_fragment_v4(profile, fragment)
        self.assertEqual(image.memory_bytes[:4], (
            (0x1000, 0x13), (0x1001, 0), (0x1002, 0), (0x1003, 0),
        ))
        self.assertIn((0x1100, 0xAA), image.memory_bytes)
        self.assertEqual(image.profile_digest, profile.digest)
        self.assertEqual(image.state_domain_digest, profile.state_domain.digest)
        self.assertEqual(len(image.digest), 64)

    def test_program_overlay_cannot_silently_rewrite_instruction_bytes(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x00000013,), entry_pc=0x1000, registers={}, csrs={},
            memory={"ram": ((0, 0xFF),)}, privilege="M", trap_vector=0x2000,
            max_steps=1, profile_digest=profile.digest,
        )
        with self.assertRaisesRegex(InputValidationError, "conflicts with instructions"):
            materialize_program_fragment_v4(profile, fragment)

    def test_profile_loader_rejects_unfrozen_fields(self):
        serialized = _profile().to_dict()
        serialized["module_name"] = "must-not-drive-generic-loader"
        with self.assertRaises(InputValidationError):
            cpu_execution_profile_v4_from_dict(serialized)

    def test_program_fragment_rawbits_records_are_lossless_and_mask_checked(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x00000013, 0x00100073), entry_pc=0x1000,
            registers={1: 0x12345678}, csrs={"mstatus": 3}, memory={},
            privilege="M", trap_vector=0x2000, max_steps=8,
            profile_digest=profile.digest,
        )
        layout = build_cpu_semantic_v4_layout(
            build_axi_lite_v4_layout(AxiLiteV4Capability(32, 32))
        )
        lane = layout.lane_layout(RawBitsV4Lane.CPU_SEMANTIC)
        self.assertEqual(
            {mode for mode, _mask in lane.submode_used_masks},
            {"SEMANTIC_OPS", "PROGRAM_FRAGMENT"},
        )
        records = encode_program_fragment_records_v4(layout, fragment, profile)
        self.assertEqual(
            decode_program_fragment_records_v4(layout, records, profile), fragment,
        )
        semantic_field = next(
            field for field in lane.fields if field.name == "cpu_semantic_byte"
        )
        corrupt = (records[0] | (1 << semantic_field.offset),) + records[1:]
        with self.assertRaisesRegex(InputValidationError, "outside its submode mask"):
            decode_program_fragment_records_v4(layout, corrupt, profile)

    def test_rv32i_boot_image_realizes_state_without_overwriting_fragment(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x00000013, 0x00100073), entry_pc=0x1000,
            registers={1: 0x12345678, 31: 0xCAFEBABE},
            csrs={"mstatus": 3}, memory={"ram": ((0x100, 0xAA),)},
            privilege="M", trap_vector=0x2000, max_steps=8,
            profile_digest=profile.digest,
        )
        boot = build_rv32i_boot_image_v4(profile, fragment)
        words = dict(boot.words)
        self.assertIn(0, words)
        self.assertEqual(words[0x1000], 0x00000013)
        self.assertEqual(words[0x1004], 0x00100073)
        self.assertEqual(words[0x1100] & 0xFF, 0xAA)
        self.assertIn("@00000400\n00000013\n00100073\n", boot.hex_text)
        self.assertEqual(len(boot.digest), 64)

    def test_bootstrap_and_fragment_must_not_overlap(self):
        profile = _profile()
        fragment = ProgramFragmentIR(
            words=(0x00000013,), entry_pc=0, registers={}, csrs={}, memory={},
            privilege="M", trap_vector=0x2000, max_steps=1,
            profile_digest=profile.digest,
        )
        shifted = CpuStateDomain(
            **{**profile.state_domain.__dict__, "pc_base": 0, "pc_size": 0x2000}
        )
        conflicting_profile = CpuExecutionProfile(
            profile.name, profile.isa, profile.extensions, shifted,
            profile.load_method, profile.trap_abi, profile.reset_behavior,
        )
        fragment = ProgramFragmentIR(
            **{**fragment.__dict__, "profile_digest": conflicting_profile.digest}
        )
        with self.assertRaisesRegex(InputValidationError, "overlaps"):
            build_rv32i_boot_image_v4(conflicting_profile, fragment)

    def test_bootstrap_uses_only_cpu_profile_declared_csrs(self):
        boots = []
        for profile in (picorv32_semantic_profile(), ultra_riscv_semantic_profile()):
            fragment = ProgramFragmentIR(
                words=(0x00000013, 0x00100073), entry_pc=0x3000,
                registers={1: 7},
                csrs={"mstatus": 1} if "mstatus" in profile.state_domain.csr_masks else {},
                memory={"mailbox": ((0, 0x5A),)}, privilege="M",
                trap_vector=0x3000, max_steps=8, profile_digest=profile.digest,
            )
            boots.append(build_rv32i_boot_image_v4(profile, fragment))
        self.assertNotEqual(boots[0].profile_digest, boots[1].profile_digest)
        self.assertNotEqual(boots[0].state_domain_digest, boots[1].state_domain_digest)
        picorv32_loader = dict(boots[0].words)
        self.assertEqual(picorv32_loader[0x2000], 0x10000F37)
        self.assertNotIn(0x300F9073, picorv32_loader.values())
        self.assertNotIn(0x305F9073, picorv32_loader.values())
        ultra_loader = dict(boots[1].words)
        self.assertIn(0x300F9073, ultra_loader.values())
        self.assertIn(0x305F9073, ultra_loader.values())


if __name__ == "__main__":
    unittest.main()
