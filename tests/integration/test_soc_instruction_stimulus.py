import unittest

from myfuzz.composition.soc_instruction_stimulus import (
    CpuInstructionCapabilities,
    SocInstructionStimulus,
    SocInstructionStimulusError,
)


class SocInstructionStimulusTest(unittest.TestCase):
    def capabilities(self, *, xlen=32, extensions=("I", "M", "C")):
        return CpuInstructionCapabilities(
            xlen=xlen, extensions=extensions,
            instruction_alignment=2 if "C" in extensions else 4,
            parameters={"RV32M": "M" in extensions, "RV32C": "C" in extensions},
            provenance="processor_execution.v1#/instances/cpu/parameters",
        )

    def layer(self, **kw):
        return SocInstructionStimulus(
            self.capabilities(), instruction_windows=((0x1000, 0x100),), **kw
        )

    @staticmethod
    def candidate(data, *, address=0x1000, be=0xF):
        return {"init_offer": 1, "init_address": address, "init_data": data,
                "init_be": be}

    def test_raw_corpus_changes_first_initialization_and_replays(self):
        first = self.layer()
        second = self.layer()
        replay = self.layer()
        first.accept(self.candidate(0x12345678))
        second.accept(self.candidate(0xDEADBEEF))
        replay.accept(self.candidate(0x12345678))
        self.assertNotEqual(first.read_instruction(0x1000, 4), second.read_instruction(0x1000, 4))
        self.assertEqual(first.read_instruction(0x1000, 4), replay.read_instruction(0x1000, 4))
        self.assertEqual(first.read_instruction(0x1000, 4), first.read_instruction(0x1000, 4))
        self.assertEqual(1, first.counters["instruction_initializations"])

    def test_compressed_and_partial_reads_share_one_byte_image(self):
        layer = self.layer()
        layer.accept(self.candidate(0x89ABCDEF, address=0x1002, be=0x3))
        half = layer.read_instruction(0x1002, 2)
        word = layer.read_instruction(0x1000, 4)
        self.assertEqual(half, (word >> 16) & 0xFFFF)
        self.assertEqual(word, layer.read_instruction(0x1000, 4))

    def test_rv64_fetch_materializes_adjacent_beats_from_one_byte_image(self):
        layer = SocInstructionStimulus(
            self.capabilities(xlen=64),
            instruction_windows=((0x1000, 0x20),),
            isa_legal=False,
        )
        layer.accept(self.candidate(0x11223344, address=0x1000))
        layer.accept(self.candidate(0x55667788, address=0x1004))
        value = layer.read_instruction(0x1000, 8)
        self.assertEqual(0x11223344, value & 0xFFFF_FFFF)
        self.assertEqual(0x55667788, value >> 32)
        self.assertEqual(value, layer.read_instruction(0x1000, 8))

    def test_instruction_alignment_and_compressed_width_are_capability_derived(self):
        no_compressed = SocInstructionStimulus(
            self.capabilities(extensions=("I", "M")),
            instruction_windows=((0x1000, 0x20),),
        )
        with self.assertRaisesRegex(SocInstructionStimulusError, "instruction-address-alignment"):
            no_compressed.accept(self.candidate(0x13, address=0x1002, be=0xF))

        compressed = self.layer()
        compressed.accept(self.candidate(0x0001, address=0x1002, be=0x3))
        compressed.read_instruction(0x1002, 2)
        self.assertEqual(16, compressed.initialization_records[-1]["corrected_candidate"]["width"])

    def test_isa_capabilities_are_checked_and_unknown_extension_fails_closed(self):
        rv32 = self.layer()
        rv64 = SocInstructionStimulus(
            self.capabilities(xlen=64, extensions=("I", "M")),
            instruction_windows=((0x1000, 0x100),),
        )
        rv32.accept(self.candidate(0xFFFFFFFF))
        rv64.accept(self.candidate(0xFFFFFFFF))
        self.assertNotEqual(rv32.provenance["isa"]["xlen"], rv64.provenance["isa"]["xlen"])
        with self.assertRaisesRegex(SocInstructionStimulusError, "unsupported-isa-extension:A"):
            SocInstructionStimulus(
                self.capabilities(xlen=64, extensions=("I", "M", "A")),
                instruction_windows=((0x1000, 0x100),),
            )
        contradictory = self.capabilities()
        contradictory = CpuInstructionCapabilities(
            xlen=contradictory.xlen, extensions=contradictory.extensions,
            instruction_alignment=contradictory.instruction_alignment,
            parameters={"XLEN": 64, "RV32M": True, "RV32C": True},
            provenance=contradictory.provenance,
        )
        with self.assertRaisesRegex(SocInstructionStimulusError, "cpu-parameter-mismatch:XLEN"):
            SocInstructionStimulus(contradictory, instruction_windows=((0x1000, 0x100),))

    def test_rule_switches_are_independent_and_bias_cannot_drive_cpu_state(self):
        legal_raw = self.layer(isa_legal=False, mmio_reachability_bias=False)
        legal_raw.accept(self.candidate(0x00000000))
        self.assertEqual(0, legal_raw.read_instruction(0x1000, 4))
        self.assertEqual(0, legal_raw.counters["isa_legal_corrections"])

        biased = self.layer(isa_legal=False, mmio_reachability_bias=True)
        result = biased.initialize_data(0xFFFF, 0xA5, windows=((0x2000, 0x20),))
        self.assertTrue(0x2000 <= result["address"] < 0x2020)
        self.assertNotIn("cpu_outputs", result)
        self.assertNotIn("registers", biased.provenance)

    def test_correction_provenance_and_directed_program_label(self):
        layer = self.layer()
        layer.accept(self.candidate(0))
        layer.read_instruction(0x1000, 4)
        record = layer.initialization_records[-1]
        self.assertIn("corrected_candidate", record)
        self.assertEqual(1, record["initialization_count"])
        self.assertGreaterEqual(layer.counters["isa_legal_corrections"], 1)
        directed = layer.preload_directed({0x1000: b"\x13\x00\x00\x00"}, kind="boot")
        self.assertEqual("directed", directed["classification"])
        self.assertEqual("boot", directed["kind"])


if __name__ == "__main__":
    unittest.main()
