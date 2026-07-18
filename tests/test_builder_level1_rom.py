import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    Level1IPWindow,
    builtin_cpu_execution_profile,
    generate_level1_rom,
)
from myfuzz.builder.input_model import InputValidationError


class Level1RomTest(unittest.TestCase):
    WINDOWS = (
        Level1IPWindow("gpio0", 0x20000000, 0x1000),
        Level1IPWindow("ram0", 0x20010000, 0x10000),
        Level1IPWindow("regs0", 0x20020000, 0x1000),
    )

    def test_profiles_lock_common_reset_vector_and_distinct_install_backends(self):
        pico = builtin_cpu_execution_profile("picorv32")
        ultra = builtin_cpu_execution_profile("ultra_riscv")
        self.assertEqual(pico.reset_vector, 0x2000)
        self.assertEqual(pico.reset_vector, ultra.reset_vector)
        self.assertEqual(pico.rom_window, ultra.rom_window)
        self.assertEqual(pico.rom_install_backend["kind"], "external_rom")
        self.assertEqual(ultra.rom_install_backend["kind"], "pre_reset_tcm_loader")
        with self.assertRaisesRegex(InputValidationError, "unknown qualified CPU"):
            builtin_cpu_execution_profile("unknown")

    def test_both_cpu_profiles_generate_the_same_rv32i_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pico = generate_level1_rom(builtin_cpu_execution_profile("picorv32"), self.WINDOWS, root / "pico")
            ultra = generate_level1_rom(builtin_cpu_execution_profile("ultra_riscv"), self.WINDOWS, root / "ultra")
            self.assertEqual(pico.semantic_digest, ultra.semantic_digest)
            self.assertEqual(pico.image_digest, ultra.image_digest)
            self.assertEqual((root / "pico/level1_rom.bin").read_bytes(),
                             (root / "ultra/level1_rom.bin").read_bytes())
            assembly = (root / "pico/level1_rom.S").read_text()
            self.assertIn("lw t1, 4(s0)", assembly)
            self.assertIn("sw t4, 0(a0)", assembly)
            self.assertNotIn("remu", assembly)
            disassembly = (root / "pico/level1_rom.disasm").read_text()
            self.assertIn("00002000 <_start>", disassembly)
            manifest = json.loads((root / "pico/level1_rom.manifest.json").read_text())
            self.assertEqual(manifest["image_digest"], hashlib.sha256(
                (root / "pico/level1_rom.bin").read_bytes()).hexdigest())

    def test_generation_is_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = generate_level1_rom(builtin_cpu_execution_profile("picorv32"), self.WINDOWS, root / "a")
            second = generate_level1_rom(builtin_cpu_execution_profile("picorv32"), self.WINDOWS, root / "b")
            first_hashes = {item["name"]: item["sha256"] for item in first.files}
            second_hashes = {item["name"]: item["sha256"] for item in second.files}
            self.assertEqual(first_hashes, second_hashes)

    def test_overlaps_and_non_power_of_two_windows_fail_closed(self):
        profile = builtin_cpu_execution_profile("picorv32")
        with self.assertRaisesRegex(InputValidationError, "power of two"):
            Level1IPWindow("bad", 0x20000000, 0x1800)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(InputValidationError, "overlap"):
                generate_level1_rom(profile, (
                    Level1IPWindow("a", 0x20000000, 0x1000),
                    Level1IPWindow("b", 0x20000000, 0x1000),
                ), directory)


if __name__ == "__main__":
    unittest.main()
