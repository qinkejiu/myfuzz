import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    CONTROL_OPCODES, add_system_services_to_soc_ir, build_control_plane,
    builtin_cpu_execution_profile, generate_control_rom, plan_system_services,
)
from myfuzz.builder.contracts import seal_contract  # noqa: E402
from test_builder_control_plane import soc_fixture  # noqa: E402


class ControlRomTest(unittest.TestCase):
    def test_generates_all_operations_without_ip_specific_tables(self):
        base = soc_fixture()
        moved_view = dict(base.address_views[0]); moved_view["global_base"] = 0x20000000
        base = seal_contract(replace(base, address_views=(moved_view,), digest=""))
        profile = builtin_cpu_execution_profile("picorv32")
        services = plan_system_services(base.address_views, profile)
        soc = add_system_services_to_soc_ir(base, services)
        control = build_control_plane(soc, cpu_profile_digest=services.profile_digest)
        with tempfile.TemporaryDirectory() as directory:
            artifact = generate_control_rom(profile, soc, control, services, directory)
            assembly = (Path(directory) / "control_rom.S").read_text()
            for opcode in CONTROL_OPCODES:
                self.assertIn(f"op_{opcode.lower()}:", assembly)
            self.assertNotIn("gpio", assembly.lower())
            self.assertNotIn("uart", assembly.lower())
            self.assertGreater((Path(directory) / "control_rom.bin").stat().st_size, 0)
            self.assertEqual(
                (Path(directory) / "control_rom.hex").read_text().splitlines()[0],
                "@00000800",
            )
            manifest = json.loads((Path(directory) / "control_rom.manifest.json").read_text())
            self.assertEqual(manifest["image_digest"], artifact.image_digest)

    def test_tcm_loader_image_is_compact(self):
        base = soc_fixture()
        moved_view = dict(base.address_views[0]); moved_view["global_base"] = 0x20000000
        base = seal_contract(replace(base, address_views=(moved_view,), digest=""))
        profile = builtin_cpu_execution_profile("ultra_riscv")
        services = plan_system_services(base.address_views, profile)
        soc = add_system_services_to_soc_ir(base, services)
        control = build_control_plane(soc, cpu_profile_digest=services.profile_digest)
        with tempfile.TemporaryDirectory() as directory:
            generate_control_rom(profile, soc, control, services, directory)
            first_line = (Path(directory) / "control_rom.hex").read_text().splitlines()[0]
            self.assertFalse(first_line.startswith("@"))


if __name__ == "__main__":
    unittest.main()
