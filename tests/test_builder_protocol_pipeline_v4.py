import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ProgramFragmentIR, RawBitsV4Lane, RawBitsV4Submode,
    build_protocol_system_v4, encode_program_fragment_records_v4,
    encode_rawbits_v4_testcase, load_system_spec, picorv32_semantic_profile,
    run_protocol_verilator_target_v4, ultra_riscv_semantic_profile,
)


class ProtocolPipelineV4Test(unittest.TestCase):
    def test_generic_command_smokes_three_two_ip_holdouts_serially(self):
        cases = (
            (
                "ultra_riscv_holdout_2ip.json",
                "ultra_riscv",
                {"ip.regs0", "ip.lfsr0"},
            ),
            (
                "picorv32_wb2axip_holdout_2ip.json",
                "picorv32",
                {"ip.gpio_bank", "ip.apb_regs"},
            ),
            (
                "picorv32_wb2axip_holdout_narrow_2ip.json",
                "picorv32",
                {"ip.register_file", "ip.empty_device"},
            ),
        )
        for spec_name, cpu_profile, expected in cases:
            with self.subTest(spec=spec_name), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "result"
                completed = subprocess.run(
                    (
                        sys.executable,
                        str(ROOT / "src/myfuzz/scripts/protocol_system_builder_v4.py"),
                        "--spec",
                        str(ROOT / "examples/protocol_system_v2" / spec_name),
                        "--project-root",
                        str(ROOT),
                        "--output-dir",
                        str(output),
                        "--cpu-profile",
                        cpu_profile,
                        "--protocol-testcases",
                        "500",
                        "--records-per-testcase",
                        "16",
                        "--wall-seconds",
                        "30",
                        "--timeout-seconds",
                        "30",
                        "--jobs",
                        "1",
                    ),
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                command = json.loads(
                    (output / "command_report.json").read_text(encoding="ascii")
                )
                smoke = json.loads(
                    (output / "smoke_report.json").read_text(encoding="ascii")
                )
                self.assertEqual(command["status"], "completed")
                self.assertFalse(command["baseline_a_affected"])
                self.assertTrue(smoke["single_case_serial"])
                self.assertEqual(set(smoke["expected_target_components"]), expected)
                self.assertTrue(
                    expected.issubset(
                        set(smoke["cpu_semantic"]["added_components_over_control"])
                    )
                )
                self.assertTrue(
                    expected.issubset(
                        set(smoke["protocol_waveform"]["hit_components"])
                    )
                )

    def test_cpu_profiles_load_and_execute_ram_write_read_serially(self):
        cases = (
            (
                "picorv32",
                ROOT / "examples/protocol_system_v2/picorv32_axi_ram.json",
                picorv32_semantic_profile,
            ),
            (
                "ultra_riscv",
                ROOT / "examples/protocol_system_v2/ultra_riscv_axi_ram.json",
                ultra_riscv_semantic_profile,
            ),
        )
        for cpu_id, spec_path, semantic_factory in cases:
            with self.subTest(cpu_id=cpu_id), tempfile.TemporaryDirectory() as directory:
                profile = semantic_factory()
                built = build_protocol_system_v4(
                    load_system_spec(spec_path),
                    ROOT,
                    Path(directory) / "build",
                    cpu_profile_id=cpu_id,
                    jobs=1,
                )
                control_fragment = ProgramFragmentIR(
                    words=(0x0000006F,), entry_pc=0x3000, registers={}, csrs={},
                    memory={}, privilege="M", trap_vector=0x3000, max_steps=1024,
                    profile_digest=profile.digest,
                )
                control_records = encode_program_fragment_records_v4(
                    built.pipeline.harness.layout, control_fragment, profile,
                )
                control_transport = encode_rawbits_v4_testcase(
                    built.pipeline.harness.layout,
                    lane=RawBitsV4Lane.CPU_SEMANTIC,
                    submode=RawBitsV4Submode.PROGRAM_FRAGMENT,
                    logical_testcase_id=1,
                    records=control_records,
                )
                control = run_protocol_verilator_target_v4(
                    built.pipeline.target.path,
                    control_transport,
                    layout_digest=built.pipeline.harness.layout.digest,
                    coverage_abi=built.pipeline.coverage_abi,
                    coverage_epoch=1,
                    environment_plan=built.pipeline.environment_plan,
                    cpu_profile=profile,
                    timeout_seconds=30,
                )
                # lui x2,0x20000; addi x3,x0,0x5a; sw x3,0(x2);
                # lw x4,0(x2); jal x0,0
                fragment = ProgramFragmentIR(
                    words=(
                        0x20000137,
                        0x05A00193,
                        0x00312023,
                        0x00012203,
                        0x0000006F,
                    ),
                    entry_pc=0x3000,
                    registers={},
                    csrs={"mstatus": 0} if "mstatus" in profile.state_domain.csr_masks else {},
                    memory={},
                    privilege="M",
                    trap_vector=0x3000,
                    max_steps=1024,
                    profile_digest=profile.digest,
                )
                records = encode_program_fragment_records_v4(
                    built.pipeline.harness.layout, fragment, profile,
                )
                transport = encode_rawbits_v4_testcase(
                    built.pipeline.harness.layout,
                    lane=RawBitsV4Lane.CPU_SEMANTIC,
                    submode=RawBitsV4Submode.PROGRAM_FRAGMENT,
                    logical_testcase_id=2,
                    records=records,
                )
                replay = run_protocol_verilator_target_v4(
                    built.pipeline.target.path,
                    transport,
                    layout_digest=built.pipeline.harness.layout.digest,
                    coverage_abi=built.pipeline.coverage_abi,
                    coverage_epoch=2,
                    environment_plan=built.pipeline.environment_plan,
                    cpu_profile=profile,
                    timeout_seconds=30,
                )
                self.assertEqual(replay.observed_classification, "cpu_semantic")
                self.assertEqual(replay.logical_records, len(records))
                self.assertGreater(replay.dut_cycles, fragment.max_steps)
                added_offsets = {
                    offset for offset in range(built.pipeline.coverage_abi.width)
                    if replay.coverage_bitmap[offset // 8] & (1 << (offset % 8))
                    and not control.coverage_bitmap[offset // 8] & (1 << (offset % 8))
                }
                added_components = {
                    str(point["component_id"])
                    for point in built.pipeline.coverage_abi.points
                    if point.get("included") and int(point["offset"]) in added_offsets
                }
                self.assertIn("ip.verilog_axi_ram_wrapper", added_components)
                hit_components = {
                    str(point["component_id"])
                    for point in built.pipeline.coverage_abi.points
                    if point.get("included")
                    and replay.coverage_bitmap[int(point["offset"]) // 8]
                    & (1 << (int(point["offset"]) % 8))
                }
                self.assertIn("ip.verilog_axi_ram_wrapper", hit_components)
                self.assertIn(f"cpu.{cpu_id}_level1_adapter", hit_components)
                self.assertFalse(
                    json.loads(
                        Path(built.report_path).read_text(encoding="ascii")
                    )["baseline_a_affected"]
                )


if __name__ == "__main__":
    unittest.main()
