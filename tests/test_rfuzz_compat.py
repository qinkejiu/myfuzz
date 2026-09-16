from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.rfuzz_compat import (
    aligned_coverage_bytes,
    aligned_input_bytes,
    render_adapter,
    render_augmented_toml,
    render_rfuzz_toml,
    render_dut_header,
    resolve_rfuzz_verilator,
    rfuzz_verilator_environment,
    server_build_command,
    validate_rfuzz_verilator_version,
)


class RfuzzCompatTests(unittest.TestCase):
    def test_protocol_sizes_are_64_bit_aligned(self) -> None:
        self.assertEqual(aligned_input_bytes(10), 8)
        self.assertEqual(aligned_input_bytes(512), 64)
        self.assertEqual(aligned_coverage_bytes(9), 14)
        self.assertEqual(aligned_coverage_bytes(1128), 1134)

    def test_adapter_maps_aligned_byte_ports_to_manual_harness(self) -> None:
        source = render_adapter(
            top="sample",
            manual_module="sample_direct_harness",
            input_name="rfuzz_input_bits",
            input_width=10,
            coverage_port="__vi_coverage",
            coverage_width=9,
        )

        self.assertIn("module sample_VHarness", source)
        self.assertIn("input logic [7:0] io_input_bytes_7", source)
        self.assertIn("output logic [7:0] io_coverage_bytes_13", source)
        self.assertIn("assign rfuzz_input_bits[7:0] = io_input_bytes_0;", source)
        self.assertIn("assign rfuzz_input_bits[9:8] = io_input_bytes_1[1:0];", source)
        self.assertIn("assign io_coverage_bytes_8 = {7'b0, __vi_coverage[8]};", source)
        self.assertIn("assign io_coverage_bytes_13 = 8'b0;", source)

    def test_augmented_toml_declares_one_counter_per_coverage_point(self) -> None:
        base = """[general]\nfilename = \"sample\"\ninstrumented = \"sources.f\"\ntop = \"sample\"\ntimestamp = 2026-07-25T00:00:00+08:00\n\n[[input]]\nname = \"rfuzz_input_bits\"\nwidth = 10\n\n"""
        result = render_augmented_toml(base, coverage_width=9)

        self.assertEqual(result.count("[[counter]]"), 9)
        self.assertIn('name = "coverage_8"', result)
        self.assertIn("width = 8", result)
        self.assertIn("index = 8", result)
        self.assertIn("signal = 8", result)

    def test_complete_toml_preserves_coverage_metadata(self) -> None:
        instrumentation = {
            "coverage_port": "__vi_coverage",
            "coverage": [
                {
                    "file": "core.sv",
                    "module": "core",
                    "signal": "__vi_cov_0",
                    "line": 42,
                    "column": 7,
                    "kind": "branch",
                    "subtype": "if_true",
                }
            ],
        }
        result = render_rfuzz_toml(
            top="core",
            input_name="rfuzz_input_bits",
            input_width=10,
            coverage_width=1,
            instrumentation=instrumentation,
            timestamp="2026-07-25T00:00:00+08:00",
        )

        self.assertEqual(result.count("[[coverage]]"), 1)
        self.assertEqual(result.count("[[counter]]"), 1)
        self.assertIn('filename = "core.sv"', result)
        self.assertIn('human = "core branch if_true line 42"', result)

    def test_server_build_is_single_threaded(self) -> None:
        command = server_build_command(
            verilator=Path("/tools/verilator"),
            flist=Path("instrumented/sources.f"),
            manual_harness=Path("harness/direct.sv"),
            adapter=Path("out/core_VHarness.sv"),
            top="core",
            out_dir=Path("out"),
            rfuzz_verilator_dir=Path("rfuzz/verilator"),
            extra_args=["-DMY_WIDTH=8"],
        )

        self.assertIn("-j", command)
        self.assertEqual(command[command.index("-j") + 1], "1")
        self.assertIn("--top-module", command)
        self.assertIn("core_VHarness", command)
        self.assertIn("-DMY_WIDTH=8", command)

    def test_dut_header_matches_adapter_ports(self) -> None:
        header = render_dut_header(top="core", input_width=10, coverage_width=9)

        self.assertIn("#include <Vcore_VHarness.h>", header)
        self.assertIn("static constexpr size_t InputSize = 8;", header)
        self.assertIn("static constexpr size_t CoverageSize = 14;", header)
        self.assertIn("top->io_input_bytes_7 = input[7];", header)
        self.assertIn("coverage[13] = top->io_coverage_bytes_13;", header)


class RfuzzVerilatorResolverTests(unittest.TestCase):
    def test_default_uses_bundled_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
            bundled.parent.mkdir(parents=True)
            bundled.write_text("#!/bin/sh\n", encoding="utf-8")
            bundled.chmod(0o755)
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(bundled.as_posix(), resolve_rfuzz_verilator(root))

    def test_explicit_environment_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {"MYFUZZ_SERVER_VERILATOR_BIN": "/opt/validated/verilator"},
                clear=True,
            ):
                self.assertEqual(
                    "/opt/validated/verilator",
                    resolve_rfuzz_verilator(root),
                )

    def test_missing_bundled_executable_fails_without_path_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                ValueError, "bundled RFuzz Verilator 5.020"
            ):
                resolve_rfuzz_verilator(Path(directory))

    def test_version_validator_accepts_only_rfuzz_compatible_verilator(self) -> None:
        version = "Verilator 5.020 2024-01-01 rev (Debian 5.020-1)"
        self.assertEqual(version, validate_rfuzz_verilator_version(version))
        with self.assertRaisesRegex(ValueError, "requires Verilator 5.020"):
            validate_rfuzz_verilator_version("Verilator 5.051 devel")

    def test_bundled_environment_points_launcher_at_relocated_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
            bundled.parent.mkdir(parents=True)
            bundled.write_text("#!/bin/sh\n", encoding="utf-8")
            bundled.chmod(0o755)
            binary = root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator_bin"
            binary.write_text("binary\n", encoding="utf-8")
            binary.chmod(0o755)
            install_root = root / "third_party/rfuzz/upstream/.tools/apt-root/usr/share/verilator"
            (install_root / "include").mkdir(parents=True)
            with patch.dict(os.environ, {"KEEP_ME": "1"}, clear=True):
                environment = rfuzz_verilator_environment(root, bundled.as_posix())

            self.assertIsNotNone(environment)
            assert environment is not None
            self.assertEqual("1", environment["KEEP_ME"])
            self.assertEqual(install_root.as_posix(), environment["VERILATOR_ROOT"])
            self.assertEqual("../../bin/verilator_bin", environment["VERILATOR_BIN"])


if __name__ == "__main__":
    unittest.main()
