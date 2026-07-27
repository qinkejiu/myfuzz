from __future__ import annotations

import importlib
import json
import tempfile
import unittest
from pathlib import Path


def original_rfuzz():
    try:
        return importlib.import_module("myfuzz.original_rfuzz")
    except ModuleNotFoundError:
        raise AssertionError("tracked native original RFuzz compatibility module is missing")


def candidate_source(*, extra_port: str = "", instance: str = "dut") -> str:
    separator = "," if extra_port else ""
    return f"""module myfuzz_candidate_direct_a6ccf1733940(
  input logic clock,
  input logic reset,
  input logic io_meta_reset,
  input logic [36:0] rfuzz_input_bits{separator}{extra_port}
);
  ibex_opentitan_real_ip_top {instance}();
endmodule
"""


def instrumentation() -> dict[str, object]:
    return {
        "coverage_port": "__vi_coverage",
        "coverage_point_count": 2,
        "coverage": [],
        "module_coverage": [
            {
                "module": "ibex_opentitan_real_ip_top",
                "active": True,
                "coverage_width": 1853,
                "local_points": 0,
                "propagated_child_count": 7,
            }
        ],
    }


class OriginalRfuzzNativeTest(unittest.TestCase):
    def test_validated_candidate_and_coverage_render_explicit_inner_dut_binding(self) -> None:
        compat = original_rfuzz()
        candidate = compat.validate_candidate_source(
            candidate_source(),
            module="myfuzz_candidate_direct_a6ccf1733940",
            ports=(
                ("clock", 1),
                ("reset", 1),
                ("io_meta_reset", 1),
                ("rfuzz_input_bits", 37),
            ),
            dut_module="ibex_opentitan_real_ip_top",
            dut_instance="dut",
        )
        coverage = compat.validate_coverage_binding(
            instrumentation(), "ibex_opentitan_real_ip_top"
        )

        wrapper = compat.render_wrapper(candidate, coverage, raw_width=37)

        self.assertIn("candidate.dut.__vi_coverage", wrapper)
        self.assertIn("myfuzz_candidate_direct_a6ccf1733940 candidate", wrapper)
        self.assertIn("aligned_input[7:0] = io_input_bytes_0", wrapper)
        self.assertIn("aligned_input[15:8] = io_input_bytes_1", wrapper)
        self.assertIn(".rfuzz_input_bits(aligned_input[36:0])", wrapper)
        self.assertEqual(1854, compat.aligned_coverage_width(1853))

    def test_candidate_validation_rejects_extra_port_and_wrong_inner_instance(self) -> None:
        compat = original_rfuzz()
        arguments = {
            "module": "myfuzz_candidate_direct_a6ccf1733940",
            "ports": (
                ("clock", 1),
                ("reset", 1),
                ("io_meta_reset", 1),
                ("rfuzz_input_bits", 37),
            ),
            "dut_module": "ibex_opentitan_real_ip_top",
            "dut_instance": "dut",
        }
        with self.assertRaisesRegex(ValueError, "exact input ports"):
            compat.validate_candidate_source(
                candidate_source(extra_port="\n  input logic surprise"), **arguments
            )
        with self.assertRaisesRegex(ValueError, "inner DUT instance"):
            compat.validate_candidate_source(
                candidate_source(instance="not_dut"), **arguments
            )

    def test_coverage_binding_rejects_missing_selected_top_record(self) -> None:
        compat = original_rfuzz()
        with self.assertRaisesRegex(ValueError, "active module coverage"):
            compat.validate_coverage_binding(instrumentation(), "other_top")

    def test_raw_abi_binding_requires_exactly_one_regular_fragment(self) -> None:
        compat = original_rfuzz()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / "harness"
            harness.mkdir()
            source = harness / "candidate.sv"
            source.write_text(candidate_source(), encoding="utf-8")
            fragment = harness / "candidate.abi.json"
            fragment.write_text(
                json.dumps(
                    {
                        "source": source.name,
                        "module": "myfuzz_candidate_direct_a6ccf1733940",
                        "raw_width": 37,
                    }
                ),
                encoding="utf-8",
            )

            selected = compat.select_raw_abi_fragment(root, harness)
            self.assertEqual(fragment, selected.path)
            (harness / "stale.abi.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one raw ABI fragment"):
                compat.select_raw_abi_fragment(root, harness)

    def test_server_command_uses_original_inputs_and_one_build_worker(self) -> None:
        compat = original_rfuzz()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            flow = root / "third_party/rfuzz/rfuzz_flow"
            verilator = flow / "verilator"
            verilator.mkdir(parents=True)
            top_cpp = verilator / "top.cpp"
            queue_cpp = verilator / "fpga_queue.cpp"
            top_cpp.write_text("// original top\n", encoding="utf-8")
            queue_cpp.write_text("// original queue\n", encoding="utf-8")
            (verilator / "fpga_queue.hpp").write_text("// original header\n", encoding="utf-8")
            instrumented = root / "instrumented"
            instrumented.mkdir()
            sources = instrumented / "sources.f"
            sources.write_text("top.sv\n", encoding="utf-8")
            harness = root / "harness"
            harness.mkdir()
            wrapper = harness / "rfuzz_wrapper.sv"
            candidate = harness / "candidate_direct.sv"
            header = harness / "dut.hpp"
            wrapper.write_text("module wrapper; endmodule\n", encoding="utf-8")
            candidate.write_text("module candidate_direct; endmodule\n", encoding="utf-8")
            header.write_text("#pragma once\n", encoding="utf-8")

            command = compat.build_server_command(
                root,
                verilator_bin="verilator",
                wrapper_module="wrapper",
                sources_file=sources,
                wrapper=wrapper,
                candidate_source=candidate,
                dut_header=header,
                server_dir=root / "server",
            )

        self.assertIn("--build-jobs", command)
        self.assertEqual("1", command[command.index("--build-jobs") + 1])
        self.assertIn(top_cpp.as_posix(), command)
        self.assertIn(queue_cpp.as_posix(), command)
        self.assertIn(candidate.as_posix(), command)
        self.assertIn("-Wno-fatal", command)
        self.assertNotIn("build_rfuzz_server.py", " ".join(command))

    def test_materialization_binds_one_fragment_and_emits_original_rfuzz_artifacts(self) -> None:
        compat = original_rfuzz()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / "harness"
            harness.mkdir()
            source = harness / "candidate_direct.sv"
            source.write_text(candidate_source(), encoding="utf-8")
            (harness / "candidate_direct.abi.json").write_text(
                json.dumps(
                    {
                        "source": source.name,
                        "module": "myfuzz_candidate_direct_a6ccf1733940",
                        "raw_width": 37,
                    }
                ),
                encoding="utf-8",
            )
            base_toml = root / "top.toml"
            base_toml.write_text("[general]\ntop = \"ibex_opentitan_real_ip_top\"\n")

            materialized = compat.materialize_harness(
                root,
                harness_dir=harness,
                base_toml=base_toml,
                instrumentation=instrumentation(),
                top="ibex_opentitan_real_ip_top",
                expected_ports=(
                    ("clock", 1),
                    ("reset", 1),
                    ("io_meta_reset", 1),
                    ("rfuzz_input_bits", 37),
                ),
            )

            self.assertIn(
                "candidate.dut.__vi_coverage",
                materialized.wrapper.read_text(encoding="utf-8"),
            )
            augmented = materialized.toml.read_text(encoding="utf-8")
            self.assertEqual(1853, augmented.count("[[counter]]"))
            self.assertEqual("candidate_direct.abi.json", materialized.raw_abi.path.name)
            self.assertTrue(materialized.header.is_file())


if __name__ == "__main__":
    unittest.main()
