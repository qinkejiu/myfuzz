from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


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
    def _install_top_source(self, root: Path) -> tuple[str, Path]:
        instrumented = root / "instrumented"
        instrumented.mkdir(parents=True, exist_ok=True)
        source_text = """module ibex_opentitan_real_ip_top;
  output wire [1852:0] __vi_coverage;
endmodule
"""
        (instrumented / "top.sv").write_text(source_text, encoding="utf-8")
        source_list = instrumented / "sources.f"
        source_list.write_text("top.sv\n", encoding="utf-8")
        return source_text, source_list

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
        with self.assertRaisesRegex(ValueError, "exact input ports"):
            compat.validate_candidate_source(
                candidate_source(extra_port=" extra"), **arguments
            )
        with self.assertRaisesRegex(ValueError, "inner DUT instance"):
            compat.validate_candidate_source(
                candidate_source(instance="not_dut"), **arguments
            )

    def test_candidate_validation_scopes_inner_dut_to_selected_module_body(self) -> None:
        compat = original_rfuzz()
        decoy = candidate_source(instance="not_dut") + (
            "module decoy; ibex_opentitan_real_ip_top dut(); endmodule\n"
        )
        with self.assertRaisesRegex(ValueError, "inner DUT instance"):
            compat.validate_candidate_source(
                decoy,
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

    def test_candidate_validation_rejects_ambiguous_and_unterminated_modules(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "exactly one candidate module"):
            compat.validate_candidate_source(
                candidate_source() + candidate_source(), **arguments
            )
        with self.assertRaisesRegex(ValueError, "endmodule"):
            compat.validate_candidate_source(
                candidate_source().replace("endmodule\n", ""), **arguments
            )

    def test_candidate_validation_rejects_invalid_emitted_identifiers(self) -> None:
        compat = original_rfuzz()
        invalid_source = candidate_source().replace(
            "module myfuzz_candidate_direct_a6ccf1733940(",
            "module myfuzz_candidate_direct_a6ccf1733940.bad(",
        )
        with self.assertRaisesRegex(ValueError, "identifier"):
            compat.validate_candidate_source(
                invalid_source,
                module="myfuzz_candidate_direct_a6ccf1733940.bad",
                ports=(
                    ("clock", 1),
                    ("reset", 1),
                    ("io_meta_reset", 1),
                    ("rfuzz_input_bits", 37),
                ),
                dut_module="ibex_opentitan_real_ip_top",
                dut_instance="dut",
            )

    def test_candidate_validation_rejects_non_ascii_emitted_identifiers(self) -> None:
        compat = original_rfuzz()
        valid_arguments = {
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
        cases = (
            (
                "candidate module",
                candidate_source().replace(
                    "module myfuzz_candidate_direct_a6ccf1733940(",
                    "module myfuzz_candidate_direct_a6ccf1733940_测试(",
                ),
                {**valid_arguments, "module": "myfuzz_candidate_direct_a6ccf1733940_测试"},
            ),
            (
                "candidate DUT module",
                candidate_source().replace(
                    "ibex_opentitan_real_ip_top dut",
                    "ibex_opentitan_real_ip_top_测试 dut",
                ),
                {**valid_arguments, "dut_module": "ibex_opentitan_real_ip_top_测试"},
            ),
            (
                "candidate DUT instance",
                candidate_source().replace(
                    "ibex_opentitan_real_ip_top dut",
                    "ibex_opentitan_real_ip_top dut_测试",
                ),
                {**valid_arguments, "dut_instance": "dut_测试"},
            ),
        )
        for label, source, arguments in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "identifier"):
                    compat.validate_candidate_source(source, **arguments)

    def test_candidate_validation_ignores_sv_strings_when_finding_module_scope(self) -> None:
        compat = original_rfuzz()
        source = candidate_source().replace(
            "  ibex_opentitan_real_ip_top dut();",
            '  string marker = "module fake endmodule // /*";\n'
            "  ibex_opentitan_real_ip_top dut();",
        )
        candidate = compat.validate_candidate_source(
            source,
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
        self.assertEqual("dut", candidate.dut_instance)

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
            fuzzer_hpp = verilator / "fuzzer.hpp"
            fuzzer_hpp.write_text("// original fuzzer\n", encoding="utf-8")
            instrumented = root / "instrumented"
            instrumented.mkdir()
            sources = instrumented / "sources.f"
            sources.write_text("top.sv\n", encoding="utf-8")
            (instrumented / "top.sv").write_text("module top; endmodule\n", encoding="utf-8")
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
            fuzzer_hpp.unlink()
            with self.assertRaisesRegex(ValueError, "fuzzer.hpp"):
                compat.build_server_command(
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
            self.assertNotIn((verilator / "fuzzer.hpp").as_posix(), command)
            self.assertIn(candidate.as_posix(), command)
            self.assertIn("-Wno-fatal", " ".join(command))
            self.assertNotIn("build_rfuzz_server.py", " ".join(command))

            outside = root.parent / f"{root.name}-outside.sv"
            outside.write_text("module outside; endmodule\n", encoding="utf-8")
            linked = instrumented / "linked.sv"
            linked.symlink_to(outside)
            for invalid_entry in (outside.as_posix(), linked.name):
                sources.write_text(invalid_entry + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "source list entry"):
                    compat.build_server_command(
                        root,
                        verilator_bin="verilator",
                        wrapper_module="wrapper",
                        sources_file=sources,
                        wrapper=wrapper,
                        candidate_source=candidate,
                        dut_header=header,
                        server_dir=root / "server",
                    )
            sources.write_text("top.sv\n", encoding="utf-8")
            for bad_args in (("--build-jobs", "8"), ("-j", "8"), ("--build-jobs=8",)):
                with self.assertRaisesRegex(ValueError, "single Verilator worker"):
                    compat.build_server_command(
                        root,
                        verilator_bin="verilator",
                        wrapper_module="wrapper",
                        sources_file=sources,
                        wrapper=wrapper,
                        candidate_source=candidate,
                        dut_header=header,
                        server_dir=root / "server",
                        verilator_args=bad_args,
                    )
            for bad_args in (
                ("--top-module", "attacker"),
                ("--top-module=attacker",),
                ("-f", "other.f"),
                ("--Mdir", "other_obj"),
                ("--Mdir=other_obj",),
                ("-o", "other_server"),
            ):
                with self.assertRaisesRegex(ValueError, "fixed Verilator binding"):
                    compat.build_server_command(
                        root,
                        verilator_bin="verilator",
                        wrapper_module="wrapper",
                        sources_file=sources,
                        wrapper=wrapper,
                        candidate_source=candidate,
                        dut_header=header,
                        server_dir=root / "server",
                        verilator_args=bad_args,
                    )

            fuzzer_hpp.write_text("// original fuzzer\n", encoding="utf-8")
            identity = compat.native_input_identity(
                root,
                sources_file=sources,
                verilator_bin="verilator",
                verilator_version="Verilator 5.020",
            )
            self.assertRegex(identity, r"^sha256:[0-9a-f]{64}$")
            top_cpp.write_text("// changed original top\n", encoding="utf-8")
            self.assertNotEqual(
                identity,
                compat.native_input_identity(
                    root,
                    sources_file=sources,
                    verilator_bin="verilator",
                    verilator_version="Verilator 5.020",
                ),
            )
            top_cpp.write_text("// original top\n", encoding="utf-8")
            self.assertNotEqual(
                identity,
                compat.native_input_identity(
                    root,
                    sources_file=sources,
                    verilator_bin="verilator",
                    verilator_version="Verilator 5.020",
                    extra_cflags=("-DCHANGED",),
                ),
            )

    def test_generated_writer_rejects_symlinked_missing_parent_before_creation(self) -> None:
        compat = original_rfuzz()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root.parent / f"{root.name}-outside-parent"
            outside.mkdir()
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "generated output parent"):
                compat.write_text_file(linked / "new" / "output.txt", "unsafe")
            self.assertFalse((outside / "new").exists())
            outside.rmdir()

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
            top_source, sources_file = self._install_top_source(root)

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
                sources_file=sources_file,
                design_source=top_source,
            )

            self.assertIn(
                "candidate.dut.__vi_coverage",
                materialized.wrapper.read_text(encoding="utf-8"),
            )
            augmented = materialized.toml.read_text(encoding="utf-8")
            self.assertEqual(1853, augmented.count("[[counter]]"))
            self.assertEqual("candidate_direct.abi.json", materialized.raw_abi.path.name)
            self.assertTrue(materialized.header.is_file())

    def test_materialized_reload_rejects_tampered_bound_artifact_content(self) -> None:
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
            top_source, sources_file = self._install_top_source(root)
            compat.materialize_harness(
                root,
                harness_dir=harness,
                base_toml=base_toml,
                instrumentation=instrumentation(),
                top="ibex_opentitan_real_ip_top",
                expected_ports=(("clock", 1), ("reset", 1), ("io_meta_reset", 1), ("rfuzz_input_bits", 37)),
                sources_file=sources_file,
                design_source=top_source,
            )
            for filename, marker in (
                ("candidate_direct.sv", "tampered candidate"),
                ("original_rfuzz_wrapper.sv", "tampered wrapper"),
                ("dut.hpp", "tampered header"),
                ("ibex_opentitan_real_ip_top.rfuzz.toml", "tampered toml"),
            ):
                path = harness / filename
                original = path.read_text(encoding="utf-8")
                path.write_text(original + marker, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "content hash"):
                    compat.load_materialized_harness(
                        root,
                        harness,
                        instrumentation=instrumentation(),
                        sources_file=sources_file,
                        design_source=top_source,
                    )
                path.write_text(original, encoding="utf-8")

            compat.load_materialized_harness(
                root,
                harness,
                instrumentation=instrumentation(),
                sources_file=sources_file,
                design_source=top_source,
            )

    def test_materialized_reload_rejects_changed_current_design_input(self) -> None:
        compat = original_rfuzz()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / "harness"
            harness.mkdir()
            source = harness / "candidate_direct.sv"
            source.write_text(candidate_source(), encoding="utf-8")
            (harness / "candidate_direct.abi.json").write_text(
                json.dumps({
                    "source": source.name,
                    "module": "myfuzz_candidate_direct_a6ccf1733940",
                    "raw_width": 37,
                }),
                encoding="utf-8",
            )
            base_toml = root / "top.toml"
            base_toml.write_text("[general]\ntop = \"ibex_opentitan_real_ip_top\"\n")
            top_source, sources_file = self._install_top_source(root)
            compat.materialize_harness(
                root,
                harness_dir=harness,
                base_toml=base_toml,
                instrumentation=instrumentation(),
                top="ibex_opentitan_real_ip_top",
                expected_ports=(("clock", 1), ("reset", 1), ("io_meta_reset", 1), ("rfuzz_input_bits", 37)),
                sources_file=sources_file,
                design_source=top_source,
            )
            changed_source = top_source.replace("[1852:0]", "[1851:0]")
            (root / "instrumented" / "top.sv").write_text(changed_source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source graph|design source|coverage port"):
                compat.load_materialized_harness(
                    root,
                    harness,
                    instrumentation=instrumentation(),
                    sources_file=sources_file,
                    design_source=changed_source,
                )

    def test_coverage_binding_checks_actual_selected_top_port_width(self) -> None:
        compat = original_rfuzz()
        top_source = """module ibex_opentitan_real_ip_top(\n  output wire [1849:0] __vi_coverage\n);\nendmodule\n"""
        with self.assertRaisesRegex(ValueError, "coverage port width"):
            compat.validate_coverage_binding(
                instrumentation(), "ibex_opentitan_real_ip_top", top_source
            )

    def test_coverage_binding_rejects_selected_top_scope_and_direction_mismatch(self) -> None:
        compat = original_rfuzz()
        decoy_source = """module ibex_opentitan_real_ip_top();
module decoy(output wire [1852:0] __vi_coverage);
endmodule
"""
        with self.assertRaisesRegex(ValueError, "coverage port"):
            compat.validate_coverage_binding(
                instrumentation(), "ibex_opentitan_real_ip_top", decoy_source
            )
        input_source = """module ibex_opentitan_real_ip_top(
  input wire [1852:0] __vi_coverage
);
endmodule
"""
        with self.assertRaisesRegex(ValueError, "coverage port"):
            compat.validate_coverage_binding(
                instrumentation(), "ibex_opentitan_real_ip_top", input_source
            )

        for subprogram in ("function void f", "task t"):
            with self.subTest(subprogram=subprogram):
                only_subprogram_source = f"""module ibex_opentitan_real_ip_top;
  {subprogram}(output logic [1852:0] __vi_coverage);
  end{subprogram.split()[0]}
  assign unused = 1'b0;
endmodule
"""
                with self.assertRaisesRegex(ValueError, "coverage port"):
                    compat.validate_coverage_binding(
                        instrumentation(),
                        "ibex_opentitan_real_ip_top",
                        only_subprogram_source,
                    )

        mixed_source = """module ibex_opentitan_real_ip_top;
  function void f(output logic [1852:0] __vi_coverage);
  endfunction
  output wire [1852:0] __vi_coverage;
endmodule
"""
        self.assertEqual(
            1853,
            compat.validate_coverage_binding(
                instrumentation(), "ibex_opentitan_real_ip_top", mixed_source
            ).width,
        )

    def test_selected_instrumented_top_source_accepts_non_ansi_module(self) -> None:
        script_dir = Path(__file__).resolve().parents[1] / "src" / "myfuzz" / "scripts"
        if script_dir.as_posix() not in sys.path:
            sys.path.insert(0, script_dir.as_posix())
        run_design_flow = importlib.import_module("run_design_flow")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "repo"
            root.mkdir()
            instrumented = root / "instrumented"
            instrumented.mkdir()
            source = root / "top.sv"
            source_text = """module selected_top;
  output wire [7:0] __vi_coverage;
endmodule
"""
            source.write_text(source_text, encoding="utf-8")
            (instrumented / "sources.f").write_text("../top.sv\n", encoding="utf-8")
            selected = run_design_flow.selected_instrumented_top_source(
                root, {"instrumented": instrumented}, {}, "selected_top"
            )
            self.assertEqual(source_text, selected)

            outside_list = root.parent / "external-sources.f"
            outside_list.write_text(f"{source.as_posix()}\n", encoding="utf-8")
            source_list = instrumented / "sources.f"
            source_list.unlink()
            source_list.symlink_to(outside_list)
            with self.assertRaisesRegex(ValueError, "source list"):
                run_design_flow.selected_instrumented_top_source(
                    root, {"instrumented": instrumented}, {}, "selected_top"
                )

    def test_materialization_rejects_existing_output_symlink_before_write(self) -> None:
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
            top_source, sources_file = self._install_top_source(root)
            outside = root.parent / f"{root.name}-outside-wrapper.sv"
            outside.write_text("before\n", encoding="utf-8")
            try:
                (harness / "original_rfuzz_wrapper.sv").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "regular"):
                    compat.materialize_harness(
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
                        sources_file=sources_file,
                        design_source=top_source,
                    )
                self.assertEqual("before\n", outside.read_text(encoding="utf-8"))
            finally:
                outside.unlink(missing_ok=True)

    def test_toml_coverage_records_must_be_objects(self) -> None:
        compat = original_rfuzz()
        del compat
        from tests.harness.test_flow_integration import frontend_manifest
        from frontend_manifest_to_rfuzz_toml import write_toml

        bad = instrumentation()
        bad["coverage"] = ["not-an-object", "also-not-an-object"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, r"coverage\[0\]"):
                write_toml(
                    frontend_manifest(), bad, "generated_top", Path(directory) / "bad.toml"
                )

    def test_toml_generation_is_deterministic_for_same_inputs(self) -> None:
        from tests.harness.test_flow_integration import (
            candidate_manifest,
            frontend_manifest,
            instrumentation_manifest,
        )
        import frontend_manifest_to_rfuzz_toml
        from frontend_manifest_to_rfuzz_toml import write_toml

        clock_type = frontend_manifest_to_rfuzz_toml.dt.datetime
        timezone_type = frontend_manifest_to_rfuzz_toml.dt.timezone
        first = clock_type(2026, 8, 3, 1, 2, 3, tzinfo=timezone_type.utc)
        second = clock_type(2026, 8, 3, 4, 5, 6, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.toml"
            second_path = Path(directory) / "second.toml"
            with patch.object(frontend_manifest_to_rfuzz_toml.dt, "datetime") as clock:
                clock.now.return_value = first
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    first_path,
                    candidate_manifest=candidate_manifest(),
                )
                clock.now.return_value = second
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    second_path,
                    candidate_manifest=candidate_manifest(),
                )
            self.assertEqual(first_path.read_text(), second_path.read_text())

            outside = Path(directory).parent / "outside.toml"
            outside.write_text("before\n", encoding="utf-8")
            linked = Path(directory) / "linked.toml"
            linked.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    linked,
                    candidate_manifest=candidate_manifest(),
                )

    def test_candidate_artifact_writer_rejects_existing_source_symlink(self) -> None:
        script_dir = Path(__file__).resolve().parents[1] / "src" / "myfuzz" / "scripts"
        if script_dir.as_posix() not in sys.path:
            sys.path.insert(0, script_dir.as_posix())
        run_design_flow = importlib.import_module("run_design_flow")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / "harness"
            harness.mkdir()
            outside = root.parent / f"{root.name}-candidate.sv"
            outside.write_text("before\n", encoding="utf-8")
            (harness / "candidate_direct.sv").symlink_to(outside)
            artifact = SimpleNamespace(
                mode="candidate_direct",
                source_text="module candidate_direct;\nendmodule\n",
                manifest_fragment=lambda: {"mode": "candidate_direct", "raw_width": 1},
            )
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                run_design_flow.write_candidate_harness_artifact(
                    {"harness": harness}, artifact
                )
            self.assertEqual("before\n", outside.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
