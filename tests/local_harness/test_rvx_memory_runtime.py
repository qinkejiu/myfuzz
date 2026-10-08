"""Generated physical runtime and one-local-tick driver for RVX memory pins."""
from dataclasses import replace
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_driver,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)
from myfuzz.local_harness.session import _OPERATIONS

ROOT = Path(__file__).resolve().parents[2]


def real_plan(profile, instance):
    request = load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": profile,
        "instance_id": instance,
        "reset_assert_ticks": 8,
        "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })
    return plan_local_harness(request, base_dir=ROOT)


class RvxMemoryRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = real_plan("configs/cpus/rvx_core/component_profile.json", "rvx_cpu")
        cls.structural = render_local_harness(cls.plan)
        cls.verification = verify_local_source_lock(
            cls.plan.profile, base_dir=ROOT, allow_source_only=True
        )
        cls.runtime = render_local_runtime(
            cls.plan, cls.structural, cls.verification, base_dir=ROOT
        )
        cls.driver = render_local_driver(cls.runtime, base_dir=ROOT)

    def test_runtime_directly_exposes_completion_memory_pins(self):
        artifact = self.runtime
        self.assertEqual(artifact.runtime_document["kind"], "rvx_memory_cpu")
        self.assertEqual(artifact.runtime_document["adapted_endpoint_ids"],
                         ["processor.memory"])
        self.assertEqual(artifact.runtime_document["adapter_sources"], [])
        self.assertNotIn("native_completion_memory_adapter", artifact.runtime_sv)
        backend = artifact.runtime_document["backend_ports"]
        by_role = {row["role"]: row for row in backend}
        expected = {
            "addr": ("output", 32),
            "read_request": ("output", 1),
            "read_response": ("input", 1),
            "read_data": ("input", 32),
            "write_request": ("output", 1),
            "write_response": ("input", 1),
            "write_data": ("output", 32),
            "write_strobe": ("output", 4),
        }
        self.assertEqual({name: (row["direction"], row["width"])
                          for name, row in by_role.items()}, expected)
        self.assertEqual({row["name"] for row in backend},
                         {"rvx_" + role for role in expected})
        self.assertTrue(all(row["name"] in {
            port["name"] for port in artifact.runtime_document["runtime_ports"]
        } for row in backend))
        exports = artifact.runtime_document["physical_exports"]
        exported_inputs = {row["physical_port"] for row in exports if row["direction"] == "input"}
        self.assertEqual(exported_inputs, set())
        for name in ("halt", "irq_external", "irq_timer", "irq_software",
                     "irq_fast", "real_time_clock"):
            self.assertNotIn(name, {row["physical_port"] for row in exports})
            disposition = next(row for row in self.plan.dispositions if row.port == name)
            self.assertEqual((disposition.disposition, disposition.value), ("constant", 0))
        self.assertEqual(artifact.runtime_document["selected_template"]["contract"]["template_id"],
                         "cpu.pipelined-memory")

    def test_driver_accepts_only_one_bounded_memory_tick(self):
        self.assertIn("rvx_memory_cpu", _OPERATIONS)
        self.assertEqual(_OPERATIONS["rvx_memory_cpu"]["STEP_RVX_MEMORY"],
                         (1, 1, 0xFFFFFFFF))
        cpp = self.driver.cpp_text
        self.assertIn('command.operation != "STEP_RVX_MEMORY"', cpp)
        self.assertIn("dut.rvx_read_response = command.fields[0];", cpp)
        self.assertIn("dut.rvx_write_response = command.fields[1];", cpp)
        self.assertIn("dut.rvx_read_data = command.fields[2];", cpp)
        self.assertIn("pre_backend = backend_snapshot(dut);", cpp)
        self.assertIn("tick(dut, &samples);", cpp)

    @unittest.skipUnless(shutil.which("c++"), "C++ compiler required")
    def test_shared_wire_parser_admits_rvx_step_shape(self):
        # Exercise the actual shared command parser: checking the generated
        # dispatch alone misses commands rejected before dispatch is reached.
        source = r'''#include <iostream>
#include "myfuzz/local_harness/rtl/local_driver_v1.h"
int main() {
  const auto parsed = myfuzz::local_driver_v1::parse_command(
      "CMD aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 STEP_RVX_MEMORY 0 0 0");
  if (!parsed.ok || parsed.command.fields.size() != 3 ||
      parsed.command.fields[0] != 0 || parsed.command.fields[1] != 0 ||
      parsed.command.fields[2] != 0) {
    std::cerr << parsed.code << ":" << parsed.detail << "\\n";
    return 1;
  }
  return 0;
}
'''
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cpp = root / "parser.cpp"
            binary = root / "parser"
            cpp.write_text(source)
            build = subprocess.run(
                [shutil.which("c++"), "-std=c++17", "-Isrc", str(cpp), "-o", str(binary)],
                cwd=ROOT, text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            parsed = subprocess.run([str(binary)], text=True, capture_output=True,
                                     timeout=5, check=False)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_runtime_rejects_changed_endpoint_roles(self):
        endpoint = next(item for item in self.plan.binding.endpoints if item.protocol)
        changed = replace(endpoint, fields=endpoint.fields[:-1])
        binding = replace(
            self.plan.binding,
            endpoints=tuple(changed if item is endpoint else item
                            for item in self.plan.binding.endpoints),
        )
        with self.assertRaises(ValueError):
            render_local_runtime(replace(self.plan, binding=binding), self.structural,
                                 self.verification, base_dir=ROOT)

    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_generated_rvx_runtime_and_driver_lint(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            structural = root / "structural.sv"
            runtime = root / "runtime.sv"
            structural.write_text(self.driver.structural.wrapper_sv)
            runtime.write_text(self.driver.runtime_sv)
            argv = self.driver.runtime_document["lint_argv"] + [
                str(structural), str(runtime)
            ]
            result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True,
                                    timeout=120, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[-8000:])
            self.assertNotIn("%Error", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
