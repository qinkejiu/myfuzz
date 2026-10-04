"""Generated CVA6 packed AXI4 runtime boundary; no execution claim here."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)


ROOT = Path(__file__).resolve().parents[2]


class Cva6PackedAxi4RuntimeAcceptance(unittest.TestCase):
    def test_single_64_bit_id4_packed_axi4_runtime_top_lints(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        request = load_local_harness_request({
            'schema_version': 'local_harness.v1',
            'profile_path': 'configs/cpus/cva6/component_profile.json',
            'instance_id': 'cva6',
            'reset_assert_ticks': 16,
            'reset_release_ticks': 20,
            'max_wait_cycles': 32,
        })
        plan = plan_local_harness(request, base_dir=ROOT)
        structural = render_local_harness(plan)
        runtime = render_local_runtime(plan, structural,
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        self.assertEqual('cva6_packed_axi4_cpu', runtime.runtime_document['kind'])
        backend = {row['name']: row for row in runtime.runtime_document['backend_ports']}
        self.assertEqual(45, len(backend))
        self.assertEqual(('output', 64),
                         (backend['axi_awaddr']['direction'], backend['axi_awaddr']['width']))
        self.assertEqual(('input', 64),
                         (backend['axi_rdata']['direction'], backend['axi_rdata']['width']))
        self.assertEqual(('output', 4),
                         (backend['axi_arid']['direction'], backend['axi_arid']['width']))
        irq = [row for row in runtime.runtime_document['physical_exports']
               if row['physical_port'] == 'irq_i' and row['role'] == 'machine_external']
        self.assertEqual(1, len(irq))
        self.assertEqual(('input', 1), (irq[0]['direction'], irq[0]['width']))
        self.assertEqual(65536, runtime.runtime_document['boot_contract']['configured_boot_base'])
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-runtime-') as directory:
            structural_file = Path(directory) / 'local_cva6.sv'
            runtime_file = Path(directory) / 'local_runtime_cva6.sv'
            structural_file.write_text(structural.wrapper_sv)
            runtime_file.write_text(runtime.runtime_sv)
            lint = subprocess.run([*runtime.runtime_document['lint_argv'],
                                   str(structural_file), str(runtime_file)],
                                  cwd=ROOT, capture_output=True, text=True, timeout=180)
            self.assertEqual(0, lint.returncode, lint.stderr[-3000:])
            self.assertNotIn('%Error', lint.stderr + lint.stdout)


if __name__ == '__main__':
    unittest.main()
