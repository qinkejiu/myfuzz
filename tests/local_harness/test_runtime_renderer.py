"""Runtime top wiring and admission, with actual pinned RTL lint."""
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime
from tests.local_harness.test_renderer import real_plan, ROOT


class RuntimeRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu = real_plan('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
        cls.gpio = real_plan('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
        cls.structures = [render_local_harness(p) for p in (cls.cpu, cls.gpio)]
        cls.verifications = [verify_local_source_lock(p.profile, base_dir=ROOT) for p in (cls.cpu, cls.gpio)]

    def artifact(self, index):
        return render_local_runtime((self.cpu, self.gpio)[index], self.structures[index], self.verifications[index], base_dir=ROOT)

    def test_deterministic_preserved_structural_identity(self):
        for index, plan in enumerate((self.cpu, self.gpio)):
            first, second = self.artifact(index), self.artifact(index)
            self.assertEqual(first.runtime_sv, second.runtime_sv)
            self.assertEqual(first.runtime_document, second.runtime_document)
            self.assertEqual(first.structural, self.structures[index])
            self.assertEqual(first.runtime_document['plan'], plan.document())
            self.assertEqual(first.runtime_document['schema_version'], 'local_runtime_artifact.v1')
            self.assertEqual(first.runtime_document['status'], 'top_only')
            self.assertEqual(first.cpp_text, '')
            self.assertEqual(first.runtime_sv.count(' u_component ('), 1)
            self.assertEqual(first.structural.wrapper_sv.count(' u_dut ('), 1)
            for port in plan.facts.ports:
                self.assertEqual(first.structural.wrapper_sv.count('.'+port.name+'('), 1)
            for row in first.structural.abi_document['ports']:
                self.assertEqual(first.runtime_sv.count('.'+row['wrapper_name']+'('), 1)
            self.assertEqual(first.runtime_document['structural_build']['parameter_overrides'],
                             dict(plan.profile.source.elaboration.parameters))

    def test_protocol_adapters_outside_structure_and_all_observations_exported(self):
        cpu, gpio = self.artifact(0), self.artifact(1)
        self.assertEqual(cpu.runtime_sv.count('obi_processor_memory_adapter #('), 2)
        self.assertIn('.READ_ONLY(1)', cpu.runtime_sv)
        self.assertIn('.HAS_BE(1)', cpu.runtime_sv)
        self.assertIn('beat_to_apb #(', gpio.runtime_sv)
        for text in (cpu.structural.wrapper_sv, gpio.structural.wrapper_sv):
            self.assertNotIn('beat_to_apb', text)
            self.assertNotIn('obi_processor_memory_adapter', text)
        for artifact in (cpu, gpio):
            exported = {r['wrapper_name']: r for r in artifact.runtime_document['physical_exports']}
            for row in artifact.structural.abi_document['ports']:
                if row['endpoint_id'] not in artifact.runtime_document['adapted_endpoint_ids']:
                    self.assertEqual(exported[row['wrapper_name']]['width'], row['width'])
                    self.assertEqual(exported[row['wrapper_name']]['direction'], row['direction'])
            self.assertTrue(any(row['width'] > 64 and row['encoding'] == 'fixed_width_hex'
                                for row in exported.values()))
        self.assertIn('.ADDRESS_WIDTH(32)', gpio.runtime_sv)
        self.assertIn('.WINDOW_SIZE(4096)', gpio.runtime_sv)
        self.assertIn('apb_paddr[11:0]', gpio.runtime_sv)

    def test_tampered_profile_structure_and_source_admission_refused(self):
        with self.assertRaises(ValueError):
            render_local_runtime(replace(self.cpu, profile_sha256='0'*64), self.structures[0], self.verifications[0], base_dir=ROOT)
        for changed in (replace(self.structures[0], wrapper_sv=self.structures[0].wrapper_sv+'// changed\n'),
                        replace(self.structures[0], abi_document={})):
            with self.assertRaises(ValueError):
                render_local_runtime(self.cpu, changed, self.verifications[0], base_dir=ROOT)
        for key, value in [('schema_version', 'other'), ('source_status', 'source_unverified'),
                           ('id', 'other'), ('selected_content_hash', 'sha256:'+'0'*64),
                           ('lock_sha256', 'broken')]:
            changed = dict(self.verifications[0], **{key: value})
            with self.assertRaises(ValueError):
                render_local_runtime(self.cpu, self.structures[0], changed, base_dir=ROOT)

    def test_unsupported_protocol_and_field_shapes_refused(self):
        endpoint = next(e for e in self.cpu.binding.endpoints if e.protocol)
        for changed in (replace(endpoint, protocol=('axi4', '1')),
                        replace(endpoint, fields=endpoint.fields[:-1])):
            binding = replace(self.cpu.binding, endpoints=tuple(changed if e is endpoint else e for e in self.cpu.binding.endpoints))
            with self.assertRaises(ValueError):
                render_local_runtime(replace(self.cpu, binding=binding), self.structures[0], self.verifications[0], base_dir=ROOT)
        with self.assertRaises(ValueError):
            render_local_runtime(replace(self.cpu, dispositions=self.cpu.dispositions[:-1]), self.structures[0], self.verifications[0], base_dir=ROOT)

    @unittest.skipUnless(shutil.which('verilator'), 'Verilator required')
    def test_actual_cve2_and_gpio_runtime_lint(self):
        for index in (0, 1):
            artifact = self.artifact(index)
            with TemporaryDirectory() as directory:
                structural = Path(directory)/'structural.sv'; structural.write_text(artifact.structural.wrapper_sv)
                runtime = Path(directory)/'runtime.sv'; runtime.write_text(artifact.runtime_sv)
                argv = artifact.runtime_document['lint_argv']+[str(structural), str(runtime)]
                result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr[-7000:])
                self.assertNotIn('%Error', result.stdout+result.stderr)

    @unittest.skipUnless(shutil.which('verilator'), 'Verilator required')
    def test_gpio_actual_address_window_rejects_alias(self):
        artifact = self.artifact(1)
        values = dict(clk='clk', reset='reset', gpio_req_valid='req_valid', gpio_req_addr='addr',
                      gpio_req_ready='req_ready', gpio_rsp_valid='rsp_valid', gpio_rsp_error='error',
                      gpio_rsp_ready='rsp_ready', gpio_req_be="4'hf")
        connections = []
        for row in artifact.runtime_document['runtime_ports']:
            expression = values.get(row['name'], "'0" if row['direction'] == 'input' else '')
            connections.append('.'+row['name']+'('+expression+')')
        bench = '''module address_gate_test;
logic clk=0, reset=0, req_valid=0, rsp_ready=0;
logic [31:0] addr=0;
wire req_ready, rsp_valid, error;
%s dut (%s);
task edge_tick;
  clk=0; #1; clk=1; #1; clk=0; #1;
endtask
initial begin
  reset=1; edge_tick(); edge_tick(); reset=0; #1;
  if (!req_ready) $fatal(1, "not ready");
  addr=32'h1000; req_valid=1; edge_tick(); req_valid=0; #1;
  if (!rsp_valid || !error || dut.u_adapter_gpio.psel || dut.u_component.u_dut.PSEL)
    $fatal(1, "outside window aliased into APB");
  rsp_ready=1; edge_tick(); rsp_ready=0;
  addr=32'hffc; req_valid=1; edge_tick(); req_valid=0; #1;
  if (rsp_valid || !dut.u_component.u_dut.PSEL || dut.apb_paddr != 32'hffc || dut.u_component.u_dut.PADDR != 12'hffc)
    $fatal(1, "last aligned local word incorrectly rejected");
  edge_tick();
  if (!dut.u_component.u_dut.PENABLE) $fatal(1, "native APB ACCESS missing");
  edge_tick();
  if (!rsp_valid || error) $fatal(1, "in-window access failed");
  $display("ADDRESS_GATE_PASS"); $finish;
end
endmodule
''' % (artifact.runtime_document['module_name'], ','.join(connections))
        with TemporaryDirectory() as directory:
            directory = Path(directory)
            structural = directory/'structural.sv'; structural.write_text(artifact.structural.wrapper_sv)
            runtime = directory/'runtime.sv'; runtime.write_text(artifact.runtime_sv)
            testbench = directory/'address_gate.sv'; testbench.write_text(bench)
            argv = list(artifact.runtime_document['lint_argv'])
            argv[argv.index('--lint-only')] = '--binary'
            argv[argv.index('--top-module')+1] = 'address_gate_test'
            argv += ['--timing', '-j', '1', '--Mdir', str(directory/'obj'),
                     str(structural), str(runtime), str(testbench)]
            build = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr[-7000:])
            run = subprocess.run([str(directory/'obj/Vaddress_gate_test')], text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            self.assertIn('ADDRESS_GATE_PASS', run.stdout)

    def test_changed_profile_constant_refused_even_with_matching_structure(self):
        entry = next(e for e in self.cpu.dispositions if e.port == 'boot_addr_i')
        changed = replace(self.cpu, dispositions=tuple(replace(e, value=e.value+4) if e is entry else e
                                                      for e in self.cpu.dispositions))
        structural = render_local_harness(changed)
        with self.assertRaisesRegex(ValueError, 'runtime-disposition-profile-mismatch'):
            render_local_runtime(changed, structural, self.verifications[0], base_dir=ROOT)

    def test_self_consistent_forged_physical_width_refused(self):
        from myfuzz.composition.component_profile import bind_profile
        facts = replace(self.cpu.facts, ports=tuple(replace(p, width=65) if p.name == 'rvfi_order' else p
                                                   for p in self.cpu.facts.ports))
        entries = tuple(replace(e, width=65, bit_hi=64) if e.port == 'rvfi_order' else e
                        for e in self.cpu.dispositions)
        changed = replace(self.cpu, facts=facts, binding=bind_profile(self.cpu.profile, facts), dispositions=entries)
        with self.assertRaisesRegex(ValueError, 'runtime-physical-facts-mismatch'):
            render_local_runtime(changed, render_local_harness(changed), self.verifications[0], base_dir=ROOT)
