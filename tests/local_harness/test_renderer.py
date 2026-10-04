from dataclasses import replace
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from myfuzz.local_harness import load_local_harness_request, plan_local_harness, render_local_harness
from myfuzz.local_harness.port_rendering import LocalPortRenderError, render_port_connections

ROOT = Path(__file__).resolve().parents[2]


def real_plan(profile, instance):
    return plan_local_harness(load_local_harness_request({
        'schema_version': 'local_harness.v1', 'profile_path': profile,
        'instance_id': instance, 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    }), base_dir=ROOT)


class LocalPortRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu = real_plan('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
        cls.gpio = real_plan('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')

    def test_full_ports_and_abi_raw_spans(self):
        for plan in (self.cpu, self.gpio):
            declarations, assignments, connections, abi = render_port_connections(plan)
            self.assertEqual(len(connections), len(plan.facts.ports))
            self.assertEqual(len(set(connections)), len(connections))
            for entry in plan.dispositions:
                rows = [r for r in abi if r['physical_port'] == entry.port
                        and r['bit_lo'] == entry.bit_lo and r['bit_hi'] == entry.bit_hi]
                exposed = entry.disposition not in ('constant', 'unconnected') and entry.role not in ('clock', 'reset')
                self.assertEqual(len(rows), int(exposed))
                if exposed:
                    self.assertEqual(rows[0]['width'], entry.bit_hi - entry.bit_lo + 1)
                    self.assertEqual(rows[0]['direction'], entry.direction)
            self.assertTrue(declarations)
            self.assertTrue(assignments)
        self.assertTrue(any(row['width'] > 64 for row in render_port_connections(self.cpu)[3]))
        self.assertTrue(any(row['width'] == 128 for row in render_port_connections(self.gpio)[3]))

    def test_rejects_invalid_coverage_direction_and_dispositions(self):
        plan = self.gpio
        entry = next(e for e in plan.dispositions if e.direction == 'input' and e.role not in ('clock', 'reset'))
        changes = [replace(entry, disposition='unconnected', target=None),
                   replace(entry, direction='inout'), replace(entry, bit_lo=-1),
                   replace(entry, bit_hi=entry.width), replace(entry, width=entry.width+1),
                   replace(entry, port='bad-name')]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(LocalPortRenderError):
                render_port_connections(replace(plan, dispositions=tuple(changed if e is entry else e for e in plan.dispositions)))
        for entries in (plan.dispositions[1:], plan.dispositions + (entry,)):
            with self.assertRaises(LocalPortRenderError):
                render_port_connections(replace(plan, dispositions=entries))
        with self.assertRaises(LocalPortRenderError):
            render_port_connections(replace(plan, facts=replace(plan.facts, selection='declared')))

    def test_reset_is_assertion_high_at_boundary(self):
        assignments = render_port_connections(self.gpio)[1]
        self.assertTrue(any(' = ~reset;' in s for s in assignments))

    def test_repeat_render_and_build_identity(self):
        for plan in (self.cpu, self.gpio):
            first = render_local_harness(plan)
            second = render_local_harness(plan)
            self.assertEqual(first.wrapper_sv, second.wrapper_sv)
            self.assertEqual(json.dumps(first.abi_document, sort_keys=True), json.dumps(second.abi_document, sort_keys=True))
            self.assertEqual(first.build_document, second.build_document)
            self.assertEqual(first.wrapper_sv.count(' u_dut ('), 1)
            self.assertEqual(first.wrapper_sv.count('module ' + first.module_name), 1)
            self.assertEqual(first.build_document['status'], 'structural_only')
            self.assertEqual(first.build_document['parameter_overrides'], dict(plan.profile.source.elaboration.parameters))
            self.assertEqual(first.build_document['source_files'], [plan.profile.source.source_root + '/' + f for f in plan.facts.files])
            for name, value in plan.profile.source.elaboration.parameters:
                self.assertIn('.' + name + '(', first.wrapper_sv)
            self.assertTrue(first.wrapper_sv.endswith('\n'))

    @unittest.skipUnless(shutil.which('verilator'), 'Verilator is required')
    def test_real_cve2_and_pulp_wrapper_lint(self):
        for plan in (self.cpu, self.gpio):
            rendered = render_local_harness(plan)
            with TemporaryDirectory() as directory:
                wrapper = Path(directory) / (rendered.module_name + '.sv')
                wrapper.write_text(rendered.wrapper_sv)
                command = list(rendered.build_document['lint_argv']) + [str(wrapper)]
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr[-6000:])
                self.assertNotIn('%Error', result.stderr + result.stdout)

    def test_parameter_type_evidence_refuses_unknown_and_ambiguous_types(self):
        from myfuzz.local_harness.parameter_evidence import parameter_evidence
        top = 'module sample import types::*; #(parameter mode_e MODE = Fast) (); endmodule'
        package = 'package types; typedef enum integer {Slow=0, Fast=2} mode_e; endpackage'
        rows = parameter_evidence('sample', ('MODE',), (('top.sv', top), ('pkg.sv', package)))
        self.assertEqual(rows[0]['qualified_type'], 'types::mode_e')
        for snapshots in ((('top.sv', top),),
                          (('top.sv', top), ('a.sv', package), ('b.sv', package)),
                          (('top.sv', top.replace('mode_e MODE', 'bad_e MODE')), ('pkg.sv', package)),
                          (('top.sv', top), ('copy.sv', top), ('pkg.sv', package))):
            with self.assertRaises(LocalPortRenderError):
                parameter_evidence('sample', ('MODE',), snapshots)

    def test_renderer_refuses_tampered_parameter_evidence(self):
        sources = tuple((name, text.replace('rv32m_e      RV32M', 'unknown_e    RV32M'))
                        for name, text in self.cpu.parameter_sources)
        with self.assertRaises(LocalPortRenderError):
            render_local_harness(replace(self.cpu, parameter_sources=sources))

    def test_rejects_reserved_and_escaped_identifiers(self):
        from myfuzz.local_harness.port_rendering import require_identifier
        for name in ('wire', 'always_ff', 'interface', 'endclass', '\\escaped', 'with', 'automatic'):
            with self.assertRaises(LocalPortRenderError):
                require_identifier(name)

    def test_split_aggregate_observation_preserves_high_to_low_order(self):
        entry = next(e for e in self.gpio.dispositions if e.port == 'gpio_padcfg')
        pieces = (replace(entry, bit_lo=64), replace(entry, bit_hi=63))
        entries = tuple(e for e in self.gpio.dispositions if e is not entry) + pieces
        rows = [row for row in render_port_connections(replace(self.gpio, dispositions=entries))[3]
                if row['physical_port'] == 'gpio_padcfg']
        self.assertEqual([(row['bit_hi'], row['bit_lo']) for row in rows], [(127, 64), (63, 0)])

    def test_explicit_unconnected_output_retains_ledger(self):
        entry = next(e for e in self.gpio.dispositions if e.port == 'interrupt')
        entries = tuple(replace(e, disposition='unconnected', target=None) if e is entry else e
                        for e in self.gpio.dispositions)
        rendered = render_local_harness(replace(self.gpio, dispositions=entries))
        self.assertFalse(any(row['physical_port'] == 'interrupt' for row in rendered.abi_document['ports']))
        self.assertTrue(any(row['port'] == 'interrupt' and row['disposition'] == 'unconnected'
                            for row in rendered.abi_document['dispositions']))
