"""Component-local deterministic clock scheduling and reset admission."""
from dataclasses import replace
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.composition.component_profile import (
    ClockBinding, ResetBinding, load_component_profile,
)
from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.clock_schedule import build_local_clock_schedule
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.port_rendering import render_port_connections
from myfuzz.local_harness.session import GeneratedLocalSession

ROOT = Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', Path(__file__).resolve().parents[2])).resolve()


def real_plan(profile, instance):
    return plan_local_harness(load_local_harness_request({
        'schema_version': 'local_harness.v1', 'profile_path': profile,
        'instance_id': instance, 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    }), base_dir=ROOT)


class MultiClockScheduleTests(unittest.TestCase):
    def test_builds_separate_fixed_phase_clock_and_reset_signals(self):
        schedule = build_local_clock_schedule(
            (ClockBinding('clk_i', 'core', 24_000_000),
             ClockBinding('clk_aon_i', 'aon', 200_000)),
            (ResetBinding('rst_ni', 'core', 'active_low', False),
             ResetBinding('rst_aon_ni', 'aon', 'active_low', False)),
            reset_assert_ticks=60, reset_release_ticks=1)

        self.assertEqual(24_000_000, schedule['fast_frequency_hz'])
        self.assertEqual('all_low_then_half_period_toggle', schedule['phase_policy'])
        clocks = {row['domain']: row for row in schedule['clocks']}
        self.assertEqual(('clk', 1, 1, 1),
                         (clocks['core']['signal'], clocks['core']['ratio'],
                          clocks['core']['half_period_fast_ticks'],
                          clocks['core']['first_rising_fast_tick']))
        self.assertEqual(('clk_aon', 120, 60, 60),
                         (clocks['aon']['signal'], clocks['aon']['ratio'],
                          clocks['aon']['half_period_fast_ticks'],
                          clocks['aon']['first_rising_fast_tick']))
        resets = {row['domain']: row for row in schedule['resets']}
        self.assertEqual(('reset_aon', 'active_low'),
                         (resets['aon']['signal'], resets['aon']['polarity']))
        self.assertEqual(('reset', 'active_low'),
                         (resets['core']['signal'], resets['core']['polarity']))
        self.assertEqual(61, schedule['startup_fast_ticks'])

    def test_single_clock_keeps_legacy_control_names(self):
        schedule = build_local_clock_schedule(
            (ClockBinding('clk_i', 'core', 50_000_000),),
            (ResetBinding('rst_ni', 'sys_rst', 'active_low', False),),
            reset_assert_ticks=8, reset_release_ticks=4)

        self.assertEqual('clk', schedule['clocks'][0]['signal'])
        self.assertEqual('reset', schedule['resets'][0]['signal'])
        self.assertEqual(12, schedule['startup_fast_ticks'])

    def test_rejects_frequency_ratios_without_supported_integer_even_schedule(self):
        cases = (
            ((ClockBinding('clk_i', 'core', 10),
              ClockBinding('clk_slow_i', 'slow', 3)), 'non_integral_ratio'),
            ((ClockBinding('clk_i', 'core', 12),
              ClockBinding('clk_slow_i', 'slow', 4)), 'odd_ratio'),
            ((ClockBinding('clk_i', 'core', 2048),
              ClockBinding('clk_slow_i', 'slow', 1)), 'ratio_exceeds_limit'),
            ((ClockBinding('clk_i', 'core', 0),), 'frequency_must_be_positive'),
        )
        resets = (ResetBinding('rst_ni', 'sys_rst', 'active_low', False),)
        for clocks, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(
                    ValueError, 'local-clock-schedule-unsupported:' + reason):
                build_local_clock_schedule(clocks, resets, reset_assert_ticks=2048,
                                           reset_release_ticks=1)

    def test_rejects_unordered_simulation_of_declared_reset_sequence(self):
        clocks = (ClockBinding('clk_i', 'core', 24_000_000),)
        resets = (ResetBinding('rst_ni', 'core', 'active_low', False,
                               sequence_after=('por_ni',)),)
        with self.assertRaisesRegex(ValueError, 'local-reset-sequence-unsupported'):
            build_local_clock_schedule(clocks, resets, reset_assert_ticks=8,
                                       reset_release_ticks=1)

    def test_requires_a_reset_sampled_edge_in_every_domain_before_ready(self):
        clocks = (ClockBinding('clk_i', 'core', 24_000_000),
                  ClockBinding('clk_aon_i', 'aon', 200_000))
        resets = (ResetBinding('rst_ni', 'core', 'active_low', False),)
        with self.assertRaisesRegex(ValueError,
                                    'local-clock-schedule-unsupported:reset_edge_not_sampled'):
            build_local_clock_schedule(clocks, resets, reset_assert_ticks=59,
                                       reset_release_ticks=1)

    def test_plan_rejects_unsupported_clock_contracts_before_source_elaboration(self):
        request = load_local_harness_request({
            'schema_version': 'local_harness.v1',
            'profile_path': 'configs/peripherals/pulp_gpio/component_profile.json',
            'instance_id': 'gpio_invalid_clock_fixture', 'reset_assert_ticks': 8,
            'reset_release_ticks': 8, 'max_wait_cycles': 16,
        })
        profile_path = ROOT / request.profile_path
        base_profile = load_component_profile(json.loads(profile_path.read_text()))
        unsupported_profiles = (
            (replace(base_profile, clocks=(
                base_profile.clocks[0],
                replace(base_profile.clocks[0], port='HCLK_SLOW', domain='slow',
                        frequency_hz=3))), 'non_integral_ratio'),
            (replace(base_profile, resets=(
                replace(base_profile.resets[0], sequence_after=('por_ni',)),)),
             'local-reset-sequence-unsupported'),
        )
        for profile, reason in unsupported_profiles:
            with self.subTest(reason=reason), \
                    patch('myfuzz.local_harness.plan.load_component_profile',
                          return_value=profile), \
                    patch('myfuzz.local_harness.plan.elaborate_profile') as elaborate:
                with self.assertRaisesRegex(ValueError, reason):
                    plan_local_harness(request, base_dir=ROOT)
                elaborate.assert_not_called()

    def test_structural_wrapper_wires_each_clock_and_reset_domain_separately(self):
        plan = real_plan('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_clock_fixture')
        clock = plan.profile.clocks[0]
        reset = replace(plan.profile.resets[0], domain='core')
        clock_fact = plan.facts.port(clock.port)
        reset_fact = plan.facts.port(reset.port)
        self.assertIsNotNone(clock_fact)
        self.assertIsNotNone(reset_fact)
        clock_entry = next(entry for entry in plan.dispositions if entry.role == 'clock')
        reset_entry = next(entry for entry in plan.dispositions if entry.role == 'reset')
        extra_clock = replace(clock, port='HCLK_AON', domain='aon', frequency_hz=200_000)
        extra_reset = replace(reset, port='HRESETn_AON', domain='aon', polarity='active_high')
        extra_clock_fact = replace(clock_fact, name=extra_clock.port)
        extra_reset_fact = replace(reset_fact, name=extra_reset.port)
        fixture_plan = replace(
            plan,
            request=replace(plan.request, reset_assert_ticks=125),
            profile=replace(plan.profile, clocks=(clock, extra_clock),
                            resets=(reset, extra_reset)),
            facts=replace(plan.facts, ports=plan.facts.ports +
                          (extra_clock_fact, extra_reset_fact)),
            dispositions=plan.dispositions + (
                replace(clock_entry, port=extra_clock.port,
                        clock_domain='aon', evidence='test_fixture'),
                replace(reset_entry, port=extra_reset.port,
                        reset_domain='aon', evidence='test_fixture')))

        declarations, statements, connections, _abi = render_port_connections(fixture_plan)

        self.assertIn('input logic clk_aon', declarations)
        self.assertIn('input logic reset_aon', declarations)
        self.assertIn('= clk;', '\n'.join(statements))
        self.assertIn('= clk_aon;', '\n'.join(statements))
        self.assertTrue(any(connection.startswith('.HCLK_AON(dut_p_')
                            for connection in connections))
        self.assertTrue(any(connection.startswith('.HRESETn_AON(dut_p_')
                            for connection in connections))
        self.assertIn('= ~reset;', '\n'.join(statements))
        self.assertIn('= reset_aon;', '\n'.join(statements))

    def test_runtime_exposes_extra_domains_but_adapter_uses_its_declared_domain(self):
        plan = real_plan('configs/peripherals/pulp_gpio/component_profile.json',
                         'gpio_runtime_clock_fixture')
        clock = plan.profile.clocks[0]
        reset = replace(plan.profile.resets[0], domain='core')
        clock_fact = plan.facts.port(clock.port)
        reset_fact = plan.facts.port(reset.port)
        clock_entry = next(entry for entry in plan.dispositions if entry.role == 'clock')
        reset_entry = next(entry for entry in plan.dispositions if entry.role == 'reset')
        extra_clock = replace(clock, port='HCLK_AON', domain='aon', frequency_hz=200_000)
        extra_reset = replace(reset, port='HRESETn_AON', domain='aon', polarity='active_high')
        endpoints = tuple(replace(endpoint, clock='aon', reset='aon')
                          if endpoint.endpoint_id == 'gpio.bus' else endpoint
                          for endpoint in plan.profile.endpoints)
        fixture_plan = replace(
            plan,
            request=replace(plan.request, reset_assert_ticks=125),
            profile=replace(plan.profile, clocks=(clock, extra_clock),
                            resets=(reset, extra_reset), endpoints=endpoints),
            facts=replace(plan.facts, ports=plan.facts.ports + (
                replace(clock_fact, name=extra_clock.port),
                replace(reset_fact, name=extra_reset.port))),
            dispositions=plan.dispositions + (
                replace(clock_entry, port=extra_clock.port,
                        clock_domain='aon', evidence='test_fixture'),
                replace(reset_entry, port=extra_reset.port,
                        reset_domain='aon', evidence='test_fixture')))
        structural = render_local_harness(fixture_plan)

        # This fixture deliberately invents physical pins absent from the pinned
        # GPIO source. Admission is mocked so this test covers only runtime
        # mapping; the real source lock and physical pin set are tested elsewhere.
        with patch('myfuzz.local_harness.runtime_renderer._admit', return_value={}):
            runtime = render_local_runtime(fixture_plan, structural, {}, base_dir=ROOT)

        self.assertEqual(250, runtime.runtime_document['clock_schedule']['clocks'][0]['ratio'])
        self.assertEqual({'clk', 'reset', 'clk_aon', 'reset_aon'}, {
            row['name'] for row in runtime.runtime_document['runtime_ports']
            if row['name'] in {'clk', 'reset', 'clk_aon', 'reset_aon'}})
        self.assertIn('.HCLK_AON(dut_p_', structural.wrapper_sv)
        self.assertIn('.HRESETn_AON(dut_p_', structural.wrapper_sv)
        self.assertIn('= clk_aon;', structural.wrapper_sv)
        self.assertIn('= reset_aon;', structural.wrapper_sv)
        self.assertIn('beat_to_apb #(', runtime.runtime_sv)
        self.assertIn('.clk(clk_aon)', runtime.runtime_sv)
        self.assertIn('.reset(reset_aon)', runtime.runtime_sv)
        self.assertIn('.clk_aon(clk_aon)', runtime.runtime_sv)
        self.assertIn('.reset_aon(reset_aon)', runtime.runtime_sv)

    def test_spi_device_boot_cycles_are_in_runtime_schedule_startup(self):
        plan = real_plan('configs/peripherals/opentitan_spi_device_local/component_profile.json',
                         'spi_device_clock_fixture')
        structural = render_local_harness(plan)
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)

        self.assertEqual('tlul_spi_device', runtime.runtime_document['kind'])
        self.assertEqual(plan.request.reset_assert_ticks + plan.request.reset_release_ticks + 4,
                         runtime.runtime_document['clock_schedule']['startup_fast_ticks'])

    @unittest.skipUnless(shutil.which('verilator') and shutil.which('c++'),
                         'Verilator and C++ are required for the synthetic RTL fixture')
    def test_dual_clock_driver_samples_edges_restarts_and_fresh_replays(self):
        request = load_local_harness_request({
            'schema_version': 'local_harness.v1',
            'profile_path': 'configs/peripherals/pulp_timer/component_profile.json',
            'instance_id': 'dual_clock_fixture', 'reset_assert_ticks': 8,
            'reset_release_ticks': 8, 'max_wait_cycles': 16,
        })
        plan = plan_local_harness(request, base_dir=ROOT)
        structural = render_local_harness(plan)
        source_verification = verify_local_source_lock(plan.profile, base_dir=ROOT)
        top = render_local_runtime(plan, structural, source_verification, base_dir=ROOT)
        document = deepcopy(top.runtime_document)
        schedule = build_local_clock_schedule(
            (ClockBinding('clk_i', 'core', 2_000_000),
             ClockBinding('clk_aon_i', 'aon', 1_000_000)),
            (ResetBinding('rst_ni', 'core', 'active_high', False),
             ResetBinding('rst_aon_ni', 'aon', 'active_high', False)),
            reset_assert_ticks=8, reset_release_ticks=8)
        document['module_name'] = 'local_runtime_dual_clock_fixture'
        document['clock_schedule'] = schedule
        original_export = document['physical_exports'][0]
        irq_export = {**original_export, 'physical_port': 'irq_o',
                      'runtime_name': 'irq_o', 'width': 4, 'hex_digits': 1}
        counter_exports = [
            {'wrapper_name': 'synthetic_core_count', 'physical_port': 'core_count_o',
             'bit_lo': 0, 'bit_hi': 31, 'width': 32, 'direction': 'output',
             'disposition': 'observe', 'endpoint_id': None, 'role': None,
             'runtime_name': 'core_count_o', 'encoding': 'integer', 'hex_digits': 8},
            {'wrapper_name': 'synthetic_aon_count', 'physical_port': 'aon_count_o',
             'bit_lo': 0, 'bit_hi': 31, 'width': 32, 'direction': 'output',
             'disposition': 'observe', 'endpoint_id': None, 'role': None,
             'runtime_name': 'aon_count_o', 'encoding': 'integer', 'hex_digits': 8},
        ]
        document['physical_exports'] = [irq_export, *counter_exports]
        document['runtime_ports'] = [
            {'name': 'clk', 'direction': 'input', 'width': 1},
            {'name': 'reset', 'direction': 'input', 'width': 1},
            {'name': 'clk_aon', 'direction': 'input', 'width': 1},
            {'name': 'reset_aon', 'direction': 'input', 'width': 1},
            *[row for row in document['runtime_ports']
              if row['name'] not in ('clk', 'reset', original_export['runtime_name'])],
            {'name': 'irq_o', 'direction': 'output', 'width': 4},
            {'name': 'core_count_o', 'direction': 'output', 'width': 32},
            {'name': 'aon_count_o', 'direction': 'output', 'width': 32},
        ]
        multi_top = replace(top, runtime_document=document)
        with patch('myfuzz.local_harness.driver_renderer.render_local_runtime',
                   return_value=multi_top):
            driver = render_local_driver(multi_top, base_dir=ROOT)

        # This assertion is intentionally before build/run: it proves that the
        # generated C++ advances the slow clock and reports domain edge counts.
        self.assertIn('dut.clk_aon', driver.cpp_text)
        self.assertIn('"clock_edges"', driver.cpp_text)

        with tempfile.TemporaryDirectory(prefix='myfuzz-dual-clock-') as work:
            directory = Path(work)
            cpp = directory / 'driver.cpp'
            cpp.write_text(driver.cpp_text)
            fixture = Path(__file__).parent / 'fixtures/multiclock_counter.sv'
            argv = [
                shutil.which('verilator'), '--cc', '--exe', '--build', '-j', '1',
                '--top-module', document['module_name'], '--Mdir', str(directory / 'obj'),
                '-CFLAGS', ('-std=c++17 -DMYFUZZ_ARTIFACT_DIGEST=' +
                    driver.runtime_document['artifact_digest'] + ' -I' +
                    str(ROOT / 'src/myfuzz/local_harness/rtl')),
                str(fixture), str(cpp),
            ]
            built = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                   timeout=120, check=False)
            self.assertEqual(0, built.returncode, (built.stdout + built.stderr)[-6000:])
            binary = directory / 'obj' / ('V' + document['module_name'])

            session = GeneratedLocalSession(driver, base_dir=ROOT,
                cache_dir=directory / 'cache', command_timeout_seconds=5)
            with patch('myfuzz.local_harness.session.build_local_harness',
                       return_value=binary):
                session.begin_case('dual-clock-first-run')
                first = [session.command('STEP_TIMER', (0,)) for _ in range(5)]
                self.assertEqual([{'aon': edge, 'core': tick}
                                  for tick, edge in enumerate((1, 1, 2, 2, 3), start=1)],
                                 [result.payload['samples'][0]['clock_edges']
                                  for result in first])
                self.assertEqual({'aon': 1, 'core': 1}, first[0].payload['samples'][0]['clock_edges'])
                self.assertEqual({'aon': 2, 'core': 3}, first[2].payload['samples'][0]['clock_edges'])
                self.assertEqual(13, first[-1].payload['samples'][0]['post']['physical']['core_count_o'])
                self.assertEqual(7, first[-1].payload['samples'][0]['post']['physical']['aon_count_o'])
                session.reset_local()
                replay = [session.command('STEP_TIMER', (0,)) for _ in range(5)]
                self.assertEqual(
                    [[item.payload['samples'] for item in run] for run in (first, replay)][0],
                    [item.payload['samples'] for item in replay])
                session.end_case()


if __name__ == '__main__':
    unittest.main()
