"""One declarative TL-UL register template exercised by two pinned real IPs."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedTlulRegisterSession, load_local_harness_request,
    compile_generated_register_ownership,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


def request(kind, *, constants=()):
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path=f'configs/peripherals/opentitan_{kind}_local/component_profile.json',
        instance_id='generic_' + kind, reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id=f'opentitan_{kind}.mmio', template_id='target.tl-ul',
            template_version='1', variant_id='user-integrity', max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id=endpoint, role=role, value=value)
                                 for endpoint, role, value in constants]},
    ))


def artifact(req):
    plan = plan_local_harness(req, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class GenericTlulContractTests(unittest.TestCase):
    def test_profile_only_requests_use_identical_generic_kind_and_preserve_tuning_identity(self):
        timer = artifact(request('rv_timer'))
        gpio = artifact(request('gpio', constants=(('gpio.pins', 'in', 0),
                                                   ('gpio.pins', 'strap_en', 0))))
        self.assertEqual('tlul_register_observe', timer.runtime_document['kind'])
        self.assertEqual(timer.runtime_document['kind'], gpio.runtime_document['kind'])
        self.assertEqual([], timer.runtime_document['fixed_physical_inputs'])
        self.assertEqual({'in', 'strap_en'},
                         {row['role'] for row in gpio.runtime_document['fixed_physical_inputs']})
        self.assertNotEqual(timer.runtime_document['artifact_digest'],
                            gpio.runtime_document['artifact_digest'])
        self.assertEqual('tlul_register_only_pin_observe_no_serial',
                         timer.runtime_document['functional_scope'])

    def test_unowned_or_out_of_width_external_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(request('gpio'))
        with self.assertRaisesRegex(ValueError, 'constant-width'):
            artifact(request('gpio', constants=(('gpio.pins', 'in', 1 << 32),
                                                 ('gpio.pins', 'strap_en', 0))))

    def test_spi_device_requires_all_four_fixed_external_inputs(self):
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(request('spi_device', constants=(('spi_device.pins', 'csb_i', 1),)))
        spi = artifact(request('spi_device', constants=(
            ('spi_device.pins', 'sck_i', 0),
            ('spi_device.pins', 'csb_i', 1),
            ('spi_device.pins', 'tpm_csb_i', 1),
            ('spi_device.pins', 'sd_i', 0))))
        self.assertEqual('tlul_register_observe', spi.runtime_document['kind'])
        self.assertEqual('tlul_register_only_pin_observe_no_serial',
                         spi.runtime_document['functional_scope'])
        self.assertEqual({'sck_i', 'csb_i', 'tpm_csb_i', 'sd_i'},
                         {row['role'] for row in spi.runtime_document['fixed_physical_inputs']})


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulRealTests(unittest.TestCase):
    def test_spi_device_profile_only_registers_and_fresh_replay(self):
        constants = (('spi_device.pins', 'sck_i', 0),
                     ('spi_device.pins', 'csb_i', 1),
                     ('spi_device.pins', 'tpm_csb_i', 1),
                     ('spi_device.pins', 'sd_i', 0))
        generated = artifact(request('spi_device', constants=constants))
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-tlul-spi-device-') as directory:
            work = Path(directory)
            sessions = []

            def factory():
                session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    setup_writes=((0x10, 1 << 4), (0x30, 0x00A11234)),
                    probe_offsets=(0x30,))
                sessions.append(session)
                return ScenarioRunner(sessions={'dut': session},
                    ownership=compile_generated_register_ownership({'dut': generated}),
                    bindings=())

            genome = ScenarioGenome(testcase_id='generic-spi-device-registers',
                direction='IP_TO_IP', path_id='tlul-register-observe',
                schedule_order=('dut',), max_steps=8, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertEqual(0x00A11234,
                             sessions[0].local_transactions[-1]['read_value'])
            self.assertTrue(any(event.get('outputs', {}).get('sd_en_o') == 0
                                and event.get('outputs', {}).get('irq_o') == 0
                                for event in trace.events))
            self.assertEqual(3, len(sessions[0].local_transactions))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(sessions[0], sessions[1])

    def test_timer_and_gpio_real_registers_and_fresh_replay(self):
        cases = (
            ('rv_timer', (), ((0x118, 5), (0x11c, 0), (0x100, 1), (0x004, 1)),
             (0x100,), 'intr_timer_expired_hart0_timer0_o', 1),
            ('gpio', (('gpio.pins', 'in', 0), ('gpio.pins', 'strap_en', 0)),
             ((0x14, 0xa5), (0x20, 0xff)), (0x14,), 'cio_gpio_o', 0xa5),
        )
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-tlul-') as directory:
            work = Path(directory)
            for kind, constants, writes, probes, observed, expected in cases:
                with self.subTest(kind=kind):
                    generated = artifact(request(kind, constants=constants))
                    sessions = []

                    def factory():
                        session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                            cache_dir=work / kind, setup_writes=writes,
                            probe_offsets=probes)
                        sessions.append(session)
                        return ScenarioRunner(sessions={'dut': session},
                            ownership=compile_generated_register_ownership({'dut': generated}),
                            bindings=())

                    genome = ScenarioGenome(testcase_id='generic-' + kind,
                        direction='IP_TO_IP', path_id='tlul-register-observe',
                        schedule_order=('dut',), max_steps=12, actions=())
                    bundle = work / ('evidence-' + kind)
                    trace = save_evidence_bundle(genome, factory, bundle, budget=None)
                    self.assertEqual('complete', trace.status, trace.events[-3:])
                    self.assertTrue(any(event.get('outputs', {}).get(observed) == expected
                                        for event in trace.events))
                    self.assertEqual(len(writes) + len(probes), len(sessions[0].local_transactions))
                    self.assertGreater(sessions[0].local_ticks, 12)
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
