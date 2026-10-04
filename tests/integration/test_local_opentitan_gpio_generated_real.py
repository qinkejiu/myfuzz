"""Pinned OpenTitan GPIO through generated TL-UL and fresh formal replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanGpioSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanGpioRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-ot-gpio-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_gpio_local/component_profile.json',
            instance_id='gpio_ot', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 30
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name, *, startup_writes=()):
        session = GeneratedOpentitanGpioSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, startup_writes=startup_writes)
        session.prepare_local()
        session.begin_case(name)
        self.addCleanup(session.end_case)
        return session

    def test_real_tlul_registers_pads_and_irq(self):
        gpio = self.session('real-gpio')
        gpio.write_register(0x14, 0xa5)
        self.assertEqual(0xa5, gpio.read_register(0x14))
        with self.assertRaisesRegex(RuntimeError, 'TL-UL write error'):
            gpio.write_register(0x14, 0xff00, be=0b0010)
        self.assertEqual(0xa5, gpio.read_register(0x14))
        gpio.write_register(0x20, 0xff)
        observed = gpio.step_local({})
        self.assertEqual((0xa5, 0xff), (observed['gpio_out'], observed['gpio_dir']))
        self.assertEqual(1, observed['alert_tx_o'])  # quiet differential alert default
        self.assertEqual(0, observed['racl_error_o'])
        gpio.write_register(0x04, 1)  # INTR_ENABLE[0]
        gpio.write_register(0x2c, 1)  # INTR_CTRL_EN_RISING[0]
        self.assertEqual(0, gpio.step_local({'gpio_in': 0})['irq'])
        levels = [gpio.step_local({'gpio_in': 1})['irq'] for _ in range(8)]
        self.assertEqual(1, levels[-1] & 1)
        self.assertEqual(1, gpio.read_register(0x00) & 1)
        gpio.write_register(0x00, 1)  # W1C
        self.assertEqual(0, gpio.step_local({})['irq'] & 1)
        gpio.write_register(0x0c, 1, be=0b0001)  # ALERT_TEST permits lane 0
        self.assertEqual(2, gpio.step_local({})['alert_tx_o'])
        self.assertTrue(any(sample['post']['interrupt'] & 1
                            for sample in gpio.drain_tick_samples()))

    def test_scenario_manifest_saved_evidence_and_fresh_replay(self):
        ownership = compile_ownership(
            (InputField('gpio', 'gpio_in', 32), InputField('gpio', 'strap_en', 1)),
            (InputOwner('gpio', 'gpio_in', 0, 32, 'source', 'external'),
             InputOwner('gpio', 'strap_en', 0, 1, 'source', 'external')))
        def factory():
            gpio = GeneratedOpentitanGpioSession(self.artifact, base_dir=ROOT,
                cache_dir=self.cache, startup_writes=((0x04, 1), (0x2c, 1)))
            return ScenarioRunner(sessions={'gpio': gpio}, ownership=ownership, bindings=())

        identity = factory().identity_document()
        doc = self.artifact.runtime_document
        timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=doc['artifact_digest'], driver_sha256=doc['cpp_sha256'],
            hold_cycles=2, release_cycles=2)
        manifest = ScenarioManifest.from_runner_identity(identity,
            scenario_id='generated-opentitan-tlul-gpio', schedule_order=('gpio',),
            scheduler_policy_id='stable-local-v1', budget=ResourceBudget(),
            reset_timings={'gpio': timing})
        self.assertEqual('scenario_runtime_manifest.v1', manifest.to_document()['schema_version'])
        import json
        import jsonschema
        schema = json.loads((ROOT / 'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema = json.loads((ROOT / 'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget'] = budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs', {}))
        jsonschema.Draft202012Validator(schema).validate(manifest.to_document())
        genome = ScenarioGenome(testcase_id='ot-gpio-rising', direction='IP_TO_IP',
            path_id='standalone-tlul-gpio', schedule_order=('gpio',), max_steps=10,
            actions=(Action('rise', 'gpio', 'gpio_in', 1, 'IP_TO_IP', Trigger('START')),
                     Action('strap', 'gpio', 'strap_en', 1, 'IP_TO_IP', Trigger('START'))))
        bundle = Path(self.temp.name) / 'formal-tlul-gpio-evidence'
        trace = save_evidence_bundle(genome, factory, bundle, budget=None)
        self.assertEqual('complete', trace.status)
        self.assertTrue(any(event.get('outputs', {}).get('irq', 0) & 1
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
