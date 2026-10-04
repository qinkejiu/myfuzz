"""Real generated PULP SPI mode 0 transfer and replay evidence."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.spi_session import GeneratedPulpSpiSession
from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
EXECUTION = '0123456789abcdef0123456789abcdef'


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedPulpSpiRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-pulp-spi-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/pulp_spi/local_component_profile.json',
            instance_id='spi_a', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_transfer(self, *, read, source, name):
        spi = GeneratedPulpSpiSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, source=source)
        spi.prepare_local()
        spi.begin_case(name)
        self.addCleanup(spi.end_case)
        spi.write_register(0x04, 1)
        spi.write_register(0x10, 0x00200000)
        if not read:
            spi.write_register(0x18, 0xa5c396f0)
        spi.write_register(0x00, 0x101 if read else 0x102)
        for _ in range(140):
            spi.step_local({})
            if any(e['bit'] == 1 and e['level'] == 1 for e in spi.peer.events):
                break
        else:
            self.fail('no native EOT')
        for _ in range(4):
            spi.step_local({})
        self.assertEqual(32, spi.peer.sample_count)
        self.assertEqual(1, sum(e['bit'] == 1 and e['level'] == 1
                                for e in spi.peer.events))
        value = spi.read_register(0x20) if read else None
        trace = spi.drain_tick_samples()
        return spi, value, trace

    def test_tx_rx_and_whole_case_replay(self):
        tx, _, tx_trace = self.run_transfer(read=False, source=b'\x00' * 4, name='tx')
        self.assertEqual((bytes.fromhex('a5c396f0'),), tx.peer.completed_frames)
        self.assertTrue(any(item['post']['events_o'] & 2 for item in tx_trace))
        first, word, trace = self.run_transfer(
            read=True, source=bytes.fromhex('a5c396f0'), name='rx-a')
        self.assertEqual(0xa5c396f0, word)
        self.assertEqual((b'\x00' * 4,), first.peer.completed_frames)
        self.assertEqual(4, first.peer.payload_index)
        second, replayed, second_trace = self.run_transfer(
            read=True, source=bytes.fromhex('a5c396f0'), name='rx-b')
        self.assertEqual(word, replayed)
        self.assertEqual(trace, second_trace)
        with self.assertRaisesRegex(ValueError, 'full-word'):
            second.write_register(0x18, 0, be=1)

    def test_same_command_receipt_is_cached_without_second_fifo_push(self):
        binary = build_local_harness(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        def command(sequence, op, *fields):
            return f'CMD {EXECUTION} {sequence:x} {op} ' + ' '.join(f'{x:x}' for x in fields)
        push = command(2, 'ACCESS_SPI', 1, 0x18, 0xa5c396f0, 15)
        lines = [command(1, 'SOURCE_SPI', 0, 0, 32), push, push,
                 command(3, 'ACCESS_SPI', 0, 0, 0, 15), 'END']
        run = subprocess.run([str(binary)], cwd=ROOT, input='\n'.join(lines) + '\n',
                             text=True, capture_output=True, timeout=10)
        self.assertEqual(0, run.returncode, run.stderr)
        replies = run.stdout.splitlines()
        self.assertEqual(replies[2], replies[3])
        self.assertTrue(replies[4].startswith('RESULT '))

    def test_scenario_manifest_and_formal_evidence_replay(self):
        def factory_for(source):
            def factory():
                spi = GeneratedPulpSpiSession(self.artifact, base_dir=ROOT,
                    cache_dir=self.cache, source=source,
                    startup_writes=((0x04, 1), (0x10, 0x00200000), (0x00, 0x101)),
                    read_rx_on_eot=True)
                return ScenarioRunner(sessions={'spi': spi},
                    ownership=compile_ownership((), ()), bindings=())
            return factory

        factory = factory_for(bytes.fromhex('a5c396f0'))
        identity = factory().identity_document()
        doc = self.artifact.runtime_document
        timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=doc['artifact_digest'], driver_sha256=doc['cpp_sha256'],
            hold_cycles=8, release_cycles=8)
        manifest = ScenarioManifest.from_runner_identity(identity,
            scenario_id='generated-spi-mode0', schedule_order=('spi',),
            scheduler_policy_id='stable-local-v1', budget=ResourceBudget(),
            reset_timings={'spi': timing})
        from copy import deepcopy
        mismatched = deepcopy(identity)
        mismatched['sessions']['spi']['type'] = (
            'myfuzz.local_harness.gpio_session.GeneratedPulpGpioSession')
        with self.assertRaisesRegex(ValueError, 'artifact kind'):
            ScenarioManifest.from_runner_identity(mismatched,
                scenario_id='generated-spi-mode0', schedule_order=('spi',),
                scheduler_policy_id='stable-local-v1', budget=ResourceBudget(),
                reset_timings={'spi': timing})
        import json
        import jsonschema
        schema = json.loads((ROOT / 'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema = json.loads((ROOT / 'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget'] = budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs', {}))
        jsonschema.Draft202012Validator(schema).validate(manifest.to_document())

        genome = ScenarioGenome(testcase_id='generated-spi-rx', direction='IP_TO_CPU',
            path_id='standalone-spi', schedule_order=('spi',), max_steps=132, actions=())
        budget = ResourceBudget(max_wall_time_ms=180000)
        bundle = Path(self.temp.name) / 'formal-spi-evidence'
        trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
        self.assertEqual('complete', trace.status)
        self.assertTrue(any(event.get('outputs', {}).get('spi_rx_word') == 0xa5c396f0
                            for event in trace.events))
        self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                            and event.get('outputs', {}).get('events_o', 0) & 2
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)

        mutated = factory_for(bytes.fromhex('a5c396f1'))
        changed = save_evidence_bundle(genome, mutated,
            Path(self.temp.name) / 'formal-spi-mutated', budget=budget)
        self.assertNotEqual(trace.semantic_sha256, changed.semantic_sha256)
        self.assertTrue(any(event.get('outputs', {}).get('spi_rx_word') == 0xa5c396f1
                            for event in changed.events))
