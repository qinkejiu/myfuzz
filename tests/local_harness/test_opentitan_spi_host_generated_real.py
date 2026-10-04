"""Pinned generated OpenTitan SPI Host TL-UL register path and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSpiHostSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_spi_host_local/component_profile.json'


def _artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=PROFILE, instance_id='spi_host', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,
        render_local_harness(plan), verify_local_source_lock(plan.profile,
            base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanSpiHostRealTests(unittest.TestCase):
    def test_real_tlul_registers_and_pad_observations_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-spi-host-generated-') as directory:
            work = Path(directory)
            artifact = _artifact()
            self.assertEqual('tlul_spi_host', artifact.runtime_document['kind'])
            self.assertEqual('all', artifact.plan.facts.selection)
            self.assertEqual(29, len(artifact.plan.facts.ports))
            self.assertEqual(7, len(artifact.runtime_document['physical_exports']))
            sessions = []

            def factory():
                session = GeneratedOpentitanSpiHostSession(artifact, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    setup_writes=((0x10, 0x80000001), (0x18, 8)),
                    probe_offsets=(0x10, 0x14, 0x18))
                sessions.append(session)
                return ScenarioRunner(sessions={'spi_host': session},
                    ownership=compile_ownership((), ()), bindings=())

            genome = ScenarioGenome(testcase_id='ot-spi-host-generated-registers',
                direction='IP_TO_CPU', path_id='tlul-registers-to-real-state',
                schedule_order=('spi_host',), max_steps=12, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000, max_transactions=5))
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertEqual(0x80000001, next(event['outputs']['reg_10']
                for event in trace.events if event.get('component') == 'spi_host'
                and 'outputs' in event and 'reg_10' in event['outputs']))
            self.assertTrue(any(event.get('kind') == 'local_register_transaction'
                                and event.get('offset') == 0x14 and not event['write']
                                and event['read_value'] & (1 << 28)
                                for event in trace.events))
            self.assertEqual(5, sum(event.get('kind') == 'local_register_transaction'
                                    for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                and event.get('component') == 'spi_host'
                                and 'sck' in event.get('outputs', {})
                                for event in trace.events))
            self.assertEqual(0, sessions[0].peer.sample_count)
            self.assertGreater(sessions[0].local_ticks, 12)
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertEqual(0, sessions[1].peer.sample_count)


if __name__ == '__main__':
    unittest.main()
