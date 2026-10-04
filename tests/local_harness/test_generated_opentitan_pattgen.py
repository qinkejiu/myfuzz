"""Pinned pattgen through the shared generated TL-UL register executor."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (GeneratedTlulRegisterSession,
    compile_generated_register_ownership, verify_local_source_lock)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact, request


PROFILE = 'configs/peripherals/opentitan_pattgen_local/component_profile.json'


class PattgenContractTests(unittest.TestCase):
    def test_new_profile_authenticates_closure_and_observes_every_output(self):
        self.assertTrue((ROOT / PROFILE).is_file(), 'pinned pattgen profile is missing')
        generated = artifact(request('pattgen'))
        self.assertEqual('tlul_register_observe', generated.runtime_document['kind'])
        self.assertEqual([], generated.runtime_document['fixed_physical_inputs'])
        names = {row['physical_port'] for row in generated.runtime_document['physical_exports']}
        self.assertTrue({'cio_pda0_tx_o', 'cio_pcl0_tx_o', 'cio_pda1_tx_o',
            'cio_pcl1_tx_o', 'intr_done_ch0_o', 'intr_done_ch1_o', 'alert_tx_o'} <= names)
        verified = verify_local_source_lock(generated.plan.profile, base_dir=ROOT)
        self.assertEqual('elaboration_verified', verified['elaboration_status'])
        self.assertEqual('source_verified', verified['source_status'])
        self.assertTrue(verified['closure_record']['elaboration']['evidence'].startswith(
            'configs/peripherals/opentitan_pattgen_local/'))

    def test_source_contract_rejects_altered_profile(self):
        self.assertTrue((ROOT / PROFILE).is_file(), 'pinned pattgen profile is missing')
        document = json.loads((ROOT / PROFILE).read_bytes())
        document['address']['registers'][0]['offset'] = 0x34
        with self.assertRaisesRegex(ValueError, 'profile-object-mismatch'):
            verify_local_source_lock(load_component_profile(document), base_dir=ROOT)

    def test_source_contract_rejects_changed_rtl_and_added_include(self):
        profile = load_component_profile(json.loads((ROOT / PROFILE).read_bytes()))
        evidence_path = 'configs/peripherals/opentitan_pattgen_local/closure.json'
        evidence = json.loads((ROOT / evidence_path).read_bytes())
        names = [row['path'] for row in evidence['closure_files']]
        names += [PROFILE, evidence_path, evidence['log_path'], 'configs/soc/sources.lock.json']
        with tempfile.TemporaryDirectory(prefix='myfuzz-pattgen-source-') as directory:
            work = Path(directory)
            for name in names:
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, work / name)
            verify_local_source_lock(profile, base_dir=work)
            wrapper = work / 'configs/peripherals/opentitan_pattgen_local/soc_opentitan_pattgen_local_target.sv'
            wrapper.write_bytes(wrapper.read_bytes() + b'\n// changed fixture\n')
            with self.assertRaisesRegex(ValueError, 'source-changed'):
                verify_local_source_lock(profile, base_dir=work)
            shutil.copyfile(ROOT / wrapper.relative_to(work), wrapper)
            extra = work / profile.source_document['include_roots'][0] / 'unexpected.svh'
            extra.write_text('// unexpected include fixture\n')
            with self.assertRaisesRegex(ValueError, 'union-changed'):
                verify_local_source_lock(profile, base_dir=work)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class PattgenRealTests(unittest.TestCase):
    def test_dual_channel_serial_bits_dividers_completion_irq_and_fresh_replay(self):
        self.assertTrue((ROOT / PROFILE).is_file(), 'pinned pattgen profile is missing')
        generated = artifact(request('pattgen'))
        size = 7 | (1 << 6) | (4 << 16)
        writes = ((0x10, 0), (0x04, 3), (0x14, 1), (0x18, 2),
                  (0x1c, 0xa5), (0x20, 0), (0x24, 0x16), (0x28, 0),
                  (0x2c, size), (0x10, 3))
        with tempfile.TemporaryDirectory(prefix='myfuzz-pattgen-') as directory:
            work = Path(directory)
            sessions = []

            def factory():
                session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                    cache_dir=work / 'cache', setup_writes=writes,
                    probe_offsets=(0x1c, 0x24, 0x2c))
                sessions.append(session)
                return ScenarioRunner(sessions={'dut': session},
                    ownership=compile_generated_register_ownership({'dut': generated}),
                    bindings=())

            genome = ScenarioGenome(testcase_id='pattgen-dual-channel-real',
                direction='IP_TO_IP', path_id='tlul-to-pattern-output',
                schedule_order=('dut',), max_steps=100, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            samples = [event for event in trace.events
                       if event.get('kind') == 'local_tick_sample' and event['phase'] == 'post']
            for channel, pattern, length, repeats, period in (
                    (0, 0xa5, 8, 2, 4), (1, 0x16, 5, 1, 6)):
                clock, data = f'cio_pcl{channel}_tx_o', f'cio_pda{channel}_tx_o'
                previous = 0
                edges = []
                for sample in samples:
                    outputs = sample['outputs']
                    if outputs[clock] and not previous:
                        edges.append((sample['local_tick'], outputs[data]))
                    previous = outputs[clock]
                self.assertEqual([(pattern >> bit) & 1 for _ in range(repeats)
                                  for bit in range(length)], [value for _, value in edges])
                self.assertEqual({period}, {b[0] - a[0] for a, b in zip(edges, edges[1:])})
                self.assertEqual(1, samples[-1]['outputs'][f'intr_done_ch{channel}_o'])
                self.assertEqual(0, samples[-1]['outputs'][clock])
                self.assertEqual(0, samples[-1]['outputs'][data])
            self.assertEqual([0xa5, 0x16, size],
                [row['read_value'] for row in sessions[0].local_transactions if not row['write']])
            self.assertTrue(all(sample['outputs'][f'cio_p{pin}{channel}_tx_en_o'] == 1
                for sample in samples for channel in (0, 1) for pin in ('da', 'cl')))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
