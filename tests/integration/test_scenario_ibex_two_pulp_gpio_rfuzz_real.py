"""RFuzz byte mutation reaches the generated Ibex/PULP/PULP/ISR chain."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.ibex_pulp_rfuzz import make_ibex_pulp_rfuzz_bundle
from myfuzz.scenario.replay import record_scenario, replay_scenario
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import (
    genome, make_factory)


FLIP_OUTPUT_BIT = bytes((0, 0, 0, 0, 0, 1, 0, 0))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedIbexPulpRfuzzRealTests(unittest.TestCase):
    def test_cpu_program_mutation_propagates_through_two_real_gpio_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pulp-rfuzz-') as directory:
            work = Path(directory)
            factory, _ = make_factory(Path(os.environ.get(
                'MYFUZZ_IBEX_GPIO_CACHE', work / 'cache')))
            decoder, targets, checker = make_ibex_pulp_rfuzz_bundle(genome(1))
            executor = ScenarioRfuzzExecutor(
                run_id='generated-ibex-two-pulp-gpio', decoder=decoder,
                factory=factory, targets=targets, checker=checker,
                evidence_dir=work / 'failures')
            batch = InputBatch(1, 8, ((bytes(8),), (FLIP_OUTPUT_BIT,)))
            self.assertEqual((b'\x00', b'\x01'), executor.execute_batch(batch))
            self.assertEqual(('complete', 'complete'),
                             tuple(receipt.status for receipt in executor.receipts))
            self.assertEqual(((), ('cpu.program.output_bit1',)),
                             tuple(receipt.applied_source_ids
                                   for receipt in executor.receipts))
            self.assertEqual((), tuple((work / 'failures').glob('*.json')))
            changed = decoder.decode((FLIP_OUTPUT_BIT,))
            trace = record_scenario(changed, factory)
            self.assertEqual('complete', trace.status)
            self.assertEqual((), checker(trace))
            self.assertTrue(any(event.get('kind') == 'mmio_delivery'
                                and event.get('device_id') == 'gpio_a'
                                and event.get('offset') == 0x0c
                                and event.get('write_value') == 3
                                for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                and event.get('source') == ('gpio_a', 'gpio_out')
                                and event.get('target') == ('gpio_b', 'gpio_in')
                                and event.get('value') == 3
                                for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'memory_write'
                                and event.get('component') == 'cpu'
                                and event.get('address') == 0x20000
                                and event.get('value') == 3
                                for event in trace.events))
            compared = replay_scenario(changed, factory, trace)
            self.assertTrue(compared.matches, compared)


if __name__ == '__main__':
    unittest.main()
