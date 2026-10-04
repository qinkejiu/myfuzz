"""The generated Ibex/PULP RFuzz bridge mutates only CPU program bytes."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.ibex_pulp_rfuzz import make_ibex_pulp_rfuzz_bundle
from myfuzz.scenario.replay import ScenarioTrace
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import genome
from tests.scenario.test_pulp_gpio_irq_chain_checker import _events


def flip(bit_index):
    return bytes((0, 0, 0, bit_index, 0, 1, 0, 0))


class IbexPulpRfuzzBundleTests(unittest.TestCase):
    def test_program_high_bits_are_only_fuzzable_source_and_select_output_49(self):
        seed = genome(1)
        decoder, targets, checker = make_ibex_pulp_rfuzz_bundle(seed, genome(0xff))
        self.assertTrue(decoder.trusted_for_search)
        self.assertEqual(('cpu.program.output_high_bits',), tuple(decoder.graph.sources))
        self.assertEqual(('cpu.b_padin_response_bit3',), tuple(target.target_id for target in targets))
        self.assertNotIn('gpio_b.gpio_in', decoder.graph.sources)
        self.assertNotIn('cpu.irq', decoder.graph.sources)
        source = decoder.graph.sources['cpu.program.output_high_bits']
        self.assertEqual((565, 7), (source.bit_offset, source.width))
        changed = decoder.decode((flip(2), flip(5)))
        boot = next(image for image in changed.initial_images if image.image_id == 'boot')
        instruction = int.from_bytes(bytes.fromhex(boot.data_hex)[68:72], 'little')
        self.assertEqual(0x49, (instruction >> 20) & 0xfff)
        maximum = decoder.decode(tuple(flip(index) for index in range(7)))
        max_boot = next(image for image in maximum.initial_images if image.image_id == 'boot')
        self.assertEqual(0xff, int.from_bytes(max_boot.data[68:72], 'little') >> 20)
        self.assertEqual((), checker(ScenarioTrace('g', 'complete', tuple(_events()),
                                                   {}, 's', 'm')))

    def test_unreviewed_seed_cannot_be_used_for_trusted_search(self):
        with self.assertRaisesRegex(ValueError, 'pinned search program'):
            make_ibex_pulp_rfuzz_bundle(genome(3), genome(0xff))
        with self.assertRaisesRegex(ValueError, 'pinned search program'):
            make_ibex_pulp_rfuzz_bundle(genome(1), genome(0x7f))

    def test_seeded_trace_fault_checker_violation_is_saved_to_corpus(self):
        seed = genome(1)
        decoder, targets, checker = make_ibex_pulp_rfuzz_bundle(seed, genome(0xff))
        events = [dict(event) for event in _events()]
        for event in events:
            if event.get('kind') == 'mmio_delivery' and event.get('device_id') == 'gpio_b' \
                    and event.get('offset') == 8 and event.get('write') is False:
                event['read_value'] = 0  # seeded trace fault, never claimed as RTL output
                break
        else:
            self.fail('synthetic checker fixture lacks B PADIN read')
        trace = ScenarioTrace('g', 'complete', tuple(events), {'cpu': 1}, 's', 'm')
        self.assertIn('gpio_b_padin_read_mismatch', checker(trace))
        with tempfile.TemporaryDirectory() as directory:
            executor = ScenarioRfuzzExecutor(
                run_id='seeded-checker-error', decoder=decoder,
                factory=lambda: None, targets=targets, checker=checker,
                evidence_dir=Path(directory))
            with patch('myfuzz.integration.scenario_rfuzz.record_scenario',
                       return_value=trace):
                executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
            receipt = executor.receipts[0]
            self.assertEqual('dut_violation', receipt.status)
            self.assertIn('gpio_b_padin_read_mismatch', receipt.violations)
            corpus = list(Path(directory).glob('dut_violation_*.json'))
            self.assertEqual(1, len(corpus))
            document = json.loads(corpus[0].read_text())
            self.assertEqual('00' * 8, document['raw_records_hex'][0])
            self.assertEqual(list(receipt.violations), document['violations'])


if __name__ == '__main__':
    unittest.main()
