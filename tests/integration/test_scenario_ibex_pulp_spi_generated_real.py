"""Generated Ibex OBI drives real PULP SPI APB3 and consumes its RX FIFO."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.spi_session import GeneratedPulpSpiSession
from myfuzz.scenario.checker import check_pulp_spi_rx_chain
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from tests.integration.test_scenario_cve2_pulp_spi_real import _artifact, _program


ROOT = Path(__file__).resolve().parents[2]
SPI_BASE = 0x40000000
RESULT = 0x20000
SOURCE_WORD = 0xA5C396F0


def genome(source_word: int = SOURCE_WORD) -> ScenarioGenome:
    if type(source_word) is not int or not 0 <= source_word <= 0xFFFFFFFF:
        raise ValueError('SPI source word must fit 32 bits')
    return ScenarioGenome(
        testcase_id=f'generated-ibex-pulp-spi-rx-{source_word:08x}',
        direction='CPU_TO_IP_TO_CPU', path_id='ibex-spi-rxfifo-ram',
        schedule_order=('cpu', 'spi'), max_steps=500, actions=(),
        initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10080, _program()),
                        MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))


def make_factory(cache_dir: Path, source_word: int):
    cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json', 'cpu')
    spi_artifact = _artifact('configs/peripherals/pulp_spi/local_component_profile.json', 'spi')
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=37, max_initialized_bytes=0x20000)
        spi = GeneratedPulpSpiSession(spi_artifact, base_dir=ROOT,
            cache_dir=cache_dir, source=source_word.to_bytes(4, 'big'))
        router = DataflowRouter((DeviceWindow('spi', SPI_BASE, 0x1000, spi),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1),),
            (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'spi': spi},
            ownership=ownership, bindings=())
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedIbexPulpSpiRealTests(unittest.TestCase):
    def test_cpu_configures_spi_and_real_rx_word_reaches_cpu_ram_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pulp-spi-') as directory:
            factory, instances = make_factory(Path(directory) / 'cache', SOURCE_WORD)
            case = genome()
            trace = record_scenario(case, factory)
            self.assertEqual('complete', trace.status)
            events = trace.events
            writes = [e for e in events if e.get('kind') == 'mmio_delivery'
                      and e.get('device_id') == 'spi' and e.get('write')]
            self.assertEqual([(4, 1), (0x10, 0x00200000), (0, 0x101)],
                [(e['offset'], e['write_value']) for e in writes])
            reads = [e for e in events if e.get('kind') == 'mmio_delivery'
                     and e.get('device_id') == 'spi' and not e.get('write')]
            self.assertTrue(any(e['offset'] == 0x20 and e['read_value'] == SOURCE_WORD
                                for e in reads))
            self.assertTrue(any(e.get('kind') == 'local_tick_sample'
                                and e.get('component') == 'spi'
                                and e.get('outputs', {}).get('events_o', 0) & 2
                                for e in events))
            self.assertEqual(32, instances[0].sessions['spi'].peer.sample_count)
            self.assertEqual(4, instances[0].sessions['spi'].peer.payload_index)
            self.assertEqual(SOURCE_WORD, instances[0].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='acceptance').value)
            self.assertTrue(any(e.get('kind') == 'memory_write'
                                and e.get('address') == RESULT
                                and e.get('value') == SOURCE_WORD for e in events))
            self.assertTrue(check_pulp_spi_rx_chain(
                events, expected_word=SOURCE_WORD)['complete'])
            self.assertFalse(any(e.get('kind') == 'reset_barrier' for e in events))
            self.assertTrue(replay_scenario(case, factory, trace).matches)
            self.assertEqual(SOURCE_WORD, instances[1].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='replay').value)
            changed_word = SOURCE_WORD ^ 1
            changed_factory, changed_instances = make_factory(
                Path(directory) / 'cache', changed_word)
            changed_trace = record_scenario(genome(changed_word), changed_factory)
            self.assertEqual('complete', changed_trace.status)
            self.assertTrue(check_pulp_spi_rx_chain(
                changed_trace.events, expected_word=changed_word)['complete'])
            self.assertNotEqual(trace.semantic_sha256, changed_trace.semantic_sha256)
            self.assertEqual(changed_word, changed_instances[0].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='changed-source').value)


if __name__ == '__main__':
    unittest.main()
