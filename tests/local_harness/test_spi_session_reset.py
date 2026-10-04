"""Generated PULP SPI must discard old tick observations at reset barriers."""
from collections import deque
import unittest
from unittest.mock import Mock, patch

from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.spi_session import GeneratedPulpSpiSession


class SpiResetTests(unittest.TestCase):
    def test_generated_spi_evidence_has_driver_bounds(self):
        from pathlib import Path
        from myfuzz.local_harness import render_local_harness,render_local_runtime,verify_local_source_lock
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.scenario.contracts import ResourceBudget
        from myfuzz.scenario.evidence import _evidence_record_bound,_final_state_growth_bound
        from myfuzz.scenario.genome import ScenarioGenome
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        from tests.local_harness.test_renderer import ROOT,real_plan
        plan=real_plan('configs/peripherals/pulp_spi/local_component_profile.json','spi')
        artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
            verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
        spi=GeneratedPulpSpiSession(artifact,base_dir=ROOT,cache_dir=Path('/tmp/unused-spi'),
            source=b'\xa5\xc3\x96\xf0')
        planned=GeneratedPulpSpiSession(artifact,base_dir=ROOT,
            cache_dir=Path('/tmp/unused-spi'),source=b'\xa5\xc3\x96\xf0',
            startup_writes=((0x04,1),(0x10,0x00200000),(0x00,0x101)),
            read_rx_on_eot=True)
        self.assertEqual(1+4*planned.max_local_ticks_per_register_access,
                         planned.max_local_ticks_per_step)
        runner=ScenarioRunner(sessions={'spi':spi},ownership=compile_ownership((),()),bindings=())
        genome=ScenarioGenome(testcase_id='spi-budget',direction='IP_TO_CPU',
            path_id='spi',schedule_order=('spi',),max_steps=1,actions=())
        self.assertGreater(_final_state_growth_bound(genome,runner,ResourceBudget()),0)
        self.assertGreater(_evidence_record_bound(genome,runner,ResourceBudget()),
            4*artifact.runtime_document['driver_limits']['reply_reservation_bytes'])

    def test_explicit_reset_discards_undelivered_pre_reset_samples(self):
        session = object.__new__(GeneratedPulpSpiSession)
        session.source = b'\xa5'
        session.peer = Mock()
        session._samples = deque(({'local_tick': 17, 'post': {'events_o': 2}},))
        with patch.object(GeneratedLocalSession, 'reset_local', return_value={'cancelled_responses': 0}):
            session.reset_local()
        self.assertEqual([], session.drain_tick_samples())
        session.peer.reset_case.assert_called_once_with(session.source)


if __name__ == '__main__':
    unittest.main()
