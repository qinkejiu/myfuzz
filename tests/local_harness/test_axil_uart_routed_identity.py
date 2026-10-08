"""Strict evidence identity for CPU-routed ZipCPU AXI-Lite UART RX."""
from copy import deepcopy
import inspect
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request,
    plan_local_harness, render_local_harness, render_local_runtime,
    verify_local_source_lock)
from myfuzz.local_harness.axil_uart_session import GeneratedAxiLiteUartSession
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import _verify_generated_session


ROOT = Path(__file__).resolve().parents[2]


class GeneratedAxiLiteUartRoutedIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/zipcpu_axiluart/component_profile.json',
            instance_id='uart', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        runtime = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(runtime, base_dir=ROOT)

    def test_cpu_route_requires_genome_source_and_cpu_owned_rx_read(self):
        self.assertIn('cpu_routed_mode', inspect.signature(
            GeneratedAxiLiteUartSession).parameters)
        with tempfile.TemporaryDirectory(prefix='myfuzz-axil-uart-routed-') as work:
            session = GeneratedAxiLiteUartSession(self.artifact, base_dir=ROOT,
                cache_dir=Path(work), source=None, cpu_routed_mode=True)
            identity = session.identity_document()
            self.assertEqual(self.artifact,
                             _verify_generated_session(identity))
            self.assertEqual('generated_axil_uart_8n1.v3',
                identity['axil_uart_service_schema_version'])
            self.assertTrue(identity['cpu_routed_mode'])
            self.assertEqual('', identity['source_hex'])
            self.assertEqual([], identity['startup_writes'])
            self.assertFalse(identity['read_rx_after_source'])

            for key, replacement in (
                    ('source_hex', '5a'),
                    ('startup_writes', [[0, 25, 15]]),
                    ('read_rx_after_source', True),
                    ('cpu_routed_mode', False),
                    ('source_mode', 'constructor')):
                changed = deepcopy(identity)
                changed[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    _verify_generated_session(changed)

            with self.assertRaises(ValueError):
                GeneratedAxiLiteUartSession(self.artifact, base_dir=ROOT,
                    cache_dir=Path(work), source=b'Z', cpu_routed_mode=True)


if __name__ == '__main__':
    unittest.main()
