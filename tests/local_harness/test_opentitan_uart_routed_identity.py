"""Strict evidence identity for the generated CPU-routed OpenTitan UART."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanUartSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import _verify_generated_session


ROOT = Path(__file__).resolve().parents[2]


class GeneratedOpentitanUartRoutedIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_uart_local/component_profile.json',
            instance_id='uart', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        runtime = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(runtime, base_dir=ROOT)

    def test_cpu_route_requires_genome_source_without_session_setup(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-uart-identity-') as work:
            session = GeneratedOpentitanUartSession(self.artifact, base_dir=ROOT,
                cache_dir=Path(work), source=None, cpu_routed_mode=True)
            identity = session.identity_document()
            self.assertEqual(self.artifact, _verify_generated_session(identity))
            self.assertEqual('generated_tlul_uart_8n1.v4',
                             identity['tlul_uart_service_schema_version'])
            with self.assertRaisesRegex(ValueError, 'unsupported UART register write'):
                session.write_register(0x00, 0x2)
            for key, replacement in (
                    ('source_hex', '5a'),
                    ('startup_writes', [[0x10, 0x80000003, 15]]),
                    ('read_rx_after_source', True),
                    ('cpu_routed_mode', False),
                    ('source_mode', 'constructor')):
                changed = deepcopy(identity)
                changed[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    _verify_generated_session(changed)
            with self.assertRaises(ValueError):
                GeneratedOpentitanUartSession(self.artifact, base_dir=ROOT,
                    cache_dir=Path(work), source=b'\x5a', cpu_routed_mode=True)

    def test_source_provenance_identity_is_authenticated_and_strict(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-uart-provenance-identity-') as work:
            session = GeneratedOpentitanUartSession(self.artifact, base_dir=ROOT,
                cache_dir=Path(work), source=None, cpu_routed_mode=True)
            session.enable_source_provenance()
            identity = session.identity_document()
            self.assertEqual(self.artifact, _verify_generated_session(identity))
            for key, value in (('schema_version', 'wrong'), ('clocks_per_bit', True),
                               ('idle_mark_bits', 16), ('frame_ticks', 321),
                               ('frame_semantics', 'fifo_acceptance'),
                               ('fifo_origin', 'known')):
                changed = deepcopy(identity)
                changed['uart_source_provenance'][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    _verify_generated_session(changed)
            changed = deepcopy(identity)
            changed['uart_source_provenance']['unexpected'] = 1
            with self.assertRaises(ValueError):
                _verify_generated_session(changed)



if __name__ == '__main__':
    unittest.main()
