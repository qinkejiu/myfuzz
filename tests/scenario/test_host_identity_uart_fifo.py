"""Keep historical v1 paths immutable while authenticating generated UART semantics."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
from myfuzz.scenario import host_identity

UART_PATHS={
 'src/myfuzz/scenario/uart_consumption.py',
 'src/myfuzz/local_harness/opentitan_uart_fifo_contract.py',
 'src/myfuzz/local_harness/opentitan_uart_session.py',
 'src/myfuzz/scenario/ibex_uart_online.py',
 'src/myfuzz/scenario/ibex_uart_online_checker.py',
 'src/myfuzz/integration/ibex_uart_online.py',
 'scripts/run_ibex_uart_online.py',
}

class HostIdentityUartFifoTests(unittest.TestCase):
    def test_legacy34_paths_remain_unchanged_and_ignore_new_observer(self):
        legacy=host_identity.host_source_identity()
        self.assertEqual(len(legacy['files']),34)
        self.assertEqual(legacy['schema_version'],'scenario_host_sources.v1')
        original=host_identity._hash_file
        with patch.object(host_identity,'_hash_file',side_effect=lambda p:'0'*64 if p.name=='uart_consumption.py' else original(p)):
            self.assertEqual(host_identity.host_source_identity(),legacy)
        self.assertTrue(UART_PATHS.isdisjoint(row['path'] for row in legacy['files']))

    def test_generated_v2_includes_prior_extensions_and_uart_modules(self):
        generated=({'build_identity':{'inputs':[]}},)
        identity=host_identity.host_source_identity(harness_identities=generated)
        paths={row['path'] for row in identity['files']}
        self.assertLessEqual(UART_PATHS,paths)
        self.assertIn('src/myfuzz/scenario/cpu_retirement.py',paths)
        self.assertIn('src/myfuzz/scenario/gpio_consumption.py',paths)
        self.assertEqual(identity['schema_version'],'scenario_harness_host_sources.v2')
        self.assertEqual(host_identity.verify_host_source_identity(identity,harness_identities=generated),identity)
        original=host_identity._hash_file
        with patch.object(host_identity,'_hash_file',side_effect=lambda p:'0'*64 if p.name=='uart_consumption.py' else original(p)):
            with self.assertRaisesRegex(ValueError,'harness host source identity mismatch'):
                host_identity.verify_host_source_identity(identity,harness_identities=generated)

    def test_import_discovery_and_fresh_envelope_include_uart_sources(self):
        from myfuzz.local_harness.build import _host_sources
        from myfuzz.integration.scenario_rfuzz_live import _FRESH_RUNTIME_SOURCES
        self.assertIn('src/myfuzz/scenario/uart_consumption.py',set(_host_sources()))
        self.assertIn('src/myfuzz/local_harness/opentitan_uart_fifo_contract.py',set(_host_sources()))
        self.assertLessEqual(UART_PATHS,set(_FRESH_RUNTIME_SOURCES))
