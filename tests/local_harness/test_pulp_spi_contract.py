"""Pinned PULP SPI facts prove a reusable APB contract, not runtime execution."""
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import (
    bind_profile, elaborate_profile, load_component_profile)
from myfuzz.composition.soc_port_dispositions import build_port_dispositions
from myfuzz.local_harness.source_lock import verify_local_source_lock
from myfuzz.local_harness.template_contracts import select_template_contract

ROOT = Path(__file__).resolve().parents[2]
SOURCES = Path(os.environ.get('MYFUZZ_PINNED_SOURCE_ROOT', ROOT))
PROFILE = ROOT / 'configs/peripherals/pulp_spi/local_component_profile.json'


class PulpSpiContractTests(unittest.TestCase):
    def profile(self):
        return load_component_profile(PROFILE)

    def verify(self, profile=None):
        module = importlib.import_module('myfuzz.local_harness.pulp_spi_contract')
        return module.verify_pulp_spi_source_contract(profile or self.profile(), base_dir=SOURCES)

    def test_profile_has_all_ports_and_real_native_pulse_observation(self):
        profile = self.profile()
        self.assertEqual('all', profile.source_document['top_port_selection'])
        self.assertEqual(7, len(profile.source.files))
        self.assertEqual([], list(profile.interrupts))
        self.assertEqual('observe', profile.port_actions[0].action)
        self.assertEqual('events_o', profile.port_actions[0].port)
        self.assertFalse(profile.capabilities['byte_enable'])

    def test_authenticated_closure_and_facts_have_no_runtime_claim(self):
        result = self.verify()
        self.assertEqual('pulp_spi_native_contract.v1', result['schema_version'])
        self.assertEqual(7, len(result['closure_files']))
        self.assertEqual(2, len(result['source_records']))
        self.assertFalse(result['runtime_effective'])
        self.assertFalse(result['artifact_source_gate_compatible'])
        self.assertEqual('spi_sdi1', result['serial']['miso'])
        self.assertEqual([0, 1], [event['bit'] for event in result['events']])
        self.assertTrue(all(event['trigger'] == 'native_pulse' for event in result['events']))
        self.assertEqual(0x28, result['events'][0]['rearm_read_offset'])
        self.assertEqual(0, result['events'][0]['rearm_read_value'])

    def test_union_profile_cannot_bypass_existing_artifact_source_gate(self):
        with self.assertRaisesRegex(ValueError, 'source-mismatch:root'):
            verify_local_source_lock(self.profile(), base_dir=SOURCES)

    def test_profile_locator_dataclass_mutation_refused(self):
        profile = self.profile()
        bad = replace(profile, source=replace(profile.source, top_module='apb_gpio'))
        with self.assertRaisesRegex(ValueError, 'source-inconsistent'):
            self.verify(bad)

    def test_profile_pin_or_file_or_parameter_mutation_refused(self):
        original = json.loads(PROFILE.read_text())
        for field in ('revision', 'files', 'parameters'):
            document = json.loads(json.dumps(original))
            if field == 'revision':
                document['source']['revision'] = 'sha256:' + '0' * 64
            elif field == 'files':
                document['source']['files'].pop()
            else:
                document['source']['elaboration']['parameters'][0]['value'] = '8'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(load_component_profile(document))

    def test_clock_reset_and_full_word_capability_mutation_refused(self):
        original = json.loads(PROFILE.read_text())
        for field in ('clock', 'reset', 'byte_enable'):
            document = json.loads(json.dumps(original))
            if field == 'clock':
                document['clocks'][0]['port'] = 'spi_clk'
            elif field == 'reset':
                document['resets'][0]['polarity'] = 'active_high'
            else:
                document['capabilities']['byte_enable'] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(load_component_profile(document))

    def test_fulltop_binding_reuses_existing_apb3_contract(self):
        profile = self.profile()
        facts = elaborate_profile(profile, base_dir=SOURCES, mode='direct')
        binding = bind_profile(profile, facts)
        self.assertEqual('all', facts.selection)
        self.assertEqual(25, len(facts.ports))
        dispositions = build_port_dispositions(
            "spi", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=profile.port_actions)
        self.assertEqual(25, len(dispositions))
        endpoint = next(ep for ep in binding.endpoints if ep.function == 'mmio_slave')
        selected = select_template_contract(endpoint, profile.capabilities)
        self.assertEqual('target.apb3', selected.contract.template_id)
        self.assertEqual('full-word', selected.contract.variant_id)
        self.assertFalse(selected.document()['runtime_effective'])
        ports = {port.name: port for port in facts.ports}
        self.assertEqual(2, ports['events_o'].width)
        self.assertEqual(2, ports['spi_mode'].width)
        self.assertEqual('input', ports['spi_sdi1'].direction)


if __name__ == '__main__':
    unittest.main()
