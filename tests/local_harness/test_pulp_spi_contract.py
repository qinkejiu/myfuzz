"""Pinned PULP SPI facts prove a reusable APB contract, not runtime execution."""
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import (
    ComponentProfileError, bind_profile, elaborate_profile, load_component_profile)
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
        self.assertTrue(result['artifact_source_gate_compatible'])
        self.assertEqual('spi_sdi1', result['serial']['miso'])
        self.assertEqual([0, 1], [event['bit'] for event in result['events']])
        self.assertTrue(all(event['trigger'] == 'native_pulse' for event in result['events']))
        self.assertEqual(0x28, result['events'][0]['rearm_read_offset'])
        self.assertEqual(0, result['events'][0]['rearm_read_value'])

    def test_union_profile_passes_strict_two_owner_artifact_gate(self):
        result = verify_local_source_lock(self.profile(), base_dir=SOURCES)
        self.assertEqual('local_source_lock_verification.v1', result['schema_version'])
        self.assertEqual(2, len(result['source_records']))

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


IRQ_PROFILE = ROOT / 'configs/peripherals/inprocess_verify_pulp_spi_irq/component_profile.json'


def _contract():
    return importlib.import_module('myfuzz.local_harness.pulp_spi_contract')


class PulpSpiDeclaredInterruptTests(unittest.TestCase):
    """A declared event output is admitted as a pulse, never as a latched status.

    The two event bits are one-cycle pulses (``apb_spi_master.sv:116-117``) and the
    status word has no read-mux arm, so the contract has to admit the declaration
    the RTL actually implements and refuse the two claims it does not: a held
    (latched) level and a software clear.
    """

    def document(self):
        return json.loads(IRQ_PROFILE.read_text())

    def profile(self):
        return load_component_profile(self.document())

    def test_declared_end_of_transfer_pulse_is_admitted(self):
        result = _contract().verify_pulp_spi_source_contract(self.profile(), base_dir=SOURCES)
        self.assertEqual(1, len(result['declared_interrupts']))
        declared = result['declared_interrupts'][0]
        self.assertEqual(('spi.events', 'eot', 1, 'pulse', 1),
                         (declared['endpoint_id'], declared['role'], declared['bit'],
                          declared['trigger'], declared['pulse_width_cycles']))
        # The declaration changes who owns the wire, not what the device is: the
        # status word still reads back 0 and there is still no clear to claim.
        semantics = result['interrupt_semantics']
        self.assertIsNone(semantics['latched_status'])
        self.assertIsNone(semantics['software_clear'])
        self.assertEqual(0, semantics['status_register']['readback_value'])
        self.assertEqual('absent', semantics['status_register']['read_mux'])

    def test_an_undeclared_profile_still_needs_the_observation_action(self):
        document = self.document()
        document['interrupts'] = []
        document['port_actions'] = []
        with self.assertRaisesRegex(ValueError, 'pulp-spi-native-event-observation-required'):
            _contract().verify_pulp_spi_source_contract(load_component_profile(document),
                                                       base_dir=SOURCES)

    def test_a_declared_pulse_without_its_width_is_refused(self):
        profile = self.profile()
        without = replace(profile, interrupts=(replace(profile.interrupts[0],
                                                       pulse_width_cycles=None),))
        with self.assertRaisesRegex(ValueError, 'pulp-spi-interrupt-pulse-width-required'):
            _contract().verify_pulp_spi_source_contract(without, base_dir=SOURCES)
        # The document path refuses the same omission even earlier, by its own name.
        document = self.document()
        del document['interrupts'][0]['pulse_width_cycles']
        with self.assertRaisesRegex(ComponentProfileError, 'interrupt-pulse-width-required'):
            load_component_profile(document)

    def test_a_latched_level_claim_is_refused(self):
        profile = self.profile()
        held = replace(profile, interrupts=(replace(profile.interrupts[0], trigger='level',
                                                    pulse_width_cycles=None),))
        with self.assertRaisesRegex(ValueError, 'pulp-spi-interrupt-must-be-pulse'):
            _contract().verify_pulp_spi_source_contract(held, base_dir=SOURCES)

    def test_a_status_clear_claim_is_refused(self):
        profile = self.profile()
        for side_effect in ('read_clears', 'write_1_to_clear'):
            registers = tuple(replace(register, side_effect=side_effect)
                              if register.offset == 0x28 else register
                              for register in profile.address.registers)
            claimed = replace(profile, address=replace(profile.address,
                                                       registers=registers))
            with self.subTest(side_effect=side_effect), \
                    self.assertRaisesRegex(ValueError,
                                           'pulp-spi-interrupt-clear-claim-unsupported'):
                _contract().verify_pulp_spi_source_contract(claimed, base_dir=SOURCES)

    def test_an_event_bit_the_rtl_does_not_drive_is_refused(self):
        profile = self.profile()
        for bit in (2, None):
            outside = replace(profile, interrupts=(replace(profile.interrupts[0], bit=bit),))
            with self.subTest(bit=bit), \
                    self.assertRaisesRegex(ValueError, 'pulp-spi-interrupt-bit-unsupported'):
                _contract().verify_pulp_spi_source_contract(outside, base_dir=SOURCES)

    def test_a_source_that_is_not_the_event_output_is_refused(self):
        profile = self.profile()
        endpoints = tuple(replace(endpoint, function='external_pins')
                          if endpoint.endpoint_id == 'spi.events' else endpoint
                          for endpoint in profile.endpoints)
        with self.assertRaisesRegex(ValueError, 'pulp-spi-interrupt-endpoint-unsupported'):
            _contract().verify_pulp_spi_source_contract(replace(profile, endpoints=endpoints),
                                                       base_dir=SOURCES)

    def test_two_owners_of_the_event_output_are_refused(self):
        document = self.document()
        document['port_actions'] = [{'port': 'events_o', 'action': 'observe',
                                     'reason': 'the same wire declared twice'}]
        with self.assertRaisesRegex(ValueError, 'pulp-spi-event-port-double-declared'):
            _contract().verify_pulp_spi_source_contract(load_component_profile(document),
                                                       base_dir=SOURCES)


if __name__ == '__main__':
    unittest.main()
