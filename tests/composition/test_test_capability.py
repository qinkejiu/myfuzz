from __future__ import annotations

import json
import unittest
from collections import UserList
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    load_component_profile,
)
from myfuzz.composition.test_capability import load_ip_test_capability


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT/'examples'/'soc_generation'/'profiles'/'novauart.json'


class LegacyProfileSchemaTests(unittest.TestCase):
    def test_component_profile_v1_rejects_inline_test_capability_extension(self):
        document = json.loads(PROFILE.read_text())
        document['test_capability'] = {
            'schema_version': 'ip_test_capability.v1',
            'component_id': document['component_id'],
        }

        with self.assertRaisesRegex(ComponentProfileError,
                                    'unknown-profile-field:test_capability'):
            load_component_profile(document)


class VersionedCapabilitySidecarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_component_profile(PROFILE)

    def loader(self):
        return load_ip_test_capability

    def document(self):
        return {
            'schema_version': 'ip_test_capability.v1',
            'component_id': self.profile.component_id,
            'profile_fingerprint': self.profile.profile_fingerprint,
            'endpoint_capabilities': [{
                'endpoint_id': 'uart.bus',
                'operations': ['request', 'accept', 'response', 'read', 'write'],
            }],
            'register_semantics': [{
                'register': 'CTRL', 'field': 'enable', 'lsb': 0, 'width': 1,
                'access': 'rw', 'read_mask': 1, 'write_mask': 1,
                'reset_value': 0, 'side_effect': 'none',
                'evidence_ref': 'rtl:uart_reg.ctrl.enable',
            }],
            'observation_mappings': [{
                'mapping_id': 'uart-rx-sample', 'endpoint_id': 'uart.pins',
                'role': 'rx', 'observation_kind': 'input_sample',
                'bit_range': [0, 0], 'endianness': 'little',
                'evidence_ref': 'rtl:uart.cio_rx_i',
            }],
        }

    def test_versioned_sidecar_loads_capabilities_registers_and_observations(self):
        capability = self.loader()(self.document(), profile=self.profile)
        self.assertEqual('novauart', capability.component_id)
        self.assertEqual(self.profile.profile_fingerprint, capability.profile_fingerprint)
        self.assertEqual(('request', 'accept', 'response', 'read', 'write'),
                         capability.endpoint_capabilities[0].operations)
        field = capability.register_semantics[0]
        self.assertEqual(('CTRL', 'enable', 0, 1),
                         (field.register, field.field, field.lsb, field.width))
        mapping = capability.observation_mappings[0]
        self.assertEqual(('uart.pins', 'rx', 'input_sample'),
                         (mapping.endpoint_id, mapping.role, mapping.observation_kind))

    def test_loaded_source_document_is_deeply_immutable(self):
        capability = self.loader()(self.document(), profile=self.profile)
        with self.assertRaises(TypeError):
            capability.source_document['register_semantics'][0]['field'] = 'corrupted'

    def test_loaded_source_document_freezes_every_supported_sequence_type(self):
        document = self.document()
        document['endpoint_capabilities'] = UserList(document['endpoint_capabilities'])

        capability = self.loader()(document, profile=self.profile)

        with self.assertRaises(AttributeError):
            capability.source_document['endpoint_capabilities'].clear()

    def test_sidecar_refuses_a_different_profile_source_revision(self):
        other_document = json.loads(PROFILE.read_text())
        other_document['source']['revision'] = 'sha256:' + '0'*64
        other_profile = load_component_profile(other_document)

        with self.assertRaisesRegex(ValueError, 'test-capability-profile-mismatch'):
            self.loader()(self.document(), profile=other_profile)

        replaced_profile = replace(
            self.profile,
            source=replace(self.profile.source, revision='sha256:' + '1'*64),
        )
        self.assertNotEqual(self.profile.profile_fingerprint,
                            replaced_profile.profile_fingerprint)
        with self.assertRaisesRegex(ValueError, 'test-capability-profile-mismatch'):
            self.loader()(self.document(), profile=replaced_profile)

    def test_sidecar_refuses_a_different_profile_with_the_same_source_revision(self):
        other_document = json.loads(PROFILE.read_text())
        other_document['description'] += ' A distinct contract.'
        other_profile = load_component_profile(other_document)

        with self.assertRaisesRegex(ValueError, 'test-capability-profile-mismatch'):
            self.loader()(self.document(), profile=other_profile)

    def test_sidecar_rejects_unknown_version_or_fields(self):
        load = self.loader()
        document = self.document()
        document['schema_version'] = 'ip_test_capability.v2'
        with self.assertRaisesRegex(ValueError, 'unsupported-test-capability-schema'):
            load(document, profile=self.profile)
        document = self.document()
        document['arbitrary'] = 'ignored behavior is unsafe'
        with self.assertRaisesRegex(ValueError, 'unknown-test-capability-field'):
            load(document, profile=self.profile)

        document = self.document()
        document['register_semantics'][0]['side_effect'] = 'invented_behavior'
        with self.assertRaisesRegex(ValueError, 'unsupported-register-field-side-effect'):
            load(document, profile=self.profile)

    def test_sidecar_rejects_embedded_code_and_unbound_observations(self):
        load = self.loader()
        document = self.document()
        document['observation_mappings'][0]['script'] = 'return 1'
        with self.assertRaisesRegex(ValueError, 'embedded-program'):
            load(document, profile=self.profile)
        document = self.document()
        document['observation_mappings'][0]['role'] = 'algorithm_complete'
        with self.assertRaisesRegex(ValueError, 'unknown-observation-role'):
            load(document, profile=self.profile)

    def test_signal_change_mapping_accepts_a_declared_input_signal(self):
        document = self.document()
        document['observation_mappings'][0]['observation_kind'] = 'signal_change'

        capability = self.loader()(document, profile=self.profile)

        self.assertEqual('signal_change', capability.observation_mappings[0].observation_kind)

    def test_sidecar_refuses_register_semantics_outside_the_profile_contract(self):
        load = self.loader()
        document = self.document()
        document['register_semantics'][0]['lsb'] = 32
        with self.assertRaisesRegex(ValueError, 'register-field-outside-width'):
            load(document, profile=self.profile)
        document = self.document()
        document['register_semantics'][0]['write_mask'] = 2
        document['register_semantics'][0]['lsb'] = 0
        with self.assertRaisesRegex(ValueError, 'register-field-mask-outside-width'):
            load(document, profile=self.profile)

    def test_sidecar_accepts_a_documented_side_effect_already_declared_by_profile(self):
        profile = load_component_profile(
            ROOT/'configs'/'peripherals'/'zipcpu_uart'/'component_profile.json')
        document = self.document()
        document.update(component_id=profile.component_id,
                        profile_fingerprint=profile.profile_fingerprint,
                        endpoint_capabilities=[], observation_mappings=[])
        document['register_semantics'] = [{
            'register': 'RXREG', 'field': 'data', 'lsb': 0, 'width': 8,
            'access': 'rw', 'read_mask': 255, 'write_mask': 255,
            'side_effect': 'read_pops_rx_fifo',
            'evidence_ref': 'rtl:wbuart.v:238',
        }]

        capability = self.loader()(document, profile=profile)
        self.assertEqual('read_pops_rx_fifo', capability.register_semantics[0].side_effect)

    def test_sidecar_accepts_all_current_novauart_register_side_effects(self):
        for register, field, access, read_mask, write_mask, effect in (
            ('TXDATA', 'tx_byte', 'wo', 0, 255, 'transmit_byte'),
            ('IRQ_STATUS', 'pending', 'rw', 1, 1, 'write_1_to_clear'),
        ):
            with self.subTest(side_effect=effect):
                document = self.document()
                document['endpoint_capabilities'] = []
                document['observation_mappings'] = []
                document['register_semantics'] = [{
                    'register': register, 'field': field, 'lsb': 0,
                    'width': 8 if register == 'TXDATA' else 1,
                    'access': access, 'read_mask': read_mask, 'write_mask': write_mask,
                    'side_effect': effect, 'evidence_ref': f'rtl:novauart.{register}',
                }]

                capability = self.loader()(document, profile=self.profile)

                self.assertEqual(effect, capability.register_semantics[0].side_effect)
