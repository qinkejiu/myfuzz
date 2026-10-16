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
from myfuzz.composition import test_capability as capability_api
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
        document['schema_version'] = 'ip_test_capability.v4'
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

    def test_v2_feature_contract_self_declares_required_observation_mappings(self):
        document = self.document()
        document['schema_version'] = 'ip_test_capability.v2'
        document['feature_contract'] = {
            'provider_id': 'example.sha',
            'provider_version': '1.0',
            'operations': [{
                'endpoint_id': 'uart.bus',
                'operation': 'completion',
                'required_observation_mappings': ['uart-rx-sample'],
                'evidence_ref': 'plugin-manifest:sha256:abc123',
            }],
        }

        capability = self.loader()(document, profile=self.profile)

        self.assertEqual(('example.sha', '1.0'),
                         (capability.feature_contract.provider_id,
                          capability.feature_contract.provider_version))
        self.assertEqual(('uart-rx-sample',),
                         capability.feature_contract.operations[0].required_observation_mappings)

    def test_v2_feature_contract_rejects_missing_or_unbound_observation_mappings(self):
        document = self.document()
        document['schema_version'] = 'ip_test_capability.v2'
        document['feature_contract'] = {
            'provider_id': 'example.sha', 'provider_version': '1.0',
            'operations': [{
                'endpoint_id': 'uart.bus', 'operation': 'completion',
                'required_observation_mappings': [],
                'evidence_ref': 'plugin-manifest:sha256:abc123',
            }],
        }
        with self.assertRaisesRegex(ValueError,
                                    'feature-observation-mappings-required'):
            self.loader()(document, profile=self.profile)

        document['feature_contract']['operations'][0][
            'required_observation_mappings'] = ['missing-map']
        with self.assertRaisesRegex(ValueError,
                                    'unknown-feature-observation-mapping:missing-map'):
            self.loader()(document, profile=self.profile)

    def test_v2_feature_contract_rejects_unknown_operations_and_fields(self):
        document = self.document()
        document['schema_version'] = 'ip_test_capability.v2'
        document['feature_contract'] = {
            'provider_id': 'example.sha', 'provider_version': '1.0',
            'operations': [{
                'endpoint_id': 'uart.bus', 'operation': 'guess_result',
                'required_observation_mappings': ['uart-rx-sample'],
                'evidence_ref': 'plugin-manifest:sha256:abc123',
            }],
        }
        with self.assertRaisesRegex(ValueError,
                                    'unsupported-feature-operation:guess_result'):
            self.loader()(document, profile=self.profile)

        document['feature_contract']['operations'][0]['callback'] = 'run'
        with self.assertRaisesRegex(ValueError, 'embedded-program'):
            self.loader()(document, profile=self.profile)

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

    def test_l2_register_plan_applies_field_access_masks_and_side_effect_opt_in(self):
        plan_register_operation = getattr(capability_api, 'plan_register_operation', None)
        self.assertIsNotNone(plan_register_operation,
                             'the L2 register action planner must be available')
        document = self.document()
        document['register_semantics'] = [
            {
                'register': 'CTRL', 'field': 'enable', 'lsb': 0, 'width': 2,
                'access': 'rw', 'read_mask': 1, 'write_mask': 1,
                'side_effect': 'none', 'evidence_ref': 'rtl:uart.ctrl.enable',
            },
            {
                'register': 'STATUS', 'field': 'ready', 'lsb': 0, 'width': 1,
                'access': 'ro', 'read_mask': 1, 'write_mask': 0,
                'side_effect': 'none', 'evidence_ref': 'rtl:uart.status.ready',
            },
            {
                'register': 'TXDATA', 'field': 'byte', 'lsb': 0, 'width': 8,
                'access': 'wo', 'read_mask': 0, 'write_mask': 255,
                'side_effect': 'transmit_byte', 'evidence_ref': 'rtl:uart.txdata',
            },
            {
                'register': 'RXDATA', 'field': 'byte', 'lsb': 0, 'width': 8,
                'access': 'ro', 'read_mask': 255, 'write_mask': 0,
                'side_effect': 'read_clears', 'evidence_ref': 'rtl:uart.rxdata',
            },
        ]
        capability = self.loader()(document, profile=self.profile)

        write = plan_register_operation(
            self.profile, capability, register='CTRL', field='enable',
            operation='register_write', value=1)
        self.assertEqual((0, 1, 1, 'none'),
                         (write.offset, write.bus_mask, write.bus_value,
                          write.side_effect))
        read = plan_register_operation(
            self.profile, capability, register='STATUS', field='ready',
            operation='register_read')
        self.assertEqual((4, 1), (read.offset, read.bus_mask))

        with self.assertRaisesRegex(ValueError, 'register-field-value-exceeds-write-mask'):
            plan_register_operation(
                self.profile, capability, register='CTRL', field='enable',
                operation='register_write', value=2)
        with self.assertRaisesRegex(ValueError, 'register-field-not-writable'):
            plan_register_operation(
                self.profile, capability, register='STATUS', field='ready',
                operation='register_write', value=1)
        with self.assertRaisesRegex(ValueError,
                                    'register-side-effect-requires-explicit-authorization:read_clears'):
            plan_register_operation(
                self.profile, capability, register='RXDATA', field='byte',
                operation='register_read')
        rx = plan_register_operation(
            self.profile, capability, register='RXDATA', field='byte',
            operation='register_read', allow_side_effect=True)
        self.assertEqual('read_clears', rx.side_effect)
        with self.assertRaisesRegex(ValueError,
                                    'register-side-effect-requires-explicit-authorization:transmit_byte'):
            plan_register_operation(
                self.profile, capability, register='TXDATA', field='byte',
                operation='register_write', value=65)
        tx = plan_register_operation(
            self.profile, capability, register='TXDATA', field='byte',
            operation='register_write', value=65, allow_side_effect=True)
        self.assertEqual((8, 255, 65, 'transmit_byte'),
                         (tx.offset, tx.bus_mask, tx.bus_value, tx.side_effect))

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
