"""Artifact-only session selection and physical input ownership."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedApb3RegisterSession,
    GeneratedTlulRegisterSession, GeneratedWishboneRegisterSession,
    compile_generated_register_bindings, compile_generated_register_ownership,
    create_generated_register_session)

from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact as tlul_artifact
from tests.local_harness.test_generic_tlul_bound_input_real import bound_request
from tests.local_harness.test_generic_apb3_register_real import artifact as apb_artifact
from tests.local_harness.test_generic_apb3_register_real import request as apb_request
from tests.local_harness.test_generic_apb3_bound_input_real import (
    source_request as apb_source_request, target_request as apb_target_request)
from tests.local_harness.test_generic_wishbone_register_real import artifact as wb_artifact
from tests.local_harness.test_generic_wishbone_register_real import request as wb_request


class GeneratedRegisterFactoryTests(unittest.TestCase):
    def test_artifact_selects_protocol_session_without_component_branch(self):
        artifacts = (
            (tlul_artifact(bound_request()), GeneratedTlulRegisterSession),
            (apb_artifact(apb_request('gpio', fixed=(('gpio.pins', 'in', 0),))),
             GeneratedApb3RegisterSession),
            (wb_artifact(wb_request('zipcpu_timer')), GeneratedWishboneRegisterSession),
        )
        with tempfile.TemporaryDirectory() as directory:
            for generated, expected in artifacts:
                with self.subTest(expected=expected.__name__):
                    session = create_generated_register_session(generated,
                        base_dir=ROOT, cache_dir=Path(directory))
                    self.assertIsInstance(session, expected)
            apb = create_generated_register_session(artifacts[1][0],
                base_dir=ROOT, cache_dir=Path(directory),
                setup_writes=((0x00, 1),), probe_offsets=(0x04,))
            self.assertEqual(((0x00, 1),), apb.setup_writes)
            self.assertEqual((0x04,), apb.probe_offsets)

    def test_physical_bound_input_stays_bound_across_artifacts(self):
        target = tlul_artifact(bound_request())
        source = apb_artifact(apb_request('gpio', environment=(
            ('gpio.pins', 'in', 'external_pins'),)))
        ownership = compile_generated_register_ownership({'b': target,
                                                         'external_gpio': source})
        self.assertEqual('a.cio_gpio_o', ownership.binding_producer(
            'b', 'gpio.pins.in', 0, 32))
        self.assertEqual('external_pins', ownership.mutation_source(
            'external_gpio', 'gpio.pins.in', 0, 32, direction='IP_TO_CPU'))
        with self.assertRaisesRegex(ValueError, 'bound input cannot be mutated'):
            ownership.mutation_source('b', 'gpio.pins.in', 0, 32,
                                      direction='IP_TO_IP')

    def test_conflicting_or_unverified_artifact_fails_closed(self):
        generated = tlul_artifact(bound_request())
        row = dict(generated.runtime_document['bound_physical_inputs'][0])
        document = dict(generated.runtime_document)
        document['dynamic_physical_inputs'] = [dict(row, source_id='illegal')]
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            compile_generated_register_ownership({'b': replace(
                generated, runtime_document=document)})
        document = dict(generated.runtime_document, driver_status='not_generated')
        with self.assertRaisesRegex(ValueError, 'generated v2'):
            create_generated_register_session(replace(generated,
                runtime_document=document), base_dir=ROOT, cache_dir=Path('/tmp'))

    def test_bound_routes_derive_only_from_exact_real_exports(self):
        source = apb_artifact(apb_source_request())
        target = apb_artifact(apb_target_request())
        bindings = compile_generated_register_bindings({'a': source, 'b': target})
        self.assertEqual(1, len(bindings))
        self.assertEqual(('a', 'gpio_out', 'b', 'gpio.pins.in', 32),
                         (bindings[0].source_component, bindings[0].source_port,
                          bindings[0].target_component, bindings[0].target_port,
                          bindings[0].width))
        with self.assertRaisesRegex(ValueError, 'distinct generated producer'):
            compile_generated_register_bindings({'b': target})
        with self.assertRaisesRegex(ValueError, 'exact real output width'):
            altered = dict(target.runtime_document)
            row = dict(altered['bound_physical_inputs'][0], width=1)
            altered['bound_physical_inputs'] = [row]
            compile_generated_register_bindings({'a': source, 'b': replace(
                target, runtime_document=altered)})


if __name__ == '__main__':
    unittest.main()
