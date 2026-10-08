"""New decoder schemas cache edge identities while legacy mapping is retained."""
from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import patch

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, SourceBindings, SourceBinding
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder
from myfuzz.scenario.runtime_path_contract import RuntimePathContract
from tests.scenario import test_rfuzz_genome_decoder as legacy


def contract(graph):
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    return RuntimePathContract(digest, (), ())


class EdgeAwareDecoderTests(unittest.TestCase):
    def fixture(self):
        old = legacy.GenomeRecordDecoderTests()
        old.setUp()
        graph = DependencyGraph(sources=tuple(old.graph.sources.values()),
            rules=old.graph.ordered_rules + (DependencyRule('cpu.irq', ('gpio.pin9',), 'EVENT_ORDER'),))
        bindings = SourceBindings((SourceBinding('cpu.program', 'memory_image', 'cpu', 'cpu.main', 0, 32, 'initial_image:cpu:cpu.main', 0x10080),
            SourceBinding('gpio.pin9', 'source', 'gpio', 'pin', 9, 1, 'external')))
        decoder = GenomeRecordDecoder(graph=graph, ownership=old.ownership,
            templates=old.decoder.templates, source_bindings=bindings, runtime_contract=contract(graph))
        return decoder, graph, old.ownership

    def test_genome_distinct_or_ids_cached_mutation_and_roundtrip_replay_only(self):
        decoder, _, _ = self.fixture()
        self.assertEqual('scenario_rfuzz_decoder.v3', decoder.document()['schema_version'])
        with patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('hot path traversal')), patch.object(DependencyGraph, 'paths_to', side_effect=AssertionError('legacy traversal')), patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('hot hash')), patch.object(SourceBindings, 'validate', side_effect=AssertionError('hot bindings')):
            first = decoder.decode((bytes((1, 0, 0, 0, 0, 1, 0, 0)),))
            second = decoder.decode((bytes((1, 1, 0, 0, 0, 1, 0, 0)),))
            self.assertNotEqual(first.path_id, second.path_id)
            direction, path = decoder.resolve_path_id(first.path_id)
            self.assertEqual('IP_TO_CPU', direction)
            self.assertEqual('cpu.irq', path.target)
            self.assertEqual(first.path_id, decoder.path_identifier(path, direction=direction))
        restored = GenomeRecordDecoder.from_document(decoder.document())
        self.assertTrue(restored.from_document_replay_only)
        self.assertFalse(restored.trusted_for_search)
        self.assertEqual(first, restored.decode((bytes((1, 0, 0, 0, 0, 1, 0, 0)),)))

    def test_external_graph_and_ownership_mutation_cannot_change_frozen_decoder(self):
        decoder, graph, ownership = self.fixture()
        before = decoder.document()
        graph.sources.clear()
        graph.rules.clear()
        ownership._bits.clear()
        self.assertEqual(before, decoder.document())
        decoder.decode((bytes((1, 0, 0, 0, 0, 1, 0, 0)),))
        with self.assertRaises((TypeError, AttributeError)):
            decoder.graph.sources.clear()
        with self.assertRaises((TypeError, AttributeError)):
            decoder.ownership._bits.clear()

    def test_contract_hash_and_noncanonical_new_document_rejected(self):
        decoder, _, _ = self.fixture()
        doc = decoder.document()
        doc['runtime_contract']['graph_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            GenomeRecordDecoder.from_document(doc)
        doc = decoder.document()
        doc['path_mapping'][0]['path_id'] = '0' * 64
        with self.assertRaises(ValueError):
            GenomeRecordDecoder.from_document(doc)
        with self.assertRaises(ValueError):
            decoder.resolve_path_id([])
        doc = decoder.document()
        doc['extra'] = 1
        with self.assertRaises(ValueError):
            GenomeRecordDecoder.from_document(doc)

    def online(self):
        from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource
        from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
        graph = OnlineDependencyGraph(sources=(OnlineDependencySource('pin', 'source', 'ip', ('IP_TO_CPU',), 'pin'),),
            rules=(DependencyRule('target', ('pin',), 'DATA_BINDING'), DependencyRule('target', ('pin',), 'EVENT_ORDER')))
        ownership = compile_ownership((InputField('ip', 'pin', 1),), (InputOwner('ip', 'pin', 0, 1, 'source', 'env'),))
        return OnlineCaseDecoder(sources=(OnlineSource('pin', 'source', 'ip', 'IP_TO_CPU', 'target', port='pin'),),
            graph=graph, ownership=ownership, schedule=('ip',), instruction_start=0, instruction_end=4,
            runtime_contract=contract(graph))

    def test_online_digest_targets_and_cached_roundtrip(self):
        from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
        decoder = self.online()
        self.assertEqual('online_case_decoder.v2', decoder.document()['schema_version'])
        with patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('hot traversal')), patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('hot hash')):
            a = decoder.decode(bytes((0, 0, 0, 1, 0, 0, 0, 0)))
            b = decoder.decode(bytes((0, 1, 0, 1, 0, 0, 0, 0)))
            self.assertNotEqual(a.path_id, b.path_id)
            self.assertEqual('target', decoder.path_target(a.path_id))
            self.assertEqual(('pin',), tuple(s.source_id for s in decoder.sources_for(a.path_id)))
        restored = OnlineCaseDecoder.from_document(decoder.document())
        self.assertTrue(restored.from_document_replay_only)
        self.assertEqual(a, restored.decode(bytes((0, 0, 0, 1, 0, 0, 0, 0))))

    def test_online_legacy_manifest_keeps_target_path_and_strict_roundtrip(self):
        from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
        original = self.online()
        legacy_decoder = OnlineCaseDecoder(sources=original.sources, ownership=original.ownership,
            graph=original.graph, schedule=('ip',), instruction_start=0, instruction_end=4)
        self.assertEqual('online_case_decoder.v1', legacy_decoder.document()['schema_version'])
        self.assertNotIn('runtime_contract', legacy_decoder.document())
        case = legacy_decoder.decode(bytes(8))
        self.assertEqual('target', case.path_id)
        restored = OnlineCaseDecoder.from_document(legacy_decoder.document())
        self.assertEqual(case, restored.decode(bytes(8)))
        bad = original.document()
        bad['path_mapping'][0]['path_id'] = '0' * 64
        with self.assertRaises(ValueError):
            OnlineCaseDecoder.from_document(bad)

    def test_compiled_mutation_authorization_cannot_name_unreachable_focus(self):
        from myfuzz.scenario.mutation import MutationPlan, _MutationAuthorization
        decoder, _, _ = self.fixture()
        direction, path = next(pair for pair in decoder.runtime_paths if pair[0] == 'IP_TO_CPU')
        with self.assertRaises(ValueError):
            _MutationAuthorization(MutationPlan(direction, path.target, path, 'cpu.program'), decoder.graph, decoder.ownership)
