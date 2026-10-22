"""Replay historical decoder rows without weakening current canonical checks."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import unittest

from myfuzz.scenario.dependency import (
    DependencyGraph, DependencyRule, FuzzableSource, SourceBinding, SourceBindings,
)
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runtime_path_contract import RuntimePathContract


class LegacyDecoderBindingsTests(unittest.TestCase):
    def decoder(self, version, kind):
        memory = kind == "memory_image"
        source = FuzzableSource("root", "cpu", "boot" if memory else "pin",
                                4, 12, ("CPU_TO_IP",), kind)
        graph = DependencyGraph(sources=(source,), rules=(
            DependencyRule("target", ("root",), "DATA_BINDING"),))
        ownership = (compile_ownership((), ()) if memory else compile_ownership(
            (InputField("cpu", "pin", 16),),
            (InputOwner("cpu", "pin", 0, 16, "source", "external"),)))
        genome = ScenarioGenome(
            "seed", "CPU_TO_IP", "target", ("cpu", "other"), 2,
            () if memory else (Action("pin", "cpu", "pin", 0,
                "CPU_TO_IP", Trigger("START"), width=16),),
            initial_images=(MemoryImage("boot", "cpu", 0x1000, "0011"),)
            if memory else ())
        bindings = SourceBindings((SourceBinding(
            "root", kind, "cpu", source.port, 4, 12,
            "initial_image:cpu:boot" if memory else "external",
            0x1000 if memory else None),))
        contract = None
        if version == 3:
            digest = hashlib.sha256(json.dumps(graph.edge_document(),
                sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode()).hexdigest()
            contract = RuntimePathContract(digest, (), ())
        return GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("target", genome),
                       DecoderTemplate("target", replace(genome, testcase_id="second"))),
            source_bindings=None if version == 1 else bindings,
            runtime_contract=contract)

    def historical(self, version, kind):
        decoder = self.decoder(version, kind)
        document = decoder.document()
        document['schema_version'] = f'scenario_rfuzz_decoder.v{version}'
        for row in document.get("sources", ()):
            row.pop("image_address", None)
        for row in document.get("source_bindings", ()):
            row.pop("image_address", None)
        return decoder, document

    def test_historical_v1_v2_v3_source_and_memory_rows_replay(self):
        for version in (1, 2, 3):
            for kind in ("source", "memory_image"):
                with self.subTest(version=version, kind=kind):
                    original, document = self.historical(version, kind)
                    snapshot = deepcopy(document)
                    restored = GenomeRecordDecoder.from_document(document)
                    raw = (bytes((0, 0, 0, 0, 0, 1, 0, 0)),)
                    self.assertEqual(original.decode(raw), restored.decode(raw))
                    self.assertFalse(restored.trusted_for_search)
                    self.assertTrue(restored.from_document_replay_only)
                    self.assertEqual(snapshot, document)
                    if version != 1:
                        self.assertEqual(0x1000 if kind == "memory_image" else None,
                            restored.source_bindings.entries[0].image_address)
                        self.assertEqual(restored.document(),
                            GenomeRecordDecoder.from_document(restored.document()).document())

    def test_historical_memory_address_requires_every_template_image(self):
        for version in (2, 3):
            for defect in ("missing", "component", "image_id", "duplicate", "address", "range"):
                with self.subTest(version=version, defect=defect):
                    _, document = self.historical(version, "memory_image")
                    images = document["templates"][1]["genome"]["initial_images"]
                    if defect == "missing":
                        images.clear()
                    elif defect == "duplicate":
                        images.append(deepcopy(images[0]))
                    elif defect == "address":
                        images[0]["address"] = 0x2000
                    elif defect == "range":
                        images[0]["data_hex"] = "00"
                    else:
                        images[0][defect] = "other"
                    with self.assertRaises(ValueError):
                        GenomeRecordDecoder.from_document(document)

    def test_historical_memory_inference_compares_external_trusted_binding(self):
        for version in (2, 3):
            with self.subTest(version=version):
                original, document = self.historical(version, "memory_image")
                GenomeRecordDecoder.from_document(document,
                    source_bindings=original.source_bindings)
                wrong = SourceBindings((replace(original.source_bindings.entries[0],
                                                image_address=0x2000),))
                with self.assertRaises(ValueError):
                    GenomeRecordDecoder.from_document(document, source_bindings=wrong)

    def test_current_documents_remain_strictly_canonical(self):
        for version in (1, 2, 3):
            for kind in ("source", "memory_image"):
                original = self.decoder(version, kind).document()
                self.assertEqual(original,
                    GenomeRecordDecoder.from_document(original).document())
                defects = ("extra", "record_bytes", "source_extra")
                if version != 1:
                    defects += ("binding_extra", "binding_address")
                for defect in defects:
                    with self.subTest(version=version, kind=kind, defect=defect):
                        document = deepcopy(original)
                        if defect == "extra":
                            document["extra"] = None
                        elif defect == "record_bytes":
                            document["record_bytes"] = 7
                        elif defect == "source_extra":
                            rows = document["graph"]["sources"] if version == 3 else document["sources"]
                            rows[0]["extra"] = None
                        elif defect == "binding_extra":
                            document["source_bindings"][0]["extra"] = None
                        else:
                            document["source_bindings"][0]["image_address"] = (
                                None if kind == "memory_image" else 0x1000)
                        with self.assertRaises(ValueError):
                            GenomeRecordDecoder.from_document(document)

    def test_historical_documents_still_reject_noncanonical_fields(self):
        for version in (1, 2, 3):
            for kind in ("source", "memory_image"):
                for defect in ("extra", "record_bytes", "binding_extra"):
                    if version == 1 and defect == "binding_extra":
                        continue
                    with self.subTest(version=version, kind=kind, defect=defect):
                        _, document = self.historical(version, kind)
                        if defect == "extra":
                            document["extra"] = None
                        elif defect == "record_bytes":
                            document["record_bytes"] = 7
                        else:
                            document["source_bindings"][0]["extra"] = None
                        with self.assertRaises(ValueError):
                            GenomeRecordDecoder.from_document(document)

    def test_mixed_address_field_versions_are_not_a_historical_document(self):
        for version in (1, 2, 3):
            original = self.decoder(version, "source")
            source = original.graph.sources["root"]
            graph = DependencyGraph(sources=(source, replace(source,
                source_id="other", bit_offset=0, width=4)),
                rules=original.graph.ordered_rules)
            binding = SourceBinding("root", "source", "cpu", "pin", 4, 12,
                                    "external")
            bindings = SourceBindings((binding, replace(binding,
                source_id="other", bit_offset=0, width=4)))
            runtime_contract = None
            if version == 3:
                digest = hashlib.sha256(json.dumps(graph.edge_document(),
                    sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False).encode()).hexdigest()
                runtime_contract = RuntimePathContract(digest, (), ())
            decoder = GenomeRecordDecoder(graph=graph, ownership=original.ownership,
                templates=original.templates,
                source_bindings=None if version == 1 else bindings,
                runtime_contract=runtime_contract)
            keys = ("sources",) if version == 1 else (
                ("sources", "source_bindings") if version == 2 else ("source_bindings",))
            for key in keys:
                with self.subTest(version=version, key=key):
                    document = decoder.document()
                    document[key][0]['image_address'] = None
                    with self.assertRaises(ValueError):
                        GenomeRecordDecoder.from_document(document)

    def test_serialization_versions_and_field_shapes(self):
        for version in (1, 2, 3):
            for kind in ('source', 'memory_image'):
                with self.subTest(version=version, kind=kind):
                    document = self.decoder(version, kind).document()
                    addressed = kind == 'memory_image' and version != 1
                    self.assertEqual(f'scenario_rfuzz_decoder.v{4 if addressed else version}',
                                     document['schema_version'])
                    for key in ('sources', 'source_bindings'):
                        for row in document.get(key, ()):
                            self.assertEqual(addressed, 'image_address' in row)

    def test_v4_missing_address_fields_do_not_trigger_legacy_inference(self):
        for version in (2, 3):
            original = self.decoder(version, 'memory_image').document()
            for key in ('sources', 'source_bindings'):
                if key not in original:
                    continue
                with self.subTest(version=version, key=key):
                    document = deepcopy(original)
                    document['schema_version'] = 'scenario_rfuzz_decoder.v4'
                    document[key][0].pop('image_address')
                    with self.assertRaises(ValueError):
                        GenomeRecordDecoder.from_document(document)

    def test_address_fields_cannot_be_labeled_as_closed_legacy_schema(self):
        for version in (2, 3):
            with self.subTest(version=version):
                document = self.decoder(version, 'memory_image').document()
                document['schema_version'] = f'scenario_rfuzz_decoder.v{version}'
                with self.assertRaises(ValueError):
                    GenomeRecordDecoder.from_document(document)

    def test_explicit_graph_address_without_bindings_also_uses_v4(self):
        for runtime in (False, True):
            with self.subTest(runtime=runtime):
                original = self.decoder(3 if runtime else 1, 'memory_image')
                source = replace(original.graph.sources['root'], image_address=0x1000)
                graph = DependencyGraph(sources=(source,), rules=original.graph.ordered_rules)
                runtime_contract = None
                if runtime:
                    digest = hashlib.sha256(json.dumps(graph.edge_document(),
                        sort_keys=True, separators=(',', ':'),
                        ensure_ascii=False).encode()).hexdigest()
                    runtime_contract = RuntimePathContract(digest, (), ())
                decoder = GenomeRecordDecoder(graph=graph, ownership=original.ownership,
                    templates=original.templates, runtime_contract=runtime_contract)
                document = decoder.document()
                self.assertEqual('scenario_rfuzz_decoder.v4', document['schema_version'])
                self.assertNotIn('source_bindings', document)
                self.assertEqual(document, GenomeRecordDecoder.from_document(document).document())
                document['schema_version'] = ('scenario_rfuzz_decoder.v3'
                                              if runtime else 'scenario_rfuzz_decoder.v1')
                with self.assertRaises(ValueError):
                    GenomeRecordDecoder.from_document(document)


if __name__ == "__main__":
    unittest.main()
