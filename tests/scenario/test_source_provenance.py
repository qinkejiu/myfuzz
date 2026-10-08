"""Strict admission records and bounded explicit lookup, without source inference."""

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
import json
import unittest


def material(**changes):
    return dict(case_id="case-a", case_index=0, source_id="cpu-program",
                path_id="cpu-uart", direction="CPU_TO_IP", component="cpu",
                action_id="load-program", role="fuzz_source", input_kind="instruction",
                input_sha256="a" * 64) | changes


class SourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("myfuzz.scenario.source_provenance"),
                             "source admission implementation is missing")
        module = importlib.import_module("myfuzz.scenario.source_provenance")
        self.Admission = module.SourceAdmission
        self.Registry = module.AdmissionRegistry

    def test_record_has_canonical_versioned_digest_and_roundtrip(self):
        record = self.Admission.create(**material(case_id="案例"))
        doc = record.document()
        expected = dict(schema_version="source_admission.v1", **material(case_id="案例"))
        raw = json.dumps(expected, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(record.admission_id, hashlib.sha256(raw).hexdigest())
        self.assertEqual(doc, expected | {"admission_id": record.admission_id})
        self.assertEqual(self.Admission.from_document(doc), record)
        with self.assertRaises(FrozenInstanceError):
            record.role = "bootstrap"
        doc["case_id"] = "changed"
        self.assertEqual(record.case_id, "案例")

    def test_all_material_fields_contribute_to_identity(self):
        first = self.Admission.create(**material())
        changes = dict(case_id="case-b", case_index=1, source_id="other-source",
                       path_id="other-path", direction="IP_TO_CPU", component="uart",
                       action_id="other-action", role="fixed_support", input_kind="source_event",
                       input_sha256="b" * 64)
        for name, value in changes.items():
            with self.subTest(field=name):
                self.assertNotEqual(first.admission_id,
                                    self.Admission.create(**material(**{name: value})).admission_id)

    def test_rejects_invalid_fields_before_record_creation(self):
        for name in material():
            bad_values = (-1, True, 0.0, "0", None) if name == "case_index" else ("", " ", None, 5, True)
            for value in bad_values:
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        self.Admission.create(**material(**{name: value}))
        for name, values in dict(role=("source", "FUZZ_SOURCE"),
                                 input_kind=("bytes", "Instruction"),
                                 direction=("cpu_to_ip", "unknown"),
                                 input_sha256=("A" * 64, "a" * 63, "g" * 64, "a" * 64 + "\n")).items():
            for value in values:
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        self.Admission.create(**material(**{name: value}))

    def test_all_roles_kinds_and_directions_are_valid(self):
        from myfuzz.scenario.genome import DIRECTIONS
        for role in ("fuzz_source", "fixed_support", "bootstrap"):
            for kind in ("instruction", "source_event"):
                for direction in DIRECTIONS:
                    self.Admission.create(**material(role=role, input_kind=kind, direction=direction))

    def test_constructor_and_loader_reject_forged_identity(self):
        record = self.Admission.create(**material())
        with self.assertRaises(ValueError):
            self.Admission(admission_id="0" * 64, **material())
        for change in ({"admission_id": "0" * 64}, {"role": "bootstrap"}):
            with self.assertRaises(ValueError):
                self.Admission.from_document(record.document() | change)

    def test_loader_requires_exact_document_shape(self):
        doc = self.Admission.create(**material()).document()
        for bad in (None, [], doc | {"unknown": 1}, doc | {"schema_version": "source_admission.v2"}):
            with self.assertRaises(ValueError):
                self.Admission.from_document(bad)
        for key in doc:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.Admission.from_document({k: v for k, v in doc.items() if k != key})

    def test_registry_register_is_idempotent_and_conflicts_leave_it_unchanged(self):
        registry = self.Registry()
        first = self.Admission.create(**material())
        self.assertIs(registry.register(first), first)
        copy = self.Admission.from_document(first.document())
        self.assertIs(registry.register(copy), first)
        before = registry.document()
        with self.assertRaises(ValueError):
            registry.register(self.Admission.create(**material(role="bootstrap")))
        with self.assertRaises(ValueError):
            registry.register(first.document())
        self.assertEqual(registry.document(), before)
        self.assertIs(registry.get(first.action_id), first)
        self.assertIsNone(registry.get("unknown"))

    def test_resolve_deduplicates_sorts_and_rejects_unknown_without_mutating(self):
        registry = self.Registry()
        records = [self.Admission.create(**material(action_id=name)) for name in ("z", "a", "m")]
        for record in records:
            registry.register(record)
        expected = tuple(sorted(records, key=lambda record: record.admission_id))
        self.assertEqual(registry.resolve(iter(("m", "z", "m", "a"))), expected)
        self.assertEqual(registry.resolve(()), ())
        before = registry.document()
        for bad in (("z", "unknown"), ("z", ""), (True,), "z", None):
            with self.assertRaises(ValueError):
                registry.resolve(bad)
        self.assertEqual(registry.document(), before)
        for bad in ("", " ", True, None):
            with self.assertRaises(ValueError):
                registry.get(bad)

    def test_registry_document_roundtrip_preserves_registration_order(self):
        registry = self.Registry()
        records = [self.Admission.create(**material(action_id=name)) for name in ("z", "a")]
        for record in records:
            registry.register(record)
        expected = {"schema_version": "source_admission_registry.v1",
                    "admissions": [record.document() for record in records]}
        self.assertEqual(registry.document(), expected)
        loaded = self.Registry.from_document(expected)
        self.assertEqual(loaded.document(), expected)
        expected["admissions"].clear()
        self.assertEqual(len(registry.document()["admissions"]), 2)
        self.assertEqual(len(loaded.document()["admissions"]), 2)

    def test_registry_loader_rejects_duplicate_and_noncanonical_rows(self):
        record = self.Admission.create(**material()).document()
        base = {"schema_version": "source_admission_registry.v1", "admissions": [record]}
        bads = (None, [], base | {"extra": 1}, {"admissions": []},
                base | {"schema_version": "source_admission_registry.v2"},
                base | {"admissions": (record,)}, base | {"admissions": [record, record]},
                base | {"admissions": [record, record | {"role": "bootstrap"}]})
        for bad in bads:
            with self.assertRaises(ValueError):
                self.Registry.from_document(bad)

    def test_registry_loader_rejects_conflicting_valid_duplicate_actions(self):
        first = self.Admission.create(**material())
        conflicting = self.Admission.create(**material(role="bootstrap"))
        with self.assertRaises(ValueError):
            self.Registry.from_document({"schema_version": "source_admission_registry.v1",
                                         "admissions": [first.document(), conflicting.document()]})
        empty = {"schema_version": "source_admission_registry.v1", "admissions": []}
        self.assertEqual(self.Registry.from_document(empty).document(), empty)


if __name__ == "__main__":
    unittest.main()
