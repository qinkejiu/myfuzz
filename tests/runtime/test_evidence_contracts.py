"""G1: evidence contracts keep the three proof layers and four states separate."""
from __future__ import annotations

import unittest

from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.evidence.contracts import (
    REFUSAL_CODES,
    EdgeClaim,
    EffectEvidence,
    EvidenceRef,
    combine_status,
    merge_obligations,
    parse_evidence_ref,
)
from myfuzz.scenario.ledger import TransactionKey

KEY = TransactionKey("exec-1", "case-1", "peripheral", 0, "peripheral.timer.bus", 4)
SOURCE = EvidenceRef("processor", 11, "cpu_mmio_store")
NATIVE = EvidenceRef("peripheral", 12, "apb_storage_probe")
DESTINATION = EvidenceRef("peripheral", 13, "ip_register_version")


def evidence(*, status="certified", scope="component_semantic_effect",
             refs=None, obligations=(("register_version_issued", "certified"),),
             binding="a" * 64, semantic="b" * 64):
    source_refs, native_refs, destination_refs = refs if refs else (
        (SOURCE,), (NATIVE,), (DESTINATION,))
    return EffectEvidence(KEY, status, scope, binding, semantic, source_refs,
                          native_refs, destination_refs, obligations)


class EvidenceRefTests(unittest.TestCase):
    def test_reference_fields_are_typed(self):
        self.assertEqual({"component": "processor", "event_id": 11,
                          "kind": "cpu_mmio_store"}, SOURCE.document())
        for args in (("", 1, "x"), ("processor", -1, "x"), ("processor", 1, ""),
                     ("processor", True, "x"), ("processor", 1, False)):
            with self.assertRaises(GenericRuntimeRefused):
                EvidenceRef(*args)

    def test_closed_parse(self):
        with self.assertRaises(GenericRuntimeRefused):
            parse_evidence_ref({"component": "cpu"})
        with self.assertRaises(GenericRuntimeRefused):
            parse_evidence_ref({"component": "cpu", "event_id": 0, "kind": "k",
                                "unexpected": 0})


class StatusPriorityTests(unittest.TestCase):
    def test_priority_order(self):
        self.assertEqual("contradicted",
                         combine_status(("certified", "contradicted", "missing")))
        self.assertEqual("missing", combine_status(("certified", "missing")))
        self.assertEqual("unsupported", combine_status(("certified", "unsupported")))
        self.assertEqual("certified", combine_status(("certified",)))
        self.assertEqual("missing", combine_status(()))

    def test_unknown_status_rejected(self):
        for value in (("certified", "success"), ("failed",)):
            with self.assertRaises(GenericRuntimeRefused):
                combine_status(value)
        with self.assertRaises(GenericRuntimeRefused):
            combine_status("certified")

    def test_merge_obligations_is_order_independent_and_conflict_fails(self):
        first = (("a", "certified"), ("b", "missing"))
        second = (("b", "contradicted"), ("c", "unsupported"))
        merged = merge_obligations(first, second)
        self.assertEqual((("a", "certified"), ("b", "contradicted"),
                          ("c", "unsupported")), merged)
        self.assertEqual(merged, merge_obligations(second, first))
        self.assertEqual(first, merge_obligations(first, first))


class EffectEvidenceTests(unittest.TestCase):
    def test_certified_evidence_shape(self):
        document = evidence().document()
        self.assertEqual("certified", document["status"])
        self.assertEqual("component_semantic_effect", document["scope"])
        self.assertEqual([["register_version_issued", "certified"]],
                         document["obligation_results"])
        self.assertEqual(64, len(evidence().sha256()))

    def test_certified_requires_every_obligation_certified(self):
        with self.assertRaises(GenericRuntimeRefused) as caught:
            evidence(obligations=(("register_version_issued", "certified"),
                                  ("native_issuer_consumed", "missing")))
        self.assertEqual("generic-contract-shape", caught.exception.code)
        self.assertEqual("/status", caught.exception.pointer)

    def test_unknown_status_and_scope_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            evidence(status="passed")
        with self.assertRaises(GenericRuntimeRefused):
            evidence(scope="retirement")
        with self.assertRaises(GenericRuntimeRefused):
            evidence(scope="irq_success")

    def test_duplicate_refs_and_obligation_names_rejected(self):
        with self.assertRaises(GenericRuntimeRefused) as caught:
            evidence(refs=((SOURCE, SOURCE), (NATIVE,), (DESTINATION,)))
        self.assertEqual("generic-contract-duplicate", caught.exception.code)
        with self.assertRaises(GenericRuntimeRefused):
            evidence(obligations=(("x", "certified"), ("x", "certified")))
        with self.assertRaises(GenericRuntimeRefused):
            evidence(obligations=(("x", "missing"), ("x", "contradicted")))

    def test_refs_must_be_immutable_tuples_of_refs(self):
        with self.assertRaises(GenericRuntimeRefused):
            evidence(refs=([SOURCE], (NATIVE,), (DESTINATION,)))
        with self.assertRaises(GenericRuntimeRefused):
            evidence(obligations=[("x", "certified")])

    def test_bool_ticks_and_digests_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            evidence(binding="A" * 64)
        with self.assertRaises(GenericRuntimeRefused):
            evidence(semantic="b" * 63)

    def test_missing_and_unsupported_are_distinct(self):
        missing = evidence(status="missing", obligations=(("x", "missing"),))
        unsupported = evidence(status="unsupported",
                               obligations=(("x", "unsupported"),))
        self.assertNotEqual(missing.document()["status"],
                            unsupported.document()["status"])
        self.assertEqual("unsupported", unsupported.document()["status"])

    def test_edge_claim_document(self):
        claim = EdgeClaim(KEY, "certified", "cross_component_consumption",
                          (SOURCE,), (NATIVE,), (DESTINATION,),
                          (("consumed_once", "certified"),))
        document = claim.document()
        self.assertEqual({
            "key", "status", "scope", "source_refs", "native_refs",
            "destination_refs", "obligation_results"}, set(document))
        self.assertEqual("cpu_mmio_store", document["source_refs"][0]["kind"])
        with self.assertRaises(GenericRuntimeRefused):
            EdgeClaim(KEY, "ok", "cross_component_consumption", (), (), (), ())


class RefusalCodeTests(unittest.TestCase):
    def test_reference_codes_present(self):
        for code in (
            "generic-source-unverified",
            "generic-semantic-unsupported",
            "generic-template-mismatch",
            "generic-adapter-missing",
            "generic-adapter-ambiguous",
            "generic-binding-drift",
            "generic-plan-mismatch",
            "generic-route-refused",
            "generic-evidence-missing",
        ):
            self.assertIn(code, REFUSAL_CODES)


if __name__ == "__main__":
    unittest.main()
