"""G5: feedback comes from observed checker/edge evidence, never expected values.

The claims below are produced by the real capture path over structural (fake)
certificates: no expected value of a case enters the feedback signal, the
values stay inside the declared candidate layout, and encoding them reuses the
flow's unchanged wire record.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from myfuzz.runtime.campaign import (
    CampaignBudget,
    RfuzzDirectedAdapter,
    run_directed_campaign,
)
from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.engine import PersistentCampaignRuntime
from myfuzz.runtime.flows.storage import (
    DEFAULT_FEEDBACK_VALUES,
    StorageFlowBackend,
    StorageFlowKernel,
)
from myfuzz.integration.compiled_candidate_layout import (
    compile_candidate_layout,
)
from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout

from tests.runtime.test_persistent_engine import (
    FakePersistentRuntime,
    _engine,
    _world,
    raw_of,
)
from tests.runtime.test_storage_kernel import (
    FakeScenarioSession,
    directed_case,
    directed_sequence,
    f2_certificate,
    f4_certificate,
    prepared_context,
)

MUTATE = "timer0.TIMER0_CTRL.CTRL.value"
ADDRESS = "timer0.TIMER0_CTRL.CTRL.address"


def _layout_path(context):
    """The declared layout path the kernel compiled (documentary form only)."""
    document = context.document()
    layout = context.layout
    rows = getattr(layout, "slices", None)
    if rows is None:
        return compile_f2_candidate_layout, layout
    return compile_candidate_layout, layout


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        (self.kernel, self.context, self.bound, self.runner, self.log,
         self.path) = prepared_context("F4")

    def claims(self, **kwargs):
        certificate = f4_certificate(self.log, **kwargs)
        return self.kernel.capture(self.context, certificate)

    def test_feedback_is_deterministic_and_bounded(self):
        claims = self.claims(value=0x12345678)
        first = self.kernel.feedback(self.context, claims)
        second = self.kernel.feedback(self.context, claims)
        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertLessEqual(len(first), DEFAULT_FEEDBACK_VALUES)
        domain = self.context.domains[0]
        for value in first:
            self.assertEqual(type(value), int)
            self.assertGreaterEqual(value, domain.minimum)
            self.assertLessEqual(value, domain.maximum)
            self.assertEqual(0, value % domain.alignment)
        self.assertEqual(len(set(first)), len(first))

    def test_feedback_ignores_expected_values(self):
        certificate = f4_certificate(self.log, value=0x1234)
        baseline = self.kernel.capture(self.context, certificate)
        perturbed = deepcopy(certificate)
        perturbed["expected_value"] = 0xDEADBEEF
        perturbed["expected"] = {"value": 0xDEADBEEF, "transaction": "expected"}
        perturbed["prerequisite"]["expected"] = 0xDEADBEEF
        perturbed["postcondition"]["expected"] = 0xDEADBEEF
        compared = self.kernel.capture(self.context, perturbed)
        self.assertEqual(
            [claim.canonical_bytes() for claim in baseline],
            [claim.canonical_bytes() for claim in compared])
        self.assertEqual(self.kernel.feedback(self.context, baseline),
                         self.kernel.feedback(self.context, compared))
        for claim in compared:
            self.assertNotIn("expected_value", claim.document())
            self.assertNotIn("expected", claim.document())

    def test_feedback_changes_when_observed_edges_change(self):
        certificate = f4_certificate(self.log, value=0x1234)
        baseline = self.kernel.capture(self.context, certificate)
        shifted = deepcopy(certificate)
        extra = self.log.add("timer0", "apb_storage_sample_post")
        shifted["joins"][0]["native_post_event"] = extra
        compared = self.kernel.capture(self.context, shifted)
        self.assertEqual("certified", compared[0].status)
        self.assertNotEqual(
            [claim.canonical_bytes() for claim in baseline],
            [claim.canonical_bytes() for claim in compared])
        self.assertNotEqual(self.kernel.feedback(self.context, baseline),
                            self.kernel.feedback(self.context, compared))

    def test_no_claims_yield_no_inputs(self):
        self.assertEqual((), self.kernel.feedback(self.context, ()))

    def test_single_valued_domain_invents_nothing(self):
        (kernel, context, _, _, log, _) = prepared_context("F2")
        certificate = f2_certificate(log, value=0x31)
        claims = kernel.capture(context, certificate)
        self.assertTrue(claims)
        self.assertEqual(1, context.domains[0].steps)
        self.assertEqual((), kernel.feedback(context, claims))

    def test_feedback_requires_claim_members(self):
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.feedback(self.context, (object(),))
        self.assertEqual("generic-contract-type", raised.exception.code)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.feedback(self.context, "not-a-sequence")
        self.assertEqual("generic-contract-type", raised.exception.code)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        (self.kernel, self.context, self.bound, self.runner, self.log,
         self.path) = prepared_context("F4")
        self.runtime = FakePersistentRuntime(self.runner, FakeScenarioSession())
        self.engine = PersistentCampaignRuntime(
            self.bound, kernel=self.kernel,
            channel=StorageFlowBackend(runtime=self.runtime,
                                       flow_id="F4").open(),
            path_id=self.path["path_id"], run_id="campaign", max_cases=4)
        self.adapter = RfuzzDirectedAdapter(kernel=self.kernel,
                                            context=self.context,
                                            mutate_source_id=MUTATE)

    def test_encoded_records_keep_the_flow_wire_interpretation(self):
        compiler, layout = _layout_path(self.context)
        self.assertEqual(4, self.context.record_length)
        value = 0x0A0B0C0D
        raw = self.adapter.encode(value)
        self.assertEqual(4, len(raw))
        decoded = layout.decode(raw)
        self.assertEqual({MUTATE: value}, decoded)
        self.assertEqual(value, int.from_bytes(raw, "little"))
        # Re-preparing the same declared facts yields the same layout object
        # value; the kernel never invents a second wire interpretation.
        again = self.kernel.prepare(self.bound, self.path["path_id"])
        self.assertEqual(layout.digest, again.layout.digest)
        self.assertEqual(self.context.layout_document,
                         again.layout_document)
        self.assertEqual(4, self.adapter.document()["wire_record_bytes"])

    def test_propose_uses_feedback_and_stays_in_the_declared_domain(self):
        claims = self.kernel.capture(self.context,
                                     f4_certificate(self.log, value=0x40))
        proposed = self.adapter.propose(claims)
        self.assertTrue(proposed)
        domain = self.context.domains[0]
        for value, raw in proposed:
            self.assertGreaterEqual(value, domain.minimum)
            self.assertLessEqual(value, domain.maximum)
            self.assertEqual(value, self.context.layout.decode(raw)[MUTATE])

    def test_adapter_runs_feedback_derived_cases_on_the_live_campaign(self):
        self.engine.start()
        self.engine.submit(directed_case("case-a", records=(raw_of(0x11),)))
        before = self.runtime.submit_calls
        results = self.adapter.run(self.engine, limit=2)
        self.assertEqual(2, len(results))
        self.assertEqual(before + 2, self.runtime.submit_calls)
        proposed = [row["value"] for row in self.adapter.cases]
        self.assertEqual(len(set(proposed)), len(proposed))
        # New certified evidence changes the feedback signal, so the next
        # proposal is a further value -- never a repeat of an effected one.
        again = self.adapter.run(self.engine, limit=1)
        self.assertEqual(1, len(again))
        self.assertNotIn(again[0]["raw_records_hex"][0],
                         [row["raw_hex"] for row in self.adapter.cases[:-1]])
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.adapter.run(self.engine, limit=1)
        self.assertEqual("generic-budget-refused", raised.exception.code)
        self.assertEqual("RUNNING", self.engine.state)
        report = self.engine.finish()
        self.assertEqual(4, len(report["cases"]))
        self.assertTrue(all(row["status"] == "effective"
                            for row in report["cases"]))
        self.assertEqual(4, len({row["records"][0]["certificate"]["case_id"]
                                 for row in report["cases"]}))
        self.assertEqual(3, len(self.adapter.used))
        values = [row["value"] for row in self.runtime.records]
        self.assertEqual(len(set(values)), len({value for value in values}))

    def test_adapter_refuses_an_undeclared_mutation_source(self):
        with self.assertRaises(GenericRuntimeRefused) as raised:
            RfuzzDirectedAdapter(kernel=self.kernel, context=self.context,
                                 mutate_source_id="timer0.NOT_DECLARED.value")
        self.assertEqual("generic-source-unverified", raised.exception.code)


class CampaignFeedbackTests(unittest.TestCase):
    def test_campaign_report_records_evidence_and_software_only_scope(self):
        bound, runner, log, plan_path = _world()
        runtime = FakePersistentRuntime(runner, FakeScenarioSession())
        backend = StorageFlowBackend(runtime=runtime, flow_id="F4")
        sequence = directed_sequence(
            directed_case("case-a", records=(raw_of(0x11),)),
            directed_case("case-b", records=(raw_of(0x22),)),
            plan_sha256=bound.plan_sha256)
        report = run_directed_campaign(
            bound_plan=bound, backend=backend, sequence=sequence,
            budget=CampaignBudget(max_cases=4))
        self.assertIsNone(report["software_only"])
        self.assertEqual(2, report["sequence_case_count"])
        self.assertEqual(4, report["evidence_count"])
        for row in report["evidence"]:
            self.assertIn("obligation_results", row)
            self.assertIn(row["status"],
                          ("certified", "missing", "contradicted",
                           "unsupported"))
        self.assertNotIn("native_token", str(report["native_certification"]))
        self.assertFalse(report["native_certification"]["claimed"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
