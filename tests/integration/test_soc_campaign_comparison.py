import unittest

from myfuzz.integration.soc_comparison import (
    SocComparisonError, compare_soc_campaign_arms,
)


def report(arm, *, layout="sha256:layout", composition="sha256:composition",
           audit="pass", tests=10, projected=10, unique=8):
    return {
        "config_id": "comparison",
        "cell_id": "cell",
        "final_status": "passed",
        "artifact": {
            "composition_hash": composition,
            "layout_hash": layout,
            "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
            "structure_audit": {"status": audit},
        },
        "rtl_execution": {"tests": tests, "coverage_records": tests,
                           "execution_totals": {"cycles": tests * 4}},
        "effective_fuzz_seconds": 2,
        "corpus": {"status": "verified", "entries": tests},
        "input_projection": {"raw_samples": tests, "projected_samples": projected,
                              "projected_unique": unique,
                              "repair_counts": {"address_repair": 1 if arm == "dependency_repair" else 0}},
        "source_target_transactions": {"status": "observed",
                                        "source": {"requests": tests},
                                        "target": {"completions": tests}},
    }


class CampaignComparisonTests(unittest.TestCase):
    def test_three_arms_are_compared_under_one_identity(self):
        result = compare_soc_campaign_arms({name: report(name) for name in (
            "direct_input", "constrained_baseline", "dependency_repair")})
        self.assertEqual("soc_campaign_comparison.v1", result["schema_version"])
        self.assertEqual("valid", result["comparison"]["status"])
        self.assertEqual(3, len(result["metrics"]))
        self.assertEqual("not-claimed", result["comparison"]["component_bug_claim"])

    def test_missing_arm_is_not_silently_treated_as_zero(self):
        result = compare_soc_campaign_arms(
            {"direct_input": report("direct_input")}, require_complete=False)
        self.assertEqual("incomplete", result["comparison"]["status"])
        self.assertEqual({"constrained_baseline", "dependency_repair"},
                         set(result["missing_arms"]))

    def test_identity_mismatch_is_rejected(self):
        arms = {name: report(name) for name in (
            "direct_input", "constrained_baseline", "dependency_repair")}
        arms["dependency_repair"] = report("dependency_repair", layout="sha256:other")
        with self.assertRaisesRegex(SocComparisonError, "identity-mismatch:layout_hash"):
            compare_soc_campaign_arms(arms)

    def test_structure_audit_failure_is_rejected(self):
        arms = {name: report(name) for name in (
            "direct_input", "constrained_baseline", "dependency_repair")}
        arms["direct_input"] = report("direct_input", audit="fail")
        with self.assertRaisesRegex(SocComparisonError, "structure-audit-not-passed"):
            compare_soc_campaign_arms(arms)


if __name__ == "__main__":
    unittest.main()
