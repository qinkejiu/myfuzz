from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from myfuzz.contracts import ContractError, content_hash, validate_contract
from myfuzz.integration.manifest import (
    load_and_validate,
    manifest_content_hash,
    merge_candidate_manifest,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/contracts/candidate_manifest.v1.valid.json"
_HASH = "sha256:" + "1" * 64

READY_FRAGMENT = {
    "candidate_id": "candidate-000",
    "composition_ir_hash": "sha256:" + "0" * 64,
    "input_manifest_hash": "__INPUT_HASH__",
    "harnesses": {
        "flat-direct": [{"content_hash": _HASH}],
        "candidate-direct": [{"content_hash": "sha256:" + "2" * 64}],
        "candidate-depaware": [{"content_hash": "sha256:" + "3" * 64}],
    },
    "raw_bit_mappings": {
        "flat-direct": [],
        "candidate-direct": [],
        "candidate-depaware": [],
    },
    "runtime": {
        "status": "ready",
        "peak_rss_bytes": 1_000_000,
        "validation": {"compile": "passed", "smoke": "passed"},
    },
}


def _base() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ManifestJoinTests(unittest.TestCase):
    def test_loader_detaches_and_validates_document(self) -> None:
        loaded = load_and_validate(FIXTURE, "candidate_manifest.v1")
        loaded["candidate_id"] = "mutated"
        self.assertEqual(json.loads(FIXTURE.read_text())["candidate_id"], "candidate-000")

    def test_merge_requires_all_groups_and_is_deterministic(self) -> None:
        base = _base()
        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        merged = merge_candidate_manifest(base, fragment)

        self.assertEqual(merged["lifecycle"], "runtime_ready")
        self.assertEqual(set(merged["harnesses"]), {
            "flat-direct", "candidate-direct", "candidate-depaware",
        })
        validate_contract(merged, "candidate_manifest.v1")
        reversed_base = dict(reversed(list(base.items())))
        reversed_fragment = dict(reversed(list(fragment.items())))
        self.assertEqual(merged, merge_candidate_manifest(reversed_base, reversed_fragment))
        self.assertEqual(manifest_content_hash(merged), manifest_content_hash(dict(merged)))

    def test_pending_runtime_does_not_claim_runtime_ready(self) -> None:
        base = _base()
        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        fragment["runtime"]["status"] = "pending"
        fragment["runtime"]["validation"]["compile"] = "pending"
        fragment["runtime"]["validation"]["smoke"] = "pending"
        merged = merge_candidate_manifest(base, fragment)
        self.assertEqual(merged["lifecycle"], "top_validated")

    def test_missing_group_and_hash_mismatch_fail(self) -> None:
        base = _base()
        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        del fragment["harnesses"]["candidate-depaware"]
        with self.assertRaisesRegex(ContractError, "missing-required-group"):
            merge_candidate_manifest(base, fragment)

        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        fragment["composition_ir_hash"] = _HASH
        with self.assertRaisesRegex(ContractError, "composition_ir_hash:mismatch"):
            merge_candidate_manifest(base, fragment)

    def test_empty_array_or_object_harness_group_is_incomplete(self) -> None:
        base = _base()
        for empty_value in ([], {}):
            fragment = copy.deepcopy(READY_FRAGMENT)
            fragment["input_manifest_hash"] = content_hash(base)
            fragment["harnesses"]["candidate-direct"] = empty_value
            with self.subTest(empty_value=empty_value), self.assertRaisesRegex(
                ContractError,
                "incomplete-required-group",
            ):
                merge_candidate_manifest(base, fragment)

    def test_candidate_mismatch_and_untrusted_fragment_fields_fail(self) -> None:
        base = _base()
        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        fragment["candidate_id"] = "other"
        with self.assertRaisesRegex(ContractError, "candidate_id:mismatch"):
            merge_candidate_manifest(base, fragment)

        fragment = copy.deepcopy(READY_FRAGMENT)
        fragment["input_manifest_hash"] = content_hash(base)
        fragment["top"] = {"module": "attacker"}
        merged = merge_candidate_manifest(base, fragment)
        self.assertEqual(merged["top"], base["top"])


if __name__ == "__main__":
    unittest.main()
