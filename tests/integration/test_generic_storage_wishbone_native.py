"""G8.1 armed native gate: the WBUART SETUP Wishbone storage row.

All checks read archived real evidence under ``runs/generic-runtime/G8``.  The
gate is armed with ``MYFUZZ_RUN_GENERIC_NATIVE=1``; without it every test is
skipped, and a skip is not a pass.

What is checked:

* one persistent three-case F4 Wishbone campaign and one fresh process drive
  the same plan bytes, with disjoint PIDs, certified four-state evidence and a
  replay match;
* the write history is persistent across cases (0x19 -> 0x55 -> 0x2a ->
  0x12345678) and every certificate carries eight instruction hops, two data
  hops and the result RAM write;
* the certificate is a Wishbone document: it names native Wishbone samples and
  never borrows an APB/OBI identity;
* the saved bundle pair verifies and the real-bundle tamper classes are
  refused;
* the APB/OBI storage paths are still live (their archived gates pass, which
  the caller runs separately) and the shared adapter/kernel files that must not
  change for this row are frozen by digest.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
G8 = ROOT / "runs/generic-runtime/G8"
EVIDENCE = G8 / "wishbone-F4-final"
VERIFICATION = G8 / "verification/wishbone-pair.json"
TAMPER = G8 / "tamper/work/tamper-report.json"
FREEZE = G8 / "G8.1-shared-core-freeze.json"

pytestmark = pytest.mark.skipif(
    os.environ.get("MYFUZZ_RUN_GENERIC_NATIVE") != "1",
    reason="real native G8.1 Wishbone gate; set MYFUZZ_RUN_GENERIC_NATIVE=1 "
           "after recording runs/generic-runtime/G8/wishbone-F4-final")


def _load(path: Path):
    assert path.is_file(), f"missing archived G8.1 evidence: {path}"
    return json.loads(path.read_text())


def _campaign(mode: str) -> dict:
    return _load(EVIDENCE / mode / "campaign.json")


def _plan_bytes(mode: str) -> bytes:
    return (EVIDENCE / mode / "execution_plan.json").read_bytes()


def _audit(mode: str) -> dict:
    return _load(EVIDENCE / mode / "execution_audit.json")


def test_three_case_persistent_certified_and_complete_fresh():
    original = _campaign("original")
    fresh = _campaign("fresh")
    assert _plan_bytes("original") == _plan_bytes("fresh")
    for label, campaign in (("original", original), ("fresh", fresh)):
        assert [case["status"] for case in campaign["cases"]] == [
            "effective"] * 3, label
        assert campaign["case_count"] == 3, label
        for case in campaign["cases"]:
            assert case["evidence"], (label, case["case_index"])
            primary = [row for row in case["evidence"]
                       if row.get("native_refs")][0]
            results = dict(primary["obligation_results"])
            assert set(results) == {
                "component_semantic_effect", "cross_component_consumption",
                "cross_component_source", "physical_protocol_sample"}, label
            assert all(status == "certified" for status in results.values()), (
                label, case["case_index"], results)
            assert primary["status"] == "certified", label
            assert len(primary["native_refs"]) == 4, label
            assert len(primary["source_refs"]) == 4, label
    original_pids = {name: row["pid"] for name, row in
                     _audit("original")["identities"].items()}
    fresh_pids = {name: row["pid"] for name, row in
                  _audit("fresh")["identities"].items()}
    assert set(original_pids) == set(fresh_pids) == {"processor", "peripheral"}
    assert not set(original_pids.values()) & set(fresh_pids.values())
    for name in original_pids:
        assert original_pids[name] > 0 and fresh_pids[name] > 0


def test_persistent_version_chain_and_exact_hops():
    expected = [0x19, 0x55, 0x2a, 0x12345678]
    for mode in ("original", "fresh"):
        # Each process starts from the measured reset value, so the chain
        # restarts at 0x19 for the fresh reproduction.
        previous = None
        campaign = _campaign(mode)
        for index, case in enumerate(campaign["cases"]):
            certificate = case["records"][0]["certificate"]
            before, after = certificate["prerequisite"], certificate["postcondition"]
            assert before["value"] == expected[index], (mode, index)
            assert after["value"] == expected[index + 1], (mode, index)
            assert before["write_count"] == index, (mode, index)
            assert after["write_count"] == index + 1, (mode, index)
            assert after["field_version"] == after["write_count"], (mode, index)
            assert after["register"] == "SETUP"
            assert after["grants_reset_prerequisite"] is False
            assert after["routed_context_authenticated"] is False
            # The stable certificate projection carries no process-local
            # identity: the same artifact, source contract and probe must hold
            # across the whole chain.
            for key in ("artifact_digest", "source_contract_digest",
                        "probe_digest", "version_basis", "history_scope"):
                assert before[key] == after[key], (mode, index, key)
            assert before["reset_epoch"] == after["reset_epoch"] == 0
            assert before["reset_waveform_observed"] is False
            assert after["reset_waveform_observed"] is False
            commit = certificate["commit"]
            assert commit["write_count"] == index + 1, (mode, index)
            assert commit["before"] == expected[index], (mode, index)
            assert commit["after"] == expected[index + 1], (mode, index)
            if previous is not None:
                assert before["value"] == previous["value"], (mode, index)
                assert before["write_count"] == previous["write_count"]
            previous = after
            hops = certificate["exact_hops"]
            assert len(hops["instruction_hops"]) == 8, (mode, index)
            assert len(hops["data_hops"]) == 2, (mode, index)
            assert hops["proof_scope"] == (
                "selected_F4_image_consumption_native_wishbone_route_native_"
                "wishbone_storage_and_CPU_readback_RAM")
            ram = hops["ram_write_hop"]
            assert ram["address"] == 0x2FFFC, (mode, index)
            assert ram["value"] == expected[index + 1]
            assert ram["byte_enable"] == 15
            assert [edge["relation"] for edge in hops["edges"]] == [
                "persistent_state", "mmio_route"]
            assert all(edge["status"] == "certified" for edge in hops["edges"])
            joins = certificate["joins"]
            assert [join["write"] for join in joins] == [True, False]
            assert joins[0]["native_wishbone_event"] < joins[0]["native_ack_event"]
            assert joins[1]["native_wishbone_event"] < joins[1]["native_ack_event"]


def test_certificate_is_a_wishbone_document():
    campaign = _campaign("original")
    text = json.dumps(campaign, sort_keys=True)
    assert "compiled_F4_wishbone_chain.v1" in text
    assert "native_APB_event" not in text
    assert "native_obi" not in text
    assert "apb-storage:" not in text
    for case in campaign["cases"]:
        certificate = case["records"][0]["certificate"]
        assert certificate["schema_version"] == "compiled_F4_wishbone_chain.v1"
        assert certificate["status"] == "certified"
        assert certificate["runtime_admitted"] is True
        token = certificate["token"]
        assert token["consumed"] is True and token["single_use"] is True
        assert token["opaque"] is True
        assert token["issuer"].endswith("WishboneStorageRegisterVersionAuthority")


def test_saved_bundle_pair_verified_and_tamper_classes_refused():
    verification = _load(VERIFICATION)
    assert verification["verdict"] == "verified", verification.get("refusal")
    assert verification["case_count"] == 3
    assert len(verification["checks"]) == 52
    assert all(row["status"] == "verified" for row in verification["checks"])
    assert len(verification["bundle_ids"]) == 2
    assert verification["bundle_ids"][0] != verification["bundle_ids"][1]
    assert (EVIDENCE / "bundle-original").is_dir()
    assert (EVIDENCE / "bundle-fresh").is_dir()
    tamper = _load(TAMPER)
    assert tamper["pristine_verdict"] == "verified"
    assert tamper["pristine_fresh_verified"] in (True, "verified")
    assert tamper["all_refused"] is True
    rows = tamper["tampers"]
    assert len(rows) == 8
    for row in rows:
        assert row["ok"] is True, row["label"]
        assert row["refused"] is True, row["label"]
        assert row["code"].startswith("saved-"), row["label"]


def test_shared_core_freeze_holds():
    freeze = _load(FREEZE)
    assert freeze["schema_version"] == "g8_1_shared_core_freeze.v1"
    files = freeze["files"]
    assert files, "freeze must record the shared APB/OBI files"
    for name in (
        "src/myfuzz/local_harness/apb3_register_session.py",
        "src/myfuzz/scenario/apb_storage_register_version.py",
        "src/myfuzz/integration/generated_storage_consumer.py",
        "src/myfuzz/integration/compiled_f4.py",
        "src/myfuzz/scenario/register_source_access.py",
        "src/myfuzz/integration/generated_register_writer.py",
        "src/myfuzz/local_harness/native_reset_producer_contract.py",
    ):
        assert name in files, name
        import hashlib
        live = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        assert live == files[name], name
