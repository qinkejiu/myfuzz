"""G6 first-slice real gate for the generic APB storage runtime.

Every check below is made against archived real native evidence.  Software
fixtures, skips and re-sealed forgeries are not accepted:

* two registered source contracts each run one persistent three-case F4
  campaign (write + CPU readback per case) and one fresh process with identical
  plan bytes, new PIDs and matching in-process replay;
* each case's four-state evidence is ``certified`` with every obligation
  certified;
* a renamed instance runs independently with the same adapter selection and a
  different identity digest;
* a real non-alias register offset is refused before any session effect;
* the saved ``generic_runtime_bundle.v1`` original/fresh pair verifies, and
  eight tamper classes on the real bundle are refused.

Arm with ``MYFUZZ_RUN_GENERIC_NATIVE=1``.  Without the switch the test is
skipped with an explicit reason; a skip is not a pass.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
G6 = ROOT / "runs/generic-runtime/G6"
SOURCES = ("timer", "spi")

pytestmark = pytest.mark.skipif(
    os.environ.get("MYFUZZ_RUN_GENERIC_NATIVE") != "1",
    reason="real native generic-storage gate; set MYFUZZ_RUN_GENERIC_NATIVE=1 "
           "after recording runs/generic-runtime/G6/*-F4-final")

sys.path.insert(0, str(ROOT / "src"))


def _load(path: Path):
    assert path.is_file(), f"missing archived evidence: {path}"
    return json.loads(path.read_text())


def _campaign(root: Path, mode: str) -> dict:
    return _load(root / mode / "campaign.json")


def _summary(root: Path, mode: str) -> dict:
    return _load(root / mode / "summary.json")


def _plan(root: Path, mode: str) -> bytes:
    return (root / mode / "execution_plan.json").read_bytes()


def _case_root(source: str) -> Path:
    return G6 / f"{source}-F4-final"


def _assert_certified(campaign: dict, label: str) -> None:
    assert [case["status"] for case in campaign["cases"]] == [
        "effective"] * 3, label
    for case in campaign["cases"]:
        assert case["evidence"], (label, case["case_index"])
        for item in case["evidence"]:
            assert item["status"] == "certified", (
                label, case["case_index"], item["status"],
                item["obligation_results"], item["source_refs"],
                item["native_refs"], item["destination_refs"])
            assert all(status == "certified"
                       for _, status in item["obligation_results"]), label


def _assert_persistent_chain(campaign: dict, label: str) -> None:
    previous = None
    for case in campaign["cases"]:
        certificate = case["records"][0]["certificate"]
        before = certificate["prerequisite"]
        after = certificate["postcondition"]
        if previous is not None:
            assert before["value"] == previous["value"], (
                label, case["case_index"], "previous write not observed")
            assert before["write_count"] == previous["write_count"], label
            assert before["command_sequence"] == previous["command_sequence"], label
        assert after["write_count"] == before["write_count"] + 1, label
        assert after["command_sequence"] > before["command_sequence"], label
        previous = after


def _reseal(bundle: Path, relative: str) -> None:
    from myfuzz.runtime.contracts import canonical_json_bytes
    import hashlib
    manifest = _load(bundle / "bundle.json")
    for row in manifest["files"]:
        if row["path"] == relative:
            row["sha256"] = hashlib.sha256(
                (bundle / relative).read_bytes()).hexdigest()
            break
    else:
        raise AssertionError(f"no manifest row for {relative}")
    (bundle / "bundle.json").write_bytes(canonical_json_bytes(manifest))


def _tamper_copy(source: Path, target: Path, relative: str, mutate) -> Path:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    document = _load(target / relative)
    mutate(document)
    (target / relative).write_bytes(
        __import__("myfuzz.runtime.contracts", fromlist=["canonical_json_bytes"])
        .canonical_json_bytes(document))
    _reseal(target, relative)
    return target


def _expect_refused(bundle: Path, codes) -> None:
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    from myfuzz.runtime.evidence.saved import verify_saved_bundle
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_saved_bundle(bundle)
    assert caught.value.code in codes, (caught.value.code, caught.value.detail)


@pytest.mark.parametrize("source", SOURCES)
def test_source_campaign_is_persistent_certified_and_fresh(source):
    root = _case_root(source)
    original = _campaign(root, "original")
    fresh = _campaign(root, "fresh")
    assert _plan(root, "original") == _plan(root, "fresh"), source
    for mode, campaign in (("original", original), ("fresh", fresh)):
        assert campaign["initialization_counts"] == {
            "build": 1, "start": 1, "begin": 1, "init": 1}, (source, mode)
        _assert_certified(campaign, f"{source}:{mode}")
        _assert_persistent_chain(campaign, f"{source}:{mode}")
        assert _summary(root, mode).get("replay_matches") is True
    original_pids = {row["pid"] for row in original["process_identities"].values()}
    fresh_pids = {row["pid"] for row in fresh["process_identities"].values()}
    assert original_pids and fresh_pids
    assert original_pids.isdisjoint(fresh_pids), source
    values = [case["records"][0]["certificate"]["commit"]["after"]
              for case in original["cases"]]
    assert any(values) and len(set(values)) == len(values), (source, values)


def test_two_sources_are_distinct_but_share_the_generic_core():
    declarations = [_load(_case_root(source) / "original" / "declarations.json")
                    for source in SOURCES]
    timer, spi = declarations
    timer_adapter = {(row["adapter_id"], row["adapter_version"])
                     for row in timer["selections"]}
    spi_adapter = {(row["adapter_id"], row["adapter_version"])
                   for row in spi["selections"]}
    assert timer_adapter == spi_adapter == {("apb3.storage.v1", "1"),
                                            ("obi.cpu.v1", "1")}
    target_digests = []
    for declaration in declarations:
        target = next(row for row in declaration["components"]
                      if any(endpoint["role"] == "target"
                             for endpoint in row["endpoints"]))
        target_digests.append((target["instance_id"],
                               target["semantic_contract_sha256"],
                               target["artifact_sha256"]))
    assert target_digests[0][1] != target_digests[1][1], target_digests
    assert target_digests[0][2] != target_digests[1][2], target_digests


def test_renamed_instance_runs_with_the_same_adapter_selection():
    root = G6 / "renamed-timer-F4-final"
    campaign = _campaign(root, "original")
    assert campaign["initialization_counts"]["build"] == 1
    _assert_certified(campaign, "renamed-timer")
    declaration = _load(root / "original" / "declarations.json")
    instances = [row["instance_id"] for row in declaration["components"]]
    assert "timer0" in instances and "processor" not in instances
    timer_declaration = _load(_case_root("timer") / "original" / "declarations.json")
    renamed_selections = {(row["adapter_id"], row["adapter_version"])
                          for row in declaration["selections"]}
    timer_selections = {(row["adapter_id"], row["adapter_version"])
                        for row in timer_declaration["selections"]}
    assert renamed_selections == timer_selections
    renamed_target = next(row for row in declaration["components"]
                          if row["instance_id"] == "timer0")
    timer_target = next(row for row in timer_declaration["components"]
                        if row["instance_id"] == "peripheral")
    assert renamed_target["artifact_sha256"] != timer_target["artifact_sha256"]
    assert (_plan(root, "original")
            != _plan(_case_root("timer"), "original"))



def _mixed_root() -> Path:
    return G6.parent / "mixed/timer-generic"


def test_mixed_f2f4_single_session_reads_the_previous_write():
    root = _mixed_root()
    plans = {}
    pids = {}
    for mode in ("original", "fresh"):
        campaign = _load(root / mode / "campaign.json")
        summary = _load(root / mode / "summary.json")
        assert campaign["initialization_counts"] == {
            "build": 1, "start": 1, "begin": 1, "init": 1}, mode
        assert [case["flow_id"] for case in campaign["cases"]] == [
            "F4", "F2", "F4"], mode
        assert [case["status"] for case in campaign["cases"]] == [
            "effective"] * 3, mode
        for case in campaign["cases"]:
            assert case["evidence"], (mode, case["case_index"])
            for item in case["evidence"]:
                assert item["status"] == "certified", (
                    mode, case["case_index"], item)
                assert all(status == "certified"
                           for _, status in item["obligation_results"])
        f4_first = campaign["cases"][0]["records"][0]["certificate"]
        f2_certificate = campaign["cases"][1]["records"][0]["certificate"]
        write_value = f4_first["commit"]["after"]
        assert f2_certificate["version_before"]["value"] == write_value, mode
        assert f2_certificate["version_witness"]["value"] == write_value, mode
        ram = f2_certificate["exact_hops"]["ram_write_hop"]["value"]
        assert ram == (write_value ^ 0x5A5), mode
        assert summary["replay_matches"] is True, mode
        plans[mode] = (root / mode / "execution_plan.json").read_bytes()
        pids[mode] = {row["pid"] for row in
                      campaign["process_identities"].values()}
    assert plans["original"] == plans["fresh"]
    assert pids["original"] and pids["fresh"]
    assert pids["original"].isdisjoint(pids["fresh"])

def test_real_non_alias_offset_is_refused_before_effect():
    report = _load(G6 / "non-alias-timer" / "refusal.json")
    assert report["verdict"] == "refused-before-effect", report
    refusal = report["non_alias_refusal"]
    assert refusal is not None
    assert refusal["code"] in ("generic-route-refused",
                               "generic-semantic-unsupported"), refusal
    assert report["alias_prepare"]["accepted"] is True
    assert report["native_effect_observed"] is False
    assert report["session_sequence_before"] == report["session_sequence_after"]
    assert report["session_ticks_before"] == report["session_ticks_after"]


@pytest.mark.parametrize("source", SOURCES)
def test_saved_bundle_original_fresh_pair_verifies(source):
    from myfuzz.runtime.evidence.saved import verify_saved_bundle
    root = _case_root(source)
    report = verify_saved_bundle(root / "bundle-original",
                                 fresh_bundle_dir=root / "bundle-fresh")
    assert report["verdict"] == "verified"
    assert report["fresh_verified"] is True
    assert report["case_count"] == 3
    assert report["tampered_refusals"] == []


def test_real_bundle_tamper_classes_are_refused():
    from myfuzz.runtime.evidence.saved import verify_saved_bundle
    root = _case_root("timer")
    original = root / "bundle-original"
    fresh = root / "bundle-fresh"
    work = root / "gate-tamper"
    work.mkdir(exist_ok=True)
    assert verify_saved_bundle(
        original, fresh_bundle_dir=fresh)["verdict"] == "verified"

    def native_rdata(document):
        for event in document:
            if event["kind"] == "apb_storage_probe" \
                    and event["payload"]["write"] is False:
                event["payload"]["rdata"] ^= 1

    _expect_refused(_tamper_copy(original, work / "native", "events.json",
                                 native_rdata),
                    ("saved-read-return-mismatch",
                     "saved-evidence-contradicted"))

    def version_value(document):
        event = next(row for row in document
                     if row["kind"] == "ip_register_version"
                     and row["payload"]["phase"] == "after")
        event["payload"]["version"]["value"] ^= 0xFF

    _expect_refused(_tamper_copy(original, work / "version", "events.json",
                                 version_value),
                    ("saved-version-chain-break", "saved-write-data-mismatch"))

    def counter(document):
        rows = [row for row in document
                if row["kind"] == "ip_register_version"]
        rows[-1]["payload"]["version"]["command_sequence"] = 0

    _expect_refused(_tamper_copy(original, work / "counter", "events.json",
                                 counter),
                    ("saved-counter-conflict", "saved-version-chain-break"))

    def process(document):
        name = sorted(document["sessions"])[0]
        document["sessions"][name]["pid"] += 1

    _expect_refused(_tamper_copy(original, work / "process", "processes.json",
                                 process),
                    ("saved-process-identity-change",))

    def plan(document):
        document["memory"]["resources"][0]["size"] += 4096

    _expect_refused(_tamper_copy(original, work / "plan", "plan.json", plan),
                    ("saved-plan-identity-mismatch", "saved-plan-not-canonical"))

    def status(document):
        document["cases"][0]["evidence"][0]["status"] = "missing"

    _expect_refused(_tamper_copy(original, work / "status", "evidence.json",
                                 status),
                    ("saved-evidence-status-mismatch",))

    def fresh_pid(document):
        original_processes = _load(original / "processes.json")
        for name, record in original_processes["sessions"].items():
            document["sessions"][name]["pid"] = record["pid"]

    reused = _tamper_copy(fresh, work / "fresh-reuse", "processes.json",
                          fresh_pid)
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_saved_bundle(original, fresh_bundle_dir=reused)
    assert caught.value.code in ("saved-fresh-identity-reuse",
                                 "saved-fresh-bundle-refused",
                                 "saved-process-identity-change")
