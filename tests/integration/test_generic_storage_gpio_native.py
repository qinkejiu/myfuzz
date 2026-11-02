"""G7 armed native gate: a genuinely new APB3 storage source (PULP GPIO PADDIR).

All checks read archived real evidence under ``runs/generic-runtime/G7``.  The
gate is armed with ``MYFUZZ_RUN_GENERIC_NATIVE=1``; without it every test is
skipped, and a skip is not a pass.

What is checked:

* the new GPIO source runs one persistent three-case F4 campaign and one fresh
  process with identical plan bytes, new PIDs, a certified chain and replay;
* it uses the same adapter selections and shared core as the timer/SPI sources
  but a distinct source contract, register, artifact and semantic digest;
* a renamed GPIO instance (gpio0) runs with the same selections;
* a real non-alias offset is refused before effect;
* wrong-side-effect register selection, a similar register/module name and a
  wrong template are refused by the source/template layer (no native effect);
* the saved bundle pair verifies and the real-bundle tamper classes are refused;
* the shared functional core hash is unchanged; only a docstring in
  ``runtime/semantics/storage.py`` changed, and no GPIO name branch exists in
  ``src/myfuzz/runtime``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
G7 = ROOT / "runs/generic-runtime/G7"
G6 = ROOT / "runs/generic-runtime/G6"

pytestmark = pytest.mark.skipif(
    os.environ.get("MYFUZZ_RUN_GENERIC_NATIVE") != "1",
    reason="real native G7 GPIO gate; set MYFUZZ_RUN_GENERIC_NATIVE=1 after "
           "recording runs/generic-runtime/G7/gpio-F4-final")


def _load(path: Path):
    assert path.is_file(), f"missing archived G7 evidence: {path}"
    return json.loads(path.read_text())


def _campaign(root: Path, mode: str) -> dict:
    return _load(root / mode / "campaign.json")


def _summary(root: Path, mode: str) -> dict:
    return _load(root / mode / "summary.json")


def _plan_bytes(root: Path, mode: str) -> bytes:
    return (root / mode / "execution_plan.json").read_bytes()


def _assert_certified(campaign: dict, label: str) -> None:
    assert [case["status"] for case in campaign["cases"]] == ["effective"] * 3, label
    for case in campaign["cases"]:
        assert case["evidence"], (label, case["case_index"])
        for item in case["evidence"]:
            assert item["status"] == "certified", (
                label, case["case_index"], item["status"],
                item["obligation_results"])
            assert all(status == "certified"
                       for _, status in item["obligation_results"]), label


def _assert_persistent_chain(campaign: dict, label: str) -> None:
    previous = None
    for case in campaign["cases"]:
        certificate = case["records"][0]["certificate"]
        before, after = certificate["prerequisite"], certificate["postcondition"]
        if previous is not None:
            assert before["value"] == previous["value"], (label, case["case_index"])
            assert before["write_count"] == previous["write_count"], label
            assert before["command_sequence"] == previous["command_sequence"], label
        assert after["write_count"] == before["write_count"] + 1, label
        assert after["command_sequence"] > before["command_sequence"], label
        previous = after


def _selections(declarations: dict) -> set[tuple[str, str]]:
    return {(row["adapter_id"], row["adapter_version"])
            for row in declarations["selections"]}


def test_gpio_three_case_persistent_certified_and_complete_fresh():
    root = G7 / "gpio-F4-final"
    assert _plan_bytes(root, "original") == _plan_bytes(root, "fresh")
    for mode in ("original", "fresh"):
        campaign = _campaign(root, mode)
        assert campaign["initialization_counts"] == {
            "build": 1, "start": 1, "begin": 1, "init": 1}, mode
        _assert_certified(campaign, f"gpio:{mode}")
        _assert_persistent_chain(campaign, f"gpio:{mode}")
        assert _summary(root, mode)["replay_matches"] is True, mode
    original = _campaign(root, "original")
    fresh = _campaign(root, "fresh")
    values = [case["records"][0]["certificate"]["commit"]["after"]
              for case in original["cases"]]
    assert values == [0x55, 0xAA, 0x12345678], values
    original_pids = {row["pid"] for row in original["process_identities"].values()}
    fresh_pids = {row["pid"] for row in fresh["process_identities"].values()}
    assert original_pids and fresh_pids and original_pids.isdisjoint(fresh_pids)


def test_gpio_is_a_distinct_source_on_the_shared_generic_core():
    gpio = _load(G7 / "gpio-F4-final/original/declarations.json")
    timer = _load(G6 / "timer-F4-final/original/declarations.json")
    assert _selections(gpio) == _selections(timer) == {
        ("apb3.storage.v1", "1"), ("obi.cpu.v1", "1")}
    gpio_target = next(row for row in gpio["components"]
                       if row["instance_id"] == "peripheral")
    timer_target = next(row for row in timer["components"]
                        if row["instance_id"] == "peripheral")
    assert gpio_target["artifact_sha256"] != timer_target["artifact_sha256"]
    assert (gpio_target["semantic_contract_sha256"]
            != timer_target["semantic_contract_sha256"])
    artifact = _load(G7 / "gpio-F4-final/original/generated/peripheral/artifact.json")
    observation = artifact["storage_observation"]
    assert observation["selection"] == {
        "contract_id": "pulp-apb-gpio.paddir.source.v1",
        "endpoint_id": "gpio.bus", "register": "PADDIR"}
    assert observation["source_contract"]["storage_expression"]["expression"] == \
        "u_component.u_dut.r_gpio_dir"
    assert artifact["kind"] == "apb3_register_observe"
    assert artifact["storage_observation"]["hierarchy_verified"] is False
    assert (G7 / "gpio-F4-final/original/execution_plan.json").read_bytes() \
        != (G6 / "timer-F4-final/original/execution_plan.json").read_bytes()


def test_renamed_gpio_instance_runs_with_the_same_selection():
    root = G7 / "renamed-gpio-F4-final"
    campaign = _campaign(root, "original")
    _assert_certified(campaign, "renamed-gpio")
    _assert_persistent_chain(campaign, "renamed-gpio")
    assert _summary(root, "original")["replay_matches"] is True
    declarations = _load(root / "original/declarations.json")
    instances = [row["instance_id"] for row in declarations["components"]]
    assert "gpio0" in instances and "peripheral" not in instances
    gpio_decl = _load(G7 / "gpio-F4-final/original/declarations.json")
    assert _selections(declarations) == _selections(gpio_decl)
    renamed_target = next(row for row in declarations["components"]
                          if row["instance_id"] == "gpio0")
    gpio_target = next(row for row in gpio_decl["components"]
                       if row["instance_id"] == "peripheral")
    assert renamed_target["artifact_sha256"] != gpio_target["artifact_sha256"]
    assert (_plan_bytes(root, "original")
            != _plan_bytes(G7 / "gpio-F4-final", "original"))


def test_real_non_alias_gpio_offset_refused_before_effect():
    report = _load(G7 / "non-alias-gpio/refusal.json")
    assert report["verdict"] == "refused-before-effect", report
    refusal = report["non_alias_refusal"]
    assert refusal is not None
    assert refusal["code"] in ("generic-route-refused",
                               "generic-semantic-unsupported"), refusal
    assert report["alias_prepare"]["accepted"] is True
    assert report["native_effect_observed"] is False
    assert report["session_sequence_before"] == report["session_sequence_after"]
    assert report["session_ticks_before"] == report["session_ticks_after"]
    assert report["process_before"] is None and report["process_after"] is None


def test_wrong_semantics_similar_names_and_template_are_refused():
    report = _load(G7 / "negatives/negative-report.json")
    assert report["all_refused"] is True, report
    assert report["all_pipeline_cases_before_native"] is True, report
    assert report["positive_control"]["refused"] is False
    codes = {row["case"]: row.get("code") for row in report["results"]}
    assert codes["wrong-register:PADOUTSET"] == "apb-storage-selection-unsupported"
    assert codes["wrong-register:PADOUT"] == "apb-storage-selection-unsupported"
    assert codes["similar-register-name"] == "apb-storage-register-mismatch"
    assert codes["similar-module-name"] == \
        "apb-storage-source-identity-unsupported"
    assert codes["reviewed-byte-drift"] == "apb-storage-reviewed-source-bytes-changed"
    assert codes["pipeline-wrong-register"] == "generic-source-unverified"
    pipeline = next(row for row in report["results"]
                    if row["case"] == "pipeline-wrong-template")
    assert pipeline["code"] == "generic-source-unverified"
    assert "template" in json.dumps(pipeline["detail"])


def test_mixed_f4f2f4_reads_the_previous_paddir_write():
    root = G7 / "mixed-gpio"
    plans = {}
    pids = {}
    for mode in ("original", "fresh"):
        campaign = _campaign(root, mode)
        assert campaign["initialization_counts"] == {
            "build": 1, "start": 1, "begin": 1, "init": 1}, mode
        assert [case["flow_id"] for case in campaign["cases"]] == [
            "F4", "F2", "F4"], mode
        assert [case["status"] for case in campaign["cases"]] == [
            "effective"] * 3, mode
        for case in campaign["cases"]:
            assert case["evidence"], (mode, case["case_index"])
            for item in case["evidence"]:
                assert item["status"] == "certified", (mode, case)
                assert all(status == "certified"
                           for _, status in item["obligation_results"])
        first = campaign["cases"][0]["records"][0]["certificate"]
        read = campaign["cases"][1]["records"][0]["certificate"]
        last = campaign["cases"][2]["records"][0]["certificate"]
        assert first["commit"]["after"] == 0x55
        assert read["version_before"]["value"] == 0x55, mode
        assert read["version_witness"]["value"] == 0x55, mode
        assert read["exact_hops"]["ram_write_hop"]["value"] == (
            0x55 ^ 0x5A5), mode
        assert last["commit"]["after"] == 0xAA
        assert _summary(root, mode)["replay_matches"] is True, mode
        plans[mode] = (root / mode / "execution_plan.json").read_bytes()
        pids[mode] = {row["pid"] for row in
                      campaign["process_identities"].values()}
    assert plans["original"] == plans["fresh"]
    assert pids["original"] and pids["fresh"]
    assert pids["original"].isdisjoint(pids["fresh"])


def test_saved_gpio_pair_verifies_and_real_tamper_classes_are_refused():
    from myfuzz.runtime.evidence.saved import verify_saved_bundle
    root = G7 / "gpio-F4-final"
    report = verify_saved_bundle(root / "bundle-original",
                                 fresh_bundle_dir=root / "bundle-fresh")
    assert report["verdict"] == "verified"
    assert report["fresh_verified"] is True
    assert report["case_count"] == 3
    verification = _load(G7 / "verification/gpio-pair.json")
    assert verification["verdict"] == "verified"
    assert verification["fresh_verified"] is True
    assert len(verification["checks"]) >= 52
    tamper = _load(G7 / "tamper/gpio-tamper.json")
    assert tamper["all_refused"] is True
    assert tamper["pristine_verdict"] == "verified"
    assert len(tamper["tampers"]) >= 8
    assert all(row["ok"] and row["refused"] for row in tamper["tampers"])


def test_shared_core_hashes_and_no_gpio_runtime_branch():
    pre = _load(G7 / "core-freeze-pre.json")
    post = _load(G7 / "core-freeze-post.json")
    changed = sorted(name for name, digest in pre["shared_files"].items()
                     if post["shared_files"].get(name) != digest)
    assert changed == ["src/myfuzz/runtime/semantics/storage.py"], changed
    assert pre["registration_file"] != post["registration_file"]
    refs = []
    for path in sorted((ROOT / "src/myfuzz/runtime").rglob("*.py")):
        if "gpio" in path.read_text().lower():
            refs.append(str(path.relative_to(ROOT)))
    assert refs == ["src/myfuzz/runtime/semantics/storage.py"], refs
    assert (G7 / "source-audit.md").is_file()
