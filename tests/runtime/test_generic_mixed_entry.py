"""The public scenario entry preserves flow order within one campaign."""
import json
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from myfuzz.runtime import campaign, generic_campaign
from myfuzz.runtime.campaign import run_directed_campaign
from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.flows.storage import StorageFlowBackend, StorageFlowChannel
from myfuzz.runtime.flows.storage import StorageFlowKernel
from tests.runtime.test_persistent_engine import FakePersistentRuntime, NoOpenBackend, _engine
from tests.runtime.test_storage_kernel import FakeScenarioSession, campaign_world, directed_case, directed_sequence


ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json"


def descriptor():
    return generic_campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT)


def test_mixed_records_keep_each_flow_and_input_in_order():
    cases = generic_campaign.select_case_records(
        descriptor(), flow="mixed", records=["F4:55000000", "F2:04100040", "F4:aa000000"])
    assert cases == (("F4", "55000000"), ("F2", "04100040"),
                     ("F4", "aa000000"))


@pytest.mark.parametrize("flow,raw", [
    ("F1", "13000000"), ("F2", "04100040"),
    ("F3", "78563412"), ("F4", "55000000")])
def test_mixed_accepts_one_declared_case(flow, raw):
    assert generic_campaign.select_case_records(
        descriptor(), flow="mixed", records=[f"{flow}:{raw}"]) == ((flow, raw),)


def test_mixed_record_limit_can_leave_one_case():
    assert generic_campaign.select_case_records(descriptor(), flow="mixed",
        records=["F3:78563412", "F4:55000000"], record_limit=1) == (("F3", "78563412"),)


def test_mixed_sequence_uses_the_declared_fuzzable_source_per_path():
    plan = {"paths": [
        {"flow_id": "F4", "path_id": "write-path", "sources": [
            {"kind": "cpu_mmio_stream", "origin": "fuzzable", "source_id": "write-source"}]},
        {"flow_id": "F2", "path_id": "read-path", "sources": [
            {"kind": "cpu_load_stream", "origin": "fuzzable", "source_id": "read-source"}]},
    ]}
    sequence = generic_campaign.case_sequence_for_plan(
        scenario_id="demo", plan_document=plan, plan_sha256="a" * 64,
        cases=(("F4", "55000000"), ("F2", "04100040"), ("F4", "aa000000")))
    assert [(row["path_id"], row["source_id"], row["raw_records_hex"][0])
            for row in sequence["cases"]] == [
        ("write-path", "write-source", "55000000"),
        ("read-path", "read-source", "04100040"),
        ("write-path", "write-source", "aa000000")]


@pytest.mark.parametrize("records", [[], ["F3:aa"], ["F1:23202000"],
                                     ["F4:invalid", "F2:04100040"]])
def test_invalid_mixed_sequence_is_refused_before_preparation(tmp_path, monkeypatch, records):
    def should_not_prepare(**kwargs):
        pytest.fail("invalid input reached preparation")
    monkeypatch.setattr(generic_campaign, "create_preparation", should_not_prepare)
    with pytest.raises(generic_campaign.GenericScenarioRefused):
        generic_campaign.run_descriptor(descriptor(), flow="mixed", mode="original",
                                        case_root=tmp_path / "run", base_dir=ROOT,
                                        sequence=records)
    assert not (tmp_path / "run").exists()


def test_cli_reports_bad_flow_record_without_starting_a_campaign(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/run_generic_scenario.py"),
         "--descriptor", str(DESCRIPTOR), "--flow", "mixed", "--mode", "original",
         "--case", str(tmp_path / "run"), "--record", "F3:aa"],
        cwd=ROOT, text=True, capture_output=True, timeout=15)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "refused"
    assert not (tmp_path / "run").exists()


def test_mixed_campaign_loads_its_default_kernel_before_plan_validation():
    backend = object.__new__(StorageFlowBackend)
    backend.supports_mixed = True
    bound = SimpleNamespace(plan=SimpleNamespace(document=lambda: {}))
    with pytest.raises(GenericRuntimeRefused) as error:
        run_directed_campaign(bound_plan=bound, backend=backend, sequence={})
    assert error.value.code == "generic-plan-mismatch"


def test_out_of_range_f2_record_is_rejected_before_backend_opens():
    bound, runner, _, path = campaign_world("F2")
    runtime = FakePersistentRuntime(runner, FakeScenarioSession())
    backend = NoOpenBackend(runtime=runtime, flow_id="F2")
    context = StorageFlowKernel().prepare(bound, path["path_id"])
    sequence = directed_sequence(directed_case(
        "bad-address", path_id=path["path_id"], source_id=context.current_source_id,
        records=("ffffffff",)), plan_sha256=bound.plan_sha256)
    with pytest.raises(GenericRuntimeRefused) as error:
        run_directed_campaign(bound_plan=bound, backend=backend, sequence=sequence)
    assert error.value.code == "generic-case-shape"
    assert runtime.submit_calls == 0


def test_mixed_refuses_a_mismatched_f2_executor():
    config = replace(descriptor(), executors={"F2": "compiled_f4_wishbone",
                                               "F4": "compiled_f4_obi_apb"})
    with pytest.raises(generic_campaign.GenericScenarioRefused):
        generic_campaign.select_case_records(
            config, flow="mixed", records=["F4:55000000", "F2:04100040"])


def test_started_session_is_finished_if_channel_start_validation_fails():
    bound, runner, _, path = campaign_world("F4")
    session = FakeScenarioSession()
    runtime = FakePersistentRuntime(runner, session)
    session.manifest = None
    channel = StorageFlowChannel(runtime, flow_id="F4", executor="test")
    engine = _engine(bound, path, runtime, channel=channel)
    engine.prepare()
    with pytest.raises(GenericRuntimeRefused):
        engine.start()
    assert runtime.finish_calls == 1
    assert engine.state == "CLOSED"


def test_mixed_report_does_not_claim_that_mixed_execution_was_refused():
    backend = SimpleNamespace(supports_mixed=True,
                              unresolved=lambda: ("mixed RFuzz wire unavailable",))
    scope = campaign.campaign_reporting_scope(backend)
    assert scope["known_limitations"] == ["mixed RFuzz wire unavailable"]
    assert scope["software_only"] is None


def test_single_flow_report_does_not_claim_real_execution_is_unavailable():
    backend = SimpleNamespace(supports_mixed=False,
                              unresolved=lambda: ("single flow per campaign",))
    scope = campaign.campaign_reporting_scope(backend)
    assert scope["known_limitations"] == ["single flow per campaign"]
    assert scope["software_only"] is None
