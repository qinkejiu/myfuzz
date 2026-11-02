"""G4: the explicit generic-runtime prepare CLI on both real scenarios.

These tests execute the real command line against the two registered APB3
storage source contracts (PULP timer and CV32E40P + OpenTitan SPI).  A passing
prepare is static documentation only: no RTL, no native child process and no
runner is started, and no native success field is written.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/run_generic_runtime.py"
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"
SPI = ROOT / "configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p"

NATIVE_SUCCESS_FIELDS = frozenset({
    "runtime_admitted", "native_verified", "native_success", "executed",
    "certified", "consumed", "case_certified", "effect_certified",
})


def _environment() -> dict:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _invoke(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments], cwd=str(ROOT),
        env=_environment(), capture_output=True, text=True, timeout=900)


def _scenario_arguments(scenario: Path, supplement: str,
                        output: Path) -> tuple[str, ...]:
    return (
        "--compose", str(scenario.relative_to(ROOT) / "compose.json"),
        "--ip-capability",
        str(scenario.relative_to(ROOT) / "test_capability.json"),
        "--supplement", str(scenario.relative_to(ROOT) / supplement),
        "--flow", "F2", "--flow", "F4",
        "--mode", "prepare",
        "--output", str(output),
    )


def _prepare(tmp_path_factory, label: str, scenario: Path, supplement: str):
    output = tmp_path_factory.mktemp(label) / "attempt1"
    completed = _invoke(*_scenario_arguments(scenario, supplement, output))
    return SimpleNamespace(output=output, completed=completed)


@pytest.fixture(scope="module")
def timer_run(tmp_path_factory):
    return _prepare(tmp_path_factory, "g4-cli-timer", TIMER,
                    "execution_supplement.json")


@pytest.fixture(scope="module")
def spi_run(tmp_path_factory):
    return _prepare(tmp_path_factory, "g4-cli-spi", SPI,
                    "f2_execution_supplement.json")


def _load(output: Path, name: str):
    return json.loads((output / name).read_text(encoding="utf-8"))


def assert_prepared(run, expected_endpoint: str) -> None:
    output = run.output
    assert run.completed.returncode == 0, run.completed.stderr
    assert run.completed.stderr == ""
    result = json.loads(run.completed.stdout)
    assert result["status"] == "prepared"
    assert result["mode"] == "prepare"
    assert result["process_started"] is False
    assert result["native_claimed"] is False
    assert result["flows"] == ["F2", "F4"]
    assert sorted(result["paths"]) == ["F2:ram.image", "F4:ram.image"]
    assert result["components"] == ["peripheral", "processor"]

    for name in ("execution_plan.json", "inputs.json", "capabilities.json",
                 "refusals.json", "digests.json"):
        assert (output / name).is_file(), name
    assert _load(output, "refusals.json") == []

    plan_bytes = (output / "execution_plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    identity = sha256(plan_bytes).hexdigest()
    assert plan["schema_version"] == "generic_execution_plan.v1"
    assert identity == result["plan_identity_sha256"]
    assert sorted(path["flow_id"] for path in plan["paths"]) == ["F2", "F4"]
    assert {row["instance_id"] for row in plan["components"]} == {
        "peripheral", "processor"}
    for row in plan["components"]:
        for name in ("source_sha256", "profile_sha256", "artifact_sha256",
                     "semantic_contract_sha256", "descriptor_sha256"):
            assert len(row[name]) == 64
        assert row["descriptor"]["schema_version"] == (
            "verified_component_descriptor.v1")
        assert row["descriptor"]["instance_id"] == row["instance_id"]
    assert {row["adapter_id"] for row in plan["selections"]} == {
        "apb3.storage.v1", "obi.cpu.v1"}
    for row in plan["selections"]:
        for name in ("instance_id", "endpoint_id", "role", "adapter_version",
                     "implementation_sha256", "component_artifact_sha256",
                     "semantic_contract_sha256", "selection_sha256"):
            assert row[name], name
    target = next(row for row in plan["selections"]
                  if row["role"] == "target")
    assert target["endpoint_id"] == expected_endpoint
    assert target["adapter_id"] == "apb3.storage.v1"
    for path in plan["paths"]:
        assert path["kernel"]["executor"] in {"compiled_f2_obi_apb",
                                              "compiled_f4_obi_apb"}
        roles = {binding["role"] for binding in path["bindings"]}
        assert roles == {"cpu", "target"}
        assert path["edges"]
    assert [row["resource_id"] for row in plan["memory"]["resources"]] == [
        "ram"]
    assert plan["scheduling"]["scope"] == "static_plan_no_live_execution"
    assert plan["evidence_obligations"]

    digests = _load(output, "digests.json")
    assert digests["plan_identity_sha256"] == identity
    assert digests["d2"] == plan["input_digests"]["d2"]
    assert digests["d3"] == plan["input_digests"]["d3"]
    assert digests["files"]["execution_plan.json"] == identity
    assert digests["native_claimed"] is False

    inputs = _load(output, "inputs.json")
    assert inputs["input_digests"] == plan["input_digests"]
    assert inputs["process_started"] is False
    assert inputs["native_claimed"] is False
    assert inputs["preparation"]["schema_version"] == "preparation_snapshot.v1"
    assert inputs["preparation"]["flows"] == ["F2", "F4"]
    assert [row["instance_id"] for row in
            inputs["preparation"]["components"]] == ["peripheral", "processor"]
    for name in ("compose", "supplement"):
        entry = inputs[name]
        assert Path(entry["absolute_path"]).is_absolute()
        assert Path(entry["absolute_path"]).is_file()
        assert sha256(Path(entry["absolute_path"]).read_bytes()).hexdigest() \
            == entry["sha256"]
    for entry in inputs["capability_paths"]:
        assert sha256(Path(entry["absolute_path"]).read_bytes()).hexdigest() \
            == entry["sha256"]

    capabilities = _load(output, "capabilities.json")
    assert capabilities["plan_identity_sha256"] == identity
    assert capabilities["process_started"] is False
    assert capabilities["native_claimed"] is False
    assert {component["instance_id"]
            for component in capabilities["components"]} == {
                "peripheral", "processor"}
    assert len(capabilities["matching_table"]) == 2
    for row in capabilities["matching_table"]:
        assert row["matched"] is True
        assert row["adapter_id"] in {"apb3.storage.v1", "obi.cpu.v1"}
        assert set(row["required_evidence"]) <= set(row["supported_evidence"])
        assert set(row["required_operations"]) <= set(
            row["supported_operations"])

    # No top-level native success claim is written anywhere.  Nested D3 labels
    # such as the execution-contract node "consumed" are declared facts, not
    # claims this prepare could certify.
    for name in ("execution_plan.json", "inputs.json", "capabilities.json",
                 "digests.json"):
        document = _load(output, name)
        assert not (NATIVE_SUCCESS_FIELDS & set(document)), name


# ---------------------------------------------------------------------------
# positive prepare runs
# ---------------------------------------------------------------------------

def test_help_exits_zero():
    completed = _invoke("--help")
    assert completed.returncode == 0
    assert "--compose" in completed.stdout
    assert "--ip-capability" in completed.stdout
    assert "--supplement" in completed.stdout
    assert "--flow" in completed.stdout
    assert "--mode" in completed.stdout
    assert "--output" in completed.stdout


def test_timer_prepare_produces_a_two_flow_plan(timer_run):
    assert_prepared(timer_run, "timer.bus")


def test_spi_prepare_produces_a_two_flow_plan(spi_run):
    assert_prepared(spi_run, "spi.bus")


def test_both_scenarios_use_the_same_plan_shape(timer_run, spi_run):
    timer_plan = _load(timer_run.output, "execution_plan.json")
    spi_plan = _load(spi_run.output, "execution_plan.json")
    assert timer_plan["schema_version"] == spi_plan["schema_version"]
    assert ([path["path_id"] for path in timer_plan["paths"]]
            == [path["path_id"] for path in spi_plan["paths"]])
    # Different source closures, same plan shape and same adapters.
    assert (timer_plan["components"][0]["source_sha256"]
            != spi_plan["components"][0]["source_sha256"] or
            timer_plan["components"][1]["source_sha256"]
            != spi_plan["components"][1]["source_sha256"])
    assert ({row["adapter_id"] for row in timer_plan["selections"]}
            == {row["adapter_id"] for row in spi_plan["selections"]})


# ---------------------------------------------------------------------------
# refusals: no process starts and the refusal document is written
# ---------------------------------------------------------------------------

def _refusal_case(tmp_path, label: str, *arguments: str):
    output = tmp_path / label
    completed = _invoke(*arguments, "--output", str(output))
    assert completed.returncode == 2
    assert "generic-runtime-refused:" in completed.stderr
    assert (output / "refusals.json").is_file()
    document = _load(output, "refusals.json")
    assert document["status"] == "refused"
    assert document["process_started"] is False
    assert len(document["refusals"]) == 1
    assert sorted((output / "refusals.json").parent.iterdir()) == [
        output / "refusals.json"]
    assert not (output / "execution_plan.json").exists()
    assert not (output / "generated").exists()
    return document["refusals"][0]


def test_run_mode_is_refused(tmp_path):
    refusal = _refusal_case(
        tmp_path, "run-mode",
        "--compose", str(TIMER.relative_to(ROOT) / "compose.json"),
        "--ip-capability",
        str(TIMER.relative_to(ROOT) / "test_capability.json"),
        "--supplement",
        str(TIMER.relative_to(ROOT) / "execution_supplement.json"),
        "--flow", "F2", "--flow", "F4", "--mode", "run")
    assert refusal["code"] == "generic-run-unsupported"
    assert refusal["pointer"] == "/mode"
    assert refusal["detail"]["supported"] == ["prepare"]


def test_unknown_flow_is_refused(tmp_path):
    refusal = _refusal_case(
        tmp_path, "bad-flow",
        "--compose", str(TIMER.relative_to(ROOT) / "compose.json"),
        "--ip-capability",
        str(TIMER.relative_to(ROOT) / "test_capability.json"),
        "--supplement",
        str(TIMER.relative_to(ROOT) / "execution_supplement.json"),
        "--flow", "F9", "--mode", "prepare")
    assert refusal["code"] == "generic-flow-unsupported"
    assert refusal["pointer"] == "/flow"
    assert refusal["detail"]["unsupported"] == ["F9"]


def test_existing_output_directory_is_refused(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    completed = _invoke(
        "--compose", str(TIMER.relative_to(ROOT) / "compose.json"),
        "--ip-capability",
        str(TIMER.relative_to(ROOT) / "test_capability.json"),
        "--supplement",
        str(TIMER.relative_to(ROOT) / "execution_supplement.json"),
        "--flow", "F2", "--mode", "prepare", "--output", str(output))
    assert completed.returncode == 2
    document = _load(output, "refusals.json")
    refusal = document["refusals"][0]
    assert refusal["code"] == "generic-output-exists"
    assert refusal["pointer"] == "/output"
    assert document["process_started"] is False
    assert not (output / "execution_plan.json").exists()
    assert not (output / "generated").exists()
