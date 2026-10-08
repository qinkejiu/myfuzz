"""覆盖 attestation 的两种 shipped 形态必须都能读，且不一致时 fail-closed。

软件测试：不渲染 harness、不启动 Verilator、不跑 RTL。合成夹具覆盖两种形态与
拒绝路径；末尾对两个真实保存运行只读复核（新形态的单 cell 运行与旧形态的参考
运行），两者都必须被 `coverage_attestation` 接受。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.scenario.rtl_branch_coverage import (
    ArtifactUnavailable,
    coverage_attestation,
    coverage_kind,
    executable_sha256,
)

ROOT = Path(__file__).resolve().parents[2]
#: 新形态：当前 builder 写的嵌套 ``coverage`` 文档。
NESTED_RUN = ROOT / "runs/p4-cpu-side-coverage-20261008-online"
#: 旧形态：扁平 ``coverage_instrumentation``/``coverage_ports`` 三键。
FLAT_RUN = ROOT / "runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926"


def _flat_provenance() -> dict:
    return {
        "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
        "executable_sha256": "sha256:" + "a" * 64,
        "coverage_instrumentation": {"instrumented_root": "/tmp/x",
                                     "instrumented_flist": "/tmp/x/f"},
        "coverage_ports": [["__vi_coverage", 1], ["__vi_coverage", 2]],
        "branch_coverage_ports": [["__vi_coverage", 1], ["__vi_coverage", 2]],
    }


def _nested_run(tmp_path: Path, *, plan_bits=(1, 2), counter_bits=(1, 2)) -> Path:
    run = tmp_path / "run"
    (run / "build").mkdir(parents=True)
    (run / "build" / "soc_coverage_plan.json").write_text(json.dumps(
        {"observed": [{"bit": bit} for bit in plan_bits]}), encoding="utf-8")
    document = {
        "client_result": {"artifact_provenance": {
            "coverage": {
                "kind": "source-instrumented-rtl-branch-u8-saturating",
                "signal": "__vi_coverage",
                "observation_plan": "soc_coverage_plan.json",
                "observations": [["__vi_coverage", bit] for bit in counter_bits],
            },
            "executable": {"sha256": "sha256:" + "b" * 64},
        }},
    }
    (run / "report.json").write_text(json.dumps(document), encoding="utf-8")
    return run


def test_flat_shape_is_read_verbatim():
    instrumentation, ports, branch, shape = coverage_attestation(
        _flat_provenance(), Path("/nonexistent"))
    assert shape == "flat_attestation"
    assert instrumentation["instrumented_root"] == "/tmp/x"
    assert ports == branch == [["__vi_coverage", 1], ["__vi_coverage", 2]]
    assert coverage_kind(_flat_provenance()).endswith("u8-saturating")
    assert executable_sha256(_flat_provenance()).startswith("sha256:aaa")


def test_nested_shape_derives_branch_ports_from_the_runs_own_plan(tmp_path):
    run = _nested_run(tmp_path)
    provenance = json.loads((run / "report.json").read_text())[
        "client_result"]["artifact_provenance"]
    instrumentation, ports, branch, shape = coverage_attestation(provenance, run)
    assert shape == "nested_coverage_attestation"
    assert instrumentation["kind"].startswith("source-instrumented-rtl-branch")
    assert ports == [["__vi_coverage", 1], ["__vi_coverage", 2]]
    assert branch == ports
    assert coverage_kind(provenance).startswith("source-instrumented-rtl-branch")
    assert executable_sha256(provenance).startswith("sha256:bbb")


def test_nested_shape_refuses_when_the_plan_and_counters_disagree(tmp_path):
    """计划与暴露计数器不一致时拒绝，绝不猜一个映射。"""
    run = _nested_run(tmp_path, plan_bits=(1, 2), counter_bits=(1, 3))
    provenance = json.loads((run / "report.json").read_text())[
        "client_result"]["artifact_provenance"]
    with pytest.raises(ArtifactUnavailable, match="disagree"):
        coverage_attestation(provenance, run)


def test_nested_shape_refuses_when_the_plan_is_missing(tmp_path):
    run = _nested_run(tmp_path)
    (run / "build" / "soc_coverage_plan.json").unlink()
    provenance = json.loads((run / "report.json").read_text())[
        "client_result"]["artifact_provenance"]
    with pytest.raises(ArtifactUnavailable, match="plan is missing"):
        coverage_attestation(provenance, run)


def test_missing_attestation_refuses():
    with pytest.raises(ArtifactUnavailable):
        coverage_attestation({}, Path("/nonexistent"))


@pytest.mark.skipif(not NESTED_RUN.is_dir(), reason="fresh run not saved here")
def test_real_current_shape_run_is_accepted():
    provenance = json.loads((NESTED_RUN / "report.json").read_text())[
        "client_result"]["artifact_provenance"]
    _i, ports, branch, shape = coverage_attestation(provenance, NESTED_RUN)
    assert shape == "nested_coverage_attestation"
    assert len(ports) == len(branch) == 128
    assert [row[1] for row in branch] == [row[1] for row in ports]


@pytest.mark.skipif(not FLAT_RUN.is_dir(), reason="reference run not saved here")
def test_real_flat_shape_run_is_still_accepted():
    provenance = json.loads((FLAT_RUN / "report.json").read_text())[
        "client_result"]["artifact_provenance"]
    _i, ports, branch, shape = coverage_attestation(provenance, FLAT_RUN)
    assert shape == "flat_attestation"
    assert len(ports) == 240 and len(branch) == 128
