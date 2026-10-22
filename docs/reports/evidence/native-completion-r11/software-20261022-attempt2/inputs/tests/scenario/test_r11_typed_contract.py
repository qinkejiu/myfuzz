"""R11 joins preserve JSON boolean types when comparing trusted contracts."""

import importlib.util
from pathlib import Path

import pytest


PATH = Path(__file__).resolve().parents[2] / "scripts/task5_native_completion_r11/r11-post-gate-audit-runner.v1.py"
SPEC = importlib.util.spec_from_file_location("r11_typed_runner", PATH)
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


@pytest.mark.parametrize("actual,expected", [
    (0, False), (0.0, False), (1, True), (1.0, True),
    ({"flag": 0}, {"flag": False}),
    ({"nested": [{"flag": 1}]}, {"nested": [{"flag": True}]}),
    ({key: 0 for key in R.CLAIMS}, R.CLAIMS),
])
def test_runner_refuses_numeric_boolean_substitution(actual, expected):
    with pytest.raises(R.RunnerError, match="mismatch:typed-contract"):
        R.equal(actual, expected, "typed-contract")


@pytest.mark.parametrize("value", [False, True, 0, 1, {"nested": [False, 1]},
                                   {"positive", "controlled-response", "native-source-refusal"}])
def test_runner_accepts_the_exact_typed_value(value):
    R.equal(value, value, "typed-contract")
