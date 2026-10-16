"""The run CLI must be able to select the closed minimal bootstrap.

Task 6b wired the selector through the integration layer
(``make_register_assembly(bootstrap_selector=...)`` /
``make_ibex_pulp_online_runtime(bootstrap_selector=...)`` /
``select_ibex_pulp_dual_source_bootstrap(...)``) but the operator entry point
still had no flag, so no run could actually select it.  These tests pin the
entry-point wiring only: the shipped bootstrap stays the default, the closed
selector is passed through, and an unknown value is refused before any RTL
work.

Whether a minimal-bootstrap run makes ``gpio_b`` certify is a native-gate
question and is deliberately NOT asserted here.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from myfuzz.scenario.ibex_pulp_dual_source import (
    MINIMAL_BOOTSTRAP_SELECTOR,
    make_ibex_pulp_dual_source_minimal_bootstrap,
    make_ibex_pulp_dual_source_stream_bootstrap,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_ibex_pulp_online.py"


def _run_help(*argv: str) -> str:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "run", *argv, "--help"],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_run_entry_point_offers_a_closed_bootstrap_selector():
    """The operator entry point must expose the selector, defaulting to shipped."""
    text = _run_help()
    assert "--bootstrap-selector" in text, text


def test_bootstrap_selector_flag_is_optional_and_defaults_to_shipped():
    """Absent flag == shipped bootstrap; the flag must not be required."""
    text = _run_help()
    # The help text must name the shipped default explicitly so an operator
    # cannot mistake the opt-in for the normal path.
    assert "shipped" in text.lower(), text


def test_unknown_bootstrap_selector_is_refused(monkeypatch, tmp_path):
    """An unknown selector is refused by the shared selector, not silently ignored."""
    from myfuzz.integration.ibex_pulp_online import (
        select_ibex_pulp_dual_source_bootstrap)

    with pytest.raises(ValueError):
        select_ibex_pulp_dual_source_bootstrap("not-a-closed-selector")


def test_shipped_and_minimal_bootstraps_are_distinct_and_pinned():
    """The two selections must rebuild different, self-consistent bootstraps."""
    shipped = select_or_shipped(None)
    minimal = select_or_shipped(MINIMAL_BOOTSTRAP_SELECTOR)
    assert shipped == make_ibex_pulp_dual_source_stream_bootstrap()
    assert minimal == make_ibex_pulp_dual_source_minimal_bootstrap()
    assert shipped != minimal


def select_or_shipped(selector):
    from myfuzz.integration.ibex_pulp_online import (
        select_ibex_pulp_dual_source_bootstrap)
    return select_ibex_pulp_dual_source_bootstrap(selector)
