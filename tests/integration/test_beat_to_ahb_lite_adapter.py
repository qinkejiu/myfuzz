"""The AHB-Lite CPU-side adapter: phase-accurate behaviour, not just lint.

CVW is the repository's only real AHB-Lite boundary.  It has a CPU-side contract
(`cpu.ahb-lite` / `cvw-external-bus`) and its top level elaborates under
Verilator, but the runtime renderer had no AHB branch and
`src/myfuzz/protocols/rtl/` contained no AHB file at all, so no runnable harness
could be produced for it.  `beat_to_ahb_lite.sv` is that missing adapter.

Lint alone cannot show the phases are right, so this drives the real module
through a self-checking testbench (`tests/integration/rtl/beat_to_ahb_lite_tb.sv`)
that models an AHB subordinate and asserts the protocol facts that matter:
a one-cycle NONSEQ address phase, HWDATA/HWSTRB in the *following* cycle,
HRDATAEXT/HRESPEXT sampled on the completion edge, a completion held until the
beat handshake accepts it, and a timeout completion when the subordinate never
asserts HREADYEXT.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'src' / 'myfuzz' / 'protocols' / 'rtl' / 'beat_to_ahb_lite.sv'
BENCH = ROOT / 'tests' / 'integration' / 'rtl' / 'beat_to_ahb_lite_tb.sv'

pytestmark = pytest.mark.skipif(
    not (shutil.which('iverilog') and shutil.which('vvp')),
    reason='Icarus Verilog is required')


def run_bench(tmp_path, adapter: Path = ADAPTER):
    compiled = subprocess.run(
        ['iverilog', '-g2012', '-s', 'beat_to_ahb_lite_tb',
         '-o', str(tmp_path / 'sim'), str(adapter), str(BENCH)],
        capture_output=True, text=True, timeout=120)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run(['vvp', str(tmp_path / 'sim')],
                          capture_output=True, text=True, timeout=120)


def test_the_adapter_implements_ahb_lite_phases(tmp_path):
    result = run_bench(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'BEAT_TO_AHB_LITE_TB: PASS' in result.stdout, result.stdout


def test_the_bench_notices_write_data_in_the_address_phase(tmp_path):
    """The guard for the test above: an AHB-Lite violation must fail it.

    Driving HWDATA/HWSTRB in the address phase instead of the following cycle is
    a real AHB-Lite violation that lint accepts, so without this guard a passing
    testbench would only prove that something ran.
    """
    source = ADAPTER.read_text(encoding='utf-8')
    assert "assign HWDATA    = (state_q == DATA) ? wdata_q : '0;" in source
    mutated = source.replace(
        "assign HWDATA    = (state_q == DATA) ? wdata_q : '0;",
        "assign HWDATA    = (state_q != IDLE) ? wdata_q : '0;")
    assert mutated != source
    probe = tmp_path / 'mutated_adapter.sv'
    probe.write_text(mutated, encoding='utf-8')
    result = run_bench(tmp_path, adapter=probe)
    assert 'FAIL' in result.stdout, result.stdout
    assert 'PASS' not in result.stdout, result.stdout


def test_the_adapter_classifies_a_held_ready_as_a_timeout(tmp_path):
    """A stuck subordinate must end the transfer, not hang the harness.

    The bench drives a subordinate that never asserts HREADYEXT and requires the
    completion to be reported as an error, so a campaign cannot stall on one
    unresponsive target.
    """
    source = ADAPTER.read_text(encoding='utf-8')
    assert 'MAX_WAIT_CYCLES' in source
    result = run_bench(tmp_path)
    # The bench prints PASS only when its timeout check passed.
    assert 'BEAT_TO_AHB_LITE_TB: PASS' in result.stdout, result.stdout

    # And the bound really is enforced: removing it must make the bench time out.
    mutated = source.replace(
        """                    end else if (wait_q >= 16'(MAX_WAIT_CYCLES - 1)) begin
                        // A held HREADYEXT is a timeout completion, not a hang.
                        rsp_valid_q <= 1'b1;
                        rdata_q     <= '0;
                        timeout_q   <= 1'b1;
                        state_q     <= IDLE;
                    end else begin
                        wait_q <= wait_q + 16'd1;
                    end""",
        """                    end else begin
                        wait_q <= wait_q + 16'd1;
                    end""")
    assert mutated != source
    probe = tmp_path / 'no_timeout.sv'
    probe.write_text(mutated, encoding='utf-8')
    result = run_bench(tmp_path, adapter=probe)
    assert 'FAIL' in result.stdout, result.stdout
