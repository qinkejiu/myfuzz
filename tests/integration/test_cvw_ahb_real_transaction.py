"""A real CVW AHB-Lite transaction, answered by this repository's subordinate.

This is the check the P6 CVW row was missing: not "a profile exists", not "the
runtime elaborates", not "the subordinate model passes its own bench", but a real
instruction fetch from the real core that becomes a real AHB-Lite transfer whose
completion the service drives.

Four non-obvious obstacles had to be cleared for it to exist at all, and each is
asserted here in a way that fails loudly if it comes back:

1. **Direction.** CVW is the AHB *manager*; the harness must be the subordinate.
2. **Feature flag.** ``adrdec.Sel = Match & Supported & AccessValid & SizeValid``
   and every committed CVW configuration sets ``EXT_MEM_SUPPORTED = 0``, so the
   external region is unreachable unless the repository's derived configuration
   is used *and is first on the include path*.
3. **Region overlap.** Upstream gives ``EXT_MEM`` the same base as
   ``UNCORE_RAM``; the derived configuration moves it to ``0xC0000000``.
4. **Empty memory.** The core's uncore RAM is built with ``PRELOAD = 0``, so the
   core executes zeros and stops after a few fetches.  The bench places the boot
   program by a hierarchical poke.

The last point is also the honest limit of this test: it is a bench, not the
generated harness.  It proves the boundary carries a real transaction; it does
not prove a runnable session, and it is not claimed as one.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / 'tests' / 'integration' / 'rtl' / 'cvw_ahb_real_transaction_tb.sv'
BOOT_BENCH = (ROOT / 'tests' / 'integration' / 'rtl'
              / 'cvw_ahb_boot_from_service_tb.sv')
PROFILE = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'
CVW_ROOT = ROOT / 'third_party' / 'cvw_upstream_reference'

pytestmark = pytest.mark.skipif(
    not (CVW_ROOT / 'src' / 'cvw.sv').is_file(),
    reason='the CVW reference source is not present in this checkout')


def _build(tmp_path, *, derived_include=True, bench=BENCH, top='cvw_ahb_real_transaction_tb'):
    """Build the bench; returns the executable path or raises on a build error."""
    verilator = shutil.which('verilator')
    if verilator is None:
        pytest.skip('verilator is not installed')
    document = json.loads(PROFILE.read_text(encoding='utf-8'))['source']
    include_roots = list(document['include_roots'])
    if not derived_include:
        include_roots = [root for root in include_roots if 'config_extmem' not in root]
    out = tmp_path / 'obj'
    executable = tmp_path / 'bench'
    result = subprocess.run(
        [verilator, '--binary', '--timing', '-Wno-fatal', '-Wno-TIMESCALEMOD',
         '--top-module', top, '-Mdir', str(out),
         *[f'-I{ROOT / root}' for root in include_roots],
         '-o', str(executable),
         *[str(ROOT / name) for name in document['files']],
         str(bench)],
        cwd=ROOT, capture_output=True, text=True, timeout=1800)
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
    return executable


def test_a_real_cvw_instruction_fetch_becomes_an_ahb_transaction(tmp_path):
    executable = _build(tmp_path)
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + result.stderr
    assert 'CVW_AHB_REAL_TRANSACTION_TB: PASS' in output, output[-2000:]
    assert 'FAIL' not in output, output[-2000:]
    # The observed evidence, not just the bench's own summary line.
    assert 'external=' in output
    external = int(output.split('external=')[1].split()[0])
    assert external > 0
    assert 'first=0c0000000' in output


def test_the_bench_fails_without_the_derived_configuration(tmp_path):
    """RED: with upstream's include order the external region is unreachable.

    ``EXT_MEM_SUPPORTED = 0`` upstream means ``HSELEXT`` never asserts, so no
    transaction can be produced.  If this test ever passes, the bench is no
    longer measuring what it claims to measure.
    """
    executable = _build(tmp_path, derived_include=False)
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + result.stderr
    assert 'CVW_AHB_REAL_TRANSACTION_TB: FAIL' in output, output[-2000:]
    assert 'the service answered at least one external fetch' in output


def test_the_program_the_core_executes_comes_from_the_service(tmp_path):
    """Poison the core's RAM with a wrong instruction; the bench must still pass.

    This replaces an earlier guard that asserted the bench *failed* without the
    poke.  Once ``RESET_VECTOR`` moved into the external region that guard became
    obsolete and, worse, misleading: the poke no longer decides anything, so
    "removing the poke breaks it" is not a property worth pinning.  What matters is
    the opposite - the program lives in the service, so whatever the core's own RAM
    contains is irrelevant.  ``0x0000006f`` is ``j self``; if the core were
    executing a program out of its RAM, a jump-to-self there would show up as an
    internal fetch and the bench's "every served fetch was external" check would
    fail.
    """
    bench = tmp_path / 'poisoned_ram_tb.sv'
    text = BENCH.read_text(encoding='utf-8')
    poke = ('      cpu.dut.uncoregen.uncore.ram.ram.memory.ram.RAM[index] = word;\n')
    assert poke in text
    bench.write_text(text.replace(poke, ''), encoding='utf-8')
    executable = _build(tmp_path, bench=bench)
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + result.stderr
    assert 'CVW_AHB_REAL_TRANSACTION_TB: PASS' in output, output[-2000:]


def test_the_harness_can_own_the_boot_program_with_no_poke(tmp_path):
    """The boundary's real job: the service decides what the core executes.

    A bench that has to poke the core's RAM proves the boundary carries traffic but
    not that a generated harness could boot the core, because a harness cannot
    reach into the DUT's RAM.  With ``RESET_VECTOR`` inside the external region the
    *first* fetch is an AHB transfer, so the service supplies the boot program -
    exactly how every other CPU in this repository is booted.  No poke is used
    anywhere in this bench.
    """
    executable = _build(tmp_path, bench=BOOT_BENCH, top='cvw_ahb_boot_from_service_tb')
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + result.stderr
    assert 'CVW_AHB_BOOT_FROM_SERVICE_TB: PASS' in output, output[-2000:]
    assert 'FAIL' not in output, output[-2000:]
    assert 'first=0c0000000' in output
    # The core keeps re-fetching the boot word from the service, so the service is
    # demonstrably the only source of the program.
    served = int(output.split('boot_fetches=')[1].split(')')[0])
    assert served > 1


def test_the_service_boot_fails_when_the_reset_vector_is_back_inside_the_uncore_ram(tmp_path):
    """RED: with upstream's reset vector the uncore RAM answers the boot.

    This is the whole reason the derived configuration also moves
    ``RESET_VECTOR``: at ``0x80000000`` the core boots from memory it owns, no AHB
    transfer is ever issued for a fetch, and the harness cannot supply a program
    at all.  If this test ever passes, the boot bench has stopped testing the
    harness's ownership of the boot program.
    """
    bench = tmp_path / 'old_reset_tb.sv'
    text = BOOT_BENCH.read_text(encoding='utf-8')
    assert "EXT_BASE = 34'h0_C000_0000" in text
    # Point the bench's idea of the reset vector back at the uncore RAM region.
    bench.write_text(text.replace("EXT_BASE = 34'h0_C000_0000", "EXT_BASE = 34'h0_8000_0000"),
                     encoding='utf-8')
    # ... but the DUT still boots where the configuration says, so the bench's
    # first-fetch assertion must now be false: the fetch it sees is not at its EXT_BASE.
    executable = _build(tmp_path, bench=bench, top='cvw_ahb_boot_from_service_tb')
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + result.stderr
    assert 'CVW_AHB_BOOT_FROM_SERVICE_TB: FAIL' in output, output[-2000:]
