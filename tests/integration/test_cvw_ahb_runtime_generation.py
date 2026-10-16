"""CVW generates a real AHB-Lite runtime top, and it elaborates with the DUT.

CVW is the repository's only real AHB-Lite boundary.  Getting a runnable runtime
out of it took four separate pieces, each of which failed loudly while it was
missing:

* ``cpu.ahb-lite``/``cvw-external-bus`` -- the CPU-side contract;
* the ``ahb-lite`` plugin's *real port name* fields, because ``bind_profile``
  admits only field ids the protocol plugin declares;
* ``runtime_renderer._AHB_LITE`` plus the ``ahb_lite_cpu`` kind branch, whose AHB
  port names must come from the ABI's ``physical_port`` -- CVW spells the
  subordinate-driven signals with an EXT suffix, so upper-casing the role emits
  ``HRDATA``/``HSEL`` and fails to bind;
* ``ahb_lite_memory_target``, the *subordinate* that answers the CPU's AHB
  transfers.

The adapter direction is the part that is easy to get backwards and did get
backwards once: CVW is the AHB **manager**, so a harness module that drives
HTRANS/HADDR itself (``beat_to_ahb_lite``) can never produce a transaction from
the CPU.  The subordinate answers instead, and the direction is asserted here by
the ABI-derived port names.

The last check is the one that matters: the generated top is elaborated together
with the real CVW source, so a wrong port name, width or direction cannot pass.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/cpus/cvw/component_profile.json'
TARGET = ROOT / 'src' / 'myfuzz' / 'protocols' / 'rtl' / 'ahb_lite_memory_target.sv'
CVW_ROOT = ROOT / 'third_party' / 'cvw_upstream_reference'
#: Keyed by the generated artifact digest, so a rebuild happens only when the
#: generated source really changes; outside tmp_path so a re-run is cheap.
CVW_BUILD_CACHE = Path(tempfile.gettempdir()) / 'myfuzz-cvw-ahb-build-cache'
#: The generated driver's execution identity is exactly 32 hex characters.
_EXECUTION = '0' * 32

pytestmark = pytest.mark.skipif(
    not (CVW_ROOT / 'src' / 'cvw.sv').is_file(),
    reason='the CVW reference source is not present in this checkout')


def render(tmp_path):
    from myfuzz.local_harness import (load_local_harness_request,
                                      plan_local_harness, render_local_harness,
                                      render_local_runtime,
                                      verify_local_source_lock)
    request = {'schema_version': 'local_harness.v1', 'profile_path': PROFILE,
               'instance_id': 'cpu', 'reset_assert_ticks': 2,
               'reset_release_ticks': 2, 'max_wait_cycles': 16}
    plan = plan_local_harness(load_local_harness_request(request), base_dir=ROOT)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    structural = render_local_harness(plan)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    (tmp_path / 'wrapper.sv').write_text(structural.wrapper_sv, encoding='utf-8')
    (tmp_path / 'runtime.sv').write_text(runtime.runtime_sv, encoding='utf-8')
    return structural, runtime


def test_the_runtime_selects_the_ahb_kind_and_the_target(tmp_path):
    structural, runtime = render(tmp_path)
    document = runtime.runtime_document
    assert document['kind'] == 'ahb_lite_cpu'
    assert [row['path'] for row in document['adapter_sources']] == [
        'src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv']
    # Exactly one target instance: the kind chain must not also instantiate one.
    assert (tmp_path / 'runtime.sv').read_text(encoding='utf-8').count(
        'ahb_lite_memory_target #(') == 1
    # The beat face carries the boundary's real address width, not a truncated 32.
    address = [row for row in document['runtime_ports']
               if row['name'].endswith('_req_addr')]
    assert address and address[0]['width'] == 34
    # The harness is the subordinate: the CPU-facing HREADY/HRDATA/HRESP must be
    # driven BY the target, i.e. bound to the target's outputs.  If the direction
    # were inverted (a manager adapter) these would be target inputs.
    runtime_sv = (tmp_path / 'runtime.sv').read_text(encoding='utf-8')
    for port in ('HREADYEXT', 'HRDATAEXT', 'HRESPEXT'):
        assert f'.{port}(' in runtime_sv, port


def test_the_subordinate_is_reset_out_of_phase_with_the_core(tmp_path):
    """The subordinate's active-low ``rst_ni`` must be ``~reset``, never ``reset``.

    ``ahb_lite_memory_target`` is an ACTIVE LOW module (``if (!rst_ni)``) and it
    gates its whole beat face on that pin::

        assign req_valid_o = rst_ni && (state_q == WAIT_DATA || state_q == WAIT_SERVICE);
        assign HREADYEXT   = rst_ni && (state_q == IDLE || state_q == COMPLETE);

    The harness ``reset`` port, by contrast, is the canonical ACTIVE HIGH reset:
    ``port_rendering`` applies the DUT's *declared* polarity when it drives the
    DUT's own reset pin, so for this profile (``reset_ext`` is declared
    ``active_high``) the wrapper passes it through unchanged.  Every other
    active-low executor the renderer instantiates (OBI, AXI4-Lite, native) is
    wired ``rst_ni = ~reset`` for exactly this reason.

    Wiring ``rst_ni(reset)`` puts the two out of phase: the subordinate sits in
    reset for the whole window in which the core is running, ``req_valid_o`` is
    pinned low, ``HREADYEXT`` never returns high, and the harness therefore starts,
    reports READY, toggles its clock, and drives *no AHB traffic at all* - which is
    the regression this test exists to catch.
    """
    structural, runtime = render(tmp_path)
    profile = json.loads((ROOT / PROFILE).read_text(encoding='utf-8'))
    resets = [row for row in profile['resets'] if row['port'] == 'reset_ext']
    assert len(resets) == 1, resets
    # The premise of the assertion below: this DUT's external reset is active high,
    # so the harness `reset` signal is already in its asserted-high form.
    assert resets[0]['polarity'] == 'active_high'
    schedule = runtime.runtime_document['clock_schedule']
    signal = [row['signal'] for row in schedule['resets']
              if row['port'] == 'reset_ext'][0]
    runtime_sv = (tmp_path / 'runtime.sv').read_text(encoding='utf-8')
    assert f'.rst_ni(~{signal})' in runtime_sv, runtime_sv
    assert f'.rst_ni({signal})' not in runtime_sv
    # ... and the DUT's own reset pin really is driven by the same signal without a
    # second inversion, which is what makes `~reset` the correct adapter form.
    backer = re.search(r'\.reset_ext\((\w+)\)', structural.wrapper_sv)
    assert backer, structural.wrapper_sv
    expression = re.search(rf'assign {backer.group(1)}\[0:0\] = ([^;]+);',
                           structural.wrapper_sv)
    assert expression and expression.group(1).strip() == signal, structural.wrapper_sv


def step_memory(process, sequence, ready, rsp_valid=0, rdata=0):
    """Send one generated STEP_MEMORY beat and return the driver's reply payload."""
    process.stdin.write(f'CMD {_EXECUTION} {sequence:x} STEP_MEMORY '
                        f'{ready:x} {rsp_valid:x} {rdata:x} 0\n')
    process.stdin.flush()
    line = process.stdout.readline()
    assert line.startswith('RESULT '), line.strip()
    tokens = line.split(' ', 5)
    return json.loads(bytes.fromhex(tokens[5]).decode())


def test_the_built_harness_drives_real_ahb_traffic_from_the_core(tmp_path):
    """The generated harness must actually put the core's fetches on the AHB bus.

    This is the end-to-end guard for the whole generated path, driven on the
    driver's own wire protocol so it does not depend on any session class: build
    the harness from the generated runtime, start it, and require the real CVW
    core to present an AHB-Lite transfer at the derived reset vector, take the
    service's answer for it, and go on fetching.

    It exists because this failed *silently*: with the subordinate's active-low
    ``rst_ni`` wired to the harness's active-high ``reset``, the harness compiled,
    started, reported READY, ran its clock and stepped for hundreds of ticks with
    ``m_req_valid`` never once asserted.  Nothing in the build or the reset report
    could see it; only the traffic itself can.
    """
    if shutil.which('verilator') is None:
        pytest.skip('verilator is not installed')
    from myfuzz.local_harness.build import build_local_harness
    from myfuzz.local_harness.driver_renderer import render_local_driver

    structural, runtime = render(tmp_path)
    artifact = render_local_driver(runtime, base_dir=ROOT)
    binary = build_local_harness(artifact, base_dir=ROOT, cache_dir=CVW_BUILD_CACHE)
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        ready_line = process.stdout.readline().strip()
        assert ready_line.startswith('READY local_driver.v1'), ready_line

        # 1. The core presents its boot fetch, and the harness accepts the beat.
        sequence = 0
        first = None
        for sequence in range(1, 401):
            pre = step_memory(process, sequence, ready=1)['pre_backend']
            if pre['m_req_valid'] and pre['m_req_ready']:
                first = pre
                break
        assert first is not None, 'the core never presented an AHB request'
        # The derived configuration moved RESET_VECTOR into the external region, so
        # the core's very first AHB transfer is the boot fetch at 0xC0000000.
        assert first['m_req_addr'] == 0xC0000000, first
        assert first['m_req_write'] == 0, first

        # 2. The subordinate took the beat, so it is in its completion phase and can
        #    consume the answer on the next tick (HREADYEXT is raised there).
        sequence += 1
        pre = step_memory(process, sequence, ready=0, rsp_valid=1,
                          rdata=0x00000013)['pre_backend']
        assert pre['m_rsp_ready'] == 1, pre

        # 3. The core adopted the word it was given and keeps fetching: the next
        #    accepted beat is a different address of the same boot line.
        following = None
        for offset in range(1, 401):
            pre = step_memory(process, sequence + offset, ready=1)['pre_backend']
            if pre['m_req_valid'] and pre['m_req_ready']:
                following = pre
                break
        assert following is not None, 'the core stopped fetching after the served beat'
        assert following['m_req_addr'] != first['m_req_addr'], following
        assert following['m_req_addr'] < 0xC0000040, following
    finally:
        process.stdin.write('END\n')
        process.stdin.flush()
        process.terminate()
        process.wait(timeout=30)


def test_the_generated_top_elaborates_with_the_real_cvw_source(tmp_path):
    """The check that a wrong port name, width or direction cannot pass.

    This uses the repository's own frontend runner rather than a hand-built
    Verilator command line.  Two hand-built lists were tried first and both were
    wrong for instructive reasons:

    * every ``.sv`` under the upstream tree -- ``Duplicate declaration of
      'M_MODE'``/``'ICACHE_SUPPORTED'``, because the ordered filelist exists to
      sequence the ``.vh`` configuration files and a blanket glob lets more than
      one compile unit pull them in;
    * the closure's recorded files -- the closure is a *provenance* record, so it
      also holds non-HDL mirrors (``act/*.h``, and ``config.vh`` at a second
      path), which the compiler then parses as Verilog.

    The profile's own ``source.files`` is the ordered compile-unit list the real
    elaboration uses, so the generated top is elaborated exactly the way the
    product elaborates it.
    """
    if shutil.which('verilator') is None:
        pytest.skip('verilator is not installed')
    structural, runtime = render(tmp_path)
    document = json.loads((ROOT / PROFILE).read_text(encoding='utf-8'))['source']
    sources = list(document['files'])
    assert sources, 'the profile declares no compile units'
    # The generation test writes into tmp_path, but the runner resolves sources
    # against the repository root and refuses a path that leaves it, so the
    # generated files must be addressed relative to that root.  They are written
    # under the repository too for the same reason.
    generated_dir = ROOT / '.superpowers' / 'cache' / 'cvw-ahb-elaboration'
    generated_dir.mkdir(parents=True, exist_ok=True)
    (generated_dir / 'wrapper.sv').write_text(structural.wrapper_sv, encoding='utf-8')
    (generated_dir / 'runtime.sv').write_text(runtime.runtime_sv, encoding='utf-8')
    relative_generated = [
        (generated_dir / name).relative_to(ROOT).as_posix()
        for name in ('wrapper.sv', 'runtime.sv')]
    from myfuzz.composition.source_elaboration import run_verilator_elaboration
    settings = document['elaboration']
    # The runner refuses an output path outside the repository root (and checks
    # that the closure has not moved under it), so the evidence dir lives in the
    # repository cache area and is removed afterwards.
    evidence = generated_dir / 'evidence'
    if evidence.exists():
        shutil.rmtree(evidence)
    try:
        # The runner raises ElaborationError on a frontend error and re-checks the
        # closure before reporting, so completing without raising is the assertion
        # that the generated top binds and elaborates against the real CVW source.
        run_verilator_elaboration(
            source_root=ROOT, top_module='local_runtime_cpu',
            source_files=tuple(sources + relative_generated),
            include_roots=tuple(document['include_roots']),
            defines=tuple(settings.get('defines') or ()),
            parameters=tuple(settings.get('parameters') or ()),
            warning_policy=settings['warning_policy'], selected_top_ports=None,
            output_dir=evidence)
        manifest = json.loads((evidence / 'manifest.json').read_text(encoding='utf-8'))
    finally:
        shutil.rmtree(evidence, ignore_errors=True)
    assert manifest['status'] == 'completed', manifest.get('error')
    assert manifest['warning_summary']['error_count'] == 0
    assert manifest['warning_summary']['parse_complete'] is True
