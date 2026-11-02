"""Facts of the AXI4 CPU analysis: identity declaration, probe source and evidence.

Two kinds of checks, both cheap:

  * the identity header is compiled and its unit test is run with g++ (no RTL);
  * the CVA6/Vexii declarations the report relies on are re-read from the exact
    files and lines it cites, and - when the probe evidence is present in the
    workspace - the saved probe log is checked for the facts the report quotes.

The evidence half is skipped when ``runs/stage2-axi4-cpu-20261101`` is absent, so
the test never depends on one machine's run directory for collection.
"""
import json
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'runs/stage2-axi4-cpu-20261101'
CVA6_PROFILE = ROOT / 'configs/cpus/cva6/component_profile.json'
CVA6_RTL = ROOT / 'third_party/cva6_upstream_reference'
VEXII_PROFILE = ROOT / 'configs/cpus/vexiiriscv/component_profile.json'
VEXII_RTL = ROOT / 'configs/cpus/vexiiriscv/generated/VexiiRiscv.v'
ADAPTER = ROOT / 'src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv'
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
ENTRY = ROOT / 'scripts/run_inprocess_f1f6.py'
REPORT = ROOT / 'docs/reports/inprocess-axi4-cpu-analysis-20261101.md'


def line(path, number):
    return path.read_text().splitlines()[number - 1]


def test_identity_header_compiles_and_passes():
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / 'identity-test'
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'tests/native/inprocess_axi4_identity_test.cpp'),
                        '-o', str(binary)], check=True)
        out = subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout
    match = re.search(r'(\d+) expectations passed', out)
    assert match and int(match.group(1)) >= 40, out


def test_cva6_identity_is_arid_rid_and_user_prot_are_tied_off():
    profile = json.loads(CVA6_PROFILE.read_text())
    endpoint = next(row for row in profile['endpoints']
                    if row['endpoint_id'] == 'processor.memory.unified')
    roles = {field['role'] for field in endpoint['fields']}
    assert {'arid', 'rid', 'awid', 'arprot', 'aruser'} <= roles
    widths = {field['role']: field['width'] for field in endpoint['fields']}
    assert widths['arid'] == widths['rid'] == widths['awid'] == 4
    # The identity is an AXI ID, not a user/prot bit: both are tied to zero by
    # the core's own shim (axi_shim.sv:95/101/258/263) and are recorded as
    # constants here.
    assert 'ar.user' in line(CVA6_RTL / 'core/axi_shim.sv', 263)
    assert 'aw.user' in line(CVA6_RTL / 'core/axi_shim.sv', 101)
    assert 'ar.prot' in line(CVA6_RTL / 'core/axi_shim.sv', 258)
    # The adapter arbitrates the I-cache as request 0 and decodes return id 0.
    adapter = CVA6_RTL / 'core/cache_subsystem/wt_axi_adapter.sv'
    assert 'arb_req' in line(adapter, 116)
    assert 'axi_rd_id_in' in line(adapter, 159) and 'arb_idx' in line(adapter, 159)
    assert 'axi_rd_id_out == 0' in line(adapter, 597)
    assert 'axi_rd_id_out[0]' in line(adapter, 638)


def test_cva6_rvfi_bundle_is_exported_and_interrupts_stay_held():
    profile = json.loads(CVA6_PROFILE.read_text())
    actions = {row['port']: row for row in profile['port_actions']}
    # The RTL really exports a retirement probe bundle, so the profile exports it
    # whole as a passive observation; what turns it into instruction records is
    # the pinned scoreboard, which is not in the core filelist and is Verilated
    # beside the generated model (see tests/local_harness/test_cva6_rvfi_retirement.py).
    assert actions['rvfi_probes_o']['action'] == 'observe'
    assert actions['irq_i']['action'] == 'constant' and actions['irq_i']['bits'] == [1]
    assert actions['time_irq_i']['action'] == 'fuzz'
    assert 'rvfi_probes_o' in line(CVA6_RTL / 'core/cva6.sv', 339)
    assert 'single AXI4 memory master' in profile['description'] or \
        'one AXI4 memory master' in profile['description']


def test_vexiiriscv_is_structural_two_endpoint_and_has_no_len_pins():
    profile = json.loads(VEXII_PROFILE.read_text())
    endpoints = {row['endpoint_id']: row for row in profile['endpoints']}
    assert set(endpoints) == {'processor.memory.i', 'processor.memory.d'}
    for row in endpoints.values():
        roles = {field['role'] for field in row['fields']}
        assert 'arlen' not in roles and 'awlen' not in roles
        assert 'arburst' not in roles and 'arlock' not in roles
    assert 'awvalid' in {field['role'] for field in endpoints['processor.memory.d']['fields']}
    # The generated top confirms the same shape: no LEN/BURST pins and 1-bit IDs.
    top = VEXII_RTL.read_text()
    assert 'LsuCachelessAxi4Plugin_logic_axi_aw_payload_id' in top
    assert 'FetchCachelessAxi4Plugin_logic_bridge_axi_ar_valid' in top
    assert 'LsuCachelessAxi4Plugin_logic_axi_aw_payload_len' not in top
    assert 'LsuCachelessAxi4Plugin_logic_axi_aw_payload_burst' not in top
    # Interrupt inputs exist in the RTL but the generated wrapper ties them to 0,
    # and the artifact exports no physical pin for them.
    assert 'int_m_external' in top
    vexii_artifacts = list((ROOT / 'runs/vexii-f1f4-20261031').glob('cache/*/inputs/generated'))
    if vexii_artifacts:
        structural = (vexii_artifacts[0] / 'structural.sv').read_text()
        assert re.search(r"assign dut_p_4[234]\[0:0\] = 1'd0;", structural)
        artifact = json.loads((vexii_artifacts[0] / 'artifact.json').read_text())
        assert not [row for row in artifact.get('runtime_ports', [])
                    if 'rvfi' in row['name'] or 'irq' in row['name']]


def test_adapter_limits_are_the_declared_ones():
    text = ADAPTER.read_text()
    assert 'arlen_i > 8\'d1' in text          # two-beat CVA6 line fill only
    assert 'awlen_i != 8\'d0' in text         # single-beat writes only
    assert 'READ_AXI_RESPONSE' in text        # the second beat is sequenced in RTL
    assert 'AXI_DECERR' in text               # unsupported bursts are refused


def test_host_has_axi4_cpu_branch_and_entry_refuses_f1_f5_by_name():
    # The 2026-11-02 integration added the AXI4 branch; the report's original
    # "no branch yet" assertion is intentionally replaced by the current facts:
    # the host has the branch, the bus macros are still a closed set, and the
    # entry names the F1/F5 refusals rather than requiring RVFI for every build.
    host = HOST.read_text()
    assert '#ifndef CPU_BUS_WISHBONE' in host
    assert '#ifndef CPU_BUS_AHB' in host
    assert '#ifndef CPU_BUS_AXI4' in host or 'CPU_BUS_AXI4' in host
    assert 'one generated header cannot select two CPU buses' in host
    entry = ENTRY.read_text()
    buses = entry.split('CPU_BUSES')[1].split('}')[0]
    assert "'ahb'" in buses and "'cva6_packed_axi4_cpu'" in buses
    assert 'AXI4_F1_REFUSAL' in entry and 'AXI4_F5_REFUSAL' in entry
    assert 'unsupported-f1:no-retirement-observation:cva6_packed_axi4' in entry
    assert 'unsupported-f5:cpu-irq-unwired:cva6_packed_axi4' in entry


@pytest.mark.skipif(not (EVIDENCE / 'logs/probe-run.log').is_file(),
                    reason='probe evidence not present in this checkout')
def test_saved_probe_log_supports_the_report():
    log = (EVIDENCE / 'logs/probe-run.log').read_text()
    assert 'verdict boot_fetch=observed tick=250 address=0x10000 arid=0 arlen=0' in log
    assert 'verdict case_A=observed' in log
    assert 'case A store_value 0x11 loaded_and_stored 0x1234' in log
    assert 'verdict case_B=stale_line_no_refetch' in log
    assert 'verdict case_C=refetch_after_reset' in log
    assert 'verdict case_D=refetched_after_fence' in log
    # A read burst is real: a line-fill request has ARLEN=1 and its first R beat
    # has RLAST=0, so a two-beat transfer cannot be mistaken for two single beats.
    assert re.search(r'^ar \d+ 0x80000000 id=0 len=1 size=3 kind=instruction$', log, re.M)
    assert re.search(r'^r \d+ 0x[0-9a-f]+ id=0 last=0 kind=instruction$', log, re.M)
    assert re.search(r'^r \d+ 0x[0-9a-f]+ id=0 last=1 kind=instruction$', log, re.M)
    # Every data beat is the D-side ID; every write strobe is a real one.
    data = re.findall(r'^ar \d+ (0x[0-9a-f]+) id=(\d+) len=0 size=\d+ kind=data$', log, re.M)
    assert data and {int(ident) for _, ident in data} == {1}
    assert re.search(r'^aw \d+ 0x20000 id=1 len=0 size=3$', log, re.M)
    assert re.search(r'^w \d+ data=0x123400000011 strb=ff last=1$', log, re.M)
    assert 'retirement unknown rvfi_pin=absent' in log
    summary = next(row for row in log.splitlines() if row.startswith('summary '))
    counts = dict(re.findall(r'(\w+)=(\d+)', summary))
    assert counts['ar_instruction'] == '20' and counts['ar_data'] == '126'
    assert counts['r_instruction'] == '32' and counts['aw'] == counts['w'] == counts['b'] == '126'
    identity = json.loads((EVIDENCE / 'identity.json').read_text())
    assert identity['rvfi_disposition'] == 'unconnected'
    assert identity['rvfi_bundle_bits'] == 6974
    assert identity['source_status'] == 'source_verified'


def test_report_states_unknowns_and_does_not_claim_f1():
    if not REPORT.is_file():
        pytest.skip('report not present in this checkout')
    text = REPORT.read_text()
    assert 'retirement unknown' in text or 'retirement = unknown' in text
    assert '未运行' in text or '仅分析' in text
    assert 'F1' in text
    for forbidden in ('F1 passed', 'F1 通过', '已通过全部'):
        assert forbidden not in text
