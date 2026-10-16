"""DMA Slice B: generation and host edge guard, without DMA transfer simulation."""
from dataclasses import replace
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.session import registered_operations
from myfuzz.protocols.catalog import load_builtin_protocol

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_wbdmac/component_profile.json',
        instance_id='dma', reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def test_pipelined_protocol_is_separate_and_has_no_invented_select():
    protocol = load_builtin_protocol('wishbone', 'pipelined')
    assert protocol.version != load_builtin_protocol('wishbone', 'classic').version
    fields = {f.field_id for f in protocol.fields}
    assert fields == {'cyc','stb','we','adr','dat_w','stall','ack','dat_r','err'}
    assert protocol.legal_adapters == ()


def test_generated_driver_exposes_both_bus_faces_and_one_edge_only(artifact):
    document = artifact.runtime_document
    assert document['kind'] == 'wishbone_dma'
    assert registered_operations('wishbone_dma') == {'STEP_WB_DMA'}
    assert document['dma_edge_contract']['input_order'] == [
        'swb_cyc','swb_stb','swb_we','swb_adr','swb_dat_w',
        'mwb_stall','mwb_ack','mwb_dat_r','mwb_err']
    ports = {p['name']:p for p in document['backend_ports']}
    assert ports['swb_adr']['width'] == 2
    assert ports['mwb_adr']['width'] == 30
    assert ports['mwb_dat_w']['direction'] == 'output'
    assert ports['mwb_dat_r']['direction'] == 'input'
    assert '.i_dev_ints(' in artifact.structural.wrapper_sv
    assert 'STEP_WB_DMA' in artifact.cpp_text
    assert 'WishboneDmaEdgeState' in artifact.cpp_text
    assert document['driver_limits']['max_samples_per_command'] == 1
    assert {r['contract']['side'] for r in document['selected_template']['executor']['protocol_templates']} == {'target','master'}


def test_policy_refuses_unowned_trigger_input(artifact):
    from myfuzz.local_harness.wishbone_dma_template import dma_edge_policy
    plan = artifact.plan
    dispositions = tuple(replace(r, disposition='functional', value=None)
        if r.port == 'i_dev_ints' else r for r in plan.dispositions)
    with pytest.raises(ValueError, match='dma-trigger-must-be-fixed-zero'):
        dma_edge_policy(replace(plan, dispositions=dispositions))


def test_native_edge_guard_and_command_parser(tmp_path):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('C++ compiler unavailable')
    program = tmp_path/'guard.cpp'
    program.write_text(r'''
#include "src/myfuzz/local_harness/rtl/wishbone_dma_edge.h"
#include "src/myfuzz/local_harness/rtl/local_driver_v1.h"
#include <cassert>
#include <string>
using myfuzz::local_driver_v1::WishboneDmaEdgeState;
int main() {
  WishboneDmaEdgeState state;
  assert(!state.check(true,true,false,false,false,true,false));
  state.commit(true,false);
  assert(state.check(true,true,false,false,false,true,false)); // held stb is a new acceptance
  assert(!state.check(true,true,true,true,false,true,false)); // stall may accompany older ack
  state.commit(false,true);
  assert(state.check(true,false,true,true,false,true,false)); // unsolicited ack
  assert(state.check(true,false,true,true,true,true,false)); // ack+err
  assert(state.check(true,true,false,true,false,true,false)); // unsupported same-edge response
  assert(state.check(false,false,true,false,false,false,true)); // slave stb without cyc
  auto parsed = myfuzz::local_driver_v1::parse_command(
    "CMD 0123456789abcdef0123456789abcdef 1 STEP_WB_DMA 1 1 1 3 ffffffff 1 0 ffffffff 0");
  assert(parsed.ok && parsed.command.fields.size()==9);
  auto bad = myfuzz::local_driver_v1::parse_command(
    "CMD 0123456789abcdef0123456789abcdef 2 STEP_WB_DMA 1 1 1 4 0 1 0 0 0");
  assert(!bad.ok);
}
''')
    built = subprocess.run([compiler,'-std=c++17','-I',str(ROOT),str(program),'-o',str(tmp_path/'guard')],capture_output=True,text=True)
    assert built.returncode == 0, built.stderr
    run = subprocess.run([str(tmp_path/'guard')],capture_output=True,text=True)
    assert run.returncode == 0, run.stderr


def test_build_identity_captures_dma_host_policy_and_protocol(artifact):
    from myfuzz.local_harness.build import local_build_identity
    identity = local_build_identity(artifact, base_dir=ROOT)
    inputs = {r['path'] for r in identity['inputs']}
    assert {'src/myfuzz/local_harness/wishbone_dma_template.py',
            'src/myfuzz/local_harness/wishbone_dma_fields.py',
            'src/myfuzz/local_harness/rtl/wishbone_dma_edge.h',
            'src/myfuzz/protocols/plugins/wishbone_pipelined.json'} <= inputs


def test_full_generated_transport_with_a_stub_model_ticks_once_and_replays(artifact, tmp_path):
    # This is deliberately a C++ host transport test, not a simulated DMA DUT.
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('C++ compiler unavailable')
    name = artifact.runtime_document['module_name']
    defaults = {'mwb_cyc':1, 'mwb_stb':1}
    fields = '\n'.join(f'  std::uint64_t {p["name"]} = {defaults.get(p["name"],0)};'
                       for p in artifact.runtime_document['runtime_ports'])
    (tmp_path/f'V{name}.h').write_text('#include <cstdint>\nstruct V'+name+' {\n'+fields+'\n void eval() {}\n void final() {}\n};\n')
    (tmp_path/'verilated.h').write_text('struct Verilated { static void commandArgs(int,char**) {} };\n')
    (tmp_path/'driver.cpp').write_text(artifact.cpp_text)
    built = subprocess.run([compiler,'-std=c++17',f'-DMYFUZZ_ARTIFACT_DIGEST={artifact.runtime_document["artifact_digest"]}',
        '-I',str(tmp_path),'-I',str(ROOT/'src/myfuzz/local_harness/rtl'),
        str(tmp_path/'driver.cpp'),'-o',str(tmp_path/'transport')],capture_output=True,text=True)
    assert built.returncode == 0, built.stderr
    prefix = 'CMD 0123456789abcdef0123456789abcdef '
    inputs = [prefix+'1 STEP_WB_DMA 0 0 0 0 0 0 0 0 0',
              prefix+'2 STEP_WB_DMA 0 0 0 0 0 1 1 0 1',
              prefix+'3 STEP_WB_DMA 0 0 0 0 0 1 1 0 0',
              prefix+'3 STEP_WB_DMA 0 0 0 0 0 1 1 0 0',
              prefix+'4 STEP_WB_DMA 0 0 0 0 0 1 1 0 0',
              prefix+'5 STEP_WB_DMA 0 1 0 0 0 1 0 0 0','END']
    result = subprocess.run([str(tmp_path/'transport')],input='\n'.join(inputs)+'\n',capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].startswith('READY local_driver.v1 ')
    replies = lines[1:]
    assert len(replies) == 6
    assert [replies[i].split()[0] for i in range(6)] == ['RESULT','ERROR','RESULT','RESULT','ERROR','ERROR']
    assert replies[2] == replies[3], 'cached transport replay must not advance an edge'
    payload = json.loads(bytes.fromhex(replies[0].split()[5]))
    assert len(payload['samples']) == 1
    assert payload['pre_backend'] == payload['samples'][0]['pre']['backend']
    assert 'physical' in payload['samples'][0]['post']
    assert replies[0].split()[3:5] == ['0','1']
    assert replies[2].split()[3:5] == ['1','2']
    assert replies[1].split()[3] == '1'
    assert replies[4].split()[3] == replies[5].split()[3] == '2'



def test_generated_dual_bus_top_elaborates_with_pinned_dma(artifact, tmp_path):
    if shutil.which('verilator') is None:
        pytest.skip('Verilator unavailable')
    wrapper = tmp_path/'structural.sv'
    runtime = tmp_path/'runtime.sv'
    wrapper.write_text(artifact.structural.wrapper_sv)
    runtime.write_text(artifact.runtime_sv)
    result = subprocess.run(['verilator','--lint-only','-Wno-fatal','--top-module',
        artifact.runtime_document['module_name'],
        str(ROOT/'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v'),
        str(wrapper),str(runtime)],capture_output=True,text=True,timeout=60)
    assert result.returncode == 0, result.stdout+result.stderr
