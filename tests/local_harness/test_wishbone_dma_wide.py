"""Wide DMA control addresses are derived from the actual bus profile."""
import pytest
from dataclasses import replace
from test_wishbone_dma_transport import artifact

from myfuzz.local_harness.wishbone_dma_fields import dma_edge_contract, selected_dma_edge_contract


def test_wide_word_control_uses_new_operation_and_preserves_old_contracts():
    legacy=dma_edge_contract()
    assert legacy['operation']=='STEP_WB_DMA' and legacy['input_maxima'][3]==3
    assert selected_dma_edge_contract()['operation']=='STEP_WB_DMA_SEL'
    for selected,make in ((False,dma_edge_contract),(True,selected_dma_edge_contract)):
        wide=make(control_address_width=4)
        assert wide['operation']==('STEP_WB_DMA_SEL_WIDE' if selected else 'STEP_WB_DMA_WIDE')
        assert wide['input_maxima'][3]==15
        assert wide['control_address_width']==4 and wide['control_address_units']=='word_index'


@pytest.mark.parametrize('width',[0,1,33,True])
def test_invalid_wide_control_width_is_refused(width):
    with pytest.raises(ValueError):
        dma_edge_contract(control_address_width=width)


def test_dma_policy_accepts_actual_wide_word_control_shape(artifact):
    from myfuzz.local_harness.wishbone_dma_template import dma_edge_policy
    old=artifact.plan
    capabilities={**old.profile.capabilities,'address_width':4}
    profile=replace(old.profile,capabilities=capabilities,
        address=replace(old.profile.address,window_size=64,alignment=64))
    endpoints=[]
    for endpoint in old.binding.endpoints:
        if endpoint.function=='mmio_slave':
            endpoint=replace(endpoint,fields=tuple(replace(f,width=4,raw_hi=3,port_width=4)
                if f.role=='adr' else f for f in endpoint.fields))
        endpoints.append(endpoint)
    plan=replace(old,profile=profile,binding=replace(old.binding,endpoints=tuple(endpoints)))
    control,master,irq,contracts=dma_edge_policy(plan)
    assert next(f.width for f in control.fields if f.role=='adr')==4
    assert len(contracts)==2


def test_wide_session_routes_declared_offset_and_rejects_outside_window(artifact,tmp_path,monkeypatch):
    from types import SimpleNamespace
    from pathlib import Path
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
    profile=replace(artifact.plan.profile,capabilities={**artifact.plan.profile.capabilities,'address_width':4},
        address=replace(artifact.plan.profile.address,window_size=32,alignment=16))
    plan=replace(artifact.plan,profile=profile)
    runtime={**artifact.runtime_document,'dma_edge_contract':dma_edge_contract(control_address_width=4)}
    session=GeneratedWishboneDmaSession(replace(artifact,plan=plan,runtime_document=runtime),
        base_dir=Path.cwd(),cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=0,max_initialized_bytes=16,
            regions=(MemoryRegion('ram',0x1000,16),)))
    calls=[]
    def step(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(payload={'pre_backend':{'swb_stall':0,'swb_ack':int(len(calls)==2),'swb_dat_r':0x37}})
    monkeypatch.setattr(session,'step_local',step)
    assert session.read_register(28)==0x37
    assert calls[0]['adr']==7 and calls[1]['adr']==7
    for offset in (29,32,64,-4):
        with pytest.raises(ValueError):session.read_register(offset)


def test_dma_control_holds_strobe_until_actual_acceptance(artifact,tmp_path,monkeypatch):
    from types import SimpleNamespace
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
    session=GeneratedWishboneDmaSession(artifact,base_dir=tmp_path,cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=0,max_initialized_bytes=16,
            regions=(MemoryRegion('ram',0x1000,16),)))
    calls=[]
    def step(**kwargs):
        calls.append(kwargs)
        index=len(calls)
        return SimpleNamespace(payload={'pre_backend':{'swb_stall':int(index<=2),
            'swb_ack':int(index==4),'swb_dat_r':0x37}})
    monkeypatch.setattr(session,'step_local',step)
    assert session.read_register(4)==0x37
    assert [call.get('stb',0) for call in calls]==[1,1,1,0,0]
    assert all(call.get('adr')==1 for call in calls[:-1])


@pytest.mark.parametrize('stall',[0,1])
def test_dma_control_rejects_ack_before_acceptance(artifact,tmp_path,monkeypatch,stall):
    from types import SimpleNamespace
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
    session=GeneratedWishboneDmaSession(artifact,base_dir=tmp_path,cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=0,max_initialized_bytes=16,
            regions=(MemoryRegion('ram',0x1000,16),)))
    monkeypatch.setattr(session,'step_local',lambda **kw:SimpleNamespace(
        payload={'pre_backend':{'swb_stall':stall,'swb_ack':1,'swb_dat_r':0}}))
    with pytest.raises(RuntimeError,match='ACK before registered acceptance'):
        session.read_register(4)


def test_driver_parser_accepts_wide_operation_without_weakening_legacy(tmp_path):
    import shutil,subprocess
    from pathlib import Path
    compiler=shutil.which('g++')
    if compiler is None:pytest.skip('C++ compiler unavailable')
    root=Path(__file__).resolve().parents[2]
    source=tmp_path/'wide.cpp'
    source.write_text(r'''
#include "src/myfuzz/local_harness/rtl/local_driver_v1.h"
#include <cassert>
int main() {
  using myfuzz::local_driver_v1::parse_command;
  assert(!parse_command("CMD 0123456789abcdef0123456789abcdef 1 STEP_WB_DMA 1 1 1 4 0 0 0 0 0").ok);
  assert(parse_command("CMD 0123456789abcdef0123456789abcdef 1 STEP_WB_DMA_WIDE 1 1 1 4 0 0 0 0 0").ok);
  assert(parse_command("CMD 0123456789abcdef0123456789abcdef 1 STEP_WB_DMA_SEL_WIDE 1 1 1 4 0 f 0 0 0 0").ok);
}
''')
    built=subprocess.run([compiler,'-std=c++17','-I',str(root),str(source),'-o',str(tmp_path/'wide')],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    run=subprocess.run([str(tmp_path/'wide')],capture_output=True,text=True)
    assert run.returncode==0,run.stderr


@pytest.mark.parametrize('selected',[False,True])
def test_wide_runtime_and_driver_render_physical_address_width(artifact,monkeypatch,selected):
    """Synthetic wider physical ABI; no claim of a matching RTL execution."""
    from pathlib import Path
    from myfuzz.local_harness.renderer import render_local_harness
    from myfuzz.local_harness.runtime_renderer import _render_admitted_runtime
    from myfuzz.local_harness import driver_renderer
    if selected:
        from myfuzz.scenario.ibex_pulp_dual_source import _artifact
        from myfuzz.composition.component_profile import elaboration_mode_scope
        from myfuzz.local_harness.build import host_source_discovery_scope
        from myfuzz.local_harness.execution_validation import execution_validation_scope
        with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
            artifact=_artifact('configs/peripherals/zipdma_smoke/component_profile.json','dma')
    old=artifact.plan
    target=next(e for e in old.binding.endpoints if e.function=='mmio_slave')
    port=next(f.port for f in target.fields if f.role=='adr')
    bindings=[]
    for endpoint in old.binding.endpoints:
        if endpoint.function=='mmio_slave':
            endpoint=replace(endpoint,fields=tuple(replace(f,width=4,raw_hi=3,port_width=4)
                if f.role=='adr' else f for f in endpoint.fields))
        bindings.append(endpoint)
    profile=replace(old.profile,capabilities={**old.profile.capabilities,'address_width':4},
        address=replace(old.profile.address,window_size=64,alignment=64))
    facts=replace(old.facts,ports=tuple(replace(p,width=4) if p.name==port else p for p in old.facts.ports))
    dispositions=tuple(replace(d,width=4,bit_hi=3) if d.port==port else d for d in old.dispositions)
    plan=replace(old,profile=profile,facts=facts,binding=replace(old.binding,endpoints=tuple(bindings)),
        dispositions=dispositions)
    structural=render_local_harness(plan)
    top=_render_admitted_runtime(plan,structural,artifact.source_verification,Path.cwd(),native_raw=False)
    assert next(p['width'] for p in top.runtime_document['backend_ports'] if p['name']=='swb_adr')==4
    monkeypatch.setattr(driver_renderer,'render_local_runtime',lambda *args,**kwargs:top)
    driver=driver_renderer.render_local_driver(top,base_dir=Path.cwd())
    assert driver.runtime_document['dma_edge_contract']['operation']==('STEP_WB_DMA_SEL_WIDE' if selected else 'STEP_WB_DMA_WIDE')
    assert 'dma_control_address_out_of_range' in driver.cpp_text
    assert 'command.fields[3] > 15ULL' in driver.cpp_text
    from myfuzz.integration.compiled_f6_runtime_path import _artifact_link_document
    from myfuzz.local_harness.dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
    link=_artifact_link_document(driver)
    assert validate_dma_artifact_endpoint_links(link,driver)
@pytest.mark.parametrize('control_selected,master_selected',[(True,False),(False,True)])
@pytest.mark.parametrize('width',[2,4])
def test_mixed_select_render_and_link_use_real_declared_sides(monkeypatch,tmp_path,control_selected,master_selected,width):
    """Synthetic port facts exercise each mixed shape, not native execution."""
    from pathlib import Path
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.renderer import render_local_harness
    from myfuzz.local_harness.runtime_renderer import _render_admitted_runtime
    from myfuzz.local_harness import driver_renderer
    from myfuzz.integration.compiled_f6_runtime_path import _artifact_link_document
    from myfuzz.local_harness.dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        artifact=_artifact('configs/peripherals/zipdma_smoke/component_profile.json','dma')
    old=artifact.plan
    missing_function='memory_master' if control_selected else 'mmio_slave'
    endpoint=next(e for e in old.binding.endpoints if e.function==missing_function)
    missing_port=next(f.port for f in endpoint.fields if f.role=='sel')
    binding=replace(old.binding,endpoints=tuple(replace(e,fields=tuple(f for f in e.fields if f.role!='sel'))
        if e.function==missing_function else e for e in old.binding.endpoints))
    endpoints=tuple(replace(e,fields=tuple(f for f in e.fields if f.role!='sel'))
        if e.function==missing_function else e for e in old.profile.endpoints)
    caps={**old.profile.capabilities,'byte_enable':control_selected,'partial_write':control_selected,
        'master_byte_enable':master_selected,'master_fixed_byte_enable':None if master_selected else 15,
        'local_runtime_variant':('wishbone_dma_control_selected_edge_v1' if control_selected
                                 else 'wishbone_dma_master_selected_edge_v1')}
    if width != 2:
        adr_port=next(f.port for e in binding.endpoints if e.function=='mmio_slave'
            for f in e.fields if f.role=='adr')
        binding=replace(binding,endpoints=tuple(replace(e,fields=tuple(
            replace(f,width=width,raw_hi=width-1,port_width=width) if f.role=='adr' else f
            for f in e.fields)) if e.function=='mmio_slave' else e for e in binding.endpoints))
        endpoints=tuple(replace(e,fields=tuple(replace(f,width=width) if f.role=='adr' else f
            for f in e.fields)) if e.function=='mmio_slave' else e for e in endpoints)
        caps['address_width']=width
    profile=replace(old.profile,endpoints=endpoints,capabilities=caps,
        address=replace(old.profile.address,window_size=4*(1 << width),alignment=4*(1 << width)))
    plan=replace(old,profile=profile,binding=binding,
        facts=replace(old.facts,ports=tuple(replace(p,width=width) if width != 2 and p.name==adr_port else p
            for p in old.facts.ports if p.name!=missing_port)),
        dispositions=tuple(replace(d,width=width,bit_hi=width-1) if width != 2 and d.port==adr_port else d
            for d in old.dispositions if d.port!=missing_port))
    structural=render_local_harness(plan)
    top=_render_admitted_runtime(plan,structural,artifact.source_verification,Path.cwd(),native_raw=False)
    monkeypatch.setattr(driver_renderer,'render_local_runtime',lambda *args,**kwargs:top)
    driver=driver_renderer.render_local_driver(top,base_dir=Path.cwd())
    names={p['name'] for p in driver.runtime_document['backend_ports']}
    assert ('swb_sel' in names)==control_selected
    assert ('mwb_sel' in names)==master_selected
    edge=driver.runtime_document['dma_edge_contract']
    assert (edge.get('control_byte_enable_signal')=='swb_sel')==control_selected
    assert (edge.get('master_byte_enable_signal')=='mwb_sel')==master_selected
    link=_artifact_link_document(driver)
    assert validate_dma_artifact_endpoint_links(link,driver)
    from types import SimpleNamespace
    from myfuzz.scenario.f6_dma_source_provider import f6_dma_static_bindings
    monkeypatch.setattr('myfuzz.composition.component_profile.elaborate_profile',lambda *a,**kw:plan.facts)
    provider=SimpleNamespace(source={'schema_version':'declared_f6_dma_source_contract.v1'},
        master_endpoint_id='dma.memory',control_endpoint_id='dma.control')
    master,control=f6_dma_static_bindings(provider,profile,base_dir=Path.cwd())
    assert master==link['links'][0]
    assert control['variant_id']==('dma-selected' if control_selected else 'dma-full-word-no-select')
    import json
    from myfuzz.local_harness.harness_set import _preflight_dma_routes
    compose=json.loads((Path.cwd()/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/compose.json').read_text())
    for row in compose['dma_master_route_bindings']:
        row['initiator_template']['variant_id']='dma-selected' if master_selected else 'dma-full-word-no-select'
    request={**compose['cpu'],'devices':compose['devices'],'memory':compose['memory'],
        'dma_master_routes':compose['dma_master_routes'],
        'dma_master_route_bindings':compose['dma_master_route_bindings']}
    bindings=_preflight_dma_routes(request,{'dma':plan,'cpu':plan})
    assert {row['initiator']['variant_id'] for row in bindings} == {
        'dma-selected' if master_selected else 'dma-full-word-no-select'}
    from myfuzz.local_harness.dma_artifact_endpoint_links import dma_link_provider_contract, _sha
    wrong=dma_link_provider_contract(control_address_width=width,
        control_selected=not control_selected,master_selected=master_selected)
    link['provider_contract_sha256']=_sha(wrong)
    link['identity_sha256']=_sha({k:v for k,v in link.items() if k!='identity_sha256'})
    with pytest.raises(ValueError):
        validate_dma_artifact_endpoint_links(link,driver)
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.local_harness.wire import DriverReceipt
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    session=GeneratedWishboneDmaSession(driver,base_dir=tmp_path,cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=0,max_initialized_bytes=16,
            regions=(MemoryRegion('ram',0x1000,16),)))
    session._execution='synthetic';session._case_id='synthetic'
    sent=[]
    def command(op,fields):
        sent.append((op,fields))
        pre=dict(mwb_cyc=1,mwb_stb=1,mwb_we=1,mwb_adr=0x400,mwb_dat_w=7)
        if master_selected:pre['mwb_sel']=7
        return DriverReceipt('result','synthetic',1,0,1,1,
            payload={'pre_backend':pre,'observations':{'backend':{'mwb_stb':1}}})
    monkeypatch.setattr(session,'command',command)
    session.step_local(cyc=1,stb=1,sel=3 if control_selected else 15)
    assert len(sent[0][1])==(10 if control_selected else 9)
    assert session.events[-1]['accepted']['byte_enable']==(7 if master_selected else 15)
