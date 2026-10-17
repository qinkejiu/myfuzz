"""Source-only A2 producer controls; no DUT, frontend, model or live issuer."""
import copy,importlib
import pytest


def helper():
    try:return importlib.import_module('myfuzz.local_harness.apb_storage_startup')
    except ModuleNotFoundError:pytest.fail('A2 helper absent')


def contract():
    return helper().startup_contract(assert_ticks=2,release_ticks=1,
        snapshot_max={'backend':{},'physical':{},'storage_probes':{'storage_value':0xffffffff,'storage_reset':1}},
        source_contract_digest='1'*64,probe_digest='2'*64,
        reset_mapping={'runtime_port':'reset','assertion_high':True,'source_port':'HRESETn','source_active_low':True})


def test_contract_closed_identity_and_zero_clock_rendering():
    h=helper();c=contract();assert h.validate_startup_contract(c)==c
    assert c['total_ticks']==3 and c['page_size']==32 and c['retrieval']=='zero_clock_READ_APB_STORAGE_STARTUP'
    text=h.render_startup_helpers(c)
    assert text.count('tick(dut, &measured)')==1 and 'dut.reset =' not in text
    page=text[text.index('static std::string storage_startup_page'):]
    assert 'tick(' not in page and 'eval(' not in page
    for field in ('page_size','max_buffer_bytes','probe_digest','reset_mapping'):
        bad=copy.deepcopy(c);bad[field]=None
        with pytest.raises(ValueError):h.validate_startup_contract(bad)


@pytest.mark.parametrize('asserted,released',[(True,1),(0,1),(1025,1),(1,-1),(1,1025)])
def test_timing_bounds(asserted,released):
    h=helper();c=contract()
    with pytest.raises(ValueError):h.startup_contract(assert_ticks=asserted,release_ticks=released,
        snapshot_max={},source_contract_digest=c['source_contract_digest'],probe_digest=c['probe_digest'],reset_mapping=c['reset_mapping'])


def test_page_requires_actual_storage_reset_and_exact_widths():
    h=helper();c=contract();ports=[dict(name=name,width=width) for name,width in h.PORT_WIDTHS.items()]
    records=[]
    for i in range(1,4):
        reset=int(i<=2);sample={'storage_probes':dict.fromkeys(h.PORT_WIDTHS,0)|{'storage_reset':reset}}
        records.append(dict(startup_edge_index=i,reset_pre=reset,reset_post=reset,
            sample=dict(local_tick=i,pre=copy.deepcopy(sample),post=copy.deepcopy(sample))))
    page=dict(schema_version='apb_storage_startup_page.v1',page_index=0,page_count=1,total_ticks=3,assert_ticks=2,release_ticks=1,records=records)
    assert h.validate_startup_page(page,c,expected_page=0,ports=ports)==records
    for field,value in [('storage_reset',0),('storage_value',True),('storage_value',1<<32)]:
        bad=copy.deepcopy(page);bad['records'][0]['sample']['pre']['storage_probes'][field]=value
        with pytest.raises(ValueError):h.validate_startup_page(bad,c,expected_page=0,ports=ports)
    with pytest.raises(ValueError):h.validate_startup_page(page,c,expected_page=1,ports=ports)


def test_buffer_bound_rejects_excessive_snapshots():
    h=helper();c=contract()
    with pytest.raises(ValueError):h.startup_contract(assert_ticks=1024,release_ticks=1024,
        snapshot_max={'wide':'f'*100000},source_contract_digest=c['source_contract_digest'],probe_digest=c['probe_digest'],reset_mapping=c['reset_mapping'])

from tests.local_harness.test_generic_apb_identity import generated
from tests.local_harness.test_apb_storage_probe_generation import selected,ROOT,SELECTOR


def selected_startup(generated):
    from dataclasses import replace
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    from myfuzz.local_harness import runtime_renderer,render_local_harness
    base=selected(generated);doc=base.plan.request.tuning.document()
    doc['apb_storage_startup']=[dict(SELECTOR,endpoint_id=base.plan.binding.endpoints[0].endpoint_id)]
    plan=replace(base.plan,request=replace(base.plan.request,tuning=load_local_harness_tuning(doc)))
    return runtime_renderer.render_local_runtime(plan,render_local_harness(plan),base.source_verification,base_dir=ROOT)


def test_generation_optin_explicit_parser_and_zero_clock_dispatch(generated):
    from myfuzz.local_harness.driver_renderer import render_local_driver
    if generated[0].plan.profile.source.top_module!='apb_timer':
        with pytest.raises(ValueError):selected_startup(generated)
        return
    runtime=selected_startup(generated);driver=render_local_driver(runtime,base_dir=ROOT)
    c=driver.runtime_document['storage_startup_capture']
    assert c['total_ticks']==runtime.plan.request.reset_assert_ticks+runtime.plan.request.reset_release_ticks
    assert driver.runtime_document['driver_schema_version']=='local_driver_generation.apb_storage_startup.v2'
    assert 'CommandSet::ApbStorageStartup' in driver.cpp_text
    assert 'capture_storage_startup(dut);' in driver.cpp_text
    assert 'READ_APB_STORAGE_STARTUP' in driver.cpp_text
    assert 'ahb_startup' not in driver.cpp_text
    assert 'READY local_driver.v1 ' in driver.cpp_text
    assert helper().contract_from_document(driver.runtime_document)==c


def test_default_cpp_bytes_unchanged_and_no_selector_key(generated):
    import types
    from myfuzz.local_harness.driver_renderer import render_local_driver
    old=types.ModuleType('myfuzz.local_harness._before_a2');old.__file__=str(ROOT/'src/myfuzz/local_harness/driver_renderer.py')
    exec((ROOT/'.superpowers/apb-storage-startup-a2/driver_renderer.before.py').read_text(),old.__dict__)
    from myfuzz.local_harness import runtime_renderer,render_local_harness
    item=generated[0]
    base=runtime_renderer.render_local_runtime(item.plan,render_local_harness(item.plan),item.source_verification,base_dir=ROOT)
    assert old.render_local_driver(base,base_dir=ROOT).cpp_text==render_local_driver(base,base_dir=ROOT).cpp_text
    assert 'apb_storage_startup' not in base.plan.request.tuning.document()


def test_rehashed_startup_selection_mutation_refused(generated):
    from dataclasses import replace
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    if generated[0].plan.profile.source.top_module!='apb_timer':pytest.skip('timer source only')
    artifact=selected_startup(generated);doc=copy.deepcopy(artifact.runtime_document)
    doc['storage_startup_selection']['register']='TIMER1_CTRL'
    with pytest.raises(ValueError):verify_apb_register_trace(replace(artifact,runtime_document=doc))


def test_maximum_edges_and_typed_selection_endpoint_contract(generated):
    from types import SimpleNamespace
    h=helper();base=contract()
    c=h.startup_contract(assert_ticks=1024,release_ticks=1024,snapshot_max={},
        source_contract_digest=base['source_contract_digest'],probe_digest=base['probe_digest'],reset_mapping=base['reset_mapping'])
    assert c['total_ticks']==2048 and c['page_count']==64
    assert c['buffer_bound_bytes']<=8*1024*1024 and c['page_json_bound_bytes']<=1024*1024
    if generated[0].plan.profile.source.top_module!='apb_timer':return
    runtime=selected_startup(generated);plan=runtime.plan;probe=runtime.runtime_document['storage_observation']
    duplicate=SimpleNamespace(request=plan.request,binding=SimpleNamespace(endpoints=plan.binding.endpoints*2))
    with pytest.raises(ValueError):h.startup_selection(duplicate,probe)
    with pytest.raises(ValueError):h.startup_selection(plan,None)
    wrong=copy.deepcopy(probe);wrong['selection']['endpoint_id']='foreign.bus'
    with pytest.raises(ValueError):h.startup_selection(plan,wrong)


@pytest.mark.parametrize('mutation',['missing','extra','schema','digest','reset','bounds','nonoptin'])
def test_build_refuses_forged_startup_metadata_before_tools(generated,mutation,monkeypatch):
    from dataclasses import replace
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness import build
    from myfuzz.local_harness.renderer import _sha
    if generated[0].plan.profile.source.top_module!='apb_timer':pytest.skip('timer source only')
    artifact=render_local_driver(selected_startup(generated),base_dir=ROOT);doc=copy.deepcopy(artifact.runtime_document)
    if mutation=='missing':del doc['storage_startup_capture']
    elif mutation=='extra':doc['storage_startup_capture']['forged']=True
    elif mutation=='schema':doc['driver_schema_version']='local_driver_generation.v1'
    elif mutation=='digest':doc['storage_startup_capture']['probe_digest']='0'*64
    elif mutation=='reset':doc['storage_startup_capture']['reset_mapping']['source_active_low']=False
    elif mutation=='bounds':doc['storage_startup_capture']['page_size']=64
    else:del doc['storage_startup_selection']
    doc['artifact_digest']=_sha({k:v for k,v in doc.items() if k!='artifact_digest'})
    monkeypatch.setattr(build,'_toolchain',lambda:pytest.fail('tool query forbidden'))
    with pytest.raises(build.LocalHarnessBuildError):build._prepare(replace(artifact,runtime_document=doc),ROOT)


def test_mini_cpp_parser_explicit_optin_preserves_standard_and_ahb(tmp_path):
    import subprocess
    source=tmp_path/'parser.cpp';binary=tmp_path/'parser'
    source.write_text(r'''
#include "src/myfuzz/local_harness/rtl/local_driver_v1.h"
#include <cassert>
using namespace myfuzz::local_driver_v1;
int main(){
 const std::string prefix="CMD 0123456789abcdef0123456789abcdef 1 ";
 auto p=parse_command(prefix+"READ_APB_STORAGE_STARTUP 0",CommandSet::ApbStorageStartup);
 assert(p.ok);
 assert(!parse_command(prefix+"READ_APB_STORAGE_STARTUP 0").ok);
 assert(!parse_command(prefix+"READ_APB_STORAGE_STARTUP 0",CommandSet::AhbStartup).ok);
 assert(!parse_command(prefix+"READ_AHB_STARTUP 0",CommandSet::ApbStorageStartup).ok);
 assert(parse_command(prefix+"READ_AHB_STARTUP 0",CommandSet::AhbStartup).ok);
 for(auto value:{"00","40","-1","0 0"})
   assert(!parse_command(prefix+"READ_APB_STORAGE_STARTUP "+value,CommandSet::ApbStorageStartup).ok);
 BoundedReplay standard(4096,4096), optin(4096,4096,CommandSet::ApbStorageStartup);
 assert(standard.accept(p.command,0,512).decision!=Decision::Fresh);
 assert(optin.accept(p.command,0,512).decision==Decision::Fresh);
 optin.finish(1,"software_fixture");
 auto cached=optin.accept(p.command,0,512);
 assert(cached.decision==Decision::Cached && cached.reply=="software_fixture");
 auto conflict=parse_command(prefix+"READ_APB_STORAGE_STARTUP 1",CommandSet::ApbStorageStartup);
 assert(optin.accept(conflict.command,0,512).decision==Decision::Rejected);
}
''')
    subprocess.run(['c++','-std=c++17','-I',str(ROOT),str(source),'-o',str(binary)],check=True,capture_output=True)
    subprocess.run([str(binary)],check=True,capture_output=True)


def test_physical_verifier_refuses_rehashed_driver_capture_contract(generated):
    from dataclasses import replace
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    from myfuzz.local_harness.renderer import _sha
    if generated[0].plan.profile.source.top_module!='apb_timer':pytest.skip('timer source only')
    artifact=render_local_driver(selected_startup(generated),base_dir=ROOT);doc=copy.deepcopy(artifact.runtime_document)
    doc['storage_startup_capture']['native_verified']=True
    doc['artifact_digest']=_sha({k:v for k,v in doc.items() if k!='artifact_digest'})
    with pytest.raises(ValueError):verify_apb_register_trace(replace(artifact,runtime_document=doc))


def test_storage_probe_without_startup_keeps_old_cpp(generated):
    import types
    from myfuzz.local_harness.driver_renderer import render_local_driver
    if generated[0].plan.profile.source.top_module!='apb_timer':pytest.skip('registered timer only')
    base=selected(generated);old=types.ModuleType('myfuzz.local_harness._before_a2_storage');old.__file__=str(ROOT/'src/myfuzz/local_harness/driver_renderer.py')
    exec((ROOT/'.superpowers/apb-storage-startup-a2/driver_renderer.before.py').read_text(),old.__dict__)
    assert old.render_local_driver(base,base_dir=ROOT).cpp_text==render_local_driver(base,base_dir=ROOT).cpp_text


def test_selector_closed_roundtrip_and_duplicates():
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    assert load_local_harness_tuning({'apb_storage_startup':[SELECTOR]}).document()['apb_storage_startup']==[SELECTOR]
    for rows in ([SELECTOR,SELECTOR],[dict(SELECTOR,enabled=True)],[dict(SELECTOR,expression='fake')]):
        with pytest.raises(ValueError):load_local_harness_tuning({'apb_storage_startup':rows})


def test_selected_driver_does_not_claim_reset_authority_or_command_continuity(generated):
    from myfuzz.local_harness.driver_renderer import render_local_driver
    if generated[0].plan.profile.source.top_module!='apb_timer':pytest.skip('registered timer only')
    driver=render_local_driver(selected_startup(generated),base_dir=ROOT);c=driver.runtime_document['storage_startup_capture']
    assert all(c[k] is False for k in ('hierarchy_verified','native_verified','reset_authority','version_authority','source_authority'))
    assert c['prefix_claim']=='captured_reset_levels_only_no_command_continuity'
    cpp=driver.cpp_text
    assert cpp.count('capture_storage_startup(dut);')==2
    assert cpp.count('tick(dut, &measured);')==1
    assert 'command.fields[0] != storage_startup_next_page' in cpp
    assert cpp.index('replay.finish(command.sequence, terminal);')<cpp.index('++storage_startup_next_page;')
    assert 'if (local_ticks != 0' in cpp
    assert 'CommandSet::ApbStorageStartup' in cpp


def test_startup_handoff_requires_persistent_storage_reset_not_readback():
    h=helper()
    last=dict.fromkeys(h.PORT_WIDTHS,0)|dict(storage_value=9,storage_reset=0,storage_pready=1)
    pre=copy.deepcopy(last)|dict(storage_psel=1,storage_penable=1,storage_paddr=4,
        storage_pwrite=1,storage_pwdata=27)
    facts=h.validate_startup_handoff(last,pre,operation='ACCESS_APB3_REG',
        fields=(1,4,27,15),reset_observed=True)
    assert facts['namespace']=='startup_to_command'
    assert facts['readback_not_storage'] is True
    assert facts['startup_value']==9 and facts['command_value']==9
    # Combinational readback/ack roles are explicitly free to change.
    pre.update(storage_prdata=0xdead,storage_pready=1,storage_pslverr=0)
    assert h.validate_startup_handoff(last,pre,operation='ACCESS_APB3_REG',
        fields=(1,4,27,15),reset_observed=True)['command_value']==9
    for field,value in [('storage_value',10),('storage_reset',1)]:
        bad=copy.deepcopy(pre);bad[field]=value
        with pytest.raises(ValueError):h.validate_startup_handoff(last,bad,
            operation='ACCESS_APB3_REG',fields=(1,4,27,15),reset_observed=True)
    for field,value in [('storage_paddr',8),('storage_pwrite',0),('storage_pwdata',1)]:
        bad=copy.deepcopy(pre);bad[field]=value
        with pytest.raises(ValueError):h.validate_startup_handoff(last,bad,
            operation='ACCESS_APB3_REG',fields=(1,4,27,15),reset_observed=True)
    # Readback is not storage: a free readback change is legal, but a readback
    # that mirrors the old value cannot hide a changed storage value.
    free=copy.deepcopy(pre);free['storage_prdata']=10
    assert h.validate_startup_handoff(last,free,operation='ACCESS_APB3_REG',
        fields=(1,4,27,15),reset_observed=True)['command_value']==9
    bad=copy.deepcopy(pre);bad['storage_value']=10;bad['storage_prdata']=9
    with pytest.raises(ValueError):h.validate_startup_handoff(last,bad,
        operation='ACCESS_APB3_REG',fields=(1,4,27,15),reset_observed=True)
    with pytest.raises(ValueError):h.validate_startup_handoff(last,pre,
        operation='ACCESS_APB3_REG',fields=(1,4,27,15),reset_observed=False)
    with pytest.raises(ValueError):h.validate_startup_handoff(None,pre,
        operation='ACCESS_APB3_REG',fields=(1,4,27,15),reset_observed=True)
    idle=dict.fromkeys(h.PORT_WIDTHS,0)|dict(storage_value=9,storage_reset=0,storage_pready=1)
    assert h.validate_startup_handoff(last,idle,operation='STEP_APB3_REG',
        fields=(),reset_observed=True)['command_value']==9
    busy=copy.deepcopy(idle);busy['storage_psel']=1
    with pytest.raises(ValueError):h.validate_startup_handoff(last,busy,
        operation='STEP_APB3_REG',fields=(),reset_observed=True)


def test_startup_handoff_refuses_synthesized_reset_release():
    h=helper()
    last=dict.fromkeys(h.PORT_WIDTHS,0)|dict(storage_value=0,storage_reset=1,storage_pready=1)
    released=dict.fromkeys(h.PORT_WIDTHS,0)|dict(storage_value=0,storage_reset=0,storage_pready=1)
    with pytest.raises(ValueError):h.validate_startup_handoff(last,released,
        operation='STEP_APB3_REG',fields=(),reset_observed=True)
    assert h.validate_startup_handoff(last,dict(last),operation='STEP_APB3_REG',
        fields=(),reset_observed=True)['startup_reset']==1
