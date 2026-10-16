"""Declared new-to-F4 IP shape, not runtime/source authority or new RTL evidence."""
import copy,json,subprocess
from pathlib import Path
import pytest
from myfuzz.scenario.compiled_paths import load_path_compile_request,compile_paths
from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout

ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/'configs/scenarios/compiled-f4-obi-apb-timer'


def declared():return json.loads((CONFIG/'path_compile_request.json').read_text())


def test_real_timer_declaration_has_only_its_own_four_byte_candidate(monkeypatch):
 monkeypatch.setattr(subprocess,'Popen',lambda *a,**kw:pytest.fail('D3 declaration must not run tools/models'))
 result=compile_paths(load_path_compile_request(declared(),base_dir=ROOT))
 path=next(p for p in result['paths'] if p['flow_id']=='F4')
 assert path['status']=='executable',path['reason']
 sources=[s for s in path['sources'] if s['kind']!='instruction_image']
 assert len(sources)==1 and sources[0]['kind']=='cpu_mmio_stream'
 assert sources[0]['register']=='TIMER0_CTRL'
 assert sources[0]['register_access']['address']==0x40001004
 assert sources[0]['register_access']['register_offset']==4
 layout=compile_candidate_layout(path)
 assert layout.byte_length==4 and len(layout.slices)==1
 records=json.loads((CONFIG/'example_records.json').read_text())
 for raw,value in zip(records,(0x55,0xaa,0x12345678)):
  assert layout.decode(bytes.fromhex(raw))=={sources[0]['source_id']:value}
 assert next(p for p in result['paths'] if p['flow_id']=='F5')['status']=='unsupported'
 assert any(p['kind']=='ip_register_version' for p in path['prerequisites'])


def test_timer_capability_does_not_borrow_gpio_or_autonomous_count_semantics():
 from myfuzz.composition.component_profile import load_component_profile
 from myfuzz.composition.test_capability import load_ip_test_capability
 doc=json.loads((CONFIG/'test_capability.json').read_text())
 timer=load_component_profile(ROOT/'configs/peripherals/pulp_timer/component_profile.json')
 cap=load_ip_test_capability(doc,profile=timer)
 assert [(r.register,r.field) for r in cap.register_semantics]==[('TIMER0_CTRL','value')]
 assert cap.register_semantics[0].reset_value==0
 assert not cap.observation_mappings
 gpio=load_component_profile(ROOT/'configs/peripherals/pulp_gpio/component_profile.json')
 with pytest.raises(ValueError):load_ip_test_capability(doc,profile=gpio)


def test_generic_target_has_no_hidden_pin_source_or_setup():
 from myfuzz.local_harness import load_local_harness_request
 request=load_local_harness_request(json.loads((CONFIG/'requests/peripheral.json').read_text()))
 assert request.profile_path=='configs/peripherals/pulp_timer/component_profile.json'
 assert {r.kind for r in request.tuning.records}=={'endpoint_policies','apb_storage_observations'}
 assert [r.document() for r in request.tuning.records if r.kind=='apb_storage_observations']==[
  {'endpoint_id':'timer.bus','contract_id':'pulp-apb-timer.ctrl0.source.v1','register':'TIMER0_CTRL'}]
 supplement=json.loads((CONFIG/'execution_supplement.json').read_text())
 assert supplement['request_supplements']=={} and supplement['ownership']=={'fields':[],'owners':[]}
 assert supplement['physical_port_map']==[]


def test_pinned_timer_source_is_different_rtl_and_no_fallback_without_sidecar():
 import hashlib
 root=ROOT/'third_party/soc-pulp-apb-timer'
 assert hashlib.sha256((root/'src/apb_timer.sv').read_bytes()).hexdigest()=='22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778'
 assert hashlib.sha256((root/'src/timer.sv').read_bytes()).hexdigest()=='d352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce'
 missing=declared();missing['devices'][0].pop('test_capability')
 result=compile_paths(load_path_compile_request(missing,base_dir=ROOT))
 path=next(p for p in result['paths'] if p['flow_id']=='F4')
 assert path['status']=='unsupported'
 assert not any(s.get('register')=='TIMER0_COUNT' for s in path['sources'])


def test_source_evidence_covers_actual_ctrl_writer_and_readback_lines():
 doc=json.loads((CONFIG/'test_capability.json').read_text())
 ref=doc['register_semantics'][0]['evidence_ref'];ranges=ref.rsplit(':',1)[1].split(';',1)[0]
 covered=set()
 for span in ranges.split(','):
  bounds=[int(x) for x in span.split('-')]
  covered.update(range(bounds[0],bounds[-1]+1))
 assert {71,89,97,113,121,130,134,139}<=covered
 lines=(ROOT/'third_party/soc-pulp-apb-timer/src/timer.sv').read_text().splitlines()
 assert 'regs_n[`REG_TIMER_CTRL] = PWDATA;' in lines[96]
 assert 'PRDATA = regs_q[`REG_TIMER_CTRL];' in lines[120]
