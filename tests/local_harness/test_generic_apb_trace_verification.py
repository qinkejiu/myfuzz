"""Pure generated wiring/diagnostic checks; no live storage authority."""
import copy
from dataclasses import replace
from types import SimpleNamespace
import pytest
from tests.local_harness.test_generic_apb_identity import generated


def verifier():
 from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
 return verify_apb_register_trace


def test_generic_trace_uses_actual_resolved_abi(generated):
 artifact,_=generated
 assert verifier()(artifact) is True
 assert artifact.runtime_document['kind']=='apb3_register_observe'
 assert 'native_physical_observation_contract' not in artifact.runtime_document


@pytest.mark.parametrize('change',[
 lambda d:d['base_protocol_trace'].update(endpoint_id='other'),
 lambda d:d['base_protocol_trace']['signals'].update(pready='m_rsp_valid'),
 lambda d:d['base_protocol_trace']['signal_widths'].update(pready=True),
 lambda d:d['base_protocol_trace'].update(max_wait_cycles=True),
 lambda d:d['base_protocol_trace'].update(clock_domain='foreign'),
 lambda d:d.update(raw_observation_schema_version='other'),
 lambda d:d.update(functional_scope='invented_peer'),
 lambda d:d['runtime_ports'].append(dict(name='trace_psel',direction='output',width=1)),
 lambda d:next(r for r in d['runtime_ports'] if r['name']=='trace_psel').update(width=True),
 lambda d:d['backend_ports'].append(copy.deepcopy(next(r for r in d['backend_ports'] if r['name']=='trace_psel'))),
 lambda d:d.update(effective_max_wait_cycles=True),
 lambda d:d.update(structural_abi={}),
])
def test_generic_trace_refuses_metadata_mutations(generated,change):
 artifact,_=generated;doc=copy.deepcopy(artifact.runtime_document);change(doc)
 with pytest.raises(ValueError):verifier()(replace(artifact,runtime_document=doc))


def test_generic_trace_refuses_rewired_or_missing_native_assign(generated):
 artifact,_=generated
 for text in (artifact.runtime_sv.replace('assign trace_psel =','assign changed_trace_psel ='),
              artifact.runtime_sv+'\nassign trace_psel = 1\'b1;\n'):
  with pytest.raises(ValueError):verifier()(replace(artifact,runtime_sv=text))


def test_non_apb_runtime_is_not_admitted(generated):
 artifact,_=generated;doc=copy.deepcopy(artifact.runtime_document);doc['kind']='axi4lite_register_observe'
 assert verifier()(replace(artifact,runtime_document=doc)) is False


def test_actual_generic_trace_join_remains_diagnostic(generated):
 from myfuzz.integration.generated_register_writer import check_writer_observation
 artifact,_=generated;trace=artifact.runtime_document['base_protocol_trace'];signals=trace['signals']
 access=dict(source_component='processor',target_component='target',device_id='window',address=0x40001004,register_offset=4)
 value=0x55;events=[]
 for write,base in ((True,0),(False,4)):
  transaction=dict(source_component='processor',source_sequence=base+1)
  events.append(dict(kind='mmio_acceptance',component='processor',source_transaction=transaction,address=access['address'],write=write,event_id=base+1))
  payload=dict(psel=1,penable=1,pready=1,pwrite=int(write),paddr=4,pslverr=0)
  payload['pwdata' if write else 'prdata']=value
  events.append(dict(kind='local_tick_sample',component='target',phase='pre',producer_event_id=base+3,event_id=base+2,outputs=dict(backend={signals[k]:v for k,v in payload.items()})))
  delivery=dict(kind='mmio_delivery',component='processor',device_id='window',address=access['address'],write=write,event_id=base+3,producer_event_id=base+3,source_transaction=transaction,byte_enable=15)
  delivery['write_value' if write else 'read_value']=value;events.append(delivery)
 events.append(dict(kind='memory_write',component='processor',address=0x100fc,value=value,byte_enable=15,event_id=8,transaction={'actual_fixture':'software_only'}))
 receipt=SimpleNamespace(events=events,case_id='software_fixture')
 declaration=dict(candidate=dict(access=access,value=value),result_address=0x100fc,refusals=['register-version-unavailable'])
 result=check_writer_observation(declaration,receipt,target_artifact=artifact)
 assert result['runtime_admitted'] is False and result['register_version_authenticated'] is False
 assert len(result['joins'])==2 and result['RAM_event']==8
 bad=copy.deepcopy(events);bad[1]['outputs']['backend'][signals['pready']]=0
 with pytest.raises(ValueError,match='native-APB-transfer'):
  check_writer_observation(declaration,SimpleNamespace(events=bad,case_id='software_fixture'),target_artifact=artifact)


def test_second_driver_refused_even_if_runtime_hash_is_recomputed(generated):
 import hashlib
 artifact,_=generated
 text=artifact.runtime_sv+"\nassign trace_psel = 1'b1;\n"
 doc=copy.deepcopy(artifact.runtime_document);doc['runtime_sv_sha256']=hashlib.sha256(text.encode()).hexdigest()
 with pytest.raises(ValueError):verifier()(replace(artifact,runtime_document=doc,runtime_sv=text))


def test_legacy_gpio_dispatch_keeps_existing_native_verifier(monkeypatch):
 from myfuzz.local_harness import native_physical_observation as module
 artifact=SimpleNamespace(runtime_document={'kind':'apb_gpio'})
 calls=[]
 monkeypatch.setattr(module,'verify_native_physical_observation',lambda actual:calls.append(actual) or True)
 assert module.verify_apb_register_trace(artifact) is True and calls==[artifact]
