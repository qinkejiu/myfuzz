"""Software-only projections of the required epoch execution joins."""
from types import SimpleNamespace
from hashlib import sha256
import pytest

from myfuzz.integration.compiled_f6_firmware import _jal
from myfuzz.scenario.ledger import TransactionKey


def sample():
    from myfuzz.scenario import f6_instruction_fetch_receipt as issuer
    boot_address=0x10000; entry=0x11000; jump_address=boot_address+4
    word=_jal(entry-jump_address)
    data=bytes.fromhex('13000000')+word.to_bytes(4,'little')
    tx=dict(execution_id='local-execution',testcase_id='test',source_component='cpu',
            source_epoch=1,channel_id='instr',source_sequence=1)
    key=TransactionKey('local-execution','test','cpu',1,'instr',2)
    post={'rvfi_valid':1,'rvfi_pc_rdata':jump_address,'rvfi_insn':word,'rvfi_order':7}
    events=[
        dict(event_id=1,kind='reset_barrier',policy='warm_all'),
        dict(event_id=2,kind='reset_image',reset_event_id=1,component='cpu',
             address=boot_address,data_hex=data.hex()),
        dict(event_id=3,kind='memory_read',component='cpu',address=jump_address,
             data_hex=data[-4:].hex(),transaction=tx,writer_event_ids=['reset-image:2']*4),
        dict(event_id=4,component='cpu',local_tick=2,outputs=dict(instr_rsp_consumed=1,
             instr_rsp_source_epoch=1,instr_rsp_source_sequence=1,instr_rsp_rdata=word)),
        dict(event_id=5,kind='instr_response',component='cpu',address=jump_address,
             transaction=tx,rdata=word,error=0,response_tick=2,producer_event_id=4),
        dict(event_id=6,component='cpu',local_tick=3,
             outputs=dict(driver_samples=[dict(post=dict(physical=post))])),
        dict(event_id=7,kind='cpu_retire',schema_version='cpu_retire.v2',component='cpu',
             pc_rdata=jump_address,insn=word,valid=1,order=7,local_tick=3,
             command_scope=dict(component='cpu',reset_epoch=1),producer_event_id=6,
             observation=dict(physical=post)),
        dict(event_id=8,kind='compiled_F6_instruction_fetch_completion',component='cpu',
             case_id='case',address=entry,reset_epoch=1,execution='new',
             key=dict(execution_id='local-execution',testcase_id='test',source_component='cpu',
                      source_epoch=1,channel_id='instr',source_sequence=2))]
    cpu=SimpleNamespace(reset_epoch=1,_execution='new',
        _physical_outputs=lambda payload:payload['observations']['physical'])
    runner=SimpleNamespace(event_count=len(events),
        _event_refs_since=lambda start,stop=None:events[start:stop],
        _event_ref_by_id=lambda event_id:next((e for e in events if e['event_id']==event_id),None))
    runtime=SimpleNamespace(cpu=cpu,cpu_id='cpu',runner=runner,
        _f6_epoch_program=dict(barrier_event_id=1,image_event_id=2,reset_epoch=1,
            boot_sha256=sha256(data).hexdigest(),manifest_sha256='a'*64,
            entry=dict(entry_address=entry,slot=1)))
    prefix=bytes.fromhex('13000000')*32
    receipt=SimpleNamespace(address=entry,case_id='case',reset_epoch=1,execution='new',key=key,
        acceptance=SimpleNamespace(address=entry,data=prefix),snapshot=SimpleNamespace(data=prefix[:4]))
    result=dict(status='passed',case_id='case',instruction_address=entry,prefix_hex=prefix.hex())
    return runtime,result,events,receipt,issuer


def test_epoch_receipt_joins_reset_image_jump_retirement_and_native_slot_fetch(monkeypatch):
    from myfuzz.integration.compiled_f6 import _f6_epoch_execution_receipt
    runtime,result,events,receipt,issuer=sample()
    monkeypatch.setattr(issuer,'f6_instruction_fetch_receipts',lambda cpu:(receipt,))
    monkeypatch.setattr(issuer,'validate_f6_instruction_fetch',lambda cpu,item:None)
    evidence=_f6_epoch_execution_receipt(runtime,result)
    assert evidence['manifest_sha256']=='a'*64
    assert evidence['entry']['entry_address']==0x11000
    assert evidence['evidence']==dict(image_event_id=2,boot_read_event_id=3,
        boot_response_event_id=5,boot_retirement_event_id=7,slot_fetch_event_id=8)


@pytest.mark.parametrize('mutation',['wrong_writer','wrong_retirement','wrong_epoch',
                                     'missing_fetch','wrong_jump','wrong_response','failed_case'])
def test_epoch_receipt_is_missing_without_a_real_matching_chain(monkeypatch,mutation):
    from myfuzz.integration.compiled_f6 import _f6_epoch_execution_receipt
    runtime,result,events,receipt,issuer=sample()
    monkeypatch.setattr(issuer,'f6_instruction_fetch_receipts',lambda cpu:(receipt,))
    monkeypatch.setattr(issuer,'validate_f6_instruction_fetch',lambda cpu,item:None)
    if mutation=='wrong_writer':events[2]['writer_event_ids']=['old']*4
    elif mutation=='wrong_retirement':events[6]['insn']^=1
    elif mutation=='wrong_epoch':events[6]['command_scope']['reset_epoch']=0
    elif mutation=='missing_fetch':events.pop()
    elif mutation=='wrong_jump':runtime._f6_epoch_program['entry']['entry_address']+=4
    elif mutation=='wrong_response':events[3]['outputs']['instr_rsp_consumed']=0
    else:result['status']='failed'
    assert _f6_epoch_execution_receipt(runtime,result) is None


def test_epoch_receipt_refuses_an_unvalidated_live_fetch_issuer(monkeypatch):
    from myfuzz.integration.compiled_f6 import _f6_epoch_execution_receipt
    runtime,result,events,receipt,issuer=sample()
    monkeypatch.setattr(issuer,'f6_instruction_fetch_receipts',lambda cpu:(receipt,))
    def reject(cpu,item): raise ValueError('no-live-issuer')
    monkeypatch.setattr(issuer,'validate_f6_instruction_fetch',reject)
    assert _f6_epoch_execution_receipt(runtime,result) is None


@pytest.mark.parametrize('proof',[None,{'manifest_sha256':'a'*64,'entry':{'slot':1},
                                      'evidence':{'slot_fetch_event_id':8}}])
def test_actual_submit_attaches_only_available_epoch_evidence(monkeypatch,proof):
    from myfuzz.integration import compiled_f6
    candidate=SimpleNamespace(raw=b'12345678',words=(1,2,3,4))
    base=dict(status='passed',case_id='run:case:0',case_index=0,
              instruction_address=0x11000,prefix_hex='13000000',feedback=[1]*5)
    runtime=SimpleNamespace(contract={'program_contract':{'slot_base':0x11000,'slot_count':2}},
        finished=False,_stop_after_expected_error=False,_terminal_error=None,cursor=0,max_cases=2,
        run_id='run',records=[],attempts=[],preflight=lambda raw:candidate,
        _verify_live_owner=lambda:None,_execute_case=lambda *args:dict(base),
        _drain_observer_view=lambda:None,_f6_epoch_program={'entry':{'slot':1}})
    monkeypatch.setattr(compiled_f6,'_f6_epoch_execution_receipt',lambda carrier,result:proof)
    returned=compiled_f6.CompiledF6Runtime.submit(runtime,candidate.raw)
    if proof is None:
        assert 'epoch_program' not in returned
    else:
        assert returned['epoch_program']==proof
    # Frozen evidence and per-case internal result stay unchanged.
    assert runtime.attempts[0]['result']==base
