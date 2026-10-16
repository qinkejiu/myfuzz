"""Actual Python Popen/wire mechanics, explicitly not native RTL eligibility."""
import json
from pathlib import Path
import pytest
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory


def wire_local(factory, directory, *, bad_ready=False, bad_padcfg=False, error=0, bad_ack=False):
    """Construct an actual target with a bounded READY/CMD/ACK/END software process."""
    local = factory().sessions['gpio_a']
    digest, asserted, released, _ = local._expected_ready()
    ready = f'READY local_driver.v1 {"0"*64 if bad_ready else digest} {asserted:x} {released:x}'
    worker = directory / 'wire-worker.py'
    worker.write_text('''#!/usr/bin/env python3
import sys,json
ready=READY
print(ready,flush=True)
tick=0
for line in sys.stdin:
 parts=line.split()
 if parts[0]=='END':break
 if parts[0]=='ACK':
  print('ACKED '+parts[1]+' '+parts[2]+' '+format(tick+BAD_ACK,'x'),flush=True);continue
 _,execution,sequence,operation,*fields=parts
 fields=[int(value,16) for value in fields]
 before=tick;count=3 if operation=='ACCESS_GPIO' else 1
 observed=dict(gpio_out=0,gpio_dir=0,gpio_in_sync=0,gpio_padcfg=PADCFG,interrupt=0,backend={},physical={})
 samples=[]
 for index in range(count):
  tick+=1
  state=dict(observed)
  state['backend']=dict(trace_psel=int(operation=='ACCESS_GPIO' and index<2),trace_penable=int(index==1),trace_pready=1,trace_pslverr=ERROR,trace_paddr=fields[2] if operation=='ACCESS_GPIO' else 0,trace_pwrite=fields[1] if operation=='ACCESS_GPIO' else 0,trace_pwdata=fields[3] if operation=='ACCESS_GPIO' else 0,trace_prdata=0)
  samples.append(dict(local_tick=tick,pre=state,post=state))
 payload=dict(schema_version='local_driver_result.v1',kind='apb_gpio',samples=samples,observations=observed,pre_backend={},rdata=0,error=ERROR)
 encoded=json.dumps(payload,sort_keys=True,separators=(',',':')).encode().hex()
 print('RESULT '+execution+' '+sequence+' '+format(before,'x')+' '+format(tick,'x')+' '+encoded,flush=True)
'''.replace('READY',repr(ready)).replace('BAD_ACK',str(int(bad_ack))).replace('PADCFG',repr('g'*32 if bad_padcfg else '0'*32)).replace('ERROR',str(error)))
    worker.chmod(0o700)
    local._binary = worker
    local.command_timeout_seconds = 2
    return local


@pytest.fixture
def mechanical_local(native_factory, tmp_path):
    local = wire_local(native_factory, tmp_path)
    yield local
    if local.process is not None:
        try:
            local.end_case()
        except ValueError:
            if local.process is not None:
                raise


def test_actual_ready_reset_close_are_mechanical_ineligible(mechanical_local):
    local=mechanical_local
    local.configure_native_reset_observation(max_lifecycles=8,max_commands=32)
    local.begin_case('mechanical')
    first,=local.native_reset_observation_lifecycles()
    assert first['native_eligible'] is False and first['kind']=='initial_begin'
    old=local.process
    local.reset_local()
    first,second=local.native_reset_observation_lifecycles()
    assert old.poll() is not None and local.process is not old
    assert second['logical_process']==2 and second['kind']=='explicit_reset'
    assert second['target_epoch']==first['target_epoch']+1
    assert second['process_exit_confirmed'] is True and second['native_eligible'] is False
    local.end_case()
    assert local.native_reset_observation_snapshot()['status']=='complete'


def test_direct_actual_write_is_covered_detached(mechanical_local):
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    local.write_register(24,17)
    row,=local.native_reset_observation_commands()
    assert row['status']=='parsed_complete' and row['operation']=='ACCESS_GPIO'
    assert row['fields']==[0,1,24,17,15] and row['command_sequence']==1
    row['fields'][3]=0
    assert local.native_reset_observation_commands()[0]['fields'][3]==17


@pytest.mark.parametrize('mode',['take','write_error','ack'])
def test_postparse_or_ack_failure_keeps_applied_history(native_factory,tmp_path,mode):
    local=wire_local(native_factory,tmp_path,bad_padcfg=mode=='take',error=int(mode=='write_error'),bad_ack=mode=='ack')
    try:
        local.configure_native_reset_observation(max_commands=32);local.begin_case('mechanical')
        if mode=='ack':
            for _ in range(16):local.command('STEP_GPIO',(0,))
        with pytest.raises((RuntimeError,ValueError)):
            local.write_register(24,17)
        state=local.native_reset_observation_snapshot()
        assert state['status']=='incomplete' and state['reason']
        assert len(state['commands'])==(17 if mode=='ack' else 1)
        if mode!='ack':assert state['commands'][0]['status']=='parsed_complete'
    finally:local.end_case()


def test_capacity_refuses_before_ack_and_command(mechanical_local):
    local=mechanical_local;local.configure_native_reset_observation(max_commands=16);local.begin_case('mechanical')
    for _ in range(16):local.command('STEP_GPIO',(0,))
    assert local._acknowledged==0
    with pytest.raises(ValueError,match='capacity'):local.command('STEP_GPIO',(0,))
    assert local._sequence==16 and local._acknowledged==0


def test_observer_validate_override_cannot_bypass_actual_command_guard(mechanical_local,monkeypatch):
    from myfuzz.local_harness.native_reset_observation import NativeResetObservation
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    sequence=local._sequence
    monkeypatch.setattr(NativeResetObservation,'validate',lambda self,**kwargs:None)
    with pytest.raises(ValueError,match='drift'):local.command('STEP_GPIO',(0,))
    assert local._sequence==sequence


def test_detached_live_process_cannot_be_replaced_or_heal(mechanical_local):
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    actual=local._process
    try:
        local._process=None
        with pytest.raises(ValueError,match='process'):local.native_reset_observation_snapshot()
    finally:local._process=actual
    assert local.native_reset_observation_snapshot()['status']=='incomplete'
    with pytest.raises(ValueError,match='incomplete'):local.command('STEP_GPIO',(0,))


def test_end_case_reaps_process_after_observer_provenance_drift(mechanical_local):
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    observer=local._native_reset_observation;process=local.process
    token,kind,encoded,bound_process,execution=observer._facts[0]
    observer._facts[0]=(token,kind,encoded,bound_process,execution+'x')
    with pytest.raises(ValueError):local.end_case()
    assert local.process is None and process.poll() is not None
    assert observer._status=='incomplete'


def test_resolved_fact_ordinal_is_global_cursor_not_process_number(mechanical_local,monkeypatch):
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    local.command('STEP_GPIO',(0,))
    observer=local._native_reset_observation
    tokens=[fact[0] for fact in observer._facts]
    # Bypass only issuer admission to inspect the internal ordinal projection;
    # this does not register a consumer or grant reset evidence.
    with monkeypatch.context() as patch:
        patch.setattr(observer,'_issuer_guard',lambda issuer:None)
        resolved=[observer._resolve_fact(token,issuer=object()) for token in tokens]
    assert [row['fact_ordinal'] for row in resolved]==list(range(1,len(tokens)+1))
    assert {row['document']['logical_process'] for row in resolved}=={1}


def test_guard_dispatch_table_replacement_fails_before_command(mechanical_local,monkeypatch):
    from myfuzz.local_harness import session as session_module
    local=mechanical_local;local.configure_native_reset_observation();local.begin_case('mechanical')
    observer=local._native_reset_observation;sequence=local._sequence
    monkeypatch.setattr(session_module,'_NATIVE_RESET_OWNER_GUARD',
                        (lambda *args,**kwargs:None,None))
    with pytest.raises(ValueError,match='guard'):
        local.command('STEP_GPIO',(0,))
    assert local._sequence==sequence and observer._status=='incomplete'
