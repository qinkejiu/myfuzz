"""File identity refusals before any generated or native execution."""
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from myfuzz.integration.compiled_execution_files import (
    _source_paths, _hashes, _unchanged, run_compiled_execution_files,
)


def inputs(tmp_path):
    (tmp_path/'src/myfuzz').mkdir(parents=True)
    (tmp_path/'src/myfuzz/marker.py').write_text('# pinned\n')
    (tmp_path/'scripts').mkdir()
    (tmp_path/'scripts/run_compiled_dataflow.py').write_text('# pinned\n')
    (tmp_path/'native').mkdir()
    (tmp_path/'native/core.sv').write_text('module core; endmodule\n')
    profile=tmp_path/'profile.json'
    profile.write_text(json.dumps({'source':{'root':'native','files':['core.sv']}}))
    request=tmp_path/'request.json';request.write_text(json.dumps({'profile_path':'profile.json'}))
    compose=tmp_path/'compose.json'
    compose.write_text(json.dumps({'cpu':{'request':'request.json'},'devices':[]}))
    supplement=tmp_path/'supplement.json';supplement.write_text('{}')
    records=tmp_path/'records.json';records.write_text('["5500000078563412"]')
    return (tmp_path,compose,(),supplement,records)


@pytest.mark.parametrize('name',['compose.json','supplement.json','request.json','profile.json','native/core.sv'])
def test_retargeted_source_symlink_refused_before_execution(tmp_path,name):
    arguments=inputs(tmp_path);paths=_source_paths(*arguments);expected=_hashes(paths)
    original=tmp_path/name;alternate=tmp_path/('alternate-'+original.name)
    alternate.write_bytes(original.read_bytes())
    original.unlink();original.symlink_to(alternate)
    with pytest.raises(ValueError,match='source-symlink-refused'):
        _unchanged(paths,expected,arguments)


def test_added_declared_native_dependency_refused(tmp_path):
    arguments=inputs(tmp_path);paths=_source_paths(*arguments);expected=_hashes(paths)
    (tmp_path/'native/extra.sv').write_text('module extra; endmodule\n')
    (tmp_path/'profile.json').write_text(json.dumps({'source':{'root':'native','files':['core.sv','extra.sv']}}))
    with pytest.raises(ValueError,match='source-input-changed'):
        _unchanged(paths,expected,arguments)


def test_unsupported_executor_retains_incomplete_report_and_explicit_lock(tmp_path):
    output=tmp_path/'evidence';lock=tmp_path/'canonical-project/heavy.lock'
    with patch('myfuzz.integration.compiled_execution_files.create_compiled_execution',
               side_effect=AssertionError('must refuse before startup')):
        with pytest.raises(ValueError,match='executor-unsupported'):
            run_compiled_execution_files(base_dir=tmp_path,compose_path=tmp_path/'missing',
                capability_paths=(),supplement_path=tmp_path/'missing',records_path=tmp_path/'missing',
                output_dir=output,cache_dir=tmp_path/'cache',executor='unsupported',heavy_lock=lock)
    report=json.loads((output/'report.json').read_text())
    assert report['status']=='refused'
    assert report['heavy_lock']==str(lock.resolve())
    assert report['runtime_admitted'] is False
    assert (output/'.incomplete').is_file()
    assert not lock.exists()


def exact_hop_fixture():
    from myfuzz.scenario.memory import ReadSnapshot
    code=bytes.fromhex('13000000')*12
    cpu='processor';source_id='ram.image:0';address=0x10080;target=0x40001004
    traces={channel:{role:channel+'_'+role for role in ('req','gnt','addr','rvalid','rdata','error','we','wdata','be')}
            for channel in ('instr','data')}
    events=[dict(event_id=1,kind='instruction_source',component=cpu,
                 source_event_id=source_id,address=address,data_hex=code.hex(),generation=0)]
    tick=0
    def step(channel,**values):
        nonlocal tick
        tick+=1;taps={signal:0 for mapping in traces.values() for signal in mapping.values()}
        taps.update({traces[channel][role]:value for role,value in values.items()})
        event=dict(event_id=len(events)+1,component=cpu,local_tick=tick,
                   outputs=dict(driver_samples=[dict(local_tick=tick,pre=dict(protocol_taps=taps))]))
        events.append(event)
        return event['event_id']
    def key(channel,sequence):
        return dict(execution_id='local-execution',testcase_id='unit',source_component=cpu,
                    source_epoch=0,channel_id=channel,source_sequence=sequence)
    snapshots=[]
    for index in range(8):
        accepted=step('instr',req=1,gnt=1,addr=address+index*4)
        data=code[index*4:index*4+4]
        snapshots.append(ReadSnapshot('unit','ram',0,128+index*4,data,((0,1),)*4,
                                      (source_id,)*4,writer_kinds=('INSTRUCTION_SOURCE',)*4))
        events.append(dict(event_id=len(events)+1,kind='memory_read',component=cpu,
            transaction=key('instr',index+1),address=address+index*4,writer_event_ids=(source_id,)*4,
            data_hex=data.hex(),byte_offset=128+index*4,versions=((0,1),)*4,memory_id='ram',
            generation=0,width_bytes=4,producer_event_id=accepted))
        step('instr',rvalid=1,rdata=int.from_bytes(data,'little'))
    joins=[]
    for index,write in enumerate((True,False)):
        native=step('data',req=1,gnt=1,addr=target,we=int(write),wdata=85,be=15)
        accepted=len(events)+1
        events.append(dict(event_id=accepted,kind='mmio_acceptance',component=cpu,device_id='peripheral',
                           producer_event_id=native))
        delivery=len(events)+1
        events.append(dict(event_id=delivery,kind='mmio_delivery',component=cpu,device_id='peripheral',
                           offset=4,source_transaction=key('data',index+1),write=write))
        step('data',rvalid=1,rdata=0 if write else 85)
        joins.append(dict(delivery_event=delivery,acceptance_event=accepted,native_APB_event=delivery,
                          source_transaction=key('data',index+1)))
    return dict(events=events,declaration=dict(code_hex=code.hex(),candidate=dict(value=85)),
        image=dict(component=cpu,port='ram'),stream=dict(register_access=dict(source_component=cpu,
            device_id='peripheral',register_offset=4,address=target)),traces=traces,address=address,
        source_event_id=source_id,joins=joins,declared_edges=[dict(relation='persistent_state'),dict(relation='mmio_route')],
        instruction_snapshots=snapshots)


def test_exact_native_hop_consumer_accepts_complete_synthetic_contract():
    from myfuzz.integration.compiled_f4 import check_f4_exact_hops
    proof=check_f4_exact_hops(**exact_hop_fixture())
    assert len(proof['instruction_hops'])==8
    assert len(proof['data_hops'])==2
    assert all(edge['status']=='certified' for edge in proof['edges'])


@pytest.mark.parametrize('mutation',['instruction_acceptance','instruction_response','instruction_value',
    'instruction_error','instruction_version','data_acceptance','data_response','data_error','router_device','router_transaction'])
def test_exact_native_hop_consumer_refuses_independent_missing_or_changed_hops(mutation):
    from myfuzz.integration.compiled_f4 import check_f4_exact_hops
    fixture=exact_hop_fixture();events=fixture['events']
    native=[e['outputs']['driver_samples'][0]['pre']['protocol_taps'] for e in events if 'outputs' in e]
    if mutation=='instruction_acceptance':native[0]['instr_gnt']=0
    elif mutation=='instruction_response':native[1]['instr_rvalid']=0
    elif mutation=='instruction_value':native[1]['instr_rdata']^=1
    elif mutation=='instruction_error':native[1]['instr_error']=1
    elif mutation=='instruction_version':
        next(e for e in events if e.get('kind')=='memory_read')['versions']=((0,9),)*4
    elif mutation=='data_acceptance':native[16]['data_gnt']=0
    elif mutation=='data_response':native[17]['data_rvalid']=0
    elif mutation=='data_error':native[17]['data_error']=1
    elif mutation=='router_device':
        next(e for e in events if e.get('kind')=='mmio_delivery')['device_id']='wrong'
    elif mutation=='router_transaction':
        next(e for e in events if e.get('kind')=='mmio_delivery')['source_transaction']['source_sequence']=9
    with pytest.raises(ValueError,match='compiled-F4-'):
        check_f4_exact_hops(**fixture)


@pytest.mark.parametrize('mutation',['missing','wrong_tick','wrong_context','wrong_value'])
def test_f4_chain_refuses_missing_or_mismatched_native_target_commit(mutation):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    transaction=dict(execution_id='local-execution',testcase_id='unit',source_component='processor',
                     source_epoch=0,channel_id='data',source_sequence=1)
    context=dict(source_transaction=transaction,address=0x40001004,offset=4,write=True,value=85,be=15,
                 command_scope=dict(component='peripheral',reset_epoch=0,command_sequence=10))
    commit=dict(context=context,before=0,after=85,epoch=0,tick=11,command_sequence=10)
    writes=[commit]
    if mutation=='missing':writes=[]
    elif mutation=='wrong_tick':commit['tick']=12
    elif mutation=='wrong_context':context['source_transaction']={**transaction,'source_sequence':2}
    elif mutation=='wrong_value':commit['after']=86
    runtime=SimpleNamespace(target_id='peripheral',artifacts={'peripheral':object()},
        access=dict(address=0x40001004,register_offset=4),authority=SimpleNamespace(writes=lambda:writes))
    receipt=SimpleNamespace(events=[dict(event_id=2,source_transaction=transaction),dict(event_id=3,local_tick=11)])
    observed=dict(joins=[dict(delivery_event=2,native_APB_event=3)])
    with patch('myfuzz.integration.compiled_f4.check_writer_observation',return_value=observed):
        with pytest.raises(ValueError,match='compiled-F4-'):
            CompiledF4Runtime._check_chain(runtime,receipt,dict(candidate=dict(value=85)),
                                          dict(value=0,reset_epoch=0),0)


@pytest.mark.parametrize('scope',['caller','private'])
@pytest.mark.parametrize('mutation',['ownership','physical_map','request','compiled','artifact'])
def test_post_start_input_identity_drift_refused_before_native_tick(scope,mutation):
    from copy import deepcopy
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime, _input_identity
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    owner=InputOwner('peripheral','gpio_in',0,1,'source','peripheral.in.external')
    inputs=dict(request=SimpleNamespace(document={'declared':1}),compiled={'compiled':1},
        ownership=compile_ownership((InputField('peripheral','gpio_in',1),),(owner,)),
        physical_port_map={('peripheral','gpio_in'):'gpio_in'})
    artifacts={'processor':SimpleNamespace(payload=b'admitted')}
    private_inputs=deepcopy(inputs);private_artifacts=deepcopy(artifacts)
    with patch('myfuzz.integration.compiled_f4.compile_paths',return_value={'compiled':1}), \
         patch('myfuzz.local_harness.generated_artifact_admission._artifact_files',side_effect=lambda a:{'source':a.payload}), \
         patch('subprocess.Popen',side_effect=AssertionError('no native tick permitted')):
        runtime=SimpleNamespace(finished=False,_caller_inputs=inputs,_caller_artifacts=artifacts,
            inputs=private_inputs,artifacts=private_artifacts,_input_digest=_input_identity(inputs,artifacts))
        changed_inputs=inputs if scope=='caller' else private_inputs
        changed_artifacts=artifacts if scope=='caller' else private_artifacts
        if mutation=='ownership':
            changed_inputs['ownership']._bits[('peripheral','gpio_in')]=(InputOwner('peripheral','gpio_in',0,1,'fixed','fixed'),)
        elif mutation=='physical_map':changed_inputs['physical_port_map'][('peripheral','gpio_in')]='other'
        elif mutation=='request':changed_inputs['request']=SimpleNamespace(document={'declared':2})
        elif mutation=='compiled':changed_inputs['compiled']={'compiled':2}
        elif mutation=='artifact':changed_artifacts['processor']=SimpleNamespace(payload=b'changed')
        with pytest.raises(ValueError,match='input-identity-changed'):
            CompiledF4Runtime._stable(runtime)
