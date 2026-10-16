"""Software bus-driver integration, not a CPU or GPIO RTL behavior oracle."""
from copy import deepcopy
import hashlib
import json
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession, _trace_semantic_sha256
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from tests.integration.test_ordinary_apb_register_replay import software_factory
from tests.local_harness.test_ordinary_apb_access_receipts import software_transport
from tests.scenario.test_register_program_runtime import request

BUS_WORD=0xd1234567


def field_factory(factory):
    """Actual services/strict target parser; execute admitted words in software."""
    create_base=software_factory(factory)
    def create():
        runner=create_base();begin_base=runner.begin_test;executed=set()
        def begin(case_id):
            begin_base(case_id)
            for name in ('gpio_a','gpio_b'):
                software_transport(runner.sessions[name],rdata=BUS_WORD)
        def steps(order):
            active=runner._test_session._register_program_runtime._active_submission
            if active is None:return
            source=active[1]['program']['source']
            if source['action_id'] in executed:return
            executed.add(source['action_id']);regs=[0]*32;cpu=runner.sessions['cpu']
            raw=bytes.fromhex(source['data_hex'])
            for offset in range(0,len(raw),4):
                word=int.from_bytes(raw[offset:offset+4],'little')
                op=word&127;rd=word>>7&31;rs1=word>>15&31;rs2=word>>20&31;funct=word>>12&7
                immediate=word>>20;immediate-=4096 if immediate&2048 else 0
                if op==0x37:regs[rd]=word&0xfffff000
                elif op==0x13:
                    if funct==0:regs[rd]=(regs[rs1]+immediate)&0xffffffff
                    elif funct==5:
                        assert word>>25==0
                        regs[rd]=regs[rs1]>>(word>>20&31)
                    elif funct==7:regs[rd]=regs[rs1]&(immediate&0xffffffff)
                    else:raise AssertionError('unsupported OP-IMM fixture')
                elif op==0x33:
                    assert word>>25==0 and funct in (6,7)
                    regs[rd]=regs[rs1]&regs[rs2] if funct==7 else regs[rs1]|regs[rs2]
                elif op in (0x03,0x23):
                    assert funct==2
                    if op==0x23:
                        immediate=(word>>25<<5)|(word>>7&31)
                        immediate-=4096 if immediate&2048 else 0
                    address=(regs[rs1]+immediate)&0xffffffff
                    cpu._pending_data=None  # software models prior response consumption
                    response=cpu._serve('data',int(op==0x23),address,regs[rs2] if op==0x23 else 0,15)
                    runner._append_external_events('cpu',len(runner._events))
                    if cpu.router.owns(address):
                        window=next(w for w in cpu.router.windows if w.base<=address<w.base+w.size)
                        runner._step_once(window.device_id);response=cpu._pending_data
                    if op==0x03:regs[rd]=response[0]
                    cpu._pending_data=None
                else:raise AssertionError('unsupported admitted compiler opcode')
                regs[0]=0
            # Model instruction response consumption and next real deferred fetch.
            cpu._pending_instr=None
            assert cpu._serve('instr',0,source['address']+len(raw),0,15) is None
            runner._append_external_events('cpu',len(runner._events))
        runner.begin_test=begin;runner.step_batch=steps
        return runner
    return create


@pytest.fixture(scope='module')
def recorded(tmp_path_factory):
    root=tmp_path_factory.mktemp('field-read-replay')
    assembly=api.make_register_assembly(advance_rounds=1,
        ordinary_apb_access_evidence={'max_records':8})
    factory=field_factory(api.make_register_factory(cache_dir=root/'render',assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    adapter=api.make_register_runtime_factory(assembly)(session)
    session.begin()
    requests=[request(case_id='pin7',action_id='read-pin7',target_instance='gpio_a',
        register='PADCFG_0',field='pin7',operation='register_read',value=None,
        result_address=0x10004,allow_side_effect=False),
        request(case_id='pin31',action_id='read-pin31',target_instance='gpio_a',
        register='INTTYPE_HIGH',field='pin31',operation='register_read',value=None,
        result_address=0x10008,allow_side_effect=False)]
    manifests=[adapter.submit(row)['manifest'] for row in requests]
    trace=session.finish();plan=session.encode_plan();bundle=root/'bundle'
    api.save_ibex_pulp_register_bundle(output_dir=bundle,assembly=assembly,
        session_manifest=session.manifest_document,plan_bytes=plan,trace=trace,runtime_state=adapter.snapshot())
    return dict(bundle=bundle,factory=factory,requests=requests,manifests=manifests,
        trace=trace,plan=json.loads(plan),state=session.runner.ordinary_apb_access_evidence_snapshot())


def install_software(monkeypatch,recorded):
    original=api.make_register_runtime_factory
    def installer(assembly):
        install=original(assembly)
        def create(session):
            session.runner._test_session=session
            return install(session)
        return create
    monkeypatch.setattr(api,'make_register_factory',lambda **kwargs:recorded['factory'])
    monkeypatch.setattr(api,'make_register_runtime_factory',installer)


def reauthenticate(bundle,changes):
    """Rehash saved comparison artifacts, never reconstruct live permission."""
    for name,document in changes.items():
        (bundle/name).write_text(api._json(document)+'\n')
    envelope=json.loads((bundle/'online_run_identity.json').read_bytes())
    identity=envelope['identity']
    for name in changes:
        identity['artifacts'][name]=hashlib.sha256((bundle/name).read_bytes()).hexdigest()
    if 'online_final_trace.json' in changes:
        trace=changes['online_final_trace.json']
        identity['trace']['semantic_sha256']=trace['semantic_sha256']
        identity['trace']['genome_sha256']=trace['genome_sha256']
    if 'online_plan.json' in changes:
        identity['genome']['plan_sha256']=hashlib.sha256((bundle/'online_plan.json').read_bytes()).hexdigest()
    if 'corpus/register_program_state.json' in changes:
        identity['run_config']['register_program_state_sha256']=identity['artifacts']['corpus/register_program_state.json']
    envelope['sha256']=hashlib.sha256(api._json(identity).encode()).hexdigest()
    (bundle/'online_run_identity.json').write_text(api._json(envelope)+'\n')
    report=json.loads((bundle/'report.json').read_bytes())
    report['online_run_identity_sha256']=envelope['sha256']
    (bundle/'report.json').write_text(api._json(report)+'\n')


def test_nonempty_actual_field_sources_cpu_ram_and_fresh_file_replay(recorded,monkeypatch):
    assert recorded['plan']['schema_version']==16
    assert recorded['state']['counts']['cpu_delivery_confirmed']==2
    for manifest,lsb,width,value in zip(recorded['manifests'],(28,30),(4,2),(13,3)):
        extraction=manifest['program']['result_storage']['field_extraction']
        assert extraction==dict(lsb=lsb,width=width,read_mask=(1<<width)-1,
            bus_width=32,representation='field_relative_zero_extended')
        assert len(bytes.fromhex(manifest['program']['source']['data_hex']))==24
        assert manifest['request']==recorded['requests'][recorded['manifests'].index(manifest)]
    writes=[event for event in recorded['trace'].events if event.get('kind')=='memory_write']
    assert [(event['address'],event['value']) for event in writes]==[(0x10004,13),(0x10008,3)]
    commits=[event for event in recorded['trace'].events if event.get('kind')=='memory_write_commit']
    assert len(commits)==2
    assert all(row['raw_event_refs'] and row['base_event_refs'] for row in recorded['state']['records'])
    install_software(monkeypatch,recorded)
    result=api.replay_ibex_pulp_register_files(cache_dir=recorded['bundle']/'unused',output_dir=recorded['bundle'])
    assert result.matches and result.ordinary_apb_access_evidence==recorded['state']


def test_rehashed_saved_masked_ram_cannot_become_actual_cpu_result(recorded,tmp_path,monkeypatch):
    import shutil
    bundle=tmp_path/'forged';shutil.copytree(recorded['bundle'],bundle)
    trace=json.loads((bundle/'online_final_trace.json').read_bytes())
    changed=False
    for event in trace['events']:
        if event.get('kind')=='memory_write' and event.get('address')==0x10004:
            event['value']=0;changed=True
    assert changed
    trace['semantic_sha256']=_trace_semantic_sha256(trace['status'],trace['events'],trace['local_ticks'])
    reauthenticate(bundle,{'online_final_trace.json':trace})
    install_software(monkeypatch,recorded)
    result=api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
    assert not result.matches


def test_rehashed_extraction_cannot_authorize_a_different_field(recorded,tmp_path,monkeypatch):
    import shutil
    bundle=tmp_path/'forged-extraction';shutil.copytree(recorded['bundle'],bundle)
    plan=json.loads((bundle/'online_plan.json').read_bytes())
    manifest=plan['register_programs']['case_manifests'][0]
    program=manifest['program']
    program['result_storage']['field_extraction']['lsb']=0
    program['identity_sha256']=hashlib.sha256(api._json({key:value for key,value in program.items()
        if key!='identity_sha256'}).encode()).hexdigest()
    state=json.loads((bundle/'corpus/register_program_state.json').read_bytes())
    state['records'][0]['manifest']=deepcopy(manifest)
    trace=json.loads((bundle/'online_final_trace.json').read_bytes())
    raw=(api._json(plan)+'\n').encode();trace['genome_sha256']=hashlib.sha256(raw).hexdigest()
    reauthenticate(bundle,{'online_plan.json':plan,'online_final_trace.json':trace,
        'corpus/register_program_state.json':state})
    from unittest.mock import patch
    with patch.object(api,'make_register_factory') as factory:
        with pytest.raises(ValueError,match='field extraction'):
            api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
        factory.assert_not_called()
