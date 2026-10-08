"""Full raw receipts, not copied accepted labels, authorize a retired UART load."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.scenario.cpu_retirement import CpuRetirementMatcher
from myfuzz.scenario.uart_consumption import UartConsumptionTracker
from tests.scenario.test_uart_native_irq_alias_review import authority
from tests.scenario.test_uart_consumption import NativeLifecycleFixture
from tests.scenario.test_cpu_retirement import fetch, retire, LW


def routed_authority():
    from types import SimpleNamespace
    import hashlib,json
    from myfuzz.scenario.dependency import DependencyGraph,DependencyRule,FuzzableSource
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract,RuntimeNode,RuntimeEdgeContract,RuntimePathContract
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    from myfuzz.scenario.router import DataflowRouter,DeviceWindow
    from myfuzz.scenario.runner import Binding
    _,owner,_,_=authority()
    graph=DependencyGraph(sources=(FuzzableSource('uart.external_rx_byte','uart','uart_rx_byte',0,8,('IP_TO_CPU',)),),rules=(
        DependencyRule('wm',('uart.external_rx_byte',),'EVENT_ORDER'),
        DependencyRule('cpu.irq',('wm',),'DATA_BINDING'),
        DependencyRule('uart.rdata',('cpu.irq',),'EVENT_ORDER')))
    digest=hashlib.sha256(json.dumps(graph.edge_document(),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    contract=RuntimePathContract(digest,(
        RuntimeNode('uart.external_rx_byte','uart','physical','uart_rx_byte',0,8),
        RuntimeNode('wm','uart','physical','uart_rx_watermark',0,1),
        RuntimeNode('cpu.irq','cpu','physical','irq',0,1),
        RuntimeNode('uart.rdata','uart','physical','rdata',0,32)),(
        RuntimeEdgeContract(1,0,'direct_binding'),RuntimeEdgeContract(2,0,'mmio_route',
            initiator_component='cpu',device_id='uart',base=0x40000000,size=4096)))
    prepared=PreparedRuntimePathContract(graph,contract,(('IP_TO_CPU',graph.edge_paths_to('uart.rdata',direction='IP_TO_CPU')[0]),))
    uart=SimpleNamespace();cpu=SimpleNamespace(router=DataflowRouter((DeviceWindow('uart',0x40000000,4096,uart),)))
    runner=SimpleNamespace(sessions={'uart':uart,'cpu':cpu},ownership=owner,
        bindings=(Binding('uart','uart_rx_watermark','cpu','irq',1),))
    compiled=prepared.bind(runner).document();compiled['declaration']=prepared.document()
    return owner,RuntimeEdgeIndex(compiled,contract.document()),compiled['paths'][0]['path_id']


class Stream:
    def __init__(self):
        self.owner, self.index, self.path = routed_authority()
        self.registry = AdmissionRegistry(); self.events = []
        self.tracker = UartConsumptionTracker(admission_registry=self.registry,
            ownership=self.owner, edge_index=self.index)
        self.native = NativeLifecycleFixture(self, self.registry)
        self.cpu = CpuRetirementMatcher(max_pending=2048)
        self.order = 0; self.fetched = False

    def consume(self, event):
        self.events.append(deepcopy(event))
        reports = self.tracker.consume(event)
        for i, report in enumerate(reports):
            if report.get('proof_scope') == 'uart_fifo_read_consumption':
                self.events.append(dict(report, event_id=f"uart-proof:{event['event_id']}:{i}",
                    producer_event_id=event['event_id']))
        return reports

    def receive(self, validate=True):
        original = SourceAdmission.create
        def admitted(**kwargs):
            kwargs.update(source_id='uart.external_rx_byte', path_id=self.path)
            return original(**kwargs)
        with patch.object(SourceAdmission, 'create', side_effect=admitted):
            return self.native.receive(validate=validate)

    def read(self):
        return self.native.read()[0]

    def cpu_load(self, key, address=0x40000018):
        if not self.fetched:
            f = fetch(LW); f.update(event_id='fetch:1');f['transaction'].update(
                execution_id=key['execution_id'], source_component=key['source_component'],
                source_epoch=key['source_epoch'])
            f['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,
                writer_event_ids=['initial-image']*4)
            self.events.append(deepcopy(f));self.cpu.consume(f);self.fetched=True
        seq=key['source_sequence']
        beat=dict(kind='data_accept',event_id=f'cpu-a:{seq}',transaction=key,
            raw_address=address,aligned_address=address,address=address,write=0,be=15,wdata=0)
        rsp=dict(beat,kind='data_response',event_id=f'cpu-d:{seq}',rdata=0,error=0)
        rvfi=retire(LW,order=self.order,address=address,data=0)
        rvfi.update(execution_id=key['execution_id'],source_component=key['source_component'],
            source_epoch=key['source_epoch'],event_id=f'cpu-r:{seq}')
        from myfuzz.scenario.uart_retired_read import _RVFI_NAMES
        from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
        for name in _RVFI_NAMES: rvfi.setdefault(name, 0)
        rvfi['valid']=1
        scope=dict(component=key['source_component'],reset_epoch=key['source_epoch'],command_sequence=self.order+1)
        rvfi.update(schema_version='cpu_retire.v2',phase='post',local_tick=self.order+1,
            command_scope=scope,receipt_id=dict(execution='cpu-native',sequence=self.order+1),
            actual_post_ref=dict(command_scope=scope,local_tick=self.order+1,phase='post'),
            receipt_ticks=dict(tick_before=self.order,tick_after=self.order+1,new_ticks=1,local_tick_base=0),
            observation_contract=ibex_irq_receipt_contract(),observation=dict(sampling_edge='post_rising',
                physical={'rvfi_'+name:rvfi[name] for name in _RVFI_NAMES}))
        self.order+=1
        for e in (beat,rsp,rvfi):
            self.events.append(deepcopy(e));reports=self.cpu.consume(e)
            for report in reports:
                if report.get('status')=='accepted':
                    self.events.append(dict(report,kind='cpu_retirement_match',
                        event_id=f'cpu-match:{seq}',producer_event_id=e['event_id']))
        return rvfi

    def lifecycle(self, delayed=False):
        validation,_=self.receive(validate=not delayed);access=self.read()
        self.cpu_load(access['source_transaction'])
        if delayed:self.consume(validation)
        return self.events


def linker(stream, **kwargs):
    from myfuzz.scenario.uart_retired_read import UartRetiredReadLinker
    return UartRetiredReadLinker(admission_registry=stream.registry,
        ownership=stream.owner, edge_index=stream.index, **kwargs)


def accepted(reports):
    return [r for r in reports if r.get('status')=='accepted']


def play(model, events):
    return [r for e in events for r in model.consume(deepcopy(e))]


def test_exact_initial_image_load_and_source_data_are_distinct():
    stream=Stream();events=stream.lifecycle();model=linker(stream)
    proofs=accepted(play(model,events));assert len(proofs)==1
    p=proofs[0];assert p['proof_scope']=='cpu_retired_uart_rdata_read'
    assert p['instruction_origin_status']=='unknown'
    assert p['operand_origin']==p['subsequent_store_origin']==p['generic_isr_origin']=='unknown'
    assert p['fullkey']['source_sequence']==1 and p['graph_path_certified'] is True
    original=deepcopy(p);assert not accepted(play(model,events[-1:]))
    assert p==original


def test_read_before_delayed_validation_and_retirement_appends_once():
    s=Stream();events=s.lifecycle(delayed=True);m=linker(s)
    proofs=accepted(play(m,events));assert len(proofs)==1
    assert m.pending_count==0


@pytest.mark.parametrize('kind', ['instr_response','data_accept','data_response',
    'cpu_retire','cpu_retirement_match','uart_frame_validation','uart_rdata_access',
    'uart_tick_observation','uart_consumption_match'])
def test_missing_exact_raw_or_logged_witness_cannot_promote(kind):
    s=Stream();events=s.lifecycle();assert not accepted(play(linker(s),
        [e for e in events if e.get('kind')!=kind]))


@pytest.mark.parametrize('field,value', [('execution_id','other'),('testcase_id','other'),
    ('source_component','other'),('source_epoch',1),('channel_id','instr'),('source_sequence',2)])
def test_equal_value_wrong_full_key_never_substitutes(field,value):
    s=Stream();events=s.lifecycle()
    for e in events:
        if e.get('kind')=='uart_consumption_match':e['source_transaction'][field]=value
    assert not accepted(play(linker(s),events))


@pytest.mark.parametrize('kind,field,value', [
    ('cpu_retirement_match','status','accepted'),
    ('cpu_retire','trap',1),('cpu_retire','mem_rmask',1),
    ('cpu_retire','rd_wdata',7),('cpu_retire','mem_rdata',7),
    ('cpu_retire','rs1_rdata',0x4000001c),('data_response','error',1),
    ('data_response','rdata',1),('data_accept','be',1)])
def test_forged_accepted_summary_does_not_override_raw_conflict(kind,field,value):
    s=Stream();events=s.lifecycle()
    for e in events:
        if e.get('kind')==kind:
            if kind=='cpu_retirement_match':e['producer_event_id']='nonexistent'
            else:e[field]=value
    assert not accepted(play(linker(s),events))


def test_more_than_256_completed_joins_release_resources():
    s=Stream();m=linker(s);proofs=[]
    for _ in range(260):
        s.events=[];s.lifecycle();proofs.extend(accepted(play(m,s.events)))
        assert m.pending_count==0
    assert len(proofs)==260 and not m.degraded


@pytest.mark.parametrize('field', ['schema_version','actual_post_ref','receipt_ticks',
    'observation_contract','receipt_id','command_scope','observation'])
def test_missing_native_retirement_receipt_fails_closed(field):
    s=Stream();events=s.lifecycle()
    for e in events:
        if e.get('kind')=='cpu_retire':e.pop(field)
    assert not accepted(play(linker(s),events))


@pytest.mark.parametrize('path,value', [
    (('receipt_id','sequence'), True), (('actual_post_ref','local_tick'), 2),
    (('receipt_ticks','new_ticks'), 2), (('receipt_ticks','local_tick_base'), 1),
    (('observation','physical','rvfi_mem_rdata'), 1),
    (('observation','physical','rvfi_valid'), False)])
def test_changed_post_receipt_or_physical_rvfi_cannot_promote(path,value):
    s=Stream();events=s.lifecycle()
    for e in events:
        if e.get('kind')=='cpu_retire':
            cursor=e
            for k in path[:-1]:cursor=cursor[k]
            cursor[path[-1]]=value
    assert not accepted(play(linker(s),events))


def test_cpu_first_then_uart_raw_and_certificate_join_exactly_once():
    s=Stream();events=s.lifecycle();cpu=[e for e in events if not e['kind'].startswith('uart_')]
    uart=[e for e in events if e['kind'].startswith('uart_')]
    m=linker(s);assert not accepted(play(m,cpu))
    assert len(accepted(play(m,uart)))==1


def test_old_delayed_source_survives_260_newer_completed_loads():
    s=Stream();validation,_=s.receive(validate=False);access=s.read();s.cpu_load(access['source_transaction'])
    m=linker(s);assert not accepted(play(m,s.events));assert m.pending_count==1
    for _ in range(260):
        s.events=[];s.lifecycle();assert len(accepted(play(m,s.events)))==1
        assert m.pending_count==1
    s.events=[];s.consume(validation)
    assert len(accepted(play(m,s.events)))==1
    assert m.pending_count==0 and not m.degraded
    assert not accepted(play(m,s.events))


def test_unknown_scope_transition_and_forged_reset_cannot_restore_certainty():
    s=Stream();events=s.lifecycle();m=linker(s)
    for e in events:
        if e.get('kind')=='cpu_retire':e['source_epoch']=1
    assert not accepted(play(m,events))
    r=dict(kind='cpu_reset',event_id='reset-forged',component='cpu',source_component='cpu',
        execution_id='cpu-execution',source_epoch=1,reset_epoch=1,physical_reset=False)
    assert m.consume(r)[0]['status']=='incomplete'


def test_pending_capacity_is_barrier_and_both_physical_resets_clear_resources():
    s=Stream();m=linker(s,max_pending=2)
    for _ in range(3):
        s.events=[];s.lifecycle(delayed=True)
        # Keep logged CPU match unresolved by withholding exact source read proof.
        reports=play(m,[e for e in s.events if e.get('kind')!='uart_consumption_match'])
    assert m.degraded and m.pending_count<=2
    assert not accepted(reports)
    r=dict(kind='cpu_reset',event_id='reset-cpu',component='cpu',source_component='cpu',
        execution_id='cpu-execution',source_epoch=1,reset_epoch=1,physical_reset=True)
    m.consume(r);s.events=[];s.native.reset();play(m,s.events)
    assert m.pending_count==0 and not m.degraded


@pytest.mark.parametrize('event', [None,[],{'kind':[]}, {'kind':'cpu_retire','event_id':True},
    {'kind':'uart_consumption_match','event_id':1,'source_transaction':[]}])
def test_partial_json_events_are_total_fail_closed(event):
    s=Stream();m=linker(s)
    assert not accepted(m.consume(event))


def test_exact_terminal_duplicate_is_idempotent_before_next_load():
    s=Stream();m=linker(s);events=s.lifecycle();assert len(accepted(play(m,events)))==1
    terminals=[e for e in events if e.get('kind') in ('cpu_retirement_match','cpu_retire','uart_consumption_match')]
    assert not accepted(play(m,terminals))
    assert not m.degraded
    s.events=[];s.lifecycle();assert len(accepted(play(m,s.events)))==1


@pytest.mark.parametrize('mutation', ['missing_index','wrong_index','wrong_owner','selfsigned'])
def test_actual_authority_required_even_when_certificates_say_accepted(mutation):
    s=Stream();events=s.lifecycle()
    if mutation=='selfsigned':
        for e in events:
            if e.get('kind')=='uart_consumption_match':
                e['source_admission']['action_id']='unregistered'
        m=linker(s)
    else:
        from myfuzz.scenario.uart_retired_read import UartRetiredReadLinker
        owner,index=s.owner,s.index
        if mutation=='missing_index':index=None
        elif mutation=='wrong_owner':_,owner,_,_=authority(owner='other')
        else:
            from tests.scenario.test_runtime_edge_index import fixture
            from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
            index=RuntimeEdgeIndex(*fixture())
        m=UartRetiredReadLinker(admission_registry=s.registry,ownership=owner,edge_index=index)
    assert not accepted(play(m,events))


def test_actual_runner_match_envelope_is_accepted_without_origin_upgrade():
    s=Stream();events=s.lifecycle()
    for e in events:
        if e.get('kind')=='cpu_retirement_match':
            e.update(component='cpu',origin_relation='retired_instruction_bytes',
                provenance=dict(origin_status='unknown',proof_scope='observation_only'))
    assert len(accepted(play(linker(s),events)))==1


def test_uart_reset_cannot_clear_cpu_receipt_barrier_or_restore_epoch_zero():
    s=Stream();events=s.lifecycle();m=linker(s)
    raw=deepcopy(next(e for e in events if e['kind']=='cpu_retire'));raw['phase']='pre'
    assert m.consume(raw)[0]['status']=='incomplete' and m.degraded
    forged=dict(kind='uart_reset',event_id='wrong-role-reset',component='cpu',
        source_component='cpu',reset_epoch=1,source_epoch=1,local_tick=0,physical_reset=True,
        command_scope=dict(component='cpu',reset_epoch=1,command_sequence=0))
    assert m.consume(forged)[0]['status']=='incomplete'
    assert m.degraded and not accepted(play(m,events))


@pytest.mark.parametrize('kind,component', [('cpu_reset','uart'),('uart_reset','cpu'),
    ('cpu_reset','unknown'),('uart_reset','unknown')])
def test_reset_kind_cannot_create_other_domain_or_unknown_state(kind,component):
    s=Stream();m=linker(s);before=dict(m._epochs)
    r=dict(kind=kind,event_id='reset-role',component=component,source_component=component,
        execution_id='cpu-execution',source_epoch=1,reset_epoch=1,physical_reset=True,
        local_tick=0,command_scope=dict(component=component,reset_epoch=1,command_sequence=0))
    assert m.consume(r)[0]['status']=='incomplete'
    assert m._epochs==before


def test_raw_cpu_component_must_be_declared_cpu_endpoint():
    s=Stream();e=deepcopy(next(e for e in s.lifecycle() if e['kind']=='instr_response'))
    e['transaction']['source_component']='uart'
    m=linker(s);reports=m.consume(e)
    assert reports and reports[0]['status']=='incomplete'
    assert ('cpu','uart') not in m._epochs


def test_wrong_declared_cpu_binding_owner_cannot_certify_selected_path():
    from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
    from myfuzz.scenario.uart_retired_read import UartRetiredReadLinker
    s=Stream();events=s.lifecycle()
    owner=compile_ownership((InputField('uart','uart_rx_byte',8),InputField('cpu','irq',1)),
        (InputOwner('uart','uart_rx_byte',0,8,'source','external_uart_rx_byte'),
         InputOwner('cpu','irq',0,1,'bound','other.uart_rx_watermark')))
    m=UartRetiredReadLinker(admission_registry=s.registry,ownership=owner,edge_index=s.index)
    assert not accepted(play(m,events))


def test_uart_reset_reclaims_canceled_cpu_resource_before_next_load():
    s=Stream();m=linker(s,max_pending=2)
    for _ in range(2):
        s.events=[];events=s.lifecycle(delayed=True)
        play(m,[e for e in events if e['kind'] not in ('uart_frame_validation','uart_consumption_match')])
    assert m.pending_count==2
    s.events=[];s.native.reset();play(m,s.events)
    assert m.pending_count==0 and not m.degraded
    # Frame counter belongs to UART epoch; CPU full-key sequence continues.
    s.native.counter=2;s.events=[];s.lifecycle()
    assert len(accepted(play(m,s.events)))==1 and not m.degraded


def test_final_journal_provenance_overlay_does_not_change_raw_semantic_receipts():
    s=Stream();events=s.lifecycle()
    for e in events:
        e['provenance']=dict(schema_version='event_source_provenance.v1',origin_status='unknown',
            proof_scope='observation_only')
    assert len(accepted(play(linker(s),events)))==1


def test_260_unrelated_ram_loads_do_not_consume_uart_pending_budget():
    s=Stream();m=linker(s,max_pending=2)
    for sequence in range(1,261):
        s.events=[];s.cpu_load(dict(execution_id='cpu-execution',testcase_id='read-case-B',
            source_component='cpu',source_epoch=0,channel_id='data',source_sequence=sequence),address=0x200)
        assert not accepted(play(m,s.events))
        assert m.pending_count==0 and not m.degraded
    s.native.counter=260;s.events=[];s.lifecycle()
    assert len(accepted(play(m,s.events)))==1


def test_fourth_uart_read_after_260_cross_case_instruction_responses():
    from myfuzz.scenario.uart_retired_read import _RVFI_NAMES
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    from tests.scenario.test_cpu_retirement import NOP
    s=Stream();m=linker(s)
    for _ in range(3):
        s.events=[];s.lifecycle();assert len(accepted(play(m,s.events)))==1
    for sequence in range(2,262):
        s.events=[];pc=0x10000+sequence*4
        f=fetch(NOP,seq=sequence,pc=pc);f.update(event_id=f'long-fetch:{sequence}')
        f['transaction'].update(execution_id='cpu-execution',testcase_id=f'instruction-case-{sequence}',
            source_component='cpu',source_epoch=0)
        f['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,writer_event_ids=['initial-image']*4)
        s.events.append(deepcopy(f));s.cpu.consume(f)
        r=retire(NOP,order=s.order,address=0,data=0)
        r.update(execution_id='cpu-execution',source_component='cpu',source_epoch=0,
            event_id=f'long-retire:{sequence}',pc_rdata=pc,pc_wdata=pc+4,
            rs1_addr=0,rs1_rdata=0,rd_addr=0,rd_wdata=0)
        for name in _RVFI_NAMES:r.setdefault(name,0)
        r['valid']=1;tick=s.order+1
        scope=dict(component='cpu',reset_epoch=0,command_sequence=tick)
        r.update(schema_version='cpu_retire.v2',phase='post',local_tick=tick,command_scope=scope,
            receipt_id=dict(execution='cpu-native',sequence=tick),
            actual_post_ref=dict(command_scope=scope,local_tick=tick,phase='post'),
            receipt_ticks=dict(tick_before=tick-1,tick_after=tick,new_ticks=1,local_tick_base=0),
            observation_contract=ibex_irq_receipt_contract(),observation=dict(sampling_edge='post_rising',
                physical={'rvfi_'+name:r[name] for name in _RVFI_NAMES}))
        s.order+=1;s.events.append(deepcopy(r));s.cpu.consume(r)
        assert not accepted(play(m,s.events))
    s.events=[];s.lifecycle();proofs=accepted(play(m,s.events))
    assert len(proofs)==1 and proofs[0]['fullkey']['source_sequence']==4
    assert not m.degraded and m.pending_count==0


def test_explicit_small_instruction_budget_still_causes_certainty_barrier():
    from tests.scenario.test_cpu_retirement import NOP
    s=Stream();m=linker(s,max_instruction_witnesses=2)
    assert len(accepted(play(m,s.lifecycle())))==1
    for seq in (2,3):
        f=fetch(NOP,seq=seq,pc=0x10000+seq*4)
        f.update(event_id=f'limited-fetch:{seq}')
        f['transaction'].update(execution_id='cpu-execution',source_component='cpu',source_epoch=0)
        m.consume(f)
    assert m.degraded
    s.events=[];s.lifecycle();assert not accepted(play(m,s.events))
