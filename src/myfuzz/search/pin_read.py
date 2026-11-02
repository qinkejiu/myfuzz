"""Installed live F5 pin -> sampled PADIN -> DUT read/dependent RAM proof.

A saved document cannot install a handle, register a writer, or mint a report.
The observer rechecks the existing F2 native proof on the actual case journal.
IRQ acceptance, ISR execution and retirement remain unknown.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import sys
from weakref import WeakKeyDictionary

from .model import canonical
from .gpio_relations import _bind_case_session, _read_case_attribution

_INSTALLATIONS = WeakKeyDictionary()
_RUNTIMES = WeakKeyDictionary()
_REPORTS = WeakKeyDictionary()


class _Report:
    def document(self):
        if self not in _REPORTS: raise ValueError('unissued_pin_report')
        return deepcopy(_REPORTS[self][1])


class _Installation:
    def current_state(self): return read_current(self)
    def observe_case(self, case_id): return observe_case(self, case_id)
    def audit(self):
        if self not in _INSTALLATIONS: raise ValueError('missing_live_pin_installation')
        return deepcopy(_INSTALLATIONS[self]['audit'])


def resource_identity(component, pin, epoch, admission_id):
    return sha256(canonical([component,pin,epoch,admission_id])).hexdigest()


def install_pin_consumer(runtime):
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.integration.shared_f5_runtime import submit_shared_f5
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority, _AUTHORITIES
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    if (type(runtime) is not CompiledF4Runtime or runtime in _RUNTIMES
            or not runtime._f2_flows or runtime.register_f2!='PADIN' or runtime._f5_preparation is None):
        raise ValueError('actual_shared_PADIN_runtime_required')
    runner=runtime.runner;target=runner.sessions[runtime.target_id];cpu=runner.sessions[runtime.cpu_id]
    if (type(runner) is not ScenarioRunner or type(target) is not GeneratedPulpGpioSession
            or type(cpu) is not GeneratedCve2Session or type(runtime.authority) is not GpioRegisterVersionAuthority
            or _AUTHORITIES.get(target) is not runtime.authority):
        raise ValueError('actual_installed_GPIO_authority_required')
    registry=runner._provenance.registry
    if type(registry) is not AdmissionRegistry: raise ValueError('actual_admission_registry_required')
    pin=next(s for s in runtime.f5_binding.path['sources'] if s['kind']=='external_pin')
    handle=_Installation()
    _INSTALLATIONS[handle]=dict(runtime=runtime,runner=runner,target=target,cpu=cpu,authority=runtime.authority,
        session=runtime.session,registry=registry,pin=pin['bit_offset'],writers={},audit=[],
        stable=CompiledF4Runtime._stable,source_submit=submit_shared_f5,exact=check_f2_exact_hops,
        events_since=ScenarioRunner.events_since,event_by_id=ScenarioRunner.event_by_id,
        event_refs_since=ScenarioRunner._event_refs_since,event_refs_code=ScenarioRunner._event_refs_since.__code__,
        registry_get=AdmissionRegistry.get,case_session=_bind_case_session(runtime.session,runner),processes=None)
    _RUNTIMES[runtime]=handle
    return handle


def _live(handle):
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.integration import native_obi_hops,shared_f5_runtime
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    from myfuzz.scenario.gpio_register_version import _AUTHORITIES
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        raise ValueError('missing_live_pin_installation')
    state=_INSTALLATIONS[handle];runtime=state['runtime'];runner=state['runner']
    if (runtime.runner is not runner or runtime.session is not state['session']
            or runtime.authority is not state['authority'] or _AUTHORITIES.get(state['target']) is not state['authority']
            or runner.sessions.get(runtime.target_id) is not state['target'] or runner.sessions.get(runtime.cpu_id) is not state['cpu']
            or runner._provenance.registry is not state['registry'] or AdmissionRegistry.get is not state['registry_get']
            or '_event_refs_since' in vars(runner)
            or ScenarioRunner._event_refs_since is not state['event_refs_since']
            or ScenarioRunner._event_refs_since.__code__ is not state['event_refs_code']
            or 'get' in vars(state['registry']) or 'events_since' in vars(runner) or 'event_by_id' in vars(runner)
            or ScenarioRunner.events_since is not state['events_since'] or ScenarioRunner.event_by_id is not state['event_by_id']
            or CompiledF4Runtime._stable is not state['stable'] or shared_f5_runtime.submit_shared_f5 is not state['source_submit']
            or native_obi_hops.check_f2_exact_hops is not state['exact']
            or not runtime._begun or runner._status!='running'):
        raise ValueError('live_pin_scope_changed')
    # This observer grants no execution authority. Runtime begin/submit/finish
    # retain full static validation; queries retain the live identity gates below.
    processes=tuple(s.process for s in (state['cpu'],state['target']))
    if any(p is None or p.poll() is not None for p in processes): raise ValueError('missing_live_pin_process')
    if any(runtime._native_processes.get(c) is not p for c,p in zip((runtime.cpu_id,runtime.target_id),processes)):
        raise ValueError('live_pin_process_identity_changed')
    if state['processes'] is None:state['processes']=processes
    if state['processes']!=processes:raise ValueError('live_pin_process_changed')
    return state


def register_pin_writer(runtime, case, receipt):
    """Only the code-owned successful F5 submit calls this optional hook."""
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    if type(runtime) is not CompiledF4Runtime:return
    handle=_RUNTIMES.get(runtime)
    if handle is None:return
    state=_live(handle)
    if sys._getframe(1).f_code is not state['source_submit'].__code__:
        raise ValueError('pin_writer_requires_actual_submit')
    source=case.source
    _validate_writer_receipt(state,case,receipt)
    admission=state['registry_get'](state['registry'],source.action_id)
    applied=[e for e in receipt.events if e.get('kind')=='gpio_input_segment_applied'
        and e.get('component')==runtime.target_id and e.get('bit_lo')==state['pin'] and e.get('width')==1
        and e.get('value')==source.value and e.get('origin')=={'kind':'source_admission','action_id':source.action_id}]
    if admission is None or admission.case_id!=case.case_id or not applied:return
    epoch=state['target'].reset_epoch
    state['writers'][source.action_id]=dict(admission=admission,epoch=epoch,case_id=case.case_id,
        value=source.value,resource_identity=resource_identity(runtime.target_id,state['pin'],epoch,admission.admission_id))


def _validate_writer_receipt(state,case,receipt):
    from myfuzz.scenario.session_runtime import OnlineCaseReceipt
    completed=state['session']._receipts.get(case.case_id)
    if (type(receipt) is not OnlineCaseReceipt or completed is None or completed[0] is not case
            or receipt.status!='running' or receipt.violations
            or replace(receipt,events=())!=completed[1]
            or receipt.events!=state['events_since'](state['runner'],receipt.event_start,stop=receipt.event_end)):
        raise ValueError('pin_writer_actual_receipt_required')


def _origin_writer(state, origin, epoch):
    if not isinstance(origin,dict) or origin.get('kind')!='native_pin_sample' or origin.get('pin')!=state['pin']:
        return None
    context=origin.get('source_context')
    segments=context.get('segments',[]) if isinstance(context,dict) else []
    candidates=[s for s in segments if s.get('bit_lo')==state['pin'] and s.get('width')==1
        and s.get('value')==origin.get('value') and s.get('origin',{}).get('kind')=='source_admission']
    if len(candidates)!=1:return None
    action_id=candidates[0]['origin'].get('action_id');writer=state['writers'].get(action_id)
    if writer is None or writer['epoch']!=epoch or writer['value']!=origin.get('value'):return None
    admission=state['registry_get'](state['registry'],action_id)
    if admission is not writer['admission'] or admission.role!='fuzz_source' or admission.input_kind!='source_event':return None
    runtime=state['runtime'];binding=runtime.f5_binding
    if admission.component!=runtime.target_id or admission.path_id!=binding.path['runtime_path_identity']['path_id']:return None
    owner=state['runner'].ownership.mutation_source(runtime.target_id,'gpio_in',state['pin'],1,direction=admission.direction)
    actual=state['runner']._provenance.edge_index.source_owner_ref(admission.source_id,admission.path_id,
        admission.direction,runtime.target_id,'gpio_in',state['pin'],1)
    return writer if owner==actual else None


def read_current(handle):
    try:
        state=_live(handle);authority=state['authority'];epoch=state['target'].reset_epoch
        enabled=authority.consume(authority.issue(register='GPIOEN',reset_epoch=epoch))
        current=authority.consume(authority.issue(register='PADIN',reset_epoch=epoch))
        writer=_origin_writer(state,current['current_origins'][state['pin']],epoch)
        return dict(status='observed',component=state['runtime'].target_id,pin=state['pin'],reset_epoch=epoch,
            value=(current['value']>>state['pin'])&1,sample_version=current['native_sample_version'],
            enabled=bool(enabled['value'] & (1<<state['pin'])),writer_attributed=writer is not None,
            writer_case_id=writer['case_id'] if writer else None,
            resource_identity=writer['resource_identity'] if writer else None,irq_consumption='unknown',execution_authority=False)
    except (ValueError,KeyError,TypeError,AttributeError,RuntimeError) as error:
        return dict(status='unknown',reason=str(error)[:256],writer_attributed=False,irq_consumption='unknown')


def authenticated_report(handle,report):
    state=_live(handle)
    if type(report) is not _Report or report not in _REPORTS or _REPORTS[report][0] is not handle:
        raise ValueError('unissued_pin_report')
    document=_REPORTS[report][1]
    if document['reset_epoch']!=state['target'].reset_epoch:raise ValueError('pin_report_epoch_changed')
    return deepcopy(document)


def _check_exact(state,runner,**kwargs):
    # Borrow only for this synchronous pure checker; detach nested version output.
    return deepcopy(state['exact'](events=state['event_refs_since'](runner,0),**kwargs))


def observe_case(handle,case_id):
    state=_live(handle);runtime=state['runtime'];session=state['session'];runner=state['runner']
    document=dict(status='unknown',relations=[],writer=None,read_case_id=case_id,
        reset_epoch=state['target'].reset_epoch,irq_consumption='unknown',grants_prerequisites=False)
    for writer in state['writers'].values():
        if writer['case_id']==case_id and writer['epoch']==document['reset_epoch']:
            document['writer']={k:writer[k] for k in ('case_id','value','resource_identity')}
    try:
        from myfuzz.scenario.session_runtime import BoundOnlineInstruction
        from myfuzz.integration.generated_register_reader import declare_reader
        from myfuzz.integration.generated_storage_consumer import _join_delivery
        from myfuzz.integration.gpio_f2_consumer import gpio_read_samples
        cases=[c for c in session.cases if c.case_id==case_id]
        if len(cases)!=1:raise ValueError('actual_pin_case_missing')
        case=cases[0];receipt=session.case_receipt(case_id)
        if type(case.source) is not BoundOnlineInstruction or case.path_id!=runtime.runtime_path_admission_f2.runtime_path_id:
            raise ValueError('not_PADIN_read_case')
        if receipt is None or receipt.status!='running' or receipt.violations:raise ValueError('actual_PADIN_receipt_required')
        witness=state['authority'].consume(state['authority'].issue(register='PADIN',reset_epoch=document['reset_epoch']))
        read=witness['read_receipt']
        if not isinstance(read,dict):raise ValueError('native_PADIN_read_missing')
        writer=_origin_writer(state,read['pin_origins'][state['pin']],read['reset_epoch'])
        if writer is None or writer['case_id']==case_id:
            document['status']='unattributed';raise ValueError('PADIN_writer_unattributed')
        declaration=declare_reader(runtime.inputs['request'],runtime.inputs['compiled'],
            source_id=runtime.stream_f2['source_id'],address=runtime.access_f2['address'],result_address=runtime.result)
        if case.source.data.hex()!=declaration['code_hex']:raise ValueError('actual_PADIN_fragment_mismatch')
        events=receipt.events;access=declaration['candidate']['access']
        deliveries=[e for e in events if e.get('kind')=='mmio_delivery' and e.get('component')==runtime.cpu_id
            and e.get('device_id')==access['device_id'] and e.get('address')==access['address'] and e.get('write') is False]
        if len(deliveries)!=1 or deliveries[0].get('read_value')!=read['value']:raise ValueError('actual_PADIN_delivery_mismatch')
        delivery=deliveries[0]
        accepted=_join_delivery(events,delivery=delivery,component=runtime.cpu_id,device=access['device_id'],
            address=access['address'],offset=8,write=False)
        pre,post=gpio_read_samples(events,target=state['target'],component=runtime.target_id,
            producer_event_id=delivery.get('producer_event_id'),signals=state['target'].artifact.runtime_document['base_protocol_trace']['signals'],
            offset=8,value=read['value'],reset_epoch=document['reset_epoch'])
        if (pre['local_tick']!=read['local_tick'] or state['target']._normalized_physical(pre['outputs'])!=read['raw_pre']
                or state['target']._normalized_physical(post['outputs'])!=read['raw_post']):
            raise ValueError('live_PADIN_read_raw_mismatch')
        ram=[e for e in events if e.get('kind')=='memory_write' and e.get('component')==runtime.cpu_id
            and e.get('address')==runtime.result and e.get('byte_enable')==15
            and e.get('value')==read['value']^declaration['xor_constant'] and e['event_id']>delivery['event_id']]
        if len(ram)!=1:raise ValueError('actual_PADIN_dependent_RAM_missing')
        joins=[dict(native_APB_event=pre['event_id'],native_post_event=post['event_id'],delivery_event=delivery['event_id'],
            acceptance_event=accepted['event_id'],source_transaction=delivery['source_transaction'],value=read['value'],write=False)]
        snapshots=[state['cpu'].memory.read(case.source.address+i,4,transaction_id=f'pin-proof:{case_id}:{i}') for i in range(0,32,4)]
        result=state['cpu'].memory.read(runtime.result,4,transaction_id=f'pin-proof:{case_id}:result')
        exact=_check_exact(state,runner,declaration=declaration,image=runtime.image_f2,
            stream=runtime.stream_f2,traces=runtime.traces_f2,address=case.source.address,source_event_id=case.source.action_id,
            joins=joins,declared_edges=runtime.declared_edges_f2,instruction_snapshots=snapshots,
            ram_event_id=ram[0]['event_id'],error_policy=runtime.error_policy_f2,
            proof_scope='pin_PADIN_OBI_dependent_RAM',result_snapshot=result)
        attribution=_read_case_attribution(state['case_session'],runner,state,{pre['event_id'],ram[0]['event_id']})
        if any(attribution.get(i,{}).get('case_id')!=case_id for i in (pre['event_id'],ram[0]['event_id'])):
            raise ValueError('actual_PADIN_case_scope_mismatch')
        value=(read['value']>>state['pin'])&1
        if value!=writer['value']:raise ValueError('actual_PADIN_writer_value_mismatch')
        relation=dict(status='verified',reward_eligible=True,component=runtime.target_id,pin=state['pin'],value=value,
            resource_identity=writer['resource_identity'],writer_case_id=writer['case_id'],read_case_id=case_id,
            reset_epoch=read['reset_epoch'],sample_version=read['field_version'],native_read=deepcopy(read),
            writer_admission=writer['admission'].document(),exact_hops=exact,irq_consumption='unknown',grants_prerequisites=False)
        document.update(status='verified',relations=[relation])
    except (ValueError,KeyError,TypeError,AttributeError,RuntimeError) as error:
        document['reason']=str(error)[:256]
    if len(state['audit'])>=4096:raise ValueError('pin_report_capacity')
    state['audit'].append(deepcopy(document));report=_Report();_REPORTS[report]=(handle,document)
    return report
