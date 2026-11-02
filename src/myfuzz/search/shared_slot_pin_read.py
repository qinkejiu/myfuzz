"""Opaque F5 pin -> PADIN/F2 observer for the actual shared-slot executor.

This observes completed sealed cases. It grants neither execution nor IRQ
prerequisites, and never treats the GPIOEN writer or bootstrap as a pin writer.
"""
from copy import deepcopy
from weakref import WeakKeyDictionary

from .pin_read import resource_identity, _validate_writer_receipt
from .gpio_relations import _bind_case_session, _read_case_attribution

_INSTALLATIONS=WeakKeyDictionary()
_RUNTIMES=WeakKeyDictionary()
_REPORTS=WeakKeyDictionary()


class _Report:
    def document(self):
        if self not in _REPORTS: raise ValueError('unissued_shared_pin_report')
        return deepcopy(_REPORTS[self][1])


class _Installation:
    def current_state(self): return read_current(self)
    def observe_case(self,case_id): return observe_case(self,case_id)
    def rebind_after_reset(self,*,barrier_event_id):
        from .shared_slot_reset import rebind_epoch
        if self not in _INSTALLATIONS: raise ValueError('missing_shared_pin_installation')
        state=_INSTALLATIONS[self]
        if state['reset_scope'] is None: raise ValueError('shared_pin_prior_live_scope_required')
        scope=rebind_epoch(state['runtime'],state['reset_scope'],barrier_event_id=barrier_event_id)
        state['writers'].clear()
        state['epoch_start_event']=barrier_event_id
        state['processes']=tuple(scope['processes'].values())
        state['reset_scope']=scope
    def audit(self):
        if self not in _INSTALLATIONS: raise ValueError('missing_shared_pin_installation')
        return deepcopy(_INSTALLATIONS[self]['audit'])


def _methods():
    from myfuzz.integration import shared_f6_slots,shared_slot_consumers,native_obi_hops
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    from myfuzz.scenario.f6_instruction_fetch_receipt import validate_shared_fixed_support
    from myfuzz.integration.gpio_f2_consumer import gpio_read_samples,validate_gpio_authority
    return (shared_f6_slots.flow_records,shared_slot_consumers.declare_slot,
        native_obi_hops.check_f2_exact_hops,ScenarioRunner.events_since,
        ScenarioRunner._event_refs_since,AdmissionRegistry.get,
        validate_shared_fixed_support,gpio_read_samples,validate_gpio_authority)


_METHOD_PINS=_methods()
_METHOD_CODES=tuple(f.__code__ for f in _METHOD_PINS)


def install_shared_slot_pin_consumer(runtime):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority,_AUTHORITIES
    if type(runtime) is not CompiledF6Runtime or runtime in _RUNTIMES:
        raise ValueError('actual_shared_slot_runtime_required')
    paths=runtime.runtime_path_admission['shared_flow_paths']
    if not {'F1','F2','F5'}<=set(paths):raise ValueError('shared_pin_PADIN_paths_required')
    pin=paths['F5']['pin'];target_id=pin['component'];runner=runtime.runner
    row,=[r for r in runtime.compiled_inputs['compiled']['paths'] if r['flow_id']=='F2' and r['status']=='executable']
    if (row['execution_contract']['register']!='PADIN'
            or row['execution_contract']['target_component']!=target_id or pin['width']!=1):
        raise ValueError('shared_PADIN_target_required')
    target=runner.sessions[target_id];authority=runtime.assembly.companion_authorities[target_id]
    registry=runner._provenance.registry
    if (type(runner) is not ScenarioRunner or type(target) is not GeneratedPulpGpioSession
            or type(runtime.cpu) is not GeneratedCve2Session or runner.sessions[runtime.cpu_id] is not runtime.cpu
            or type(authority) is not GpioRegisterVersionAuthority or _AUTHORITIES.get(target) is not authority
            or authority.target is not target or type(registry) is not AdmissionRegistry):
        raise ValueError('actual_shared_GPIO_owners_required')
    methods=_methods()
    if methods!=_METHOD_PINS or tuple(f.__code__ for f in methods)!=_METHOD_CODES:
        raise ValueError('shared_pin_method_drift')
    methods[0](runtime)  # authenticate the installed slot ledger
    handle=_Installation()
    _INSTALLATIONS[handle]=dict(runtime=runtime,runner=runner,session=runtime.session,cpu=runtime.cpu,
        target=target,target_id=target_id,pin=pin['bit_offset'],authority=authority,registry=registry,
        paths=deepcopy(paths),f2_row=deepcopy(row),writers={},audit=[],processes=None,
        reset_scope=None,epoch_start_event=0,
        methods=methods,codes=tuple(f.__code__ for f in methods),events_since=methods[3],
        case_session=_bind_case_session(runtime.session,runner))
    _RUNTIMES[runtime]=handle
    return handle


def _live(handle):
    from myfuzz.scenario.gpio_register_version import _AUTHORITIES
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        raise ValueError('missing_shared_pin_installation')
    s=_INSTALLATIONS[handle];r=s['runtime'];runner=s['runner']
    if (type(r) is not CompiledF6Runtime or r.runner is not runner or r.session is not s['session'] or r.cpu is not s['cpu']
            or runner.sessions.get(r.cpu_id) is not s['cpu']
            or runner.sessions.get(s['target_id']) is not s['target']
            or r.assembly.companion_authorities.get(s['target_id']) is not s['authority']
            or _AUTHORITIES.get(s['target']) is not s['authority'] or runner._provenance.registry is not s['registry']
            or r.runtime_path_admission['shared_flow_paths']!=s['paths']
            or _methods()!=s['methods'] or tuple(f.__code__ for f in s['methods'])!=s['codes']
            or any(k in vars(runner) for k in ('events_since','_event_refs_since')) or 'get' in vars(s['registry'])
            or not r._begun or r.finished or runner._status!='running'):
        raise ValueError('shared_pin_live_scope_changed')
    processes=tuple(local.process for local in runner.sessions.values())
    if any(p is None or p.poll() is not None for p in processes):raise ValueError('missing_shared_pin_process')
    if any(r._native_processes.get(name) is not local.process for name,local in runner.sessions.items()):
        raise ValueError('shared_pin_process_identity_changed')
    if s['processes'] is None:s['processes']=processes
    if s['processes']!=processes:raise ValueError('shared_pin_process_changed')
    if s['reset_scope'] is None:
        from .shared_slot_reset import capture_epoch
        s['reset_scope']=capture_epoch(r)
    elif (runner.command_epoch!=s['reset_scope']['command_epoch']
            or any(runner.sessions[name].reset_epoch!=epoch
                   for name,epoch in s['reset_scope']['epochs'].items())):
        raise ValueError('shared_pin_reset_rebind_required')
    s['methods'][8](s['authority'])
    return s


def _case(s,row):
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction
    cases=s['session'].cases;i=row['session_case_index']
    if not 0<=i<len(cases) or cases[i].case_id!=row['case_id'] or row['status']!='passed':
        raise ValueError('sealed_shared_pin_case_required')
    case=cases[i];receipt=s['session'].case_receipt(case.case_id)
    if receipt.event_start < s['epoch_start_event']:
        raise ValueError('shared_pin_pre_reset_case')
    _validate_writer_receipt(s,case,receipt)
    cert=row['certificate']
    if (cert.get('status')!='certified' or cert.get('case_id')!=case.case_id
            or cert.get('flow_id')!=row['flow']):
        raise ValueError('sealed_shared_pin_certificate_required')
    if row['flow']=='F2' and (type(case.source) is not BoundOnlineInstruction
            or case.path_id!=s['paths']['F2']['path_id']):raise ValueError('actual_shared_F2_source_required')
    return case,receipt


def _refresh_writers(s,rows):
    from myfuzz.scenario.batch import BatchSourceEvent
    for row in rows:
        if row['flow']!='F5' or row['status']!='passed':continue
        completed=s['session']._receipts.get(row['case_id'])
        if completed is not None and completed[1].event_start<s['epoch_start_event']:continue
        case,receipt=_case(s,row);source=case.source
        if type(source) is not BatchSourceEvent:raise ValueError('actual_shared_F5_pin_source_required')
        bound=s['methods'][6](s['cpu'],case_id=case.case_id)
        if (bound['slot_index']!=row['slot_index'] or bound['session_case_index']!=row['session_case_index']
                or bound['role']!='fixed_support' or bound['fuzz_authority'] is not False or bound['F6_authority'] is not False
                or case.path_id!=s['paths']['F5']['path_id']
                or (source.component,source.port,source.bit_offset,source.width)!=(s['target_id'],s['paths']['F5']['pin']['port'],s['pin'],1)):
            raise ValueError('actual_shared_F5_support_required')
        admission=s['methods'][5](s['registry'],source.action_id)
        applied=[e for e in receipt.events if e.get('kind')=='gpio_input_segment_applied'
            and e.get('component')==source.component and e.get('bit_lo')==s['pin'] and e.get('width')==1
            and e.get('value')==source.value and e.get('origin')==dict(kind='source_admission',action_id=source.action_id)]
        if (admission is None or admission.case_id!=case.case_id or admission.role!='fuzz_source'
                or admission.input_kind!='source_event' or not applied):raise ValueError('actual_shared_F5_admission_required')
        epoch=s['target'].reset_epoch
        if not any(e.get('reset_epoch')==epoch for e in applied):continue
        s['writers'][source.action_id]=dict(admission=admission,epoch=epoch,case_id=case.case_id,value=source.value,
            session_case_index=row['session_case_index'],
            resource_identity=resource_identity(s['target_id'],s['pin'],epoch,admission.admission_id))


def _origin_writer(s,origin,epoch):
    if not isinstance(origin,dict) or origin.get('kind')!='native_pin_sample' or origin.get('pin')!=s['pin']:return None
    context=origin.get('source_context');segments=context.get('segments',[]) if isinstance(context,dict) else []
    candidates=[v for v in segments if v.get('bit_lo')==s['pin'] and v.get('width')==1
        and v.get('value')==origin.get('value') and v.get('origin',{}).get('kind')=='source_admission']
    if len(candidates)!=1:return None
    action=candidates[0]['origin'].get('action_id');writer=s['writers'].get(action)
    if writer is None or writer['epoch']!=epoch or writer['value']!=origin.get('value'):return None
    admission=s['methods'][5](s['registry'],action)
    if (admission is not writer['admission'] or admission.component!=s['target_id']
            or admission.path_id!=s['paths']['F5']['path_id'] or admission.role!='fuzz_source'
            or admission.input_kind!='source_event'):return None
    runner=s['runner'];owner=runner.ownership.mutation_source(s['target_id'],'gpio_in',s['pin'],1,direction=admission.direction)
    actual=runner._provenance.edge_index.source_owner_ref(admission.source_id,admission.path_id,
        admission.direction,s['target_id'],'gpio_in',s['pin'],1)
    return writer if owner==actual else None


def read_current(handle):
    try:
        s=_live(handle);_refresh_writers(s,s['methods'][0](s['runtime']))
        epoch=s['target'].reset_epoch;authority=s['authority']
        enabled=authority.consume(authority.issue(register='GPIOEN',reset_epoch=epoch))
        current=authority.consume(authority.issue(register='PADIN',reset_epoch=epoch))
        writer=_origin_writer(s,current['current_origins'][s['pin']],epoch)
        return dict(status='observed',component=s['target_id'],pin=s['pin'],reset_epoch=epoch,
            value=(current['value']>>s['pin'])&1,sample_version=current['native_sample_version'],
            enabled=bool(enabled['value']&(1<<s['pin'])),writer_attributed=writer is not None,
            writer_case_id=writer['case_id'] if writer else None,resource_identity=writer['resource_identity'] if writer else None,
            irq_consumption='unknown',execution_authority=False)
    except (ValueError,KeyError,TypeError,AttributeError,RuntimeError) as error:
        return dict(status='unknown',reason=str(error)[:256],writer_attributed=False,irq_consumption='unknown')


def authenticated_report(handle,report):
    s=_live(handle)
    if type(report) is not _Report or report not in _REPORTS or _REPORTS[report][0] is not handle:
        raise ValueError('unissued_shared_pin_report')
    doc=_REPORTS[report][1]
    if doc['reset_epoch']!=s['target'].reset_epoch:raise ValueError('shared_pin_report_epoch_changed')
    return deepcopy(doc)


def observe_case(handle,case_id):
    s=_live(handle);runtime=s['runtime'];runner=s['runner'];epoch=s['target'].reset_epoch
    doc=dict(status='unknown',relations=[],writer=None,read_case_id=case_id,reset_epoch=epoch,
        irq_consumption='unknown',grants_prerequisites=False)
    try:
        rows=s['methods'][0](runtime);_refresh_writers(s,rows)
        row,=[row for row in rows if row['case_id']==case_id]
        for writer in s['writers'].values():
            if writer['case_id']==case_id and writer['epoch']==epoch:doc['writer']={k:writer[k] for k in ('case_id','value','resource_identity')}
        if row['flow']!='F2':raise ValueError('not_shared_PADIN_read_case')
        case,receipt=_case(s,row)
        declaration=s['methods'][1](runtime.compiled_inputs,runtime.contract['program_contract']['shared_slots'],
            runtime.runtime_path_admission,flow='F2',raw=bytes.fromhex(row['raw_hex']),slot_index=row['slot_index'])
        if case.source.data.hex()!=declaration['code_hex']:raise ValueError('shared_PADIN_fragment_mismatch')
        witness=s['authority'].consume(s['authority'].issue(register='PADIN',reset_epoch=epoch));read=witness['read_receipt']
        if type(read) is not dict or read.get('reset_epoch')!=epoch:raise ValueError('native_PADIN_read_missing')
        writer=_origin_writer(s,read['pin_origins'][s['pin']],epoch)
        if writer is None or writer['session_case_index']>=row['session_case_index']:
            doc['status']='unattributed';raise ValueError('PADIN_writer_unattributed')
        from myfuzz.integration.generated_storage_consumer import _join_delivery
        from myfuzz.integration.compiled_f4 import _cpu_traces,_cpu_error_policy
        from myfuzz.integration.compiled_f2 import _f2_edges
        events=receipt.events;access=declaration['candidate']['access']
        deliveries=[e for e in events if e.get('kind')=='mmio_delivery' and e.get('component')==runtime.cpu_id
            and e.get('device_id')==access['device_id'] and e.get('address')==access['address'] and e.get('write') is False]
        if len(deliveries)!=1 or deliveries[0].get('read_value')!=read['value']:raise ValueError('shared_PADIN_delivery_mismatch')
        delivery=deliveries[0]
        accepted=_join_delivery(events,delivery=delivery,component=runtime.cpu_id,device=access['device_id'],address=access['address'],offset=8,write=False)
        pre,post=s['methods'][7](events,target=s['target'],component=s['target_id'],producer_event_id=delivery['producer_event_id'],
            signals=s['target'].artifact.runtime_document['base_protocol_trace']['signals'],offset=8,value=read['value'],reset_epoch=epoch)
        if (pre['local_tick']!=read['local_tick'] or s['target']._normalized_physical(pre['outputs'])!=read['raw_pre']
                or s['target']._normalized_physical(post['outputs'])!=read['raw_post']):raise ValueError('live_shared_PADIN_raw_mismatch')
        ram=[e for e in events if e.get('kind')=='memory_write' and e.get('component')==runtime.cpu_id
            and e.get('address')==declaration['result_address'] and e.get('byte_enable')==15
            and e.get('value')==read['value']^declaration['xor_constant'] and e['event_id']>delivery['event_id']]
        if len(ram)!=1:raise ValueError('shared_PADIN_dependent_RAM_missing')
        joins=[dict(native_APB_event=pre['event_id'],native_post_event=post['event_id'],delivery_event=delivery['event_id'],
            acceptance_event=accepted['event_id'],source_transaction=delivery['source_transaction'],value=read['value'],write=False)]
        image=next(v for v in s['f2_row']['sources'] if v['kind']=='instruction_image')
        stream=next(v for v in s['f2_row']['sources'] if v['kind']=='cpu_load_stream')
        union=dict(runtime.compiled_inputs['compiled'],runtime_dependency_graph=runtime.runtime_path_admission['runtime_graph'],
            runtime_path_contract=runtime.runtime_path_admission['runtime_contract'])
        snapshots=[runtime.memory.read(case.source.address+i,4,transaction_id=f'shared-pin:{case_id}:{i}') for i in range(0,32,4)]
        result=runtime.memory.read(declaration['result_address'],4,transaction_id=f'shared-pin:{case_id}:result')
        exact=deepcopy(s['methods'][2](events=s['methods'][4](runner,0,stop=receipt.event_end),declaration=declaration,
            image=image,stream=stream,traces=_cpu_traces(runtime.cpu.artifact,image,stream),address=case.source.address,
            source_event_id=case.source.action_id,joins=joins,declared_edges=_f2_edges(union,image,stream['register_access']),
            instruction_snapshots=snapshots,ram_event_id=ram[0]['event_id'],error_policy=_cpu_error_policy(runtime.cpu.artifact,image,stream),
            proof_scope='pin_PADIN_OBI_dependent_RAM',result_snapshot=result))
        needed={pre['event_id'],ram[0]['event_id']}
        attribution=_read_case_attribution(s['case_session'],runner,s,needed)
        if any(attribution.get(i,{}).get('case_id')!=case_id for i in needed):raise ValueError('shared_PADIN_case_scope_mismatch')
        value=(read['value']>>s['pin'])&1
        if value!=writer['value']:raise ValueError('shared_PADIN_writer_value_mismatch')
        relation=dict(status='verified',reward_eligible=True,component=s['target_id'],pin=s['pin'],value=value,
            resource_identity=writer['resource_identity'],writer_case_id=writer['case_id'],read_case_id=case_id,
            reset_epoch=epoch,sample_version=read['field_version'],native_read=deepcopy(read),writer_admission=writer['admission'].document(),
            exact_hops=exact,irq_consumption='unknown',grants_prerequisites=False)
        doc.update(status='verified',relations=[relation])
    except (ValueError,KeyError,TypeError,AttributeError,RuntimeError) as error:doc['reason']=str(error)[:256]
    if len(s['audit'])>=4096:raise ValueError('shared_pin_report_capacity')
    s['audit'].append(deepcopy(doc));report=_Report();_REPORTS[report]=(handle,doc)
    return report
