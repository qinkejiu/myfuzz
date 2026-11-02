"""Installed shared-slot RAM versions and sealed F3 -> F1 attribution.

Host byte cells describe current versions; only a sealed native OBI read plus
its installed dependency certificates can earn relation credit. Neither source
instruction causality nor retirement is inferred from this relation.
"""
from copy import deepcopy
from weakref import WeakKeyDictionary
from .ram import _unknown
from .ram_actions import ram_identity
from .gpio_relations import _bind_case_session

_INSTALLATIONS=WeakKeyDictionary()

class _Installation:
    def current_state(self): return read_current(self)
    def observe_case(self,case_id): return observe_case(self,case_id)
    def rebind_after_reset(self,*,barrier_event_id):
        from .shared_slot_reset import rebind_epoch
        if self not in _INSTALLATIONS: raise ValueError('missing_shared_RAM_installation')
        state=_INSTALLATIONS[self]
        if state['reset_scope'] is None: raise ValueError('shared_RAM_prior_live_scope_required')
        scope=rebind_epoch(state['runtime'],state['reset_scope'],barrier_event_id=barrier_event_id)
        state['tracker'].reset(event_id=barrier_event_id)
        state['cursor']=barrier_event_id
        state['process']=scope['processes'][state['runtime'].cpu_id]
        state['reset_scope']=scope


def install_shared_slot_ram_consumer(runtime):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.shared_f6_slots import flow_records
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    if type(runtime) is not CompiledF6Runtime:
        raise ValueError('actual_shared_slot_runtime_required')
    runner=runtime.runner;cpu=runtime.cpu;provider=runner._memory_dependency_consumer
    if (type(runner) is not ScenarioRunner or type(cpu) is not GeneratedCve2Session
            or runner.sessions.get(runtime.cpu_id) is not cpu
            or type(provider) is not MemoryDependencyEvidenceConsumer):
        raise ValueError('actual_shared_slot_RAM_provider_required')
    paths=runtime.runtime_path_admission['shared_flow_paths']
    if not {'F1','F3'}<=set(paths):raise ValueError('shared_RAM_paths_required')
    images=[]
    for flow in ('F1','F3'):
        path,=[p for p in runtime.compiled_inputs['compiled']['paths'] if p['flow_id']==flow and p['status']=='executable']
        image,=[s for s in path['sources'] if s['kind']=='instruction_image']
        images.append(image)
    if any((i['port'],i['range'])!=(images[0]['port'],images[0]['range']) for i in images):
        raise ValueError('shared_RAM_resource_mismatch')
    flow_records(runtime)  # requires the actual constructor-installed seal ledger
    handle=_Installation()
    _INSTALLATIONS[handle]=dict(runtime=runtime,runner=runner,cpu=cpu,session=runtime.session,
        provider=provider,memory=runtime.memory,image=deepcopy(images[0]),paths=deepcopy(paths),
        address=runtime.contract['program_contract']['shared_slots']['scratch_address'],
        tracker=LiveMemoryEffectTracker(consumer=provider),cursor=0,process=None,reset_scope=None,
        case_session=_bind_case_session(runtime.session,runner),
        methods=(ScenarioRunner._event_refs_since,ScenarioRunner.event_by_id,flow_records),
        codes=tuple(f.__code__ for f in (ScenarioRunner._event_refs_since,ScenarioRunner.event_by_id,flow_records)))
    return handle


def _live(handle):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.shared_f6_slots import flow_records
    from myfuzz.scenario.runner import ScenarioRunner
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        raise ValueError('missing_shared_RAM_installation')
    s=_INSTALLATIONS[handle];r=s['runtime'];runner=s['runner'];cpu=s['cpu']
    methods=(ScenarioRunner._event_refs_since,ScenarioRunner.event_by_id,flow_records)
    if (type(r) is not CompiledF6Runtime or r.runner is not runner or r.cpu is not cpu
            or r.session is not s['session'] or r.memory is not s['memory']
            or runner.sessions.get(r.cpu_id) is not cpu
            or runner._memory_dependency_consumer is not s['provider']
            or r.runtime_path_admission['shared_flow_paths']!=s['paths']
            or methods!=s['methods'] or tuple(f.__code__ for f in methods)!=s['codes']
            or any(k in vars(runner) for k in ('events_since','event_by_id','_event_refs_since'))
            or not r._begun or r.finished or runner._status!='running'):
        raise ValueError('shared_RAM_live_scope_changed')
    process=cpu.process
    if process is None or process.poll() is not None or r._native_processes.get(r.cpu_id) is not process:
        raise ValueError('shared_RAM_live_process_required')
    if s['process'] is None:s['process']=process
    if s['process'] is not process:raise ValueError('shared_RAM_process_changed')
    if s['reset_scope'] is None:
        from .shared_slot_reset import capture_epoch
        s['reset_scope']=capture_epoch(r)
    elif (runner.command_epoch!=s['reset_scope']['command_epoch']
            or any(runner.sessions[name].reset_epoch!=epoch
                   for name,epoch in s['reset_scope']['epochs'].items())):
        raise ValueError('shared_RAM_reset_rebind_required')
    rows=flow_records(r)
    count=runner.event_count
    for event in methods[0](runner,s['cursor'],stop=count):s['tracker'].consume_event(event)
    s['cursor']=count
    return s,rows,count


def _attribution(s,rows,needed):
    """Read pinned immutable bounds and individually indexed native events.

    No receipt or event references escape this helper. Native evidence is still
    authenticated by the installed tracker and the sealed consumer certificate.
    """
    from myfuzz.scenario.session_runtime import ScenarioSession,OnlineCaseReceipt
    session=s['session'];binding=s['case_session']
    if (type(session) is not ScenarioSession or session.runner is not s['runner']
            or 'case_receipt' in vars(session) or 'cases' in vars(session)
            or ScenarioSession.case_receipt is not binding['reader']
            or ScenarioSession.case_receipt.__code__ is not binding['reader_code']
            or ScenarioSession.cases.fget is not binding['getter']
            or ScenarioSession.cases.fget.__code__ is not binding['getter_code']):
        raise ValueError('shared_RAM_case_reader_drift')
    cases=session.cases;result={};previous_end=0
    for row in rows:
        i=row['session_case_index']
        if not 0<=i<len(cases) or cases[i].case_id!=row['case_id']:
            raise ValueError('shared_RAM_sealed_case_drift')
        completed=session._receipts.get(row['case_id'])
        if completed is None:continue
        case,metadata=completed
        if (case is not cases[i] or type(metadata) is not OnlineCaseReceipt
                or metadata.case_id!=row['case_id'] or metadata.events!=()
                or not previous_end<=metadata.event_start<=metadata.event_end<=s['runner'].event_count):
            raise ValueError('shared_RAM_receipt_boundary_drift')
        previous_end=metadata.event_end
        for event_id in needed:
            if type(event_id) is not int or event_id<=0:
                raise ValueError('shared_RAM_event_ID_required')
            if metadata.event_start<=event_id-1<metadata.event_end:
                event=s['methods'][1](s['runner'],event_id)
                if event is None or event.get('event_id')!=event_id:
                    raise ValueError('shared_RAM_event_ID_order_drift')
                if event_id in result:raise ValueError('shared_RAM_overlapping_receipts')
                result[event_id]=dict(case_id=case.case_id,case_index=i)
    if session.cases!=cases:raise ValueError('shared_RAM_cases_changed')
    return result


def _matches_f3_commit(s,resource,row):
    """Join distinct store-observation and issuer commit events exactly."""
    try:
        cert=row['certificate'];observed=cert['memory_store_observation']
        if (cert.get('status')!='certified' or cert.get('case_id')!=row['case_id']
                or cert.get('flow_id')!='F3' or cert.get('ram_address')!=s['address']):return False
        get=s['methods'][1];runner=s['runner']
        commit=get(runner,resource['observation_event_id'])
        store=get(runner,observed['memory_write_event'])
        if not isinstance(commit,dict) or not isinstance(store,dict):return False
        doc=commit['commit_document'];tx=observed['transaction']
        version=resource['version'];base=s['address']-s['image']['range'][0]
        if (commit.get('kind')!='memory_write_commit' or store.get('kind')!='memory_write'
                or commit.get('schema_version')!='memory_write_commit.v1'
                or commit['event_id']!=resource['observation_event_id']
                or store['event_id']!=observed['memory_write_event']
                or not observed['acceptance_event']<store['event_id']<commit['event_id']<observed['response_event']
                or commit['producer_event_id']!=store['producer_event_id']
                or store['producer_event_id']!=observed['acceptance_event']
                or commit['component']!=s['runtime'].cpu_id or store['component']!=commit['component']
                or commit['transaction']!=tx or store['transaction']!=tx or doc['fullkey']!=tx
                or tx['source_component']!=s['runtime'].cpu_id or tx['channel_id']!='data'
                or tx['source_epoch']!=s['cpu'].reset_epoch
                or doc['memory_id']!=s['image']['port'] or store['memory_id']!=doc['memory_id']
                or store['address']!=s['address'] or doc['byte_offset']!=base or store['byte_offset']!=base
                or doc['generation']!=version[0] or store['generation']!=version[0]
                or list(doc['version'])!=version or list(store['version'])!=version
                or doc['width_bytes']!=4 or store['width_bytes']!=4
                or doc['byte_enable']!=15 or store['byte_enable']!=15
                or doc['commit_status']!='complete' or doc['performed_effect'] is not True):return False
        cells=doc['enabled_byte_cells']
        if (len(cells)!=4 or {c['byte_offset'] for c in cells}!=set(range(base,base+4))
                or any(c['writer_kind']!='STORE' or list(c['version'])!=version
                    or c['value']!=(store['value']>>(8*(c['byte_offset']-base)))&255 for c in cells)):
            return False
        cell,=[c for c in cells if c['byte_offset']==resource['byte_offset']]
        return cell['value']==resource['value']
    except (KeyError,TypeError,ValueError):return False


def _current(s,rows):
    resources=[];offset=s['address']-s['image']['range'][0]
    for lane in range(4):
        witnesses=s['tracker'].retained_ram_witnesses(s['image']['port'],offset+lane)
        if len(witnesses)!=1:
            state=_unknown('no_exact_current_store_version')
            tracker=s['tracker']
            cell=s['memory'].inspect_byte(s['image']['port'],offset+lane)
            state.update(reset_epoch=s['cpu'].reset_epoch,
                tracker=tracker.document(), consumer_reason=tracker._consumer._reason,
                missing_byte_offset=offset+lane,
                cell=None if cell is None else dict(version=list(cell.version),
                    writer_kind=cell.writer_kind,writer_event_id=cell.writer_event_id),
                retained_writers=[dict(event_id=writer['event_id'],version=list(identity[4]),
                    writer_event_id=identity[5])
                    for identity,writer in tracker._consumer._writers.items()
                    if identity[1]==s['image']['port'] and identity[3]==offset+lane])
            return state
        w=witnesses[0]
        resources.append(dict(byte_offset=offset+lane,version=list(w.version),value=w.value,
            observation_event_id=w.event_id,evidence_ref=w.evidence_ref))
    observed=_attribution(s,rows,{r['observation_event_id'] for r in resources})
    sealed={r['case_id']:r for r in rows if r['status']=='passed' and r['flow']=='F3'}
    writers=[observed.get(r['observation_event_id'],{}).get('case_id') for r in resources]
    attributed=all(w in sealed for w in writers)
    if attributed:
        for resource,writer in zip(resources,writers,strict=True):
            if not _matches_f3_commit(s,resource,sealed[writer]):
                attributed=False;break
    return dict(status='observed',component=s['runtime'].cpu_id,memory_id=s['image']['port'],
        address=s['address'],reset_epoch=s['cpu'].reset_epoch,
        value=sum(r['value']<<(8*i) for i,r in enumerate(resources)),byte_resources=resources,
        writer_case_ids=writers,writer_attributed=attributed,
        proof_scope='current_installed_host_memory_bytes',execution_authority=False,
        retirement='unknown',source_origin='unknown')


def read_current(handle):
    try:
        s,rows,count=_live(handle);result=_current(s,rows)
        return result if s['runner'].event_count==count else _unknown('RAM_journal_changed')
    except (ValueError,TypeError,KeyError,AttributeError,RuntimeError) as e:
        return _unknown('shared_RAM_unavailable:'+str(e)[:512])


def match_current_read(current,observation):
    try:
        resources=current['byte_resources'];rows=observation['byte_relations']
        return (current['status']=='observed' and len(resources)==len(rows)==4
            and all((r['byte_offset'],r['version'],r['value'],r['observation_event_id'])==
                (c['byte_offset'],c['byte_version'],c['value'],c['write_event_id'])
                for r,c in zip(resources,rows,strict=True)))
    except (KeyError,TypeError,ValueError):return False


def observe_case(handle,case_id):
    unknown=dict(status='unknown',relations=[],retirement='unknown',source_origin='unknown')
    try:
        from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
        s,rows,count=_live(handle);current=_current(s,rows)
        row,=[r for r in rows if r['case_id']==case_id and r['status']=='passed' and r['flow']=='F1']
        cert=row['certificate'];observation=cert.get('memory_read_observation')
        if (cert.get('status')!='certified' or cert.get('case_id')!=case_id
                or cert.get('flow_id')!='F1' or cert.get('operation')!='ram_read_word'
                or cert.get('ram_address')!=s['address'] or not current.get('writer_attributed')
                or not match_current_read(current,observation)):return unknown
        report=MemoryDependencyEvidenceConsumer.report(s['provider'])
        if report.get('journal_integrity') is not True:return unknown
        if any(c not in report['certificates'] for c in observation['byte_relations']):return unknown
        needed={r['write_event_id'] for r in observation['byte_relations']}|{observation['memory_read_event']}
        observed=_attribution(s,rows,needed)
        writers=[observed.get(r['write_event_id'],{}).get('case_id') for r in observation['byte_relations']]
        if (observed.get(observation['memory_read_event'],{}).get('case_id')!=case_id
                or writers!=current['writer_case_ids'] or case_id in writers
                or s['runner'].event_count!=count):return unknown
        relation=dict(status='verified',reward_eligible=True,read_case_id=case_id,
            writer_case_ids=writers,resource_identity=ram_identity(current),
            component=current['component'],memory_id=current['memory_id'],address=current['address'],
            value=current['value'],native_read_observation=deepcopy(observation),
            retirement='unknown',source_origin='unknown',grants_prerequisites=False)
        return dict(unknown,status='verified',relations=[relation])
    except (ValueError,TypeError,KeyError,AttributeError,RuntimeError):return unknown
