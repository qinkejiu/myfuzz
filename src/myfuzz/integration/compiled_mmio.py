"""Protocol-level CPU/MMIO on the existing generated sessions and scheduler.

No internal register probe or storage-version issuer is required or invented.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from .compiled_process_audit import BuiltProcessAudit
from .compiled_f4 import (_input_identity,_cpu_traces,_cpu_error_policy,_f4_edges,
    check_f4_exact_hops,_semantic_canonical,normalized_semantic_sha256)
from .compiled_f2 import CompiledF2Runtime,_f2_edges
from .compiled_candidate_layout import compile_candidate_layout
from .compiled_f2_layout import compile_f2_candidate_layout
from .compiled_f4_runtime_path import admit_compiled_f4_runtime_path
from .compiled_f2_runtime_path import admit_compiled_f2_runtime_path
from .generated_register_writer import declare_writer
from .generated_register_reader import declare_reader
from .native_obi_hops import check_f2_exact_hops
from ..scenario.runtime_path_contract import PreparedRuntimePathContract
from ..runtime.adapters.apb3_mmio import bank_contract_facts
from .mmio_cpu_adapter import select_mmio_cpu


def memory_feedback_options(cpu_adapter, *, memory_flows):
    """The session receipt options one CPU row's own declaration asks for.

    The independent F1/F3 memory flows need a live host-RAM commit stream and
    writer-aware read receipts.  A ``split`` session numbers its data beats on
    their own channel and has both, so it asks for them (plus the measured tick
    stream) whenever the memory flows run.  A ``unified`` session has neither
    unless its adapter *declares* ``memory_receipts_on_unified``, and the
    default is ``False``: no row is switched on by protocol name, and an
    undeclared unified row simply returns no options here.
    """
    if not memory_flows:
        return {}
    channel = getattr(cpu_adapter, 'channel_model', 'split')
    if channel == 'split':
        return {'memory_commit_receipts': True, 'memory_readback_receipts': True,
                'physical_tick_samples': True}
    if channel == 'unified' and getattr(
            cpu_adapter, 'memory_receipts_on_unified', False) is True:
        # The unified packed port already measures every tick the runner needs;
        # only the two receipt streams are opted in.
        return {'memory_commit_receipts': True, 'memory_readback_receipts': True}
    return {}


def _target_adapter(artifact, access, request):
    """Select by the real target artifact; never by a CPU/IP pair."""
    from .extension_plugins import target_adapter as _extension_target
    extended=_extension_target(artifact,access,request)
    if extended is not None:return extended
    kind=artifact.runtime_document.get('kind')
    if kind=='apb3_register_observe':
        if artifact.runtime_document.get('storage_observation') is not None:return None
        from ..local_harness.apb3_register_session import GeneratedApb3RegisterSession
        return ('apb',GeneratedApb3RegisterSession,
            bank_contract_facts(artifact,endpoint_id=access['target_endpoint']),observe_mmio_bus)
    if kind=='wishbone_register_observe':
        if artifact.runtime_document.get('storage_observation') is not None:return None
        from .wishbone_mmio_target import observe_wishbone_mmio_bus
        from ..local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
        from ..runtime.adapters.wishbone_mmio import admission_facts
        windows=[row for row in request.wiring.document.get('windows',())
                 if row.get('target_instance')==access['target_component']
                 and row.get('endpoint_id') in (None,access['target_endpoint'])]
        if len(windows)!=1:raise ValueError('Wishbone-MMIO-one-declared-window-required')
        row=windows[0]
        triple=(row.get('template'),'1',row.get('variant_id'))
        preparation=SimpleNamespace(declared_endpoint_template=lambda component,endpoint:triple
            if (component,endpoint)==(access['target_component'],access['target_endpoint']) else None)
        admitted=admission_facts(artifact,preparation=preparation,base_dir=request.base_dir)
        return ('wishbone',GeneratedWishboneRegisterSession,admitted['facts']['semantic'],observe_wishbone_mmio_bus)
    return None


def mmio_support(*,artifacts,compiled_inputs,flow):
    if not isinstance(compiled_inputs,dict) or not isinstance(compiled_inputs.get('compiled'),dict):return None
    paths=[p for p in compiled_inputs['compiled']['paths'] if p['flow_id']==flow and p['status']=='executable']
    if len(paths)!=1:return None
    stream=next(s for s in paths[0]['sources'] if s['kind'] in ('cpu_mmio_stream','cpu_load_stream'))
    access=stream['register_access'];artifact=artifacts[access['target_component']]
    target=_target_adapter(artifact,access,compiled_inputs['request'])
    if target is None:return None
    image=next(s for s in paths[0]['sources'] if s['kind']=='instruction_image')
    try:cpu_adapter=select_mmio_cpu(artifacts[image['component']],image,stream)
    except ValueError as error:
        return dict(status='unsupported',execution_supported=0,runtime_admitted=False,executor='compiled_mmio',
            path_id=paths[0]['path_id'],reason=str(error))
    semantic=target[2]
    regs=[r for r in semantic.document()['registers'] if r['name']==access['register'] and r['offset']==access['register_offset']]
    if len(regs)!=1 or ('w' if flow=='F4' else 'r') not in regs[0]['access']:
        raise ValueError('declared-MMIO-register-access-required')
    return dict(status='supported',execution_supported=1,runtime_admitted=False,
        executor='compiled_mmio',path_id=paths[0]['path_id'],
        support_scope='native_CPU_MMIO_transport_no_internal_storage_version',
        producer_binding=semantic.document(),startup_requires=[])


def observe_mmio_bus(declaration,receipt,*,target_artifact,flow):
    """Join actual CPU Router deliveries to actual APB completion and RAM."""
    from ..local_harness.native_physical_observation import verify_apb_register_trace
    if verify_apb_register_trace(target_artifact) is not True:raise ValueError('native-APB-trace-required')
    access=declaration['candidate']['access'];events=receipt.events
    signals=target_artifact.runtime_document['base_protocol_trace']['signals']
    deliveries=[e for e in events if e.get('kind')=='mmio_delivery' and e.get('component')==access['source_component']
        and e.get('device_id')==access['device_id'] and e.get('address')==access['address']]
    writes=[e for e in deliveries if e.get('write') is True]
    reads=[e for e in deliveries if e.get('write') is False]
    if len(reads)!=1 or len(writes)!=(1 if flow=='F4' else 0):raise ValueError('MMIO-transfer-count')
    if writes and (writes[0]['write_value']!=declaration['candidate']['value'] or writes[0]['event_id']>=reads[0]['event_id']):
        raise ValueError('MMIO-native-write-value-or-order')
    joined=[]
    for delivery in writes+reads:
        accepted=[e for e in events if e.get('kind')=='mmio_acceptance' and e.get('source_transaction')==delivery['source_transaction']
            and e.get('address')==access['address'] and e.get('write')==delivery['write'] and e['event_id']<delivery['event_id']]
        wanted=dict(psel=1,penable=1,pready=1,pwrite=int(delivery['write']),paddr=access['register_offset'],pslverr=0)
        value=delivery['write_value'] if delivery['write'] else delivery['read_value']
        wanted['pwdata' if delivery['write'] else 'prdata']=value
        physical=[e for e in events if e.get('kind')=='local_tick_sample' and e.get('component')==access['target_component']
            and e.get('phase')=='pre' and e.get('producer_event_id')==delivery.get('producer_event_id')
            and all(e.get('outputs',{}).get('backend',{}).get(signals[k])==v for k,v in wanted.items())]
        if len(accepted)!=1 or len(physical)!=1:raise ValueError('MMIO-native-APB-acceptance-join')
        joined.append(dict(native_APB_event=physical[0]['event_id'],acceptance_event=accepted[0]['event_id'],
            delivery_event=delivery['event_id'],source_transaction=delivery['source_transaction'],write=delivery['write'],value=value))
    read_value=reads[0]['read_value'];result=read_value ^ (declaration['xor_constant'] if flow=='F2' else 0)
    ram=[e for e in events if e.get('kind')=='memory_write' and e.get('component')==access['source_component']
        and e.get('address')==declaration['result_address'] and e.get('value')==result and e.get('byte_enable')==15
        and e['event_id']>reads[0]['event_id']]
    if len(ram)!=1:raise ValueError('MMIO-read-return-dependent-RAM')
    return dict(joins=joined,RAM_event=ram[0]['event_id'],read_value=read_value,result_value=result)


@dataclass(frozen=True)
class MmioBinding:
    body:bytes
    @property
    def digest(self):return sha256(self.body).hexdigest()
    def document(self):return json.loads(self.body)


class CompiledMmioRuntime(BuiltProcessAudit):
    """One persistent CPU, RAM, APB target, Runner and ScenarioSession."""
    def __init__(self,*,artifacts,compiled_inputs,base_dir,cache_dir,run_id,
                 rounds_per_case=128,max_cases=16,defer_begin=False,mixed_flows=True,default_flow=None,
                 memory_flows=False,**options):
        if options:raise ValueError('unsupported-MMIO-runtime-options:'+','.join(options))
        if type(memory_flows) is not bool or memory_flows and not mixed_flows:
            raise ValueError('MMIO-memory-flows-require-mixed-runtime')
        if any(type(v) is not int or not 1<=v<=65536 for v in (rounds_per_case,max_cases)):raise ValueError('MMIO-budget-invalid')
        from ..local_harness.cpu_session import GeneratedCve2Session
        from ..scenario.memory import PersistentMemory,MemoryRegion
        from ..scenario.router import DataflowRouter,DeviceWindow
        from ..scenario.runner import ScenarioRunner
        from ..scenario.genome import ScenarioGenome
        from ..scenario.session_runtime import ScenarioSession
        self.artifacts=artifacts;self.inputs=compiled_inputs;self.base_dir=Path(base_dir);self.cache_dir=Path(cache_dir)
        self.run_id=run_id;self.rounds=rounds_per_case;self.max_cases=max_cases
        if default_flow not in (None,'F2','F4'):raise ValueError('MMIO-default-flow')
        self.default_flow=default_flow
        self.records=[];self.finished=False;self._begun=False;self._deferred_begin=defer_begin;self._mixed_flows=mixed_flows
        self._memory_flows=memory_flows
        self._build_audit_sink=None;self._build_audit_previous={};self._terminal_error=None;self.authority=None
        self._identity=_input_identity(compiled_inputs,artifacts)
        self.paths={p['flow_id']:p for p in compiled_inputs['compiled']['paths'] if p['status']=='executable' and p['flow_id'] in ('F2','F4')}
        if not self.paths:raise ValueError('executable-MMIO-path-required')
        self.admissions={};self.layouts={};self.streams={};self.images={}
        for flow,path in self.paths.items():
            support=mmio_support(artifacts=artifacts,compiled_inputs=compiled_inputs,flow=flow)
            if support is None or support['execution_supported']!=1:raise ValueError('protocol-MMIO-only:'+str(support))
            self.admissions[flow]=(admit_compiled_f4_runtime_path if flow=='F4' else admit_compiled_f2_runtime_path)(request=compiled_inputs['request'],compiled=compiled_inputs['compiled'],path=path)
            self.layouts[flow]=(compile_candidate_layout if flow=='F4' else compile_f2_candidate_layout)(path)
            self.streams[flow]=next(s for s in path['sources'] if s['kind'] in ('cpu_mmio_stream','cpu_load_stream'))
            self.images[flow]=next(s for s in path['sources'] if s['kind']=='instruction_image')
        flow=next(iter(self.paths));self.image=self.images[flow];self.stream=self.streams[flow]
        self.cpu_id=self.image['component'];self.target_id=self.stream['register_access']['target_component']
        if any(s['register_access']['target_component']!=self.target_id for s in self.streams.values()):raise ValueError('one-MMIO-target-required')
        request=compiled_inputs['request'];resources=[r for r in request.wiring.resources if r.component_instance==self.cpu_id]
        from ..isa.constraints import f1_isa_from_profile
        instruction_isa=f1_isa_from_profile(artifacts[self.cpu_id].plan.profile) if memory_flows else None
        memory=PersistentMemory(regions=tuple(MemoryRegion(r.resource_id,r.base,r.size,readable=r.read,writable=r.write) for r in resources),
            initialization_seed=0,max_initialized_bytes=sum(r.size for r in resources),
            instruction_isa=instruction_isa if instruction_isa and len(instruction_isa.extensions)>1 else None)
        self.instruction_isa=memory.instruction_isa
        self.start=self.image['range'][0];self.result=(self.image['range'][1]-3)&~3;self.cursor=None;self.first_fetch=None
        target_adapter=_target_adapter(artifacts[self.target_id],self.stream['register_access'],request)
        if target_adapter is None:raise ValueError('MMIO-target-adapter-unsupported')
        self.target_protocol,target_type,_,self._observe_target_bus=target_adapter
        target=target_type(artifacts[self.target_id],base_dir=self.base_dir,cache_dir=self.cache_dir)
        windows=tuple(DeviceWindow(w.device_id,w.base,w.size,target) for w in request.wiring.windows if w.target_instance==self.target_id)
        if len(windows)!=len(request.wiring.windows):raise ValueError('one-MMIO-router-target-required')
        self.cpu_adapter=select_mmio_cpu(artifacts[self.cpu_id],self.image,self.stream,base_dir=self.base_dir)
        cpu_options=(dict(defer_mmio=True,hold_declared_instructions=True) if self.cpu_adapter.protocol=='ahb-lite' else {})
        receipt_options=memory_feedback_options(self.cpu_adapter,memory_flows=memory_flows)
        memory_feedback=bool(receipt_options)
        cpu_options.update(receipt_options)
        cpu=self.cpu_adapter.session_type(artifacts[self.cpu_id],base_dir=self.base_dir,cache_dir=self.cache_dir,memory=memory,router=DataflowRouter(windows),
            **cpu_options)
        self.runner=ScenarioRunner(sessions={self.cpu_id:cpu,self.target_id:target},ownership=compiled_inputs['ownership'],bindings=())
        self.traces=self.cpu_adapter.traces
        self.error_policy=self.cpu_adapter.policy
        self._build_sessions=dict(self.runner.sessions)
        first=next(iter(self.admissions.values())).prepared
        paths=tuple(row for admission in self.admissions.values() for row in admission.prepared.runtime_paths)
        instruction_bindings=tuple(a.instruction_binding for a in self.admissions.values())
        if memory_flows:
            from ..runtime.flows.memory import prepare_memory_paths, install_memory_feedback
            memory_prepared, memory_bindings=prepare_memory_paths(request=request,compiled=compiled_inputs['compiled'])
            if (_semantic_canonical(memory_prepared.graph.edge_document()) != _semantic_canonical(first.graph.edge_document())
                    or _semantic_canonical(memory_prepared.contract.document()) != _semantic_canonical(first.contract.document())):
                raise ValueError('MMIO-memory-shared-graph-mismatch')
            self.memory_bindings={binding.source_id.split('.')[0]:binding for binding in memory_bindings}
            paths += memory_prepared.runtime_paths
            instruction_bindings += tuple(memory_bindings)
            if memory_feedback:
                # The commit authority authenticates a commit by its channel id,
                # so a unified row must declare the channel it really numbers its
                # beats on.  The default (``None``) keeps the split rows' 'data'.
                install_memory_feedback(self.runner,cpu_id=self.cpu_id,
                    runtime_contract_sha256=first.contract.identity_sha256,
                    channel_id=('data' if self.cpu_adapter.channel_model=='split'
                                else 'memory'))
        prepared=PreparedRuntimePathContract(first.graph,first.contract,paths)
        self.runtime_path_admission=SimpleNamespace(prepared=prepared)
        self.execution_binding=MmioBinding(_semantic_canonical(dict(schema_version='compiled_MMIO_binding.v1',
            input_identity=self._identity,prepared=prepared.document(),
            cpu_adapter=dict(protocol=self.cpu_adapter.protocol,instruction_granule=self.cpu_adapter.instruction_granule,traces=self.traces,error_policy=self.error_policy),artifacts={k:v.runtime_document['artifact_digest'] for k,v in artifacts.items()},
            **({'target_protocol':self.target_protocol} if self.target_protocol!='apb' else {}))))
        template=ScenarioGenome(run_id,'CPU_TO_IP',self.admissions[flow].runtime_path_id,tuple(self.runner.sessions),rounds_per_case*max_cases*2,())
        self.session=ScenarioSession(template,self.runner,checker_configuration_only=True)
        self.session.configure_runtime_paths(prepared.graph,prepared.contract,paths,source_ownership=compiled_inputs['ownership'],
            instruction_image_bindings=instruction_bindings)
        self.session.declare_instruction_slots(self.cpu_id,self.start,(self.result-self.start-(4 if memory_flows else 0))//4)
        if not defer_begin:self.begin()

    def _stable(self,*,allow_finished=False):
        if self.finished and not allow_finished:raise ValueError('MMIO-runtime-finished')
        if _input_identity(self.inputs,self.artifacts)!=self._identity:raise ValueError('MMIO-input-drift')
        self.session._runtime_compiled.validate_topology()

    def begin(self):
        for local in self._build_sessions.values():
            local.configure_built_executable_receipt();local.prepare_local()
        self._built_receipts={name:local.validate_built_executable_receipt() for name,local in self._build_sessions.items()}
        # Reuse the existing protocol-neutral pending-fetch bootstrap unchanged.
        return CompiledF2Runtime.begin(self)

    def _accepted_first_fetch(self,events):
        if self.cpu_adapter.protocol=='ahb-lite':events=self.runner._event_refs_since(0)
        return self.cpu_adapter.first_fetch(events,self.cpu_id)

    def online_identity_configuration(self):return self.execution_binding.document()

    def submit(self,raw,flow=None,testcase_id=None):
        from ..scenario.session_runtime import OnlineCase,BoundOnlineInstruction
        from ..scenario.batch import BatchAdvance
        flow=flow or self.default_flow or ('F4' if 'F4' in self.paths else 'F2')
        if flow in ('F1','F3') and self._memory_flows:
            from ..runtime.flows.memory import submit_memory_case
            return submit_memory_case(self,raw,flow=flow,testcase_id=testcase_id)
        if flow not in self.paths or not self._begun:raise ValueError('MMIO-flow-or-lifecycle')
        self._stable()
        if len(self.records)>=self.max_cases:raise ValueError('MMIO-case-budget')
        stream=self.streams[flow];image=self.images[flow]
        if flow=='F4':value=self.layouts[flow].decode(raw)[stream['source_id']]
        else:
            classified=self.layouts[flow].classify(raw)
            if not classified.accepted:raise ValueError('MMIO-F2-candidate:'+str(classified.reason))
            value=classified.address
        index=len(self.records)
        declaration=(declare_writer(self.inputs['request'],self.inputs['compiled'],source_id=stream['source_id'],value=value,result_address=self.result)
            if flow=='F4' else declare_reader(self.inputs['request'],self.inputs['compiled'],source_id=stream['source_id'],address=value,result_address=self.result))
        declaration=self.cpu_adapter.prepare_declaration(declaration,address=self.cursor)
        code=bytes.fromhex(declaration['code_hex']);source=image['source_id']+':'+str(index)
        if self.cursor+len(code)>self.result-(4 if self._memory_flows else 0):raise ValueError('MMIO-instruction-image-exhausted')
        admission=self.admissions[flow];direction= self.paths[flow]['direction']
        case=OnlineCase(f'{self.run_id}:{index}',direction,admission.runtime_path_id,
            BoundOnlineInstruction(source,self.cpu_id,self.cursor,code.hex(),admission.instruction_binding.source_id),
            tuple(BatchAdvance(tuple(self.runner.sessions)) for _ in range(self.rounds)))
        # End the case at this fragment's first unmaterialized fetch slot so
        # the host-caused stall is not charged as a DUT protocol violation.
        from ..runtime.flows.memory import fragment_boundary_park
        stop_after_advance,park_evidence=fragment_boundary_park(
            self.runner.sessions[self.cpu_id],self.cursor+len(code),
            component=self.cpu_id,rounds=self.rounds)
        receipt=self.session.submit_case(case,stop_after_advance=stop_after_advance)
        if receipt.violations or receipt.status!='running':raise ValueError('MMIO-native-protocol-failed')
        observed=self._observe_target_bus(declaration,receipt,target_artifact=self.artifacts[self.target_id],flow=flow)
        events=self.runner._event_refs_since(0);memory=self.runner.sessions[self.cpu_id].memory
        snapshots=[memory.read(self.cursor+offset,4,transaction_id=f'MMIO-proof:{index}:{offset}') for offset in range(0,32,4)]
        common=dict(events=events,declaration=declaration,image=image,stream=stream,traces=self.traces,address=self.cursor,
            source_event_id=source,joins=observed['joins'],instruction_snapshots=snapshots,ram_event_id=observed['RAM_event'],
            error_policy=self.error_policy,proof_scope='native_OBI_APB_MMIO_return_dependent_RAM_no_internal_version')
        if self.cpu_adapter.protocol!='obi' or self.target_protocol!='apb':
            from .native_mmio_hops import check_native_mmio_hops
            kwargs={k:v for k,v in common.items() if k not in ('traces','error_policy','proof_scope')}
            kwargs['result_snapshot']=memory.read(self.result,4,transaction_id=f'MMIO-result:{index}')
            # Two declared scopes reach this seam, and neither is inferred here:
            # a row that has no fetch identity states that as a refusal
            # (``instruction_hop_refusal``), and a row whose adapter *proved*
            # one from its own RTL states it as ``instruction_id_map``.  The
            # same data joins are consumed in both cases; only the instruction
            # chain differs (see integration/native_mmio_data_hops.py).
            refusal=((self.traces or {}).get('instruction_hop_refusal')
                     if isinstance(self.traces,dict) else None)
            id_map=((self.traces or {}).get('instruction_id_map')
                    if isinstance(self.traces,dict) else None)
            if refusal is None and id_map is None:
                exact=check_native_mmio_hops(**kwargs,cpu_adapter=self.cpu_adapter,flow=flow)
            else:
                from .native_mmio_data_hops import check_native_mmio_data_hops
                exact=check_native_mmio_data_hops(**kwargs,cpu_adapter=self.cpu_adapter,flow=flow,
                    refusal=refusal,instruction_id_map=id_map)
        elif flow=='F4':exact=check_f4_exact_hops(**common,declared_edges=_f4_edges(self.inputs['compiled'],image,stream['register_access']),readback_value=observed['read_value'])
        else:exact=check_f2_exact_hops(**common,declared_edges=_f2_edges(self.inputs['compiled'],image,stream['register_access']),
            result_snapshot=memory.read(self.result,4,transaction_id=f'MMIO-result:{index}'))
        if self.cpu_adapter.protocol=='obi' and self.target_protocol=='apb':
            exact['native_protocol']='obi'
            for hop in exact['data_hops']+[exact['ram_write_hop']]:hop['native_cpu']=deepcopy(hop['native_obi'])
        certificate=dict(schema_version='compiled_mmio_case.v1',flow_id=flow,native_cpu_protocol=self.cpu_adapter.protocol,status='observed',case_id=case.case_id,
            path_id=self.paths[flow]['path_id'],source_id=stream['source_id'],instruction_address=self.cursor,
            instruction_sha256=sha256(code).hexdigest(),execution_binding_sha256=self.execution_binding.digest,
            internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False,
            component_semantic_effect='unsupported',**observed,exact_hops=deepcopy(exact),
            instruction_boundary_park=park_evidence(receipt))
        self.records.append(dict(flow=flow,raw=raw.hex(),value=value,certificate=certificate));self.cursor+=len(code)
        return deepcopy(certificate)

    def feedback(self):return dict(cases=len(self.records),certified=0,storage_reward=0)

    def finish(self):
        if not self.finished:
            try:self._stable()
            finally:self.trace=self.session.finish();self.finished=True
        audit=self.execution_audit()
        if any(r['returncode']!=0 for r in audit['exits'].values()):raise ValueError('MMIO-native-exit-failed')
        events=list(self.runner.events_since(0))
        return dict(schema_version='compiled_mmio_prefix.v1',run_id=self.run_id,native_cpu_protocol=self.cpu_adapter.protocol,records=deepcopy(self.records),
            compiled_sha256=sha256(_semantic_canonical(self.inputs['compiled'])).hexdigest(),
            execution_binding=self.execution_binding.document(),execution_binding_sha256=self.execution_binding.digest,
            semantic_hash=normalized_semantic_sha256(self.trace.status,events,self.trace.local_ticks),
            online_plan=json.loads(self.session.encode_plan()),actual_events=events,trace_local_ticks=dict(self.trace.local_ticks),
            original_execution_audit=audit,original_build=self.build_audit_snapshot(closed=True),feedback=self.feedback())

    def replay(self,prefix,*,audit_sink=None):
        from .compiled_f6 import _normalized_f6_prefix,_first_difference
        expected=self.finish()
        if prefix!=expected:raise ValueError('MMIO-original-prefix-mismatch')
        fresh=type(self)(artifacts=self.artifacts,compiled_inputs=self.inputs,base_dir=self.base_dir,cache_dir=self.cache_dir,
            run_id=self.run_id,rounds_per_case=self.rounds,max_cases=self.max_cases,mixed_flows=self._mixed_flows,
            memory_flows=self._memory_flows,default_flow=self.default_flow)
        try:
            for row in self.records:fresh.submit(bytes.fromhex(row['raw']),flow=row['flow'],
                testcase_id=row['certificate'].get('case_id') if row['flow'] in ('F1','F3') else None)
            actual=fresh.finish()
            difference=_first_difference(_normalized_f6_prefix(expected),_normalized_f6_prefix(actual))
            report=dict(matches=difference is None,first_difference=difference,actual_prefix=actual,
                original_execution_audit=self.execution_audit(),execution_audit=fresh.execution_audit(),scope='full_native_MMIO_no_internal_version')
            if audit_sink:audit_sink(deepcopy(report))
            if difference is not None:raise ValueError('MMIO-full-fresh-prefix-mismatch:'+str(difference))
            return report
        finally:
            if not fresh.finished:fresh.finish()
