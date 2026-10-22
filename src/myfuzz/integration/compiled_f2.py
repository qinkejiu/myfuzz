"""Execute the original compiled F2 through native OBI/APB read responses.

Selection and saved identities grant no authority. Each live read resolves its
current IP version from the installed native issuer and proves consumption by a
dependent CPU store into the declared persistent result word.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
from collections.abc import Mapping
from types import MappingProxyType
from hashlib import sha256
from pathlib import Path
import json

from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts, _difference
from myfuzz.local_harness.generated_execution_admission import GeneratedExecutionRefused
from myfuzz.scenario.compiled_paths import compile_paths, compiled_document_sha256
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, BoundOnlineInstruction
from myfuzz.scenario.batch import BatchAdvance
from myfuzz.scenario.source_actions import ip_register_prerequisite
from .compiled_f2_runtime_path import admit_compiled_f2_runtime_path
from .compiled_f2_layout import compile_f2_candidate_layout
from .compiled_f2_consumer import (select_f2_read_producer,build_f2_read_producer,
    capture_f2_read_version,check_f2_read_observation)
from .generated_register_reader import declare_reader
from .compiled_f2_build_join import validate_built_receipts,built_receipt_sha256
from .compiled_f4 import (_digest,_input_identity,_closure,_artifact_execution_identity,
    _cpu_error_policy,_cpu_traces,_native_steps,_semantic_canonical,
    normalized_semantic_sha256,_check_fresh_identities,_capture_build_construction,
    _diagnostic_build_snapshot)
from .native_obi_hops import check_f2_exact_hops


def _layout_document(layout):
    return dict(schema_version='compiled_F2_candidate_layout.v1',digest=layout.digest,
        byte_length=layout.byte_length,source_slices=[asdict(row) for row in layout.source_slices])


def _cpu_policy(artifact,image,stream):
    policy=_cpu_error_policy(artifact,image,stream)
    return dict(policy,schema_version='compiled_F2_cpu_error_policy.v1')


@dataclass(frozen=True,slots=True)
class CompiledF2ExecutionBinding:
    document_json: str

    def __post_init__(self):
        try:
            doc=json.loads(self.document_json)
            valid=(type(self) is CompiledF2ExecutionBinding and type(self.document_json) is str
                and type(doc) is dict and doc.get('schema_version')=='compiled_F2_execution_binding.v1'
                and doc.get('binding_sha256')==_digest({k:v for k,v in doc.items() if k!='binding_sha256'}))
        except (TypeError,ValueError):valid=False
        if not valid:raise ValueError('compiled-F2-execution-binding-required')

    @classmethod
    def build(cls,document):
        if type(document) is not dict:raise ValueError('compiled-F2-execution-binding-required')
        body={k:v for k,v in document.items() if k!='binding_sha256'}
        body['binding_sha256']=_digest(body)
        return cls(json.dumps(body,sort_keys=True,separators=(',',':')))

    def document(self):return json.loads(self.document_json)

    @property
    def digest(self):return self.document()['binding_sha256']


def _f2_edges(compiled,image,access):
    """Resolve the three declared F2 edges with their real CPU/IP roles.

    Both MMIO declarations name the same initiator/device pair, so the route
    leg can only come from the graph's own node ownership: the request leg is
    CPU -> IP and the return leg is IP -> CPU.  A graph that puts both legs on
    the CPU is refused here instead of being relabelled into a CPU -> CPU
    route.
    """
    graph=compiled['runtime_dependency_graph'];contract=compiled['runtime_path_contract']
    if not isinstance(graph,dict) or not isinstance(contract,dict):
        raise ValueError('compiled-F2-runtime-contract-required')
    components={row['node_id']:row['component'] for row in contract['nodes']}
    expected={'F2.read_request':('F2.program_image','persistent_state','read_request'),
              'F2.read_response':('F2.read_request','mmio_route','read_request'),
              'F2.data_read_consumed':('F2.read_response','mmio_route','read_return')}
    rules=[row for row in graph['rules'] if row['target'].startswith('F2.')]
    if len(rules)!=3 or {row['target'] for row in rules}!=set(expected):
        raise ValueError('compiled-F2-declared-edge-shape-unsupported')
    cpu=access['source_component'];device=access['target_component']
    node_components={
        'F2.program_image':image['component'],'F2.read_request':cpu,
        'F2.read_response':device,'F2.data_read_consumed':cpu}
    if image['component']!=cpu or device==cpu or access['device_id']!=device:
        raise ValueError('compiled-F2-CPU-to-CPU-route-unsupported')
    for node,component in node_components.items():
        actual=components.get(node)
        if actual is None:
            raise ValueError('compiled-F2-declared-node-mismatch')
        if actual!=component:
            if node in ('F2.read_request','F2.read_response','F2.data_read_consumed'):
                raise ValueError('compiled-F2-CPU-to-CPU-route-unsupported')
            raise ValueError('compiled-F2-declared-node-mismatch')
    edges=[]
    for rule in sorted(rules,key=lambda row:row['rule_index']):
        prerequisite,relation,role=expected[rule['target']]
        rows=[row for row in contract['edges'] if row['rule_index']==rule['rule_index']]
        if rule['prerequisites']!=[prerequisite] or len(rows)!=1:
            raise ValueError('compiled-F2-declared-edge-shape-unsupported')
        edge=rows[0]
        if edge['prerequisite_index']!=0 or edge['relation']!=relation:
            raise ValueError('compiled-F2-declared-edge-shape-unsupported')
        if relation=='persistent_state':
            if (edge['resource_component'],edge['resource_id'])!=(image['component'],image['port']):
                raise ValueError('compiled-F2-declared-resource-mismatch')
        elif (edge['initiator_component'],edge['device_id'],edge['base'],edge['size'])!=(
                cpu,device,access['window_base'],access['window_size']):
            raise ValueError('compiled-F2-declared-route-mismatch')
        edges.append(dict(edge,prerequisite=prerequisite,target=rule['target'],role=role,
            source_component=node_components[prerequisite],
            target_component=node_components[rule['target']]))
    if ([row['role'] for row in edges]!=
            ['read_request','read_request','read_return']):
        raise ValueError('compiled-F2-declared-role-mismatch')
    return edges


def _admit_f2(*,artifacts,compiled_inputs,base_dir=None):
    if type(compiled_inputs) is not dict or set(compiled_inputs)!={'request','compiled','ownership','physical_port_map'}:
        raise GeneratedExecutionRefused('compiled-runtime-input-required','/compiled_inputs')
    admission=admit_compiled_artifacts(artifacts=artifacts,**compiled_inputs)
    if admission['status']!='compatible':
        raise GeneratedExecutionRefused('compiled-runtime-input-refused','/compiled_inputs',admission)
    request=compiled_inputs['request'];compiled=compiled_inputs['compiled'];wiring=request.wiring
    if (type(wiring.fixed_inputs) is not tuple or not isinstance(wiring.document,Mapping)
            or type(wiring.document.get('fixed_inputs',[])) is not list
            or wiring.fixed_inputs or wiring.document.get('fixed_inputs')):
        raise ValueError('compiled-F2-composition-fixed-input-unsupported')
    runtime=admit_compiled_f2_runtime_path(request=request,compiled=compiled)
    # Validate the in-memory typed row, not its JSON round-trip: declared
    # constraint parameters are typed tuples that the document form widens to
    # lists.  The canonical admission above already proves the JSON forms agree.
    rows=[row for row in compiled['paths'] if row['flow_id']=='F2' and row['status']=='executable']
    if len(rows)!=1:raise ValueError('compiled-F2-executable-required')
    path=deepcopy(rows[0]);compile_f2_candidate_layout(path)
    image=next(s for s in path['sources'] if s['kind']=='instruction_image')
    stream=next(s for s in path['sources'] if s['kind']=='cpu_load_stream');access=stream['register_access']
    _f2_edges(compiled,image,access)
    cpu=request.cpu
    if (image['component']!=cpu.instance_id or access['source_component']!=cpu.instance_id
            or len(request.devices)!=1 or request.devices[0].instance_id!=access['target_component']
            or set(artifacts)!={cpu.instance_id,access['target_component']}):
        raise ValueError('compiled-F2-topology-unsupported')
    if cpu.profile.cpu.xlen!=32 or 'I' not in {e.upper() for e in cpu.profile.cpu.extensions}:
        raise ValueError('compiled-F2-RV32I-required')
    if artifacts[cpu.instance_id].runtime_document['kind']!='obi_cpu':
        raise ValueError('compiled-F2-CPU-protocol-unsupported')
    _cpu_policy(artifacts[cpu.instance_id],image,stream);_cpu_traces(artifacts[cpu.instance_id],image,stream)
    if (path['seed'] is not None or path['termination_observation']['kind']!='consumption'
            or sorted(a['expectation_id'] for a in path['assertions'])!=sorted([
                'protocol_checker.receipt_violations','cross_component.declared_edge_hops'])
            or len(path['bound_inputs'])!=1 or path['bound_inputs'][0]['kind']!='ip_read_response'):
        raise ValueError('compiled-F2-checker-or-source-unsupported')
    for rule in path['constraints']['rules']:
        parameters=dict(rule.get('parameters',[]))
        if (rule['primitive']!='reachable_window' or rule['phase']!='runtime'
                or rule['category']!='environment_hard' or rule['owner']!='cpu'
                or rule['checker']!='soc_structure_audit.controller_mmio'
                or parameters!={'base':access['window_base'],'size':access['window_size'],
                    'request_sources':(access['device_id'],),'bus_owner':'cpu'}
                or rule['fields'] or rule['read_set'] or rule['write_set']
                or rule.get('raw_bits') or rule.get('applies_in_modes')
                or rule['state_bits']!=0 or rule['budget']!=1
                or rule['failure_class']!='constraint_conflict' or rule['basis']!='soc_plan.address_map.windows'):
            raise ValueError('compiled-F2-constraint-rule-unsupported')
    if wiring.deliveries or any(o['kind']=='bound' for o in compiled_inputs['ownership'].document()['owners']):
        raise ValueError('compiled-F2-physical-binding-unsupported')
    resources=[r for r in wiring.resources if r.component_instance==cpu.instance_id]
    result=image['range'][1]-3
    if (any(r.base is None or r.size is None or r.read is None or r.write is None
            or r.initialization_policy!='preload' for r in resources)
            or not any(r.resource_id==image['port'] and r.read is True and r.write is True
                and r.base<=result and result+4<=r.base+r.size for r in resources)
            or any(w.target_instance!=access['target_component'] for w in wiring.windows)):
        raise ValueError('compiled-F2-memory-or-router-unsupported')
    declare_reader(request,compiled,source_id=stream['source_id'],address=access['address'],result_address=result)
    return deepcopy(path),select_f2_read_producer(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)


def admit_f2(*,artifacts,compiled_inputs,base_dir=None):
    return _admit_f2(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)[0]


def _private_admission_snapshot(artifacts,inputs,base_dir):
    issued=_input_identity(inputs,artifacts);memo={};visited=set()
    def proxies(value):
        if id(value) in visited:return
        visited.add(id(value))
        if isinstance(value,Mapping):
            for key,item in value.items():proxies(key);proxies(item)
            if isinstance(value,MappingProxyType):memo[id(value)]=MappingProxyType(deepcopy(dict(value),memo))
        elif is_dataclass(value) and not isinstance(value,type):
            for field in fields(value):proxies(getattr(value,field.name))
        elif isinstance(value,(list,tuple,set,frozenset)):
            for item in value:proxies(item)
    proxies(artifacts);proxies(inputs)
    private_artifacts=deepcopy(dict(artifacts),memo);private_inputs=deepcopy(inputs,memo)
    if _input_identity(private_inputs,private_artifacts)!=issued:raise ValueError('compiled-F2-private-reconstruction-mismatch')
    _admit_f2(artifacts=private_artifacts,compiled_inputs=private_inputs,base_dir=base_dir)
    return private_artifacts,private_inputs


def _execution_binding_document(*,artifacts,compiled_inputs,path,layout,producer_binding,base_dir,
        source_closure=None,built_receipts=None,runtime_path_admission=None):
    request=compiled_inputs['request'];cpu=request.cpu.instance_id
    image=next(s for s in path['sources'] if s['kind']=='instruction_image')
    stream=next(s for s in path['sources'] if s['kind']=='cpu_load_stream');access=stream['register_access']
    admission=runtime_path_admission or admit_compiled_f2_runtime_path(request=request,compiled=compiled_inputs['compiled'],path=path)
    admission.validate_cached_identity();producer=producer_binding.document();target=access['target_component']
    traces=_cpu_traces(artifacts[cpu],image,stream);policy=_cpu_policy(artifacts[cpu],image,stream)
    body=dict(schema_version='compiled_F2_execution_binding.v1',path_id=path['path_id'],
        runtime_path_id=admission.runtime_path_id,runtime_contract_sha256=admission.prepared.contract.identity_sha256,
        runtime_path_admission=admission.document(),runtime_path_admission_sha256=admission.digest,
        selected_path_sha256=_digest(path),compiled_document_sha256=compiled_document_sha256(compiled_inputs['compiled']),
        request_sha256=_digest(request.document),artifact_identities={n:_artifact_execution_identity(a) for n,a in sorted(artifacts.items())},
        cpu=dict(instance_id=cpu,profile_fingerprint=artifacts[cpu].plan.profile.profile_fingerprint,
            xlen=request.cpu.profile.cpu.xlen,extensions=list(request.cpu.profile.cpu.extensions),
            runtime_kind=artifacts[cpu].runtime_document['kind'],error_policy=policy,trace_contract=traces,trace_contract_sha256=_digest(traces)),
        candidate_layout=_layout_document(layout),
        target=dict(component=target,artifact_kind=producer['target_artifact_kind'],endpoint_id=access['target_endpoint'],
            protocol=producer['protocol'],template=producer['template'],
            window=dict(device_id=access['device_id'],target_instance=target,base=access['window_base'],size=access['window_size'],
                register_address=access['address'],register_offset=access['register_offset']),
            source_contract_id=producer['source'].get('contract_id'),source_contract_digest=producer['source'].get('contract_digest'),
            producer_binding_sha256=producer_binding.digest),producer_binding=producer,
        prerequisites=deepcopy(path['prerequisites']),prerequisites_sha256=_digest(path['prerequisites']),
        assertions=deepcopy(path['assertions']),assertions_sha256=_digest(path['assertions']),
        ownership_sha256=_digest(compiled_inputs['ownership'].document()),
        physical_port_map_sha256=_digest(sorted((list(k),v) for k,v in compiled_inputs['physical_port_map'].items())),
        executor_source_closure_sha256=_digest(_closure(base_dir) if source_closure is None else source_closure))
    if built_receipts is not None:
        validate_built_receipts(artifacts,built_receipts)
        body.update(built_executable_receipts=deepcopy(built_receipts),built_executable_receipts_sha256=built_receipt_sha256(built_receipts))
    return body


def derive_f2_execution_binding(*,artifacts,compiled_inputs,base_dir=None):
    path,producer=_admit_f2(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)
    return CompiledF2ExecutionBinding.build(_execution_binding_document(artifacts=artifacts,compiled_inputs=compiled_inputs,
        path=path,layout=compile_f2_candidate_layout(path),producer_binding=producer,base_dir=base_dir))


class CompiledF2Runtime:
    """One continuous F2 testcase with live pre-read versions and fresh replay.

    The candidate supplies only the declared load address.  The IP read
    response, the current IP register version and the dependent RAM store are
    observed natively; a read response is never relabelled as a RAM byte
    version and the two route legs keep their own CPU/IP endpoints.
    """
    @host_source_discovery_scope()
    @_capture_build_construction
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f2', rounds_per_case=128, max_cases=64,
                 expected_built_receipts=None, build_audit_sink=None):
        self.path=admit_f2(artifacts=artifacts,compiled_inputs=compiled_inputs,
            base_dir=Path(base_dir))
        self.layout=compile_f2_candidate_layout(self.path)
        self._replay_identities=[]
        if any(type(v) is not int or not 1<=v<=65536 for v in (rounds_per_case,max_cases)):
            raise ValueError('compiled-F2-budget-invalid')
        self._caller_inputs=compiled_inputs;self._caller_artifacts=artifacts
        self._input_digest=_input_identity(compiled_inputs,artifacts)
        self.artifacts,self.inputs=_private_admission_snapshot(artifacts,compiled_inputs,
            Path(base_dir))
        compiled_inputs=self.inputs;artifacts=self.artifacts
        self.base_dir=Path(base_dir);self.cache_dir=Path(cache_dir);self.run_id=run_id
        self.runtime_path_admission=admit_compiled_f2_runtime_path(
            request=compiled_inputs['request'],compiled=compiled_inputs['compiled'],
            path=self.path)
        self.producer_binding=select_f2_read_producer(artifacts=artifacts,
            compiled_inputs=compiled_inputs,base_dir=self.base_dir)
        self.row=self.producer_binding.row
        self.register_name=self.producer_binding.document()['register']['name']
        self.rounds=rounds_per_case;self.max_cases=max_cases
        self.records=[];self.finished=False
        self.closure=_closure(base_dir)
        self.compiled_digest=compiled_document_sha256(compiled_inputs['compiled'])
        request=compiled_inputs['request'];self.cpu_id=request.cpu.instance_id
        self.stream=next(s for s in self.path['sources'] if s['kind']=='cpu_load_stream')
        self.access=self.stream['register_access'];self.target_id=self.access['target_component']
        self.image=next(s for s in self.path['sources'] if s['kind']=='instruction_image')
        self.declared_edges=_f2_edges(compiled_inputs['compiled'],self.image,self.access)
        self.error_policy=_cpu_policy(artifacts[self.cpu_id],self.image,self.stream)
        self.traces=_cpu_traces(artifacts[self.cpu_id],self.image,self.stream)
        self.start=self.image['range'][0]
        self.cursor=None;self.first_fetch=None
        self.end=self.image['range'][1]+1
        self.result=self.end-4
        resources=[r for r in request.wiring.resources if r.component_instance==self.cpu_id]
        if (any(r.base is None or r.size is None or r.read is None or r.write is None
                for r in resources)
                or any(r.initialization_policy!='preload' for r in resources)):
            raise ValueError('compiled-F2-memory-resource-unsupported')
        if not any(r.resource_id==self.image['port'] and r.read is True and r.write is True
                   and r.base<=self.result and self.result+4<=r.base+r.size
                   for r in resources):
            raise ValueError('compiled-F2-writable-image-result-resource-required')
        memory=PersistentMemory(regions=tuple(MemoryRegion(r.resource_id,r.base,r.size,
            readable=r.read,writable=r.write) for r in resources),initialization_seed=0,
            max_initialized_bytes=sum(r.size for r in resources))
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        target,self.authority=build_f2_read_producer(self.producer_binding,
            artifact=self.artifacts[self.target_id],base_dir=self.base_dir,
            cache_dir=self.cache_dir,max_cases=max_cases)
        windows=tuple(DeviceWindow(w.device_id,w.base,w.size,target)
            for w in request.wiring.windows)
        if any(w.target_instance!=self.target_id for w in request.wiring.windows):
            raise ValueError('compiled-F2-router-target-unsupported')
        cpu=GeneratedCve2Session(artifacts[self.cpu_id],base_dir=self.base_dir,
            cache_dir=self.cache_dir,memory=memory,router=DataflowRouter(windows),
            defer_mmio=True)
        self.runner=ScenarioRunner(sessions={self.cpu_id:cpu,self.target_id:target},
            ownership=compiled_inputs['ownership'],bindings=())
        self._build_sessions=dict(self.runner.sessions)
        for name,local in sorted(self._build_sessions.items()):
            local.configure_built_executable_receipt()
            local.prepare_local()
        self._built_receipts={name:local.validate_built_executable_receipt()
            for name,local in sorted(self._build_sessions.items())}
        validate_built_receipts(self.artifacts,self._built_receipts)
        if (expected_built_receipts is not None
                and _semantic_canonical(expected_built_receipts)!=
                    _semantic_canonical(self._built_receipts)):
            raise ValueError('compiled-F2-built-receipt-identity-mismatch')
        self.execution_binding=CompiledF2ExecutionBinding.build(
            _execution_binding_document(artifacts=artifacts,compiled_inputs=compiled_inputs,
                path=self.path,layout=self.layout,producer_binding=self.producer_binding,
                base_dir=self.base_dir,source_closure=self.closure,
                built_receipts=self._built_receipts,
                runtime_path_admission=self.runtime_path_admission))
        template=ScenarioGenome(run_id,'CPU_TO_IP',
            self.runtime_path_admission.runtime_path_id,tuple(self.runner.sessions),
            rounds_per_case*max_cases*2,())
        self._pending=None;self._checked=None
        self.session=ScenarioSession(template,self.runner,checker=self._check_receipt,
            checker_configuration_only=True)
        self.session.declare_instruction_slots(self.cpu_id,self.start,
            (self.result-self.start)//4)
        prepared=self.runtime_path_admission.prepared
        self.session.configure_runtime_paths(prepared.graph,prepared.contract,
            prepared.runtime_paths,source_ownership=compiled_inputs['ownership'],
            instruction_image_bindings=(self.runtime_path_admission.instruction_binding,))
        try:
            self._stable()
            self.session.begin()
            self._native_processes={name:session.process
                for name,session in self.runner.sessions.items()}
            self._process_identities=self._validated_build_process_identities()
            startup_build=_diagnostic_build_snapshot(self)
            if build_audit_sink is not None:
                build_audit_sink(startup_build)
            # The IP's normal idle step with empty inputs establishes the
            # current source-verified storage state and startup handoff.
            self.session.advance_initial((self.target_id,))
            # Stall the native first fetch before materializing candidate bytes.
            for _ in range(self.rounds):
                self._stable()
                bootstrap=self.session.advance_initial((self.cpu_id,))
                steps=list(_native_steps(bootstrap.events,self.cpu_id))
                signals=self.traces['instr']
                accepted=[(event,taps) for event,taps in steps
                    if taps.get(signals['req'])==1 and taps.get(signals['gnt'])==1]
                if accepted:
                    event,taps=accepted[0];self.cursor=taps[signals['addr']]
                    self.first_fetch=dict(address=self.cursor,event_id=event['event_id'])
                    break
            if (self.cursor is None or self.cursor%4
                    or not self.start<=self.cursor<self.result):
                raise ValueError('compiled-F2-first-fetch-outside-image')
        except BaseException as error:
            if self.session._begun and not self.session._finished:
                try:self.session.finish()
                except BaseException as cleanup:
                    error.add_note('compiled-F2 session cleanup: '+repr(cleanup))
            raise

    def online_identity_configuration(self):
        return dict(schema_version='compiled_F2_checker.v1',path_id=self.path['path_id'],
            compiled_sha256=self.compiled_digest,assertions=self.path['assertions'],
            candidate_layout=_layout_document(self.layout),
            cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            producer_row=self.producer_binding.row,
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest)

    def _check_receipt(self,receipt):
        if receipt.violations:
            self._checked=None
            return tuple(receipt.violations)
        if self._pending is None:
            return tuple(receipt.violations)
        declaration,before,prior=self._pending
        try:
            # The post-read token is issued only after the command receipt, the
            # same ordering F4's storage consumer uses: a new APB command clears
            # earlier tokens, so a pre-command token could never be consumed.
            token=self.authority.issue(register=self.register_name,
                reset_epoch=before.document()['reset_epoch'])
            observed,after=check_f2_read_observation(declaration,receipt,
                target_artifact=self.artifacts[self.target_id],authority=self.authority,
                token=token,before=before,register=self.register_name,
                reset_epoch=before.document()['reset_epoch'],prior_writes=prior)
            memory=self.runner.sessions[self.cpu_id].memory
            instruction_snapshots=[memory.read(self.cursor+offset,4,
                transaction_id=f'compiled-F2-check:{len(self.records)}:{offset}')
                for offset in range(0,32,4)]
            result_snapshot=memory.read(self.result,4,
                transaction_id=f'compiled-F2-check-result:{len(self.records)}')
            exact=check_f2_exact_hops(events=self.runner.events_since(0),
                declaration=declaration,image=self.image,stream=self.stream,
                traces=self.traces,address=self.cursor,
                source_event_id=self.image['source_id']+f':{len(self.records)}',
                joins=observed['joins'],declared_edges=self.declared_edges,
                instruction_snapshots=instruction_snapshots,
                ram_event_id=observed['RAM_event'],error_policy=self.error_policy,
                proof_scope=('selected_F2_image_consumption_native_OBI_route_native_APB_'
                    f'live_{self.register_name}_dependent_result_RAM'),
                result_snapshot=result_snapshot)
            self._checked=(observed,after,exact)
            return tuple(receipt.violations)
        except ValueError as error:
            self._checked=None
            return (str(error),)

    def _stable(self,*,allow_finished=False):
        if self.finished and not allow_finished:
            raise ValueError('compiled-F2-runtime-finished')
        if (_input_identity(self._caller_inputs,self._caller_artifacts)!=self._input_digest
                or _input_identity(self.inputs,self.artifacts)!=self._input_digest):
            raise ValueError('compiled-F2-input-identity-changed')
        if _cpu_policy(self.artifacts[self.cpu_id],self.image,self.stream)!=self.error_policy:
            raise ValueError('compiled-F2-error-policy-identity-changed')
        if compile_f2_candidate_layout(self.path)!=self.layout:
            raise ValueError('compiled-F2-layout-identity-changed')
        path,producer=_admit_f2(artifacts=self.artifacts,compiled_inputs=self.inputs,
            base_dir=self.base_dir)
        if path!=self.path:
            raise ValueError('compiled-F2-admission-changed')
        # Producer bindings are sealed by identity in their selecting object,
        # so the stable comparison is their complete canonical document.
        if (type(producer) is not type(self.producer_binding)
                or producer.document_json!=self.producer_binding.document_json):
            raise ValueError('compiled-F2-producer-binding-changed')
        admission=getattr(self,'runtime_path_admission',None)
        if admission is None:
            raise ValueError('compiled-F2-runtime-path-admission-removed')
        admission.validate_cached_identity()
        if (self.session.runtime_contract!=admission.prepared.contract
                or self.session.runtime_path_document['declaration']!=
                    admission.prepared.document()
                or self.session.instruction_image_binding_documents!=
                    (admission.instruction_binding.document(),)):
            raise ValueError('compiled-F2-runtime-path-session-changed')
        current_closure=_closure(self.base_dir)
        if (current_closure!=self.closure
                or compiled_document_sha256(self.inputs['compiled'])!=self.compiled_digest
                or _difference(compile_paths(self.inputs['request']),
                    self.inputs['compiled']) is not None):
            raise ValueError('compiled-F2-source-identity-changed')
        current_body=_execution_binding_document(artifacts=self.artifacts,
            compiled_inputs=self.inputs,path=path,
            layout=compile_f2_candidate_layout(path),
            producer_binding=producer,base_dir=self.base_dir,
            source_closure=current_closure,runtime_path_admission=admission,
            built_receipts=self._validated_built_receipts())
        current=CompiledF2ExecutionBinding.build(current_body)
        if current.document_json!=self.execution_binding.document_json:
            raise ValueError('compiled-F2-execution-binding-changed')

    def _decode_candidate(self,raw):
        issued=compile_f2_candidate_layout(self.path)
        if self.layout!=issued:
            raise ValueError('compiled-F2-layout-identity-changed')
        if type(raw) is not bytes or len(raw)!=self.layout.byte_length:
            raise ValueError('compiled-F2-candidate-record-length')
        selection=self.layout.classify(raw)
        if not selection.accepted:
            raise ValueError('compiled-F2-candidate-'+str(selection.reason))
        return selection.address

    def _validated_built_receipts(self):
        receipts={name:local.validate_built_executable_receipt()
            for name,local in sorted(self._build_sessions.items())}
        validate_built_receipts(self.artifacts,receipts)
        if _semantic_canonical(receipts)!=_semantic_canonical(self._built_receipts):
            raise ValueError('compiled-F2-built-receipt-identity-changed')
        return receipts

    def _validated_build_process_identities(self):
        receipts=self._validated_built_receipts()
        identities={}
        for name,local in self._build_sessions.items():
            launches=local.built_executable_launch_observations()
            if len(launches)!=1:
                raise ValueError('compiled-F2-built-process-launch-missing')
            row=launches[0];receipt=receipts[name]
            expected=dict(artifact_digest=receipt['artifact_digest'],
                build_digest=receipt['build_digest'],binary_sha256=receipt['binary_sha256'],
                built_receipt_sha256=built_receipt_sha256(receipt),
                observed_executable_sha256=receipt['binary_sha256'],
                ready_artifact_digest=receipt['artifact_digest'])
            process=self._native_processes[name]
            if (any(row.get(key)!=value for key,value in expected.items())
                    or row.get('pid')!=process.pid
                    or row.get('execution_nonce')!=local._execution):
                raise ValueError('compiled-F2-built-process-identity-mismatch')
            identities[name]=dict(component=name,
                role='cpu' if name==self.cpu_id else 'bound_target',
                pid=row['pid'],execution_nonce=row['execution_nonce'],**expected)
        return identities

    def build_audit_snapshot(self,*,closed=None):
        previous=deepcopy(getattr(self,'_build_audit_previous',{}))
        receipts=previous.get('receipts',{})
        observations=previous.get('preparation_observations',{})
        audit=previous.get('execution_audit',{})
        identities=audit.get('identities',{})
        exits=audit.get('exits',{})
        failures=previous.get('unavailable',{})
        for name,local in self._build_sessions.items():
            def unavailable(label,error):
                failures.setdefault(name,{})[label]=dict(
                    error_type=type(error).__name__,error=str(error))
            for target,label,accessor in (
                    (receipts,'receipt','built_executable_receipt_document'),
                    (observations,'preparation','build_preparation_observation_document')):
                try:target[name]=getattr(local,accessor)()
                except BaseException as error:unavailable(label,error)
            try:launches=local.built_executable_launch_observations()
            except BaseException as error:
                unavailable('launches',error)
                try:launches=local._built_executable_launch_diagnostics()
                except BaseException as diagnostic_error:
                    unavailable('launch_diagnostics',diagnostic_error)
                    launches=()
            try:
                if launches:
                    row=launches[-1]
                    identities[name]=dict(row,component=name,
                        role='cpu' if name==getattr(self,'cpu_id',None) else 'bound_target')
                    exits[name]=dict(returncode=row.get('returncode'),
                        reaped=row.get('reaped',False))
            except BaseException as error:
                unavailable('launch_document',error)
        snapshot=dict(receipts=receipts,preparation_observations=observations,
            execution_audit=dict(identities=identities,exits=exits,
                closed=bool(getattr(self,'finished',False) if closed is None else closed)),
            unavailable=failures)
        self._build_audit_previous=deepcopy(snapshot)
        return deepcopy(snapshot)

    def execution_audit(self):
        identities=self._validated_build_process_identities()
        if identities!=self._process_identities:
            raise ValueError('compiled-F2-built-process-identity-changed')
        codes={name:proc.poll() for name,proc in self._native_processes.items()}
        return dict(schema_version='compiled_F2_execution_audit.v1',
            identities=deepcopy(self._process_identities),
            exits={name:dict(returncode=code,reaped=code is not None)
                for name,code in codes.items()},closed=self.finished)

    @host_source_discovery_scope()
    def submit(self,raw):
        """Submit one declared load address; the IP response stays bound."""
        self._stable()
        address=self._decode_candidate(raw)
        if len(self.records)>=self.max_cases:
            raise ValueError('compiled-F2-case-budget-exhausted')
        declaration=declare_reader(self.inputs['request'],self.inputs['compiled'],
            source_id=self.stream['source_id'],address=address,result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        if self.cursor+len(code)>self.result:
            raise ValueError('compiled-F2-slot-exhausted')
        target=self.runner.sessions[self.target_id]
        before=capture_f2_read_version(self.authority,register=self.register_name,
            reset_epoch=target.reset_epoch)
        pre=before.document();prior=pre['write_count']
        index=len(self.records);case_id=f'{self.run_id}:{index}'
        case=OnlineCase(case_id,'CPU_TO_IP',
            self.runtime_path_admission.runtime_path_id,
            BoundOnlineInstruction(self.image['source_id']+f':{index}',self.cpu_id,
                self.cursor,code.hex(),
                self.runtime_path_admission.instruction_binding.source_id),
            tuple(BatchAdvance(tuple(self.runner.sessions)) for _ in range(self.rounds)))
        self._stable()
        self._pending=(declaration,before,prior);self._checked=None
        receipt=self.session.submit_case(case)
        self._pending=None
        if receipt.violations or self._checked is None or receipt.status!='running':
            raise ValueError('compiled-F2-protocol-checker-failed:'+
                str(receipt.violations))
        observed,after,exact=self._checked
        data_hop=exact['data_hops'][0]
        prerequisite=ip_register_prerequisite(self.target_id,self.register_name,
            pre['reset_epoch'],data_hop['native_APB_event'],
            pre['field_version']).document()
        # Project the live witnesses onto their stable version facts.  PID,
        # execution nonce and build identity are validated against the live
        # token but cannot enter a fresh-prefix comparison; the raw witnesses
        # remain in the recorded events.
        from .generated_storage_consumer import stable_storage_version
        certificate=dict(schema_version='compiled_F2_chain.v1',status='certified',
            path_id=self.path['path_id'],source_id=self.stream['source_id'],
            case_id=case_id,instruction_source_id=self.image['source_id'],
            instruction_address=self.cursor,instruction_sha256=sha256(code).hexdigest(),
            prerequisite=prerequisite,
            postcondition=stable_storage_version(after),
            version_before=stable_storage_version(observed['version_before']),
            version_witness=stable_storage_version(observed['version_witness']),
            joins=observed['joins'],
            first_fetch=self.first_fetch,exact_hops=exact,
            assertions=[
                dict(expectation_id='protocol_checker.receipt_violations',
                    status='passed',evidence=dict(violations=list(receipt.violations))),
                dict(expectation_id='cross_component.declared_edge_hops',
                    status='passed',evidence=dict(
                        edge_ids=[[edge['rule_index'],edge['prerequisite_index']]
                            for edge in exact['edges']],
                        roles=[edge['role'] for edge in exact['edges']],
                        endpoints=[[edge['source_component'],edge['target_component']]
                            for edge in exact['edges']],
                        transaction=deepcopy(data_hop['source_transaction']),
                        instruction_source_id=self.image['source_id'],
                        native_read_APB_event=data_hop['native_APB_event'],
                        native_read_OBI_events=[data_hop['native_acceptance_event'],
                            data_hop['native_response_event']],
                        dependent_RAM_write_event=
                            exact['ram_write_hop']['memory_write_event']))],
            execution_binding_sha256=self.execution_binding.digest,
            runtime_path_id=self.runtime_path_admission.runtime_path_id,
            runtime_path_admission_sha256=self.runtime_path_admission.digest,
            runtime_admitted=True)
        self.records.append(dict(raw=raw.hex(),value=address,
            source_values={self.stream['source_id']:address},
            certificate=certificate))
        self.cursor+=len(code)
        return deepcopy(certificate)

    def feedback(self):
        return dict(cases=len(self.records),certified=len(self.records),
            distinct_addresses=len({record['value'] for record in self.records}),
            dependent_result_stores=len(self.records),
            register_versions=len({record['certificate']['version_before']['field_version']
                for record in self.records}))

    def assertion_results(self):
        """Typed expectation rows over this runtime's own observed evidence."""
        from myfuzz.scenario.compiled_assertion_results import build_assertion_results
        from myfuzz.scenario.compiled_assertion_results import _json
        path=self.execution_binding.document()['runtime_path_admission']['selected_path']
        path_sha256=sha256(_json(path).encode()).hexdigest()
        identity=dict(compiled_document_sha256=self.compiled_digest,
            binding_sha256=self.execution_binding.digest,path_sha256=path_sha256,
            run_id=self.run_id)
        cases=[]
        for record in self.records:
            certificate=record['certificate'];case_id=certificate['case_id']
            inventory={};observations={}
            for assertion in certificate['assertions']:
                expectation=assertion['expectation_id']
                ref=f'{case_id}:{expectation}'
                inventory[ref]=dict(kind=expectation,outcome=assertion['status'],
                    scope={**identity,'case_id':case_id,'expectation_id':expectation},
                    details=deepcopy(assertion['evidence']))
                observations[expectation]=dict(status=assertion['status'],
                    reason='exact native observation available',
                    evidence_refs=[ref])
            cases.append(dict(case_id=case_id,observations=observations,
                evidence_inventory=inventory))
        return build_assertion_results(
            compiled_document_sha256=self.compiled_digest,
            binding_sha256=self.execution_binding.digest,path=path,
            run_id=self.run_id,cases=cases)

    @host_source_discovery_scope()
    def finish(self):
        if not self.finished:
            try:self._stable()
            finally:
                self.trace=self.session.finish();self.finished=True
        self._stable(allow_finished=True)
        if any(row['returncode']!=0 for row in self.execution_audit()['exits'].values()):
            raise ValueError('compiled-F2-native-exit-failed')
        semantic_hash=normalized_semantic_sha256(self.trace.status,
            self.trace.events,self.trace.local_ticks)
        return dict(schema_version='compiled_F2_prefix.v1',run_id=self.run_id,
            compiled_sha256=self.compiled_digest,source_files=self.closure,
            artifact_digests={n:a.runtime_document['artifact_digest']
                for n,a in self.artifacts.items()},
            rounds_per_case=self.rounds,max_cases=self.max_cases,
            records=deepcopy(self.records),
            candidate_layout=_layout_document(self.layout),
            cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest,
            runtime_path_admission=
                self.execution_binding.document().get('runtime_path_admission'),
            assertions=self.assertion_results(),
            online_plan=json.loads(self.session.encode_plan()),
            semantic_hash=semantic_hash,feedback=self.feedback())

    @host_source_discovery_scope()
    def replay(self,plan,*,audit_sink=None):
        """Reexecute every candidate, resolving live prerequisites anew."""
        self._stable(allow_finished=True)
        expected=self.finish()
        if _difference(expected,plan) is not None:
            raise ValueError('compiled-F2-prefix-mismatch')
        envelope=dict(scope='full_fresh_prefix_real_RTL_and_live_read_versions',
            original_execution_audit=self.execution_audit(),
            original_build=_diagnostic_build_snapshot(self))
        try:
            fresh=type(self)(artifacts=self.artifacts,compiled_inputs=self.inputs,
                base_dir=self.base_dir,cache_dir=self.cache_dir,run_id=self.run_id,
                rounds_per_case=self.rounds,max_cases=self.max_cases,
                expected_built_receipts=self._built_receipts,
                build_audit_sink=lambda snapshot:envelope.update(fresh_build=snapshot))
        except BaseException as error:
            envelope.update(error_type=type(error).__name__,error=str(error),
                startup_partial_trace_available=False)
            if audit_sink is not None:
                try:audit_sink(deepcopy(envelope))
                except BaseException as export_error:
                    error.add_note('compiled-F2 replay export: '+repr(export_error))
            raise
        primary_error=None
        try:
            identities=fresh.execution_audit()['identities']
            _check_fresh_identities([self._process_identities]+self._replay_identities,
                identities)
            self._replay_identities.append(deepcopy(identities))
            envelope['fresh_build']=_diagnostic_build_snapshot(fresh,
                previous=envelope.get('fresh_build'))
            for record in plan['records']:
                fresh.submit(bytes.fromhex(record['raw']))
            actual=fresh.finish()
            envelope.update(_compare_prefixes(expected,actual),actual_prefix=actual)
            return envelope
        except BaseException as error:
            primary_error=error
            envelope.update(error_type=type(error).__name__,error=str(error))
            raise
        finally:
            secondary_errors=[]
            if not fresh.finished:
                try:fresh.finish()
                except BaseException as error:
                    secondary_errors.append(error)
                    envelope['cleanup_failure']=dict(error_type=type(error).__name__,
                        error=str(error))
            for key,capture in (
                    ('fresh_build',lambda:_diagnostic_build_snapshot(fresh,
                        previous=envelope.get('fresh_build'),error=primary_error)),
                    ('execution_audit',fresh.execution_audit),
                    ('actual_events',lambda:list(fresh.runner.events_since(0)))):
                try:envelope[key]=capture()
                except BaseException as error:
                    secondary_errors.append(error)
                    envelope.setdefault('audit_failures',[]).append(
                        dict(stage=key,error_type=type(error).__name__,
                            error=str(error)))
            if audit_sink is not None:
                try:audit_sink(deepcopy(envelope))
                except BaseException as error:secondary_errors.append(error)
            if primary_error is not None:
                for error in secondary_errors:
                    primary_error.add_note('compiled-F2 replay cleanup/audit: '+repr(error))
            elif secondary_errors:
                primary=secondary_errors[0]
                for error in secondary_errors[1:]:
                    primary.add_note('compiled-F2 replay cleanup/audit: '+repr(error))


def _compare_prefixes(expected,actual):
    from myfuzz.integration.compiled_f4 import _compare_prefixes as compare
    return compare(expected,actual)
