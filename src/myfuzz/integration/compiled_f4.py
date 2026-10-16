"""Execute the selected compiled F4 through generated OBI/APB RTL.

This adapter admits one RV32I instruction image and a source pinned GPIOEN
producer. Other flows and producer contracts are explicitly unsupported.
"""
from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass
from collections.abc import Mapping
from types import MappingProxyType
from hashlib import sha256
import json
from pathlib import Path

from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts, _difference
from myfuzz.local_harness.generated_execution_admission import GeneratedExecutionRefused
from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.scenario.compiled_paths import compile_paths
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, OnlineInstruction
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from .generated_register_writer import declare_writer, check_writer_observation


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _closure(base_dir):
    # The whole Python implementation participates in replay identity: helpers,
    # Router, scheduler, checker and compiler changes all invalidate a plan.
    root=Path(base_dir)
    return {str(p.relative_to(root)):sha256(p.read_bytes()).hexdigest()
            for p in sorted((root/'src/myfuzz').rglob('*.py'))}


def _input_identity(inputs, artifacts):
    """Include per-bit ownership, not only its lossy owner-set document."""
    from myfuzz.local_harness.generated_artifact_admission import _artifact_files
    return _digest(dict(request=inputs['request'].document,
        compiled=compile_paths(inputs['request']), supplied=inputs['compiled'],
        ownership=[(list(key), [asdict(owner) for owner in bits])
                   for key, bits in sorted(inputs['ownership']._bits.items())],
        physical_ports=sorted((list(key), value) for key, value in inputs['physical_port_map'].items()),
        artifacts={name:{key:sha256(value).hexdigest() for key,value in _artifact_files(artifact).items()}
                   for name,artifact in artifacts.items()}))


def _private_admission_snapshot(artifacts, inputs, base_dir):
    """Copy admitted data, including independent immutable profile proxies.

    MappingProxyType deliberately cannot be pickled by deepcopy. Pre-populate
    its copy memo with new immutable proxies over privately copied dictionaries;
    the remaining admitted dataclasses then use normal deepcopy semantics.
    No source reread, frontend process or native execution is needed to copy
    the exact already-issued declaration bytes.
    """
    issued_identity=_input_identity(inputs,artifacts)
    memo={};visited=set()
    def proxies(value):
        if id(value) in visited:return
        visited.add(id(value))
        if isinstance(value,Mapping):
            for key,item in value.items():proxies(key);proxies(item)
            if isinstance(value,MappingProxyType):
                memo[id(value)]=MappingProxyType(deepcopy(dict(value),memo))
        elif is_dataclass(value) and not isinstance(value,type):
            for field in fields(value):proxies(getattr(value,field.name))
        elif isinstance(value,(list,tuple,set,frozenset)):
            for item in value:proxies(item)
    proxies(artifacts);proxies(inputs)
    private_artifacts=deepcopy(dict(artifacts),memo)
    private_inputs=deepcopy(inputs,memo)
    if _input_identity(private_inputs,private_artifacts)!=issued_identity:
        raise ValueError('compiled-F4-private-reconstruction-mismatch')
    admit_f4(artifacts=private_artifacts,compiled_inputs=private_inputs)
    return private_artifacts,private_inputs


def _f4_edges(compiled, image, access):
    graph=compiled['runtime_dependency_graph'];contract=compiled['runtime_path_contract']
    if not isinstance(graph,dict) or not isinstance(contract,dict):
        raise ValueError('compiled-F4-runtime-contract-required')
    rules=[r for r in graph['rules'] if r['target'].startswith('F4.')]
    expected={'F4.mmio_access':('F4.program_image','persistent_state'),
              'F4.device_register_response':('F4.mmio_access','mmio_route')}
    if len(rules)!=2 or {r['target'] for r in rules}!=set(expected):
        raise ValueError('compiled-F4-declared-edge-shape-unsupported')
    edges=[]
    for rule in rules:
        prerequisite,relation=expected[rule['target']]
        rows=[e for e in contract['edges'] if e['rule_index']==rule['rule_index']]
        if rule['prerequisites']!=[prerequisite] or len(rows)!=1:
            raise ValueError('compiled-F4-declared-edge-shape-unsupported')
        edge=rows[0]
        if edge['prerequisite_index']!=0 or edge['relation']!=relation:
            raise ValueError('compiled-F4-declared-edge-shape-unsupported')
        if relation=='persistent_state':
            if (edge['resource_component'],edge['resource_id'])!=(image['component'],image['port']):
                raise ValueError('compiled-F4-declared-resource-mismatch')
        elif (edge['initiator_component'],edge['device_id'],edge['base'],edge['size'])!=(
                access['source_component'],access['device_id'],access['window_base'],access['window_size']):
            raise ValueError('compiled-F4-declared-route-mismatch')
        edges.append(dict(edge,prerequisite=prerequisite,target=rule['target']))
    return edges


def _cpu_traces(artifact, image, stream):
    traces=artifact.runtime_document.get('base_protocol_traces', {}).get('traces', [])
    result={}
    for channel, endpoint in (('instr',image['endpoint_id']),('data',stream['register_access']['source_endpoint'])):
        rows=[t for t in traces if t.get('endpoint_id')==endpoint and t.get('protocol')=='obi'
              and t.get('boundary')=='cpu_physical_abi' and t.get('max_outstanding')==1]
        if len(rows)!=1:raise ValueError('compiled-F4-native-CPU-trace-required')
        signals=rows[0]['signals']
        required={'req','gnt','addr','rvalid','rdata','error'}
        if channel=='data':required|={'we','wdata','be'}
        if not required<=set(signals):
            raise ValueError('compiled-F4-native-CPU-trace-required')
        result[channel]=signals
    return result


def _native_steps(events, component):
    for event in events:
        if event.get('component')!=component or 'outputs' not in event or 'local_tick' not in event:
            continue
        samples=event['outputs'].get('driver_samples')
        if samples is None:continue
        if len(samples)!=1 or samples[0]['local_tick']!=event['local_tick']:
            raise ValueError('compiled-F4-native-CPU-sample-shape')
        yield event,samples[0]['pre']['protocol_taps']


def check_f4_exact_hops(*, events, declaration, image, stream, traces, address, source_event_id, joins, declared_edges, instruction_snapshots):
    """Consume the narrow F4 chain: image byte versions, native OBI and APB.

    A consumed fetch is not instruction retirement. F4 declares consumption;
    no retirement or unrelated fixed-topology ChainCertificates claim is made.
    The native ABI permits exactly one outstanding beat per channel, so each
    response consumes the exact outstanding acceptance, never an adjacent row.
    """
    cpu=image['component'];access=stream['register_access'];code=bytes.fromhex(declaration['code_hex'])
    by_id={e['event_id']:e for e in events}
    if len(by_id)!=len(events):raise ValueError('compiled-F4-duplicate-event-identity')
    sources=[e for e in events if e.get('kind')=='instruction_source' and e.get('component')==cpu
             and e.get('source_event_id')==source_event_id and e.get('address')==address
             and e.get('data_hex')==code.hex()]
    if len(sources)!=1:raise ValueError('compiled-F4-instruction-source-missing')
    from myfuzz.scenario.edge_provenance import _transaction_key
    route_transaction=by_id[joins[0]['delivery_event']]['source_transaction']
    if _transaction_key(route_transaction) is None:raise ValueError('compiled-F4-transaction-malformed')
    source=sources[0];pending={'instr':None,'data':None};sequence={'instr':0,'data':0};completed={}
    for step,taps in _native_steps(events,cpu):
        for channel,signals in traces.items():
            def pin(role):return taps.get(signals.get(role))
            # OBI has no response backpressure at this physical CPU boundary.
            if pin('rvalid')==1:
                if type(pin('error')) is not int or pin('error')!=0:
                    raise ValueError('compiled-F4-native-CPU-response-error')
                accepted=pending[channel]
                if accepted is None:raise ValueError('compiled-F4-native-response-unowned')
                key=(channel,accepted['sequence'])
                completed[key]=dict(accepted, response_event=step['event_id'],rdata=pin('rdata'),error=pin('error'))
                pending[channel]=None
            if pin('req')==1 and pin('gnt')==1:
                if pending[channel] is not None:raise ValueError('compiled-F4-native-outstanding-overlap')
                sequence[channel]+=1
                pending[channel]=dict(sequence=sequence[channel],acceptance_event=step['event_id'],
                    address=pin('addr'),write=pin('we') if channel=='data' else 0,
                    value=pin('wdata'),byte_enable=pin('be'))
    instruction_hops=[]
    # The eight functional instructions must all be consumed from this image.
    # Four trailing NOPs merely separate contiguous candidates.
    for offset in range(0,32,4):
        rows=[e for e in events if e.get('kind')=='memory_read' and e.get('component')==cpu
              and e.get('address')==address+offset and e.get('transaction',{}).get('channel_id')=='instr'
              and isinstance(e.get('writer_event_ids'),(list,tuple))
              and tuple(e['writer_event_ids'])==(source_event_id,)*4
              and e.get('data_hex')==code[offset:offset+4].hex()]
        if len(rows)!=1:raise ValueError('compiled-F4-instruction-version-hop-missing')
        read=rows[0];transaction=read['transaction']
        snapshot=instruction_snapshots[offset//4]
        if (read['data_hex']!=snapshot.data.hex() or read['byte_offset']!=snapshot.byte_offset
                or [list(v) for v in read['versions']]!=[list(v) for v in snapshot.versions]
                or tuple(read['writer_event_ids'])!=snapshot.writer_event_ids
                or snapshot.writer_kinds!=('INSTRUCTION_SOURCE',)*4):
            raise ValueError('compiled-F4-instruction-authoritative-version-mismatch')
        if (_transaction_key(transaction) is None or any(transaction[k]!=route_transaction[k]
                for k in ('execution_id','testcase_id','source_component','source_epoch'))):
            raise ValueError('compiled-F4-instruction-transaction-mismatch')
        beat=completed.get(('instr',transaction['source_sequence']))
        if (read.get('memory_id')!=image['port'] or read.get('generation')!=source['generation']
                or read.get('width_bytes')!=4 or len(read.get('versions',[]))!=4
                or any(type(v) not in (list,tuple) or len(v)!=2
                       or any(type(n) is not int or n<0 for n in v)
                       or v[0]!=source['generation'] or v[1]<1 for v in read['versions'])
                or any(v!=read['versions'][0] for v in read['versions'])
                or beat is None or beat['address']!=address+offset
                or beat['rdata']!=int.from_bytes(code[offset:offset+4],'little')
                or not beat['acceptance_event']<=read['producer_event_id']<beat['response_event']):
            raise ValueError('compiled-F4-native-instruction-consumption-missing')
        instruction_hops.append(dict(beat,source_event=source['event_id'],
            memory_read_event=read['event_id'],versions=read['versions']))
    data_hops=[]
    for join in joins:
        delivery=by_id[join['delivery_event']];accept=by_id[join['acceptance_event']]
        transaction=delivery['source_transaction'];beat=completed.get(('data',transaction['source_sequence']))
        if (_transaction_key(transaction) is None
                or any(transaction[k]!=route_transaction[k] for k in ('execution_id','testcase_id','source_component','source_epoch'))
                or transaction.get('source_component')!=cpu or transaction.get('source_epoch')!=0
                or transaction.get('channel_id')!='data' or accept.get('component')!=cpu
                or accept.get('device_id')!=access['device_id']
                or delivery.get('device_id')!=access['device_id']
                or delivery.get('offset')!=access['register_offset']
                or beat is None or beat['acceptance_event']!=accept['producer_event_id']
                or beat['address']!=access['address'] or beat['write']!=int(delivery['write'])
                or (delivery['write'] and (beat['value']!=declaration['candidate']['value'] or beat['byte_enable']!=15))
                or (not delivery['write'] and beat['rdata']!=declaration['candidate']['value'])
                or not accept['event_id']<delivery['event_id']<beat['response_event']):
            raise ValueError('compiled-F4-native-data-route-hop-missing')
        data_hops.append(dict(join,native_acceptance_event=beat['acceptance_event'],
            native_response_event=beat['response_event'],native_obi=dict(beat)))
    # SW and LW fetches must precede their actual data requests.
    if (instruction_hops[4]['response_event']>=data_hops[0]['native_acceptance_event']
            or instruction_hops[5]['response_event']>=data_hops[1]['native_acceptance_event']):
        raise ValueError('compiled-F4-instruction-data-order')
    return dict(schema_version='compiled_F4_exact_hops.v1',
        proof_scope='selected_F4_image_consumption_native_OBI_route_native_APB_live_GPIOEN',
        instruction_hops=instruction_hops,data_hops=data_hops,
        edges=[dict(edge,status='certified',hops=(instruction_hops if edge['relation']=='persistent_state' else data_hops))
               for edge in declared_edges])


def admit_f4(*, artifacts, compiled_inputs):
    """Pure exact D2/D3/ownership admission before constructing any process."""
    if not isinstance(compiled_inputs, dict) or set(compiled_inputs)!={'request','compiled','ownership','physical_port_map'}:
        raise GeneratedExecutionRefused('compiled-runtime-input-required','/compiled_inputs')
    admission=admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs)
    if admission['status']!='compatible':
        raise GeneratedExecutionRefused('compiled-runtime-input-refused','/compiled_inputs',admission)
    request=compiled_inputs['request'];compiled=compiled_inputs['compiled']
    selected=[p for p in compiled['paths'] if p['flow_id']=='F4' and p['status']=='executable']
    if len(selected)!=1:raise ValueError('compiled-F4-executable-required')
    path=selected[0]
    if any(s['kind'] not in {'instruction_image','cpu_mmio_stream','external_pin'} for s in path['sources']):
        raise ValueError('compiled-F4-source-kind-unsupported')
    sources={kind:[s for s in path['sources'] if s['kind']==kind]
             for kind in ('instruction_image','cpu_mmio_stream')}
    if any(len(rows)!=1 for rows in sources.values()):raise ValueError('compiled-F4-source-shape-unsupported')
    image=sources['instruction_image'][0];stream=sources['cpu_mmio_stream'][0];access=stream['register_access']
    cpu=request.cpu
    if (image['component']!=cpu.instance_id or access['source_component']!=cpu.instance_id
            or len(request.devices)!=1 or request.devices[0].instance_id!=access['target_component']):
        raise ValueError('compiled-F4-topology-unsupported')
    if cpu.profile.cpu.xlen!=32 or 'I' not in {e.upper() for e in cpu.profile.cpu.extensions}:
        raise ValueError('compiled-F4-RV32I-required')
    if artifacts[cpu.instance_id].runtime_document['kind']!='obi_cpu':
        raise ValueError('compiled-F4-CPU-protocol-unsupported')
    _cpu_traces(artifacts[cpu.instance_id], image, stream)
    _f4_edges(compiled,image,access)
    resources=[r for r in request.wiring.resources if r.component_instance==cpu.instance_id]
    result=image['range'][1]-3
    if (any(r.base is None or r.size is None or r.read is None or r.write is None
            or r.initialization_policy!='preload' for r in resources)
            or not any(r.resource_id==image['port'] and r.read is True and r.write is True
                       and r.base<=result and result+4<=r.base+r.size for r in resources)):
        raise ValueError('compiled-F4-writable-image-result-resource-required')
    for source in path['sources']:
        if source['kind']=='external_pin' and (source['component']!=access['target_component']
                or not 1<=source['width']<=32 or source['bit_offset']!=0
                or source['mask']!=(1<<source['width'])-1
                or source['alignment']!=1 or source['range'] is not None):
            raise ValueError('compiled-F4-external-pin-shape-unsupported')
    target=artifacts[access['target_component']]
    from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    if (target.runtime_document['kind']!='apb_gpio' or access['register']!='GPIOEN'
            or target.runtime_document.get('gpio_observation_contract')!=pulp_gpio_observation_contract()
            or verify_native_physical_observation(target) is not True):
        raise ValueError('compiled-F4-register-authority-unsupported')
    expected_pre=[dict(kind='ip_register_version',subject=dict(component=access['target_component'],register='GPIOEN',reset_epoch=0))]
    if [dict(kind=p['kind'],subject=p['subject']) for p in path['prerequisites']]!=expected_pre:
        raise ValueError('compiled-F4-prerequisite-unsupported')
    if (path['seed'] is not None or path['termination_observation']['kind']!='consumption'
            or {a['expectation_id'] for a in path['assertions']}!={
                'protocol_checker.receipt_violations','cross_component.declared_edge_hops',
                'cross_component.chain_certificate_hops'}):
        raise ValueError('compiled-F4-checker-or-seed-unsupported')
    if len(path['bound_inputs'])!=1 or path['bound_inputs'][0]['kind']!='ip_register_commit':
        raise ValueError('compiled-F4-bound-producer-unsupported')
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
                or rule['failure_class']!='constraint_conflict'
                or rule['basis']!='soc_plan.address_map.windows'):
            raise ValueError('compiled-F4-constraint-rule-unsupported')
    if request.wiring.deliveries:
        raise ValueError('compiled-F4-deliveries-unsupported')
    if any(o['kind']=='bound' for o in compiled_inputs['ownership'].document()['owners']):
        raise ValueError('compiled-F4-physical-binding-unsupported')
    return deepcopy(path)


class CompiledF4Runtime:
    """One continuous testcase with live prerequisites and fresh prefix replay."""
    @host_source_discovery_scope()
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f4', rounds_per_case=128, max_cases=64):
        self.path=admit_f4(artifacts=artifacts,compiled_inputs=compiled_inputs)
        if any(type(v) is not int or not 1<=v<=65536 for v in (rounds_per_case,max_cases)):
            raise ValueError('compiled-F4-budget-invalid')
        self._caller_inputs=compiled_inputs;self._caller_artifacts=artifacts
        self._input_digest=_input_identity(compiled_inputs,artifacts)
        self.artifacts,self.inputs=_private_admission_snapshot(artifacts,compiled_inputs,Path(base_dir))
        compiled_inputs=self.inputs;artifacts=self.artifacts
        self.base_dir=Path(base_dir);self.cache_dir=Path(cache_dir);self.run_id=run_id
        self.rounds=rounds_per_case;self.max_cases=max_cases;self.records=[];self.finished=False
        self.closure=_closure(base_dir);self.compiled_digest=_digest(compiled_inputs['compiled'])
        request=compiled_inputs['request'];self.cpu_id=request.cpu.instance_id
        self.stream=next(s for s in self.path['sources'] if s['kind']=='cpu_mmio_stream')
        self.access=self.stream['register_access'];self.target_id=self.access['target_component']
        image=next(s for s in self.path['sources'] if s['kind']=='instruction_image')
        self.declared_edges=_f4_edges(compiled_inputs['compiled'],image,self.access)
        self.image=image;self.traces=_cpu_traces(artifacts[self.cpu_id],image,self.stream)
        self.start=image['range'][0]
        self.cursor=None;self.first_fetch=None
        self.end=image['range'][1]+1
        self.result=self.end-4
        resources=[r for r in request.wiring.resources if r.component_instance==self.cpu_id]
        if (any(r.base is None or r.size is None or r.read is None or r.write is None for r in resources)
                or any(r.initialization_policy!='preload' for r in resources)):
            raise ValueError('compiled-F4-memory-resource-unsupported')
        if not any(r.resource_id==image['port'] and r.read is True and r.write is True
                   and r.base<=self.result and self.result+4<=r.base+r.size for r in resources):
            raise ValueError('compiled-F4-writable-image-result-resource-required')
        memory=PersistentMemory(regions=tuple(MemoryRegion(r.resource_id,r.base,r.size,
            readable=r.read,writable=r.write) for r in resources), initialization_seed=0,
            max_initialized_bytes=sum(r.size for r in resources))
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
        target=GeneratedPulpGpioSession(artifacts[self.target_id],base_dir=self.base_dir,cache_dir=self.cache_dir)
        self.authority=GpioRegisterVersionAuthority(target,max_writes=max_cases+8)
        windows=tuple(DeviceWindow(w.device_id,w.base,w.size,target) for w in request.wiring.windows)
        if any(w.target_instance!=self.target_id for w in request.wiring.windows):
            raise ValueError('compiled-F4-router-target-unsupported')
        cpu=GeneratedCve2Session(artifacts[self.cpu_id],base_dir=self.base_dir,cache_dir=self.cache_dir,
            memory=memory,router=DataflowRouter(windows),defer_mmio=True)
        self.runner=ScenarioRunner(sessions={self.cpu_id:cpu,self.target_id:target},
            ownership=compiled_inputs['ownership'],bindings=())
        template=ScenarioGenome(run_id,'CPU_TO_IP',self.path['path_id'],tuple(self.runner.sessions),
            rounds_per_case*max_cases*2,())
        self._pending=None;self._checked=None
        self.session=ScenarioSession(template,self.runner,checker=self._check_receipt,
            checker_configuration_only=True)
        # Retain exact source bytes; every future slot remains unmaterialized.
        self.session.declare_instruction_slots(self.cpu_id,self.start,(self.result-self.start)//4)
        try:
            self._stable()
            self.session.begin()
            self.session.advance_initial((self.target_id,))
            self.authority.consume(self.authority.issue(reset_epoch=0))
            # Observe and stall the native first fetch before materializing bytes.
            for _ in range(self.rounds):
                self._stable()
                bootstrap=self.session.advance_initial((self.cpu_id,))
                steps=list(_native_steps(bootstrap.events,self.cpu_id))
                signals=self.traces['instr']
                accepted=[(e,t) for e,t in steps if t.get(signals['req'])==1 and t.get(signals['gnt'])==1]
                if accepted:
                    event,taps=accepted[0];self.cursor=taps[signals['addr']]
                    self.first_fetch=dict(address=self.cursor,event_id=event['event_id'])
                    break
            if (self.cursor is None or self.cursor%4 or not self.start<=self.cursor<self.result):
                raise ValueError('compiled-F4-first-fetch-outside-image')
        except BaseException:
            if self.session._begun and not self.session._finished:self.session.finish()
            raise

    def online_identity_configuration(self):
        return dict(schema_version='compiled_F4_checker.v1',path_id=self.path['path_id'],
            compiled_sha256=self.compiled_digest,assertions=self.path['assertions'])

    def _check_receipt(self, receipt):
        if receipt.violations:
            self._checked=None
            return tuple(receipt.violations)
        if self._pending is None:
            return tuple(receipt.violations)
        declaration,before,prior=self._pending
        try:
            observed,commit,after=self._check_chain(receipt,declaration,before,prior)
            self._checked=(observed,commit,after)
            return tuple(receipt.violations)
        except ValueError as error:
            self._checked=None
            return (str(error),)

    def _check_chain(self,receipt,declaration,before,prior):
        value=declaration['candidate']['value']
        observed=check_writer_observation(declaration,receipt,target_artifact=self.artifacts[self.target_id])
        writes=self.authority.writes()[prior:]
        if len(writes)!=1:raise ValueError('compiled-F4-bound-commit-count')
        commit=writes[0];context=commit['context']
        delivery=next(e for e in receipt.events if e.get('event_id')==observed['joins'][0]['delivery_event'])
        if (not context or context['source_transaction']!=delivery['source_transaction']
                or context['address']!=self.access['address'] or context['offset']!=self.access['register_offset']
                or context['write'] is not True or context['value']!=value or context['be']!=15
                or commit['before']!=before['value'] or commit['after']!=value or commit['epoch']!=before['reset_epoch']):
            raise ValueError('compiled-F4-bound-commit-join-mismatch')
        physical=next(e for e in receipt.events if e.get('event_id')==observed['joins'][0]['native_APB_event'])
        if commit['tick']!=physical['local_tick'] or context['command_scope']!={
                'component':self.target_id,'reset_epoch':commit['epoch'],'command_sequence':commit['command_sequence']}:
            raise ValueError('compiled-F4-native-commit-identity-mismatch')
        after=self.authority.consume(self.authority.issue(reset_epoch=before['reset_epoch']))
        if after['value']!=value:raise ValueError('compiled-F4-live-register-mismatch')
        instruction_snapshots=[self.runner.sessions[self.cpu_id].memory.read(self.cursor+offset,4,
            transaction_id=f'compiled-F4-check:{len(self.records)}:{offset}') for offset in range(0,32,4)]
        observed['exact_hops']=check_f4_exact_hops(events=self.runner.events_since(0),
            declaration=declaration,image=self.image,stream=self.stream,traces=self.traces,
            address=self.cursor,source_event_id=self.image['source_id']+f':{len(self.records)}',
            joins=observed['joins'],declared_edges=self.declared_edges,instruction_snapshots=instruction_snapshots)
        observed['exact_hops']['assertions']=[
            dict(expectation_id='protocol_checker.receipt_violations',status='passed',evidence=dict(violations=list(receipt.violations))),
            dict(expectation_id='cross_component.declared_edge_hops',status='passed',
                 evidence=dict(edge_ids=[[e['rule_index'],e['prerequisite_index']] for e in observed['exact_hops']['edges']])),
            dict(expectation_id='cross_component.chain_certificate_hops',status='passed',
                 evidence=dict(instruction_source=self.image['source_id'],commit_tick=commit['tick'],
                               data_transactions=[h['source_transaction'] for h in observed['exact_hops']['data_hops']]))]
        return observed,commit,after

    def _stable(self, *, allow_finished=False):
        if self.finished and not allow_finished:raise ValueError('compiled-F4-runtime-finished')
        if (_input_identity(self._caller_inputs,self._caller_artifacts)!=self._input_digest
                or _input_identity(self.inputs,self.artifacts)!=self._input_digest):
            raise ValueError('compiled-F4-input-identity-changed')
        if admit_f4(artifacts=self.artifacts,compiled_inputs=self.inputs)!=self.path:
            raise ValueError('compiled-F4-admission-changed')
        if (_closure(self.base_dir)!=self.closure or _digest(self.inputs['compiled'])!=self.compiled_digest
                or _difference(compile_paths(self.inputs['request']),self.inputs['compiled']) is not None):
            raise ValueError('compiled-F4-source-identity-changed')

    @host_source_discovery_scope()
    def submit(self, raw):
        """Consume one fuzzer record; its low target word is the F4 candidate."""
        self._stable()
        if type(raw) is not bytes or len(raw)!=8:raise ValueError('compiled-F4-record-required')
        if len(self.records)>=self.max_cases:raise ValueError('compiled-F4-case-budget-exhausted')
        value=int.from_bytes(raw[:4],'little')
        declaration=declare_writer(self.inputs['request'],self.inputs['compiled'],
            source_id=self.stream['source_id'],value=value,result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        if self.cursor+len(code)>self.result:raise ValueError('compiled-F4-slot-exhausted')
        external=[s for s in self.path['sources'] if s['kind']=='external_pin']
        for number,source in enumerate(external):
            self._stable()
            pin_value=int.from_bytes(raw[4:],'little') & source['mask']
            pin_case=OnlineCase(f'{self.run_id}:{len(self.records)}:external:{number}',
                'CPU_TO_IP',self.path['path_id'],BatchSourceEvent(
                    source['source_id']+f':{len(self.records)}',source['component'],
                    source['port'],pin_value,source['bit_offset'],source['width']),
                (BatchAdvance((source['component'],)),))
            pin_receipt=self.session.submit_case(pin_case)
            if pin_receipt.violations:raise ValueError('compiled-F4-external-source-failed')
        before=self.authority.consume(self.authority.issue(reset_epoch=self.runner.sessions[self.target_id].reset_epoch))
        prior=len(self.authority.writes())
        index=len(self.records);case_id=f'{self.run_id}:{index}'
        case=OnlineCase(case_id,'CPU_TO_IP',self.path['path_id'],
            OnlineInstruction(self.image['source_id']+f':{index}',self.cpu_id,self.cursor,code.hex()),
            tuple(BatchAdvance(tuple(self.runner.sessions)) for _ in range(self.rounds)))
        self._stable()
        self._pending=(declaration,before,prior);self._checked=None
        receipt=self.session.submit_case(case)
        self._pending=None
        if receipt.violations or self._checked is None or receipt.status!='running':
            raise ValueError('compiled-F4-protocol-checker-failed:'+str(receipt.violations))
        observed,commit,after=self._checked
        certificate=dict(schema_version='compiled_F4_chain.v1',status='certified',
            path_id=self.path['path_id'],source_id=self.stream['source_id'],
            bound_input_id=self.path['bound_inputs'][0]['input_id'],case_id=case_id,
            instruction_source_id=next(s['source_id'] for s in self.path['sources'] if s['kind']=='instruction_image'),
            instruction_address=self.cursor,instruction_sha256=sha256(code).hexdigest(),
            prerequisite=before,commit=commit,postcondition=after,joins=observed['joins'],
            first_fetch=self.first_fetch,exact_hops=observed['exact_hops'],
            assertions=observed['exact_hops']['assertions'],
            runtime_admitted=True)
        self.records.append(dict(raw=raw.hex(),value=value,certificate=certificate))
        self.cursor+=len(code)
        return deepcopy(certificate)

    def feedback(self):
        return dict(cases=len(self.records),certified=len(self.records),
            distinct_values=len({r['value'] for r in self.records}),
            changed_versions=sum(r['certificate']['commit']['before']!=r['value'] for r in self.records))

    @host_source_discovery_scope()
    def finish(self):
        if not self.finished:
            try:self._stable()
            finally:
                self.trace=self.session.finish();self.finished=True
        self._stable(allow_finished=True)
        return dict(schema_version='compiled_F4_prefix.v1',run_id=self.run_id,
            compiled_sha256=self.compiled_digest,source_files=self.closure,
            artifact_digests={n:a.runtime_document['artifact_digest'] for n,a in self.artifacts.items()},
            rounds_per_case=self.rounds,max_cases=self.max_cases,records=deepcopy(self.records),
            online_plan=json.loads(self.session.encode_plan()),
            semantic_hash=self.trace.semantic_sha256,feedback=self.feedback())

    @host_source_discovery_scope()
    def replay(self, plan):
        """Reexecute every candidate, checking live prerequisites anew."""
        self._stable(allow_finished=True)
        expected=self.finish()
        if _difference(expected,plan) is not None:raise ValueError('compiled-F4-prefix-mismatch')
        fresh=type(self)(artifacts=self.artifacts,compiled_inputs=self.inputs,
            base_dir=self.base_dir,cache_dir=self.cache_dir,run_id=self.run_id,
            rounds_per_case=self.rounds,max_cases=self.max_cases)
        try:
            for record in plan['records']:fresh.submit(bytes.fromhex(record['raw']))
            actual=fresh.finish()
            # PIDs and execution nonces must be fresh. They authenticate each
            # local run but are not a deterministic hardware observation.
            def normalized(doc):
                result=deepcopy(doc)
                for row in result['records']:
                    for key in ('prerequisite','postcondition'):
                        row['certificate'][key].pop('process_scope',None)
                return result
            return dict(matches=_difference(normalized(expected),normalized(actual)) is None,
                scope='full_fresh_prefix_real_RTL_and_live_register_prerequisites',
                expected_semantic_hash=expected['semantic_hash'],actual_semantic_hash=actual['semantic_hash'])
        finally:
            if not fresh.finished:fresh.finish()
