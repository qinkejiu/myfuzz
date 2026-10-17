"""Execute the selected compiled F4 through generated OBI/APB RTL.

This adapter admits one RV32I instruction image and one closed storage producer
row: the source-pinned PULP GPIOEN causal ABI or the registered generic APB
storage ABI (``GeneratedApb3RegisterSession`` with a live
``ApbStorageRegisterVersionAuthority`` token joined to CPU acceptance, Router
delivery, native APB pre/post samples and CPU readback/RAM). Other flows and
producer contracts are explicitly unsupported.
"""
from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from hashlib import sha256
import json
from pathlib import Path
import re

from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts, _difference
from myfuzz.local_harness.generated_execution_admission import GeneratedExecutionRefused
from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.scenario.compiled_paths import (
    compile_paths, compiled_document_sha256)
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, OnlineInstruction
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from .compiled_candidate_layout import compile_candidate_layout, CandidateLayout, LAYOUT_SCHEMA
from .compiled_storage_producer import (
    ROW_GENERIC_APB_STORAGE, ROW_GPIO_CAUSAL, build_storage_producer,
    select_storage_producer)
from .generated_register_writer import declare_writer, check_writer_observation
from .generated_storage_consumer import (
    check_storage_observation, stable_storage_version, storage_consumer_support)


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _layout_document(layout):
    return dict(schema_version=LAYOUT_SCHEMA,digest=layout.digest,
        byte_length=layout.byte_length,bit_length=layout.bit_length,
        derived_image_source_id=layout.derived_image_source_id,
        slices=[asdict(row) for row in layout.slices])


# The C routed-storage receipt id embeds the driver's process-local execution
# nonce: ``apb-storage:<execution>:<sequence>``.  The nonce is regenerated for
# every fresh process, so it is the only byte allowed to differ between an
# honest primary run and its fresh replay.  It is normalized only for the
# verification semantic hash; receipts, events and certificates keep the real
# value untouched and are joined by their real fields.
_PROCESS_LOCAL_EXECUTION = '<compiled-f4-process-execution>'
_ACCESS_SEQUENCE = re.compile('[0-9]+')


def _normalize_target_access_id(value):
    prefix = 'apb-storage:'
    if type(value) is not str or not value.startswith(prefix):
        return value
    execution, separator, sequence = value[len(prefix):].rpartition(':')
    if not separator or not execution or _ACCESS_SEQUENCE.fullmatch(sequence) is None:
        return value
    return prefix + _PROCESS_LOCAL_EXECUTION + ':' + sequence


def _project_process_local(value):
    """Copy an event tree and normalize only process-local access ids."""
    if isinstance(value, dict):
        return {key: (_normalize_target_access_id(item)
                      if key == 'target_access_id'
                      else _project_process_local(item))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_project_process_local(item) for item in value]
    return value


def _semantic_canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def normalized_semantic_sha256(status, events, ticks):
    """Semantic hash of the real event chain minus process-local receipt UUIDs.

    Uses the same canonical byte layout as
    ``session_runtime._trace_semantic_sha256`` for an event-journal snapshot.
    Only ``target_access_id`` execution segments are replaced with a stable
    placeholder; every sequence suffix, every other field, the local ticks and
    the status still participate.
    """
    if (type(status) is not str or not isinstance(ticks, dict)
            or any(type(key) is not str or type(value) is not int
                   for key, value in ticks.items())
            or not isinstance(events, Sequence)
            or isinstance(events, (str, bytes, bytearray))):
        raise ValueError('compiled-F4-semantic-hash-input-required')
    digest = sha256()
    digest.update(b'{"events":[')
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError('compiled-F4-semantic-hash-input-required')
        if index:
            digest.update(b',')
        digest.update(_semantic_canonical(_project_process_local(event)))
    digest.update(b'],"local_ticks":')
    digest.update(_semantic_canonical(ticks))
    digest.update(b',"status":')
    digest.update(_semantic_canonical(status))
    digest.update(b'"}')
    return digest.hexdigest()


def _check_fresh_identities(previous, actual):
    if not previous or set(actual)!=set(previous[0]):
        raise ValueError('compiled-F4-fresh-process-shape')
    pids=set();nonces=set()
    for component,row in actual.items():
        reference=previous[0][component]
        if (any(row.get(k)!=reference.get(k) for k in ('component','role','artifact_digest'))
                or type(row.get('pid')) is not int or row['pid']<=0
                or not isinstance(row.get('execution_nonce'),str) or not row['execution_nonce']):
            raise ValueError('compiled-F4-fresh-process-shape')
        if row['pid'] in pids or row['execution_nonce'] in nonces:
            raise ValueError('compiled-F4-fresh-process-identity-reused')
        pids.add(row['pid']);nonces.add(row['execution_nonce'])
    for run in previous:
        if (pids & {r['pid'] for r in run.values()}
                or nonces & {r['execution_nonce'] for r in run.values()}):
            raise ValueError('compiled-F4-fresh-process-identity-reused')


def _compare_prefixes(expected,actual):
    def normalized(doc):
        result=deepcopy(doc)
        for row in result['records']:
            for key in ('prerequisite','postcondition'):
                row['certificate'][key].pop('process_scope',None)
        return result
    difference=_difference(normalized(expected),normalized(actual))
    return dict(matches=difference is None,first_difference=difference,
        verification_scope='full',
        expected_semantic_hash=expected['semantic_hash'],actual_semantic_hash=actual['semantic_hash'])


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
    _admit_f4(artifacts=private_artifacts,compiled_inputs=private_inputs,base_dir=base_dir)
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


_OBI_ADAPTER_PATH='src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv'
# Reviewed implementation contains the synchronous backend ERR fail-stop.
_OBI_FAIL_STOP_SHA256='59730c6742a85351d6e2cbf284d88185c874080274f323f2364268f2da3440df'


def _cpu_error_policy(artifact,image,stream):
    """Derive a success-only ABI policy from exact generated declarations."""
    from myfuzz.local_harness.native_physical_observation import verify_cpu_obi_protocol_traces
    from myfuzz.local_harness.template_contracts import select_template_contract
    verify_cpu_obi_protocol_traces(artifact)
    document=artifact.runtime_document;profile=artifact.plan.profile
    error=profile.capabilities.get('error_response')
    if type(error) is not bool:raise ValueError('compiled-F4-explicit-error-capability-required')
    endpoints={e.endpoint_id:e for e in artifact.plan.binding.endpoints}
    contracts=[]
    for endpoint_id,base_variant in ((image['endpoint_id'],'read-only'),
            (stream['register_access']['source_endpoint'],'read-write')):
        endpoint=endpoints[endpoint_id]
        contracts.append(select_template_contract(endpoint,profile.capabilities,
            template_id='cpu.obi',template_version='1',
            variant_id=base_variant+('' if error else '-no-error-pins')).document())
    executor=document['selected_template']['executor']
    if (executor['protocol_templates']!=sorted(contracts,key=lambda r:r['binding']['endpoint_id'])
            or executor['binding']['declared_profile_facts'].get('error_response') is not error
            or executor['binding']['adapter_sources']!=document['adapter_sources']):
        raise ValueError('compiled-F4-error-policy-contract-mismatch')
    adapter=dict(path=_OBI_ADAPTER_PATH,sha256=_OBI_FAIL_STOP_SHA256)
    if (document['adapter_sources']!=[adapter]
            or sha256((Path(__file__).resolve().parents[3]/_OBI_ADAPTER_PATH).read_bytes()).hexdigest()!=adapter['sha256']
            or artifact.runtime_sv.count(f'.HAS_ERROR({int(error)})')!=2
            or artifact.runtime_sv.count('obi_processor_memory_adapter #(')!=2):
        raise ValueError('compiled-F4-error-policy-adapter-closure')
    return dict(schema_version='compiled_F4_cpu_error_policy.v1',
        mode='native_error_role' if error else 'fail_stop_no_error_pin',
        native_error_observation=error,
        backend_error_policy='propagate_error' if error else 'fail_stop_no_error_pin_to_raise',
        selected_contracts=contracts,adapter_source=adapter)


def _check_error_assertions(path,policy):
    # Existing receipt/edge/chain assertions prove successful responses only.
    # Error reporting/trap assertions require physical error observation.
    if not policy['native_error_observation'] and any(
            row.get('expectation_id')=='protocol_checker.native_error_response'
            for row in path['assertions']):
        raise ValueError('compiled-F4-native-error-observation-unsupported')


def _cpu_traces(artifact, image, stream):
    policy=_cpu_error_policy(artifact,image,stream)
    traces=artifact.runtime_document.get('base_protocol_traces', {}).get('traces', [])
    result={}
    for channel, endpoint in (('instr',image['endpoint_id']),('data',stream['register_access']['source_endpoint'])):
        rows=[t for t in traces if t.get('endpoint_id')==endpoint and t.get('protocol')=='obi'
              and t.get('boundary')=='cpu_physical_abi' and t.get('max_outstanding')==1]
        if len(rows)!=1:raise ValueError('compiled-F4-native-CPU-trace-required')
        signals=rows[0]['signals']
        required={'req','gnt','addr','rvalid','rdata'}
        if policy['native_error_observation']:required.add('error')
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


def check_f4_exact_hops(*, events, declaration, image, stream, traces, address, source_event_id, joins, declared_edges, instruction_snapshots, error_policy=None):
    """Consume the narrow F4 chain: image byte versions, native OBI and APB.

    A consumed fetch is not instruction retirement. F4 declares consumption;
    no retirement or unrelated fixed-topology ChainCertificates claim is made.
    The native ABI permits exactly one outstanding beat per channel, so each
    response consumes the exact outstanding acceptance, never an adjacent row.
    """
    if error_policy is None:error_policy=dict(mode='native_error_role',native_error_observation=True)
    if (error_policy.get('mode'),error_policy.get('native_error_observation')) not in {
            ('native_error_role',True),('fail_stop_no_error_pin',False)}:
        raise ValueError('compiled-F4-error-policy-invalid')
    if not error_policy['native_error_observation'] and any('error' in row for row in traces.values()):
        raise ValueError('compiled-F4-error-policy-trace-contradiction')
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
                if error_policy['native_error_observation'] and (type(pin('error')) is not int or pin('error')!=0):
                    raise ValueError('compiled-F4-native-CPU-response-error')
                accepted=pending[channel]
                if accepted is None:raise ValueError('compiled-F4-native-response-unowned')
                key=(channel,accepted['sequence'])
                completed[key]=dict(accepted, response_event=step['event_id'],rdata=pin('rdata'),error=pin('error') if error_policy['native_error_observation'] else None)
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
        cpu_error_policy=deepcopy(error_policy),
        instruction_hops=instruction_hops,data_hops=data_hops,
        edges=[dict(edge,status='certified',hops=(instruction_hops if edge['relation']=='persistent_state' else data_hops))
               for edge in declared_edges])


def admit_f4(*, artifacts, compiled_inputs, base_dir=None):
    """Pure exact D2/D3/ownership admission before constructing any process."""
    return _admit_f4(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)[0]


def _admit_f4(*, artifacts, compiled_inputs, base_dir=None):
    """Admission plus the immutable producer binding rebuilt from source inputs."""
    if not isinstance(compiled_inputs, dict) or set(compiled_inputs)!={'request','compiled','ownership','physical_port_map'}:
        raise GeneratedExecutionRefused('compiled-runtime-input-required','/compiled_inputs')
    admission=admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs)
    if admission['status']!='compatible':
        raise GeneratedExecutionRefused('compiled-runtime-input-refused','/compiled_inputs',admission)
    request=compiled_inputs['request'];compiled=compiled_inputs['compiled']
    selected=[p for p in compiled['paths'] if p['flow_id']=='F4' and p['status']=='executable']
    if len(selected)!=1:raise ValueError('compiled-F4-executable-required')
    path=selected[0]
    compile_candidate_layout(path)
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
    policy=_cpu_error_policy(artifacts[cpu.instance_id],image,stream)
    _check_error_assertions(path,policy)
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
        if source['kind']=='external_pin' and source['component']!=access['target_component']:
            raise ValueError('compiled-F4-external-pin-shape-unsupported')
    # Closed producer selection replaces the former GPIO/GPIOEN hard limit.
    binding=select_storage_producer(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)
    expected_pre=[binding.document()['prerequisite']['expected']]
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
    return deepcopy(path),binding


class CompiledF4Runtime:
    """One continuous testcase with live prerequisites and fresh prefix replay."""
    @host_source_discovery_scope()
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f4', rounds_per_case=128, max_cases=64):
        self.path=admit_f4(artifacts=artifacts,compiled_inputs=compiled_inputs,
            base_dir=Path(base_dir))
        self.layout=compile_candidate_layout(self.path)
        self._replay_identities=[]
        if any(type(v) is not int or not 1<=v<=65536 for v in (rounds_per_case,max_cases)):
            raise ValueError('compiled-F4-budget-invalid')
        self._caller_inputs=compiled_inputs;self._caller_artifacts=artifacts
        self._input_digest=_input_identity(compiled_inputs,artifacts)
        self.artifacts,self.inputs=_private_admission_snapshot(artifacts,compiled_inputs,Path(base_dir))
        compiled_inputs=self.inputs;artifacts=self.artifacts
        self.base_dir=Path(base_dir);self.cache_dir=Path(cache_dir);self.run_id=run_id
        self.producer_binding=select_storage_producer(artifacts=artifacts,
            compiled_inputs=compiled_inputs,base_dir=self.base_dir)
        self.row=self.producer_binding.row
        self.register_name=self.producer_binding.document()['register']['name']
        if self.row!=ROW_GPIO_CAUSAL:
            # The generic APB storage row is executable only through its
            # in-row consumer, exact C issuer and complete four receipt joins.
            # Without them this refuses before any constructor or native tick.
            support=storage_consumer_support(binding=self.producer_binding,
                artifacts=artifacts)
            if support['complete'] is not True:
                missing=','.join(row['element'] for row in support['refusals'])
                raise ValueError(
                    'compiled-F4-generic-receipt-join-incomplete:'+missing)
            self.receipt_elements=support
        self.rounds=rounds_per_case;self.max_cases=max_cases;self.records=[];self.finished=False
        self.closure=_closure(base_dir);self.compiled_digest=compiled_document_sha256(compiled_inputs['compiled'])
        request=compiled_inputs['request'];self.cpu_id=request.cpu.instance_id
        self.stream=next(s for s in self.path['sources'] if s['kind']=='cpu_mmio_stream')
        self.access=self.stream['register_access'];self.target_id=self.access['target_component']
        image=next(s for s in self.path['sources'] if s['kind']=='instruction_image')
        self.declared_edges=_f4_edges(compiled_inputs['compiled'],image,self.access)
        self.image=image;self.error_policy=_cpu_error_policy(artifacts[self.cpu_id],image,self.stream)
        self.traces=_cpu_traces(artifacts[self.cpu_id],image,self.stream)
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
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        target,self.authority=build_storage_producer(self.producer_binding,
            artifact=self.artifacts[self.target_id],base_dir=self.base_dir,
            cache_dir=self.cache_dir,max_cases=max_cases)
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
            self._native_processes={name:session.process for name,session in self.runner.sessions.items()}
            self._process_identities={name:dict(component=name,
                role='cpu' if name==self.cpu_id else 'bound_target',pid=proc.pid,
                execution_nonce=self.runner.sessions[name]._execution,
                artifact_digest=self.artifacts[name].runtime_document['artifact_digest'])
                for name,proc in self._native_processes.items()}
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
            compiled_sha256=self.compiled_digest,assertions=self.path['assertions'],
            candidate_layout=_layout_document(self.layout),cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            producer_row=self.producer_binding.row)

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
        if self.row==ROW_GENERIC_APB_STORAGE:
            token=self.authority.issue(register=self.register_name,
                reset_epoch=before['reset_epoch'])
            observed,commit,after=check_storage_observation(declaration,receipt,
                target_artifact=self.artifacts[self.target_id],authority=self.authority,
                token=token,register=self.register_name,
                reset_epoch=before['reset_epoch'],before=before,prior_writes=prior)
        else:
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
            joins=observed['joins'],declared_edges=self.declared_edges,instruction_snapshots=instruction_snapshots,
            error_policy=self.error_policy)
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
        if _cpu_error_policy(self.artifacts[self.cpu_id],self.image,self.stream)!=self.error_policy:
            raise ValueError('compiled-F4-error-policy-identity-changed')
        if compile_candidate_layout(self.path)!=self.layout:
            raise ValueError('compiled-F4-layout-identity-changed')
        path,binding=_admit_f4(artifacts=self.artifacts,compiled_inputs=self.inputs,
            base_dir=self.base_dir)
        if path!=self.path:
            raise ValueError('compiled-F4-admission-changed')
        if binding!=self.producer_binding:
            raise ValueError('compiled-F4-producer-binding-changed')
        if (_closure(self.base_dir)!=self.closure or compiled_document_sha256(self.inputs['compiled'])!=self.compiled_digest
                or _difference(compile_paths(self.inputs['request']),self.inputs['compiled']) is not None):
            raise ValueError('compiled-F4-source-identity-changed')

    def _decode_candidate(self,raw):
        issued=compile_candidate_layout(self.path)
        if type(self.layout) is not CandidateLayout or self.layout!=issued:
            raise ValueError('compiled-F4-layout-identity-changed')
        return issued.decode(raw)

    def execution_audit(self):
        codes={name:proc.poll() for name,proc in self._native_processes.items()}
        return dict(schema_version='compiled_F4_execution_audit.v1',
            identities=deepcopy(self._process_identities),
            exits={name:dict(returncode=code,reaped=code is not None)
                   for name,code in codes.items()},closed=self.finished)

    @host_source_discovery_scope()
    def submit(self, raw):
        """Decode every declared candidate slice before executing any source."""
        self._stable()
        values=self._decode_candidate(raw)
        if len(self.records)>=self.max_cases:raise ValueError('compiled-F4-case-budget-exhausted')
        value=values[self.stream['source_id']]
        declaration=declare_writer(self.inputs['request'],self.inputs['compiled'],
            source_id=self.stream['source_id'],value=value,result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        if self.cursor+len(code)>self.result:raise ValueError('compiled-F4-slot-exhausted')
        external=[s for s in self.path['sources'] if s['kind']=='external_pin']
        for number,source in enumerate(external):
            self._stable()
            pin_value=values[source['source_id']]
            pin_case=OnlineCase(f'{self.run_id}:{len(self.records)}:external:{number}',
                'CPU_TO_IP',self.path['path_id'],BatchSourceEvent(
                    source['source_id']+f':{len(self.records)}',source['component'],
                    source['port'],pin_value,source['bit_offset'],source['width']),
                (BatchAdvance((source['component'],)),))
            pin_receipt=self.session.submit_case(pin_case)
            if pin_receipt.violations:raise ValueError('compiled-F4-external-source-failed')
        before=self.authority.consume(self.authority.issue(reset_epoch=self.runner.sessions[self.target_id].reset_epoch))
        prerequisite=(stable_storage_version(before)
                      if self.row==ROW_GENERIC_APB_STORAGE else before)
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
            prerequisite=prerequisite,commit=commit,postcondition=after,joins=observed['joins'],
            first_fetch=self.first_fetch,exact_hops=observed['exact_hops'],
            assertions=observed['exact_hops']['assertions'],
            runtime_admitted=True)
        self.records.append(dict(raw=raw.hex(),value=value,source_values=values,certificate=certificate))
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
        if any(row['returncode']!=0 for row in self.execution_audit()['exits'].values()):
            raise ValueError('compiled-F4-native-exit-failed')
        # The generic row's C receipts carry the process-local driver execution
        # nonce inside ``apb-storage:<execution>:<n>``.  A fresh replay must be
        # compared on the real chain without that nonce; receipts/events keep
        # their real bytes and are never rewritten.  The GPIO row never
        # produces this id and keeps its exact previous hash.
        semantic_hash=(normalized_semantic_sha256(self.trace.status,
            self.trace.events,self.trace.local_ticks)
            if self.row==ROW_GENERIC_APB_STORAGE else self.trace.semantic_sha256)
        return dict(schema_version='compiled_F4_prefix.v1',run_id=self.run_id,
            compiled_sha256=self.compiled_digest,source_files=self.closure,
            artifact_digests={n:a.runtime_document['artifact_digest'] for n,a in self.artifacts.items()},
            rounds_per_case=self.rounds,max_cases=self.max_cases,records=deepcopy(self.records),
            candidate_layout=_layout_document(self.layout),cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            online_plan=json.loads(self.session.encode_plan()),
            semantic_hash=semantic_hash,feedback=self.feedback())

    @host_source_discovery_scope()
    def replay(self, plan, *, audit_sink=None):
        """Reexecute every candidate, checking live prerequisites anew."""
        self._stable(allow_finished=True)
        expected=self.finish()
        if _difference(expected,plan) is not None:raise ValueError('compiled-F4-prefix-mismatch')
        envelope=dict(scope='full_fresh_prefix_real_RTL_and_live_register_prerequisites',
            original_execution_audit=self.execution_audit())
        try:
            fresh=type(self)(artifacts=self.artifacts,compiled_inputs=self.inputs,
                base_dir=self.base_dir,cache_dir=self.cache_dir,run_id=self.run_id,
                rounds_per_case=self.rounds,max_cases=self.max_cases)
        except BaseException as error:
            envelope.update(error_type=type(error).__name__,error=str(error),
                startup_partial_trace_available=False)
            if audit_sink is not None:audit_sink(deepcopy(envelope))
            raise
        primary_error=None
        try:
            identities=fresh.execution_audit()['identities']
            _check_fresh_identities([self._process_identities]+self._replay_identities,identities)
            self._replay_identities.append(deepcopy(identities))
            for record in plan['records']:fresh.submit(bytes.fromhex(record['raw']))
            actual=fresh.finish()
            envelope.update(_compare_prefixes(expected,actual),actual_prefix=actual)
            return envelope
        except BaseException as error:
            primary_error=error
            envelope.update(error_type=type(error).__name__,error=str(error))
            raise
        finally:
            cleanup_error=None
            if not fresh.finished:
                try:fresh.finish()
                except BaseException as error:
                    cleanup_error=error
                    envelope['cleanup_failure']=dict(error_type=type(error).__name__,error=str(error))
            envelope['execution_audit']=fresh.execution_audit()
            envelope['actual_events']=list(fresh.runner.events_since(0))
            if audit_sink is not None:audit_sink(deepcopy(envelope))
            if cleanup_error is not None and primary_error is None:raise cleanup_error
