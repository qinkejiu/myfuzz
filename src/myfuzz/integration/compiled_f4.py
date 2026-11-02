"""Execute the selected compiled F4 through generated OBI/APB RTL.

This adapter admits one RV32I instruction image and one closed storage producer
row: the source-pinned PULP GPIOEN causal ABI or the registered generic APB
storage ABI (``GeneratedApb3RegisterSession`` with a live
``ApbStorageRegisterVersionAuthority`` token joined to CPU acceptance, Router
delivery, native APB pre/post samples and CPU readback/RAM). Other flows and
producer contracts are explicitly unsupported.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from hashlib import sha256
import json
from functools import wraps
from os.path import relpath
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
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, BoundOnlineInstruction
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from .compiled_candidate_layout import compile_candidate_layout, CandidateLayout, LAYOUT_SCHEMA

_EVENT_REFS_READER = ScenarioRunner._event_refs_since
_EVENT_REFS_CODE = _EVENT_REFS_READER.__code__


def _borrow_exact_events(runner):
    if (type(runner) is not ScenarioRunner or '_event_refs_since' in vars(runner)
            or ScenarioRunner._event_refs_since is not _EVENT_REFS_READER
            or _EVENT_REFS_READER.__code__ is not _EVENT_REFS_CODE):
        raise ValueError('compiled-exact-event-reader-drift')
    return _EVENT_REFS_READER(runner, 0)


def _borrow_events(runner, start=0):
    """Borrow this runner's journal from ``start`` for one synchronous pure read.

    Two cases, and the fallback is deliberate:

    * the exact pinned ``ScenarioRunner`` still owning the sealed
      ``_event_refs_since`` -> its own records, no copy.  The caller must not
      mutate or retain them and must detach every document it keeps.
    * anything else (a replaced instance/class reader, or a fixture runner such
      as ``SimpleNamespace(events_since=...)``) -> that runner's public
      ``events_since(start)``, which keeps its documented detaching semantics.

    Unlike ``_borrow_exact_events`` this is not a strictness check: it raises
    only when the runner can serve neither reader.
    """
    if (type(runner) is ScenarioRunner and '_event_refs_since' not in vars(runner)
            and ScenarioRunner._event_refs_since is _EVENT_REFS_READER
            and _EVENT_REFS_READER.__code__ is _EVENT_REFS_CODE):
        return _EVENT_REFS_READER(runner, start)
    read = getattr(runner, 'events_since', None)
    if not callable(read):
        raise ValueError('compiled-event-reader-unavailable')
    return read(start)

from .compiled_f4_runtime_path import admit_compiled_f4_runtime_path
from .compiled_process_audit import (BuiltProcessAudit,
    diagnostic_build_snapshot as _diagnostic_build_snapshot,
    capture_build_construction as _capture_build_construction)
from .compiled_f4_build_join import built_receipt_sha256, validate_built_receipts
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
            if row['certificate'].get('schema_version') in (
                    'compiled_memory_case.v1','compiled_shared_F5_case.v1'):
                continue
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
    return {relpath(p, root):sha256(p.read_bytes()).hexdigest()
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


@dataclass(frozen=True, slots=True)
class CompiledF4ExecutionBinding:
    """Detached identity for one admitted compiled-F4 execution contract.

    The binding is descriptive, not an authority. Runtime admission still
    rebuilds the current compiled path and source producer before use.
    """

    document_json: str

    def __post_init__(self):
        if type(self) is not CompiledF4ExecutionBinding or type(self.document_json) is not str:
            raise ValueError('compiled-F4-execution-binding-required')
        try:
            document = json.loads(self.document_json)
        except (TypeError, ValueError) as error:
            raise ValueError('compiled-F4-execution-binding-required') from error
        if (type(document) is not dict
                or document.get('schema_version') != 'compiled_F4_execution_binding.v1'
                or document.get('binding_sha256') != _digest(
                    {key: value for key, value in document.items()
                     if key != 'binding_sha256'})):
            raise ValueError('compiled-F4-execution-binding-required')

    @classmethod
    def build(cls, document):
        if type(document) is not dict:
            raise ValueError('compiled-F4-execution-binding-required')
        issued = {key: value for key, value in document.items()
                  if key != 'binding_sha256'}
        issued['binding_sha256'] = _digest(issued)
        return cls(json.dumps(issued, sort_keys=True, separators=(',', ':')))

    def document(self):
        return json.loads(self.document_json)

    @property
    def digest(self):
        return self.document()['binding_sha256']


def _artifact_execution_identity(artifact):
    from myfuzz.local_harness.generated_artifact_admission import _artifact_files

    profile = artifact.plan.profile
    source = profile.source
    generated_files = {name: sha256(contents).hexdigest()
                       for name, contents in sorted(_artifact_files(artifact).items())}
    return dict(instance_id=artifact.plan.request.instance_id,
        component_id=profile.component_id,
        artifact_kind=artifact.runtime_document.get('kind'),
        artifact_digest=artifact.runtime_document.get('artifact_digest'),
        generated_files_sha256=generated_files,
        generated_artifact_bytes_sha256=_digest(generated_files),
        profile_fingerprint=profile.profile_fingerprint,
        source_root=source.source_root, source_revision=source.revision,
        source_top_module=source.top_module,
        source_verification_sha256=_digest(artifact.source_verification))


def _execution_binding_document(*, artifacts, compiled_inputs, path, layout,
                                cpu_error_policy, producer_binding, base_dir,
                                source_closure=None, compiled_sha256=None,
                                cpu_traces=None, runtime_path_admission=None, built_receipts=None):
    request = compiled_inputs['request']
    image = next(source for source in path['sources']
                 if source['kind'] == 'instruction_image')
    stream = next(source for source in path['sources']
                  if source['kind'] == 'cpu_mmio_stream')
    access = stream['register_access']
    cpu_id = request.cpu.instance_id
    target_id = access['target_component']
    producer = producer_binding.document()
    windows = [window for window in request.wiring.windows
               if window.device_id == access['device_id']]
    if len(windows) != 1:
        raise ValueError('compiled-F4-execution-window-ambiguous')
    window = windows[0]
    if (window.target_instance != target_id or window.base != access['window_base']
            or window.size != access['window_size']):
        raise ValueError('compiled-F4-execution-window-mismatch')
    cpu_artifact = artifacts[cpu_id]
    cpu_traces = (_cpu_traces(cpu_artifact, image, stream)
                  if cpu_traces is None else cpu_traces)
    cpu_identity = dict(instance_id=cpu_id,
        profile_fingerprint=cpu_artifact.plan.profile.profile_fingerprint,
        xlen=cpu_artifact.plan.profile.cpu.xlen,
        extensions=list(cpu_artifact.plan.profile.cpu.extensions),
        runtime_kind=cpu_artifact.runtime_document.get('kind'),
        error_policy=deepcopy(cpu_error_policy),
        trace_contract=cpu_traces,
        trace_contract_sha256=_digest(cpu_traces))
    source = producer.get('source', {})
    target = dict(component=target_id, artifact_kind=producer.get('target_artifact_kind'),
        endpoint_id=producer.get('endpoint_id'), protocol=producer.get('protocol'),
        template=producer.get('template'),
        window=dict(device_id=window.device_id, target_instance=window.target_instance,
            base=window.base, size=window.size,
            register_address=access['address'],
            register_offset=access['register_offset']),
        source_contract_id=source.get('contract_id'),
        source_contract_digest=source.get('contract_digest'),
        producer_binding_sha256=producer_binding.digest)
    assertions = deepcopy(path['assertions'])
    prerequisites = deepcopy(path['prerequisites'])
    admission = (admit_compiled_f4_runtime_path(request=request,
        compiled=compiled_inputs['compiled'], path=path)
        if runtime_path_admission is None else runtime_path_admission)
    admission.validate_cached_identity()
    body = dict(schema_version='compiled_F4_execution_binding.v1',
        path_id=path['path_id'],
        runtime_path_id=admission.runtime_path_id,
        runtime_contract_sha256=admission.prepared.contract.identity_sha256,
        runtime_path_admission=admission.document(),
        runtime_path_admission_sha256=admission.digest,
        selected_path_sha256=_digest(path),
        compiled_document_sha256=(compiled_document_sha256(compiled_inputs['compiled'])
            if compiled_sha256 is None else compiled_sha256),
        request_sha256=_digest(request.document),
        artifact_identities={name: _artifact_execution_identity(artifacts[name])
                             for name in sorted(artifacts)},
        cpu=cpu_identity,
        candidate_layout=_layout_document(layout),
        target=target,
        producer_binding=producer,
        prerequisites=prerequisites,
        prerequisites_sha256=_digest(prerequisites),
        assertions=assertions,
        assertions_sha256=_digest(assertions),
        ownership_sha256=_digest(compiled_inputs['ownership'].document()),
        physical_port_map_sha256=_digest(sorted(
            (list(key), value) for key, value in compiled_inputs['physical_port_map'].items())),
        executor_source_closure_sha256=_digest(
            _closure(base_dir) if source_closure is None else source_closure))
    if built_receipts is not None:
        validate_built_receipts(artifacts, built_receipts)
        body['built_executable_receipts'] = deepcopy(built_receipts)
        body['built_executable_receipts_sha256'] = built_receipt_sha256(built_receipts)
    return body


def derive_f4_execution_binding(*, artifacts, compiled_inputs, base_dir=None):
    """Re-admit inputs and derive their canonical F4 execution identity.

    This document never grants runtime admission by itself; the live runtime
    calls the same admission path and compares the rebuilt identity.
    """
    path, producer_binding = _admit_f4(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    layout = compile_candidate_layout(path)
    image = next(source for source in path['sources']
                 if source['kind'] == 'instruction_image')
    stream = next(source for source in path['sources']
                  if source['kind'] == 'cpu_mmio_stream')
    cpu_policy = _cpu_error_policy(
        artifacts[compiled_inputs['request'].cpu.instance_id], image, stream)
    body = _execution_binding_document(artifacts=artifacts,
        compiled_inputs=compiled_inputs, path=path, layout=layout,
        cpu_error_policy=cpu_policy, producer_binding=producer_binding,
        base_dir=base_dir)
    return CompiledF4ExecutionBinding.build(body)


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


def check_f4_exact_hops(*, events, declaration, image, stream, traces, address, source_event_id, joins, declared_edges, instruction_snapshots, ram_event_id, error_policy=None, proof_scope=None, readback_value=None):
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
                or (not delivery['write'] and beat['rdata']!=(declaration['candidate']['value'] if readback_value is None else readback_value))
                or not accept['event_id']<delivery['event_id']<beat['response_event']):
            raise ValueError('compiled-F4-native-data-route-hop-missing')
        data_hops.append(dict(join,native_acceptance_event=beat['acceptance_event'],
            native_response_event=beat['response_event'],native_obi=dict(beat)))
    # SW and LW fetches must precede their actual data requests.
    if (instruction_hops[4]['response_event']>=data_hops[0]['native_acceptance_event']
            or instruction_hops[5]['response_event']>=data_hops[1]['native_acceptance_event']):
        raise ValueError('compiled-F4-instruction-data-order')
    result_address=declaration.get('result_address')
    candidate=declaration.get('candidate')
    value=(candidate.get('value') if isinstance(candidate,dict) else None) if readback_value is None else readback_value
    memory_range=image.get('range')
    if (not isinstance(memory_range,(list,tuple)) or len(memory_range)!=2
            or any(type(bound) is not int for bound in memory_range)
            or not 0<=memory_range[0]<=memory_range[1]<1<<32
            or type(result_address) is not int or result_address< memory_range[0]
            or result_address+3>memory_range[1] or result_address%4
            or type(value) is not int or not 0<=value<=0xffffffff
            or type(ram_event_id) is not int):
        raise ValueError('compiled-F4-result-RAM-hop-missing')
    ram_event=by_id.get(ram_event_id)
    if (not isinstance(ram_event,dict) or ram_event.get('kind')!='memory_write'
            or ram_event.get('component')!=cpu
            or ram_event.get('memory_id')!=image.get('port')
            or ram_event.get('address')!=result_address
            or ram_event.get('value')!=value
            or ram_event.get('byte_enable')!=15
            or ram_event.get('width_bytes')!=4
            or type(ram_event.get('generation')) is not int
            or ram_event['generation']<0
            or type(ram_event.get('byte_offset')) is not int
            or ram_event['byte_offset']!=result_address-memory_range[0]):
        raise ValueError('compiled-F4-result-RAM-hop-missing')
    version=ram_event.get('version')
    if (not isinstance(version,(list,tuple)) or len(version)!=2
            or any(type(item) is not int or item<0 for item in version)
            or version[0]!=ram_event['generation'] or version[1]<1):
        raise ValueError('compiled-F4-result-RAM-version-mismatch')
    transaction=ram_event.get('transaction')
    if _transaction_key(transaction) is None:
        raise ValueError('compiled-F4-result-RAM-transaction-mismatch')
    read_transaction=data_hops[1]['source_transaction']
    if (transaction.get('channel_id')!='data'
            or transaction.get('source_component')!=cpu
            or transaction.get('source_epoch')!=0
            or any(transaction.get(key)!=read_transaction.get(key)
                   for key in ('execution_id','testcase_id','source_component',
                               'source_epoch'))
            or transaction.get('source_sequence')
            !=read_transaction.get('source_sequence',-1)+1):
        raise ValueError('compiled-F4-result-RAM-transaction-mismatch')
    ram_beat=completed.get(('data',transaction['source_sequence']))
    read_beat=data_hops[1]['native_obi']
    if (ram_beat is None or ram_beat['write']!=1
            or ram_beat['address']!=result_address or ram_beat['value']!=value
            or ram_beat['byte_enable']!=15
            or ram_event.get('producer_event_id')!=ram_beat['acceptance_event']
            or ram_beat['acceptance_event']<=read_beat['response_event']
            or not ram_beat['acceptance_event']<ram_event_id<ram_beat['response_event']):
        raise ValueError('compiled-F4-result-RAM-native-hop-missing')
    ram_write_hop=dict(memory_write_event=ram_event_id,
        producer_event_id=ram_event['producer_event_id'],
        memory_id=ram_event['memory_id'],generation=ram_event['generation'],
        byte_offset=ram_event['byte_offset'],width_bytes=ram_event['width_bytes'],
        address=ram_event['address'],value=ram_event['value'],
        byte_enable=ram_event['byte_enable'],version=list(version),
        transaction=deepcopy(transaction),
        native_acceptance_event=ram_beat['acceptance_event'],
        native_response_event=ram_beat['response_event'],native_obi=dict(ram_beat))
    return dict(schema_version='compiled_F4_exact_hops.v2',
        proof_scope=(proof_scope or
            'selected_F4_image_consumption_native_OBI_route_native_APB_live_register_version_result_RAM'),
        cpu_error_policy=deepcopy(error_policy),
        instruction_hops=instruction_hops,data_hops=data_hops,
        ram_write_hop=ram_write_hop,
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
    # Generic compiled-artifact admission also serves D3 flows whose fixed
    # composition inputs have an explicit owner.  The compiled-F4 executor has
    # no such ownership identity, so refuse composition-level constants here,
    # at the executor-specific admission boundary. D2 artifact-level fixed
    # physical pins remain supported and are included in the artifact identity.
    wiring=getattr(request,'wiring',None)
    typed_fixed=getattr(wiring,'fixed_inputs',None)
    if type(typed_fixed) is not tuple:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/fixed_inputs',
            {'requires':'a typed tuple of composition fixed inputs'})
    wiring_document=getattr(wiring,'document',None)
    if not isinstance(wiring_document,Mapping):
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/document',
            {'requires':'the parsed wiring document'})
    raw_fixed=wiring_document.get('fixed_inputs',[])
    if type(raw_fixed) is not list:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/document/fixed_inputs',
            {'requires':'a list of composition fixed inputs'})
    if typed_fixed:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-fixed-input-unsupported',
            '/request/wiring/fixed_inputs',
            {'requires':'compiled-F4 does not bind composition wiring constants',
             'rows':typed_fixed})
    if raw_fixed:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-fixed-input-unsupported',
            '/request/wiring/document/fixed_inputs',
            {'requires':'compiled-F4 does not bind composition wiring constants',
             'rows':raw_fixed})
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
    if (request.wiring.deliveries
            or any(o['kind']=='bound' for o in compiled_inputs['ownership'].document()['owners'])):
        from .shared_f5_runtime import admit_shared_f5_declaration
        admit_shared_f5_declaration(artifacts=artifacts,compiled_inputs=compiled_inputs)
    return deepcopy(path),binding


class CompiledF4Runtime(BuiltProcessAudit):
    """One continuous testcase with live prerequisites and fresh prefix replay."""
    _audit_error_prefix = 'compiled-F4'
    _audit_schema = 'compiled_F4_execution_audit.v1'
    @host_source_discovery_scope()
    @_capture_build_construction
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f4', rounds_per_case=128, max_cases=64,
                 expected_built_receipts=None, build_audit_sink=None,
                 defer_begin=False, mixed_flows=False, memory_flows=False,
                 f5_preparation=None, irq_firmware=False):
        if f5_preparation is not None and not mixed_flows:
            raise ValueError('shared-F5-mixed-runtime-required')
        if f5_preparation is None and compiled_inputs['request'].wiring.deliveries:
            raise ValueError('shared-F5-live-preparation-required')
        if type(irq_firmware) is not bool or irq_firmware and f5_preparation is None:
            raise ValueError('shared-IRQ-explicit-F5-preparation-required')
        self._irq_firmware_enabled=irq_firmware
        self.irq_firmware=None;self.irq_bootstrap=None
        self._f5_preparation = f5_preparation
        self.path=admit_f4(artifacts=artifacts,compiled_inputs=compiled_inputs,
            base_dir=Path(base_dir))
        self.layout=compile_candidate_layout(self.path)
        self._replay_identities=[]
        if any(type(v) is not int or not 1<=v<=65536 for v in (rounds_per_case,max_cases)):
            raise ValueError('compiled-F4-budget-invalid')
        if type(defer_begin) is not bool:
            raise ValueError('compiled-F4-defer-begin-invalid')
        if type(mixed_flows) is not bool:
            raise ValueError('compiled-storage-mixed-flag-invalid')
        if type(memory_flows) is not bool or memory_flows and not mixed_flows:
            raise ValueError('compiled-memory-shared-flows-invalid')
        self._mixed_flows = mixed_flows
        self._f2_flows = mixed_flows and (f5_preparation is None or 'F2' in f5_preparation.flow_ids)
        self._memory_flows = memory_flows
        self._caller_inputs=compiled_inputs;self._caller_artifacts=artifacts
        self._input_digest=_input_identity(compiled_inputs,artifacts)
        self.artifacts,self.inputs=_private_admission_snapshot(artifacts,compiled_inputs,Path(base_dir))
        compiled_inputs=self.inputs;artifacts=self.artifacts
        self.base_dir=Path(base_dir);self.cache_dir=Path(cache_dir);self.run_id=run_id
        self.runtime_path_admission=admit_compiled_f4_runtime_path(
            request=compiled_inputs['request'], compiled=compiled_inputs['compiled'],
            path=self.path)
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
        self.attempts=[];self._failed_attempt=None
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
        from myfuzz.isa.constraints import f1_isa_from_profile
        instruction_isa = f1_isa_from_profile(artifacts[self.cpu_id].plan.profile)
        memory=PersistentMemory(regions=tuple(MemoryRegion(r.resource_id,r.base,r.size,
            readable=r.read,writable=r.write) for r in resources), initialization_seed=0,
            max_initialized_bytes=sum(r.size for r in resources),
            instruction_isa=instruction_isa if len(instruction_isa.extensions) > 1 else None)
        self.instruction_isa=memory.instruction_isa
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        target,self.authority=build_storage_producer(self.producer_binding,
            artifact=self.artifacts[self.target_id],base_dir=self.base_dir,
            cache_dir=self.cache_dir,max_cases=max_cases)
        windows=tuple(DeviceWindow(w.device_id,w.base,w.size,target) for w in request.wiring.windows)
        if any(w.target_instance!=self.target_id for w in request.wiring.windows):
            raise ValueError('compiled-F4-router-target-unsupported')
        cpu_class=GeneratedCve2Session;cpu_options={}
        if self._f5_preparation is not None:
            from .shared_f5_runtime import (PhysicalIrqCpuSession,
                admit_shared_f5_declaration, prepare_shared_f5)
            cpu_class=PhysicalIrqCpuSession
            cpu_options['native_irq_receipts']=self._irq_firmware_enabled
            cpu_options['irq_input_port']=admit_shared_f5_declaration(
                artifacts=self.artifacts,compiled_inputs=self.inputs)
        cpu=cpu_class(artifacts[self.cpu_id],base_dir=self.base_dir,cache_dir=self.cache_dir,
            memory=memory,router=DataflowRouter(windows),defer_mmio=True,
            memory_commit_receipts=self._memory_flows,
            memory_readback_receipts=self._memory_flows,**cpu_options)
        runner_ownership=compiled_inputs['ownership'];bindings=();irq_pulses=None
        if self._f5_preparation is not None:
            self.f5_binding=prepare_shared_f5(preparation=self._f5_preparation,
                artifacts=self.artifacts,compiled_inputs=self.inputs,
                cpu_id=self.cpu_id,target_id=self.target_id,cpu=cpu,target=target)
            if getattr(self,'_irq_firmware_enabled',False):
                from .shared_irq_firmware import admit_irq_firmware,build_irq_firmware,expected_boot_fetch
                self._irq_firmware_parameters=admit_irq_firmware(self)
                self.irq_firmware=build_irq_firmware(**self._irq_firmware_parameters,first_fetch=expected_boot_fetch(self))
            runner_ownership=self.f5_binding.ownership
            bindings=(self.f5_binding.binding,);irq_pulses={self.f5_binding.binding:4}
        self.runner=ScenarioRunner(sessions={self.cpu_id:cpu,self.target_id:target},
            ownership=runner_ownership,bindings=bindings,irq_pulses=irq_pulses)
        if self._f5_preparation is not None:
            self.f5_crosswalk=self.f5_binding.validate(self.runner)
        if self._memory_flows:
            from myfuzz.runtime.flows.memory import install_memory_feedback
            install_memory_feedback(self.runner, cpu_id=self.cpu_id,
                runtime_contract_sha256=self.runtime_path_admission.prepared.contract.identity_sha256)
        self._build_sessions = dict(self.runner.sessions)
        for name, local in sorted(self._build_sessions.items()):
            local.configure_built_executable_receipt()
            local.prepare_local()
        self._built_receipts = {name:local.validate_built_executable_receipt()
                                for name,local in sorted(self._build_sessions.items())}
        validate_built_receipts(self.artifacts, self._built_receipts)
        if (expected_built_receipts is not None
                and _semantic_canonical(expected_built_receipts) != _semantic_canonical(self._built_receipts)):
            raise ValueError('compiled-F4-built-receipt-identity-mismatch')
        execution_binding_document=_execution_binding_document(
            artifacts=artifacts, compiled_inputs=compiled_inputs,
            path=self.path, layout=self.layout,
            cpu_error_policy=self.error_policy,
            producer_binding=self.producer_binding, base_dir=self.base_dir,
            source_closure=self.closure,
            compiled_sha256=self.compiled_digest, cpu_traces=self.traces,
            runtime_path_admission=self.runtime_path_admission,
            built_receipts=self._built_receipts)
        self.execution_binding=CompiledF4ExecutionBinding.build(
            execution_binding_document)
        if self._f2_flows:
            self._setup_mixed_flows(compiled_inputs=compiled_inputs)
        if self._memory_flows:
            from myfuzz.runtime.flows.memory import prepare_memory_paths
            self.memory_prepared, memory_bindings = prepare_memory_paths(
                request=self.inputs['request'], compiled=self.inputs['compiled'])
            self.memory_bindings = {binding.source_id.split('.')[0]: binding
                                    for binding in memory_bindings}
        fixed_images=()
        if getattr(self,'_irq_firmware_enabled',False):
            from .shared_irq_firmware import firmware_images
            fixed_images=firmware_images(self,self.irq_firmware)
        template=ScenarioGenome(run_id,'CPU_TO_IP',self.runtime_path_admission.runtime_path_id,tuple(self.runner.sessions),
            max(rounds_per_case*max_cases*2,8192) if getattr(self,'_irq_firmware_enabled',False) else rounds_per_case*max_cases*2,(),initial_images=fixed_images)
        self._pending=None;self._checked=None
        self.session=ScenarioSession(template,self.runner,checker=self._check_receipt,
            checker_configuration_only=True)
        # Retain exact source bytes; every future slot remains unmaterialized.
        if getattr(self,'_irq_firmware_enabled',False):
            self.session.declare_instruction_slots(self.cpu_id,self.start+0x1000,(self.result-self.start-0x1000)//4)
        else:
            self.session.declare_instruction_slots(self.cpu_id,self.start,(self.result-self.start)//4)
        prepared=self.runtime_path_admission.prepared
        if self._mixed_flows:
            paths=prepared.runtime_paths
            if self._f2_flows:
                prepared_f2=self.runtime_path_admission_f2.prepared
                if (_semantic_canonical(prepared_f2.graph.edge_document())
                    != _semantic_canonical(prepared.graph.edge_document())
                    or _semantic_canonical(prepared_f2.contract.document())
                    != _semantic_canonical(prepared.contract.document())):
                    raise ValueError('compiled-storage-mixed-graph-mismatch')
                paths=self._mixed_runtime_paths(prepared.runtime_paths,
                                            prepared_f2.runtime_paths)
            if self._f5_preparation is not None:
                paths=self._mixed_runtime_paths(paths,self.f5_binding.prepared.runtime_paths)
            if self._memory_flows:
                if (_semantic_canonical(self.memory_prepared.graph.edge_document())
                        != _semantic_canonical(prepared.graph.edge_document())
                        or _semantic_canonical(self.memory_prepared.contract.document())
                        != _semantic_canonical(prepared.contract.document())):
                    raise ValueError('compiled-memory-shared-graph-mismatch')
                paths=self._mixed_runtime_paths(paths, self.memory_prepared.runtime_paths)
            from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
            instruction_bindings=(self.runtime_path_admission.instruction_binding,)
            if self._f2_flows:
                instruction_bindings += (self.runtime_path_admission_f2.instruction_binding,)
            if self._memory_flows:
                instruction_bindings += tuple(self.memory_bindings[flow] for flow in ('F1', 'F3'))
            self.session.configure_runtime_paths(prepared.graph, prepared.contract,
                paths, source_ownership=compiled_inputs['ownership'],
                instruction_image_bindings=instruction_bindings)
            self._mixed_contract=prepared.contract
            self._mixed_declaration=PreparedRuntimePathContract(
                prepared.graph, prepared.contract, paths).document()
            self._mixed_binding_docs=tuple(binding.document() for binding in instruction_bindings)
        else:
            self.session.configure_runtime_paths(prepared.graph, prepared.contract,
                prepared.runtime_paths, source_ownership=compiled_inputs['ownership'],
                instruction_image_bindings=(self.runtime_path_admission.instruction_binding,))
        if getattr(self,'_irq_firmware_enabled',False):
            self.runner.configure_gpio_irq_dependency_evidence(source_component=self.target_id,
                target_component=self.cpu_id,pin=self._irq_firmware_parameters['pin'],
                runtime_contract_sha256=self._mixed_contract.identity_sha256)
        self._deferred_begin = bool(defer_begin)
        self._begun = False
        if not defer_begin:
            self.begin()

    def begin(self):
        """Begin the single native session; the constructor does this unless deferred.

        Deferring lets a caller bind its process-local execution plan to these
        exact runner/session objects *before* ``ScenarioSession.begin`` and the
        native bootstrap.  Every other construction step already happened.
        """
        if self._begun:
            raise ValueError('compiled-F4-already-begun')
        try:
            self._stable()
            self.session.begin()
            self._native_processes={name:session.process for name,session in self.runner.sessions.items()}
            self._process_identities = self._validated_build_process_identities()
            startup_build = _diagnostic_build_snapshot(self)
            if self._build_audit_sink is not None:
                self._build_audit_sink(startup_build)
            self.session.advance_initial((self.target_id,))
            self.authority.consume(
                self._issue_register_version(reset_epoch=0))
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
            if getattr(self,'_irq_firmware_enabled',False):
                from .shared_irq_firmware import advance_irq_bootstrap
                advance_irq_bootstrap(self)
            self._begun = True
        except BaseException as error:
            if self.session._begun and not self.session._finished:
                try:self.session.finish()
                except BaseException as cleanup:error.add_note('compiled-F4 session cleanup: '+repr(cleanup))
            if getattr(self, '_build_audit_sink', None) is not None:
                try:self._build_audit_sink(_diagnostic_build_snapshot(self, closed=True, error=error))
                except BaseException as audit_error:error.add_note('compiled-F4 partial build audit: '+repr(audit_error))
            raise


    # ------------------------------------------------------------------
    # Mixed F2+F4 support: one CPU/IP/memory/runner/session, two flow kernels
    # ------------------------------------------------------------------
    @staticmethod
    def _mixed_runtime_paths(first, second):
        rows=[];seen=set()
        for row in (*first, *second):
            direction,path=row
            key=(direction,path.target)
            if key in seen:continue
            seen.add(key);rows.append((direction,path))
        return tuple(rows)

    def _setup_mixed_flows(self, *, compiled_inputs):
        from .compiled_f2 import (_admit_f2, _cpu_policy as _f2_cpu_policy,
            _cpu_traces as _f2_cpu_traces,
            _execution_binding_document as _f2_binding_document,
            _f2_edges, CompiledF2ExecutionBinding)
        from .compiled_f2_runtime_path import admit_compiled_f2_runtime_path
        from .compiled_f2_layout import compile_f2_candidate_layout
        from .compiled_f2_consumer import select_f2_read_producer
        path,producer=_admit_f2(artifacts=self.artifacts,
            compiled_inputs=self.inputs,base_dir=self.base_dir)
        self.path_f2=path
        self.layout_f2=compile_f2_candidate_layout(path)
        self.producer_binding_f2=producer
        self.runtime_path_admission_f2=admit_compiled_f2_runtime_path(
            request=self.inputs['request'],compiled=self.inputs['compiled'],path=path)
        self.stream_f2=next(s for s in path['sources'] if s['kind']=='cpu_load_stream')
        self.access_f2=self.stream_f2['register_access']
        image_f2=next(s for s in path['sources'] if s['kind']=='instruction_image')
        if (self.access_f2['target_component']!=self.target_id
                or self.access_f2['source_component']!=self.cpu_id
                or image_f2['source_id']!=self.image['source_id']):
            raise ValueError('compiled-storage-mixed-target-mismatch')
        register_f2=self.producer_binding_f2.document()['register']['name']
        if register_f2!=self.register_name and not (
                self.row==ROW_GPIO_CAUSAL and self.register_name=='GPIOEN' and register_f2=='PADIN'
                and self.access_f2['register_offset']==8):
            raise ValueError('compiled-storage-mixed-register-mismatch')
        self.register_f2=register_f2
        if (image_f2['range'][0]!=self.start
                or image_f2['range'][1]+1!=self.end):
            raise ValueError('compiled-storage-mixed-image-mismatch')
        self.image_f2=image_f2
        self.declared_edges_f2=_f2_edges(self.inputs['compiled'],image_f2,
                                         self.access_f2)
        self.error_policy_f2=_f2_cpu_policy(self.artifacts[self.cpu_id],
                                            image_f2,self.stream_f2)
        self.traces_f2=_f2_cpu_traces(self.artifacts[self.cpu_id],image_f2,
                                      self.stream_f2)
        body=_f2_binding_document(artifacts=self.artifacts,
            compiled_inputs=self.inputs,path=path,layout=self.layout_f2,
            producer_binding=self.producer_binding_f2,base_dir=self.base_dir,
            source_closure=self.closure,
            runtime_path_admission=self.runtime_path_admission_f2,
            built_receipts=self._built_receipts)
        self.execution_binding_f2=CompiledF2ExecutionBinding.build(body)

    def _submit_f2(self, raw):
        """F2 read case on the shared CPU/target/memory/session."""
        from .compiled_f2_consumer import capture_f2_read_version
        from .compiled_f2_layout import compile_f2_candidate_layout
        from .generated_register_reader import declare_reader
        from myfuzz.scenario.source_actions import ip_register_prerequisite
        if self._failed_attempt is not None:
            raise ValueError('compiled-storage-mixed-failed-attempt:'+self._failed_attempt)
        self._stable()
        issued=compile_f2_candidate_layout(self.path_f2)
        if self.layout_f2!=issued:
            raise ValueError('compiled-F2-layout-identity-changed')
        if type(raw) is not bytes or len(raw)!=self.layout_f2.byte_length:
            raise ValueError('compiled-F2-candidate-record-length')
        selection=self.layout_f2.classify(raw)
        if not selection.accepted:
            raise ValueError('compiled-F2-candidate-'+str(selection.reason))
        address=selection.address
        if len(self.records)>=self.max_cases:
            raise ValueError('compiled-storage-mixed-case-budget-exhausted')
        declaration=declare_reader(self.inputs['request'],self.inputs['compiled'],
            source_id=self.stream_f2['source_id'],address=address,
            result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        if self.cursor+len(code)>self.result-(4 if getattr(self, '_memory_flows', False) else 0):
            raise ValueError('compiled-F2-slot-exhausted')
        target=self.runner.sessions[self.target_id]
        before=capture_f2_read_version(self.authority,register=self.register_f2,
            reset_epoch=target.reset_epoch)
        pre=before.document();prior=pre['write_count']
        index=len(self.records);case_id=f'{self.run_id}:{index}'
        case=OnlineCase(case_id,'CPU_TO_IP',
            self.runtime_path_admission_f2.runtime_path_id,
            BoundOnlineInstruction(self.image_f2['source_id']+f':{index}',
                self.cpu_id,self.cursor,code.hex(),
                self.runtime_path_admission_f2.instruction_binding.source_id),
            tuple(BatchAdvance(tuple(self.runner.sessions)) for _ in range(self.rounds)))
        self._stable()
        self._pending=('F2',declaration,before,prior);self._checked=None
        self._attempt=dict(case_id=case_id,raw=raw.hex(),value=address,
            instruction_address=self.cursor,assertions={})
        try:
            receipt=self.session.submit_case(case)
            if receipt.violations or self._checked is None or receipt.status!='running':
                raise ValueError('compiled-F2-protocol-checker-failed:'+
                    str(receipt.violations))
            observed,after,exact=self._checked
            data_hop=exact['data_hops'][0]
            from .compiled_f2_consumer import stable_f2_read_version
            actual_before=observed['version_before']
            prerequisite=ip_register_prerequisite(self.target_id,self.register_f2,
                actual_before['reset_epoch'],data_hop['native_APB_event'],
                actual_before['field_version']).document()
            certificate=dict(schema_version='compiled_F2_chain.v1',status='certified',
                path_id=self.path_f2['path_id'],source_id=self.stream_f2['source_id'],
                case_id=case_id,instruction_source_id=self.image_f2['source_id'],
                instruction_address=self.cursor,
                instruction_sha256=sha256(code).hexdigest(),
                prerequisite=prerequisite,
                postcondition=stable_f2_read_version(after),
                version_before=stable_f2_read_version(actual_before),
                version_witness=stable_f2_read_version(observed['version_witness']),
                **({'native_read':deepcopy(observed['actual_read'])} if 'actual_read' in observed else {}),
                joins=observed['joins'],first_fetch=self.first_fetch,
                exact_hops=exact,
                assertions=[
                    dict(expectation_id='protocol_checker.receipt_violations',
                        status='passed',
                        evidence=dict(violations=list(receipt.violations))),
                    dict(expectation_id='cross_component.declared_edge_hops',
                        status='passed',evidence=dict(
                            edge_ids=[[edge['rule_index'],
                                edge['prerequisite_index']] for edge in exact['edges']],
                            roles=[edge['role'] for edge in exact['edges']],
                            endpoints=[[edge['source_component'],
                                edge['target_component']] for edge in exact['edges']],
                            transaction=deepcopy(data_hop['source_transaction']),
                            instruction_source_id=self.image_f2['source_id'],
                            native_read_APB_event=data_hop['native_APB_event'],
                            native_read_OBI_events=[
                                data_hop['native_acceptance_event'],
                                data_hop['native_response_event']],
                            dependent_RAM_write_event=
                                exact['ram_write_hop']['memory_write_event']))],
                execution_binding_sha256=self.execution_binding_f2.digest,
                runtime_path_id=self.runtime_path_admission_f2.runtime_path_id,
                runtime_path_admission_sha256=self.runtime_path_admission_f2.digest,
                runtime_admitted=True)
            record=dict(raw=raw.hex(),value=address,
                source_values={self.stream_f2['source_id']:address},
                certificate=certificate,flow='F2')
            self.records.append(record)
            self.cursor+=len(code)
            return deepcopy(certificate)
        except BaseException as error:
            self._failed_attempt=f'{self.run_id}:{index}'
            raise
        finally:
            self._pending=None;self._checked=None;self._attempt=None

    def _check_chain_f2(self, receipt, declaration, before, prior):
        from .compiled_f2_consumer import check_f2_read_observation
        from .native_obi_hops import check_f2_exact_hops
        token=self.authority.issue(register=self.register_f2,
            reset_epoch=before.document()['reset_epoch'])
        observed,after=check_f2_read_observation(declaration,receipt,
            target_artifact=self.artifacts[self.target_id],
            authority=self.authority,token=token,before=before,
            register=self.register_f2,
            reset_epoch=before.document()['reset_epoch'],prior_writes=prior)
        memory=self.runner.sessions[self.cpu_id].memory
        instruction_snapshots=[memory.read(self.cursor+offset,4,
            transaction_id=f'compiled-storage-mixed-check:{len(self.records)}:{offset}')
            for offset in range(0,32,4)]
        result_snapshot=memory.read(self.result,4,
            transaction_id=f'compiled-storage-mixed-result:{len(self.records)}')
        exact=deepcopy(check_f2_exact_hops(events=_borrow_exact_events(self.runner),
            declaration=declaration,image=self.image_f2,stream=self.stream_f2,
            traces=self.traces_f2,address=self.cursor,
            source_event_id=self.image_f2['source_id']+f':{len(self.records)}',
            joins=observed['joins'],declared_edges=self.declared_edges_f2,
            instruction_snapshots=instruction_snapshots,
            ram_event_id=observed['RAM_event'],error_policy=self.error_policy_f2,
            proof_scope=('selected_F2_image_consumption_native_OBI_route_native_APB_'
                f'live_{self.register_f2}_mixed_result_RAM'),
            result_snapshot=result_snapshot))
        return observed,after,exact

    def _issue_register_version(self, *, reset_epoch):
        return self.authority.issue(register=self.register_name,
            reset_epoch=reset_epoch)

    def online_identity_configuration(self):
        return dict(schema_version='compiled_F4_checker.v2',path_id=self.path['path_id'],
            **(dict(irq_firmware_parameters=deepcopy(self._irq_firmware_parameters)) if getattr(self,'_irq_firmware_enabled',False) else {}),
            compiled_sha256=self.compiled_digest,assertions=self.path['assertions'],
            candidate_layout=_layout_document(self.layout),cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            producer_row=self.producer_binding.row,
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest)

    def _check_receipt(self, receipt):
        if receipt.violations:
            self._checked=None
            return tuple(receipt.violations)
        if self._pending is None:
            return tuple(receipt.violations)
        flow,declaration,before,prior=self._pending
        try:
            if flow=='F2':
                observed,after,exact=self._check_chain_f2(receipt,declaration,
                                                          before,prior)
                self._checked=(observed,after,exact)
            else:
                observed,commit,after=self._check_chain(receipt,declaration,
                                                        before,prior)
                self._checked=(observed,commit,after)
            return tuple(receipt.violations)
        except ValueError as error:
            self._checked=None
            return (str(error),)

    def _check_chain(self,receipt,declaration,before,prior):
        if self.row==ROW_GENERIC_APB_STORAGE:
            token=self._issue_register_version(
                reset_epoch=before['reset_epoch'])
            observed,commit,after=check_storage_observation(declaration,receipt,
                target_artifact=self.artifacts[self.target_id],authority=self.authority,
                token=token,register=self.register_name,
                reset_epoch=before['reset_epoch'],before=before,prior_writes=prior)
        else:
            from .gpio_write_consumer import check_gpio_write_observation
            observed,commit,after=check_gpio_write_observation(declaration,receipt,
                target_artifact=self.artifacts[self.target_id],authority=self.authority,
                access=self.access,target_component=self.target_id,register=self.register_name,
                reset_epoch=before['reset_epoch'],before=before,prior_writes=prior)
        instruction_snapshots=[self.runner.sessions[self.cpu_id].memory.read(self.cursor+offset,4,
            transaction_id=f'compiled-F4-check:{len(self.records)}:{offset}') for offset in range(0,32,4)]
        observed['exact_hops']=deepcopy(check_f4_exact_hops(events=_borrow_exact_events(self.runner),
            declaration=declaration,image=self.image,stream=self.stream,traces=self.traces,
            address=self.cursor,source_event_id=self.image['source_id']+f':{len(self.records)}',
            joins=observed['joins'],declared_edges=self.declared_edges,instruction_snapshots=instruction_snapshots,
            ram_event_id=observed['RAM_event'],
            error_policy=self.error_policy,
            proof_scope=(f'selected_F4_image_consumption_native_OBI_route_native_APB_'
                         f'{self.row}_live_{self.register_name}_result_RAM')))
        observed['exact_hops']['assertions']=[
            dict(expectation_id='protocol_checker.receipt_violations',status='passed',evidence=dict(violations=list(receipt.violations))),
            dict(expectation_id='cross_component.declared_edge_hops',status='passed',
                 evidence=dict(edge_ids=[[e['rule_index'],e['prerequisite_index']] for e in observed['exact_hops']['edges']])),
            dict(expectation_id='cross_component.chain_certificate_hops',status='passed',
                 evidence=dict(instruction_source=self.image['source_id'],commit_tick=commit['tick'],
                               data_transactions=[h['source_transaction'] for h in observed['exact_hops']['data_hops']]))]
        observed['exact_hops']['assertions'].append(
            dict(expectation_id='cross_component.readback_ram_write_hop',status='passed',
                 evidence=dict(memory_write_event=observed['exact_hops']['ram_write_hop']['memory_write_event'],
                               transaction=observed['exact_hops']['ram_write_hop']['transaction'],
                               address=observed['exact_hops']['ram_write_hop']['address'],
                               value=observed['exact_hops']['ram_write_hop']['value'])))
        return observed,commit,after

    def _stable(self, *, allow_finished=False):
        if getattr(self,'_irq_firmware_enabled',False) and self.irq_firmware is not None:
            from .shared_irq_firmware import build_irq_firmware,firmware_digest,expected_boot_fetch,firmware_images
            parameters=dict(image_start=self.image['range'][0],image_end=self.image['range'][1]+1,
                gpio_base=self.access['window_base'],pin=next(s['bit_offset'] for s in self.f5_binding.path['sources'] if s['kind']=='external_pin'))
            if self._irq_firmware_parameters!=parameters or not self.runner.sessions[self.cpu_id].native_irq_receipts_enabled:
                raise ValueError('shared-IRQ-firmware-binding-changed')
            expected=build_irq_firmware(**parameters,first_fetch=expected_boot_fetch(self))
            if (self.irq_firmware!=expected or self.session.template.initial_images!=firmware_images(self,expected)
                    or self.irq_bootstrap is not None and self.irq_bootstrap['firmware_sha256']!=firmware_digest(expected)):
                raise ValueError('shared-IRQ-fixed-firmware-changed')
        if self.finished and not allow_finished:raise ValueError('compiled-F4-runtime-finished')
        if getattr(self,'_f5_preparation',None) is not None:
            if self.f5_binding.validate(self.runner) != self.f5_crosswalk:
                raise ValueError('shared-F5-live-binding-changed')
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
        admission=getattr(self, 'runtime_path_admission', None)
        if admission is None and isinstance(self, CompiledF4Runtime):
            raise ValueError('compiled-F4-runtime-path-admission-removed')
        if admission is not None:
            admission.validate_cached_identity()
            if self._mixed_flows:
                if (self.session.runtime_contract is not self._mixed_contract
                        or self.session.runtime_path_document['declaration']
                        != self._mixed_declaration
                        or self.session.instruction_image_binding_documents
                        != self._mixed_binding_docs):
                    raise ValueError(
                        'compiled-storage-mixed-runtime-path-session-changed')
            elif (self.session.runtime_contract != admission.prepared.contract
                    or self.session.runtime_path_document['declaration'] != admission.prepared.document()
                    or self.session.instruction_image_binding_documents !=
                        (admission.instruction_binding.document(),)):
                raise ValueError('compiled-F4-runtime-path-session-changed')
        current_closure=_closure(self.base_dir)
        if (current_closure!=self.closure or compiled_document_sha256(self.inputs['compiled'])!=self.compiled_digest
                or _difference(compile_paths(self.inputs['request']),self.inputs['compiled']) is not None):
            raise ValueError('compiled-F4-source-identity-changed')
        current_body=_execution_binding_document(artifacts=self.artifacts,
            compiled_inputs=self.inputs, path=path,
            layout=compile_candidate_layout(path),
            cpu_error_policy=self.error_policy, producer_binding=binding,
            base_dir=self.base_dir, source_closure=current_closure,
            compiled_sha256=self.compiled_digest, cpu_traces=self.traces,
            runtime_path_admission=admission,
            built_receipts=self._validated_built_receipts())
        current_binding=CompiledF4ExecutionBinding.build(current_body)
        if current_binding.document_json!=self.execution_binding.document_json:
            raise ValueError('compiled-F4-execution-binding-changed')
        if self._f2_flows:
            from .compiled_f2 import (CompiledF2ExecutionBinding,
                _admit_f2, _execution_binding_document as _f2_binding_document)
            from .compiled_f2_layout import compile_f2_candidate_layout
            if compile_f2_candidate_layout(self.path_f2)!=self.layout_f2:
                raise ValueError('compiled-F2-layout-identity-changed')
            path_f2,producer_f2=_admit_f2(artifacts=self.artifacts,
                compiled_inputs=self.inputs,base_dir=self.base_dir)
            if (path_f2!=self.path_f2
                    or type(producer_f2) is not type(self.producer_binding_f2)
                    or producer_f2.document_json
                    != self.producer_binding_f2.document_json):
                raise ValueError('compiled-F2-admission-changed')
            self.runtime_path_admission_f2.validate_cached_identity()
            body_f2=_f2_binding_document(artifacts=self.artifacts,
                compiled_inputs=self.inputs,path=path_f2,
                layout=self.layout_f2,producer_binding=producer_f2,
                base_dir=self.base_dir,source_closure=current_closure,
                runtime_path_admission=self.runtime_path_admission_f2,
                built_receipts=self._validated_built_receipts())
            if (CompiledF2ExecutionBinding.build(body_f2).document_json
                    != self.execution_binding_f2.document_json):
                raise ValueError('compiled-F2-execution-binding-changed')
        if getattr(self, '_memory_flows', False):
            from myfuzz.runtime.flows.memory import prepare_memory_paths
            current, bindings = prepare_memory_paths(request=self.inputs['request'],
                                                     compiled=self.inputs['compiled'])
            if (_semantic_canonical(current.document()) != _semantic_canonical(self.memory_prepared.document())
                    or _semantic_canonical({binding.source_id.split('.')[0]: binding.document() for binding in bindings})
                    != _semantic_canonical({key: binding.document() for key, binding in self.memory_bindings.items()})):
                raise ValueError('compiled-memory-path-identity-changed')

    def _decode_candidate(self,raw):
        issued=compile_candidate_layout(self.path)
        if type(self.layout) is not CandidateLayout or self.layout!=issued:
            raise ValueError('compiled-F4-layout-identity-changed')
        return issued.decode(raw)





    def submit(self, raw, flow=None, testcase_id=None):
        """Submit one candidate for the declared flow.

        Single-flow runtimes keep ``flow=None`` and their historical behaviour.
        A mixed runtime requires the caller to state the flow; both flows share
        this one runner, session, memory and native target authority.
        """
        if not self._mixed_flows:
            return self._submit_f4(raw)
        if flow == 'F4':
            return self._submit_f4(raw)
        if flow == 'F2':
            if not self._f2_flows:
                raise ValueError('shared-F5-F2-consumer-unsupported')
            return self._submit_f2(raw)
        if flow in ('F1', 'F3') and self._memory_flows:
            from myfuzz.runtime.flows.memory import submit_memory_case
            return submit_memory_case(self, raw, flow=flow, testcase_id=testcase_id)
        if flow == 'F5' and self._f5_preparation is not None:
            from .shared_f5_runtime import submit_shared_f5
            return submit_shared_f5(self,raw,testcase_id=testcase_id)
        raise ValueError('compiled-storage-mixed-flow-required')

    @host_source_discovery_scope()
    def _submit_f4(self, raw, flow='F4'):
        """Decode every declared candidate slice before executing any source."""
        self._stable()
        values=self._decode_candidate(raw)
        if len(self.records)>=self.max_cases:raise ValueError('compiled-F4-case-budget-exhausted')
        value=values[self.stream['source_id']]
        declaration=declare_writer(self.inputs['request'],self.inputs['compiled'],
            source_id=self.stream['source_id'],value=value,result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        if self.cursor+len(code)>self.result-(4 if getattr(self, '_memory_flows', False) else 0):raise ValueError('compiled-F4-slot-exhausted')
        external=[s for s in self.path['sources'] if s['kind']=='external_pin']
        for number,source in enumerate(external):
            self._stable()
            pin_value=values[source['source_id']]
            pin_direction='CPU_TO_IP';pin_path_id=None
            if self._f5_preparation is not None:
                pin_direction=self.f5_binding.path['direction']
                pin_path_id=self.f5_binding.path['runtime_path_identity']['path_id']
            else:
                pin_direction,pin_path_id=self.runtime_path_admission.external_pin_path(source['source_id'])
            pin_case=OnlineCase(f'{self.run_id}:{len(self.records)}:external:{number}',
                pin_direction,pin_path_id,BatchSourceEvent(
                    source['source_id']+f':{len(self.records)}',source['component'],
                    source['port'],pin_value,source['bit_offset'],source['width']),
                (BatchAdvance((source['component'],)),))
            pin_receipt=self.session.submit_case(pin_case)
            if pin_receipt.violations:raise ValueError('compiled-F4-external-source-failed')
        before=self.authority.consume(self._issue_register_version(
            reset_epoch=self.runner.sessions[self.target_id].reset_epoch))
        prerequisite=(stable_storage_version(before)
                      if self.row==ROW_GENERIC_APB_STORAGE else before)
        prior=len(self.authority.writes())
        index=len(self.records);case_id=f'{self.run_id}:{index}'
        case=OnlineCase(case_id,'CPU_TO_IP',self.runtime_path_admission.runtime_path_id,
            BoundOnlineInstruction(self.image['source_id']+f':{index}',self.cpu_id,self.cursor,code.hex(),
                self.runtime_path_admission.instruction_binding.source_id),
            tuple(BatchAdvance(tuple(self.runner.sessions)) for _ in range(self.rounds)))
        self._stable()
        self._pending=('F4',declaration,before,prior);self._checked=None
        receipt=self.session.submit_case(case)
        self._pending=None
        if receipt.violations or self._checked is None or receipt.status!='running':
            raise ValueError('compiled-F4-protocol-checker-failed:'+str(receipt.violations))
        observed,commit,after=self._checked
        certificate=dict(schema_version='compiled_F4_chain.v3',status='certified',
            path_id=self.path['path_id'],source_id=self.stream['source_id'],
            bound_input_id=self.path['bound_inputs'][0]['input_id'],case_id=case_id,
            instruction_source_id=next(s['source_id'] for s in self.path['sources'] if s['kind']=='instruction_image'),
            instruction_address=self.cursor,instruction_sha256=sha256(code).hexdigest(),
            prerequisite=prerequisite,commit=commit,postcondition=after,joins=observed['joins'],
            first_fetch=self.first_fetch,exact_hops=observed['exact_hops'],
            assertions=observed['exact_hops']['assertions'],
            execution_binding_sha256=self.execution_binding.digest,
            runtime_path_id=self.runtime_path_admission.runtime_path_id,
            runtime_path_admission_sha256=self.runtime_path_admission.digest,
            runtime_admitted=True)
        record=dict(raw=raw.hex(),value=value,source_values=values,certificate=certificate)
        if self._mixed_flows:record['flow']='F4'
        self.records.append(record)
        self.cursor+=len(code)
        return deepcopy(certificate)

    def feedback(self):
        if self._mixed_flows:
            f4=[r for r in self.records if r.get('flow')=='F4']
            f2=[r for r in self.records if r.get('flow')=='F2']
            return dict(cases=len(self.records),certified=len(f4)+len(f2),
                memory_cases=sum(r.get('flow') in ('F1','F3') for r in self.records),
                write_cases=len(f4),read_cases=len(f2),
                distinct_values=len({r['value'] for r in f4}),
                changed_versions=sum(r['certificate']['commit']['before']
                                     !=r['value'] for r in f4),
                read_versions=len({r['certificate']['version_before']
                                   ['field_version'] for r in f2}))
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
        if self._mixed_flows:
            from .compiled_f2 import _layout_document as _f2_layout_document
            return dict(schema_version='compiled_storage_mixed_prefix.v1',
                run_id=self.run_id,compiled_sha256=self.compiled_digest,
                source_files=self.closure,
                **(dict(irq_firmware=deepcopy(self.irq_firmware),irq_bootstrap=deepcopy(self.irq_bootstrap),
                    irq_dependency_evidence=self.runner.gpio_irq_dependency_evidence_report()) if getattr(self,'_irq_firmware_enabled',False) else {}),
                artifact_digests={n:a.runtime_document['artifact_digest']
                                  for n,a in self.artifacts.items()},
                rounds_per_case=self.rounds,max_cases=self.max_cases,
                records=deepcopy(self.records),
                candidate_layouts={**({'F2':_f2_layout_document(self.layout_f2)} if self._f2_flows else {}),
                                   'F4':_layout_document(self.layout)},
                cpu_error_policies={**({'F2':deepcopy(self.error_policy_f2)} if self._f2_flows else {}),
                                    'F4':deepcopy(self.error_policy)},
                producer_bindings={**({'F2':self.producer_binding_f2.document()} if self._f2_flows else {}),
                                   'F4':self.producer_binding.document()},
                execution_bindings={**({'F2':self.execution_binding_f2.document()} if self._f2_flows else {}),
                                    'F4':self.execution_binding.document()},
                execution_binding_sha256={
                    **({'F2':self.execution_binding_f2.digest} if self._f2_flows else {}),
                    'F4':self.execution_binding.digest},
                runtime_path_admissions={
                    **({'F2':self.execution_binding_f2.document().get(
                        'runtime_path_admission')} if self._f2_flows else {}),
                    'F4':self.execution_binding.document().get(
                        'runtime_path_admission')},
                **({'f5_crosswalk':deepcopy(self.f5_crosswalk),
                    'unsupported_flows':['F6'] if self._f2_flows else ['F2','F6']}
                   if self._f5_preparation is not None else {}),
                online_plan=json.loads(self.session.encode_plan()),
                semantic_hash=semantic_hash,feedback=self.feedback())
        return dict(schema_version='compiled_F4_prefix.v2',run_id=self.run_id,
            compiled_sha256=self.compiled_digest,source_files=self.closure,
            artifact_digests={n:a.runtime_document['artifact_digest'] for n,a in self.artifacts.items()},
            rounds_per_case=self.rounds,max_cases=self.max_cases,records=deepcopy(self.records),
            candidate_layout=_layout_document(self.layout),cpu_error_policy=deepcopy(self.error_policy),
            producer_binding=self.producer_binding.document(),
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest,
            runtime_path_admission=self.execution_binding.document().get('runtime_path_admission'),
            online_plan=json.loads(self.session.encode_plan()),
            semantic_hash=semantic_hash,feedback=self.feedback())

    @host_source_discovery_scope()
    def replay(self, plan, *, audit_sink=None):
        """Reexecute every candidate, checking live prerequisites anew."""
        self._stable(allow_finished=True)
        expected=self.finish()
        if _difference(expected,plan) is not None:raise ValueError('compiled-F4-prefix-mismatch')
        envelope=dict(scope='full_fresh_prefix_real_RTL_and_live_register_prerequisites',
            original_execution_audit=self.execution_audit(),
            original_build=_diagnostic_build_snapshot(self))
        try:
            fresh=type(self)(artifacts=self.artifacts,compiled_inputs=self.inputs,
                base_dir=self.base_dir,cache_dir=self.cache_dir,run_id=self.run_id,
                rounds_per_case=self.rounds,max_cases=self.max_cases,
                expected_built_receipts=self._built_receipts,
                mixed_flows=self._mixed_flows,
                memory_flows=self._memory_flows,
                f5_preparation=self._f5_preparation,
                irq_firmware=getattr(self,'_irq_firmware_enabled',False),
                build_audit_sink=lambda snapshot:envelope.update(fresh_build=snapshot))
        except BaseException as error:
            envelope.update(error_type=type(error).__name__,error=str(error),
                startup_partial_trace_available=False)
            if audit_sink is not None:
                try:audit_sink(deepcopy(envelope))
                except BaseException as export_error:
                    error.add_note('compiled-F4 replay export: '+repr(export_error))
            raise
        primary_error=None
        try:
            identities=fresh.execution_audit()['identities']
            _check_fresh_identities([self._process_identities]+self._replay_identities,identities)
            self._replay_identities.append(deepcopy(identities))
            envelope['fresh_build'] = _diagnostic_build_snapshot(fresh,
                previous=envelope.get('fresh_build'))
            for record in plan['records']:
                fresh.submit(bytes.fromhex(record['raw']),
                             flow=record.get('flow') if self._mixed_flows else None,
                             testcase_id=record['certificate'].get('case_id')
                                 if record.get('flow') in ('F1','F3','F5') else None)
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
                    envelope['cleanup_failure']=dict(error_type=type(error).__name__,error=str(error))
            # Diagnostic capture must survive strict audit refusal after drift.
            for key, capture in (
                    ('fresh_build', lambda:_diagnostic_build_snapshot(fresh,
                        previous=envelope.get('fresh_build'),error=primary_error)),
                    ('execution_audit', fresh.execution_audit),
                    ('actual_events', lambda:list(fresh.runner.events_since(0)))):
                try:envelope[key]=capture()
                except BaseException as error:
                    secondary_errors.append(error)
                    envelope.setdefault('audit_failures',[]).append(
                        dict(stage=key,error_type=type(error).__name__,error=str(error)))
            if audit_sink is not None:
                try:audit_sink(deepcopy(envelope))
                except BaseException as error:secondary_errors.append(error)
            if primary_error is not None:
                for error in secondary_errors:
                    primary_error.add_note('compiled-F4 replay cleanup/audit: '+repr(error))
            elif secondary_errors:
                primary=secondary_errors[0]
                for error in secondary_errors[1:]:primary.add_note('compiled-F4 replay cleanup/audit: '+repr(error))
                raise primary
