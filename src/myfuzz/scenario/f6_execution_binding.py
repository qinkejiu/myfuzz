"""Closed, live-owner binding for the compiled F6 RAM-DMA execution.

The document is descriptive. The in-process registry is what associates that
document with the actual Runner, sessions, program, and bound route object.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from weakref import WeakKeyDictionary, ref
import json


SCHEMA_VERSION = 'compiled_F6_execution_binding.v1'
_BINDING_KEYS = frozenset({
    'schema_version', 'run_id', 'path_id', 'flow_id',
    'compiled_document_sha256', 'request_sha256',
    'execution_contract_sha256', 'runtime_path_admission',
    'runtime_path_admission_sha256', 'selected_path_sha256',
    'sparse_program_manifest', 'program_sha256', 'artifact_identities',
    'topology_binding', 'topology_binding_sha256', 'dma_route_admission',
    'dma_route_admission_sha256', 'dma_routes', 'cpu', 'dma', 'memory',
    'issuer_contracts', 'expectation_ids', 'ownership_sha256',
    'physical_port_map_sha256', 'executor_source_closure_sha256',
    'binding_sha256'})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F6-execution-binding-' + code)


from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy as _F6RamDmaPolicy

_F6_POLICY_METHOD_NAMES = (
    'state', 'records', 'identity_document', 'begin_case',
    'begin_transfer', 'accepted', 'completed')


def _policy_descriptor_codes(descriptor):
    if type(descriptor) is property:
        return tuple(getattr(accessor, '__code__', None) for accessor in
            (descriptor.fget, descriptor.fset, descriptor.fdel)
            if accessor is not None)
    return (getattr(descriptor, '__code__', None),)


_F6_POLICY_METHOD_BASELINE = tuple(
    (name, vars(_F6RamDmaPolicy)[name],
     _policy_descriptor_codes(vars(_F6RamDmaPolicy)[name]))
    for name in _F6_POLICY_METHOD_NAMES)


def _f6_policy_method_pins(policy):
    _require(type(policy) is _F6RamDmaPolicy, 'policy-type')
    cls = type(policy)
    current = []
    for name, baseline_descriptor, baseline_codes in _F6_POLICY_METHOD_BASELINE:
        descriptor = vars(cls).get(name)
        codes = _policy_descriptor_codes(descriptor)
        _require(descriptor is baseline_descriptor and codes == baseline_codes,
            'policy-method-owner')
        current.append((name, descriptor, codes))
    return tuple(current)


class CompiledF6ExecutionBinding:
    """Immutable canonical descriptor; not authority without the live pins."""
    __slots__ = ('_document_json',)

    def __init__(self, document):
        if type(document) is not dict:
            raise ValueError('compiled-F6-execution-binding-document-required')
        body = {key: value for key, value in document.items()
                if key != 'binding_sha256'}
        group_mode = 'gpio_irq' in body.get('runtime_path_admission',{}).get('execution_contract',{}).get('program_contract',{})
        expected_keys = _BINDING_KEYS | ({'runtime_topology'} if group_mode else set())
        if (set(document) != expected_keys
                or body.get('schema_version') != SCHEMA_VERSION):
            raise ValueError('compiled-F6-execution-binding-schema')
        issued = dict(body, binding_sha256=_digest(body))
        if document['binding_sha256'] != issued['binding_sha256']:
            raise ValueError('compiled-F6-execution-binding-digest')
        object.__setattr__(self, '_document_json', _canonical(issued).decode())

    def __setattr__(self, name, value):
        raise AttributeError('compiled F6 execution binding is immutable')

    def document(self):
        return json.loads(self._document_json)

    @property
    def digest(self):
        return self.document()['binding_sha256']


_LIVE_BINDINGS = WeakKeyDictionary()


def _artifact_identity(artifact):
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    return _artifact_execution_identity(artifact)


def _program_document(program, contract):
    from myfuzz.integration.compiled_f6_firmware import F6Firmware
    _require(type(program) is F6Firmware, 'program-type')
    document = program.document()
    _require(type(document) is dict
        and document.get('schema_version') == 'compiled_F6_firmware.v1'
        and document.get('program_contract') == contract['program_contract']
        and document.get('initial_segment_manifest') ==
            contract['program_contract']['initial_image']
        and document.get('manifest_sha256') ==
            contract['program_contract']['initial_image_sha256'], 'program-contract')
    return document


def _validate_f6_route_policy(policy, contract):
    method_pins = _f6_policy_method_pins(policy)
    _require(not any(name in vars(policy) for name in
        ('identity_document', 'begin_case', 'begin_transfer', 'accepted',
         'completed')), 'policy-method-owner')
    stored = getattr(policy, '_contract', None)
    _require(type(stored) is str, 'policy-contract')
    try:
        policy_contract = json.loads(stored)
        matches = _canonical(policy_contract) == _canonical(contract)
    except (TypeError, ValueError, RecursionError):
        matches = False
    _require(matches, 'policy-contract')
    return method_pins


def _validate_bound_topology(*, bound_topology, runner, path, request,
                             artifacts, cpu, dma):
    from myfuzz.scenario.dma_intent_topology_binding import (
        BoundDmaIntentTopology, PreparedDmaIntentBinding)
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    from myfuzz.scenario.runtime_path_contract import CompiledRuntimePathContract
    from myfuzz.local_harness.dma_artifact_endpoint_links import (
        validate_dma_artifact_endpoint_links)
    from myfuzz.integration.compiled_f6_runtime_path import (
        _artifact_link_document, restore_prepared_runtime_paths)

    _require(type(bound_topology) is BoundDmaIntentTopology,
        'bound-topology-type')
    _require('validate_topology' not in vars(bound_topology)
        and 'match_dma_master_route' not in vars(bound_topology)
        and type(bound_topology).validate_topology is
            BoundDmaIntentTopology.validate_topology
        and type(bound_topology).match_dma_master_route is
            BoundDmaIntentTopology.match_dma_master_route,
        'bound-topology-method-owner')
    compilation = bound_topology.runtime_compilation
    edge_index = bound_topology._runtime_edge_index
    _require(type(compilation) is CompiledRuntimePathContract
        and compilation._runner is runner, 'topology-runner-owner')
    expected_sessions = {cpu.artifact.plan.request.instance_id, dma.artifact.plan.request.instance_id}
    if 'shared_storage_path' in path:
        expected_sessions.add(path['shared_storage_path']['component'])
    # Each selected shared path can involve a different companion.  In
    # particular F2/F4 may use an APB target while F5 uses a GPIO IRQ source.
    # Bind all of those selected components to the same live runner; an
    # unselected companion is checked separately by validate_companion_sessions.
    for selected in path.get('shared_flow_paths', {}).values():
        expected_sessions.add(selected['component'])
        expected_sessions.add(selected['cpu_component'])
    _require(type(compilation._sessions) is tuple
        and {name for name, _ in compilation._sessions} == expected_sessions
        and len(compilation._sessions) == len(expected_sessions)
        and all(runner.sessions.get(name) is session
            for name, session in compilation._sessions)
        and runner.sessions.get(cpu.artifact.plan.request.instance_id) is cpu
        and runner.sessions.get(dma.artifact.plan.request.instance_id) is dma,
        'topology-session-owner')

    selected_ids = path.get('runtime_path_ids')
    _require(type(selected_ids) is list and bool(selected_ids)
        and len(set(selected_ids)) == len(selected_ids)
        and set(row.get('path_id') for row in compilation.document().get('paths', ()))
            == set(selected_ids), 'runtime-compilation-path-set')
    prepared = restore_prepared_runtime_paths(path)
    declaration = PreparedDmaIntentBinding.from_document(
        path['dma_intent_binding'], prepared_runtime_paths=prepared)
    _require(declaration.document()['wiring'] == request.wiring.document,
        'd4-wiring-join')
    _require(compilation._ownership is runner.ownership
        and compilation._bindings is runner.bindings,
        'topology-ownership-join')

    credential_bytes = bound_topology._document_bytes
    _require(type(credential_bytes) is bytes, 'topology-credential-bytes')
    try:
        credential = json.loads(credential_bytes)
    except (ValueError, UnicodeError) as error:
        raise ValueError('compiled-F6-execution-binding-topology-credential') from error
    credential_keys = {'schema_version', 'declaration_sha256', 'prepared_sha256',
        'runtime_contract_sha256', 'runtime_compilation_sha256', 'topology_sha256',
        'artifact_links', 'routes', 'tier', 'identity_sha256'}
    _require(type(credential) is dict and credential_bytes == _canonical(credential)
        and set(credential) == credential_keys,
        'topology-credential-shape')
    unsigned = {key: value for key, value in credential.items()
        if key != 'identity_sha256'}
    _require(credential.get('schema_version') == 'dma_intent_topology_binding.v1'
        and credential.get('tier') == 'topology_bound'
        and credential.get('identity_sha256') == _digest(unsigned),
        'topology-credential-digest')
    _require(credential.get('declaration_sha256') == declaration.identity_sha256
        and credential.get('prepared_sha256') == _digest(prepared.document())
        and credential.get('runtime_contract_sha256') ==
            prepared.contract.identity_sha256
        and credential.get('runtime_compilation_sha256') ==
            compilation.identity_sha256
        and credential.get('topology_sha256') == compilation.topology_sha256,
        'topology-credential-crosswalk')

    dma_id = dma.artifact.plan.request.instance_id
    endpoint_doc = _artifact_link_document(artifacts[dma_id])
    endpoint_doc = validate_dma_artifact_endpoint_links(endpoint_doc,
        artifacts[dma_id]).document()
    expected_links = [dict(instance_id=dma_id, endpoint_links=endpoint_doc)]
    _require(credential.get('artifact_links') == expected_links,
        'topology-credential-artifact-links')

    routes_by_key = {route.key: route
        for route in prepared.contract.dma_master_routes}
    intents = {route.route_id: route
        for route in request.wiring.dma_master_routes}
    expected_routes = []
    for row in declaration.document()['route_links']:
        route = routes_by_key.get((row['rule_index'], row['prerequisite_index']))
        intent = intents.get(row['route_id'])
        _require(route is not None and intent is not None,
            'topology-credential-route-coverage')
        expected_routes.append(dict(route_id=intent.route_id,
            intent_sha256=intent.identity_sha256,
            rule_index=route.rule_index,
            prerequisite_index=route.prerequisite_index,
            runtime_route_sha256=route.identity_sha256,
            endpoint_link_sha256=_digest(row['endpoint_link'])))
    expected_routes.sort(key=lambda row: row['route_id'])
    _require(credential.get('routes') == expected_routes
        and len(expected_routes) == len(routes_by_key) == 2,
        'topology-credential-routes')

    index_input = dict(compilation.document(), declaration=prepared.document())
    expected_index = RuntimeEdgeIndex(index_input,
        prepared.contract.document(), prepared=prepared)
    _require(type(edge_index) is RuntimeEdgeIndex
        and 'match_dma_master_route' not in vars(edge_index)
        and edge_index.document() == expected_index.document()
        and edge_index.identity_sha256 == expected_index.identity_sha256
        and dict(edge_index._dma_routes_by_key) ==
            dict(expected_index._dma_routes_by_key),
        'topology-edge-index-crosswalk')
    bound_topology.validate_topology()
    return dict(selected_path_ids=tuple(selected_ids),
        compilation=compilation, edge_index=edge_index)


def _live_objects(*, contract, artifacts, compiled_inputs, base_dir, run_id,
                  program, runner, bound_topology):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_session import (
        GeneratedWishboneDmaSession, _f6_dma_session_type_allowlist,
        _verify_f6_dma_route_validator)
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case
    from myfuzz.scenario.memory_service import (
        _arm_f6_dma_read, _complete_f6_dma_read,
        _validate_f6_dma_read, _f6_dma_read_results)

    _require(type(run_id) is str and bool(run_id) and run_id.strip() == run_id,
        'run-id')
    _require(type(compiled_inputs) is dict and set(compiled_inputs) == {
        'request', 'compiled', 'ownership', 'physical_port_map'}, 'inputs')
    request = compiled_inputs['request']
    _require(type(artifacts) is dict, 'artifact-map')
    from myfuzz.scenario.compiled_paths import (
        PathCompileRequest, compile_paths, compiled_document_sha256)
    _require(type(request) is PathCompileRequest, 'request')
    fresh_compiled = compile_paths(request)
    _require(_canonical(fresh_compiled) == _canonical(compiled_inputs['compiled']),
        'compiled-recompile')

    from myfuzz.scenario.f6_execution_contract import (
        compile_f6_execution_contract, validate_f6_execution_contract)
    fresh_contract = compile_f6_execution_contract(request, base_dir=base_dir)
    validate_f6_execution_contract(contract, request=request, base_dir=base_dir)
    _require(_canonical(fresh_contract) == _canonical(contract), 'contract-recompile')

    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path)
    path = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    _require(_canonical(path['execution_contract']) == _canonical(contract),
        'path-contract')
    program_doc = _program_document(program, contract)

    _require(type(getattr(runner, 'sessions', None)) is dict, 'runner-sessions')
    try:
        dma_session_classes = _f6_dma_session_type_allowlist()
    except (AttributeError, ImportError, TypeError, ValueError) as error:
        raise ValueError(
            'compiled-F6-execution-binding-dma-session-class') from error
    cpu_id, dma_id = contract['cpu']['instance_id'], contract['dma']['instance_id']
    from myfuzz.integration.f6_storage_companion import (
        companion_artifact_documents, validate_companion_sessions)
    companions = companion_artifact_documents(contract=contract, artifacts=artifacts,
        request=request, base_dir=base_dir)
    _require(set(artifacts) == {cpu_id, dma_id, *companions}, 'artifact-set')
    cpu, dma = runner.sessions.get(cpu_id), runner.sessions.get(dma_id)
    _require(type(cpu) is GeneratedCve2Session
        and type(dma) in dma_session_classes, 'registered-sessions')
    _require(cpu.artifact is artifacts[cpu_id]
        and dma.artifact is artifacts[dma_id], 'artifact-owner')
    _require(set(runner.sessions) == set(artifacts), 'runner-session-set')
    validate_companion_sessions(documents=companions, artifacts=artifacts, sessions=runner.sessions)
    for name, companion in companions.items():
        window = companion['window']
        matches = [row for row in cpu.router.windows if row.device_id == name
            and row.base == window['base'] and row.size == window['size']
            and row.target is runner.sessions[name]]
        _require(len(matches) == 1, 'companion-router-owner')
    topology = _validate_bound_topology(bound_topology=bound_topology,
        runner=runner, path=path, request=request, artifacts=artifacts,
        cpu=cpu, dma=dma)

    route_admission = getattr(dma, '_dma_route_admission', None)
    _require(type(route_admission) is DmaMasterRouteAdmission
        and route_admission._bound_topology is bound_topology,
        'live-route-admission')
    route_policy = route_admission._beat_policy
    route_policy_method_pins = _validate_f6_route_policy(route_policy, contract)
    _require('_validate_dma_route_topology' not in vars(dma)
        and callable(getattr(dma, '_dma_route_validator', None)),
        'route-admission-validator')
    try:
        _verify_f6_dma_route_validator(dma, admission=route_admission)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(
            'compiled-F6-execution-binding-route-admission-validator') from error
    dma_session_classes[0]._validate_dma_route_topology(dma)
    route_validator = dma._dma_route_validator
    _require(route_admission._path_id in topology['selected_path_ids'],
        'route-admission-path')
    route_identity = route_admission.identity_document()
    _require(route_identity.get('binding_identity_sha256') ==
        bound_topology.identity_sha256, 'route-topology-identity')
    selected = {row['operation']: row for row in path['selected_dma_routes']}
    _require(set(selected) == {'read', 'write'}, 'selected-route-pair')
    for operation, route in (('read', route_admission._read_route),
                             ('write', route_admission._write_route)):
        _require(route.document() == selected[operation],
            'live-route-' + operation)
        _require(route.target_kind == 'persistent_memory'
            and route.target_component == cpu_id
            and route.operation == operation
            and route.permissions == (operation,),
            'route-contract-' + operation)
    links = path['route_links']
    _require(type(links) is list and len(links) == 2, 'route-links')
    route_links_by_key = {(row['rule_index'], row['prerequisite_index']): row
        for row in links}
    master_endpoint = contract['dma']['master_endpoint_link']['endpoint_id']
    for operation, route in (('read', route_admission._read_route),
                             ('write', route_admission._write_route)):
        row = route_links_by_key.get(route.key)
        _require(type(row) is dict, 'route-link-' + operation)
        link = row.get('endpoint_link', {})
        _require(link.get('mode') == 'explicit_alias'
            and link.get('static_endpoint_id') == master_endpoint
            and link.get('artifact_endpoint_id') == master_endpoint
            and link.get('runtime_endpoint_id') == route.endpoint_id
            and link.get('operation') == operation, 'endpoint-alias')

    memory = cpu.memory
    cpu_service = cpu.service
    dma_service = dma.memory_service
    _require(type(cpu_service) is MemoryService
        and type(dma_service) is MemoryService
        and cpu_service is not dma_service
        and cpu_service.memory is memory
        and dma_service.memory is memory
        and cpu_service.ledger is not dma_service.ledger,
        'shared-memory-owners')
    memory_resource = contract['memory']['resource']
    from myfuzz.scenario.runtime_path_contract import (
        persistent_memory_route_identity_document)
    memory_identity = persistent_memory_route_identity_document(memory,
        memory_id=memory_resource['resource_id'], base=memory_resource['base'],
        size=memory_resource['size'])
    expected_memory = path['selected_dma_routes'][0]['target_identity_sha256']
    _require(_digest(memory_identity) == expected_memory, 'memory-target-identity')

    return dict(path=path, program_doc=program_doc, cpu=cpu, dma=dma, companions=companions,
        route_admission=route_admission, memory=memory, cpu_service=cpu_service,
        dma_service=dma_service, memory_identity=memory_identity,
        route_policy=route_policy, route_validator=route_validator,
        route_policy_method_pins=route_policy_method_pins,
        task5_consumer=capture_f6_case,
        task5_read_issuers=(_arm_f6_dma_read, _complete_f6_dma_read,
            _validate_f6_dma_read, _f6_dma_read_results),
        compiled_sha256=compiled_document_sha256(fresh_compiled))


def _closure(base_dir):
    root = Path(base_dir)
    return {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / 'src/myfuzz').rglob('*.py'))}


def _body(*, contract, artifacts, compiled_inputs, base_dir, run_id, program,
          runner, bound_topology, _live=None):
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.integration.compiled_f6_runtime_path import _digest as _path_digest

    live = (_live if _live is not None else _live_objects(
        contract=contract, artifacts=artifacts, compiled_inputs=compiled_inputs,
        base_dir=base_dir, run_id=run_id, program=program, runner=runner,
        bound_topology=bound_topology))
    path = live['path']
    cpu, dma = live['cpu'], live['dma']
    route_admission = live['route_admission']
    body = dict(schema_version=SCHEMA_VERSION, run_id=run_id,
        path_id=contract['path_id'], flow_id='F6',
        compiled_document_sha256=live['compiled_sha256'],
        request_sha256=_digest(compiled_inputs['request'].document),
        execution_contract_sha256=_digest(contract),
        runtime_path_admission=path,
        runtime_path_admission_sha256=path['admission_sha256'],
        selected_path_sha256=_path_digest(path['logical_path']),
        sparse_program_manifest=deepcopy(path['sparse_program_manifest']),
        program_sha256=_digest(live['program_doc']),
        artifact_identities={name: _artifact_identity(artifacts[name])
            for name in sorted(artifacts)},
        topology_binding=bound_topology.document(),
        topology_binding_sha256=bound_topology.identity_sha256,
        dma_route_admission=route_admission.identity_document(),
        dma_route_admission_sha256=_digest(route_admission.identity_document()),
        dma_routes=[deepcopy(row) for row in path['selected_dma_routes']],
        cpu=dict(instance_id=contract['cpu']['instance_id'],
            profile_fingerprint=cpu.artifact.plan.profile.profile_fingerprint,
            runtime_artifact_sha256=_digest(cpu.artifact.runtime_document),
            irq_provider=deepcopy(contract['irq']['native_take_provider']),
            mret_issuer_schema='native_f6_isr_return.v1'),
        dma=dict(instance_id=contract['dma']['instance_id'],
            profile_fingerprint=dma.artifact.plan.profile.profile_fingerprint,
            runtime_artifact_sha256=_digest(dma.artifact.runtime_document)),
        memory=dict(identity=live['memory_identity'],
            identity_sha256=_digest(live['memory_identity']),
            cpu_service_owner='cpu', dma_service_owner='dma',
            distinct_service_objects=True, distinct_ledger_objects=True),
        issuer_contracts=dict(response_fault_schema='f6_dma_response_fault.v1',
            task5_consumer='myfuzz.integration.compiled_f6_consumer.capture_f6_case',
            read_issuer_schema='f6_dma_read_result.v1',
            mret_issuer_schema='native_f6_isr_return.v1'),
        expectation_ids=list(EXPECTATION_IDS),
        ownership_sha256=_digest(compiled_inputs['ownership'].document()),
        physical_port_map_sha256=_digest(sorted((list(key), value)
            for key, value in compiled_inputs['physical_port_map'].items())),
        executor_source_closure_sha256=_digest(_closure(base_dir)))
    if 'gpio_irq' in contract['program_contract']:
        topology = bound_topology.runtime_compilation.document()['topology']
        _require(_digest(topology) == body['topology_binding']['topology_sha256']
            and bool(topology.get('irq_delivery_groups')), 'actual-shared-IRQ-topology')
        body['runtime_topology'] = topology
    if live.get('companions'):
        body['issuer_contracts']['shared_companions'] = deepcopy(live['companions'])
    return body


def build_f6_execution_binding(*, contract, artifacts, compiled_inputs,
        base_dir, run_id, program, runner, bound_topology) -> dict:
    """Build and privately pin one same-call F6 execution declaration."""
    live = _live_objects(contract=contract, artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir, run_id=run_id,
        program=program, runner=runner, bound_topology=bound_topology)
    body = _body(contract=contract, artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir, run_id=run_id,
        program=program, runner=runner, bound_topology=bound_topology,
        _live=live)
    body['binding_sha256'] = _digest(body)
    binding = CompiledF6ExecutionBinding(body).document()
    try:
        rows = _LIVE_BINDINGS.setdefault(runner, {})
        policy_ref = ref(live['route_policy'])
        route_validator_ref = ref(live['route_validator'])
    except TypeError as error:
        raise ValueError('compiled-F6-execution-binding-live-runner-required') from error
    rows[binding['binding_sha256']] = dict(contract=contract,
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=Path(base_dir),
        run_id=run_id, program=program, runner_ref=ref(runner),
        bound_topology_ref=ref(bound_topology),
        cpu_ref=ref(runner.sessions[contract['cpu']['instance_id']]),
        dma_ref=ref(runner.sessions[contract['dma']['instance_id']]),
        companion_refs={name: ref(runner.sessions[name]) for name in live.get('companions', {})},
        route_admission_ref=ref(live['route_admission']),
        route_policy_ref=policy_ref, route_validator_ref=route_validator_ref,
        route_policy_method_pins=live['route_policy_method_pins'],
        task5_consumer=live['task5_consumer'],
        task5_read_issuers=live['task5_read_issuers'])
    return binding


def revoke_f6_execution_binding(runner, binding_sha256) -> bool:
    """Revoke the live in-process owner grant when the original runtime ends."""
    if (type(binding_sha256) is not str or len(binding_sha256) != 64
            or any(ch not in '0123456789abcdef' for ch in binding_sha256)):
        raise ValueError('compiled-F6-execution-binding-revoke-digest')
    try:
        rows = _LIVE_BINDINGS.get(runner)
    except TypeError as error:
        raise ValueError('compiled-F6-execution-binding-revoke-runner') from error
    if rows is None or binding_sha256 not in rows:
        return False
    rows.pop(binding_sha256)
    if not rows:
        try:
            del _LIVE_BINDINGS[runner]
        except KeyError:
            pass
    return True


def _validate_registered_issuers(pins, binding_sha256):
    cpu, dma = pins['cpu_ref'](), pins['dma_ref']()
    if cpu is None or dma is None:
        raise ValueError('compiled-F6-execution-binding-live-owner-required')
    from myfuzz.scenario.native_f6_isr_return import _issuer_state
    issuer = getattr(cpu, '_f6_isr_return', None)
    try:
        state = _issuer_state(issuer)
    except (TypeError, ValueError) as error:
        raise ValueError('compiled-F6-execution-binding-mret-issuer') from error
    _require(state['issuer'] is issuer and state['binding'] == binding_sha256,
        'mret-issuer-binding')
    fault = getattr(dma, '_f6_response_fault', None)
    if fault is not None:
        from myfuzz.local_harness.f6_dma_response_fault import (
            _validate_f6_response_fault)
        checked = _validate_f6_response_fault(dma)
        _require(checked is fault
            and checked.document()['execution_binding_sha256'] == binding_sha256,
            'fault-issuer-binding')
    from myfuzz.scenario.memory_service import _f6_dma_read_results
    _f6_dma_read_results(dma)  # Original Task5 issuer owner check, no enrollment.


def validate_f6_execution_binding(document, *, contract, artifacts,
        compiled_inputs, base_dir, run_id, program, runner,
        bound_topology) -> dict:
    """Rebuild the declaration and require its original in-process owner pins."""
    try:
        binding = CompiledF6ExecutionBinding(document).document()
        pins = _LIVE_BINDINGS.get(runner, {}).get(binding['binding_sha256'])
    except (TypeError, AttributeError) as error:
        raise ValueError('compiled-F6-execution-binding-live-owner-required') from error
    if pins is None:
        raise ValueError('compiled-F6-execution-binding-live-owner-required')
    if (pins['runner_ref']() is not runner
            or pins['bound_topology_ref']() is not bound_topology
            or pins['cpu_ref']() is not runner.sessions.get(contract['cpu']['instance_id'])
            or pins['dma_ref']() is not runner.sessions.get(contract['dma']['instance_id'])
            or any(owner() is not runner.sessions.get(name)
                   for name, owner in pins.get('companion_refs', {}).items())):
        raise ValueError('compiled-F6-execution-binding-live-owner-required')
    dma = pins['dma_ref']()
    admission = getattr(dma, '_dma_route_admission', None)
    if (pins['route_admission_ref']() is None
            or admission is not pins['route_admission_ref']()):
        raise ValueError('compiled-F6-execution-binding-owner-route-admission')
    policy = pins['route_policy_ref']()
    if (policy is None or getattr(admission, '_beat_policy', None) is not policy):
        raise ValueError('compiled-F6-execution-binding-owner-route-policy')
    if (_validate_f6_route_policy(policy, contract)
            != pins['route_policy_method_pins']):
        raise ValueError('compiled-F6-execution-binding-owner-route-policy-method')
    if (pins['route_validator_ref']() is None
            or getattr(dma, '_dma_route_validator', None) is not
                pins['route_validator_ref']()):
        raise ValueError('compiled-F6-execution-binding-owner-route-validator')
    for name, value in (('contract', contract), ('artifacts', artifacts),
            ('compiled_inputs', compiled_inputs), ('program', program),
            ):
        if pins[name] is not value:
            raise ValueError('compiled-F6-execution-binding-owner-' + name)
    if pins['run_id'] != run_id or pins['base_dir'] != Path(base_dir):
        raise ValueError('compiled-F6-execution-binding-owner-run-or-root')
    live = _live_objects(contract=contract, artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir, run_id=run_id,
        program=program, runner=runner, bound_topology=bound_topology)
    if (pins['task5_consumer'] is not live['task5_consumer']
            or pins['task5_read_issuers'] != live['task5_read_issuers']):
        raise ValueError('compiled-F6-execution-binding-owner-task5-issuer')
    rebuilt = _body(contract=contract, artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir, run_id=run_id,
        program=program, runner=runner, bound_topology=bound_topology,
        _live=live)
    rebuilt['binding_sha256'] = _digest(rebuilt)
    current = CompiledF6ExecutionBinding(rebuilt).document()
    if current != binding:
        raise ValueError('compiled-F6-execution-binding-drift')
    _validate_registered_issuers(pins, binding['binding_sha256'])
    return deepcopy(binding)
