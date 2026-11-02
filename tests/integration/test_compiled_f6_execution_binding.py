"""Source-backed software checks for the compiled F6 live path/binding."""
from copy import deepcopy
import hashlib
import json

import pytest

from tests.integration.test_compiled_f6_contract import ROOT, f6, source_inputs


@pytest.fixture(scope='module')
def inputs():
    request, compiled, artifacts = source_inputs()
    from myfuzz.scenario.ownership import compile_ownership
    compiled_inputs = dict(request=request, compiled=compiled,
        ownership=compile_ownership((), ()), physical_port_map={})
    return compiled_inputs, artifacts


def test_runtime_path_admission_adds_exact_ram_read_write_route_pair(inputs):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    compiled_inputs, artifacts = inputs
    before = deepcopy(compiled_inputs['compiled'])
    admitted = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=ROOT)

    assert admitted['schema_version'] == 'compiled_F6_runtime_path_admission.v1'
    assert compiled_inputs['compiled'] == before
    assert admitted['compiled_document_sha256']
    assert admitted['execution_contract'] == f6(compiled_inputs['compiled'])['execution_contract']
    assert admitted['d3_path']['logical_path_id'] == f6(compiled_inputs['compiled'])['path_id']

    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    prepared = PreparedRuntimePathContract.from_document(admitted['prepared_runtime_paths'])
    routes = prepared.contract.dma_master_routes
    assert len(routes) == 2
    assert {route.operation for route in routes} == {'read', 'write'}
    assert {route.permissions for route in routes} == {('read',), ('write',)}
    assert all(route.target_kind == 'persistent_memory' for route in routes)
    assert len({route.target_id for route in routes}) == 1
    selected = [edge for _, path in prepared.runtime_paths for edge in path.edges]
    assert sum(edge.kind == 'DMA_MASTER_TRANSFER' for edge in selected) == 2

    declaration = admitted['dma_intent_binding']
    assert declaration['schema_version'] == 'dma_intent_binding_declaration.v1'
    links = declaration['route_links']
    assert len(links) == 2
    assert {row['endpoint_link']['static_endpoint_id'] for row in links} == {'dma.memory'}
    assert {row['endpoint_link']['runtime_endpoint_id'] for row in links} == {
        'read_master', 'write_master'}
    assert {row['endpoint_link']['mode'] for row in links} == {'explicit_alias'}


@pytest.mark.parametrize('mutation', ['compiled', 'artifact', 'route_intents'])
def test_runtime_path_admission_recompiles_same_call_inputs(inputs, mutation):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    compiled_inputs, original_artifacts = inputs
    altered_inputs = dict(compiled_inputs)
    artifacts = dict(original_artifacts)
    if mutation == 'compiled':
        altered_inputs['compiled'] = deepcopy(compiled_inputs['compiled'])
        f6(altered_inputs['compiled'])['execution_contract']['path_id'] += '.drift'
    elif mutation == 'artifact':
        from dataclasses import replace
        artifacts['dma'] = deepcopy(original_artifacts['dma'])
        artifacts['dma'] = replace(artifacts['dma'], runtime_sv=(
            artifacts['dma'].runtime_sv + '\n// source-backed identity drift\n'))
    else:
        from dataclasses import replace
        from myfuzz.scenario.compiled_paths import load_path_wiring
        document = json.loads(json.dumps(compiled_inputs['request'].document,
            sort_keys=True))
        document['wiring']['dma_master_routes']['routes'].pop()
        document['wiring']['dma_master_route_bindings'].pop()
        document['wiring']['dma_master_routes_sha256'] = hashlib.sha256(
            json.dumps(document['wiring']['dma_master_routes'],
                sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                allow_nan=False).encode()).hexdigest()
        wiring = load_path_wiring(document['wiring'])
        altered_inputs['request'] = replace(compiled_inputs['request'],
            wiring=wiring, document=document)
    with pytest.raises((TypeError, ValueError)):
        admit_compiled_f6_runtime_path(artifacts=artifacts,
            compiled_inputs=altered_inputs, base_dir=ROOT)


def test_execution_binding_rejects_detached_document_as_live_authority():
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding

    # Serialized owner and route fields are not a live Runner/session grant.
    detached = dict(schema_version='compiled_F6_execution_binding.v1',
        binding_sha256='0'*64, execution_binding_sha256='1'*64)
    with pytest.raises((TypeError, ValueError)):
        validate_f6_execution_binding(detached, contract={}, artifacts={},
            compiled_inputs={}, base_dir=ROOT, run_id='run', program={},
            runner=object(), bound_topology=object())


def test_runtime_path_artifact_link_document_is_actual_closed_binder_input(inputs):
    from myfuzz.integration.compiled_f6_runtime_path import _artifact_link_document
    from myfuzz.local_harness.dma_artifact_endpoint_links import (
        validate_dma_artifact_endpoint_links)

    compiled_inputs, artifacts = inputs
    document = _artifact_link_document(artifacts['dma'])
    parsed = validate_dma_artifact_endpoint_links(document, artifacts['dma'])
    assert parsed.document() == document


def _live_binding_context(compiled_inputs, artifacts, tmp_path,
                          dma_session_type=None, boundary_static_validation=False):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path, restore_prepared_runtime_paths,
        _artifact_link_document)
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    if dma_session_type is None:
        dma_session_type = GeneratedWishboneDmaSession
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.dma_intent_topology_binding import (
        PreparedDmaIntentBinding, bind_dma_intent_topology)
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner

    path = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=ROOT)
    contract = path['execution_contract']
    resource = contract['memory']['resource']
    memory = PersistentMemory(regions=(MemoryRegion(resource['resource_id'],
        resource['base'], resource['size'], readable=resource['read'],
        writable=resource['write']),), initialization_seed=0,
        max_initialized_bytes=resource['size'])
    program = build_f6_firmware(contract)
    for address, data in program.initial_images.items():
        memory.preload(address, data)
    for address, count in program.instruction_slots:
        memory.declare_instruction_slots(address, count)

    dma_id = contract['dma']['instance_id']
    cpu_id = contract['cpu']['instance_id']
    dma = dma_session_type(artifacts[dma_id], base_dir=ROOT,
        cache_dir=tmp_path, memory_service=MemoryService(memory,
            TransactionLedger(), include_writer_kinds=True, commit_stream_capacity=64),
        source_component=dma_id)
    control = contract['control']
    cpu = GeneratedCve2Session(artifacts[cpu_id], base_dir=ROOT,
        cache_dir=tmp_path, memory=memory,
        router=DataflowRouter((DeviceWindow(control['device_id'],
            control['base'], control['size'], dma),)), native_irq_receipts=True,
        memory_commit_receipts=True, memory_readback_receipts=True,
        physical_tick_samples=True)
    runner = ScenarioRunner(sessions={cpu_id: cpu, dma_id: dma},
        ownership=compiled_inputs['ownership'], bindings=())
    prepared = restore_prepared_runtime_paths(path)
    declaration = PreparedDmaIntentBinding.from_document(
        path['dma_intent_binding'], prepared_runtime_paths=prepared)
    bound = bind_dma_intent_topology(declaration, runner,
        artifact_links={dma_id: _artifact_link_document(artifacts[dma_id])},
        path_ids=tuple(path['runtime_path_ids']),
        boundary_static_validation=boundary_static_validation)
    routes = {route.operation: route for route in prepared.contract.dma_master_routes}
    policy = F6RamDmaPolicy(contract)
    admission = DmaMasterRouteAdmission(policy, bound,
        path_id=path['runtime_path_ids'][0], read_route=routes['read'],
        write_route=routes['write'])
    dma.configure_dma_route_admission(admission)
    return dict(path=path, contract=contract, program=program,
        runner=runner, bound=bound, cpu=cpu, dma=dma, policy=policy,
        admission=admission, prepared=prepared)


@pytest.fixture
def live_binding(inputs, tmp_path):
    compiled_inputs, artifacts = inputs
    return compiled_inputs, artifacts, _live_binding_context(
        compiled_inputs, artifacts, tmp_path)


def test_live_execution_binding_rejects_same_sessions_under_a_different_runner(live_binding):
    from myfuzz.scenario.f6_execution_binding import (
        build_f6_execution_binding, validate_f6_execution_binding)
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return
    from myfuzz.scenario.runner import ScenarioRunner

    compiled_inputs, artifacts, live = live_binding
    duplicate_runner = ScenarioRunner(sessions=dict(live['runner'].sessions),
        ownership=compiled_inputs['ownership'], bindings=())
    with pytest.raises(ValueError, match='compiled-F6-execution-binding-topology-runner-owner'):
        build_f6_execution_binding(contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='binding-owner', program=live['program'], runner=duplicate_runner,
            bound_topology=live['bound'])


def test_live_execution_binding_rejects_stale_credential_and_substituted_route_index(
        live_binding, tmp_path):
    from hashlib import sha256
    import json

    from myfuzz.integration.compiled_f6_runtime_path import restore_prepared_runtime_paths
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.scenario.dma_intent_topology_binding import BoundDmaIntentTopology
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner

    compiled_inputs, artifacts, live = live_binding
    prepared = restore_prepared_runtime_paths(live['path'])
    credential = live['bound'].document()
    credential['prepared_sha256'] = '0' * 64
    body = {key: value for key, value in credential.items()
        if key != 'identity_sha256'}
    credential['identity_sha256'] = sha256(json.dumps(body, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    encoded = json.dumps(credential, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    forged = BoundDmaIntentTopology(live['bound'].runtime_compilation,
        object(), encoded)

    dma = GeneratedWishboneDmaSession(artifacts['dma'], base_dir=ROOT,
        cache_dir=tmp_path, memory_service=MemoryService(live['cpu'].memory,
            TransactionLedger(), include_writer_kinds=True, commit_stream_capacity=64),
        source_component='dma')
    control = live['contract']['control']
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=ROOT,
        cache_dir=tmp_path, memory=live['cpu'].memory,
        router=DataflowRouter((DeviceWindow(control['device_id'], control['base'],
            control['size'], dma),)), native_irq_receipts=True,
        memory_commit_receipts=True, memory_readback_receipts=True,
        physical_tick_samples=True)
    routes = {route.operation: route for route in prepared.contract.dma_master_routes}
    admission = DmaMasterRouteAdmission(F6RamDmaPolicy(live['contract']), forged,
        path_id=live['path']['runtime_path_ids'][0], read_route=routes['read'],
        write_route=routes['write'])
    dma.configure_dma_route_admission(admission)
    runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma},
        ownership=compiled_inputs['ownership'], bindings=())

    with pytest.raises(ValueError, match='compiled-F6-execution-binding'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT, run_id='forged-topology',
            program=live['program'], runner=runner, bound_topology=forged)


def test_live_execution_binding_requires_route_path_selected_by_same_admission(
        live_binding, tmp_path):
    from myfuzz.integration.compiled_f6_runtime_path import restore_prepared_runtime_paths
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner

    compiled_inputs, artifacts, live = live_binding
    prepared = restore_prepared_runtime_paths(live['path'])
    dma = GeneratedWishboneDmaSession(artifacts['dma'], base_dir=ROOT,
        cache_dir=tmp_path, memory_service=MemoryService(live['cpu'].memory,
            TransactionLedger(), include_writer_kinds=True, commit_stream_capacity=64),
        source_component='dma')
    control = live['contract']['control']
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=ROOT,
        cache_dir=tmp_path, memory=live['cpu'].memory,
        router=DataflowRouter((DeviceWindow(control['device_id'], control['base'],
            control['size'], dma),)), native_irq_receipts=True,
        memory_commit_receipts=True, memory_readback_receipts=True,
        physical_tick_samples=True)
    routes = {route.operation: route for route in prepared.contract.dma_master_routes}
    admission = DmaMasterRouteAdmission(F6RamDmaPolicy(live['contract']),
        live['bound'], path_id='unselected-path', read_route=routes['read'],
        write_route=routes['write'])
    dma.configure_dma_route_admission(admission)
    runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma},
        ownership=compiled_inputs['ownership'], bindings=())

    with pytest.raises(ValueError, match='compiled-F6-execution-binding'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT, run_id='unselected-route',
            program=live['program'], runner=runner, bound_topology=live['bound'])


def test_live_execution_binding_revocation_clears_authority(live_binding):
    from myfuzz.scenario.f6_execution_binding import (
        build_f6_execution_binding, revoke_f6_execution_binding,
        validate_f6_execution_binding)
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return

    compiled_inputs, artifacts, live = live_binding
    binding = build_f6_execution_binding(contract=live['contract'],
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        run_id='revocable-binding', program=live['program'], runner=live['runner'],
        bound_topology=live['bound'])
    install_f6_isr_return(live['cpu'], contract=live['contract'],
        execution_binding_sha256=binding['binding_sha256'])
    validate_f6_execution_binding(binding, contract=live['contract'],
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        run_id='revocable-binding', program=live['program'], runner=live['runner'],
        bound_topology=live['bound'])

    assert revoke_f6_execution_binding(live['runner'],
        binding['binding_sha256']) is True
    with pytest.raises(ValueError, match='compiled-F6-execution-binding-live-owner-required'):
        validate_f6_execution_binding(binding, contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='revocable-binding', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_live_execution_binding_accepts_scheduler_dma_subclass(inputs, tmp_path):
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)
    from myfuzz.scenario.f6_execution_binding import (
        build_f6_execution_binding, validate_f6_execution_binding)
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return

    compiled_inputs, artifacts = inputs
    live = _live_binding_context(compiled_inputs, artifacts, tmp_path,
        dma_session_type=GeneratedWishboneDmaScenarioSession)
    assert type(live['dma']) is GeneratedWishboneDmaScenarioSession
    binding = build_f6_execution_binding(contract=live['contract'],
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        run_id='scheduler-subclass-binding', program=live['program'],
        runner=live['runner'], bound_topology=live['bound'])
    install_f6_isr_return(live['cpu'], contract=live['contract'],
        execution_binding_sha256=binding['binding_sha256'])
    assert validate_f6_execution_binding(binding, contract=live['contract'],
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        run_id='scheduler-subclass-binding', program=live['program'],
        runner=live['runner'], bound_topology=live['bound']) == binding


def test_execution_binding_rejects_rebound_scheduler_dma_class_alias(
        inputs, tmp_path, monkeypatch):
    import myfuzz.local_harness.wishbone_dma_scenario_session as scenario_dma
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding

    compiled_inputs, artifacts = inputs
    original_class = scenario_dma.GeneratedWishboneDmaScenarioSession
    live = _live_binding_context(compiled_inputs, artifacts, tmp_path,
        dma_session_type=original_class)

    class SpoofedScenarioDma(original_class):
        pass

    monkeypatch.setattr(scenario_dma, 'GeneratedWishboneDmaScenarioSession',
        SpoofedScenarioDma)
    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-dma-session-class'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='rebound-scheduler-dma-class', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_execution_binding_rejects_scheduler_subclass_base_method_override(
        inputs, tmp_path, monkeypatch):
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding

    compiled_inputs, artifacts = inputs
    live = _live_binding_context(compiled_inputs, artifacts, tmp_path,
        dma_session_type=GeneratedWishboneDmaScenarioSession)
    monkeypatch.setattr(GeneratedWishboneDmaSession,
        'configure_dma_route_admission', lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-route-admission-validator'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='scheduler-dma-method-override', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_execution_binding_rejects_scheduler_override_method_drift(
        inputs, tmp_path, monkeypatch):
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding

    compiled_inputs, artifacts = inputs
    live = _live_binding_context(compiled_inputs, artifacts, tmp_path,
        dma_session_type=GeneratedWishboneDmaScenarioSession)
    monkeypatch.setattr(GeneratedWishboneDmaScenarioSession,
        'step_local', lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-dma-session-class'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='scheduler-dma-step-local-drift', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


@pytest.mark.parametrize('attribute,value', [
    ('artifact_kind', 'spoofed_wishbone_dma'),
    ('max_local_ticks_per_step', 2),
    ('max_transaction_events_per_step', 2),
    ('max_mmio_target_accesses_per_step', 1),
])
def test_execution_binding_rejects_scheduler_class_data_attribute_drift(
        inputs, tmp_path, monkeypatch, attribute, value):
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding

    compiled_inputs, artifacts = inputs
    live = _live_binding_context(compiled_inputs, artifacts, tmp_path,
        dma_session_type=GeneratedWishboneDmaScenarioSession)
    monkeypatch.setattr(GeneratedWishboneDmaScenarioSession, attribute, value)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-dma-session-class'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='scheduler-dma-class-data-drift-' + attribute,
            program=live['program'], runner=live['runner'],
            bound_topology=live['bound'])


def _build_and_install_binding(compiled_inputs, artifacts, live, run_id):
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return

    binding = build_f6_execution_binding(contract=live['contract'],
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        run_id=run_id, program=live['program'], runner=live['runner'],
        bound_topology=live['bound'])
    install_f6_isr_return(live['cpu'], contract=live['contract'],
        execution_binding_sha256=binding['binding_sha256'])
    return binding


def test_execution_binding_validation_requires_its_digest(live_binding):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding

    compiled_inputs, artifacts, live = live_binding
    binding = _build_and_install_binding(compiled_inputs, artifacts, live,
        'missing-binding-digest')
    incomplete = dict(binding)
    del incomplete['binding_sha256']

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-schema'):
        validate_f6_execution_binding(incomplete, contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='missing-binding-digest', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


@pytest.mark.parametrize('policy_kind', ['duck_typed_f6_identity', 'wrong_contract'])
def test_execution_binding_requires_the_exact_f6_policy_and_contract(
        live_binding, policy_kind):
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy

    compiled_inputs, artifacts, live = live_binding
    admission = live['admission']
    actual = admission._beat_policy
    if policy_kind == 'duck_typed_f6_identity':
        class DuckPolicy:
            state = 'idle'

            def identity_document(self):
                return actual.identity_document()

            def begin_case(self, *_args):
                pass

            def accepted(self, *_args, **_kwargs):
                pass

            def completed(self, *_args, **_kwargs):
                pass

        admission._beat_policy = DuckPolicy()
    else:
        wrong_contract = deepcopy(live['contract'])
        wrong_contract['candidate_layout']['seed'].reverse()
        admission._beat_policy = F6RamDmaPolicy(wrong_contract)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-policy'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='wrong-f6-policy-' + policy_kind, program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_execution_binding_rejects_semantically_identical_admission_replacement(
        live_binding):
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding

    compiled_inputs, artifacts, live = live_binding
    binding = _build_and_install_binding(compiled_inputs, artifacts, live,
        'replacement-route-admission')
    original = live['admission']
    live['dma']._dma_route_admission = DmaMasterRouteAdmission(
        original._beat_policy, live['bound'], path_id=original._path_id,
        read_route=original._read_route, write_route=original._write_route)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-owner-route-admission'):
        validate_f6_execution_binding(binding, contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='replacement-route-admission', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_execution_binding_rejects_semantically_identical_policy_replacement(
        live_binding):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy

    compiled_inputs, artifacts, live = live_binding
    binding = _build_and_install_binding(compiled_inputs, artifacts, live,
        'replacement-route-policy')
    live['admission']._beat_policy = F6RamDmaPolicy(live['contract'])

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-owner-route-policy'):
        validate_f6_execution_binding(binding, contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='replacement-route-policy', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])


def test_dma_route_admission_is_weak_referenceable(live_binding):
    from weakref import ref

    _compiled_inputs, _artifacts, live = live_binding
    assert ref(live['admission'])() is live['admission']


@pytest.mark.parametrize('method_name', ['accepted', 'begin_case'])
def test_execution_binding_rejects_f6_policy_class_method_patch_before_bind(
        live_binding, monkeypatch, method_name):
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy

    compiled_inputs, artifacts, live = live_binding
    monkeypatch.setattr(F6RamDmaPolicy, method_name,
        lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-policy-method-owner'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='patched-policy-before-bind-' + method_name,
            program=live['program'], runner=live['runner'],
            bound_topology=live['bound'])


@pytest.mark.parametrize('method_name', ['accepted', 'begin_case'])
def test_execution_binding_rejects_f6_policy_class_method_patch_after_bind(
        live_binding, monkeypatch, method_name):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy

    compiled_inputs, artifacts, live = live_binding
    run_id = 'patched-policy-after-bind-' + method_name
    binding = _build_and_install_binding(compiled_inputs, artifacts, live, run_id)
    monkeypatch.setattr(F6RamDmaPolicy, method_name,
        lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-policy-method-owner'):
        validate_f6_execution_binding(binding, contract=live['contract'],
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id=run_id, program=live['program'], runner=live['runner'],
            bound_topology=live['bound'])


def test_execution_binding_rejects_noop_dma_route_validator_before_bind(
        live_binding):
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    from myfuzz.local_harness.wishbone_dma_session import (
        _F6_ROUTE_VALIDATOR_OWNERS, _verify_f6_dma_route_validator)

    compiled_inputs, artifacts, live = live_binding
    assert live['dma'] in _F6_ROUTE_VALIDATOR_OWNERS
    assert _verify_f6_dma_route_validator(live['dma'],
        admission=live['admission']) is True
    live['dma']._dma_route_validator = lambda: None

    with pytest.raises(ValueError,
            match='compiled-F6-execution-binding-route-admission-validator'):
        build_f6_execution_binding(contract=live['contract'], artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            run_id='noop-route-validator-before-bind', program=live['program'],
            runner=live['runner'], bound_topology=live['bound'])



def test_boundary_mode_uses_registered_dynamic_callback_and_full_binding_boundary(inputs,tmp_path):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    from myfuzz.local_harness.wishbone_dma_session import _verify_f6_dma_route_validator
    compiled_inputs,artifacts=inputs
    live=_live_binding_context(compiled_inputs,artifacts,tmp_path,boundary_static_validation=True)
    binding=_build_and_install_binding(compiled_inputs,artifacts,live,'boundary-owner')
    assert _verify_f6_dma_route_validator(live['dma'],admission=live['admission'])
    compilation=live['bound'].runtime_compilation
    assert compilation._boundary_static_validation is True
    live['dma']._validate_dma_route_topology()
    document=artifacts['dma'].runtime_document
    document['static_boundary_test']=1
    try:
        live['dma']._validate_dma_route_topology()
        with pytest.raises(ValueError):
            validate_f6_execution_binding(binding,contract=live['contract'],artifacts=artifacts,
                compiled_inputs=compiled_inputs,base_dir=ROOT,run_id='boundary-owner',
                program=live['program'],runner=live['runner'],bound_topology=live['bound'])
    finally:
        document.pop('static_boundary_test')
