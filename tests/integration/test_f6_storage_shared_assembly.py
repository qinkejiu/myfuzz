"""Three actual pre-start component owners, with no native build or launch."""
from copy import deepcopy
from dataclasses import replace
import pytest

from tests.integration.test_compiled_f6_contract import ROOT, source_inputs
from tests.integration.test_compiled_f4_storage_producer import timer_loaded


@pytest.fixture(scope='module')
def inputs(tmp_path_factory):
    from myfuzz.scenario.compiled_paths import compile_paths, load_path_wiring
    from myfuzz.scenario.ownership import compile_ownership
    request, _, artifacts = source_inputs()
    storage_artifacts, storage_inputs = timer_loaded(tmp_path_factory.mktemp('f6-storage-source'))
    storage = storage_inputs['request'].devices[0]
    wiring = deepcopy(dict(request.wiring.document))
    storage_window = storage_inputs['request'].wiring.document['windows'][0]
    wiring['windows'].append(deepcopy(dict(storage_window)))
    document = deepcopy(request.document)
    document['devices'].append(deepcopy(storage_inputs['request'].document['devices'][0]))
    document['wiring'] = wiring
    request = replace(request, devices=(*request.devices, storage),
        wiring=load_path_wiring(wiring), document=document)
    artifacts = dict(artifacts, **{storage.instance_id: storage_artifacts[storage.instance_id]})
    return dict(request=request, compiled=compile_paths(request),
        ownership=compile_ownership((), ()), physical_port_map={}), artifacts


def assemble(inputs, tmp_path, **kwargs):
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly
    compiled, artifacts = inputs
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled, base_dir=ROOT)
    return build_f6_assembly(contract=admission['execution_contract'], artifacts=artifacts,
        request=compiled['request'], ownership=_f6_runner_ownership(compiled['ownership'],
            cpu_id='cpu', dma_id='dma'), base_dir=ROOT, cache_dir=tmp_path, **kwargs)


def test_three_components_share_one_cpu_ram_router_and_runner(inputs, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    assembly = assemble(inputs, tmp_path)
    assert set(assembly.runner.sessions) == {'cpu', 'dma', 'peripheral'}
    storage = assembly.runner.sessions['peripheral']
    assert type(storage) is GeneratedApb3RegisterSession
    assert assembly.cpu.memory is assembly.dma.memory_service.memory is assembly.memory
    assert {window.device_id: window.target for window in assembly.cpu.router.windows} == {
        'dma': assembly.dma, 'peripheral': storage}
    assert len(assembly.runner.bindings) == 1
    assert assembly.runner.bindings[0].source_component == 'dma'
    assert all(local.process is None for local in assembly.runner.sessions.values())
    assert assembly.companion_document()['peripheral']['register'] == 'TIMER0_CTRL'


def test_external_companion_session_is_reused(inputs, tmp_path):
    first = assemble(inputs, tmp_path)
    second = assemble(inputs, tmp_path, memory=first.memory, cpu=first.cpu,
        dma=first.dma, runner=first.runner, companions=first.companions)
    assert second.runner is first.runner
    assert second.companions['peripheral'] is first.companions['peripheral']


def test_extra_artifact_without_typed_declaration_is_refused(inputs, tmp_path):
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    compiled, artifacts = inputs
    contract = next(p for p in compiled['compiled']['paths'] if p['flow_id'] == 'F6')['execution_contract']
    with pytest.raises(ValueError, match='companion-request-required'):
        build_f6_assembly(contract=contract, artifacts=artifacts,
            ownership=_f6_runner_ownership(compiled['ownership'], cpu_id='cpu', dma_id='dma'),
            base_dir=ROOT, cache_dir=tmp_path)


def test_three_component_constructor_consumes_external_assembly(inputs, tmp_path, monkeypatch):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    assembly = assemble(inputs, tmp_path)
    prepared = []
    class StopBeforeBuild(Exception):
        pass
    def stop(self):
        prepared.append(self)
        raise StopBeforeBuild
    monkeypatch.setattr(GeneratedCve2Session, 'prepare_local', stop)
    with pytest.raises(StopBeforeBuild):
        CompiledF6Runtime(artifacts=inputs[1], compiled_inputs=inputs[0],
            base_dir=ROOT, cache_dir=tmp_path, shared_assembly=assembly,
            max_cases=1, defer_begin=True)
    assert prepared == [assembly.cpu]


@pytest.mark.parametrize('mutation', ['hidden_setup', 'unrouted_owner'])
def test_companion_ownership_drift_refuses_before_build(inputs, tmp_path, mutation):
    first = assemble(inputs, tmp_path)
    if mutation == 'hidden_setup':
        first.companions['peripheral'].setup_writes = ((0, 1),)
    else:
        first.cpu.router.windows = first.cpu.router.windows[:1]
    with pytest.raises(ValueError, match='hidden-setup|control-window'):
        assemble(inputs, tmp_path, memory=first.memory, cpu=first.cpu, dma=first.dma,
            runner=first.runner, companions=first.companions)


def test_three_component_native_case_configuration_is_explicit_and_single_irq():
    import json
    root = ROOT / 'configs/scenarios/compiled-f6-ibex-wbdmac-storage'
    case = json.loads((root / 'assembly_case.json').read_text())
    compose = json.loads((root / case['compose']).read_text())
    supplement = json.loads((root / case['supplement']).read_text())
    assert {row['instance_id'] for row in compose['devices']} == {'dma', 'peripheral'}
    assert len(supplement['request_supplements']['deliveries']) == 1
    assert supplement['request_supplements']['deliveries'][0]['producer_instance'] == 'dma'
    assert len(case['capabilities']) == 2
    assert case['storage_flow_consumption'] == 'fixed_CPU_MMIO_readback_requires_native_evidence'


def live_session_binding(inputs, tmp_path):
    from myfuzz.integration.compiled_f6 import _f6_session_template
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path, restore_prepared_runtime_paths, _artifact_link_document)
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.dma_intent_topology_binding import PreparedDmaIntentBinding
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.scenario.f6_execution_binding import build_f6_execution_binding
    compiled, artifacts = inputs
    assembly = assemble(inputs, tmp_path)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=compiled, base_dir=ROOT)
    contract = admission['execution_contract']
    from myfuzz.integration.compiled_f6 import _digest
    from myfuzz.scenario.ibex_pulp_dual_source import install_host_ram_commit_journal
    install_host_ram_commit_journal(assembly.runner,
        services={'cpu': assembly.cpu.service, 'dma': assembly.dma.service},
        channel_ids={'cpu': 'data', 'dma': 'dma-memory'})
    assembly.runner.configure_memory_dependency_evidence(runtime_contract_sha256=_digest(contract))
    program = build_f6_firmware(contract)
    prepared = restore_prepared_runtime_paths(admission)
    template = _f6_session_template(run_id='three-component-binding', cpu_id='cpu',
        path_id=admission['runtime_path_ids'][1], program=program,
        rounds_per_case=256, runner=assembly.runner)
    assert set(template.schedule_order) == set(assembly.runner.sessions)
    session = ScenarioSession(template, assembly.runner, checker_configuration_only=True)
    declaration = PreparedDmaIntentBinding.from_document(admission['dma_intent_binding'],
        prepared_runtime_paths=prepared)
    session.configure_runtime_paths(prepared.graph, prepared.contract, prepared.runtime_paths,
        source_ownership=assembly.runner.ownership, dma_intent_binding=declaration,
        dma_artifact_links={'dma': _artifact_link_document(artifacts['dma'])})
    routes = {route.operation: route for route in prepared.contract.dma_master_routes}
    route = DmaMasterRouteAdmission(F6RamDmaPolicy(contract), session.bound_dma_topology,
        path_id=admission['runtime_path_ids'][0], read_route=routes['read'], write_route=routes['write'])
    assembly.dma.configure_dma_route_admission(route)
    kwargs = dict(contract=contract, artifacts=artifacts, compiled_inputs=compiled,
        base_dir=ROOT, run_id='three-component-binding', program=program,
        runner=assembly.runner, bound_topology=session.bound_dma_topology)
    binding = build_f6_execution_binding(**kwargs)
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return
    install_f6_isr_return(assembly.cpu, contract=contract,
        execution_binding_sha256=binding['binding_sha256'])
    return assembly, session, binding, kwargs


def test_shared_session_accepts_three_component_template_and_full_typed_binding(inputs, tmp_path):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    assembly, session, binding, kwargs = live_session_binding(inputs, tmp_path)
    validate_f6_execution_binding(binding, **kwargs)
    assert set(binding['artifact_identities']) == {'cpu', 'dma', 'peripheral'}
    assert binding['issuer_contracts']['shared_companions'] == assembly.companion_document()
    # The selected DMA graph pins its two participants; the storage companion
    # is a separate live owner in the same runner, never a fabricated DMA hop.
    assert len(session.bound_dma_topology.runtime_compilation._sessions) == 2


def test_live_shared_binding_rejects_replaced_companion(inputs, tmp_path):
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    assembly, _, binding, kwargs = live_session_binding(inputs, tmp_path)
    assembly.runner.sessions['peripheral'] = object()
    with pytest.raises(ValueError, match='companion-session-owner|live-owner|topology'):
        validate_f6_execution_binding(binding, **kwargs)
