"""Shared slots separate physical position, session order and F6 ordinal."""
from copy import deepcopy
from dataclasses import replace
import pytest

from tests.integration.test_f6_storage_shared_assembly import inputs, ROOT


def mixed_inputs(inputs):
    from myfuzz.scenario.compiled_paths import compile_paths
    compiled, artifacts = inputs
    doc = deepcopy(compiled['request'].document)
    doc['f6_execution']['program']['slot_count'] = 4
    doc['f6_execution']['shared_slots'] = dict(component='peripheral',
        contract_id='pulp-apb-timer.ctrl0.source.v1', register='TIMER0_CTRL', results_base=0x25000)
    request = replace(compiled['request'], document=doc)
    return dict(compiled, request=request, compiled=compile_paths(request)), artifacts


def test_union_contract_selects_real_storage_and_dma_paths(inputs, tmp_path):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path, restore_prepared_runtime_paths
    compiled, artifacts = mixed_inputs(inputs)
    admitted = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=compiled, base_dir=ROOT)
    prepared = restore_prepared_runtime_paths(admitted)
    assert len(prepared.runtime_paths) == 3
    assert len(prepared.contract.dma_master_routes) == 2
    shared = admitted['shared_storage_path']
    assert shared['component'] == 'peripheral'
    assert shared['source_id'] == 'F4.program_image'
    assert shared['path_id'] == prepared.path_ids[2]


def test_shared_writer_is_canonical_writer_plus_completion_footer(inputs):
    from myfuzz.integration.shared_f6_slots import declare_shared_writer
    compiled, _ = mixed_inputs(inputs)
    support = next(p['execution_contract']['program_contract']['shared_slots']
        for p in compiled['compiled']['paths'] if p['flow_id'] == 'F6')
    declaration = declare_shared_writer(compiled, support, raw=(85).to_bytes(4, 'little'), slot_index=0)
    code = bytes.fromhex(declaration['code_hex'])
    assert len(code) == 128
    assert code[:48].hex() == declaration['canonical_writer_code_hex']
    assert code[48:56].hex() == '1305100093051000'


def test_union_binding_consumes_all_three_actual_owners(inputs, tmp_path):
    from tests.integration.test_f6_storage_shared_assembly import live_session_binding
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    mixed = mixed_inputs(inputs)
    assembly, session, binding, kwargs = live_session_binding(mixed, tmp_path)
    validate_f6_execution_binding(binding, **kwargs)
    assert {name for name, _ in session.bound_dma_topology.runtime_compilation._sessions} == {
        'cpu', 'dma', 'peripheral'}
    assert set(assembly.companion_authorities) == {'peripheral'}
    assert binding['runtime_path_admission']['shared_storage_path']['component'] == 'peripheral'


def test_public_descriptor_selects_real_mixed_records():
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    descriptor = load_descriptor(ROOT/'configs/scenarios/compiled-f6-ibex-wbdmac-storage/generic_shared_slots.json', base_dir=ROOT)
    rows = ['F4:55000000','F6:0110c00008000000','F4:aa000000','F6:0110c00008000000']
    assert descriptor.shared_slots and len(descriptor.capability) == 2
    assert select_case_records(descriptor, flow='mixed', records=rows) == tuple(tuple(row.split(':')) for row in rows)


def test_public_preparation_issues_one_joint_source_backed_union(tmp_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    descriptor = load_descriptor(ROOT/'configs/scenarios/compiled-f6-ibex-wbdmac-storage/generic_shared_slots.json', base_dir=ROOT)
    with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
        context = create_preparation(base_dir=ROOT, compose_path=descriptor.compose,
            capability_paths=descriptor.capability, supplement_path=descriptor.supplement,
            generated_dir=tmp_path/'generated', flow_ids=descriptor.flow_ids)
        try:
            admitted = admit_compiled_f6_runtime_path(artifacts=dict(context.artifacts),
                compiled_inputs=context.compiled_inputs(), base_dir=ROOT)
            assert len(admitted['runtime_path_ids']) == 3
            assert admitted['execution_contract']['program_contract']['slot_count'] == 4
        finally:
            context.close()


def test_real_constructor_installs_joint_paths_and_sealed_mapping(inputs, tmp_path, monkeypatch):
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.shared_f6_slots import flow_records
    from tests.integration.test_f6_storage_shared_assembly import assemble
    compiled, artifacts = mixed_inputs(inputs)
    assembly = assemble((compiled, artifacts), tmp_path)
    _install_software_process_boundary(monkeypatch)
    runtime = CompiledF6Runtime(artifacts=artifacts, compiled_inputs=compiled,
        base_dir=ROOT, cache_dir=tmp_path, max_cases=2, defer_begin=True, shared_assembly=assembly)
    assert runtime._begin_state == 'created'
    assert len(runtime.session.instruction_image_binding_documents) == 2
    assert len(runtime.session.runtime_path_ids) == 3
    assert flow_records(runtime) == []
    assert runtime._f6_isr_return is runtime.cpu._f6_isr_return


def test_online_dispatch_separates_global_slot_and_DMA_ordinals(monkeypatch):
    """Software boundary only: actual submit/ledger, simulated case execution."""
    from types import SimpleNamespace
    from myfuzz.integration import compiled_f6 as module, shared_f6_slots as slots
    class CPU:
        pass
    runtime = module.CompiledF6Runtime.__new__(module.CompiledF6Runtime)
    cpu = CPU()
    cpu._execution, cpu._case_id, cpu.reset_epoch = 'a'*32, 'native', 1
    cpu.process = SimpleNamespace(poll=lambda: None)
    runtime.cpu, runtime.memory, runtime.runner = cpu, object(), object()
    runtime.session = SimpleNamespace(_cases=[])
    runtime.contract = {'program_contract': {'shared_slots': {'enabled_flows':['F4','F6']}, 'slot_count':4, 'slot_base':0x11000}}
    runtime.run_id, runtime.finished, runtime.cursor, runtime.max_cases = 'online', False, 0, 2
    runtime.records, runtime.attempts, runtime.observer_view = [], [], []
    runtime.compiled_inputs = {'compiled':{}}
    runtime.runtime_path_admission = {}
    runtime.layout = SimpleNamespace(decode=lambda raw: SimpleNamespace(raw=raw, words=(1,2,3,4)))
    runtime._verify_live_owner = lambda: True
    runtime._drain_observer_view = lambda: None
    transitions = []
    monkeypatch.setattr(module, 'advance_f6_dma_logical_scope',
        lambda owner, prior, next_case_index: transitions.append((prior['case_index'],next_case_index)))
    def execute(self, candidate, index, attempt):
        self.session._cases.append(SimpleNamespace(case_id=attempt['case_id']))
        event = dict(event_id=len(self.observer_view)+1, address=attempt['instruction_address']+256)
        self.observer_view.append(event)
        attempt['next_fetch'] = event['event_id']
        attempt['status_kind'] = 'passed'
        return dict(status='passed', prefix_hex='00'*128, feedback=[1]*5)
    monkeypatch.setattr(module.CompiledF6Runtime, '_execute_case', execute)
    slots._RUNTIMES[runtime] = dict(cpu=cpu, memory=runtime.memory, runner=runtime.runner,
        session=runtime.session, scope=None, rows=[], pins=tuple((name,
            getattr(type(runtime), name), getattr(type(runtime), name).__code__)
            for name in ('submit','_execute_case')))
    monkeypatch.setattr(slots, 'declare_shared_writer', lambda *a, **k: {})
    from myfuzz.integration import shared_slot_consumers
    monkeypatch.setattr(shared_slot_consumers,'declare_slot',lambda *a, **k: {})
    from myfuzz.integration import shared_slot_auxiliary
    monkeypatch.setattr(shared_slot_auxiliary,'auxiliary_sources',lambda *a,**k: [])
    def writer(owner, raw, mapping):
        owner.session._cases.append(SimpleNamespace(case_id=mapping['case_id']))
        certificate = dict(status='certified', value=int.from_bytes(raw,'little'))
        slots.seal_case(owner, mapping['case_id'], certificate, {'address':0})
        return certificate
    monkeypatch.setattr(slots, 'submit_writer', writer)
    # Deliberately simulated execution helpers, never a native authority grant.
    monkeypatch.setattr(slots, '_HELPER_PINS', tuple((name, getattr(slots, name),
        getattr(slots, name).__code__) for name, _, _ in slots._HELPER_PINS))
    # Each next action is chosen only after the previous call returns.
    runtime.submit(bytes.fromhex('55000000'), flow='F4')
    runtime.submit(bytes.fromhex('0110c00008000000'))
    runtime.submit(bytes.fromhex('aa000000'), flow='F4')
    runtime.submit(bytes.fromhex('0110c00008000000'))
    rows = slots.flow_records(runtime)
    assert [row['flow'] for row in rows] == ['F4','F6','F4','F6']
    assert [row['slot_index'] for row in rows] == [0,1,2,3]
    assert [row['session_case_index'] for row in rows] == [0,1,2,3]
    assert [row['f6_case_index'] for row in rows] == [None,0,None,1]
    assert len(runtime.records) == len(runtime.attempts) == 2
    assert [row['slot_index'] for row in runtime.attempts] == [1,3]
    assert transitions == [(0,1)]
    rows[0]['flow'] = 'F6'
    assert slots.flow_records(runtime)[0]['flow'] == 'F4'
    slots._RUNTIMES[runtime]['rows'][0]['slot_index'] = 9
    with pytest.raises(ValueError, match='sealed-record-drift'):
        slots.flow_records(runtime)


def test_shared_catalog_preserves_flow_family_and_online_pending():
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.search.descriptor_search import RecordSelector
    descriptor = load_descriptor(ROOT/'configs/scenarios/compiled-f6-ibex-wbdmac-storage/generic_shared_slots.json', base_dir=ROOT)
    rows = ['F4:55000000','F6:0110c00008000000']
    selector = RecordSelector(descriptor, flow='mixed', records=rows, policy='state', seed=7, cases=4)
    assert {row.source_id for row in selector.catalog.actions} == {'F4','F6'}
    first = selector.choose()
    assert first in rows
    with pytest.raises(ValueError, match='previous decision pending'):
        selector.choose()
    selector.settle(first)
    second = selector.choose()
    assert second in rows
    selector.settle(second)
    assert selector.document()['sequence'] == [first,second]


def test_typed_slot_mapping_rejects_wrong_source_path_and_address(inputs, tmp_path):
    from types import SimpleNamespace
    from myfuzz.integration import shared_f6_slots as slots
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.scenario.session_runtime import OnlineCase, BoundOnlineInstruction, BatchAdvance
    compiled, artifacts = mixed_inputs(inputs)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=compiled, base_dir=ROOT)
    runtime = CompiledF6Runtime.__new__(CompiledF6Runtime)
    runtime.cpu, runtime.runner, runtime.memory = object(), object(), object()
    runtime.session = SimpleNamespace(_cases=[])
    runtime.compiled_inputs, runtime.runtime_path_admission = compiled, admission
    runtime.contract = admission['execution_contract']
    layout = runtime.contract['program_contract']['shared_slots']
    declaration = slots.declare_shared_writer(compiled, layout, raw=bytes.fromhex('55000000'), slot_index=0)
    path = admission['shared_storage_path']
    address = runtime.contract['program_contract']['slot_base']
    case = OnlineCase('typed:F4:0', 'CPU_TO_IP', path['path_id'],
        BoundOnlineInstruction('writer', 'cpu', address, declaration['code_hex'], path['source_id']), (BatchAdvance(('cpu',)),))
    runtime.session._cases.append(case)
    slots._RUNTIMES[runtime] = dict(cpu=runtime.cpu, memory=runtime.memory, runner=runtime.runner,
        session=runtime.session, scope=None, pins=[], rows=[dict(case_id=case.case_id,
            flow='F4', raw_hex='55000000', slot_index=0,session_case_index=0,f6_case_index=None,status='reserved')])
    assert slots.instruction_case_mapping(runtime, runtime.session, case, 0)['flow'] == 'F4'
    for bad in (replace(case, path_id=admission['runtime_path_ids'][1]),
                replace(case, source=replace(case.source, source_id=runtime.contract['instruction_source_id'])),
                replace(case, source=replace(case.source, address=address+256))):
        runtime.session._cases[0] = bad
        with pytest.raises(ValueError, match='typed-path-source-mapping'):
            slots.instruction_case_mapping(runtime, runtime.session, bad, 0)
