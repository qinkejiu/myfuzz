"""Actual prepared F5 pin and fixed-support declarations, no native harness."""
from copy import deepcopy
import pytest
from tests.integration.test_compiled_f6_contract import ROOT


@pytest.fixture(scope='module')
def all_six(tmp_path_factory):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.composition.component_profile import elaboration_mode_scope
    descriptor = load_descriptor(ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json',base_dir=ROOT)
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        context = create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
            capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
            generated_dir=tmp_path_factory.mktemp('all-six')/'generated',flow_ids=descriptor.flow_ids)
    yield context
    context.close()


def test_actual_all_six_preparation_rebuilds_joint_paths(all_six):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_slot_consumers import instruction_bindings
    from myfuzz.integration.shared_slot_paths import validate_shared_flow_admission
    admission = admit_compiled_f6_runtime_path(artifacts=dict(all_six.artifacts),compiled_inputs=all_six.compiled_inputs(),base_dir=ROOT)
    assert set(admission['shared_flow_paths']) == {'F1','F2','F3','F4','F5','F6'}
    assert len(admission['runtime_path_ids']) == 7
    assert len(instruction_bindings(admission)) == 5
    assert admission['shared_flow_paths']['F5']['support_flow_id'] == 'F1'
    validate_shared_flow_admission(admission)
    import json
    saved = json.loads(json.dumps(admission))
    validate_shared_flow_admission(saved)
    for field in ('path_id','source_id'):
        changed = deepcopy(saved)
        changed['shared_flow_paths']['F5'][field] += '-forged'
        with pytest.raises(ValueError,match='union-rebuild-mismatch'):
            validate_shared_flow_admission(changed)
    assert saved['prepared_runtime_paths']['selections'][-1]['direction']=='IP_TO_CPU'
    changed = deepcopy(saved)
    changed['prepared_runtime_paths']['selections'][-1]['direction']='CPU_TO_IP'
    with pytest.raises(ValueError):
        validate_shared_flow_admission(changed)
    changed = deepcopy(saved)
    changed['shared_flow_paths']['F5']['irq_group']['members'][0]['source_component'] = 'forged'
    with pytest.raises(ValueError):
        validate_shared_flow_admission(changed)


def test_all_six_fixed_support_declaration_is_NOP_and_actual_pin(all_six):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f5_slots import declare_shared_pin
    admission = admit_compiled_f6_runtime_path(artifacts=dict(all_six.artifacts),compiled_inputs=all_six.compiled_inputs(),base_dir=ROOT)
    layout = admission['execution_contract']['program_contract']['shared_slots']
    result = declare_shared_pin(all_six.compiled_inputs(),layout,admission,raw=bytes.fromhex('0000000100000000'),slot_index=0)
    assert result['code_hex']=='13000000'*32
    assert result['bit_offset']==8 and result['value']==1
    assert result['support_source_id']==admission['shared_flow_paths']['F1']['source_id']
    changed = deepcopy(admission)
    changed['shared_flow_paths']['F1']['base'] = result['instruction_address']+4
    with pytest.raises(ValueError,match='fixed-support-image-range'):
        declare_shared_pin(all_six.compiled_inputs(),layout,changed,raw=bytes.fromhex('0000000100000000'),slot_index=0)


def test_actual_session_support_callback_binds_original_acceptance(all_six,tmp_path,monkeypatch):
    """Software IPC boundary; only real MemoryService acceptance is asserted."""
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime,_f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly,shared_irq_ownership
    from myfuzz.scenario.f6_instruction_fetch_receipt import validate_shared_fixed_support,_bind_shared_fixed_support
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
    inputs,artifacts = all_six.compiled_inputs(),dict(all_six.artifacts)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    contract = admission['execution_contract']
    ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),
        contract,artifacts,base_dir=ROOT)
    assembly = build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],
        ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
    _install_software_process_boundary(monkeypatch)
    runtime = CompiledF6Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,
        cache_dir=tmp_path,max_cases=8,defer_begin=True,shared_assembly=assembly)
    # Suppress all DUT clocks; constructor and source/admission callbacks remain original.
    monkeypatch.setattr(runtime.session,'advance_initial',lambda schedule: SimpleNamespace(violations=(),status='running'))
    monkeypatch.setattr(runtime,'_bootstrap_to_first_slot',lambda: None)
    runtime.begin()
    class StopAfterSupport(Exception): pass
    def stop(*args,**kwargs): raise StopAfterSupport('stop before pin drive / DUT clocks')
    monkeypatch.setattr(runtime.runner,'inject_source',stop)
    with pytest.raises(StopAfterSupport):
        runtime.submit(bytes.fromhex('0000000100000000'),flow='F5')
    case, = runtime.session._cases
    bound = validate_shared_fixed_support(runtime.cpu,case_id=case.case_id)
    assert bound['role']=='fixed_support' and bound['slot_index']==bound['session_case_index']==0
    assert bound['F6_authority'] is False and bound['fuzz_authority'] is False
    assert bound['source']['data_hex']=='13000000'*32
    assert runtime.records == runtime.attempts == []
    # An equal-looking DTO cannot call the original fixed-support callback.
    with pytest.raises(ValueError,match='original _execute_case'):
        _bind_shared_fixed_support(runtime.cpu,runtime.session,case,0,case.support_instructions[0],None,None)


@pytest.mark.parametrize('flow,raw',[('F1','13000000'),('F2','08000040'),('F3','55000000')])
def test_real_non_DMA_source_callback_never_enrolls_F6(all_six,tmp_path,monkeypatch,flow,raw):
    """Original session callback with a real service; no DUT clock or proof."""
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime,_f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly,shared_irq_ownership
    from myfuzz.scenario.f6_instruction_fetch_receipt import f6_instruction_fetch_receipts,_issuer_acceptances
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
    inputs,artifacts = all_six.compiled_inputs(),dict(all_six.artifacts)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    contract = admission['execution_contract']
    if flow=='F2':
        # Use the actual declared read endpoint, never a host sampled value.
        row, = [row for row in inputs['compiled']['paths'] if row['flow_id']=='F2' and row['status']=='executable']
        raw = row['execution_contract']['address'].to_bytes(4,'little').hex()
    ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),
        contract,artifacts,base_dir=ROOT)
    assembly = build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],
        ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
    _install_software_process_boundary(monkeypatch)
    runtime = CompiledF6Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,
        cache_dir=tmp_path,max_cases=8,defer_begin=True,shared_assembly=assembly)
    monkeypatch.setattr(runtime.session,'advance_initial',lambda schedule: SimpleNamespace(violations=(),status='running'))
    monkeypatch.setattr(runtime,'_bootstrap_to_first_slot',lambda: None)
    runtime.begin()
    # F2's version consumer runs after source binding; this fixture does not
    # issue a target native version and asserts only the instruction binding.
    if flow=='F2':
        from myfuzz.integration import compiled_f2_consumer
        monkeypatch.setattr(compiled_f2_consumer,'capture_f2_read_version',lambda *a,**k: None)
    class StopBeforeDUTClock(Exception): pass
    def stop(*args,**kwargs): raise StopBeforeDUTClock('source bound before any DUT step')
    monkeypatch.setattr(runtime.runner,'step_batch',stop)
    with pytest.raises(StopBeforeDUTClock):
        runtime.submit(bytes.fromhex(raw),flow=flow)
    case, = runtime.session._cases
    assert case.source.source_id==admission['shared_flow_paths'][flow]['source_id']
    admission_row = runtime.runner._provenance.registry.get(case.source.action_id)
    assert admission_row.source_id==case.source.source_id and admission_row.case_index==0
    assert any(row.get('source_event_id')==case.source.action_id and 'f6_acceptance_anchor' in row
        for row in runtime.runner.events_since(0))
    assert f6_instruction_fetch_receipts(runtime.cpu)==()
    assert _issuer_acceptances(runtime.cpu._f6_instruction_fetch)==()
    assert runtime.records==runtime.attempts==[]
