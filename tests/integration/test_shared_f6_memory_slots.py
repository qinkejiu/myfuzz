"""Five typed flows share the one F6 session's code slots and RAM owner."""
from copy import deepcopy
from dataclasses import replace
import pytest
from tests.integration.test_f6_storage_shared_assembly import inputs,ROOT
from tests.integration.test_shared_f6_slots import mixed_inputs


def five_inputs(inputs):
    from myfuzz.scenario.compiled_paths import compile_paths
    compiled,artifacts = mixed_inputs(inputs)
    document = deepcopy(compiled['request'].document)
    document['f6_execution']['program']['slot_count'] = 8
    document['f6_execution']['shared_slots']['flows'] = ['F1','F2','F3','F4','F6']
    request = replace(compiled['request'],document=document)
    return dict(compiled,request=request,compiled=compile_paths(request)),artifacts


def test_union_exposes_each_actual_typed_instruction_path(inputs):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_slot_consumers import instruction_bindings
    compiled,artifacts = five_inputs(inputs)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=compiled,base_dir=ROOT)
    assert set(admission['shared_flow_paths']) == {'F1','F2','F3','F4','F6'}
    assert len(admission['runtime_path_ids']) == 6
    assert len(admission['selected_dma_routes']) == 2
    bindings = instruction_bindings(admission)
    assert {binding.source_id for binding in bindings.values()} == {
        'F1.program_image','F2.program_image','F3.program_image','F4.program_image','shared_ram.image'}
    assert {binding.memory_id for binding in bindings.values()} == {'shared_ram'}


def test_explicit_shared_target_selects_declared_register_and_rejects_missing(inputs):
    from myfuzz.scenario.compiled_paths import compile_paths
    compiled, _ = five_inputs(inputs)
    document = deepcopy(compiled['request'].document)
    document['f6_execution']['shared_slots']['read_register'] = 'TIMER0_CTRL'
    request = replace(compiled['request'], document=document)
    paths = compile_paths(request)['paths']
    for flow in ('F2', 'F4'):
        row, = [p for p in paths if p['flow_id'] == flow]
        access, = [s['register_access'] for s in row['sources'] if 'register_access' in s]
        assert row['status'] == 'executable'
        assert access['target_component'] == 'peripheral'
        assert access['register'] == 'TIMER0_CTRL'
    document['f6_execution']['shared_slots']['read_register'] = 'missing'
    paths = compile_paths(replace(request, document=document))['paths']
    row, = [p for p in paths if p['flow_id'] == 'F2']
    assert row['status'] != 'executable'
    assert row['reason']['code'] == 'selected-mmio-read-register-unavailable'


@pytest.mark.parametrize('flow,raw',[('F1','13000000'),('F1','03200000'),('F2','04100040'),('F3','55000000'),('F4','aa000000')])
def test_lowering_reuses_existing_memory_and_register_generators(inputs,flow,raw):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_slot_consumers import declare_slot,instruction_bindings
    compiled,artifacts = five_inputs(inputs)
    admission = admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=compiled,base_dir=ROOT)
    layout = admission['execution_contract']['program_contract']['shared_slots']
    declaration = declare_slot(compiled,layout,admission,flow=flow,raw=bytes.fromhex(raw),slot_index=2)
    code = bytes.fromhex(declaration['code_hex'])
    assert len(code) == 128
    if flow in ('F1','F3'):
        from types import SimpleNamespace
        from myfuzz.runtime.flows.memory import lower_memory_code
        original,operation,address = lower_memory_code(SimpleNamespace(memory_bindings=instruction_bindings(admission),
            result=layout['scratch_address']+4),bytes.fromhex(raw),flow=flow)
        assert code.startswith(original)
        assert declaration['operation'] == operation and declaration['ram_address'] == address
    if flow == 'F2':
        assert declaration['address'] == 0x40001004
        assert declaration['result_address'] == layout['results_base']+8


def test_five_flow_real_constructor_reuses_exact_three_owners(inputs,tmp_path,monkeypatch):
    from tests.integration.test_f6_storage_shared_assembly import assemble
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.shared_slot_consumers import instruction_bindings
    compiled,artifacts = five_inputs(inputs)
    assembly = assemble((compiled,artifacts),tmp_path)
    _install_software_process_boundary(monkeypatch)
    runtime = CompiledF6Runtime(artifacts=artifacts,compiled_inputs=compiled,base_dir=ROOT,
        cache_dir=tmp_path,max_cases=8,defer_begin=True,shared_assembly=assembly)
    assert runtime.cpu is assembly.cpu and runtime.memory is assembly.memory and runtime.runner is assembly.runner
    from myfuzz.isa.constraints import f1_isa_from_profile
    expected_isa = f1_isa_from_profile(artifacts[runtime.cpu_id].plan.profile)
    if 'M' in expected_isa.extensions:
        assert runtime.memory.instruction_isa == expected_isa
    assert len(runtime.session.runtime_path_ids) == 6
    assert len(runtime.session.instruction_image_binding_documents) == 5
    assert set(instruction_bindings(runtime.runtime_path_admission)) == {'F1','F2','F3','F4','F6'}
    assert {name for name,_ in runtime.bound_topology.runtime_compilation._sessions} == {'cpu','dma','peripheral'}


def test_five_flow_admission_rebuild_rejects_hidden_extra_graph(inputs):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_slot_paths import validate_shared_flow_admission
    compiled,artifacts = five_inputs(inputs)
    original = admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=compiled,base_dir=ROOT)
    validate_shared_flow_admission(original)
    changed = deepcopy(original)
    changed['shared_flow_paths']['F1']['source_id'] = changed['shared_flow_paths']['F4']['source_id']
    with pytest.raises(ValueError,match='union-rebuild-mismatch'):
        validate_shared_flow_admission(changed)
    changed = deepcopy(original)
    changed['shared_flow_compilation']['paths'][0]['status'] = 'unsupported'
    with pytest.raises(ValueError,match='compiled-evidence-digest'):
        validate_shared_flow_admission(changed)
