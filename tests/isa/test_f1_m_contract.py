import pytest

from myfuzz.isa.constraints import IsaContract
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes


MUL = bytes.fromhex('3307d602')


def test_f1_isa_comes_from_declared_cpu_profile():
    from pathlib import Path
    from types import SimpleNamespace
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.isa.constraints import f1_isa_from_profile
    root = Path(__file__).resolve().parents[2]
    profile = load_component_profile(root / 'configs/cpus/cv32e20/component_profile.json')
    assert f1_isa_from_profile(profile).extensions == ('I', 'M', 'C')
    i_only = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=('i',)))
    assert f1_isa_from_profile(i_only).extensions == ('I',)


def test_m_validation_and_memory_admission_use_explicit_isa_contract():
    i = IsaContract(32, ('I',))
    im = IsaContract(32, ('I', 'M'))
    with pytest.raises(ValueError):
        validate_instruction_bytes(MUL)
    with pytest.raises(ValueError):
        validate_instruction_bytes(MUL, isa=i)
    validate_instruction_bytes(MUL, isa=im)
    default = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
                               initialization_seed=0, max_initialized_bytes=0x1000)
    default.declare_instruction_slots(0x1000)
    with pytest.raises(ValueError):
        default.accept_instructions(0x1000, MUL, source_event_id='input')
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
        initialization_seed=0, max_initialized_bytes=0x1000, instruction_isa=im)
    memory.declare_instruction_slots(0x1000)
    accepted = memory.accept_instructions(0x1000, MUL, source_event_id='input')
    assert accepted.data == MUL
    assert memory.identity_document()['instruction_isa'] == {'xlen': 32, 'extensions': ['I', 'M']}
    memory.cold_reset()
    assert memory.identity_document()['instruction_isa'] == {'xlen': 32, 'extensions': ['I', 'M']}


def test_f1_kernel_and_lowerer_enforce_bound_cpu_isa():
    from types import SimpleNamespace
    from myfuzz.runtime.flows.memory import MemoryFlowContext, MemoryFlowKernel, lower_memory_code
    i = IsaContract(32, ('I',))
    im = IsaContract(32, ('I', 'M'))
    case = {'testcase_id': 'test', 'path_id': 'path', 'source_id': 'source',
            'raw_records_hex': [MUL.hex()]}
    with pytest.raises(ValueError):
        MemoryFlowKernel().lower(MemoryFlowContext('a' * 64, 'path', 'F1', 'source', i), case)
    lower = MemoryFlowKernel().lower(MemoryFlowContext('a' * 64, 'path', 'F1', 'source', im), case)
    assert lower.raw_records == (MUL,)
    with pytest.raises(ValueError):
        lower_memory_code(SimpleNamespace(instruction_isa=i), MUL, flow='F1')
    assert lower_memory_code(SimpleNamespace(instruction_isa=im), MUL, flow='F1') == (MUL, 'instruction', None)


def test_f1_kernel_prepares_isa_from_bound_cpu_memory():
    from types import SimpleNamespace
    from myfuzz.runtime.flows.memory import MemoryFlowKernel
    im = IsaContract(32, ('I', 'M'))
    path = {'path_id': 'path', 'flow_id': 'F1', 'sources': [
        {'kind': 'instruction_image', 'origin': 'fuzzable', 'source_id': 'source', 'component': 'cpu'}]}
    plan = SimpleNamespace(document=lambda: {'paths': [path]})
    bound = SimpleNamespace(plan=plan, plan_sha256='a'*64,
        sessions={'cpu': SimpleNamespace(memory=SimpleNamespace(instruction_isa=im))})
    context = MemoryFlowKernel().prepare(bound, 'path')
    assert context.instruction_isa == im
    case = {'testcase_id': 'test', 'path_id': 'path', 'source_id': 'source', 'raw_records_hex': [MUL.hex()]}
    assert MemoryFlowKernel().lower(context, case).raw_records == (MUL,)


def test_bound_m_memory_replays_same_mixed_program_after_cold_reset():
    im = IsaContract(32, ('I', 'M'))
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
        initialization_seed=0, max_initialized_bytes=0x1000, instruction_isa=im)
    memory.declare_instruction_slots(0x1000, 3)
    program = bytes.fromhex('1306700093063000') + MUL
    first = memory.accept_instructions(0x1000, program, source_event_id='original')
    memory.warm_reset()
    assert memory.read(0x1008, 4, transaction_id='read-m').value == int.from_bytes(MUL, 'little')
    memory.cold_reset()
    replay = memory.accept_instructions(0x1000, program, source_event_id='fresh')
    assert replay.data == first.data and replay.generation == first.generation + 1
    assert memory.identity_document()['instruction_isa']['extensions'] == ['I', 'M']


def test_shared_descriptor_allows_m_as_syntax_but_runtime_still_checks_cpu():
    from pathlib import Path
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    root = Path(__file__).resolve().parents[2]
    descriptor = load_descriptor(root / 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/generic_scenario.json', base_dir=root)
    assert select_case_records(descriptor, flow='mixed', records=['F1:' + MUL.hex()]) == (('F1', MUL.hex()),)
    default = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
                               initialization_seed=0, max_initialized_bytes=0x1000)
    default.declare_instruction_slots(0x1000)
    with pytest.raises(ValueError):
        default.accept_instructions(0x1000, MUL, source_event_id='input')


def test_shared_slot_lowering_accepts_m_only_when_live_isa_allows_it(monkeypatch):
    from myfuzz.integration import shared_slot_consumers as shared
    monkeypatch.setattr(shared, 'instruction_bindings', lambda admission: {})
    inputs = {'compiled': {'paths': [{'flow_id': 'F1', 'status': 'executable'}]}}
    layout = {'scratch_address': 0x1000}
    with pytest.raises(ValueError):
        shared.declare_slot(inputs, layout, {}, flow='F1', raw=MUL, slot_index=0)
    declaration = shared.declare_slot(inputs, layout, {}, flow='F1', raw=MUL,
        slot_index=0, instruction_isa=IsaContract(32, ('I', 'M')))
    assert bytes.fromhex(declaration['code_hex']).startswith(MUL)


def test_shared_instruction_binding_reconstructs_with_same_live_isa(monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration import shared_f6_slots as slots, shared_slot_consumers as consumers
    from myfuzz.scenario.session_runtime import OnlineCase, BoundOnlineInstruction, BatchAdvance
    im = IsaContract(32, ('I', 'M'))
    monkeypatch.setattr(consumers, 'instruction_bindings', lambda admission: {})
    inputs = {'compiled': {'paths': [{'flow_id': 'F1', 'status': 'executable'}]}}
    layout = {'scratch_address': 0x2000}
    admission = {'shared_flow_paths': {'F1': {'path_id': 'path', 'source_id': 'source'}}}
    declaration = consumers.declare_slot(inputs, layout, admission, flow='F1', raw=MUL,
                                         slot_index=0, instruction_isa=im)
    case = OnlineCase('f1', 'CPU_TO_IP', 'path',
        BoundOnlineInstruction('input', 'cpu', 0x11000, declaration['code_hex'], 'source'),
        (BatchAdvance(('cpu',)),))
    session = SimpleNamespace(_cases=[case])
    runtime = SimpleNamespace(memory=SimpleNamespace(instruction_isa=im), session=session,
        compiled_inputs=inputs, runtime_path_admission=admission,
        contract={'program_contract': {'slot_base': 0x11000, 'shared_slots': layout}})
    row = {'flow': 'F1', 'raw_hex': MUL.hex(), 'slot_index': 0,
           'case_id': 'f1', 'session_case_index': 0}
    monkeypatch.setattr(slots, '_check_helpers', lambda: None)
    monkeypatch.setattr(slots, '_state', lambda runtime: {'session': session})
    monkeypatch.setattr(slots, 'case_mapping', lambda runtime, case_id: row)
    assert slots.instruction_case_mapping(runtime, session, case, 0) == row
    runtime.memory.instruction_isa = IsaContract(32, ('I',))
    with pytest.raises(ValueError):
        slots.instruction_case_mapping(runtime, session, case, 0)
