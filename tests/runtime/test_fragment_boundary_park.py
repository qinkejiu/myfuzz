"""F1/F3 and F2/F4 cases stop where the CPU parks off the fragment end.

The host deliberately leaves the next instruction slot unmaterialized, so a
whole rounds-per-case budget of fetch waiting is host-caused. These controls
use a simulated CPU and session only; no RTL or Verilator is started.
"""
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.runtime.flows.memory import submit_memory_case


class FakeCpu:
    """One CPU whose fetch park follows a per-advance script.

    Script entries are offsets from the fragment end (``0`` is the real
    boundary this case owns, a negative offset is still inside the fragment)
    or ``None`` for "no outstanding fetch".
    """

    def __init__(self, script):
        self.script = list(script)
        self.waiting_instruction_address = None
        self.local_ticks = 0
        self.reset_epoch = 0
        self.memory = SimpleNamespace(generation=0,
            read=lambda address, size, transaction_id=None: 0)

    def advance(self, end):
        self.local_ticks += 1
        if self.script:
            step = self.script.pop(0)
            self.waiting_instruction_address = None if step is None else end + step


class FakeSession:
    """Apply ``stop_after_advance`` exactly as the real online session does."""

    def __init__(self, cpu):
        self.cpu = cpu
        self.executed = None
        self.template = SimpleNamespace(testcase_id='unit')

    def submit_case(self, case, **options):
        stop = options.get('stop_after_advance')
        end = case.source.address + len(bytes.fromhex(case.source.data_hex))
        executed = 0
        for index in range(len(case.advances)):
            self.cpu.advance(end)
            executed = index + 1
            if stop is not None and stop(index):
                break
        self.executed = executed
        return SimpleNamespace(status='running', violations=(), events=(),
                               case_id=case.case_id, event_start=0, event_end=0,
                               local_ticks_before={}, local_ticks_after={
                                   'processor': self.cpu.local_ticks})


def memory_runtime(cpu, *, rounds=8, cursor=0x10000, result=0x1fffc):
    bindings = {flow: SimpleNamespace(source_id=f'{flow}.program_image',
                                      path_id=f'runtime-{flow}', base=0x10000,
                                      size=0x10000, readable=True, writable=True)
                for flow in ('F1', 'F3')}
    return SimpleNamespace(_stable=lambda: None, finished=False, records=[],
        max_cases=4, cursor=cursor, result=result, rounds=rounds, cpu_id='processor',
        runner=SimpleNamespace(sessions={'processor': cpu}, events_since=lambda index: ()),
        session=FakeSession(cpu),
        run_id='unit', memory_bindings=bindings,
        image={'port': 'ram', 'range': [0x10000, 0x1fffc]},
        traces={}, error_policy={})


def test_f1_and_f3_stop_only_at_the_fragment_end_fetch():
    for flow in ('F1', 'F3'):
        # Park inside the fragment, then idle, then at the fragment end: only
        # the last one is the boundary this case owns.
        cpu = FakeCpu([-8, None, 0])
        runtime = memory_runtime(cpu)
        result = submit_memory_case(runtime, b'\x13\x00\x00\x00', flow=flow)
        park = result['instruction_boundary_park']
        assert park['address'] == park['expected_address']
        assert park['tick'] == cpu.local_ticks
        assert park['reason'] == 'fragment_end_instruction_fetch'
        assert park['stopped_after_advance'] == 2
        assert runtime.session.executed == 3  # never before the end address


def test_a_park_that_predates_the_case_is_not_counted():
    cpu = FakeCpu([])
    runtime = memory_runtime(cpu, rounds=4)
    # Lowered F1 word plus the four-slot park padding: 4 + 16 = 20 bytes.
    cpu.waiting_instruction_address = runtime.cursor + 20
    result = submit_memory_case(runtime, b'\x13\x00\x00\x00', flow='F1')
    assert runtime.session.executed == 4  # the whole budget really ran
    park = result['instruction_boundary_park']
    assert park['stopped_after_advance'] is None
    assert park['reason'] == 'pre_submission_instruction_park'


def test_no_park_means_no_claimed_boundary():
    cpu = FakeCpu([])
    runtime = memory_runtime(cpu, rounds=3)
    result = submit_memory_case(runtime, b'\x13\x00\x00\x00', flow='F1')
    park = result['instruction_boundary_park']
    assert (park['address'], park['stopped_after_advance']) == (None, None)
    assert park['reason'] == 'no_instruction_fetch_park'
    assert runtime.session.executed == 3


def test_settle_window_stays_inside_the_declared_wait_bound():
    """The case keeps a short post-park window but never reaches the bound."""
    for declared, expected in ((16, 12), (6, 2), (3, 1)):
        cpu = FakeCpu([0] * 20)
        cpu.artifact = SimpleNamespace(
            runtime_document={'effective_max_wait_cycles': declared})
        runtime = memory_runtime(cpu, rounds=20)
        result = submit_memory_case(runtime, b'\x13\x00\x00\x00', flow='F1')
        park = result['instruction_boundary_park']
        assert park['settle_advances'] == expected
        assert park['park_observations'] == expected
        assert runtime.session.executed == expected
        assert runtime.session.executed < declared  # host hold is never a violation


def test_compiled_mmio_f2_and_f4_record_the_real_park():
    from myfuzz.integration import compiled_mmio
    for flow in ('F2', 'F4'):
        cpu = FakeCpu([-4, 0])
        session = FakeSession(cpu)
        runtime = SimpleNamespace(_stable=lambda: None, _memory_flows=False,
            _begun=True, records=[], max_cases=4, rounds=8, run_id='unit',
            default_flow=flow,
            paths={flow: {'path_id': f'runtime-{flow}', 'direction': 'CPU_TO_IP'}},
            streams={flow: {'source_id': f'{flow}.stream',
                'register_access': {'target_component': 'target'}}},
            images={flow: {'source_id': f'{flow}.image'}},
            layouts={flow: SimpleNamespace(
                classify=lambda raw: SimpleNamespace(accepted=True, address=0x1000),
                decode=lambda raw: {f'{flow}.stream': 0x1000})},
            admissions={flow: SimpleNamespace(runtime_path_id=f'runtime-{flow}',
                instruction_binding=SimpleNamespace(source_id=f'{flow}.image'))},
            cursor=0x10000, result=0x1fffc, cpu_id='processor', target_id='target',
            cpu_adapter=SimpleNamespace(protocol='obi',
                prepare_declaration=lambda declaration, address: dict(
                    declaration, code_hex='1300000013000000')),
            target_protocol='apb', traces={}, error_policy={},
            artifacts={'target': SimpleNamespace()},
            inputs={'request': None, 'compiled': None},
            execution_binding=SimpleNamespace(digest='0' * 64),
            runner=SimpleNamespace(sessions={'processor': cpu,
                'target': SimpleNamespace()},
                _event_refs_since=lambda index: ()),
            session=session,
            _observe_target_bus=lambda *args, **options: {
                'joins': [], 'RAM_event': 1, 'read_value': 0})
        exact = {'data_hops': [{'native_obi': {}}],
                 'ram_write_hop': {'native_obi': {}}}
        with patch.object(compiled_mmio, 'declare_reader', return_value={}), \
                patch.object(compiled_mmio, 'declare_writer', return_value={}), \
                patch.object(compiled_mmio, 'check_f2_exact_hops', return_value=exact), \
                patch.object(compiled_mmio, 'check_f4_exact_hops', return_value=exact), \
                patch.object(compiled_mmio, '_f2_edges', return_value=()), \
                patch.object(compiled_mmio, '_f4_edges', return_value=()):
            certificate = compiled_mmio.CompiledMmioRuntime.submit(
                runtime, b'\0' * 4, flow=flow)
        park = certificate['instruction_boundary_park']
        assert park['address'] == park['expected_address'] == 0x10008
        assert park['reason'] == 'fragment_end_instruction_fetch'
        assert park['stopped_after_advance'] == 1
        assert session.executed == 2
        assert runtime.cursor == 0x10008
