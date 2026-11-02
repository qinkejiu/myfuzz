"""Task6 runtime budget/preflight checks use source-backed static inputs."""
import pytest

from tests.integration.test_compiled_f6_contract import ROOT, source_inputs


class _LiveProcessDouble:
    """Synthetic process identity; it starts no native process."""
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        return None


@pytest.fixture(scope='module')
def inputs():
    request, compiled, artifacts = source_inputs()
    from myfuzz.scenario.ownership import compile_ownership
    return dict(request=request, compiled=compiled,
        ownership=compile_ownership((), ()), physical_port_map={}), artifacts


def test_case_advances_keep_cpu_dma_order_but_split_runner_failure_boundaries():
    from myfuzz.integration.compiled_f6 import _compiled_f6_case_advances

    advances = _compiled_f6_case_advances('cpu', 'dma', 2)

    assert [advance.schedule for advance in advances] == [
        ('cpu',), ('dma',), ('cpu',), ('dma',)]


@pytest.mark.parametrize('kwargs', [
    {'max_cases': 17},
    {'max_cases': 0},
    {'rounds_per_case': 0},
])
def test_runtime_rejects_invalid_budget_before_constructing_sessions(inputs, tmp_path, kwargs, monkeypatch):
    from myfuzz.integration import compiled_f6

    constructed = []
    monkeypatch.setattr(compiled_f6, 'ScenarioRunner',
        lambda **values: constructed.append(values))
    compiled_inputs, artifacts = inputs
    with pytest.raises(ValueError, match='compiled-F6-budget-invalid'):
        compiled_f6.CompiledF6Runtime(artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT, cache_dir=tmp_path,
            run_id='runtime-budget', **kwargs)
    assert constructed == []


def test_preflight_decodes_candidate_without_consuming_slots_or_running_sessions(inputs, tmp_path, monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from tests.integration.test_compiled_f6_contract import f6

    compiled_inputs, artifacts = inputs
    path = f6(compiled_inputs['compiled'])
    layout = compile_f6_candidate_layout(path)
    raw = sum(word << (11*index) for index, word in enumerate((51, 52, 53, 54))).to_bytes(8, 'little')
    # Construct the runtime shell without invoking any local/native process.
    runtime = object.__new__(compiled_f6.CompiledF6Runtime)
    runtime.path = path
    runtime.layout = layout
    runtime.records = []
    runtime.max_cases = 2
    runtime.cursor = 0
    runtime.runner = object()
    runtime.session = object()
    runtime.finished = False

    candidate = runtime.preflight(raw)
    assert candidate.words == (51, 52, 53, 54)
    assert runtime.records == []
    assert runtime.cursor == 0


def test_runtime_path_admission_has_distinct_online_instruction_and_dma_route_paths(inputs):
    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path, restore_prepared_runtime_paths)
    from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding

    compiled_inputs, artifacts = inputs
    path = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=ROOT)
    prepared = restore_prepared_runtime_paths(path)
    assert len(path['runtime_path_ids']) == 2
    assert len(prepared.path_ids) == 2
    image = next(source for source in prepared.graph.sources.values()
        if source.source_id == path['execution_contract']['instruction_source_id'])
    assert image.kind == 'memory_image'
    assert image.image_address is None  # The live image binding pins the actual RAM aperture.
    binding = InstructionImageSourceBinding(path_id=prepared.path_ids[1],
        direction='CPU_TO_IP', source_id=image.source_id,
        logical_source_id=image.source_id,
        component=path['execution_contract']['cpu']['instance_id'],
        memory_id=path['execution_contract']['memory']['resource']['resource_id'],
        base=path['execution_contract']['memory']['resource']['base'],
        size=path['execution_contract']['memory']['resource']['size'],
        readable=True, writable=True)
    binding.validate_prepared(prepared)


def test_raw_dma_irq_edge_uses_the_admitted_physical_export_runtime_name(inputs):
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from tests.integration.test_compiled_f6_contract import f6

    compiled_inputs, artifacts = inputs
    contract = f6(compiled_inputs['compiled'])['execution_contract']
    exports = [row for row in artifacts['dma'].runtime_document['physical_exports']
        if row.get('physical_port') == contract['irq']['producer_port']
        and row.get('endpoint_id') == contract['irq']['producer_endpoint_id']
        and row.get('direction') == 'output' and row.get('role') == 'irq'
        and row.get('width') == 1 and row.get('disposition') == 'functional']
    assert len(exports) == 1
    runtime_name = exports[0]['runtime_name']
    assert runtime_name != contract['irq']['producer_port']
    high = dict(kind='dma_edge', tick=9, payload={'observations': {
        'physical': {runtime_name: 1}}})
    runtime = object.__new__(CompiledF6Runtime)
    runtime.contract = contract
    runtime.dma = SimpleNamespace(artifact=artifacts['dma'],
        _irq_runtime_name=runtime_name,
        source_component=contract['irq']['producer_instance'], events=[high])
    runtime._f6_irq_runtime_name = runtime_name

    assert runtime._raw_dma_irq_edge() is high

    low = dict(kind='dma_edge', tick=10, payload={'observations': {
        'physical': {runtime_name: 0}}})
    runtime.dma.events.append(low)
    assert runtime._raw_dma_irq_edge() is None

    runtime.dma._irq_runtime_name = 'unadmitted_runtime_name'
    with pytest.raises(ValueError, match='compiled-F6-DMA-IRQ-runtime-export-drift'):
        runtime._raw_dma_irq_edge()
    runtime.dma._irq_runtime_name = runtime_name
    del runtime._f6_irq_runtime_name
    with pytest.raises(ValueError, match='compiled-F6-DMA-IRQ-runtime-export-drift'):
        runtime._raw_dma_irq_edge()


def test_observer_view_reads_f6_records_from_runner_journal_after_stream_drain(inputs):
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from tests.integration.test_compiled_f6_contract import f6

    compiled_inputs, _artifacts = inputs
    contract = f6(compiled_inputs['compiled'])['execution_contract']
    records = [
        dict(event_id=1, kind='dma_edge', component='dma', tick=7,
            reset_epoch=0, payload={'observations': {'physical': {'irq_o': 1}}}),
        dict(event_id=2, kind='memory_read', component='dma', address=0x10100),
        dict(event_id=3, kind='memory_write_commit', component='dma',
            commit_id='commit:1'),
        dict(event_id=4, kind='data_accept', component='cpu', address=0x40000000),
        dict(event_id=5, kind='local_tick_sample', component='cpu', local_tick=8),
    ]

    class Journal:
        event_count = len(records)

        def events_since(self, index):
            return tuple(records[index:])

    cpu = SimpleNamespace(cpu_events=[], service=SimpleNamespace(
        events=[], drain_commit_events=lambda: []),
        router=SimpleNamespace(acceptances=[], deliveries=[]))
    dma = SimpleNamespace(events=[], memory_service=SimpleNamespace(
        events=[], drain_commit_events=lambda: []))
    runtime = object.__new__(CompiledF6Runtime)
    runtime.contract = contract
    runtime.cpu = cpu
    runtime.dma = dma
    runtime.runner = Journal()
    runtime.observer_view = []
    runtime._observer_offsets = {}
    runtime._observer_commit_ids = set()
    runtime._observer_raw_event_ids = {}
    runtime._active_f6_irq_delivery = {'already-published': True}
    runtime._f6_isr_return = SimpleNamespace(events=[])
    runtime._issuer_event_count = 0

    runtime._drain_observer_view()

    assert [(row['kind'], row['component']) for row in runtime.observer_view] == [
        ('dma_edge', 'dma'), ('memory_read', 'dma'),
        ('memory_write_commit', 'dma'), ('data_accept', 'cpu')]
    assert [row['runner_event_id'] for row in runtime.observer_view] == [1, 2, 3, 4]
    assert [row['event_id'] for row in runtime.observer_view] == [1, 2, 3, 4]

    runtime._drain_observer_view()
    assert len(runtime.observer_view) == 4


def test_raw_dma_irq_edge_reads_journal_projection_after_source_stream_drain(inputs):
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from tests.integration.test_compiled_f6_contract import f6

    compiled_inputs, artifacts = inputs
    contract = f6(compiled_inputs['compiled'])['execution_contract']
    runtime_name = next(row['runtime_name'] for row in
        artifacts['dma'].runtime_document['physical_exports']
        if row.get('physical_port') == contract['irq']['producer_port']
        and row.get('endpoint_id') == contract['irq']['producer_endpoint_id']
        and row.get('direction') == 'output' and row.get('role') == 'irq'
        and row.get('width') == 1 and row.get('disposition') == 'functional')
    high = dict(event_id=1, runner_event_id=91, component='dma',
        kind='dma_edge', tick=9, reset_epoch=0,
        payload={'observations': {'physical': {runtime_name: 1}}})
    low = dict(event_id=2, runner_event_id=93, component='dma',
        kind='dma_edge', tick=10, reset_epoch=0,
        payload={'observations': {'physical': {runtime_name: 0}}})
    runtime = object.__new__(CompiledF6Runtime)
    runtime.contract = contract
    runtime.dma = SimpleNamespace(artifact=artifacts['dma'],
        _irq_runtime_name=runtime_name,
        source_component=contract['irq']['producer_instance'], events=[])
    runtime._f6_irq_runtime_name = runtime_name
    runtime.observer_view = [high]

    assert runtime._raw_dma_irq_edge() is high

    runtime.observer_view.append(low)
    assert runtime._raw_dma_irq_edge() is None


def test_f6_consumer_authenticates_cpu_row_through_runner_journal_after_drain():
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6_consumer import _Case

    source = dict(event_id=91, producer_event_id=44, kind='instr_response',
        component='cpu', address=0x11000, response_tick=12)
    projected = dict(source, event_id=1, runner_event_id=91)
    consumer = object.__new__(_Case)
    consumer.cpu = SimpleNamespace(cpu_events=[])
    consumer.cpu_id = 'cpu'
    dma_source = dict(event_id=92, producer_event_id=45, kind='dma_edge',
        component='dma', tick=13, accepted={'transaction': 'dma-key'})
    dma_projected = dict(dma_source, event_id=2, runner_event_id=92)
    journal = {91: source, 92: dma_source}
    consumer.dma = SimpleNamespace(events=[])
    consumer.dma_id = 'dma'
    consumer.runtime = SimpleNamespace(runner=SimpleNamespace(
        event_by_id=lambda event_id: journal.get(event_id)))

    assert consumer.live_cpu(projected) is None
    assert consumer.live_dma(dma_projected) is None


def test_f6_consumer_rejects_journal_row_without_runner_identity_even_if_stream_matches():
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction

    source = dict(event_id=91, producer_event_id=44, kind='instr_response',
        component='cpu', address=0x11000, response_tick=12)
    projected = dict(source, event_id=1)
    consumer = object.__new__(_Case)
    consumer.cpu = SimpleNamespace(cpu_events=[dict(source)])
    consumer.cpu_id = 'cpu'
    consumer.runtime = SimpleNamespace(runner=SimpleNamespace(
        event_by_id=lambda event_id: source if event_id == 91 else None))

    with pytest.raises(_Contradiction, match='Runner journal event identity'):
        consumer.live_cpu(projected)


def test_f6_consumer_binds_runner_row_producer_link():
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction

    source = dict(event_id=91, producer_event_id=44, kind='instr_response',
        component='cpu', address=0x11000, response_tick=12)
    projected = dict(source, event_id=1, runner_event_id=91,
        producer_event_id=45)
    consumer = object.__new__(_Case)
    consumer.cpu = SimpleNamespace(cpu_events=[])
    consumer.cpu_id = 'cpu'
    consumer.runtime = SimpleNamespace(runner=SimpleNamespace(
        event_by_id=lambda event_id: source if event_id == 91 else None))

    with pytest.raises(_Contradiction, match='Runner journal event identity'):
        consumer.live_cpu(projected)


def _completed_case(tmp_path, monkeypatch, *, fault=None):
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch,
        fault=fault)
    runtime.cpu._process = _LiveProcessDouble(1001)
    runtime.dma._process = _LiveProcessDouble(1002)
    runtime._f6_original_cpu_process = runtime.cpu.process
    runtime._f6_original_dma_process = runtime.dma.process
    runtime._f6_original_cpu_process_id = runtime.cpu.process.pid
    runtime._f6_original_dma_process_id = runtime.dma.process.pid
    runtime._f6_original_cpu_execution = runtime.cpu._execution
    runtime._f6_original_dma_execution = runtime.dma._execution
    runtime._f6_original_cpu_reset_epoch = runtime.cpu.reset_epoch
    runtime._f6_original_dma_reset_epoch = runtime.dma.reset_epoch
    runtime._f6_original_cpu_case_id = runtime.cpu._case_id
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case
    material = capture_f6_case(runtime, attempt)
    runtime.attempts = [attempt]
    runtime.max_cases = runtime.contract['program_contract']['slot_count']
    runtime._f6_used_dma_case_ids = {runtime.dma._case_id}
    delivery = next(row for row in runtime.observer_view
        if row.get('kind') == 'binding_delivery')
    runtime._active_f6_irq_delivery = dict(
        output_id=delivery['source_event_id'],
        delivery_id=delivery['event_id'],
        source_output_key=delivery['source_output_key'],
        start_local_tick=delivery['start_local_tick'],
        end_local_tick=delivery['end_local_tick'])
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    attempt['words'] = list(compile_f6_candidate_layout(runtime.path).decode(
        bytes.fromhex(attempt['raw8_hex'])).words)
    expected_error = any(row.get('error') == 1 for row in runtime.policy.records)
    incomplete = any(row.get('status') != 'passed'
        for row in material['observations'].values())
    attempt['status_kind'] = ('expected_error' if expected_error else
        'failed' if incomplete else 'passed')
    attempt['expected_error'] = expected_error
    attempt['feedback'] = [0] * 5 if expected_error or incomplete else [1] * 5
    attempt['_runner_event_start'] = 0
    from myfuzz.integration.compiled_f6 import _freeze_f6_case
    _freeze_f6_case(runtime, attempt, material)
    from types import SimpleNamespace
    cpu_id = runtime.cpu.source_component
    normalized_execution = f'local-driver:{cpu_id}:1'

    def runner_events_since(_start):
        rows = [dict(row) for row in runtime.observer_view]
        for row in rows:
            receipt = row.get('receipt_id')
            if (row.get('kind') == 'cpu_external_irq_sample'
                    and type(receipt) is dict):
                receipt['execution'] = normalized_execution
        return tuple(rows)

    runtime.runner = SimpleNamespace(sessions={
        runtime.cpu.source_component: runtime.cpu,
        runtime.dma.source_component: runtime.dma},
        events_since=runner_events_since,
        _source_transport_scopes={runtime.cpu.source_component: {
            runtime.cpu._execution: normalized_execution}})
    return runtime, attempt, material


def _assert_local_completion_without_graph(material):
    observations = material['observations']
    cross = observations['cross_component.declared_edge_hops']
    assert cross['status'] == 'missing'
    assert cross['reason'] == 'Runner raw event archive unavailable'
    assert all(row['status'] == 'passed' for name, row in observations.items()
               if name != 'cross_component.declared_edge_hops')


def _transition_unit_case(tmp_path, monkeypatch):
    """Supply a consumer approval at the transition unit's inventory boundary.

    The transport fixture has no authenticated Runner graph. Its real collector
    remains missing; this stub is neither registered evidence nor a native gate
    result. These tests exercise the runtime's scope transition after approval.
    """
    from copy import deepcopy
    from myfuzz.integration import compiled_f6

    runtime, attempt, collected = _completed_case(tmp_path, monkeypatch)
    _assert_local_completion_without_graph(collected)
    approved = deepcopy(collected)
    approved['observations']['cross_component.declared_edge_hops'].update(
        status='passed', reason='transition unit consumer approval stub')
    original_inventory = compiled_f6._case_inventory

    def inventory(owner):
        return ([deepcopy(approved)] if owner is runtime
                else original_inventory(owner))

    monkeypatch.setattr(compiled_f6, '_case_inventory', inventory)
    attempt.update(status_kind='passed', feedback=[1] * 5)
    del runtime._f6_case_freezes
    compiled_f6._freeze_f6_case(runtime, attempt, approved)
    # The original collector's registry still reports the unavailable graph.
    assert runtime.case_inventory == [collected]
    return runtime, attempt, approved


def test_f6_attempt_reference_collector_accepts_schema_version_only_mret_row(
        tmp_path, monkeypatch):
    from types import SimpleNamespace

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path,
        monkeypatch)
    attempt['words'] = list(compile_f6_candidate_layout(runtime.path).decode(
        bytes.fromhex(attempt['raw8_hex'])).words)
    mret_rows = [row for row in runtime.observer_view
        if row.get('schema_version') == 'native_f6_isr_return.v1']
    assert len(mret_rows) == 1
    assert 'kind' not in mret_rows[0]

    attempt['return'] = None
    collector = SimpleNamespace(observer_view=runtime.observer_view,
        cpu_id=runtime.cpu.source_component,
        dma_id=runtime.dma.source_component,
        contract=runtime.contract,
        cpu=SimpleNamespace(_request_evidence={}, _waiting_instr=None),
        _case_has_expected_error=False,
        _active_f6_irq_delivery=None,
        _transaction_for_ref=lambda ref: next((row.get('transaction')
            for row in runtime.observer_view
            if row.get('event_id') == ref), None),
        _append_observer=lambda *_args, **_kwargs: None)
    CompiledF6Runtime._attempt_references(
        collector, attempt, start_event_id=0)

    assert attempt['return'] == mret_rows[0]['event_id']


def test_f6_attempt_reference_collector_uses_declared_status_offset(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    runtime,attempt=make_case(support_inputs.__wrapped__(),tmp_path,monkeypatch)
    attempt['words']=list(compile_f6_candidate_layout(runtime.path).decode(bytes.fromhex(attempt['raw8_hex'])).words)
    base=runtime.contract['control']['base']
    status,=[row for row in runtime.observer_view if row.get('component')==runtime.cpu.source_component
        and row.get('kind')=='data_response' and row.get('address')==base and row.get('write')==0]
    runtime.contract['dma']['csr']['offsets']['control']=4
    status['address']=base+4
    collector=SimpleNamespace(observer_view=runtime.observer_view,cpu_id=runtime.cpu.source_component,
        dma_id=runtime.dma.source_component,contract=runtime.contract,
        cpu=SimpleNamespace(_request_evidence={},_waiting_instr=None),_case_has_expected_error=False,
        _active_f6_irq_delivery=None,_transaction_for_ref=lambda ref:next((row.get('transaction')
            for row in runtime.observer_view if row.get('event_id')==ref),None),
        _append_observer=lambda *_args,**_kwargs:None)
    CompiledF6Runtime._attempt_references(collector,attempt,start_event_id=0)
    assert attempt['status']==status['event_id']


def _transition(runtime, attempt, next_case_index):
    from myfuzz.integration.compiled_f6 import advance_f6_dma_logical_scope
    return advance_f6_dma_logical_scope(runtime, attempt,
        next_case_index=next_case_index)


def _case_stop_ready(runtime, attempt):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6_irq import f6_dma_irq_runtime_name

    runtime.cpu_id = runtime.cpu.source_component
    runtime.dma_id = runtime.dma.source_component
    runtime.runner._status = 'running'
    runtime._f6_irq_runtime_name = f6_dma_irq_runtime_name(
        runtime.dma, runtime.contract['irq'])
    CompiledF6Runtime._capture_f6_pending_fetch_sample(runtime, attempt)
    return CompiledF6Runtime._case_boundary_stop_ready(runtime, attempt)


def test_case_early_stop_requires_complete_success_boundary(
        tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch)
    _assert_local_completion_without_graph(material)
    assert attempt['status_kind'] == 'failed'
    assert attempt['expected_error'] is False
    assert attempt['feedback'] == [0] * 5
    assert all(row['error'] == 0 for row in runtime.policy.records)
    runtime.response_fault = None

    assert _case_stop_ready(runtime, attempt) is True


def test_case_early_stop_uses_declared_nonzero_status_offset(tmp_path,monkeypatch):
    runtime,attempt,_material=_completed_case(tmp_path,monkeypatch)
    runtime.response_fault=None
    base=runtime.contract['control']['base']
    status,=[row for row in runtime.observer_view if row.get('kind')=='data_response'
        and row.get('component')==runtime.cpu.source_component and row.get('address')==base and row.get('write')==0]
    runtime.contract['dma']['csr']['offsets']['control']=4
    status['address']=base+4
    assert _case_stop_ready(runtime,attempt) is True


def test_case_early_stop_reads_irq_expiry_from_runner_journal_after_stream_drain(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    journal_rows = runtime.runner.events_since(0)
    assert any(row.get('kind') == 'cpu_external_irq_sample'
        for row in journal_rows)
    runtime.runner.events_since = lambda _start: journal_rows
    runtime.observer_view[:] = [row for row in runtime.observer_view
        if row.get('kind') != 'cpu_external_irq_sample']

    assert _case_stop_ready(runtime, attempt) is True


@pytest.mark.parametrize('boolean_field', ('local_tick', 'reset_epoch'))
def test_case_early_stop_rejects_boolean_irq_sample_tick_or_epoch(
        tmp_path, monkeypatch, boolean_field):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    delivery = next(row for row in runtime.observer_view
        if row.get('kind') == 'binding_delivery')
    delivery.update(start_local_tick=1, end_local_tick=17)
    runtime._active_f6_irq_delivery.update(start_local_tick=1, end_local_tick=17)
    journal = [dict(row) for row in runtime.runner.events_since(0)]
    cpu_id = runtime.cpu.source_component
    for row in journal:
        if row.get('kind') == 'cpu_external_irq_sample':
            row['local_tick'] = 10000
    source_key = delivery['source_output_key']
    normalized_execution = runtime.runner._source_transport_scopes[cpu_id][
        runtime.cpu._execution]
    for tick in range(1, 18):
        expected = int(tick < 17)
        sample = dict(event_id=len(journal) + 1,
            kind='cpu_external_irq_sample',
            schema_version='cpu_external_irq_sample.v1',
            component=cpu_id, local_tick=tick, reset_epoch=0,
            command_scope=dict(component=cpu_id, reset_epoch=0,
                command_sequence=2000 + tick),
            receipt_id=dict(execution=normalized_execution,
                sequence=2000 + tick), expected_input=expected,
            actual_pre_input=expected, actual_post_input=expected)
        if expected:
            sample.update(binding_delivery_event_id=delivery['event_id'],
                source_output_key=source_key,
                input_context=dict(schema_version='native_irq_input_context.v1',
                    binding_delivery_event_id=delivery['event_id'],
                    expected_input=1, source_output_key=source_key,
                    target_component=cpu_id, target_epoch=0))
        journal.append(sample)
    journal[-17][boolean_field] = (True if boolean_field == 'local_tick'
        else False)
    runtime.runner.events_since = lambda _start: tuple(journal)

    assert _case_stop_ready(runtime, attempt) is False


def test_f6_consumer_reconstructs_route_match_with_admitted_path_id(
        tmp_path, monkeypatch):
    from myfuzz.integration.compiled_f6_consumer import _Case

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    admitted_path_id = runtime.route_admission.identity_document()['path_id']
    runtime.contract['path_id'] = 'different-static-path-id'
    consumer = object.__new__(_Case)
    consumer.runtime = runtime
    consumer.attempt = attempt
    consumer.contract = runtime.contract
    consumer.cpu = runtime.cpu
    consumer.dma = runtime.dma
    consumer.cpu_id = runtime.cpu.source_component
    consumer.dma_id = runtime.dma.source_component
    consumer.index = {}
    for row in runtime.observer_view:
        consumer.index.setdefault((row['component'], row['event_id']), []).append(row)
    consumer.used = []
    consumer.raw_evidence = []
    consumer.seen_raw = set()

    _event, _key, match = consumer.dma_beat('reads', 0, write=False,
        address=runtime.contract['program_contract']['source_address'], value=0)

    assert match['path_id'] == admitted_path_id


def test_f6_scope_freeze_accepts_complete_successful_dma_prefix_for_missing_observation(
        tmp_path, monkeypatch):
    from copy import deepcopy

    from myfuzz.integration.compiled_f6 import _f6_scope_snapshot_failure

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    attempt['status_kind'] = 'failed'
    attempt['expected_error'] = False
    snapshot = dict(dma_case_id=runtime.dma._case_id,
        route_matches=deepcopy(runtime.route_admission.route_matches),
        policy_records=deepcopy(runtime.policy.records))

    assert _f6_scope_snapshot_failure(runtime, attempt, snapshot) is None


def test_f6_copied_read_snapshot_omission_is_missing_and_freezable(
        tmp_path, monkeypatch):
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    from myfuzz.integration.compiled_f6 import _freeze_f6_case
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)
    attempt['words'] = list(compile_f6_candidate_layout(runtime.path).decode(
        bytes.fromhex(attempt['raw8_hex'])).words)
    omitted = attempt['read_snapshots'][1]
    runtime.observer_view[:] = [row for row in runtime.observer_view
        if row.get('event_id') != omitted]

    material = capture_f6_case(runtime, attempt)
    observation = material['observations']['dma.word_transfer_join']
    assert observation['status'] == 'missing', observation

    attempt['status_kind'] = 'failed'
    attempt['expected_error'] = False
    _freeze_f6_case(runtime, attempt, material)
    assert attempt['case_id'] in runtime._f6_case_freezes


@pytest.mark.parametrize('expected_error', ['missing', None, 0, 1, True])
def test_failed_f6_scope_requires_literal_false_expected_error(
        tmp_path, monkeypatch, expected_error):
    from copy import deepcopy
    from myfuzz.integration.compiled_f6 import _f6_scope_snapshot_failure

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    attempt['status_kind'] = 'failed'
    if expected_error == 'missing':
        attempt.pop('expected_error', None)
    else:
        attempt['expected_error'] = expected_error
    snapshot = dict(dma_case_id=runtime.dma._case_id,
        route_matches=deepcopy(runtime.route_admission.route_matches),
        policy_records=deepcopy(runtime.policy.records))

    assert _f6_scope_snapshot_failure(runtime, attempt, snapshot) is not None


def test_runner_acknowledged_f6_commits_join_to_journal_and_completed_receipt(
        tmp_path, monkeypatch):
    from copy import deepcopy
    from types import SimpleNamespace
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    from myfuzz.integration.compiled_f6_consumer import _Case
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)
    attempt['words'] = list(compile_f6_candidate_layout(runtime.path).decode(
        bytes.fromhex(attempt['raw8_hex'])).words)
    case = _Case(runtime, attempt)
    journal = {}
    for runner_event_id, row in enumerate(runtime.observer_view, start=1):
        source = deepcopy(row)
        source['event_id'] = runner_event_id
        row['runner_event_id'] = runner_event_id
        journal[runner_event_id] = source
    runtime.runner = SimpleNamespace(event_by_id=lambda event_id:
        journal.get(event_id))

    cpu_service = runtime.cpu.service
    cpu_service.ack_commit_events(tuple(cpu_service._pending_commits))
    dma_service = runtime.dma.memory_service
    dma_service.ack_commit_events(tuple(dma_service._pending_commits))

    source = case.reference(attempt['sources'][0], 'memory_write', case.cpu_id)
    case.independent_source(source,
        address=runtime.contract['program_contract']['source_address'],
        value=attempt['words'][0])
    commit_event = case.reference(attempt['source_commits'][0],
        'memory_write_commit', case.cpu_id)
    key = case.cpu_key(source)
    document = case.commit(commit_event, cpu_service, key=key,
        address=runtime.contract['program_contract']['source_address'],
        value=attempt['words'][0])
    assert document['fullkey'] == commit_event['transaction']


@pytest.mark.parametrize('invalid', ['owner', 'runner_id'])
def test_f6_memory_service_fallback_refuses_wrong_or_unresolved_owner(
        invalid):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction

    case = object.__new__(_Case)
    case.runtime = SimpleNamespace(runner=None)
    source = dict(kind='memory_write', transaction=dict(sequence=1),
        address=0x1000, value=7)
    service = SimpleNamespace(events=[source])
    row = dict(source, event_id=1, component='cpu')
    owner = 'cpu'
    if invalid == 'owner':
        row['component'] = 'dma'
    else:
        case.runtime.runner = SimpleNamespace()
        row['runner_event_id'] = 11

    with pytest.raises(_Contradiction):
        case.live_memory_service_event(row, owner, service)


def test_f6_memory_service_fallback_accepts_exact_synthetic_projection():
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6_consumer import _Case

    case = object.__new__(_Case)
    case.runtime = SimpleNamespace(runner=None)
    source = dict(kind='memory_write', transaction=dict(sequence=1),
        address=0x1000, value=7)
    service = SimpleNamespace(events=[source])
    row = dict(source, event_id=1, component='cpu')

    assert case.live_memory_service_event(row, 'cpu', service) is source


@pytest.mark.parametrize('extra_identity', [
    {'producer_event_id': 17},
    {'runner_event_id': None},
])
def test_f6_memory_service_fallback_rejects_unrecognized_identity_envelope(
        extra_identity):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction

    case = object.__new__(_Case)
    case.runtime = SimpleNamespace(runner=None)
    source = dict(kind='memory_write', transaction=dict(sequence=1),
        address=0x1000, value=7)
    service = SimpleNamespace(events=[source])
    row = dict(source, event_id=1, component='cpu', **extra_identity)

    with pytest.raises(_Contradiction):
        case.live_memory_service_event(row, 'cpu', service)


def test_f6_runner_read_callback_projection_checks_provenance_and_exact_payload(
        tmp_path, monkeypatch):
    from copy import deepcopy
    from types import SimpleNamespace
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction
    from myfuzz.scenario.memory_service import _f6_dma_read_results, _validate_f6_dma_read

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)
    case = _Case(runtime, attempt)
    selected_ref = attempt['read_snapshots'][0]
    row = next(row for row in runtime.observer_view
        if row.get('event_id') == selected_ref and row.get('component') == 'dma')
    key, snapshot, handle = _f6_dma_read_results(runtime.dma)[0]
    actual = _validate_f6_dma_read(runtime.dma,
        runtime.dma.memory_service,key,snapshot,handle)
    resource_names=('memory_id','generation','byte_offset','address',
        'width_bytes','byte_enable','transaction','version','versions',
        'writer_event_id','writer_event_ids','writer_kinds')
    resource={name:list(row[name]) if type(row.get(name)) is tuple
        else row[name] for name in resource_names if name in row}
    provenance=dict(schema_version='event_source_provenance.v1',
        observed_case=dict(case_id=attempt['case_id'],case_index=attempt['case_index']),
        origin_admission_ids=[],origin_status='unknown',
        unknown_writer_ids=list(dict.fromkeys(row['writer_event_ids'])),
        invalid_origin_references=0,proof_scope='memory_writer_snapshot',
        edge_candidates=[],resource=resource)
    runner_event_id=1000
    row['producer_event_id']=runner_event_id-1
    row['runner_event_id']=runner_event_id
    row['provenance']=deepcopy(provenance)
    source=deepcopy(row)
    source['event_id']=runner_event_id
    source.pop('runner_event_id')
    journal={runner_event_id:source}
    runtime.runner=SimpleNamespace(event_by_id=lambda event_id:
        journal.get(event_id))

    case.callback_event(row,actual,'dma','memory_read')

    original_row=deepcopy(row)
    original_source=deepcopy(source)
    mutations=(
        lambda: row['provenance'].update(unreviewed_field=True),
        lambda: row.update(unreviewed_callback_field=True),
        lambda: row.update(value=row['value']+1),
        lambda: row.update(runner_event_id=runner_event_id+1),
    )
    for mutate in mutations:
        row.clear();row.update(deepcopy(original_row))
        source.clear();source.update(deepcopy(original_source))
        journal[runner_event_id]=source
        mutate()
        source.clear();source.update(deepcopy(row))
        source['event_id']=runner_event_id
        source.pop('runner_event_id',None)
        with pytest.raises(_Contradiction):
            case.callback_event(row,actual,'dma','memory_read')


def test_case_early_stop_finds_fetch_handshake_after_runner_drains_cpu_samples(
        tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch)
    _assert_local_completion_without_graph(material)
    runtime.response_fault = None

    boundary_tick = runtime.cpu._request_evidence['instr']['acceptance_tick']
    drained = runtime.cpu.drain_tick_samples()
    assert any(row['local_tick'] == boundary_tick for row in drained)
    assert runtime.cpu._physical_tick_samples == []
    assert runtime.cpu.drain_tick_samples() == []

    assert _case_stop_ready(runtime, attempt) is True


def test_case_early_stop_uses_same_scoped_fetch_after_cpu_advances_again(
        tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch)
    _assert_local_completion_without_graph(material)
    runtime.response_fault = None
    request = runtime.cpu._request_evidence['instr']
    tick = request['acceptance_tick']
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    assert CompiledF6Runtime._capture_f6_pending_fetch_sample(
        runtime, attempt) is True
    runtime.cpu.local_ticks += 1

    assert request['acceptance_tick'] == tick < runtime.cpu.local_ticks
    assert _case_stop_ready(runtime, attempt) is True


@pytest.mark.parametrize('signal', ['i_req_valid', 'i_req_ready'])
def test_pending_fetch_latch_requires_both_pre_handshake_signals(
        tmp_path, monkeypatch, signal):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    request = runtime.cpu._request_evidence['instr']
    sample = next(row for row in runtime.cpu._physical_tick_samples
        if row['local_tick'] == request['acceptance_tick'])
    sample['pre']['backend'][signal] = 0

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    assert CompiledF6Runtime._capture_f6_pending_fetch_sample(
        runtime, attempt) is False
    assert getattr(runtime, '_f6_pending_fetch_sample', None) is None


@pytest.mark.parametrize('changed_scope', ['execution', 'reset_epoch', 'transaction'])
def test_case_early_stop_rejects_latched_fetch_after_scope_changes(
        tmp_path, monkeypatch, changed_scope):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    assert CompiledF6Runtime._capture_f6_pending_fetch_sample(
        runtime, attempt) is True
    runtime.cpu.local_ticks += 1

    if changed_scope == 'execution':
        runtime.cpu._execution = 'different-execution'
    elif changed_scope == 'reset_epoch':
        runtime.cpu.reset_epoch += 1
        transaction = CompiledF6Runtime._jsonable(
            runtime.cpu._request_evidence['instr']['transaction'])
        transaction['source_epoch'] = runtime.cpu.reset_epoch
        runtime.cpu._request_evidence['instr']['transaction'] = transaction
        from myfuzz.scenario.ledger import TransactionKey
        runtime.cpu._waiting_instr = (TransactionKey(**transaction),
            runtime.cpu._request_evidence['instr']['address'])
    else:
        transaction = CompiledF6Runtime._jsonable(
            runtime.cpu._request_evidence['instr']['transaction'])
        transaction['source_sequence'] += 1
        runtime.cpu._request_evidence['instr']['transaction'] = transaction
        from myfuzz.scenario.ledger import TransactionKey
        runtime.cpu._waiting_instr = (TransactionKey(**transaction),
            runtime.cpu._request_evidence['instr']['address'])

    assert _case_stop_ready(runtime, attempt) is False


def test_case_early_stop_accepts_only_selected_error_current_island_boundary(
        tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch,
        fault=('read', 1))
    assert any(row['status'] != 'passed'
        for row in material['observations'].values())
    from myfuzz.local_harness.f6_dma_response_fault import (
        F6ResponseFaultDeclaration)
    runtime.response_fault = F6ResponseFaultDeclaration(0, 'read', 1)
    from myfuzz.scenario.ledger import TransactionKey
    request = runtime.cpu._request_evidence['instr']
    runtime.cpu._pending_instr = None
    runtime.cpu._waiting_instr = (TransactionKey(**request['transaction']),
        request['address'])

    assert _case_stop_ready(runtime, attempt) is True


def test_case_early_stop_refuses_missing_irq_expiry_or_wrong_fetch_handshake(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    delivery = next(row for row in runtime.observer_view
        if row.get('kind') == 'binding_delivery')
    expiry_tick = delivery['end_local_tick']
    expiry = next(row for row in runtime.observer_view
        if row.get('kind') == 'cpu_external_irq_sample'
        and row.get('local_tick') == expiry_tick)
    runtime.observer_view.remove(expiry)
    assert _case_stop_ready(runtime, attempt) is False

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    boundary_tick = runtime.cpu._request_evidence['instr']['acceptance_tick']
    sample = next(row for row in runtime.cpu._physical_tick_samples
        if row['local_tick'] == boundary_tick)
    sample['pre']['backend']['i_req_addr'] += 4
    assert _case_stop_ready(runtime, attempt) is False


def test_case_early_stop_requires_live_delivery_and_exact_fetch_scope(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    runtime._active_f6_irq_delivery = None
    assert _case_stop_ready(runtime, attempt) is False

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    request = runtime.cpu._request_evidence['instr']
    transaction = dict(request['transaction'])
    transaction['testcase_id'] = 'another-testcase'
    request['transaction'] = transaction
    from myfuzz.scenario.ledger import TransactionKey
    runtime.cpu._waiting_instr = (TransactionKey(**transaction),
        request['address'])
    assert _case_stop_ready(runtime, attempt) is False


def test_case_early_stop_binds_irq_source_key_to_original_edge_tick_and_epoch(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    output = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_output'])
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    key = list(output['source_output_key'])
    key[3] += 1
    output['source_output_key'] = list(key)
    delivery['source_output_key'] = list(key)
    runtime._active_f6_irq_delivery['source_output_key'] = list(key)
    for row in runtime.observer_view:
        if row.get('kind') != 'cpu_external_irq_sample' or row.get('source_output_key') is None:
            continue
        row['source_output_key'] = list(key)
        if type(row.get('input_context')) is dict:
            row['input_context']['source_output_key'] = list(key)
    assert _case_stop_ready(runtime, attempt) is False

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    output = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_output'])
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    edge = next(row for row in runtime.observer_view
        if row.get('event_id') == output['producer_event_id'])
    edge['reset_epoch'] = runtime.dma.reset_epoch + 1
    assert _case_stop_ready(runtime, attempt) is False


def test_case_early_stop_rejects_bool_source_epoch_even_when_equal_to_zero(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    output = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_output'])
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    key = list(output['source_output_key'])
    assert key[1] == runtime.dma.reset_epoch == 0
    key[1] = False
    output['source_output_key'] = list(key)
    delivery['source_output_key'] = list(key)
    runtime._active_f6_irq_delivery['source_output_key'] = list(key)
    for row in runtime.observer_view:
        if row.get('kind') != 'cpu_external_irq_sample' or row.get('source_output_key') is None:
            continue
        row['source_output_key'] = list(key)
        if type(row.get('input_context')) is dict:
            row['input_context']['source_output_key'] = list(key)

    assert _case_stop_ready(runtime, attempt) is False


def test_success_boundary_advances_only_dma_logical_scope_and_snapshots_case_history(
        tmp_path, monkeypatch):
    runtime, attempt, material = _transition_unit_case(tmp_path, monkeypatch)
    assert all(row['status'] == 'passed' for row in material['observations'].values())

    cpu = runtime.cpu
    dma = runtime.dma
    cpu_state = (cpu._case_id, dict(cpu._sequences), cpu._native_irq_take_sequence,
        cpu._waiting_instr, cpu._pending_instr, cpu._pending_data,
        cpu.local_ticks, cpu.reset_epoch, cpu._execution,
        cpu._request_evidence['instr'].copy(), cpu.memory, cpu.service,
        tuple(cpu.cpu_events), tuple(cpu._physical_tick_samples))
    dma_state = (dma.process, dma._execution, dma.reset_epoch, dma.local_ticks,
        dma.memory_service, dma.memory_service.ledger, tuple(dma.events),
        dma._sequence, dma._acknowledged, dma._reader, dma._pending)
    route_matches = runtime.route_admission.route_matches
    policy_records = runtime.policy.records
    assert len(route_matches) == len(policy_records) == 8
    assert cpu._waiting_instr is not None

    transition = _transition(runtime, attempt, 1)

    assert transition['status'] == 'advanced'
    assert transition['previous_case_id'] == 'stream'
    assert transition['testcase_id'] == 'synthetic-run:dma:1'
    assert transition['route_matches'] == route_matches
    assert transition['policy_records'] == policy_records
    assert attempt['route_match_history'] == route_matches
    assert attempt['policy_records'] == policy_records
    assert (cpu._case_id, cpu._sequences, cpu._native_irq_take_sequence,
        cpu._waiting_instr, cpu._pending_instr, cpu._pending_data,
        cpu.local_ticks, cpu.reset_epoch, cpu._execution,
        cpu._request_evidence['instr'], cpu.memory, cpu.service,
        tuple(cpu.cpu_events), tuple(cpu._physical_tick_samples)) == cpu_state
    assert (dma.process, dma._execution, dma.reset_epoch, dma.local_ticks,
        dma.memory_service, dma.memory_service.ledger, tuple(dma.events),
        dma._sequence, dma._acknowledged, dma._reader, dma._pending) == dma_state
    assert dma._case_id == transition['testcase_id']
    assert dma._source_sequence == 0
    assert runtime.route_admission.route_matches == []
    assert runtime.policy.state == 'ready'
    assert runtime.policy.records == []


def test_scope_transition_accepts_only_registered_scenario_dma_subclass(
        tmp_path, monkeypatch):
    runtime, attempt, _material = _transition_unit_case(tmp_path, monkeypatch)
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)

    runtime.dma.__class__ = GeneratedWishboneDmaScenarioSession
    assert type(runtime.dma) is GeneratedWishboneDmaScenarioSession
    transition = _transition(runtime, attempt, 1)

    assert transition['status'] == 'advanced'
    assert runtime.dma._case_id == 'synthetic-run:dma:1'


def test_scope_transition_rejects_missing_graph_without_consumer_approval(
        tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch)
    _assert_local_completion_without_graph(material)
    before = (runtime.dma._case_id, tuple(runtime.route_admission.route_matches),
              tuple(runtime.policy.records))

    with pytest.raises(ValueError, match='f6-case-boundary-not-successful'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, tuple(runtime.route_admission.route_matches),
            tuple(runtime.policy.records)) == before


@pytest.mark.parametrize('next_case_index', [0, 2, 16, True])
def test_scope_transition_rejects_nonconsecutive_or_invalid_index_without_mutation(
        tmp_path, monkeypatch, next_case_index):
    runtime, attempt, _ = _completed_case(tmp_path, monkeypatch)
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma._execution, runtime.dma.reset_epoch,
        runtime.dma.local_ticks, tuple(runtime.dma.events),
        runtime.route_admission.route_matches, runtime.policy.records)

    with pytest.raises(ValueError, match='f6-case-index'):
        _transition(runtime, attempt, next_case_index)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma._execution, runtime.dma.reset_epoch,
        runtime.dma.local_ticks, tuple(runtime.dma.events),
        runtime.route_admission.route_matches, runtime.policy.records) == before


def test_scope_transition_rejects_reused_dma_testcase_id_without_mutation(
        tmp_path, monkeypatch):
    runtime, attempt, _ = _completed_case(tmp_path, monkeypatch)
    runtime._f6_used_dma_case_ids.add('synthetic-run:dma:1')
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records)

    with pytest.raises(ValueError, match='f6-case-testcase-id-reused'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records) == before


@pytest.mark.parametrize('owner', ['cpu', 'dma'])
@pytest.mark.parametrize('change', ['missing_process', 'replacement', 'pid', 'execution', 'epoch'])
def test_scope_transition_rejects_original_process_or_scope_drift_before_mutation(
        tmp_path, monkeypatch, owner, change):
    runtime, attempt, _ = _completed_case(tmp_path, monkeypatch)
    session = runtime.cpu if owner == 'cpu' else runtime.dma
    if change == 'missing_process':
        session._process = None
    elif change == 'replacement':
        session._process = _LiveProcessDouble(9000)
    elif change == 'pid':
        session._process.pid += 1
    elif change == 'execution':
        session._execution = 'f' * 32
    else:
        session.reset_epoch += 1
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records)

    with pytest.raises(ValueError, match='f6-case-native-identity-drift'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records) == before


def test_scope_transition_requires_task5_inventory_to_remain_immutable(
        tmp_path, monkeypatch):
    runtime, attempt, _ = _completed_case(tmp_path, monkeypatch)
    attempt['prefix_hex'] = '00' * 128
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records)

    with pytest.raises(ValueError, match='F6 independent case inventory is immutable'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records) == before


def test_scope_transition_rejects_co_mutated_frozen_route_policy_snapshot(
        tmp_path, monkeypatch):
    from copy import deepcopy
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.integration.compiled_f6 import _freeze_matches

    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    frozen = runtime._f6_case_freezes[attempt['case_id']]
    route = deepcopy(runtime.route_admission.route_matches[-1])
    policy = deepcopy(runtime.policy.records[-1])
    transaction = dict(route['transaction'])
    transaction['source_sequence'] += 100
    key = TransactionKey(**transaction)
    route['transaction'] = asdict(key)
    policy['transaction'] = asdict(key)
    runtime.route_admission._route_matches[key] = route
    runtime.policy._records.append(policy)
    frozen['route_matches'] = deepcopy(runtime.route_admission.route_matches)
    frozen['policy_records'] = runtime.policy.records

    with pytest.raises(ValueError, match='F6 independent case inventory is immutable'):
        _freeze_matches(runtime, attempt, frozen)


def test_case_freeze_refuses_empty_route_or_policy_snapshot(tmp_path, monkeypatch):
    from myfuzz.integration.compiled_f6 import _freeze_f6_case

    runtime, attempt, material = _completed_case(tmp_path, monkeypatch)
    runtime._f6_case_freezes.clear()
    runtime.route_admission._route_matches.clear()
    runtime.policy._records.clear()

    with pytest.raises(ValueError,
            match='compiled-F6-case-freeze-scope-snapshot-invalid'):
        _freeze_f6_case(runtime, attempt, material)


@pytest.mark.parametrize('owner', ['admission', 'policy'])
def test_scope_transition_rejects_owner_method_drift_before_any_mutation(
        tmp_path, monkeypatch, owner):
    runtime, attempt, _ = _completed_case(tmp_path, monkeypatch)
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records)

    target = type(runtime.route_admission if owner == 'admission' else runtime.policy)
    monkeypatch.setattr(target, 'begin_case', lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match='f6-case-owner-method-drift'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.process, runtime.dma.local_ticks,
        runtime.route_admission.route_matches, runtime.policy.records) == before


def test_expected_err_cannot_advance_dma_scope(tmp_path, monkeypatch):
    runtime, attempt, material = _completed_case(tmp_path, monkeypatch,
        fault=('write', 2))
    assert material['observations']['dma.irq_isr_completion']['status'] == 'failed'
    before = (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.local_ticks, tuple(runtime.dma.events),
        runtime.route_admission.route_matches, runtime.policy.records)

    with pytest.raises(ValueError, match='f6-case-boundary-not-successful'):
        _transition(runtime, attempt, 1)

    assert (runtime.dma._case_id, runtime.dma._source_sequence,
        runtime.dma.local_ticks, tuple(runtime.dma.events),
        runtime.route_admission.route_matches, runtime.policy.records) == before


@pytest.mark.parametrize('replacement', ['pre_binding_noop', 'post_binding_noop'])
def test_f6_route_validator_requires_original_admission_owner_before_binding(
        tmp_path, monkeypatch, replacement):
    runtime, _attempt, _material = _completed_case(tmp_path, monkeypatch)
    from myfuzz.local_harness.wishbone_dma_session import (
        _verify_f6_dma_route_validator)

    if replacement == 'pre_binding_noop':
        # Simulate a callback installed before the live execution binding is
        # built. A callable slot alone must not be accepted as route authority.
        runtime.dma._dma_route_validator = lambda: None
    else:
        # Replacing the registered callback after admission must be detected.
        runtime.dma._dma_route_validator = lambda: None

    with pytest.raises(ValueError, match='F6 DMA route validator is not original'):
        _verify_f6_dma_route_validator(runtime.dma,
            admission=runtime.route_admission)


def test_f6_route_validator_registrar_drift_refuses_before_route_install(
        tmp_path, monkeypatch):
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    import myfuzz.local_harness.wishbone_dma_session as dma_module

    monkeypatch.setattr(dma_module, '_register_f6_route_validator',
        lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match='F6 DMA route validator registrar drift'):
        make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)


def _lifecycle_shell(compiled_inputs):
    from myfuzz.integration import compiled_f6
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from tests.integration.test_compiled_f6_contract import f6

    runtime = object.__new__(compiled_f6.CompiledF6Runtime)
    runtime.path = f6(compiled_inputs['compiled'])
    runtime.contract = runtime.path['execution_contract']
    runtime.layout = compile_f6_candidate_layout(runtime.path)
    runtime.records = []
    runtime.attempts = []
    runtime.cursor = 0
    runtime.max_cases = 2
    runtime.finished = False
    runtime._stop_after_expected_error = False
    runtime._terminal_error = None
    runtime._finish_document = None
    runtime.run_id = 'lifecycle-run'
    runtime._drain_observer_view = lambda: None
    return runtime


def test_submit_rejects_invalid_raw_without_admitting_attempt_or_effects(inputs, monkeypatch):
    from myfuzz.integration import compiled_f6

    compiled_inputs, _artifacts = inputs
    runtime = _lifecycle_shell(compiled_inputs)
    effects = []
    monkeypatch.setattr(runtime, '_verify_live_owner',
        lambda: effects.append('owner-check'), raising=False)
    monkeypatch.setattr(runtime, '_execute_case',
        lambda *args, **kwargs: effects.append('execute'), raising=False)

    with pytest.raises(ValueError, match='compiled-F6-layout-record-length'):
        compiled_f6.CompiledF6Runtime.submit(runtime, b'bad')

    assert effects == []
    assert runtime.attempts == []
    assert runtime.records == []
    assert runtime.cursor == 0


def test_submit_stops_after_expected_error_case(inputs, monkeypatch):
    from myfuzz.integration import compiled_f6
    from types import SimpleNamespace

    compiled_inputs, _artifacts = inputs
    runtime = _lifecycle_shell(compiled_inputs)
    candidate = SimpleNamespace(raw=b'12345678', words=(1, 2, 3, 4))
    calls = []
    monkeypatch.setattr(runtime, 'preflight', lambda raw: candidate)
    monkeypatch.setattr(runtime, '_verify_live_owner', lambda: None, raising=False)

    def execute(_candidate, index, attempt):
        calls.append(index)
        attempt['status'] = 'expected_error'
        runtime._stop_after_expected_error = True
        return dict(status='expected_error', case_index=index,
            prefix_hex='00', feedback=[0, 0, 0, 0, 0])

    monkeypatch.setattr(runtime, '_execute_case', execute, raising=False)

    first = compiled_f6.CompiledF6Runtime.submit(runtime, candidate.raw)
    assert first['status'] == 'expected_error'
    with pytest.raises(ValueError, match='compiled-F6-expected-error-stops-campaign'):
        compiled_f6.CompiledF6Runtime.submit(runtime, candidate.raw)
    assert calls == [0]
    assert len(runtime.attempts) == len(runtime.records) == runtime.cursor == 1


def test_finish_returns_cached_pair_material_without_finishing_twice(inputs, monkeypatch):
    from myfuzz.integration import compiled_f6

    compiled_inputs, _artifacts = inputs
    runtime = _lifecycle_shell(compiled_inputs)
    calls = []
    material = dict(schema_version='compiled_F6_prefix.v1', cases=[])
    monkeypatch.setattr(runtime, '_finish_once',
        lambda: calls.append('finish') or material, raising=False)

    first = compiled_f6.CompiledF6Runtime.finish(runtime)
    first['cases'].append('mutated caller copy')
    second = compiled_f6.CompiledF6Runtime.finish(runtime)

    assert calls == ['finish']
    assert second == material
    assert runtime.finished is True


def _finish_gate_shell(monkeypatch, *, invalid=None, primary=None):
    import hashlib
    import json
    from types import SimpleNamespace
    from myfuzz.integration import compiled_f6
    from myfuzz.integration.compiled_build_join import built_receipt_sha256
    from myfuzz.scenario.replay import ScenarioTrace

    runtime = object.__new__(compiled_f6.CompiledF6Runtime)
    trace_status = ('protocol_violation' if invalid in
        ('trace_terminal_failure', 'trace_status_owner_mismatch')
        else 'unknown_terminal' if invalid == 'trace_status_unknown'
        else [] if invalid == 'trace_status_type'
        else 'running' if invalid == 'trace_status' else 'complete')
    plan = dict(schema_version=(6 if invalid == 'online_plan_wrong_version' else 10),
        template={}, instruction_slots=[], warmup_advances=[],
        cases=[{'case_id': 'case-0'}], runtime_paths={},
        provenance_configuration={}, source_admissions=[])
    plan_bytes = json.dumps(plan, separators=(',', ':')).encode()
    journal_events = [{'event_id': 1, 'kind': 'step'}]
    trace_events = [dict(row) for row in journal_events]
    trace_ticks = {'cpu': 1, 'dma': 1}
    if invalid == 'trace_runner_event_bool':
        journal_events[0]['event_id'] = True
    runner_ticks = {'cpu': 1, 'dma': 1}
    if invalid == 'trace_runner_tick_bool':
        runner_ticks['cpu'] = True
    manifest_sha256 = 'c' * 64
    if invalid == 'trace_events_owner_mismatch':
        trace_events[0]['kind'] = 'different-step'
    if invalid == 'trace_ticks_owner_mismatch':
        trace_ticks['cpu'] = 2
    from myfuzz.scenario.session_runtime import _trace_semantic_sha256
    trace_semantic_sha256 = _trace_semantic_sha256(
        trace_status, trace_events, trace_ticks)
    if invalid == 'trace_semantic_hash_mismatch':
        trace_semantic_sha256 = 'b' * 64
    genome_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    if invalid == 'trace_genome_hash_mismatch':
        genome_sha256 = 'a' * 64
    trace_manifest_sha256 = manifest_sha256
    if invalid == 'trace_manifest_hash_mismatch':
        trace_manifest_sha256 = 'd' * 64
    trace = ScenarioTrace(genome_sha256, trace_status,
        tuple(trace_events), trace_ticks, trace_semantic_sha256,
        trace_manifest_sha256)
    if invalid == 'trace_missing':
        trace = None
    assertion = dict(
        assertions=dict(schema_version='compiled_F6_assertion_results.v1',
            cases=[dict(case_id='case-0', assertions=[])]),
        assertion_evidence=dict(schema_version='compiled_F6_assertion_evidence.v1',
            cases=[dict(case_id='case-0', observations={}, evidence_inventory={})]))
    artifacts = {}
    receipts = {}
    identities = {}
    exits = {}
    processes = {}
    for index, component in enumerate(('cpu', 'dma')):
        artifact_digest = str(index + 1) * 64
        artifact = SimpleNamespace(runtime_document={'artifact_digest': artifact_digest},
            plan=SimpleNamespace(request=SimpleNamespace(instance_id=component)))
        artifacts[component] = artifact
        build_identity = dict(schema_version='local_harness_build_identity.v1',
            artifact_digest=artifact_digest, inputs=[], toolchain={})
        build_identity['build_digest'] = built_receipt_sha256(build_identity)
        receipt = dict(schema_version='local_harness_built_receipt.v1',
            artifact_digest=artifact_digest, build_digest=build_identity['build_digest'],
            build_identity=build_identity, binary_sha256=str(index + 3) * 64)
        receipts[component] = receipt
        pid = 8100 + index
        nonce = component + '-finish-gate-execution'
        identities[component] = dict(component=component,
            role='cpu' if component == 'cpu' else 'bound_target', pid=pid,
            execution_nonce=nonce, artifact_digest=artifact_digest,
            build_digest=receipt['build_digest'],
            binary_sha256=receipt['binary_sha256'],
            built_receipt_sha256=built_receipt_sha256(receipt),
            observed_executable_sha256=receipt['binary_sha256'],
            ready_artifact_digest=artifact_digest)
        exits[component] = dict(returncode=0, reaped=True)
        processes[component] = SimpleNamespace(pid=pid, poll=lambda: 0)
    audit = dict(schema_version='compiled_F6_execution_audit.v1',
        identities=identities, exits=exits, closed=True)
    build = dict(receipts=receipts,
        preparation_observations={component: dict(outcome='ready')
            for component in artifacts},
        execution_audit=dict(identities=identities, exits=exits, closed=True),
        unavailable={})
    if invalid == 'build_audit_nonzero_exit':
        build['execution_audit']['exits']['dma']['returncode'] = 1

    def encode_plan():
        if invalid == 'online_plan_error':
            raise OSError('synthetic plan unavailable')
        return (b'null' if invalid == 'online_plan_none'
            else plan_bytes)

    runtime.session = SimpleNamespace(finish=lambda: trace, encode_plan=encode_plan,
        _finished=True, _halt_reason=None,
        _manifest_sha256=manifest_sha256)
    runtime.runner = SimpleNamespace(events_since=lambda _start:
        None if invalid == 'events_wrong_shape' else journal_events,
        event_count=len(journal_events),
        sessions={'cpu': object(), 'dma': object()},
        local_ticks=runner_ticks,
        failure_status=('protocol_violation'
            if invalid == 'trace_terminal_failure' else None))
    runtime.artifacts = artifacts
    runtime.compiled_document_sha256 = 'c' * 64
    runtime.binding_sha256 = 'd' * 64
    runtime.execution_binding_sha256 = 'd' * 64
    runtime.execution_binding = {}
    # This isolated export fixture has no constructed live binding; exercise
    # that dependency separately in the boundary tests and real-binding suite.
    runtime.contract = {'program_contract': {}}
    runtime.compiled_inputs = {}
    runtime.base_dir = __import__('pathlib').Path.cwd()
    runtime.program = object()
    runtime.bound_topology = object()
    from myfuzz.scenario import f6_execution_binding
    monkeypatch.setattr(f6_execution_binding, 'validate_f6_execution_binding',
        lambda *args, **kwargs: {})
    runtime.runtime_path_admission = {}
    runtime.rounds_per_case = 4
    runtime.max_cases = 1
    runtime.run_id = 'finish-gate-run'
    runtime.cpu_id = 'cpu'
    runtime.records = [{'case_id': 'case-0'}]
    runtime.attempts = [{'case_id': 'case-0', 'status_kind': 'passed'}]
    runtime.finished = False
    runtime._terminal_error = primary
    runtime._finish_document = None
    runtime._finish_started = False
    runtime._session_finish_called = False

    runtime._build_sessions = {}
    runtime._native_processes = ({} if invalid == 'execution_audit_empty'
        else processes)
    runtime._process_identities = ({} if invalid == 'execution_audit_empty'
        else identities)
    runtime._validated_build_process_identities = lambda: (
        {} if invalid == 'execution_audit_empty' else identities)
    runtime._built_receipts = receipts
    runtime._build_audit_previous = {}
    runtime.build_audit_snapshot = lambda closed=None: (
        None if invalid == 'build_audit_none' else build)
    from myfuzz.scenario import f6_assertion_evidence
    monkeypatch.setattr(f6_assertion_evidence, 'build_f6_assertion_material',
        lambda _runtime: None if invalid == 'assertion_material_none' else assertion)
    if invalid == 'events_raise':
        runtime.runner.events_since = lambda _start: (_ for _ in ()).throw(
            OSError('synthetic events unavailable'))
    return runtime


def test_finish_preserves_valid_terminal_failed_trace_as_partial_without_feedback(
        monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    runtime = _finish_gate_shell(monkeypatch, invalid='trace_terminal_failure')
    runtime.attempts[-1]['status_kind'] = 'failed'
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)

    prefix = compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert prefix['status'] == 'partial'
    assert prefix['scope'] == 'partial'
    assert prefix['completed'] is False
    assert prefix['trace_status'] == 'protocol_violation'
    assert prefix['semantic_hash'] == runtime.trace.semantic_sha256
    assert prefix['trace_local_ticks'] == runtime.trace.local_ticks
    assert prefix['trace_genome_sha256'] == runtime.trace.genome_sha256
    assert prefix['trace_manifest_sha256'] == runtime.trace.manifest_sha256
    assert prefix['feedback'] == [0] * 5


@pytest.mark.parametrize('invalid', (
    'trace_events_owner_mismatch', 'trace_ticks_owner_mismatch',
    'trace_semantic_hash_mismatch', 'trace_genome_hash_mismatch',
    'trace_manifest_hash_mismatch', 'trace_runner_event_bool',
    'trace_runner_tick_bool'))
def test_finish_rejects_trace_without_owner_snapshot_and_digest_join(
        monkeypatch, invalid):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch, invalid=invalid)
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)
    with pytest.raises(ValueError, match='compiled-F6-mandatory-export-unavailable:trace:'):
        compiled_f6.CompiledF6Runtime._finish_once(runtime)
    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['trace_status'] == 'complete'
    assert runtime._finish_document['feedback'] == [0] * 5


def test_finish_zeroes_feedback_when_a_mandatory_export_fails(
        monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    runtime = _finish_gate_shell(monkeypatch)

    def fail_plan(_runtime, name, _document, **_kwargs):
        return 'synthetic-plan-export-failure' if name == 'online_plan' else None

    monkeypatch.setattr(compiled_f6, '_f6_export_failure', fail_plan)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)

    with pytest.raises(ValueError, match='compiled-F6-mandatory-export-unavailable:online_plan:'):
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['scope'] == 'partial'
    assert runtime._finish_document['feedback'] == [0] * 5


def test_finish_preserves_trace_events_when_runner_event_export_fails(
        monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    runtime = _finish_gate_shell(monkeypatch)
    calls = [0]
    owner_events = [{'event_id': 1, 'kind': 'step'}]

    def events_since(_start):
        calls[0] += 1
        if calls[0] == 1:
            raise OSError('synthetic one-shot event export failure')
        return owner_events

    runtime.runner.events_since = events_since
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)

    with pytest.raises(OSError, match='synthetic one-shot event export failure'):
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    prefix = runtime._finish_document
    assert prefix['status'] == 'partial'
    assert prefix['actual_events'] is None
    assert prefix['trace_events_source'] == 'trace_material'
    assert prefix['trace_events'] == list(runtime.trace.events)
    assert prefix['semantic_hash'] == runtime.trace.semantic_sha256
    assert prefix['feedback'] == [0] * 5


def test_finish_captures_best_effort_trace_when_session_finish_raises(
        monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    runtime = _finish_gate_shell(monkeypatch)
    trace = runtime.session.finish()
    runtime.session.finish = lambda: (_ for _ in ()).throw(
        RuntimeError('synthetic session finish failure'))
    runtime.session.trace = lambda: trace
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)

    with pytest.raises(RuntimeError, match='synthetic session finish failure'):
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    prefix = runtime._finish_document
    assert prefix['status'] == 'partial'
    assert prefix['trace_status'] == 'complete'
    assert prefix['trace_local_ticks'] == trace.local_ticks
    assert prefix['trace_events_source'] == 'actual_events'
    assert prefix['feedback'] == [0] * 5


def test_submit_exception_clears_feedback_already_written_to_failed_attempt(
        monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration import compiled_f6, compiled_f6_consumer

    runtime = object.__new__(compiled_f6.CompiledF6Runtime)
    runtime.finished = False
    runtime._stop_after_expected_error = False
    runtime._terminal_error = None
    runtime.cursor = 0
    runtime.max_cases = 1
    runtime.run_id = 'failed-feedback-run'
    runtime.contract = {'program_contract': {'slot_base': 0x1000}}
    runtime.records = []
    runtime.attempts = []
    candidate = SimpleNamespace(raw=b'12345678', words=(1, 2))
    runtime.preflight = lambda _raw: candidate
    runtime._verify_live_owner = lambda: None

    def fail_after_feedback(_candidate, _index, attempt):
        attempt['feedback'] = [1] * 5
        attempt['result'] = {'feedback': [1] * 5}
        raise RuntimeError('failure after case feedback')

    runtime._execute_case = fail_after_feedback
    monkeypatch.setattr(compiled_f6_consumer, 'capture_f6_case',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError('diagnostic only')))

    with pytest.raises(RuntimeError, match='failure after case feedback'):
        compiled_f6.CompiledF6Runtime.submit(runtime, b'candidate')

    attempt = runtime.attempts[0]
    assert attempt['status_kind'] == 'failed'
    assert attempt['feedback'] == [0] * 5
    assert attempt['result']['feedback'] == [0] * 5


def test_finish_rejects_missing_mandatory_exports_and_incomplete_trace(monkeypatch):
    from myfuzz.integration import compiled_f6

    # The small status-assembly shell deliberately does not model source-backed
    # plan/assertion/route owners. Isolate the complete status branch here;
    # separate tests exercise the real mandatory validators.
    with monkeypatch.context() as success_patch:
        success = _finish_gate_shell(success_patch)
        success_patch.setattr(compiled_f6, '_f6_export_failure',
            lambda *_args, **_kwargs: None)
        success_patch.setattr(compiled_f6, '_f6_trace_failure',
            lambda *_args: None)
        success_patch.setattr(compiled_f6, '_f6_finish_state_failure',
            lambda *_args, **_kwargs: None)
        assert compiled_f6.CompiledF6Runtime._finish_once(success)['completed'] is True

    for invalid in ('online_plan_none', 'online_plan_error',
            'online_plan_wrong_version',
            'assertion_material_none', 'events_wrong_shape', 'events_raise',
            'execution_audit_empty', 'build_audit_none',
            'build_audit_nonzero_exit', 'trace_missing',
            'trace_status', 'trace_status_unknown', 'trace_status_type',
            'trace_status_owner_mismatch'):
        runtime = _finish_gate_shell(monkeypatch, invalid=invalid)
        with pytest.raises((ValueError, OSError, TypeError)) as caught:
            compiled_f6.CompiledF6Runtime._finish_once(runtime)
        assert runtime._finish_document['status'] == 'partial'
        assert runtime._finish_document['scope'] == 'partial'
        assert runtime._finish_document['completed'] is False
        assert runtime._finish_document['error'] is not None
        expected_name = ('trace' if invalid.startswith('trace_') else
            'online_plan' if invalid.startswith('online_plan_') else
            'assertion_material' if invalid == 'assertion_material_none' else
            'events' if invalid.startswith('events_') else
            'execution_audit' if invalid == 'execution_audit_empty' else
            'build_audit')
        assert expected_name in runtime._finish_document['unavailable']


@pytest.mark.parametrize('invalid', ['events_wrong_shape', 'events_raise', 'build_audit_none'])
def test_finish_preserves_first_error_and_notes_missing_export_diagnostics(
        monkeypatch, invalid):
    from myfuzz.integration import compiled_f6

    primary = RuntimeError('original case failure')
    runtime = _finish_gate_shell(monkeypatch, invalid=invalid, primary=primary)

    with pytest.raises(RuntimeError, match='original case failure') as caught:
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert caught.value is primary
    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['completed'] is False
    expected_name = 'build_audit' if invalid == 'build_audit_none' else 'events'
    assert any(expected_name in note for note in getattr(primary, '__notes__', ()))


def test_expected_error_finish_export_failure_cannot_claim_full_failed_prefix(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch, invalid='events_raise')
    runtime.attempts[-1]['status_kind'] = 'expected_error'
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure',
        lambda *_args, **_kwargs: None)

    with pytest.raises(OSError, match='synthetic events unavailable'):
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['scope'] == 'partial'
    assert runtime._finish_document['completed'] is False
    assert runtime._finish_document['feedback'] == [0] * 5


def test_finish_rejects_non_f6_online_plan_schema_and_missing_f6_sections(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch, invalid='online_plan_wrong_version')
    expected = dict(schema_version=24, template={'version': 2},
        instruction_slots=[], warmup_advances=[],
        cases=[{'case_id': 'case-0'}], runtime_paths={'schema_version': 'runtime.v1'},
        provenance_configuration={'schema_version': 'provenance.v1'},
        source_admissions={'schema_version': 'admissions.v1'},
        instruction_image_bindings=[{'schema_version': 'instruction_image_binding.v1'}])
    monkeypatch.setattr(compiled_f6, '_f6_expected_online_plan',
        lambda _runtime: expected)

    for plan in (
            {'schema_version': 6, 'template': {}, 'cases': [{'case_id': 'case-0'}]},
            {'schema_version': 24, 'cases': [{'case_id': 'case-0'}]}):
        assert compiled_f6._f6_export_failure(runtime,
            'online_plan', plan) == 'online-plan-shape-or-cases'


def test_events_validator_rejects_rows_without_authoritative_identity(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch)

    assert compiled_f6._f6_export_failure(runtime, 'events', [{}]) == 'event-list-shape'
    assert compiled_f6._f6_export_failure(runtime, 'events', [
        dict(event_id=1, component='cpu')]) == 'event-list-identity'


def test_events_validator_accepts_runner_step_records_without_kind_fields(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch)
    step = dict(event_id=1, component='cpu', local_tick=1,
        inputs={'irq': 0}, outputs={'instr_req_valid': 0})

    assert compiled_f6._f6_export_failure(runtime, 'events', [step]) is None

    for rows in (
            [dict(step, event_id=2)],
            [step, dict(step, event_id=3)],
            [dict(step, event_id=2), dict(step, event_id=1)]):
        assert compiled_f6._f6_export_failure(runtime, 'events', rows) == 'event-list-identity'


def test_events_validator_rejects_a_truncated_but_contiguous_runner_prefix(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch)
    runtime.runner.event_count = 2
    first = dict(event_id=1, component='cpu', local_tick=1,
        inputs={'irq': 0}, outputs={'instr_req_valid': 0})

    assert compiled_f6._f6_export_failure(runtime, 'events', [first]) == 'event-list-identity'


def _finish_gate_build_preparation(runtime):
    from pathlib import Path
    from types import SimpleNamespace

    observations = {}
    sessions = {}
    for component in runtime.artifacts:
        manifest = Path('/tmp/f6-finish-gate') / component / 'manifest.json'
        digest = ('a' if component == 'cpu' else 'b') * 64
        observations[component] = dict(
            schema_version='local_harness_build_preparation.v1',
            outcome='cache_hit', compiled_this_invocation=False,
            compile_seconds=None,
            compile_seconds_reason='not_compiled_this_invocation',
            actual_build_argv=None, failure_stage=None,
            manifest_path=str(manifest), manifest_sha256=digest,
            preparation_seconds=0.0)
        result = SimpleNamespace(binary_path=manifest.parent / 'synthetic.bin',
            _manifest_sha256=digest)
        sessions[component] = SimpleNamespace(_built_pin=lambda result=result:
            (result,))
    runtime._build_sessions = sessions
    build = runtime.build_audit_snapshot()
    build['preparation_observations'] = observations
    runtime.build_audit_snapshot = lambda closed=None: build
    return build


def test_finish_rejects_nonzero_nested_build_exit_against_top_level_audit(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch, invalid='build_audit_nonzero_exit')
    build = _finish_gate_build_preparation(runtime)
    top = dict(schema_version=runtime._audit_schema,
        identities=runtime._process_identities,
        exits={component: dict(returncode=0, reaped=True)
            for component in runtime.artifacts}, closed=True)
    build['execution_audit']['exits']['dma']['returncode'] = 1

    assert compiled_f6._f6_export_failure(runtime, 'build_audit', build,
        execution_audit=top) == 'build-audit-process-join'


def test_online_plan_validator_returns_refusal_for_non_json_shape(monkeypatch):
    from myfuzz.integration import compiled_f6

    runtime = _finish_gate_shell(monkeypatch)
    monkeypatch.setattr(compiled_f6, '_f6_expected_online_plan',
        lambda _runtime: {'schema_version': 24, 'cases': [
            {'case_id': 'case-0'}]})
    malformed = {'schema_version': 24, 'cases': [
        {'case_id': 'case-0', 'invalid': float('nan')}]}

    reason = compiled_f6._f6_export_failure(runtime, 'online_plan', malformed)

    assert reason == 'online-plan-shape-or-cases'


def test_finish_preserves_primary_and_partial_document_if_case_revalidation_raises(
        monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    primary = RuntimeError('primary before corrupt attempt')
    runtime = _finish_gate_shell(monkeypatch, primary=primary)
    runtime.attempts = [dict(case_id='case-0', case_index=0,
        status_kind='passed', public_mutation=float('nan'))]
    runtime.records = [dict(case_id='case-0')]
    runtime._f6_case_freezes = {'case-0': dict(attempt_case_index=0,
        attempt_sha256='1' * 64, inventory_sha256='2' * 64,
        dma_case_id='run:dma:0', route_matches=[], policy_records=[])}
    scope_case = dict(case_id='case-0', observations={
        'one': {'status': 'passed'}}, evidence_inventory={'one': {}})
    assertion = {'assertions': {}, 'assertion_evidence': {
        'cases': [scope_case]}}
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_trace_failure', lambda *_args: None)
    monkeypatch.setattr(compiled_f6, '_build_f6_assertion_material',
        lambda _runtime: assertion)
    monkeypatch.setattr(compiled_f6, '_case_inventory',
        lambda _runtime: [scope_case])
    monkeypatch.setattr(compiled_f6, 'diagnostic_build_snapshot',
        lambda *_args, **_kwargs: runtime.build_audit_snapshot())
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)
    runtime.dma = type('Dma', (), {'_case_id': 'run:dma:0'})()
    runtime.route_admission = type('Admission', (), {'route_matches': []})()
    runtime.policy = type('Policy', (), {'records': []})()
    monkeypatch.setattr(compiled_f6, '_f6_expected_online_plan',
        lambda _runtime: {'schema_version': 24, 'cases': [
            {'case_id': 'case-0'}]})

    with pytest.raises(RuntimeError, match='primary before corrupt attempt') as caught:
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert caught.value is primary
    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['scope'] == 'partial'
    assert runtime._finish_document['completed'] is False
    assert 'case_state' in runtime._finish_document['unavailable']
    assert any('case_state' in note for note in primary.__notes__)


def test_finish_preserves_partial_document_when_export_validator_raises(monkeypatch):
    from myfuzz.integration import compiled_f6

    primary = RuntimeError('first case error')
    runtime = _finish_gate_shell(monkeypatch, primary=primary)

    def validator(_runtime, name, _value, **_kwargs):
        if name == 'online_plan':
            raise ValueError('malformed online plan validator input')
        return None

    monkeypatch.setattr(compiled_f6, '_f6_export_failure', validator)

    with pytest.raises(RuntimeError, match='first case error') as caught:
        compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert caught.value is primary
    assert runtime._finish_document['status'] == 'partial'
    assert runtime._finish_document['completed'] is False
    assert 'online_plan' in runtime._finish_document['unavailable']
    assert any('online_plan' in note for note in primary.__notes__)


def test_finish_preserves_final_dma_case_id_before_session_teardown(monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_assertion_evidence

    runtime = _finish_gate_shell(monkeypatch)
    runtime.dma = SimpleNamespace(_case_id='run:dma:0')
    observed = {}
    trace = runtime.session.finish()

    def finish_session():
        runtime.dma._case_id = None
        return trace

    runtime.session.finish = finish_session
    monkeypatch.setattr(compiled_f6, '_f6_export_failure',
        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compiled_f6, '_f6_trace_failure', lambda *_args: None)
    monkeypatch.setattr(compiled_f6, '_build_f6_assertion_material',
        lambda _runtime: {'assertions': {}, 'assertion_evidence': {}})
    monkeypatch.setattr(compiled_f6, 'diagnostic_build_snapshot',
        lambda *_args, **_kwargs: runtime.build_audit_snapshot())
    monkeypatch.setattr(f6_assertion_evidence, 'f6_case_feedback',
        lambda *_args, **_kwargs: [1] * 5)

    def check_state(_runtime, *, online_plan, assertion_material, feedback,
            final_dma_case_id):
        observed['final_dma_case_id'] = final_dma_case_id
        return None

    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure', check_state)

    result = compiled_f6.CompiledF6Runtime._finish_once(runtime)

    assert result['status'] == 'complete'
    assert runtime.dma._case_id is None
    assert observed['final_dma_case_id'] == 'run:dma:0'


def _install_software_process_boundary(monkeypatch):
    from copy import deepcopy
    from pathlib import Path
    from myfuzz.integration.compiled_build_join import built_receipt_sha256
    from myfuzz.local_harness.session import GeneratedLocalSession

    state = {'next_pid': 12000, 'events': []}

    class Process:
        def __init__(self, pid):
            self.pid = pid
            self.returncode = None

        def poll(self):
            return self.returncode

    def receipt(session):
        artifact_digest = session.artifact.runtime_document['artifact_digest']
        identity = dict(schema_version='local_harness_build_identity.v1',
            artifact_digest=artifact_digest, inputs=[], toolchain={})
        identity['build_digest'] = built_receipt_sha256(identity)
        return dict(schema_version='local_harness_built_receipt.v1',
            artifact_digest=artifact_digest, build_digest=identity['build_digest'],
            build_identity=identity,
            binary_sha256=built_receipt_sha256(['synthetic-binary', artifact_digest]))

    def validate_receipt(session):
        state['events'].append(('validate_receipt',
            session.artifact.plan.request.instance_id))
        return receipt(session)

    def preparation(session):
        component = session.artifact.plan.request.instance_id
        manifest = Path('/tmp/f6-runtime-software-boundary') / component / 'manifest.json'
        return dict(schema_version='local_harness_build_preparation.v1',
            outcome='cache_hit', compiled_this_invocation=False,
            compile_seconds=None,
            compile_seconds_reason='not_compiled_this_invocation',
            actual_build_argv=None, failure_stage=None,
            manifest_path=str(manifest), manifest_sha256='a' * 64,
            preparation_seconds=0.0)

    def built_pin(session):
        from types import SimpleNamespace
        row = preparation(session)
        result = SimpleNamespace(binary_path=Path(row['manifest_path']).parent
            / 'synthetic.bin', _manifest_sha256=row['manifest_sha256'])
        return result, receipt(session), 'b' * 64, row, session.artifact

    def identity_document(session):
        state['events'].append(('identity',
            session.artifact.plan.request.instance_id))
        admitted = receipt(session)
        return dict(schema_version='generated_local_session_identity.v1',
            runtime_artifact=deepcopy(session.artifact.runtime_document),
            build_identity=deepcopy(admitted['build_identity']),
            built_executable_receipt=deepcopy(admitted),
            command_timeout_seconds=session.command_timeout_seconds)

    def prepare_local(session):
        state['events'].append(('prepare',
            session.artifact.plan.request.instance_id))
        session._prepare_attempted = True

    def begin_case(session, testcase_id):
        if session._process is not None:
            raise RuntimeError('software process is already live')
        state['next_pid'] += 1
        process = Process(state['next_pid'])
        session._execution = f'{process.pid:032x}'
        session._sequence = 0
        session._acknowledged = 0
        session._tick_base = session.local_ticks
        session._case_id = testcase_id
        session._reader.reset()
        session._process = process
        session._start_attempted = True
        admitted = receipt(session)
        session._built_launches.append(dict(pid=process.pid,
            execution_nonce=session._execution, argv=['synthetic-harness'],
            built_receipt_sha256=built_receipt_sha256(admitted),
            artifact_digest=admitted['artifact_digest'],
            build_digest=admitted['build_digest'],
            binary_sha256=admitted['binary_sha256'],
            observed_executable_sha256=admitted['binary_sha256'],
            ready_artifact_digest=admitted['artifact_digest'],
            failure_stage=None, returncode=None, reaped=False, aborted=False))

    def end_case(session):
        process = session._process
        if process is None:
            return
        process.returncode = 0
        for row in session._built_launches:
            if row.get('pid') == process.pid:
                row.update(returncode=0, reaped=True, aborted=False)
        session._process = None
        session._case_id = None

    monkeypatch.setattr(GeneratedLocalSession, 'prepare_local', prepare_local)
    monkeypatch.setattr(GeneratedLocalSession, 'begin_case', begin_case)
    monkeypatch.setattr(GeneratedLocalSession, 'end_case', end_case)
    monkeypatch.setattr(GeneratedLocalSession, 'identity_document', identity_document)
    monkeypatch.setattr(GeneratedLocalSession, '_built_pin', built_pin)
    monkeypatch.setattr(GeneratedLocalSession,
        'validate_built_executable_receipt', validate_receipt)
    monkeypatch.setattr(GeneratedLocalSession,
        'built_executable_receipt_document', lambda session: deepcopy(receipt(session)))
    monkeypatch.setattr(GeneratedLocalSession,
        'build_preparation_observation_document',
        preparation)
    monkeypatch.setattr(GeneratedLocalSession,
        'built_executable_launch_observations',
        lambda session: tuple(deepcopy(session._built_launches)))
    from myfuzz.integration import compiled_build_join
    validate_join = compiled_build_join.validate_built_receipts

    def join_receipts(artifacts, receipts):
        state['events'].append(('join_receipts', None))
        return validate_join(artifacts, receipts)

    monkeypatch.setattr(compiled_build_join, 'validate_built_receipts',
        join_receipts)
    return state


def test_rfuzz_entry_uses_deferred_begin_and_retains_start_failure(tmp_path, monkeypatch):
    from myfuzz.integration import compiled_f6_rfuzz_session as live
    from myfuzz.local_harness import generated_artifact_admission as admission

    calls = []
    class Runtime:
        execution_binding = {}
        finished = False
        def execution_audit(self):
            return {}
        def __init__(self, **kwargs):
            calls.append(('construct', kwargs['defer_begin']))
        def begin(self):
            calls.append(('begin',))
            self.finished = True
            raise RuntimeError('startup-test-failure')

    monkeypatch.setattr(live, 'CompiledF6Runtime', Runtime)
    monkeypatch.setattr(live, 'assess_compiled_f6_support', lambda **kwargs: {
        'execution_supported': 1, 'admission': {'execution_contract': {
            'program_contract': {'slot_count': 2}}}})
    monkeypatch.setattr(admission, 'validated_f6_provider_credentials',
        lambda *args, **kwargs: {'file_pins': {}})
    monkeypatch.setattr(live, 'build_compiled_f6_build_join', lambda **kwargs: {})
    monkeypatch.setattr(live, 'write_pinned_json', lambda *args, **kwargs: None)
    monkeypatch.setattr(live, 'build_compiled_f6_rfuzz_executor',
        lambda *args, **kwargs: pytest.fail('executor must not start'))
    with pytest.raises(RuntimeError, match='startup-test-failure'):
        live._run_f6_live_and_fresh_owned(
            artifacts={}, compiled_inputs={}, base_dir=ROOT, cache_dir=tmp_path,
            run_id='test', session_dir=tmp_path, output_dir=tmp_path,
            client_binary=tmp_path / 'unused', budget_seconds=1, max_tests=1,
            search_seed=0, max_runs_per_batch=1)
    assert calls == [('construct', True), ('begin',)]


@pytest.mark.parametrize('defer_begin', [False, True])
def test_binding_validation_runs_once_per_required_boundary(
        inputs, tmp_path, monkeypatch, defer_begin):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_execution_binding, f6_instruction_fetch_receipt

    compiled_inputs, artifacts = inputs
    _install_software_process_boundary(monkeypatch)
    monkeypatch.setattr(f6_instruction_fetch_receipt,
        'install_f6_instruction_fetch', lambda *args, **kwargs: None)
    monkeypatch.setattr(compiled_f6.CompiledF6Runtime, '_bootstrap_to_first_slot',
        lambda self: None)
    calls = []
    validate = f6_execution_binding.validate_f6_execution_binding
    def counted(*args, **kwargs):
        calls.append('validate')
        return validate(*args, **kwargs)
    monkeypatch.setattr(f6_execution_binding, 'validate_f6_execution_binding', counted)
    runtime = compiled_f6.CompiledF6Runtime(
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        cache_dir=tmp_path, run_id='f6-boundary-validation', rounds_per_case=1,
        max_cases=2, defer_begin=defer_begin)
    try:
        assert len(calls) == 1
        if defer_begin:
            assert all(local.process is None for local in runtime.runner.sessions.values())
            runtime.begin()
            assert len(calls) == 2
    finally:
        if runtime.session._begun and not runtime.session._finished:
            runtime.session.finish()


def test_deferred_start_rejects_replaced_inputs_before_any_process(
        inputs, tmp_path, monkeypatch):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_instruction_fetch_receipt

    compiled_inputs, artifacts = inputs
    _install_software_process_boundary(monkeypatch)
    monkeypatch.setattr(f6_instruction_fetch_receipt,
        'install_f6_instruction_fetch', lambda *args, **kwargs: None)
    runtime = compiled_f6.CompiledF6Runtime(
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        cache_dir=tmp_path, run_id='f6-boundary-drift', rounds_per_case=1,
        max_cases=2, defer_begin=True)
    runtime.compiled_inputs['compiled'] = dict(runtime.compiled_inputs['compiled'])
    with pytest.raises(ValueError, match='compiled-F6-input-owner-changed'):
        runtime.begin()
    assert all(local.process is None for local in runtime.runner.sessions.values())


@pytest.mark.parametrize('failure', ['after-begin', 'bootstrap'])
def test_deferred_begin_failure_closes_processes_and_cannot_retry(
        inputs, tmp_path, monkeypatch, failure):
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario import f6_instruction_fetch_receipt

    compiled_inputs, artifacts = inputs
    _install_software_process_boundary(monkeypatch)
    monkeypatch.setattr(f6_instruction_fetch_receipt,
        'install_f6_instruction_fetch', lambda *args, **kwargs: None)
    runtime = compiled_f6.CompiledF6Runtime(
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT,
        cache_dir=tmp_path, run_id='f6-deferred-failure', rounds_per_case=1,
        max_cases=2, defer_begin=True)
    processes = []

    def fail_after_begin():
        original_begin()
        processes.extend(local.process for local in runtime.runner.sessions.values())
        raise RuntimeError('startup-test-failure')

    def fail_bootstrap():
        processes.extend(local.process for local in runtime.runner.sessions.values())
        raise RuntimeError('startup-test-failure')

    if failure == 'after-begin':
        original_begin = runtime.session.begin
        monkeypatch.setattr(runtime.session, 'begin', fail_after_begin)
    else:
        monkeypatch.setattr(runtime, '_bootstrap_to_first_slot', fail_bootstrap)
    with pytest.raises(RuntimeError, match='startup-test-failure'):
        runtime.begin()
    assert len(processes) == 2
    assert all(process.poll() is not None for process in processes)
    assert all(local.process is None for local in runtime.runner.sessions.values())
    with pytest.raises(ValueError, match='compiled-F6-begin-failed'):
        runtime.begin()


@pytest.mark.parametrize('defer_begin', [False, True])
def test_compiled_runtime_constructs_submits_twice_and_replays_fresh_orchestration(
        inputs, tmp_path, monkeypatch, defer_begin):
    """Exercise runtime orchestration with software process/step boundaries only.

    `_execute_case` below still calls the real ScenarioSession.submit_case and
    real instruction admission. The synthetic Runner steps and pass/error rows
    make this orchestration coverage, not Task6 DMA dataflow acceptance.
    """
    import json
    from myfuzz.integration import compiled_f6
    from myfuzz.scenario.batch import BatchAdvance
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction, OnlineCase
    from myfuzz.scenario import f6_assertion_evidence

    compiled_inputs, artifacts = inputs
    build_boundary = _install_software_process_boundary(monkeypatch)
    # This fixture invents waiting requests and never samples real OBI
    # responses. It exercises case orchestration without fetch authority;
    # the original CPU/Runner receipt path has its own software-boundary suite.
    from myfuzz.scenario import f6_instruction_fetch_receipt
    monkeypatch.setattr(f6_instruction_fetch_receipt,
        'install_f6_instruction_fetch', lambda *args, **kwargs: None)
    submissions = []
    callback_steps = []

    def install_fetch(runtime, index):
        cpu = runtime.cpu
        address = runtime.contract['program_contract']['slot_base'] + 256*index
        sequence = index + 1
        cpu._sequences['instr'] = sequence
        key = TransactionKey(cpu._execution, cpu._case_id, cpu.source_component,
            cpu.reset_epoch, 'instr', sequence)
        cpu._waiting_instr = (key, address)
        cpu._pending_instr = None
        cpu._request_evidence['instr'] = dict(address=address,
            transaction=key, acceptance_tick=cpu.local_ticks)
        return address, key

    def bootstrap(runtime):
        address, key = install_fetch(runtime, 0)
        runtime._first_fetch = dict(address=address, transaction=key,
            acceptance_tick=runtime.cpu.local_ticks)

    monkeypatch.setattr(compiled_f6.CompiledF6Runtime,
        '_bootstrap_to_first_slot', bootstrap)

    def synthetic_step_batch(runner, schedule, *, on_step=None):
        for component in schedule:
            if on_step is not None:
                callback_steps.append(component)
                on_step(component, {'software_step': True})

    monkeypatch.setattr(compiled_f6.ScenarioRunner, 'step_batch',
        synthetic_step_batch)

    def advance(runtime, _previous, *, next_case_index):
        from copy import deepcopy
        testcase_id = f'{runtime.run_id}:dma:{next_case_index}'
        previous_freeze = runtime._f6_case_freezes[_previous['case_id']]
        _previous['route_match_history'] = deepcopy(
            previous_freeze['route_matches'])
        _previous['policy_records'] = deepcopy(
            previous_freeze['policy_records'])
        _previous['scope_transition'] = dict(
            previous_case_id=previous_freeze['dma_case_id'],
            testcase_id=testcase_id,
            case_id=f'{runtime.run_id}:case:{next_case_index}',
            case_index=next_case_index)
        # This orchestration fixture skips the native transfer path, so close
        # its synthetic policy cursor before asking the real route owner to
        # open the next logical case.
        runtime.policy._pending = None
        runtime.policy._state = 'complete'
        runtime.dma._case_id = testcase_id
        runtime.dma._source_sequence = 0
        runtime.route_admission.begin_case(runtime.dma._execution, testcase_id)
        runtime._f6_used_dma_case_ids.add(testcase_id)
        runtime._f6_last_dma_case_index = next_case_index
        address, key = install_fetch(runtime, next_case_index)
        return dict(status='advanced', testcase_id=testcase_id,
            address=address, transaction=key)

    monkeypatch.setattr(compiled_f6, 'advance_f6_dma_logical_scope', advance)

    def execute_case(runtime, candidate, index, attempt):
        from copy import deepcopy
        from myfuzz.integration.compiled_f6 import _freeze_f6_case
        from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
        cpu_id = runtime.cpu_id
        slot = runtime.contract['program_contract']['slot_base'] + 256*index
        prefix = runtime.program.prefix(candidate, case_index=index)
        runtime.program.validate_prefix(prefix, candidate, case_index=index)
        source_id = runtime.contract['instruction_source_id']
        case_id = f'{runtime.run_id}:case:{index}'
        case = OnlineCase(case_id, 'CPU_TO_IP',
            runtime.runtime_path_admission['runtime_path_ids'][1],
            BoundOnlineInstruction(f'{source_id}:{index}', cpu_id, slot,
                prefix.hex(), source_id),
            (BatchAdvance((runtime.cpu_id,)),
                BatchAdvance((runtime.dma_id,))))
        receipt = runtime.session.submit_case(case,
            step_observer=lambda component, outputs:
                runtime._on_component_step(attempt, component, outputs),
            stop_after_advance=lambda command_index:
                index == 0 and command_index == 0)
        submissions.append(dict(case_id=case.case_id, status=receipt.status,
            components=(runtime.cpu, runtime.dma), processes=(runtime.cpu.process,
                runtime.dma.process), callback_components=tuple(
                    component for component in (runtime.cpu_id, runtime.dma_id))))
        expected_error = index == 1
        status = 'expected_error' if expected_error else 'passed'
        feedback = [0] * 5 if expected_error else [1] * 5
        scope = f6_assertion_evidence._scope(runtime)
        observations = {}
        evidence_inventory = {}
        for expectation_id in EXPECTATION_IDS:
            failed = expected_error and expectation_id == 'dma.irq_isr_completion'
            reference = f'{case_id}:{expectation_id}'
            evidence_scope = dict(scope, case_id=case_id,
                expectation_id=expectation_id)
            details = ({'error_completion': {'terminal_marker': 2}}
                if failed else {})
            details.update(raw_references=[], raw_evidence=[])
            if expectation_id == 'protocol_checker.receipt_violations':
                details.update(findings=[], observation_count=1,
                    checker_mode='synthetic_runner_orchestration_fixture')
            elif not failed:
                details['raw_evidence'] = [dict(component='synthetic',
                    event_id=1, kind='fixture_evidence')]
                details['raw_references'] = [dict(component='synthetic',
                    event_id=1, kind='fixture_evidence')]
            evidence_inventory[reference] = dict(kind=expectation_id,
                outcome='failed' if failed else 'passed',
                scope=evidence_scope, details=details)
            observations[expectation_id] = dict(
                status='failed' if failed else 'passed',
                reason='synthetic expected error' if failed else 'synthetic pass',
                evidence_refs=[reference])
        material = dict(case_id=case_id, observations=observations,
            evidence_inventory=evidence_inventory)
        attempt.update(case_id=case_id, case_index=index,
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            instruction_address=slot, prefix_hex=prefix.hex(),
            status_kind=status, expected_error=expected_error,
            feedback=feedback, case_material=material)
        route_rows = []
        policy_rows = []
        beat_count = 8
        for beat_index in range(beat_count):
            operation = 'read' if beat_index < 4 else 'write'
            word_index = beat_index if beat_index < 4 else beat_index - 4
            write = operation == 'write'
            route_owner = (runtime.route_admission._read_route if operation == 'read'
                else runtime.route_admission._write_route)
            address = (runtime.contract['program_contract']['source_address']
                if operation == 'read' else
                runtime.contract['program_contract']['destination_address']) + 4*word_index
            from dataclasses import asdict
            from myfuzz.scenario.ledger import TransactionKey
            key = TransactionKey(runtime.dma._execution, runtime.dma._case_id,
                runtime.dma.source_component, runtime.dma.reset_epoch,
                'dma-memory', beat_index + 1)
            error = int(expected_error and beat_index == beat_count - 1)
            route_row = dict(route_sha256=route_owner.identity_sha256,
                edge_key=route_owner.key, source_node_id=route_owner.source_node_id,
                target_node_id=route_owner.target_node_id,
                path_id=runtime.route_admission._path_id,
                initiator_component=route_owner.initiator_component,
                endpoint_id=route_owner.endpoint_id,
                target_kind=route_owner.target_kind,
                target_component=route_owner.target_component,
                target_id=route_owner.target_id, base=route_owner.base,
                size=route_owner.size, operation=operation, address=address,
                byte_enable=15, transaction=asdict(key),
                target_identity_sha256=route_owner.target_identity_sha256)
            route_rows.append(route_row)
            policy_rows.append(dict(transaction=asdict(key), address=address,
                write=write, value=(candidate.words[word_index] if write else 0),
                byte_enable=15, word_index=word_index, rdata=0, error=error))
            runtime.route_admission._route_matches[key] = route_row
        runtime.policy._records = policy_rows
        runtime.policy._pending = None
        runtime.policy._read = 4
        runtime.policy._write = 4 if not expected_error else 3
        runtime.policy._state = ('expected_response_fault_pending'
            if expected_error else 'complete')
        runtime._stop_after_expected_error = expected_error
        result = dict(status=status, case_id=case_id, case_index=index,
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            instruction_address=slot, prefix_hex=prefix.hex(),
            observations=deepcopy(observations), feedback=feedback)
        attempt['result'] = deepcopy(result)
        _freeze_f6_case(runtime, attempt, material)
        runtime._f6_last_dma_case_index = index
        return result

    monkeypatch.setattr(compiled_f6.CompiledF6Runtime, '_execute_case', execute_case)

    def assertion_material(runtime):
        from myfuzz.scenario.f6_assertion_evidence import _build, _scope
        return _build(_scope(runtime), [attempt['case_material']
            for attempt in runtime.attempts])

    monkeypatch.setattr(f6_assertion_evidence, 'build_f6_assertion_material',
        assertion_material)
    monkeypatch.setattr(compiled_f6, '_case_inventory',
        lambda runtime: [attempt['case_material'] for attempt in runtime.attempts])

    runtime = compiled_f6.CompiledF6Runtime(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=ROOT, cache_dir=tmp_path,
        run_id='f6-runtime-orchestration', rounds_per_case=1, max_cases=2,
        defer_begin=defer_begin)
    if defer_begin:
        assert runtime.runner._status == 'created'
        assert all(local.process is None for local in runtime.runner.sessions.values())
        with pytest.raises(ValueError, match='compiled-F6-runtime-not-begun'):
            runtime.submit(bytes(8))
        with pytest.raises(ValueError, match='compiled-F6-runtime-not-begun'):
            runtime.finish()
        assert not runtime.session._begun
        runtime.begin()
        with pytest.raises(ValueError, match='compiled-F6-already-begun'):
            runtime.begin()
    assert runtime._f6_instruction_fetch is None
    assert getattr(runtime.cpu, '_f6_instruction_fetch', None) is None
    assert runtime.runner.protocol_checker_report(runtime.dma_id)['status'] == 'incomplete'
    assert runtime.runner.protocol_checker_report(runtime.dma_id)[
        'installed_endpoint_ids'] == ['dma.control', 'dma.memory']
    commit_journal = runtime.runner._uart_ram_commit_join
    commit_authority = commit_journal._authority
    assert set(commit_authority._installed) == {runtime.cpu_id, runtime.dma_id}
    assert commit_authority._installed[runtime.cpu_id][0] is runtime.cpu.service
    assert commit_authority._installed[runtime.dma_id][0] is runtime.dma.memory_service
    assert commit_authority._channel_ids == {
        runtime.cpu_id: 'data', runtime.dma_id: 'dma-memory'}
    first_identity = next(index for index, row in enumerate(build_boundary['events'])
        if row[0] == 'identity')
    assert {row[1] for row in build_boundary['events'][:first_identity]
        if row[0] == 'prepare'} == set(runtime.runner.sessions)
    assert {row[1] for row in build_boundary['events'][:first_identity]
        if row[0] == 'validate_receipt'} == set(runtime.runner.sessions)
    join_index = next(index for index, row in enumerate(build_boundary['events'])
        if row[0] == 'join_receipts')
    assert join_index < first_identity
    assert type(runtime.session).__name__ == 'ScenarioSession'
    assert type(runtime.runner) is compiled_f6.ScenarioRunner
    assert type(runtime.dma).__name__ == 'GeneratedWishboneDmaScenarioSession'
    original_sessions = (runtime.cpu, runtime.dma)
    original_processes = (runtime.cpu.process, runtime.dma.process)
    original_pids = (runtime.cpu.process.pid, runtime.dma.process.pid)
    raw = sum(word << (11*index)
        for index, word in enumerate((51, 52, 53, 54))).to_bytes(8, 'little')
    raw_second = sum(word << (11*index)
        for index, word in enumerate((61, 62, 63, 64))).to_bytes(8, 'little')

    first = runtime.submit(raw)
    second = runtime.submit(raw_second)
    assert (first['status'], second['status']) == ('passed', 'expected_error')
    assert first['words'] != second['words']
    assert first['instruction_address'] != second['instruction_address']
    assert [row['case_id'] for row in submissions] == [
        'f6-runtime-orchestration:case:0', 'f6-runtime-orchestration:case:1']
    assert all(row['status'] == 'running' for row in submissions)
    assert all(row['components'] == original_sessions for row in submissions)
    assert all(row['processes'] == original_processes for row in submissions)
    assert callback_steps == [runtime.cpu_id,
        runtime.cpu_id, runtime.dma_id]
    assert (runtime.cpu, runtime.dma) == original_sessions
    assert (runtime.cpu.process, runtime.dma.process) == original_processes
    assert (runtime.cpu.process.pid, runtime.dma.process.pid) == original_pids
    assert len(runtime.session._cases) == 2
    assert runtime.cursor == 2

    prior_terminal = runtime.session._terminal_failure
    runtime.session._terminal_failure = dict(phase='checker', case_index=1,
        case_id='f6-runtime-orchestration:case:1', command_index=None,
        error_type='ValueError', error_message='synthetic terminal plan')
    try:
        terminal_plan = json.loads(runtime.session.encode_plan())
        projected_terminal_plan = compiled_f6._f6_expected_online_plan(runtime)
        assert terminal_plan['schema_version'] == 25
        assert compiled_f6._canonical(terminal_plan) == compiled_f6._canonical(
            projected_terminal_plan)
        assert compiled_f6._f6_export_failure(runtime, 'online_plan',
            terminal_plan) is None
        refusal = compiled_f6._f6_finish_state_failure(runtime,
            online_plan=terminal_plan,
            assertion_material=assertion_material(runtime), feedback=[0]*5,
            final_dma_case_id=runtime.dma._case_id)
        assert refusal == 'case-terminal-online-plan-not-accepted'
    finally:
        runtime.session._terminal_failure = prior_terminal

    prefix = runtime.finish()
    assert prefix['status'] == 'expected_error'
    assert prefix['scope'] == 'failed_prefix_full'
    assert prefix['completed'] is False
    assert prefix['feedback'] == [0] * 5
    assert type(prefix['online_plan']) is dict
    assert len(prefix['online_plan']['cases']) == 2
    assert prefix['online_plan']['cases'][0]['advances'] == [
        [runtime.cpu_id]]
    assert prefix['online_plan']['cases'][1]['advances'] == [
        [runtime.cpu_id], [runtime.dma_id]]
    assert set(prefix['original_execution_audit']['identities']) == {
        runtime.cpu_id, runtime.dma_id}

    envelope = runtime.replay(prefix)
    assert envelope['scope'] == 'failed_prefix_full'
    assert envelope['completed'] is False
    assert envelope['matches'] is True
    assert envelope['actual_prefix']['status'] == 'expected_error'
    assert envelope['actual_prefix']['scope'] == 'failed_prefix_full'
    assert envelope['actual_events']
    assert envelope['execution_audit']['identities']
    assert envelope['original_execution_audit']['identities']
    assert envelope['original_build'] and envelope['fresh_build']
    assert envelope['build_join']['status'] == 'complete'
    assert all(case['case_id'] in json.dumps(envelope['actual_prefix'])
        for case in runtime.attempts)



def test_f6_configuration_references_byte_addresses_and_write_delivery():
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime

    base = 0x40000000
    p = dict(slot_base=0x11000, operand_instruction_offsets=[0, 4, 8, 12],
        source_address=0x22000, destination_address=0x23000, result_base=0x24000)
    contract = dict(program_contract=p, control=dict(base=base,
        configuration_order=['src', 'dst', 'len', 'ctrl']),
        dma=dict(csr=dict(offsets=dict(src=8, dst=12, len=4, ctrl=0))))
    rows = []
    for index, (offset, value) in enumerate(zip((8, 12, 4, 0),
            (0x22000, 0x23000, 4, 0x0fed0004))):
        rows.append(dict(event_id=index+1, component='cpu', kind='data_accept',
            address=base+offset, write=1, wdata=value))
        rows.append(dict(event_id=index+11, component='cpu', kind='mmio_delivery',
            address=base+offset, write=True, write_value=value))
    rows.append(dict(event_id=20, component='cpu', kind='mmio_delivery',
        address=base, write=False, read_value=0))
    collector = SimpleNamespace(observer_view=rows, cpu_id='cpu', dma_id='dma',
        contract=contract, cpu=SimpleNamespace(_request_evidence={}, _waiting_instr=None),
        _active_f6_irq_delivery=None, _case_has_expected_error=False,
        _transaction_for_ref=lambda _ref: None,
        _append_observer=lambda *_args, **_kwargs: None)
    attempt = dict(case_index=0, words=[1, 2, 3, 4])
    CompiledF6Runtime._attempt_references(collector, attempt, start_event_id=0)
    assert attempt['configuration'] == [1, 2, 3, 4]
    assert attempt['deliveries'] == [11, 12, 13, 14]


def test_f6_read_scope_accepts_ignored_nonzero_write_data(tmp_path, monkeypatch):
    from copy import deepcopy
    from myfuzz.integration.compiled_f6 import _f6_scope_snapshot_failure
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case

    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)
    attempt['words'] = list(compile_f6_candidate_layout(runtime.path).decode(
        bytes.fromhex(attempt['raw8_hex'])).words)
    attempt['status_kind'], attempt['expected_error'] = 'passed', False
    snapshot = dict(dma_case_id=runtime.dma._case_id,
        route_matches=deepcopy(runtime.route_admission.route_matches),
        policy_records=deepcopy(runtime.policy.records))
    snapshot['policy_records'][2]['value'] = 1
    assert _f6_scope_snapshot_failure(runtime, attempt, snapshot) is None


def test_f6_consumer_accepts_ignored_nonzero_read_write_data(tmp_path, monkeypatch):
    from copy import deepcopy
    from myfuzz.integration.compiled_f6_consumer import _Case

    from tests.integration.f6_compiled_support import inputs as support_inputs, make_case
    runtime, attempt = make_case(support_inputs.__wrapped__(), tmp_path, monkeypatch)
    consumer = object.__new__(_Case)
    consumer.runtime, consumer.attempt, consumer.contract = runtime, attempt, runtime.contract
    consumer.cpu, consumer.dma = runtime.cpu, runtime.dma
    consumer.cpu_id, consumer.dma_id = runtime.cpu.source_component, runtime.dma.source_component
    row = deepcopy(next(r for r in runtime.observer_view
        if r.get('component') == consumer.dma_id and r.get('event_id') == attempt['reads'][0]))
    row['accepted']['value'] = 1
    row['payload']['pre_backend']['mwb_dat_w'] = 1
    consumer.event = lambda *_args: row
    consumer.unique = lambda *_args, **_kwargs: None
    consumer.live_dma = lambda *_args: None
    consumer.dma_beat('reads', 0, write=False,
        address=runtime.contract['program_contract']['source_address'], value=0)
