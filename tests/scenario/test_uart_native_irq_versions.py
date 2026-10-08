from copy import deepcopy
import hashlib
import json

from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership


def authority():
    registry = AdmissionRegistry()
    document = dict(action_id='rx-a', component='uart', port='uart_rx_byte',
                    value=0x5a, bit_offset=0, width=8, kind='source_event')
    digest = hashlib.sha256(json.dumps(document, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    admission = SourceAdmission.create(case_id='source-A', case_index=0,
        source_id='rx', path_id='owner-only', direction='IP_TO_CPU', component='uart',
        action_id='rx-a', role='fuzz_source', input_kind='source_event', input_sha256=digest)
    registry.register(admission)
    ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),
        InputField('cpu', 'irq', 1)), (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'rx'),
        InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_watermark')))
    return registry, ownership, admission


def join():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    registry, ownership, admission = authority()
    return UartNativeIrqJoin(ownership=ownership, admission_registry=registry), admission


def aliased_authority(*, width=8, path=None, direction='IP_TO_CPU', component='uart'):
    from types import SimpleNamespace
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
    from myfuzz.scenario.runner import Binding
    from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract, PreparedRuntimePathContract
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    graph = DependencyGraph(sources=(FuzzableSource('uart.external_rx_byte', 'uart',
        'uart_rx_byte', 0, width, ('IP_TO_CPU',)),), rules=(
        DependencyRule('uart.rx_watermark', ('uart.external_rx_byte',), 'EVENT_ORDER'),
        DependencyRule('cpu.uart_irq', ('uart.rx_watermark',), 'DATA_BINDING')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('uart.external_rx_byte', 'uart', 'physical', 'uart_rx_byte', 0, width),
        RuntimeNode('uart.rx_watermark', 'uart', 'physical', 'uart_rx_watermark', 0, 1),
        RuntimeNode('cpu.uart_irq', 'cpu', 'physical', 'irq', 0, 1)),
        (RuntimeEdgeContract(1, 0, 'direct_binding'),))
    ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8), InputField('cpu', 'irq', 1)),
        (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'external_uart_rx_byte'),
         InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_watermark')))
    prepared = PreparedRuntimePathContract(graph, contract, (('IP_TO_CPU',
        graph.edge_paths_to('cpu.uart_irq', direction='IP_TO_CPU')[0]),))
    runner = SimpleNamespace(sessions={'uart':SimpleNamespace(), 'cpu':SimpleNamespace()},
        ownership=ownership, bindings=(Binding('uart', 'uart_rx_watermark', 'cpu', 'irq', 1),))
    compiled = prepared.bind(runner).document(); compiled['declaration'] = prepared.document()
    index = RuntimeEdgeIndex(compiled, contract.document())
    _, _, original = authority()
    admission = SourceAdmission.create(case_id=original.case_id, case_index=0,
        source_id='uart.external_rx_byte', path_id=path or compiled['paths'][0]['path_id'],
        direction=direction, component=component, action_id=original.action_id,
        role=original.role, input_kind='source_event', input_sha256=original.input_sha256)
    registry = AdmissionRegistry(); registry.register(admission)
    return registry, ownership, index, admission


def test_actual_logical_source_alias_requires_selected_compiled_authority():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    registry, ownership, index, admission = aliased_authority()
    tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry, edge_index=index)
    event = raw(); tracker.consume(event); tracker.consume(update(event))
    assert accepted(tracker.consume(retention(admission)), 'native_irq_cause')


def test_alias_without_index_or_wrong_selected_source_scope_never_promotes():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    for options, missing in (({}, True), ({'path':'unselected'}, False),
            ({'direction':'CPU_TO_IP'}, False), ({'component':'cpu'}, False), ({'width':7}, False)):
        registry, ownership, index, admission = aliased_authority(**options)
        tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry,
            edge_index=None if missing else index)
        event = raw(); tracker.consume(event); tracker.consume(update(event))
        records = tracker.consume(retention(admission))
        assert not accepted(records, 'native_irq_cause')
        assert any(record.get('status') == 'incomplete' for record in records)


def raw(tick=1, *, prior=0, output=1, entry_count=1):
    from myfuzz.local_harness.opentitan_uart_fifo_contract import (
        UART_FIFO_PROBES, uart_fifo_observation_contract)
    pre = {'probe_uart_' + key: 0 for key in UART_FIFO_PROBES}
    pre.update(probe_uart_fifo_depth=entry_count, probe_uart_watermark_threshold=1,
        probe_uart_event_rx_watermark=int(entry_count > 0),
        probe_uart_intr_enable_rx_watermark=1, probe_uart_irq_rx_watermark=prior,
        intr_rx_watermark_o=prior)
    post = {**pre, 'probe_uart_irq_rx_watermark': output, 'intr_rx_watermark_o': output}
    return dict(kind='uart_tick_observation', event_id=100 + tick, component='uart',
        reset_epoch=0, local_tick=tick, command_scope=dict(component='uart', reset_epoch=0,
        command_sequence=tick), receipt_id=dict(execution='uart-process', sequence=tick),
        observation_contract=uart_fifo_observation_contract(), pre=pre, post=post)


def update(event, entries=None):
    a, b = event['pre'], event['post']
    return dict(kind='uart_irq_update', schema_version='uart_irq_update.v1',
        event_id=200 + event['local_tick'], component='uart', reset_epoch=0,
        local_tick=event['local_tick'], observation_event_id=event['event_id'],
        irq_class='rx_watermark', pre_output=a['probe_uart_irq_rx_watermark'],
        post_output=b['probe_uart_irq_rx_watermark'], pre_event=a['probe_uart_event_rx_watermark'],
        pre_state=a['probe_uart_intr_state_rx_watermark'],
        post_state=b['probe_uart_intr_state_rx_watermark'],
        pre_enable=a['probe_uart_intr_enable_rx_watermark'],
        pre_test=a['probe_uart_intr_test_rx_watermark'],
        pre_test_qe=a['probe_uart_intr_test_qe_rx_watermark'],
        pre_watermark_test=a['probe_uart_watermark_test'],
        post_watermark_test=b['probe_uart_watermark_test'],
        watermark_threshold=a['probe_uart_watermark_threshold'],
        watermark_level=a['probe_uart_watermark_level'], pre_depth=a['probe_uart_fifo_depth'],
        pre_entry_ids=entries if entries is not None else [['uart', 0, 0, 1]])


def retention(admission, entry=None):
    return dict(kind='uart_consumption_match', schema_version='uart_consumption_match.v1',
        event_id=300, component='uart', reset_epoch=0, local_tick=2,
        status='accepted', proof_scope='uart_fifo_retention',
        entry_id=entry if entry is not None else ['uart', 0, 0, 1],
        retained_at_push=True, source_admission=admission.document(), frame_id='frame-a',
        receiver_id=['uart', 0, 1], receiver_start_event=1, completion_event=2,
        push_event=3, validation_event=4, sample_refs=[dict(event_id=i) for i in range(10)])


def accepted(records, scope):
    return [record for record in records if record.get('status') == 'accepted'
            and record.get('proof_scope') == scope]


def test_post_cause_is_exact_pre_queue_and_late_source_proof_appends():
    tracker, admission = join()
    event = raw()
    tracker.consume(event)
    records = tracker.consume(update(event))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    assert resource['value'] == 1 and resource['pre_entry_ids'] == [['uart', 0, 0, 1]]
    assert tracker.output_at('uart', 0, 2, 'post', 'rx_watermark') is None
    assert not accepted(records, 'native_irq_cause')
    original = deepcopy(resource)
    records = tracker.consume(retention(admission))
    assert len(accepted(records, 'native_irq_cause')) == 1
    assert resource == original


def test_alias_bool_reset_and_equal_entry_mismatch_never_promote():
    for mutation in ('alias', 'bool', 'epoch', 'wrong_entry'):
        tracker, admission = join()
        event = raw()
        if mutation == 'alias': event['post']['intr_rx_watermark_o'] = 0
        if mutation == 'bool': event['pre']['probe_uart_intr_enable_rx_watermark'] = True
        if mutation == 'epoch': event['reset_epoch'] = True
        tracker.consume(event)
        records = tracker.consume(update(event))
        records += tracker.consume(retention(admission,
            ['uart', 0, 0, 2] if mutation == 'wrong_entry' else None))
        assert not accepted(records, 'native_irq_cause')


def test_test_only_and_mixed_queue_never_nominate_single_frame():
    for mutation in ('test', 'mixed'):
        tracker, admission = join()
        event = raw(entry_count=2 if mutation == 'mixed' else 1)
        if mutation == 'test': event['pre']['probe_uart_watermark_test'] = 1
        tracker.consume(event)
        entries = [['uart', 0, 0, 1], ['uart', 0, 0, 2]] if mutation == 'mixed' else None
        tracker.consume(update(event, entries))
        assert not accepted(tracker.consume(retention(admission)), 'native_irq_cause')


def test_more_than_capacity_source_versions_recycle_unreferenced_history():
    tracker, admission = join()
    tracker.consume(retention(admission))
    for tick in range(1, 1101):
        event = raw(tick, prior=int(tick > 1)); event['event_id'] = 10000 + tick * 10
        tracker.consume(event)
        derived = update(event); derived['event_id'] = event['event_id'] + 1
        tracker.consume(derived)
    assert tracker._global_bad is False
    resource = tracker.output_at('uart', 0, 1100, 'post', 'rx_watermark')
    assert resource['value'] == 1
    assert tracker.output_at('uart', 0, 1, 'post', 'rx_watermark') is None
