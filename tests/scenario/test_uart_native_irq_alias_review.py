"""Independent logical-source/physical-owner authority review; software only."""
from types import SimpleNamespace
import hashlib
import json

import pytest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runtime_path_contract import (PreparedRuntimePathContract,
    RuntimeNode, RuntimeEdgeContract, RuntimePathContract)
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
from myfuzz.scenario.runner import Binding
from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
from tests.scenario.test_uart_native_irq_versions import raw, update, retention, accepted
from tests.scenario.test_uart_native_irq_binding import delivery
from tests.scenario.test_uart_native_irq_taken import sample, taken


def authority(*, bit=0, width=8, owner='external_uart_rx_byte'):
    graph = DependencyGraph(sources=(FuzzableSource('uart.external_rx_byte',
        'uart', 'uart_rx_byte', bit, width, ('IP_TO_CPU',)),), rules=(
        DependencyRule('wm', ('uart.external_rx_byte',), 'EVENT_ORDER'),
        DependencyRule('cpu.irq', ('wm',), 'DATA_BINDING')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('uart.external_rx_byte', 'uart', 'physical', 'uart_rx_byte', bit, width),
        RuntimeNode('wm', 'uart', 'physical', 'uart_rx_watermark', 0, 1),
        RuntimeNode('cpu.irq', 'cpu', 'physical', 'irq', 0, 1)),
        (RuntimeEdgeContract(1, 0, 'direct_binding'),))
    ownership = compile_ownership((InputField('uart', 'uart_rx_byte', bit + width),
        InputField('cpu', 'irq', 1)), (InputOwner('uart', 'uart_rx_byte', bit, width,
        'source', owner), InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_watermark')) +
        ((InputOwner('uart', 'uart_rx_byte', 0, bit, 'fixed', 'zero'),) if bit else ()))
    prepared = PreparedRuntimePathContract(graph, contract, (
        ('IP_TO_CPU', graph.edge_paths_to('cpu.irq', direction='IP_TO_CPU')[0]),))
    runner = SimpleNamespace(sessions={'uart': SimpleNamespace(), 'cpu': SimpleNamespace()},
        ownership=ownership, bindings=(Binding('uart', 'uart_rx_watermark', 'cpu', 'irq', 1),))
    compiled = prepared.bind(runner).document(); compiled['declaration'] = prepared.document()
    index = RuntimeEdgeIndex(compiled, contract.document())
    # Take the authenticated selected path ID, never construct a name-based path.
    path_id = compiled['paths'][0]['path_id']
    admission = SourceAdmission.create(case_id='alias-review', case_index=0,
        source_id='uart.external_rx_byte', path_id=path_id, direction='IP_TO_CPU',
        component='uart', action_id='alias-rx', role='fuzz_source',
        input_kind='source_event', input_sha256='a' * 64)
    registry = AdmissionRegistry(); registry.register(admission)
    return registry, ownership, index, admission


def chain(registry, ownership, index, admission):
    tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry,
        edge_index=index)
    event = raw(); records = list(tracker.consume(event))
    records.extend(tracker.consume(update(event)))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    records.extend(tracker.consume(delivery(resource)))
    records.extend(tracker.consume(sample())); records.extend(tracker.consume(taken()))
    records.extend(tracker.consume(retention(admission)))
    return records


def test_verified_index_resolves_distinct_logical_source_and_physical_owner():
    registry, ownership, index, admission = authority()
    assert index.source_owner_ref(admission.source_id, admission.path_id,
        admission.direction, 'uart', 'uart_rx_byte', 0, 8) == 'external_uart_rx_byte'
    records = chain(registry, ownership, index, admission)
    assert len(accepted(records, 'native_irq_cause')) == 1
    assert len(accepted(records, 'cpu_external_irq_taken')) == 1


@pytest.mark.parametrize('mutation', ['missing_index', 'wrong_index', 'wrong_owner', 'wrong_path',
    'wrong_direction', 'wrong_component', 'wrong_bits', 'self_signed'])
def test_alias_without_exact_registered_index_authority_never_promotes(mutation):
    registry, ownership, index, admission = authority()
    if mutation == 'missing_index': index = None
    elif mutation == 'wrong_index':
        from tests.scenario.test_runtime_edge_index import fixture
        index = RuntimeEdgeIndex(*fixture())
    elif mutation == 'wrong_owner': _, _, index, _ = authority(owner='other_external_owner')
    elif mutation == 'wrong_bits': _, _, index, _ = authority(bit=1, width=7)
    else:
        doc = admission.document(); doc.pop('admission_id')
        if mutation == 'wrong_path': doc['path_id'] = 'unselected-path'
        elif mutation == 'wrong_direction': doc['direction'] = 'IP_TO_IP'
        elif mutation == 'wrong_component': doc['component'] = 'other'
        else: doc['action_id'] = 'self-signed-unregistered'
        doc.pop('schema_version'); admission = SourceAdmission.create(**doc)
        if mutation != 'self_signed':
            registry = AdmissionRegistry(); registry.register(admission)
    records = chain(registry, ownership, index, admission)
    assert not accepted(records, 'native_irq_cause')
    assert not accepted(records, 'cpu_external_irq_taken')
