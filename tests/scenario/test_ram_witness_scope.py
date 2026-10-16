"""RAM prerequisite lane admission; software records, no DUT claim."""
from copy import deepcopy

import pytest

from myfuzz.scenario.source_actions import CrossCaseEffectTracker
from tests.scenario.test_dynamic_ram_prerequisite import commit_event


@pytest.mark.parametrize('fault', [
    'disabled_lane', 'outside_span', 'missing_lane', 'duplicate_lane',
    'cell_version', 'generation', 'zero_version', 'bool_enable',
    'huge_width', 'bad_value_after_valid_lane',
])
def test_inconsistent_commit_cannot_supply_any_ram_prerequisite(fault):
    event = commit_event(1, commit_id='a', byte_offset=128)
    doc = event['commit_document']
    doc.update(width_bytes=2, byte_enable=3)
    cell = doc['enabled_byte_cells'][0]
    doc['enabled_byte_cells'].append({**deepcopy(cell), 'byte_offset': 129})
    if fault == 'disabled_lane': doc['byte_enable'] = 1
    elif fault == 'outside_span': doc['enabled_byte_cells'][1]['byte_offset'] = 130
    elif fault == 'missing_lane': doc['enabled_byte_cells'].pop()
    elif fault == 'duplicate_lane': doc['enabled_byte_cells'][1]['byte_offset'] = 128
    elif fault == 'cell_version': doc['enabled_byte_cells'][1]['version'] = [0, 2]
    elif fault == 'generation': doc['version'] = [1, 1]
    elif fault == 'zero_version':
        doc['version'] = [0, 0]
        for row in doc['enabled_byte_cells']: row['version'] = [0, 0]
    elif fault == 'bool_enable': doc['byte_enable'] = True
    elif fault == 'huge_width': doc['width_bytes'] = 1 << 30
    elif fault == 'bad_value_after_valid_lane': doc['enabled_byte_cells'][1]['value'] = 256
    tracker = CrossCaseEffectTracker()
    assert tracker.ingest([event]) == ()
    assert tracker.retained_ram_witnesses('ram', 128) == ()


def test_partial_commit_supplies_only_enabled_lane_with_exact_version():
    event = commit_event(1, commit_id='a', byte_offset=129)
    event['commit_document'].update(byte_offset=128, width_bytes=4, byte_enable=2)
    tracker = CrossCaseEffectTracker()
    witnesses = tracker.ingest([event])
    assert len(witnesses) == 1
    assert witnesses[0].version == (0, 1)
    assert len(tracker.retained_ram_witnesses('ram', 129)) == 1
    assert tracker.retained_ram_witnesses('ram', 128) == ()


@pytest.mark.parametrize('fault', ['generation', 'sequence', 'span'])
def test_commit_identity_must_fit_actual_uint64_memory_contract(fault):
    event = commit_event(1, commit_id='a', byte_offset=128)
    doc = event['commit_document']
    cell = doc['enabled_byte_cells'][0]
    if fault == 'generation':
        doc['generation'] = 1 << 64
        doc['version'] = cell['version'] = [1 << 64, 1]
    elif fault == 'sequence': doc['version'] = cell['version'] = [0, 1 << 64]
    else:
        doc.update(byte_offset=(1 << 64) - 1, width_bytes=2, byte_enable=2)
        cell['byte_offset'] = 1 << 64
    assert CrossCaseEffectTracker().ingest([event]) == ()


@pytest.mark.parametrize('width', [1, 2, 4, 8])
def test_actual_memory_service_commit_preserves_enabled_lane_scope(width):
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.memory_service import MemoryService
    from tests.scenario.test_memory_read_authority import key

    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=7, max_initialized_bytes=4096)
    service = MemoryService(memory, TransactionLedger(), commit_stream_capacity=4)
    lane = width - 1
    service.write(key(), 0x20000, 0x5a << (8 * lane),
                  width_bytes=width, byte_enable=1 << lane)
    event, = service.drain_commit_events()
    tracker = CrossCaseEffectTracker()
    witness, = tracker.ingest([{**event, 'event_id': 1, 'component': 'cpu'}])
    assert witness.subject['byte_offset'] == lane
    assert witness.value == 0x5a
    assert witness.version == (0, 1)
    for other in range(width):
        assert bool(tracker.retained_ram_witnesses('ram', other)) == (other == lane)
