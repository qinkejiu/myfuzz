"""Shared compiled transport and admitted F2 address seed contract."""
import importlib
import struct
from types import SimpleNamespace

import pytest
from tests.integration.test_compiled_f2_decoder import inputs


def transport():
    return importlib.import_module('myfuzz.integration.compiled_rfuzz_transport')


def frame(count):
    return struct.pack('>IIHHHHQ', 0x19931993, 42, 1, 0, 0, 0, count) + bytes(8 * count)


@pytest.mark.parametrize('count', [1, 8, 9, 64, 200])
def test_common_wire_preserves_all_records(count):
    batch = transport().parse_compiled_input_buffer(frame(count))
    assert batch.tests == (tuple(bytes(8) for _ in range(count)),)
    from myfuzz.integration.compiled_rfuzz import parse_compiled_input_buffer
    assert parse_compiled_input_buffer(frame(count)) == batch


def test_common_wire_refuses_above_200():
    with pytest.raises(ValueError):
        transport().parse_compiled_input_buffer(frame(201))


def test_f2_wire_seed_is_the_admitted_address(inputs):
    from myfuzz.integration.compiled_f2_rfuzz import f2_seed_record
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    path = next(p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F2')
    raw = f2_seed_record(path)
    assert raw == path['execution_contract']['address'].to_bytes(4, 'little') + bytes(4)
    assert compile_f2_candidate_layout(path).classify(raw[:4]).accepted
    assert path['seed'] is None
    from copy import deepcopy
    invalid = deepcopy(path)
    invalid['seed'] = {'address': 0}
    with pytest.raises(ValueError):
        f2_seed_record(invalid)


def test_owned_pair_closes_handles_checks_capacity_and_tuple_order(monkeypatch):
    module = transport()
    opened, closed, writes, calls = [], [], [], []
    capacity = [32]
    class Segment:
        def __init__(self, identity, **kwargs):
            self.identity = identity
            self.size = capacity[0]
            opened.append((identity, kwargs))
        def __enter__(self): return self
        def __exit__(self, *args): closed.append(self.identity)
        def read(self): return frame(1)
        def write(self, data): writes.append(data)
    monkeypatch.setattr(module, 'OwnedSegment', Segment)
    def execute(batch, *, on_receipt):
        calls.append(on_receipt)
        return (b'\x07',)
    executor = SimpleNamespace(counter_count=1, execute_batch=execute)
    callback = object()
    assert module.process_compiled_owned_pair(executor, 11, 12, creator_pid=123, on_receipt=callback) == (12, 11)
    assert opened == [(11, {'creator_pid': 123}), (12, {'creator_pid': 123, 'writable': True})]
    assert closed == [12, 11] and calls == [callback]
    assert len(writes[0]) == 32 and writes[0][-8:] == bytes(8)
    capacity[0] = 23
    with pytest.raises(ValueError, match='capacity'):
        module.process_compiled_owned_pair(executor, 11, 12, creator_pid=123)
    assert closed == [12, 11, 12, 11] and len(calls) == 1
    with pytest.raises(ValueError, match='alias'):
        module.process_compiled_owned_pair(executor, 11, 11, creator_pid=123)
    assert len(opened) == 4
