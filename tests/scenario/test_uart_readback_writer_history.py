"""Bounded writer history without discarding a live read snapshot's version."""
from copy import deepcopy
from dataclasses import asdict

from myfuzz.scenario.ledger import TransactionKey
from tests.scenario.test_uart_memory_readback import scenario_readback, play


def writer_fixture():
    join, events, write_token, read_token, *_ = scenario_readback()
    play(join, events, write_token, read_token)
    service = join._read_authority._installed['cpu'][0]
    template = deepcopy(next(iter(join._writers.values())))
    return join, service, template


def next_writer(join, service, template, sequence, *, address=0x20000):
    prior = template['store_fullkey']
    key = TransactionKey(**dict(prior, source_sequence=sequence))
    value = sequence & 255
    receipt = service.write(key, address, value, width_bytes=4, byte_enable=15)
    document = receipt.commit_document()
    service.ack_commit_events((document['commit_id'],))
    report = deepcopy(template)
    report.update(store_fullkey=asdict(key), memory_id=document['memory_id'],
                  generation=document['generation'], byte_offset=document['byte_offset'],
                  byte_value=value, byte_version=document['version'],
                  writer_event_id=str(key), commit_id=document['commit_id'])
    return report


def test_three_hundred_overwrites_reclaim_only_obsolete_writer_versions():
    join, service, template = writer_fixture()
    for sequence in range(4, 304):
        report = next_writer(join, service, template, sequence)
        assert join._remember_writer(report)
        assert len(join._writers) <= join.max_writer_versions
        current = service.memory._bytes[('host-ram', 0)]
        assert any(writer['byte_version'] == list(current.version)
                   for writer in join._writers.values())
    assert not join.degraded
    assert len(join._writers) <= 256


def test_issued_read_and_pending_retirement_pin_old_writer_across_overwrite():
    join, events, write_token, read_token, *_ = scenario_readback()
    split = next(i for i, event in enumerate(events)
                 if event.get('kind') == 'memory_read_issuance')
    play(join, events[:split], write_token, None)
    assert len(join._writers) == 1
    service = join._read_authority._installed['cpu'][0]
    template = deepcopy(next(iter(join._writers.values())))
    next_writer(join, service, template, 4)

    join._reclaim_obsolete_writers()
    assert len(join._writers) == 1  # Authority still holds the issued snapshot.
    play(join, [events[split]], None, read_token)
    join._reclaim_obsolete_writers()
    assert len(join._writers) == 1  # Join now holds it until LW retires.
    out = play(join, events[split + 1:], None, None)
    assert len([p for p in out if p.get('kind') == 'uart_memory_readback'
                and p.get('status') == 'accepted']) == 1
    join._reclaim_obsolete_writers()
    assert len(join._writers) == 0


def test_distinct_current_cells_cannot_be_evicted_for_capacity():
    join, service, template = writer_fixture()
    join.max_writer_versions = 2
    first = next_writer(join, service, template, 4, address=0x20004)
    second = next_writer(join, service, template, 5, address=0x20008)
    assert join._remember_writer(first)
    assert not join._remember_writer(second)
    assert join.degraded
    assert len(join._writers) == 2
