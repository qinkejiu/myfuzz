"""Synthetic-wire tests for the declared ARID/RID instruction hop.

Every sample below is a hand-written pair of AXI4 edges, not a replayed RTL run:
the point of these tests is that the reader accepts *only* the ID the adapter
declared, covers both 32-bit words of one 8-byte granule, refuses a row that
declares nothing, and never switches on the unified commit stream by itself.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

from myfuzz.integration import cva6_axi_mmio
from myfuzz.integration.cva6_axi_mmio import (cva6_axi_mmio_traces,
                                             cva6_instruction_identity,
                                             replay_cva6_axi)
from myfuzz.integration.compiled_mmio import memory_feedback_options
from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter
from myfuzz.integration.native_mmio_data_hops import (_id_instruction_hops,
                                                      _instruction_id_fields,
                                                      check_native_mmio_data_hops)
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE
from myfuzz.local_harness.cva6_axi_mmio_session import GeneratedCva6AxiMmioSession

MEMORY_BASE = 0x10000
FIRST = bytes.fromhex('b7000040')   # one real generated word
SECOND = bytes.fromhex('93800000')  # and the real NOP beside it
GRANULE = FIRST + SECOND            # one 8-byte fetch beat's worth
SOURCE_ID = 'ram.image:0'


class _Profile:
    capabilities = {'address_width': 64, 'data_width': 64, 'id_width': 4,
                    'user_width': 64, 'byte_enable': True,
                    'error_response': True, 'bursts': False,
                    'max_outstanding': 1}


class _Plan:
    profile = _Profile()

    class request:
        instance_id = 'processor'


class _Artifact:
    def __init__(self):
        self.plan = _Plan()
        self.runtime_document = {
            'kind': 'cva6_packed_axi4_cpu',
            'backend_ports': [
                {'name': 'axi_' + role, 'role': role, 'channel': 'axi',
                 'direction': direction, 'width': width}
                for role, (direction, width) in CVA6_AXI_SHAPE.items()],
            'boot_contract': {'configured_boot_base': MEMORY_BASE},
        }


def sample(event_id, tick, **roles):
    backend = {name: 0 for name in
               ('axi_' + role for role in CVA6_AXI_SHAPE)}
    for key, value in roles.items():
        backend['axi_' + key] = value
    return {'event_id': event_id, 'component': 'processor', 'local_tick': tick,
            'outputs': {'driver_samples': [
                {'local_tick': tick, 'pre': {'backend': backend}}]}}


def granule_events(*, chunks, arid=0, rid=0, rsize=3, base=MEMORY_BASE,
                   source_event_id=SOURCE_ID, start_event=1, start_tick=1,
                   generation=0, commit=1):
    """One materialization plus one accepted-AR/R pair per 8-byte granule.

    Returns ``(events, accepted)`` where ``accepted`` is the list of
    ``(sequence, acceptance_event, response_event, address)`` the replay must
    reproduce.  The journal entry each beat really produced is placed strictly
    between its own acceptance and response, exactly like the live session.
    """
    events = []
    event_id = start_event
    tick = start_tick
    code = b''.join(chunks)
    events.append({'event_id': event_id, 'component': 'processor',
                   'kind': 'instruction_source', 'address': base,
                   'data_hex': code.hex(), 'source_event_id': source_event_id,
                   'generation': generation})
    source_event = event_id
    event_id += 1
    accepted = []
    for index, chunk in enumerate(chunks):
        address = base + 8 * index
        sequence = index + 1
        acceptance = event_id
        events.append(sample(event_id, tick, arvalid=1, arready=1,
                             araddr=address, arsize=rsize, arlen=0, arburst=1,
                             arid=arid))
        event_id += 1
        tick += 1
        # The host RAM service's own record of that granule, between the two
        # edges the beat was accepted and answered on.
        events.append({
            'event_id': event_id, 'component': 'processor',
            'kind': 'memory_read', 'address': address, 'memory_id': 'ram',
            'generation': generation, 'byte_offset': address - base,
            'width_bytes': len(chunk), 'value': int.from_bytes(chunk, 'little'),
            'data_hex': chunk.hex(), 'producer_event_id': acceptance,
            'versions': [[generation, commit]] * len(chunk),
            'writer_event_ids': [source_event_id] * len(chunk),
            'writer_kinds': ['INSTRUCTION_SOURCE'] * len(chunk),
            'transaction': {'channel_id': 'memory',
                            'execution_id': 'local-execution',
                            'testcase_id': 'synthetic',
                            'source_component': 'processor',
                            'source_epoch': 0, 'source_sequence': sequence},
        })
        event_id += 1
        tick += 1
        response = event_id
        events.append(sample(event_id, tick, rvalid=1, rready=1, rid=rid,
                             rdata=int.from_bytes(chunk, 'little'), rlast=1,
                             rresp=0))
        event_id += 1
        tick += 1
        accepted.append((sequence, acceptance, response, address))
    return events, accepted, source_event


def hops_for(events, code, *, source_event_id=SOURCE_ID, fields=None,
             instruction_snapshots=None, base=MEMORY_BASE):
    traces = cva6_axi_mmio_traces(_Artifact())
    completed, _reads = replay_cva6_axi(events, 'processor', traces)
    if fields is None:
        fields = _instruction_id_fields(traces['instruction_id_map'])
    source = next(event for event in events
                  if event.get('kind') == 'instruction_source')
    return _id_instruction_hops(
        events=events, cpu='processor', address=base, code=code,
        source=source, source_event_id=source_event_id, completed=completed,
        fields=fields,
        image={'component': 'processor', 'port': 'ram',
               'range': [MEMORY_BASE, MEMORY_BASE + 0xffff]},
        instruction_snapshots=instruction_snapshots), completed


def test_only_the_declared_read_id_becomes_a_fetch_hop():
    """ARID 0 is the fetch, ARID 1 is data - even at the very same address."""
    events, accepted, _source = granule_events(chunks=[GRANULE])
    data_acceptance = events[-1]['event_id'] + 1
    # One more read of the *same* granule with the other declared ID and the
    # same bytes: if the reader ever took a beat by address alone this would
    # show up as a second hop.
    events.append(sample(data_acceptance, 99, arvalid=1, arready=1,
                         araddr=MEMORY_BASE, arsize=3, arlen=0, arburst=1,
                         arid=1))
    events.append(sample(data_acceptance + 1, 100, rvalid=1, rready=1, rid=1,
                         rdata=int.from_bytes(GRANULE, 'little'), rlast=1,
                         rresp=0))
    hops, completed = hops_for(events, GRANULE)
    assert len(completed) == 2
    assert len(hops) == 1
    hop = hops[0]
    assert (hop['arid'], hop['rid'], hop['arsize']) == (0, 0, 3)
    assert len(hop['native_beats']) == 1
    assert hop['acceptance_event'] == accepted[0][1]
    assert hop['response_event'] == accepted[0][2]
    assert hop['superseded_same_address_beats'] == []
    # The ARID=1 beat exists on this port but is not part of the fetch hop.
    assert data_acceptance not in {beat['acceptance_event']
                                  for beat in hop['native_beats']}


def test_one_eight_byte_beat_covers_two_32_bit_words():
    """The granule is reported at its real width and split into two words."""
    events, _accepted, _source = granule_events(chunks=[GRANULE])
    hops, _completed = hops_for(events, GRANULE)
    assert len(hops) == 1
    hop = hops[0]
    assert (hop['granule_bytes'], hop['granule_hex']) == (8, GRANULE.hex())
    assert hop['fetched_hex'] == GRANULE.hex()
    assert hop['bytes_match'] is True
    words = hop['instruction_words']
    assert [word['address'] for word in words] == [MEMORY_BASE, MEMORY_BASE + 4]
    assert [word['source_word_hex'] for word in words] == [FIRST.hex(), SECOND.hex()]
    assert [word['fetched_word_hex'] for word in words] == [FIRST.hex(), SECOND.hex()]
    assert all(word['bytes_match'] == [True] * 4 for word in words)
    assert [word['authoritative_snapshot'] for word in words] == [
        'not-in-declared-window'] * 2
    assert hop['instruction_source_byte_offset'] == 0
    assert hop['native_beats'][0]['read_hex'] == GRANULE.hex()


def test_a_granule_that_was_never_fetched_on_the_declared_id_is_refused():
    """A read with another ID (or no beat at all) is never a fetch hop."""
    events, _accepted, _source = granule_events(chunks=[GRANULE, GRANULE],
                                               arid=1, rid=1)
    # Two granules declared, but the bus only ever read them as data (ID 1).
    with pytest.raises(ValueError):
        hops_for(events, GRANULE + GRANULE)


def test_a_granule_with_no_beat_and_no_read_is_an_observation_gap():
    """Two different refusals: unavailable evidence versus contradictory."""
    from myfuzz.integration.native_obi_hops import F2ObservationMissing
    events, _accepted, _source = granule_events(chunks=[GRANULE])
    with pytest.raises(F2ObservationMissing):
        # The second declared granule was never read at all.
        hops_for(events, GRANULE + GRANULE)


def test_a_response_on_the_other_id_is_refused():
    events, _accepted, _source = granule_events(chunks=[GRANULE], arid=0, rid=1)
    with pytest.raises(ValueError) as error:
        hops_for(events, GRANULE)
    assert 'instruction-id-response' in str(error.value)


def test_an_undeclared_row_keeps_the_data_only_scope(monkeypatch):
    """Without the anchors there is no map, so nothing opens a hop."""
    monkeypatch.setattr(cva6_axi_mmio, '_read_anchor', lambda path, marker: None)
    assert cva6_instruction_identity() is None
    traces = cva6_axi_mmio_traces(_Artifact())
    assert 'instruction_id_map' not in traces
    assert traces['instruction_hop_refusal'] == cva6_axi_mmio.INSTRUCTION_HOP_REFUSAL
    # ... and the reader refuses a row that declares neither scope, instead of
    # silently falling back to "no instruction hop".
    with pytest.raises(ValueError) as error:
        check_native_mmio_data_hops(
            events=[], declaration={}, image={'component': 'processor'},
            stream={}, address=0, source_event_id='x', joins=[], ram_event_id=1,
            instruction_snapshots=(), result_snapshot=None,
            cpu_adapter=MmioCpuAdapter('axi4', object, traces, {}), flow='F2')
    assert 'scope-required' in str(error.value)
    with pytest.raises(ValueError) as conflict:
        check_native_mmio_data_hops(
            events=[], declaration={}, image={'component': 'processor'},
            stream={}, address=0, source_event_id='x', joins=[], ram_event_id=1,
            instruction_snapshots=(), result_snapshot=None,
            cpu_adapter=MmioCpuAdapter('axi4', object, traces, {}), flow='F2',
            refusal='no identity', instruction_id_map={'arid': 0, 'rid': 0,
                                                       'granule_bytes': 8,
                                                       'rsize': 3})
    assert 'scope-conflict' in str(conflict.value)


def test_the_declared_map_must_name_the_real_fetch_width():
    good = {'arid': 0, 'rid': 0, 'granule_bytes': 8, 'rsize': 3}
    assert _instruction_id_fields(good)['granule_bytes'] == 8
    for broken in ({**good, 'rsize': 2, 'granule_bytes': 4},   # 4-byte beat
                   {**good, 'rid': None},                      # no response ID
                   {**good, 'arid': 99},                       # outside 4 bits
                   {**good, 'note': 'extra'},                   # not a declaration
                   {'arid': 0}):                                # incomplete
        with pytest.raises(ValueError):
            _instruction_id_fields(broken)


def test_the_unified_commit_switch_is_off_unless_the_row_declares_it():
    session = GeneratedCva6AxiMmioSession.__init__
    defaults = {name: parameter.default
                for name, parameter in
                __import__('inspect').signature(session).parameters.items()}
    assert defaults['memory_commit_receipts'] is False
    assert defaults['memory_readback_receipts'] is False
    assert 'physical_tick_samples' not in defaults
    assert isinstance(GeneratedCva6AxiMmioSession.memory_flows_enabled, property)
    split = MmioCpuAdapter('obi', object, {}, {})
    unified = MmioCpuAdapter('axi4-lite', object, {}, {}, 4, 'unified')
    declared = MmioCpuAdapter('axi4', object, {}, {}, 8, 'unified',
                              memory_receipts_on_unified=True)
    assert unified.memory_receipts_on_unified is False
    assert memory_feedback_options(split, memory_flows=True) == {
        'memory_commit_receipts': True, 'memory_readback_receipts': True,
        'physical_tick_samples': True}
    assert memory_feedback_options(unified, memory_flows=True) == {}
    assert memory_feedback_options(declared, memory_flows=True) == {
        'memory_commit_receipts': True, 'memory_readback_receipts': True}
    for adapter in (split, unified, declared):
        assert memory_feedback_options(adapter, memory_flows=False) == {}
