"""Restricted live issued host RAM low byte readback, never detached labels."""
from copy import deepcopy
from dataclasses import asdict

from tests.scenario.test_uart_store_memory import setup
from tests.scenario.test_uart_operand_seed import overwrite
from tests.scenario.test_cpu_retirement import fetch
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
from myfuzz.scenario.uart_memory_readback import UartMemoryReadbackJoin


LW = 0x0002a383  # lw x7, 0(x5)


def scenario_readback():
    stream, store, service, write_authority, write_token, commit, _ = setup()
    service.include_writer_kinds = True
    read_authority = MemoryReadAuthority(services={'cpu': service})
    write_key = TransactionKey(**commit['transaction'])
    read_key = TransactionKey(**dict(commit['transaction'], source_sequence=3))
    snapshot = read_authority.read('cpu', service, read_key, 0x20000, width_bytes=4)
    read_token, read_issued = read_authority.drain()[0]
    read_event = dict(read_issued, kind='memory_read_issuance',
                      status='accepted', event_id='read-issued')
    raw = overwrite(store)
    raw.update(event_id='read-retire', order=2, insn=LW,
               pc_rdata=0x108, pc_wdata=0x10c,
               rs1_addr=5, rs1_rdata=0x20000, rs2_addr=0, rs2_rdata=0,
               rd_addr=7, rd_wdata=snapshot.value, mem_addr=0x20000,
               mem_rmask=15, mem_wmask=0, mem_rdata=snapshot.value,
               mem_wdata=0, mode=3)
    raw['provenance'] = {'observed_case': {'case_id': 'later-logical-case',
                                           'case_index': 2}}
    raw['observation']['physical'] = {
        'rvfi_' + name: raw[name] for name in store['observation']['physical']
        for name in [name[5:]]}
    instruction = fetch(LW, seq=3, pc=0x108)
    instruction.update(event_id='read-fetch')
    instruction['transaction'].update(execution_id=read_key.execution_id,
        testcase_id=read_key.testcase_id, source_component='cpu', source_epoch=0)
    instruction['snapshot'].update(writer_kinds=['INITIAL_IMAGE'] * 4,
                                   writer_event_ids=['initial-image'] * 4)
    accept = dict(kind='data_accept', event_id='read-accept', transaction=asdict(read_key),
                  raw_address=0x20000, aligned_address=0x20000, address=0x20000,
                  write=0, be=15, wdata=0)
    response = dict(accept, kind='data_response', event_id='read-response',
                    rdata=snapshot.value, error=0,
                    snapshot={**asdict(snapshot), 'data_hex': snapshot.data.hex(),
                              'value': snapshot.value})
    response['snapshot'].pop('data')
    join = UartMemoryReadbackJoin(memory_commit_authority=write_authority,
        memory_read_authority=read_authority, admission_registry=stream.registry,
        ownership=stream.owner, edge_index=stream.index)
    events = [commit, *stream.events, read_event, instruction, accept, response, raw]
    return join, events, write_token, read_token, write_key, read_key, snapshot


def play(join, events, write_token, read_token):
    out = []
    for event in events:
        token = write_token if event.get('kind') == 'memory_write_commit' else None
        read = read_token if event.get('kind') == 'memory_read_issuance' else None
        out.extend(join.consume(deepcopy(event), commit_token=token, read_token=read))
    return out


def test_later_retired_load_reads_exact_prior_uart_writer_low_byte():
    join, events, write_token, read_token, write_key, read_key, snapshot = scenario_readback()
    out = play(join, events, write_token, read_token)
    proofs = [p for p in out if p.get('status') == 'accepted'
              and p.get('kind') == 'uart_memory_readback']
    assert len(proofs) == 1
    proof = proofs[0]
    assert proof['store_fullkey'] == asdict(write_key)
    assert proof['load_fullkey'] == asdict(read_key)
    assert proof['store_byte_version'] == [0, 1]
    assert proof['load_retirement_event_id'] == 'read-retire'
    assert proof['loaded_register'] == 7 and proof['byte_value'] == 0
    assert proof['influenced_bits'] == [0, 8]
    assert proof['upper_bits_origin'] == proof['rtl_ram_origin'] == 'unknown'
    assert proof['source_case_id'] == 'source-case-A'
    assert proof['load_observed_case'] == {'case_id': 'later-logical-case', 'case_index': 2}


def test_detached_saved_read_issuance_without_live_token_never_authorizes():
    join, events, write_token, _, *_ = scenario_readback()
    out = play(join, events, write_token, None)
    assert not [p for p in out if p.get('kind') == 'uart_memory_readback'
                and p.get('status') == 'accepted']


def test_changed_read_writer_version_or_byte_blocks_origin():
    join, events, write_token, read_token, *_ = scenario_readback()
    response = next(e for e in events if e.get('kind') == 'data_response'
                    and e.get('event_id') == 'read-response')
    response['snapshot']['versions'] = [[0, 99], *response['snapshot']['versions'][1:]]
    out = play(join, events, write_token, read_token)
    assert not [p for p in out if p.get('kind') == 'uart_memory_readback'
                and p.get('status') == 'accepted']


def test_unrelated_or_overwritten_writer_is_unknown_without_global_barrier():
    join, events, write_token, read_token, *_ = scenario_readback()
    before = events[:-4]
    play(join, before, write_token, read_token)
    assert len(join._writers) == 1
    join._writers.clear()  # Model a later exact writer-version invalidation.
    out = play(join, events[-4:], None, None)
    assert not [p for p in out if p.get('kind') == 'uart_memory_readback'
                and p.get('status') == 'accepted']
    assert not join.degraded


def test_degraded_readback_join_retires_live_read_token_once_without_certifying():
    join, events, _, read_token, *_ = scenario_readback()
    join._store._retire.max_pending = 1
    first = fetch(seq=1)
    first['event_id'] = 'first-distinct-fetch'
    second = fetch(seq=2, writer='different-version')
    second['event_id'] = 'second-distinct-fetch'
    join.consume(first)
    join.consume(second)
    assert join.degraded
    read_event = next(event for event in events
                      if event.get('kind') == 'memory_read_issuance')
    assert join.consume(deepcopy(read_event), read_token=read_token) == ()
    assert join._read_authority.pending_count == 0
    assert join.consume(deepcopy(read_event), read_token=read_token) == ()
    assert join.degraded
