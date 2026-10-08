"""Restricted UART low byte to an actual modeled host RAM STORE cell."""
from copy import deepcopy
from dataclasses import asdict

from tests.scenario.test_uart_operand_use import scenario
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.uart_ram_commit_join import UartRamCommitJoin


def fixture(*, wrong_value=False, delayed=False):
    stream, store = scenario(delayed=delayed)
    key_doc = next(event['transaction'] for event in stream.events
                   if event.get('kind') == 'data_accept' and event['transaction']['source_sequence'] == 2)
    key = TransactionKey(**key_doc)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=9, max_initialized_bytes=4096)
    service = MemoryService(memory, TransactionLedger(), commit_stream_capacity=4)
    service.read(TransactionKey(**dict(key_doc, source_sequence=1)),
                 0x20000, width_bytes=4)
    receipt = service.write(key, 0x20000, 1 if wrong_value else 0,
                            width_bytes=4, byte_enable=15)
    join = UartRamCommitJoin(admission_registry=stream.registry, ownership=stream.owner,
                             edge_index=stream.index, services={'cpu': service})
    return stream, store, service, receipt, join


def test_installed_commit_and_retired_uart_operand_certify_only_low_byte_writer():
    stream, store, service, receipt, join = fixture()
    assert join.stage_commit('cpu', service, service.ledger, receipt.transaction_id, receipt)
    reports = [report for event in stream.events for report in join.consume(deepcopy(event))]
    accepted = [report for report in reports if report.get('status') == 'accepted']
    assert len(accepted) == 1
    report = accepted[0]
    assert report['proof_scope'] == 'uart_seed_operand_host_ram_byte_writer'
    assert report['operand_retirement_event_id'] == store['event_id']
    assert report['fullkey'] == asdict(receipt.transaction_id)
    assert report['memory_id'] == 'ram' and report['byte_offset'] == 0
    assert report['byte_version'] == list(receipt.version) and report['byte_value'] == 0
    assert report['influenced_bits'] == [0, 8]
    assert report['upper_bits_origin'] == report['rtl_ram_origin'] == 'unknown'


def test_equal_shaped_wrong_commit_value_does_not_certify():
    stream, _, service, receipt, join = fixture(wrong_value=True)
    assert join.stage_commit('cpu', service, service.ledger, receipt.transaction_id, receipt)
    reports = [report for event in stream.events for report in join.consume(deepcopy(event))]
    assert not [report for report in reports if report.get('status') == 'accepted']


def test_delayed_seed_links_the_same_historical_retirement_and_commit():
    stream, store, service, receipt, join = fixture(delayed=True)
    assert join.stage_commit('cpu', service, service.ledger, receipt.transaction_id, receipt)
    reports = [report for event in stream.events for report in join.consume(deepcopy(event))]
    accepted = [report for report in reports if report.get('status') == 'accepted']
    assert len(accepted) == 1
    assert accepted[0]['operand_retirement_event_id'] == store['event_id']


def test_detached_receipt_or_forged_use_label_cannot_certify():
    stream, _, service, receipt, join = fixture()
    assert not join.consume(dict(kind='uart_operand_use', status='accepted',
                                  operand_retirement_event_id='store-retire'))
    assert not join.consume(dict(kind='cpu_retirement_match', status='accepted',
                                  transaction_keys=[asdict(receipt.transaction_id)]))
    assert not join.consume(dict(kind='memory_commit_authority', status='accepted',
                                  commit_document=receipt.commit_document()))
    service.ack_commit_events((receipt.commit_document()['commit_id'],))
    assert not join.stage_commit('cpu', service, service.ledger, receipt.transaction_id, receipt)
    reports = [report for event in stream.events for report in join.consume(deepcopy(event))]
    assert not [report for report in reports if report.get('status') == 'accepted']
