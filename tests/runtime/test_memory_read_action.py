"""Bounded RAM-read grammar and actual opt-in callback receipts, no native run."""
from types import SimpleNamespace

import pytest

from myfuzz.runtime.flows.memory import (
    RAM_READ_TOKEN, MemoryFlowContext, MemoryFlowKernel,
    lower_memory_code, install_memory_feedback,
)


def test_reserved_token_is_admitted_but_arbitrary_loads_stay_rejected():
    assert RAM_READ_TOKEN.hex() == '03200000'
    context = MemoryFlowContext('a' * 64, 'path', 'F1', 'image')
    row = dict(testcase_id='read', path_id='path', source_id='image',
               raw_records_hex=[RAM_READ_TOKEN.hex()])
    assert MemoryFlowKernel().lower(context, row).raw_records == (RAM_READ_TOKEN,)
    with pytest.raises(ValueError):
        MemoryFlowKernel().lower(context, dict(row, raw_records_hex=['83200000']))


def test_read_token_lowers_to_actual_dut_load_at_declared_scratch():
    from myfuzz.scenario.rv32i_sources import fragment_bytes, mmio_access_fragment, MmioWindow
    binding = SimpleNamespace(base=0x10000, size=0x10000, readable=True, writable=True)
    runtime = SimpleNamespace(result=0x1fffc, memory_bindings={'F1': binding, 'F3': binding})
    code, operation, address = lower_memory_code(runtime, RAM_READ_TOKEN, flow='F1')
    assert operation == 'ram_read_word' and address == 0x1fff8
    assert code == fragment_bytes(mmio_access_fragment('LW', address,
        windows=(MmioWindow(binding.base, binding.size),), base_register=1, data_register=2))
    assert code != RAM_READ_TOKEN  # This is a typed token, not a raw LW program.
    assert lower_memory_code(runtime, bytes.fromhex('13000000'), flow='F1') == (
        bytes.fromhex('13000000'), 'instruction', None)


@pytest.mark.parametrize('change', ['unreadable', 'short_range', 'misaligned'])
def test_read_token_cannot_escape_declared_ram(change):
    binding = SimpleNamespace(base=0x10000, size=0x10000, readable=True, writable=True)
    runtime = SimpleNamespace(result=0x1fffc, memory_bindings={'F1': binding})
    if change == 'unreadable': binding.readable = False
    if change == 'short_range': binding.size = 4
    if change == 'misaligned': runtime.result += 1
    with pytest.raises(ValueError): lower_memory_code(runtime, RAM_READ_TOKEN, flow='F1')


def test_installation_uses_same_actual_cpu_service_and_emits_exact_byte_relations():
    from tests.scenario.test_memory_dependency_runner import wired
    runner, cpu = wired()
    install_memory_feedback(runner, cpu_id='cpu', runtime_contract_sha256='a' * 64)
    cpu._serve('data', 1, 0x20000, 0x12345678, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 0
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    report = runner.memory_dependency_evidence_report()
    assert report['journal_integrity'] is True
    assert report['counts']['verified'] == 4
    assert {row['value'] for row in report['certificates']} == {0x12, 0x34, 0x56, 0x78}
    assert all(row['memory_kind'] == 'modeled_host_persistent_memory'
               and row['source_origin'] == 'unknown' for row in report['certificates'])


def _read_fixture():
    from tests.runtime.test_f1_f3_shared_execution import _f3_observation_fixture
    args = _f3_observation_fixture()
    accept, write, response = args['events']
    accept['outputs']['driver_samples'][0]['pre']['protocol_taps']['we'] = 0
    response['outputs']['driver_samples'][0]['pre']['protocol_taps']['rdata'] = args['value']
    transaction = write['transaction']
    args['events'][1] = dict(event_id=2, kind='memory_read_issuance', component='cpu',
        producer_event_id=1, fullkey=transaction, address=args['address'], width_bytes=4,
        memory_id='ram', generation=0, byte_offset=128, value=args['value'],
        versions=[[0, 1]] * 4, writer_event_ids=['writer'] * 4)
    args['report'] = dict(journal_integrity=True, certificates=[dict(
        evidence_id=str(i), component='cpu', memory_id='ram', generation=0,
        proof_scope='memory_byte_version', validity='historical',
        byte_offset=128+i, byte_version=[0, 1], writer_event_id='writer',
        write_event_id=1, read_event_id=2, read_transaction=transaction,
        value=(args['value'] >> (8*i)) & 255) for i in range(4)])
    args.pop('value')
    args.pop('transaction_scope')
    return args


def test_read_observation_requires_native_response_and_exact_four_byte_versions():
    from myfuzz.runtime.flows.memory import observe_ram_read_documentary
    result = observe_ram_read_documentary(**_read_fixture())
    assert result['status'] == 'observed'
    assert result['response_event'] == 3
    assert len(result['byte_relations']) == 4
    assert result['retirement'] == 'unknown'
    assert result['reward_eligible'] is False


@pytest.mark.parametrize('change', ['response', 'version', 'missing_byte', 'read_transaction', 'integrity'])
def test_read_observation_stays_unknown_without_exact_join(change):
    from myfuzz.runtime.flows.memory import observe_ram_read_documentary
    args = _read_fixture()
    if change == 'response': args['events'].pop()
    if change == 'version': args['report']['certificates'][0]['byte_version'] = [0, 2]
    if change == 'missing_byte': args['report']['certificates'].pop()
    if change == 'read_transaction': args['report']['certificates'][0]['read_transaction'] = {}
    if change == 'integrity': args['report']['journal_integrity'] = False
    assert observe_ram_read_documentary(**args) is None
