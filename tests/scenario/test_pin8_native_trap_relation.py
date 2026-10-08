"""Native CPU receipts narrow the IRQ/trap relation without asserting source lineage."""

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

import pytest

from myfuzz.scenario.pin8_trap_retirement_certificates import Pin8TrapRetirementCertificates


TRACE = (Path(__file__).resolve().parents[2] / 'runs' /
         'current-dataflow-p2-native-gated-20261007-online' /
         'online_final_trace.json')


@lru_cache(maxsize=1)
def events():
    return json.loads(TRACE.read_text())['events']


def proof_ids(items):
    return [p['retirement_event_id'] for p in
            Pin8TrapRetirementCertificates(require_native_receipts=True).ingest(items)]


def damaged(event_id, change):
    items = list(events())
    row = deepcopy(items[event_id - 1])
    change(row)
    items[event_id - 1] = row
    return items


def test_real_native_trace_has_four_bounded_relations_and_no_retirement_token():
    proofs = Pin8TrapRetirementCertificates(require_native_receipts=True).ingest(events())
    assert proof_ids(events()) == [4911, 12192, 17222, 22204]
    assert all(p['proof_scope'] == 'native_receipt_bounded_architectural_trap_relation'
               and p['explicit_source_token_on_retirement'] is False for p in proofs)
    assert all(p['native_take_event_id'] < p['cpu_irq_taken_event_id']
               < p['retirement_event_id'] for p in proofs)


@pytest.mark.parametrize('event_id,change', [
    (4699, lambda e: e.update(sample_event_id=1)),
    (4699, lambda e: e.update(receipt_id={'execution': 'forged', 'sequence': 122})),
    (4699, lambda e: e.update(actual_pre_input=0)),
    (4699, lambda e: e['notification_post'].update(rvfi_valid=1)),
    (4698, lambda e: e.update(actual_pre_input=0)),
    (4698, lambda e: e['notification_post'].update(rvfi_valid=1)),
    (4698, lambda e: e.update(source_epoch=1)),
    (4698, lambda e: e.update(execution_id='forged')),
    (4699, lambda e: e.update(reset_epoch=1)),
    (4699, lambda e: e.update(execution_id='forged')),
    (4911, lambda e: e.update(receipt_id={'execution': 'forged', 'sequence': 127})),
    (4911, lambda e: e.update(execution_id='forged')),
    (4911, lambda e: e.update(source_epoch=1)),
    (4910, lambda e: e.update(command_scope={'component': 'cpu', 'reset_epoch': 0,
                                             'command_sequence': 126})),
    (4701, lambda e: e.update(cpu_step_event_id=1)),
])
def test_corrupted_native_receipt_or_join_rejects_first_relation(event_id, change):
    assert 4911 not in proof_ids(damaged(event_id, change))


def test_missing_intermediate_cpu_sample_rejects_first_relation():
    sample = next(e for e in events()[4701:4911]
                  if e.get('kind') == 'cpu_external_irq_sample')
    assert 4911 not in proof_ids(damaged(sample['event_id'],
                                    lambda e: e.update(kind='removed_sample')))


def test_second_pre_edge_take_during_interval_rejects_first_relation():
    sample = next(e for e in events()[4701:4911]
                  if e.get('kind') == 'cpu_external_irq_sample')
    assert 4911 not in proof_ids(damaged(sample['event_id'],
                                    lambda e: e.update(irq_taken_pre=1)))


def test_noninteger_post_retirement_notification_rejects_first_relation():
    assert 4911 not in proof_ids(damaged(4698,
                                    lambda e: e['notification_post'].update(rvfi_valid=False)))


def test_changed_intermediate_outer_identity_rejects_first_relation():
    sample = next(e for e in events()[4701:4911]
                  if e.get('kind') == 'cpu_external_irq_sample')
    assert 4911 not in proof_ids(damaged(sample['event_id'],
                                    lambda e: e.update(execution_id='forged')))


def test_intermediate_native_post_notification_must_match_cpu_step():
    sample = next(e for e in events()[4701:4911]
                  if e.get('kind') == 'cpu_external_irq_sample'
                  and e['notification_post']['rvfi_valid'] == 0)
    for field, value in (('rvfi_intr', 1), ('rvfi_ext_irq_valid', 0)):
        assert 4911 not in proof_ids(damaged(sample['event_id'],
                                        lambda e: e['notification_post'].update({field: value})))


def test_intermediate_native_notification_contract_and_types_fail_closed():
    sample = next(e for e in events()[4701:4911]
                  if e.get('kind') == 'cpu_external_irq_sample'
                  and e['notification_post']['rvfi_valid'] == 0)
    for change in (
            lambda e: e['notification_post'].update(rvfi_intr=True),
            lambda e: e['notification_post'].pop('rvfi_ext_pre_mip'),
            lambda e: e['observation_contract'].update(schema_version='forged')):
        assert 4911 not in proof_ids(damaged(sample['event_id'], change))


def test_malformed_native_reference_fails_closed_without_crash():
    assert 4911 not in proof_ids(damaged(4699,
                                    lambda e: e.update(sample_event_id=[])))


def test_old_trace_without_native_receipts_does_not_gain_strict_relation():
    old = (Path(__file__).resolve().parents[2] / 'runs' /
           'current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online' /
           'online_final_trace.json')
    assert proof_ids(json.loads(old.read_text())['events']) == []
