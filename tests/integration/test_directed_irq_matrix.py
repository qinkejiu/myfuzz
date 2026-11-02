"""Directed IRQ matrix gates: reset, exception and multi-source attribution.

Every check here is a software/pure-reducer gate.  The documents are real:

* the CPU IRQ contracts are the pinned ``ibex``/``cv32e20``/``cv32e40p``
  receipt contracts and the production serial/notification helpers;
* the multi-source group is reconstructed from the saved declared-IRQ journal
  under ``research/input-strategy-audit-20261027/runs/declared-irq-20261029``
  and must reproduce its recorded ``group_sha256``;
* the two-member declaration comes from
  ``configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared``.

Nothing here starts RTL or a native process.  The native half of the matrix is
``scripts/run_directed_irq_native.py`` run by the lead in the frozen window;
these tests never stand in for it.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import importlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
DECLARED = ROOT / 'research/input-strategy-audit-20261027/runs/declared-irq-20261029'
SHARED_SCENARIO = ROOT / 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared'
REAL_GROUP_RUN = 'spi-cv32e20-v1'

RESET_KINDS = ('reset_barrier', 'cpu_reset', 'gpio_reset_resource')
_REFERENCE_FIELDS = ('producer_event_id', 'cpu_step_event_id', 'native_sample_event_id',
                     'native_take_event_id', 'group_delivery_event_id', 'sample_event_id')


# --------------------------------------------------------------------------- #
# Real saved-journal helpers
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=4)
def _saved_journal(run):
    events_path = DECLARED / run / 'original/events.json'
    config_path = DECLARED / run / 'config.json'
    if not events_path.is_file() or not config_path.is_file():
        pytest.skip('saved declared-IRQ journal unavailable: ' + str(events_path))
    events = json.loads(events_path.read_text(encoding='utf-8'))
    config = json.loads(config_path.read_text(encoding='utf-8'))
    return tuple(events), config


def _index(events):
    return {event['event_id']: event for event in events}


def _one(events, *, kind, **fields):
    rows = [event for event in events if event.get('kind') == kind
            and all(event.get(name) == value for name, value in fields.items())]
    if len(rows) != 1:
        pytest.skip('saved journal lacks one %s event' % kind)
    return rows[0]


def _remap(row, mapping):
    for name in _REFERENCE_FIELDS:
        value = row.get(name)
        if type(value) is int and value in mapping:
            row[name] = mapping[value]
    for member in row.get('members') or ():
        for name in ('native_source', 'latest_native_source'):
            reference = member.get(name)
            if (isinstance(reference, dict) and type(reference.get('event_id')) is int
                    and reference['event_id'] in mapping):
                reference['event_id'] = mapping[reference['event_id']]


def _contiguous(entries):
    """Renumber in list order; ``None`` marks a synthesized (key-less) event.

    ``entries`` is a list of ``(original_event_id_or_None, event)`` pairs.  A
    real event keeps its identity only through this mapping, so every join is
    recomputed from the produced fields instead of from original numbering.
    """
    mapping = {}
    for position, (original, _) in enumerate(entries, 1):
        if type(original) is int and original not in mapping:
            mapping[original] = position
    journal = []
    for position, (_, event) in enumerate(entries, 1):
        row = deepcopy(event)
        row['event_id'] = position
        _remap(row, mapping)
        journal.append(row)
    return journal, {row['event_id']: row for row in journal}


def _group_from_frame(frame, config):
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    members = tuple(
        IrqDeliveryMember(*member['source_id'].split('.', 1), mode=member.get('mode', 'pulse'),
                          pulse_width_ticks=config['pulse_width_ticks'],
                          source_bit_offset=config.get('source_bit_offset', 0),
                          source_adapter=config.get('source_adapter'))
        for member in frame['members'])
    return IrqDeliveryGroup(frame['group_id'], frame['target_component'],
                            frame['target_port'], members)


@lru_cache(maxsize=2)
def _group_window(run=REAL_GROUP_RUN):
    """The real two-member OR frame window: (rows, group, config)."""
    events, config = _saved_journal(run)
    by_id = _index(events)
    take = _one(events, kind='cpu_external_irq_taken')
    frame = _one(events, kind='irq_group_delivery', native_take_event_id=take['event_id'])
    sample = by_id[frame['native_sample_event_id']]
    group = _group_from_frame(frame, config)
    if group.identity_sha256 != frame['group_sha256']:
        pytest.skip('saved IRQ group declaration cannot be reconstructed')
    wanted = {frame['event_id'], take['event_id'], sample['event_id'],
              frame['cpu_step_event_id'], sample['producer_event_id']}
    for member in frame['members']:
        for name in ('native_source', 'latest_native_source'):
            wanted.add(member[name]['event_id'])
    members = {(member['source_id'].split('.', 1)[0],
                member['source_id'].split('.', 1)[1]) for member in frame['members']}
    for event in events:
        source = event.get('source')
        if event.get('kind') in ('pulse_start', 'source_start', 'source_end') and (
                isinstance(source, (list, tuple)) and tuple(source) in members):
            wanted.add(event['event_id'])
        if (event.get('kind') == 'irq_group_acceptance'
                and event.get('native_take_event_id') == take['event_id']):
            wanted.add(event['event_id'])
    rows = [(event_id, by_id[event_id]) for event_id in sorted(wanted)]
    return tuple(rows), group, config


def _render(rows):
    return _contiguous(rows)


def _join_group_frame(group, journal):
    """Re-derive the delivery join for the journal's single frame."""
    from myfuzz.integration.saved_irq_group import frame_for_sample
    frames = [event for event in journal if event.get('kind') == 'irq_group_delivery']
    assert len(frames) == 1, 'expected exactly one delivery frame'
    sample = _index(journal)[frames[0]['native_sample_event_id']]
    return frame_for_sample(group, sample, journal, _index(journal))


def _join_take_sample(group, journal):
    """Attempt a join when the journal has no delivery frame at all."""
    from myfuzz.integration.saved_irq_group import frame_for_sample
    sample = next(event for event in journal
                  if event.get('kind') == 'cpu_external_irq_sample'
                  and event.get('irq_taken_pre') == 1)
    return frame_for_sample(group, sample, journal, _index(journal))


# --------------------------------------------------------------------------- #
# Real CPU contracts
# --------------------------------------------------------------------------- #

_CONTRACTS = {
    'ibex_rvfi_local': ('myfuzz.local_harness.ibex_irq_receipt_contract',
                        'ibex_irq_receipt_contract', 'ibex_pkg::ExcCauseIrqExternalM'),
    'cv32e20': ('myfuzz.local_harness.cv32e20_irq_receipt_contract',
                'cv32e20_irq_receipt_contract', 'cve2_pkg::EXC_CAUSE_IRQ_EXTERNAL_M'),
    'cv32e40p_rvfi_local': ('myfuzz.local_harness.cv32e40p_irq_receipt_contract',
                            'cv32e40p_irq_receipt_contract', None),
}


def _contract(profile_id):
    module, name, cause = _CONTRACTS[profile_id]
    try:
        imported = importlib.import_module(module)
    except ImportError:
        pytest.skip('concurrent CPU IRQ receipt contract not importable: ' + module)
    return getattr(imported, name)(), cause


def _strip_parens(term):
    text = term.strip()
    while text.startswith('(') and text.endswith(')'):
        depth = 0
        balanced = True
        for position, char in enumerate(text):
            depth += char == '('
            depth -= char == ')'
            if depth == 0 and position != len(text) - 1:
                balanced = False
                break
            if depth < 0:
                balanced = False
                break
        if not balanced:
            break
        text = text[1:-1].strip()
    return text


def _conjuncts(expression):
    return [_strip_parens(term) for term in expression.split('&')]


def _atoms(expression, signal):
    pattern = re.compile(r'\b' + re.escape(signal) + r'\s*(?P<op>==|!=)\s*(?P<value>.+)$')
    rows = []
    for term in _conjuncts(expression):
        match = pattern.search(term)
        if match is not None:
            rows.append((match.group('op'), match.group('value').strip(), term))
    return rows


def test_external_cause_selection_requires_the_external_cause_value():
    """The acceptance probe is the only lineage source and it conjoins the cause."""
    for profile_id in ('ibex_rvfi_local', 'cv32e20', 'cv32e40p_rvfi_local'):
        contract, expected_cause = _contract(profile_id)
        expression = contract['decision_probes']['irq_taken_pre']
        terms = _conjuncts(expression)
        assert any('pc_set_o' in term for term in terms), profile_id
        assert any('csr_save_cause' in term for term in terms), profile_id
        causes = _atoms(expression, 'exc_cause_o')
        muxes = _atoms(expression, 'exc_pc_mux_o')
        assert len(causes) == 1 and len(muxes) == 1, profile_id
        operator, cause_value, _ = causes[0]
        assert operator == '==', profile_id
        # One equality against exactly one literal: a different cause cannot select.
        assert not re.search(r'[|?,]|\binside\b|\bor\b', cause_value), profile_id
        assert muxes[0][0] == '==' and muxes[0][1].endswith('EXC_PC_IRQ'), profile_id
        if profile_id == 'cv32e40p_rvfi_local':
            assert cause_value == "5'd%d" % contract['input_bit_offset']
            assert contract['input_bit_offset'] == 11
        else:
            assert cause_value == expected_cause, profile_id


def test_non_irq_exception_redirect_is_mutually_exclusive_with_acceptance():
    """CV32E40P proves redirect exclusion explicitly; the others by cause value."""
    contract, _ = _contract('cv32e40p_rvfi_local')
    probes = {**contract['decision_probes'], **contract['decision_probes_all']}
    for name in ('irq_redirect_pre', 'irq_taken_pre', 'irq_ack_pre', 'irq_id_pre',
                 'irq_entry_pc'):
        assert name in probes, name
    redirect = _conjuncts(probes['irq_redirect_pre'])
    muxes = _atoms(probes['irq_redirect_pre'], 'exc_pc_mux_o')
    assert muxes and all(operator == '!=' for operator, _, _ in muxes)
    redirected = {value for _, value, _ in muxes}
    assert any(value.endswith('EXC_PC_IRQ') for value in redirected)
    # Debug entry is excluded from the redirect probe as well.
    assert any(value.endswith('EXC_PC_DBD') for value in redirected)
    assert any(value.endswith('EXC_PC_DBE') for value in redirected)
    acceptance_mux = _atoms(probes['irq_taken_pre'], 'exc_pc_mux_o')
    assert acceptance_mux and acceptance_mux[0][1].endswith('EXC_PC_IRQ')
    # A redirect needs pc_set too, but it never names the IRQ vector and it
    # deliberately leaves csr_save_cause out (it is asserted one cycle later).
    assert any('pc_set_o' in term for term in redirect)
    assert not any('csr_save_cause' in term for term in redirect)
    assert not any(mux[1].endswith('EXC_PC_IRQ') for mux in muxes if mux[0] == '==')
    assert contract['retirement_authority'] == 'pc_insn_order_only'
    assert 'intr' in contract['unobserved_retirement_fields']
    assert contract['decision_acceptance']['source_id'] == 11
    assert contract['decision_probe_widths']['irq_id_pre'] == 5


def test_debug_or_nmi_diversion_refuses_retirement_lineage():
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_retirement_diversion_fields, native_irq_retirement_diverted)
    ibex, _ = _contract('ibex_rvfi_local')
    cve2, _ = _contract('cv32e20')
    for contract in (ibex, cve2):
        fields = native_irq_retirement_diversion_fields(contract)
        assert fields
        quiet = {name: 0 for name in fields}
        assert native_irq_retirement_diverted(contract, quiet) is False
        for name in fields:
            diverted = dict(quiet)
            diverted[name] = 1
            assert native_irq_retirement_diverted(contract, diverted) is True, name
        # A missing observation is not a quiet retirement.
        assert native_irq_retirement_diverted(contract, {}) is True
    masked = cve2['decision_probes']['irq_masked_pre']
    assert 'debug_mode_q' in masked and 'nmi_mode_q' in masked
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_sideband
    sideband = cv32e20_irq_sideband()
    assert '.debug_mode ||' in sideband and '.nmi_mode' in sideband
    assert 'irq_pending_q <= \'0; irq_intr_q <= \'0; irq_stage_q <= \'0;' in sideband
    e40, _ = _contract('cv32e40p_rvfi_local')
    assert 'debug_mode_q' in e40['decision_probes']['irq_masked_pre']
    assert e40['retirement_diversion_scope'] == 'unobservable'
    assert e40['retirement_diversion_fields'] == []


def test_notification_is_not_source_authority_in_every_contract():
    ibex, _ = _contract('ibex_rvfi_local')
    cve2, _ = _contract('cv32e20')
    e40, _ = _contract('cv32e40p_rvfi_local')
    assert ibex['notification_semantics'] == 'actual_post_extension_even_without_retirement'
    assert ibex['context_semantics'] == 'planned_binding_refs_never_source_authority'
    assert 'not_source_authority' in cve2['notification_semantics']
    assert cve2['context_semantics'] == 'planned_binding_refs_never_source_authority'
    assert 'rvfi_intr_is_not_driven' in e40['notification_semantics']
    assert e40['retirement_fields'] == ['valid', 'order', 'insn', 'pc_rdata']
    assert ibex['generic_irq_entry_origin'] == 'unknown'
    assert cve2['generic_irq_entry_origin'] == 'unknown'


def test_real_take_document_needs_the_external_cause_flag():
    """A redirect/debug decision document cannot be admitted as a take."""
    from myfuzz.scenario.gpio_irq_dependency_evidence import GpioNativeIrqEvidenceConsumer
    events, _ = _saved_journal('spi-ibex-v1')
    take = _one(events, kind='cpu_external_irq_taken')
    by_id = _index(events)
    sample = by_id[take['sample_event_id']]
    step = by_id[sample['producer_event_id']]

    def consumer():
        return GpioNativeIrqEvidenceConsumer(
            source_component='spi_active', target_component='cpu', pin=8,
            source_port='events_o', target_port='irq', runtime_contract_sha256='a' * 64)

    def feed(events_to_feed, consumer_):
        journal, _ = _contiguous([(event['event_id'], event)
                                  for event in events_to_feed])
        for event in journal:
            consumer_.consume(event)
        return journal

    admitted = consumer()
    feed([step, sample, take], admitted)
    assert list(admitted._native) == [1]
    assert 'take' in admitted._native[1]
    refused = consumer()
    redirected = deepcopy(take)
    redirected['irq_taken_pre'] = 0
    feed([step, sample, redirected], refused)
    assert 'take' not in refused._native[1]
    assert refused.report()['counts']['irq_acceptance'] == 0


def test_non_external_retirement_never_mints_serial_lineage():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    events, _ = _saved_journal('spi-ibex-v1')
    take = _one(events, kind='cpu_external_irq_taken')
    retirements = [event for event in events if event.get('kind') == 'cpu_retire']
    interrupt_retirements = [event for event in retirements if event.get('intr') == 1]
    assert len(interrupt_retirements) == 1
    serial = interrupt_retirements[0]['irq_serial_observation']['retirement']
    assert serial['status'] == 'observed' and serial['value'] > 0
    for event in retirements:
        if event is interrupt_retirements[0]:
            continue
        assert event['irq_serial_observation']['retirement']['value'] == 0
    certificates = IrqSerialCertificates().ingest(events)
    assert len(certificates) == 1
    # A synchronous trap retirement (intr=0, trap=1) with the same token refuses.
    trap = deepcopy(interrupt_retirements[0])
    trap['intr'] = 0
    trap['trap'] = 1
    journal, _ = _contiguous([(take['event_id'], deepcopy(take)),
                              (interrupt_retirements[0]['event_id'], trap)])
    assert IrqSerialCertificates().ingest(journal) == ()
    consumer = IrqSerialCertificates()
    consumer.ingest(journal)
    assert 'retirement_not_interrupt' in [record['reason']
                                          for record in consumer.rejections()]


# --------------------------------------------------------------------------- #
# (a) reset: measured barrier invalidates lineage, installed state and epoch
# --------------------------------------------------------------------------- #

def _reset_document(kind, *, epoch, local_tick=4):
    if kind == 'reset_barrier':
        return dict(kind=kind, policy='cold_all', memory_generations={'ram': 0},
                    cancelled_responses={}, cancelled_target_requests={},
                    pending_responses_before_reset={}, pending_events_before_reset={},
                    pending_events_after_reset={}, cancelled_dataflow_targets=[],
                    cancelled_irq_pulses={})
    component = 'cpu' if kind == 'cpu_reset' else 'peripheral'
    return dict(kind=kind, component=component, reset_epoch=epoch, source_epoch=epoch,
                local_tick=local_tick)


def _real_serial_pair():
    events, _ = _saved_journal('spi-ibex-v1')
    take = _one(events, kind='cpu_external_irq_taken')
    retirement = _one(events, kind='cpu_retire', intr=1)
    return deepcopy(take), deepcopy(retirement)


@pytest.mark.parametrize('kind', RESET_KINDS)
def test_measured_reset_barrier_invalidates_real_pending_serial_lineage(kind):
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    take, retirement = _real_serial_pair()
    baseline, _ = _contiguous([(take['event_id'], take),
                               (retirement['event_id'], retirement)])
    assert len(IrqSerialCertificates().ingest(baseline)) == 1
    reset = _reset_document(kind, epoch=1)
    broken, _ = _contiguous([(take['event_id'], take), (None, reset),
                             (retirement['event_id'], retirement)])
    consumer = IrqSerialCertificates()
    assert consumer.ingest(broken) == ()
    assert consumer.pending_count == 0
    reasons = [record['reason'] for record in consumer.rejections()]
    assert 'unmatched_retirement_serial' in reasons
    # The same retirement after the barrier stays refused: no later event restores it.
    assert consumer.ingest([{**broken[-1], 'event_id': len(broken) + 1,
                             'producer_event_id': 4242}]) == ()
    assert consumer.pending_count == 0


def test_post_reset_lineage_requires_a_fresh_epoch_and_take_identity():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    take, retirement = _real_serial_pair()
    reset = _reset_document('reset_barrier', epoch=1)
    fresh_take = deepcopy(take)
    fresh_take['reset_epoch'] = fresh_take['source_epoch'] = 1
    fresh_take['take_key'] = ['cpu', 1, 1]
    fresh_retirement = deepcopy(retirement)
    fresh_retirement['reset_epoch'] = fresh_retirement['source_epoch'] = 1
    fresh_retirement['producer_event_id'] = fresh_retirement['producer_event_id'] + 7
    good, _ = _contiguous([(None, reset), (take['event_id'], fresh_take),
                           (retirement['event_id'], fresh_retirement)])
    certificates = IrqSerialCertificates().ingest(good)
    assert len(certificates) == 1 and certificates[0]['reset_epoch'] == 1
    # Reusing the pre-reset take identity in the new epoch refuses.
    stale = deepcopy(fresh_take)
    stale['take_key'] = ['cpu', 0, 1]
    stale_journal, _ = _contiguous([(None, reset), (take['event_id'], stale),
                                    (retirement['event_id'], fresh_retirement)])
    consumer = IrqSerialCertificates()
    assert consumer.ingest(stale_journal) == ()
    assert 'take_key_scope_mismatch' in [record['reason']
                                        for record in consumer.rejections()]


def _probes(**fields):
    from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES
    document = {'gpio_probe_' + name: 0 for name in PULP_GPIO_PROBES}
    document['gpio_in'] = 0
    document.update({'gpio_probe_' + name: value for name, value in fields.items()})
    active = document['gpio_probe_psel'] & document['gpio_probe_penable'] \
        & document['gpio_probe_pwrite']
    document['gpio_probe_write'] = active
    if active:
        word = document['gpio_probe_decoded_word']
        if word in (3, 4, 5):
            document['gpio_probe_write_out'] = 0xffffffff
        if word == 6:
            document['gpio_probe_write_inten'] = 0xffffffff
    return document


def _gpio_access(event_id, *, epoch, offset=12, value=1, old=0, new=1):
    from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
    pre = _probes(psel=1, penable=1, pwrite=1, pwdata=value, pready=1, apb_addr=offset,
                  decoded_word=(offset >> 2) & 31, out=old)
    post = _probes(out=new)
    return dict(kind='gpio_apb_access', event_id=event_id, component='gpio',
                reset_epoch=epoch, source_epoch=epoch, local_tick=event_id,
                observation_contract=pulp_gpio_observation_contract(),
                pre=pre, post=post, status='observed', phase='pre',
                access_id='access-%d' % event_id, raw_offset=offset,
                decoded_offset=((offset >> 2) & 31) << 2, write=True, wdata=value,
                source_transaction=dict(execution_id='local', testcase_id='directed-irq',
                                        source_component='cpu', source_epoch=epoch,
                                        channel_id='data', source_sequence=event_id),
                command_scope=dict(component='gpio', reset_epoch=epoch,
                                   command_sequence=event_id),
                target_response=dict(rdata=0, error=0))


def _gpio_reset(event_id, *, epoch):
    return dict(kind='gpio_reset', event_id=event_id, component='gpio',
                reset_epoch=epoch, source_epoch=epoch, local_tick=event_id)


def test_gpio_dependency_reducer_invalidates_installed_state_and_epoch():
    from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
    tracker = GpioConsumptionTracker()
    first = tracker.consume(_gpio_access(1, epoch=0))
    commit = [record for record in first if record['kind'] == 'gpio_register_commit'][0]
    assert commit['status'] == 'observed'
    installed = deepcopy(commit['bit_resources'][0])
    assert installed['reset_epoch'] == 0
    barrier = tracker.consume(_gpio_reset(2, epoch=1))
    resource = [record for record in barrier if record['kind'] == 'gpio_reset_resource']
    assert len(resource) == 1 and resource[0]['status'] == 'observed'
    # The old epoch is refused, exactly and by name.
    stale = tracker.consume(_gpio_access(3, epoch=0))
    assert [record['kind'] for record in stale] == ['gpio_consumption_match']
    assert stale[0]['status'] == 'rejected'
    assert stale[0]['reason'] == 'epoch_without_advanced_reset'
    # A fresh epoch is required and sufficient; installed state restarts.
    fresh = tracker.consume(_gpio_access(4, epoch=1))
    commit = [record for record in fresh if record['kind'] == 'gpio_register_commit'][0]
    assert commit['status'] == 'observed'
    assert commit['bit_resources'][0]['reset_epoch'] == 1
    assert commit['bit_resources'][0]['observation_event_id'] != installed['observation_event_id']
    # A set-operation bit depends on the fresh epoch baseline, never on the
    # pre-reset installed resource.
    set_commit = [record for record in tracker.consume(
        _gpio_access(5, epoch=1, offset=16, value=2, old=1, new=3))
        if record['kind'] == 'gpio_register_commit'][0]
    touched = [ref for ref in set_commit['bit_resources']
               if ref['version'] != installed['version']]
    assert set_commit['status'] == 'observed'
    dependencies = [ref for ref in set_commit['bit_resources']
                    if ref.get('dependencies')]
    assert dependencies
    assert all(ref['dependencies'][0]['reset_epoch'] == 1 for ref in dependencies)
    assert all(ref['dependencies'][0]['observation_event_id']
               != installed['observation_event_id'] for ref in dependencies)
    assert touched
    # A reset that does not advance the epoch is refused.
    repeated = tracker.consume(_gpio_reset(5, epoch=1))
    assert [record['reason'] for record in repeated] == ['reset_epoch_did_not_advance']


def test_gpio_irq_evidence_reducer_drops_pre_reset_native_state():
    from myfuzz.scenario.gpio_irq_dependency_evidence import GpioNativeIrqEvidenceConsumer
    events, _ = _saved_journal('spi-ibex-v1')
    take = _one(events, kind='cpu_external_irq_taken')
    by_id = _index(events)
    sample = by_id[take['sample_event_id']]
    step = by_id[sample['producer_event_id']]
    consumer = GpioNativeIrqEvidenceConsumer(
        source_component='spi_active', target_component='cpu', pin=8,
        source_port='events_o', target_port='irq', runtime_contract_sha256='a' * 64)
    journal, _ = _contiguous([(step['event_id'], step),
                              (sample['event_id'], sample),
                              (None, _reset_document('reset_barrier', epoch=1)),
                              (take['event_id'], deepcopy(take))])
    consumer.consume(journal[0])
    consumer.consume(journal[1])
    assert len(consumer._native) == 1
    consumer.consume(journal[2])
    assert consumer._native == {} and consumer._events == {}
    assert consumer._accepted == {} and consumer._serial_pending == {}
    consumer.consume(journal[3])
    assert consumer._native == {}
    assert consumer.report()['counts']['irq_acceptance'] == 0
    report = consumer.report()
    assert report['native_authority'] is False and report['reward_eligible'] is False
    assert report['grants_prerequisites'] is False
    assert report['isr_mmio'] == 'unknown' and report['irq_consumption'] == 'unknown'


# --------------------------------------------------------------------------- #
# (c) multi-source attribution
# --------------------------------------------------------------------------- #

def test_real_two_member_group_document_reproduces_its_recorded_identity():
    rows, group, config = _group_window()
    journal, _ = _render(rows)
    frame = next(event for event in journal if event.get('kind') == 'irq_group_delivery')
    assert len(group.members) == 2
    assert group.group_id == frame['group_id']
    assert group.identity_sha256 == frame['group_sha256']
    assert group.owner_ref == 'irq-group:' + group.group_id
    assert config['source_adapter'] == 'declared-output.v1'
    joined = _join_group_frame(group, journal)
    active = config['active_id'] + '.' + config['source_port']
    assert joined['attribution_status'] == 'unique'
    assert joined['unique_source'] == active
    assert joined['active_sources'] == [active]
    assert joined['value'] == 1 and joined['grants_prerequisites'] is False
    acceptances = [event for event in journal if event.get('kind') == 'irq_group_acceptance']
    assert len(acceptances) == 1
    assert acceptances[0]['unique_source'] == active
    assert acceptances[0]['grants_prerequisites'] is False
    assert 'reward' not in json.dumps(acceptances[0])


def test_two_simultaneously_active_members_are_joint_and_earn_no_credit():
    rows, group, config = _group_window()
    frame_original = next(event for _, event in rows
                          if event.get('kind') == 'irq_group_delivery')
    frame_position = [position for position, (_, event) in enumerate(rows)
                      if event.get('kind') == 'irq_group_delivery'][0]
    active_member, idle_member = frame_original['members']
    idle_component, idle_port = idle_member['source_id'].split('.', 1)
    idle_reference = deepcopy(idle_member['latest_native_source'])
    wire = idle_reference.get('runtime_name')
    assert type(wire) is str and wire
    idle_sample_id = idle_reference['event_id']
    pulse = dict(kind='pulse_start', source=[idle_component, idle_port],
                 target=[group.target_component, group.target_port],
                 start_cpu_tick=frame_original['cpu_tick'],
                 end_cpu_tick_exclusive=frame_original['cpu_tick']
                 + config['pulse_width_ticks'])
    joint_rows = [(original, deepcopy(event)) for original, event in rows]
    for _, event in joint_rows:
        if event.get('event_id') == idle_sample_id:
            event['local_tick'] = frame_original['cpu_tick']
            event['outputs'][idle_port] = 1
            event['outputs']['physical'][wire] = 1
        if event.get('kind') != 'irq_group_delivery':
            continue
        idle = event['members'][1]
        idle['value'] = 1
        idle['native_source'] = deepcopy(idle_reference)
        idle['latest_native_source'] = deepcopy(idle_reference)
        event['active_sources'] = [active_member['source_id'], idle_member['source_id']]
        event['unique_source'] = None
        event['attribution_status'] = 'joint'
        event['value'] = 1
    # The idle pulse window opens before the CPU step that samples it.
    step_position = [position for position, (_, event) in enumerate(joint_rows)
                     if event.get('event_id') == frame_original['cpu_step_event_id']][0]
    joint_rows.insert(min(step_position, frame_position), (None, pulse))
    journal, _ = _render(joint_rows)
    joined = _join_group_frame(group, journal)
    assert joined['attribution_status'] == 'joint'
    assert joined['unique_source'] is None
    assert joined['active_sources'] == [active_member['source_id'], idle_member['source_id']]
    assert joined['value'] == 1
    assert joined['grants_prerequisites'] is False
    # The runner refuses to keep a planned single-source context for a joint frame.
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroupState
    from myfuzz.scenario.runner import ScenarioRunner
    state = IrqDeliveryGroupState(group, {})
    state.active_frame = joined
    runner = object.__new__(ScenarioRunner)
    runner._irq_group_states = {group.group_id: state}
    runner._irq_group_adapters = {binding: {'physical_port': member.source_port}
                                  for binding, member in zip(group.member_bindings(),
                                                             group.members)}
    unique_reference = next(row['native_source'] for row in joined['members']
                            if row['source_id'] == active_member['source_id'])
    planned = [active_member['source_id'].split('.', 1)[0], 0,
               active_member['source_id'].split('.', 1)[1], unique_reference['local_tick']]
    cpu = SimpleNamespace(_next_irq_input_context={'source_output_key': planned})
    cpu.set_next_irq_input_context = lambda value: setattr(
        cpu, '_next_irq_input_context', value)
    runner._guard_irq_group_input_context(group.target_component, cpu)
    assert cpu._next_irq_input_context is None
    # Control: the same plan survives a genuinely unique frame.
    unique_frame, _ = _contiguous([(original, event) for original, event in rows])
    unique_joined = _join_group_frame(group, unique_frame)
    state.active_frame = unique_joined
    cpu._next_irq_input_context = {'source_output_key': planned}
    runner._guard_irq_group_input_context(group.target_component, cpu)
    assert cpu._next_irq_input_context is not None


def test_member_without_an_exact_native_reference_earns_no_attribution():
    from myfuzz.scenario.irq import IrqPulseDelivery
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroupState
    rows, group, _ = _group_window()
    journal, _ = _render(rows)
    stripped_rows = [(key, deepcopy(event)) for key, event in rows]
    for key, event in stripped_rows:
        if event.get('kind') == 'irq_group_delivery':
            event['members'][0].pop('native_source', None)
    stripped, _ = _render(stripped_rows)
    with pytest.raises(ValueError, match='member sample reference'):
        _join_group_frame(group, stripped)
    # A reference to another component's sample is not an origin either.
    swapped_rows = [(key, deepcopy(event)) for key, event in rows]
    members = next(event for _, event in swapped_rows
                   if event.get('kind') == 'irq_group_delivery')['members']
    members[0]['native_source'] = deepcopy(members[1]['native_source'])
    swapped, _ = _render(swapped_rows)
    with pytest.raises(ValueError, match='member native sample/epoch mismatch'):
        _join_group_frame(group, swapped)
    # The reducer itself refuses an origin without a complete native reference.
    binding = group.member_bindings()[0]
    pulses = {binding: IrqPulseDelivery(width_ticks=16, require_observed_baseline=True)}
    state = IrqDeliveryGroupState(group, pulses)
    with pytest.raises(ValueError, match='native member reference required'):
        state.observe(binding, 1, {'component': binding.source_component,
                                   'event_id': 0, 'reset_epoch': 0, 'local_tick': 0,
                                   'phase': 'post'})
    assert not state.samples


def test_take_without_its_delivery_frame_cannot_be_joined():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    rows, group, _ = _group_window()
    events, _ = _saved_journal(REAL_GROUP_RUN)
    take = _one(events, kind='cpu_external_irq_taken')
    token = take['irq_serial_observation']['decision']['value']
    retirement = next(event for event in events if event.get('kind') == 'cpu_retire'
                      and event.get('irq_serial_observation', {}).get(
                          'retirement', {}).get('value') == token)
    without_frame = [(key, deepcopy(event)) for key, event in rows
                     if event.get('kind') not in ('irq_group_delivery',
                                                  'irq_group_acceptance')]
    without_frame.append((retirement['event_id'], deepcopy(retirement)))
    journal, _ = _render(without_frame)
    with pytest.raises(ValueError, match='frame missing'):
        _join_take_sample(group, journal)
    certificates = IrqSerialCertificates().ingest(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate['scope'] == 'external_irq_decision_serial_to_rvfi_retirement_serial'
    assert certificate['take_identity'] == {'take_key': ['cpu', 0, 1]}
    # The certificate carries no delivery/source attribution of its own.
    assert 'unique_source' not in certificate and 'group_id' not in certificate
    assert 'event_adjacency' in certificate['not_proof_of']


def _single_member_group():
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    return IrqDeliveryGroup('directed-overrun', 'cpu', 'irq_external_i',
                            (IrqDeliveryMember('timer', 'o_int', mode='pulse',
                                               pulse_width_ticks=4),))


def _single_member_rows(*, value, sample_tick, wire):
    group = _single_member_group()
    binding = group.member_bindings()[0]
    reference = dict(component=binding.source_component, event_id=200, reset_epoch=0,
                     local_tick=sample_tick, phase='post', runtime_name=wire)
    rows = [
        (100, dict(event_id=100, kind='local_tick_sample', component='timer',
                   reset_epoch=0, local_tick=sample_tick, phase='post',
                   outputs={'o_int': 1, 'physical': {wire: 1}})),
        (200, dict(event_id=200, kind='local_tick_sample', component='timer',
                   reset_epoch=0, local_tick=sample_tick, phase='post',
                   outputs={'o_int': 1, 'physical': {wire: 1}})),
        (300, dict(event_id=300, component='cpu', local_tick=sample_tick,
                   inputs={'irq_external_i': value},
                   outputs={'irq_taken_pre': 0})),
        (400, dict(event_id=400, kind='cpu_external_irq_sample', component='cpu',
                   execution_id='local', reset_epoch=0, local_tick=sample_tick,
                   command_scope=dict(component='cpu', reset_epoch=0, command_sequence=1),
                   receipt_id=dict(execution='local-driver:cpu:1', sequence=1),
                   producer_event_id=300, expected_input=value,
                   actual_pre_input=value, actual_post_input=value,
                   irq_taken_pre=0)),
        (500, dict(event_id=500, kind='irq_group_delivery', group_id=group.group_id,
                   group_sha256=group.identity_sha256,
                   target_component=group.target_component,
                   target_port=group.target_port, cpu_tick=sample_tick, value=value,
                   members=[dict(source_id='timer.o_int', mode='pulse', value=value,
                                 native_source=deepcopy(reference),
                                 latest_native_source=deepcopy(reference), pulse=None)],
                   active_sources=['timer.o_int'] if value else [],
                   attribution_status='unique' if value else 'unknown',
                   unique_source='timer.o_int' if value else None,
                   native_sample_event_id=400, cpu_step_event_id=300,
                   target_epoch=0, receipt_id=dict(execution='local-driver:cpu:1',
                                                   sequence=1),
                   grants_prerequisites=False)),
    ]
    return group, rows


def test_overrun_and_reset_cancelled_pulse_earn_no_delivery():
    from myfuzz.scenario.irq import IrqPulseDelivery
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroupState
    pulse = IrqPulseDelivery(width_ticks=4)
    pulse.observe_source(1, source_tick=1, cpu_tick=0)
    pulse.observe_source(0, source_tick=2, cpu_tick=1)
    pulse.observe_source(1, source_tick=3, cpu_tick=2)
    assert pulse.status == 'unsupported_irq_overrun'
    overruns = [event for event in pulse.events if event['kind'] == 'irq_overrun']
    assert len(overruns) == 1 and overruns[0]['policy'] == 'terminate_unsupported'
    assert overruns[0]['active_source_event_id'] == 1
    starts = [event for event in pulse.events if event['kind'] == 'pulse_start']
    assert len(starts) == 1 and starts[0]['source_event_id'] == 1
    # The overrun edge has no delivery window: at tick 6 the honest frame is 0.
    group, honest_rows = _single_member_rows(value=0, sample_tick=6, wire='rt_o_int')
    journal, _ = _render(honest_rows)
    joined = _join_group_frame(group, journal)
    assert joined['value'] == 0 and joined['unique_source'] is None
    assert joined['attribution_status'] == 'unknown'
    # A frame claiming that delivery cannot be re-derived from the journal.
    _, claimed_rows = _single_member_rows(value=1, sample_tick=6, wire='rt_o_int')
    claimed, _ = _render(claimed_rows)
    with pytest.raises(ValueError, match='pulse/OR value mismatch'):
        _join_group_frame(group, claimed)
    # A reset-cancelled pulse delivers nothing either.
    pulse.reset(cpu_tick=3)
    assert [event['kind'] for event in pulse.events].count('pulse_cancelled_by_reset') == 1
    assert pulse.input_at(4) == 0
    binding = group.member_bindings()[0]
    state = IrqDeliveryGroupState(group, {binding: pulse})
    state.observe(binding, 1, dict(component='timer', event_id=1, reset_epoch=0,
                                   local_tick=1, phase='post'))
    state.reset()
    assert state.last_delivery is None
    with pytest.raises(ValueError, match='native state unavailable'):
        state.frame(4)


def test_post_reset_member_sample_from_the_old_epoch_is_refused():
    """After a measured reset the runner refuses a member sample of the old epoch."""
    from myfuzz.scenario.irq import IrqPulseDelivery
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroupState
    from myfuzz.scenario.runner import ScenarioRunner
    rows, group, config = _group_window()
    frame = next(event for _, event in rows if event.get('kind') == 'irq_group_delivery')
    pulses = {binding: IrqPulseDelivery(width_ticks=config['pulse_width_ticks'])
              for binding in group.member_bindings()}
    state = IrqDeliveryGroupState(group, pulses)
    for member, binding in zip(group.members, group.member_bindings()):
        declared = next(row for row in frame['members']
                        if row['source_id'] == member.source_id)
        reference = declared['native_source']
        state.observe(binding, declared['value'],
                      {name: reference[name] for name in ('component', 'event_id',
                                                         'reset_epoch', 'local_tick',
                                                         'phase')})
    runner = object.__new__(ScenarioRunner)
    runner._inputs = {group.target_component: {}}
    runner._irq_pulses = {}
    runner._irq_group_members = {binding: group for binding in group.member_bindings()}
    runner.local_ticks = {group.target_component: frame['cpu_tick']}
    runner._irq_group_states = {group.group_id: state}
    runner.sessions = {member.source_component: SimpleNamespace(reset_epoch=0)
                       for member in group.members}
    assert group.target_port in runner._effective_inputs(group.target_component)
    # A measured reset advances the epoch; the old member documents are refused.
    for session in runner.sessions.values():
        session.reset_epoch = 1
    with pytest.raises(ValueError, match='epoch changed'):
        runner._effective_inputs(group.target_component)
    # Fresh native samples (the post-reset epoch) are required and sufficient.
    for member, binding in zip(group.members, group.member_bindings()):
        declared = next(row for row in frame['members']
                        if row['source_id'] == member.source_id)
        reference = dict(declared['native_source'], reset_epoch=1)
        state.observe(binding, declared['value'],
                      {name: reference[name] for name in ('component', 'event_id',
                                                         'reset_epoch', 'local_tick',
                                                         'phase')})
    assert group.target_port in runner._effective_inputs(group.target_component)


# --------------------------------------------------------------------------- #
# (c) the declared real two-member group from the compiled scenario config
# --------------------------------------------------------------------------- #

def _shared_declaration():
    supplement = json.loads((SHARED_SCENARIO / 'execution_supplement.json').read_text(
        encoding='utf-8'))
    return supplement['request_supplements']


def test_shared_scenario_declares_the_real_two_member_or_group():
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
    supplements = _shared_declaration()
    declaration = supplements['f6_execution']['gpio_irq']
    assert declaration['group_id'] == 'shared-external'
    assert declaration['component'] == 'peripheral'
    deliveries = {row.get('producer_instance'): row for row in supplements['deliveries']}
    assert deliveries['dma']['producer_signal'] == 'o_interrupt'
    assert deliveries['peripheral']['producer_signal'] == 'interrupt'
    assert all(row['consumer_instance'] == 'cpu' for row in deliveries.values())
    document = {
        'schema_version': 'host_irq_delivery_group.v1',
        'group_id': declaration['group_id'], 'target_component': 'cpu',
        'target_port': 'irq_external_i',
        'members': [
            {'source_component': 'dma', 'source_port': 'irq', 'mode': 'pulse',
             'pulse_width_ticks': 16, 'source_bit_offset': 0},
            {'source_component': declaration['component'],
             'source_port': deliveries[declaration['component']]['producer_signal'],
             'mode': 'pulse', 'pulse_width_ticks': 4, 'source_bit_offset': 0},
        ],
        'target_bit_offset': 0, 'operation': 'or',
    }
    group = IrqDeliveryGroup.from_document(document)
    assert json.loads(json.dumps(group.document())) == document
    assert group.owner_ref == 'irq-group:shared-external'
    assert [member.source_id for member in group.members] == ['dma.irq',
                                                             'peripheral.interrupt']
    assert len(group.member_bindings()) == 2


@pytest.mark.skipif(
    __import__('os').environ.get('MYFUZZ_DIRECTED_IRQ_SLOW') != '1',
    reason='real compiled preparation needs ~36s; set MYFUZZ_DIRECTED_IRQ_SLOW=1')
def test_shared_scenario_builds_that_group_from_real_artifacts(tmp_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import shared_irq_group
    descriptor = load_descriptor(SHARED_SCENARIO / 'generic_scenario.json', base_dir=ROOT)
    preparation = create_preparation(
        base_dir=ROOT, compose_path=descriptor.compose,
        capability_paths=descriptor.capability, supplement_path=descriptor.supplement,
        generated_dir=tmp_path / 'generated', flow_ids=descriptor.flow_ids)
    try:
        admission = admit_compiled_f6_runtime_path(
            artifacts=dict(preparation.artifacts),
            compiled_inputs=preparation.compiled_inputs(), base_dir=ROOT)
        group = shared_irq_group(admission['execution_contract'],
                                 preparation.artifacts, base_dir=ROOT)
        assert group.group_id == 'shared-external'
        assert group.target_component == 'cpu'
        assert group.target_port == 'irq_external_i'
        assert [(member.source_component, member.source_port, member.mode,
                 member.pulse_width_ticks) for member in group.members] == [
            ('dma', 'irq', 'pulse', 16), ('peripheral', 'interrupt', 'pulse', 4)]
    finally:
        preparation.close()
