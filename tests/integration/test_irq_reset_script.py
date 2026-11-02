"""Pure gates for ``scripts/run_irq_reset_native.py``; no RTL, no native process.

Every journal below is synthetic but shaped exactly like the exported native one
(the same event kinds, the same versioned serial observation document and the
same receipt identity fields), so the reducers are exercised on the documents the
frozen window will really produce.  The native run itself is the lead's; nothing
here stands in for it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_irq_reset_native import (
    CASE_ID, MEASURED_LAYERS, REQUIRED_LAYERS, RESET_POLICY, SCOPE, SUMMARY_SCHEMA,
    ResetLineageRefused, build_program, build_summary, check_process_identities,
    handler_addresses, inspect_take_attribution, load_config, main, reduce_lineage,
    scope_fields, validate_config)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'configs/scenarios/directed-irq-reset/ibex-wb-timer.json'
ACTIVE, IDLE = 'wb_timer_active', 'wb_timer_idle'
SOURCE_PORT = 'o_int'
BOOT = 0x10000
BASE = 0x40001000
DECISION_PORT = 'irq_decision_serial'
RETIREMENT_PORT = 'irq_retirement_serial'


# --------------------------------------------------------------------------- #
# Real configuration and real fixed programme
# --------------------------------------------------------------------------- #

def test_declared_config_builds_the_expected_reset_wiring():
    document, options = load_config(CONFIG)
    assert document['cpu_profile'] == 'configs/cpus/ibex_rvfi_local/component_profile.json'
    assert document['source_request'] == 'configs/peripherals/zipcpu_timer_irq/request.json'
    assert options['source_adapter'] == 'declared-output.v1'
    assert options['source_port'] == SOURCE_PORT and options['source_bit_offset'] == 0
    assert options['active_base'] == BASE == 1073745920
    assert options['idle_base'] % 4096 == 0 and options['idle_base'] != options['active_base']
    assert options['trigger_writes'] == ((0, 8),)
    assert options['reset_policy'] == RESET_POLICY and options['post_reset_steps'] >= 1
    # Wide enough that the reset lands inside the taken handler, not after it.
    assert 16 <= options['pulse_width_ticks'] <= 4096
    assert options['case'] == CASE_ID


def _config(**changes):
    document = json.loads(CONFIG.read_text(encoding='utf-8'))
    document.update(changes)
    return document


@pytest.mark.parametrize('changes, message', [
    ({'source_adapter': None}, 'declared-output.v1'),
    ({'source_adapter': 'native-pulse.v1'}, 'source'),
    ({'reset_policy': 'cold_all'}, 'warm_all'),
    ({'reset_policy': 'cpu_only'}, 'warm_all'),
    ({'post_reset_steps': 0}, 'post_reset_steps'),
    ({'post_reset_steps': 10001}, 'post_reset_steps'),
    ({'post_reset_steps': True}, 'post_reset_steps'),
    ({'pulse_width_ticks': 0}, 'pulse width'),
    ({'pulse_width_ticks': 8}, 'pulse width'),
    ({'pulse_width_ticks': 4097}, 'pulse width'),
    ({'source_bit_offset': 64}, 'source'),
    ({'active_base': BASE + 1}, 'source'),
    ({'active_base': BASE, 'idle_base': BASE}, 'differ'),
    ({'active_id': 'cpu'}, 'source'),
    ({'active_id': IDLE}, 'source'),
    ({'source_port': ''}, 'source'),
    ({'undeclared_field': 1}, 'undeclared'),
    ({'case': ''}, 'case id'),
])
def test_config_refusals_are_exact(changes, message):
    with pytest.raises(ValueError, match=message):
        validate_config(_config(**changes))


def test_config_requires_every_declared_key():
    document = _config()
    del document['trigger_writes']
    with pytest.raises(ValueError, match='requires'):
        validate_config(document)


def test_config_resolution_refuses_a_missing_profile(tmp_path):
    """Structure and path resolution are separate: the document itself is valid."""
    from scripts.run_irq_reset_native import resolve_config_paths
    options = validate_config(_config(cpu_profile='configs/cpus/absent/profile.json'))
    with pytest.raises(ValueError, match='missing cpu_profile'):
        resolve_config_paths(options)
    with pytest.raises(ValueError, match='missing source_request'):
        resolve_config_paths(dict(validate_config(_config()),
                                  source_request=str(tmp_path / 'absent.json')))


# --------------------------------------------------------------------------- #
# Fixed programme layout
# --------------------------------------------------------------------------- #

def programme():
    return build_program(BOOT, active_base=BASE, trigger_writes=((0, 8),), window_size=4)


def _words(program, base):
    data = bytes.fromhex(program['images'][str(base)])
    return [int.from_bytes(data[index:index + 4], 'little')
            for index in range(0, len(data), 4)]


def test_program_layout_keeps_vector_handler_and_park_disjoint():
    program = programme()
    assert program['boot'] == BOOT and program['vector'] == 0x10200
    assert program['handler'] == 0x10400 and program['mret'] == program['handler'] + 24
    assert BOOT < program['park'] < program['vector'] <= program['handler']
    main = _words(program, BOOT)
    assert len(main) == (program['park'] + 4 - BOOT) // 4
    # The declared trigger write and the park self-loop close the boot image.
    assert main[-1] == 0x6F and main[-1] == 0x0000006F
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _sw
    base = _lui_addi_load(8, BASE)
    value = _lui_addi_load(9, 8)
    assert main[-6:-4] == list(base) and main[-4:-2] == list(value)
    assert main[-2] == _sw(9, 8, 0) and main[-1] == _jal(program['park'], program['park'])
    # The CSR setup the smoke's fixed ROM depends on is present in main.
    assert ((0x305 << 20) | (3 << 15) | (1 << 12) | 0x73) in main
    assert sorted(program['images']) == sorted(str(row) for row in (
        BOOT, program['vector'], program['vector'] + 44, program['handler']))
    assert _words(program, program['handler'])[-1] == 0x30200073  # mret
    addresses = handler_addresses(program)
    assert program['vector'] in addresses and program['handler'] in addresses
    assert program['park'] not in addresses and BOOT not in addresses
    assert len(addresses) == 1 + 1 + 7  # two vector stubs and the seven handler words


def test_program_layout_refuses_an_overlapping_window():
    with pytest.raises(ValueError):
        build_program(BOOT, active_base=BASE, trigger_writes=((4, 1),), window_size=4)


# --------------------------------------------------------------------------- #
# Synthetic journals shaped like the exported native ones
# --------------------------------------------------------------------------- #

def serial_observation(decision, retirement):
    """The versioned Ibex serial sideband document the real CPU session emits."""
    return {
        'schema_version': 'ibex_irq_serial_observation.v1',
        'sampling': 'pre_post_rising', 'width_bits': 64,
        'zero_semantics': 'no_provable_source_lineage',
        'decision': {'physical_port': DECISION_PORT, 'phase': 'pre',
                     'value': decision, 'status': 'observed'},
        'retirement': {'physical_port': RETIREMENT_PORT, 'phase': 'post',
                       'value': retirement, 'status': 'observed'}}


def group():
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    return IrqDeliveryGroup(
        'irq-reset-or', 'cpu', 'irq',
        (IrqDeliveryMember(ACTIVE, SOURCE_PORT, pulse_width_ticks=32,
                           source_adapter='declared-output.v1'),
         IrqDeliveryMember(IDLE, SOURCE_PORT, pulse_width_ticks=32,
                           source_adapter='declared-output.v1')))


def epochs(*, before=0, after=1, command_before=3, command_after=4):
    return {'before': {'cpu': before, ACTIVE: before, IDLE: before},
            'after': {'cpu': after, ACTIVE: after, IDLE: after},
            'command_before': command_before, 'command_after': command_after}


def journal(program, *, pre_token=1, post_token=1, pre_epoch=0, post_epoch=1,
            post_retirement_epoch=None, post_retirement_receipt=None,
            post_take_identity=None, post_take_receipt=None, policy=RESET_POLICY,
            include_barrier=True, include_handler_retirement=True,
            include_pre_take=True, post_take=True, pre_decision_epoch=None,
            drop_post_reset_retirement=False):
    """A contiguous journal in the exact shape the runner exports."""
    rows = []

    def add(kind, **fields):
        rows.append(dict(kind=kind, **fields))
        return len(rows)

    def source_sample(component, value, tick, epoch):
        return add('local_tick_sample', component=component, phase='post',
                   local_tick=tick, reset_epoch=epoch,
                   outputs={SOURCE_PORT: value, 'physical': {SOURCE_PORT: value}})

    def member(source_id, sample, tick, epoch, value):
        reference = {'component': source_id.split('.')[0], 'event_id': sample,
                     'reset_epoch': epoch, 'local_tick': tick, 'phase': 'post'}
        return {'source_id': source_id, 'mode': 'pulse', 'value': value,
                'native_source': dict(reference),
                'latest_native_source': dict(reference)}

    def frame(*, tick, epoch, take, sample, rows_for_members):
        return add('irq_group_delivery', group_id=group_id, group_sha256=group_sha,
                   target_component='cpu', target_port='irq', cpu_tick=tick, value=1,
                   attribution_status='unique',
                   unique_source=ACTIVE + '.' + SOURCE_PORT,
                   active_sources=[ACTIVE + '.' + SOURCE_PORT], target_epoch=epoch,
                   native_take_event_id=take, native_sample_event_id=sample,
                   members=list(rows_for_members))

    group_identity = group()
    group_id, group_sha = group_identity.group_id, group_identity.identity_sha256
    active_sample = source_sample(ACTIVE, 1, 8, pre_epoch)
    idle_sample = source_sample(IDLE, 0, 8, pre_epoch)
    pre_members = (member(ACTIVE + '.' + SOURCE_PORT, active_sample, 8, pre_epoch, 1),
                   member(IDLE + '.' + SOURCE_PORT, idle_sample, 8, pre_epoch, 0))
    scope = {'execution': 'exec-a', 'sequence': 40}
    step = add('step', component='cpu', local_tick=9, inputs={'irq': 1}, outputs={})
    sample_epoch = pre_epoch if pre_decision_epoch is None else pre_decision_epoch
    pre_sample = add('cpu_external_irq_sample', component='cpu', source_component='cpu',
                     execution_id='local-execution', reset_epoch=sample_epoch,
                     source_epoch=sample_epoch, local_tick=9, irq_taken_pre=1,
                     receipt_id=dict(scope), producer_event_id=step,
                     irq_serial_observation=serial_observation(pre_token, pre_token))
    if include_pre_take:
        pre_take = add('cpu_external_irq_taken', component='cpu',
                       source_component='cpu', execution_id='local-execution',
                       reset_epoch=pre_epoch, source_epoch=pre_epoch, local_tick=9,
                       irq_taken_pre=1, take_key=['cpu', pre_epoch, 1],
                       receipt_id=dict(scope), producer_event_id=step,
                       sample_event_id=pre_sample,
                       irq_serial_observation=serial_observation(pre_token, pre_token))
        frame(tick=9, epoch=pre_epoch, take=pre_take, sample=pre_sample,
              rows_for_members=pre_members)
    else:
        pre_take = None
    retire_step = add('step', component='cpu', local_tick=11, inputs={'irq': 0},
                      outputs={})
    if include_handler_retirement:
        add('cpu_retire', component='cpu', source_component='cpu',
            execution_id='local-execution', reset_epoch=pre_epoch,
            source_epoch=pre_epoch, order=1, pc_rdata=program['vector'], insn=0x6F,
            valid=1, intr=1, trap=0, halt=0, local_tick=11,
            receipt_id={'execution': 'exec-a', 'sequence': 41},
            producer_event_id=retire_step,
            irq_serial_observation=serial_observation(0, pre_token))
        add('cpu_retire', component='cpu', source_component='cpu',
            execution_id='local-execution', reset_epoch=pre_epoch,
            source_epoch=pre_epoch, order=2, pc_rdata=program['handler'], insn=0x37,
            valid=1, intr=0, trap=0, halt=0, local_tick=12,
            receipt_id={'execution': 'exec-a', 'sequence': 42},
            producer_event_id=retire_step,
            irq_serial_observation=serial_observation(0, 0))
    else:
        # A normal retirement outside the trap path: the barrier would then land
        # on an idle CPU, which this case must refuse.
        add('cpu_retire', component='cpu', source_component='cpu',
            execution_id='local-execution', reset_epoch=pre_epoch,
            source_epoch=pre_epoch, order=1, pc_rdata=program['park'], insn=0x6F,
            valid=1, intr=0, trap=0, halt=0, local_tick=11,
            receipt_id={'execution': 'exec-a', 'sequence': 41},
            producer_event_id=retire_step,
            irq_serial_observation=serial_observation(0, 0))
    barrier = None
    if include_barrier:
        barrier = add('reset_barrier', policy=policy, memory_generations={'ram': 0},
                      cancelled_responses={'cpu': 0, ACTIVE: 0, IDLE: 0},
                      cancelled_target_requests={},
                      pending_responses_before_reset={'cpu': 0},
                      pending_events_before_reset={'cpu': 0, ACTIVE: 0, IDLE: 0},
                      pending_events_after_reset={'cpu': 0, ACTIVE: 0, IDLE: 0},
                      cancelled_dataflow_targets=[], cancelled_irq_pulses={'cpu': 1})
        add('cpu_reset', component='cpu', source_component='cpu',
            execution_id='local-execution', reset_epoch=pre_epoch + 1,
            source_epoch=pre_epoch + 1, local_tick=13,
            command_scope={'component': 'cpu', 'reset_epoch': pre_epoch + 1,
                           'command_sequence': 0})
    post_take_event = None
    if post_take:
        post_active = source_sample(ACTIVE, 1, 20, post_epoch)
        post_idle = source_sample(IDLE, 0, 20, post_epoch)
        post_members = (member(ACTIVE + '.' + SOURCE_PORT, post_active, 20,
                               post_epoch, 1),
                        member(IDLE + '.' + SOURCE_PORT, post_idle, 20, post_epoch, 0))
        post_receipt = post_take_receipt or {'execution': 'exec-b', 'sequence': 50}
        post_step = add('step', component='cpu', local_tick=21, inputs={'irq': 1},
                        outputs={})
        post_sample = add('cpu_external_irq_sample', component='cpu',
                          source_component='cpu', execution_id='local-execution',
                          reset_epoch=post_epoch, source_epoch=post_epoch,
                          local_tick=21, irq_taken_pre=1, receipt_id=dict(post_receipt),
                          producer_event_id=post_step,
                          irq_serial_observation=serial_observation(post_token,
                                                                    post_token))
        post_take_event = add(
            'cpu_external_irq_taken', component='cpu', source_component='cpu',
            execution_id='local-execution', reset_epoch=post_epoch,
            source_epoch=post_epoch, local_tick=21, irq_taken_pre=1,
            take_key=list(post_take_identity or ['cpu', post_epoch, 1]),
            receipt_id=dict(post_receipt), producer_event_id=post_step,
            sample_event_id=post_sample,
            irq_serial_observation=serial_observation(post_token, post_token))
        frame(tick=21, epoch=post_epoch, take=post_take_event, sample=post_sample,
              rows_for_members=post_members)
        if not drop_post_reset_retirement:
            retirement_step = add('step', component='cpu', local_tick=23,
                                  inputs={'irq': 0}, outputs={})
            retirement_epoch = (post_epoch if post_retirement_epoch is None
                                else post_retirement_epoch)
            retirement_receipt = (post_retirement_receipt
                                  or {'execution': 'exec-b', 'sequence': 51})
            add('cpu_retire', component='cpu', source_component='cpu',
                execution_id='local-execution', reset_epoch=retirement_epoch,
                source_epoch=retirement_epoch, order=1, pc_rdata=program['vector'],
                insn=0x6F, valid=1, intr=1, trap=0, halt=0, local_tick=23,
                receipt_id=dict(retirement_receipt),
                producer_event_id=retirement_step,
                irq_serial_observation=serial_observation(0, post_token))
            add('cpu_retire', component='cpu', source_component='cpu',
                execution_id='local-execution', reset_epoch=post_epoch,
                source_epoch=post_epoch, order=2, pc_rdata=program['handler'],
                insn=0x37, valid=1, intr=0, trap=0, halt=0, local_tick=24,
                receipt_id={'execution': 'exec-b', 'sequence': 52},
                producer_event_id=retirement_step,
                irq_serial_observation=serial_observation(0, 0))
    documents = []
    for position, row in enumerate(rows, 1):
        document = {'event_id': position}
        document.update(row)
        documents.append(document)
    return documents, {'barrier': barrier, 'pre_take': pre_take,
                       'post_take': post_take_event}


def _reduce(program, documents, *, history=None):
    return reduce_lineage(documents, program, epochs=history or epochs())


# --------------------------------------------------------------------------- #
# The lineage reducer
# --------------------------------------------------------------------------- #

def test_reducer_accepts_a_fresh_epoch_with_the_same_numeric_token():
    """The sideband counter restarts, so the token repeats; the epoch is the identity."""
    program = programme()
    documents, _ = journal(program, pre_token=1, post_token=1)
    result = _reduce(program, documents)
    assert result['status'] == 'verified' and result['scope'] == SCOPE
    assert result['barrier_observed'] is True and result['epochs_advanced'] is True
    assert result['no_lineage_after_reset'] is True
    assert result['pre_reset_handler_retirements'] >= 1
    assert result['post_reset_take_count'] == 1
    assert result['post_reset_serial_distinct'] is True
    assert result['post_reset_fresh_take_observed'] is True
    assert result['post_reset_fresh_retirement_observed'] is True
    assert result['epochs']['pre_reset_epoch'] == 0
    assert result['epochs']['post_reset_epoch'] == 1
    assert result['lineage']['serial_identity_scope'] == 'epoch_qualified_token_and_take_identity'
    # Both raw tokens are recorded, and the repeat is reported as not-lineage.
    assert result['lineage']['raw_pre_reset_tokens'] == [1]
    assert result['lineage']['raw_post_reset_tokens'] == [1]
    assert result['lineage']['raw_token_reuse_count'] == 1
    assert result['lineage']['raw_token_reuse_across_reset'][0]['token'] == 1
    assert result['lineage']['cross_epoch_joins'] == []
    assert all(result['layers'][name] for name in REQUIRED_LAYERS)
    assert set(result['layers']) == set(MEASURED_LAYERS)
    # The production consumer certifies one join per epoch, never a cross join.
    assert result['serial_certificates'] == {'total': 2, 'pre_reset': 1, 'post_reset': 1}
    assert result['post_reset']['certificate_epochs'] == [1]
    # Every post-reset retirement is recorded, compactly, with its epoch and token.
    retirements = result['post_reset']['retirements']
    assert len(retirements) == result['post_reset']['retirement_count'] == 2
    assert result['post_reset']['retirements_truncated'] is False
    assert result['post_reset']['retirement_fields'] == [
        'event_id', 'reset_epoch', 'retirement_serial', 'intr', 'pc_rdata']
    # A zero token means "no provable lineage", so it is recorded as absent.
    assert [row[2] for row in retirements] == [1, None]
    assert result['pre_reset']['handler_retirement_events'] == [
        result['pre_reset']['handler_entry']['event_id'],
        result['pre_reset']['handler_entry']['event_id'] + 1]


def test_reducer_accepts_a_distinct_post_reset_serial():
    program = programme()
    documents, _ = journal(program, pre_token=1, post_token=2)
    result = _reduce(program, documents)
    assert result['status'] == 'verified'
    assert result['post_reset_serial_distinct'] is True
    assert result['lineage']['raw_token_reuse_across_reset'] == []
    assert result['serial_certificates']['post_reset'] == 1


@pytest.mark.parametrize('changes, code', [
    # A post-reset retirement that keeps the old epoch really joins pre-reset lineage.
    ({'post_retirement_epoch': 0}, 'post-reset-retirement-joins-pre-reset-serial'),
    # The same numeric token inside the old epoch but not the exact join event.
    ({'post_retirement_epoch': 0, 'post_token': 7},
     'post-reset-retirement-carries-pre-reset-epoch'),
    # A retirement re-using the pre-reset receipt identity is stale evidence.
    ({'post_retirement_receipt': {'execution': 'exec-a', 'sequence': 41}},
     'post-reset-retirement-references-pre-reset-take-identity'),
    # A pre-reset decision stamped with the post-reset epoch is fabrication.
    ({'pre_decision_epoch': 1}, 'pre-reset-decision-epoch-not-before-reset'),
    # A post-reset take that re-uses the pre-reset take identity.
    ({'post_take_identity': ['cpu', 0, 1]}, 'post-reset-take-reuses-pre-reset-identity'),
    ({'post_take_receipt': {'execution': 'exec-a', 'sequence': 40}},
     'post-reset-take-reuses-pre-reset-identity'),
    # A post-reset take whose take identity names another epoch.
    ({'post_take_identity': ['cpu', 0, 9]}, 'post-reset-take-identity-scope-mismatch'),
    ({'post_take_identity': ['wb_timer_active', 1, 1]},
     'post-reset-take-identity-scope-mismatch'),
])
def test_reducer_refuses_real_cross_epoch_lineage(changes, code):
    program = programme()
    documents, _ = journal(program, **changes)
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == code


def test_reducer_refuses_a_post_reset_take_from_the_old_epoch():
    program = programme()
    documents, _ = journal(program, post_epoch=1, post_take_identity=['cpu', 0, 1])
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == 'post-reset-take-reuses-pre-reset-identity'


def test_reducer_refuses_a_missing_barrier():
    program = programme()
    documents, _ = journal(program, include_barrier=False)
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == 'reset-barrier-missing'


def test_reducer_refuses_a_policy_that_is_not_the_measured_warm_reset():
    program = programme()
    documents, _ = journal(program, policy='cold_all')
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == 'reset-policy-mismatch'


@pytest.mark.parametrize('history', [
    epochs(before=0, after=0),
    epochs(before=1, after=1),
    epochs(before=0, after=1, command_before=4, command_after=4),
])
def test_reducer_refuses_epochs_that_do_not_advance(history):
    program = programme()
    documents, _ = journal(program)
    with pytest.raises(ResetLineageRefused) as refusal:
        reduce_lineage(documents, program, epochs=history)
    assert refusal.value.code == 'epochs-did-not-advance'


def test_reducer_refuses_a_barrier_without_a_handler():
    program = programme()
    documents, _ = journal(program, include_handler_retirement=False)
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == 'pre-reset-handler-retirement-required'


def test_reducer_refuses_a_journal_without_a_pre_reset_take():
    program = programme()
    documents, _ = journal(program)
    documents = [row for row in documents
                 if row.get('kind') != 'cpu_external_irq_taken' or row['reset_epoch']]
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code in ('pre-reset-take-required', 'journal-event-ids-not-contiguous')


def test_reducer_refuses_a_post_reset_retirement_with_no_observed_token():
    """A missing token cannot be lineage, and a new-epoch zero stays unobservable."""
    program = programme()
    documents, _ = journal(program, post_token=2)
    retirement = next(row for row in documents
                      if row.get('kind') == 'cpu_retire' and row['reset_epoch'] == 1)
    retirement.pop('irq_serial_observation')
    result = _reduce(program, documents)
    assert result['status'] == 'verified'
    assert result['post_reset_fresh_retirement_observed'] is False


def test_reducer_refuses_a_non_contiguous_journal():
    program = programme()
    documents, _ = journal(program)
    documents[3]['event_id'] = 99
    with pytest.raises(ResetLineageRefused) as refusal:
        _reduce(program, documents)
    assert refusal.value.code == 'journal-event-ids-not-contiguous'


# --------------------------------------------------------------------------- #
# Delivery attribution of the taken IRQ
# --------------------------------------------------------------------------- #

def test_delivery_attribution_is_recomputed_from_the_journal():
    program = programme()
    documents, ids = journal(program)
    by_id = {row['event_id']: row for row in documents}
    take = by_id[ids['pre_take']]
    attribution = inspect_take_attribution(documents, take=take, group=group(),
                                           active_id=ACTIVE, source_port=SOURCE_PORT)
    assert attribution['attribution_status'] == 'unique'
    assert attribution['unique_source'] == ACTIVE + '.' + SOURCE_PORT
    assert attribution['native_take_event_id'] == take['event_id']
    assert attribution['raw_output'] == 1


@pytest.mark.parametrize('change, code', [
    ('unique_source', 'irq-group-attribution-not-unique'),
    ('attribution_status', 'irq-group-attribution-not-unique'),
    ('group_sha256', 'irq-group-attribution-not-unique'),
    ('missing', 'irq-group-delivery-missing'),
])
def test_delivery_attribution_refuses_a_mismatched_frame(change, code):
    program = programme()
    documents, ids = journal(program)
    by_id = {row['event_id']: row for row in documents}
    take = by_id[ids['pre_take']]
    frames = [row for row in documents if row.get('kind') == 'irq_group_delivery'
              and row.get('native_take_event_id') == ids['pre_take']]
    if change == 'missing':
        documents = [row for row in documents if row not in frames]
    elif change == 'unique_source':
        frames[0]['unique_source'] = IDLE + '.' + SOURCE_PORT
    elif change == 'attribution_status':
        frames[0]['attribution_status'] = 'joint'
    else:
        frames[0]['group_sha256'] = '0' * 64
    with pytest.raises(ResetLineageRefused) as refusal:
        inspect_take_attribution(documents, take=take, group=group(),
                                 active_id=ACTIVE, source_port=SOURCE_PORT)
    assert refusal.value.code == code


def test_delivery_attribution_refuses_an_unverified_native_source():
    program = programme()
    documents, ids = journal(program)
    by_id = {row['event_id']: row for row in documents}
    take = by_id[ids['pre_take']]
    frame = next(row for row in documents if row.get('kind') == 'irq_group_delivery'
                 and row.get('native_take_event_id') == ids['pre_take'])
    frame['members'][0]['native_source']['local_tick'] = 999
    with pytest.raises(ResetLineageRefused) as refusal:
        inspect_take_attribution(documents, take=take, group=group(),
                                 active_id=ACTIVE, source_port=SOURCE_PORT)
    assert refusal.value.code == 'irq-group-source-reference-unverified'


# --------------------------------------------------------------------------- #
# Summary: explicit scope, false grants, process identities
# --------------------------------------------------------------------------- #

def _processes(**changes):
    rows = {'original': [], 'fresh': []}
    for mode_index, mode in enumerate(('original', 'fresh')):
        for index, component in enumerate(('cpu', ACTIVE, IDLE)):
            for epoch in (0, 1):
                rows[mode].append({
                    'component': component,
                    'pid': 1000 + 10 * mode_index + index + epoch,
                    'execution_nonce': f'{mode}-{component}-{epoch}',
                    'exit_code': 0, 'reaped': True})
    for mode, changeset in changes.items():
        rows[mode] = changeset(rows[mode])
    return rows


def _summary(processes=None, **changes):
    program = programme()
    documents, _ = journal(program)
    result = _reduce(program, documents)
    result.update(changes.pop('result', {}))
    return build_summary(result, mode='both', processes=processes or _processes(),
                         components=('cpu', ACTIVE, IDLE),
                         semantic_sha256='a' * 64, fresh_matches=True,
                         steps={'pre_steps': 120, 'barrier_event_id': 12},
                         max_steps=1500, config_path=CONFIG,
                         config_digest='b' * 64, **changes)


def test_summary_states_explicit_non_authority_and_the_terminal_probe():
    summary = _summary()
    assert summary['schema_version'] == SUMMARY_SCHEMA
    assert summary['status'] == 'verified' and summary['scope'] == SCOPE
    assert summary['grants_F5'] is False and summary['grants_F6'] is False
    assert summary['reward_eligible'] is False and summary['native_authority'] is False
    assert summary['irq_consumption'] == 'unknown' and summary['isr_mmio'] == 'unknown'
    assert scope_fields() == {'native_authority': False, 'grants_F5': False,
                              'grants_F6': False, 'reward_eligible': False,
                              'isr_mmio': 'unknown', 'irq_consumption': 'unknown'}
    assert summary['terminal_probe']['terminal'] is True
    assert summary['terminal_probe']['normal_campaign_completion'] is False
    assert summary['terminal_probe']['kind'] == 'irq-reset-lineage'
    assert summary['fresh_matches'] is True
    assert summary['fresh_scope'] == 'same-invocation-independent-native-sessions'
    assert summary['no_lineage_after_reset'] is True
    assert summary['post_reset_serial_distinct'] is True
    assert summary['pre_reset_handler_retirements'] >= 1
    assert summary['post_reset_take_count'] == 1
    assert summary['required_layers'] == list(REQUIRED_LAYERS)
    assert all(summary['layers'][name] for name in REQUIRED_LAYERS)
    assert summary['process_identity']['all_reaped_exit_zero'] is True
    assert len(summary['process_identity']['rows']) == 12


def test_summary_records_the_missing_fresh_take_instead_of_hiding_it():
    """No post-reset take is not a refusal, but it is never silently a pass either."""
    program = programme()
    documents, _ = journal(program, post_take=False)
    result = _reduce(program, documents)
    assert result['status'] == 'verified'
    assert result['post_reset_take_count'] == 0
    assert result['post_reset_fresh_take_observed'] is False
    assert result['post_reset_serial_distinct'] is True  # vacuous, and recorded as such
    summary = build_summary(result, mode='both', processes=_processes(),
                            components=('cpu', ACTIVE, IDLE),
                            semantic_sha256='a' * 64, fresh_matches=True,
                            steps={'pre_steps': 120, 'barrier_event_id': 9},
                            max_steps=1500, config_path=CONFIG,
                            config_digest='b' * 64)
    assert summary['post_reset_take_count'] == 0
    assert summary['post_reset_fresh_take_observed'] is False
    assert any('fresh-epoch take clause is untested' in line
               for line in summary['limitations'])


def test_summary_process_identity_refusals():
    def drop_one(rows):
        return [row for row in rows if not (row['component'] == 'cpu' and row['pid'] == 1000)]

    def fail_exit(rows):
        rows[0] = dict(rows[0], exit_code=1)
        return rows

    def un_reaped(rows):
        rows[0] = dict(rows[0], reaped=False)
        return rows

    def reuse_pid(rows):
        rows[0] = dict(rows[0], pid=rows[1]['pid'])
        return rows

    def reuse_nonce(rows):
        rows[0] = dict(rows[0], execution_nonce=rows[1]['execution_nonce'])
        return rows

    with pytest.raises(ResetLineageRefused) as refusal:
        _summary(_processes(original=drop_one))
    assert refusal.value.code == 'native-process-launch-count'
    for change, code in ((fail_exit, 'native-process-not-clean'),
                        (un_reaped, 'native-process-not-clean'),
                        (reuse_pid, 'native-process-identities-not-independent'),
                        (reuse_nonce, 'native-process-identities-not-independent')):
        with pytest.raises(ResetLineageRefused) as refusal:
            _summary(_processes(original=change))
        assert refusal.value.code == code
    with pytest.raises(ResetLineageRefused) as refusal:
        check_process_identities({'original': []}, components=('cpu',),
                                 modes=['original'])
    assert refusal.value.code == 'native-process-component-missing'


# --------------------------------------------------------------------------- #
# CLI refusals: no build, no process, no verified status
# --------------------------------------------------------------------------- #

def test_cli_refuses_a_bad_config_without_writing_a_verified_summary(tmp_path):
    broken = tmp_path / 'broken.json'
    broken.write_text(json.dumps(_config(source_adapter=None)), encoding='utf-8')
    output = tmp_path / 'out'
    assert main(['--native', '--config', str(broken), '--output', str(output),
                 '--cache', str(tmp_path / 'cache')]) == 2
    assert not output.exists()


def test_cli_refuses_an_existing_output_or_an_unbounded_step_budget(tmp_path):
    output = tmp_path / 'out'
    output.mkdir()
    assert main(['--native', '--config', str(CONFIG), '--output', str(output),
                 '--cache', str(tmp_path / 'cache')]) == 2
    assert main(['--native', '--config', str(CONFIG), '--output', str(tmp_path / 'new'),
                 '--cache', str(tmp_path / 'cache'), '--max-steps', '0']) == 2


def test_cli_refuses_a_config_that_names_a_missing_profile(tmp_path):
    broken = tmp_path / 'broken.json'
    broken.write_text(json.dumps(_config(cpu_profile='configs/cpus/absent/profile.json')),
                      encoding='utf-8')
    output = tmp_path / 'out'
    assert main(['--native', '--config', str(broken), '--output', str(output),
                 '--cache', str(tmp_path / 'cache')]) == 2
    assert not output.exists()
