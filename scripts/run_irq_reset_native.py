#!/usr/bin/env python3
"""Directed native reset barrier between a real IRQ acceptance and its retirement.

One CPU session plus the two declared-output target sessions (the same public
factories ``scripts/run_timer_irq_smoke.py`` uses) run a fixed program that
performs the declared MMIO trigger writes; the organic target output travels
through the existing ``IrqDeliveryGroup`` OR group into the CPU's parsed
external-IRQ input and produces a real ``cpu_external_irq_taken``.  The run keeps
stepping until the taken handler has really retired instructions, then applies a
real ``ScenarioRunner.reset_all('warm_all')`` - a measured reset barrier in the
middle of a live handler, not an epoch bump and not a simulated event.  After the
barrier it steps a bounded budget and records every post-reset take and
retirement.

Lineage is judged exactly as the production consumer judges it:
``IrqSerialCertificates`` joins a decision token to a retirement token only when
both carry the same ``execution_id``, ``reset_epoch`` and component and the
tokens are nonzero and equal.  The passive sideband counter is cleared by the
same reset (``src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv``), so a
post-reset take legitimately repeats the *numeric* token of a pre-reset take; the
epoch is what makes the evidence distinct.  A post-reset retirement is refused
only when it really joins pre-reset lineage: it keeps the old epoch, joins a
pre-reset decision scope, or reuses a pre-reset take/receipt identity.

This is a directed evidence case.  It grants no F5/F6 authority, no storage
version, no ISR/MMIO claim and no reward.  It never runs without ``--native``,
and it never reports ``verified`` without a real barrier and a real journal.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

RESULT_SCHEMA = 'irq_reset_lineage.v1'
SUMMARY_SCHEMA = 'irq_reset_native_summary.v1'
TERMINAL_PROBE_SCHEMA = 'irq_reset_terminal_probe.v1'
CASE_ID = 'reset-then-irq'
RESET_POLICY = 'warm_all'
SCOPE = 'measured-reset-barrier-between-native-irq-decision-and-handler-retirement'
FRESH_SCOPE = 'same-invocation-independent-native-sessions'
REQUIRED_LAYERS = ('reset_barrier', 'no_lineage_after_reset', 'post_reset_fresh_epoch')
MEASURED_LAYERS = REQUIRED_LAYERS + ('irq_serial_certificate',)
REQUIRED_KEYS = frozenset((
    'schema_version', 'cpu_profile', 'source_request', 'source_adapter', 'source_port',
    'source_bit_offset', 'pulse_width_ticks', 'active_id', 'idle_id', 'active_base',
    'idle_base', 'trigger_writes', 'reset_policy', 'post_reset_steps'))
OPTIONAL_KEYS = frozenset(('case', 'notes'))
# The handler body must really have started before the barrier can be called a
# reset *inside* a handler, and the CPU input must still be asserted then; the
# smoke's own default is 16 ticks and this case declares a wider pulse.
MINIMUM_PULSE_WIDTH = 16
MAXIMUM_PULSE_WIDTH = 4096
MAXIMUM_POST_RESET_STEPS = 10000
_LINEAGE_LIMIT = 32
_RETIREMENT_LIMIT = 4096


class ResetLineageRefused(RuntimeError):
    """A measured reset case whose recorded evidence does not close."""

    def __init__(self, code, detail):
        super().__init__(code + ': ' + detail)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------- #
# Configuration: the source wiring is the smoke's own declaration, nothing new
# --------------------------------------------------------------------------- #

def validate_config(document):
    """Validate the reset-case configuration; return the normalized options."""
    if not isinstance(document, dict):
        raise ValueError('IRQ reset config must be a JSON object')
    unknown = sorted(set(document) - REQUIRED_KEYS - OPTIONAL_KEYS)
    if unknown:
        raise ValueError('undeclared IRQ reset config key: ' + ','.join(unknown))
    missing = sorted(REQUIRED_KEYS - set(document))
    if missing:
        raise ValueError('IRQ reset config requires: ' + ','.join(missing))
    from scripts.run_timer_irq_smoke import source_options
    try:
        wiring = source_options(document)
    except KeyError as error:  # a declared key with an unusable value
        raise ValueError('IRQ reset source wiring is incomplete: ' + str(error)) from error
    if wiring['source_adapter'] != 'declared-output.v1':
        raise ValueError('IRQ reset requires the declared-output.v1 source adapter')
    if wiring['active_base'] == wiring['idle_base']:
        raise ValueError('IRQ reset active and idle windows must differ')
    if not MINIMUM_PULSE_WIDTH <= wiring['pulse_width_ticks'] <= MAXIMUM_PULSE_WIDTH:
        raise ValueError('IRQ reset pulse width must stay asserted across handler entry: '
                         f'{MINIMUM_PULSE_WIDTH}..{MAXIMUM_PULSE_WIDTH} ticks')
    if document['reset_policy'] != RESET_POLICY:
        raise ValueError('IRQ reset policy must be the measured whole-scenario '
                         f'{RESET_POLICY} reset')
    steps = document['post_reset_steps']
    if type(steps) is not int or not 1 <= steps <= MAXIMUM_POST_RESET_STEPS:
        raise ValueError(f'IRQ reset post_reset_steps must be 1..{MAXIMUM_POST_RESET_STEPS}')
    case = document.get('case', CASE_ID)
    if type(case) is not str or not case.strip():
        raise ValueError('IRQ reset case id must be a non-empty string')
    if 'notes' in document and type(document['notes']) is not str:
        raise ValueError('IRQ reset notes must be a string')
    return dict(wiring, cpu_profile=document['cpu_profile'], case=case,
                reset_policy=document['reset_policy'],
                post_reset_steps=steps)


def resolve_config_paths(options, *, base_dir=ROOT):
    """Resolve the two declared profile paths without building anything."""
    paths = {}
    for name in ('cpu_profile', 'source_request'):
        declared = options[name]
        path = Path(declared)
        resolved = path if path.is_absolute() else Path(base_dir) / path
        if not resolved.is_file():
            raise ValueError('IRQ reset config references a missing ' + name + ': ' + declared)
        paths[name] = resolved
    return paths


def load_config(path, *, base_dir=ROOT):
    """Read, validate and resolve one configuration file."""
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    options = validate_config(document)
    resolve_config_paths(options, base_dir=base_dir)
    return document, options


# --------------------------------------------------------------------------- #
# Fixed program layout (the smoke's own firmware builder)
# --------------------------------------------------------------------------- #

def build_program(boot, *, active_base, trigger_writes, window_size):
    """The fixed ROM plus the declared trigger writes, with a checked layout."""
    from scripts.run_timer_irq_smoke import timer_program
    program = timer_program(boot, active_base,
                            trigger_writes=tuple(trigger_writes), window_size=window_size)
    bases = {int(base) for base in program['images']}
    if (type(boot) is not int or program.get('boot') != boot
            or not all(type(program.get(name)) is int
                       for name in ('vector', 'handler', 'park'))
            or not boot < program['park'] < program['vector'] <= program['handler']
            or bases != {boot, program['vector'], program['vector'] + 44,
                         program['handler']}):
        raise ValueError('fixed IRQ reset programme layout mismatch')
    return program


def handler_addresses(program):
    """Every fixed trap-path instruction address: the vector stubs and the handler."""
    addresses = set()
    for base, data in program['images'].items():
        start = int(base)
        if start == program['boot']:
            continue
        addresses.update(start + 4 * index
                         for index in range(len(bytes.fromhex(data)) // 4))
    if not addresses:
        raise ValueError('fixed IRQ reset programme has no trap-path image')
    return frozenset(sorted(addresses))


# --------------------------------------------------------------------------- #
# Journal reducers (pure; no session, no process, no clock)
# --------------------------------------------------------------------------- #

def _epoch(event):
    value = event.get('reset_epoch')
    return value if type(value) is int and value >= 0 else None


def _observed_token(event, role):
    """One physically observed, nonzero serial token; 0 means 'no lineage'."""
    document = event.get('irq_serial_observation')
    if not isinstance(document, dict):
        return None
    row = document.get(role)
    if not isinstance(row, dict) or row.get('status') != 'observed':
        return None
    value = row.get('value')
    return value if type(value) is int and value > 0 else None


def _take_identity(event):
    key = event.get('take_key')
    if (type(key) is not list or len(key) != 3 or type(key[0]) is not str
            or type(key[1]) is not int or key[1] < 0
            or type(key[2]) is not int or key[2] < 1):
        return None
    return (key[0], key[1], key[2])


def _receipt_identity(event):
    receipt = event.get('receipt_id')
    if not isinstance(receipt, dict):
        return None
    execution, sequence = receipt.get('execution'), receipt.get('sequence')
    if type(execution) is not str or not execution or type(sequence) is not int:
        return None
    return (execution, sequence)


def _decisions(events):
    """Every observed nonzero decision scope in one journal window."""
    rows = []
    for event in events:
        if event.get('kind') not in ('cpu_external_irq_sample', 'cpu_external_irq_taken'):
            continue
        token = _observed_token(event, 'decision')
        epoch = _epoch(event)
        if token is None or epoch is None:
            continue
        rows.append({'event_id': event['event_id'], 'kind': event.get('kind'),
                     'epoch': epoch, 'token': token,
                     'identity': _take_identity(event),
                     'receipt': _receipt_identity(event)})
    return rows


def _retirements(events):
    rows = []
    for event in events:
        if event.get('kind') != 'cpu_retire':
            continue
        rows.append({'event_id': event['event_id'], 'epoch': _epoch(event),
                     'token': _observed_token(event, 'retirement'),
                     'intr': event.get('intr'), 'pc_rdata': event.get('pc_rdata'),
                     'local_tick': event.get('local_tick'),
                     'receipt': _receipt_identity(event),
                     'producer_event_id': event.get('producer_event_id')})
    return rows


def _barrier(events, policy):
    barriers = [event for event in events if event.get('kind') == 'reset_barrier']
    if len(barriers) != 1:
        raise ResetLineageRefused('reset-barrier-missing',
                                  f'exactly one measured reset_barrier is required, saw {len(barriers)}')
    barrier = barriers[0]
    if barrier.get('policy') != policy:
        raise ResetLineageRefused('reset-policy-mismatch',
                                  'measured reset policy ' + str(barrier.get('policy'))
                                  + ' is not the declared ' + policy)
    if not isinstance(barrier.get('memory_generations'), dict) \
            or not barrier['memory_generations']:
        raise ResetLineageRefused('reset-barrier-incomplete',
                                  'the measured barrier carries no memory generations')
    return barrier


def _require_contiguous(events):
    if not events:
        raise ResetLineageRefused('journal-empty', 'the exported journal is empty')
    for position, event in enumerate(events, 1):
        if not isinstance(event, dict) or event.get('event_id') != position:
            raise ResetLineageRefused('journal-event-ids-not-contiguous',
                                      'event ' + str(position) + ' is not contiguous')
    return events


def _certificates(events):
    """The production exact-join consumer over the same real journal."""
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    consumer = IrqSerialCertificates()
    try:
        return consumer.ingest(events)
    except ValueError as error:
        raise ResetLineageRefused('irq-serial-consumer-refused', str(error)) from error


def reduce_lineage(events, program, *, epochs, policy=RESET_POLICY):
    """Derive the reset-lineage verdict from one exported journal.

    ``epochs`` is ``{'before': {component: int}, 'after': {component: int},
    'command_before': int, 'command_after': int}`` read from the live sessions
    around ``reset_all``.  Every refusal is a real cross-epoch join, never a
    numeric token repeat inside a new epoch.
    """
    events = list(_require_contiguous(events))
    history = handler_addresses(program)
    barrier = _barrier(events, policy)
    barrier_id = barrier['event_id']
    before = [event for event in events if event['event_id'] < barrier_id]
    after = [event for event in events if event['event_id'] > barrier_id]

    session_before = epochs.get('before') or {}
    session_after = epochs.get('after') or {}
    if (not session_before or not session_after
            or set(session_before) != set(session_after)
            or any(type(value) is not int for value in
                   (*session_before.values(), *session_after.values()))
            or not all(session_after[name] > session_before[name] for name in session_before)):
        raise ResetLineageRefused('epochs-did-not-advance',
                                  'every scenario session must advance its reset epoch: '
                                  + json.dumps({'before': session_before, 'after': session_after},
                                               sort_keys=True))
    if (type(epochs.get('command_before')) is not int
            or type(epochs.get('command_after')) is not int
            or epochs['command_after'] <= epochs['command_before']):
        raise ResetLineageRefused('epochs-did-not-advance',
                                  'the measured barrier must advance the runner command epoch')

    pre_takes = [event for event in before if event.get('kind') == 'cpu_external_irq_taken']
    if len(pre_takes) != 1:
        raise ResetLineageRefused('pre-reset-take-required',
                                  'exactly one pre-reset native take is required, saw '
                                  + str(len(pre_takes)))
    take = pre_takes[0]
    take_epoch = _epoch(take)
    take_token = _observed_token(take, 'decision')
    if take.get('irq_taken_pre') != 1 or take_token is None or take_epoch is None:
        raise ResetLineageRefused('pre-reset-take-not-accepted',
                                  'the pre-reset take lacks a real acceptance and decision token')

    handler = [row for row in _retirements(before)
               if row['event_id'] > take['event_id'] and row['pc_rdata'] in history]
    if not handler:
        raise ResetLineageRefused(
            'pre-reset-handler-retirement-required',
            'the barrier must interrupt a real handler: no trap-path retirement precedes it')

    pre_decisions = _decisions(before)
    pre_retirements = _retirements(before)
    post_decisions = _decisions(after)
    post_retirements = _retirements(after)
    post_takes = [event for event in after if event.get('kind') == 'cpu_external_irq_taken']

    for decision in pre_decisions:
        if decision['epoch'] >= take_epoch + 1:
            raise ResetLineageRefused(
                'pre-reset-decision-epoch-not-before-reset',
                'a pre-reset decision is stamped with the post-reset epoch: '
                + str(decision['epoch']))

    # Pre-reset lineage identities: an old-epoch scope (execution, epoch,
    # component), a take identity, and a receipt identity.
    pre_scopes = {(decision['epoch'], decision['token']) for decision in pre_decisions}
    pre_identities = {row['identity'] for row in pre_decisions if row['identity'] is not None}
    pre_receipts = {row['receipt'] for row in (*pre_decisions, *pre_retirements)
                    if row['receipt'] is not None}
    pre_take_keys = {_take_identity(take)} - {None}
    pre_event_ids = {decision['event_id'] for decision in pre_decisions}

    raw_reuse = []
    _seen_raw = set()
    for row in post_retirements:
        if row['token'] is None:
            continue
        # A retirement that names pre-reset evidence is stale, whatever epoch it
        # prints: it reuses a real pre-reset receipt, or the CPU step that
        # produced a pre-reset decision.
        if row['receipt'] is not None and row['receipt'] in pre_receipts:
            raise ResetLineageRefused(
                'post-reset-retirement-references-pre-reset-take-identity',
                'retirement event ' + str(row['event_id'])
                + ' reuses a pre-reset receipt identity')
        if row['producer_event_id'] in pre_event_ids:
            raise ResetLineageRefused(
                'post-reset-retirement-references-pre-reset-take-identity',
                'retirement event ' + str(row['event_id'])
                + ' references a pre-reset decision event')
        # The exact consumer join: same execution scope, same epoch, same
        # nonzero token, decision first. A numeric repeat in the NEW epoch is
        # not a join; a repeat inside the OLD epoch scope is.
        joined = [decision for decision in pre_decisions
                  if decision['epoch'] == row['epoch'] and decision['token'] == row['token']
                  and decision['event_id'] < row['event_id']]
        if joined:
            raise ResetLineageRefused(
                'post-reset-retirement-joins-pre-reset-serial',
                'retirement event ' + str(row['event_id']) + ' joins pre-reset decision '
                + str(joined[0]['event_id']) + ' at epoch ' + str(row['epoch']))
        if row['epoch'] is None or row['epoch'] <= take_epoch:
            raise ResetLineageRefused(
                'post-reset-retirement-carries-pre-reset-epoch',
                'retirement event ' + str(row['event_id']) + ' keeps reset epoch '
                + str(row['epoch']) + ' after the measured barrier')
        for decision in pre_decisions:
            pair = (decision['epoch'], decision['token'], row['event_id'])
            if decision['token'] == row['token'] and pair not in _seen_raw:
                _seen_raw.add(pair)
                if len(raw_reuse) < _LINEAGE_LIMIT:
                    raw_reuse.append({'pre_decision_event_id': decision['event_id'],
                                      'post_retirement_event_id': row['event_id'],
                                      'token': row['token'],
                                      'pre_epoch': decision['epoch'],
                                      'post_epoch': row['epoch']})
    joins = []

    post_epoch = take_epoch + 1
    fresh_takes = []
    for event in post_takes:
        epoch = _epoch(event)
        identity = _take_identity(event)
        token = _observed_token(event, 'decision')
        if event.get('irq_taken_pre') != 1 or token is None:
            raise ResetLineageRefused('post-reset-take-not-accepted',
                                      'post-reset take event ' + str(event['event_id'])
                                      + ' lacks a real acceptance and decision token')
        if identity is None:
            raise ResetLineageRefused('post-reset-take-identity-malformed',
                                      'post-reset take event ' + str(event['event_id'])
                                      + ' has no exact take identity')
        if identity in pre_identities or identity in pre_take_keys:
            raise ResetLineageRefused(
                'post-reset-take-reuses-pre-reset-identity',
                'post-reset take event ' + str(event['event_id'])
                + ' reuses a pre-reset take identity')
        receipt = _receipt_identity(event)
        if receipt is not None and receipt in pre_receipts:
            raise ResetLineageRefused(
                'post-reset-take-reuses-pre-reset-identity',
                'post-reset take event ' + str(event['event_id'])
                + ' reuses a pre-reset receipt identity')
        if epoch != post_epoch:
            raise ResetLineageRefused(
                'post-reset-take-epoch-not-fresh',
                'post-reset take event ' + str(event['event_id']) + ' carries epoch '
                + str(epoch) + ' instead of the measured ' + str(post_epoch))
        if identity[1] != epoch or identity[0] != event.get('component'):
            raise ResetLineageRefused(
                'post-reset-take-identity-scope-mismatch',
                'post-reset take event ' + str(event['event_id'])
                + ' claims take identity ' + json.dumps(list(identity))
                + ' inside an event stamped ' + json.dumps(
                    {'component': event.get('component'), 'reset_epoch': epoch}))
        if (epoch, token) in pre_scopes:
            raise ResetLineageRefused(
                'post-reset-take-reuses-pre-reset-serial',
                'post-reset take event ' + str(event['event_id'])
                + ' reuses the pre-reset decision scope')
        fresh_takes.append({'event_id': event['event_id'], 'epoch': epoch,
                            'token': token, 'identity': identity,
                            'local_tick': event.get('local_tick'),
                            'producer_event_id': event.get('producer_event_id')})

    post_tokens = {(item['epoch'], item['token']) for item in fresh_takes}
    distinct = (len(post_tokens) == len(fresh_takes)
                and not (post_tokens & pre_scopes))
    if not distinct:
        raise ResetLineageRefused(
            'post-reset-serial-not-distinct',
            'post-reset takes reuse a decision scope: '
            + json.dumps(sorted(post_tokens), sort_keys=True))

    certificates = _certificates(events)
    pre_certificates = [row for row in certificates
                        if row['retirement_event_id'] < barrier_id]
    post_certificates = [row for row in certificates
                         if row['retirement_event_id'] > barrier_id]
    if any(row['reset_epoch'] <= take_epoch for row in post_certificates):
        raise ResetLineageRefused(
            'post-reset-certificate-joins-pre-reset-epoch',
            'the production serial consumer certified a post-barrier retirement in the '
            'pre-reset epoch')

    linked = []
    for row in fresh_takes:
        matches = [retirement for retirement in post_retirements
                   if retirement['token'] == row['token']
                   and retirement['epoch'] == row['epoch']
                   and retirement['event_id'] > row['event_id']]
        if matches:
            linked.append({'take_event_id': row['event_id'],
                           'retirement_event_id': matches[0]['event_id'],
                           'token': row['token'], 'epoch': row['epoch'],
                           'pc_rdata': matches[0]['pc_rdata'],
                           'intr': matches[0]['intr'],
                           'local_tick': matches[0]['local_tick']})

    if not pre_certificates:
        raise ResetLineageRefused(
            'pre-reset-certificate-missing',
            'the pre-reset decision and its handler retirement do not certify one join')

    entry = handler[0]
    return {
        'schema_version': RESULT_SCHEMA,
        'status': 'verified',
        'scope': SCOPE,
        'case': CASE_ID,
        'reset_policy': policy,
        'barrier': {
            'event_id': barrier_id, 'policy': barrier['policy'],
            'memory_generations': dict(barrier['memory_generations']),
            'cancelled_responses': dict(barrier.get('cancelled_responses') or {}),
            'cancelled_target_requests': dict(barrier.get('cancelled_target_requests') or {}),
            'cancelled_irq_pulses': dict(barrier.get('cancelled_irq_pulses') or {}),
            'cancelled_irq_pulse_count': sum(
                (barrier.get('cancelled_irq_pulses') or {}).values()),
            'cancelled_dataflow_targets': list(barrier.get('cancelled_dataflow_targets') or ()),
            'pending_events_before_reset': dict(
                barrier.get('pending_events_before_reset') or {}),
            'pending_events_after_reset': dict(
                barrier.get('pending_events_after_reset') or {}),
        },
        'epochs': {
            'advanced': True,
            'pre_reset_epoch': take_epoch,
            'post_reset_epoch': post_epoch,
            'command_epoch': {'before': epochs['command_before'],
                              'after': epochs['command_after']},
            'sessions': {'before': dict(session_before), 'after': dict(session_after)},
        },
        'pre_reset': {
            'take': {'event_id': take['event_id'],
                     'decision_serial': take_token,
                     'reset_epoch': take_epoch,
                     'take_key': list(take.get('take_key') or ()),
                     'local_tick': take.get('local_tick'),
                     'producer_event_id': take.get('producer_event_id')},
            'decision_tokens': sorted({row['token'] for row in pre_decisions}),
            'decision_observations': len(pre_decisions),
            'retirement_count': len(pre_retirements),
            'handler_retirements': len(handler),
            'handler_retirement_events': [row['event_id'] for row in handler],
            'handler_entry': {'event_id': entry['event_id'],
                              'pc_rdata': entry['pc_rdata'],
                              'intr': entry['intr'],
                              'retirement_serial': entry['token'],
                              'local_tick': entry['local_tick']},
            'certificates': len(pre_certificates),
        },
        'post_reset': {
            'take_count': len(fresh_takes),
            'takes': fresh_takes,
            'retirement_count': len(post_retirements),
            'retirement_fields': ['event_id', 'reset_epoch', 'retirement_serial',
                                  'intr', 'pc_rdata'],
            'retirements': [[row['event_id'], row['epoch'], row['token'], row['intr'],
                             row['pc_rdata']] for row in post_retirements[:_RETIREMENT_LIMIT]],
            'retirements_truncated': len(post_retirements) > _RETIREMENT_LIMIT,
            'retirement_journal': 'events.json (cpu_retire rows with this reset_epoch)',
            'interrupt_retirements': sum(1 for row in post_retirements
                                         if row['intr'] == 1),
            'linked_retirements': linked,
            'certificates': len(post_certificates),
            'certificate_epochs': sorted({row['reset_epoch'] for row in post_certificates}),
        },
        'lineage': {
            'no_lineage_after_reset': True,
            'serial_identity_scope': 'epoch_qualified_token_and_take_identity',
            'join_semantics': ('exact (execution_id, reset_epoch, component, token) equality '
                               'with a nonzero token and a decision that precedes the '
                               'retirement, as IrqSerialCertificates computes it'),
            'raw_pre_reset_tokens': sorted({row['token'] for row in pre_decisions}),
            'raw_post_reset_tokens': sorted({row['token'] for row in post_decisions}),
            'raw_token_reuse_across_reset': raw_reuse,
            'raw_token_reuse_count': len(raw_reuse),
            'raw_token_reuse_is_not_lineage': True,
            'cross_epoch_joins': joins,
        },
        'barrier_observed': True,
        'epochs_advanced': True,
        'no_lineage_after_reset': True,
        'pre_reset_handler_retirements': len(handler),
        'post_reset_take_count': len(fresh_takes),
        'post_reset_serial_distinct': bool(distinct),
        'post_reset_fresh_take_observed': bool(fresh_takes),
        'post_reset_fresh_retirement_observed': bool(linked),
        'layers': {'reset_barrier': True,
                   'no_lineage_after_reset': True,
                   'post_reset_fresh_epoch': post_epoch == take_epoch + 1,
                   'irq_serial_certificate': bool(pre_certificates)},
        'serial_certificates': {'total': len(certificates),
                                'pre_reset': len(pre_certificates),
                                'post_reset': len(post_certificates)},
    }


def inspect_take_attribution(events, *, take, group, active_id, source_port,
                             source_bit_offset=0):
    """The real OR frame and native source of one take, re-derived from the journal."""
    by_id = {event['event_id']: event for event in events}
    frames = [event for event in events if event.get('kind') == 'irq_group_delivery'
              and event.get('native_take_event_id') == take['event_id']]
    if len(frames) != 1:
        raise ResetLineageRefused('irq-group-delivery-missing',
                                  'the native take has no unique delivery frame: '
                                  + str(len(frames)))
    frame = frames[0]
    expected = active_id + '.' + source_port
    if (frame.get('group_id') != group.group_id
            or frame.get('group_sha256') != group.identity_sha256
            or frame.get('attribution_status') != 'unique'
            or frame.get('unique_source') != expected
            or frame.get('active_sources') != [expected]
            or frame.get('value') != 1
            or frame.get('target_epoch') != take.get('reset_epoch')):
        raise ResetLineageRefused('irq-group-attribution-not-unique',
                                  'the take is not uniquely attributed to ' + expected)
    member, = [row for row in frame['members'] if row.get('source_id') == expected]
    reference = member.get('native_source') or {}
    pulse = by_id.get(reference.get('event_id'))
    raw = (pulse or {}).get('outputs', {}).get(source_port)
    if (pulse is None or pulse.get('kind') != 'local_tick_sample'
            or pulse.get('component') != active_id
            or pulse.get('phase') != reference.get('phase')
            or pulse.get('local_tick') != reference.get('local_tick')
            or pulse.get('reset_epoch') != reference.get('reset_epoch')
            or type(raw) is not int or not (raw >> source_bit_offset) & 1):
        raise ResetLineageRefused('irq-group-source-reference-unverified',
                                  'the delivery frame does not reference the declared native '
                                  'output sample')
    return {'delivery_event_id': frame['event_id'],
            'group_id': group.group_id,
            'group_sha256': group.identity_sha256,
            'attribution_status': 'unique',
            'unique_source': expected,
            'native_take_event_id': take['event_id'],
            'native_source_event_id': reference['event_id'],
            'native_source_tick': reference['local_tick'],
            'native_source_epoch': reference['reset_epoch'],
            'source_bit_offset': source_bit_offset,
            'raw_output': raw}


# --------------------------------------------------------------------------- #
# Process identities: the pre-reset and post-reset launch of every component
# --------------------------------------------------------------------------- #

def check_process_identities(processes, *, components, modes):
    """Every component shows both native launches, reaped, exit 0, independent."""
    rows = []
    seen = {}
    for mode in modes:
        identities = processes.get(mode) or ()
        per_component = {}
        for row in identities:
            per_component.setdefault(row.get('component'), []).append(row)
        if set(per_component) != set(components):
            raise ResetLineageRefused(
                'native-process-component-missing',
                mode + ' did not launch every component: '
                + json.dumps(sorted(str(name) for name in per_component), sort_keys=True))
        for component in components:
            launched = per_component[component]
            if len(launched) != 2:
                raise ResetLineageRefused(
                    'native-process-launch-count',
                    mode + '/' + component + ' must show the pre-reset and post-reset '
                    'launch, saw ' + str(len(launched)))
            for row in launched:
                if (type(row.get('pid')) is not int or row['exit_code'] != 0
                        or row.get('reaped') is not True
                        or type(row.get('execution_nonce')) is not str
                        or not row['execution_nonce']):
                    raise ResetLineageRefused(
                        'native-process-not-clean',
                        mode + '/' + component + ' has a process without a clean reaped exit 0')
                key = (component, row.get('pid'), row['execution_nonce'])
                if key in seen:
                    raise ResetLineageRefused(
                        'native-process-identities-not-independent',
                        'a process identity was reused: ' + json.dumps(key[:-1]))
                seen[key] = mode
                rows.append({'mode': mode, 'component': component, 'pid': row['pid'],
                             'execution_nonce': row['execution_nonce'],
                             'exit_code': row['exit_code'], 'reaped': row['reaped']})
    pids = {}
    nonces = {}
    for row in rows:
        pids.setdefault(row['component'], set()).add(row['pid'])
        nonces.setdefault(row['component'], set()).add(row['execution_nonce'])
    expected = 2 * len(modes)
    for component in components:
        if len(pids[component]) != expected:
            raise ResetLineageRefused(
                'native-process-identities-not-independent',
                component + ' reused a pid across the fresh invocation')
        if len(nonces[component]) != expected:
            raise ResetLineageRefused(
                'native-process-identities-not-independent',
                component + ' reused an execution nonce')
    return {'scope': 'per-component-pre-reset-and-post-reset-launches',
            'all_reaped_exit_zero': True, 'rows': rows}


# --------------------------------------------------------------------------- #
# One real native session
# --------------------------------------------------------------------------- #

def flush_component_facts(runner, component):
    """Drain buffered session facts between steps (here: the barrier's cpu_reset).

    ``ScenarioRunner`` drains a session's buffered facts while it steps that
    session.  The ``cpu_reset`` fact the barrier produces would then be consumed
    *inside* the CPU step, and its group-reset semantics would clear the installed
    IRQ-group frame before ``finish_step``.  Draining it immediately after the
    barrier keeps the fact (and its epoch) in the journal without breaking the
    frame.  This is the same private drain the runner itself uses.
    """
    return runner._append_external_events(component, runner.event_count)


def execute_once(artifacts, program, options, *, base, cache, output, max_steps):
    """Run one real native session through the barrier and export its journal."""
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner
    from scripts.run_timer_irq_smoke import target_session
    output.mkdir()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                              initialization_seed=0, max_initialized_bytes=0x20000)
    memory.preload(program['marker'], bytes(8))
    for address, data in program['images'].items():
        memory.preload(int(address), bytes.fromhex(data))
    active, idle = options['active_id'], options['idle_id']
    sources = {name: target_session(artifacts[name], base=base, cache=cache)
               for name in (active, idle)}
    router = DataflowRouter(tuple(
        DeviceWindow(name, options['active_base'] if name == active else options['idle_base'],
                     session.artifact.plan.profile.address.window_size, session)
        for name, session in sources.items()))
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=base, cache_dir=cache, memory=memory,
                               router=router, native_irq_receipts=True,
                               physical_tick_samples=True)
    group = IrqDeliveryGroup('irq-reset-or', 'cpu', cpu.irq_input_port,
                             tuple(IrqDeliveryMember(name, options['source_port'],
                                                     pulse_width_ticks=options['pulse_width_ticks'],
                                                     source_bit_offset=options['source_bit_offset'],
                                                     source_adapter=options['source_adapter'])
                                   for name in sources))
    fields = [InputField('cpu', cpu.irq_input_port, 1)]
    owners = [InputOwner('cpu', cpu.irq_input_port, 0, 1, 'bound', group.owner_ref)]
    for name, source in sources.items():
        for row in source.artifact.runtime_document['fixed_physical_inputs']:
            port = row['endpoint_id'] + '.' + row['role']
            fields.append(InputField(name, port, row['width']))
            owners.append(InputOwner(name, port, 0, row['width'], 'fixed', 'profile_constant'))
    runner = ScenarioRunner(sessions={'cpu': cpu, **sources},
                            ownership=compile_ownership(tuple(fields), tuple(owners)),
                            bindings=group.member_bindings(),
                            irq_delivery_groups=(group,))
    for session in runner.sessions.values():
        session.configure_built_executable_receipt()
    for name in sources:
        # The installed observer validates its actual WB raw fields.
        if runner.install_protocol_checker(name) is None:
            raise ValueError('actual target protocol checker required')
    result = None
    stats = {}
    with record_local_commands() as recording:
        try:
            runner.begin_test('irq-reset-lineage')
            # Actual reset-idle samples before any CPU clock.
            for name in sources:
                runner.step(name)
            take = None
            entry = None
            pre_steps = 0
            cursor = 0
            for _ in range(max_steps):
                runner.step('cpu')
                for name in router.ready_targets:
                    runner.step(name)
                for name in sources:
                    runner.step(name)
                pre_steps += 1
                for event in runner._event_refs_since(cursor):
                    kind = event.get('kind')
                    if kind == 'cpu_external_irq_taken' and take is None:
                        take = {'event_id': event['event_id'],
                                'take_key': list(event.get('take_key') or ()),
                                'reset_epoch': event.get('reset_epoch'),
                                'local_tick': event.get('local_tick')}
                    elif (take is not None and entry is None and kind == 'cpu_retire'
                            and event.get('pc_rdata') == program['handler']):
                        entry = {'event_id': event['event_id'],
                                 'pc_rdata': event.get('pc_rdata'),
                                 'local_tick': event.get('local_tick')}
                cursor = runner.event_count
                if take is not None and entry is not None:
                    break
            else:
                raise ValueError('pre-reset IRQ take/handler retirement step budget exhausted')
            epochs_before = {name: session.reset_epoch
                             for name, session in runner.sessions.items()}
            command_before = runner.command_epoch
            # The real whole-scenario reset: every session relaunches its actual
            # RTL process, memory follows the declared policy and the barrier
            # carries its own generations and cancellations.
            reset = runner.reset_all(RESET_POLICY)
            epochs_after = {name: session.reset_epoch
                            for name, session in runner.sessions.items()}
            command_after = runner.command_epoch
            flush_component_facts(runner, 'cpu')
            # Fresh-epoch native source samples before the next CPU clock.
            for name in sources:
                runner.step(name)
            reset_cursor = runner.event_count
            for _ in range(options['post_reset_steps']):
                runner.step('cpu')
                for name in router.ready_targets:
                    runner.step(name)
                for name in sources:
                    runner.step(name)
            post_cursor = runner.event_count
            if post_cursor <= reset_cursor:
                raise ValueError('post-reset phase recorded no native evidence')
            events = list(runner.events)
            epochs = {'before': epochs_before, 'after': epochs_after,
                      'command_before': command_before, 'command_after': command_after}
            result = reduce_lineage(events, program, epochs=epochs,
                                    policy=RESET_POLICY)
            by_id = {event['event_id']: event for event in events}
            pre_take = by_id[result['pre_reset']['take']['event_id']]
            result['delivery'] = inspect_take_attribution(
                events, take=pre_take, group=group, active_id=active,
                source_port=options['source_port'],
                source_bit_offset=options['source_bit_offset'])
            if result['post_reset']['take_count']:
                post_take = by_id[result['post_reset']['takes'][0]['event_id']]
                result['post_reset']['delivery'] = inspect_take_attribution(
                    events, take=post_take, group=group, active_id=active,
                    source_port=options['source_port'],
                    source_bit_offset=options['source_bit_offset'])
            result['native'] = True
            result['epochs']['reset_result'] = {
                'policy': reset.policy,
                'memory_generations': dict(reset.memory_generations),
                'cancelled_responses': dict(reset.cancelled_responses)}
            result['steps'] = {'pre_reset': pre_steps,
                               'post_reset': options['post_reset_steps']}
            stats = {'pre_steps': pre_steps, 'barrier_event_id':
                     result['barrier']['event_id']}
        except BaseException as error:
            save(output / 'failure.json', dict(error_type=type(error).__name__,
                                               error=str(error),
                                               code=getattr(error, 'code', None)))
            raise
        finally:
            try:
                runner.finalize()
            finally:
                save(output / 'events.json', runner.events)
                save(output / 'local_commands.json', recording.export_sessions())
                save(output / 'executions.json', recording.export_executions())
    identities = recording.export_executions()
    if result is None:
        raise ValueError('native session produced no reset-lineage evidence')
    save(output / 'result.json', result)
    return result, identities, stats


# --------------------------------------------------------------------------- #
# Scope, summary and CLI
# --------------------------------------------------------------------------- #

def scope_fields():
    """Explicit non-authority: this case certifies one reset lineage hop only."""
    return {'native_authority': False, 'grants_F5': False, 'grants_F6': False,
            'reward_eligible': False, 'isr_mmio': 'unknown',
            'irq_consumption': 'unknown'}


def build_summary(result, *, mode, processes, components, semantic_sha256,
                  fresh_matches, steps, max_steps, config_path, config_digest):
    """The explicit summary document; every authority field stays false."""
    fields = scope_fields()
    identity = check_process_identities(processes, components=components, modes=list(processes))
    document = {
        'schema_version': SUMMARY_SCHEMA,
        'status': 'verified',
        'case': result['case'],
        'scope': SCOPE,
        'native': True,
        'mode': mode,
        'fresh_matches': fresh_matches,
        'fresh_scope': (FRESH_SCOPE if mode == 'both' else 'single-invocation'),
        'semantic_sha256': semantic_sha256,
        'processes': {name: [dict(row) for row in rows]
                      for name, rows in processes.items()},
        'process_identity': identity,
        'result': result,
        'barrier_observed': result['barrier_observed'],
        'epochs_advanced': result['epochs_advanced'],
        'no_lineage_after_reset': result['no_lineage_after_reset'],
        'post_reset_serial_distinct': result['post_reset_serial_distinct'],
        'pre_reset_handler_retirements': result['pre_reset_handler_retirements'],
        'post_reset_take_count': result['post_reset_take_count'],
        'post_reset_fresh_take_observed': result['post_reset_fresh_take_observed'],
        'layers': dict(result['layers']),
        'required_layers': list(REQUIRED_LAYERS),
        'measured_layers': list(MEASURED_LAYERS),
        'steps': steps,
        'max_steps': max_steps,
        'config': {'path': str(config_path), 'sha256': config_digest},
        **fields,
        'terminal_probe': {
            'schema_version': TERMINAL_PROBE_SCHEMA,
            'terminal': True,
            'kind': 'irq-reset-lineage',
            'reset_policy': result['reset_policy'],
            'barrier_event_id': result['barrier']['event_id'],
            'pre_reset_epoch': result['epochs']['pre_reset_epoch'],
            'post_reset_epoch': result['epochs']['post_reset_epoch'],
            'normal_campaign_completion': False,
        },
        'limitations': ([
            'One directed case: a real reset barrier between one native IRQ '
            'acceptance and its handler retirement.',
            'Lineage is exact epoch-qualified serial identity, not a propagation '
            'chain, an instruction origin or an ISR effect.',
            'The passive serial counter is cleared by the same reset, so a post-reset '
            'take may repeat the numeric token of a pre-reset take; only the epoch '
            'and the take identity distinguish the evidence.',
            'No F5/F6 authority, no storage version, no ISR/MMIO claim and no reward.',
            'Native authority remains with the frozen-window acceptance process.',
        ] + ([] if result['post_reset_fresh_take_observed'] else [
            'The bounded post-reset phase observed no fresh take: lineage '
            'invalidation and the epoch advance are verified, but the '
            'fresh-epoch take clause is untested in this run. Raise '
            'post_reset_steps (config) or --max-steps and re-run.',
        ])),
    }
    return document


def refusal_summary(*, code, detail, stage, mode, native=True, **extra):
    document = {
        'schema_version': SUMMARY_SCHEMA,
        'status': 'refused',
        'case': CASE_ID,
        'scope': 'irq-reset-lineage-refusal',
        'native': native,
        'mode': mode,
        'fresh_matches': None,
        'refusal': {'code': code, 'reason': detail, 'stage': stage},
        'terminal_probe': {'schema_version': TERMINAL_PROBE_SCHEMA, 'terminal': True,
                           'kind': 'irq-reset-lineage', 'normal_campaign_completion': False},
        **scope_fields(),
        'limitations': ['A refusal is never a pass: no verified status was written.'],
    }
    document.update(extra)
    return document


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def artifact_for(base, relative, instance_id):
    """Build one local harness artifact through the public factory."""
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                      render_local_harness, render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    document = json.loads((Path(base) / relative).read_text(encoding='utf-8'))
    document['instance_id'] = instance_id
    plan = plan_local_harness(load_local_harness_request(document), base_dir=base)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
                               verify_local_source_lock(plan.profile, base_dir=base),
                               base_dir=base), base_dir=base)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--config', type=Path,
                        default=ROOT / 'configs/scenarios/directed-irq-reset/ibex-wb-timer.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, default=1500)
    parser.add_argument('--mode', choices=('original', 'fresh', 'both'), default='both')
    args = parser.parse_args(argv)
    base = Path(__file__).resolve().parents[1]
    if not 1 <= args.max_steps <= 10000:
        print(json.dumps({'status': 'refused', 'code': 'invalid-max-steps',
                          'reason': 'bounded positive max-steps required'}, sort_keys=True))
        return 2
    if args.output.exists():
        print(json.dumps({'status': 'refused', 'code': 'output-exists',
                          'reason': 'IRQ reset output must not exist'}, sort_keys=True))
        return 2
    try:
        document, options = load_config(args.config, base_dir=base)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'code': 'configuration-refused',
                          'reason': str(error)}, sort_keys=True))
        return 2
    args.output.mkdir(parents=True)
    save(args.output / 'config.json', document)
    modes = ('original', 'fresh') if args.mode == 'both' else (args.mode,)
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    results = {}
    processes = {}
    stats = {}
    try:
        with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
                execution_validation_scope():
            from myfuzz.scenario.ibex_pulp_dual_source import _artifact
            artifacts = {'cpu': _artifact(options['cpu_profile'], 'cpu')}
            artifacts.update({name: artifact_for(base, options['source_request'], name)
                              for name in (options['active_id'], options['idle_id'])})
            boot = source_backed_boot_fetch(
                artifacts['cpu'].plan.profile, base_dir=base,
                configured_boot_base=artifacts['cpu'].runtime_document
                ['boot_contract']['configured_boot_base'])
            program = build_program(boot, active_base=options['active_base'],
                                    trigger_writes=options['trigger_writes'],
                                    window_size=artifacts[options['active_id']]
                                    .plan.profile.address.window_size)
            save(args.output / 'program.json', program)
            for name, artifact in artifacts.items():
                save(args.output / (name + '-artifact.json'), artifact.runtime_document)
            for mode in modes:
                result, identities, step_counts = execute_once(
                    artifacts, program, options, base=base, cache=args.cache,
                    output=args.output / mode, max_steps=args.max_steps)
                results[mode] = result
                processes[mode] = [dict(row) for row in identities]
                stats[mode] = step_counts
        if args.mode == 'both':
            for component in artifacts:
                rows = {mode: [row for row in processes[mode]
                               if row.get('component') == component]
                        for mode in modes}
                if any(len(rows[mode]) != 2 for mode in modes):
                    raise ResetLineageRefused(
                        'native-process-launch-count',
                        component + ' must show the pre-reset and post-reset launch in both '
                        'invocations')
                for name in ('pid', 'execution_nonce'):
                    values = [row[name] for mode in modes for row in rows[mode]]
                    if any(type(value) is int and value <= 0 for value in values) \
                            or len(set(values)) != len(values):
                        raise ResetLineageRefused(
                            'native-process-identities-not-independent',
                            component + ' reused a ' + name + ' across the fresh invocation')
            if results['original'] != results['fresh']:
                raise ResetLineageRefused('fresh-semantic-mismatch',
                                          'the two independent native sessions disagree')
        primary = results['original' if 'original' in results else modes[0]]
        digest = sha256(json.dumps(primary, sort_keys=True).encode()).hexdigest()
        summary = build_summary(
            primary, mode=args.mode, processes=processes,
            components=tuple(artifacts),
            semantic_sha256=digest,
            fresh_matches=(results['original'] == results['fresh']
                           if args.mode == 'both' else None),
            steps=stats['original' if 'original' in stats else modes[0]],
            max_steps=args.max_steps,
            config_path=args.config,
            config_digest=sha256(Path(args.config).read_bytes()).hexdigest())
        save(args.output / 'summary.json', summary)
    except ResetLineageRefused as error:
        summary = refusal_summary(code=error.code, detail=error.detail,
                                 stage='reset-lineage', mode=args.mode,
                                 results={name: result for name, result in results.items()})
        save(args.output / 'summary.json', summary)
        print(json.dumps({'status': 'refused', 'code': error.code,
                          'reason': error.detail, 'output': str(args.output)},
                         sort_keys=True))
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        summary = refusal_summary(code='case-execution-failed', detail=str(error),
                                  stage='native-execution', mode=args.mode)
        save(args.output / 'summary.json', summary)
        print(json.dumps({'status': 'refused', 'code': 'case-execution-failed',
                          'reason': str(error), 'output': str(args.output)},
                         sort_keys=True))
        return 2
    except Exception as error:  # a real native failure is never a pass either
        detail = type(error).__name__ + ': ' + str(error)
        summary = refusal_summary(code='native-execution-failed', detail=detail,
                                  stage='native-execution', mode=args.mode)
        save(args.output / 'summary.json', summary)
        print(json.dumps({'status': 'refused', 'code': 'native-execution-failed',
                          'reason': detail, 'output': str(args.output)}, sort_keys=True))
        return 2
    print(json.dumps({'status': 'verified', 'mode': args.mode,
                      'barrier_event_id': primary['barrier']['event_id'],
                      'no_lineage_after_reset': primary['no_lineage_after_reset'],
                      'post_reset_take_count': primary['post_reset_take_count'],
                      'output': str(args.output)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
