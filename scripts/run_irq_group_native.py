#!/usr/bin/env python3
"""Two declared-output IRQ targets in one real host OR group (native case).

The case builds exactly the same public objects as the single-source smoke
script: the generated target sessions, one ``GeneratedCve2Session`` CPU with
native IRQ receipts, one ``DataflowRouter`` and one ``IrqDeliveryGroup`` whose
members are the two declared outputs.  One fixed CPU program performs the
declared MMIO trigger writes in order and parks; no host pulse is injected and
no per-CPU/IP executor is added.

The OR group delivers 1 as soon as the FIRST member pulse rises and the CPU
takes on that tick, so two enabled triggers always yield a take unique to the
first member.  The joint case therefore reuses the masked bootstrap idiom of the
existing fixed program (``scripts/run_cv32e20_irq_smoke.fixed_program``: a
``csrrc mstatus, 8`` phase and a later ``csrrs mstatus, 8`` enable): the fixed
case program clears ``mstatus.MIE``, performs both declared trigger writes in
order, sets ``mstatus.MIE`` and parks.  The one real take then happens with both
native pulses high.  This is real CPU CSR state, never a host-invented pulse,
and the pulse widths are bounded below by the enable->take latency and above by
the ISR return (a still-high OR after ``MRET`` would produce a second take and
the shared observer requires exactly one).

Attribution is never assumed.  Every reported fact is re-derived from the actual
journal:

* the trigger deliveries are the actual ``mmio_delivery`` writes in plan order
  at ``base + offset`` with the declared value;
* each member's pulse is that target's own ``local_tick_sample`` at the frame's
  ``native_source`` reference, read from ``outputs.physical[runtime_name]`` with
  its declared bit;
* the OR frame is the one joined to the **single** native take at the take tick;
* ``observe_declared_irq_consumption`` (the shared layered observer of the F5
  work) is the authority for the observation document.

``expected_attribution='joint'`` requires two active members at the take tick,
both members' raw pulse bits at 1 in their own real samples, and the shared
observer to refuse with ``status='ambiguous'``, ``irq_consumption='unknown'``
and the exact ``declared-F5-OR-attribution-not-unique`` refusal while claiming
no credit.  ``expected_attribution='unique'`` requires exactly one active member
and the full verified consumption document (``status='verified'``,
``irq_consumption='verified'``, value joins) through the same observer.

``--mode both`` runs two independent native sessions and requires semantic
equality, per-component distinct pid/execution nonce and clean reaped exits.

No F5 pin grammar, F6 storage version, ISR authority or reward is granted:
``grants_F5``, ``grants_F6`` and ``reward_eligible`` are always false.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile

SCHEMA_VERSION = 'irq_group_native_config.v1'
PROGRAM_SCHEMA = 'irq_group_native_program.v1'
CASE_SCHEMA = 'irq_group_native_case.v1'
SUMMARY_SCHEMA = 'irq_group_native_summary.v1'
ATTRIBUTIONS = ('joint', 'unique')
#: The exact refusal the shared layered observer returns for a joint OR frame.
REFUSAL_AMBIGUOUS = 'declared-F5-OR-attribution-not-unique'
ZERO_GRANTS = dict(reward_eligible=False, grants_F5=False, grants_F6=False,
                   grants_prerequisites=False)
MRET_WORD = 0x30200073
MSTATUS_MIE = 8
CSR_MSTATUS = 0x300
SETTLE_TICKS = 8


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def read(path):
    return json.loads(Path(path).read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def semantic_digest(document):
    return sha256(canonical(document).encode()).hexdigest()


def _require(condition, reason):
    if not condition:
        raise ValueError('irq-group-' + reason)


# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------
def case_options(config):
    """Validate the case declaration and return the resolved options.

    A case is two declared-output members of one OR group (the same real group
    in every config of a family), one ordered trigger plan and one expectation.
    The two target bases must be distinct page-aligned windows because the real
    router refuses overlapping windows.
    """
    _require(isinstance(config, dict), 'configuration-shape')
    _require(config.get('schema_version') == SCHEMA_VERSION, 'configuration-schema')
    cpu_profile = config.get('cpu_profile')
    _require(type(cpu_profile) is str and cpu_profile, 'configuration-cpu-profile')
    expected = config.get('expected_attribution')
    _require(expected in ATTRIBUTIONS, 'configuration-expected-attribution')
    gate = config.get('mie_gate')
    _require(type(gate) is bool, 'configuration-mie-gate')
    if expected == 'joint':
        _require(gate is True, 'configuration-joint-requires-mie-gate')
    else:
        _require(gate is False, 'configuration-unique-forbids-mie-gate')
    group_id = config.get('group_id')
    _require(type(group_id) is str and group_id and group_id.strip() == group_id,
             'configuration-group-id')
    sources = config.get('sources')
    _require(isinstance(sources, list) and len(sources) == 2, 'configuration-two-sources')
    rows = []
    for row in sources:
        _require(isinstance(row, dict), 'configuration-source-shape')
        name = row.get('id')
        _require(type(name) is str and name and name.strip() == name and name != 'cpu',
                 'configuration-source-id')
        request = row.get('request')
        _require(type(request) is str and request, 'configuration-source-request')
        base = row.get('base')
        _require(type(base) is int and 0 <= base < 1 << 32 and base % 4096 == 0
                 and base + 4096 <= 1 << 32, 'configuration-source-base')
        port = row.get('source_port')
        _require(type(port) is str and port and port.strip() == port,
                 'configuration-source-port')
        offset = row.get('source_bit_offset')
        _require(type(offset) is int and 0 <= offset < 64, 'configuration-source-bit-offset')
        width = row.get('pulse_width_ticks')
        _require(type(width) is int and 1 <= width <= 4096, 'configuration-source-pulse-width')
        rows.append(dict(id=name, request=request, base=base, source_port=port,
                         source_bit_offset=offset, pulse_width_ticks=width))
    _require(len({row['id'] for row in rows}) == 2, 'configuration-source-ids-unique')
    _require(len({row['base'] for row in rows}) == 2, 'configuration-source-bases-unique')
    observed = config.get('observed_source_id')
    _require(type(observed) is str and observed in {row['id'] for row in rows},
             'configuration-observed-source')
    plan = config.get('trigger_writes')
    _require(isinstance(plan, list) and 1 <= len(plan) <= 8, 'configuration-trigger-plan')
    by_id = {row['id']: row for row in rows}
    writes = []
    for row in plan:
        _require(isinstance(row, (list, tuple)) and len(row) == 3, 'configuration-trigger-write')
        name, offset, value = row
        _require(type(name) is str and name in by_id, 'configuration-trigger-source')
        _require(type(offset) is int and offset >= 0 and offset % 4 == 0,
                 'configuration-trigger-offset')
        _require(type(value) is int and 0 <= value < 1 << 32, 'configuration-trigger-value')
        writes.append((name, offset, value))
    if expected == 'joint':
        _require(len(writes) == 2 and {row[0] for row in writes} == set(by_id),
                 'configuration-joint-trigger-plan-members')
    else:
        _require(len(writes) == 1 and writes[0][0] == observed,
                 'configuration-unique-trigger-plan-observed-source')
    return dict(schema_version=SCHEMA_VERSION, cpu_profile=cpu_profile,
                expected_attribution=expected, mie_gate=gate, group_id=group_id,
                observed_source_id=observed, sources=tuple(rows),
                trigger_writes=tuple(writes))


def source_by_id(options):
    return {row['id']: row for row in options['sources']}


def member_source_ids(options):
    return tuple(row['id'] + '.' + row['source_port'] for row in options['sources'])


def observed_member_id(options):
    source = source_by_id(options)[options['observed_source_id']]
    return source['id'] + '.' + source['source_port']


def consumption_fields(config, admission, source):
    """Validate the observed member's fixed-firmware fields against admission.

    The rules are the existing F5 rules (``scripts/run_declared_irq_f5.f5_fields``
    validate the target window, the image layout, the status offsets against the
    admitted declared register map and the declared clear writes); only the
    two-source config shape is mapped onto that view here.
    """
    from scripts.run_declared_irq_f5 import f5_fields
    _require(isinstance(admission, dict) and admission.get('status') == 'admitted',
             'admission-not-admitted')
    view = dict(config, active_base=source['base'],
                target_window=dict(base=source['base'],
                                   size=admission['target']['window_size']))
    fields = f5_fields(view, admission)
    _require(fields['target_base'] == source['base'], 'admission-window-base-mismatch')
    return fields


def admit_case(config, options, base):
    """Admit the observed member's declared register map with the shared gate."""
    from myfuzz.integration.declared_irq_consumption import admit_declared_irq_consumption
    source = source_by_id(options)[options['observed_source_id']]
    document = dict(config, source_request=source['request'])
    admission = admit_declared_irq_consumption(document, base_dir=base)
    _require(admission['status'] == 'admitted', 'admission-' + str(admission.get('reason')))
    return admission


# ---------------------------------------------------------------------------
# Fixed case program
# ---------------------------------------------------------------------------
def case_program(firmware, options, *, windows):
    """The fixed case image: declared trigger writes in order, then a park.

    A joint case clears ``mstatus.MIE`` before the writes and sets it after them
    with the same CSR idiom as the existing fixed smoke program
    (``_addi(3,0,8); csrrc mstatus, x3`` / ``csrrs mstatus, x3``).  The gate is
    what makes the single real take land inside the overlap; the overlap proof
    itself still comes from the actual journal.
    """
    from myfuzz.integration.declared_irq_consumption import _csr
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _sw
    _require(isinstance(firmware, dict) and type(firmware.get('dynamic_start')) is int
             and type(firmware.get('image_end')) is int and firmware['handler_words'] > 0,
             'program-firmware')
    by_id = source_by_id(options)
    _require(isinstance(windows, dict) and set(windows) == set(by_id)
             and all(type(value) is int and value >= 4 for value in windows.values()),
             'program-windows')
    words = []

    def emit(word, kind):
        words.append((word, kind))

    if options['mie_gate']:
        emit(_addi(3, 0, MSTATUS_MIE), 'load_mie_mask')
        emit(_csr(CSR_MSTATUS, 3, 3, 0), 'clear_mstatus_mie')
    for source_id, offset, value in options['trigger_writes']:
        source = by_id[source_id]
        _require(offset + 4 <= windows[source_id], 'program-trigger-outside-window')
        _require(value < 1 << 32, 'program-trigger-value')
        if offset < 2048:
            for word in _lui_addi_load(8, source['base']):
                emit(word, 'load_base:' + source_id)
            for word in _lui_addi_load(9, value):
                emit(word, 'load_value:' + source_id)
            emit(_sw(9, 8, offset), 'store_trigger:' + source_id)
        else:
            # RV32 SW sign-extends its 12-bit displacement.  Materialize the
            # complete address instead of truncating a legal large offset.
            for word in _lui_addi_load(10, source['base'] + offset):
                emit(word, 'load_address:' + source_id)
            for word in _lui_addi_load(9, value):
                emit(word, 'load_value:' + source_id)
            emit(_sw(9, 10, 0), 'store_trigger:' + source_id)
    if options['mie_gate']:
        emit(_csr(CSR_MSTATUS, 3, 2, 0), 'set_mstatus_mie')
    entry = firmware['dynamic_start']
    park = entry + 4 * len(words)
    words.append((_jal(park, park), 'park'))
    _require(park + 4 <= firmware['image_end'], 'program-overflow')
    fixed = [(row['address'], row['address'] + len(bytes.fromhex(row['data_hex'])))
             for row in firmware['segments']]
    fixed.extend([(firmware['scratch'], firmware['scratch'] + 16),
                  (firmware['result_address'],
                   firmware['result_address'] + 4 * firmware['result_words'])])
    _require(all(stop <= entry or park + 4 <= start for start, stop in fixed),
             'program-overlaps-fixed-image')
    images = {segment['address']: segment['data_hex'] for segment in firmware['segments']}
    _require(entry not in images, 'program-entry-overlaps-fixed-image')
    code = b''.join(word.to_bytes(4, 'little') for word, _ in words)
    images[entry] = code.hex()
    return dict(
        schema_version=PROGRAM_SCHEMA, firmware_digest=firmware.get('digest'),
        image_start=firmware['image_start'], image_end=firmware['image_end'],
        vector=firmware['vector'], handler=firmware['handler'], mret_pc=firmware['mret_pc'],
        case_entry=entry, park=park, mie_gate=options['mie_gate'],
        trigger_writes=[list(row) for row in options['trigger_writes']],
        words=[dict(pc=entry + 4 * position, word=word, kind=kind)
               for position, (word, kind) in enumerate(words)],
        images={str(address): data for address, data in sorted(images.items())},
        case_words=len(words), fixed_words=sum(len(bytes.fromhex(segment['data_hex'])) // 4
                                               for segment in firmware['segments']),
        dynamic_sha256=sha256(code).hexdigest())


# ---------------------------------------------------------------------------
# Offline derivation from the actual journal
# ---------------------------------------------------------------------------
def _by_id(events):
    rows = {}
    for event in events:
        identifier = event.get('event_id')
        if type(identifier) is not int:
            continue
        _require(identifier not in rows, 'duplicate-event-id')
        rows[identifier] = event
    return rows


def _trigger_deliveries(events, options):
    by_id = source_by_id(options)
    deliveries = [event for event in events
                  if event.get('kind') == 'mmio_delivery'
                  and event.get('component') == 'cpu'
                  and event.get('write') is True
                  and event.get('device_id') in by_id]
    deliveries.sort(key=lambda event: event['event_id'])
    actual = [(event.get('device_id'), event.get('offset'), event.get('write_value'))
              for event in deliveries]
    _require(actual == list(options['trigger_writes']), 'actual-MMIO-trigger-sequence')
    for event, (name, offset, _) in zip(deliveries, options['trigger_writes']):
        _require(event.get('address') == by_id[name]['base'] + offset,
                 'actual-MMIO-trigger-address')
    return deliveries


def _member_sample(rows, *, reference, member, mapping, require_bit):
    """Resolve one frame member's own real raw output sample."""
    _require(isinstance(reference, dict), 'member-native-source-reference')
    pulse = rows.get(reference.get('event_id'))
    _require(isinstance(pulse, dict) and pulse.get('kind') == 'local_tick_sample'
             and pulse.get('component') == member['source_component']
             and pulse.get('phase') == reference.get('phase')
             and pulse.get('local_tick') == reference.get('local_tick')
             and pulse.get('reset_epoch') == reference.get('reset_epoch'),
             'member-native-pulse-sample')
    _require(reference.get('runtime_name') == mapping['runtime_name'],
             'member-native-output-wire')
    physical = (pulse.get('outputs') or {}).get('physical') or {}
    raw = physical.get(mapping['runtime_name'])
    _require(type(raw) is int and 0 <= raw < 1 << mapping['source_width'],
             'member-native-output-raw')
    _require(type(mapping['raw_bit_offset']) is int
             and 0 <= mapping['raw_bit_offset'] < 64
             and raw >> mapping['raw_bit_offset'] & 1 == require_bit,
             'member-native-output-bit')
    _require((pulse.get('outputs') or {}).get(member['source_port']) == raw,
             'member-native-output-projection')
    return dict(event_id=pulse['event_id'], component=pulse.get('component'),
                local_tick=pulse.get('local_tick'), phase=pulse.get('phase'),
                reset_epoch=pulse.get('reset_epoch'), runtime_name=mapping['runtime_name'],
                physical_port=member['source_port'], raw_value=raw,
                bit=mapping['raw_bit_offset'], bit_value=require_bit,
                adapter_id=reference.get('adapter_id'))


def _cpu_evidence(events, *, rows, frame, take, cpu_id):
    sample = rows.get(frame.get('native_sample_event_id'))
    _require(isinstance(sample, dict) and sample.get('kind') == 'cpu_external_irq_sample'
             and sample.get('component') == cpu_id
             and sample.get('event_id') == take.get('sample_event_id')
             and sample.get('producer_event_id') == take.get('producer_event_id')
             and sample.get('local_tick') == frame.get('cpu_tick')
             and take.get('local_tick') == frame.get('cpu_tick'),
             'actual-parsed-CPU-input')
    for event in (sample, take):
        _require(all(type(event.get(key)) is int and event[key] == frame.get('value')
                     for key in ('expected_input', 'actual_pre_input', 'actual_post_input')),
                 'CPU-input-pre-post-mismatch')
        _require(not event.get('trap') and not event.get('halt'), 'native-take-diverted')
        observed_mask = event.get('irq_masked_pre')
        _require(observed_mask is None or observed_mask in (0, 1), 'native-mask-probe')
    _require(type(take.get('irq_taken_pre')) is int and take['irq_taken_pre'] == 1,
             'native-take-decision-probe')
    _require(take.get('irq_masked_pre') in (None, 0), 'native-take-unmasked')
    serial = (take.get('irq_serial_observation') or {}).get('decision') or {}
    token = serial.get('value') if serial.get('status') == 'observed' else None
    _require(token is None or (type(token) is int and token > 0),
             'non-zero-native-decision-serial')
    retirements = [event for event in events
                   if event.get('kind') == 'cpu_retire' and event.get('component') == cpu_id]
    entered = [event for event in retirements if event.get('intr') == 1]
    _require(len(entered) == 1, 'one-first-handler-entry-retirement')
    entry = entered[0]
    _require(entry.get('valid') == 1 and not entry.get('trap') and not entry.get('halt'),
             'first-handler-entry-retirement-valid')
    if token is not None:
        linked = [event for event in retirements
                  if (event.get('irq_serial_observation') or {}).get('retirement', {})
                  .get('status') == 'observed'
                  and event['irq_serial_observation']['retirement']['value'] == token]
        _require(len(linked) == 1 and linked[0]['event_id'] == entry['event_id'],
                 'first-handler-retirement-serial')
        join_scope = 'exact_decision_serial_join'
    else:
        following = [event for event in retirements
                     if event.get('event_id', 0) > take.get('event_id', 0)]
        _require(bool(following) and following[0]['event_id'] == entry['event_id'],
                 'first-retirement-after-take')
        join_scope = 'first_retirement_after_native_take'
    return dict(sample_event_id=sample['event_id'],
                sample_producer_event_id=sample.get('producer_event_id'),
                take_event_id=take['event_id'], local_tick=take.get('local_tick'),
                take_key=take.get('take_key'), irq_taken_pre=take.get('irq_taken_pre'),
                irq_masked_pre=take.get('irq_masked_pre'),
                decision_serial=token,
                decision_serial_status=('observed' if token is not None else 'unavailable'),
                first_handler_retirement=dict(event_id=entry['event_id'],
                                              pc=entry.get('pc_rdata'),
                                              insn=entry.get('insn'),
                                              order=entry.get('order'),
                                              scope=join_scope))


def transport_evidence(events, *, group, options, mappings, cpu_id='cpu'):
    """Re-derive the two-source OR transport from the actual journal only."""
    _require(type(events) in (list, tuple), 'transport-events')
    _require(hasattr(group, 'members') and hasattr(group, 'identity_sha256'),
             'transport-group')
    rows = _by_id(events)
    member_rows = {row.source_component + '.' + row.source_port:
                   dict(source_component=row.source_component, source_port=row.source_port)
                   for row in group.members}
    declared = member_source_ids(options)
    _require(tuple(member_rows) == declared, 'group-members-match-declaration')
    _require(isinstance(mappings, dict) and set(mappings) == set(declared),
             'group-mappings-match-declaration')
    deliveries = _trigger_deliveries(events, options)
    delivery_by_member = {event['device_id']: event for event in deliveries}
    takes = [event for event in events
             if event.get('kind') == 'cpu_external_irq_taken' and event.get('component') == cpu_id]
    _require(len(takes) == 1, 'one-actual-native-CPU-take')
    take = takes[0]
    frames = [event for event in events if event.get('kind') == 'irq_group_delivery'
              and event.get('native_take_event_id') == take['event_id']]
    _require(len(frames) == 1, 'actual-OR-frame-take-join')
    frame = frames[0]
    _require(frame.get('group_id') == group.group_id
             and frame.get('group_sha256') == group.identity_sha256
             and frame.get('target_component') == group.target_component
             and frame.get('target_port') == group.target_port, 'OR-frame-group-identity')
    _require(frame.get('value') == 1, 'OR-frame-value')
    frame_members = frame.get('members') or ()
    _require([row.get('source_id') for row in frame_members] == list(declared),
             'OR-frame-declared-members')
    active = list(frame.get('active_sources') or ())
    _require(len(active) == len(set(active)) and set(active) <= set(declared),
             'OR-frame-active-within-group')
    _require(frame.get('attribution_status') in ('unique', 'joint', 'unknown'),
             'OR-frame-attribution')
    actual = ('joint' if frame.get('attribution_status') == 'joint' and len(active) == 2
              else 'unique' if frame.get('attribution_status') == 'unique' and len(active) == 1
              else 'unknown')
    _require(actual == options['expected_attribution'], 'attribution-mismatch')
    proofs = []
    for member_row in frame_members:
        source_id = member_row.get('source_id')
        value = member_row.get('value')
        _require(type(value) is int and value in (0, 1), 'OR-frame-member-value')
        member = member_rows[source_id]
        proof = _member_sample(rows, reference=member_row.get('native_source'),
                               member=member, mapping=mappings[source_id],
                               require_bit=value)
        proof.update(source_id=source_id, value=value)
        if value == 1:
            trigger = delivery_by_member.get(member['source_component'])
            _require(trigger is not None and proof['event_id'] > trigger['event_id'],
                     'member-pulse-after-own-trigger')
        _require(proof['event_id'] < frame['event_id'], 'member-pulse-before-frame')
        proofs.append(proof)
    delivery_events = [dict(event_id=event['event_id'], device_id=event.get('device_id'),
                            offset=event.get('offset'), value=event.get('write_value'),
                            address=event.get('address'))
                       for event in deliveries]
    _require(delivery_events and delivery_events[-1]['event_id'] < take['event_id'],
             'trigger-before-take')
    if actual == 'joint':
        _require(sorted(active) == sorted(declared), 'joint-frame-both-members-active')
        _require(frame.get('unique_source') is None, 'joint-frame-no-unique-source')
        for proof in proofs:
            _require(proof['value'] == 1 and proof['bit_value'] == 1,
                     'joint-member-native-output')
    else:
        observed = observed_member_id(options)
        _require(active == [observed], 'unique-frame-single-active-member')
        _require(frame.get('unique_source') == observed, 'unique-frame-exact-source')
        for proof in proofs:
            if proof['source_id'] == observed:
                _require(proof['value'] == 1 and proof['bit_value'] == 1,
                         'unique-member-native-output')
            else:
                _require(proof['value'] == 0 and proof['bit_value'] == 0,
                         'unique-other-member-inactive')
        for event in events:
            if event.get('kind') != 'irq_group_delivery':
                continue
            active_elsewhere = list(event.get('active_sources') or ())
            _require(set(active_elsewhere) <= {observed},
                     'unique-case-single-active-member')
    joint_frames = [event for event in events
                    if event.get('kind') == 'irq_group_delivery'
                    and sorted(event.get('active_sources') or ()) == sorted(declared)]
    evidence = dict(
        status='observed', attribution=actual,
        frame=dict(event_id=frame['event_id'], group_id=frame.get('group_id'),
                   group_sha256=frame.get('group_sha256'),
                   target_component=frame.get('target_component'),
                   target_port=frame.get('target_port'),
                   cpu_tick=frame.get('cpu_tick'), value=frame.get('value'),
                   attribution_status=frame.get('attribution_status'),
                   unique_source=frame.get('unique_source'), active_sources=active,
                   native_sample_event_id=frame.get('native_sample_event_id'),
                   native_take_event_id=frame.get('native_take_event_id')),
        active_sources=active, unique_source=frame.get('unique_source'),
        members=proofs, trigger_deliveries=delivery_events,
        overlap=dict(joint_frame_count=len(joint_frames),
                     joint_frame_ticks=[event.get('cpu_tick') for event in joint_frames],
                     take_inside_joint_frames=bool(joint_frames)),
        cpu=_cpu_evidence(events, rows=rows, frame=frame, take=take, cpu_id=cpu_id),
        group=group.document())
    return evidence


def verify_observation(observation, *, expected_attribution, active_sources,
                       observed_member_id, group):
    """Require the shared layered observation to match the derived attribution.

    ``joint`` -> the exact ambiguous/unknown refusal with zero credit;
    ``unique`` -> the full verified consumption document with its value joins.
    """
    _require(isinstance(observation, dict), 'observation-shape')
    refusals = observation.get('refusals')
    _require(isinstance(refusals, list), 'observation-refusals')
    document_group = observation.get('group') or {}
    _require(document_group.get('group_id') == group.group_id
             and document_group.get('group_sha256') == group.identity_sha256,
             'observation-group-identity')
    transport = observation.get('transport') or {}
    for field, value in ZERO_GRANTS.items():
        _require(observation.get(field) is value, 'observation-false-grant-' + field)
    consumption = observation.get('consumption') or {}
    if expected_attribution == 'joint':
        _require(observation.get('status') == 'ambiguous', 'joint-observation-ambiguous')
        _require(observation.get('irq_consumption') == 'unknown',
                 'joint-observation-consumption-unknown')
        _require(refusals == [REFUSAL_AMBIGUOUS], 'joint-observation-refusal')
        _require(consumption.get('status') == 'ambiguous'
                 and consumption.get('irq_consumption') == 'unknown'
                 and consumption.get('reason') == REFUSAL_AMBIGUOUS,
                 'joint-observation-consumption')
        _require(consumption.get('active_sources') == list(active_sources),
                 'joint-observation-active-sources')
        _require('register_reads' not in consumption
                 and 'result_ram_writes' not in consumption,
                 'joint-observation-no-credit')
        _require(transport.get('attribution') == 'ambiguous', 'joint-transport-attribution')
        _require(transport.get('or_frame', {}).get('active_sources') == list(active_sources),
                 'joint-transport-active-sources')
        _require(observation.get('cause_source') == 'unknown', 'joint-observation-cause')
        scope = 'joint_two_source_attribution_no_credit'
    else:
        _require(observation.get('status') == 'verified', 'unique-observation-verified')
        _require(observation.get('irq_consumption') == 'verified',
                 'unique-observation-consumption-verified')
        _require(refusals == [], 'unique-observation-no-refusal')
        _require(transport.get('attribution') == 'unique', 'unique-transport-attribution')
        _require(transport.get('or_frame', {}).get('unique_source') == observed_member_id,
                 'unique-transport-exact-source')
        _require(consumption.get('status') == 'verified'
                 and consumption.get('irq_consumption') == 'verified',
                 'unique-consumption-verified')
        joins = consumption.get('retirement_joins')
        _require(joins in ('exact_fields', 'by_documented_order'),
                 'unique-consumption-retirement-joins')
        expected_join = ('delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value'
                         if joins == 'exact_fields' else
                         'delivery_read_value==OBI_rdata==RAM_write_value')
        _require(consumption.get('value_join') == expected_join,
                 'unique-consumption-value-join')
        reads = consumption.get('register_reads') or []
        writes = consumption.get('result_ram_writes') or []
        _require(bool(reads) and bool(writes), 'unique-consumption-value-chain')
        values = {read.get('target_register_index'): read.get('value') for read in reads}
        for write in writes:
            _require(values.get(write.get('index')) == write.get('value'),
                     'unique-consumption-write-value')
        mret = consumption.get('mret') or {}
        _require(type(mret.get('insn')) is int and mret['insn'] == MRET_WORD,
                 'unique-consumption-mret')
        _require((consumption.get('successor') or {}).get('event_id') is not None,
                 'unique-consumption-successor')
        _require(observation.get('cause_source') in ('unknown', 'read_status_bit'),
                 'unique-observation-cause')
        unknown = observation.get('unknown') or {}
        _require(unknown.get('internal_version') == 'unknown'
                 and unknown.get('case_origin') == 'unknown',
                 'unique-observation-unknown')
        scope = 'unique_member_full_verified_consumption'
    return dict(scope=scope, status=observation.get('status'),
                irq_consumption=observation.get('irq_consumption'),
                refusals=list(refusals), cause_source=observation.get('cause_source'),
                transport=dict(attribution=transport.get('attribution'),
                               or_frame=dict(transport.get('or_frame') or {})),
                consumption={key: consumption.get(key) for key in
                             ('status', 'irq_consumption', 'value_join',
                              'retirement_joins', 'reason')})


def case_document(*, options, group, mappings, transport, observation, program,
                  firmware, admission, case_id):
    """Assemble the verified case document from the derived facts only."""
    _require(transport.get('status') == 'observed', 'case-transport')
    verified = verify_observation(observation,
                                  expected_attribution=options['expected_attribution'],
                                  active_sources=transport['active_sources'],
                                  observed_member_id=observed_member_id(options),
                                  group=group)
    scope = dict(
        case=case_id, attribution=verified['scope'],
        cpu=options['cpu_profile'], group=group.group_id,
        sources=[row['id'] for row in options['sources']],
        observed_source=options['observed_source_id'],
        transport=('two_member_OR_joint_at_single_native_take'
                   if options['expected_attribution'] == 'joint'
                   else 'single_member_unique_at_single_native_take'),
        consumption=('ambiguous_unknown_no_credit'
                     if options['expected_attribution'] == 'joint'
                     else 'verified_declared_status_read_value_chain'),
        native='one-CPU-and-two-declared-output-targets-in-one-OR-group',
        excludes=['F5-pin-grammar', 'F6-storage-version', 'ISR-MMIO-authority',
                  'internal-IP-cause', 'internal-IP-version', 'case-origin',
                  'cross-case-writer-attribution', 'reward'])
    return dict(
        schema_version=CASE_SCHEMA, case_id=case_id, status='verified',
        expected_attribution=options['expected_attribution'],
        attribution=transport['attribution'], active_sources=transport['active_sources'],
        unique_source=transport['unique_source'], frame=transport['frame'],
        members=transport['members'], overlap=transport['overlap'],
        trigger_plan=[list(row) for row in options['trigger_writes']],
        trigger_deliveries=transport['trigger_deliveries'], cpu=transport['cpu'],
        group=dict(group_id=group.group_id, group_sha256=group.identity_sha256,
                   target_component=group.target_component, target_port=group.target_port,
                   document=group.document()),
        sources=[dict(row, adapter_id=mappings[row['id'] + '.' + row['source_port']]['adapter_id'],
                      runtime_name=mappings[row['id'] + '.' + row['source_port']]['runtime_name'],
                      source_width=mappings[row['id'] + '.' + row['source_port']]['source_width'])
                 for row in options['sources']],
        firmware=dict(digest=firmware.get('digest'), target_base=firmware['target_base'],
                      status_offsets=list(firmware['status_offsets']),
                      handler=firmware['handler'], mret_pc=firmware['mret_pc'],
                      case_entry=program['case_entry'], park=program['park'],
                      mie_gate=program['mie_gate'],
                      dynamic_sha256=program['dynamic_sha256'],
                      case_words=program['case_words']),
        admission=dict(status=admission['status'],
                       target=dict(component_id=admission['target']['component_id'],
                                   window_size=admission['target']['window_size'],
                                   protocol=admission['target']['protocol'],
                                   profile_fingerprint=admission['target']['profile_fingerprint']),
                       cpu=dict(component_id=admission['cpu']['component_id'],
                                retirement_authority=admission['cpu']['retirement_authority'])),
        observation=dict(status=verified['status'],
                         irq_consumption=verified['irq_consumption'],
                         refusals=verified['refusals'],
                         cause_source=verified['cause_source'],
                         transport=verified['transport'],
                         consumption=verified['consumption']),
        scope=scope,
        unknown=dict(internal_ip_cause='unknown', internal_ip_version='unknown',
                     case_origin='unknown', cross_case_writer_attribution='unknown'),
        **ZERO_GRANTS)


def summary_document(*, options, case, processes, mode, fresh_matches=None):
    """The saved summary; never grants F5/F6/storage/reward authority."""
    _require(isinstance(case, dict) and case.get('status') == 'verified', 'summary-case')
    for field, value in ZERO_GRANTS.items():
        _require(case.get(field) is value, 'summary-case-false-grant-' + field)
    digest = semantic_digest(case)
    return dict(
        schema_version=SUMMARY_SCHEMA, mode=mode, status=case['status'],
        case_id=case['case_id'], expected_attribution=options['expected_attribution'],
        attribution=case['attribution'], observed_source=options['observed_source_id'],
        group=dict(group_id=case['group']['group_id'],
                   group_sha256=case['group']['group_sha256']),
        sources=[row['id'] for row in options['sources']],
        mie_gate=options['mie_gate'],
        scope=dict(case['scope'],
                   mode_scope=('same-invocation-independent-native-sessions'
                               if mode == 'both' else 'single-native-session-' + str(mode)),
                   fresh_matches=fresh_matches),
        native_take=dict(event_id=case['cpu']['take_event_id'],
                         local_tick=case['cpu']['local_tick'],
                         take_key=case['cpu']['take_key'],
                         decision_serial=case['cpu']['decision_serial'],
                         first_handler_retirement=case['cpu']['first_handler_retirement']),
        observation=dict(status=case['observation']['status'],
                         irq_consumption=case['observation']['irq_consumption'],
                         refusals=case['observation']['refusals'],
                         cause_source=case['observation']['cause_source']),
        isr_mmio='unknown', internal_version='unknown', case_origin='unknown',
        semantic_sha256=digest, case=case, processes=processes,
        fresh_matches=fresh_matches,
        fresh_scope=('same-invocation-independent-native-sessions' if mode == 'both'
                     else 'single-native-session'),
        result=dict(status=case['status'], scope=case['scope']['case'],
                    decision_serial=case['cpu']['decision_serial'],
                    native_take_tick=case['cpu']['local_tick'],
                    first_retirement_pc=case['cpu']['first_handler_retirement']['pc']),
        **ZERO_GRANTS)


# ---------------------------------------------------------------------------
# Native execution (frozen window only)
# ---------------------------------------------------------------------------
def prepare_case(config, *, base):
    """Everything the case needs before any process starts."""
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.integration.declared_irq_consumption import build_declared_irq_firmware
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact as cpu_artifact
    from scripts.run_timer_irq_smoke import timer_artifact
    options = case_options(config)
    admission = admit_case(config, options, base)
    observed = source_by_id(options)[options['observed_source_id']]
    fields = consumption_fields(config, admission, observed)
    artifacts = {'cpu': cpu_artifact(options['cpu_profile'], 'cpu')}
    for row in options['sources']:
        artifacts[row['id']] = timer_artifact(base, row['request'], row['id'])
    windows = {row['id']: artifacts[row['id']].plan.profile.address.window_size
               for row in options['sources']}
    boot = source_backed_boot_fetch(artifacts['cpu'].plan.profile, base_dir=base,
                                    configured_boot_base=artifacts['cpu'].runtime_document[
                                        'boot_contract']['configured_boot_base'])
    firmware = build_declared_irq_firmware(
        image_start=fields['image_start'], image_end=fields['image_end'], first_fetch=boot,
        target_base=fields['target_base'], status_offsets=fields['status_offsets'],
        result_address=fields['result_address'], clear_writes=fields['clear_writes'])
    _require(firmware['first_fetch'] == boot, 'configured-boot-fetch-mismatch')
    firmware['cause_bits'] = dict(fields['cause_bits'])
    firmware['digest'] = semantic_digest({key: value for key, value in firmware.items()
                                          if key != 'digest'})
    program = case_program(firmware, options, windows=windows)
    return dict(options=options, admission=admission, fields=fields, artifacts=artifacts,
                windows=windows, firmware=firmware, program=program, boot=boot)


def execute_once(prepared, *, base, cache, output, max_steps, case_id, cpu_id='cpu'):
    """One real native session; returns the derived case document and processes."""
    from myfuzz.integration.declared_irq_consumption import observe_declared_irq_consumption
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner
    from scripts.run_declared_irq_f5 import cpu_obi_traces
    from scripts.run_timer_irq_smoke import target_session
    options = prepared['options']
    artifacts = prepared['artifacts']
    firmware = prepared['firmware']
    program = prepared['program']
    output.mkdir(parents=True, exist_ok=False)
    size = firmware['image_end'] - firmware['image_start']
    memory = PersistentMemory(regions=(MemoryRegion('ram', firmware['image_start'], size),),
                              initialization_seed=0, max_initialized_bytes=size)
    for address, data in program['images'].items():
        memory.preload(int(address), bytes.fromhex(data))
    memory.preload(firmware['scratch'], bytes(16))
    memory.preload(firmware['result_address'], bytes(4 * firmware['result_words']))
    sources = {row['id']: target_session(artifacts[row['id']], base=base, cache=cache)
               for row in options['sources']}
    router = DataflowRouter(tuple(
        DeviceWindow(row['id'], row['base'],
                     artifacts[row['id']].plan.profile.address.window_size, sources[row['id']])
        for row in options['sources']))
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=base, cache_dir=cache, memory=memory,
                               router=router, native_irq_receipts=True,
                               physical_tick_samples=True)
    mappings = {row['id'] + '.' + row['source_port']:
                declared_irq_runtime_mapping(sources[row['id']],
                                             physical_port=row['source_port'],
                                             source_bit_offset=row['source_bit_offset'])
                for row in options['sources']}
    group = IrqDeliveryGroup(options['group_id'], cpu_id, cpu.irq_input_port,
                             tuple(IrqDeliveryMember(row['id'], row['source_port'],
                                                     pulse_width_ticks=row['pulse_width_ticks'],
                                                     source_bit_offset=row['source_bit_offset'],
                                                     source_adapter='declared-output.v1')
                                   for row in options['sources']))
    fields = [InputField(cpu_id, cpu.irq_input_port, 1)]
    owners = [InputOwner(cpu_id, cpu.irq_input_port, 0, 1, 'bound', group.owner_ref)]
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
        if runner.install_protocol_checker(name) is None:
            raise ValueError('actual target protocol checker required')
    with record_local_commands() as recording:
        try:
            runner.begin_test(case_id)
            # Capture the actual reset-idle baselines before any case request.
            for name in sources:
                runner.step(name)
            cursor = 0
            mret_order = None
            completed = 0
            settle = 0
            for _ in range(max_steps):
                runner.step(cpu_id)
                for name in router.ready_targets:
                    runner.step(name)
                for name in sources:
                    runner.step(name)
                for event in runner._event_refs_since(cursor):
                    if event.get('kind') != 'cpu_retire':
                        continue
                    if event.get('pc_rdata') == firmware['mret_pc'] and mret_order is None:
                        mret_order = event.get('order')
                    elif mret_order is not None and event.get('order', 0) > mret_order:
                        completed += 1
                cursor = runner.event_count
                if completed >= 2:
                    settle += 1
                    if settle >= SETTLE_TICKS:
                        break
            else:
                raise ValueError('irq-group-step-budget-exhausted')
        except BaseException as error:
            save(output / 'failure.json', dict(error_type=type(error).__name__,
                                               error=str(error)))
            raise
        finally:
            try:
                runner.finalize()
            finally:
                save(output / 'events.json', runner.events)
                save(output / 'local_commands.json', recording.export_sessions())
                save(output / 'executions.json', recording.export_executions())
    events = tuple(runner._event_refs_since(0))
    processes = recording.export_executions()
    _require(len(processes) == 1 + len(sources)
             and all(row.get('exit_code') == 0 and row.get('reaped') for row in processes),
             'clean-native-process-exits')
    transport = transport_evidence(events, group=group, options=options, mappings=mappings)
    traces, policy = cpu_obi_traces(artifacts['cpu'])
    observed = source_by_id(options)[options['observed_source_id']]
    observation = observe_declared_irq_consumption(
        events=events, receipt=SimpleNamespace(case_id=case_id, events=events),
        traces=traces, error_policy=policy, cpu_id=cpu_id,
        target_id=options['observed_source_id'],
        access=dict(device_id=options['observed_source_id'],
                    target_component=options['observed_source_id'],
                    window_base=observed['base'],
                    window_size=prepared['admission']['target']['window_size'],
                    offset=int(prepared['fields']['status_offsets'][0])),
        firmware=firmware, group=group,
        target_trace=artifacts[options['observed_source_id']].runtime_document[
            'base_protocol_trace'],
        successor_range=(firmware['image_start'], firmware['image_end']),
        cpu_contract=native_irq_receipt_contract(artifacts['cpu']))
    save(output / 'observation.json', observation)
    case = case_document(options=options, group=group, mappings=mappings,
                         transport=transport, observation=observation, program=program,
                         firmware=firmware, admission=prepared['admission'],
                         case_id=case_id)
    save(output / 'case.json', case)
    return case, processes


def _independent_processes(original, fresh, components):
    _require(len(original) == len(fresh) == len(components), 'process-count')
    for component in components:
        first = [row for row in original if row.get('component') == component]
        second = [row for row in fresh if row.get('component') == component]
        _require(len(first) == 1 and len(second) == 1, 'process-identity-' + component)
        one, two = first[0], second[0]
        _require(type(one.get('pid')) is int and type(two.get('pid')) is int
                 and one['pid'] != two['pid'], 'independent-pid-' + component)
        distinct = (type(one.get('execution_nonce')) is str and one['execution_nonce']
                    and type(two.get('execution_nonce')) is str and two['execution_nonce'])
        _require(distinct and one['execution_nonce'] != two['execution_nonce'],
                 'independent-execution-nonce-' + component)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=None)
    parser.add_argument('--max-steps', type=int, default=2000)
    parser.add_argument('--mode', choices=('original', 'fresh', 'both'), default='both')
    parser.add_argument('--original', type=Path, default=None,
                        help='fresh only: compare the original summary digest after writing')
    args = parser.parse_args()
    base = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(base), str(base / 'src')]
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    _require(1 <= args.max_steps <= 10000, 'bounded-positive-max-steps')
    _require(not args.output.exists(), 'output-must-not-exist')
    _require(args.mode == 'fresh' or args.original is None, 'original-mode-cannot-compare')
    config_path = args.config if args.config.is_absolute() else base / args.config
    config = read(config_path)
    cache = (args.cache or Path(tempfile.gettempdir())
             / 'myfuzz-irq-group-native-cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    case_id = 'irq-group-native-' + config_path.stem
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            execution_validation_scope():
        prepared = prepare_case(config, base=base)
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / 'config.json', config)
    save(args.output / 'admission.json', prepared['admission'])
    save(args.output / 'program.json', prepared['program'])
    for name, artifact in prepared['artifacts'].items():
        save(args.output / (name + '-artifact.json'), artifact.runtime_document)
    modes = ('original', 'fresh') if args.mode == 'both' else (args.mode,)
    runs = {}
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            execution_validation_scope():
        for mode in modes:
            case, processes = execute_once(prepared, base=base, cache=cache,
                                           output=args.output / mode,
                                           max_steps=args.max_steps, case_id=case_id)
            runs[mode] = dict(case=case, processes=processes)
    fresh_matches = None
    if args.mode == 'both':
        components = ('cpu',) + tuple(row['id'] for row in prepared['options']['sources'])
        _independent_processes(runs['original']['processes'], runs['fresh']['processes'],
                               components)
        _require(semantic_digest(runs['original']['case'])
                 == semantic_digest(runs['fresh']['case']), 'fresh-semantic-mismatch')
        fresh_matches = True
    elif args.mode == 'fresh' and args.original is not None:
        original = read(args.original / 'summary.json')
        fresh_matches = (original.get('semantic_sha256')
                         == semantic_digest(runs['fresh']['case']))
        _require(fresh_matches, 'fresh-semantic-mismatch')
    case = runs[modes[-1]]['case']
    summary = summary_document(options=prepared['options'], case=case,
                               processes={mode: runs[mode]['processes'] for mode in modes},
                               mode=args.mode, fresh_matches=fresh_matches)
    save(args.output / 'summary.json', summary)
    print(json.dumps(dict(status=summary['status'], attribution=summary['attribution'],
                          expected_attribution=summary['expected_attribution'],
                          semantic_sha256=summary['semantic_sha256'],
                          output=str(args.output)), sort_keys=True))


if __name__ == '__main__':
    main()
