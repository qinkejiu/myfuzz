"""Pure tests for the two-source IRQ group native case.

No DUT is built and no native session is started here.  The three real configs
are validated against their real admission, the fixed case program is decoded,
and the offline derivation is exercised over synthetic journals shaped exactly
like the actual native journals (two ``mmio_delivery`` trigger writes, the
targets' own ``local_tick_sample`` raw outputs, the parsed CPU input, one native
take and the OR group frame with its member references).

The joint journal is additionally fed to the *real* shared observer
(``observe_declared_irq_consumption``) so the exact ambiguous refusal is the
production one; the unique observation document is a synthetic stand-in shaped
like the verified F5 document (the full consumption journal belongs to its own
suite) and is labelled as such.
"""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.run_irq_group_native import (
    MRET_WORD, REFUSAL_AMBIGUOUS, ZERO_GRANTS, admit_case, case_document,
    case_options, case_program, consumption_fields, member_source_ids,
    observed_member_id, semantic_digest, source_by_id, summary_document,
    transport_evidence, verify_observation)
from myfuzz.integration.declared_irq_consumption import (
    build_declared_irq_firmware, observe_declared_irq_consumption)
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember

ROOT = Path(__file__).resolve().parents[2]
CASES = ('joint-two-targets-ibex', 'unique-wb-timer-ibex', 'unique-apb-spi-ibex')
JOINT, TIMER, SPI = CASES
MEMBER_WIRES = {'wb_timer': 'rt_synthetic_wb_timer', 'spi': 'rt_synthetic_spi'}
MEMBER_WIDTHS = {'wb_timer': 1, 'spi': 2}
BOOT = 0x10080
TRIGGER_DEVICE = {'wb_timer': 'wb_timer', 'spi': 'spi'}


def configuration(name):
    return json.loads((ROOT / 'configs/scenarios/directed-irq-group'
                       / (name + '.json')).read_text())


def world(name):
    """Resolve one real config exactly like the native runner's preparation."""
    from myfuzz.composition.component_profile import load_component_profile
    config = configuration(name)
    options = case_options(config)
    admission = admit_case(config, options, ROOT)
    observed = source_by_id(options)[options['observed_source_id']]
    fields = consumption_fields(config, admission, observed)
    windows = {}
    for row in options['sources']:
        request = json.loads((ROOT / row['request']).read_text())
        windows[row['id']] = load_component_profile(
            ROOT / request['profile_path']).address.window_size
    firmware = build_declared_irq_firmware(
        image_start=fields['image_start'], image_end=fields['image_end'], first_fetch=BOOT,
        target_base=fields['target_base'], status_offsets=fields['status_offsets'],
        result_address=fields['result_address'], clear_writes=fields['clear_writes'])
    firmware['cause_bits'] = dict(fields['cause_bits'])
    firmware['digest'] = semantic_digest({key: value for key, value in firmware.items()
                                          if key != 'digest'})
    program = case_program(firmware, options, windows=windows)
    group = IrqDeliveryGroup(options['group_id'], 'cpu', 'irq',
                             tuple(IrqDeliveryMember(row['id'], row['source_port'],
                                                     pulse_width_ticks=row['pulse_width_ticks'],
                                                     source_bit_offset=row['source_bit_offset'],
                                                     source_adapter='declared-output.v1')
                                   for row in options['sources']))
    mappings = {row['id'] + '.' + row['source_port']:
                dict(adapter_id='declared-output.v1', physical_port=row['source_port'],
                     runtime_name=MEMBER_WIRES[row['id']],
                     source_width=MEMBER_WIDTHS[row['id']],
                     raw_bit_offset=row['source_bit_offset'])
                for row in options['sources']}
    return dict(config=config, options=options, admission=admission, fields=fields,
                firmware=firmware, program=program, group=group, mappings=mappings,
                windows=windows)


def _world(name):
    cache = _world.__dict__.setdefault('cache', {})
    if name not in cache:
        cache[name] = world(name)
    return cache[name]


def target_sample(event_id, *, component, tick, wire, raw, projection):
    return dict(kind='local_tick_sample', component=component, event_id=event_id,
                local_tick=tick, phase='post', reset_epoch=0, producer_event_id=event_id - 1,
                observation_schema_version='ip_raw_observation.v1',
                outputs=dict(physical={wire: raw}, **projection))


def trigger_delivery(event_id, *, row, offset, value):
    return dict(kind='mmio_delivery', component='cpu', event_id=event_id,
                device_id=row['id'], address=row['base'] + offset, offset=offset,
                write=True, write_value=value, read_value=None, byte_enable=15,
                producer_event_id=event_id - 1)


def member_reference(source_id, event_id, tick):
    source, port = source_id.split('.')
    return dict(adapter_id='declared-output.v1', component=source, event_id=event_id,
                local_tick=tick, phase='post', reset_epoch=0,
                runtime_name=MEMBER_WIRES[source], source_port=port)


def cpu_events(*, take=True, serial=5):
    sample = dict(kind='cpu_external_irq_sample', component='cpu', event_id=20,
                  local_tick=90, producer_event_id=19, expected_input=1,
                  actual_pre_input=1, actual_post_input=1, irq_masked_pre=0,
                  reset_epoch=0)
    taken = dict(kind='cpu_external_irq_taken', component='cpu', event_id=21,
                 local_tick=90, producer_event_id=19, sample_event_id=20,
                 take_key=['cpu', 0, 1], expected_input=1, actual_pre_input=1,
                 actual_post_input=1, irq_masked_pre=0, irq_taken_pre=1, reset_epoch=0,
                 irq_serial_observation=dict(
                     decision=dict(status='observed', value=serial),
                     retirement=dict(status='observed', value=0)))
    entry = dict(kind='cpu_retire', component='cpu', event_id=30, order=40,
                 pc_rdata=0x1022c, insn=0x06f, intr=1, trap=0, halt=0, valid=1,
                 local_tick=95,
                 irq_serial_observation=dict(retirement=dict(status='observed',
                                                             value=serial)))
    return ([sample, taken] if take else [sample]), entry


def joint_journal(case=JOINT):
    """Two real trigger writes, two real pulses, one take, one joint frame."""
    resolved = _world(case)
    options = resolved['options']
    rows = source_by_id(options)
    writes = options['trigger_writes']
    events = [trigger_delivery(5 + position, row=rows[name], offset=offset, value=value)
              for position, (name, offset, value) in enumerate(writes)]
    pulses = {}
    for position, name in enumerate(('wb_timer', 'spi')):
        event_id = 10 + position
        source = rows[name]
        pulses[name] = event_id
        events.append(target_sample(event_id, component=name, tick=50 + position,
                                    wire=MEMBER_WIRES[name], raw=1,
                                    projection={source['source_port']: 1}))
    events.extend(cpu_events()[0])
    members = [dict(source_id=source_id, mode='pulse', value=1,
                    native_source=member_reference(source_id, pulses[source_id.split('.')[0]],
                                                   tick=50 + index),
                    latest_native_source=member_reference(
                        source_id, pulses[source_id.split('.')[0]], tick=50 + index))
               for index, source_id in enumerate(member_source_ids(options))]
    events.append(dict(kind='irq_group_delivery', event_id=22,
                       group_id=resolved['group'].group_id,
                       group_sha256=resolved['group'].identity_sha256,
                       target_component='cpu', target_port='irq', cpu_tick=90, value=1,
                       attribution_status='joint', unique_source=None,
                       active_sources=list(member_source_ids(options)),
                       native_sample_event_id=20, native_take_event_id=21,
                       members=members))
    events.append(cpu_events()[1])
    events.sort(key=lambda event: event['event_id'])
    return events


def unique_journal(case=TIMER):
    """One real trigger write, one real pulse, one idle member, one unique frame."""
    resolved = _world(case)
    options = resolved['options']
    rows = source_by_id(options)
    name, offset, value = options['trigger_writes'][0]
    events = [trigger_delivery(5, row=rows[name], offset=offset, value=value)]
    observed = observed_member_id(options)
    idle_id, = [source_id for source_id in member_source_ids(options)
                if source_id != observed]
    pulses = {}
    for event_id, source_id in ((10, observed), (11, idle_id)):
        source, port = source_id.split('.')
        raw = 1 if source_id == observed else 0
        pulses[source_id] = event_id
        events.append(target_sample(event_id, component=source, tick=50,
                                    wire=MEMBER_WIRES[source], raw=raw,
                                    projection={port: raw}))
    events.extend(cpu_events()[0])
    members = [dict(source_id=source_id, mode='pulse',
                    value=1 if source_id == observed else 0,
                    native_source=member_reference(source_id, pulses[source_id], 50),
                    latest_native_source=member_reference(source_id, pulses[source_id], 50))
               for source_id in member_source_ids(options)]
    events.append(dict(kind='irq_group_delivery', event_id=22,
                       group_id=resolved['group'].group_id,
                       group_sha256=resolved['group'].identity_sha256,
                       target_component='cpu', target_port='irq', cpu_tick=90, value=1,
                       attribution_status='unique', unique_source=observed,
                       active_sources=[observed], native_sample_event_id=20,
                       native_take_event_id=21, members=members))
    events.append(cpu_events()[1])
    events.sort(key=lambda event: event['event_id'])
    return events


def find(events, event_id):
    return next(event for event in events if event['event_id'] == event_id)


def verified_observation(case=TIMER):
    """Synthetic stand-in shaped exactly like the verified F5 observation.

    The real verified document needs the full consumption journal (target native
    samples, OBI beats, RAM writes, retirements); that chain is covered by
    ``test_declared_irq_f5_consumption.py``.  Here only the fields the two-source
    case consumes are exercised.
    """
    resolved = _world(case)
    group = resolved['group']
    observed = observed_member_id(resolved['options'])
    value = 0x1234
    return dict(
        schema_version='declared_irq_f5_consumption.v1', status='verified',
        irq_consumption='verified', case_id='synthetic-verified',
        group=dict(group_id=group.group_id, group_sha256=group.identity_sha256,
                   target_component=group.target_component,
                   target_port=group.target_port,
                   member_source_ids=list(member_source_ids(resolved['options']))),
        transport=dict(status='observed', attribution='unique',
                       or_frame=dict(unique_source=observed, active_sources=[observed])),
        consumption=dict(
            status='verified', irq_consumption='verified',
            value_join='delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value',
            retirement_joins='exact_fields',
            register_reads=[dict(offset=resolved['fields']['status_offsets'][0],
                                 value=value, target_register_index=0)],
            result_ram_writes=[dict(index=0, address=resolved['firmware']['result_address'],
                                    value=value)],
            mret=dict(insn=MRET_WORD), successor=dict(event_id=41)),
        cause_source='unknown',
        unknown=dict(internal_ip_cause='unknown', internal_version='unknown',
                     case_origin='unknown',
                     cross_case_writer_attribution='unknown'),
        refusals=[], **ZERO_GRANTS)


def joint_case(case=JOINT):
    resolved = _world(case)
    events = joint_journal(case)
    transport = transport_evidence(events, group=resolved['group'],
                                   options=resolved['options'],
                                   mappings=resolved['mappings'])
    observation = observe_declared_irq_consumption(
        events=tuple(events), receipt=SimpleNamespace(case_id='synthetic-joint',
                                                      events=tuple(events)),
        traces={}, error_policy=None, cpu_id='cpu',
        target_id=resolved['options']['observed_source_id'],
        access=dict(device_id=resolved['options']['observed_source_id'],
                    target_component=resolved['options']['observed_source_id'],
                    window_base=resolved['fields']['target_base'],
                    window_size=resolved['fields']['window_size'],
                    offset=resolved['fields']['status_offsets'][0]),
        firmware=resolved['firmware'], group=resolved['group'])
    return transport, observation


def derive_unique(case=TIMER, *, observation=None, events=None):
    resolved = _world(case)
    events = unique_journal(case) if events is None else events
    transport = transport_evidence(events, group=resolved['group'],
                                   options=resolved['options'],
                                   mappings=resolved['mappings'])
    return transport, (verified_observation(case) if observation is None else observation)


# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('name', CASES)
def test_real_configs_declare_the_two_real_declared_output_members(name):
    resolved = _world(name)
    options = resolved['options']
    assert [row['id'] for row in options['sources']] == ['wb_timer', 'spi']
    assert [(row['source_port'], row['source_bit_offset'])
            for row in options['sources']] == [('o_int', 0), ('events_o', 0)]
    assert [row['base'] for row in options['sources']] == [0x40001000, 0x40002000]
    assert member_source_ids(options) == ('wb_timer.o_int', 'spi.events_o')
    assert resolved['windows'] == {'wb_timer': 4, 'spi': 4096}
    assert options['group_id'] == 'declared-irq-group-wb-timer-apb-spi'
    widths = [row['pulse_width_ticks'] for row in options['sources']]
    if name == JOINT:
        assert options['expected_attribution'] == 'joint'
        assert options['mie_gate'] is True
        assert options['observed_source_id'] == 'wb_timer'
        assert widths == [22, 22]
        assert options['trigger_writes'] == (('wb_timer', 0, 8), ('spi', 36, 0x80000000))
    else:
        assert options['expected_attribution'] == 'unique'
        assert options['mie_gate'] is False
        # The single-member cases reuse the proven F5 native host width.
        assert widths == [16, 16]
        assert len(options['trigger_writes']) == 1
        assert options['trigger_writes'][0][0] == options['observed_source_id']
    assert options['observed_source_id'] in {row['id'] for row in options['sources']}


def test_all_three_configs_declare_the_same_two_member_group():
    identities, documents = [], []
    for name in CASES:
        resolved = _world(name)
        documents.append(resolved['group'].document())
        identities.append(resolved['group'].identity_sha256)
    membership = [(row['source_component'], row['source_port'], row['mode'])
                  for row in documents[0]['members']]
    assert membership == [('wb_timer', 'o_int', 'pulse'), ('spi', 'events_o', 'pulse')]
    assert all([(row['source_component'], row['source_port'], row['mode'])
                for row in document['members']] == membership for document in documents)
    # The two single-member configs are the same real group object; the joint
    # case only widens the host pulse stretch, which is part of the identity.
    assert identities[1] == identities[2]
    assert identities[0] != identities[1]
    joint, single = documents[0], documents[1]
    for key in ('group_id', 'target_component', 'target_port', 'operation'):
        assert joint[key] == single[key]
    for left, right in zip(joint['members'], single['members']):
        assert {key: value for key, value in left.items() if key != 'pulse_width_ticks'} == \
            {key: value for key, value in right.items() if key != 'pulse_width_ticks'}


@pytest.mark.parametrize('name', CASES)
def test_real_configs_admit_the_observed_declared_register_map(name):
    resolved = _world(name)
    admission = resolved['admission']
    assert admission['status'] == 'admitted'
    assert admission['cpu']['retirement_authority'] == 'full_rvfi_retirement_receipt'
    observed = source_by_id(resolved['options'])[resolved['options']['observed_source_id']]
    assert resolved['fields']['target_base'] == observed['base']
    expected = ([0] if resolved['options']['observed_source_id'] == 'wb_timer' else [40])
    assert resolved['fields']['status_offsets'] == expected
    assert [row['offset'] for row in admission['target']['status_registers']] == expected
    assert admission['target']['window_size'] == resolved['windows'][observed['id']]


MUTATIONS = (
    ('configuration-shape', lambda config: []),
    ('configuration-schema', lambda config: dict(config, schema_version='other')),
    ('configuration-cpu-profile', lambda config: dict(config, cpu_profile='')),
    ('configuration-expected-attribution',
     lambda config: dict(config, expected_attribution='both')),
    ('configuration-mie-gate', lambda config: dict(config, mie_gate='yes')),
    ('configuration-joint-requires-mie-gate',
     lambda config: dict(config, mie_gate=False)),
    ('configuration-two-sources',
     lambda config: dict(config, sources=config['sources'][:1])),
    ('configuration-source-ids-unique',
     lambda config: dict(config, sources=[dict(config['sources'][0]),
                                          dict(config['sources'][1], id='wb_timer')])),
    ('configuration-source-bases-unique',
     lambda config: dict(config, sources=[dict(config['sources'][0]),
                                          dict(config['sources'][1],
                                               base=config['sources'][0]['base'])])),
    ('configuration-source-base',
     lambda config: dict(config, sources=[dict(config['sources'][0], base=0x40001008),
                                          config['sources'][1]])),
    ('configuration-source-port',
     lambda config: dict(config, sources=[dict(config['sources'][0], source_port=''),
                                          config['sources'][1]])),
    ('configuration-source-bit-offset',
     lambda config: dict(config, sources=[dict(config['sources'][0],
                                               source_bit_offset=64),
                                          config['sources'][1]])),
    ('configuration-source-pulse-width',
     lambda config: dict(config, sources=[dict(config['sources'][0],
                                               pulse_width_ticks=0),
                                          config['sources'][1]])),
    ('configuration-observed-source',
     lambda config: dict(config, observed_source_id='gpio')),
    ('configuration-trigger-plan', lambda config: dict(config, trigger_writes=[])),
    ('configuration-trigger-source',
     lambda config: dict(config, trigger_writes=[['uart', 0, 1], ['spi', 36, 1]])),
    ('configuration-trigger-offset',
     lambda config: dict(config, trigger_writes=[['wb_timer', 2, 8],
                                                ['spi', 36, 0x80000000]])),
    ('configuration-trigger-value',
     lambda config: dict(config, trigger_writes=[['wb_timer', 0, -1],
                                                ['spi', 36, 0x80000000]])),
    ('configuration-joint-trigger-plan-members',
     lambda config: dict(config, trigger_writes=[['wb_timer', 0, 8]])),
    ('configuration-joint-trigger-plan-members',
     lambda config: dict(config, trigger_writes=[['wb_timer', 0, 8],
                                                ['wb_timer', 0, 9]])),
)


@pytest.mark.parametrize('reason,mutation', MUTATIONS)
def test_joint_configuration_refusals(reason, mutation):
    with pytest.raises(ValueError, match='irq-group-' + reason):
        case_options(mutation(configuration(JOINT)))


def test_unique_configuration_refusals():
    with pytest.raises(ValueError, match='irq-group-configuration-unique-forbids-mie-gate'):
        case_options(dict(configuration(TIMER), mie_gate=True))
    # A unique case must trigger the member it observes, once.
    with pytest.raises(ValueError, match='irq-group-configuration-unique-trigger-plan-observed-source'):
        case_options(dict(configuration(TIMER), trigger_writes=[['spi', 36, 0x80000000]]))
    with pytest.raises(ValueError, match='irq-group-configuration-unique-trigger-plan-observed-source'):
        case_options(dict(configuration(TIMER), trigger_writes=[['wb_timer', 0, 8],
                                                               ['spi', 36, 0x80000000]]))


def test_consumption_fields_refuse_an_undeclared_status_offset():
    resolved = _world(SPI)
    with pytest.raises(ValueError, match='declared-F5-configuration-status-offset-undeclared'):
        consumption_fields(dict(resolved['config'], status_offsets=[42]),
                           resolved['admission'],
                           source_by_id(resolved['options'])['spi'])
    observed = source_by_id(resolved['options'])['spi']
    assert consumption_fields(resolved['config'], resolved['admission'],
                              observed)['window_size'] == \
        resolved['admission']['target']['window_size']
    with pytest.raises(ValueError, match='irq-group-admission-not-admitted'):
        consumption_fields(resolved['config'], dict(resolved['admission'],
                                                    status='unsupported'),
                           source_by_id(resolved['options'])['spi'])


# ---------------------------------------------------------------------------
# Fixed program
# ---------------------------------------------------------------------------
def words(data_hex):
    data = bytes.fromhex(data_hex)
    return [int.from_bytes(data[offset:offset + 4], 'little')
            for offset in range(0, len(data), 4)]


def addi_immediate(word):
    immediate = (word >> 20) & 0xfff
    return immediate - (1 << 12) if immediate & 0x800 else immediate


def store_offset(word):
    return (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 31)


@pytest.mark.parametrize('name', (TIMER, SPI))
def test_unique_program_is_the_declared_store_then_a_park(name):
    resolved = _world(name)
    program = resolved['program']
    source = source_by_id(resolved['options'])[resolved['options']['observed_source_id']]
    image = words(program['images'][str(program['case_entry'])])
    assert program['mie_gate'] is False
    assert program['case_words'] == 6 and len(image) == 6
    assert [row['kind'] for row in program['words']] == [
        'load_base:' + source['id'], 'load_base:' + source['id'],
        'load_value:' + source['id'], 'load_value:' + source['id'],
        'store_trigger:' + source['id'], 'park']
    assert image[0] & 0x7f == 0x37 and image[1] & 0x7f == 0x13
    assert (image[0] & 0xfffff000) + addi_immediate(image[1]) == source['base']
    assert (image[2] & 0x7f == 0x37
            and (image[2] & 0xfffff000) + addi_immediate(image[3])
            == resolved['options']['trigger_writes'][0][2])
    store = image[4]
    assert store & 0x7f == 0x23 and (store >> 15) & 31 == 8 and (store >> 20) & 31 == 9
    assert store_offset(store) == resolved['options']['trigger_writes'][0][1]
    assert image[5] == 0x0000006f and program['park'] == program['case_entry'] + 5 * 4
    assert program['dynamic_sha256'] == semantic_digest_hex(
        program['images'][str(program['case_entry'])])
    fixed = [(row['address'], row['address'] + len(bytes.fromhex(row['data_hex'])))
             for row in resolved['firmware']['segments']]
    assert all(stop <= program['case_entry'] or program['park'] + 4 <= start
               for start, stop in fixed)


def semantic_digest_hex(data_hex):
    from hashlib import sha256
    return sha256(bytes.fromhex(data_hex)).hexdigest()


def test_joint_program_gates_mie_around_both_ordered_stores():
    resolved = _world(JOINT)
    program = resolved['program']
    options = resolved['options']
    image = words(program['images'][str(program['case_entry'])])
    kinds = [row['kind'] for row in program['words']]
    assert program['mie_gate'] is True
    assert program['case_words'] == 14 and len(image) == 14
    # The masked-phase idiom of scripts/run_cv32e20_irq_smoke.fixed_program:
    # addi x3, 0, 8 ; csrrc mstatus, x3  ...  csrrs mstatus, x3.
    assert image[0] == 0x00800193 and addi_immediate(image[0]) == 8
    assert image[1] == 0x3001b073 and (image[1] >> 12) & 7 == 3
    assert image[12] == 0x3001a073 and (image[12] >> 12) & 7 == 2
    assert kinds[0] == 'load_mie_mask' and kinds[1] == 'clear_mstatus_mie'
    assert kinds[12] == 'set_mstatus_mie' and kinds[13] == 'park'
    rows = source_by_id(options)
    position = 2
    for name, offset, value in options['trigger_writes']:
        source = rows[name]
        assert (image[position] & 0xfffff000) + addi_immediate(image[position + 1]) \
            == source['base']
        assert (image[position + 2] & 0xfffff000) + addi_immediate(image[position + 3]) \
            == value
        store = image[position + 4]
        assert store & 0x7f == 0x23 and (store >> 15) & 31 == 8
        assert store_offset(store) == offset
        position += 5
    assert kinds[6] == 'store_trigger:wb_timer' and kinds[11] == 'store_trigger:spi'
    assert image[13] == 0x0000006f and program['park'] == program['case_entry'] + 13 * 4
    # The fixed images are still present and untouched by the case image.
    for segment in resolved['firmware']['segments']:
        assert program['images'][str(segment['address'])] == segment['data_hex']


def fake_firmware(**overrides):
    document = dict(image_start=0x10000, image_end=0x30000, dynamic_start=0x11000,
                    first_fetch=BOOT, vector=0x10200, handler=0x10400, scratch=0x10c00,
                    result_address=0x10c40, result_words=1, status_offsets=[0],
                    handler_words=16, segments=[], digest='synthetic')
    document.update(overrides)
    return document


def test_program_refuses_offsets_outside_the_declared_window():
    resolved = _world(JOINT)
    with pytest.raises(ValueError, match='irq-group-program-trigger-outside-window'):
        case_program(resolved['firmware'],
                     dict(resolved['options'], trigger_writes=(('wb_timer', 4, 8),)),
                     windows={'wb_timer': 4, 'spi': 4096})
    with pytest.raises(ValueError, match='irq-group-program-trigger-outside-window'):
        case_program(resolved['firmware'],
                     dict(resolved['options'], trigger_writes=(('spi', 4096, 1),)),
                     windows={'wb_timer': 4, 'spi': 4096})
    with pytest.raises(ValueError, match='irq-group-program-windows'):
        case_program(resolved['firmware'], resolved['options'], windows={'wb_timer': 4})
    with pytest.raises(ValueError, match='irq-group-program-firmware'):
        case_program(dict(resolved['firmware'], handler_words=0), resolved['options'],
                     windows={'wb_timer': 4, 'spi': 4096})


def test_program_refuses_an_image_that_leaves_the_fixed_window():
    resolved = _world(JOINT)
    with pytest.raises(ValueError, match='irq-group-program-overflow'):
        case_program(fake_firmware(dynamic_start=0x2fff0), resolved['options'],
                     windows={'wb_timer': 4, 'spi': 4096})
    with pytest.raises(ValueError, match='irq-group-program-overlaps-fixed-image'):
        case_program(fake_firmware(segments=[dict(name='trap', address=0x11010,
                                                  data_hex='00000000')]),
                     resolved['options'], windows={'wb_timer': 4, 'spi': 4096})


# ---------------------------------------------------------------------------
# Offline derivation: joint
# ---------------------------------------------------------------------------
def test_joint_journal_derives_joint_and_the_shared_observer_refuses():
    resolved = _world(JOINT)
    transport, observation = joint_case()
    assert transport['attribution'] == 'joint'
    assert transport['frame']['value'] == 1
    assert transport['frame']['attribution_status'] == 'joint'
    assert transport['frame']['unique_source'] is None
    assert transport['active_sources'] == list(member_source_ids(resolved['options']))
    # Both members' own raw output samples prove the declared bit.
    proofs = {proof['source_id']: proof for proof in transport['members']}
    assert proofs['wb_timer.o_int']['raw_value'] == 1
    assert proofs['wb_timer.o_int']['bit_value'] == 1
    assert proofs['spi.events_o']['raw_value'] == 1
    assert proofs['spi.events_o']['bit_value'] == 1
    assert proofs['spi.events_o']['runtime_name'] == MEMBER_WIRES['spi']
    # The single native take and its decision serial join the handler entry.
    assert transport['cpu']['decision_serial'] == 5
    assert transport['cpu']['decision_serial_status'] == 'observed'
    assert transport['cpu']['first_handler_retirement']['event_id'] == 30
    assert transport['overlap']['joint_frame_count'] == 1
    # The production observer refuses the joint frame as ambiguous.
    assert observation['status'] == 'ambiguous'
    assert observation['irq_consumption'] == 'unknown'
    assert observation['refusals'] == [REFUSAL_AMBIGUOUS]
    assert observation['consumption']['status'] == 'ambiguous'
    assert observation['consumption']['active_sources'] == transport['active_sources']
    assert observation['transport']['attribution'] == 'ambiguous'
    case = case_document(options=resolved['options'], group=resolved['group'],
                         mappings=resolved['mappings'], transport=transport,
                         observation=observation, program=resolved['program'],
                         firmware=resolved['firmware'], admission=resolved['admission'],
                         case_id='synthetic-joint')
    assert case['status'] == 'verified' and case['attribution'] == 'joint'
    assert case['observation']['refusals'] == [REFUSAL_AMBIGUOUS]
    assert case['scope']['consumption'] == 'ambiguous_unknown_no_credit'
    for flag in ('grants_F5', 'grants_F6', 'reward_eligible', 'grants_prerequisites'):
        assert case[flag] is False


def test_joint_frame_is_never_accepted_as_unique():
    # The joint journal's real frame is joint; even if an (inconsistent) unique
    # expectation is forced onto the same two-write plan it must be refused.
    resolved = _world(JOINT)
    forced = dict(resolved['options'], expected_attribution='unique')
    with pytest.raises(ValueError, match='irq-group-attribution-mismatch'):
        transport_evidence(joint_journal(JOINT), group=resolved['group'],
                           options=forced, mappings=resolved['mappings'])
    # And a unique frame under a forced joint expectation is refused too.
    resolved = _world(TIMER)
    forced = dict(resolved['options'], expected_attribution='joint')
    with pytest.raises(ValueError, match='irq-group-attribution-mismatch'):
        transport_evidence(unique_journal(TIMER), group=resolved['group'],
                           options=forced, mappings=resolved['mappings'])


def test_joint_case_needs_two_members_active_in_the_take_frame():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    frame = find(events, 22)
    frame['attribution_status'] = 'unique'
    frame['unique_source'] = 'wb_timer.o_int'
    frame['active_sources'] = ['wb_timer.o_int']
    with pytest.raises(ValueError, match='irq-group-attribution-mismatch'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_joint_frame_without_a_take_refuses():
    resolved = _world(JOINT)
    events = [event for event in joint_journal(JOINT)
              if event['event_id'] not in (21, 30)]
    frame = find(events, 22)
    del frame['native_take_event_id']
    with pytest.raises(ValueError, match='irq-group-one-actual-native-CPU-take'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    events = joint_journal(JOINT)
    find(events, 22)['native_take_event_id'] = 999
    with pytest.raises(ValueError, match='irq-group-actual-OR-frame-take-join'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_two_takes_refuse():
    resolved = _world(JOINT)
    events = joint_journal(JOINT)
    second = dict(deepcopy(find(events, 21)), event_id=40, sample_event_id=39,
                  irq_serial_observation=dict(decision=dict(status='observed', value=6),
                                              retirement=dict(status='observed', value=0)))
    events.append(second)
    events.sort(key=lambda event: event['event_id'])
    with pytest.raises(ValueError, match='irq-group-one-actual-native-CPU-take'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_frame_with_a_foreign_member_refuses():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    frame = find(events, 22)
    frame['members'].append(dict(source_id='gpio.irq', mode='pulse', value=1,
                                 native_source=frame['members'][0]['native_source']))
    with pytest.raises(ValueError, match='irq-group-OR-frame-declared-members'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    events = deepcopy(joint_journal(JOINT))
    find(events, 22)['active_sources'] = ['gpio.irq', 'wb_timer.o_int']
    with pytest.raises(ValueError, match='irq-group-OR-frame-active-within-group'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    # A frame of another group is refused by identity.
    events = deepcopy(joint_journal(JOINT))
    find(events, 22)['group_sha256'] = '0' * 64
    with pytest.raises(ValueError, match='irq-group-OR-frame-group-identity'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_member_raw_bit_must_match_the_frame_value():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    find(events, 10)['outputs']['physical'][MEMBER_WIRES['wb_timer']] = 0
    find(events, 10)['outputs']['o_int'] = 0
    with pytest.raises(ValueError, match='irq-group-member-native-output-bit'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    # A member reference that is not the declared wire refuses.
    events = deepcopy(joint_journal(JOINT))
    find(events, 11)['outputs']['physical'][MEMBER_WIRES['spi']] = 2
    with pytest.raises(ValueError, match='irq-group-member-native-output-bit'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_member_pulse_must_follow_its_own_trigger_write():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    for event in (find(events, 5), find(events, 6)):
        event['event_id'] = event['event_id'] + 100
        event['producer_event_id'] = event['event_id'] - 1
    events.sort(key=lambda event: event['event_id'])
    with pytest.raises(ValueError, match='irq-group-member-pulse-after-own-trigger'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_trigger_sequence_must_be_the_declared_plan():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    first, second = find(events, 5), find(events, 6)
    first['device_id'], second['device_id'] = second['device_id'], first['device_id']
    first['address'], second['address'] = second['address'], first['address']
    with pytest.raises(ValueError, match='irq-group-actual-MMIO-trigger-sequence'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    events = deepcopy(joint_journal(JOINT))
    find(events, 5)['address'] = 0x40001004
    with pytest.raises(ValueError, match='irq-group-actual-MMIO-trigger-address'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_cpu_input_and_serial_are_required():
    resolved = _world(JOINT)
    events = deepcopy(joint_journal(JOINT))
    find(events, 21)['irq_taken_pre'] = 0
    with pytest.raises(ValueError, match='irq-group-native-take-decision-probe'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    events = deepcopy(joint_journal(JOINT))
    find(events, 20)['actual_post_input'] = 0
    with pytest.raises(ValueError, match='irq-group-CPU-input-pre-post-mismatch'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])
    events = deepcopy(joint_journal(JOINT))
    find(events, 30)['irq_serial_observation']['retirement']['value'] = 6
    with pytest.raises(ValueError, match='irq-group-first-handler-retirement-serial'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


# ---------------------------------------------------------------------------
# Offline derivation: unique
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('name', (TIMER, SPI))
def test_unique_journal_derives_one_active_member_and_accepts_the_verified_chain(name):
    resolved = _world(name)
    transport, observation = derive_unique(name)
    observed = observed_member_id(resolved['options'])
    assert transport['attribution'] == 'unique'
    assert transport['active_sources'] == [observed]
    assert transport['unique_source'] == observed
    proofs = {proof['source_id']: proof for proof in transport['members']}
    assert proofs[observed]['raw_value'] == 1
    idle_id, = [source_id for source_id in member_source_ids(resolved['options'])
                if source_id != observed]
    assert proofs[idle_id]['value'] == 0 and proofs[idle_id]['raw_value'] == 0
    case = case_document(options=resolved['options'], group=resolved['group'],
                         mappings=resolved['mappings'], transport=transport,
                         observation=observation, program=resolved['program'],
                         firmware=resolved['firmware'], admission=resolved['admission'],
                         case_id='synthetic-unique')
    assert case['status'] == 'verified' and case['attribution'] == 'unique'
    assert case['observation']['status'] == 'verified'
    assert case['observation']['irq_consumption'] == 'verified'
    assert case['scope']['consumption'] == 'verified_declared_status_read_value_chain'


def test_unique_case_requires_exactly_one_active_member():
    resolved = _world(TIMER)
    events = deepcopy(unique_journal(TIMER))
    frame = find(events, 22)
    # The untriggered member becomes genuinely active: no longer unique.
    find(events, 11)['outputs']['physical'][MEMBER_WIRES['spi']] = 1
    find(events, 11)['outputs']['events_o'] = 1
    frame['members'][1]['value'] = 1
    frame['attribution_status'] = 'joint'
    frame['unique_source'] = None
    frame['active_sources'] = list(member_source_ids(resolved['options']))
    with pytest.raises(ValueError, match='irq-group-attribution-mismatch'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_unique_case_refuses_an_other_member_active_anywhere_else():
    resolved = _world(TIMER)
    events = deepcopy(unique_journal(TIMER))
    idle_id, = [source_id for source_id in member_source_ids(resolved['options'])
                if source_id != observed_member_id(resolved['options'])]
    frame = dict(find(events, 22), event_id=24, cpu_tick=91, value=0,
                 active_sources=[idle_id], attribution_status='unique',
                 unique_source=idle_id)
    frame.pop('native_take_event_id')
    frame.pop('native_sample_event_id')
    events.append(frame)
    events.sort(key=lambda event: event['event_id'])
    with pytest.raises(ValueError, match='irq-group-unique-case-single-active-member'):
        transport_evidence(events, group=resolved['group'], options=resolved['options'],
                           mappings=resolved['mappings'])


def test_unique_observation_must_be_the_verified_chain():
    resolved = _world(TIMER)
    transport, _ = derive_unique(TIMER)
    broken = verified_observation(TIMER)
    broken['status'] = 'refused'
    with pytest.raises(ValueError, match='irq-group-unique-observation-verified'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    broken = verified_observation(TIMER)
    broken['consumption']['value_join'] = 'delivery_read_value==RAM_write_value'
    with pytest.raises(ValueError, match='irq-group-unique-consumption-value-join'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    broken = verified_observation(TIMER)
    broken['consumption']['result_ram_writes'][0]['value'] = 0xdead
    with pytest.raises(ValueError, match='irq-group-unique-consumption-write-value'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    broken = verified_observation(TIMER)
    broken['consumption']['mret']['insn'] = 0x00000013
    with pytest.raises(ValueError, match='irq-group-unique-consumption-mret'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    broken = verified_observation(TIMER)
    broken['grants_F5'] = True
    with pytest.raises(ValueError, match='irq-group-observation-false-grant-grants_F5'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    broken = verified_observation(TIMER)
    broken['group']['group_sha256'] = '1' * 64
    with pytest.raises(ValueError, match='irq-group-observation-group-identity'):
        verify_observation(broken, expected_attribution='unique',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])


def test_joint_observation_must_be_the_ambiguous_refusal():
    resolved = _world(JOINT)
    transport, observation = joint_case()
    verified = verified_observation(SPI)
    verified['group'] = dict(verified['group'], group_id=resolved['group'].group_id,
                             group_sha256=resolved['group'].identity_sha256)
    with pytest.raises(ValueError, match='irq-group-joint-observation-ambiguous'):
        verify_observation(verified, expected_attribution='joint',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    assert observation['refusals'] == [REFUSAL_AMBIGUOUS]
    other = deepcopy(observation)
    other['refusals'] = ['declared-F5-one-actual-native-CPU-take-required']
    with pytest.raises(ValueError, match='irq-group-joint-observation-refusal'):
        verify_observation(other, expected_attribution='joint',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    other = deepcopy(observation)
    other['consumption']['active_sources'] = ['wb_timer.o_int']
    with pytest.raises(ValueError, match='irq-group-joint-observation-active-sources'):
        verify_observation(other, expected_attribution='joint',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])
    other = deepcopy(observation)
    other['consumption']['register_reads'] = [dict(offset=40, value=1)]
    with pytest.raises(ValueError, match='irq-group-joint-observation-no-credit'):
        verify_observation(other, expected_attribution='joint',
                           active_sources=transport['active_sources'],
                           observed_member_id=observed_member_id(resolved['options']),
                           group=resolved['group'])


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def test_summary_never_grants_f5_f6_or_reward():
    resolved = _world(JOINT)
    transport, observation = joint_case()
    case = case_document(options=resolved['options'], group=resolved['group'],
                         mappings=resolved['mappings'], transport=transport,
                         observation=observation, program=resolved['program'],
                         firmware=resolved['firmware'], admission=resolved['admission'],
                         case_id='synthetic-joint')
    summary = summary_document(options=resolved['options'], case=case,
                               processes={'original': [], 'fresh': []}, mode='both',
                               fresh_matches=True)
    assert summary['status'] == 'verified'
    assert summary['attribution'] == 'joint'
    assert summary['expected_attribution'] == 'joint'
    assert summary['mie_gate'] is True
    for flag in ('grants_F5', 'grants_F6', 'reward_eligible', 'grants_prerequisites'):
        assert summary[flag] is False
    assert summary['isr_mmio'] == 'unknown'
    assert summary['internal_version'] == 'unknown'
    assert summary['case_origin'] == 'unknown'
    assert summary['scope']['mode_scope'] == 'same-invocation-independent-native-sessions'
    assert 'F5-pin-grammar' in summary['scope']['excludes']
    assert 'reward' in summary['scope']['excludes']
    assert summary['semantic_sha256'] == semantic_digest(case)
    assert summary['fresh_scope'] == 'same-invocation-independent-native-sessions'
    assert summary['result']['decision_serial'] == 5
    with pytest.raises(ValueError, match='irq-group-summary-case-false-grant-grants_F5'):
        summary_document(options=resolved['options'],
                         case=dict(case, grants_F5=True),
                         processes={}, mode='both')
    with pytest.raises(ValueError, match='irq-group-summary-case'):
        summary_document(options=resolved['options'], case=dict(case, status='refused'),
                         processes={}, mode='both')


def test_semantic_digest_is_canonical_and_order_independent():
    assert semantic_digest({'b': 2, 'a': 1}) == semantic_digest({'a': 1, 'b': 2})
    assert semantic_digest({'a': 1}) != semantic_digest({'a': 2})
