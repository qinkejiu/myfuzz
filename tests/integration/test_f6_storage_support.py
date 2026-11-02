"""Fixed storage support uses shared source contracts and CPU instruction ABI."""
from copy import deepcopy
from dataclasses import replace
import pytest

from tests.integration.test_f6_storage_shared_assembly import inputs, ROOT


def support_inputs(inputs, **overrides):
    from myfuzz.scenario.compiled_paths import compile_paths
    compiled, artifacts = inputs
    request = compiled['request']
    document = deepcopy(request.document)
    document['f6_execution']['program']['slot_count'] = 1
    support = dict(component='peripheral', contract_id='pulp-apb-timer.ctrl0.source.v1',
        register='TIMER0_CTRL', before_value=0x55, after_value=0xaa,
        before_result_address=0x25000, after_result_address=0x25004)
    support.update(overrides)
    document['f6_execution']['storage_support'] = support
    request = replace(request, document=document)
    return dict(compiled, request=request, compiled=compile_paths(request)), artifacts


def test_support_is_source_derived_and_uses_canonical_shared_writer(inputs):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.integration.f6_storage_support import storage_fragment
    from myfuzz.integration.generated_register_writer import declare_writer
    compiled, _ = support_inputs(inputs)
    contract = next(p['execution_contract'] for p in compiled['compiled']['paths'] if p['flow_id'] == 'F6')
    support = contract['program_contract']['storage_support']
    assert support['address'] == 0x40001004
    assert support['ownership'] == 'fixed_support'
    path = next(p for p in compiled['compiled']['paths'] if p['flow_id'] == 'F4')
    source = next(s for s in path['sources'] if s['kind'] == 'cpu_mmio_stream')
    program = build_f6_firmware(contract)
    for phase in ('before', 'after'):
        declaration = declare_writer(compiled['request'], compiled['compiled'],
            source_id=source['source_id'], value=support[phase+'_value'],
            result_address=support[phase+'_result_address'])
        assert storage_fragment(support, phase).hex() == declaration['code_hex']
        site = program.document()['storage_support_sites'][phase]
        initial = program.initial_images[site['segment_address']]
        offset = site['address'] - site['segment_address']
        assert initial[offset:offset+site['size']] == bytes.fromhex(declaration['code_hex'])


@pytest.mark.parametrize('overrides', [
    dict(register='COUNT'), dict(before_value=-1),
    dict(before_result_address=0x22000), dict(after_result_address=0x25000),
    dict(component='dma'),
])
def test_support_cannot_bypass_source_or_ram_reservations(inputs, overrides):
    with pytest.raises(ValueError):
        support_inputs(inputs, **overrides)


def test_support_keeps_full_three_component_live_binding(inputs, tmp_path):
    from tests.integration.test_f6_storage_shared_assembly import live_session_binding
    from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
    compiled = support_inputs(inputs)
    assembly, _, binding, kwargs = live_session_binding(compiled, tmp_path)
    validate_f6_execution_binding(binding, **kwargs)
    authority = assembly.companion_authorities['peripheral']
    assert authority.target is assembly.companions['peripheral']
    assert set(binding['issuer_contracts']['shared_companions']) == {'peripheral'}


def support_journal():
    """Synthetic native beats and callback joins; never live authority."""
    from myfuzz.integration.f6_storage_support import storage_fragment
    support = dict(address=0x40001004, before_value=85, before_result_address=0x25000)
    code = storage_fragment(support, 'before')
    site = dict(address=0x100a0)
    roles = ('req', 'gnt', 'addr', 'we', 'wdata', 'be', 'rvalid', 'rdata', 'error')
    traces = {channel: {role: channel+'_'+role for role in roles} for channel in ('instr', 'data')}
    events = []
    def add(**row):
        row['event_id'] = len(events)+1
        events.append(row)
        return row
    def step(channel, **pins):
        tick = len(events)+1
        return add(component='cpu', local_tick=tick,
            outputs=dict(driver_samples=[dict(local_tick=tick,
                pre=dict(protocol_taps={traces[channel][role]: value for role, value in pins.items()}))]))
    for index, offset in enumerate(range(0, 32, 4), 1):
        request = step('instr', req=1, gnt=1, addr=site['address']+offset)
        add(kind='memory_read', component='cpu', address=site['address']+offset,
            producer_event_id=request['event_id'], data_hex=code[offset:offset+4].hex(),
            writer_kinds=('INITIAL_IMAGE',)*4,
            transaction=dict(channel_id='instr', source_sequence=index))
        step('instr', rvalid=1, error=0, rdata=int.from_bytes(code[offset:offset+4], 'little'))
    joins = []
    for index, write in ((1, True), (2, False)):
        request = step('data', req=1, gnt=1, addr=support['address'], we=int(write), wdata=85 if write else 0, be=15)
        accepted = add(kind='mmio_acceptance', producer_event_id=request['event_id'])
        delivery = add(kind='mmio_delivery', source_transaction=dict(source_sequence=index))
        step('data', rvalid=1, error=0, rdata=0 if write else 85)
        joins.append(dict(acceptance_event=accepted['event_id'], delivery_event=delivery['event_id'], write=write))
    request = step('data', req=1, gnt=1, addr=0x25000, we=1, wdata=85, be=15)
    ram = add(kind='memory_write', producer_event_id=request['event_id'], value=85,
        transaction=dict(source_sequence=3))
    step('data', rvalid=1, error=0, rdata=0)
    return events, dict(support=support, phase='before', cpu='cpu', code=code, site=site,
        observed=dict(joins=joins, RAM_event=ram['event_id'])), traces


def test_fixed_support_requires_native_instruction_and_data_consumption():
    from myfuzz.integration.f6_storage_support import verify_support_native_hops
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    events, kwargs, traces = support_journal()
    beats = collect_native_obi_beats(events, cpu='cpu', traces=traces,
        error_policy=dict(native_error_observation=True))
    instructions, data, ram = verify_support_native_hops(events, **kwargs, beats=beats)
    assert len(instructions) == 8
    assert data[1]['rdata'] == ram['value'] == 85
    assert ram['acceptance_event'] > data[1]['response_event']


@pytest.mark.parametrize('mutation', ['wrong_return', 'foreign_instruction_writer', 'foreign_acceptance', 'RAM_value'])
def test_fixed_support_rejects_counterfactual_native_hops(mutation):
    from myfuzz.integration.f6_storage_support import verify_support_native_hops
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    events, kwargs, traces = support_journal()
    if mutation == 'wrong_return':
        beat = next(row for row in events if row.get('outputs', {}).get('driver_samples', [{}])[0]
            .get('pre', {}).get('protocol_taps', {}).get('data_rdata') == 85)
        beat['outputs']['driver_samples'][0]['pre']['protocol_taps']['data_rdata'] = 86
    elif mutation == 'foreign_instruction_writer':
        next(row for row in events if row.get('kind') == 'memory_read')['writer_kinds'] = ('STORE',)*4
    elif mutation == 'foreign_acceptance':
        next(row for row in events if row.get('kind') == 'mmio_acceptance')['producer_event_id'] = 1
    else:
        next(row for row in events if row.get('kind') == 'memory_write')['value'] = 86
    beats = collect_native_obi_beats(events, cpu='cpu', traces=traces,
        error_policy=dict(native_error_observation=True))
    with pytest.raises(ValueError, match='compiled-F6-storage-support-'):
        verify_support_native_hops(events, **kwargs, beats=beats)
