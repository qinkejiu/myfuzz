"""Directed BOOM -> APB3 F2/F4 campaign: encodings, joins and fresh comparison.

Synthetic only: no RTL, no Verilator build, no native process.  The join is
exercised against exactly the event shapes the standard ``ScenarioRunner``
emits (``mmio_acceptance`` / ``mmio_delivery`` / ``local_tick_sample``) and the
``coherent_accepted_raw`` rows the BOOM session's own stream produces.
"""
import pytest

from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
from myfuzz.scenario import boom_tl_apb_f2f4 as campaign

RESULT = campaign.RESULT
ADDRESS = campaign.REGISTER_ADDRESS


def _program_words(image):
    return [int.from_bytes(image[offset:offset + 4], 'little')
            for offset in range(0, len(image), 4)]


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------
def test_programs_are_whole_line_images_that_end_in_a_self_jump():
    for image in (campaign.f4_program(ADDRESS, 0x55),
                  campaign.f2_program(ADDRESS)):
        assert len(image) == campaign.PROGRAM_BYTES
        words = _program_words(image)
        executed = [word for word in words if word != campaign.NOP]
        assert executed[-1] == campaign.JAL_SELF
        last_executable = max(index for index, word in enumerate(words)
                              if word != campaign.NOP)
        assert set(words[last_executable + 1:]) == {campaign.NOP}


def test_every_emitted_word_is_a_legal_rv64i_instruction():
    provider = RiscvInstructionProvider(IsaContract(64, ('I',)))
    for image in (campaign.f4_program(ADDRESS, 0x1234),
                  campaign.f2_program(ADDRESS)):
        for word in _program_words(image):
            assert provider.is_legal_word(word), hex(word)


def test_f4_image_orders_the_write_before_the_read():
    words = _program_words(campaign.f4_program(ADDRESS, 0x55))
    fence = words.index(campaign.FENCE_IORW)
    store = next(index for index, word in enumerate(words)
                 if word & 0x7f == 0x23)
    load = next(index for index, word in enumerate(words)
                if word & 0x7f == 0x03)
    assert store < fence < load


def test_f2_image_xors_the_loaded_word_before_storing_it():
    words = _program_words(campaign.f2_program(ADDRESS))
    load = next(index for index, word in enumerate(words)
                if word & 0x7f == 0x03)
    xori = next(index for index, word in enumerate(words)
                if word & 0x7f == 0x13 and (word >> 12) & 7 == 4)
    store = next(index for index, word in enumerate(words)
                 if word & 0x7f == 0x23)
    assert load < xori < store
    assert (words[xori] >> 20) & 0xfff == campaign.F2_XOR_CONSTANT


def test_program_identity_is_stable_and_value_dependent():
    first = campaign.f4_program(ADDRESS, 0x55)
    assert first == campaign.f4_program(ADDRESS, 0x55)
    assert first != campaign.f4_program(ADDRESS, 0xaa)


# ---------------------------------------------------------------------------
# case plans
# ---------------------------------------------------------------------------
def test_plan_f4_masks_to_the_declared_write_mask():
    plan = campaign.plan_f4(bytes.fromhex('34120000'))
    assert plan.flow == 'F4'
    assert plan.expected_readback == 0x1234
    assert plan.expected_result == 0x1234
    with pytest.raises(ValueError, match='BOOM-F4-value-exceeds-declared-write-mask'):
        campaign.plan_f4((0x10000).to_bytes(4, 'little'))
    with pytest.raises(ValueError, match='BOOM-F4-record-shape'):
        campaign.plan_f4(b'\x00\x00')


def test_plan_f2_requires_the_declared_register_address():
    plan = campaign.plan_f2(ADDRESS.to_bytes(4, 'little'), source_value=0x1234)
    assert plan.flow == 'F2'
    assert plan.expected_readback == 0x1234
    assert plan.expected_result == 0x1234 ^ campaign.F2_XOR_CONSTANT
    with pytest.raises(ValueError, match='BOOM-F2-record-address-mismatch'):
        campaign.plan_f2((ADDRESS + 4).to_bytes(4, 'little'), source_value=1)
    with pytest.raises(ValueError, match='BOOM-F2-source-value'):
        campaign.plan_f2(ADDRESS.to_bytes(4, 'little'), source_value=0x10000)


# ---------------------------------------------------------------------------
# synthetic journals that mirror the real emitted shapes
# ---------------------------------------------------------------------------
def _native(channel, *, opcode, size=2, mask=0x0f, source=3, address=ADDRESS,
            data=0, external=None, event_id=1):
    native = {'channel': channel, 'opcode': opcode, 'param': 0, 'size': size,
              'mask': mask, 'source': source, 'address': address, 'data': data}
    if external is not None:
        native['external'] = external
    return {'kind': 'coherent_accepted_raw', 'raw_event_id': event_id,
            'local_tick': event_id, 'native_event': native}


def _runner_events(flow, value, readback):
    transfers = ([('write', 1, value)] if flow == 'F4' else [])
    transfers.append(('read', len(transfers) + 1, readback))
    events = []
    for order, (kind, sequence, payload) in enumerate(transfers, start=1):
        producer = 900 + order
        events.append({'event_id': 100 * order + 1, 'kind': 'mmio_acceptance',
                       'source_sequence': sequence, 'acceptance_order': order,
                       'address': ADDRESS, 'offset': campaign.REGISTER_OFFSET,
                       'write': kind == 'write',
                       'write_value': payload if kind == 'write' else None})
        events.append({'event_id': 100 * order + 2, 'kind': 'mmio_delivery',
                       'source_sequence': sequence, 'delivery_order': order,
                       'producer_event_id': producer,
                       'write': kind == 'write',
                       'write_value': payload if kind == 'write' else None,
                       'read_value': payload if kind == 'read' else None})
        events.append({'event_id': 100 * order + 3, 'kind': 'local_tick_sample',
                       'component': campaign.TARGET_COMPONENT, 'phase': 'pre',
                       'producer_event_id': producer, 'local_tick': order,
                       'outputs': {'backend': {
                           'trace_psel': 1, 'trace_penable': 1,
                           'trace_pwrite': int(kind == 'write'),
                           'trace_paddr': campaign.REGISTER_OFFSET,
                           'trace_pwdata': payload if kind == 'write' else 0,
                           'trace_prdata': payload if kind == 'read' else 0,
                           'trace_pready': 1, 'trace_pslverr': 0}}})
    return events


def snapshot(flow, *, value=0x55, readback=None, ram_result=None,
             result_store_data=None):
    readback = value if readback is None else readback
    result = (readback ^ campaign.F2_XOR_CONSTANT if flow == 'F2' else readback)
    runtime = [_native('A', opcode=0, data=value, event_id=1),
               _native('D', opcode=0, data=0, external=True, event_id=2)]
    if flow == 'F4':
        runtime += [_native('A', opcode=4, data=0, event_id=3),
                    _native('D', opcode=1, data=readback, external=True, event_id=4)]
    runtime.append(_native('A', opcode=0, address=RESULT,
                           data=result_store_data if result_store_data is not None
                           else result, event_id=9))
    return {'execution_id': 'exec-1', 'reset_epoch': 1, 'local_ticks': 123,
            'runtime_events': runtime,
            'runner_events': _runner_events(flow, value, readback),
            'deliveries': [], 'transactions': [],
            'coherent_report': {'structural_error': False, 'stream_closed': True},
            '_result': result if ram_result is None else ram_result}


def certificate(flow, **keywords):
    snap = snapshot(flow, **keywords)
    value = keywords.get('value', 0x55)
    return campaign._certificate(
        plan=(campaign.plan_f4(value.to_bytes(4, 'little')) if flow == 'F4'
              else campaign.plan_f2(ADDRESS.to_bytes(4, 'little'),
                                    source_value=value)),
        case_id='case', snapshot=snap,
        outputs={f'ram_{RESULT:x}': snap['_result']}, edges=123, wall=1.5)


# ---------------------------------------------------------------------------
# joins
# ---------------------------------------------------------------------------
def test_f4_join_requires_write_then_read_with_the_same_value():
    case = certificate('F4', value=0xaa)
    assert case['hops'] == 2
    assert case['read_value'] == 0xaa
    assert case['ram_result'] == 0xaa
    assert case['case_pass'] is True
    write, read = case['joins']
    assert write['write'] is True and read['write'] is False
    assert write['target_physical'][0]['trace_pwdata'] == 0xaa
    assert read['target_physical'][0]['trace_prdata'] == 0xaa
    assert read['native_D_data'] == 0xaa


def test_f2_join_requires_the_xor_dependent_store():
    case = certificate('F2', value=0x1234)
    assert case['hops'] == 1
    assert case['read_value'] == 0x1234
    assert case['result_value'] == 0x1234 ^ campaign.F2_XOR_CONSTANT
    assert case['ram_result'] == case['result_value']
    assert case['case_pass'] is True


def test_readback_mismatch_breaks_the_f4_case():
    case = certificate('F4', value=0xaa, readback=0xab)
    assert case['case_pass'] is False


def test_missing_dependent_ram_store_breaks_the_case():
    case = certificate('F4', value=0x55, result_store_data=0)
    assert case['case_pass'] is False
    case = certificate('F4', value=0x55, ram_result=0)
    assert case['case_pass'] is False


def test_apb_physical_evidence_must_agree_with_the_delivery():
    snap = snapshot('F4', value=0x55)
    for row in snap['runner_events']:
        if row['kind'] == 'local_tick_sample' and row['outputs']['backend']['trace_pwrite'] == 1:
            row['outputs']['backend']['trace_pwdata'] = 0x56
    case = campaign._certificate(
        plan=campaign.plan_f4(bytes.fromhex('55000000')), case_id='case',
        snapshot=snap, outputs={f'ram_{RESULT:x}': 0x55}, edges=10, wall=1.0)
    assert case['case_pass'] is False


def test_missing_physical_sample_breaks_the_case():
    snap = snapshot('F4', value=0x55)
    snap['runner_events'] = [row for row in snap['runner_events']
                             if row['kind'] != 'local_tick_sample']
    case = campaign._certificate(
        plan=campaign.plan_f4(bytes.fromhex('55000000')), case_id='case',
        snapshot=snap, outputs={f'ram_{RESULT:x}': 0x55}, edges=10, wall=1.0)
    assert case['case_pass'] is False
    assert case['target_physical_matched'] == 0


def test_structural_stream_error_breaks_the_case():
    snap = snapshot('F4', value=0x55)
    snap['coherent_report']['structural_error'] = True
    case = campaign._certificate(
        plan=campaign.plan_f4(bytes.fromhex('55000000')), case_id='case',
        snapshot=snap, outputs={f'ram_{RESULT:x}': 0x55}, edges=10, wall=1.0)
    assert case['case_pass'] is False


# ---------------------------------------------------------------------------
# fresh comparison
# ---------------------------------------------------------------------------
def _report(*cases):
    return {'schema_version': 'boom_tl_apb_directed_campaign.v1',
            'case_count': len(cases), 'cases': list(cases)}


def test_fresh_comparison_ignores_process_scope_and_wall_clock():
    left = certificate('F4', value=0x55)
    right = dict(left, cpu_execution_id='exec-2', wall_seconds=99.0,
                 cpu_local_ticks=999)
    assert campaign.compare_fresh(_report(left), _report(right))['matches'] is True


def test_fresh_comparison_reports_the_first_differing_field():
    left = certificate('F4', value=0x55)
    right = dict(left, read_value=0x56)
    result = campaign.compare_fresh(_report(left), _report(right))
    assert result['matches'] is False
    assert result['reason'] == 'case-field'
    assert 'read_value' in result['difference']


def test_fresh_comparison_reports_a_case_count_change():
    left = certificate('F4', value=0x55)
    assert campaign.compare_fresh(_report(left), _report())['reason'] == 'case-count'


# ---------------------------------------------------------------------------
# declared ownership of the real target
# ---------------------------------------------------------------------------
class _TargetArtifact:
    def __init__(self, *, dynamic=(), bound=(), fixed=()):
        self.runtime_document = {
            'dynamic_physical_inputs': list(dynamic),
            'bound_physical_inputs': list(bound),
            'fixed_physical_inputs': list(fixed)}


def test_target_ownership_declares_fixed_inputs_from_the_artifact():
    artifact = _TargetArtifact(fixed=[
        {'endpoint_id': 'i2c.pins', 'role': 'scl_pad_i', 'width': 1, 'value': 1},
        {'endpoint_id': 'i2c.pins', 'role': 'sda_pad_i', 'width': 1, 'value': 1}])
    document = campaign.target_ownership(artifact, 'i2c').document()
    assert {row['port'] for row in document['fields']} == {
        'i2c.pins.scl_pad_i', 'i2c.pins.sda_pad_i'}
    assert all(row['kind'] == 'fixed' and row['producer_ref'] == 'profile_constant'
               for row in document['owners'])


def test_target_ownership_refuses_a_fuzzable_target_input():
    artifact = _TargetArtifact(dynamic=[{'input_name': 'gpio_in', 'width': 32,
                                        'source_id': 's'}])
    with pytest.raises(ValueError, match='BOOM-directed-target-has-fuzzable-inputs'):
        campaign.target_ownership(artifact, 'i2c')
