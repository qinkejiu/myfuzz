"""Archived limited-authority F6 ISR projection (PC/instruction/order only).

Every archive here is an explicitly synthetic Runner journal derived from the
registered source contract and the compiled program; no native campaign, no
Verilator build and no native acceptance is claimed.  Expectations are read
from the input documents (contract, program firmware, raw events) instead of
the projector's own output.
"""
from copy import deepcopy

import pytest

from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
from myfuzz.integration.compiled_f6_saved_semantics import (
    _saved_retirement_scope, project_saved_irq_isr)
from myfuzz.local_harness.cv32e20_irq_receipt_contract import (
    cv32e20_irq_receipt_contract)
from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
    cv32e40p_irq_receipt_contract)
from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
from myfuzz.local_harness.native_irq_receipt_contract import (
    native_irq_acceptance, native_irq_decision_probes)
from myfuzz.scenario.irq_return_successor import (
    FULL_RVFI_AUTHORITY, PC_INSN_ORDER_ONLY_AUTHORITY, retirement_authority)
# The legacy synthetic journal builder is reused as input material; the limited
# archive below rewrites only the CPU evidence shape, never the raw DMA/CPU
# transactions, commits or ticks it archived.
from tests.integration import test_compiled_f6_saved_semantics as legacy


def _fixture_function(fixture):
    return getattr(fixture, '__wrapped__', fixture)


def build_full_archive():
    """The legacy synthetic ibex/RVFI archive (full retirement authority)."""
    base = _fixture_function(legacy.archive)()
    words = _fixture_function(legacy.word_transfer_archive)(base)
    return legacy._irq_archive(words)


def rows(archive, kind):
    return [row for row in archive['events'] if row.get('kind') == kind]


def take_row(archive):
    return rows(archive, 'cpu_external_irq_taken')[0]


def return_row(archive):
    return rows(archive, 'native_f6_isr_return.v1')[0]


def sample(archive, tick, phase):
    return next(row for row in rows(archive, 'local_tick_sample')
        if row.get('local_tick') == tick and row.get('phase') == phase)


def physical(archive, tick, phase='post'):
    return sample(archive, tick, phase)['outputs']['physical']


def physical_of(row):
    return (row.get('outputs') or {}).get('physical') or {}


def build_limited_archive(archive):
    """Rewrite the same raw journal for the registered CV32E40P adapter.

    Only evidence shapes change: the CPU's four assigned RVFI fields, its real
    ack/id/entry-PC probes and its input pin.  Every other raw fact (DMA edges,
    CPU transactions, commits, ticks) stays exactly as archived.
    """
    archive = deepcopy(archive)
    contract, attempt = archive['contract'], archive['attempt']
    cpu, program = contract['cpu']['instance_id'], contract['program_contract']
    provider = cv32e40p_irq_receipt_contract()
    acceptance = native_irq_acceptance(provider)
    widths = native_irq_decision_probes(provider)
    contract['cpu']['native_irq_provider'] = deepcopy(provider)
    contract['irq']['native_take_provider'] = deepcopy(provider)
    contract['irq']['consumer_port'] = provider['input_port']
    assert acceptance['entry_pc_probe'] in widths
    taken = take_row(archive)
    tick_of = taken['local_tick']
    for row in archive['events']:
        if row.get('component') != cpu:
            continue
        if 'observation_contract' in row:
            row['observation_contract'] = deepcopy(provider)
        outputs = row.get('outputs')
        if type(outputs) is not dict or type(outputs.get('physical')) is not dict:
            continue
        previous = outputs['physical']
        current = {name: previous[name] for name in
            ('rvfi_valid', 'rvfi_order', 'rvfi_insn', 'rvfi_pc_rdata')
            if name in previous}
        # The real one-bit IRQ input of this CPU adapter.
        current[provider['input_port']] = previous.get('irq_external_i', 0)
        # Real pre-edge controller probes on every sampled edge.
        current['probe_irq_masked_pre'] = previous.get('probe_irq_masked_pre', 0)
        current['probe_irq_taken_pre'] = previous.get('probe_irq_taken_pre', 0)
        current['probe_irq_ack_pre'] = int(row.get('local_tick') == tick_of)
        current['probe_irq_id_pre'] = (acceptance['source_id']
            if row.get('local_tick') == tick_of else 0)
        current['probe_irq_entry_pc'] = (program['isr_address']
            if row.get('local_tick') == tick_of else 0)
        current['probe_irq_redirect_pre'] = 0
        current['probe_irq_redirect_cause'] = 0
        outputs['physical'] = current
    taken.pop('irq_serial_observation', None)
    taken.update(irq_masked_pre=0, irq_taken_pre=1,
        **{acceptance['ack_probe']: 1},
        **{acceptance['id_probe']: acceptance['source_id']},
        **{acceptance['entry_pc_probe']: program['isr_address']},
        irq_redirect_pre=0, irq_redirect_cause=0,
        accepted_source_id=acceptance['source_id'])
    returned = return_row(archive)
    returned.pop('pc_wdata', None)
    returned['return_target_source'] = 'first_subsequent_valid_retirement_pc'
    # The live limited issuer restates only observable retirement facts. Model
    # that shape from the raw rows so the projection's comparisons are
    # actually exercised, not skipped.
    receipts = {row['local_tick']: row['receipt_id']
        for row in rows(archive, 'cpu_external_irq_sample')}
    posts = {row['local_tick']: row for row in rows(archive, 'local_tick_sample')
        if row.get('component') == cpu and row.get('phase') == 'post'
        and type(row.get('outputs')) is dict
        and type(row['outputs'].get('physical')) is dict}

    def blob(tick):
        value = posts[tick]['outputs']['physical']
        return dict(event_id=None, pc=value['rvfi_pc_rdata'],
            insn=value['rvfi_insn'], order=value['rvfi_order'],
            local_tick=tick, receipt_id=dict(receipts[tick]))

    valid = [tick for tick in sorted(posts)
        if posts[tick]['outputs']['physical'].get('rvfi_valid') == 1]
    entry_tick = next(tick for tick in valid if tick >= tick_of
        and posts[tick]['outputs']['physical']['rvfi_pc_rdata']
            == program['isr_address'])
    mret_tick = next(tick for tick in valid if tick > entry_tick
        and posts[tick]['outputs']['physical']['rvfi_insn'] == 0x30200073)
    returned.update(entry=blob(entry_tick), mret=blob(mret_tick),
        mret_pc=blob(mret_tick)['pc'],
        retirement_authority='pc_insn_order_only',
        unobserved_fields=deepcopy(provider['unobserved_retirement_fields']),
        retirement_diversion_scope='unobservable',
        take_pre_edge_observation=dict(
            ack_probe=1, id_probe=acceptance['source_id'],
            source_id=acceptance['source_id'],
            entry_pc_probe=program['isr_address'],
            irq_taken_pre=1, irq_redirect_pre=0, irq_redirect_cause=0),
        pre_entry_retirements=[])
    legacy.refresh(archive)
    return archive


@pytest.fixture(scope='module')
def full_archive():
    return build_full_archive()


@pytest.fixture
def limited_archive(full_archive):
    return build_limited_archive(full_archive)


def project(archive):
    return project_saved_irq_isr(**archive)


def mutate(full_archive, mutation):
    archive = build_limited_archive(full_archive)
    mutation(archive)
    legacy.refresh(archive)
    return project(archive)


def reasons(result):
    return [issue['reason'] for issue in result['details'].get('issues', [])]


def assert_refused(result, outcome, reason):
    assert result['kind'] == 'dma.irq_isr_completion'
    assert result['outcome'] == outcome, result['details'].get('issues')
    assert any(reason in text for text in reasons(result)), result['details']


# ---------------------------------------------------------------------------
# Authority selection: registered contracts decide, not archive shape.
# ---------------------------------------------------------------------------

def test_registered_authority_split_is_explicit():
    assert retirement_authority(ibex_irq_receipt_contract()) == FULL_RVFI_AUTHORITY
    assert retirement_authority(cv32e20_irq_receipt_contract()) == FULL_RVFI_AUTHORITY
    assert retirement_authority(cv32e40p_irq_receipt_contract()) == \
        PC_INSN_ORDER_ONLY_AUTHORITY
    assert _saved_retirement_scope(ibex_irq_receipt_contract())['limited'] is False
    assert _saved_retirement_scope(cv32e20_irq_receipt_contract())['limited'] is False
    limited = _saved_retirement_scope(cv32e40p_irq_receipt_contract())
    assert limited['limited'] is True
    assert set(limited['fields']) == {'rvfi_valid', 'rvfi_order', 'rvfi_insn',
        'rvfi_pc_rdata'}
    assert set(limited['unobserved']) == {'rvfi_intr', 'rvfi_pc_wdata', 'rvfi_trap',
        'rvfi_mode', 'rvfi_halt', 'rvfi_mem_addr', 'rvfi_mem_rdata',
        'rvfi_mem_wdata', 'rvfi_mem_rmask', 'rvfi_mem_wmask'}
    assert limited['acceptance'] == native_irq_acceptance(
        cv32e40p_irq_receipt_contract())


def test_unknown_retirement_authority_is_refused():
    provider = deepcopy(cv32e40p_irq_receipt_contract())
    provider['retirement_authority'] = 'full_rvfi_when_convenient'
    with pytest.raises(ValueError):
        _saved_retirement_scope(provider)


# ---------------------------------------------------------------------------
# Upward view: the limited archive validates from raw facts.
# ---------------------------------------------------------------------------

def test_limited_irq_isr_is_rebuilt_from_raw_events(limited_archive):
    contract = limited_archive['contract']
    program = contract['program_contract']
    attempt = limited_archive['attempt']
    firmware = build_f6_firmware(contract)
    returned = return_row(limited_archive)
    result = project(limited_archive)
    assert result['outcome'] == 'passed', result['details'].get('issues')
    details = result['details']
    assert details['retirement_authority'] == PC_INSN_ORDER_ONLY_AUTHORITY
    contract_fields = cv32e40p_irq_receipt_contract()['unobserved_retirement_fields']
    assert set(details['unobserved_fields']) == {
        name if name.startswith('rvfi_') else 'rvfi_' + name
        for name in contract_fields}
    assert details['retirement_diversion_scope'] == 'unobservable'
    # The entry is the declared ISR address observed by the real probe and the
    # first retirement retired there, with the first fixed handler word.
    assert details['entry_pc'] == program['isr_address']
    entry_word = int.from_bytes(
        firmware.initial_images[program['isr_address']][:4], 'little')
    entry = next(physical(limited_archive, tick)
        for tick in range(take_row(limited_archive)['local_tick'],
            returned['successor_local_tick'] + 1)
        if physical(limited_archive, tick).get('rvfi_pc_rdata')
            == program['isr_address'])
    assert entry['rvfi_insn'] == entry_word
    # MRET is the actual fixed-site retirement; its pc_wdata is never read.
    assert details['mret_pc'] == firmware.document()['isr']['mret_addresses'][0]
    assert details['mret_pc'] != entry['rvfi_pc_rdata']
    assert details['mret_rvfi_order'] == returned['rvfi_order']
    # The successor is the immediately following retirement inside the dynamic
    # slot window, and the return target is that successor PC.
    slot = program['slot_base'] + program['slot_bytes'] * attempt['case_index']
    successor = physical(limited_archive, returned['successor_local_tick'])
    assert details['successor_rvfi_order'] == returned['successor_rvfi_order'] \
        == details['mret_rvfi_order'] + 1
    assert details['return_target'] == successor['rvfi_pc_rdata']
    assert slot <= details['return_target'] < slot + program['online_prefix_bytes'] + 8
    assert details['return_target_source'] == 'first_subsequent_valid_retirement_pc'
    assert 'pc_wdata' not in details
    # Every probe reading is the archived real pre-edge value.
    acceptance = native_irq_acceptance(cv32e40p_irq_receipt_contract())
    assert details['take_probes'] == {
        'irq_ack_pre': 1,
        'irq_entry_pc': program['isr_address'],
        'irq_id_pre': acceptance['source_id'],
        'irq_redirect_pre': 0,
        'irq_taken_pre': 1}
    # No rebuilt field claims an unobserved retirement field; the declared
    # unobserved names appear only as the recorded declaration itself.
    claims = []

    def walk(value):
        if type(value) is dict:
            for key, item in value.items():
                if key == 'unobserved_fields':
                    continue
                normalized = key if key.startswith('rvfi_') else 'rvfi_' + key
                if normalized in set(details['unobserved_fields']):
                    claims.append(key)
                walk(item)
        elif type(value) is list:
            for item in value:
                walk(item)

    walk(details)
    assert claims == []


def test_limited_error_branch_chain_is_rebuilt(full_archive):
    """The expected-ERR branch uses the same limited chain; only its declared
    ERR completion rule refuses, exactly as for the full authority."""
    base = _fixture_function(legacy.archive)()
    word = _fixture_function(legacy.word_transfer_archive)(base)
    error_full = legacy._irq_archive(word, error=True)
    archive = build_limited_archive(error_full)
    returned = return_row(archive)
    result = project(archive)
    assert result['outcome'] == 'failed', result['details'].get('issues')
    assert reasons(result) == ['native expected ERR completed the error ISR branch']
    program = archive['contract']['program_contract']
    firmware = build_f6_firmware(archive['contract'])
    assert result['details']['retirement_authority'] == PC_INSN_ORDER_ONLY_AUTHORITY
    assert result['details']['entry_pc'] == program['isr_address']
    assert result['details']['mret_pc'] == firmware.document()['isr']['mret_addresses'][1]
    assert result['details']['return_target'] == \
        physical(archive, returned['successor_local_tick'])['rvfi_pc_rdata']


def test_sibling_saved_projections_ignore_the_retirement_authority(full_archive):
    """CPU configuration/word joins use CPU transactions, not RVFI memory."""
    from myfuzz.integration.compiled_f6_saved_semantics import (
        project_saved_cpu_configuration, project_saved_cross_component_edges,
        project_saved_word_transfer)
    limited = build_limited_archive(full_archive)

    def projections(archive):
        common = dict(attempt=archive['attempt'], contract=archive['contract'],
            events=archive['events'], local_by_id=archive['local_by_id'])
        configuration = project_saved_cpu_configuration(**common)
        words = project_saved_word_transfer(binding=archive['binding'], **common)
        edges = project_saved_cross_component_edges(binding=archive['binding'],
            cpu_artifact=None, **common)
        return configuration, words, edges

    full_config, full_words, full_edges = projections(full_archive)
    limited_config, limited_words, limited_edges = projections(limited)
    # The retirement authority cannot change a CPU transaction join.
    assert limited_config['outcome'] == full_config['outcome']
    assert limited_config['details']['issues'] == full_config['details']['issues']
    assert limited_edges['outcome'] == full_edges['outcome']
    # The four-word DMA/RAM projection is unchanged and still passes.
    assert full_words['outcome'] == limited_words['outcome'] == 'passed'
    assert limited_words['details']['words'] == full_words['details']['words']


def test_limited_production_observer_summary_is_validated(full_archive):
    """A production issuer summary (no provenance) states observable metadata."""
    archive = build_limited_archive(full_archive)
    returned = return_row(archive)
    archive['events'].remove(returned)
    returned.pop('provenance')
    firmware = build_f6_firmware(archive['contract'])
    returned['phase'] = 'post'
    returned['isr_sha256'] = firmware.document()['isr']['sha256']
    returned['return_receipt_ticks'] = next(row for row in
        rows(archive, 'cpu_external_irq_sample')
        if row.get('local_tick') == returned['local_tick'])['receipt_ticks']
    cpu = archive['contract']['cpu']['instance_id']
    observer = archive['local_by_id'][cpu, archive['attempt']['return']]
    observer.pop('runner_event_id', None)
    observer.pop('provenance', None)
    observer.update({key: deepcopy(value) for key, value in returned.items()
        if key != 'event_id'})
    assert project(archive)['outcome'] == 'passed'
    # An unobservable field in the same summary is still refused.
    observer['pc_wdata'] = 0xdeadbeec
    assert_refused(project(archive), 'failed',
        'claims unobservable retirement field pc_wdata in saved ISR return document')


def test_limited_projection_does_not_trust_saved_derived_fields(full_archive):
    def wrong(field, value):
        def mutation(archive):
            return_row(archive)[field] = value
        return mutation

    returned = return_row(build_limited_archive(full_archive))
    # Observable derived fields are compared against the raw chain: any
    # disagreement refuses even though the field is only a derived claim.
    for field, value in (('handler_entry_rvfi_order', 9),
            ('return_target', returned['successor_pc_rdata'] + 4),
            ('successor_instruction', 0x00000013),
            ('rvfi_order', 1)):
        result = mutate(full_archive, wrong(field, value))
        assert_refused(result, 'failed', 'limited')
    # A pure label with no observed counterpart is carried, not trusted.
    archive = build_limited_archive(full_archive)
    return_row(archive)['return_target_authority'] = 'inferred_architectural_successor_after_MRET'
    legacy.refresh(archive)
    assert project(archive)['outcome'] == 'passed'


def test_limited_projection_recomputes_successor_instruction_response(full_archive):
    archive = build_limited_archive(full_archive)
    returned = return_row(archive)
    successor = physical(archive, returned['successor_local_tick'])
    response = next(row for row in rows(archive, 'instr_response')
        if row.get('address') == successor['rvfi_pc_rdata'])
    assert returned['successor_instruction_response']['transaction'] \
        == response['transaction']
    returned['successor_instruction_response']['rdata'] ^= 1
    legacy.refresh(archive)
    assert_refused(project(archive), 'failed',
        'limited successor instruction response differs from raw Runner row')


def test_limited_cpu_with_full_rvfi_fields_is_fabrication(full_archive):
    """A saved archive may not claim full RVFI authority for this CPU."""
    archive = deepcopy(full_archive)
    contract, attempt = archive['contract'], archive['attempt']
    cpu = contract['cpu']['instance_id']
    provider = cv32e40p_irq_receipt_contract()
    contract['cpu']['native_irq_provider'] = deepcopy(provider)
    contract['irq']['native_take_provider'] = deepcopy(provider)
    contract['irq']['consumer_port'] = provider['input_port']
    for row in archive['events']:
        if row.get('component') == cpu and 'observation_contract' in row:
            row['observation_contract'] = deepcopy(provider)
    legacy.refresh(archive)
    result = project(archive)
    # The saved return document is scanned first, so the precise first claim is
    # its pc_wdata: a field this CPU never drives.
    assert_refused(result, 'failed',
        'claims unobservable retirement field pc_wdata in saved ISR return document')


# ---------------------------------------------------------------------------
# Refusals: every observed field must be actual, and only actual.
# ---------------------------------------------------------------------------

def _probe_everywhere(archive, name, value):
    for row in archive['events']:
        outputs = row.get('outputs')
        if (row.get('component') == archive['contract']['cpu']['instance_id']
                and type(outputs) is dict and type(outputs.get('physical')) is dict):
            outputs['physical']['probe_' + name] = value


def _drop_probe(archive, name):
    for row in archive['events']:
        outputs = row.get('outputs')
        if (row.get('component') == archive['contract']['cpu']['instance_id']
                and type(outputs) is dict and type(outputs.get('physical')) is dict):
            outputs['physical'].pop('probe_' + name, None)


def _drop_take_probe(archive, name):
    take_row(archive).pop(name, None)
    _drop_probe(archive, name)


def _move_entry_pc(archive, delta):
    program = archive['contract']['program_contract']
    value = program['isr_address'] + delta
    take_row(archive)['irq_entry_pc'] = value
    _probe_everywhere(archive, 'irq_entry_pc', value)


def _entry_sample(archive):
    """The first valid retirement whose PC is the declared handler address."""
    program = archive['contract']['program_contract']
    cpu = archive['contract']['cpu']['instance_id']
    found = [row for row in rows(archive, 'local_tick_sample')
        if row.get('component') == cpu and row.get('phase') == 'post'
        and physical_of(row).get('rvfi_valid') == 1
        and physical_of(row).get('rvfi_pc_rdata') == program['isr_address']]
    found.sort(key=lambda row: row['local_tick'])
    assert len(found) == 1, 'archive must contain one handler entry retirement'
    return found[0]


def _successor_sample(archive):
    returned = return_row(archive)
    return next(row for row in rows(archive, 'local_tick_sample')
        if row.get('local_tick') == returned['successor_local_tick']
        and row.get('phase') == 'post')


def _mret_sample(archive):
    returned = return_row(archive)
    return next(row for row in rows(archive, 'local_tick_sample')
        if row.get('local_tick') == returned['local_tick']
        and row.get('phase') == 'post')


def _wrong_entry_word(archive):
    row = _entry_sample(archive)
    row['outputs']['physical']['rvfi_insn'] ^= 1


def _missing_mret(archive):
    _mret_sample(archive)['outputs']['physical']['rvfi_insn'] = 0x00000013


def _wrong_mret_site(archive):
    row = _mret_sample(archive)
    row['outputs']['physical']['rvfi_pc_rdata'] += 4


def _successor_order_gap(archive):
    row = _successor_sample(archive)
    row['outputs']['physical']['rvfi_order'] += 1


def _successor_out_of_window(archive):
    row = _successor_sample(archive)
    row['outputs']['physical']['rvfi_pc_rdata'] += \
        archive['contract']['program_contract']['slot_bytes']


def _missing_instruction_response(archive):
    program = archive['contract']['program_contract']
    returned = return_row(archive)
    target = returned['successor_pc_rdata']
    returned.pop('successor_instruction_response')
    for row in rows(archive, 'instr_response'):
        if row.get('address') == target:
            archive['events'].remove(row)


def _wrong_source_byte_version(archive):
    program = archive['contract']['program_contract']
    row = next(row for row in rows(archive, 'data_response')
        if row.get('address') == program['destination_address']
        and row.get('write') == 0)
    row['snapshot']['versions'] = [0, 999]


def _intervening_redirect(archive):
    contract, attempt = archive['contract'], archive['attempt']
    archive['events'].append(dict(
        component=contract['cpu']['instance_id'],
        kind='cpu_native_exception_redirect',
        event_id=max(row['event_id'] for row in archive['events']) + 1,
        provenance=dict(observed_case=dict(case_id=attempt['case_id'],
            case_index=attempt['case_index'])),
        local_tick=take_row(archive)['local_tick'] + 1, reset_epoch=0,
        redirect_cause=0))


def _fabricated(field, value, tick=None):
    def mutation(archive):
        returned = return_row(archive)
        row = (_mret_sample(archive) if tick is None else sample(archive, tick, 'post'))
        row['outputs']['physical'][field] = value
    return mutation


def _saved(field, value):
    def mutation(archive):
        return_row(archive)[field] = value
    return mutation


def _attempt_saved(field, value):
    def mutation(archive):
        archive['attempt'][field] = value
    return mutation


def _mutated_contract(source_id):
    def mutation(archive):
        provider = deepcopy(archive['contract']['cpu']['native_irq_provider'])
        provider['decision_acceptance']['source_id'] = source_id
        archive['contract']['cpu']['native_irq_provider'] = provider
        archive['contract']['irq']['native_take_provider'] = deepcopy(provider)
    return mutation


@pytest.mark.parametrize('mutation,outcome,reason', [
    (lambda a: _drop_take_probe(a, 'irq_entry_pc'), 'missing',
        'limited pre-edge probe unavailable: irq_entry_pc'),
    (lambda a: _move_entry_pc(a, 4), 'failed',
        'limited take entry PC is not the declared ISR address'),
    (lambda a: take_row(a).update(irq_entry_pc=take_row(a)['irq_entry_pc'] + 4),
        'failed', 'conflicting limited pre-edge probe observations: irq_entry_pc'),
    (lambda a: _drop_take_probe(a, 'irq_ack_pre'), 'missing',
        'limited pre-edge probe unavailable: irq_ack_pre'),
    (lambda a: (take_row(a).update(irq_ack_pre=0),
        _probe_everywhere(a, 'irq_ack_pre', 0)), 'failed',
        'limited take lacks the real acknowledged interrupt'),
    (lambda a: (take_row(a).update(irq_id_pre=7),
        _probe_everywhere(a, 'irq_id_pre', 7)), 'failed',
        'limited take id is not the declared external source'),
    (lambda a: take_row(a).pop('observation_contract'), 'failed',
        'limited IRQ take provider mismatch'),
    (_wrong_entry_word, 'failed',
        'limited ISR entry instruction differs from the declared handler word'),
    (_missing_mret, 'failed', 'limited duplicate/missing raw MRET'),
    (_wrong_mret_site, 'failed',
        'limited raw MRET site/branch/order mismatch'),
    (_successor_order_gap, 'failed',
        'limited ISR retirement order discontinuity'),
    (_successor_out_of_window, 'failed',
        'limited first post-MRET successor is not the current dynamic return'),
    (_missing_instruction_response, 'missing',
        'limited successor instruction response transaction unavailable'),
    (_wrong_source_byte_version, 'failed',
        'ISR readback destination writer/version join'),
    (_intervening_redirect, 'failed',
        'limited ISR intervening native exception redirect'),
    (_fabricated('rvfi_pc_wdata', 0xdeadbeec), 'failed',
        'claims unobservable retirement field rvfi_pc_wdata'),
    (_fabricated('rvfi_intr', 1), 'failed',
        'claims unobservable retirement field rvfi_intr'),
    (_fabricated('rvfi_trap', 1), 'failed',
        'claims unobservable retirement field rvfi_trap'),
    (_fabricated('rvfi_mode', 3), 'failed',
        'claims unobservable retirement field rvfi_mode'),
    (_fabricated('rvfi_halt', 0), 'failed',
        'claims unobservable retirement field rvfi_halt'),
    (_fabricated('rvfi_mem_rdata', 1), 'failed',
        'claims unobservable retirement field rvfi_mem_rdata'),
    (_fabricated('rvfi_mem_addr', 0), 'failed',
        'claims unobservable retirement field rvfi_mem_addr'),
    (_fabricated('rvfi_shadow_field', 1), 'failed',
        'claims undeclared RVFI retirement field rvfi_shadow_field'),
    (_saved('pc_wdata', 0xdeadbeec), 'failed',
        'claims unobservable retirement field pc_wdata'),
    (_saved('successor_irq_serial_observation',
        dict(retirement=dict(status='observed', value=0))), 'failed',
        'claims unobservable IRQ serial token successor_irq_serial_observation'),
    (_saved('internal_version', 'cv32e40p-r1'), 'failed',
        'claims unobservable internal_version in saved ISR return document'),
    (_attempt_saved('internal_version', 'cv32e40p-r1'), 'failed',
        'claims unobservable internal_version in archive'),
    (lambda a: return_row(a).pop('handler_entry_receipt_id'), 'missing',
        'limited saved ISR return field unavailable: handler_entry_receipt_id'),
    (_saved('retirement_authority', FULL_RVFI_AUTHORITY), 'failed',
        'limited saved retirement authority mismatch'),
    (lambda a: return_row(a)['entry'].update(pc=return_row(a)['entry']['pc'] + 4),
        'failed', 'limited saved handler entry evidence differs from raw retirements'),
    (lambda a: return_row(a)['mret'].update(
        order=return_row(a)['mret']['order'] + 1), 'failed',
        'limited saved MRET evidence differs from raw retirements'),
    (lambda a: return_row(a)['take_pre_edge_observation'].update(id_probe=7),
        'failed',
        'limited saved take pre-edge observation differs from the raw take'),
    (lambda a: return_row(a)['entry'].update(intr=1), 'failed',
        'claims unobservable retirement field intr in saved ISR return document entry'),
    (lambda a: return_row(a).update(pre_entry_retirements=[
        dict(pc=take_row(a)['irq_entry_pc'], insn=0, order=0, local_tick=200,
            receipt_id=dict(execution=return_row(a)['execution'], sequence=200),
            pc_wdata=0)]), 'failed',
        'claims unobservable retirement field pc_wdata'),
    (lambda a: return_row(a).update(unobserved_fields=['intr']), 'failed',
        'limited saved unobserved field declaration mismatch'),
    (_saved('decision_acceptance', dict(ack_probe='irq_ack_pre',
        id_probe='irq_id_pre', source_id=7, id_width=5,
        entry_pc_probe='irq_entry_pc')), 'failed',
        'limited saved decision acceptance differs from the contract'),
    (_mutated_contract(12), 'failed', 'unregistered-native-IRQ-receipt-contract'),
])
def test_limited_archive_refusals(full_archive, mutation, outcome, reason):
    result = mutate(full_archive, mutation)
    assert_refused(result, outcome, reason)


def test_limited_archive_requires_the_observed_fields(full_archive):
    def missing_field(archive):
        _successor_sample(archive)['outputs']['physical'].pop('rvfi_order')

    result = mutate(full_archive, missing_field)
    assert_refused(result, 'missing', 'limited retirement field unavailable')


# ---------------------------------------------------------------------------
# Full-RVFI archives keep the legacy branch exactly.
# ---------------------------------------------------------------------------

def test_full_rvfi_archive_is_not_routed_through_limited_branch(full_archive):
    # The archived full-RVFI CPU observation stream keeps its own fields; the
    # same raw journal is only rewritten for the limited adapter by the helper.
    assert 'rvfi_intr' in physical(full_archive, 202)
    assert 'rvfi_intr' not in physical(build_limited_archive(full_archive), 202)
    result = project(full_archive)
    assert result['outcome'] == 'passed', result['details'].get('issues')
    details = result['details']
    assert details['retirement_authority'] == FULL_RVFI_AUTHORITY
    assert details['unobserved_fields'] == []
    # Legacy detail fields are retained, including the pc_wdata observation.
    assert 'pc_wdata' in details
    assert details['return_target'] == details['return_target'] and \
        details['return_target_source'] == \
        'first_subsequent_valid_RVFI_pc_rdata_with_instruction_response'
    # No limited-authority evidence is invented for a full-RVFI archive.
    for key in ('take_probes', 'entry_pc', 'mret_pc', 'retirement_diversion_scope'):
        assert key not in details
    # The full archive still carries rvfi_intr/rvfi_pc_wdata; routing it
    # through the limited scanner would refuse it.
    assert 'rvfi_pc_wdata' in physical(full_archive, 240)


def test_full_rvfi_pc_wdata_remains_an_observation(full_archive):
    archive = deepcopy(full_archive)
    returned = return_row(archive)
    returned['pc_wdata'] = 0
    for row in rows(archive, 'local_tick_sample'):
        if row.get('local_tick') == returned['local_tick']:
            row['outputs']['physical']['rvfi_pc_wdata'] = 0
    legacy.refresh(archive)
    result = project(archive)
    assert result['outcome'] == 'passed', result['details'].get('issues')
    assert result['details']['pc_wdata'] == 0
    assert result['details']['return_target'] != 0
