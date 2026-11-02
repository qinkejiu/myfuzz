"""Independent, offline F6 CPU-configuration projection from archived facts.

This module grants no live-session, native-execution, or service authority.
The caller supplies the compiled contract and authoritative Runner archive.
Observer references only select rows; they never supply semantic conclusions.
"""
from copy import deepcopy
from .f6_saved_slot_mapping import saved_slot_mapping, saved_shared_union
import json

from .compiled_f6_firmware import build_f6_firmware
from .compiled_f6_layout import F6Candidate


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False)


def _cpu_sample_index(events, cpu):
    """Index native CPU samples once, preserving all rows and their order."""
    groups = {}
    for row in events:
        if row.get('component') != cpu or row.get('kind') != 'local_tick_sample':
            continue
        tick = row.get('local_tick')
        # JSON non-numeric values cannot equal the integer ticks queried by the
        # verifier. bool/float are retained to match Python numeric equality,
        # including duplicate and malformed phase checks downstream.
        if type(tick) in (int, float, bool):
            groups.setdefault(tick, []).append(row)
    return groups


class _EvidenceIssue(Exception):
    def __init__(self, outcome, reason):
        super().__init__(reason)
        self.outcome = outcome


def _require(condition, reason):
    if not condition:
        raise _EvidenceIssue('failed', reason)


def _present(condition, reason):
    if not condition:
        raise _EvidenceIssue('missing', reason)


def _selected_dma(contract, *, side='master'):
    dma=contract.get('dma',{})
    source=dma.get('source_contract',{})
    schema=source.get('schema_version')
    link=dma.get('master_endpoint_link')
    if side == 'control' and type(dma.get('selected_template')) is dict:
        control=dma['selected_template'].get('control')
        if type(control) is dict:
            link={'template_binding':control}
    if link is not None:
        binding=link.get('template_binding') if type(link) is dict else None
        variant=binding.get('variant_id') if type(binding) is dict else None
        _require(variant in ('dma-selected','dma-full-word-no-select'),
            'DMA master endpoint variant missing or unsupported')
        if schema=='zipdma_selected_profile_contract.v1':
            _require(variant=='dma-selected','DMA selected source and endpoint variant differ')
        return variant=='dma-selected'
    # Compatibility for older saved documents without a master endpoint link.
    # Newly declared DMA sources must carry the verified endpoint binding.
    _require(schema!='declared_f6_dma_source_contract.v1',
        'declared DMA master endpoint binding missing')
    return schema=='zipdma_selected_profile_contract.v1'


def _saved_level_irq_evidence(contract, group, events, runner, cpu, dma, epoch, case, take, delivery, runtime_name, native_testcase_id=None):
    """Join a level IRQ take to a real clear transaction and later low."""
    from .saved_irq_group import frame_for_sample
    def rows(kind, owner, predicate=lambda row: True):
        return [r for r in events if r.get('kind') == kind and r.get('component') == owner
            and r.get('provenance', {}).get('observed_case') == case and predicate(r)]
    def one(items, name):
        _require(len(items) <= 1, 'duplicate '+name)
        _present(bool(items), name+' unavailable')
        return items[0]
    _present(take is not None, 'level IRQ take unavailable')
    _require(take.get('reset_epoch') == epoch and take.get('binding_delivery_event_id') == delivery.get('event_id')
        and take.get('source_output_key') == delivery.get('source_output_key'), 'level take/source scope')
    high = one(rows('cpu_external_irq_sample', cpu, lambda r:r.get('local_tick') == take.get('local_tick')
        and r.get('reset_epoch') == epoch), 'level high sample')
    frame = frame_for_sample(group, high, events, runner, dma_runtime_name=runtime_name)
    _require(frame.get('unique_source') == dma+'.irq' and frame.get('native_take_event_id') == take['event_id']
        and frame.get('take_key') == take.get('take_key'), 'level take is not uniquely DMA attributed')
    clear = contract['dma']['behavior']['irq_clear']
    _require(clear.get('method') == 'write', 'level clear contract')
    address = contract['control']['base'] + clear['offset']
    accept = one(rows('data_accept', cpu, lambda r:r['event_id'] > take['event_id']
        and r.get('address') == address and r.get('write') == 1 and r.get('wdata') == clear['value']), 'level clear accept')
    key = accept.get('transaction')
    _require(type(key) is dict and key.get('source_component') == cpu and key.get('source_epoch') == epoch
        and type(key.get('testcase_id')) is str and bool(key['testcase_id'])
        and (native_testcase_id is None or key['testcase_id'] == native_testcase_id)
        and key.get('execution_id') == 'local-execution', 'level clear transaction scope')
    delivered = one(rows('mmio_delivery', cpu, lambda r:r.get('source_transaction') == key
        and r.get('device_id') == contract['control']['device_id'] and r.get('address') == address
        and r.get('write') is True), 'level clear delivery')
    response = one(rows('data_response', cpu, lambda r:r.get('transaction') == key
        and r.get('address') == address and r.get('write') == 1), 'level clear response')
    receipt = delivered.get('dma_control_receipt')
    expected = dict(source_transaction=key,address=address,offset=clear['offset'],write=True,
        value=clear['value'],byte_enable=clear['byte_enable'])
    _require(type(receipt) is dict and all(receipt.get(k) == v for k,v in expected.items())
        and accept['event_id'] < delivered['event_id'] < response['event_id'], 'level clear receipt mismatch')
    ticks = receipt.get('edge_ticks')
    _require(type(ticks) is list and bool(ticks) and all(type(t) is int for t in ticks), 'level clear edge ticks')
    if _selected_dma(contract, side='control'):
        requests=rows('dma_edge',dma,lambda r:r.get('tick') in ticks)
        request=_control_accepted(requests)['payload']['pre_backend']
        _require(all(type(request.get(k)) is int and request[k]==v for k,v in
            dict(swb_cyc=1,swb_we=1,swb_adr=clear['offset']//4,
                swb_dat_w=clear['value'],swb_sel=clear['byte_enable']).items()),
            'level clear native control request/SEL mismatch')
    lows = rows('cpu_external_irq_sample', cpu, lambda r:r.get('reset_epoch') == epoch
        and type(r.get('local_tick')) is int and r['local_tick'] > take['local_tick']
        and all(r.get(k) == 0 for k in ('expected_input','actual_pre_input','actual_post_input')))
    for sample in lows:
        frame = frame_for_sample(group, sample, events, runner, dma_runtime_name=runtime_name)
        member = next((m for m in frame['members'] if m.get('source_id') == dma+'.irq'), None)
        ref = member.get('latest_native_source') if type(member) is dict else None
        raw = runner.get(ref.get('event_id')) if type(ref) is dict else None
        if (frame.get('value') == 0 and type(member) is dict and member.get('mode') == 'level' and member.get('value') == 0
                and type(raw) is dict and raw.get('kind') == 'local_tick_sample'
                and raw.get('component') == dma and raw.get('reset_epoch') == epoch
                and raw.get('phase') == 'post' and type(raw.get('local_tick')) is int
                and raw['local_tick'] >= ticks[0] and take['event_id'] < raw['event_id'] < sample['event_id']):
            return dict(clear_accept_event_id=accept['event_id'],clear_delivery_event_id=delivered['event_id'],
                clear_response_event_id=response['event_id'],low_source_event_id=raw['event_id'],
                low_sample_event_id=sample['event_id'],low_local_tick=sample['local_tick'])
    _present(False, 'level clear followed by real low sample unavailable')

def _saved_dma_configuration_values(program, csr, behavior, control_size):
    from .f6_dma_behavior import validate_f6_dma_behavior
    behavior = validate_f6_dma_behavior(behavior, control_size=control_size)
    length = csr['length_words'] * (4 if behavior['length_unit'] == 'bytes' else 1)
    return (program['source_address'], program['destination_address'], length, csr['start_word'])


def _control_accepted(edges):
    """Return the one accepted control beat after any held STB wait cycles."""
    ordered = sorted(edges, key=lambda row: row['tick'])
    active = [row for row in ordered if row.get('payload',{}).get('pre_backend',{}).get('swb_stb') == 1]
    accepted = [row for row in active if row['payload']['pre_backend'].get('swb_stall') == 0]
    _present(bool(active), 'native DMA control request unavailable')
    _present(bool(accepted), 'native DMA control acceptance unavailable')
    _require(len(accepted) == 1, 'native DMA control acceptance cardinality')
    request = accepted[0]
    reference=request['payload']['pre_backend']
    _require(all(row['payload']['pre_backend'].get('swb_stb') == int(row['tick'] <= request['tick'])
        for row in ordered)
        and all(row['payload']['pre_backend'].get('swb_stall') == 1
            for row in active if row['tick'] < request['tick'])
        and all(all(row['payload']['pre_backend'].get(k)==reference.get(k)
            for k in ('swb_cyc','swb_we','swb_adr','swb_dat_w','swb_sel')) for row in active),
        'native DMA control wait/acceptance order')
    return request


def _saved_clear_request(contract, events, case, cpu, dma, *, dma_tick=None, cpu_tick=None, transaction=None):
    """Recognize a separate ISR clear only through its own archived transaction."""
    clear = contract.get('dma', {}).get('behavior', {}).get('irq_clear', {})
    if clear.get('method') != 'write':
        return False
    address = contract['control']['base'] + clear['offset']
    value, be = clear['value'], clear['byte_enable']
    def rows(kind, component):
        return [r for r in events if r.get('kind') == kind and r.get('component') == component
            and r.get('provenance', {}).get('observed_case') == case]
    matches = []
    for delivered in rows('mmio_delivery', cpu):
        key = delivered.get('source_transaction')
        receipt = delivered.get('dma_control_receipt')
        if (type(key) is not dict or type(receipt) is not dict
                or delivered.get('device_id') != contract['control']['device_id']
                or delivered.get('address') != address or delivered.get('write') is not True
                or delivered.get('write_value') != value or delivered.get('byte_enable') != be):
            continue
        expected = dict(source_transaction=key,address=address,offset=clear['offset'],
            write=True,value=value,byte_enable=be)
        ticks = receipt.get('edge_ticks')
        if (any(receipt.get(k) != v for k,v in expected.items()) or type(ticks) is not list
                or len(ticks) < 3 or any(type(t) is not int for t in ticks)
                or ticks != list(range(ticks[0],ticks[0]+len(ticks)))):
            continue
        accepts = [r for r in rows('data_accept',cpu) if r.get('transaction') == key
            and r.get('address') == address and r.get('write') == 1 and r.get('wdata') == value and r.get('be') == be]
        responses = [r for r in rows('data_response',cpu) if r.get('transaction') == key
            and r.get('address') == address and r.get('write') == 1 and r.get('wdata') == value
            and r.get('be') == be and r.get('error') == 0]
        routed = [r for r in rows('mmio_acceptance',cpu) if r.get('source_transaction') == key
            and r.get('device_id') == contract['control']['device_id'] and r.get('address') == address
            and r.get('write') is True and r.get('write_value') == value and r.get('byte_enable') == be]
        if len(accepts) != 1 or len(responses) != 1 or len(routed) != 1:
            continue
        accept = accepts[0]
        takes = [r for r in rows('cpu_external_irq_taken',cpu) if r.get('reset_epoch') == key.get('source_epoch')
            and r['event_id'] < accept['event_id']]
        if (len(takes) != 1 or key.get('source_component') != cpu or key.get('channel_id') != 'data'
                or key.get('execution_id') != 'local-execution' or not key.get('testcase_id')
                or not accept['event_id'] < delivered['event_id'] < responses[0]['event_id']):
            continue
        samples = [r for r in rows('local_tick_sample',cpu) if r.get('phase') == 'pre'
            and r.get('local_tick') == accept.get('acceptance_tick')]
        if len(samples) != 1:
            continue
        backend = samples[0].get('outputs',{}).get('backend',{})
        if any(backend.get(k) != v for k,v in dict(d_req_valid=1,d_req_ready=1,d_req_write=1,
                d_req_addr=address,d_req_be=be,d_req_wdata=value).items()):
            continue
        edges = [r for r in rows('dma_edge',dma) if r.get('tick') in ticks]
        acks = [r for r in edges if r.get('payload',{}).get('pre_backend',{}).get('swb_ack') == 1]
        if len(edges) != len(ticks) or len(acks) != 1:
            continue
        try:
            request = _control_accepted(edges)
        except _EvidenceIssue:
            continue
        active = [r for r in edges if r.get('payload',{}).get('pre_backend',{}).get('swb_stb') == 1]
        expected_pre=dict(swb_cyc=1,swb_we=1,swb_adr=clear['offset']//4,swb_dat_w=value)
        if _selected_dma(contract,side='control'):
            expected_pre['swb_sel']=be
        if (active[0].get('tick') != ticks[0] or acks[0].get('tick') != ticks[-2]
                or request['tick'] >= acks[0]['tick']
                or any(any(r['payload']['pre_backend'].get(k) != v
                    for k,v in expected_pre.items()) for r in active)):
            continue
        if transaction is not None and transaction != key:
            continue
        if dma_tick is not None and dma_tick not in {row['tick'] for row in active}:
            continue
        if cpu_tick is not None and cpu_tick != accept.get('acceptance_tick'):
            continue
        matches.append(delivered)
    return len(matches) == 1

def project_saved_cpu_configuration(*, attempt, contract, events, local_by_id, shared_context=None):
    """Return ``{kind, outcome, details}`` for one saved configuration attempt.

    ``local_by_id`` maps (component, Observer ID) to authenticated Observer
    rows. Selected rows are checked again against their Runner IDs. Discovery
    and duplicate detection use *all* Runner rows, including rows omitted from
    that Observer inventory. Unsupported/missing evidence cannot pass.

    Details are a canonical JSON document specific to this projection, not a
    reconstruction of the live consumer's diagnostic/independent-edge DTOs.
    Contradictions take precedence over missing independent observations.
    """
    issues = []
    details = dict(schema_version='compiled_F6_saved_cpu_configuration.v1',
                   operands=[], configuration_transactions=[], writes=[])

    def check(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except _EvidenceIssue as error:
            issues.append(dict(outcome=error.outcome, reason=str(error)))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as error:
            issues.append(dict(outcome='failed', reason='invalid evidence: '+str(error)))
        return None

    indices = None

    def setup():
        nonlocal indices
        indices = saved_slot_mapping(attempt, contract, events, shared_context)
        _require(type(attempt) is dict and type(contract) is dict
                 and type(events) is list and type(local_by_id) is dict, 'input shape')
        _require(type(attempt.get('case_id')) is str and bool(attempt['case_id'])
                 and type(attempt.get('case_index')) is int, 'attempt identity')
        program = contract['program_contract']
        cpu, dma = contract['cpu']['instance_id'], contract['dma']['instance_id']
        _require(type(cpu) is str and type(dma) is str and cpu != dma, 'component identities')
        names = contract['control']['configuration_order']
        _require(names == contract['dma']['csr']['configuration_order']
                 and len(names) == 4, 'configuration order contract')
        raw = bytes.fromhex(attempt['raw8_hex'])
        value = int.from_bytes(raw, 'little')
        candidate = F6Candidate(raw, tuple((value >> (11*i)) & 2047 for i in range(4)))
        prefix = bytes.fromhex(attempt['prefix_hex'])
        build_f6_firmware(contract).validate_prefix(prefix, candidate,
                                                  case_index=attempt['case_index'])
        runner = {}
        for row in events:
            _require(type(row) is dict and type(row.get('event_id')) is int
                     and row['event_id'] > 0 and row['event_id'] not in runner,
                     'duplicate/invalid Runner event identity')
            runner[row['event_id']] = row
        return program, cpu, dma, names, prefix, runner

    prepared = check(setup)
    if prepared is not None:
        program, cpu, dma, names, prefix, runner = prepared
        expected_case = dict(case_id=attempt['case_id'], case_index=indices['session_case_index'])
        scope_keys = []
        orders = {name: [] for name in ('cpu', 'transaction_sequence', 'router_acceptance',
                                       'router_delivery', 'target_delivery', 'dma')}
        chosen_runner_ids = set()
        cpu_samples = {}
        sequence_histories = {}
        for row in events:
            if row.get('component') == cpu and row.get('kind') == 'local_tick_sample':
                tick = row.get('local_tick')
                if type(tick) is int:
                    cpu_samples.setdefault(tick, []).append(row)

        def observed_case(row):
            provenance = row.get('provenance')
            return provenance.get('observed_case') if type(provenance) is dict else None

        def in_case(row):
            return observed_case(row) == expected_case

        def case_scope(row):
            _present(observed_case(row) is not None, 'case provenance unavailable')
            _require(_canonical(observed_case(row)) == _canonical(expected_case),
                     'cross-case evidence')

        def reference(section, index, kind):
            refs = attempt.get(section)
            _present(refs is not None, section+' references unavailable')
            _require(type(refs) is list, section+' references are not a list')
            _require(len(refs) <= 4 and len(set(refs)) == len(refs),
                     section+' duplicate/extra references')
            _present(index < len(refs) and refs[index] is not None,
                     section+' reference unavailable')
            ref = refs[index]
            _require(type(ref) is int and ref > 0, section+' reference identity')
            row = local_by_id.get((cpu, ref))
            _present(row is not None, section+' Observer row unavailable')
            _require(type(row) is dict and row.get('event_id') == ref
                     and row.get('component') == cpu and row.get('kind') == kind,
                     section+' Observer reference mismatch')
            rid = row.get('runner_event_id')
            _require(type(rid) is int and rid > 0, 'Observer Runner link identity')
            actual = runner.get(rid)
            _present(actual is not None, 'referenced Runner row unavailable')
            projected = {k:v for k,v in row.items() if k != 'runner_event_id'}
            projected['event_id'] = rid
            _require(_canonical(projected) == _canonical(actual), 'Observer Runner row mismatch')
            _require(rid not in chosen_runner_ids, 'reused Runner reference')
            chosen_runner_ids.add(rid)
            case_scope(actual)
            return actual

        def key(row, channel, source=False):
            transaction = row.get('source_transaction' if source else 'transaction')
            fields = {'execution_id', 'testcase_id', 'source_component',
                      'source_epoch', 'channel_id', 'source_sequence'}
            _require(type(transaction) is dict and set(transaction) == fields,
                     'incomplete transaction identity')
            _require(all(type(transaction[k]) is str and transaction[k] for k in
                         ('execution_id','testcase_id','source_component','channel_id'))
                     and all(type(transaction[k]) is int and transaction[k] >= 0
                             for k in ('source_epoch','source_sequence'))
                     and transaction['source_component'] == cpu
                     and transaction['channel_id'] == channel, 'transaction owner/channel')
            scope = {k:transaction[k] for k in
                     ('execution_id','testcase_id','source_component','source_epoch')}
            if scope_keys:
                _require(scope == scope_keys[0], 'cross-scope CPU transaction')
            else:
                scope_keys.append(scope)
            for field, transaction_field in [('execution_id','execution_id'),
                    ('source_component','source_component'), ('source_epoch','source_epoch'),
                    ('reset_epoch','source_epoch')]:
                if field in row:
                    _require(type(row[field]) is type(transaction[transaction_field])
                             and row[field] == transaction[transaction_field],
                             'CPU envelope transaction mismatch')
            return transaction

        def unique(kind, *, address, transaction=None, acceptance_tick=None, source=False):
            field = 'source_transaction' if source else 'transaction'
            # Same key is relevant even if an attacker changes its address or
            # provenance; same address is relevant throughout this attempt.
            matches = [r for r in events if r.get('component') == cpu
                and r.get('kind') == kind and (
                    transaction is not None and r.get(field) == transaction
                    or r.get('address') == address and (in_case(r)
                        and (kind == 'instr_response' or r.get('write') != 0)
                        or acceptance_tick is not None
                        and r.get('acceptance_tick') == acceptance_tick))]
            matches = [r for r in matches if not (transaction is not None
                and type(r.get(field)) is dict and r.get(field) != transaction
                and _saved_clear_request(contract, events, expected_case, cpu, dma,
                    transaction=r.get(field)))]
            _require(len(matches) <= 1, 'duplicate '+kind+' in transaction/address domain')
            _present(matches, kind+' observation unavailable')
            row = matches[0]
            case_scope(row)
            if transaction is not None:
                _require(_canonical(row.get(field)) == _canonical(transaction),
                         kind+' transaction mismatch')
            return row

        def cpu_sample(tick, *, current_case=True):
            phases = cpu_samples.get(tick, [])
            _present(phases, 'CPU native samples unavailable')
            _require(len(phases) <= 2 and len({r.get('phase') for r in phases}) == len(phases),
                     'duplicate CPU native sample phase')
            _require(all(r.get('phase') in ('pre','post') for r in phases), 'CPU sample phase')
            _present(len(phases) == 2, 'complete CPU native sample unavailable')
            pre = next(r for r in phases if r['phase'] == 'pre')
            post = next(r for r in phases if r['phase'] == 'post')
            if current_case:
                for row in phases:
                    case_scope(row)
            producer = runner.get(pre.get('producer_event_id'))
            _require(type(producer) is dict and producer.get('component') == cpu
                and producer.get('local_tick') == tick and 'kind' not in producer
                and type(producer.get('inputs')) is dict and type(producer.get('outputs')) is dict
                and post.get('producer_event_id') == producer['event_id']
                and producer['event_id'] < pre['event_id'] < post['event_id'],
                'CPU sample producer/phase identity')
            _present(type(pre.get('outputs', {}).get('backend')) is dict,
                     'CPU native backend unavailable')
            return pre['outputs']['backend']

        def cpu_event_step(row, tick):
            cpu_sample(tick)
            pre = next(r for r in cpu_samples[tick] if r['phase'] == 'pre')
            producer_id = row.get('producer_event_id')
            _present(producer_id is not None, 'CPU semantic event producer unavailable')
            _require(type(producer_id) is int and producer_id == pre['producer_event_id']
                and producer_id < row['event_id'] < pre['event_id'],
                'CPU semantic event producer/tick/drain order mismatch')
            return runner[producer_id]

        def native_sequence(transaction, tick):
            # Generated OBI service counters reset at native begin/reset, not
            # at an F6 logical case boundary. _serve allocates exactly one key
            # per accepted PRE handshake. Thus history must include boot and
            # previous logical cases, including every idle tick, until this A.
            anchors = [r for r in events if r.get('component') == cpu
                and r.get('kind') in ('cpu_native_startup', 'cpu_reset')
                and type(r.get('local_tick')) is int and r['local_tick'] < tick]
            _present(anchors, 'native CPU sequence reset anchor unavailable')
            start = max(r['local_tick'] for r in anchors)
            latest = [r for r in anchors if r['local_tick'] == start]
            _require(len(latest) == 1, 'duplicate native CPU sequence reset anchor')
            anchor = latest[0]
            _require(start >= 0 and anchor.get('physical_reset') is True
                and type(anchor.get('reset_epoch')) is int
                and anchor['reset_epoch'] == transaction['source_epoch']
                and anchor.get('source_component') == transaction['source_component']
                and anchor.get('execution_id') == transaction['execution_id'],
                'native CPU sequence reset scope mismatch')
            state = sequence_histories.setdefault(anchor['event_id'],
                dict(tick=start, counts=dict(instr=0, data=0), ordinals={},
                     previous_producer=anchor['event_id']))
            while state['tick'] < tick:
                next_tick = state['tick']+1
                backend = cpu_sample(next_tick, current_case=False)
                pre = next(r for r in cpu_samples[next_tick] if r['phase'] == 'pre')
                if next_tick == 1 and start == 0 and pre['producer_event_id'] < anchor['event_id']:
                    # The startup-ready receipt is drained by the first step,
                    # after its producer and before the PRE/POST observations.
                    post = next(r for r in cpu_samples[next_tick] if r['phase'] == 'post')
                    producer = runner[pre['producer_event_id']]
                    scope = pre.get('f6_obi_scope')
                    receipt = anchor.get('receipt_id')
                    alias = receipt.get('execution', '') if type(receipt) is dict else ''
                    alias_prefix = 'local-driver:' + cpu + ':'
                    ordinal = alias[len(alias_prefix):] if type(alias) is str and alias.startswith(alias_prefix) else ''
                    _require(anchor.get('kind') == 'cpu_native_startup'
                        and anchor.get('schema_version') == 'cpu_native_startup.v1'
                        and anchor.get('phase') == 'startup_ready'
                        and anchor.get('producer_event_id') == producer['event_id']
                        and producer['event_id'] < anchor['event_id'] < pre['event_id']
                        and anchor.get('command_scope') == dict(component=cpu, reset_epoch=anchor['reset_epoch'], command_sequence=0)
                        and type(receipt) is dict and set(receipt) == {'execution', 'sequence'}
                        and type(receipt['sequence']) is int and receipt['sequence'] == 0
                        and ordinal.isascii() and ordinal.isdigit() and ordinal[0:1] not in ('','0')
                        and type(scope) is list and len(scope)==4
                        and type(scope[0]) is str and bool(scope[0])
                        and type(scope[1]) is int and scope[1]==1
                        and type(scope[2]) is int and scope[2]==anchor['reset_epoch']
                        and type(scope[3]) is int and scope[3]==1
                        and _canonical(post.get('f6_obi_scope')) == _canonical(scope)
                        and producer.get('outputs', {}).get('driver_samples') == [dict(local_tick=1,
                            pre=pre.get('outputs'), post=post.get('outputs'))],
                        'native CPU startup first-step producer/scope mismatch')
                else:
                    _require(pre['producer_event_id'] > state['previous_producer'],
                             'native CPU reset/history producer chronology mismatch')
                accepted = {}
                for channel, tag in (('instr','i'),('data','d')):
                    valid, ready = backend.get(tag+'_req_valid'), backend.get(tag+'_req_ready')
                    _present(valid is not None and ready is not None,
                             'native CPU sequence handshake history unavailable')
                    _require(type(valid) is int and valid in (0,1)
                        and type(ready) is int and ready in (0,1),
                        'native CPU sequence handshake history malformed')
                    accepted[channel] = int(valid == ready == 1)
                for channel, increment in accepted.items():
                    state['counts'][channel] += increment
                state['ordinals'][next_tick] = dict(state['counts'])
                state['tick'] = next_tick
                state['previous_producer'] = pre['producer_event_id']
            _require(transaction['source_sequence'] ==
                     state['ordinals'][tick][transaction['channel_id']],
                     'CPU transaction sequence differs from native PRE ordinal')

        def native_request(row, address, value, channel):
            backend = cpu_sample(row['acceptance_tick'])
            write = int(channel == 'data')
            tag = 'd' if write else 'i'
            for field, expected in [('req_valid',1),('req_ready',1),('req_write',write),
                    ('req_addr',address),('req_be',15),('req_wdata',value if write else row['wdata'])]:
                _require(type(backend.get(tag+'_'+field)) is int
                         and backend[tag+'_'+field] == expected, 'CPU native accepted handshake')

        def cpu_response(row, address, value, channel):
            transaction = key(row, channel)
            write = int(channel == 'data')
            for field, expected in [('address',address),('raw_address',address),
                    ('aligned_address',address),('write',write),('be',15),('error',0),
                    ('wdata' if write else 'rdata',value)]:
                _require(type(row.get(field)) is int and row[field] == expected,
                         'CPU response '+field+' mismatch')
            a, b = row.get('acceptance_tick'), row.get('response_tick')
            _require(type(a) is int and type(b) is int and 0 <= a < b, 'CPU response chronology')
            check(native_sequence, transaction, a)
            check(cpu_event_step, row, b)
            tag = 'd' if write else 'i'
            def consumed():
                backend = cpu_sample(b)
                for field, expected in [('rsp_valid',1),('rsp_ready',1),
                        ('rsp_rdata',row['rdata']),('rsp_error',0)]:
                    _require(type(backend.get(tag+'_'+field)) is int
                             and backend[tag+'_'+field] == expected, 'CPU native consumed handshake')
                pre = next(r for r in cpu_samples[b] if r['phase'] == 'pre')
                outputs = runner[pre['producer_event_id']]['outputs']
                expected = (dict(data_rsp_consumed=1,
                    data_rsp_source_epoch=transaction['source_epoch'],
                    data_rsp_source_sequence=transaction['source_sequence'],
                    data_rsp_rdata=row['rdata']) if write else dict(instr_rsp_consumed=1,
                    instr_rsp_source_epoch=transaction['source_epoch'],
                    instr_rsp_source_sequence=transaction['source_sequence'],
                    instr_rsp_rdata=row['rdata']))
                for field, value in expected.items():
                    _present(field in outputs, 'CPU response producer identity unavailable')
                    _require(type(outputs[field]) is int and outputs[field] == value,
                             'CPU response producer transaction/consumption mismatch')
            check(native_request, row, address, value, channel)
            check(consumed)
            return transaction

        def operand(index, offset):
            selected = check(reference, 'operands', index, 'instr_response')
            address = program['slot_base']+program['slot_bytes']*indices['slot_index']+offset
            row = unique('instr_response', address=address,
                transaction=selected.get('transaction') if selected else None)
            if selected is not None:
                _require(row == selected, 'operand reference selection mismatch')
            data = prefix[offset:offset+4]
            check(cpu_response, row, address, int.from_bytes(data, 'little'), 'instr')
            snapshot = row.get('snapshot')
            _present(snapshot is not None, 'instruction-source snapshot unavailable')
            _require(type(snapshot) is dict and type(snapshot.get('value')) is int
                and snapshot['value'] == int.from_bytes(data, 'little')
                and snapshot.get('data_hex') == data.hex()
                and snapshot.get('writer_kinds') == ['INSTRUCTION_SOURCE']*4,
                'instruction-source snapshot bytes/writers mismatch')
            if selected is not None:
                details['operands'].append(attempt['operands'][index])

        def routing(row, transaction, address, value, offset):
            _require(key(row, 'data', source=True) == transaction, 'router transaction mismatch')
            expected = dict(device_id=contract['control']['device_id'], address=address,
                offset=offset, beat_bytes=4, write=True, byte_enable=15, write_value=value,
                source_sequence=transaction['source_sequence'])
            _require(all(type(row.get(k)) is type(v) and row[k] == v for k,v in expected.items()),
                     'router address/value/BE/device mismatch')
            if row.get('kind') == 'mmio_acceptance':
                producer = runner.get(row.get('producer_event_id'))
                _present(producer is not None, 'router acceptance producer unavailable')
                tick = producer.get('local_tick')
                _require(type(tick) is int, 'router acceptance producer tick')
                check(cpu_event_step, row, tick)
                check(native_sequence, transaction, tick)
                check(native_request, dict(acceptance_tick=tick), address, value, 'data')

        def control(delivery, transaction, address, value, offset):
            receipt = delivery.get('dma_control_receipt')
            _present(receipt is not None, 'consumed control receipt unavailable')
            expected = dict(source_transaction=transaction, address=address, offset=offset,
                            write=True, value=value, byte_enable=15)
            _require(type(receipt) is dict and all(
                _canonical(receipt.get(k)) == _canonical(v) for k,v in expected.items()),
                'control receipt transaction/address/value mismatch')
            context = receipt.get('delivery_context')
            _present(context is not None, 'control delivery context unavailable')
            expected_context = dict(source_transaction=transaction,
                device_id=contract['control']['device_id'], window_base=contract['control']['base'],
                address=address, offset=offset, write=True, value=value, be=15)
            if 'size' in contract['control']:
                expected_context['window_size'] = contract['control']['size']
            _require(type(context) is dict and all(_canonical(context.get(k)) == _canonical(v)
                     for k,v in expected_context.items()), 'control receipt delivery context mismatch')
            ticks = receipt.get('edge_ticks')
            _present(ticks is not None and ticks != [], 'control native edge references unavailable')
            _require(type(ticks) is list and all(type(t) is int and t >= 0 for t in ticks)
                     and ticks == sorted(set(ticks)), 'control native edge tick identity/order')
            # The compiled F6 service uses max_control_edges=32. Its callback
            # emits one STB, wait edges through the first ACK, then one idle.
            _require(3 <= len(ticks) <= 32
                and ticks == list(range(ticks[0], ticks[0]+len(ticks))),
                'control callback edge coverage/bound mismatch')
            producer_id = delivery.get('producer_event_id')
            _present(producer_id is not None, 'router delivery target producer unavailable')
            _require(type(producer_id) is int, 'router delivery target producer identity')
            producer = runner.get(producer_id)
            _present(producer is not None, 'router delivery target step unavailable')
            case_scope(producer)
            _require(producer.get('component') == dma and 'kind' not in producer
                and type(producer.get('inputs')) is dict and type(producer.get('outputs')) is dict
                and type(producer.get('local_tick')) is int
                and producer['local_tick']+1 == ticks[0]
                and producer_id < delivery['event_id'],
                'router delivery triggering DMA target step mismatch')
            edges = []
            for row in events:
                if row.get('component') != dma or row.get('kind') != 'dma_edge':
                    continue
                pre = row.get('payload', {}).get('pre_backend', {})
                claimed = row.get('tick') in ticks
                same_request = (in_case(row) and pre.get('swb_stb') == 1
                                and pre.get('swb_we') != 0
                                and pre.get('swb_adr') == offset//4)
                if not (claimed or same_request):
                    continue
                case_scope(row)
                # A same-address request outside the claimed callback is a
                # contradiction, never something to discard after discovery.
                if not claimed and _saved_clear_request(contract,events,expected_case,cpu,dma,dma_tick=row.get('tick')):
                    continue
                _require(claimed, 'control request outside receipt edge ticks')
                edges.append(row)
            _require(len({r.get('tick') for r in edges}) == len(edges), 'duplicate DMA control tick')
            _present(set(r['tick'] for r in edges) == set(ticks), 'native DMA control edges unavailable')
            request = _control_accepted(edges)
            pre = request['payload']['pre_backend']
            expected = dict(swb_cyc=1, swb_stb=1, swb_we=1, swb_adr=offset//4, swb_dat_w=value)
            _require(all(type(pre.get(k)) is int and pre[k] == v for k,v in expected.items()),
                     'native DMA control request payload mismatch')
            if _selected_dma(contract, side='control'):
                _require(type(pre.get('swb_sel')) is int and pre['swb_sel']==receipt['byte_enable'],
                    'native DMA control SEL mismatch')
            acknowledgements = [r for r in edges if r['payload']['pre_backend'].get('swb_ack') == 1]
            _present(acknowledgements, 'native DMA control ACK unavailable')
            _require(len(acknowledgements) == 1, 'duplicate native DMA control ACK')
            ordered = sorted(edges, key=lambda r:r['tick'])
            _require(request['tick'] < acknowledgements[0]['tick'] and acknowledgements[0] is ordered[-2],
                     'native DMA request/ACK callback order mismatch')
            for i, edge in enumerate(ordered):
                final = i == len(ordered)-1
                expected = dict(swb_cyc=0 if final else 1, swb_stb=int(edge['tick'] <= request['tick']),
                    swb_we=0 if final else 1, swb_adr=0 if final else offset//4,
                    swb_dat_w=0 if final else value, swb_ack=int(i==len(ordered)-2))
                pre = edge['payload']['pre_backend']
                _require(all(type(pre.get(k)) is int and pre[k] == v for k,v in expected.items()),
                         'native DMA control callback payload/idle mismatch')
                if _selected_dma(contract, side='control') and not final and edge['tick'] <= request['tick']:
                    _require(pre.get('swb_sel') == receipt['byte_enable'], 'native DMA held SEL mismatch')
            orders['dma'].append(request['tick'])
            return [r['event_id'] for r in sorted(edges, key=lambda r:r['tick'])]

        def configuration(index, name, value):
            offset = contract['dma']['csr']['offsets'][name]
            address = contract['control']['base']+offset
            def independent_native_requests():
                observed = []
                for row in events:
                    if row.get('component') != dma or row.get('kind') != 'dma_edge' or not in_case(row):
                        continue
                    pre = row.get('payload', {}).get('pre_backend', {})
                    if pre.get('swb_stb') == 1 and pre.get('swb_we') != 0 and pre.get('swb_adr') == offset//4:
                        if _saved_clear_request(contract,events,expected_case,cpu,dma,dma_tick=row.get('tick')):
                            continue
                        if pre.get('swb_stall') == 0:
                            observed.append(pre)
                _require(len(observed) <= 1, 'duplicate native DMA configuration write')
                for pre in observed:
                    _require(type(pre.get('swb_cyc')) is int and pre['swb_cyc'] == 1
                        and type(pre.get('swb_we')) is int and pre['swb_we'] == 1
                        and type(pre.get('swb_dat_w')) is int and pre['swb_dat_w'] == value,
                        'independent native DMA configuration value mismatch')
            check(independent_native_requests)
            def independent_cpu_requests():
                requests = []
                for phases in cpu_samples.values():
                    for sample in phases:
                        if sample.get('phase') != 'pre' or not in_case(sample):
                            continue
                        pre = sample.get('outputs', {}).get('backend', {})
                        if (pre.get('d_req_valid') == pre.get('d_req_ready') == 1
                                and pre.get('d_req_addr') == address and pre.get('d_req_write') != 0):
                            if _saved_clear_request(contract,events,expected_case,cpu,dma,cpu_tick=sample.get('local_tick')):
                                continue
                            requests.append(sample)
                            expected = dict(d_req_write=1, d_req_addr=address, d_req_be=15, d_req_wdata=value)
                            _require(all(type(pre.get(k)) is int and pre[k] == v for k,v in expected.items()),
                                     'independent native CPU configuration payload mismatch')
                            check(cpu_sample, sample['local_tick'])
                _require(len(requests) <= 1, 'duplicate native CPU configuration request')
            check(independent_cpu_requests)
            selected = check(reference, 'configuration', index, 'data_accept')
            delivery_ref = check(reference, 'deliveries', index, 'mmio_delivery')
            accepted = check(unique, 'data_accept', address=address,
                             transaction=selected.get('transaction') if selected else None)
            response = check(unique, 'data_response', address=address,
                transaction=accepted.get('transaction') if accepted else None,
                acceptance_tick=accepted.get('acceptance_tick') if accepted else None)
            router_accept = check(unique, 'mmio_acceptance', address=address,
                transaction=accepted.get('transaction') if accepted else None, source=True)
            delivery = check(unique, 'mmio_delivery', address=address,
                transaction=accepted.get('transaction') if accepted else
                    delivery_ref.get('source_transaction') if delivery_ref else None, source=True)
            # Missing one branch must not suppress contradictions in the
            # surviving independent response/router/control observations.
            anchor = next((r for r in (accepted,response,router_accept,delivery) if r is not None), None)
            if anchor is None:
                return
            transaction = check(key, anchor, 'data', source='source_transaction' in anchor)
            if transaction is None:
                return
            details['configuration_transactions'].append(deepcopy(transaction))
            orders['transaction_sequence'].append(transaction['source_sequence'])
            def acceptance():
                if selected is not None:
                    _require(accepted == selected, 'configuration reference selection mismatch')
                expected = dict(address=address, raw_address=address, aligned_address=address,
                                write=1, wdata=value, be=15)
                _require(all(type(accepted.get(k)) is int and accepted[k] == v
                             for k,v in expected.items()), 'CPU configuration write mismatch')
                tick = accepted.get('acceptance_tick')
                _require(type(tick) is int and tick >= 0, 'CPU acceptance tick')
                orders['cpu'].append(tick)
                # The acceptance is an independent observed leaf even when
                # its native response is absent from a partial archive.
                check(native_sequence, transaction, tick)
                check(native_request, accepted, address, value, 'data')
                check(cpu_event_step, accepted, tick)
            if accepted is not None:
                check(acceptance)
            if response is not None:
                check(_require, response.get('transaction') == transaction, 'CPU response transaction mismatch')
                check(cpu_response, response, address, value, 'data')
                if accepted is not None:
                    check(_require, response.get('acceptance_tick') == accepted.get('acceptance_tick'),
                          'CPU acceptance/response tick mismatch')
            for row, order_fields in [(router_accept,[('acceptance_order','router_acceptance')]),
                    (delivery,[('delivery_order','router_delivery'),('target_delivery_order','target_delivery')])]:
                if row is None:
                    continue
                check(routing, row, transaction, address, value, offset)
                for field, group in order_fields:
                    order = row.get(field)
                    if type(order) is int and order > 0:
                        orders[group].append(order)
                    else:
                        check(_require, False, 'router ordering identity')
            if router_accept is not None and accepted is not None:
                check(_require, router_accept.get('producer_event_id') == accepted.get('producer_event_id')
                    and router_accept['event_id'] < accepted['event_id'],
                    'router acceptance/CPU acceptance normalized drain order mismatch')
            if delivery is not None:
                if delivery_ref is not None:
                    check(_require, delivery == delivery_ref, 'delivery reference selection mismatch')
                edge_ids = check(control, delivery, transaction, address, value, offset)
                if response is not None and type(response.get('producer_event_id')) is int:
                    check(_require, delivery['event_id'] < response['producer_event_id'],
                          'router delivery follows CPU response producer')
                details['writes'].append(dict(name=name, address=address, value=value,
                    transaction=deepcopy(transaction), native_control_events=edge_ids or []))

        for i, offset in enumerate(program['operand_instruction_offsets']):
            check(operand, i, offset)
        for i, (name, value) in enumerate(zip(names,
                _saved_dma_configuration_values(program, contract['dma']['csr'], contract['dma'].get('behavior'),
                    contract['control'].get('size', 16)))):
            check(configuration, i, name, value)
        for group, values in orders.items():
            check(_require, values == sorted(set(values)), group+' configuration order mismatch')
            check(_present, len(values) == 4, group+' four-write ordering unavailable')

    # Deduplicate diagnostics without depending on input mapping iteration order.
    details['issues'] = sorted({(i['outcome'], i['reason']) for i in issues})
    details['issues'] = [dict(outcome=outcome, reason=reason) for outcome,reason in details['issues']]
    outcome = ('failed' if any(i['outcome'] == 'failed' for i in issues)
               else 'missing' if issues else 'passed')
    return json.loads(_canonical(dict(kind='dma.cpu_configuration', outcome=outcome, details=details)))


def _project_saved_word_transfer(*, attempt, contract, binding, events, local_by_id, shared_context=None):
    """Project the four-word DMA chain from a saved Runner archive.

    The supplied binding is a detached, already-recompiled F6 execution
    binding. This function verifies its canonical route documents and checks
    every referenced Observer row against its unique Runner row. It reads no
    live session, ledger, memory service, issued-read token, or receipt object;
    the result is an offline semantic reconstruction of archived facts only.
    """
    from hashlib import sha256
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract

    issues = []
    edge_issues = {index:[] for index in range(3)}
    active_edge_ids = (0,1,2)
    details = dict(schema_version='compiled_F6_saved_word_transfer.v1',
        words=[], raw_references=[], partial_effects=dict(
            source_commit_event_ids=[], read_snapshot_event_ids=[],
            destination_commit_event_ids=[], accepted_transactions=[]),
        graph_edge_issues={str(index):[] for index in range(3)})

    def capture(function, *args, _edge_ids=None, **kwargs):
        edge_ids=active_edge_ids if _edge_ids is None else _edge_ids
        try:
            return function(*args, **kwargs)
        except _EvidenceIssue as error:
            issue=dict(outcome=error.outcome, reason=str(error))
            issues.append(issue)
            for index in edge_ids:
                edge_issues[index].append(deepcopy(issue))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError,
                IndexError) as error:
            issue=dict(outcome='failed', reason='invalid evidence: '+str(error))
            issues.append(issue)
            for index in edge_ids:
                edge_issues[index].append(deepcopy(issue))
        return None

    def finish():
        for field in ('source_commit_event_ids', 'read_snapshot_event_ids',
                'destination_commit_event_ids'):
            details['partial_effects'][field] = sorted(
                set(details['partial_effects'][field]))
        transactions = {_canonical(row): row for row in
            details['partial_effects']['accepted_transactions']}
        details['partial_effects']['accepted_transactions'] = sorted(
            transactions.values(), key=lambda transaction:
                transaction.get('source_sequence', -1))
        unique = sorted({(row['outcome'], row['reason']) for row in issues})
        details['issues'] = [dict(outcome=outcome, reason=reason)
            for outcome, reason in unique]
        for index, rows in edge_issues.items():
            details['graph_edge_issues'][str(index)] = [dict(outcome=status,reason=reason)
                for status,reason in sorted({(row['outcome'],row['reason']) for row in rows})]
        outcome = ('failed' if any(row['outcome'] == 'failed' for row in issues)
                   else 'missing' if issues else 'passed')
        return json.loads(_canonical(dict(kind='dma.word_transfer_join',
            outcome=outcome, details=details)))

    indices = None

    def input_document():
        nonlocal indices
        indices = saved_slot_mapping(attempt, contract, events, shared_context)
        _require(type(attempt) is dict and type(contract) is dict
            and type(binding) is dict and type(events) is list
            and type(local_by_id) is dict, 'input shape')
        _require(type(attempt.get('case_id')) is str and bool(attempt['case_id'])
            and type(attempt.get('case_index')) is int
            and attempt['case_index'] >= 0, 'attempt identity')
        program = contract['program_contract']
        cpu = contract['cpu']['instance_id']
        dma = contract['dma']['instance_id']
        _require(type(cpu) is str and bool(cpu) and type(dma) is str
            and bool(dma) and cpu != dma, 'component identities')
        raw = bytes.fromhex(attempt['raw8_hex'])
        _require(len(raw) == 8, 'candidate raw8 width')
        packed = int.from_bytes(raw, 'little')
        _require(packed >> 44 == 0, 'candidate reserved bits are nonzero')
        words = tuple((packed >> (11 * index)) & 0x7ff for index in range(4))
        _require(len(set(words)) == 4, 'candidate words are not distinct')
        declared_words = attempt.get('words')
        if declared_words is not None:
            _require(type(declared_words) is list and declared_words == list(words),
                'saved candidate words differ from raw8')
        prefix = bytes.fromhex(attempt['prefix_hex'])
        candidate = F6Candidate(raw, words)
        build_f6_firmware(contract).validate_prefix(prefix, candidate,
            case_index=attempt['case_index'])

        runner = {}
        for row in events:
            _require(type(row) is dict and type(row.get('event_id')) is int
                and row['event_id'] > 0 and row['event_id'] not in runner,
                'duplicate/invalid Runner event identity')
            runner[row['event_id']] = row

        binding_body = {key: value for key, value in binding.items()
            if key != 'binding_sha256'}
        _require(binding.get('schema_version') == 'compiled_F6_execution_binding.v1'
            and type(binding.get('binding_sha256')) is str
            and binding['binding_sha256'] == sha256(_canonical(binding_body).encode()).hexdigest()
            and binding.get('flow_id') == 'F6'
            and binding.get('path_id') == contract.get('path_id'),
            'execution binding identity/digest')
        contract_digest = sha256(_canonical(contract).encode()).hexdigest()
        if 'execution_contract_sha256' in binding:
            _require(binding['execution_contract_sha256'] == contract_digest,
                'execution binding contract digest')
        bound_routes = binding.get('dma_routes')
        path = binding.get('runtime_path_admission')
        selected_routes = path.get('selected_dma_routes') if type(path) is dict else None
        _present(type(bound_routes) is list and type(selected_routes) is list,
            'bound DMA route inventory unavailable')
        _require(_canonical(bound_routes) == _canonical(selected_routes),
            'execution binding route views disagree')
        _require(len(bound_routes) == 2, 'execution binding route count')
        routes = {}
        for document in bound_routes:
            try:
                route = DmaMasterRouteContract.from_document(document)
            except (TypeError, ValueError, KeyError) as error:
                raise _EvidenceIssue('failed', 'invalid bound route document: '+str(error)) from error
            _require(route.operation not in routes, 'duplicate bound route operation')
            routes[route.operation] = route.document()
        _require(set(routes) == {'read', 'write'}, 'bound read/write route pair')

        master = contract['master_routes']
        intent_document = master['intents']
        intents = intent_document.get('routes') if type(intent_document) is dict else None
        _present(type(intents) is list, 'contract DMA route intents unavailable')
        _require(len(intents) == 2, 'contract DMA route intent count')
        intent_by_operation = {}
        for intent in intents:
            _require(type(intent) is dict and intent.get('operation') in ('read', 'write')
                and intent['operation'] not in intent_by_operation,
                'contract DMA route intent identity')
            intent_by_operation[intent['operation']] = intent
        _require(set(intent_by_operation) == {'read', 'write'},
            'contract DMA read/write intent pair')
        resource = contract['memory']['resource']
        _require(type(resource) is dict
            and type(resource.get('resource_id')) is str and bool(resource['resource_id'])
            and type(resource.get('base')) is int and type(resource.get('size')) is int
            and resource['base'] >= 0 and resource['size'] > 0,
            'contract shared memory resource')
        bound_memory = binding.get('memory')
        _present(type(bound_memory) is dict
            and type(bound_memory.get('identity_sha256')) is str,
            'bound memory identity hash unavailable')
        identity_hash = bound_memory['identity_sha256']
        _require(len(identity_hash) == 64 and all(character in '0123456789abcdef'
            for character in identity_hash), 'bound memory identity hash')
        physical_link = master.get('physical_endpoint_link')
        _present(type(physical_link) is dict, 'contract DMA endpoint binding unavailable')
        contract_bindings = master.get('bindings')
        _present(type(contract_bindings) is list and len(contract_bindings) == 2,
            'contract DMA route bindings unavailable')
        binding_by_id = {row.get('route_id'): row for row in contract_bindings
            if type(row) is dict}
        _require(len(binding_by_id) == 2, 'duplicate/incomplete contract route bindings')
        route_links = path.get('route_links') if type(path) is dict else None
        for operation, route_doc in routes.items():
            route = DmaMasterRouteContract.from_document(route_doc)
            intent = intent_by_operation[operation]
            route_binding = binding_by_id.get(intent.get('route_id'))
            _present(type(route_binding) is dict, 'contract route binding unavailable')
            target = intent.get('target')
            _require(route_binding.get('initiator') == physical_link.get('template_binding')
                and route.initiator_component == intent.get('initiator_instance') == dma
                and (route.endpoint_id == physical_link.get('endpoint_id')
                    or route_links is not None)
                and route.target_kind == target.get('kind') == 'persistent_memory'
                and route.target_component == target.get('component_instance') == cpu
                and route.target_id == target.get('resource_id') == resource['resource_id']
                and route.base == intent.get('base') == resource['base']
                and route.size == intent.get('size') == resource['size']
                and route.operation == intent.get('operation')
                and list(route.permissions) == intent.get('permissions')
                and route.byte_enable == intent.get('byte_enable') == 15
                and list(route.readable_offsets) == intent.get('readable_offsets') == []
                and list(route.writable_offsets) == intent.get('writable_offsets') == []
                and type(intent.get('accepted_write_values')) is dict
                and intent['accepted_write_values'].get('values') == []
                and route.accepted_write_values == (),
                'bound route differs from contract intent/endpoint/resource')
            _require(route.target_identity_sha256 == identity_hash,
                'bound route memory identity mismatch')
        if route_links is not None:
            _require(type(route_links) is list and len(route_links) == 2,
                'runtime route link inventory')
            for operation, route_doc in routes.items():
                intent = intent_by_operation[operation]
                matches = [row for row in route_links
                    if type(row) is dict and row.get('route_id') == intent['route_id']]
                _require(len(matches) == 1, 'runtime route endpoint link cardinality')
                link = matches[0]
                endpoint = link.get('endpoint_link')
                _require(link.get('runtime_route_sha256') == route_doc['identity_sha256']
                    and link.get('rule_index') == route_doc['rule_index']
                    and link.get('prerequisite_index') == route_doc['prerequisite_index']
                    and type(endpoint) is dict
                    and endpoint.get('static_endpoint_id') == intent['initiator_endpoint_id']
                    and endpoint.get('artifact_endpoint_id') == physical_link['endpoint_id']
                    and endpoint.get('runtime_endpoint_id') == route_doc['endpoint_id']
                    and (route_doc['endpoint_id'] == physical_link['endpoint_id']
                        or endpoint.get('mode') == 'explicit_alias'
                        and endpoint.get('artifact_link_id') == physical_link.get('link_id')
                        and endpoint.get('artifact_link_provider_id') == 'wishbone-dma-single-master.v1')
                    and endpoint.get('operation') == operation
                    and endpoint.get('template_binding') == physical_link['template_binding'],
                    'runtime route endpoint binding mismatch')
        return dict(program=program, cpu=cpu, dma=dma, resource=resource,
            prefix=prefix,
            words=words, routes=routes, runner=runner,
            expected_case=dict(case_id=attempt['case_id'], case_index=indices['session_case_index']))

    prepared = capture(input_document)
    if prepared is None:
        return finish()
    p = prepared['program']
    cpu, dma, runner = prepared['cpu'], prepared['dma'], prepared['runner']
    words, routes, resource = prepared['words'], prepared['routes'], prepared['resource']
    prefix = prepared['prefix']
    expected_case = prepared['expected_case']

    def dma_effect_order(accepted, effect, response):
        accept_id, snapshot_id = accepted.get('event_id'), effect.get('event_id')
        response_id, tick = response.get('event_id'), accepted.get('tick')
        if any(type(value) is not int for value in (accept_id, snapshot_id, response_id, tick)):
            return False
        if not (accept_id < response_id and snapshot_id < response_id):
            return False
        if accept_id < snapshot_id:
            return True
        producer_id = accepted.get('producer_event_id')
        producer = runner.get(producer_id) if type(producer_id) is int else None
        return (type(producer) is dict and producer_id < snapshot_id < accept_id
            and effect.get('producer_event_id') == producer_id
            and producer.get('component') == dma
            and type(producer.get('local_tick')) is int
            and producer['local_tick'] == tick
            and effect.get('transaction') == accepted.get('accepted', {}).get('transaction'))

    chosen_runner_ids = set()
    selected_refs = {}
    source_rows = [None] * 4
    source_documents = [None] * 4
    source_keys = [None] * 4
    operand_rows = [None] * 4
    operand_facts = [None] * 4
    details['operands'] = []

    def case_scope(row):
        provenance = row.get('provenance')
        _present(type(provenance) is dict
            and provenance.get('observed_case') is not None,
            'Runner case provenance unavailable')
        _require(_canonical(provenance['observed_case']) == _canonical(expected_case),
            'cross-case Runner evidence')

    def belongs_to_case(row):
        provenance = row.get('provenance')
        try:
            return (type(provenance) is dict
                and _canonical(provenance.get('observed_case'))
                    == _canonical(expected_case))
        except (TypeError, ValueError):
            return False

    def reference(section, index, owner, kind, *, optional=False):
        refs = attempt.get(section)
        _present(refs is not None, section+' references unavailable')
        _require(type(refs) is list and len(refs) <= 4,
            section+' reference list shape')
        _present(index < len(refs), section+' word reference unavailable')
        ref = refs[index]
        if ref is None and optional:
            return None
        _present(ref is not None, section+' word reference unavailable')
        _require(type(ref) is int and ref > 0, section+' Observer identity')
        row = local_by_id.get((owner, ref))
        _present(row is not None, section+' Observer row unavailable')
        _require(type(row) is dict and row.get('event_id') == ref
            and row.get('component') == owner
            and row.get('kind', row.get('schema_version')) == kind,
            section+' Observer reference mismatch')
        runner_id = row.get('runner_event_id')
        _require(type(runner_id) is int and runner_id > 0,
            section+' Runner link identity')
        actual = runner.get(runner_id)
        _present(actual is not None, section+' Runner row unavailable')
        projected = {key: value for key, value in row.items()
            if key != 'runner_event_id'}
        projected['event_id'] = runner_id
        _require(_canonical(projected) == _canonical(actual),
            section+' Observer/Runner row mismatch')
        links = [(key, candidate) for key, candidate in local_by_id.items()
            if key[0] == owner and type(candidate) is dict
            and candidate.get('runner_event_id') == runner_id]
        _require(len(links) == 1 and links[0][0] == (owner, ref),
            section+' Observer/Runner link is not bijective')
        _require(runner_id not in chosen_runner_ids,
            'Runner event reused by selected word-transfer references')
        chosen_runner_ids.add(runner_id)
        case_scope(actual)
        detail_ref = dict(component=owner, event_id=ref, kind=kind)
        if detail_ref not in details['raw_references']:
            details['raw_references'].append(detail_ref)
        return actual

    def key(row, owner, channel, *, scope_cache):
        transaction = row.get('transaction')
        fields = {'execution_id', 'testcase_id', 'source_component',
            'source_epoch', 'channel_id', 'source_sequence'}
        _require(type(transaction) is dict and set(transaction) == fields,
            'incomplete full transaction identity')
        _require(all(type(transaction[name]) is str and transaction[name]
            for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
            and all(type(transaction[name]) is int and transaction[name] >= 0
                for name in ('source_epoch', 'source_sequence'))
            and transaction['source_component'] == owner
            and transaction['channel_id'] == channel,
            'transaction owner/channel/field types')
        scope = tuple(transaction[name] for name in
            ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
        previous = scope_cache.get(owner)
        _require(previous is None or previous == scope,
            'cross-scope transaction identity')
        scope_cache[owner] = scope
        return transaction

    def unique_transaction(owner, kind, transaction, *, nested=None):
        field = nested or 'transaction'
        matches = [row for row in events
            if row.get('component') == owner and row.get('kind') == kind
            and type(row.get(field)) is dict
            and row[field] == transaction]
        _require(len(matches) <= 1, 'duplicate '+kind+' transaction event')
        _present(matches, kind+' transaction event unavailable')
        return matches[0]

    scope_cache = {}

    cpu_samples_by_tick = _cpu_sample_index(events, cpu)

    def cpu_samples(tick, *, current_case):
        samples = cpu_samples_by_tick.get(tick, [])
        _present(samples, 'CPU native PRE/POST samples unavailable')
        _require(len(samples) <= 2
            and len({row.get('phase') for row in samples}) == len(samples),
            'duplicate CPU native sample phase')
        _require(all(row.get('phase') in ('pre', 'post') for row in samples),
            'CPU native sample phase')
        _present(len(samples) == 2, 'complete CPU native PRE/POST sample unavailable')
        pre = next(row for row in samples if row['phase'] == 'pre')
        post = next(row for row in samples if row['phase'] == 'post')
        if current_case:
            case_scope(pre)
            case_scope(post)
        producer_id = pre.get('producer_event_id')
        producer = runner.get(producer_id)
        _require(type(producer_id) is int and type(producer) is dict
            and producer.get('component') == cpu
            and producer.get('local_tick') == tick and 'kind' not in producer
            and type(producer.get('inputs')) is dict
            and type(producer.get('outputs')) is dict
            and post.get('producer_event_id') == producer_id
            and producer_id < pre['event_id'] < post['event_id'],
            'CPU sample Runner producer/phase chronology')
        backend = pre.get('outputs', {}).get('backend')
        _present(type(backend) is dict, 'CPU PRE backend sample unavailable')
        return backend, producer, pre, post

    def cpu_sequence(transaction, acceptance_tick):
        anchors = [row for row in events if row.get('component') == cpu
            and row.get('kind') in ('cpu_native_startup', 'cpu_reset')
            and type(row.get('local_tick')) is int
            and row['local_tick'] < acceptance_tick]
        _present(anchors, 'CPU transaction sequence reset anchor unavailable')
        start = max(row['local_tick'] for row in anchors)
        latest = [row for row in anchors if row['local_tick'] == start]
        _require(len(latest) == 1, 'duplicate CPU transaction sequence anchor')
        anchor = latest[0]
        _require(anchor.get('physical_reset') is True
            and anchor.get('reset_epoch') == transaction['source_epoch']
            and anchor.get('source_component') == transaction['source_component']
            and anchor.get('execution_id') == transaction['execution_id'],
            'CPU transaction sequence anchor scope')
        counts = dict(instr=0, data=0)
        for tick in range(start+1, acceptance_tick+1):
            backend, _producer, _pre, _post = cpu_samples(tick,
                current_case=(tick == acceptance_tick))
            for channel, prefix in (('instr', 'i'), ('data', 'd')):
                valid = backend.get(prefix+'_req_valid')
                ready = backend.get(prefix+'_req_ready')
                _present(valid is not None and ready is not None,
                    'CPU transaction sequence handshake history unavailable')
                _require(type(valid) is int and valid in (0, 1)
                    and type(ready) is int and ready in (0, 1),
                    'CPU transaction sequence handshake history malformed')
                counts[channel] += int(valid == ready == 1)
        _require(transaction['source_sequence'] == counts[transaction['channel_id']],
            'CPU transaction sequence differs from actual PRE ordinal')

    def cpu_source_acceptance(row, transaction, address, value):
        _require(row.get('transaction') == transaction
            and all(type(row.get(name)) is int for name in
                ('address', 'raw_address', 'aligned_address', 'write', 'be', 'wdata', 'acceptance_tick'))
            and row['address'] == row['raw_address'] == row['aligned_address'] == address
            and row['write'] == 1 and row['be'] == 15 and row['wdata'] == value,
            'CPU source native acceptance record mismatch')
        tick = row['acceptance_tick']
        _require(type(tick) is int and tick >= 0, 'CPU source acceptance tick')
        backend, _producer, pre, _post = cpu_samples(tick, current_case=True)
        for name, expected in (('d_req_valid', 1), ('d_req_ready', 1),
                ('d_req_write', 1), ('d_req_addr', address),
                ('d_req_be', 15), ('d_req_wdata', value)):
            _require(type(backend.get(name)) is int and backend[name] == expected,
                'CPU source PRE handshake '+name)
        _require(row.get('producer_event_id') == pre.get('producer_event_id')
            and row['producer_event_id'] < row['event_id'] < pre['event_id'],
            'CPU source acceptance Runner step ordering')
        cpu_sequence(transaction, tick)

    def cpu_source_response(row, transaction, address, value, acceptance):
        for name, expected in (('transaction', transaction), ('address', address),
                ('raw_address', address), ('aligned_address', address),
                ('write', 1), ('be', 15), ('wdata', value), ('error', 0), ('rdata', 0)):
            _require(row.get(name) == expected, 'CPU source response '+name)
        tick = row.get('response_tick')
        _require(type(tick) is int and tick > acceptance['acceptance_tick']
            and row.get('acceptance_tick') == acceptance['acceptance_tick'],
            'CPU source response chronology')
        backend, producer, pre, _post = cpu_samples(tick, current_case=True)
        for name, expected in (('d_rsp_valid', 1), ('d_rsp_ready', 1),
                ('d_rsp_rdata', 0), ('d_rsp_error', 0)):
            _require(type(backend.get(name)) is int and backend[name] == expected,
                'CPU source response PRE handshake '+name)
        outputs = producer['outputs']
        for name, expected in (('data_rsp_consumed', 1),
                ('data_rsp_source_epoch', transaction['source_epoch']),
                ('data_rsp_source_sequence', transaction['source_sequence']),
                ('data_rsp_rdata', 0)):
            _present(name in outputs, 'CPU source response producer identity unavailable')
            _require(type(outputs[name]) is int and outputs[name] == expected,
                'CPU source response producer identity '+name)
        _require(row.get('producer_event_id') == pre.get('producer_event_id')
            and row['producer_event_id'] < row['event_id'] < pre['event_id'],
            'CPU source response Runner step ordering')

    def validate_commit(row, transaction, address, value):
        _require(row.get('transaction') == transaction
            and row.get('kind') == 'memory_write_commit'
            and row.get('schema_version') == 'memory_write_commit.v1'
            and type(row.get('service_commit_sequence')) is int
            and row['service_commit_sequence'] > 0,
            'write commit event identity/schema')
        document = row.get('commit_document')
        expected_fields = {'schema_version', 'fullkey', 'memory_kind', 'memory_id',
            'generation', 'byte_offset', 'width_bytes', 'byte_enable', 'version',
            'payload_sha256', 'commit_status', 'performed_effect',
            'enabled_byte_cells', 'commit_id'}
        _require(type(document) is dict and set(document) == expected_fields,
            'write commit document shape')
        _require(document.get('schema_version') == 'memory_write_commit_receipt.v1'
            and document.get('fullkey') == transaction
            and document.get('commit_id') == row.get('commit_id')
            and document.get('memory_kind') == 'modeled_host_persistent_memory'
            and document.get('memory_id') == resource['resource_id']
            and type(document.get('generation')) is int
            and document['generation'] >= 0
            and type(document.get('byte_offset')) is int
            and document['byte_offset'] == address - resource['base']
            and document.get('width_bytes') == 4
            and document.get('byte_enable') == 15
            and document.get('commit_status') == 'complete'
            and document.get('performed_effect') is True,
            'write commit owner/span/effect')
        version = document.get('version')
        _require(type(version) is list and len(version) == 2
            and all(type(value) is int and value >= 0 for value in version)
            and version[0] == document['generation'] and version[1] > 0,
            'write commit version shape')
        payload = dict(op='write', address=address, value=value,
            width_bytes=4, byte_enable=15)
        payload_hash = sha256(_canonical(payload).encode()).hexdigest()
        unsigned = dict(document)
        commit_id = unsigned.pop('commit_id')
        _require(type(commit_id) is str and len(commit_id) == 64
            and sha256(_canonical(unsigned).encode()).hexdigest() == commit_id
            and document.get('payload_sha256') == payload_hash,
            'write commit hash/payload digest')
        expected_cells = [dict(byte_offset=document['byte_offset'] + lane,
            value=(value >> (8*lane)) & 255, version=version,
            writer_kind='STORE', writer_event_id=str(TransactionKey(**transaction)))
            for lane in range(4)]
        _require(type(document.get('enabled_byte_cells')) is list
            and _canonical(document['enabled_byte_cells']) == _canonical(expected_cells),
            'write commit byte cells/writer/data mismatch')
        return document

    def validate_source(index, source, commit):
        if source is None:
            return None
        address, value = p['source_address'] + 4*index, words[index]
        transaction = key(source, cpu, 'data', scope_cache=scope_cache)
        source_keys[index] = transaction
        _require(type(source.get('address')) is int
            and source.get('address') == address
            and source.get('width_bytes') == 4
            and source.get('value') == value
            and source.get('byte_enable') == 15,
            'CPU source store address/value/BE')
        observed_commit = unique_transaction(cpu, 'memory_write_commit', transaction)
        case_scope(observed_commit)
        details['partial_effects']['source_commit_event_ids'].append(
            observed_commit['event_id'])
        if commit is not None:
            _require(commit == observed_commit, 'source commit reference differs from Runner join')
        document = validate_commit(observed_commit, transaction, address, value)
        _require(source.get('memory_id') == document['memory_id']
            and source.get('generation') == document['generation']
            and source.get('byte_offset') == document['byte_offset']
            and list(source.get('version', ())) == document['version'],
            'CPU source store commit owner/span/version mismatch')
        accepted = unique_transaction(cpu, 'data_accept', transaction)
        response = unique_transaction(cpu, 'data_response', transaction)
        case_scope(accepted)
        case_scope(response)
        cpu_source_acceptance(accepted, transaction, address, value)
        cpu_source_response(response, transaction, address, value, accepted)
        _require(source['event_id'] < observed_commit['event_id']
            and accepted['acceptance_tick'] < response['response_tick'],
            'CPU source commit/handshake chronology')
        source_rows[index] = source
        source_documents[index] = document
        return document

    def validate_operand(index, offset, selected):
        address = p['slot_base'] + p['slot_bytes']*indices['slot_index'] + offset
        source_slice = prefix[offset:offset+4]
        _require(len(source_slice) == 4, 'candidate functional-fetch slice width')
        value = int.from_bytes(source_slice, 'little')
        transaction = key(selected, cpu, 'instr', scope_cache={})
        source_scope = scope_cache.get(cpu)
        if source_scope is not None:
            _require(tuple(transaction[name] for name in
                ('execution_id', 'testcase_id', 'source_component', 'source_epoch'))
                == source_scope[:4], 'functional fetch crossed CPU testcase/execution scope')
        response = unique_transaction(cpu, 'instr_response', transaction)
        _require(response == selected, 'functional fetch reference differs from Runner response')
        for name, expected in (('address', address), ('raw_address', address),
                ('aligned_address', address), ('write', 0), ('be', 15),
                ('wdata', 0), ('rdata', value), ('error', 0)):
            _require(type(response.get(name)) is int and response[name] == expected,
                'functional fetch response '+name)
        acceptance_tick, response_tick = response.get('acceptance_tick'), response.get('response_tick')
        _require(type(acceptance_tick) is int and acceptance_tick >= 0
            and type(response_tick) is int and response_tick > acceptance_tick,
            'functional fetch response chronology')
        backend, _producer, _pre, _post = cpu_samples(acceptance_tick, current_case=True)
        for name, expected in (('i_req_valid', 1), ('i_req_ready', 1),
                ('i_req_write', 0), ('i_req_addr', address), ('i_req_be', 15),
                ('i_req_wdata', 0)):
            _require(type(backend.get(name)) is int and backend[name] == expected,
                'functional fetch PRE handshake '+name)
        cpu_sequence(transaction, acceptance_tick)
        backend, producer, pre, _post = cpu_samples(response_tick, current_case=True)
        for name, expected in (('i_rsp_valid', 1), ('i_rsp_ready', 1),
                ('i_rsp_rdata', value), ('i_rsp_error', 0)):
            _require(type(backend.get(name)) is int and backend[name] == expected,
                'functional fetch response PRE handshake '+name)
        for name, expected in (('instr_rsp_consumed', 1),
                ('instr_rsp_source_epoch', transaction['source_epoch']),
                ('instr_rsp_source_sequence', transaction['source_sequence']),
                ('instr_rsp_rdata', value)):
            _present(name in producer['outputs'],
                'functional fetch consumer identity unavailable')
            _require(type(producer['outputs'][name]) is int
                and producer['outputs'][name] == expected,
                'functional fetch consumer identity '+name)
        _require(response.get('producer_event_id') == pre.get('producer_event_id')
            and response['producer_event_id'] < response['event_id'] < pre['event_id'],
            'functional fetch response Runner step ordering')
        snapshot = response.get('snapshot')
        _present(type(snapshot) is dict, 'functional fetch source snapshot unavailable')
        _require(type(snapshot.get('value')) is int and snapshot['value'] == value
            and snapshot.get('data_hex') == source_slice.hex()
            and snapshot.get('writer_kinds') == ['INSTRUCTION_SOURCE']*4,
            'functional fetch source snapshot bytes/writers mismatch')
        return dict(address=address, source_slice_hex=source_slice.hex(),
            transaction=deepcopy(transaction), response_event_id=response['event_id'],
            response_value=value)

    def route_for(operation, address):
        route = routes[operation]
        _require(address % 4 == 0 and route['base'] <= address
            and address + 4 <= route['base'] + route['size'],
            'DMA address outside bound '+operation+' route')
        _require(route['operation'] == operation and route['byte_enable'] == 15,
            'DMA operation/BE differs from bound route')
        return route

    def validate_dma_accept(row, index, operation, transaction_scope):
        case_scope(row)
        address = (p['destination_address'] if operation == 'write'
            else p['source_address']) + 4*index
        value = words[index]
        accepted = row.get('accepted')
        _require(type(accepted) is dict, 'DMA accepted beat unavailable')
        transaction = key(accepted, dma, 'dma-memory', scope_cache=scope_cache)
        if transaction_scope is not None:
            _require(tuple(transaction[name] for name in
                ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                == transaction_scope, 'DMA transaction crossed testcase/execution scope')
        details['partial_effects']['accepted_transactions'].append(
            deepcopy(transaction))
        expected_sequence = index + (5 if operation == 'write' else 1)
        _require(transaction['source_sequence'] == expected_sequence,
            'DMA accepted beat source sequence/order')
        expected_write = operation == 'write'
        _require(type(accepted.get('write')) is bool
            and accepted['write'] is expected_write
            and accepted.get('transaction') == transaction
            and accepted.get('address') == address
            and accepted.get('word_address') == address >> 2
            and type(accepted.get('value')) is int
            and 0 <= accepted['value'] < 2**32
            and (not expected_write or accepted['value'] == value)
            and accepted.get('byte_enable') == 15,
            'DMA accepted transaction/address/value/BE')
        pre = row.get('payload', {}).get('pre_backend')
        _present(type(pre) is dict, 'DMA accepted PRE payload unavailable')
        expected_pre = dict(mwb_cyc=1, mwb_stb=1,
            mwb_we=int(expected_write), mwb_adr=address >> 2,
            mwb_dat_w=accepted['value'], mwb_stall=0)
        _require(all(type(pre.get(name)) is int and pre.get(name) == expected
            for name, expected in expected_pre.items()),
            'DMA accepted native PRE handshake/address/data')
        if _selected_dma(contract):
            _require(type(pre.get('mwb_sel')) is int and pre['mwb_sel']==accepted['byte_enable'],
                'DMA accepted native PRE SEL mismatch')
        tick = row.get('tick')
        _require(type(tick) is int and tick > 0, 'DMA accepted native tick')
        route_for(operation, address)
        return transaction, address, value, tick

    def validate_dma_response(row, transaction, accepted_tick, *, error, value):
        if accepted_tick is None:
            _require(row.get('kind') == 'dma_edge'
                and type(row.get('tick')) is int and row['tick'] > 0,
                'DMA response native edge tick unavailable')
        else:
            _require(row.get('kind') == 'dma_edge'
                and type(row.get('tick')) is int and row['tick'] > accepted_tick,
                'DMA response must be a distinct later native edge')
        response = row.get('response')
        _require(type(response) is dict
            and set(response) == {'transaction', 'rdata', 'error', 'delay'}
            and response.get('transaction') == transaction
            and type(response.get('error')) is int
            and response['error'] == int(error)
            and type(response.get('rdata')) is int
            and response['rdata'] == value
            and type(response.get('delay')) is int and response['delay'] >= 0,
            'DMA response transaction/data/error')
        pre = row.get('payload', {}).get('pre_backend')
        _present(type(pre) is dict, 'DMA response PRE payload unavailable')
        ack, err = (0, 1) if error else (1, 0)
        _require(type(pre.get('mwb_ack')) is int and pre['mwb_ack'] == ack
            and type(pre.get('mwb_err')) is int and pre['mwb_err'] == err
            and type(pre.get('mwb_dat_r')) is int and pre['mwb_dat_r'] == value,
            'DMA response native PRE ACK/ERR/data')
        return row['tick']

    def validate_snapshot(row, index, transaction, source_document):
        address, value = p['source_address'] + 4*index, words[index]
        _require(row.get('transaction') == transaction
            and row.get('address') == address and row.get('width_bytes') == 4
            and row.get('memory_id') == resource['resource_id']
            and type(row.get('generation')) is int and row['generation'] >= 0
            and row.get('byte_offset') == address - resource['base']
            and row.get('value') == value
            and row.get('data_hex') == value.to_bytes(4, 'little').hex(),
            'DMA read snapshot owner/address/data')
        versions = row.get('versions')
        writers = row.get('writer_event_ids')
        kinds = row.get('writer_kinds')
        _require(type(versions) in (list, tuple) and len(versions) == 4
            and all(type(version) in (list, tuple) and len(version) == 2
                and type(version[0]) is int and version[0] == row['generation']
                and type(version[1]) is int and version[1] > 0
                for version in versions)
            and type(writers) in (list, tuple) and len(writers) == 4
            and all(type(writer) is str and bool(writer) for writer in writers)
            and type(kinds) in (list, tuple) and list(kinds) == ['STORE']*4,
            'DMA read snapshot byte versions/writers/data shape mismatch')
        if type(source_document) is dict:
            source_key = source_document['fullkey']
            expected_writer = str(TransactionKey(**source_key))
            expected_version = source_document['version']
            _require(row.get('memory_id') == source_document['memory_id']
                and row.get('generation') == source_document['generation']
                and row.get('byte_offset') == source_document['byte_offset']
                and all(list(version) == expected_version for version in versions)
                and list(writers) == [expected_writer]*4,
                'DMA read snapshot byte versions/writers/source mismatch')

    def validate_bound_route_match(route, accepted_transaction, operation, address):
        _require(route_for(operation, address) is route,
            'DMA route selection differs from bound operation')
        if type(attempt.get('route_match_history')) is list:
            history = [row for row in attempt['route_match_history']
                if type(row) is dict and row.get('transaction') == accepted_transaction]
            if history:
                _require(len(history) == 1, 'duplicate saved DMA route match')
                expected = dict(route_sha256=route['identity_sha256'],
                    edge_key=[route['rule_index'], route['prerequisite_index']],
                    source_node_id=route['source_node_id'],
                    target_node_id=route['target_node_id'],
                    path_id=contract['path_id'],
                    initiator_component=route['initiator_component'],
                    endpoint_id=route['endpoint_id'], target_kind=route['target_kind'],
                    target_component=route['target_component'], target_id=route['target_id'],
                    base=route['base'], size=route['size'], operation=operation,
                    address=address, byte_enable=15,
                    transaction=accepted_transaction,
                    target_identity_sha256=route['target_identity_sha256'])
                _require(history[0] == expected,
                    'saved route match differs from bound route/raw PRE')

    def inventory_partial_dma_observations():
        """Retain and audit case-scoped raw DMA facts even when ERR join fails."""
        nonlocal active_edge_ids
        active_edge_ids=(0,1,2)
        dma_scope = None
        case_facts = [row for row in events
            if row.get('component') == dma and belongs_to_case(row)
            and (type(row.get('accepted')) is dict
                or type(row.get('transaction')) is dict
                or row.get('kind') in ('memory_read', 'memory_write_commit')
                or (type(row.get('response')) is dict
                    and type(row['response'].get('transaction')) is dict))]
        for row in case_facts:
            transaction_row = (row['accepted'] if type(row.get('accepted')) is dict
                else row['response'] if type(row.get('response')) is dict
                    and type(row['response'].get('transaction')) is dict
                else row)
            transaction = capture(key, transaction_row, dma, 'dma-memory',
                scope_cache=scope_cache)
            if transaction is not None:
                dma_scope = tuple(transaction[name] for name in
                    ('execution_id', 'testcase_id', 'source_component',
                     'source_epoch', 'channel_id'))
                break
        accepted_domain = []
        for row in events:
            accepted = row.get('accepted')
            transaction = accepted.get('transaction') if type(accepted) is dict else None
            if row.get('component') != dma or row.get('kind') != 'dma_edge' \
                    or type(transaction) is not dict:
                continue
            row_scope = tuple(transaction.get(name) for name in
                ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
            if belongs_to_case(row) or (dma_scope is not None and row_scope == dma_scope):
                accepted_domain.append(row)
        accepted_domain.sort(key=lambda row: (
            row.get('accepted', {}).get('transaction', {}).get('source_sequence')
                if type(row.get('accepted', {}).get('transaction')) is dict
                    and type(row['accepted']['transaction'].get('source_sequence')) is int
                else -1,
            row.get('event_id') if type(row.get('event_id')) is int else -1))

        # Effects are inventoried independently of accepted-beat availability.
        # A missing acceptance join must not erase a snapshot or commit that
        # the Runner actually saved for this case.
        effect_domain = []
        for effect in events:
            tx = effect.get('transaction')
            if (effect.get('component') != dma
                    or effect.get('kind') not in ('memory_read', 'memory_write_commit')):
                continue
            effect_scope = (tuple(tx.get(name) for name in
                ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                if type(tx) is dict else None)
            if belongs_to_case(effect) or (dma_scope is not None and effect_scope == dma_scope):
                effect_domain.append(effect)
        for effect in effect_domain:
            active_edge_ids=((0,) if effect.get('kind')=='memory_read' else (2,))
            capture(case_scope, effect)
            if belongs_to_case(effect):
                event_id = effect.get('event_id')
                capture(_require, type(event_id) is int and event_id > 0,
                    'raw DMA effect event identity unavailable')
                if type(event_id) is int and event_id > 0:
                    field = ('read_snapshot_event_ids'
                        if effect.get('kind') == 'memory_read'
                        else 'destination_commit_event_ids')
                    details['partial_effects'][field].append(event_id)
            transaction = capture(key, effect, dma, 'dma-memory',
                scope_cache=scope_cache)
            if transaction is None:
                continue
            sequence = transaction['source_sequence']
            if not 1 <= sequence <= 8:
                capture(_require, False,
                    'raw DMA effect sequence outside four-word transfer')
                continue
            operation = 'read' if sequence <= 4 else 'write'
            index = sequence - 1 if operation == 'read' else sequence - 5
            expected_kind = 'memory_read' if operation == 'read' else 'memory_write_commit'
            capture(_require, effect.get('kind') == expected_kind,
                'raw DMA effect kind differs from transaction sequence')
            matching_effects = [candidate for candidate in events
                if candidate.get('component') == dma
                and candidate.get('kind') == expected_kind
                and candidate.get('transaction') == transaction]
            capture(_require, len(matching_effects) <= 1,
                'duplicate raw DMA effect transaction')
            address = (p['source_address'] if operation == 'read'
                else p['destination_address']) + 4*index
            value = words[index]
            capture(validate_bound_route_match, routes[operation], transaction,
                operation, address)
            if expected_kind == 'memory_read':
                capture(validate_snapshot, effect, index, transaction,
                    source_documents[index])
            else:
                document = capture(validate_commit, effect, transaction,
                    address, value)
                if document is not None and source_documents[index] is not None:
                    capture(_require, document['generation']
                        == source_documents[index]['generation']
                        and document['version'][1] > source_documents[index]['version'][1],
                        'raw destination version does not follow source')
            accepted_matches = [candidate for candidate in accepted_domain
                if type(candidate.get('accepted')) is dict
                and candidate['accepted'].get('transaction') == transaction]
            capture(_require, len(accepted_matches) <= 1,
                'duplicate accepted beat for raw DMA effect')
            if not accepted_matches:
                capture(_present, False,
                    'raw DMA effect has no matching accepted beat')
            accepted_row = accepted_matches[0] if len(accepted_matches) == 1 else None
            receipt = (accepted_row.get('environment_error_receipt')
                if accepted_row is not None else None)
            has_sealed_no_effect_receipt = (type(receipt) is dict
                and receipt.get('source_transaction') == transaction
                and receipt.get('error') == 1
                and receipt.get('target_effect') is False
                and receipt.get('timing') == 'before_target_effect'
                and receipt.get('execution_binding_sha256') == binding['binding_sha256'])
            if has_sealed_no_effect_receipt:
                active_edge_ids=(0,) if operation=='read' else (2,)
                capture(_require, False,
                    'raw DMA effect contradicts no-effect receipt')
            active_edge_ids=(0,1) if operation=='read' else (2,)
            response_rows = [candidate for candidate in events
                if candidate.get('component') == dma
                and candidate.get('kind') == 'dma_edge'
                and type(candidate.get('response')) is dict
                and candidate['response'].get('transaction') == transaction]
            capture(_require, len(response_rows) <= 1,
                'duplicate response for raw DMA effect')
            if not response_rows:
                capture(_present, False,
                    'raw DMA effect has no matching response')
            accepted_tick = (accepted_row.get('tick')
                if accepted_row is not None else None)
            for response in response_rows:
                capture(case_scope, response)
                payload = response.get('response')
                error_value = payload.get('error') if type(payload) is dict else None
                is_error = error_value == 1
                response_value = 0 if is_error or operation == 'write' else value
                capture(validate_dma_response, response, transaction,
                    accepted_tick, error=is_error, value=response_value)
                capture(_require, type(effect.get('event_id')) is int
                    and type(response.get('event_id')) is int
                    and effect['event_id'] < response['event_id'],
                    'raw DMA effect/response chronology')
                if accepted_row is not None:
                    active_edge_ids=(0,1) if operation=='read' else (2,)
                    capture(_require, type(accepted_row.get('event_id')) is int
                        and type(effect.get('event_id')) is int
                        and type(response.get('event_id')) is int
                        and accepted_row['event_id'] < effect['event_id'],
                        'raw DMA effect acceptance/response chronology')
        sequences = []
        for row in accepted_domain:
            accepted_for_scope=row.get('accepted')
            transaction_for_scope=(accepted_for_scope.get('transaction')
                if type(accepted_for_scope) is dict else None)
            sequence_for_scope=(transaction_for_scope.get('source_sequence')
                if type(transaction_for_scope) is dict else None)
            active_edge_ids=((0,1) if type(sequence_for_scope) is int
                and 1<=sequence_for_scope<=4 else
                (1,2) if type(sequence_for_scope) is int
                and 5<=sequence_for_scope<=8 else (0,1,2))
            capture(case_scope, row)
            accepted = row.get('accepted')
            transaction = capture(key, accepted, dma, 'dma-memory',
                scope_cache=scope_cache)
            if transaction is None:
                continue
            sequence = transaction['source_sequence']
            sequences.append(sequence)
            if not 1 <= sequence <= 8:
                if belongs_to_case(row):
                    details['partial_effects']['accepted_transactions'].append(
                        deepcopy(transaction))
                capture(_require, False,
                    'raw DMA accepted sequence outside four-word transfer')
                continue
            operation = 'read' if sequence <= 4 else 'write'
            index = sequence - 1 if operation == 'read' else sequence - 5
            joined = capture(validate_dma_accept, row, index, operation, dma_scope)
            address = (p['source_address'] if operation == 'read'
                else p['destination_address']) + 4*index
            value = words[index] if operation == 'write' else 0
            capture(validate_bound_route_match, routes[operation], transaction,
                operation, address)
            acceptance_tick = row.get('tick')
            fault_receipt = row.get('environment_error_receipt')
            receipt_selects_row = False
            if fault_receipt is not None:
                expected_receipt = dict(
                    schema_version='f6_dma_environment_error_receipt.v1',
                    owner=dma, source_transaction=transaction, error=1,
                    target_effect=False, timing='before_target_effect',
                    op='master_environment_error', address=address,
                    write=operation == 'write', value=(words[index]
                        if operation == 'write' else 0), byte_enable=15,
                    reason='declared_f6_response_fault',
                    selector=dict(case_index=attempt['case_index'],
                        operation=operation, word_index=index),
                    execution_binding_sha256=binding['binding_sha256'])
                receipt_selects_row = (type(fault_receipt) is dict
                    and fault_receipt == expected_receipt)
                capture(_require, receipt_selects_row,
                    'raw expected-error receipt identity/effect')

            active_edge_ids=(0,1) if operation=='read' else (2,)
            response_rows = [candidate for candidate in events
                if candidate.get('component') == dma
                and candidate.get('kind') == 'dma_edge'
                and type(candidate.get('response')) is dict
                and candidate['response'].get('transaction') == transaction]
            capture(_require, len(response_rows) <= 1,
                'duplicate raw DMA response transaction')
            if not response_rows and not receipt_selects_row:
                capture(_present, False, 'raw DMA response unavailable')
            for response in response_rows:
                capture(case_scope, response)
                payload = response.get('response')
                error_value = payload.get('error') if type(payload) is dict else None
                is_error = error_value == 1
                response_value = 0 if is_error or operation == 'write' else words[index]
                capture(validate_dma_response, response, transaction,
                    acceptance_tick, error=is_error, value=response_value)
                capture(_require, type(row.get('event_id')) is int
                    and type(response.get('event_id')) is int
                    and row['event_id'] < response['event_id'],
                    'raw DMA response event chronology')

            effect_kind = 'memory_read' if operation == 'read' else 'memory_write_commit'
            active_edge_ids=(0,) if operation=='read' else (2,)
            effects = [candidate for candidate in events
                if candidate.get('component') == dma
                and candidate.get('kind') == effect_kind
                and candidate.get('transaction') == transaction]
            capture(_require, len(effects) <= 1,
                'duplicate raw DMA '+effect_kind+' transaction')
            if not effects and not receipt_selects_row:
                capture(_present, False, 'raw DMA '+effect_kind+' unavailable')
            for effect in effects:
                capture(case_scope, effect)
                if operation == 'read':
                    capture(validate_snapshot, effect, index, transaction,
                        source_documents[index])
                    if belongs_to_case(row) and belongs_to_case(effect):
                        details['partial_effects']['read_snapshot_event_ids'].append(
                            effect['event_id'])
                else:
                    document = capture(validate_commit, effect, transaction,
                        address, words[index])
                    if document is not None and source_documents[index] is not None:
                        capture(_require, document['generation']
                            == source_documents[index]['generation']
                            and document['version'][1]
                            > source_documents[index]['version'][1],
                            'raw destination version does not follow source')
                    if belongs_to_case(row) and belongs_to_case(effect):
                        details['partial_effects']['destination_commit_event_ids'].append(
                            effect['event_id'])
                for response in response_rows:
                    capture(_require, type(row.get('event_id')) is int
                        and type(effect.get('event_id')) is int
                        and type(response.get('event_id')) is int
                        and row['event_id'] < effect['event_id'] < response['event_id'],
                        'raw DMA effect chronology')
        if sequences:
            active_edge_ids=(1,)
            capture(_require, len(sequences) == len(set(sequences)),
                'duplicate raw DMA accepted sequence in partial inventory')
        active_edge_ids=(0,1,2)

    # Authenticate every selected source reference before using any semantic data.
    for index in range(4):
        active_edge_ids=(0,)
        selected_source = capture(reference, 'sources', index, cpu, 'memory_write')
        selected_commit = capture(reference, 'source_commits', index, cpu,
            'memory_write_commit')
        address = p['source_address'] + 4*index
        offset = address - resource['base']
        selected_transactions = []
        for selected_row in (selected_source, selected_commit):
            transaction = (selected_row.get('transaction')
                if type(selected_row) is dict else None)
            if type(transaction) is dict:
                selected_transactions.append(_canonical(transaction))
        raw_sources = [row for row in events
            if row.get('component') == cpu and row.get('kind') == 'memory_write'
            and ((type(row.get('transaction')) is dict
                    and _canonical(row['transaction']) in selected_transactions)
                or (row.get('address') == address
                    and row.get('memory_id') == resource['resource_id']
                    and row.get('byte_offset') == offset
                    and (type(row.get('provenance')) is dict
                        and row['provenance'].get('observed_case') == expected_case)))]
        capture(_require, len(raw_sources) <= 1,
            'duplicate raw CPU source store for candidate word')
        if selected_source is not None and raw_sources:
            capture(_require, selected_source == raw_sources[0],
                'selected CPU source reference differs from raw address discovery')
        source_rows[index] = (raw_sources[0] if raw_sources else selected_source)
        if source_rows[index] is not None:
            capture(case_scope, source_rows[index])
            source_documents[index] = capture(validate_source, index,
                source_rows[index], selected_commit)
        elif selected_commit is not None:
            # A surviving commit still has to be internally valid, even when
            # neither the source-store selector nor the source-store row exists.
            transaction = capture(key, selected_commit, cpu, 'data',
                scope_cache=scope_cache)
            if transaction is not None:
                capture(case_scope, selected_commit)
                source_documents[index] = capture(validate_commit, selected_commit,
                    transaction, address, words[index])
                source_keys[index] = transaction
                if belongs_to_case(selected_commit):
                    details['partial_effects']['source_commit_event_ids'].append(
                        selected_commit['event_id'])

    offsets = p.get('operand_instruction_offsets')
    active_edge_ids=()
    if type(offsets) is not list or len(offsets) != 4:
        capture(_present, False, 'four candidate functional-fetch offsets unavailable')
        offsets = [None] * 4
    for index, offset in enumerate(offsets):
        active_edge_ids=()
        selected_operand = capture(reference, 'operands', index, cpu, 'instr_response')
        address = (p['slot_base'] + p['slot_bytes']*indices['slot_index'] + offset
            if type(offset) is int else None)
        selected_tx = (selected_operand.get('transaction')
            if type(selected_operand) is dict else None)
        raw_operands = [row for row in events
            if row.get('component') == cpu and row.get('kind') == 'instr_response'
            and ((type(selected_tx) is dict
                    and row.get('transaction') == selected_tx)
                or (address is not None and row.get('address') == address
                    and type(row.get('provenance')) is dict
                    and row['provenance'].get('observed_case') == expected_case))]
        capture(_require, len(raw_operands) <= 1,
            'duplicate raw functional fetch response for operand')
        if selected_operand is not None and raw_operands:
            capture(_require, selected_operand == raw_operands[0],
                'selected operand reference differs from raw fetch discovery')
        operand_rows[index] = raw_operands[0] if raw_operands else selected_operand
        if operand_rows[index] is not None and offset is not None:
            capture(case_scope, operand_rows[index])
            operand_facts[index] = capture(validate_operand, index, offset,
                operand_rows[index])
            if operand_facts[index] is not None:
                details['operands'].append(dict(word_index=index,
                    **operand_facts[index]))

    expected_error = attempt.get('expected_error') is True
    active_edge_ids=(0,1,2)
    # A present native ERR is discovered from the raw Runner stream, not the
    # saved attempt status or nested diagnostic details.
    raw_errors = [row for row in events if row.get('component') == dma
        and row.get('kind') == 'dma_edge'
        and type(row.get('response')) is dict
        and row['response'].get('error') == 1]
    error_in_case = []
    for row in raw_errors:
        provenance = row.get('provenance')
        if type(provenance) is dict and provenance.get('observed_case') == expected_case:
            error_in_case.append(row)
    expected_error = expected_error or bool(error_in_case)

    if expected_error:
        inventory_partial_dma_observations()
        accepted_refs = []
        for section in ('reads', 'writes'):
            refs = attempt.get(section)
            if type(refs) is not list:
                capture(_present, False, section+' partial references unavailable')
                continue
            capture(_require, len(refs) <= 4, section+' partial reference count')
            for index in range(min(4, len(refs))):
                if refs[index] is None:
                    continue
                row = capture(reference, section, index, dma, 'dma_edge', optional=True)
                if row is not None:
                    accepted_refs.append((section, index, row))
        error_responses = []
        for section in ('read_responses', 'write_responses'):
            refs = attempt.get(section)
            if type(refs) is not list:
                continue
            capture(_require, len(refs) <= 4, section+' partial reference count')
            for index, ref in enumerate(refs[:4]):
                if ref is None:
                    continue
                observer = local_by_id.get((dma, ref)) if type(ref) is int else None
                if (type(observer) is dict and type(observer.get('response')) is dict
                        and observer['response'].get('error') != 1):
                    # Prior successful responses are authenticated once in the
                    # prefix loop below; selecting them here would reuse their
                    # Runner identities and falsely reject a valid ERR prefix.
                    continue
                row = capture(reference, section, index, dma, 'dma_edge', optional=True)
                if row is not None and type(row.get('response')) is dict \
                        and row['response'].get('error') == 1:
                    error_responses.append((section, index, row))
        capture(_present, bool(error_in_case or error_responses),
            'expected-error archive has no scoped native ERR response')
        if not error_in_case and not error_responses:
            return finish()
        capture(_require, len(error_in_case) <= 1 and len(error_responses) <= 1,
            'duplicate native expected-error response')
        if error_in_case:
            selected_error = error_in_case[0]
            capture(case_scope, selected_error)
        elif error_responses:
            selected_error = error_responses[0][2]
        else:
            capture(_present, False,
                'expected-error response has no selected Observer reference')
            return finish()
        capture(case_scope, selected_error)
        if error_responses:
            capture(_require, error_responses[0][2] == selected_error,
                'scoped native ERR differs from selected Observer response')
        error_payload = selected_error.get('response', {})
        error_key = error_payload.get('transaction')
        error_transaction = capture(key, error_payload, dma, 'dma-memory',
            scope_cache=scope_cache)
        if error_transaction is not None:
            accepted_ref_matches = [row for _section, _index, row in accepted_refs
                if type(row.get('accepted')) is dict
                and row['accepted'].get('transaction') == error_transaction]
            raw_accepted_matches = [row for row in events
                if row.get('component') == dma and row.get('kind') == 'dma_edge'
                and type(row.get('accepted')) is dict
                and row['accepted'].get('transaction') == error_transaction]
            capture(_require, len(accepted_ref_matches) <= 1
                and len(raw_accepted_matches) <= 1,
                'duplicate selected native ERR accepted beat')
            accepted_error = (accepted_ref_matches[0]
                if accepted_ref_matches else
                raw_accepted_matches[0] if raw_accepted_matches else None)
            if accepted_ref_matches and raw_accepted_matches:
                capture(_require, accepted_ref_matches[0] == raw_accepted_matches[0],
                    'selected ERR acceptance reference differs from raw Runner row')
            if accepted_error is None:
                issues.append(dict(outcome='failed',
                    reason='selected native ERR has no referenced accepted beat in Runner archive'))
                receipt = None
            else:
                capture(case_scope, accepted_error)
                receipt = accepted_error.get('environment_error_receipt')
            capture(_present, type(receipt) is dict,
                'selected native ERR receipt unavailable')
            receipt = receipt if type(receipt) is dict else {}
            sequence = error_transaction['source_sequence']
            operation = 'read' if sequence <= 4 else 'write'
            word_index = sequence - 1 if operation == 'read' else sequence - 5
            valid_error_word = 0 <= word_index < 4
            capture(_require, valid_error_word,
                'selected native ERR operation/index')
            address = ((p['source_address'] if operation == 'read'
                else p['destination_address']) + 4*word_index
                if valid_error_word else None)
            value = (words[word_index] if valid_error_word and operation == 'write'
                else 0 if valid_error_word else None)
            capture(_require, valid_error_word and type(receipt) is dict
                and receipt.get('schema_version') == 'f6_dma_environment_error_receipt.v1'
                and receipt.get('owner') == dma
                and receipt.get('source_transaction') == error_transaction
                and receipt.get('error') == 1
                and receipt.get('target_effect') is False
                and receipt.get('timing') == 'before_target_effect'
                and receipt.get('op') == 'master_environment_error'
                and receipt.get('address') == address
                and receipt.get('write') is (operation == 'write')
                and receipt.get('value') == value
                and receipt.get('byte_enable') == 15
                and receipt.get('reason') == 'declared_f6_response_fault',
                'selected native ERR receipt identity/effect')
            selector = receipt.get('selector')
            capture(_require, valid_error_word and type(selector) is dict
                and selector.get('case_index') == attempt['case_index']
                and selector.get('operation') == operation
                and selector.get('word_index') == word_index
                and receipt.get('execution_binding_sha256') == binding['binding_sha256'],
                'selected native ERR selector/binding')
            if valid_error_word:
                route = routes[operation]
                capture(validate_bound_route_match, route, error_transaction,
                    operation, address)
                if accepted_error is not None:
                    capture(validate_dma_accept, accepted_error, word_index,
                        operation, scope_cache.get(dma))
            capture(validate_dma_response, selected_error, error_transaction,
                accepted_error.get('tick') if accepted_error is not None else -1,
                error=True, value=0)
            for effect_kind in ('memory_read', 'memory_write_commit'):
                effects = [row for row in events if row.get('component') == dma
                    and row.get('kind') == effect_kind
                    and row.get('transaction') == error_transaction]
                capture(_require, not effects,
                    'selected native ERR has target-side '+effect_kind)
            if valid_error_word:
                no_effect_section = 'read_snapshots' if operation == 'read' else 'word_commits'
                refs = attempt.get(no_effect_section)
                has_no_effect_ref_slot = (type(refs) is list and len(refs) > word_index)
                capture(_present, has_no_effect_ref_slot,
                    'selected native ERR target-effect reference unavailable')
                if has_no_effect_ref_slot:
                    capture(_require, refs[word_index] is None,
                        'selected native ERR has a saved target effect reference')
            if attempt.get('expected_error') is not True:
                issues.append(dict(outcome='failed', reason='native DMA ERR was not declared expected'))
            partial = details['partial_effects']
            partial['error_response'] = dict(event_id=selected_error['event_id'],
                transaction=deepcopy(error_transaction), operation=operation,
                word_index=word_index,
                target_effect=(receipt.get('target_effect')
                    if type(receipt.get('target_effect')) is bool else None))
            # Validate and retain every successful prior raw effect. A local
            # memory-service commit sequence is owner-local; DMA ticks and its
            # transaction sequence define transfer chronology.
            dma_scope = tuple(error_transaction[name] for name in
                ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
            accepted_domain = []
            for row in events:
                accepted = row.get('accepted')
                tx = accepted.get('transaction') if type(accepted) is dict else None
                if (row.get('component') == dma and row.get('kind') == 'dma_edge'
                        and type(tx) is dict
                        and tuple(tx.get(name) for name in
                            ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                            == dma_scope):
                    accepted_domain.append(row)
            accepted_domain.sort(key=lambda row: (
                row.get('accepted', {}).get('transaction', {}).get('source_sequence')
                    if type(row.get('accepted', {}).get('transaction')) is dict
                        and type(row['accepted']['transaction'].get('source_sequence')) is int
                    else -1,
                row.get('event_id') if type(row.get('event_id')) is int else -1))
            for row in accepted_domain:
                capture(case_scope, row)
            selected_sequence = error_transaction['source_sequence']
            accepted_sequences = [row.get('accepted', {}).get('transaction', {}).get(
                'source_sequence') for row in accepted_domain]
            valid_selected_sequence = (type(selected_sequence) is int
                and 1 <= selected_sequence <= 8)
            capture(_require, valid_selected_sequence,
                'selected expected-error DMA sequence outside four-word transfer')
            expected_prefix = (list(range(1, selected_sequence +
                (1 if accepted_error is not None else 0)))
                if valid_selected_sequence else [])
            capture(_require, valid_selected_sequence
                and accepted_sequences == expected_prefix,
                'expected-error DMA accepted prefix/sequence')
            if accepted_error is not None:
                capture(_require, bool(accepted_domain)
                    and accepted_domain[-1].get('accepted', {}).get(
                        'transaction') == error_transaction,
                    'DMA accepted beat follows selected expected ERR')
            else:
                capture(_require, not any(type(row.get('accepted')) is dict
                    and type(row['accepted'].get('transaction')) is dict
                    and type(row['accepted']['transaction'].get('source_sequence')) is int
                    and row['accepted']['transaction']['source_sequence'] >= selected_sequence
                    for row in accepted_domain),
                    'DMA accepted beat follows selected expected ERR')
            prior_domain = [row for row in accepted_domain
                if type(row.get('accepted')) is dict
                and type(row['accepted'].get('transaction')) is dict
                and type(row['accepted']['transaction'].get('source_sequence')) is int
                and row['accepted']['transaction']['source_sequence'] < selected_sequence]
            for row in prior_domain:
                tx = row['accepted']['transaction']
                seq = tx['source_sequence']
                accepted_in_case = belongs_to_case(row)
                prior_operation = 'read' if seq <= 4 else 'write'
                prior_index = seq-1 if prior_operation == 'read' else seq-5
                capture(_require, 0 <= prior_index < 4,
                    'prior expected-error DMA operation/index')
                if not 0 <= prior_index < 4:
                    continue
                route = routes[prior_operation]
                prior_address = (p['source_address'] if prior_operation == 'read'
                    else p['destination_address']) + 4*prior_index
                prior_value = words[prior_index] if prior_operation == 'write' else 0
                capture(validate_dma_accept, row, prior_index,
                    prior_operation, dma_scope)
                response_rows = [candidate for candidate in events
                    if candidate.get('component') == dma
                    and candidate.get('kind') == 'dma_edge'
                    and type(candidate.get('response')) is dict
                    and candidate['response'].get('transaction') == tx]
                capture(_require, len(response_rows) <= 1,
                    'prior expected-error DMA beat response cardinality')
                if not response_rows:
                    capture(_present, False,
                        'prior expected-error DMA response unavailable')
                for response_row in response_rows:
                    capture(case_scope, response_row)
                    capture(validate_dma_response, response_row, tx,
                        row.get('tick'), error=False,
                        value=(words[prior_index]
                            if prior_operation == 'read' else 0))
                    capture(_require, type(row.get('tick')) is int
                        and type(response_row.get('tick')) is int
                        and type(selected_error.get('tick')) is int
                        and row['tick'] < response_row['tick'] < selected_error['tick'],
                        'prior expected-error DMA response chronology')
                response = response_rows[0] if len(response_rows) == 1 else None
                response_section = ('read_responses' if prior_operation == 'read'
                    else 'write_responses')
                response_refs = attempt.get(response_section)
                if type(response_refs) is not list or len(response_refs) <= prior_index \
                        or response_refs[prior_index] is None:
                    capture(_present, False,
                        'prior expected-error response reference unavailable')
                    selected_response = None
                else:
                    selected_response = capture(reference, response_section,
                        prior_index, dma, 'dma_edge')
                if response is not None:
                    capture(_require, selected_response is not None
                        and selected_response == response,
                        'prior expected-error response reference differs from Runner response')
                elif selected_response is not None:
                    capture(_require, any(selected_response == candidate
                        for candidate in response_rows),
                        'prior expected-error response reference is outside Runner response inventory')
                capture(validate_bound_route_match, route, tx,
                    prior_operation, prior_address)
                if prior_operation == 'read':
                    effects = [candidate for candidate in events
                        if candidate.get('component') == dma
                        and candidate.get('kind') == 'memory_read'
                        and candidate.get('transaction') == tx]
                    capture(_require, len(effects) <= 1,
                        'prior expected-error read snapshot cardinality')
                    if not effects:
                        capture(_present, False,
                            'prior expected-error read snapshot unavailable')
                    snap_refs = attempt.get('read_snapshots')
                    snap_ref = (snap_refs[prior_index]
                        if type(snap_refs) is list and len(snap_refs) > prior_index
                        else None)
                    if snap_ref is None:
                        capture(_present, False,
                            'prior expected-error read snapshot reference unavailable')
                    snap = capture(reference, 'read_snapshots', prior_index,
                        dma, 'memory_read') if snap_ref is not None else None
                    for effect in effects:
                        capture(case_scope, effect)
                        capture(validate_snapshot, effect, prior_index, tx,
                            source_documents[prior_index])
                        if accepted_in_case and belongs_to_case(effect):
                            partial['read_snapshot_event_ids'].append(effect['event_id'])
                        for response_row in response_rows:
                            capture(_require, type(row.get('tick')) is int
                                and type(effect.get('event_id')) is int
                                and type(response_row.get('event_id')) is int
                                and row['event_id'] < effect['event_id'] < response_row['event_id'],
                                'prior expected-error read snapshot chronology')
                    if snap is not None:
                        capture(_require, any(snap == effect for effect in effects),
                            'prior read snapshot reference differs from Runner event')
                else:
                    effects = [candidate for candidate in events
                        if candidate.get('component') == dma
                        and candidate.get('kind') == 'memory_write_commit'
                        and candidate.get('transaction') == tx]
                    capture(_require, len(effects) <= 1,
                        'prior expected-error destination commit cardinality')
                    if not effects:
                        capture(_present, False,
                            'prior expected-error destination commit unavailable')
                    commit_refs = attempt.get('word_commits')
                    commit_ref = (commit_refs[prior_index]
                        if type(commit_refs) is list and len(commit_refs) > prior_index
                        else None)
                    if commit_ref is None:
                        capture(_present, False,
                            'prior expected-error destination commit reference unavailable')
                    commit = capture(reference, 'word_commits', prior_index,
                        dma, 'memory_write_commit') if commit_ref is not None else None
                    for effect in effects:
                        capture(case_scope, effect)
                        document = capture(validate_commit, effect, tx,
                            prior_address, words[prior_index])
                        if document is not None and source_documents[prior_index] is not None:
                            capture(_require, document['generation'] == source_documents[prior_index]['generation']
                                and document['version'][1] > source_documents[prior_index]['version'][1],
                                'prior destination version does not follow source commit')
                        if accepted_in_case and belongs_to_case(effect):
                            partial['destination_commit_event_ids'].append(effect['event_id'])
                        for response_row in response_rows:
                            capture(_require, type(row.get('tick')) is int
                                and type(effect.get('event_id')) is int
                                and type(response_row.get('event_id')) is int
                                and row['event_id'] < effect['event_id'] < response_row['event_id'],
                                'prior expected-error destination commit chronology')
                    if commit is not None:
                        capture(_require, any(commit == effect for effect in effects),
                            'prior destination commit reference differs from Runner event')
            issues.append(dict(outcome='failed',
                reason='expected native DMA ERR cannot certify four-word success'))
        return finish()

    # The success branch requires four independently selected rows in every
    # word domain. Resolve all leaves before joining so a missing branch cannot
    # hide a contradiction in another observed branch.
    sections = (
        ('reads', 'read_accept', dma, 'dma_edge'),
        ('read_snapshots', 'snapshot', dma, 'memory_read'),
        ('read_responses', 'read_response', dma, 'dma_edge'),
        ('writes', 'write_accept', dma, 'dma_edge'),
        ('word_commits', 'destination_commit', dma, 'memory_write_commit'),
        ('write_responses', 'write_response', dma, 'dma_edge'))
    selected = {name: [None]*4 for _section, name, _owner, _kind in sections}
    for section, name, owner, kind in sections:
        active_edge_ids=((0,1) if section in ('reads','read_responses') else
            (0,) if section=='read_snapshots' else
            (1,2) if section=='writes' else (2,))
        for index in range(4):
            selected[name][index] = capture(reference, section, index,
                owner, kind)

    dma_scope = None
    accepted_ticks, read_response_ticks = [], []
    write_ticks, write_response_ticks = [], []
    read_sequences, write_sequences = [], []
    words_joined = []
    for index, value in enumerate(words):
        source = source_rows[index]
        source_document = source_documents[index]
        read_accept = selected['read_accept'][index]
        snapshot = selected['snapshot'][index]
        read_response = selected['read_response'][index]
        write_accept = selected['write_accept'][index]
        commit = selected['destination_commit'][index]
        write_response = selected['write_response'][index]
        if read_accept is not None:
            active_edge_ids=(0,1)
            read_join = capture(validate_dma_accept, read_accept, index,
                'read', dma_scope)
            if read_join is not None:
                read_tx, read_address, _read_value, read_tick = read_join
                dma_scope = tuple(read_tx[name] for name in
                    ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                route = routes['read']
                capture(validate_bound_route_match, route, read_tx, 'read',
                    read_address)
                accepted_ticks.append(read_tick)
                read_sequences.append(read_tx['source_sequence'])
                if snapshot is not None:
                    active_edge_ids=(0,)
                    capture(validate_snapshot, snapshot, index,
                        read_tx, source_document)
                active_edge_ids=(0,1)
                if read_response is not None:
                    tick = capture(validate_dma_response, read_response, read_tx,
                        read_accept.get('tick'), error=False, value=value)
                    if tick is not None:
                        read_response_ticks.append(tick)
                response_matches = [row for row in events
                    if row.get('component') == dma and row.get('kind') == 'dma_edge'
                    and type(row.get('response')) is dict
                    and row['response'].get('transaction') == read_tx]
                capture(_require, len(response_matches) <= 1,
                    'duplicate DMA read response transaction')
                if response_matches:
                    capture(_require, read_response is not None
                        and response_matches[0] == read_response,
                        'read response reference differs from unique Runner response')
                else:
                    capture(_present, False, 'unique DMA read response unavailable')
                # A snapshot is evidence for RAM -> DMA read only. Keep a
                # missing or contradictory snapshot from degrading the
                # independent read-response -> write-acceptance edge.
                active_edge_ids=(0,)
                snapshot_matches = [row for row in events
                    if row.get('component') == dma and row.get('kind') == 'memory_read'
                    and row.get('transaction') == read_tx]
                capture(_require, len(snapshot_matches) <= 1,
                    'duplicate DMA read snapshot transaction')
                if snapshot_matches:
                    active_edge_ids=(0,)
                    capture(_require, snapshot is not None
                        and snapshot_matches[0] == snapshot,
                        'read snapshot reference differs from unique Runner callback')
                else:
                    capture(_present, False, 'unique DMA read snapshot unavailable')
                if snapshot is not None:
                    details['partial_effects']['read_snapshot_event_ids'].append(
                        snapshot['event_id'])
        if write_accept is not None:
            active_edge_ids=(1,2)
            write_join = capture(validate_dma_accept, write_accept, index,
                'write', dma_scope)
            if write_join is not None:
                write_tx, write_address, _write_value, write_tick = write_join
                if dma_scope is None:
                    dma_scope = tuple(write_tx[name] for name in
                        ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                route = routes['write']
                capture(validate_bound_route_match, route, write_tx, 'write',
                    write_address)
                write_ticks.append(write_tick)
                write_sequences.append(write_tx['source_sequence'])
                active_edge_ids=(2,)
                if commit is not None:
                    commit_document = capture(validate_commit, commit, write_tx,
                        p['destination_address'] + 4*index, value)
                    if commit_document is not None and source_document is not None:
                        capture(_require, commit_document['generation'] == source_document['generation']
                            and commit_document['version'][1] > source_document['version'][1],
                            'destination commit version does not follow source version')
                    details['partial_effects']['destination_commit_event_ids'].append(
                        commit['event_id'])
                commit_matches = [row for row in events
                    if row.get('component') == dma and row.get('kind') == 'memory_write_commit'
                    and row.get('transaction') == write_tx]
                capture(_require, len(commit_matches) <= 1,
                    'duplicate destination commit transaction')
                if commit_matches:
                    capture(_require, commit is not None
                        and commit_matches[0] == commit,
                        'destination commit reference differs from unique Runner event')
                else:
                    capture(_present, False, 'destination commit transaction unavailable')
                active_edge_ids=(2,)
                if write_response is not None:
                    tick = capture(validate_dma_response, write_response, write_tx,
                        write_accept.get('tick'), error=False, value=0)
                    if tick is not None:
                        write_response_ticks.append(tick)
                response_matches = [row for row in events
                    if row.get('component') == dma and row.get('kind') == 'dma_edge'
                    and type(row.get('response')) is dict
                    and row['response'].get('transaction') == write_tx]
                capture(_require, len(response_matches) <= 1,
                    'duplicate DMA write response transaction')
                if response_matches:
                    capture(_require, write_response is not None
                        and response_matches[0] == write_response,
                        'write response reference differs from unique Runner response')
                else:
                    capture(_present, False, 'unique DMA write response unavailable')
        if (source is not None and source_document is not None
                and read_accept is not None and snapshot is not None
                and read_response is not None and write_accept is not None
                and commit is not None and write_response is not None):
            read_tx = read_accept['accepted']['transaction']
            write_tx = write_accept['accepted']['transaction']
            source_tx = source['transaction']
            read_tick = read_accept['tick']
            write_tick = write_accept['tick']
            active_edge_ids=(0,)
            source_commit_ids=details['partial_effects']['source_commit_event_ids']
            source_commit_event_id=(source_commit_ids[index]
                if len(source_commit_ids)>index else None)
            capture(_present, type(source_commit_event_id) is int,
                'CPU source commit event identity unavailable')
            if type(source_commit_event_id) is int:
                capture(_require, source['event_id'] < source_commit_event_id
                    < min(read_accept['event_id'], snapshot['event_id'])
                    and dma_effect_order(read_accept, snapshot, read_response),
                'CPU source commit/read transfer chronology')
            active_edge_ids=(1,)
            capture(_require, read_tx['source_sequence'] < write_tx['source_sequence']
                and read_response['event_id'] < write_accept['event_id']
                and read_tick < read_response['tick'] < write_tick,
                'DMA read response must precede corresponding write acceptance')
            active_edge_ids=(2,)
            capture(_require, dma_effect_order(write_accept, commit, write_response),
                'DMA write/commit/response chronology')
            destination_doc = commit['commit_document']
            active_edge_ids=(2,)
            capture(_require, destination_doc['version'][0] == source_document['version'][0]
                and destination_doc['version'][1] > source_document['version'][1],
                'destination byte version does not descend from source generation')
            if not issues and operand_facts[index] is not None:
                words_joined.append(dict(word_index=index, value=value,
                    candidate_source_slice_hex=operand_facts[index]['source_slice_hex'],
                    functional_fetch_transaction=deepcopy(operand_facts[index]['transaction']),
                    functional_fetch_response_event_id=operand_facts[index]['response_event_id'],
                    functional_fetch_address=operand_facts[index]['address'],
                    source_transaction=deepcopy(source_tx),
                    source_commit_id=source_document['commit_id'],
                    source_version=deepcopy(source_document['version']),
                    read_transaction=deepcopy(read_tx),
                    source_byte_versions=deepcopy(snapshot['versions']),
                    source_byte_writers=deepcopy(snapshot['writer_event_ids']),
                    read_route_sha256=routes['read']['identity_sha256'],
                    write_transaction=deepcopy(write_tx),
                    write_route_sha256=routes['write']['identity_sha256'],
                    destination_commit_id=destination_doc['commit_id'],
                    destination_version=deepcopy(destination_doc['version']),
                    byte_enable=15,
                    read_response_event_id=read_response['event_id'],
                    write_response_event_id=write_response['event_id']))
        active_edge_ids=(0,1,2)

    # Discover accepted DMA beats from the Runner archive as well as the
    # attempt selectors. A missing selector must not hide a contradictory PRE
    # beat that is still present in the authenticated stream.
    dma_case_rows = [row for row in events
        if row.get('component') == dma and row.get('kind') == 'dma_edge'
        and type(row.get('accepted')) is dict
        and type(row.get('provenance')) is dict
        and row['provenance'].get('observed_case') == expected_case]
    if dma_scope is None:
        for row in dma_case_rows:
            transaction = capture(key, row['accepted'], dma, 'dma-memory',
                scope_cache=scope_cache)
            if transaction is not None:
                dma_scope = tuple(transaction[name] for name in
                    ('execution_id', 'testcase_id', 'source_component',
                     'source_epoch', 'channel_id'))
                break

    accepted_domain = []
    if dma_scope is not None:
        for row in raw_errors:
            response = row.get('response')
            transaction = response.get('transaction') if type(response) is dict else None
            if (type(transaction) is dict and tuple(transaction.get(name) for name in
                    ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
                    == dma_scope):
                capture(case_scope, row)
                capture(_require, False,
                    'native DMA ERR exists in selected four-word success scope')
    for row in events:
        accepted = row.get('accepted')
        transaction = accepted.get('transaction') if type(accepted) is dict else None
        if row.get('component') != dma or row.get('kind') != 'dma_edge' \
                or type(accepted) is not dict:
            continue
        row_scope = (tuple(transaction.get(name) for name in
            ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
            if type(transaction) is dict else None)
        is_case_row = row in dma_case_rows
        if is_case_row or (dma_scope is not None and row_scope == dma_scope):
            accepted_domain.append(row)
    accepted_domain.sort(key=lambda row: (
        row.get('accepted', {}).get('transaction', {}).get('source_sequence')
        if type(row.get('accepted', {}).get('transaction')) is dict
            and type(row['accepted']['transaction'].get('source_sequence')) is int
        else -1, row.get('event_id', -1)))
    raw_accepts_by_sequence = {}
    for row in accepted_domain:
        raw_tx=(row.get('accepted',{}).get('transaction')
            if type(row.get('accepted')) is dict else None)
        raw_sequence=(raw_tx.get('source_sequence')
            if type(raw_tx) is dict else None)
        active_edge_ids=((0,1) if type(raw_sequence) is int
            and 1<=raw_sequence<=4 else
            (1,2) if type(raw_sequence) is int
            and 5<=raw_sequence<=8 else (0,1,2))
        capture(case_scope, row)
        accepted = row.get('accepted')
        transaction = capture(key, accepted, dma, 'dma-memory',
            scope_cache=scope_cache)
        if transaction is None:
            continue
        row_scope = tuple(transaction[name] for name in
            ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
        if dma_scope is None:
            dma_scope = row_scope
        else:
            capture(_require, row_scope == dma_scope,
                'raw DMA acceptance crossed testcase/execution scope')
        sequence = transaction['source_sequence']
        if not 1 <= sequence <= 8:
            capture(_require, False,
                'raw DMA acceptance sequence outside four-word transfer')
            continue
        operation = 'read' if sequence <= 4 else 'write'
        index = sequence - 1 if operation == 'read' else sequence - 5
        joined = capture(validate_dma_accept, row, index, operation, dma_scope)
        if joined is not None:
            capture(validate_bound_route_match, routes[operation], transaction,
                operation, joined[1])
        raw_accepts_by_sequence.setdefault(sequence, []).append((row, transaction))

    if accepted_domain:
        sequences = [row['accepted']['transaction'].get('source_sequence')
            for row in accepted_domain
            if type(row.get('accepted')) is dict
            and type(row['accepted'].get('transaction')) is dict]
        capture(_require, len(accepted_domain) <= 8,
            'extra accepted DMA beat in case scope')
        capture(_require, len(sequences) == len(set(sequences)),
            'DMA accepted transaction sequence has duplicate')
        if len(accepted_domain) < 8:
            capture(_present, len(accepted_domain) == 8,
                'four reads/four writes accepted beat inventory')
        elif len(accepted_domain) == 8:
            capture(_require, sequences == list(range(1, 9)),
                'DMA accepted transaction sequence has gap/reorder')
    else:
        capture(_present, False, 'raw DMA accepted beat inventory unavailable')

    # Recheck every discovered beat's raw response/effect chain independently
    # of the attempt's response/snapshot/commit reference arrays.
    raw_read_response_ticks, raw_write_response_ticks = [], []
    for sequence, accepted_rows in sorted(raw_accepts_by_sequence.items()):
        index = sequence - 1 if sequence <= 4 else sequence - 5
        operation = 'read' if sequence <= 4 else 'write'
        active_edge_ids=(0,1) if operation=='read' else (2,)
        address = (p['source_address'] if operation == 'read'
            else p['destination_address']) + 4*index
        value = words[index]
        response_value = value if operation == 'read' else 0
        if len(accepted_rows) != 1:
            continue
        accepted_row, transaction = accepted_rows[0]
        accepted_tick = accepted_row.get('tick')
        response_rows = [row for row in events
            if row.get('component') == dma and row.get('kind') == 'dma_edge'
            and type(row.get('response')) is dict
            and row['response'].get('transaction') == transaction]
        active_edge_ids=(0,1) if operation=='read' else (2,)
        capture(_require, len(response_rows) <= 1,
            'duplicate raw DMA response transaction')
        response = response_rows[0] if response_rows else None
        if response is None:
            capture(_present, False, 'raw DMA response unavailable')
        else:
            capture(case_scope, response)
            response_tick = capture(validate_dma_response, response, transaction,
                accepted_tick, error=False, value=response_value)
            if response_tick is not None:
                if operation == 'read':
                    raw_read_response_ticks.append(response_tick)
                else:
                    raw_write_response_ticks.append(response_tick)
        effect_kind = 'memory_read' if operation == 'read' else 'memory_write_commit'
        active_edge_ids=(0,) if operation=='read' else (2,)
        effect_rows = [row for row in events
            if row.get('component') == dma and row.get('kind') == effect_kind
            and row.get('transaction') == transaction]
        capture(_require, len(effect_rows) <= 1,
            'duplicate raw DMA '+effect_kind+' transaction')
        if not effect_rows:
            capture(_present, False, 'raw DMA '+effect_kind+' unavailable')
            continue
        effect = effect_rows[0]
        capture(case_scope, effect)
        if operation == 'read':
            capture(validate_snapshot, effect, index, transaction,
                source_documents[index])
            details['partial_effects']['read_snapshot_event_ids'].append(
                effect['event_id'])
            if (type(accepted_tick) is int and response is not None):
                capture(_require, dma_effect_order(accepted_row, effect, response)
                    and accepted_tick < response.get('tick', -1),
                    'raw DMA read snapshot chronology')
        else:
            document = capture(validate_commit, effect, transaction, address,
                words[index])
            if document is not None and source_documents[index] is not None:
                capture(_require, document['generation'] == source_documents[index]['generation']
                    and document['version'][1] > source_documents[index]['version'][1],
                    'raw destination commit version does not follow source')
            details['partial_effects']['destination_commit_event_ids'].append(
                effect['event_id'])
            if (type(accepted_tick) is int and response is not None):
                capture(_require, dma_effect_order(accepted_row, effect, response)
                    and accepted_tick < response.get('tick', -1),
                    'raw DMA destination commit chronology')
    # The aggregate read-before-write checks belong only to the causal edge.
    # The preceding per-transaction effect validation may have left edge 2
    # selected, so reset the issue bucket before evaluating chronology.
    active_edge_ids=(1,)
    if set(raw_accepts_by_sequence) == set(range(1, 9)) \
            and all(len(raw_accepts_by_sequence[sequence]) == 1
                for sequence in range(1, 9)):
        raw_read_accept_ticks = [raw_accepts_by_sequence[sequence][0][0].get('tick')
            for sequence in range(1, 5)]
        raw_write_accept_ticks = [raw_accepts_by_sequence[sequence][0][0].get('tick')
            for sequence in range(5, 9)]
        accepted_tick_inventory_valid = all(type(tick) is int
            for tick in raw_read_accept_ticks + raw_write_accept_ticks)
        capture(_present, accepted_tick_inventory_valid,
            'raw accepted tick inventory unavailable or malformed')
        if (accepted_tick_inventory_valid and len(raw_read_response_ticks) == 4
                and len(raw_write_response_ticks) == 4):
            capture(_require, raw_read_accept_ticks == sorted(set(raw_read_accept_ticks))
                and raw_write_accept_ticks == sorted(set(raw_write_accept_ticks))
                and raw_read_response_ticks == sorted(set(raw_read_response_ticks))
                and raw_write_response_ticks == sorted(set(raw_write_response_ticks))
                and max(raw_read_accept_ticks) < min(raw_write_accept_ticks)
                and max(raw_read_response_ticks) < min(raw_write_accept_ticks),
                'raw four-read-before-four-write chronology')
        else:
            capture(_present, False,
                'raw response ticks incomplete for transfer chronology')
        active_edge_ids=(1,)
    else:
        active_edge_ids=(1,)
        capture(_present, False,
            'raw four-read/four-write accepted chronology unavailable')
    if len(accepted_ticks) == len(read_response_ticks) == 4 \
            and len(write_ticks) == len(write_response_ticks) == 4:
        active_edge_ids=(1,)
        capture(_require, accepted_ticks == sorted(set(accepted_ticks))
            and write_ticks == sorted(set(write_ticks))
            and read_response_ticks == sorted(set(read_response_ticks))
            and write_response_ticks == sorted(set(write_response_ticks))
            and max(accepted_ticks) < min(write_ticks)
            and max(read_response_ticks) < min(write_ticks),
            'strict four-read-before-four-write chronology')
        capture(_require, read_sequences == [1, 2, 3, 4]
            and write_sequences == [5, 6, 7, 8],
            'four-read/four-write full transaction order')
    else:
        active_edge_ids=(1,)
        capture(_present, False, 'complete read/write chronology unavailable')
    details['words'] = words_joined
    return finish()


def project_saved_word_transfer(*, attempt, contract, binding, events, local_by_id, shared_context=None):
    """Return a stable outcome document for one saved word-transfer archive."""
    try:
        return _project_saved_word_transfer(attempt=attempt, contract=contract,
            binding=binding, events=events, local_by_id=local_by_id, shared_context=shared_context)
    except _EvidenceIssue as error:
        outcome, reason = error.outcome, str(error)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError,
            IndexError) as error:
        outcome, reason = 'failed', 'invalid evidence: '+str(error)
    issue=dict(outcome=outcome,reason=reason)
    return json.loads(_canonical(dict(kind='dma.word_transfer_join',
        outcome=outcome, details=dict(
            schema_version='compiled_F6_saved_word_transfer.v1',
            words=[], operands=[], raw_references=[],
            partial_effects=dict(source_commit_event_ids=[],
                read_snapshot_event_ids=[], destination_commit_event_ids=[],
                accepted_transactions=[]),
            graph_edge_issues={str(index):[deepcopy(issue)] for index in range(3)},
            issues=[issue]))))


def _registered_saved_irq_provider(contract, cpu_artifact):
    from myfuzz.local_harness.native_irq_receipt_contract import (
        validate_native_irq_receipt_contract, native_irq_receipt_contract)
    provider = contract['cpu']['native_irq_provider']
    validate_native_irq_receipt_contract(provider)
    if cpu_artifact is not None:
        _require(native_irq_receipt_contract(cpu_artifact) == provider,
                 'saved CPU IRQ provider differs from actual artifact')
    return deepcopy(provider)


# A CPU whose admitted RVFI observation stream is PC/instruction/order only.
# The archived projection must never read, zero-fill or re-derive the fields
# the registered contract declares unobserved.
_LIMITED_RETIREMENT_WIDTHS = {'rvfi_valid': 1, 'rvfi_order': 64,
    'rvfi_insn': 32, 'rvfi_pc_rdata': 32}
_UNOBSERVABLE_RETIREMENT_FIELDS = frozenset({'intr', 'pc_wdata', 'trap', 'mode',
    'halt', 'mem_addr', 'mem_rdata', 'mem_wdata', 'mem_rmask', 'mem_wmask'})
_SERIAL_TOKEN_KEYS = frozenset({'irq_serial_observation',
    'take_irq_serial_observation', 'handler_entry_irq_serial_observation',
    'successor_irq_serial_observation', 'irq_decision_serial',
    'irq_retirement_serial', 'serial_observation', 'retirement_serial'})


def _observed_retirement_names(names):
    """Normalize declared retirement field names to their rvfi_ spelling."""
    if type(names) not in (list, tuple) or not names:
        return None
    normalized = []
    for name in names:
        if type(name) is not str or not name or name.strip() != name:
            return None
        normalized.append(name if name.startswith('rvfi_') else 'rvfi_' + name)
    return normalized


def _saved_retirement_scope(provider):
    """Select and validate the archived authority of one registered provider.

    A provider without a declaration keeps the legacy full-RVFI authority, so
    Ibex and CV32E20 archives project exactly as before.  A limited provider is
    pinned to the registered code-owned contract: the four observed retirement
    fields, every declared unobservable field, the real pre-edge acceptance
    probes and the absence of an exact serial token.
    """
    from myfuzz.scenario.irq_return_successor import (
        PC_INSN_ORDER_ONLY_AUTHORITY, retirement_authority)
    authority = retirement_authority(provider)
    if authority != PC_INSN_ORDER_ONLY_AUTHORITY:
        return dict(authority=authority, limited=False, fields=(), widths={},
            unobserved=(), acceptance=None, probes={}, redirects=None)
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_acceptance, native_irq_decision_probes,
        native_irq_notification_observed, native_irq_redirect_probes,
        native_irq_retirement_diversion_scope, native_irq_serial_observable)
    fields = _observed_retirement_names(provider.get('retirement_fields'))
    _require(fields is not None and len(fields) == len(set(fields))
        and set(fields) == set(_LIMITED_RETIREMENT_WIDTHS),
        'limited authority observed retirement fields must be exactly '
        'valid/order/insn/pc_rdata')
    unobserved = _observed_retirement_names(provider.get('unobserved_retirement_fields'))
    _require(unobserved is not None and len(unobserved) == len(set(unobserved))
        and not set(unobserved) & set(fields)
        and set('rvfi_' + name for name in _UNOBSERVABLE_RETIREMENT_FIELDS) <= set(unobserved),
        'limited authority must declare every unobservable retirement field')
    _require(native_irq_serial_observable(provider) is False,
        'limited authority cannot own an exact IRQ serial token')
    _require(native_irq_notification_observed(provider, {'rvfi_valid': 1}) is False,
        'limited authority cannot claim a post-edge IRQ notification')
    _require(native_irq_retirement_diversion_scope(provider) == 'unobservable',
        'limited authority cannot claim per-retirement diversion observation')
    acceptance = native_irq_acceptance(provider)
    _require(type(acceptance) is dict and type(acceptance.get('source_id')) is int
        and type(acceptance.get('id_width')) is int and 0 < acceptance['id_width'] <= 64,
        'limited authority decision acceptance')
    probes = native_irq_decision_probes(provider)
    _require(all(acceptance.get(name) in probes for name in
            ('ack_probe', 'id_probe', 'entry_pc_probe'))
        and 'irq_taken_pre' in probes, 'limited authority acceptance probes')
    widths = dict(_LIMITED_RETIREMENT_WIDTHS)
    widths.update(probes)
    notifications = provider.get('notification_widths')
    if type(notifications) is dict:
        _require(all(type(width) is int and width > 0
            for width in notifications.values()), 'limited authority notification widths')
        widths.update(notifications)
    input_port = provider.get('input_port')
    _require(type(input_port) is str and bool(input_port),
        'limited authority input port')
    widths[input_port] = provider.get('input_width', 1)
    return dict(authority=authority, limited=True, fields=tuple(fields),
        widths=widths, unobserved=tuple(sorted(set(unobserved))),
        acceptance=acceptance, probes=probes,
        redirects=native_irq_redirect_probes(provider))


def _limited_claim_reasons(fields, observed, unobserved, *, where):
    """Unobservable claims made by one flat field mapping of an archived fact."""
    reasons = []
    if type(fields) is not dict:
        return reasons
    for key, value in fields.items():
        if type(key) is not str:
            continue
        name = key if key.startswith('rvfi_') else 'rvfi_' + key
        short = key[5:] if key.startswith('rvfi_') else key
        if name in unobserved:
            reasons.append('claims unobservable retirement field ' + key +
                ' in ' + where)
        elif key.startswith('rvfi_') and name not in observed:
            reasons.append('claims undeclared RVFI retirement field ' + key +
                ' in ' + where)
        elif short.startswith('mem_'):
            reasons.append('claims unobservable retirement memory field ' + key +
                ' in ' + where)
        elif key in _SERIAL_TOKEN_KEYS and value is not None:
            reasons.append('claims unobservable IRQ serial token ' + key +
                ' in ' + where)
        elif key == 'internal_version' and value != 'unknown':
            reasons.append('claims unobservable internal_version in ' + where)
    return reasons


def _limited_document_claim_reasons(document, observed, unobserved, *, where):
    """Every unobservable retirement claim of one saved archived document."""
    reasons = _limited_claim_reasons(document, observed, unobserved, where=where)
    if type(document) is not dict:
        return reasons
    outputs = document.get('outputs')
    if type(outputs) is dict:
        reasons += _limited_claim_reasons(outputs, observed, unobserved,
            where=where + ' outputs')
        if type(outputs.get('physical')) is dict:
            reasons += _limited_claim_reasons(outputs['physical'], observed,
                unobserved, where=where + ' outputs.physical')
    for key in ('physical', 'successor_instruction_response', 'payload',
            'entry', 'mret', 'take_pre_edge_observation'):
        if type(document.get(key)) is dict:
            reasons += _limited_claim_reasons(document[key], observed,
                unobserved, where=where + ' ' + key)
    for key in ('dispatcher_retirements', 'pre_entry_retirements'):
        rows = document.get(key)
        if type(rows) is not list:
            continue
        for index, row in enumerate(rows):
            reasons += _limited_claim_reasons(row, observed, unobserved,
                where=where + ' ' + key + '[' + str(index) + ']')
    return reasons


def _nested_internal_version_reasons(value, *, where='archive', depth=0):
    """A saved archive may not claim a CPU internal version it cannot observe."""
    reasons = []
    if depth > 12:
        return reasons
    if type(value) is dict:
        if 'internal_version' in value and value['internal_version'] != 'unknown':
            reasons.append('claims unobservable internal_version in ' + where)
        for key, item in value.items():
            if key == 'provenance':
                continue
            reasons += _nested_internal_version_reasons(item,
                where=where + '.' + str(key), depth=depth + 1)
    elif type(value) is list:
        for index, item in enumerate(value[:256]):
            reasons += _nested_internal_version_reasons(item,
                where=where + '[' + str(index) + ']', depth=depth + 1)
    return reasons


def project_saved_irq_isr(*, attempt, contract, binding, events, local_by_id,
                          dma_irq_runtime_name=None, cpu_artifact=None, shared_context=None):
    """Independently rebuild fixed-provider F6 completion from archived facts.

    This is an offline projection. Observer IDs are selectors and are always
    resolved back to Runner content. It neither recreates issuer/ledger seals
    nor grants live/native authority. MRET's pc_wdata has no target authority.

    ``dma_irq_runtime_name`` must come from the caller's independently admitted
    DMA artifact export mapping. Production Observer-only source summaries
    require it; synthetic Runner-backed fixtures may use the logical port.
    """
    from hashlib import sha256
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_serial_observation, native_irq_retirement_diverted,
        native_irq_retirement_diversion_fields)
    from myfuzz.scenario.ledger import TransactionKey

    issues = []
    details = dict(schema_version='compiled_F6_saved_irq_isr.v1',
        raw_references=[], observer_references=[], results=[], irq_input_samples=[], partial_effects={})

    def capture(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except _EvidenceIssue as error:
            issues.append(dict(outcome=error.outcome, reason=str(error)))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError,
                IndexError) as error:
            issues.append(dict(outcome='failed', reason='invalid evidence: '+str(error)))
        return None

    def finish():
        details['issues'] = [dict(outcome=outcome, reason=reason)
            for outcome, reason in sorted({(i['outcome'], i['reason']) for i in issues})]
        outcome = ('failed' if any(i['outcome']=='failed' for i in issues)
            else 'missing' if issues else 'passed')
        details['raw_references'] = sorted(
            {r['runner_event_id']: r for r in details['raw_references']}.values(),
            key=lambda row: row['runner_event_id'])
        return json.loads(_canonical(dict(kind='dma.irq_isr_completion',
            outcome=outcome, details=details)))

    indices = None

    def setup():
        nonlocal indices
        indices = saved_slot_mapping(attempt, contract, events, shared_context)
        _require(type(attempt) is dict and type(contract) is dict
            and type(binding) is dict and type(events) is list
            and type(local_by_id) is dict, 'input shape')
        _require(type(attempt.get('case_id')) is str and bool(attempt['case_id'])
            and type(attempt.get('case_index')) is int and attempt['case_index']>=0,
            'attempt identity')
        cpu, dma = contract['cpu']['instance_id'], contract['dma']['instance_id']
        _require(type(cpu) is str and type(dma) is str and cpu != dma,
            'component identities')
        runner = {}
        for row in events:
            _require(type(row) is dict and type(row.get('event_id')) is int
                and row['event_id']>0 and row['event_id'] not in runner,
                'duplicate/invalid Runner event identity')
            runner[row['event_id']] = row
        provider = _registered_saved_irq_provider(contract, cpu_artifact)
        irq = contract['irq']
        _require(type(irq.get('producer_port')) is str and bool(irq['producer_port'])
            and type(irq.get('producer_endpoint_id')) is str and bool(irq['producer_endpoint_id']),
            'logical IRQ port/endpoint contract identity')
        if dma_irq_runtime_name is not None:
            _require(type(dma_irq_runtime_name) is str and bool(dma_irq_runtime_name)
                and dma_irq_runtime_name.strip()==dma_irq_runtime_name,
                'admitted DMA IRQ runtime name shape')
        _require(contract['cpu'].get('native_irq_provider') == provider
            and irq.get('native_take_provider') == provider
            and irq.get('consumer_instance') == cpu and irq.get('producer_instance') == dma
            and irq.get('consumer_port') == provider['input_port']
            and ((irq.get('delivery_policy') == 'IrqPulseDelivery'
                and type(irq.get('target_local_ticks')) is int and irq['target_local_ticks']==16
                and irq.get('clear_policy') == 'fixed_expiry')
                or (irq.get('delivery_policy') == 'level'
                    and type(irq.get('target_local_ticks')) is int and irq['target_local_ticks']==0
                    and irq.get('clear_policy') == 'software_write'))
            and irq.get('isr_return_schema') == 'native_f6_isr_return.v1',
            'contract does not select registered fixed-pulse IRQ provider')
        raw = bytes.fromhex(attempt['raw8_hex'])
        _require(len(raw)==8 and int.from_bytes(raw,'little') >> 44 == 0,
            'candidate raw8 shape')
        words = tuple((int.from_bytes(raw,'little') >> (11*i)) & 2047 for i in range(4))
        fw = build_f6_firmware(contract)
        fw.validate_prefix(bytes.fromhex(attempt['prefix_hex']), F6Candidate(raw,words),
            case_index=attempt['case_index'])
        retirement = _saved_retirement_scope(provider)
        return cpu, dma, runner, provider, irq, words, fw, retirement

    prepared = capture(setup)
    if prepared is None:
        return finish()
    cpu, dma, runner, provider, irq, words, fw, retirement = prepared
    limited = retirement['limited']
    details['retirement_authority'] = retirement['authority']
    details['unobserved_fields'] = list(retirement['unobserved'])
    if limited:
        # No per-retirement debug/NMI/halt field is driven, so the projection
        # cannot claim to have inspected diversion absence.
        details['retirement_diversion_scope'] = 'unobservable'
    if limited:
        # Full-RVFI observation widths are never assumed here: this CPU drives
        # only the four assigned fields, its real IRQ outputs and its probes.
        physical_widths = dict(retirement['widths'])
    else:
        physical_widths = {provider['input_port']: 1,
            'irq_decision_serial': 64, 'irq_retirement_serial': 64,
            'rvfi_valid': 1, 'rvfi_trap': 1, 'rvfi_intr': 1, 'rvfi_mode': 2,
            'rvfi_order': 64, 'rvfi_insn': 32, 'rvfi_pc_rdata': 32, 'rvfi_pc_wdata': 32,
            'probe_irq_taken_pre': 1, 'probe_irq_masked_pre': 1}
        physical_widths.update({name: 1 for name in native_irq_retirement_diversion_fields(provider)})

    def cpu_physical_exports():
        # Legacy synthetic archives have no bound CPU artifact and directly
        # record logical fields. A bound execution must supply its artifact.
        if cpu_artifact is None:
            _present(cpu not in binding.get('artifact_identities', {}),
                'bound CPU physical export artifact unavailable')
            return None
        from myfuzz.integration.compiled_f4 import _artifact_execution_identity
        from myfuzz.local_harness.native_physical_observation import verify_cpu_obi_protocol_traces
        runtime = cpu_artifact.runtime_document
        plan = cpu_artifact.plan
        identity = _artifact_execution_identity(cpu_artifact)
        bound_cpu = binding.get('cpu', {})
        _require(verify_cpu_obi_protocol_traces(cpu_artifact) is True
            and plan.request.instance_id == cpu and runtime.get('kind') == 'obi_cpu'
            and binding.get('artifact_identities', {}).get(cpu) == identity
            and bound_cpu.get('instance_id') == cpu
            and bound_cpu.get('profile_fingerprint') == plan.profile.profile_fingerprint
            and bound_cpu.get('runtime_artifact_sha256') == sha256(_canonical(runtime).encode()).hexdigest(),
            'CPU physical export artifact binding identity')
        expected = {name: ('input' if name == provider['input_port'] else 'output', width)
            for name, width in physical_widths.items() if not name.startswith('probe_')}
        exports = runtime.get('physical_exports')
        _present(type(exports) is list, 'CPU physical exports unavailable')
        mapping = {}
        for logical, (direction, width) in expected.items():
            rows = [row for row in exports if type(row) is dict and row.get('physical_port') == logical]
            _present(bool(rows), 'CPU physical export unavailable: '+logical)
            _require(len(rows) == 1, 'ambiguous CPU physical export: '+logical)
            row = rows[0]
            name = row.get('runtime_name')
            _require(row.get('direction') == direction and type(row.get('width')) is int
                and row['width'] == width and type(name) is str and bool(name)
                and name.strip() == name, 'invalid CPU physical export: '+logical)
            if logical == provider['input_port']:
                endpoints = [ep for ep in plan.binding.endpoints
                    if ep.endpoint_id == row.get('endpoint_id')
                    and ep.function == 'interrupt_entry']
                _require(len(endpoints) == 1 and row.get('disposition') == 'functional'
                    and row.get('endpoint_id') == irq.get('consumer_endpoint_id')
                    and row.get('role') == 'external', 'CPU IRQ input endpoint mismatch')
            else:
                _require(row.get('disposition') == 'observe', 'CPU observation export mismatch')
            _require(sum(1 for candidate in exports if type(candidate) is dict
                and candidate.get('runtime_name') == name) == 1,
                'ambiguous CPU physical runtime name: '+logical)
            mapping[logical] = name
        return mapping

    physical_mapping = capture(cpu_physical_exports)
    if issues:
        return finish()

    def physical_view(row):
        physical = row.get('outputs', {}).get('physical')
        _present(type(physical) is dict, 'CPU raw physical fields unavailable')
        view = dict(physical)
        for logical, name in (physical_mapping or {}).items():
            _require(logical == name or logical not in physical,
                'conflicting CPU logical/raw physical field')
            if name in physical:
                view[logical] = physical[name]
        for logical, width in physical_widths.items():
            if logical in view:
                value = view[logical]
                _require(type(value) is int and 0 <= value < (1 << width),
                    'invalid CPU physical value: ' + logical)
        return view
    p = contract['program_contract']
    case = dict(case_id=attempt['case_id'], case_index=indices['session_case_index'])

    def limited_decision_probe(view, name, width):
        """One contract-declared pre-edge probe, mapped or raw runtime name."""
        if name in view:
            value = view[name]
        elif 'probe_' + name in view:
            value = view['probe_' + name]
        else:
            _present(False, 'limited pre-edge decision probe unavailable: ' + name)
            return None
        _require(type(value) is int and 0 <= value < 1 << width,
            'limited pre-edge decision probe value: ' + name)
        return value

    def limited_take_probes():
        """Rebuild one native take from its real pre-edge acceptance probes.

        The declared ack/id/entry-PC probes are the only decision observations
        this authority owns. They are read from the raw take event and the PRE
        sample of the same parsed step; disagreement refuses rather than
        choosing one of them.
        """
        _present(take is not None, 'limited native IRQ take event unavailable')
        acceptance, probes = retirement['acceptance'], retirement['probes']
        pre = physical_view(tick_sample(take['local_tick'], 'pre'))
        observed = {}

        def probe(name):
            _present(type(name) is str and name in probes,
                'undeclared limited decision probe: ' + str(name))
            values = []
            if name in take:
                values.append(take[name])
            if name in pre:
                values.append(pre[name])
            elif 'probe_' + name in pre:
                values.append(pre['probe_' + name])
            _present(bool(values), 'limited pre-edge probe unavailable: ' + name)
            _require(all(type(value) is int and 0 <= value < 1 << probes[name]
                for value in values), 'limited pre-edge probe value: ' + name)
            _require(len(set(values)) == 1,
                'conflicting limited pre-edge probe observations: ' + name)
            observed[name] = values[0]
            return values[0]

        _require(probe('irq_taken_pre') == 1,
            'limited take has no actual native IRQ decision')
        _require(probe(acceptance['ack_probe']) == 1,
            'limited take lacks the real acknowledged interrupt')
        identifier = probe(acceptance['id_probe'])
        _require(identifier == acceptance['source_id']
            and 0 <= identifier < 1 << acceptance['id_width'],
            'limited take id is not the declared external source')
        entry_pc = probe(acceptance['entry_pc_probe'])
        _require(entry_pc == p['isr_address'] and entry_pc % 4 == 0,
            'limited take entry PC is not the declared ISR address')
        if 'accepted_source_id' in take:
            _require(take['accepted_source_id'] == acceptance['source_id'],
                'limited take accepted source id mismatch')
        if retirement['redirects'] is not None:
            _require(probe(retirement['redirects']['taken']) == 0,
                'limited take is a non-IRQ exception redirect')
        details['take_probes'] = {name: observed[name] for name in sorted(observed)}
        return entry_pc

    def limited_retirement_leaf(row):
        """Every archived POST sample must carry only the observed stream."""
        physical = physical_view(row)
        _present(type(physical.get('rvfi_valid')) is int,
            'raw limited retirement valid field unavailable')
        _require(physical['rvfi_valid'] in (0, 1),
            'raw limited retirement valid field type')
        if physical['rvfi_valid']:
            _present(all(type(physical.get(name)) is int for name in
                    ('rvfi_order', 'rvfi_insn', 'rvfi_pc_rdata')),
                'raw limited retirement field unavailable')
            _require(physical['rvfi_order'] > 0
                and 0 <= physical['rvfi_insn'] < 1 << 32
                and 0 <= physical['rvfi_pc_rdata'] < 1 << 32,
                'raw limited retirement field/width')

    def in_case(row):
        provenance = row.get('provenance')
        return type(provenance) is dict and provenance.get('observed_case') == case

    def scoped(row):
        provenance = row.get('provenance')
        _present(type(provenance) is dict and provenance.get('observed_case') is not None,
            'case provenance unavailable')
        _require(provenance['observed_case'] == case, 'cross-case Runner evidence')
        details['raw_references'].append(dict(component=row['component'],
            kind=row.get('kind'), runner_event_id=row['event_id']))
        return row

    def unique(kind, owner, predicate=lambda row:True):
        domain = [row for row in events if row.get('kind')==kind
            and row.get('component')==owner and predicate(row)]
        # Foreign cases with unrelated identities cannot enter this projection.
        current = [row for row in domain if in_case(row)]
        _require(len(current)<=1, 'duplicate '+kind+' Runner evidence')
        _present(bool(current), kind+' Runner evidence unavailable')
        return scoped(current[0])

    def selector(ref, owner, kind):
        _present(ref is not None, kind+' Observer reference unavailable')
        _require(type(ref) is int and ref>0, kind+' reference identity')
        observer = local_by_id.get((owner,ref))
        _present(observer is not None, kind+' Observer row unavailable')
        _require(type(observer) is dict and observer.get('event_id')==ref
            and observer.get('component')==owner
            and observer.get('kind',observer.get('schema_version'))==kind,
            kind+' Observer identity mismatch')
        rid = observer.get('runner_event_id')
        if rid is None and kind in ('source_start','binding_delivery',
                'native_f6_isr_return.v1','native_fetch_boundary'):
            # These are production Observer summaries, not Runner events.
            # Their independent raw joins are checked below; do not invent a
            # Runner link or provenance envelope for the summaries themselves.
            identity_field = {'source_start':'source_output_key',
                'binding_delivery':'source_event_id',
                'native_f6_isr_return.v1':'case_id',
                'native_fetch_boundary':'transaction'}[kind]
            duplicates=[value for value in local_by_id.values()
                if type(value) is dict and value.get('component')==owner
                and value.get('kind',value.get('schema_version'))==kind
                and value.get(identity_field)==observer.get(identity_field)]
            _require(len(duplicates)==1,'duplicate derived '+kind+' Observer evidence')
            details['observer_references'].append(dict(component=owner,event_id=ref,kind=kind))
            return observer
        _require(type(rid) is int and rid>0, kind+' Runner reference identity')
        actual = runner.get(rid)
        _present(actual is not None, kind+' Runner row unavailable')
        expected = {k:v for k,v in observer.items() if k not in ('event_id','runner_event_id')}
        _require(expected == {k:v for k,v in actual.items() if k!='event_id'},
            kind+' Observer differs from Runner')
        links=[key for key,value in local_by_id.items() if key[0]==owner
            and type(value) is dict and value.get('runner_event_id')==rid]
        _require(links==[(owner,ref)],kind+' Observer/Runner link is not bijective')
        return scoped(actual)

    selected = {}
    for section,kind,owner in (
            ('irq_output','source_start',dma), ('irq_delivery','binding_delivery',cpu),
            ('irq','cpu_external_irq_taken',cpu), ('return','native_f6_isr_return.v1',cpu),
            ('status','data_response',cpu), ('status_store','memory_write',cpu),
            ('terminal','memory_write',cpu), ('next_fetch','native_fetch_boundary',cpu)):
        selected[section] = capture(selector, attempt.get(section),owner,kind)
        observer_only=(selected[section] is not None
            and kind in ('source_start','binding_delivery','native_f6_isr_return.v1','native_fetch_boundary')
            and 'provenance' not in selected[section])
        if kind not in ('data_response','memory_write') and not observer_only:
            discovered=capture(unique,kind,owner)
            if selected[section] is None:selected[section]=discovered
    # Missing selectors remain missing, while surviving raw rows still undergo
    # independent validation so omissions cannot conceal contradictions.
    for section,kind,owner,predicate in (
            ('status','data_response',cpu,lambda row:row.get('address')==contract['control']['base']+contract['dma']['csr']['offsets']['control'] and row.get('write')==0),
            ('status_store','memory_write',cpu,lambda row:row.get('address')==p['result_base']+24*attempt['case_index']),
            ('terminal','memory_write',cpu,lambda row:row.get('address')==p['result_base']+24*attempt['case_index']+20)):
        discovered=capture(unique,kind,owner,predicate)
        if selected[section] is None:selected[section]=discovered
    # DMA success and the sealed ERR prefix are reconstructed by the adjacent
    # independent projector, with status labels removed as branch authority.
    dma_attempt = deepcopy(attempt)
    raw_errors = [r for r in events if in_case(r) and r.get('component')==dma
        and r.get('kind')=='dma_edge' and type(r.get('response')) is dict
        and r['response'].get('error')==1]
    dma_attempt['expected_error'] = bool(raw_errors)
    word_document = project_saved_word_transfer(attempt=dma_attempt, contract=contract,
        binding=binding, events=events, local_by_id=local_by_id, shared_context=shared_context)
    details['partial_effects'] = word_document['details'].get('partial_effects',{})
    issues.extend(issue for issue in word_document['details'].get('issues',[])
        if issue['reason']!='expected native DMA ERR cannot certify four-word success')
    # A word projector deliberately returns failed for an expected native ERR;
    # completion below independently checks whether its error ISR closed.

    cpu_scope = None
    take = selected['irq']
    returned = selected['return']
    if returned is not None:
        cpu_scope = (returned.get('execution'),returned.get('reset_epoch'),
            returned.get('native_testcase_id'))
    elif take is not None:
        boundary_scope = selected.get('next_fetch') or {}
        cpu_scope = (take.get('receipt_id',{}).get('execution'),take.get('reset_epoch'),
            boundary_scope.get('native_testcase_id'))

    # Normalized Runner receipt names are replay-stable aliases. Only bind one
    # back to a raw nonce when both physical phases and the measured step name
    # the same owner, epoch, command, tick and original driver samples.
    raw_to_alias = {}
    alias_to_raw = {}

    def native_scope(row):
        _require(cpu_scope is not None and type(cpu_scope[0]) is str and bool(cpu_scope[0])
            and type(cpu_scope[1]) is int and cpu_scope[1]>=0, 'native CPU scope')
        _require(row.get('reset_epoch') == cpu_scope[1]
            and type(row.get('reset_epoch')) is int, 'native reset scope')
        receipt = row.get('receipt_id')
        _require(type(receipt) is dict and set(receipt)=={'execution','sequence'}
            and type(receipt.get('execution')) is str and bool(receipt['execution'])
            and type(receipt.get('sequence')) is int and receipt['sequence']>0,
            'native execution/receipt identity')
        _require(row.get('command_scope') == dict(component=cpu,reset_epoch=cpu_scope[1],
            command_sequence=receipt['sequence']), 'native command identity')
        if receipt['execution'] == cpu_scope[0]:
            return receipt
        alias = receipt['execution']
        prefix = 'local-driver:' + cpu + ':'
        ordinal = alias[len(prefix):] if alias.startswith(prefix) else ''
        _require(ordinal.isascii() and ordinal.isdigit() and ordinal[0:1] not in ('','0'),
            'native normalized receipt owner/alias mismatch')
        tick = row.get('local_tick')
        _require(type(tick) is int and tick>0, 'native normalized receipt tick')
        pre, post = tick_sample(tick,'pre'), tick_sample(tick,'post')
        _present('f6_obi_scope' in pre and 'f6_obi_scope' in post,
            'native raw receipt scope unavailable')
        expected_scope = [cpu_scope[0],receipt['sequence'],cpu_scope[1],tick]
        _require(_canonical(pre['f6_obi_scope'])==_canonical(expected_scope)
            and _canonical(post['f6_obi_scope'])==_canonical(expected_scope)
            and row.get('producer_event_id')==pre.get('producer_event_id')
            and pre.get('producer_event_id')==post.get('producer_event_id'),
            'native raw/normalized receipt scope mismatch')
        producer = runner.get(pre['producer_event_id'])
        driver_samples = producer.get('outputs',{}).get('driver_samples')
        _present(type(driver_samples) is list and len(driver_samples)==1,
            'native raw driver sample unavailable')
        sample = driver_samples[0]
        ticks = row.get('receipt_ticks')
        _require(type(ticks) is dict and all(type(ticks.get(k)) is int for k in
                ('tick_before','tick_after','new_ticks','local_tick_base'))
            and ticks['new_ticks']==1 and ticks['tick_after']==ticks['tick_before']+1
            and ticks['tick_after']+ticks['local_tick_base']==tick
            and type(sample) is dict and sample.get('local_tick')==ticks['tick_after']
            and sample.get('pre')==pre.get('outputs') and sample.get('post')==post.get('outputs'),
            'native raw driver sample/tick mismatch')
        if row.get('kind') == 'cpu_external_irq_taken':
            sample_row = unique('cpu_external_irq_sample',cpu,
                lambda candidate:candidate.get('local_tick')==tick)
            _require(row.get('sample_event_id')==sample_row['event_id']
                and sample_row.get('producer_event_id')==row.get('producer_event_id')
                and sample_row.get('receipt_id')==receipt
                and sample_row.get('command_scope')==row.get('command_scope')
                and _canonical(row.get('sample_ref'))==_canonical({
                    'command_scope': row['command_scope'], 'local_tick': tick}),
                'native IRQ take/sample identity mismatch')
        _require(raw_to_alias.get(cpu_scope[0],alias)==alias
            and alias_to_raw.get(alias,cpu_scope[0])==cpu_scope[0],
            'native raw/normalized receipt mapping ambiguous')
        raw_to_alias[cpu_scope[0]]=alias
        alias_to_raw[alias]=cpu_scope[0]
        return {'execution':cpu_scope[0], 'sequence':receipt['sequence']}

    def tick_sample(tick,phase):
        _require(type(tick) is int and tick>=0, 'native local tick type')
        row = unique('local_tick_sample',cpu,lambda row:
            row.get('local_tick')==tick and row.get('phase')==phase)
        producer = runner.get(row.get('producer_event_id'))
        _present(producer is not None, 'native CPU sample producer unavailable')
        scoped(producer)
        _require(producer.get('component')==cpu and 'kind' not in producer
            and producer.get('local_tick')==tick and type(producer.get('inputs')) is dict
            and type(producer.get('outputs')) is dict
            and producer['event_id']<row['event_id'], 'native CPU sample producer identity')
        other=[candidate for candidate in events if in_case(candidate)
            and candidate.get('component')==cpu and candidate.get('kind')=='local_tick_sample'
            and candidate.get('local_tick')==tick and candidate.get('phase')!=phase]
        if other:
            _require(len(other)==1 and other[0].get('producer_event_id')==row.get('producer_event_id')
                and (row['event_id']<other[0]['event_id'] if phase=='pre' else other[0]['event_id']<row['event_id']),
                'native PRE/POST producer/order mismatch')
        return row

    def key_check(key,channel='data'):
        _require(type(key) is dict and set(key)=={'execution_id','testcase_id',
            'source_component','source_epoch','channel_id','source_sequence'}
            and key.get('execution_id')=='local-execution'
            and key.get('source_component')==cpu and type(key.get('source_epoch')) is int
            and key['source_epoch']==cpu_scope[1] and key.get('channel_id')==channel
            and type(key.get('source_sequence')) is int and key['source_sequence']>0
            and type(key.get('testcase_id')) is str and bool(key['testcase_id'])
            and (cpu_scope[2] is None or key['testcase_id']==cpu_scope[2]),
            'CPU transaction identity/scope')
        return key

    def response(row,address,write,value=None,channel='data'):
        scoped(row)
        key = key_check(row.get('transaction'),channel)
        _require(row.get('address')==address and row.get('raw_address')==address
            and row.get('aligned_address')==address and type(row.get('write')) is int
            and row['write']==int(write) and type(row.get('be')) is int and row['be']==15
            and type(row.get('error')) is int and row['error']==0
            and type(row.get('rdata')) is int and 0<=row['rdata']<1<<32
            and (value is None or row.get('wdata' if write else 'rdata')==value),
            'CPU response address/value/error/BE')
        at, rt = row.get('acceptance_tick'), row.get('response_tick')
        _require(type(at) is int and type(rt) is int and at<rt, 'CPU response chronology')
        capture(unique,row['kind'],cpu,lambda candidate:candidate.get('transaction')==key)
        if channel=='data':
            def acceptance():
                accepted=unique('data_accept',cpu,lambda candidate:candidate.get('transaction')==key)
                _require(all(accepted.get(k)==row.get(k) for k in
                    ('transaction','address','raw_address','aligned_address','write','be','wdata','acceptance_tick')),
                    'CPU accepted request/response join')
                sample=tick_sample(at,'pre')
                _require(accepted.get('producer_event_id')==sample.get('producer_event_id'),
                    'CPU acceptance producer identity')
            capture(acceptance)
        tag = 'i' if channel=='instr' else 'd'
        for tick,expected in ((at,{tag+'_req_valid':1,tag+'_req_ready':1,
                tag+'_req_addr':address,tag+'_req_write':int(write),tag+'_req_be':15,
                tag+'_req_wdata':row.get('wdata')}),
                (rt,{tag+'_rsp_valid':1,tag+'_rsp_ready':1,
                    tag+'_rsp_rdata':row['rdata'],tag+'_rsp_error':0})):
            sample = tick_sample(tick,'pre')
            backend = sample.get('outputs',{}).get('backend')
            _present(type(backend) is dict, 'CPU response native bus sample unavailable')
            _require(all(type(backend.get(k)) is int and backend[k]==v for k,v in expected.items()),
                'CPU response native handshake mismatch')
            if tick==rt:
                _require(row.get('producer_event_id')==sample.get('producer_event_id'),
                    'CPU response producer mismatch')
                producer=runner[sample['producer_event_id']]
                rsp_tag='instr' if channel=='instr' else 'data'
                for field,expected_value in ((rsp_tag+'_rsp_consumed',1),
                        (rsp_tag+'_rsp_source_epoch',key['source_epoch']),
                        (rsp_tag+'_rsp_source_sequence',key['source_sequence']),
                        (rsp_tag+'_rsp_rdata',row['rdata'])):
                    _present(field in producer['outputs'],'CPU response producer identity unavailable')
                    _require(type(producer['outputs'][field]) is int
                        and producer['outputs'][field]==expected_value,
                        'CPU response producer transaction identity')
        return key

    def commit(row,key,address,value):
        scoped(row)
        doc = row.get('commit_document')
        _require(type(doc) is dict and row.get('transaction')==key
            and doc.get('fullkey')==key and doc.get('memory_id')==contract['memory']['resource']['resource_id']
            and doc.get('byte_offset')==address-contract['memory']['resource']['base']
            and doc.get('width_bytes')==4 and doc.get('byte_enable')==15
            and doc.get('performed_effect') is True and doc.get('commit_status')=='complete',
            'CPU result commit identity/span/effect')
        unsigned = dict(doc)
        digest = unsigned.pop('commit_id',None)
        _require(digest==row.get('commit_id') and digest==sha256(_canonical(unsigned).encode()).hexdigest()
            and doc.get('payload_sha256')==sha256(_canonical(dict(op='write',address=address,
                value=value,width_bytes=4,byte_enable=15)).encode()).hexdigest(),
            'CPU result commit hash/value')
        cells = [dict(byte_offset=doc['byte_offset']+i,value=(value>>(8*i))&255,
            version=doc['version'],writer_kind='STORE',writer_event_id=str(TransactionKey(**key)))
            for i in range(4)]
        _require(doc.get('enabled_byte_cells')==cells, 'CPU result commit byte writers')
        return doc

    def store(row,address,value):
        _require(row.get('address')==address and row.get('value')==value
            and type(row.get('byte_enable')) is int and row['byte_enable']==15
            and row.get('width_bytes')==4,'CPU result store address/value/BE')
        key = key_check(row.get('transaction'))
        capture(unique,'memory_write',cpu,lambda candidate:candidate.get('transaction')==key)
        accept = capture(unique,'data_accept',cpu,lambda candidate:candidate.get('transaction')==key)
        rsp = unique('data_response',cpu,lambda candidate:candidate.get('transaction')==key)
        response(rsp,address,True,value)
        if accept is not None:
            _require(accept.get('address')==address and accept.get('write')==1
                and accept.get('wdata')==value and accept.get('be')==15
                and accept.get('acceptance_tick')==rsp.get('acceptance_tick'),
                'CPU result acceptance mismatch')
        doc = commit(unique('memory_write_commit',cpu,
            lambda candidate:candidate.get('transaction')==key),key,address,value)
        _require(all(row.get(field)==doc.get(field) for field in
            ('memory_id','generation','byte_offset','version')), 'CPU result store/commit join')
        return rsp

    output, delivery, status = selected['irq_output'], selected['irq_delivery'], selected['status']
    status_offset=contract['dma']['csr']['offsets']['control']
    status_address=contract['control']['base']+status_offset
    error = bool(raw_errors)
    if status is not None:
        capture(response,status,status_address,False)
        if type(status.get('rdata')) is int:
            error = bool(status['rdata'] & contract['dma']['csr']['status_error_mask'])
            capture(_require,error==bool(raw_errors),'actual ISR status/native fault branch mismatch')
            details['actual_status_word'] = status['rdata']
        def status_delivery():
            row = unique('mmio_delivery',cpu,lambda r:r.get('source_transaction')==status.get('transaction'))
            _require(row.get('device_id')==contract['control']['device_id']
                and row.get('address')==status_address and row.get('write') is False
                and row.get('read_value')==status.get('rdata'), 'ISR status control delivery mismatch')
            receipt=row.get('dma_control_receipt')
            _present(receipt is not None,'ISR status native control receipt unavailable')
            expected=dict(source_transaction=status['transaction'],address=status_address,
                offset=status_offset,write=False,value=0,byte_enable=15)
            _require(type(receipt) is dict and all(receipt.get(k)==v for k,v in expected.items()),
                'ISR status native control receipt transaction/span')
            context=receipt.get('delivery_context')
            _require(type(context) is dict and all(context.get(k)==v for k,v in dict(
                source_transaction=status['transaction'],device_id=contract['control']['device_id'],
                window_base=contract['control']['base'],window_size=contract['control']['size'],
                address=status_address,offset=status_offset,write=False,value=0,be=15).items()),
                'ISR status native control context')
            ticks=receipt.get('edge_ticks')
            _require(type(ticks) is list and len(ticks)>=3
                and all(type(t) is int and t>0 for t in ticks)
                and ticks==list(range(ticks[0],ticks[-1]+1)), 'ISR status control tick identity')
            edges=[]
            for tick in ticks:
                edge=unique('dma_edge',dma,lambda r,t=tick:r.get('tick')==t)
                edges.append(edge)
            ack=[e for e in edges if e.get('payload',{}).get('pre_backend',{}).get('swb_ack')==1]
            accepted=_control_accepted(edges)
            _require(len(ack)==1,'ISR status native control request/ACK cardinality')
            request=accepted['payload']['pre_backend'];answer=ack[0]['payload']['pre_backend']
            if _selected_dma(contract, side='control'):
                _require(type(request.get('swb_sel')) is int and request['swb_sel']==receipt['byte_enable'],
                    'ISR status native control SEL mismatch')
            _require(all(request.get(k)==v for k,v in dict(swb_cyc=1,swb_stb=1,
                swb_we=0,swb_adr=status_offset//4,swb_dat_w=0).items())
                and answer.get('swb_dat_r')==status['rdata']
                and accepted['tick']<ack[0]['tick']<edges[-1]['tick'],
                'ISR status actual native control response')
            for edge in edges:
                if edge['tick'] <= accepted['tick']:
                    pre=edge['payload']['pre_backend']
                    _require(all(pre.get(k)==v for k,v in dict(swb_cyc=1,swb_stb=1,
                        swb_we=0,swb_adr=status_offset//4,swb_dat_w=0).items()),
                        'ISR status held control request mismatch')
                    if _selected_dma(contract, side='control'):
                        _require(pre.get('swb_sel')==receipt['byte_enable'], 'ISR status held SEL mismatch')
            last=edges[-1]['payload']['pre_backend']
            _require(all(last.get(k)==0 for k in ('swb_cyc','swb_stb','swb_we','swb_ack')),
                'ISR status native control final idle')
            producer=runner.get(row.get('producer_event_id'))
            _present(producer is not None,'ISR status control producer unavailable')
            scoped(producer)
            _require(producer.get('component')==dma and 'kind' not in producer
                and producer.get('local_tick')==ticks[0]-1,'ISR status control producer identity')
        capture(status_delivery)

    if output is not None:
        def source():
            key = output.get('source_output_key')
            _require(type(key) is list and len(key)==4 and key[0]==dma
                and type(key[1]) is int and key[1]>=0 and key[2]==irq['producer_port']
                and type(key[3]) is int and key[3]>0,'DMA IRQ output key')
            if output.get('runner_event_id') is None and 'provenance' not in output:
                _require(output.get('source')==[dma,'irq'] and output.get('target')==[cpu,'irq']
                    and output.get('source_event_id')==output.get('producer_event_id'),
                    'derived IRQ source owner/reference')
            raw = selector(output.get('producer_event_id'),dma,'dma_edge')
            _require(raw.get('tick')==key[3] and raw.get('reset_epoch')==key[1]
                and type(raw.get('reset_epoch')) is int, 'DMA IRQ edge key/scope')
            if 'provenance' not in output:
                _present(dma_irq_runtime_name is not None,
                    'source-admitted DMA IRQ runtime name unavailable')
            runtime_name=(dma_irq_runtime_name if dma_irq_runtime_name is not None
                else irq['producer_port'])
            physical=raw.get('payload',{}).get('observations',{}).get('physical')
            _present(type(physical) is dict and runtime_name in physical,
                'admitted DMA IRQ physical observation unavailable')
            _require(type(physical[runtime_name]) is int and physical[runtime_name]==1,
                'DMA IRQ has no actual physical source')
            responses = [r for r in events if in_case(r) and r.get('component')==dma
                and r.get('kind')=='dma_edge' and type(r.get('response')) is dict]
            _present(bool(responses),'DMA final response unavailable')
            _require(all(type(r.get('tick')) is int and r['tick']<=raw['tick']
                and r['event_id']<=raw['event_id'] for r in responses),
                'DMA IRQ precedes final response')
            if any(r['event_id']==raw['event_id'] for r in responses):
                # A same-edge response is only ordered by the driver's
                # actual pre-response and post-IRQ physical observations.
                final_refs = attempt.get('write_responses')
                final = (selector(final_refs[-1],dma,'dma_edge')
                    if not error and type(final_refs) is list and final_refs else
                    raw_errors[-1] if error and raw_errors else None)
                payload = raw.get('payload', {}); samples = payload.get('samples')
                _require(final is not None and final.get('event_id')==raw['event_id']
                    and type(samples) is list and len(samples)==1
                    and raw.get('native_local_tick')==raw['tick']
                    and samples[0].get('local_tick')==raw['tick'],
                    'same-edge DMA final response native sample identity')
                pre=samples[0].get('pre',{}); post=samples[0].get('post',{})
                pre_backend=pre.get('backend',{}); pre_physical=pre.get('physical',{})
                post_physical=post.get('physical',{})
                _require(pre_backend==payload.get('pre_backend')
                    and post==payload.get('observations')
                    and type(pre_backend.get('mwb_ack')) is int and pre_backend['mwb_ack']==1
                    and pre_backend.get('mwb_err')==raw['response'].get('error')
                    and type(pre_physical.get(runtime_name)) is int and pre_physical[runtime_name]==0
                    and type(post_physical.get(runtime_name)) is int and post_physical[runtime_name]==1,
                    'same-edge DMA response/IRQ physical phase mismatch')
        capture(source)
    if delivery is not None and irq.get('delivery_policy') == 'level':
        def level_delivery():
            from .saved_irq_group import rebuild_group
            _require(type(delivery.get('start_local_tick')) is int and delivery['start_local_tick'] >= 0
                and delivery.get('end_local_tick') is None and delivery.get('target_component') == cpu
                and delivery.get('target_epoch') == cpu_scope[1] and delivery.get('delivery_id') == irq['delivery_id']
                and delivery.get('source_event_id') == attempt.get('irq_output')
                and output is not None and delivery.get('source_output_key') == output.get('source_output_key'),
                'level IRQ delivery/source scope')
            group = rebuild_group(contract, binding, provider['input_port'])
            _present(group is not None, 'level IRQ group unavailable')
            details['irq_delivery_group'] = group.document()
            result = _saved_level_irq_evidence(contract, group, events, runner, cpu, dma, cpu_scope[1],
                case, take, delivery, dma_irq_runtime_name, cpu_scope[2])
            key_check(runner[result['clear_accept_event_id']]['transaction'])
            high = unique('cpu_external_irq_sample', cpu, lambda r:r.get('local_tick') == take.get('local_tick'))
            native_scope(high)
            for phase in ('pre', 'post'):
                _require(physical_view(tick_sample(take['local_tick'], phase)).get(provider['input_port']) == 1,
                    'level IRQ high physical input mismatch')
            low = runner[result['low_sample_event_id']]
            native_scope(low)
            for phase in ('pre', 'post'):
                _require(physical_view(tick_sample(low['local_tick'], phase)).get(provider['input_port']) == 0,
                    'level IRQ low physical input mismatch')
            native_scope(take)
            _require(take.get('local_tick') >= delivery['start_local_tick'], 'level take precedes delivery')
            if limited:
                _require(take.get('observation_contract') == provider, 'limited IRQ take provider mismatch')
                limited_take_probes()
            else:
                raw = physical_view(tick_sample(take['local_tick'],'pre'))
                _require(raw.get('probe_irq_taken_pre') == 1 and raw.get('probe_irq_masked_pre') == 0,
                    'IRQ take has no physical decision')
            details['level_irq_clear'] = result
        capture(level_delivery)
    if delivery is not None and irq.get('delivery_policy') != 'level':
        group_state={}
        def window():
            start,end = delivery.get('start_local_tick'),delivery.get('end_local_tick')
            _require(type(start) is int and type(end) is int and 0<=start<end<1<<64
                and end==start+16 and delivery.get('target_component')==cpu
                and type(delivery.get('target_epoch')) is int and delivery['target_epoch']==cpu_scope[1]
                and delivery.get('delivery_id')==irq['delivery_id']
                and delivery.get('source_event_id')==attempt.get('irq_output'), 'IRQ delivery/window/scope')
            if output is not None:
                _require(delivery.get('source_output_key')==output.get('source_output_key')
                    and attempt.get('irq_output')<attempt.get('irq_delivery'), 'IRQ delivery/source join')
            from .saved_irq_group import rebuild_group
            group_state['group']=rebuild_group(contract,binding,provider['input_port'])
            bound=[]
            for sample in events:
                if sample.get('kind')!='cpu_external_irq_sample':continue
                context=sample.get('input_context')
                linked=(sample.get('binding_delivery_event_id')==attempt.get('irq_delivery')
                    or type(context) is dict and context.get('binding_delivery_event_id')==attempt.get('irq_delivery'))
                if not linked:continue
                scoped(sample)
                _require(sample.get('component')==cpu and sample.get('reset_epoch')==cpu_scope[1]
                    and sample.get('source_output_key')==delivery.get('source_output_key'),
                    'derived IRQ window crossed raw scope/source')
                bound.append(sample)
            ticks=[sample.get('local_tick') for sample in bound]
            _require(all(type(tick) is int for tick in ticks)
                and len(ticks)==len(set(ticks)),'duplicate/malformed bound IRQ tick')
            _require(len(ticks)<=16,'extra bound IRQ input samples')
            if group_state['group'] is not None:
                details['irq_delivery_group']=group_state['group'].document()
            elif len(ticks)==16:
                observed_start=min(ticks)
                _require(sorted(ticks)==list(range(observed_start,observed_start+16))
                    and start==observed_start and end==observed_start+16,
                    'derived IRQ window contradicts raw sample span')
                details['irq_window']=dict(start_local_tick=observed_start,
                    end_local_tick=observed_start+16)
            else:
                capture(_present,False,'complete raw bound IRQ sample span unavailable')
            return start,end
        interval = capture(window)
        if interval is not None:
            start,end = interval
            def input_sample(row,tick):
                native_scope(row)
                _require(row.get('observation_contract')==provider,'IRQ input provider mismatch')
                active=int(tick<end)
                group=group_state.get('group')
                unique_dma=bool(active)
                if group is not None:
                    from .saved_irq_group import frame_for_sample
                    frame=frame_for_sample(group,row,events,runner,dma_runtime_name=dma_irq_runtime_name)
                    _require(frame['members'][0]['value']==active,'group DMA pulse/window mismatch')
                    unique_dma=active and frame['unique_source']==group.members[0].source_id
                    active=frame['value']
                _require(all(type(row.get(n)) is int and row[n]==active for n in
                    ('expected_input','actual_pre_input','actual_post_input')),
                    'IRQ input fixed window/expiry mismatch')
                if unique_dma:
                    context=row.get('input_context')
                    _require(row.get('binding_delivery_event_id')==attempt.get('irq_delivery')
                        and row.get('source_output_key')==delivery.get('source_output_key')
                        and type(context) is dict and context.get('binding_delivery_event_id')==attempt.get('irq_delivery')
                        and context.get('source_output_key')==delivery.get('source_output_key')
                        and context.get('target_component')==cpu and context.get('target_epoch')==cpu_scope[1]
                        and context.get('expected_input')==1,'IRQ input delivery/source context')
                else:
                    _require(row.get('input_context') is None
                        and row.get('binding_delivery_event_id') is None
                        and row.get('source_output_key') is None,'IRQ expiry retains active context')
                for phase in ('pre','post'):
                    sample=tick_sample(tick,phase)
                    physical=physical_view(sample)
                    _require(physical.get(provider['input_port'])==active,'IRQ physical input mismatch')
                details['irq_input_samples'].append(row['event_id'])
                if tick==end:details['irq_expiry_sample']=row['event_id']
            for tick in range(start,end+1):
                row=capture(unique,'cpu_external_irq_sample',cpu,lambda r,t=tick:r.get('local_tick')==t)
                if row is not None:capture(input_sample,row,tick)
            if take is not None:
                def taken():
                    native_scope(take)
                    group=group_state.get('group')
                    if group is not None:
                        from .saved_irq_group import frame_for_sample
                        sample=unique('cpu_external_irq_sample',cpu,lambda r:r.get('local_tick')==take.get('local_tick'))
                        frame=frame_for_sample(group,sample,events,runner,dma_runtime_name=dma_irq_runtime_name)
                        _require(frame['unique_source']==group.members[0].source_id
                            and frame.get('native_take_event_id')==take['event_id']
                            and frame.get('take_key')==take.get('take_key'),'group take is not uniquely DMA attributed')
                    take_fields=(('actual_pre_input',1),('actual_post_input',1),
                        ('irq_taken_pre',1)) if limited else (
                        ('actual_pre_input',1),('actual_post_input',1),
                        ('irq_masked_pre',0),('irq_taken_pre',1))
                    _require(type(take.get('local_tick')) is int and start<=take['local_tick']<end
                        and take.get('binding_delivery_event_id')==attempt.get('irq_delivery')
                        and take.get('source_output_key')==delivery.get('source_output_key')
                        and take.get('take_key')[:2]==[cpu,cpu_scope[1]]
                        and type(take['take_key'][2]) is int and take['take_key'][2]>0
                        and all(type(take.get(k)) is int and take[k]==v for k,v in take_fields),
                        'IRQ delivery/native take mismatch')
                    if limited:
                        # The real ack/id/entry-PC decision of this CPU; no
                        # rvfi_intr, debug or halt field is consulted.
                        _require(take.get('observation_contract')==provider,
                            'limited IRQ take provider mismatch')
                        limited_take_probes()
                    else:
                        raw=physical_view(tick_sample(take['local_tick'],'pre'))
                        _require(raw.get('probe_irq_taken_pre')==1 and raw.get('probe_irq_masked_pre')==0,
                            'IRQ take has no physical decision')
                capture(taken)

    result_base=p['result_base']+24*attempt['case_index']
    if selected['status_store'] is not None and status is not None:
        capture(store,selected['status_store'],result_base,status.get('rdata'))
    terminal_response = (capture(store,selected['terminal'],result_base+20,2 if error else 1)
        if selected['terminal'] is not None else None)
    for section,kind in (('readbacks','data_response'),('results','memory_write')):
        refs=attempt.get(section)
        capture(_require,type(refs) is list and len(refs)==(0 if error else 4),
            'error/success '+section+' branch cardinality')
        if type(refs) is list:
            capture(lambda:_require(all(type(ref) is int and ref>0 or ref is None for ref in refs)
                and len(set(refs))==len(refs),section+' duplicate/invalid references'))
    if error:
        for row in events:
            if not in_case(row) or row.get('component')!=cpu:continue
            if (row.get('kind')=='data_response' and row.get('write')==0
                    and type(row.get('address')) is int and p['destination_address']<=row['address']<p['destination_address']+16
                    or row.get('kind')=='memory_write' and type(row.get('address')) is int
                    and result_base+4<=row['address']<result_base+20):
                capture(_require,False,'error ISR has raw success readback/result')
    else:
        for index,word in enumerate(words):
            def result_word():
                reads=attempt.get('readbacks',[]);results=attempt.get('results',[])
                read=capture(selector,reads[index] if index<len(reads) else None,cpu,'data_response')
                raw_read=capture(unique,'data_response',cpu,lambda row:
                    row.get('address')==p['destination_address']+4*index and row.get('write')==0)
                if read is None:read=raw_read
                _present(read is not None,'ISR readback unavailable')
                response(read,p['destination_address']+4*index,False,word)
                commits=attempt.get('word_commits',[])
                dest=selector(commits[index] if index<len(commits) else None,dma,'memory_write_commit')
                doc=dest['commit_document'];snapshot=read.get('snapshot',{})
                _require(snapshot.get('versions')==[doc['version']]*4
                    and snapshot.get('writer_event_ids')==[str(TransactionKey(**doc['fullkey']))]*4
                    and snapshot.get('writer_kinds')==['STORE']*4,'ISR readback destination writer/version join')
                result=capture(selector,results[index] if index<len(results) else None,cpu,'memory_write')
                raw_result=capture(unique,'memory_write',cpu,lambda row:
                    row.get('address')==result_base+4+4*index)
                if result is None:result=raw_result
                _present(result is not None,'ISR result store unavailable')
                rsp=store(result,result_base+4+4*index,word)
                _require(read['response_tick']<rsp['acceptance_tick']
                    and (take is None or take['local_tick']<read['acceptance_tick'])
                    and (returned is None or rsp['response_tick']<returned['local_tick']),
                    'ISR readback/result chronology')
                details['results'].append(dict(word_index=index,read_transaction=read['transaction'],
                    result_transaction=result['transaction']))
            capture(result_word)

    if take is not None and returned is not None:
        def raw_retirement_leaf(row):
            physical=physical_view(row)
            _require(not native_irq_retirement_diverted(provider, physical),
                'raw retirement debug/halt diversion')
            _require(type(physical.get('rvfi_valid')) is int and physical['rvfi_valid'] in (0,1),
                'raw retirement valid field type')
            if physical['rvfi_valid']:
                _require(type(physical.get('rvfi_trap')) is int and physical['rvfi_trap']==0
                    and type(physical.get('rvfi_mode')) is int and physical['rvfi_mode']==3
                    and type(physical.get('rvfi_intr')) is int and physical['rvfi_intr'] in (0,1)
                    and type(physical.get('rvfi_order')) is int and physical['rvfi_order']>0,
                    'raw retirement trap/privilege/order')
        low,high=take.get('local_tick'),returned.get('successor_local_tick')
        if type(low) is int and type(high) is int:
            for row in events:
                if (in_case(row) and row.get('component')==cpu
                        and row.get('kind')=='local_tick_sample' and row.get('phase')=='post'
                        and type(row.get('local_tick')) is int and low<=row['local_tick']<=high):
                    capture(limited_retirement_leaf if limited
                        else raw_retirement_leaf,row)
    if returned is not None:
        def limited_retirement_chain():
            """Rebuild take/entry/MRET/successor from assigned RVFI and probes.

            Per-retirement trap/intr/privilege, MRET ``pc_wdata``, memory
            fields and the passive serial token are not driven by this CPU.
            They are never read, defaulted or inferred; an archived document
            that claims one is refused as fabricated evidence.
            """
            observed=set(retirement['fields'])
            unobserved=set(retirement['unobserved'])
            acceptance=retirement['acceptance']
            _require(returned.get('schema_version')=='native_f6_isr_return.v1'
                and returned.get('case_id')==case['case_id']
                and returned.get('case_index')==attempt['case_index']
                and returned.get('execution_binding_sha256')==binding.get('binding_sha256')
                and returned.get('component',cpu)==cpu,
                'limited ISR return case/binding/schema')
            _present(take is not None,'limited ISR return native take unavailable')
            # Fabricated full-RVFI authority is refused before any join reads
            # a field, with the exact claiming document named.
            claims=(_limited_document_claim_reasons(returned,observed,unobserved,
                    where='saved ISR return document')
                + _limited_document_claim_reasons(take,observed,unobserved,
                    where='saved IRQ take event')
                + [reason for row in events
                    if in_case(row) and row.get('component')==cpu
                    for reason in _limited_document_claim_reasons(row,observed,
                        unobserved,where='archived CPU event '+str(row.get('event_id')))]
                + _nested_internal_version_reasons(attempt))
            _require(not claims,claims[0] if claims else '')
            if 'retirement_authority' in returned:
                _require(returned['retirement_authority']==retirement['authority'],
                    'limited saved retirement authority mismatch')
            if 'retirement_diversion_scope' in returned:
                _require(returned['retirement_diversion_scope']=='unobservable',
                    'limited saved retirement diversion scope mismatch')
            if 'decision_acceptance' in returned:
                _require(returned['decision_acceptance']==acceptance,
                    'limited saved decision acceptance differs from the contract')
            if 'unobserved_fields' in returned:
                declared_unobserved=(_observed_retirement_names(
                    returned['unobserved_fields']) or [])
                _require(set(declared_unobserved)==unobserved,
                    'limited saved unobserved field declaration mismatch')
            _require(returned.get('irq_take_key')==take.get('take_key')
                and returned.get('take_receipt_id')==native_scope(take),
                'limited ISR return/take identity')

            def required(field):
                _present(type(field) is str and returned.get(field) is not None,
                    'limited saved ISR return field unavailable: '+str(field))
                return returned[field]

            entry_id=required('handler_entry_receipt_id')
            ret_id=required('return_receipt_id')
            successor_id=required('successor_receipt_id')
            _require(all(type(rid) is dict and rid.get('execution')==cpu_scope[0]
                and type(rid.get('sequence')) is int and rid['sequence']>0
                for rid in (entry_id,ret_id,successor_id)),
                'limited ISR return receipt identity')
            mret_tick=required('local_tick');successor_tick=required('successor_local_tick')
            _require(type(mret_tick) is int and type(successor_tick) is int
                and take['local_tick']<mret_tick<successor_tick
                and take['receipt_id']['sequence']<=entry_id['sequence']<ret_id['sequence']<successor_id['sequence'],
                'limited ISR return receipt chronology')
            resets=[r for r in events if in_case(r) and r.get('component')==cpu
                and r.get('kind') in ('cpu_native_startup','component_reset')
                and type(r.get('local_tick')) is int
                and take['local_tick']<=r['local_tick']<=successor_tick]
            _require(not resets,'limited ISR intervening reset')
            # A real non-IRQ exception redirect between the take and the
            # successor is actual diversion evidence and refuses the return.
            redirects=[r for r in events if in_case(r) and r.get('component')==cpu
                and r.get('kind')=='cpu_native_exception_redirect'
                and type(r.get('local_tick')) is int
                and take['local_tick']<=r['local_tick']<=successor_tick]
            _require(not redirects,'limited ISR intervening native exception redirect')
            entry_pc=limited_take_probes()
            valid=[];previous_sequence=None
            for tick in range(take['local_tick'],successor_tick+1):
                sample=tick_sample(tick,'post')
                receipt=native_scope(unique('cpu_external_irq_sample',cpu,
                    lambda row,t=tick:row.get('local_tick')==t))
                _require(previous_sequence is None or receipt['sequence']==previous_sequence+1,
                    'limited ISR native receipt discontinuity')
                previous_sequence=receipt['sequence']
                physical=physical_view(sample)
                _present(type(physical.get('rvfi_valid')) is int,
                    'limited ISR retirement valid field unavailable')
                _require(physical['rvfi_valid'] in (0,1),
                    'limited ISR retirement valid field type')
                if tick>take['local_tick']:
                    pre=physical_view(tick_sample(tick,'pre'))
                    _require(limited_decision_probe(pre,'irq_taken_pre',
                            retirement['probes']['irq_taken_pre'])==0,
                        'limited ISR intervening native take')
                if physical.get('rvfi_valid')==1:
                    _present(all(type(physical.get(name)) is int for name in
                            ('rvfi_order','rvfi_insn','rvfi_pc_rdata')),
                        'limited ISR retirement field unavailable')
                    _require(physical['rvfi_order']>0
                        and 0<=physical['rvfi_insn']<1<<32
                        and 0<=physical['rvfi_pc_rdata']<1<<32,
                        'limited ISR retirement field/width')
                    if valid:_require(physical['rvfi_order']==valid[-1][2]['rvfi_order']+1,
                        'limited ISR retirement order discontinuity')
                    valid.append((tick,receipt,physical))
            entries=[r for r in valid if r[2].get('rvfi_pc_rdata')==entry_pc]
            _require(len(entries)==1,'limited ISR entry retirement missing/duplicate')
            entry_tick,entry_receipt,entry=entries[0]
            _require(entry['rvfi_insn']==int.from_bytes(
                    fw.initial_images[p['isr_address']][:4],'little'),
                'limited ISR entry instruction differs from the declared handler word')
            _require(entry_receipt==entry_id
                and entry['rvfi_order']==returned.get('handler_entry_rvfi_order')
                and returned.get('handler_entry_pc_rdata')==entry_pc,
                'limited ISR entry/take identity')
            # A saved entry blob may restate only the raw entry retirement.
            entry_blob=returned.get('entry')
            if type(entry_blob) is dict:
                for field,value in dict(pc=entry_pc,insn=entry['rvfi_insn'],
                        order=entry['rvfi_order'],local_tick=entry_tick,
                        receipt_id=entry_receipt).items():
                    if field in entry_blob:
                        _require(entry_blob[field]==value,
                            'limited saved handler entry evidence differs from raw retirements')
            dispatch=fw.document().get('irq_dispatch')
            if dispatch is not None:
                from .shared_irq_retirement import validate_dma_dispatch_retirements
                count=len(dispatch['stages']['dma_dispatch_path'])+1
                actual=[dict(pc=physical['rvfi_pc_rdata'],instruction=physical['rvfi_insn'],
                    rvfi_order=physical['rvfi_order'],receipt_id=receipt)
                    for tick,receipt,physical in valid if tick>=entry_tick][:count]
                validate_dma_dispatch_retirements(dispatch,
                    fw.initial_images[p['isr_address']],actual)
                declared=dict(dispatcher_stage_sha256=dispatch['identity_sha256'],
                    dma_stage_address=dispatch['stages']['dma']['address'],
                    dispatcher_retirements=actual)
                for field in declared:
                    if field in returned:
                        _require(returned[field]==declared[field],
                            'limited saved dispatcher evidence differs from raw retirements')
            mrets=[r for r in valid if r[2].get('rvfi_insn')==0x30200073]
            _require(len(mrets)==1,'limited duplicate/missing raw MRET')
            actual_tick,actual_receipt,mret=mrets[0]
            _require(actual_tick==mret_tick and actual_receipt==ret_id
                and type(mret['rvfi_pc_rdata']) is int
                and mret['rvfi_pc_rdata']==fw.document()['isr']['mret_addresses'][int(error)]
                and mret['rvfi_pc_rdata']==returned.get('pc_rdata')
                and mret['rvfi_order']==returned.get('rvfi_order')
                and returned.get('instruction')==0x30200073
                and entry_tick<mret_tick,
                'limited raw MRET site/branch/order mismatch')
            mret_blob=returned.get('mret')
            if type(mret_blob) is dict:
                for field,value in dict(pc=mret['rvfi_pc_rdata'],insn=0x30200073,
                        order=mret['rvfi_order'],local_tick=mret_tick,
                        receipt_id=ret_id).items():
                    if field in mret_blob:
                        _require(mret_blob[field]==value,
                            'limited saved MRET evidence differs from raw retirements')
            pre_edge=returned.get('take_pre_edge_observation')
            if type(pre_edge) is dict:
                expected=dict(source_id=acceptance['source_id'],
                    **{name:take.get(name) for name in
                        ('irq_taken_pre','irq_redirect_pre','irq_redirect_cause')})
                for role in ('ack_probe','id_probe','entry_pc_probe'):
                    if role in acceptance:
                        expected[role]=take.get(acceptance[role])
                for field,value in expected.items():
                    if field in pre_edge:
                        _require(pre_edge[field]==value,
                            'limited saved take pre-edge observation differs from the raw take')
            after=[r for r in valid if r[0]>mret_tick]
            _require(len(after)==1,'limited first valid post-MRET retirement mismatch')
            tick,receipt,successor=after[0]
            pc=successor['rvfi_pc_rdata'];insn=successor['rvfi_insn']
            slot=p['slot_base']+p['slot_bytes']*indices['slot_index']
            from myfuzz.scenario.irq_return_successor import validate_return_successor
            try:
                validate_return_successor(
                    dict(order=mret['rvfi_order'],local_tick=mret_tick,receipt_id=ret_id),
                    dict(order=successor['rvfi_order'],local_tick=tick,receipt_id=receipt,
                        pc_rdata=pc),
                    start=slot,end=slot+136,authority=retirement['authority'])
            except ValueError as failure:
                raise _EvidenceIssue('failed',
                    'limited first post-MRET successor is not the current dynamic return'
                    ) from failure
            _require(tick==successor_tick and receipt==successor_id
                and successor['rvfi_order']==mret['rvfi_order']+1==returned.get('successor_rvfi_order')
                and pc==returned.get('successor_pc_rdata')==returned.get('return_target')
                and insn==returned.get('successor_instruction') and type(pc) is int and pc%4==0
                and slot<=pc<slot+136,
                'limited first post-MRET successor identity/scope')
            data=(bytes.fromhex(attempt['prefix_hex'])[pc-slot:pc-slot+4] if pc<slot+128
                else fw.initial_images[slot+128][pc-slot-128:pc-slot-124])
            _require(len(data)==4 and int.from_bytes(data,'little')==insn,
                'limited successor instruction differs from canonical prefix/preload')
            response_document=returned.get('successor_instruction_response')
            _present(type(response_document) is dict
                and type(response_document.get('transaction')) is dict,
                'limited successor instruction response transaction unavailable')
            response_transaction=response_document['transaction']
            rsp=unique('instr_response',cpu,lambda row:
                row.get('transaction')==response_transaction)
            response(rsp,pc,False,insn,'instr')
            response_receipt=native_scope(unique('cpu_external_irq_sample',cpu,
                lambda row:row.get('local_tick')==rsp['response_tick']))
            _require(response_receipt==returned.get('successor_instruction_response_receipt_id')
                and response_receipt['sequence']<=successor_id['sequence'],
                'limited successor instruction response receipt join')
            raw_response={k:v for k,v in rsp.items() if k not in
                ('event_id','runner_event_id','provenance','producer_event_id')}
            _require(raw_response==returned.get('successor_instruction_response'),
                'limited successor instruction response differs from raw Runner row')
            mret_input=unique('cpu_external_irq_sample',cpu,
                lambda row:row.get('local_tick')==mret_tick)
            expected_metadata=dict(phase='post',
                isr_sha256=fw.document()['isr']['sha256'],
                return_receipt_ticks=mret_input.get('receipt_ticks'))
            if 'provenance' not in returned:
                # Production issuer summaries must state every observable
                # derived field; only the omitted unobservable ones are absent.
                _present(type(expected_metadata['return_receipt_ticks']) is dict,
                    'limited MRET parsed receipt tick scope unavailable')
                for field,value in expected_metadata.items():
                    _require(returned.get(field)==value,
                        'limited saved ISR return differs from raw observations: '+field)
            else:
                for field,value in expected_metadata.items():
                    if field in returned:
                        _require(returned[field]==value,
                            'limited saved ISR return differs from raw observations: '+field)
            receipt_ticks=expected_metadata['return_receipt_ticks']
            if type(receipt_ticks) is dict:
                _require(all(type(receipt_ticks.get(field)) is int
                        for field in ('tick_before','tick_after','new_ticks','local_tick_base'))
                    and receipt_ticks['new_ticks']==1
                    and receipt_ticks['tick_after']==receipt_ticks['tick_before']+1
                    and receipt_ticks['tick_after']+receipt_ticks['local_tick_base']==mret_tick,
                    'limited MRET parsed receipt tick identity')
            if status is not None:_require(take['local_tick']<status['acceptance_tick']<mret_tick,
                'limited ISR status chronology')
            if terminal_response is not None:_require(terminal_response['response_tick']<mret_tick,
                'limited terminal store/MRET chronology')
            if delivery is not None:
                if irq.get('delivery_policy') == 'level':
                    low = details.get('level_irq_clear')
                    _present(low is not None, 'level IRQ clear evidence unavailable before MRET')
                    _require(low['low_local_tick'] < mret_tick, 'limited MRET precedes observed IRQ low')
                else:
                    _require(delivery['end_local_tick'] < mret_tick, 'limited MRET precedes IRQ expiry')
            source_label=returned.get('return_target_source')
            if source_label is not None:
                _require(type(source_label) is str and 'pc_wdata' not in source_label,
                    'limited return target cannot rest on unobserved pc_wdata')
            details.update(return_target=pc,
                return_target_source='first_subsequent_valid_retirement_pc',
                return_target_authority='inferred_architectural_successor_after_MRET',
                entry_pc=entry_pc,mret_pc=mret['rvfi_pc_rdata'],
                mret_rvfi_order=mret['rvfi_order'],
                successor_rvfi_order=successor['rvfi_order'])
        def retirement_chain():
            _require(returned.get('case_id')==case['case_id'] and returned.get('case_index')==attempt['case_index']
                and returned.get('execution_binding_sha256')==binding.get('binding_sha256')
                and returned.get('schema_version')=='native_f6_isr_return.v1', 'ISR return case/binding/schema')
            _present(take is not None,'ISR return native take unavailable')
            _require(returned.get('irq_take_key')==take.get('take_key')
                and returned.get('take_receipt_id')==native_scope(take), 'ISR return/take identity')
            entry_id=returned['handler_entry_receipt_id'];ret_id=returned['return_receipt_id']
            successor_id=returned['successor_receipt_id']
            _require(all(type(rid) is dict and rid.get('execution')==cpu_scope[0]
                and type(rid.get('sequence')) is int and rid['sequence']>0
                for rid in (entry_id,ret_id,successor_id)), 'ISR return receipt identity')
            mret_tick,successor_tick=returned['local_tick'],returned['successor_local_tick']
            _require(type(mret_tick) is int and type(successor_tick) is int
                and take['local_tick']<mret_tick<successor_tick
                and take['receipt_id']['sequence']<=entry_id['sequence']<ret_id['sequence']<successor_id['sequence'],
                'ISR return receipt chronology')
            resets=[r for r in events if in_case(r) and r.get('component')==cpu
                and r.get('kind') in ('cpu_native_startup','component_reset')
                and type(r.get('local_tick')) is int
                and take['local_tick']<=r['local_tick']<=successor_tick]
            _require(not resets,'ISR intervening reset')
            valid=[];previous_sequence=None
            for tick in range(take['local_tick'],successor_tick+1):
                sample=tick_sample(tick,'post')
                # Runner's raw sample must retain the parsed command identity;
                # gaps cannot be filled from an exported return certificate.
                receipt=native_scope(unique('cpu_external_irq_sample',cpu,
                    lambda row,t=tick:row.get('local_tick')==t))
                _require(previous_sequence is None or receipt['sequence']==previous_sequence+1,
                    'ISR native receipt discontinuity')
                previous_sequence=receipt['sequence']
                physical=physical_view(sample)
                _require(not native_irq_retirement_diverted(provider, physical),
                    'ISR debug/halt diversion')
                if tick>take['local_tick']:
                    pre=physical_view(tick_sample(tick,'pre'))
                    _require(pre.get('probe_irq_taken_pre')==0,'ISR intervening native take')
                if physical.get('rvfi_valid')==1:
                    _require(physical.get('rvfi_trap')==0 and physical.get('rvfi_mode')==3
                        and type(physical.get('rvfi_order')) is int and physical['rvfi_order']>0,
                        'ISR invalid retirement/trap/privilege')
                    if valid:_require(physical['rvfi_order']==valid[-1][2]['rvfi_order']+1,
                        'ISR retirement order discontinuity')
                    valid.append((tick,receipt,physical))
            entries=[r for r in valid if r[2].get('rvfi_intr')==1
                or r[2].get('rvfi_pc_rdata')==p['isr_address']]
            _require(len(entries)==1,'ISR entry missing/duplicate')
            entry_tick,entry_receipt,entry=entries[0]
            decision=physical_view(tick_sample(take['local_tick'],'pre')).get('irq_decision_serial')
            _require(type(decision) is int and decision>0
                and take.get('irq_serial_observation',{}).get('decision',{}).get('value')==decision
                and take.get('irq_serial_observation',{}).get('decision',{}).get('status')=='observed'
                and entry.get('irq_retirement_serial')==decision and entry.get('rvfi_intr')==1
                and entry.get('rvfi_pc_rdata')==p['isr_address']
                and entry.get('rvfi_insn')==int.from_bytes(fw.initial_images[p['isr_address']][:4],'little')
                and entry_receipt==entry_id and entry['rvfi_order']==returned['handler_entry_rvfi_order']
                and returned['handler_entry_pc_rdata']==p['isr_address'], 'ISR entry/take serial join')
            dispatch=fw.document().get('irq_dispatch')
            if dispatch is not None:
                from .shared_irq_retirement import validate_dma_dispatch_retirements
                count=len(dispatch['stages']['dma_dispatch_path'])+1
                actual=[dict(pc=physical['rvfi_pc_rdata'],instruction=physical['rvfi_insn'],
                    rvfi_order=physical['rvfi_order'],receipt_id=receipt)
                    for tick,receipt,physical in valid if tick>=entry_tick][:count]
                validate_dma_dispatch_retirements(dispatch,fw.initial_images[p['isr_address']],actual)
                _require(returned.get('dispatcher_stage_sha256')==dispatch['identity_sha256']
                    and returned.get('dma_stage_address')==dispatch['stages']['dma']['address']
                    and returned.get('dispatcher_retirements')==actual,
                    'ISR saved dispatcher/actual DMA retirement mismatch')
            mrets=[r for r in valid if r[2].get('rvfi_insn')==0x30200073]
            _require(len(mrets)==1,'duplicate/missing raw MRET')
            actual_tick,actual_receipt,mret=mrets[0]
            _require(actual_tick==mret_tick and actual_receipt==ret_id
                and mret['rvfi_pc_rdata']==fw.document()['isr']['mret_addresses'][int(error)]
                and mret['rvfi_pc_rdata']==returned.get('pc_rdata')
                and mret.get('rvfi_pc_wdata')==returned.get('pc_wdata')
                and mret['rvfi_order']==returned.get('rvfi_order')
                and returned.get('instruction')==0x30200073
                and mret.get('irq_retirement_serial')==0
                and mret.get('rvfi_intr')==0 and entry_tick<mret_tick,
                'raw MRET site/branch/order mismatch')
            after=[r for r in valid if r[0]>mret_tick]
            _require(len(after)==1,'first valid post-MRET retirement mismatch')
            tick,receipt,successor=after[0]
            pc=successor.get('rvfi_pc_rdata');insn=successor.get('rvfi_insn')
            slot=p['slot_base']+p['slot_bytes']*indices['slot_index']
            _require(tick==successor_tick and receipt==successor_id
                and successor.get('rvfi_intr')==0 and successor.get('irq_retirement_serial')==0
                and successor['rvfi_order']==mret['rvfi_order']+1==returned.get('successor_rvfi_order')
                and pc==returned.get('successor_pc_rdata')==returned.get('return_target')
                and insn==returned.get('successor_instruction') and type(pc) is int and pc%4==0
                and slot<=pc<slot+136,'first valid post-MRET successor identity/scope')
            data=(bytes.fromhex(attempt['prefix_hex'])[pc-slot:pc-slot+4] if pc<slot+128
                else fw.initial_images[slot+128][pc-slot-128:pc-slot-124])
            _require(len(data)==4 and int.from_bytes(data,'little')==insn,
                'successor instruction differs from canonical prefix/preload')
            response_document=returned.get('successor_instruction_response')
            _present(type(response_document) is dict
                and type(response_document.get('transaction')) is dict,
                'successor instruction response transaction unavailable')
            response_transaction=response_document['transaction']
            rsp=unique('instr_response',cpu,lambda row:
                row.get('transaction')==response_transaction)
            response(rsp,pc,False,insn,'instr')
            response_receipt=native_scope(unique('cpu_external_irq_sample',cpu,
                lambda row:row.get('local_tick')==rsp['response_tick']))
            _require(response_receipt==returned.get('successor_instruction_response_receipt_id')
                and response_receipt['sequence']<=successor_id['sequence'],
                'successor instruction response receipt join')
            raw_response={k:v for k,v in rsp.items() if k not in
                ('event_id','runner_event_id','provenance','producer_event_id')}
            _require(raw_response==returned.get('successor_instruction_response'),
                'successor instruction response differs from raw Runner row')
            if 'provenance' not in returned:
                def serial(physical):
                    return native_irq_serial_observation(provider, sampling='post_rising',
                        decision_phase='post',retirement_phase='post',
                        decision_value=physical.get('irq_decision_serial'),
                        retirement_value=physical.get('irq_retirement_serial'))
                mret_input=unique('cpu_external_irq_sample',cpu,
                    lambda row:row.get('local_tick')==mret_tick)
                expected_metadata=dict(phase='post',isr_sha256=fw.document()['isr']['sha256'],
                    take_irq_serial_observation=take.get('irq_serial_observation'),
                    handler_entry_irq_serial_observation=serial(entry),
                    irq_serial_observation=serial(mret),
                    successor_irq_serial_observation=serial(successor),
                    return_receipt_ticks=mret_input.get('receipt_ticks'),
                    return_target_source='first_subsequent_valid_RVFI_pc_rdata_with_instruction_response',
                    return_target_authority='inferred_architectural_successor_after_MRET')
                _present(expected_metadata['return_receipt_ticks'] is not None,
                    'MRET parsed receipt tick scope unavailable')
                _require(all(returned.get(field)==value for field,value in expected_metadata.items()),
                    'derived ISR return differs from raw provider observations')
                receipt_ticks=expected_metadata['return_receipt_ticks']
                _require(type(receipt_ticks) is dict and all(type(receipt_ticks.get(field)) is int
                    for field in ('tick_before','tick_after','new_ticks','local_tick_base'))
                    and receipt_ticks['new_ticks']==1
                    and receipt_ticks['tick_after']==receipt_ticks['tick_before']+1
                    and receipt_ticks['tick_after']+receipt_ticks['local_tick_base']==mret_tick,
                    'MRET parsed receipt tick identity')
            if status is not None:_require(take['local_tick']<status['acceptance_tick']<mret_tick,
                'ISR status chronology')
            if terminal_response is not None:_require(terminal_response['response_tick']<mret_tick,
                'terminal store/MRET chronology')
            if delivery is not None:
                if irq.get('delivery_policy') == 'level':
                    low = details.get('level_irq_clear')
                    _present(low is not None, 'level IRQ clear evidence unavailable before MRET')
                    _require(low['low_local_tick'] < mret_tick, 'MRET precedes observed IRQ low')
                else:
                    _require(delivery['end_local_tick'] < mret_tick, 'MRET precedes IRQ expiry')
            details.update(return_target=pc,pc_wdata=mret.get('rvfi_pc_wdata'),
                return_target_source='first_subsequent_valid_RVFI_pc_rdata_with_instruction_response',
                return_target_authority='inferred_architectural_successor_after_MRET')
        capture(limited_retirement_chain if limited else retirement_chain)
    boundary=selected['next_fetch']
    if boundary is not None:
        def fetch_boundary():
            key_check(boundary.get('transaction'),'instr')
            expected=(p['slot_base']+256*indices['slot_index']+128 if error else
                p['slot_base']+256*(indices['slot_index']+1)
                if indices['slot_index']+1<p['slot_count'] else p['park_address'])
            _require(boundary.get('address')==expected and boundary.get('execution')==cpu_scope[0]
                and type(boundary.get('reset_epoch')) is int and boundary['reset_epoch']==cpu_scope[1]
                and boundary.get('native_testcase_id')==cpu_scope[2]
                and type(boundary.get('local_tick')) is int,'next fetch address/scope')
            if returned is not None:_require(boundary['local_tick']>returned['successor_local_tick'],
                'next fetch/successor chronology')
            backend=tick_sample(boundary['local_tick'],'pre')['outputs']['backend']
            _require(backend.get('i_req_valid')==backend.get('i_req_ready')==1
                and backend.get('i_req_addr')==expected
                and backend.get('i_req_write')==0 and backend.get('i_req_be')==15
                and backend.get('i_req_wdata')==0,'next fetch native handshake')
            if 'provenance' not in boundary:
                native_scope(unique('cpu_external_irq_sample',cpu,
                    lambda row:row.get('local_tick')==boundary['local_tick']))
                _require(boundary.get('boundary')==('error_current_island' if error else 'next_prefix_or_park'),
                    'derived next fetch boundary branch')
                boundary_sample_id=tick_sample(boundary['local_tick'],'pre')['event_id']
                reset_rows=[row for row in events if row.get('component')==cpu
                    and row.get('kind')=='cpu_reset' and row.get('reset_epoch')==cpu_scope[1]
                    and row.get('event_id',0)<boundary_sample_id]
                floor=max((row['event_id'] for row in reset_rows),default=0)
                _require(bool(reset_rows) or cpu_scope[1]==0,'next fetch reset anchor')
                count=0
                for raw in events:
                    if (raw.get('component')!=cpu or raw.get('kind')!='local_tick_sample'
                            or raw.get('phase')!='pre' or not floor<raw['event_id']
                            <=boundary_sample_id):continue
                    data=raw.get('outputs',{}).get('backend',{})
                    _require(all(type(data.get(field)) is int and data[field] in (0,1)
                        for field in ('i_req_valid','i_req_ready')),'next fetch sequence sample shape')
                    count+=int(data['i_req_valid']==data['i_req_ready']==1)
                _require(boundary['transaction']['source_sequence']==count,
                    'next fetch native transaction ordinal')
            details['next_address']=expected
        capture(fetch_boundary)
    if error and not issues:
        details['error_completion']=dict(terminal_marker=2,
            next_address=details.get('next_address'),return_target=details.get('return_target'))
        issues.append(dict(outcome='failed',reason='native expected ERR completed the error ISR branch'))
    return finish()


def _project_saved_cross_component_edges(*, attempt, contract, binding, events,
        local_by_id, cpu_artifact, shared_context=None):
    """Reconstruct declared F6 hops solely from detached archived Runner facts.

    This is an offline evidence projection, never an issuance or replay of live
    memory authority. Original source acceptance is required for the instruction
    hop; saved outcomes and diagnostic edge labels are deliberately ignored.
    """
    from hashlib import sha256
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from myfuzz.scenario.source_provenance import SourceAdmission

    details = dict(schema_version='compiled_F6_declared_edge_hops.v1',
        edges=[], component_evidence={}, raw_references=[], raw_evidence=[], issues=[])
    declaration_issues = []

    def capture(issues, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except _EvidenceIssue as error:
            issues.append(dict(outcome=error.outcome, reason=str(error)))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError,
                IndexError) as error:
            issues.append(dict(outcome='failed', reason='invalid evidence: '+str(error)))
        return None

    def digest(value):
        return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()

    def outcome(issues):
        return ('failed' if any(row['outcome']=='failed' for row in issues)
            else 'missing' if issues else 'passed')

    def normalized(issues):
        return [dict(outcome=status, reason=reason) for status,reason in sorted(
            {(row['outcome'],row['reason']) for row in issues})]

    indices = None

    def declarations():
        nonlocal indices
        indices = saved_slot_mapping(attempt, contract, events, shared_context)
        _require(type(attempt) is dict and type(contract) is dict and type(binding) is dict
            and type(events) is list and type(local_by_id) is dict, 'input shape')
        _require(type(attempt.get('case_id')) is str and bool(attempt['case_id'])
            and type(attempt.get('case_index')) is int and attempt['case_index'] >= 0,
            'attempt identity')
        cpu, dma = contract['cpu']['instance_id'], contract['dma']['instance_id']
        resource, program = contract['memory']['resource'], contract['program_contract']
        _require(type(cpu) is str and type(dma) is str and cpu != dma, 'component identities')
        from myfuzz.integration.compiled_f4 import _artifact_execution_identity
        from myfuzz.local_harness.native_physical_observation import \
            verify_cpu_obi_protocol_traces

        try:
            _require(verify_cpu_obi_protocol_traces(cpu_artifact) is True,
                'CPU OBI artifact protocol trace verification failed')
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            _require(False, 'CPU OBI artifact protocol trace verification failed: '
                + str(error))
        artifact_plan = cpu_artifact.plan
        artifact_runtime = cpu_artifact.runtime_document
        _require(artifact_plan.request.instance_id == cpu
            and artifact_runtime.get('kind') == 'obi_cpu',
            'CPU OBI artifact instance/kind mismatch')
        artifact_endpoints = [endpoint for endpoint in artifact_plan.binding.endpoints
            if endpoint.protocol is not None]
        instruction_endpoints = [endpoint for endpoint in artifact_endpoints
            if endpoint.function == 'instruction_memory_master']
        data_endpoints = [endpoint for endpoint in artifact_endpoints
            if endpoint.function == 'data_memory_master']
        _require(len(instruction_endpoints) == len(data_endpoints) == 1,
            'CPU OBI artifact instruction/data endpoint inventory mismatch')
        instruction_endpoint = instruction_endpoints[0]
        data_endpoint = data_endpoints[0]
        cpu_contract = contract['cpu']
        _require(cpu_contract.get('artifact_kind') == 'obi_cpu'
            and cpu_contract.get('profile_fingerprint') ==
                artifact_plan.profile.profile_fingerprint
            and cpu_contract.get('instruction_endpoint_id') ==
                instruction_endpoint.endpoint_id
            and cpu_contract.get('data_endpoint_id') == data_endpoint.endpoint_id
            and cpu_contract.get('source_verification_sha256') ==
                _artifact_execution_identity(cpu_artifact)['source_verification_sha256'],
            'CPU OBI artifact contract identity/endpoint mismatch')
        artifact_identity = _artifact_execution_identity(cpu_artifact)
        _require(binding.get('artifact_identities', {}).get(cpu) == artifact_identity,
            'CPU OBI artifact binding identity mismatch')
        binding_cpu = binding.get('cpu')
        _require(type(binding_cpu) is dict
            and binding_cpu.get('instance_id') == cpu
            and binding_cpu.get('profile_fingerprint') ==
                artifact_plan.profile.profile_fingerprint
            and binding_cpu.get('runtime_artifact_sha256') == digest(artifact_runtime),
            'CPU OBI artifact runtime binding digest mismatch')
        trace_document = artifact_runtime['base_protocol_traces']
        traces = trace_document['traces']
        _require(type(traces) is list and all(type(trace) is dict for trace in traces),
            'CPU OBI artifact trace inventory shape')
        trace_by_endpoint = {trace.get('endpoint_id'): trace for trace in traces}
        _require(set(trace_by_endpoint) == {instruction_endpoint.endpoint_id,
                data_endpoint.endpoint_id},
            'CPU OBI artifact trace endpoint closure mismatch')
        instruction_trace = trace_by_endpoint[instruction_endpoint.endpoint_id]
        instruction_signals = instruction_trace['signals']
        for trace in traces:
            signals = trace.get('signals')
            widths = trace.get('signal_widths')
            _require(type(trace.get('endpoint_id')) is str and trace['endpoint_id']
                and type(signals) is dict and bool(signals)
                and all(type(role) is str and role and type(name) is str and name
                    for role,name in signals.items())
                and type(widths) is dict and set(widths)==set(signals)
                and all(type(width) is int and width>0 for width in widths.values()),
                'CPU OBI artifact trace signal/width schema mismatch')
        error_capability = artifact_plan.profile.capabilities.get('error_response')
        _require(type(error_capability) is bool, 'CPU OBI explicit error capability required')
        required_roles = {'req','addr','gnt','rvalid','rdata'}
        if error_capability:
            required_roles.add('error')
        _require(type(instruction_signals) is dict
            and required_roles <= set(instruction_signals)
            and ('error' in instruction_signals) == error_capability
            and all(type(name) is str and name for name in instruction_signals.values()),
            'CPU OBI instruction trace role mapping mismatch')
        instruction_error_tap = (instruction_signals['error']
            if error_capability else None)
        trace_tap_names = [name for trace in traces
            for name in trace['signals'].values()]
        protocol_tap_names = set(trace_tap_names)
        ports = artifact_runtime.get('protocol_tap_ports')
        _require(type(ports) is list and all(type(port) is dict for port in ports),
            'CPU OBI artifact protocol TAP port inventory shape')
        port_fields = {'name','direction','width','role','endpoint_id','source_wire'}
        port_names = []
        port_by_name = {}
        for port in ports:
            _require(set(port)==port_fields
                and all(type(port.get(field)) is str and port[field]
                    for field in ('name','direction','role','endpoint_id','source_wire'))
                and type(port.get('width')) is int and port['width']>0,
                'CPU OBI artifact protocol TAP port field/type mismatch')
            port_names.append(port['name'])
            port_by_name[port['name']] = port
        _require(bool(protocol_tap_names)
            and all(type(name) is str and name for name in trace_tap_names)
            and len(protocol_tap_names) == len(trace_tap_names)
            and len(port_names) == len(ports)
            and len(set(port_names)) == len(port_names)
            and set(port_names) == protocol_tap_names,
            'CPU OBI artifact exact protocol TAP closure mismatch')
        for trace in traces:
            for role,name in trace['signals'].items():
                port = port_by_name[name]
                _require(port['endpoint_id']==trace['endpoint_id']
                    and port['role']==role
                    and port['width']==trace['signal_widths'][role],
                    'CPU OBI artifact protocol TAP trace mapping mismatch')
        body = {k:v for k,v in binding.items() if k != 'binding_sha256'}
        _require(binding.get('schema_version') == 'compiled_F6_execution_binding.v1'
            and binding.get('binding_sha256') == digest(body)
            and binding.get('flow_id') == 'F6' and binding.get('path_id') == contract['path_id'],
            'execution binding identity/digest/path')
        path = binding.get('runtime_path_admission')
        _present(type(path) is dict, 'runtime path admission unavailable')
        _require(path.get('schema_version') == 'compiled_F6_runtime_path_admission.v1'
            and path.get('admission_sha256') == digest({k:v for k,v in path.items()
                if k != 'admission_sha256'}), 'runtime path admission identity/digest')
        _require(path.get('execution_contract') == contract
            and path.get('execution_contract_sha256') == digest(contract),
            'runtime admission execution contract scope')
        if 'execution_contract_sha256' in binding:
            _require(binding['execution_contract_sha256'] == digest(contract),
                'execution binding contract digest')
        graph = DependencyGraph.from_edge_document(path['runtime_graph'])
        prepared = PreparedRuntimePathContract.from_document(path['prepared_runtime_paths'])
        _require(prepared.document() == path['prepared_runtime_paths']
            and path['prepared_runtime_paths']['graph'] == graph.edge_document()
            and path['prepared_runtime_paths']['contract'] == path['runtime_contract']
            and list(prepared.path_ids) == path['runtime_path_ids'],
            'prepared runtime path identity/scope')
        source = contract['instruction_source_id']
        _require(source == program['instruction_source_id'], 'instruction source contract disagreement')
        nodes = ['F6.runtime_ram_source_words', 'F6.runtime_dma_read_words',
            'F6.runtime_dma_write_words', 'F6.runtime_ram_destination_words',
            source, 'F6.runtime_online_instruction_prefixes']
        pairs = [(0,1,'DMA_MASTER_TRANSFER','dma_master_route'),
            (1,2,'EVENT_ORDER','causal_order'), (2,3,'DMA_MASTER_TRANSFER','dma_master_route'),
            (4,5,'PERSISTENT_STATE_RULE','persistent_state')]
        expected_edges = [dict(rule_index=index, prerequisite_index=0,
            prerequisite=nodes[left], target=nodes[right], kind=kind)
            for index,(left,right,kind,_relation) in enumerate(pairs)]
        extras = saved_shared_union(contract, binding)
        _require(graph.edge_document()['edges'] == expected_edges + extras['edges'],
            'exact four declared graph edges required')
        runtime = prepared.contract
        _require(runtime.graph_sha256 == digest(graph.edge_document())
            and [(edge.rule_index,edge.prerequisite_index,edge.relation)
                for edge in runtime.edges] == [(i,0,pair[3]) for i,pair in enumerate(pairs)] + extras['relations'],
            'runtime graph hash/exact four edge declarations')
        base_nodes = [node for node in runtime.nodes if node.node_id in nodes]
        _require(len(runtime.nodes) == 6+len(extras['nodes'])
            and {node.node_id for node in runtime.nodes} == set(nodes)|set(extras['nodes'])
            and all((node.component,node.kind) == extras['nodes'][node.node_id]
                for node in runtime.nodes if node.node_id in extras['nodes'])
            and all(node.component == (dma if node.node_id in nodes[1:3] else cpu)
                and node.kind == ('logical' if node.node_id in (nodes[1],nodes[2],nodes[5])
                    else 'state') for node in base_nodes), 'runtime node component/kind scope')
        _require(runtime.edges[3].resource_component == cpu
            and runtime.edges[3].resource_id == resource['resource_id'],
            'persistent state resource declaration')
        _require(set(graph.sources) == {nodes[0],source}|extras['sources'], 'runtime source declaration inventory')
        for source_node in graph.sources.values():
            pin_source = path.get('shared_flow_paths',{}).get('F5',{}).get('source_id')
            if source_node.source_id==pin_source:
                continue  # Exact pin/group declaration was rebuilt above; it is not a RAM source.
            if source_node.source_id in extras['sources']:
                _require(source_node.width == resource['size']*8
                    and source_node.image_address is None, 'shared storage source span')
            _require(source_node.component == cpu and source_node.port == resource['resource_id']
                and source_node.kind == 'memory_image' and source_node.bit_offset == 0
                and source_node.directions == ('CPU_TO_IP',), 'runtime source declaration scope')
        _require(graph.sources[nodes[0]].width == contract['memory']['source']['size']*8
            and graph.sources[source].width == resource['size']*8
            and graph.sources[source].image_address is None
            and graph.sources[nodes[0]].image_address == program['source_address'],
            'runtime source declaration span')
        selections = path['prepared_runtime_paths']['selections']
        # saved_shared_union rebuilt every extra selection, including IP_TO_CPU F5.
        # Only the two fixed F6 selections have the CPU_TO_IP direction below.
        _require(len(selections) == extras['selection_count'] and all(row['direction']=='CPU_TO_IP' for row in selections[:2])
            and [row['source_ids'] for row in selections[:2]] == [[nodes[0]],[source]]
            and [row['target'] for row in selections[:2]] == [nodes[3],nodes[5]]
            and [[(edge['rule_index'],edge['prerequisite_index']) for edge in row['edges']]
                for row in selections[:2]] == [[(0,0),(1,0),(2,0)],[(3,0)]],
            'runtime selection path scope')
        routes = [route.document() for route in runtime.dma_master_routes]
        _require(routes == path['selected_dma_routes'] == binding['dma_routes']
            and [(route['rule_index'],route['prerequisite_index'],route['operation'],
                route['source_node_id'],route['target_node_id']) for route in routes]
            == [(0,0,'read',nodes[0],nodes[1]),(2,0,'write',nodes[2],nodes[3])],
            'exact declared DMA route identities')
        runner = {}
        previous_event_id=0
        for row in events:
            _require(type(row) is dict and type(row.get('event_id')) is int
                and row['event_id']>previous_event_id
                and row['event_id'] not in runner,
                'Runner event append order identity mismatch')
            runner[row['event_id']] = row
            previous_event_id=row['event_id']
        raw = bytes.fromhex(attempt['raw8_hex'])
        packed = int.from_bytes(raw,'little')
        prefix = bytes.fromhex(attempt['prefix_hex'])
        build_f6_firmware(contract).validate_prefix(prefix,
            F6Candidate(raw, tuple((packed >> (11*i)) & 2047 for i in range(4))),
            case_index=attempt['case_index'])
        return dict(cpu=cpu,dma=dma,resource=resource,program=program,source=source,
            nodes=nodes,pairs=pairs,runner=runner,prefix=prefix,path=path,
            protocol_tap_names=protocol_tap_names,
            instruction_signals=instruction_signals,
            instruction_error_tap=instruction_error_tap)

    prepared = capture(declaration_issues, declarations)
    word = project_saved_word_transfer(attempt=attempt,contract=contract,binding=binding,
        events=events,local_by_id=local_by_id, shared_context=shared_context)
    details['component_evidence']['word_transfer'] = word
    word_issues = deepcopy(word.get('details',{}).get('issues',[]))
    # Keep a row for every required edge even when declarations are incomplete.
    for index,relation in enumerate(('dma_master_route','causal_order','dma_master_route','persistent_state')):
        details['edges'].append(dict(rule_index=index,prerequisite_index=0,relation=relation,
            outcome='missing',runner_event_ids=[],evidence=[],issues=[]))
    if prepared is not None:
        cpu,dma,resource,program,source,runner,prefix,path = (prepared[key] for key in
            ('cpu','dma','resource','program','source','runner','prefix','path'))
        protocol_tap_names = prepared['protocol_tap_names']
        instruction_signals = prepared['instruction_signals']
        instruction_error_tap = prepared['instruction_error_tap']
        expected_case = dict(case_id=attempt['case_id'],case_index=indices['session_case_index'])

        def in_case(row):
            provenance = row.get('provenance')
            return type(provenance) is dict and provenance.get('observed_case') == expected_case

        def scope(row):
            _require(row.get('provenance') is None or type(row.get('provenance')) is dict,
                'invalid Runner case provenance')
            _present(type(row.get('provenance')) is dict
                and row['provenance'].get('observed_case') is not None,
                'Runner case provenance unavailable')
            _require(in_case(row),'cross-case Runner evidence')

        def optional_scope(row):
            """Check provenance when present; typed receipt joins carry missing scope."""
            provenance=row.get('provenance')
            _require(provenance is None or type(provenance) is dict,
                'invalid Runner case provenance')
            observed=provenance.get('observed_case') if type(provenance) is dict else None
            if observed is not None:
                _require(_canonical(observed)==_canonical(expected_case),
                    'cross-case Runner evidence')

        for index,edge in enumerate(details['edges']):
            left,right,_kind,_relation = prepared['pairs'][index]
            edge.update(source_node_id=prepared['nodes'][left],target_node_id=prepared['nodes'][right],
                runtime_graph_sha256=path['runtime_contract']['graph_sha256'],
                path_id=path['runtime_path_ids'][1 if index==3 else 0])
        for index in range(3):
            edge = details['edges'][index]
            # Each edge carries only issues captured in its own witness domain.
            # The component-wide word result remains separately included below.
            edge['issues'].extend(deepcopy(
                word['details'].get('graph_edge_issues',{}).get(str(index),[])))
            edge['evidence'] = deepcopy(word['details']['words'])
            edge['partial_effects'] = deepcopy(word['details']['partial_effects'])
            fields = ('sources','source_commits','reads','read_snapshots','read_responses') if index==0 else (
                ('reads','read_responses','writes','write_responses') if index==1 else
                ('writes','word_commits','write_responses'))
            ids = []
            for field in fields:
                refs = attempt.get(field,[])
                if type(refs) is not list:
                    continue
                for ref in refs:
                    row = local_by_id.get((cpu if field in ('sources','source_commits') else dma,ref))
                    if type(row) is dict and row.get('runner_event_id') in runner:
                        ids.append(row['runner_event_id'])
            edge['runner_event_ids'] = sorted(set(ids))
            _route = next((r for r in binding['dma_routes']
                if r['rule_index']==index),None)
            if _route is not None:
                edge['route_sha256'] = _route['identity_sha256']
            edge['outcome'] = outcome(edge['issues'])

        edge = details['edges'][3]
        issues = edge['issues']
        action = source+':'+str(attempt['case_index'])
        slot = program['slot_base']+program['slot_bytes']*indices['slot_index']
        expected_source = dict(action_id=action,component=cpu,address=slot,
            data_hex=prefix.hex(),source_id=source,kind='instruction')
        def action_matches(row,field):
            return type(row.get(field)) is dict and row[field].get('action_id')==action

        for row in events:
            if row.get('kind')=='source_admission':
                capture(issues,_require,type(row.get('admission')) is dict,
                    'malformed Runner source admission')
        original = [row for row in events if (row.get('component')==cpu
                or row.get('kind')=='source_admission'
                and (action_matches(row,'admission') or type(row.get('admission')) is dict
                    and row['admission'].get('case_id')==attempt['case_id']))
            and row.get('kind') in ('source_admission','instruction_source')
            and (in_case(row) or row.get('source_event_id')==action
                or action_matches(row,'source') or action_matches(row,'admission'))]
        edge['runner_event_ids'] = sorted(row['event_id'] for row in original)
        for row in original:
            if row.get('kind')!='source_admission':
                capture(issues,optional_scope,row)
        groups = {}
        for kind in ('source_admission','instruction_source'):
            candidates = [row for row in original if row.get('kind')==kind]
            capture(issues,_require,len(candidates)<=1,'duplicate original '+kind)
            capture(issues,_present,bool(candidates),'original '+kind+' unavailable')
            groups[kind] = candidates[0] if len(candidates)==1 else None
        admission_row,service = (groups[kind] for kind in
            ('source_admission','instruction_source'))
        completion_rows = [row for row in events
            if row.get('kind')=='compiled_F6_instruction_fetch_completion']

        def validate_admission():
            admission = SourceAdmission.from_document(admission_row['admission'])
            for name,value in dict(case_id=attempt['case_id'],case_index=indices['session_case_index'],
                    source_id=source,path_id=path['runtime_path_ids'][1],direction='CPU_TO_IP',
                    component=cpu,action_id=action,role='fuzz_source',input_kind='instruction',
                    input_sha256=digest(expected_source)).items():
                _require(getattr(admission,name)==value,'source admission '+name)
            return admission.document()

        if admission_row is not None:
            capture(issues,validate_admission)
        if service is not None:
            for name,value in dict(address=slot,data_hex=prefix.hex(),source_event_id=action).items():
                capture(issues,_require,service.get(name)==value,'instruction source service '+name)
            if admission_row is not None:
                capture(issues,_require,admission_row['event_id']<service['event_id'],
                    'instruction source original admission/service chronology')
            producer = runner.get(service.get('producer_event_id'))
            if completion_rows:
                capture(issues,_require,type(producer) is dict and producer is admission_row
                    and producer.get('kind')=='source_admission',
                    'instruction source admission Runner producer identity')
            else:
                capture(issues,_require,type(producer) is dict and producer.get('component')==cpu
                    and 'kind' not in producer and producer['event_id']<service['event_id'],
                    'instruction source service Runner drain producer identity')

        # Without native completion receipts, source service labels and legacy
        # operand responses cannot prove the original accepted 128-byte image.
        if not completion_rows:
            capture(issues,_present,False,'original F6 instruction acceptance witness unavailable')
        tx_scopes = []
        used = set()
        operand_refs = attempt.get('operands')
        if type(operand_refs) is list:
            capture(issues,_require,len(operand_refs)<=4
                and len({_canonical(ref) for ref in operand_refs})==len(operand_refs),
                'duplicate/extra operand Observer references')
        def configured_cpu_scopes():
            refs=attempt.get('configuration',[])
            _require(type(refs) is list,'CPU configuration Observer reference inventory')
            _require(all(type(ref) is int and ref>0 for ref in refs)
                and len(refs)==len(set(refs)),
                'CPU configuration Observer references are malformed or duplicated')
            fields={'execution_id','testcase_id','source_component','source_epoch',
                'channel_id','source_sequence'}
            result=[]
            for ref in refs:
                observed=local_by_id.get((cpu,ref))
                _present(type(observed) is dict,'CPU configuration Observer row unavailable')
                _require(observed.get('event_id')==ref and observed.get('component')==cpu
                    and type(observed.get('runner_event_id')) is int
                    and observed['runner_event_id']>0,
                    'CPU configuration Observer identity')
                runner_id=observed['runner_event_id']
                raw=runner.get(runner_id)
                _present(type(raw) is dict,'CPU configuration Runner row unavailable')
                _require(raw.get('event_id')==runner_id and raw.get('component')==cpu
                    and raw.get('kind')=='data_accept',
                    'CPU configuration Runner kind/component identity')
                projected={name:value for name,value in observed.items()
                    if name!='runner_event_id'}
                projected['event_id']=runner_id
                _require(_canonical(projected)==_canonical(raw),
                    'CPU configuration Observer/Runner row mismatch')
                optional_scope(raw)
                transaction=raw.get('transaction')
                _require(type(transaction) is dict and set(transaction)==fields
                    and all(type(transaction[name]) is str and transaction[name]
                        for name in ('execution_id','testcase_id','source_component','channel_id'))
                    and all(type(transaction[name]) is int and transaction[name]>=0
                        for name in ('source_epoch','source_sequence'))
                    and transaction['source_component']==cpu
                    and transaction['channel_id']=='data'
                    and transaction['source_sequence']>0,
                    'CPU configuration TransactionKey scope')
                result.append({name:transaction[name] for name in
                    ('execution_id','testcase_id','source_component','source_epoch')})
            return result

        if completion_rows:
            cpu_scopes=capture(issues,configured_cpu_scopes)
            if cpu_scopes is None:
                cpu_scopes=[]
        else:
            # Preserve the legacy operand-only path's case-provenance filter.
            cpu_scopes = [{name:row['transaction'].get(name) for name in
                    ('execution_id','testcase_id','source_component','source_epoch')}
                for row in events if row.get('component')==cpu and in_case(row)
                and row.get('kind')=='data_accept' and type(row.get('transaction')) is dict]

        def native_sample(tick):
            samples = [row for row in events if row.get('component')==cpu
                and row.get('kind')=='local_tick_sample' and row.get('local_tick')==tick]
            _require(len(samples)<=2 and len({row.get('phase') for row in samples})==len(samples),
                'duplicate instruction native sample phase')
            _present(len(samples)==2,'instruction native PRE/POST unavailable')
            _require({row.get('phase') for row in samples}=={'pre','post'},'instruction sample phases')
            pre = next(row for row in samples if row['phase']=='pre')
            post = next(row for row in samples if row['phase']=='post')
            for row in samples:
                scope(row)
            producer = runner.get(pre.get('producer_event_id'))
            _require(type(producer) is dict and producer.get('component')==cpu
                and 'kind' not in producer and producer.get('local_tick')==tick
                and post.get('producer_event_id')==producer['event_id']
                and producer['event_id']<pre['event_id']<post['event_id'],
                'instruction native producer/phase identity')
            _present(type(pre.get('outputs',{}).get('backend')) is dict,
                'instruction native backend unavailable')
            return pre['outputs']['backend'],producer,pre

        def operand_reference(index,row):
            refs = attempt.get('operands')
            _present(type(refs) is list and index<len(refs),'operand Observer reference unavailable')
            ref = refs[index]
            _require(type(ref) is int and ref>0 and ref not in used,'duplicate/invalid operand Observer reference')
            used.add(ref)
            observed = local_by_id.get((cpu,ref))
            _present(type(observed) is dict,'operand Observer row unavailable')
            projected = {k:v for k,v in observed.items() if k!='runner_event_id'}
            projected['event_id'] = observed.get('runner_event_id')
            _require(observed.get('event_id')==ref and projected==row,
                'operand authenticated Observer/Runner mismatch')
            _require(sum(type(other) is dict and other.get('runner_event_id')==row['event_id']
                for (component,_ref),other in local_by_id.items() if component==cpu)==1,
                'operand Observer/Runner link is not bijective')
            details['raw_references'].append(dict(component=cpu,event_id=ref,
                kind='instr_response'))

        def operand(index,offset):
            address,data = slot+offset,prefix[offset:offset+4]
            candidates = [row for row in events if row.get('component')==cpu
                and row.get('kind')=='instr_response' and row.get('address')==address]
            edge['runner_event_ids'].extend(row['event_id'] for row in candidates)
            _require(len(candidates)<=1,'duplicate operand instruction response')
            _present(candidates,'operand instruction response unavailable')
            row = candidates[0]
            scope(row)
            capture(issues,operand_reference,index,row)
            transaction = row.get('transaction')
            fields = {'execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence'}
            _require(type(transaction) is dict and set(transaction)==fields
                and all(type(transaction[key]) is str and transaction[key]
                    for key in ('execution_id','testcase_id','source_component','channel_id'))
                and all(type(transaction[key]) is int and transaction[key]>=0
                    for key in ('source_epoch','source_sequence'))
                and transaction['source_component']==cpu and transaction['channel_id']=='instr',
                'instruction full transaction scope')
            tx_scope = {key:transaction[key] for key in fields-{'source_sequence'}}
            _require(not tx_scopes or tx_scopes[0]==tx_scope,'cross-scope instruction transaction')
            tx_scopes.append(tx_scope)
            shared_scope = {name:transaction[name] for name in
                ('execution_id','testcase_id','source_component','source_epoch')}
            _require(all(peer==shared_scope for peer in cpu_scopes),
                'instruction transaction crossed current CPU execution/testcase scope')
            value = int.from_bytes(data,'little')
            for name,expected in dict(address=address,raw_address=address,aligned_address=address,
                    write=0,be=15,wdata=0,rdata=value,error=0).items():
                _require(type(row.get(name)) is int and row[name]==expected,'operand response '+name)
            snapshot = row.get('snapshot')
            _present(type(snapshot) is dict,'operand instruction snapshot unavailable')
            for name,expected in dict(memory_id=resource['resource_id'],byte_offset=address-resource['base'],
                    value=value,data_hex=data.hex(),writer_event_ids=[action]*4,
                    writer_kinds=['INSTRUCTION_SOURCE']*4).items():
                _present(name in snapshot,'operand snapshot '+name+' unavailable')
                _require(snapshot[name]==expected,'operand snapshot '+name+' mismatch')
            _present('generation' in snapshot and 'versions' in snapshot,
                'operand snapshot byte versions unavailable')
            generation,versions = snapshot['generation'],snapshot['versions']
            _require(type(generation) is int and generation>=0
                and type(versions) is list and len(versions)==4
                and all(type(version) is list and len(version)==2
                    and all(type(value) is int and value>=0 for value in version)
                    and version[0]==generation and version[1]>0 for version in versions)
                and len({_canonical(version) for version in versions})==1,
                'operand snapshot byte version shape/generation')
            if service is not None:
                _require(type(service.get('generation')) is int
                    and service['generation']==generation,
                    'operand snapshot generation differs from original source service')
            at,rt = row.get('acceptance_tick'),row.get('response_tick')
            _require(type(at) is int and type(rt) is int and 0<=at<rt,'operand native tick order')
            backend,_producer,_pre = native_sample(at)
            for name,expected in dict(i_req_valid=1,i_req_ready=1,i_req_write=0,
                    i_req_addr=address,i_req_be=15,i_req_wdata=0).items():
                _require(type(backend.get(name)) is int and backend[name]==expected,
                    'operand native acceptance '+name)
            backend,producer,pre = native_sample(rt)
            for name,expected in dict(i_rsp_valid=1,i_rsp_ready=1,i_rsp_rdata=value,i_rsp_error=0).items():
                _require(type(backend.get(name)) is int and backend[name]==expected,
                    'operand native consumption '+name)
            for name,expected in dict(instr_rsp_consumed=1,
                    instr_rsp_source_epoch=transaction['source_epoch'],
                    instr_rsp_source_sequence=transaction['source_sequence'],instr_rsp_rdata=value).items():
                _present(name in producer.get('outputs',{}),'instruction consume identity unavailable')
                _require(type(producer['outputs'][name]) is int and producer['outputs'][name]==expected,
                    'operand native producer '+name)
            _require(row.get('producer_event_id')==producer['event_id']
                and producer['event_id']<row['event_id']<pre['event_id'],
                'instruction response producer/drain order')
            edge['evidence'].append(dict(operand_index=index,transaction=deepcopy(transaction),
                response_event_id=row['event_id'],snapshot=deepcopy(snapshot)))

        def project_completions():
            from myfuzz.scenario.ledger import TransactionKey

            expected_fields = {'execution_id','testcase_id','source_component',
                'source_epoch','channel_id','source_sequence'}
            acceptance_fields = {'memory_id','address','byte_offset','generation',
                'data_hex','source_event_id','versions','writer_event_ids','writer_kinds'}
            snapshot_fields = {'transaction_id','memory_id','generation','byte_offset',
                'data_hex','versions','writer_event_ids','materialized_offsets','writer_kinds'}
            receipt_fields={'key','snapshot','acceptance','source','admission','run_id',
                'execution_binding_sha256','case_id','case_index','execution','testcase_id',
                'reset_epoch','address','acceptance_tick','snapshot_tick','response_tick',
                'request_scope','response_scope','request_pre','response_pre','response_post',
                'backend_response_tick','backend_response_scope','backend_response_pre',
                'backend_response_post','schema_version','proof_scope','grants_source_authority',
                'kind','component','event_id','producer_event_id','admission_event_id',
                'service_event_id','instr_response_event_id','memory_read_event_id',
                'request_pre_event_id','request_producer_event_id',
                'backend_response_pre_event_id','backend_response_producer_event_id',
                'backend_response_post_event_id','response_pre_event_id',
                'response_producer_event_id','response_post_event_id'}
            root_fields = ('admission_event_id','service_event_id','memory_read_event_id',
                'instr_response_event_id','request_pre_event_id','request_producer_event_id',
                'backend_response_pre_event_id','backend_response_producer_event_id',
                'backend_response_post_event_id','response_pre_event_id',
                'response_producer_event_id','response_post_event_id')
            root_names = dict(admission_event_id='admission', service_event_id='service',
                memory_read_event_id='memory_read', instr_response_event_id='instr_response',
                request_pre_event_id='request_pre', request_producer_event_id='request_producer',
                backend_response_pre_event_id='backend_response_pre',
                backend_response_producer_event_id='backend_response_producer',
                backend_response_post_event_id='backend_response_post',
                response_pre_event_id='response_pre',
                response_producer_event_id='response_producer',
                response_post_event_id='response_post')
            prefix_end=slot+program['online_prefix_bytes']
            def receipt_scope_match(row):
                if type(row) is not dict or row.get('kind') != \
                        'compiled_F6_instruction_fetch_completion':
                    return False
                address=row.get('address')
                same_prefix=(type(address) is int and slot<=address<prefix_end)
                return (row.get('case_id')==attempt['case_id']
                    or row.get('case_index')==attempt['case_index'] or same_prefix)
            known_receipts = [row for row in events if receipt_scope_match(row)]
            _present(bool(known_receipts),'native instruction fetch completion receipts unavailable')
            # Keep diagnostic closure even if later semantic validation rejects
            # a receipt. These IDs are only retained when parseable and present
            # in the original Runner index; they do not establish trust.
            diagnostic_ids=set()
            for receipt in known_receipts:
                candidates=[receipt.get('event_id')]
                candidates.extend(receipt.get(field) for field in root_fields)
                for event_id in candidates:
                    if type(event_id) is not int or event_id<=0 or event_id in diagnostic_ids:
                        continue
                    raw=runner.get(event_id)
                    if type(raw) is dict and raw.get('event_id')==event_id:
                        diagnostic_ids.add(event_id)
                        edge['runner_event_ids'].append(event_id)
            _require(type(admission_row) is dict and type(service) is dict,
                'instruction source admission/service required')
            _require(type(admission_row.get('event_id')) is int
                and type(service.get('event_id')) is int
                and service.get('producer_event_id')==admission_row['event_id'],
                'instruction source admission/service Runner join')

            def observer_reference(raw, expected_kind):
                _require(type(raw) is dict and type(raw.get('event_id')) is int,
                    'Observer reference Runner identity')
                links = [(key,row) for key,row in local_by_id.items()
                    if type(key) is tuple and len(key)==2
                    and type(row) is dict and row.get('runner_event_id')==raw['event_id']]
                _require(len(links)==1 and links[0][0][0]==cpu,
                    'Observer/Runner reference is not bijective')
                (component,ref),observed = links[0]
                _require(type(ref) is int and ref>0 and observed.get('event_id')==ref
                    and observed.get('component')==cpu and observed.get('kind')==expected_kind,
                    'Observer reference component/kind identity')
                projected={name:value for name,value in observed.items()
                    if name!='runner_event_id'}
                projected['event_id']=observed.get('runner_event_id')
                _require(_canonical(projected)==_canonical(raw),
                    'Observer/Runner reference row mismatch')
                reference=dict(component=cpu,event_id=ref,kind=expected_kind)
                if reference not in details['raw_references']:
                    details['raw_references'].append(reference)
                return ref

            service_ref=observer_reference(service,'instruction_source')
            completion_refs=[]
            for row in known_receipts:
                _require(row.get('component')==cpu,
                    'instruction completion receipt CPU owner')
                completion_refs.append(observer_reference(row,
                    'compiled_F6_instruction_fetch_completion'))
            observer_receipts=[(key,row) for key,row in local_by_id.items()
                if type(key) is tuple and len(key)==2 and type(row) is dict
                and row.get('kind')=='compiled_F6_instruction_fetch_completion'
                and receipt_scope_match(row)]
            _require(len(observer_receipts)==len(known_receipts)
                and all(key[0]==cpu for key,_row in observer_receipts)
                and {row.get('runner_event_id') for _key,row in observer_receipts}
                    == {row['event_id'] for row in known_receipts},
                'completion Observer reference inventory differs from Runner receipt inventory')

            acceptance_material=None
            key_ids=set()
            covered=set()
            used_roots={}
            last_receipt=None
            completion_response_ids=set()
            evidence=[]
            tick_base_by_epoch={}

            def root(receipt, field, expected_kind, *, expected_component=cpu):
                event_id=receipt.get(field)
                _require(type(event_id) is int and event_id>0,
                    'completion root reference identity: '+field)
                row=runner.get(event_id)
                _require(type(row) is dict,'completion root Runner row unavailable: '+field)
                _require(row.get('event_id')==event_id and row.get('kind')==expected_kind
                    and row.get('component')==expected_component,
                    'completion root Runner kind/component mismatch: '+field)
                # Runner can append receipt roots after the observed case is
                # cleared. Typed IDs, scopes, samples and producer joins below
                # authenticate them when generic provenance is absent.
                request_fields = ('request_pre_event_id', 'request_producer_event_id')
                cursor = attempt.get('_runner_event_start')
                previous_case = indices['previous_case']
                # The previous case stops with the next prefix request pending.
                # Only its exact first-slot request roots may precede admission;
                # all typed request/key/sample joins below still authenticate it.
                handover = (field in request_fields and previous_case is not None
                    and receipt.get('address') == slot and type(cursor) is int
                    and all(type(receipt.get(name)) is int
                        and 0 < receipt[name] <= cursor
                        and type(runner.get(receipt[name])) is dict
                        and type(runner[receipt[name]].get('provenance')) is dict
                        and _canonical(runner[receipt[name]]['provenance'].get('observed_case'))
                            == _canonical(previous_case) for name in request_fields))
                if not handover:
                    optional_scope(row)
                return row

            def tap_inventory(sample, label):
                taps = sample.get('protocol_taps') if type(sample) is dict else None
                _require(type(taps) is dict and set(taps) == protocol_tap_names
                    and all(type(value) is int for value in taps.values()),
                    'native OBI '+label+' physical tap inventory')
                return taps

            def backend_sample(row, receipt, phase, scope_value, expected):
                _require(row.get('phase')==phase
                    and type(row.get('local_tick')) is int
                    and row.get('local_tick')==scope_value[3]
                    and _canonical(row.get('f6_obi_scope'))==_canonical(scope_value)
                    and _canonical(row.get('outputs'))==_canonical(expected),
                    'native OBI '+phase.upper()+' archived sample differs from receipt')
                return tap_inventory(expected, phase.upper())

            def step_driver_sample(producer, runner_tick, expected_pre, expected_post, label):
                samples=producer.get('outputs',{}).get('driver_samples')
                _require(type(samples) in (list,tuple) and len(samples)==1
                    and type(samples[0]) is dict
                    and set(samples[0])=={'local_tick','pre','post'}
                    and type(samples[0]['local_tick']) is int
                    and samples[0]['local_tick']>0
                    and type(producer.get('local_tick')) is int
                    and producer['local_tick']==runner_tick,
                    'instruction '+label+' step sample inventory mismatch')
                sample=samples[0]
                tick_base=runner_tick-sample['local_tick']
                _require(tick_base>=0,
                    'instruction '+label+' step sample local tick base is invalid')
                _require(_canonical(sample['pre'])==_canonical(expected_pre)
                    and (expected_post is None
                        or _canonical(sample['post'])==_canonical(expected_post)),
                    'instruction '+label+' step sample differs from receipt')
                return sample,tick_base

            def validate_receipt(receipt):
                nonlocal acceptance_material, last_receipt
                optional_scope(receipt)
                actual_fields=set(receipt)
                _require(actual_fields==receipt_fields
                    or actual_fields==receipt_fields|{'provenance'},
                    'instruction completion receipt field inventory')
                _require(receipt.get('schema_version')==
                    'compiled_F6_instruction_fetch_completion.v1'
                    and receipt.get('proof_scope')=='native_obi_instruction_fetch_completed'
                    and receipt.get('grants_source_authority') is False,
                    'instruction completion receipt schema/proof scope')
                _require(receipt.get('case_id')==attempt['case_id']
                    and type(receipt.get('case_index')) is int
                    and receipt.get('case_index')==attempt['case_index']
                    and receipt.get('run_id')==attempt['case_id'].split(':case:',1)[0]
                    and receipt.get('execution_binding_sha256')==binding['binding_sha256'],
                    'instruction completion case/run/binding scope')
                key=receipt.get('key')
                _require(type(key) is dict and set(key)==expected_fields
                    and all(type(key[name]) is str and key[name] for name in
                        ('execution_id','testcase_id','source_component','channel_id'))
                    and all(type(key[name]) is int and key[name]>=0 for name in
                        ('source_epoch','source_sequence'))
                    and key['source_sequence']>0 and key['source_component']==cpu
                    and key['channel_id']=='instr',
                    'instruction completion complete TransactionKey')
                key_id=_canonical(key)
                _require(key_id not in key_ids,'duplicate instruction completion TransactionKey')
                key_ids.add(key_id)
                tx=TransactionKey(**key)
                execution=receipt.get('execution')
                testcase=receipt.get('testcase_id')
                epoch=receipt.get('reset_epoch')
                _require(type(execution) is str and bool(execution)
                    and type(testcase) is str and testcase==key['testcase_id']
                    and type(epoch) is int and epoch==key['source_epoch'],
                    'instruction completion native execution/testcase/epoch scope')
                shared_scope={name:key[name] for name in
                    ('execution_id','testcase_id','source_component','source_epoch')}
                # When the attempt has no configuration transactions, the
                # receipt's already checked key/native scopes are the explicit
                # sole scope evidence rather than an empty all() result.
                scope_evidence=cpu_scopes if cpu_scopes else [shared_scope]
                _require(bool(scope_evidence) and all(peer==shared_scope
                    for peer in scope_evidence),
                    'instruction completion crossed CPU execution/testcase scope')
                address=receipt.get('address')
                _require(type(address) is int and slot<=address<prefix_end
                    and address%4==0 and (address-slot)%4==0,
                    'instruction completion address outside aligned prefix')
                offset=address-slot
                data=prefix[offset:offset+4]
                value=int.from_bytes(data,'little')
                _require(type(receipt.get('acceptance_tick')) is int
                    and type(receipt.get('snapshot_tick')) is int
                    and type(receipt.get('backend_response_tick')) is int
                    and type(receipt.get('response_tick')) is int
                    and 0<=receipt['acceptance_tick']<=receipt['snapshot_tick']
                    <receipt['backend_response_tick']<receipt['response_tick'],
                    'instruction completion tick chronology')
                scopes={}
                for phase,tick in (('request',receipt['acceptance_tick']),
                        ('backend_response',receipt['backend_response_tick']),
                        ('response',receipt['response_tick'])):
                    scope_value=receipt.get(phase+'_scope')
                    _require(type(scope_value) in (list,tuple) and len(scope_value)==4
                        and type(scope_value[0]) is str and scope_value[0]==execution
                        and type(scope_value[1]) is int and scope_value[1]>0
                        and type(scope_value[2]) is int and scope_value[2]==epoch
                        and type(scope_value[3]) is int and scope_value[3]==tick,
                        'instruction completion '+phase+' command scope')
                    scope_value=list(scope_value)
                    scopes[phase]=scope_value

                source_doc=dict(action_id=action,component=cpu,address=slot,
                    data_hex=prefix.hex(),source_id=source)
                _require(_canonical(receipt.get('source'))==_canonical(source_doc),
                    'instruction completion source binding')
                admission_doc=receipt.get('admission')
                _require(_canonical(admission_doc)==_canonical(admission_row.get('admission')),
                    'instruction completion admission reference differs from Runner source admission')
                _require(receipt.get('admission_event_id')==admission_row['event_id']
                    and receipt.get('service_event_id')==service['event_id'],
                    'instruction completion admission/service event IDs')
                acceptance=receipt.get('acceptance')
                _require(type(acceptance) is dict and set(acceptance)==acceptance_fields,
                    'instruction acceptance field inventory')
                _require(acceptance.get('memory_id')==resource['resource_id']
                    and acceptance.get('address')==slot
                    and acceptance.get('byte_offset')==slot-resource['base']
                    and type(acceptance.get('generation')) is int
                    and acceptance.get('generation')==service.get('generation')
                    and acceptance.get('source_event_id')==action
                    and acceptance.get('data_hex')==prefix.hex(),
                    'instruction acceptance source/image identity')
                versions=acceptance.get('versions')
                writer_ids=acceptance.get('writer_event_ids')
                writer_kinds=acceptance.get('writer_kinds')
                _require(type(versions) in (list,tuple) and len(versions)==len(prefix)
                    and all(type(pair) in (list,tuple) and len(pair)==2
                        and all(type(part) is int and part>=0 for part in pair)
                        and pair[0]==acceptance['generation'] and pair[1]>0 for pair in versions)
                    # PersistentMemory.accept_instructions calls _next_version
                    # once and assigns that same version to every accepted byte.
                    and len({_canonical(pair) for pair in versions})==1,
                    'instruction acceptance full byte-version chain')
                _require(type(writer_ids) in (list,tuple) and len(writer_ids)==len(prefix)
                    and _canonical(writer_ids)==_canonical([action]*len(prefix))
                    and type(writer_kinds) in (list,tuple) and len(writer_kinds)==len(prefix)
                    and _canonical(writer_kinds)==_canonical(['INSTRUCTION_SOURCE']*len(prefix)),
                    'instruction acceptance full byte-writer chain')
                if acceptance_material is None:
                    acceptance_material=deepcopy(acceptance)
                else:
                    _require(_canonical(acceptance)==_canonical(acceptance_material),
                        'instruction receipts disagree on original full acceptance')

                snap=receipt.get('snapshot')
                _require(type(snap) is dict and set(snap)==snapshot_fields,
                    'instruction completion snapshot field inventory')
                _require(snap.get('transaction_id')==str(tx)
                    and snap.get('memory_id')==resource['resource_id']
                    and snap.get('generation')==acceptance['generation']
                    and snap.get('byte_offset')==acceptance['byte_offset']+offset
                    and snap.get('data_hex')==data.hex()
                    and _canonical(snap.get('versions'))==_canonical(versions[offset:offset+4])
                    and _canonical(snap.get('writer_event_ids'))==_canonical(writer_ids[offset:offset+4])
                    and _canonical(snap.get('writer_kinds'))==_canonical(writer_kinds[offset:offset+4])
                    and type(snap.get('materialized_offsets')) in (list,tuple)
                    and len(snap['materialized_offsets'])==0,
                    'instruction snapshot differs from accepted source byte versions')
                mem=root(receipt,'memory_read_event_id','memory_read')
                _require(_canonical(mem.get('transaction'))==_canonical(key)
                    and mem.get('address')==address
                    and mem.get('width_bytes')==4 and mem.get('memory_id')==snap['memory_id']
                    and mem.get('generation')==snap['generation']
                    and mem.get('byte_offset')==snap['byte_offset']
                    and mem.get('data_hex')==snap['data_hex'] and mem.get('value')==value
                    and _canonical(mem.get('versions'))==_canonical(snap['versions'])
                    and _canonical(mem.get('writer_event_ids'))==_canonical(snap['writer_event_ids'])
                    and _canonical(mem.get('writer_kinds'))==_canonical(snap['writer_kinds']),
                    'instruction memory-read Runner receipt differs from snapshot')
                response=root(receipt,'instr_response_event_id','instr_response')
                response_snapshot=dict(snap,value=value)
                response_ints=('address','raw_address','aligned_address','write','be',
                    'wdata','rdata','error','acceptance_tick','response_tick')
                _require(all(type(response.get(name)) is int for name in response_ints)
                    and _canonical(response.get('transaction'))==_canonical(key)
                    and response.get('address')==address and response.get('raw_address')==address
                    and response.get('aligned_address')==address and response.get('write')==0
                    and response.get('be')==15 and response.get('wdata')==0
                    and response.get('rdata')==value and response.get('error')==0
                    and response.get('acceptance_tick')==receipt['acceptance_tick']
                    and response.get('response_tick')==receipt['backend_response_tick']
                    and response.get('response_boundary')=='obi_adapter_backend_acceptance'
                    and _canonical(response.get('snapshot'))==_canonical(response_snapshot),
                    'instruction backend response Runner event differs from receipt')

                admission_root=root(receipt,'admission_event_id','source_admission',
                    expected_component=None)
                _require(_canonical(admission_root.get('admission'))==_canonical(admission_doc),
                    'instruction admission root document')
                service_root=root(receipt,'service_event_id','instruction_source')
                _require(service_root is service and service_root.get('producer_event_id')
                    ==admission_root['event_id'] and service_root.get('address')==slot
                    and service_root.get('data_hex')==prefix.hex()
                    and service_root.get('source_event_id')==action
                    and service_root.get('generation')==acceptance['generation'],
                    'instruction source-service root identity')
                acceptance_anchor=service_root.get('f6_acceptance_anchor')
                _present(type(acceptance_anchor) is dict,
                    'original instruction source acceptance version anchor unavailable')
                anchor_fields={'schema_version','memory_id','address','byte_offset',
                    'generation','data_hex','source_event_id','versions',
                    'writer_event_ids','writer_kinds'}
                _require(set(acceptance_anchor)==anchor_fields
                    and acceptance_anchor.get('schema_version')==
                        'compiled_F6_instruction_acceptance_anchor.v1'
                    and _canonical({name:value for name,value in acceptance_anchor.items()
                        if name!='schema_version'})==_canonical(acceptance),
                    'instruction source acceptance anchor differs from typed acceptance')

                request_pre=root(receipt,'request_pre_event_id','local_tick_sample')
                request_producer=root(receipt,'request_producer_event_id',None)
                _require(request_pre.get('phase')=='pre'
                    and type(request_pre.get('local_tick')) is int
                    and request_pre.get('local_tick')==receipt['acceptance_tick']
                    and _canonical(request_pre.get('f6_obi_scope'))==_canonical(scopes['request'])
                    and request_pre.get('producer_event_id')==request_producer['event_id']
                    and 'kind' not in request_producer
                    and type(request_producer.get('local_tick')) is int
                    and request_producer.get('local_tick')==receipt['acceptance_tick'],
                    'instruction request PRE/step join')
                request_expected=receipt.get('request_pre')
                _require(type(request_expected) is dict
                    and _canonical(request_pre.get('outputs'))==_canonical(request_expected)
                    and _canonical(request_producer.get('outputs',{}).get('driver_samples',[{}])[0].get('pre'))
                        ==_canonical(request_expected),
                    'instruction request PRE archived source mismatch')
                request_driver_sample,request_tick_base=step_driver_sample(
                    request_producer,receipt['acceptance_tick'],request_expected,None,'request')
                tap_inventory(request_driver_sample['post'],'request POST')
                request_backend=request_expected.get('backend',{})
                request_taps=tap_inventory(request_expected,'request PRE')
                _require(all(type(request_backend.get(name)) is int
                    and request_backend[name]==expected for name,expected in dict(
                        i_req_valid=1,i_req_ready=1,i_req_write=0,i_req_addr=address,
                        i_req_be=15,i_req_wdata=0).items()),
                    'instruction backend request PRE handshake')
                _require(request_taps.get(instruction_signals['req'])==1
                    and request_taps.get(instruction_signals['gnt'])==1
                    and request_taps.get(instruction_signals['addr'])==address,
                    'instruction physical OBI request PRE taps')
                request_outputs=request_producer.get('outputs',{})
                request_accepted=request_outputs.get('instr_req_accepted')
                request_address=request_outputs.get('instr_addr')
                _require(type(request_accepted) is int and request_accepted==1
                    and type(request_address) is int and request_address==address,
                    'instruction request step producer identity')

                backend_pre=root(receipt,'backend_response_pre_event_id','local_tick_sample')
                backend_producer=root(receipt,'backend_response_producer_event_id',None)
                backend_post=root(receipt,'backend_response_post_event_id','local_tick_sample')
                for row,phase,expected in ((backend_pre,'pre',receipt.get('backend_response_pre')),
                        (backend_post,'post',receipt.get('backend_response_post'))):
                    backend_sample(row,receipt,phase,scopes['backend_response'],expected)
                    _require(row.get('producer_event_id')==backend_producer['event_id'],
                        'instruction backend response sample producer join')
                _require('kind' not in backend_producer
                    and type(backend_producer.get('local_tick')) is int
                    and backend_producer.get('local_tick')==receipt['backend_response_tick']
                    and backend_pre['event_id']<backend_post['event_id']
                    ,
                    'instruction backend response step producer identity')
                _backend_driver_sample,backend_tick_base=step_driver_sample(
                    backend_producer,receipt['backend_response_tick'],
                    receipt.get('backend_response_pre'),receipt.get('backend_response_post'),
                    'backend response')
                backend_actual=receipt.get('backend_response_pre',{}).get('backend',{})
                _require(all(type(backend_actual.get(name)) is int
                    and backend_actual[name]==expected for name,expected in dict(
                        i_rsp_valid=1,i_rsp_ready=1,i_rsp_rdata=value,i_rsp_error=0).items()),
                    'instruction backend response PRE handshake')
                backend_outputs=backend_producer.get('outputs',{})
                backend_consumed=backend_outputs.get('instr_rsp_consumed')
                backend_source_epoch=backend_outputs.get('instr_rsp_source_epoch')
                backend_source_sequence=backend_outputs.get('instr_rsp_source_sequence')
                backend_rdata=backend_outputs.get('instr_rsp_rdata')
                _require(type(backend_consumed) is int and backend_consumed==1
                    and type(backend_source_epoch) is int and backend_source_epoch==epoch
                    and type(backend_source_sequence) is int
                    and backend_source_sequence==key['source_sequence']
                    and type(backend_rdata) is int and backend_rdata==value,
                    'instruction backend response step transaction')
                post_taps=receipt.get('backend_response_post',{}).get('protocol_taps',{})
                _require(post_taps.get(instruction_signals['rvalid'])==1
                    and post_taps.get(instruction_signals['rdata'])==value
                    and (instruction_error_tap is None
                         or post_taps.get(instruction_error_tap)==0),
                    'instruction backend response POST physical taps')

                response_pre=root(receipt,'response_pre_event_id','local_tick_sample')
                response_producer=root(receipt,'response_producer_event_id',None)
                response_post=root(receipt,'response_post_event_id','local_tick_sample')
                for row,phase,expected in ((response_pre,'pre',receipt.get('response_pre')),
                        (response_post,'post',receipt.get('response_post'))):
                    backend_sample(row,receipt,phase,scopes['response'],expected)
                    _require(row.get('producer_event_id')==response_producer['event_id'],
                        'instruction native response sample producer join')
                _require('kind' not in response_producer
                    and type(response_producer.get('local_tick')) is int
                    and response_producer.get('local_tick')==receipt['response_tick']
                    and response_pre['event_id']<response_post['event_id']
                    ,
                    'instruction native response step producer identity')
                _response_driver_sample,response_tick_base=step_driver_sample(
                    response_producer,receipt['response_tick'],receipt.get('response_pre'),
                    receipt.get('response_post'),'native response')
                _require(request_tick_base==backend_tick_base==response_tick_base,
                    'instruction step samples disagree on native tick base')
                prior_tick_base=tick_base_by_epoch.setdefault(epoch,request_tick_base)
                _require(prior_tick_base==request_tick_base,
                    'instruction step sample tick base changed within reset epoch')
                native_pre=receipt.get('response_pre',{}).get('protocol_taps',{})
                _require(native_pre.get(instruction_signals['rvalid'])==1
                    and native_pre.get(instruction_signals['rdata'])==value
                    and (instruction_error_tap is None
                         or native_pre.get(instruction_error_tap)==0),
                    'instruction native OBI response PRE completion handshake')
                _require(receipt.get('producer_event_id')==response_pre['event_id'],
                    'instruction completion final native PRE reference')

                _require(admission_root['event_id']<service_root['event_id']
                    <mem['event_id']<response['event_id']<backend_pre['event_id']
                    <backend_post['event_id']<response_pre['event_id']
                    <response_post['event_id']<receipt['event_id']
                    # Runner appends memory reads while servicing the CPU
                    # step, before it journals that same step's PRE sample.
                    # The PRE/producer/output/scope joins above bind the
                    # request; its event id therefore need not precede the
                    # memory-read journal row.
                    and request_pre['event_id']<backend_pre['event_id']
                    and response.get('producer_event_id')==backend_producer['event_id'],
                    'instruction receipt Runner chronology')

                roots={}
                newly_used={}
                for field in root_fields:
                    root_id=receipt[field]
                    if field not in ('admission_event_id','service_event_id'):
                        previous=used_roots.get(root_id)
                        shared_field={'request_pre_event_id':'response_pre_event_id',
                            'request_producer_event_id':'response_producer_event_id'}.get(field)
                        shared=(previous is not None and last_receipt is not None
                            and previous == (shared_field, last_receipt['event_id'])
                            and shared_field is not None
                            and receipt['request_pre_event_id'] == last_receipt['response_pre_event_id']
                            and receipt['request_producer_event_id'] == last_receipt['response_producer_event_id']
                            and _canonical(receipt['request_scope']) == _canonical(last_receipt['response_scope'])
                            and receipt['acceptance_tick'] == last_receipt['response_tick']
                            and _canonical(receipt['request_pre']) == _canonical(last_receipt['response_pre'])
                            and all(key[name] == last_receipt['key'][name] for name in
                                ('execution_id','testcase_id','source_component','source_epoch','channel_id'))
                            and key['source_sequence'] == last_receipt['key']['source_sequence'] + 1)
                        _require(root_id not in newly_used and (previous is None or shared),
                            'instruction receipt borrowed/reused Runner root reference')
                        newly_used[root_id]=(field, receipt['event_id'])
                    roots[root_names[field]]=root_id
                    edge['runner_event_ids'].append(root_id)
                edge['runner_event_ids'].append(receipt['event_id'])
                completion_response_ids.add(response['event_id'])
                covered.add(address)
                evidence.append(dict(address=address,key=deepcopy(key),
                    completion_event_id=receipt['event_id'],root_refs=roots))
                used_roots.update(newly_used)
                last_receipt=receipt

            # Duplicate keys are detected before any row-specific root checks,
            # including when a malformed receipt reuses another address's key.
            prekeys=[]
            for receipt in known_receipts:
                key=receipt.get('key')
                if type(key) is dict:
                    prekeys.append(_canonical(key))
            _require(len(prekeys)==len(set(prekeys)),
                'duplicate instruction completion TransactionKey')
            for receipt in known_receipts:
                capture(issues,validate_receipt,receipt)
            # Keep every individually validated completion even when the
            # aggregate prefix or response inventory is incomplete. The live
            # consumer must be able to compare the original partial receipts
            # and report `missing` without discarding their evidence.
            edge['evidence']=evidence
            prefix_responses=[row for row in events if row.get('component')==cpu
                and row.get('kind')=='instr_response' and type(row.get('address')) is int
                and slot<=row['address']<prefix_end]
            _present(len(prefix_responses)==len(completion_response_ids)
                and {row['event_id'] for row in prefix_responses}==completion_response_ids,
                'prefix instruction response completion receipt inventory incomplete')
            expected_addresses={slot+offset for offset in range(0,
                program['online_prefix_bytes'],4)}
            _present(covered==expected_addresses,
                'native OBI receipts do not cover all 32 aligned prefix addresses')
            edge['runner_event_ids'].append(service['event_id'])
            edge['runner_event_ids'].append(admission_row['event_id'])
            edge['runner_event_ids']=sorted(set(edge['runner_event_ids']))

        if completion_rows:
            capture(issues,project_completions)
        else:
            for index,offset in enumerate(program['operand_instruction_offsets']):
                capture(issues,operand,index,offset)
        edge['runner_event_ids'] = sorted(set(edge['runner_event_ids']))
        edge['outcome'] = outcome(issues)
    else:
        for index,edge in enumerate(details['edges']):
            edge['issues'].extend(deepcopy(declaration_issues))
            if index<3:
                edge['issues'].extend(deepcopy(word_issues))
            edge['outcome'] = outcome(edge['issues'])
    all_issues = list(declaration_issues)
    all_issues.extend(word_issues)
    for edge in details['edges']:
        edge['issues'] = normalized(edge['issues'])
        all_issues.extend(edge['issues'])
    details['issues'] = normalized(all_issues)
    if prepared is not None:
        ids = {rid for edge in details['edges'] for rid in edge['runner_event_ids']}
        details['raw_evidence'] = [deepcopy(runner[rid]) for rid in sorted(ids)]
        details['raw_references'].extend(deepcopy(word['details']['raw_references']))
    return json.loads(_canonical(dict(kind='cross_component.declared_edge_hops',
        outcome=outcome(all_issues),details=details)))


def project_saved_cross_component_edges(*, attempt, contract, binding, events,
        local_by_id, cpu_artifact, shared_context=None):
    """Return a closed offline declared-edge result, including invalid archives."""
    try:
        return _project_saved_cross_component_edges(attempt=attempt,contract=contract,
            binding=binding,events=events,local_by_id=local_by_id,
            cpu_artifact=cpu_artifact, shared_context=shared_context)
    except _EvidenceIssue as error:
        outcome,reason = error.outcome,str(error)
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError) as error:
        outcome,reason = 'failed','invalid evidence: '+str(error)
    issue = dict(outcome=outcome,reason=reason)
    return dict(kind='cross_component.declared_edge_hops',outcome=outcome,
        details=dict(schema_version='compiled_F6_declared_edge_hops.v1',
            edges=[dict(rule_index=index,prerequisite_index=0,relation=relation,
                outcome=outcome,runner_event_ids=[],evidence=[],issues=[deepcopy(issue)])
                for index,relation in enumerate(('dma_master_route','causal_order',
                    'dma_master_route','persistent_state'))],
            component_evidence={},raw_references=[],raw_evidence=[],issues=[issue]))
