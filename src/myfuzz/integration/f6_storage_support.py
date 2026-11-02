"""Fixed support actions from the registered storage contract, not a selector.

The same RV32I writer ABI and live storage consumer used elsewhere perform the
CPU write/readback. DMA and storage retain separate evidence and version scopes.
"""
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F6-storage-support-' + reason)


def compile_storage_support(request, declaration, *, base_dir):
    from myfuzz.local_harness.apb_storage_source_contract import select_apb_storage_source_contract
    keys = {'component', 'contract_id', 'register', 'before_value', 'after_value',
            'before_result_address', 'after_result_address'}
    _require(type(declaration) is dict and set(declaration) == keys, 'fields')
    target = request.device(declaration['component'])
    _require(target is not None, 'component')
    source = select_apb_storage_source_contract(target.profile, base_dir=base_dir,
        selection={key: declaration[key] for key in ('contract_id', 'register')})
    windows = [window for window in request.wiring.windows
        if window.target_instance == target.instance_id]
    _require(len(windows) == 1 and target.endpoint(windows[0].endpoint_id).protocol == ('apb', '3'), 'window')
    register = source['register']
    _require(register['width'] == 32 and register['read_mask'] == register['write_mask'] == 0xffffffff,
        'register-word')
    for phase in ('before', 'after'):
        value, address = declaration[phase+'_value'], declaration[phase+'_result_address']
        _require(type(value) is int and 0 <= value <= 0xffffffff
            and type(address) is int and 0 <= address <= 0xfffffffc and address % 4 == 0, 'operand')
    return dict(deepcopy(declaration), schema_version='compiled_storage_fixed_support.v1',
        ownership='fixed_support', address=windows[0].base+register['canonical_offset'],
        window_base=windows[0].base, window_size=windows[0].size,
        register_offset=register['canonical_offset'], source_contract_digest=source['digest'])


def storage_fragment(support, phase):
    from myfuzz.scenario.rv32i_sources import Rv32iInstruction, fragment_bytes, _split_address
    _require(phase in ('before', 'after'), 'phase')
    ah, al = _split_address(support['address'])
    vh, vl = _split_address(support[phase+'_value'])
    rh, rl = _split_address(support[phase+'_result_address'])
    # Keep the common generated_register_writer ABI byte-for-byte.
    return fragment_bytes((Rv32iInstruction('LUI', rd=1, immediate=ah),
        Rv32iInstruction('ADDI', rd=1, rs1=1, immediate=al),
        Rv32iInstruction('LUI', rd=2, immediate=vh),
        Rv32iInstruction('ADDI', rd=2, rs1=2, immediate=vl),
        Rv32iInstruction('SW', rs1=1, rs2=2), Rv32iInstruction('LW', rd=3, rs1=1),
        Rv32iInstruction('LUI', rd=4, immediate=rh),
        Rv32iInstruction('SW', rs1=4, rs2=3, immediate=rl),
        *(Rv32iInstruction('NOP') for _ in range(4))))


def capture_support_start(runtime):
    """Observe the native target before boot support; drive no register value."""
    support = runtime.contract['program_contract'].get('storage_support')
    if support is None:
        return
    target_id = support['component']
    receipt = runtime.session.advance_initial((target_id,))
    _require(not receipt.violations and receipt.status in ('running', 'complete'), 'startup')
    authority = runtime.assembly.companion_authorities[target_id]
    runtime._storage_support_before = authority.consume(authority.issue(
        register=support['register'], reset_epoch=authority.target.reset_epoch))
    runtime._storage_support_event_start = runtime.runner.event_count
    runtime.storage_support_evidence = {}
    runtime.storage_support_raw = {}


def capture_support_phase(runtime, phase):
    support = runtime.contract['program_contract'].get('storage_support')
    if support is None:
        return
    from .generated_register_writer import declare_writer
    from .generated_storage_consumer import check_storage_observation, stable_storage_version
    from .native_obi_hops import collect_native_obi_beats
    from .compiled_f4 import _cpu_traces, _cpu_error_policy
    target_id = support['component']
    authority = runtime.assembly.companion_authorities[target_id]
    path = next(row for row in runtime.compiled_inputs['compiled']['paths'] if row['flow_id'] == 'F4')
    image = next(source for source in path['sources'] if source['kind'] == 'instruction_image')
    stream = next(source for source in path['sources'] if source['kind'] == 'cpu_mmio_stream')
    _require(stream['register_access']['target_component'] == target_id, 'source-owner')
    declaration = declare_writer(runtime.compiled_inputs['request'], runtime.compiled_inputs['compiled'],
        source_id=stream['source_id'], value=support[phase+'_value'],
        result_address=support[phase+'_result_address'])
    code = storage_fragment(support, phase)
    _require(code.hex() == declaration['code_hex'], 'writer-ABI')
    events = runtime.runner.events_since(runtime._storage_support_event_start)
    before = runtime._storage_support_before
    token = authority.issue(register=support['register'], reset_epoch=authority.target.reset_epoch)
    observed, commit, after = check_storage_observation(declaration,
        SimpleNamespace(case_id=runtime.run_id+':support:'+phase, events=events),
        target_artifact=runtime.artifacts[target_id], authority=authority, token=token,
        register=support['register'], reset_epoch=authority.target.reset_epoch,
        before=before, prior_writes=before['write_count'])
    # Consume complete native OBI beats, rather than accepting a host readback.
    all_events = runtime.runner.events_since(0)
    traces = _cpu_traces(runtime.artifacts[runtime.cpu_id], image, stream)
    policy = _cpu_error_policy(runtime.artifacts[runtime.cpu_id], image, stream)
    beats = collect_native_obi_beats(all_events, cpu=runtime.cpu_id, traces=traces, error_policy=policy)
    site = runtime.program.document()['storage_support_sites'][phase]
    instruction_hops, data, ram_beat = verify_support_native_hops(all_events,
        support=support, phase=phase, cpu=runtime.cpu_id, code=code, site=site,
        observed=observed, beats=beats)
    runtime.storage_support_evidence[phase] = dict(schema_version='compiled_storage_fixed_support_evidence.v1',
        status='verified', scope='fixed_firmware_CPU_MMIO_readback_not_dynamic_F4_selection',
        component=target_id, register=support['register'], value=support[phase+'_value'],
        instruction_address=site['address'], instruction_sha256=sha256(code).hexdigest(),
        version_before=stable_storage_version(before), version_after=after,
        joins=observed['joins'], commit=commit, instruction_hops=instruction_hops,
        native_data_hops=data, native_RAM_hop=deepcopy(ram_beat), RAM_event=observed['RAM_event'],
        cross_case_relation='not_claimed')
    runtime.storage_support_raw[phase] = dict(version_before=before,
        version_after=authority.consume(authority.issue(register=support['register'],
            reset_epoch=authority.target.reset_epoch)), events=list(events),
        native_commands=list(authority.target.native_reset_observation_commands()))
    runtime._storage_support_before = runtime.storage_support_raw[phase]['version_after']
    runtime._storage_support_event_start = runtime.runner.event_count


def verify_support_native_hops(events, *, support, phase, cpu, code, site, observed, beats):
    """Check joins against reconstructed native beats; issue no authority."""
    by_id = {row['event_id']: row for row in events}
    data = []
    for join in observed['joins']:
        delivery = by_id[join['delivery_event']]
        key = delivery['source_transaction']
        beat = beats.get(('data', key['source_sequence']))
        expected_value = support[phase+'_value']
        _require(beat is not None and beat['address'] == support['address']
            and beat['write'] == int(join['write']) and beat['byte_enable'] == 15
            and (beat['value'] if join['write'] else beat['rdata']) == expected_value
            and beat['acceptance_event'] == by_id[join['acceptance_event']]['producer_event_id']
            and beat['acceptance_event'] < join['acceptance_event'] < join['delivery_event'] < beat['response_event'],
            'native-OBI-data')
        data.append(deepcopy(beat))
    ram = by_id[observed['RAM_event']]
    ram_beat = beats.get(('data', ram['transaction']['source_sequence']))
    _require(ram_beat is not None and ram_beat['write'] == 1
        and ram_beat['address'] == support[phase+'_result_address']
        and ram_beat['value'] == ram['value'] == support[phase+'_value'] and ram_beat['byte_enable'] == 15
        and ram['producer_event_id'] == ram_beat['acceptance_event']
        and ram_beat['acceptance_event'] < ram['event_id'] < ram_beat['response_event']
        and ram_beat['acceptance_event'] > data[1]['response_event'], 'native-OBI-RAM')
    instruction_hops = []
    for offset in range(0, 32, 4):
        matches = [row for row in events if row.get('kind') == 'memory_read'
            and row.get('component') == cpu and row.get('address') == site['address']+offset
            and row.get('transaction', {}).get('channel_id') == 'instr'
            and row.get('data_hex') == code[offset:offset+4].hex()
            and tuple(row.get('writer_kinds', ())) == ('INITIAL_IMAGE',)*4]
        _require(bool(matches), 'fixed-instruction-read')
        read = matches[0]
        beat = beats.get(('instr', read['transaction']['source_sequence']))
        _require(beat is not None and beat['address'] == site['address']+offset
            and beat['rdata'] == int.from_bytes(code[offset:offset+4], 'little')
            and read['producer_event_id'] == beat['acceptance_event']
            and beat['acceptance_event'] < read['event_id'] < beat['response_event'], 'fixed-instruction-OBI')
        instruction_hops.append(dict(memory_read_event=read['event_id'],
            native_acceptance_event=beat['acceptance_event'], native_response_event=beat['response_event']))
    return instruction_hops, data, ram_beat
