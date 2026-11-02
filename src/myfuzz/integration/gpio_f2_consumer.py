"""GPIOEN F2 read proof from the existing source-pinned live GPIO issuer.

The raw APB/native-command join proves the read; the caller must additionally
run check_f2_exact_hops to prove actual CPU OBI consumption and dependent store.
"""
from copy import deepcopy
from weakref import WeakKeyDictionary

from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.native_physical_observation import (
    verify_native_physical_observation, verify_apb_register_trace)
from myfuzz.local_harness.pulp_gpio_probe_contract import (
    pulp_gpio_observation_contract, pulp_gpio_probe_document,
    verify_pulp_gpio_source_contract, PULP_GPIO_PROBES)
from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
from .compiled_storage_producer import _module_source, _endpoint_protocol, _GPIO_TEMPLATE
from .generated_storage_consumer import _join_delivery

ROW = 'gpio_causal_read_abi'
VERSION_SCHEMA = 'compiled_GPIO_F2_version.v1'
_BEFORE = WeakKeyDictionary()
_AUTHORITY = GpioRegisterVersionAuthority
_ISSUE = _AUTHORITY.issue
_CONSUME = _AUTHORITY.consume
_VALIDATE = _AUTHORITY._validate


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F2-GPIO-' + reason)


def _digest(value):
    from .compiled_f2_consumer import _digest as digest
    return digest(value)


def gpio_read_producer_document(*, artifact, access, contract, layout, compiled, base_dir):
    verify_pulp_gpio_source_contract(artifact.plan.profile, base_dir=base_dir)
    doc = artifact.runtime_document
    _require(doc.get('kind') == 'apb_gpio'
        and doc.get('gpio_observation_contract') == pulp_gpio_observation_contract()
        and verify_native_physical_observation(artifact) is True
        and verify_apb_register_trace(artifact) is True, 'observation-contract')
    _require((access['register'], access['register_offset']) in (('GPIOEN', 4), ('PADIN', 8)),
        'register-unsupported')
    selected = doc.get('selected_template', {}).get('contract', {})
    _require(all(selected.get(key) == value for key, value in _GPIO_TEMPLATE.items()), 'template-contract')
    return dict(schema_version='compiled_F2_read_producer_binding.v1', row=ROW,
        target_component=access['target_component'], target_artifact_digest=doc['artifact_digest'],
        target_artifact_kind=doc['kind'], endpoint_id=access['target_endpoint'],
        protocol=list(_endpoint_protocol(artifact, access['target_endpoint'], ('apb', '3'))),
        template=dict(_GPIO_TEMPLATE),
        register=dict(name=access['register'], offset=access['register_offset'], width=32, read_mask=0xffffffff,
            address=access['address'], operation='read', byte_enables=[15]),
        source=dict(pulp_gpio_probe_document()['source']),
        probe=pulp_gpio_observation_contract(),
        producer=dict(session_source_sha256=_module_source(GeneratedPulpGpioSession),
            issuer_source_sha256=_module_source(GpioRegisterVersionAuthority),
            consumer_source_sha256=_module_source(check_gpio_read_observation),
            session_construction=dict(setup_writes=[], probe_offsets=[], dynamic_inputs=[], bound_inputs=[]),
            grants_reset_prerequisite=False), execution_contract=contract,
        compiled_sha256=_digest(compiled), layout_digest=layout.digest, live_authority='not_claimed')


def validate_gpio_authority(authority):
    _require(type(authority) is _AUTHORITY and GpioRegisterVersionAuthority is _AUTHORITY
        and _AUTHORITY.issue is _ISSUE and _AUTHORITY.consume is _CONSUME
        and _AUTHORITY._validate is _VALIDATE, 'authority-required')
    _VALIDATE(authority)


def gpio_version_document(raw, history):
    """Project live issuance plus its separately authenticated native writes."""
    return dict(deepcopy(raw), schema_version=VERSION_SCHEMA, write_count=len(history),
        field_version=raw.get('native_sample_version', len(history)), write_history_sha256=_digest(history),
        version_basis=('all_measured_PADIN_enabled_sample_updates' if raw['register'] == 'PADIN'
            else 'all_measured_GPIOEN_writes_since_first_command'),
        history_scope='complete_commands_since_first_measured_state_not_unobserved_startup',
        grants_reset_prerequisite=False)


def stable_gpio_read_version(witness):
    _require(type(witness) is dict and witness.get('schema_version') == VERSION_SCHEMA,
        'version-shape')
    return {key: deepcopy(value) for key, value in witness.items()
        if key not in ('process_scope', 'write_history_sha256', 'input_sample', 'read_receipt','current_origins')}


def capture_gpio_read_version(authority, *, register, reset_epoch):
    from .compiled_f2_consumer import F2ReadVersion, _json
    validate_gpio_authority(authority)
    raw = authority.consume(authority.issue(register=register, reset_epoch=reset_epoch))
    history = authority.writes()
    before = F2ReadVersion(_json(gpio_version_document(raw, history)))
    _BEFORE[before] = (authority, deepcopy(history))
    return before


def gpio_read_samples(events, *, target, component, producer_event_id, signals, offset, value, reset_epoch):
    rows = [row for row in events if row.get('kind') == 'local_tick_sample'
        and row.get('component') == component and row.get('producer_event_id') == producer_event_id]
    candidates = []
    for row in rows:
        if row.get('phase') != 'pre':
            continue
        outputs = row.get('outputs', {})
        backend = outputs.get('backend', {})
        if all(backend.get(signals[k]) == v for k, v in
               dict(psel=1, penable=1, pready=1, pwrite=0, paddr=offset).items()):
            candidates.append(row)
    _require(len(candidates) == 1, 'native-read-count')
    pre = candidates[0]
    posts = [row for row in rows if row.get('phase') == 'post' and row.get('local_tick') == pre.get('local_tick')]
    _require(len(posts) == 1, 'native-post-missing')
    post = posts[0]
    for row in (pre, post):
        _require(row.get('reset_epoch') == reset_epoch and type(row.get('local_tick')) is int
            and row['local_tick'] > 0 and row.get('observation_schema_version') == 'ip_raw_observation.v1',
            'native-sample-scope')
        probes = target._normalized_physical(row['outputs'])
        _require(all(type(probes.get('gpio_probe_' + name)) is int
            and 0 <= probes['gpio_probe_' + name] < 1 << width
            for name, (width, _) in PULP_GPIO_PROBES.items()), 'probe-width')
        if offset == 4:
            _require(probes['gpio_probe_gpioen'] == value, 'read-version-changed')
    probes = target._normalized_physical(pre['outputs'])
    backend = pre['outputs']['backend']
    for role in ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata', 'pslverr'):
        probe_role = 'apb_addr' if role == 'paddr' else role
        _require(backend.get(signals[role]) == probes['gpio_probe_' + probe_role], 'probe-trace-mismatch')
    _require(probes['gpio_probe_prdata'] == value and probes['gpio_probe_pslverr'] == 0
        and probes['gpio_probe_decoded_word'] == offset // 4, 'read-value-or-register')
    if offset == 8:
        _require(probes['gpio_probe_padin_latch'] == value, 'read-version-changed')
    return pre, post


def check_gpio_read_observation(declaration, receipt, *, target_artifact, authority,
        token, before, register, reset_epoch, prior_writes):
    validate_gpio_authority(authority)
    _require(before in _BEFORE and _BEFORE[before][0] is authority, 'live-before-required')
    target = authority.target
    _require(target.artifact is target_artifact and target.reset_epoch == reset_epoch, 'target-epoch')
    verify_pulp_gpio_source_contract(target_artifact.plan.profile, base_dir=target.base_dir)
    _require(verify_native_physical_observation(target_artifact) is True
        and verify_apb_register_trace(target_artifact) is True, 'physical-observation')
    pre, history = before.document(), _BEFORE[before][1]
    _require(register == pre['register'] and register in ('GPIOEN', 'PADIN') and pre['reset_epoch'] == reset_epoch
        and pre['write_count'] == prior_writes and authority.writes() == history
        and _digest(history) == pre['write_history_sha256'], 'history-changed')
    access, events = declaration['candidate']['access'], receipt.events
    deliveries = [row for row in events if row.get('kind') == 'mmio_delivery'
        and row.get('component') == access['source_component']]
    _require(len(deliveries) == 1 and deliveries[0].get('write') is False, 'delivery-count-or-value')
    delivery = deliveries[0]
    actual_post = gpio_version_document(authority.consume(token), authority.writes())
    if register == 'PADIN':
        read = actual_post.get('read_receipt')
        _require(type(read) is dict and read['command_sequence'] > pre['command_sequence'], 'actual-read-required')
        pre = dict(pre, value=read['value'], field_version=read['field_version'],
            native_sample_version=read['field_version'], local_tick=read['local_tick'],
            command_sequence=read['command_sequence'])
    _require(delivery.get('read_value') == pre['value'], 'delivery-count-or-value')
    accepted = _join_delivery(events, delivery=delivery, component=access['source_component'],
        device=access['device_id'], address=access['address'], offset=access['register_offset'], write=False)
    raw_pre, raw_post = gpio_read_samples(events, target=target, component=access['target_component'],
        producer_event_id=delivery.get('producer_event_id'),
        signals=target_artifact.runtime_document['base_protocol_trace']['signals'],
        offset=access['register_offset'], value=pre['value'], reset_epoch=reset_epoch)
    commands = [command for command in target.native_reset_observation_commands()
        if command.get('target_epoch') == reset_epoch
        and before.document()['command_sequence'] < command.get('command_sequence', -1) <= target._sequence]
    _require([command['command_sequence'] for command in commands]
        == list(range(before.document()['command_sequence'] + 1, target._sequence + 1)), 'command-gap')
    accesses = []
    for command in commands:
        _require(command.get('status') == 'parsed_complete'
            and type(command.get('parsed_receipt_projection')) is dict, 'command-incomplete')
        fields = command.get('fields')
        if command['operation'] == 'ACCESS_GPIO':
            accesses.append(command)
            _require(type(fields) is list and len(fields) == 5
                and fields[1:] == [0, access['register_offset'], 0, 15], 'native-command')
        else:
            _require(command['operation'] == 'STEP_GPIO' and type(fields) is list
                and len(fields) == 1 and type(fields[0]) is int, 'unexpected-command')
    _require(len(accesses) == 1, 'native-command-count')
    samples = accesses[0]['parsed_receipt_projection']['payload']['samples']
    matches = [sample for sample in samples if sample['local_tick'] + target._tick_base == raw_pre['local_tick']]
    _require(len(matches) == 1, 'native-command-sample')
    for phase, row in (('pre', raw_pre), ('post', raw_post)):
        _require(matches[0][phase] == row['outputs'], 'native-sample-mismatch')
    post = actual_post
    volatile = {'local_tick', 'command_sequence'}
    if register == 'PADIN':
        volatile |= {'value', 'field_version', 'native_sample_version', 'input_sample', 'read_receipt','current_origins'}
        read = post['read_receipt']
        _require(read['local_tick'] == raw_pre['local_tick']
            and read['raw_pre'] == target._normalized_physical(raw_pre['outputs'])
            and read['raw_post'] == target._normalized_physical(raw_post['outputs']), 'actual-read-sample')
    _require(all(post[key] == value for key, value in pre.items() if key not in volatile), 'version-changed')
    _require(post['local_tick'] > before.document()['local_tick'] and post['local_tick'] >= raw_post['local_tick']
        and post['local_tick'] == target.local_ticks and post['command_sequence'] == target._sequence
        and post['command_sequence'] > before.document()['command_sequence']
        and target.process is not None and target.process.poll() is None
        and post['process_scope'] == dict(pid=target.process.pid, execution=target._execution), 'version-scope')
    ram = [row for row in events if row.get('kind') == 'memory_write'
        and row.get('component') == access['source_component']
        and row.get('address') == declaration['result_address'] and row.get('byte_enable') == 15
        and row.get('value') == pre['value'] ^ declaration['xor_constant']
        and row.get('event_id', 0) > delivery['event_id']]
    _require(len(ram) == 1, 'dependent-RAM-missing')
    del _BEFORE[before]
    join = dict(delivery_event=delivery['event_id'], acceptance_event=accepted['event_id'],
        native_APB_event=raw_pre['event_id'], native_post_event=raw_post['event_id'],
        source_transaction=deepcopy(delivery['source_transaction']), write=False, value=pre['value'])
    return dict(schema_version='compiled_F2_read_observation.v1', joins=[join],
        version_before=pre, version_witness=post,
        actual_read=deepcopy(post.get('read_receipt')) if register == 'PADIN' else None,
        RAM_event=ram[0]['event_id'], runtime_admitted=False), post
