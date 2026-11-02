"""GPIO F2 source admission and synthetic raw-receipt controls, no native RTL."""
from copy import deepcopy
from types import SimpleNamespace
import pytest

from tests.integration.test_compiled_f4_storage_producer import gpio_generated, ROOT


def test_gpio_f2_selects_and_constructs_existing_live_authority(gpio_generated, tmp_path):
    from myfuzz.integration.compiled_f2_consumer import select_f2_read_producer, build_f2_read_producer
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    artifacts, inputs = gpio_generated
    binding = select_f2_read_producer(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    assert binding.row == 'gpio_causal_read_abi'
    assert binding.document()['register']['name'] == 'PADIN'
    target, authority = build_f2_read_producer(binding, artifact=artifacts[binding.target_component],
        base_dir=ROOT, cache_dir=tmp_path, max_cases=2)
    assert type(target) is GeneratedPulpGpioSession
    assert type(authority) is GpioRegisterVersionAuthority
    with pytest.raises(ValueError, match='current-state-unavailable'):
        authority.issue(register='PADIN', reset_epoch=0)


def test_gpio_f2_stable_projection_keeps_version_removes_process_scope():
    from myfuzz.integration.compiled_f2_consumer import stable_f2_read_version
    from myfuzz.integration.gpio_f2_consumer import gpio_version_document
    raw = dict(register='GPIOEN', reset_epoch=0, value=42, local_tick=4,
        command_sequence=2, process_scope=dict(pid=1, execution='first'),
        source_sha256='a'*64, artifact_digest='b'*64, observation_contract={'real': 'probe'})
    before = gpio_version_document(raw, [])
    assert before['write_count'] == before['field_version'] == 0
    changed = deepcopy(before)
    changed['process_scope'] = dict(pid=2, execution='fresh')
    assert stable_f2_read_version(before) == stable_f2_read_version(changed)
    changed['field_version'] = 1
    assert stable_f2_read_version(before) != stable_f2_read_version(changed)


def raw_case(gpio_generated):
    artifacts, _ = gpio_generated
    artifact = next(a for a in artifacts.values() if a.runtime_document['kind'] == 'apb_gpio')
    signals = artifact.runtime_document['base_protocol_trace']['signals']
    from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES
    physical = {row['runtime_name']: 0 for row in artifact.runtime_document['physical_exports']}
    def set_probe(name, value):
        row = next(r for r in artifact.runtime_document['physical_exports'] if r['physical_port'] == 'gpio_probe_' + name)
        physical[row['runtime_name']] = value
    for name, value in dict(psel=1, penable=1, pready=1, pwrite=0,
        apb_addr=4, decoded_word=1, gpioen=42, prdata=42).items():
        set_probe(name, value)
    backend = {signals[k]: v for k, v in dict(psel=1, penable=1, pready=1,
        pwrite=0, paddr=4, prdata=42, pwdata=0, pslverr=0).items()}
    outputs = dict(physical=physical, backend=backend)
    rows = [dict(kind='local_tick_sample', component='gpio', phase=phase,
        local_tick=7, producer_event_id=10, reset_epoch=0,
        observation_schema_version='ip_raw_observation.v1', event_id=20+i,
        outputs=deepcopy(outputs)) for i, phase in enumerate(('pre', 'post'))]
    target = SimpleNamespace(_artifact_document=artifact.runtime_document)
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    target._normalized_physical = lambda value: GeneratedPulpGpioSession._normalized_physical(target, value)
    return target, signals, rows


def test_gpio_read_requires_native_pre_post_state(gpio_generated):
    from myfuzz.integration.gpio_f2_consumer import gpio_read_samples
    target, signals, rows = raw_case(gpio_generated)
    pre, post = gpio_read_samples(rows, target=target, component='gpio',
        producer_event_id=10, signals=signals, offset=4, value=42, reset_epoch=0)
    assert pre['event_id'] == 20 and post['event_id'] == 21


@pytest.mark.parametrize('mutation', ['missing_post', 'changed_version', 'wrong_read', 'wrong_epoch', 'raw_backend_drift'])
def test_gpio_read_rejects_counterfactual_raw_samples(gpio_generated, mutation):
    from myfuzz.integration.gpio_f2_consumer import gpio_read_samples
    target, signals, rows = raw_case(gpio_generated)
    if mutation == 'missing_post':
        rows.pop()
    elif mutation == 'wrong_epoch':
        rows[0]['reset_epoch'] = 1
    else:
        port = {'changed_version': 'gpio_probe_gpioen', 'wrong_read': 'gpio_probe_prdata',
                'raw_backend_drift': 'gpio_probe_apb_addr'}[mutation]
        runtime = next(r['runtime_name'] for r in target._artifact_document['physical_exports'] if r['physical_port'] == port)
        rows[-1 if mutation == 'changed_version' else 0]['outputs']['physical'][runtime] ^= 1
    with pytest.raises(ValueError, match='compiled-F2-GPIO-'):
        gpio_read_samples(rows, target=target, component='gpio', producer_event_id=10,
            signals=signals, offset=4, value=42, reset_epoch=0)


def native_padin_edge(previous=None, *, tick=1, pin=1, read=False):
    from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES
    from myfuzz.scenario.gpio_register_version import _advance_padin_sample
    pre = {'gpio_probe_' + name: 0 for name in PULP_GPIO_PROBES}
    pre['gpio_in'] = pin
    pre['gpio_probe_input_clock_enable'] = 1
    pre['gpio_probe_gpioen'] = 1
    if previous:
        for name, value in previous['post'].items():
            pre['gpio_probe_' + name] = value
    if read:
        pre.update(gpio_probe_psel=1, gpio_probe_penable=1, gpio_probe_pready=1,
            gpio_probe_decoded_word=2, gpio_probe_apb_addr=8,
            gpio_probe_prdata=pre['gpio_probe_padin_latch'])
    post = deepcopy(pre)
    post.update(gpio_probe_sync0=(pre['gpio_probe_sync0'] & ~15) | (pin & 15),
        gpio_probe_sync1=(pre['gpio_probe_sync1'] & ~15) | (pre['gpio_probe_sync0'] & 15),
        gpio_probe_padin_latch=(pre['gpio_probe_padin_latch'] & ~15) | (pre['gpio_probe_sync1'] & 15))
    state = _advance_padin_sample(previous, pre, post, tick=tick, sequence=tick,
        identity=('actual-process-double', 0), context={'source_event_id': 'pin-input',
            'segments': [dict(bit_lo=0, width=1, value=1)]})
    return state, pre, post


def test_padin_version_tracks_actual_pipeline_and_read_edge():
    state = None
    for tick in range(1, 5):
        state, _, _ = native_padin_edge(state, tick=tick, read=tick == 4)
    read = state['read']
    assert state['version'] == 4 and read['field_version'] == 3
    assert read['value'] == state['post']['padin_latch'] == 1
    assert read['pin_origins'][0] == dict(kind='native_pin_sample', pin=0,
        value=1, local_tick=1, source_context={'source_event_id': 'pin-input',
            'segments': [dict(bit_lo=0, width=1, value=1)]})
    # Equal-valued enabled updates still install another measured version.
    later, _, _ = native_padin_edge(state, tick=5)
    assert later['post']['padin_latch'] == 1 and later['version'] == 5
    assert later['read'] == read


@pytest.mark.parametrize('mutation', ['gap', 'host_value_instead_of_native_pipeline', 'wrong_prdata'])
def test_padin_reducer_refuses_unobserved_or_contradictory_updates(mutation):
    from myfuzz.scenario.gpio_register_version import _advance_padin_sample
    state, _, _ = native_padin_edge(tick=1)
    _, pre, post = native_padin_edge(state, tick=2, read=True)
    tick = 3 if mutation == 'gap' else 2
    if mutation == 'host_value_instead_of_native_pipeline':
        post['gpio_probe_padin_latch'] = pre['gpio_in']
    elif mutation == 'wrong_prdata':
        pre['gpio_probe_prdata'] ^= 1
    with pytest.raises(ValueError, match='PADIN-'):
        _advance_padin_sample(state, pre, post, tick=tick, sequence=2,
            identity=('actual-process-double', 0), context=None)


def mock_padin_consumer_case(gpio_generated, monkeypatch):
    """Synthetic receipt join only; authentication is explicitly a test double."""
    from myfuzz.integration import gpio_f2_consumer as consumer
    artifacts, _ = gpio_generated
    artifact = next(a for a in artifacts.values() if a.runtime_document['kind'] == 'apb_gpio')
    target = SimpleNamespace(artifact=artifact, _artifact_document=artifact.runtime_document,
        reset_epoch=0, _sequence=3, local_ticks=3, _tick_base=0, _execution='synthetic',
        base_dir=ROOT, process=SimpleNamespace(pid=71, poll=lambda: None))
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    target._normalized_physical = lambda snapshot: GeneratedPulpGpioSession._normalized_physical(target, snapshot)
    state = None
    for tick in range(1, 4):
        state, _, _ = native_padin_edge(state, tick=tick)
    prior = dict(register='PADIN', reset_epoch=0, value=state['post']['padin_latch'],
        local_tick=3, command_sequence=3, native_sample_version=3,
        source_sha256='a'*64, artifact_digest=artifact.runtime_document['artifact_digest'],
        observation_contract=consumer.pulp_gpio_observation_contract(),
        process_scope=dict(pid=71, execution='synthetic'), input_sample=state['input_sample'], read_receipt=None)
    state, pre, post = native_padin_edge(state, tick=4, read=True)
    after = dict(prior, local_tick=4, command_sequence=4, native_sample_version=4,
        input_sample=state['input_sample'], read_receipt=state['read'])
    token = object()
    authority = SimpleNamespace(target=target, writes=lambda: [], issue=lambda **kwargs: token,
        consume=lambda received: deepcopy(prior if target._sequence == 3 else after))
    monkeypatch.setattr(consumer, 'validate_gpio_authority', lambda value: None)
    before = consumer.capture_gpio_read_version(authority, register='PADIN', reset_epoch=0)
    target._sequence = target.local_ticks = 4
    signals = artifact.runtime_document['base_protocol_trace']['signals']
    def snapshot(probes):
        physical = {row['runtime_name']: probes[row['physical_port']]
            for row in artifact.runtime_document['physical_exports'] if row['physical_port'] in probes}
        backend = {signals[name]: probes['gpio_probe_' + ('apb_addr' if name == 'paddr' else name)]
            for name in ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'prdata', 'pwdata', 'pslverr')}
        return dict(physical=physical, backend=backend)
    native = dict(local_tick=4, pre=snapshot(pre), post=snapshot(post))
    command = dict(target_epoch=0, command_sequence=4, operation='ACCESS_GPIO',
        fields=[1, 0, 8, 0, 15], status='parsed_complete',
        parsed_receipt_projection=dict(payload=dict(samples=[deepcopy(native)])))
    target.native_reset_observation_commands = lambda: [command]
    tx = dict(execution_id='synthetic', testcase_id='case', source_component='cpu',
        source_epoch=0, channel_id='data', source_sequence=1)
    events = [dict(event_id=1, kind='mmio_acceptance', component='cpu', address=0x40000008,
        source_transaction=tx, write=False)]
    for event_id, phase in ((2, 'pre'), (3, 'post')):
        events.append(dict(event_id=event_id, kind='local_tick_sample', component='gpio',
            phase=phase, local_tick=4, producer_event_id=10, reset_epoch=0,
            observation_schema_version='ip_raw_observation.v1', outputs=deepcopy(native[phase])))
    events += [dict(event_id=4, kind='mmio_delivery', component='cpu', device_id='gpio',
        address=0x40000008, offset=8, write=False, byte_enable=15, read_value=1,
        source_transaction=tx, producer_event_id=10),
        dict(event_id=5, kind='memory_write', component='cpu', address=0x2000,
            byte_enable=15, value=1 ^ 0x5a5)]
    declaration = dict(candidate=dict(access=dict(source_component='cpu', target_component='gpio',
        device_id='gpio', address=0x40000008, register_offset=8)), result_address=0x2000, xor_constant=0x5a5)
    return consumer, declaration, SimpleNamespace(events=events), dict(target_artifact=artifact,
        authority=authority, token=token, before=before, register='PADIN', reset_epoch=0, prior_writes=0), command


def test_complete_mock_padin_consumption_uses_actual_read_version(gpio_generated, monkeypatch):
    consumer, declaration, receipt, kwargs, _ = mock_padin_consumer_case(gpio_generated, monkeypatch)
    observed, post = consumer.check_gpio_read_observation(declaration, receipt, **kwargs)
    assert observed['actual_read']['schema_version'] == 'gpio_PADIN_native_read_receipt.v1'
    assert observed['actual_read']['value'] == observed['version_before']['value'] == 1
    assert observed['version_before']['field_version'] == 3
    assert post['field_version'] == 4
    assert observed['RAM_event'] == 5 and observed['joins'][0]['native_APB_event'] == 2
    assert observed['runtime_admitted'] is False


def test_padin_context_must_match_actual_native_pin_sample():
    from myfuzz.scenario.gpio_register_version import _advance_padin_sample
    _, pre, post = native_padin_edge(tick=1, pin=0)
    state = _advance_padin_sample(None, pre, post, tick=1, sequence=1,
        identity=('actual-process-double', 0), context={'segments': [dict(bit_lo=0, width=1, value=1)]})
    assert state['input_sample']['value'] == 0
    assert state['input_sample']['source_context'] is None
    assert state['origins']['sync0'][0]['source_context'] is None


@pytest.mark.parametrize('mutation', ['command_gap', 'command_samples', 'dependent_ram', 'read_receipt'])
def test_complete_mock_padin_consumption_rejects_counterfactual(gpio_generated, monkeypatch, mutation):
    consumer, declaration, receipt, kwargs, command = mock_padin_consumer_case(gpio_generated, monkeypatch)
    if mutation == 'command_gap':
        command['command_sequence'] += 1
    elif mutation == 'command_samples':
        command['parsed_receipt_projection']['payload']['samples'][0]['pre']['backend']['foreign'] = 1
    elif mutation == 'dependent_ram':
        receipt.events[-1]['value'] ^= 1
    else:
        original = kwargs['authority'].consume
        def changed(token):
            value = original(token)
            value['read_receipt']['raw_pre']['gpio_probe_gpioen'] ^= 1
            return value
        kwargs['authority'].consume = changed
    with pytest.raises(ValueError, match='compiled-F2-GPIO-'):
        consumer.check_gpio_read_observation(declaration, receipt, **kwargs)


def test_gpio_typed_f2_retains_native_obi_and_dependent_store_hops(tmp_path, monkeypatch):
    from tests.integration.test_compiled_f2_read_response import _journal, _check
    from tests.integration import test_compiled_f4 as fixture
    monkeypatch.setattr(fixture, 'CONFIG', ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex')
    context = _journal(fixture.loaded(tmp_path))
    exact = _check(context)
    assert exact['data_hops'][0]['native_acceptance_event'] > 0
    assert exact['data_hops'][0]['native_response_event'] > 0
    assert exact['ram_write_hop']['memory_write_event'] > 0
