from dataclasses import asdict
from pathlib import Path

import pytest

from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.pulp_gpio_dma_paths import PulpGpioDmaBeatAdmission
from test_wishbone_dma_transport import artifact

ROOT = Path(__file__).resolve().parents[2]
GPIO_BASE = 0x40001000
VALUE = 0xA55A3CC3


class ProviderTarget:
    def __init__(self, mutate=None):
        self.local_ticks = 0
        self.gpio_events = []
        self.uart_events = ()
        self.mutate = mutate
        self.calls = []
        self.profile = 'pulp-gpio-test-target'

    def identity_document(self):
        return {'component': 'gpio', 'profile': self.profile}

    def write_register(self, offset, value, *, be):
        raise AssertionError('provider must be used for this target')

    def dma_master_target_access(self, key, *, address, offset, write, value,
                                 byte_enable, delivery_context):
        self.calls.append((key, address, offset, write, value, byte_enable,
                           delivery_context))
        request = dict(address=address, offset=offset, write=write,
                       value=value, byte_enable=byte_enable)
        result = dict(schema_version='dma_master_target_access.v1',
            status='observed', source_transaction=asdict(key),
            request=request, response={'rdata': 0, 'error': 0},
            target_access_id='gpio-access:case:1',
            target_access={'status': 'observed',
                'source_transaction': asdict(key),
                'access_id': 'gpio-access:case:1'},
            target_request={'status': 'observed',
                'source_transaction': asdict(key),
                'access_id': 'gpio-access:case:1'},
            target_response={'status': 'observed',
                'source_transaction': asdict(key),
                'access_id': 'gpio-access:case:1'},
            target_effect={'status': 'observed',
                'source_transaction': asdict(key), 'request': request,
                'access_id': 'gpio-access:case:1'})
        if self.mutate is not None:
            self.mutate(result, key)
        self.local_ticks += 1
        self.gpio_events.append(result)
        return result


def _session(artifact, tmp_path, target, admission=None):
    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
        regions=(MemoryRegion('ram', 0x1000, 16),))
    window = MasterTargetWindow('gpio', GPIO_BASE, 0x1000, target,
        (12,), (VALUE,))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=memory, master_targets=(window,))
    if admission is not None:
        session.configure_dma_route_admission(admission)
    session._execution = 'provider-test-execution'
    session._case_id = 'provider-test-case'

    def command(op, fields):
        return DriverReceipt('result', session._execution, 1, 0, 1, 1,
            payload={'observations': {'backend': {'mwb_stb': 0}},
                'pre_backend': dict(mwb_cyc=1, mwb_stb=1, mwb_we=1,
                    mwb_adr=(GPIO_BASE + 12) >> 2, mwb_dat_w=VALUE)})

    session.command = command
    return session


def test_route_admission_is_called_before_target_and_completed_after_receipt(
        artifact, tmp_path):
    class Admission:
        def __init__(self):
            self.accepted_rows = []
            self.completed_rows = []
            self.selected_write_address = GPIO_BASE + 12

        def identity_document(self):
            return {'schema_version': 'test_dma_route_admission.v1',
                    'selected_write_address': self.selected_write_address}

        def accepted(self, key, **request):
            self.accepted_rows.append((key, request))

        def completed(self, key, **response):
            self.completed_rows.append((key, response))

    target = ProviderTarget()
    admission = Admission()
    session = _session(artifact, tmp_path, target, admission)

    session.step_local()

    key = TransactionKey(**session.events[0]['accepted']['transaction'])
    assert admission.accepted_rows == [(key, {
        'address': GPIO_BASE + 12, 'write': True, 'value': VALUE,
        'byte_enable': 15, 'target': session.master_targets[0]})]
    assert admission.completed_rows == [(key, {'rdata': 0, 'error': 0})]


def test_route_admission_replacement_is_caught_before_any_target_effect(
        artifact, tmp_path):
    class Admission:
        def identity_document(self):
            return {'schema_version': 'test_dma_route_admission.v1'}

        def accepted(self, key, **request):
            return None

        def completed(self, key, **response):
            return None

    target = ProviderTarget()
    session = _session(artifact, tmp_path, target, Admission())
    session._dma_route_admission = Admission()

    with pytest.raises(ValueError, match='route admission changed'):
        session.step_local()

    assert target.calls == []


def test_route_admission_strategy_mutation_is_rejected_before_target_effect(
        artifact, tmp_path):
    class Admission:
        def __init__(self):
            self.selected_write_address = GPIO_BASE + 12

        def identity_document(self):
            return {'schema_version': 'test_dma_route_admission.v1',
                    'selected_write_address': self.selected_write_address}

        def accepted(self, key, **request):
            return None

        def completed(self, key, **response):
            return None

    target = ProviderTarget()
    admission = Admission()
    session = _session(artifact, tmp_path, target, admission)
    admission.selected_write_address = GPIO_BASE + 16

    with pytest.raises(ValueError, match='route admission identity changed'):
        session.step_local()

    assert target.calls == []


@pytest.mark.parametrize('mutation', ['selected_address', 'window_base', 'target_profile'])
@pytest.mark.parametrize('validation_point', ['case', 'step'])
def test_pulp_admission_route_or_profile_drift_is_rejected_before_target_effect(
        artifact, tmp_path, mutation, validation_point):
    target = ProviderTarget()
    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
        regions=(MemoryRegion('ram', 0x1000, 16),))
    window = MasterTargetWindow('gpio', GPIO_BASE, 0x1000, target,
        (12,), (VALUE,))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=memory, master_targets=(window,))
    admission = PulpGpioDmaBeatAdmission(image_address=0x1000,
        gpio_window=window)
    session.configure_dma_route_admission(admission)
    if mutation == 'selected_address':
        object.__setattr__(admission, '_image_address', 0x1004)
    elif mutation == 'window_base':
        object.__setattr__(window, 'base', GPIO_BASE + 0x1000)
    else:
        target.profile = 'changed-pulp-gpio-profile'

    if validation_point == 'case':
        validate = lambda: session.begin_case('never-started')
    else:
        session._execution = 'pinned-admission-test'
        session._case_id = 'before-step'
        session.command = lambda *args, **kwargs: pytest.fail(
            'admission drift must be checked before the RTL command')
        validate = session.step_local
    with pytest.raises(ValueError, match='route admission identity changed'):
        validate()

    assert target.calls == []


def test_provider_receipt_joins_exact_accepted_dma_transaction(artifact, tmp_path):
    target = ProviderTarget()
    session = _session(artifact, tmp_path, target)

    session.step_local()

    accepted = session.events[0]['accepted']
    key = TransactionKey(**accepted['transaction'])
    assert target.calls == [(key, GPIO_BASE + 12, 12, True, VALUE, 15,
        {'source_transaction': asdict(key), 'device_id': 'gpio',
         'address': GPIO_BASE + 12, 'offset': 12, 'write': True,
         'value': VALUE, 'be': 15, 'window_base': GPIO_BASE,
         'window_size': 0x1000})]
    receipt = accepted['target_delivery']['target_provider_receipt']
    assert receipt['source_transaction'] == accepted['transaction']
    assert receipt['request'] == {'address': GPIO_BASE + 12, 'offset': 12,
        'write': True, 'value': VALUE, 'byte_enable': 15}
    assert receipt['target_effect']['request'] == receipt['request']
    assert session.pending_responses == 1


@pytest.mark.parametrize('mutation,match', [
    (lambda result, key: result.pop('target_effect'), 'receipt schema'),
    (lambda result, key: result.__setitem__('source_transaction',
        asdict(TransactionKey('other', key.testcase_id, key.source_component,
            key.source_epoch, key.channel_id, key.source_sequence))),
        'transaction key'),
    (lambda result, key: result['request'].__setitem__('address', GPIO_BASE),
        'request mismatch'),
    (lambda result, key: result['target_access'].__setitem__('status', 'incomplete'),
        'target evidence'),
    (lambda result, key: result['target_effect'].__setitem__('status', 'incomplete'),
        'target effect'),
    (lambda result, key: result['response'].__setitem__('error', 1),
        'target response'),
])
def test_provider_mismatch_never_creates_successful_dma_response(
        artifact, tmp_path, mutation, match):
    target = ProviderTarget(mutation)
    session = _session(artifact, tmp_path, target)

    with pytest.raises(RuntimeError, match=match):
        session.step_local()

    assert session.pending_responses == 0
    assert session.memory_service.ledger.unresolved_keys


@pytest.mark.parametrize('witness', ['target_request', 'target_response', 'target_effect'])
def test_provider_witnesses_must_join_the_same_target_access(
        artifact, tmp_path, witness):
    def mutate(result, _key):
        result[witness]['access_id'] = 'gpio-access:other'

    target = ProviderTarget(mutate)
    session = _session(artifact, tmp_path, target)

    with pytest.raises(RuntimeError, match='access identity mismatch'):
        session.step_local()

    assert session.pending_responses == 0
    assert session.memory_service.ledger.unresolved_keys


def test_full_32_bit_range_window_is_validated_without_enumeration(
        artifact, tmp_path):
    target = ProviderTarget()
    window = MasterTargetWindow('gpio', GPIO_BASE, 0x1000, target,
        (12,), range(0, 1 << 32))

    assert window.accepts(GPIO_BASE + 12, True, 0xffffffff, 15)
    assert window.accepts(GPIO_BASE + 12, True, 0, 15)
    assert not window.accepts(GPIO_BASE + 12, True, 1 << 32, 15)


def test_out_of_word_range_is_rejected(artifact, tmp_path):
    target = ProviderTarget()

    with pytest.raises(ValueError, match='invalid DMA master target window'):
        MasterTargetWindow('gpio', GPIO_BASE, 0x1000, target,
            (12,), range(-1, 1))
