"""Pure tests for the CVW directed session assembly.

The assembly has three declared pieces - a boot image, an instruction source and
a runner factory - plus the driver-side directed branch.  Everything here runs
without starting RTL: the boot image and the source are exercised against a real
``PersistentMemory`` and a stub session, the driver branch against a stub entry
inside a temporary heavy-worker lock, and the session assertions/receipts against
synthetic evidence.  The real session itself is
``tests/integration/test_cvw_runtime_family.py::test_the_family_cli_starts_a_real_directed_session_and_grades_f4``
under ``MYFUZZ_SCENARIO_REAL=1``.
"""
from __future__ import annotations

import json
from pathlib import Path
import types

import pytest

from myfuzz.integration import cvw_directed_session as directed
from myfuzz.integration import cvw_pulp_online as family_module
from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
                                                    RuntimeFamily,
                                                    run_directed_family_session)
from myfuzz.scenario import cvw_session
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# the boot image
# ---------------------------------------------------------------------------

def test_the_boot_image_is_derived_from_the_family_declaration():
    image = cvw_session.make_cvw_boot_image()
    wiring = family_module.cvw_pulp_gpio_wiring()
    assert image.base == wiring.boot_base == 0xC0000000
    assert image.result == 0xC0000400
    assert image.gpio_base == wiring.window_base == 0xCFFF0000
    assert len(image.data) == 256 and image.words == 64
    declaration = image.document()
    assert declaration['schema_version'] == 'cvw_boot_image.v1'
    assert declaration['sha256'] == image.sha256
    assert declaration['source'].endswith(':cvw_gpio_program')
    # The result window the directed session reads back is disjoint.
    assert image.result >= image.base + len(image.data)
    memory = PersistentMemory(regions=(MemoryRegion('ram', image.base, 0x1000),),
                              initialization_seed=7, max_initialized_bytes=0x1000)
    image.install_result_window(memory)
    assert [memory.read(image.result + offset, 4,
                        transaction_id=f'pure-{offset}').value
            for offset in (0, 4, 8, 12)] == [0, 0, 0, 0]


def test_the_boot_image_refuses_a_result_window_over_the_program():
    image = cvw_session.make_cvw_boot_image()
    with pytest.raises(ValueError, match='overlaps'):
        cvw_session.CvwBootImage(base=image.base, result=image.base + 8,
                                 data=image.data, source='test',
                                 gpio_base=image.gpio_base)


@pytest.mark.parametrize('field,value,match', [
    ('base', 0xC0000002, 'aligned'),
    ('result', 0xC0000001, 'aligned'),
    ('data', b'\x01\x02\x03', 'words'),
    ('data', b'', 'words'),
    ('source', '', 'provenance'),
])
def test_the_boot_image_refuses_a_malformed_declaration(field, value, match):
    image = cvw_session.make_cvw_boot_image()
    arguments = dict(base=image.base, result=image.result, data=image.data,
                     source=image.source, gpio_base=image.gpio_base)
    arguments[field] = value
    with pytest.raises(ValueError, match=match):
        cvw_session.CvwBootImage(**arguments)


def test_a_mutated_wiring_moves_the_derived_image(monkeypatch):
    def moved():
        return types.SimpleNamespace(boot_base=0xC1000000,
                                     window_base=0xC1FFF000)

    monkeypatch.setattr(cvw_session, 'cvw_pulp_gpio_wiring', moved)
    image = cvw_session.make_cvw_boot_image()
    assert image.base == 0xC1000000
    assert image.gpio_base == 0xC1FFF000
    # The derived result window follows the derived base; it is never a literal.
    assert image.result == 0xC1000000 + 0x400


# ---------------------------------------------------------------------------
# the instruction source
# ---------------------------------------------------------------------------

class _StubSession:
    """The exact surface the source reads, with a real persistent memory."""

    def __init__(self, image, *, slots=()):
        self.memory = PersistentMemory(
            regions=(MemoryRegion('ram', image.base, 0x2000),),
            initialization_seed=7, max_initialized_bytes=0x2000)
        self.memory.declare_instruction_slots(image.base, 1)
        for address, count in slots:
            self.memory.declare_instruction_slots(address, count)
        self.boot_base = image.base
        self.instruction_hold_ticks = 0
        self.last_samples = ()

    def measured_request_address(self):
        if not self.last_samples:
            return None
        backend = self.last_samples[0].get('pre', {}).get('backend', {})
        return backend.get('m_req_addr') if backend.get('m_req_valid') == 1 else None


def test_the_source_does_not_supply_a_word_nobody_asked_for():
    image = cvw_session.make_cvw_boot_image()
    session = _StubSession(image)
    source = cvw_session.CvwBootInstructionSource(image)
    source.before_step(session)
    assert session.memory.instruction_slot_unmaterialized(image.base) is True
    assert source.evidence()['delivered'] is False
    assert source.evidence()['first_measured_fetch_address'] is None


def test_the_source_supplies_the_image_on_the_measured_reset_vector():
    image = cvw_session.make_cvw_boot_image()
    session = _StubSession(image)
    source = cvw_session.CvwBootInstructionSource(image)
    source.before_step(session)                       # nothing measured yet
    session.instruction_hold_ticks = 2
    session.last_samples = ({'pre': {'backend': {
        'm_req_valid': 1, 'm_req_addr': image.base}}},)
    source.before_step(session)
    evidence = source.evidence()
    assert evidence['delivered'] is True
    assert evidence['first_measured_fetch_address'] == image.base
    assert evidence['hold_ticks_before_delivery'] == 2
    # The reset word went through the validated online-slot interface; every
    # following declared byte is the fixed initial image.
    assert session.memory.read(image.base, 4, transaction_id='boot').value \
        == int.from_bytes(image.data[:4], 'little')
    assert session.memory.read(image.base + 4, 4,
                               transaction_id='rest').value \
        == int.from_bytes(image.data[4:8], 'little')
    # A measured request outside the declared reset vector is refused, not
    # adapted into a supply for a different address.
    other = _StubSession(image)
    other.last_samples = ({'pre': {'backend': {
        'm_req_valid': 1, 'm_req_addr': image.base + 4}}},)
    with pytest.raises(ValueError, match='declared reset vector'):
        cvw_session.CvwBootInstructionSource(image).before_step(other)


def test_the_source_records_only_real_accepted_beats_and_can_reset():
    image = cvw_session.make_cvw_boot_image()
    source = cvw_session.CvwBootInstructionSource(image)
    source.after_step(None, {'data_req_valid': 1, 'data_addr': image.base,
                             'data_req_accepted': False})
    assert source.evidence()['first_presented_address'] == image.base
    source.after_step(None, {'data_req_valid': 1, 'data_addr': image.base + 8,
                             'data_req_accepted': True, 'data_write': False,
                             'data_wdata': 0, 'data_be': 15})
    evidence = source.evidence()
    assert evidence['accepted_count'] == 1
    assert evidence['fetch_addresses_from_image'] == [image.base + 8]
    source.reset()
    assert source.evidence()['accepted_count'] == 0
    assert source.evidence()['delivered'] is False


# ---------------------------------------------------------------------------
# the AHB session's hold generalization
# ---------------------------------------------------------------------------

def test_the_hold_covers_a_declared_unfilled_slot_only_with_a_source():
    image = cvw_session.make_cvw_boot_image()
    session = _StubSession(image, slots=((image.base + 8, 1),))

    class Holder(_StubSession):
        instruction_source = None
        boot_base = image.base

        def _instruction_slot_required(self, address):
            return self.memory.instruction_slot_unmaterialized(address)

        def _boot_word_required(self):
            # Pretend the reset word was already supplied, so the only thing
            # left to hold is the measured non-boot slot.
            return False

    holder = Holder.__new__(Holder)
    holder.memory = session.memory
    holder.instruction_hold_ticks = 0
    holder.last_samples = ({'pre': {'backend': {
        'm_req_valid': 1, 'm_req_addr': image.base + 8}}},)
    holder._measured_request = lambda: (image.base + 8, False)
    # Without a declared source the measured non-boot slot is not held: the
    # previous behaviour is preserved byte for byte.
    assert GeneratedAhbMemorySession._held_instruction_address(holder) is None
    holder.instruction_source = cvw_session.CvwBootInstructionSource(image)
    assert GeneratedAhbMemorySession._held_instruction_address(holder) \
        == image.base + 8
    # A write to the same declared unfilled slot is served, never held.
    holder._measured_request = lambda: (image.base + 8, True)
    assert GeneratedAhbMemorySession._held_instruction_address(holder) is None


def test_the_session_measured_request_address_reads_the_pre_phase():
    class Sample:
        last_samples = ({'pre': {'backend': {'m_req_valid': 1,
                                             'm_req_addr': 0xC0000000}}},)
        _measured_request = GeneratedAhbMemorySession._measured_request

    assert GeneratedAhbMemorySession.measured_request_address(Sample()) \
        == 0xC0000000
    assert GeneratedAhbMemorySession._measured_request(Sample()) == \
        (0xC0000000, False)
    Sample.last_samples = ({'pre': {'backend': {
        'm_req_valid': 1, 'm_req_addr': 0xC0000000, 'm_req_write': 1}}},)
    assert GeneratedAhbMemorySession._measured_request(Sample()) == \
        (0xC0000000, True)
    Sample.last_samples = ({'pre': {'backend': {'m_req_valid': 0}}},)
    assert GeneratedAhbMemorySession.measured_request_address(Sample()) is None
    Sample.last_samples = ()
    assert GeneratedAhbMemorySession.measured_request_address(Sample()) is None


# ---------------------------------------------------------------------------
# the directed-session document logic
# ---------------------------------------------------------------------------

def _evidence():
    deliveries = [
        {'offset': 0, 'write': True, 'write_value': 0xFFFFFFFF, 'read_value': None},
        {'offset': 4, 'write': True, 'write_value': 0xFFFFFFFF, 'read_value': None},
        {'offset': 12, 'write': True, 'write_value': 0x35, 'read_value': None},
        {'offset': 12, 'write': False, 'write_value': None, 'read_value': 0x35},
        {'offset': 12, 'write': True, 'write_value': 0x6A, 'read_value': None},
        {'offset': 12, 'write': False, 'write_value': None, 'read_value': 0x6A},
        {'offset': 8, 'write': False, 'write_value': None, 'read_value': 0xA5},
    ]
    return {
        'run_id': 'pure-run', 'case_id': 'pure-case',
        'case_kind': 'directed_fixed_image', 'flow_id': 'F4',
        'direction': 'CPU_TO_IP', 'elapsed_seconds': 1.0, 'cpu_steps': 100,
        'local_ticks': {'cpu': 100, 'gpio': 100},
        'result_words': [0x35, 0x6A, 1, 0xA5], 'result_state': 'success',
        'external_pin_value': 0xA5,
        'final_target_state': {'gpio_out': 0x6A, 'gpio_dir': 0xFFFFFFFF,
                               'gpio_in_sync': 0xA5, 'rdata': 0},
        'accepted_beats': [{'step': 1, 'address': 0xC0000000, 'write': False,
                            'value': 0, 'byte_enable': 15}],
        'accepted_beat_count': 1,
        'deliveries': deliveries, 'delivery_count': len(deliveries),
        'cpu': {'accepted_addresses': [0xC0000000],
                'memory_writes': [{'address': 0xC0000408, 'value': 1,
                                   'byte_enable': 15, 'width_bytes': 4}],
                'pending_responses': 0, 'mmio_write_count': 3,
                'mmio_read_count': 3, 'instruction_hold_ticks': 1,
                'instruction_hold_addresses': [0xC0000000]},
        'instruction_source': {
            'schema_version': 'cvw_boot_instruction_source_evidence.v1',
            'boot_image_sha256': 'a' * 64, 'delivered': True,
            'delivered_step': 2, 'hold_ticks_before_delivery': 1,
            'first_presented_address': 0xC0000000, 'first_presented_step': 1,
            'first_measured_fetch_address': 0xC0000000,
            'instruction_steps': 2, 'accepted_beats': [],
            'accepted_count': 0,
            'fetch_addresses_from_image': [0xC0000000],
            'fetch_count_from_image': 1},
        'artifact_digests': {'cpu': 'b' * 64, 'gpio': 'c' * 64},
        'identities': {
            'cpu': {'runtime_artifact': {'boot_contract': {
                'configured_boot_base': 0xC0000000}},
                'execution_id': 'volatile'},
            'gpio': {'gpio_target_context_schema_version': 'x',
                     'execution_id': 'volatile'},
            'memory': {'initialization_seed': 7}},
        'error': None,
    }


def test_the_interaction_assertion_accepts_a_real_sequence():
    directed._assert_interaction(_evidence())


@pytest.mark.parametrize('mutation,message', [
    (lambda e: e.update(deliveries=[]), 'no CPU'),
    (lambda e: e.update(result_words=[0, 0, 0, 0]), 'result words'),
    (lambda e: e['deliveries'].__setitem__(2, {**e['deliveries'][2],
                                               'write_value': 0x36}),
     'delivery sequence'),
    (lambda e: e['deliveries'].__setitem__(3, {**e['deliveries'][3],
                                               'read_value': 0x36}),
     'delivery sequence'),
    (lambda e: e['final_target_state'].update(gpio_out=0), 'output'),
    (lambda e: e['final_target_state'].update(gpio_dir=0), 'direction'),
    (lambda e: e['instruction_source'].update(delivered=False), 'never supplied'),
    (lambda e: e['instruction_source'].update(
        first_measured_fetch_address=0xC0000004), 'first measured fetch'),
    (lambda e: e['instruction_source'].update(
        hold_ticks_before_delivery=None), 'never held'),
])
def test_the_interaction_assertion_refuses_an_untrue_sequence(mutation, message):
    evidence = _evidence()
    mutation(evidence)
    with pytest.raises(RuntimeError, match=message):
        directed._assert_interaction(evidence)


def test_the_observable_projection_scrubs_run_identity_and_detects_change():
    first = _evidence()
    fresh = _evidence()
    fresh['run_id'] = 'another-run'
    fresh['case_id'] = 'another-case'
    fresh['identities']['cpu']['execution_id'] = 'another-volatile'
    comparison = directed._compare(first, fresh)
    assert comparison['matches'] is True
    assert comparison['first_difference'] is None
    assert comparison['event_count'] > 0
    fresh['final_target_state']['gpio_out'] = 0
    comparison = directed._compare(first, fresh)
    assert comparison['matches'] is False
    assert comparison['first_difference'] == 'final_target_state'
    assert comparison['difference_context'] is not None


def test_the_receipt_names_a_real_f4_edge_and_the_report_is_honest():
    evidence = _evidence()
    receipt = directed._receipt(
        evidence, path_id='F4:ram.image',
        assembly_document={'schema_version': 'cvw_session_assembly.v1'})
    assert receipt['schema_version'] == directed.RECEIPT_SCHEMA
    assert receipt['flow_id'] == 'F4' and receipt['direction'] == 'CPU_TO_IP'
    assert receipt['candidate_disposition_reason'] == 'rtl_case_committed'
    assert receipt['local_ticks'] == {'cpu': 100, 'gpio': 100}
    assert receipt['total_local_ticks'] == 200
    assert receipt['interaction_new_features'] == [
        'cpu:gpio:apb00_write', 'cpu:gpio:apb04_write',
        'cpu:gpio:apb0c_write', 'cpu:gpio:apb0c_read',
        'cpu:gpio:apb08_read']
    comparison = directed._compare(evidence, _evidence())
    report = directed._report(
        evidence, receipt=receipt,
        assembly_document={'schema_version': 'cvw_session_assembly.v1'},
        first_elapsed=1.0, fresh_elapsed=2.0, comparison=comparison)
    assert report['execution_mode'] == 'directed_fixed_image'
    assert report['tests'] == 1 and report['statuses'] == {'complete': 1}
    assert report['elapsed_seconds'] == 3.0
    assert report['record_semantics']['candidate_disposition_reason'] == \
        'rtl_case_committed'
    assert report['fresh_replay']['matches'] is True
    assert report['not_claimed'] == list(directed.NOT_CLAIMED)
    assert 'no RFuzz online campaign' in report['not_claimed'][0]


def test_the_compiled_f4_path_id_is_the_single_executable_f4():
    document = {'paths': [
        {'path_id': 'F1:ram.image', 'flow_id': 'F1', 'status': 'executable'},
        {'path_id': 'F4:ram.image', 'flow_id': 'F4', 'status': 'executable'},
        {'path_id': 'F5:processor', 'flow_id': 'F5', 'status': 'unsupported'}]}
    assert directed._compiled_f4_path_id(document) == 'F4:ram.image'
    document['paths'].append({'path_id': 'F4:other', 'flow_id': 'F4',
                              'status': 'executable'})
    assert directed._compiled_f4_path_id(document) is None
    assert directed._compiled_f4_path_id(None) is None


# ---------------------------------------------------------------------------
# the driver's directed branch
# ---------------------------------------------------------------------------

def _stub_family(entry='pure_stub:entry'):
    class StubFamily(RuntimeFamily):
        def directed_session_entry(self):
            return entry

    return StubFamily(
        family_id='pure-directed', cpu_component_id='cvw', cpu_profile='x',
        device_component_id='gpio', device_protocol=('apb', '3'),
        device_endpoint_function='mmio_slave',
        cpu_master_protocol=('ahb-lite', '1'),
        wiring_declaration='x:y', runtime_entry='x:y', replay_entry='x:z',
        session_assembly='myfuzz.integration.cvw_pulp_online:CVW_SESSION_ASSEMBLY')


def test_the_driver_runs_a_declared_directed_entry_inside_the_heavy_lock(
        tmp_path, monkeypatch):
    calls = {}

    def entry(**kwargs):
        calls.update(kwargs)
        Path(kwargs['session_dir']).mkdir()
        return {'report': {'tests': 1},
                'fresh_verification': {'matches': True},
                'assembly': {'kind': 'directed_fixed_image'}}

    module = types.ModuleType('pure_stub')
    module.entry = entry
    monkeypatch.setitem(__import__('sys').modules, 'pure_stub', module)
    import myfuzz.local_harness.generated_artifact_admission as admission
    monkeypatch.setattr(admission, 'load_generated_artifacts',
                        lambda **kwargs: {'cpu': object(), 'gpio': object()})
    (tmp_path / 'generated').mkdir()
    (tmp_path / 'cache').mkdir()
    outcome = run_directed_family_session(
        family=_stub_family(), output_dir=tmp_path,
        session_dir=tmp_path / 'session', cache_dir=tmp_path / 'cache',
        run_id='pure', budget_seconds=1.0, base_dir=tmp_path)
    assert outcome['report'] == {'tests': 1}
    assert calls['run_id'] == 'pure'
    assert calls['generated_artifacts'].keys() == {'cpu', 'gpio'}
    assert (tmp_path / '.superpowers' / 'sdd' /
            'stage2-heavy-worker.lock').is_file()


def test_the_driver_refuses_a_family_without_a_resolvable_assembly(tmp_path):
    class NoAssembly(RuntimeFamily):
        def session_assembly_document(self):
            return {'status': 'unavailable', 'declaration': 'x:y',
                    'error': 'missing'}

        def directed_session_entry(self):
            return 'pure_stub:entry'

    family = NoAssembly(
        family_id='pure-directed', cpu_component_id='cvw', cpu_profile='x',
        device_component_id='gpio', device_protocol=('apb', '3'),
        device_endpoint_function='mmio_slave',
        cpu_master_protocol=('ahb-lite', '1'),
        wiring_declaration='x:y', runtime_entry='x:y', replay_entry='x:z')
    with pytest.raises(AutoHarnessRefused) as raised:
        run_directed_family_session(
            family=family, output_dir=tmp_path,
            session_dir=tmp_path / 'session', cache_dir=tmp_path,
            run_id='pure', budget_seconds=1.0, base_dir=tmp_path)
    assert raised.value.code == 'directed-session-assembly-unavailable'
    assert raised.value.pointer == '/runtime'


def test_the_direct_bundle_names_every_directed_document(tmp_path):
    from myfuzz.local_harness.auto_harness_test import write_directed_bundle
    session = tmp_path / 'session'
    session.mkdir()
    (session / 'report.json').write_text('{}\n', encoding='utf-8')
    (session / 'receipts.jsonl').write_text('{"case_id":"x"}\n', encoding='utf-8')
    (session / 'directed-session.json').write_text('{}\n', encoding='utf-8')
    fresh = tmp_path / 'fresh-verification.json'
    fresh.write_text('{"matches":true}\n', encoding='utf-8')
    manifest = write_directed_bundle(
        session_dir=session, fresh_verification_path=fresh,
        bundle_dir=tmp_path / 'bundle')
    assert manifest['schema_version'] == 'directed_session_bundle.v1'
    assert manifest['authenticated_online_prefix'] is False
    assert {row['name'] for row in manifest['files']} == {
        'report.json', 'receipts.jsonl', 'directed-session.json',
        'fresh-verification.json'}
    assert all(row['matches_session'] for row in manifest['files'])
