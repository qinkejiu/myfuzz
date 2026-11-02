"""Retirement-authority split for the shared ISR chain and the F6 return issuer.

The CV32E40P adapter observes only ``rvfi_valid/rvfi_order/rvfi_insn/
rvfi_pc_rdata`` and the real pre-edge ``irq_ack_o``/``irq_id_o``/exception-PC
probes.  These tests prove that a PC/order/insn-only ISR is accepted only when
its ordered retirements, ordered native data transactions and OBI beats agree
with the admitted firmware, and that every full-RVFI path keeps its exact
behaviour.
"""
from copy import deepcopy
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.integration import shared_irq_firmware as firmware_module
from myfuzz.integration import native_obi_hops, compiled_f4
from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.session_runtime import OnlineInstruction

ROOT = Path(__file__).resolve().parents[2]
LIMITED = 'pc_insn_order_only'
FULL = 'full_rvfi'
EXECUTION = 'a' * 32


def limited_contract():
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        cv32e40p_irq_receipt_contract)
    return cv32e40p_irq_receipt_contract()


def limited_artifact_profile():
    return SimpleNamespace(component_id='cv32e40p_rvfi_local')


def firmware():
    return firmware_module.build_irq_firmware(image_start=0x10000, image_end=0x40000,
        first_fetch=0x10080, gpio_base=0x40001000, pin=8)


def image_words(fw):
    words = {}
    for segment in fw['segments']:
        data = bytes.fromhex(segment['data_hex'])
        for offset in range(0, len(data), 4):
            words[segment['address'] + offset] = int.from_bytes(
                data[offset:offset + 4], 'little')
    return words


def isr_path(fw, entry_pc):
    """The declared (PC, word) path from the real entry PC, from the document."""
    handler = next(s for s in fw['segments'] if s['name'] == 'handler')
    data = bytes.fromhex(handler['data_hex'])
    handler_path = [(handler['address'] + i, int.from_bytes(data[i:i + 4], 'little'))
                    for i in range(0, len(data), 4)]
    if entry_pc == handler['address']:
        return handler_path
    words = image_words(fw)
    return [(entry_pc, words[entry_pc])] + handler_path


def declared_data_operations(fw):
    """Hand-derived ordered data operations of the fixed GPIO handler.

    Derived from the documented firmware layout: scratch is the saved-register
    block, ``gpio.base``+padin/status are the two read-clear reads, result+0/4
    store those read values and result+8 counts one increment.
    """
    scratch = fw['scratch']
    base = fw['gpio']['base']
    result = fw['result']
    return [
        dict(kind='write', address=scratch + 0, value=None),
        dict(kind='write', address=scratch + 4, value=None),
        dict(kind='write', address=scratch + 8, value=None),
        dict(kind='write', address=scratch + 12, value=None),
        dict(kind='read', address=base + 8, value=0x5a),
        dict(kind='write', address=result + 0, value=0x5a),
        dict(kind='read', address=base + 36, value=0x80),
        dict(kind='write', address=result + 4, value=0x80),
        dict(kind='read', address=result + 8, value=7),
        dict(kind='write', address=result + 8, value=8),
        dict(kind='read', address=scratch + 0, value=0x1000),
        dict(kind='read', address=scratch + 4, value=0x1001),
        dict(kind='read', address=scratch + 8, value=0x1002),
        dict(kind='read', address=scratch + 12, value=0x1003),
    ]


def transaction(sequence):
    return dict(execution_id='local-execution', testcase_id='one',
        source_component='cpu', source_epoch=0, channel_id='data',
        source_sequence=sequence)


def limited_world(monkeypatch, *, tamper=None):
    """Synthetic journal: real take probes, fixed firmware and native beats."""
    from myfuzz.scenario.source_provenance import SourceAdmission, AdmissionRegistry
    contract = limited_contract()
    fw = firmware()
    entry_pc = fw['vector'] + 44
    path = isr_path(fw, entry_pc)
    entry_word = path[0][1]
    operations = declared_data_operations(fw)
    handler_code = bytes.fromhex(
        next(s for s in fw['segments'] if s['name'] == 'handler')['data_hex'])
    assert len(handler_code) % 4 == 0
    assert path[-1][1] == 0x30200073 and path[0][0] == entry_pc
    # Successor support: the real memory service bytes of the resumed slot.
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x30000),),
        initialization_seed=0, max_initialized_bytes=0x30000)
    memory.declare_instruction_slots(0x11000, 4)
    service = MemoryService(memory, TransactionLedger())
    support = OnlineInstruction('fixed-nops', 'cpu', 0x11000, '13000000' * 4)
    service.accept_instructions(support.address, support.data,
        source_event_id=support.action_id)
    key = TransactionKey(execution_id='local-execution', testcase_id='one',
        source_component='cpu', source_epoch=0, channel_id='instr', source_sequence=1)
    snapshot = service.read(key, 0x11000, width_bytes=4)
    source_event = {**service.events[0], 'component': 'cpu', 'event_id': 1}
    instruction_read = {**next(e for e in service.events if e['kind'] == 'memory_read'),
        'component': 'cpu', 'event_id': 2996, 'producer_event_id': 2999}
    response = dict(kind='instr_response', component='cpu', event_id=3002,
        producer_event_id=3000, address=0x11000, rdata=0x13, error=0,
        response_tick=22, transaction=asdict(key),
        snapshot={**asdict(snapshot), 'value': snapshot.value,
                  'data_hex': snapshot.data.hex()})
    backend_step = dict(event_id=3000, component='cpu', local_tick=22,
        outputs=dict(driver_samples=[{'pre': {'backend': dict(i_rsp_valid=1,
            i_rsp_ready=1, i_rsp_error=0, i_rsp_rdata=0x13)}}],
            instr_rsp_consumed=1, instr_rsp_rdata=0x13,
            instr_rsp_source_sequence=1, instr_rsp_source_epoch=0))
    physical_step = dict(event_id=3001, component='cpu', local_tick=23)
    mret_order = len(path)
    successor = dict(kind='cpu_retire', component='cpu', event_id=300010,
        order=mret_order + 1, local_tick=24,
        receipt_id={'execution': EXECUTION, 'sequence': 124},
        pc_rdata=0x11000, insn=0x13, valid=1, schema_version='cpu_retire.v2',
        observation_contract=contract)

    events = [source_event, instruction_read, backend_step, physical_step,
              response, successor]
    # Real pre-edge acceptance of the receipt's own take.
    events.append(dict(event_id=3, component='cpu', local_tick=0, inputs={'irq': 1},
        outputs={'irq_taken_pre': 1}))
    events.append(dict(event_id=4, kind='gpio_irq_trigger', component='gpio',
        origin_status='known', local_tick=0))
    take_tick = 0
    events.append(dict(event_id=5, kind='cpu_external_irq_taken', component='cpu',
        producer_event_id=3, local_tick=take_tick, take_key=['cpu', 0, 1],
        receipt_id={'execution': EXECUTION, 'sequence': 1},
        source_epoch=0, reset_epoch=0, command_scope=dict(component='cpu',
            reset_epoch=0, command_sequence=1),
        irq_ack_pre=1, irq_id_pre=11, irq_entry_pc=entry_pc,
        irq_taken_pre=1, irq_redirect_pre=0, irq_redirect_cause=0))
    registry = AdmissionRegistry()
    admission = registry.register(SourceAdmission.create(case_id='one', case_index=0,
        source_id='pin8', path_id='pin-path', direction='IP_TO_CPU',
        component='gpio', action_id='one:pin', role='fuzz_source',
        input_kind='source_event', input_sha256='a' * 64))
    sample = dict(origin_status='known', origin_refs=[admission.document()], value=1)
    certificate = dict(proof_scope='irq_acceptance', status='observed',
        source_component='gpio', target_component='cpu', pin=8, reward_eligible=False,
        born=5, trigger_id='trigger-1',
        source_trigger=dict(trigger_id='trigger-1', trigger_event_id=4,
            observation_event_id=4, sample_event_id=4),
        source_epoch=0, target_epoch=0, input_event_id=3,
        source_origin_status='known',
        pin_causes=[dict(pin=8, current_sample=deepcopy(sample))],
        taken_event_id=5, native_take_event_id=5, take_key=['cpu', 0, 1])
    # Fixed retirements: entry trampoline plus the handler words. Ids are spaced
    # so the ordered native data transactions live strictly inside the window.
    for index, (pc, word) in enumerate(path):
        events.append(dict(event_id=100000 + 100 * index, kind='cpu_retire',
            component='cpu', pc_rdata=pc, insn=word, order=index + 1,
            valid=1, local_tick=1 + index, schema_version='cpu_retire.v2',
            observation_contract=contract,
            receipt_id={'execution': EXECUTION, 'sequence': 100 + index}))
    # Ordered native data transactions and their OBI beats.
    beats = {}
    next_id = 100001
    for index, operation in enumerate(operations):
        sequence = index + 1
        tx = transaction(sequence)
        write = operation['kind'] == 'write'
        value = operation['value'] if operation['value'] is not None else 0x1000 + index
        if operation['address'] >= fw['gpio']['base']:
            acceptance_id = next_id
            next_id += 1
        event_id = next_id
        next_id += 1
        beat = dict(acceptance_event=event_id - 1, response_event=event_id + 1,
            address=operation['address'], write=int(write), value=value,
            rdata=value, byte_enable=15)
        beats[('data', sequence)] = beat
        if operation['address'] >= fw['gpio']['base']:
            delivery = dict(event_id=event_id, kind='mmio_delivery', component='cpu',
                device_id='gpio', address=operation['address'],
                offset=operation['address'] - fw['gpio']['base'], write=write,
                byte_enable=15, read_value=value, source_transaction=deepcopy(tx))
            acceptance = dict(event_id=acceptance_id, kind='mmio_acceptance',
                component='cpu', producer_event_id=acceptance_id,
                source_transaction=deepcopy(tx), address=operation['address'],
                write=write)
            events.extend([acceptance, delivery])
        else:
            event = dict(event_id=event_id,
                kind='memory_write' if write else 'memory_read', component='cpu',
                address=operation['address'], producer_event_id=event_id - 1,
                transaction=deepcopy(tx), byte_enable=15, width_bytes=4)
            if write:
                event['value'] = value
            else:
                event.update(value=value, data_hex=value.to_bytes(4, 'little').hex())
            events.append(event)
    beats[('instr', 1)] = dict(address=0x11000, rdata=0x13, acceptance_event=2999,
        response_event=3001)
    events.sort(key=lambda row: row['event_id'])
    registry_path = 'pin-path'
    runtime = SimpleNamespace(
        artifacts={'cpu': SimpleNamespace(plan=SimpleNamespace(
            profile=limited_artifact_profile()))},
        session=SimpleNamespace(cases=[SimpleNamespace(case_id='one',
            source=SimpleNamespace(action_id='one:pin', value=1),
            support_instructions=(support,))]),
        f5_binding=SimpleNamespace(path={'runtime_path_identity': {
            'path_id': registry_path}}),
        _irq_firmware_enabled=True, runner=SimpleNamespace(
            sessions={'cpu': SimpleNamespace(memory=memory)},
            _provenance=SimpleNamespace(registry=registry),
            gpio_irq_dependency_evidence_report=lambda: dict(
                certificates=[deepcopy(certificate)])),
        irq_firmware=deepcopy(fw), cpu_id='cpu', target_id='gpio',
        access={'device_id': 'gpio'}, traces={}, error_policy={}, result=0x3fffc,
        image={'port': 'ram'})
    if tamper is not None:
        tamper(dict(events=events, beats=beats, path=path, fw=fw, runtime=runtime,
            operations=operations, contract=contract))
    monkeypatch.setattr(compiled_f4, '_borrow_exact_events',
        lambda runner: tuple(events))
    monkeypatch.setattr(native_obi_hops, 'collect_native_obi_beats',
        lambda *a, **k: beats)
    receipt = SimpleNamespace(events=tuple(events), case_id='one')
    return runtime, receipt, entry_pc, entry_word


def test_limited_contract_declares_the_pc_order_insn_authority():
    contract = limited_contract()
    assert contract['retirement_authority'] == LIMITED
    assert set(contract['retirement_fields']) == {'valid', 'order', 'insn', 'pc_rdata'}
    assert set(contract['unobserved_retirement_fields']) == {
        'intr', 'pc_wdata', 'trap', 'halt', 'mode', 'mem_addr', 'mem_rdata',
        'mem_wdata', 'mem_rmask', 'mem_wmask'}
    assert contract['retirement_diversion_fields'] == []
    assert contract['retirement_diversion_scope'] == 'unobservable'
    assert contract['decision_acceptance'] == dict(ack_probe='irq_ack_pre',
        id_probe='irq_id_pre', source_id=11, id_width=5, entry_pc_probe='irq_entry_pc')
    assert 'serial_observation' not in contract


def test_limited_authority_accepts_the_ordered_retirement_and_data_join(monkeypatch):
    runtime, receipt, entry_pc, entry_word = limited_world(monkeypatch)
    result = firmware_module.observe_irq_isr(runtime, receipt)
    assert result['status'] == 'verified', result.get('reason')
    assert result['retirement_authority'] == LIMITED
    certificate, = result['certificates']
    assert certificate['retirement_authority'] == LIMITED
    assert certificate['unobserved_fields'] == list(
        limited_contract()['unobserved_retirement_fields'])
    assert certificate['native_take_event_id'] == 5
    assert certificate['entry_retirement']['event_id'] == 100000
    assert certificate['entry_retirement']['pc'] == entry_pc
    assert certificate['entry_retirement']['insn'] == entry_word
    assert certificate['entry_retirement']['order'] == 1
    assert certificate['entry_retirement']['local_tick'] == 1
    assert [row['address'] for row in certificate['ordered_data_transactions']] == [
        row['address'] for row in declared_data_operations(firmware())]
    assert [row['offset'] for row in certificate['register_reads']] == [8, 36]
    assert [row['address'] for row in certificate['result_RAM']] == [
        firmware()['result'], firmware()['result'] + 4, firmware()['result'] + 8]
    assert certificate['per_retirement_join'] == 'unobservable'
    assert certificate['join_scope'] == 'ordered_retirement_to_actual_data_transaction'
    assert certificate['retirement_diversion_scope'] == 'unobservable'
    assert certificate['raw_mret_pc_wdata'] is None
    assert certificate['return_proof']['retirement_authority'] == LIMITED
    assert 'raw_mret_pc_wdata' not in certificate['return_proof'] or \
        certificate['return_proof']['raw_mret_pc_wdata'] is None
    assert result['reward_eligible'] is False and result['grants_prerequisites'] is False
    # No unobservable observation may be claimed as a value anywhere.
    assert _claimed_unobserved_keys(certificate) == set()


def _claimed_unobserved_keys(value):
    """Every dict key that would be a claimed value the CPU cannot observe."""
    forbidden = set(limited_contract()['unobserved_retirement_fields'])
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for key, child in node.items():
                if key in forbidden:
                    found.add(key)
                walk(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child)

    walk(value)
    return found


def _change_event(events, event_id, **fields):
    event = next(row for row in events if row['event_id'] == event_id)
    event.update(fields)


@pytest.mark.parametrize('fault', ['entry_pc', 'entry_insn', 'missing_mret',
    'successor_outside', 'successor_gap', 'redirect', 'data_missing', 'data_extra',
    'data_order', 'data_value', 'fabricated_mem', 'fabricated_intr',
    'take_ack', 'take_id', 'empty_unobserved'])
def test_limited_authority_refuses_unjoined_or_fabricated_evidence(monkeypatch, fault):
    def tamper(world):
        events, runtime = world['events'], world['runtime']
        path = world['path']
        if fault == 'entry_pc':
            # The real take names a different redirect target than the firmware.
            _change_event(events, 5, irq_entry_pc=path[0][0] + 4)
        elif fault == 'entry_insn':
            _change_event(events, 100000, insn=0x13)
        elif fault == 'missing_mret':
            mret = 100000 + 100 * (len(path) - 1)
            events.remove(next(row for row in events if row['event_id'] == mret))
        elif fault == 'successor_outside':
            _change_event(events, 300010, pc_rdata=0x11180)
        elif fault == 'successor_gap':
            _change_event(events, 300010, order=len(path) + 2)
        elif fault == 'redirect':
            events.append(dict(event_id=1500, kind='cpu_native_exception_redirect',
                component='cpu', local_tick=12, redirect_cause=2))
        elif fault == 'data_missing':
            events.remove(next(row for row in events
                if row.get('kind') == 'mmio_delivery'))
        elif fault == 'data_extra':
            events.append(dict(event_id=100030, kind='memory_write', component='cpu',
                address=0x3f000, value=1, byte_enable=15, producer_event_id=100029,
                transaction=transaction(99)))
            world['beats'][('data', 99)] = dict(acceptance_event=100029,
                response_event=100031, address=0x3f000, write=1, value=1, byte_enable=15)
        elif fault == 'data_order':
            first = next(row for row in events if row.get('kind') == 'mmio_delivery')
            first['source_transaction']['source_sequence'] = 99
        elif fault == 'data_value':
            write = next(row for row in events if row.get('kind') == 'memory_write'
                and row['address'] == firmware()['result'])
            write['value'] ^= 0x10
        elif fault == 'fabricated_mem':
            _change_event(events, 100100, mem_addr=firmware()['result'], mem_rmask=15,
                mem_rdata=0x5a)
        elif fault == 'fabricated_intr':
            _change_event(events, 100100, intr=0)
        elif fault == 'take_ack':
            _change_event(events, 5, irq_ack_pre=0)
        elif fault == 'take_id':
            _change_event(events, 5, irq_id_pre=12)
        if fault == 'empty_unobserved':
            # A limited adapter that cannot name its unobserved fields refuses.
            import myfuzz.local_harness.native_irq_receipt_contract as native
            mutated = limited_contract()
            mutated.pop('unobserved_retirement_fields')
            monkeypatch.setattr(native, 'native_irq_receipt_contract',
                lambda artifact: mutated)
    runtime, receipt, *_ = limited_world(monkeypatch, tamper=tamper)
    result = firmware_module.observe_irq_isr(runtime, receipt)
    assert result['status'] == 'unknown', result
    assert result['certificates'] == []
    assert result['reward_eligible'] is False


def test_full_rvfi_observer_keeps_exact_certificate_fields(monkeypatch):
    from tests.integration import test_shared_irq_firmware as existing
    runtime, receipt, *_ = existing.observer_world(monkeypatch)
    result = firmware_module.observe_irq_isr(runtime, receipt)
    assert result['status'] == 'verified', result.get('reason')
    assert result['retirement_authority'] == FULL
    certificate, = result['certificates']
    assert set(certificate) == {'status', 'case_id', 'native_IRQ', 'source_admission',
        'handler_retire_events', 'register_reads', 'result_RAM', 'mret_event',
        'raw_mret_pc_wdata', 'return_PC', 'return_proof'}
    assert certificate['raw_mret_pc_wdata'] == runtime.irq_firmware['dynamic_start']


# ---------------------------------------------------------------------------
# Successor field rules: the same rule under both retirement authorities.
# ---------------------------------------------------------------------------

def successor_pair():
    mret = dict(insn=0x30200073, order=10, local_tick=20,
        receipt_id={'execution': 'run', 'sequence': 20})
    successor = dict(order=11, local_tick=23,
        receipt_id={'execution': 'run', 'sequence': 23}, pc_rdata=0x11000,
        intr=0, irq_serial_observation={'retirement': {'status': 'observed', 'value': 0}})
    return mret, successor


def test_limited_successor_requires_no_intr_and_no_retirement_serial():
    from myfuzz.scenario.irq_return_successor import validate_return_successor
    mret, successor = successor_pair()
    for absent in ({}, {'irq_serial_observation': None},
                   {'irq_serial_observation': {'retirement': {'status': 'unobservable',
                                                              'value': None}}}):
        candidate = {key: value for key, value in successor.items()
                     if key not in ('intr', 'irq_serial_observation')}
        candidate.update(deepcopy(absent))
        assert validate_return_successor(mret, candidate, start=0x11000, end=0x11010,
            authority=LIMITED) == 0x11000
    for claimed in ({'intr': 0}, {'intr': 1},
                    {'irq_serial_observation': {'retirement': {'status': 'observed', 'value': 0}}},
                    {'irq_serial_observation': {'retirement': {'status': 'observed', 'value': 4}}},
                    {'irq_serial_observation': {'retirement': {'status': 'unobservable', 'value': 0}}}):
        candidate = {key: value for key, value in successor.items()
                     if key not in ('intr', 'irq_serial_observation')}
        candidate.update(claimed)
        with pytest.raises(ValueError):
            validate_return_successor(mret, candidate, start=0x11000, end=0x11010,
                authority=LIMITED)


@pytest.mark.parametrize('change', [{'order': 12}, {'pc_rdata': 0x10200},
    {'local_tick': 20}, {'receipt_id': {'execution': 'other', 'sequence': 23}},
    {'receipt_id': {'execution': 'run', 'sequence': 20}}])
def test_limited_successor_still_needs_the_immediate_current_return(change):
    from myfuzz.scenario.irq_return_successor import validate_return_successor
    mret, successor = successor_pair()
    candidate = {key: value for key, value in successor.items()
                 if key in ('order', 'local_tick', 'receipt_id', 'pc_rdata')}
    candidate.update(change)
    with pytest.raises(ValueError):
        validate_return_successor(mret, candidate, start=0x11000, end=0x11010,
            authority=LIMITED)


def test_missing_authority_declaration_keeps_the_legacy_full_rule():
    from myfuzz.scenario.irq_return_successor import retirement_authority
    assert retirement_authority(None) == FULL
    assert retirement_authority({}) == FULL
    assert retirement_authority({'retirement_authority': FULL}) == FULL
    with pytest.raises(ValueError):
        retirement_authority({'retirement_authority': 'invented'})


# ---------------------------------------------------------------------------
# F6 issuer under the real CV32E40P artifact and contract.
# ---------------------------------------------------------------------------

E40_PROFILE = 'configs/cpus/cv32e40p_rvfi_local/component_profile.json'


@lru_cache(maxsize=1)
def e40_artifact():
    from myfuzz.local_harness import (render_local_harness, render_local_runtime,
        verify_local_source_lock)
    from tests.local_harness.test_renderer import real_plan
    plan = real_plan(E40_PROFILE, 'processor')
    return render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)


def e40_f6_contract():
    from hashlib import sha256
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.scenario.native_f6_isr_return import _canonical
    from tests.integration.test_compiled_f6_contract import source_inputs, f6
    artifact = e40_artifact()
    _, compiled, _ = source_inputs()
    contract = deepcopy(f6(compiled)['execution_contract'])
    provider = native_irq_receipt_contract(artifact)
    contract['cpu'].update(instance_id='processor',
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        source_verification_sha256=sha256(_canonical(
            artifact.runtime_document['source_verification']).encode()).hexdigest(),
        native_irq_provider=provider)
    contract['irq'].update(native_take_provider=deepcopy(provider),
        consumer_instance='processor', consumer_port=provider['input_port'])
    contract['program_contract'].update(boot_address=0x10000,
        initial_image=[], initial_image_sha256=None)
    program = build_f6_firmware(contract)
    contract['program_contract'].update(
        initial_image=list(program.initial_segment_manifest),
        initial_image_sha256=program.manifest_sha256)
    return contract


def e40_session():
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from tests.local_harness.test_cpu_session import NAMES, Target
    artifact = e40_artifact()
    cpu = GeneratedCve2Session(artifact, base_dir=ROOT,
        cache_dir=Path('/tmp/e40-f6-retirement-only'),
        memory=PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
            initialization_seed=3, max_initialized_bytes=0x30000),
        router=DataflowRouter((DeviceWindow('target', 0x40000000, 0x1000,
            Target()),)), native_irq_receipts=True)
    cpu._case_id = 'stream'
    cpu._execution = EXECUTION
    return cpu


def e40_receipt(cpu, values, *, probes, rvfi, irq):
    from myfuzz.local_harness.wire import DriverReceipt
    from tests.local_harness.test_cpu_session import NAMES
    exports = cpu._artifact_document['physical_exports']
    physical = {row['runtime_name']: ('0' * row['hex_digits'] if row['width'] > 64 else 0)
                for row in exports}
    physical[cpu._irq_runtime_name] = irq
    physical.update({'probe_' + name: value for name, value in probes.items()})
    names = {row['physical_port']: row['runtime_name'] for row in exports}
    physical.update({names['rvfi_' + key]: value for key, value in rvfi.items()})
    post = deepcopy(physical)
    pre = dict.fromkeys(NAMES, 0)
    pre.update(zip(('i_req_ready', 'i_rsp_valid', 'i_rsp_rdata', 'i_rsp_error',
                    'd_req_ready', 'd_rsp_valid', 'd_rsp_rdata', 'd_rsp_error'),
                   values[1:]))
    # The backend response-ready line is not part of the command tuple; a
    # pending instruction response is consumed on this edge.
    pre['i_rsp_ready'] = values[2]
    pre['d_rsp_ready'] = values[6]
    tick = cpu.local_ticks - cpu._tick_base + 1
    sequence = cpu._sequence + 1
    payload = dict(kind='obi_cpu',
        samples=[dict(local_tick=tick, pre={'backend': pre, 'physical': physical},
                      post={'backend': pre, 'physical': post})],
        pre_backend=pre, observations={'backend': pre, 'physical': post},
        rdata=0, error=0)
    receipt = DriverReceipt('result', cpu._execution, sequence, tick - 1, tick, 1, payload)
    cpu._sequence = sequence
    cpu.local_ticks = cpu._tick_base + tick
    return receipt


DEFAULT_PROBES = dict(irq_masked_pre=0, irq_taken_pre=0, irq_ack_pre=0, irq_id_pre=0,
    irq_entry_pc=0, irq_redirect_pre=0, irq_redirect_cause=0)
DEFAULT_RVFI = dict(valid=0, order=0, insn=0, pc_rdata=0)


def e40_step(cpu, *, probes=None, rvfi=None, irq=1):
    all_probes = dict(DEFAULT_PROBES)
    all_probes.update(probes or {})
    fields = dict(DEFAULT_RVFI)
    fields.update(rvfi or {})
    with patch.object(cpu, 'command', side_effect=lambda op, values: e40_receipt(
            cpu, values, probes=all_probes, rvfi=fields, irq=values[0])):
        return cpu.step_local({'irq': irq})


def e40_take(cpu, contract, *, entry_pc=None, **fields):
    isr = contract['program_contract']['isr_address']
    probes = dict(irq_taken_pre=1, irq_ack_pre=1, irq_id_pre=11,
        irq_entry_pc=isr if entry_pc is None else entry_pc, irq_redirect_pre=0)
    probes.update(fields)
    e40_step(cpu, probes=probes)


def e40_entry(cpu, contract, *, order=1, insn=None, irq=0):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    p = contract['program_contract']
    word = (int.from_bytes(build_f6_firmware(contract).initial_images[p['isr_address']][:4],
        'little') if insn is None else insn)
    e40_step(cpu, rvfi=dict(valid=1, order=order, insn=word,
        pc_rdata=p['isr_address']), irq=irq)


def e40_mret(cpu, contract, *, order=2, irq=0):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    site = build_f6_firmware(contract).document()['isr']['mret_addresses'][0]
    e40_step(cpu, rvfi=dict(valid=1, order=order, insn=0x30200073,
        pc_rdata=site), irq=irq)


def e40_resume(cpu, contract, *, order=3, pc=None, response_word=0x13, irq=0):
    p = contract['program_contract']
    address = p['slot_base'] + p['online_prefix_bytes'] if pc is None else pc
    cpu.memory.preload(address & ~3, response_word.to_bytes(4, 'little'))
    cpu._pending_instr = cpu._serve('instr', 0, address, 0, 15)
    e40_step(cpu, rvfi=dict(valid=1, order=order, insn=0x13,
        pc_rdata=address), irq=irq)


def e40_install():
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return
    contract = e40_f6_contract()
    cpu = e40_session()
    issuer = install_f6_isr_return(cpu, contract=contract,
        execution_binding_sha256='b' * 64)
    issuer.begin_case('stream:case0', case_index=0,
        irq_take_key=['processor', 0, 1])
    return contract, cpu, issuer


def test_e40_limited_issuer_emits_pc_insn_order_evidence_only():
    contract, cpu, issuer = e40_install()
    e40_take(cpu, contract)
    e40_entry(cpu, contract)
    e40_mret(cpu, contract)
    e40_resume(cpu, contract)
    event, = issuer.events
    unobserved = limited_contract()['unobserved_retirement_fields']
    assert event['retirement_authority'] == LIMITED
    assert event['unobserved_fields'] == list(unobserved)
    assert event['retirement_diversion_scope'] == 'unobservable'
    for key in ('pc_wdata', 'intr', 'irq_serial_observation',
                'handler_entry_irq_serial_observation', 'take_irq_serial_observation',
                'successor_irq_serial_observation'):
        assert key not in event
    assert _claimed_unobserved_keys(event) == set()
    assert event['entry']['event_id'] is None
    assert event['mret_pc'] == event['pc_rdata'] == event['mret']['pc']
    assert event['entry']['pc'] == contract['program_contract']['isr_address']
    assert event['entry']['order'] == 1 and event['entry']['local_tick'] == 2
    assert event['handler_entry_pc_rdata'] == event['entry']['pc']
    assert event['successor_pc_rdata'] == (
        contract['program_contract']['slot_base']
        + contract['program_contract']['online_prefix_bytes'])
    assert event['successor_rvfi_order'] == event['rvfi_order'] + 1
    assert event['return_target_source'] == 'first_subsequent_valid_retirement_pc'
    assert event['take_pre_edge_observation']['irq_ack_pre'] == 1
    assert event['take_pre_edge_observation']['irq_id_pre'] == 11
    document = issuer.document()
    assert document['retirement_authority'] == LIMITED
    assert document['unobserved_fields'] == list(unobserved)
    assert document['retirement_diversion_scope'] == 'unobservable'
    assert document['decision_acceptance'] == limited_contract()['decision_acceptance']
    assert _claimed_unobserved_keys(document) == set()
    retire = next(row for row in cpu.cpu_events if row.get('kind') == 'cpu_retire')
    assert set(retire['observation']['physical']) == {'rvfi_valid', 'rvfi_order',
        'rvfi_insn', 'rvfi_pc_rdata'}


@pytest.mark.parametrize('mode', ['entry_pc', 'entry_insn', 'no_take',
    'successor_outside', 'successor_order', 'redirect', 'no_ack'])
def test_e40_limited_issuer_refuses_unjoined_return_evidence(mode):
    contract, cpu, issuer = e40_install()
    with pytest.raises((ValueError, Exception)):
        if mode == 'entry_pc':
            e40_take(cpu, contract, entry_pc=contract['program_contract']['isr_address'] + 4)
        elif mode == 'no_ack':
            e40_take(cpu, contract, irq_ack_pre=0)
        elif mode == 'no_take':
            e40_mret(cpu, contract)
        elif mode == 'entry_insn':
            e40_take(cpu, contract)
            e40_entry(cpu, contract, insn=0x13)
        elif mode == 'successor_outside':
            e40_take(cpu, contract)
            e40_entry(cpu, contract)
            e40_mret(cpu, contract)
            e40_resume(cpu, contract, pc=0x11180)
        elif mode == 'successor_order':
            e40_take(cpu, contract)
            e40_entry(cpu, contract)
            e40_mret(cpu, contract)
            e40_resume(cpu, contract, order=4)
        else:
            e40_take(cpu, contract)
            e40_entry(cpu, contract)
            e40_step(cpu, probes=dict(irq_redirect_pre=1, irq_redirect_cause=2))
            e40_mret(cpu, contract)
    assert issuer.events == ()


def test_e40_limited_issuer_without_the_fixed_MRET_issues_nothing():
    contract, cpu, issuer = e40_install()
    e40_take(cpu, contract)
    e40_entry(cpu, contract)
    e40_resume(cpu, contract, order=2)
    assert issuer.events == ()
    assert issuer.document()['retirement_authority'] == LIMITED


# ---------------------------------------------------------------------------
# Port-local host IRQ coordinates (CV32E40P DUT bit 11 -> host bit 0).
# ---------------------------------------------------------------------------

def _irq_artifact(port, *, width, bit_lo, bit_hi, direction='input'):
    return SimpleNamespace(runtime_document=dict(physical_exports=[
        dict(physical_port=port, direction=direction, width=width,
             bit_lo=bit_lo, bit_hi=bit_hi)]))


def _ownership_document(offset):
    return dict(fields=[dict(component_id='processor', port='irq_i', width=1)],
        owners=[dict(component_id='processor', port='irq_i', bit_offset=offset,
            width=1, kind='bound', producer_ref='peripheral.interrupt')])


def test_host_irq_offset_is_port_local_for_all_three_cpu_adapters():
    from myfuzz.integration.shared_f5_runtime import shared_f5_irq_host_offset
    # Ibex/CV32E20: declared at DUT/HOST bit 0.
    assert shared_f5_irq_host_offset(_irq_artifact('irq_external_i', width=1,
        bit_lo=0, bit_hi=0), port='irq_external_i', dut_offset=0) == 0
    # CV32E40P: the DUT vector bit is 11, the host port slice is bit 0.
    assert shared_f5_irq_host_offset(_irq_artifact('irq_i', width=1,
        bit_lo=11, bit_hi=11), port='irq_i', dut_offset=11) == 0


@pytest.mark.parametrize('artifact,dut_offset,port', [
    (_irq_artifact('irq_i', width=2, bit_lo=11, bit_hi=12), 11, 'irq_i'),
    (_irq_artifact('irq_i', width=1, bit_lo=11, bit_hi=11, direction='output'), 11, 'irq_i'),
    (_irq_artifact('irq_i', width=1, bit_lo=12, bit_hi=12), 11, 'irq_i'),
    (_irq_artifact('irq_i', width=1, bit_lo=11, bit_hi=11), 11, 'other_irq'),
])
def test_host_irq_offset_refuses_ambiguous_or_inconsistent_exports(artifact, dut_offset, port):
    from myfuzz.integration.shared_f5_runtime import shared_f5_irq_host_offset
    with pytest.raises(ValueError):
        shared_f5_irq_host_offset(artifact, port=port, dut_offset=dut_offset)


def test_e40_ownership_is_rewritten_in_port_local_coordinates():
    from myfuzz.integration.shared_f5_runtime import shared_f5_ownership_document
    e40 = _ownership_document(0)
    rewritten = shared_f5_ownership_document(e40, cpu_id='processor', port='irq_i',
        host_offset=0, expected_producer_ref='peripheral.interrupt',
        producer_ref='peripheral.irq')
    assert rewritten['owners'][0]['producer_ref'] == 'peripheral.irq'
    assert rewritten['owners'][0]['bit_offset'] == 0
    # The compiled document is unchanged; only the returned copy is rewritten.
    assert e40['owners'][0]['producer_ref'] == 'peripheral.interrupt'
    # The DUT-vector coordinate (11) is not a host ownership offset here.
    with pytest.raises(ValueError):
        shared_f5_ownership_document(_ownership_document(11), cpu_id='processor',
            port='irq_i', host_offset=0, expected_producer_ref='peripheral.interrupt',
            producer_ref='peripheral.irq')


def test_ibex_and_e20_keep_the_old_binding_and_ownership_documents():
    from myfuzz.integration.shared_f5_runtime import (shared_f5_irq_host_offset,
        shared_f5_ownership_document)
    from myfuzz.scenario.runner import Binding
    for port, bit in (('irq_external_i', 0), ('irq', 0)):
        artifact = _irq_artifact(port, width=1, bit_lo=bit, bit_hi=bit)
        host = shared_f5_irq_host_offset(artifact, port=port, dut_offset=bit)
        assert host == bit == 0
        binding = Binding('peripheral', 'interrupt', 'processor', port, 1, 0, host)
        assert (binding.target_bit_offset, binding.source_bit_offset) == (0, 0)
        document = dict(fields=[dict(component_id='processor', port=port, width=1)],
            owners=[dict(component_id='processor', port=port, bit_offset=0,
                width=1, kind='bound', producer_ref='peripheral.interrupt')])
        rewritten = shared_f5_ownership_document(document, cpu_id='processor',
            port=port, host_offset=host, expected_producer_ref='peripheral.interrupt',
            producer_ref='peripheral.irq')
        assert rewritten['owners'][0] == dict(component_id='processor', port=port,
            bit_offset=0, width=1, kind='bound', producer_ref='peripheral.irq')


def test_real_e40_artifact_cpu_irq_line_is_host_bit_zero():
    from myfuzz.integration.shared_f5_runtime import shared_f5_irq_host_offset
    artifact = e40_artifact()
    rows = [row for row in artifact.runtime_document['physical_exports']
            if row['physical_port'] == 'irq_i']
    assert len(rows) == 1 and rows[0]['width'] == 1
    assert (rows[0]['bit_lo'], rows[0]['bit_hi']) == (11, 11)
    # The compiled F5 node carries the same DUT bit; the host coordinate is 0.
    assert shared_f5_irq_host_offset(artifact, port='irq_i', dut_offset=11) == 0


def test_real_ibex_artifact_keeps_its_declared_cpu_irq_bit():
    from myfuzz.integration.shared_f5_runtime import shared_f5_irq_host_offset
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    artifact = _ibex_artifact()
    rows = [row for row in artifact.runtime_document['physical_exports']
            if row['physical_port'] == 'irq_external_i']
    assert len(rows) == 1 and rows[0]['width'] == 1
    assert shared_f5_irq_host_offset(artifact, port='irq_external_i',
        dut_offset=rows[0]['bit_lo']) == rows[0]['bit_lo'] == 0


@lru_cache(maxsize=1)
def _ibex_artifact():
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    return _artifact('configs/cpus/ibex_rvfi_local/component_profile.json', 'processor')


def test_f5_topology_validator_uses_the_port_local_cpu_bit():
    import inspect
    from myfuzz.integration import compiled_f5_crosswalk as crosswalk
    source = inspect.getsource(crosswalk._validate_f5_topology)
    assert 'shared_f5_irq_host_offset' in source
    assert 'binding.target_bit_offset == cpu_host_bit' in source
    assert 'binding.target_bit_offset == cpu[\'bit_offset\']' not in source
    assert "ownership.binding_producer(target['component'], cpu['port'], cpu_host_bit, 1)" in source
