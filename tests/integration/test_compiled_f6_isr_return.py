"""Synthetic parsed receipts exercise the source-backed narrow F6 issuer only."""
from copy import deepcopy
from dataclasses import replace
import importlib
import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from tests.local_harness import test_cpu_native_irq_receipt as irq_tests
from tests.integration.test_compiled_f6_contract import source_inputs, f6, ROOT


def module():
    name = 'myfuzz.scenario.native_f6_isr_return'
    assert importlib.util.find_spec(name) is not None, 'F6 MRET issuer is not installed'
    return importlib.import_module(name)


@pytest.fixture(autouse=True)
def no_build_identity(monkeypatch):
    # identity_document's build admission would invoke a frontend. This suite
    # tests source/receipt authority; no built-process identity is claimed.
    monkeypatch.setattr('myfuzz.local_harness.session.local_build_identity',
        lambda *a, **k: {'software_test_boundary': True})


@pytest.fixture(scope='module')
def inputs():
    _, compiled, artifacts = source_inputs()
    return f6(compiled)['execution_contract'], artifacts['cpu']


def make_setup(inputs):
    contract, artifact = inputs
    session = GeneratedCve2Session(artifact, base_dir=ROOT,
        cache_dir=Path('/tmp/f6-isr-return-unused'),
        memory=PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
            initialization_seed=3, max_initialized_bytes=0x30000),
        router=DataflowRouter((DeviceWindow('target', 0x40000000, 0x1000,
            irq_tests.Target()),)), native_irq_receipts=True)
    session._case_id = 'stream'
    session._execution = 'a' * 32
    return deepcopy(contract), session, irq_tests.CpuNativeIrqReceiptTests()


@pytest.fixture
def setup(inputs):
    return make_setup(inputs)


def install(setup):
    contract, session, helper = setup
    issuer = module().install_f6_isr_return(session, contract=contract,
        execution_binding_sha256='b' * 64)
    issuer.begin_case('stream:case0', case_index=0, irq_take_key=['cpu', 0, 1])
    return contract, session, helper, issuer


def mutation(session, **overrides):
    def mutate(payload, irq):
        names = {r['physical_port']: r['runtime_name']
                 for r in session._artifact_document['physical_exports']}
        pre, post = [payload['samples'][0][phase]['physical'] for phase in ('pre', 'post')]
        pre[names['irq_decision_serial']] = overrides.get('take_serial', 4)
        post[names['irq_retirement_serial']] = overrides.get('return_serial', 4)
        fields = {'rvfi_mode': 3, **{name: value for name, value in overrides.items() if name.startswith('rvfi_')}}
        if overrides.get('consume_instruction'):
            payload['pre_backend']['i_rsp_ready'] = 1
        for name, value in fields.items():
            post[names[name]] = value
    return mutate


def take(session, helper, **kwargs):
    helper.step(session, taken=1, irq_valid=1, mutation=mutation(session, **kwargs))


def return_mret(contract, session, helper, **kwargs):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    fields = dict(rvfi_valid=1, rvfi_order=2, rvfi_insn=0x30200073,
        rvfi_pc_rdata=build_f6_firmware(contract).document()['isr']['mret_addresses'][0],
        rvfi_pc_wdata=contract['program_contract']['slot_base']+128, rvfi_trap=0)
    fields.update(kwargs)
    fields.setdefault('return_serial', 0)
    helper.step(session, irq=0, mutation=mutation(session, **fields))


def test_actual_take_and_later_parsed_mret_bind_distinct_receipts(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_and_resume(contract, session, helper)
    event, = issuer.events
    assert event['schema_version'] == 'native_f6_isr_return.v1'
    assert event['case_id'] == 'stream:case0' and event['case_index'] == 0
    assert event['irq_take_key'] == ['cpu', 0, 1]
    assert event['take_receipt_id'] == {'execution': 'a'*32, 'sequence': 1}
    assert event['return_receipt_id'] == {'execution': 'a'*32, 'sequence': 3}
    assert event['handler_entry_receipt_id'] == {'execution': 'a'*32, 'sequence': 2}
    assert event['instruction'] == 0x30200073 and event['rvfi_order'] == 2
    assert event['isr_sha256'] == issuer.document()['isr']['sha256']
    assert event['execution_binding_sha256'] == 'b'*64
    assert event['irq_serial_observation']['retirement']['value'] == 0
    assert event['take_irq_serial_observation']['decision']['value'] == 4
    assert session.identity_document()['native_f6_isr_return'] == issuer.document()
    event['case_id'] = 'mutated'
    assert issuer.events[0]['case_id'] == 'stream:case0'
    detached = issuer.document(); detached['isr']['sha256'] = '0'*64
    assert issuer.document()['isr']['sha256'] != '0'*64


def test_pre_edge_take_and_post_edge_handler_entry_may_share_one_receipt(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter_one_receipt(contract, session, helper)
    return_and_resume(contract, session, helper)

    event, = issuer.events
    assert event['take_receipt_id'] == {'execution': 'a'*32, 'sequence': 1}
    assert event['handler_entry_receipt_id'] == event['take_receipt_id']


def test_duplicate_take_for_same_receipt_refuses_mret(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter_one_receipt(contract, session, helper)
    event = next(e for e in session.cpu_events if e['kind']=='cpu_external_irq_taken')
    session.cpu_events.append(deepcopy(event))
    with pytest.raises(ValueError):
        return_mret(contract, session, helper)
    assert issuer.events == ()


def test_same_receipt_take_and_entry_require_equal_serials(setup):
    contract, session, helper, issuer = install(setup)
    with pytest.raises(ValueError):
        take_and_enter_one_receipt(contract, session, helper, return_serial=5)
    assert issuer.events == ()


def test_pinned_take_survives_normal_runner_event_drain(setup):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    # ScenarioRunner drains this producer list into its detached event journal
    # after the step. The issuer must rely on its already pinned actual receipt.
    session.cpu_events.clear()
    enter_isr(contract, session, helper)
    return_and_resume(contract, session, helper)

    event, = issuer.events
    assert event['take_receipt_id'] == {'execution': 'a'*32, 'sequence': 1}
    assert event['handler_entry_receipt_id'] == {'execution': 'a'*32, 'sequence': 2}


@pytest.mark.parametrize('site_index', [0, 1])
def test_both_canonical_success_and_error_mret_sites_are_supported(setup, site_index):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    site = build_f6_firmware(contract).document()['isr']['mret_addresses'][site_index]
    return_and_resume(contract, session, helper, rvfi_pc_rdata=site)
    assert issuer.events[0]['pc_rdata'] == site


def test_saved_retire_json_has_no_return_authority(setup):
    _, session, _, issuer = install(setup)
    assert not callable(getattr(issuer, 'observe_saved_event', None))
    session.cpu_events.append(dict(kind='cpu_retire', insn=0x30200073, valid=1))
    assert issuer.events == ()
    with pytest.raises(ValueError):
        module().F6IsrReturnIssuer(session)
    with pytest.raises(AttributeError):
        issuer.events = ({'schema_version': 'native_f6_isr_return.v1'},)


@pytest.mark.parametrize('key', [['wrong', 0, 1], ['cpu', 1, 1], ['cpu', 0, 0],
    ['cpu', 0, 2], ['cpu', False, 1], ['cpu', 0, True]])
def test_wrong_take_keys_refuse_at_begin(setup, key):
    contract, session, _ = setup
    issuer = module().install_f6_isr_return(session, contract=contract,
        execution_binding_sha256='b'*64)
    with pytest.raises(ValueError):
        issuer.begin_case('stream:case0', case_index=0, irq_take_key=key)


@pytest.mark.parametrize('fields', [dict(rvfi_insn=0x13), dict(rvfi_pc_rdata=0x1022c),
    dict(rvfi_pc_rdata=0x10400), dict(resume_pc=0x11100),
    dict(resume_pc=0x11088), dict(resume_pc=0x11081),
    dict(rvfi_trap=1), dict(return_serial=4),
    dict(return_serial=5), dict(rvfi_order=0)])
def test_invalid_or_unrelated_mret_observations_never_issue(setup, fields):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    with pytest.raises((ValueError, ProtocolEnvironmentError)):
        return_and_resume(contract, session, helper, **fields)
    assert issuer.events == ()


def test_same_receipt_as_take_is_not_a_return(setup):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    contract, session, helper, issuer = install(setup)
    with pytest.raises((ValueError, ProtocolEnvironmentError)):
        take(session, helper, rvfi_valid=1, rvfi_order=1, rvfi_insn=0x30200073,
            rvfi_pc_rdata=build_f6_firmware(contract).document()['isr']['mret_addresses'][0],
            rvfi_pc_wdata=0x11080)
    assert issuer.events == ()


@pytest.mark.parametrize('mode', ['no_take', 'zero_take_serial', 'duplicate_take_event',
    'altered_take_event', 'epoch', 'execution', 'testcase', 'nonce', 'incomplete_post', 'forged_issuer'])
def test_native_scope_and_take_provenance_fail_closed(setup, mode):
    contract, session, helper, issuer = install(setup)
    if mode != 'no_take':
        take(session, helper, take_serial=0 if mode == 'zero_take_serial' else 4)
        if mode == 'zero_take_serial':
            with pytest.raises(ValueError):enter_isr(contract, session, helper)
            assert issuer.events == ()
            return
        enter_isr(contract, session, helper)
    if mode == 'duplicate_take_event':
        session.cpu_events.append(deepcopy(next(e for e in session.cpu_events if e['kind']=='cpu_external_irq_taken')))
    if mode == 'altered_take_event':
        next(e for e in session.cpu_events if e['kind']=='cpu_external_irq_taken')['receipt_id']['sequence'] = 99
    if mode == 'epoch':session.reset_epoch += 1
    if mode == 'execution':session._execution = 'c'*32
    if mode == 'testcase':session._case_id = 'other'
    if mode == 'forged_issuer':session._f6_isr_return = object()
    if mode in ('nonce', 'incomplete_post'):
        original = helper.receipt
        def altered(cpu, values, **kwargs):
            result = original(cpu, values, **kwargs)
            if mode == 'nonce':return replace(result, execution='c'*32)
            name = next(r['runtime_name'] for r in cpu._artifact_document['physical_exports']
                if r['physical_port']=='rvfi_pc_rdata')
            result.payload['samples'][0]['post']['physical'].pop(name)
            return result
        with patch.object(helper, 'receipt', side_effect=altered):
            with pytest.raises((ValueError, ProtocolEnvironmentError)):
                return_and_resume(contract, session, helper)
    else:
        with pytest.raises((ValueError, ProtocolEnvironmentError)):
            return_and_resume(contract, session, helper)
    if mode == 'forged_issuer':
        with pytest.raises(ValueError):issuer.document()
        session._f6_isr_return = issuer
    assert issuer.events == ()


def test_current_case_and_take_cannot_be_reused(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    with pytest.raises(ValueError):
        issuer.begin_case('stream:case1', case_index=1, irq_take_key=['cpu', 0, 1])
    return_and_resume(contract, session, helper)
    with pytest.raises(ValueError):
        issuer.begin_case('stream:case1', case_index=1, irq_take_key=['cpu', 0, 1])
    issuer.begin_case('stream:case1', case_index=1, irq_take_key=['cpu', 0, 2])
    take(session, helper, take_serial=5)
    enter_isr(contract, session, helper, order=4, serial=5)
    return_and_resume(contract, session, helper, rvfi_order=5, resume_pc=0x11180)
    assert [e['case_index'] for e in issuer.events] == [0, 1]


@pytest.mark.parametrize('mode', ['disabled', 'wrong_profile', 'wrong_source', 'wrong_provider',
    'nested_program', 'manifest', 'hash', 'empty_manifest', 'unbound_cpu', 'sha', 'retire_override',
    'missing_serial', 'wrong_session_type', 'source_component_drift'])
def test_installer_requires_original_registered_source_and_complete_contract(setup, mode):
    contract, session, _ = setup
    if mode == 'disabled':session._native_irq_receipts = False
    if mode == 'wrong_profile':
        session.artifact = replace(session.artifact, plan=replace(session.artifact.plan,
            profile=replace(session.artifact.plan.profile, component_id='ibex_obi_local')))
    if mode == 'wrong_source':session._artifact_document['source_verification'] = {}
    if mode == 'wrong_provider':contract['irq']['native_take_provider'] = {}
    if mode == 'nested_program':contract = contract['program_contract']
    if mode == 'manifest':contract['program_contract']['initial_image'][1]['sha256'] = '0'*64
    if mode == 'hash':contract['program_contract']['initial_image_sha256'] = '0'*64
    if mode == 'empty_manifest':
        contract['program_contract'].update(initial_image=[], initial_image_sha256=None)
    if mode == 'unbound_cpu':contract['cpu']['instance_id'] = 'other'
    if mode == 'retire_override':session._retire = lambda *a, **k: None
    if mode == 'source_component_drift':
        session.source_component = 'other'
        contract['cpu']['instance_id'] = contract['irq']['consumer_instance'] = 'other'
    if mode == 'wrong_session_type':
        session.__class__ = type('UnregisteredCpu', (GeneratedCve2Session,), {})
    if mode == 'missing_serial':
        rows = [row for row in session._artifact_document['physical_exports']
                if row['physical_port'] != 'irq_retirement_serial']
        session._artifact_document['physical_exports'] = rows
        doc = deepcopy(session.artifact.runtime_document)
        doc['physical_exports'] = deepcopy(rows)
        session.artifact = replace(session.artifact, runtime_document=doc)
    with pytest.raises(ValueError):
        module().install_f6_isr_return(session, contract=contract,
            execution_binding_sha256='bad' if mode == 'sha' else 'b'*64)


def test_once_only_install_and_original_callback_cannot_be_bypassed(setup):
    contract, session, helper, issuer = install(setup)
    with pytest.raises(ValueError):
        module().install_f6_isr_return(session, contract=contract, execution_binding_sha256='b'*64)
    take_and_enter(contract, session, helper)
    with patch.object(session, '_native_retirement_receipt', return_value={}):
        with pytest.raises(ValueError):
            return_and_resume(contract, session, helper)
    assert issuer.events == ()


def test_direct_private_hook_and_saved_receipt_cannot_issue(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    captured = []
    original = helper.receipt
    def capture(*a, **kwargs):
        receipt = original(*a, **kwargs);captured.append(receipt);return receipt
    with patch.object(helper, 'receipt', side_effect=capture):
        return_and_resume(contract, session, helper)
    physical = session._physical_outputs({'observations': captured[-1].payload['samples'][0]['post']})
    with pytest.raises(ValueError):
        session._retire(physical, receipt=captured[-1])
    with pytest.raises(ValueError):
        module()._capture_f6_native_retirement(session, captured[-1], physical)
    assert len(issuer.events) == 1


def test_absent_installer_preserves_native_identity_and_events(setup):
    contract, session, helper = setup
    before = deepcopy(session.identity_document())
    take_and_enter(contract, session, helper)
    return_and_resume(contract, session, helper)
    assert session.identity_document() == before
    assert 'native_f6_isr_return' not in before
    assert not any(e.get('schema_version')=='native_f6_isr_return.v1' for e in session.cpu_events)


@pytest.mark.parametrize('mode', ['epoch', 'execution', 'disabled'])
def test_campaign_scope_cannot_change_between_logical_cases(setup, mode):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_and_resume(contract, session, helper)
    if mode == 'epoch':session.reset_epoch += 1
    if mode == 'execution':session._execution = 'c'*32
    if mode == 'disabled':session._native_irq_receipts = False
    with pytest.raises(ValueError):
        issuer.begin_case('stream:case1', case_index=1,
            irq_take_key=['cpu', session.reset_epoch, 2])


def test_fabricated_take_event_cannot_replace_actual_receipt_source(setup):
    contract, session, helper, issuer = install(setup)
    fake = dict(kind='cpu_external_irq_taken', take_key=['cpu', 0, 1],
        source_epoch=0, receipt_id={'execution': 'a'*32, 'sequence': 1},
        command_scope=dict(component='cpu', reset_epoch=0, command_sequence=1))
    session.cpu_events.append(fake)
    with pytest.raises(ValueError):
        return_and_resume(contract, session, helper)
    assert issuer.events == ()


def test_disabling_native_provider_during_pending_case_refuses(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    session._native_irq_receipts = False
    with pytest.raises(ValueError):
        return_and_resume(contract, session, helper)
    session._native_irq_receipts = True
    assert issuer.events == ()


def enter_isr(contract, session, helper, *, order=1, serial=4, **kwargs):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    firmware = build_f6_firmware(contract)
    address = contract['program_contract']['isr_address']
    fields = dict(rvfi_valid=1, rvfi_order=order, rvfi_intr=1, rvfi_trap=0,
        rvfi_pc_rdata=address, rvfi_pc_wdata=address+4,
        rvfi_insn=int.from_bytes(firmware.initial_images[address][:4], 'little'), return_serial=serial)
    fields.update(kwargs)
    helper.step(session, irq=0, mutation=mutation(session, **fields))


def test_source_valid_entry_then_zero_serial_mret(setup):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    enter_isr(contract, session, helper)
    return_and_resume(contract, session, helper, return_serial=0)
    event, = issuer.events
    assert event['handler_entry_receipt_id']['sequence'] == 2
    assert event['handler_entry_rvfi_order'] == 1
    assert event['handler_entry_irq_serial_observation']['retirement']['value'] == 4
    assert event['irq_serial_observation']['retirement']['value'] == 0


def test_nonzero_mret_serial_cannot_skip_actual_entry(setup):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    with pytest.raises(ValueError):
        return_mret(contract, session, helper, return_serial=4)
    assert issuer.events == ()


def take_and_enter(contract, session, helper):
    take(session, helper)
    enter_isr(contract, session, helper)


def take_and_enter_one_receipt(contract, session, helper, **overrides):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    firmware = build_f6_firmware(contract)
    address = contract['program_contract']['isr_address']
    fields = dict(rvfi_valid=1, rvfi_order=1, rvfi_intr=1, rvfi_trap=0,
        rvfi_pc_rdata=address, rvfi_pc_wdata=address+4,
        rvfi_insn=int.from_bytes(firmware.initial_images[address][:4], 'little'))
    fields.update(overrides)
    helper.step(session, taken=1, irq_valid=1,
                mutation=mutation(session, **fields))


@pytest.mark.parametrize('fields', [dict(rvfi_intr=0),
    dict(rvfi_trap=1), dict(rvfi_pc_rdata=0x10230), dict(rvfi_insn=0x13),
    dict(serial=0), dict(serial=5), dict(order=0)])
def test_invalid_handler_entry_refuses(setup, fields):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    with pytest.raises(ValueError):
        enter_isr(contract, session, helper, **fields)
    assert issuer.events == ()


@pytest.mark.parametrize('conflict', ['trap', 'handler_entry', 'new_take', 'order_regression'])
def test_intervening_conflict_cannot_be_repaired_by_later_mret(setup, conflict):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    fields = dict(rvfi_valid=1, rvfi_order=2, rvfi_pc_rdata=0x10230, rvfi_insn=0x13,
        rvfi_intr=int(conflict=='handler_entry'), rvfi_trap=int(conflict=='trap'), return_serial=0)
    if conflict == 'order_regression':fields['rvfi_order'] = 1
    with pytest.raises(ValueError):
        helper.step(session, taken=int(conflict=='new_take'), mutation=mutation(session, **fields))
    with pytest.raises(ValueError):
        return_and_resume(contract, session, helper, rvfi_order=3)
    assert issuer.events == ()


def test_invalid_rvfi_stale_entry_and_mret_fields_carry_no_authority(setup):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    enter_isr(contract, session, helper, rvfi_valid=0)
    assert issuer.events == ()
    enter_isr(contract, session, helper)
    return_mret(contract, session, helper, rvfi_valid=0, rvfi_trap=1)
    assert issuer.events == ()
    return_mret(contract, session, helper)
    assert issuer.events == ()
    resume(session, helper)
    return_mret(contract, session, helper, rvfi_valid=0)
    assert len(issuer.events) == 1


def test_mret_is_pending_until_source_proven_successor(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper, rvfi_pc_wdata=0xdeadbeec)
    assert issuer.events == ()


def resume(session, helper, *, order=3, address=0x11080, with_response=True,
           response_word=0x13, response_error=0, response_key_patch=None, **kwargs):
    fields = dict(rvfi_valid=1, rvfi_order=order, rvfi_pc_rdata=address,
        rvfi_pc_wdata=address, rvfi_insn=0x13, rvfi_intr=0, rvfi_trap=0,
        return_serial=0)
    fields.update(kwargs)
    if with_response:
        session.memory.preload(address & ~3, response_word.to_bytes(4, 'little'))
        session._pending_instr = session._serve('instr', 0, address, 0, 15)
        if response_key_patch:
            session._request_evidence['instr']['transaction'].update(response_key_patch)
        if response_error:
            data, _, sequence = session._pending_instr
            session._pending_instr = (data, response_error, sequence)
        fields['consume_instruction'] = True
    helper.step(session, irq=0, mutation=mutation(session, **fields))


def consume_instruction_response(session, helper, *, address=0x11080, response_word=0x13):
    """Produce an actual consumed response on a non-retiring CPU receipt."""
    session.memory.preload(address & ~3, response_word.to_bytes(4, 'little'))
    session._pending_instr = session._serve('instr', 0, address, 0, 15)
    fields = dict(rvfi_valid=0, rvfi_order=0, rvfi_pc_rdata=address,
        rvfi_pc_wdata=address, rvfi_insn=response_word, rvfi_intr=0, rvfi_trap=0,
        return_serial=0, consume_instruction=True)
    helper.step(session, irq=0, mutation=mutation(session, **fields))


def test_actual_successor_certifies_target_and_preserves_raw_mret_pc_wdata(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper, rvfi_pc_wdata=0xdeadbeec)
    assert issuer.events == ()
    resume(session, helper)
    event, = issuer.events
    assert event['pc_wdata'] == 0xdeadbeec
    assert event['successor_pc_rdata'] == 0x11080
    assert event['successor_rvfi_order'] == 3
    assert event['successor_receipt_id']['sequence'] == 4


def test_pinned_successor_response_survives_normal_runner_event_drain(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper, rvfi_pc_wdata=0xdeadbeec)

    consume_instruction_response(session, helper)
    response, = [row for row in session.cpu_events if row.get('kind') == 'instr_response']
    response_receipt_id = {'execution': 'a'*32, 'sequence': 4}
    assert response['response_tick'] == session.local_ticks

    # ScenarioRunner moves each step's producer events into its detached
    # journal. The issuer's original parsed-receipt pin must survive that drain.
    session.cpu_events.clear()
    resume(session, helper, with_response=False)

    event, = issuer.events
    assert event['successor_receipt_id'] == {'execution': 'a'*32, 'sequence': 5}
    assert event['successor_instruction_response_receipt_id'] == response_receipt_id
    assert event['successor_pc_rdata'] == 0x11080


def test_altered_pinned_successor_response_still_refuses_after_drain(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    consume_instruction_response(session, helper)
    response, = [row for row in session.cpu_events if row.get('kind') == 'instr_response']
    session.cpu_events.clear()
    response['transaction']['source_epoch'] = 1

    with pytest.raises(ValueError):
        resume(session, helper, with_response=False)
    assert issuer.events == ()


def test_visible_duplicate_successor_response_refuses(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    consume_instruction_response(session, helper)
    response, = [row for row in session.cpu_events if row.get('kind') == 'instr_response']
    session.cpu_events.append(deepcopy(response))

    with pytest.raises(ValueError):
        resume(session, helper, with_response=False)
    assert issuer.events == ()


def test_visible_replacement_successor_response_refuses_after_drain(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    consume_instruction_response(session, helper)
    response, = [row for row in session.cpu_events if row.get('kind') == 'instr_response']
    session.cpu_events.clear()
    session.cpu_events.append(deepcopy(response))

    with pytest.raises(ValueError):
        resume(session, helper, with_response=False)
    assert issuer.events == ()


@pytest.mark.parametrize('kwargs', [dict(order=4), dict(address=0x11180),
    dict(address=0x11088), dict(address=0x11081), dict(rvfi_intr=1),
    dict(rvfi_trap=1), dict(return_serial=4)])
def test_pending_mret_requires_immediate_current_slot_actual_successor(setup, kwargs):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    with pytest.raises(ValueError):
        resume(session, helper, **kwargs)
    assert issuer.events == ()


def return_and_resume(contract, session, helper, *, resume_pc=0x11080, **kwargs):
    return_mret(contract, session, helper, **kwargs)
    if kwargs.get('rvfi_valid', 1):
        resume(session, helper, order=kwargs.get('rvfi_order', 2)+1, address=resume_pc)


@pytest.mark.parametrize('fields', [dict(rvfi_ext_debug_mode=1), dict(rvfi_ext_debug_req=1),
    dict(rvfi_halt=1), dict(rvfi_mode=0), dict(with_response=False),
    dict(response_word=0x93), dict(response_error=1)])
def test_actual_successor_requires_privilege_debug_clear_and_matching_instruction_response(setup, fields):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    with pytest.raises(ValueError):
        resume(session, helper, **fields)
    assert issuer.events == ()


def test_saved_instruction_response_cannot_certify_actual_successor(setup):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    session.cpu_events.append(dict(kind='instr_response', address=0x11080, rdata=0x13,
        error=0, response_tick=session.local_ticks))
    with pytest.raises(ValueError):
        resume(session, helper, with_response=False)
    assert issuer.events == ()


def test_actual_logical_instance_rename_uses_same_registered_provider():
    _, compiled, artifacts = source_inputs('renamed_processor', 'renamed_mover')
    contract, session, helper = make_setup((f6(compiled)['execution_contract'], artifacts['renamed_processor']))
    issuer = module().install_f6_isr_return(session, contract=contract, execution_binding_sha256='b'*64)
    issuer.begin_case('stream:case0', case_index=0, irq_take_key=['renamed_processor', 0, 1])
    take_and_enter(contract, session, helper)
    return_and_resume(contract, session, helper)
    assert issuer.events[0]['component'] == 'renamed_processor'


@pytest.mark.parametrize('fields', [dict(rvfi_ext_debug_mode=1), dict(rvfi_ext_debug_req=1), dict(rvfi_halt=1)])
def test_invalid_cycle_debug_diversion_refuses_and_stays_conflicted(setup, fields):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    with pytest.raises(ValueError):
        helper.step(session, irq=0, mutation=mutation(session, rvfi_valid=0, **fields))
    with pytest.raises(ValueError):
        return_mret(contract, session, helper)
    assert issuer.events == ()


@pytest.mark.parametrize('key_patch', [dict(execution_id='other'), dict(testcase_id='other'),
    dict(source_component='other'), dict(source_epoch=1), dict(channel_id='data'),
    dict(source_sequence=99), dict(source_sequence=True)])
def test_successor_instruction_response_full_transaction_key_is_closed(setup, key_patch):
    contract, session, helper, issuer = install(setup)
    take_and_enter(contract, session, helper)
    return_mret(contract, session, helper)
    with pytest.raises(ValueError):
        resume(session, helper, response_key_patch=key_patch)
    assert issuer.events == ()


@pytest.mark.parametrize('refusal', ['altered_take', 'missing_entry', 'wrong_entry_serial'])
def test_refused_native_chain_cannot_recover_after_restoring_evidence(setup, refusal):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    if refusal == 'altered_take':
        enter_isr(contract, session, helper)
        actual_take = next(e for e in session.cpu_events if e['kind']=='cpu_external_irq_taken')
        actual_take['receipt_id']['sequence'] = 99
        with pytest.raises(ValueError):return_mret(contract, session, helper)
        with pytest.raises(ValueError):return_mret(contract, session, helper, rvfi_order=3)
    elif refusal == 'missing_entry':
        with pytest.raises(ValueError):return_mret(contract, session, helper)
        with pytest.raises(ValueError):enter_isr(contract, session, helper, order=3)
    else:
        with pytest.raises(ValueError):enter_isr(contract, session, helper, serial=5)
        with pytest.raises(ValueError):enter_isr(contract, session, helper, order=2)
    assert issuer.events == ()


@pytest.mark.parametrize('stage', ['before_entry', 'before_mret'])
def test_post_take_component_drift_refuses_and_cannot_recover(setup, stage):
    contract, session, helper, issuer = install(setup)
    take(session, helper)
    if stage == 'before_mret':enter_isr(contract, session, helper)
    session.source_component = 'mutated_component'
    with pytest.raises(ValueError):
        if stage == 'before_entry':enter_isr(contract, session, helper)
        else:return_and_resume(contract, session, helper)
    session.source_component = 'cpu'
    with pytest.raises(ValueError):
        if stage == 'before_entry':enter_isr(contract, session, helper, order=2)
        else:return_mret(contract, session, helper, rvfi_order=4)
    assert issuer.events == ()


def install_dispatch(setup):
    from tests.integration.test_shared_irq_dispatcher import declaration
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    contract,session,helper=setup;p=contract['program_contract']
    p['gpio_irq']=declaration();p['initial_image']=[];p['initial_image_sha256']=None
    fw=build_f6_firmware(contract);p['initial_image']=list(fw.initial_segment_manifest);p['initial_image_sha256']=fw.manifest_sha256
    contract,session,helper,issuer=install(setup)
    return contract,session,helper,issuer,fw.document()['irq_dispatch']


def dispatch_retire(contract,session,helper,pc,order):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    entry=contract['program_contract']['isr_address'];data=build_f6_firmware(contract).initial_images[entry]
    insn=int.from_bytes(data[pc-entry:pc-entry+4],'little')
    helper.step(session,irq=0,mutation=mutation(session,rvfi_valid=1,rvfi_order=order,rvfi_intr=0,rvfi_trap=0,
        rvfi_pc_rdata=pc,rvfi_insn=insn,return_serial=0))


def test_shared_dispatcher_requires_actual_DMA_branch_before_MRET(setup):
    c,s,h,issuer,dispatch=install_dispatch(setup)
    take_and_enter(c,s,h)
    path=dispatch['stages']['dma_dispatch_path'][1:]+[dispatch['stages']['dma']['address']]
    for order,pc in enumerate(path,2):dispatch_retire(c,s,h,pc,order)
    return_and_resume(c,s,h,rvfi_order=len(path)+2)
    event,=issuer.events
    assert event['dispatcher_stage_sha256']==dispatch['identity_sha256']
    assert [r['pc'] for r in event['dispatcher_retirements']]==dispatch['stages']['dma_dispatch_path']+[dispatch['stages']['dma']['address']]
    assert event['dma_stage_address']==dispatch['stages']['dma']['address']


@pytest.mark.parametrize('jump',['dma','gpio'])
def test_shared_dispatcher_cannot_skip_entry_path_or_grant_GPIO_MRET(setup,jump):
    c,s,h,issuer,dispatch=install_dispatch(setup)
    take_and_enter(c,s,h)
    with pytest.raises(ValueError,match='dispatcher'):
        dispatch_retire(c,s,h,dispatch['stages'][jump]['address'],2)
    assert issuer.events==()


def test_no_current_case_cannot_observe_arbitrary_MRET(setup):
    c,s,h=setup
    issuer=module().install_f6_isr_return(s,contract=c,execution_binding_sha256='b'*64)
    with pytest.raises(ValueError,match='shared GPIO|current logical case'):
        return_mret(c,s,h)
    assert issuer.events==()


def test_GPIO_MRET_permission_requires_actual_shared_support_scope():
    from myfuzz.scenario.native_f6_isr_return import _allow_shared_gpio_mret
    with pytest.raises(ValueError,match='shared GPIO'):
        _allow_shared_gpio_mret(object(),dict(active=None,dispatch=None,program={}),dict(rvfi_insn=0x30200073))


def test_active_F6_cannot_use_GPIO_MRET_site(setup):
    c,s,h,issuer,dispatch=install_dispatch(setup)
    take_and_enter(c,s,h)
    path=dispatch['stages']['dma_dispatch_path'][1:]+[dispatch['stages']['dma']['address']]
    for order,pc in enumerate(path,2):dispatch_retire(c,s,h,pc,order)
    with pytest.raises(ValueError,match='invalid fixed ISR MRET'):
        return_mret(c,s,h,rvfi_order=len(path)+2,rvfi_pc_rdata=dispatch['stages']['gpio']['mret_addresses'][0])
    assert issuer.events==()


def install_declared_dispatch(setup):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    contract,session,helper=setup;p=contract['program_contract']
    p['declared_irq']={'schema_version':'shared_declared_irq_contract.v1',
        'phase_address':0x25000,'scratch_address':0x25100,'result_address':0x25200,
        'dma_handler_address':0x102a0,'target_handler_address':0x10380,
        'target_window':{'base':0x40003000,'size':4096},'status_offsets':[4],'clear_writes':[]}
    p['initial_image']=[];p['initial_image_sha256']=None
    fw=build_f6_firmware(contract);p['initial_image']=list(fw.initial_segment_manifest);p['initial_image_sha256']=fw.manifest_sha256
    contract,session,helper,issuer=install(setup)
    return contract,session,helper,issuer,fw.document()['irq_dispatch']


def test_declared_dispatcher_requires_actual_dma_path_before_f6_mret(setup):
    c,s,h,issuer,dispatch=install_declared_dispatch(setup)
    take_and_enter(c,s,h)
    path=dispatch['stages']['dma_dispatch_path'][1:]+[dispatch['stages']['dma']['address']]
    for order,pc in enumerate(path,2):dispatch_retire(c,s,h,pc,order)
    return_and_resume(c,s,h,rvfi_order=len(path)+2)
    event,=issuer.events
    assert event['dispatcher_stage_sha256']==dispatch['identity_sha256']
    assert [r['pc'] for r in event['dispatcher_retirements']]==dispatch['stages']['dma_dispatch_path']+[dispatch['stages']['dma']['address']]


def test_active_dma_case_cannot_claim_declared_target_mret(setup):
    c,s,h,issuer,dispatch=install_declared_dispatch(setup)
    take_and_enter(c,s,h)
    path=dispatch['stages']['dma_dispatch_path'][1:]+[dispatch['stages']['dma']['address']]
    for order,pc in enumerate(path,2):dispatch_retire(c,s,h,pc,order)
    with pytest.raises(ValueError,match='invalid fixed ISR MRET'):
        return_mret(c,s,h,rvfi_order=len(path)+2,rvfi_pc_rdata=dispatch['stages']['declared_target']['mret_addresses'][0])
    assert issuer.events==()
