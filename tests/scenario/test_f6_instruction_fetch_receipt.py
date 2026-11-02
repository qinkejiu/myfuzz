"""Software parsed OBI boundary only: no native process or build is launched."""
from collections import deque
from copy import deepcopy
from dataclasses import asdict, replace
import importlib
import importlib.util

import pytest

from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.scenario.batch import BatchAdvance
from myfuzz.scenario.session_runtime import BoundOnlineInstruction, OnlineCase
from tests.integration.test_compiled_f6_contract import ROOT, source_inputs
from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
from tests.local_harness import test_cpu_native_irq_receipt as irq_tests


def module():
    name = 'myfuzz.scenario.f6_instruction_fetch_receipt'
    assert importlib.util.find_spec(name) is not None, 'F6 OBI receipt producer is absent'
    return importlib.import_module(name)


@pytest.fixture(scope='module')
def inputs():
    module()
    return source_inputs()


@pytest.fixture
def live(inputs, tmp_path, monkeypatch):
    return make_live(inputs, tmp_path, monkeypatch)


def make_live(inputs, tmp_path, monkeypatch):
    module()
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.scenario.ownership import compile_ownership
    _install_software_process_boundary(monkeypatch)
    monkeypatch.setattr(CompiledF6Runtime, '_bootstrap_to_first_slot', lambda self: None)
    request, compiled, artifacts = inputs
    runtime = CompiledF6Runtime(artifacts=artifacts,
        compiled_inputs=dict(request=request, compiled=compiled,
            ownership=compile_ownership((), ()), physical_port_map={}),
        base_dir=ROOT, cache_dir=tmp_path, run_id='fetch-receipt',
        rounds_per_case=128, max_cases=2)
    helper, commands = irq_tests.CpuNativeIrqReceiptTests(), deque()

    def command(cpu, operation, values):
        assert cpu is runtime.cpu and operation == 'STEP_CPU'
        observed = commands.popleft() if commands else {}
        def mutate(payload, irq):
            payload['pre_backend'].update(observed)
            backend = payload['pre_backend']
            previous_response = getattr(runtime, '_test_previous_response', {})
            for phase in ('pre', 'post'):
                taps = {}
                for trace in cpu._artifact_document['base_protocol_traces']['traces']:
                    prefix = 'i' if trace['endpoint_id'] == runtime.contract['cpu']['instruction_endpoint_id'] else 'd'
                    roles = dict(req=backend[prefix+'_req_valid'], gnt=backend[prefix+'_req_valid'] & backend[prefix+'_req_ready'],
                        addr=backend[prefix+'_req_addr'], we=backend[prefix+'_req_write'],
                        wdata=backend[prefix+'_req_wdata'], be=backend[prefix+'_req_be'],
                        rvalid=(int(bool(backend[prefix+'_rsp_valid'] and backend[prefix+'_rsp_ready'])) if phase == 'post'
                            else previous_response.get(prefix, (0, 0, 0))[0]),
                        rdata=(backend[prefix+'_rsp_rdata'] if phase == 'post' else previous_response.get(prefix, (0, 0, 0))[1]),
                        error=(backend[prefix+'_rsp_error'] if phase == 'post' else previous_response.get(prefix, (0, 0, 0))[2]))
                    taps.update({name: roles[role] for role, name in trace['signals'].items()})
                payload['samples'][0][phase]['protocol_taps'] = taps
            if hasattr(runtime, '_test_mutate_payload'):
                runtime._test_mutate_payload(payload)
            runtime._test_previous_response = {prefix: (int(bool(backend[prefix+'_rsp_valid']
                and backend[prefix+'_rsp_ready'])), backend[prefix+'_rsp_rdata'],
                backend[prefix+'_rsp_error']) for prefix in ('i', 'd')}
        return helper.receipt(cpu, values, mutation=mutate)
    monkeypatch.setattr(GeneratedLocalSession, 'command', command)
    runtime._test_commands = commands
    return runtime


def step(runtime, **observed):
    runtime._test_commands.append(observed)
    runtime.runner.step_batch((runtime.cpu_id,))


def request(runtime, offset=0):
    address = runtime.contract['program_contract']['slot_base'] + offset
    step(runtime, i_req_valid=1, i_req_addr=address, i_req_be=15)
    return address


def admit(runtime):
    candidate = runtime.preflight(sum(v << (11*i) for i, v in
        enumerate((11, 12, 13, 14))).to_bytes(8, 'little'))
    address = runtime.contract['program_contract']['slot_base']
    source_id = runtime.contract['instruction_source_id']
    case = OnlineCase('fetch-receipt:case:0', 'CPU_TO_IP',
        runtime.runtime_path_admission['runtime_path_ids'][1],
        BoundOnlineInstruction('fetch-source:0', runtime.cpu_id, address,
            runtime.program.prefix(candidate, case_index=0).hex(), source_id),
        (BatchAdvance((runtime.cpu_id,)),))
    runtime.session.submit_case(case)
    return case


def complete(runtime):
    request(runtime)
    case = admit(runtime)
    assert module().f6_instruction_fetch_receipts(runtime.cpu) == ()
    step(runtime, i_rsp_ready=1)
    assert module().f6_instruction_fetch_receipts(runtime.cpu) == (), 'backend consumption is only an OBI offer'
    step(runtime)
    receipt, = module().f6_instruction_fetch_receipts(runtime.cpu)
    return case, receipt


def acceptance_anchor(acceptance):
    document = asdict(acceptance)
    document['data_hex'] = document.pop('data').hex()
    document['versions'] = [list(version) for version in document['versions']]
    document['writer_event_ids'] = list(document['writer_event_ids'])
    document['writer_kinds'] = list(document['writer_kinds'])
    return dict(schema_version='compiled_F6_instruction_acceptance_anchor.v1',
        **document)


def test_waiting_request_source_snapshot_and_consumption_keep_original_identity(live):
    case, receipt = complete(live)
    assert receipt.source is case.source
    assert receipt.admission is live.runner._provenance.registry.get(case.source.action_id)
    assert receipt.acceptance is live.cpu._f6_instruction_fetch.acceptances[0]
    assert receipt.snapshot is live.cpu.service.ledger._entries[receipt.key].receipt
    assert receipt.schema_version == 'compiled_F6_instruction_fetch_completion.v1'
    assert receipt.proof_scope == 'native_obi_instruction_fetch_completed'
    assert receipt.grants_source_authority is False
    assert receipt.acceptance_tick < receipt.response_tick
    assert receipt.request_pre['backend']['i_req_valid'] == receipt.request_pre['backend']['i_req_ready'] == 1
    assert receipt.backend_response_pre['backend']['i_rsp_valid'] == receipt.backend_response_pre['backend']['i_rsp_ready'] == 1
    assert receipt.response_pre['protocol_taps']['trace_obi_i_rvalid'] == 1
    assert receipt.snapshot.data == case.source.data[:4]


def test_runner_publishes_original_raw_and_service_references_and_observer_projection(live):
    case, receipt = complete(live)
    events = live.runner.events
    event, = [e for e in events if e.get('kind') == 'compiled_F6_instruction_fetch_completion']
    by_id = {e['event_id']: e for e in events}
    assert event['run_id'] == live.run_id
    assert event['execution_binding_sha256'] == live.execution_binding_sha256
    assert event['case_id'] == case.case_id and event['case_index'] == 0
    assert event['key'] == asdict(receipt.key)
    assert by_id[event['admission_event_id']]['admission'] == receipt.admission.document()
    assert by_id[event['service_event_id']]['kind'] == 'instruction_source'
    assert by_id[event['service_event_id']]['f6_acceptance_anchor'] == \
        acceptance_anchor(receipt.acceptance)
    assert by_id[event['instr_response_event_id']]['kind'] == 'instr_response'
    for phase in ('request', 'backend_response', 'response'):
        raw = by_id[event[phase + '_pre_event_id']]
        producer = by_id[event[phase + '_producer_event_id']]
        assert raw['phase'] == 'pre' and raw['kind'] == 'local_tick_sample'
        assert raw['producer_event_id'] == producer['event_id']
        assert raw['outputs'] == getattr(receipt, phase + '_pre')
        assert producer['component'] == live.cpu_id and 'outputs' in producer
    assert event['request_pre_event_id'] < event['admission_event_id'] < event['service_event_id'] < event['memory_read_event_id'] < event['instr_response_event_id'] < event['backend_response_pre_event_id'] < event['backend_response_post_event_id'] < event['response_pre_event_id'] < event['event_id']
    assert by_id[event['instr_response_event_id']]['producer_event_id'] == event['backend_response_producer_event_id']
    assert event['backend_response_producer_event_id'] != event['response_producer_event_id']
    live._drain_observer_view()
    row, = [e for e in live.observer_view if e.get('kind') == event['kind']]
    assert row['runner_event_id'] == event['event_id']


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'version'])
def test_runner_refuses_missing_or_malformed_f6_acceptance_anchor(live, mutation):
    request(live)
    case = admit(live)
    service, = [row for row in live.runner.events
        if row.get('kind') == 'instruction_source'
        and row.get('source_event_id') == case.source.action_id]
    record = live.runner._event_ref_by_id(service['event_id'])
    if mutation == 'missing':
        record.pop('f6_acceptance_anchor', None)
    else:
        anchor = deepcopy(record.get('f6_acceptance_anchor') or
            acceptance_anchor(live.cpu._f6_instruction_fetch.acceptances[0]))
        if mutation == 'extra':
            anchor['unexpected'] = True
        else:
            anchor['versions'][0][1] += 1
        record['f6_acceptance_anchor'] = anchor

    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live, i_rsp_ready=1)
        step(live)
    assert not [row for row in live.runner.events
        if row.get('kind') == 'compiled_F6_instruction_fetch_completion']


def test_all_32_prefix_words_receive_a_receipt_and_fixed_control_fetch_does_not(live):
    complete(live)
    for offset in range(4, 128, 4):
        request(live, offset)
        step(live, i_rsp_ready=1)
        step(live)
    assert len(module().f6_instruction_fetch_receipts(live.cpu)) == 32
    request(live, 128)
    step(live, i_rsp_ready=1)
    step(live)
    assert len(module().f6_instruction_fetch_receipts(live.cpu)) == 32


def test_offer_and_stall_never_complete(live):
    request(live)
    admit(live)
    for _ in range(3):
        step(live, i_rsp_ready=0)
    assert module().f6_instruction_fetch_receipts(live.cpu) == ()


@pytest.mark.parametrize('field,value', [
    ('data', b'\0'*4), ('versions', ((0, 999),)*4),
    ('writer_event_ids', ('forged',)*4), ('writer_kinds', ('STORE',)*4),
])
def test_modified_snapshot_material_fails_closed(live, field, value):
    request(live)
    admit(live)
    snapshot = live.cpu.service.ledger._entries[live.cpu._waiting_instr[0]].receipt if live.cpu._waiting_instr else next(
        entry.receipt for key, entry in live.cpu.service.ledger._entries.items() if key.channel_id == 'instr')
    object.__setattr__(snapshot, field, value)
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live, i_rsp_ready=1)


@pytest.mark.parametrize('change', ['source', 'case', 'case_path', 'path', 'run', 'binding', 'key', 'epoch', 'epoch_boolean', 'owner'])
def test_source_scope_and_owner_drift_refuse(live, change):
    case, receipt = complete(live)
    if change == 'source':
        object.__setattr__(case.source, 'source_id', 'forged')
    elif change == 'case':
        object.__setattr__(case, 'case_id', 'forged')
    elif change == 'case_path':
        object.__setattr__(case, 'path_id', 'forged')
    elif change == 'binding':
        live.execution_binding_sha256 = 'c' * 64
    elif change == 'path':
        object.__setattr__(receipt.admission, 'path_id', 'forged')
    elif change == 'run':
        object.__setattr__(receipt, 'run_id', 'forged')
    elif change == 'key':
        object.__setattr__(receipt.key, 'source_sequence', 999)
    elif change == 'epoch_boolean':
        live.cpu.reset_epoch = False
    elif change == 'epoch':
        live.cpu.reset_epoch += 1
    else:
        live.cpu.service.ledger = deepcopy(live.cpu.service.ledger)
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(live.cpu, receipt)


def test_serialized_equal_receipt_and_cross_owner_are_not_live_authority(live):
    _, receipt = complete(live)
    for forged in (asdict(receipt), replace(receipt)):
        with pytest.raises(ValueError, match='F6 instruction fetch'):
            module().validate_f6_instruction_fetch(live.cpu, forged)
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(object(), receipt)


def test_without_opt_in_no_receipt_and_instruction_acceptance_is_preserved(inputs):
    module()
    from tests.integration.test_compiled_f6_isr_return import make_setup
    from tests.integration.test_compiled_f6_contract import f6
    _, compiled, artifacts = inputs
    _, cpu, _ = make_setup((f6(compiled)['execution_contract'], artifacts['cpu']))
    cpu.declare_instruction_slots(0x10000)
    acceptance = cpu.accept_instructions(0x10000, b'\x13\0\0\0', source_event_id='ordinary')
    assert acceptance is None
    assert cpu.service.events[-1]['kind'] == 'instruction_source'
    assert set(cpu.service.events[-1]) == {
        'kind', 'address', 'data_hex', 'source_event_id', 'generation'}
    assert module().f6_instruction_fetch_receipts(cpu) == ()


def test_direct_completion_injection_refuses_and_poison_is_permanent(live):
    request(live)
    admit(live)
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module()._complete_f6_instruction_fetch(live.cpu, None, {}, None)
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live, i_rsp_ready=1)


def test_obi_owned_producer_is_installed():
    module()


def test_refetch_same_address_distinct_keys_and_budget_derived_capacity(live):
    _, first = complete(live)
    for _ in range(35):
        request(live)
        step(live, i_rsp_ready=1)
        step(live)
    receipts = module().f6_instruction_fetch_receipts(live.cpu)
    assert len(receipts) == 36
    assert len({r.key for r in receipts}) == 36
    assert {r.address for r in receipts} == {first.address}
    configuration = live.cpu._f6_instruction_fetch.document()
    assert configuration['max_pending'] == 1
    assert configuration['max_receipts'] == live.session.template.max_steps * live.max_cases


def test_same_complete_key_cannot_be_replayed_as_another_fetch(live):
    complete(live)
    live.cpu._sequences['instr'] -= 1
    with pytest.raises(ValueError):
        request(live)


@pytest.mark.parametrize('target', ['request_missing', 'request_tap', 'request_producer',
    'response_tap', 'response_producer', 'service_parent', 'admission'])
def test_runner_refuses_missing_or_tampered_original_journal_rows(live, monkeypatch, target):
    request(live)
    admit(live)
    if target.startswith('request'):
        raw = next(e for e in live.runner.events if e.get('kind') == 'local_tick_sample'
            and e.get('component') == live.cpu_id and e.get('phase') == 'pre')
        record = live.runner._event_ref_by_id(raw['event_id'])
        if target == 'request_missing':
            record['kind'] = 'removed_raw'
        elif target == 'request_tap':
            record['outputs']['protocol_taps']['trace_obi_i_gnt'] = 0
        else:
            record['producer_event_id'] = 0
    elif target.startswith('response'):
        original = live.runner._route_observed_outputs
        def route(component, outputs, event_id, tick, phase):
            original(component, outputs, event_id, tick, phase)
            if component == live.cpu_id and phase == 'pre':
                record = live.runner._event_ref_by_id(event_id)
                if target == 'response_tap':
                    record['outputs']['protocol_taps']['trace_obi_i_rdata'] ^= 1
                else:
                    record['producer_event_id'] = 0
        monkeypatch.setattr(live.runner, '_route_observed_outputs', route)
    else:
        kind = 'instruction_source' if target == 'service_parent' else 'source_admission'
        event = next(e for e in live.runner.events if e.get('kind') == kind)
        record = live.runner._event_ref_by_id(event['event_id'])
        if target == 'service_parent':
            record['producer_event_id'] = record['event_id']
        else:
            record['admission']['case_id'] = 'other'
    with pytest.raises(ValueError):
        step(live, i_rsp_ready=1)
        step(live)
    assert not [e for e in live.runner.events if e.get('kind') == 'compiled_F6_instruction_fetch_completion']


@pytest.mark.parametrize('kind', ['snapshot', 'acceptance', 'key'])
def test_equal_reconstructed_original_object_is_refused(live, kind):
    _, receipt = complete(live)
    object.__setattr__(receipt, kind, replace(getattr(receipt, kind)))
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(live.cpu, receipt)


def test_synchronized_acceptance_and_runner_anchor_mutation_still_refuses(live):
    case, receipt = complete(live)
    service = next(row for row in live.runner.events
        if row.get('kind') == 'instruction_source'
        and row.get('source_event_id') == case.source.action_id)
    record = live.runner._event_ref_by_id(service['event_id'])
    anchor = deepcopy(record['f6_acceptance_anchor'])
    changed_versions = [list(version) for version in receipt.acceptance.versions]
    changed_versions[0][1] += 1
    object.__setattr__(receipt.acceptance, 'versions',
        tuple(tuple(version) for version in changed_versions))
    anchor['versions'] = changed_versions
    record['f6_acceptance_anchor'] = anchor

    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(live.cpu, receipt)


@pytest.mark.parametrize('lifecycle', ['reset', 'abort', 'finish'])
def test_lifecycle_revokes_previously_issued_objects(live, monkeypatch, lifecycle):
    _, receipt = complete(live)
    if lifecycle == 'reset':
        live.cpu.reset_local()
    elif lifecycle == 'abort':
        monkeypatch.setattr(GeneratedLocalSession, '_abort', lambda self: None)
        live.cpu._abort()
    else:
        live.cpu.end_case()
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(live.cpu, receipt)


def test_source_service_is_saved_before_first_native_step(live, monkeypatch):
    request(live)
    original = live.runner.step_batch
    seen = []
    def observe(schedule, **kwargs):
        seen.extend(e for e in live.runner.events if e.get('kind') == 'instruction_source')
        return original(schedule, **kwargs)
    monkeypatch.setattr(live.runner, 'step_batch', observe)
    admit(live)
    assert len(seen) == 1
    parent = live.runner.event_by_id(seen[0]['producer_event_id'])
    assert parent['kind'] == 'source_admission'


def test_preseeded_ledger_and_caller_event_cannot_issue_an_actual_read(live):
    from myfuzz.scenario.ledger import TransactionKey
    case = admit(live)
    key = TransactionKey('local-execution', live.cpu._case_id, live.cpu_id,
        live.cpu.reset_epoch, 'instr', 1)
    snapshot = live.cpu.memory.read(case.source.address, 4, transaction_id=str(key))
    live.cpu.service.ledger.execute_once(key, dict(op='read', address=case.source.address,
        width_bytes=4), lambda: snapshot)
    live.cpu.service.events.append(dict(kind='memory_read', transaction=asdict(key),
        address=case.source.address, width_bytes=4, memory_id=snapshot.memory_id,
        generation=snapshot.generation, byte_offset=snapshot.byte_offset,
        value=snapshot.value, data_hex=snapshot.data.hex(), versions=snapshot.versions,
        writer_event_ids=snapshot.writer_event_ids))
    with pytest.raises(ValueError):
        request(live)


def test_external_dto_cannot_inject_reserved_completion_event(live):
    live.cpu.cpu_events.append(dict(kind='compiled_F6_instruction_fetch_completion',
        schema_version='compiled_F6_instruction_fetch_completion.v1'))
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live)


def test_cross_fresh_issuer_cannot_consume_original_objects(live, inputs, tmp_path, monkeypatch):
    _, receipt = complete(live)
    fresh = make_live(inputs, tmp_path/'fresh', monkeypatch)
    assert fresh.cpu is not live.cpu and fresh.cpu.memory is not live.cpu.memory
    assert fresh.cpu._execution != live.cpu._execution or fresh.cpu.process is not live.cpu.process
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().validate_f6_instruction_fetch(fresh.cpu, receipt)


def test_provider_method_replacement_is_refused(live, monkeypatch):
    _, receipt = complete(live)
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    original = GeneratedCve2Session._serve
    monkeypatch.setattr(GeneratedCve2Session, '_serve', lambda *a, **k: original(*a, **k))
    with pytest.raises(ValueError, match='original method drift'):
        module().validate_f6_instruction_fetch(live.cpu, receipt)


def test_saved_receipt_dict_cannot_publish_through_runner(live):
    _, receipt = complete(live)
    saved = next(e for e in live.runner.events if e.get('kind') == 'compiled_F6_instruction_fetch_completion')
    with pytest.raises(ValueError, match='completion publication'):
        live.runner._append_ordinary_observed_event(deepcopy(saved))


def test_issuer_exposes_no_mutable_registry_and_keeps_exact_configuration(live):
    issuer = live.cpu._f6_instruction_fetch
    assert not hasattr(module(), '_OWNERS') and not hasattr(module(), '_state')
    assert issuer.document()['run_id'] == live.run_id
    assert issuer.document()['execution_binding_sha256'] == live.execution_binding_sha256
    with pytest.raises(AttributeError):
        issuer._owner = lambda: live.cpu


def test_f6_shaped_direct_install_is_not_the_runtime_constructor(live):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory import PersistentMemory
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.session_runtime import ScenarioSession
    cpu = GeneratedCve2Session(live.cpu.artifact, base_dir=ROOT,
        cache_dir=live.cache_dir, memory=PersistentMemory(regions=live.cpu.memory._regions,
            initialization_seed=3, max_initialized_bytes=0x30000),
        router=live.cpu.router, native_irq_receipts=True, physical_tick_samples=True)
    runner = ScenarioRunner(sessions={live.cpu_id: cpu, live.dma_id: live.dma},
        ownership=compile_ownership((), ()), bindings=())
    runner.configure_provenance(live.runner._provenance.edge_index)
    scenario = ScenarioSession(live.session.template, runner, checker_configuration_only=True)
    with pytest.raises(ValueError, match='original compiled F6 runtime construction'):
        module().install_f6_instruction_fetch(cpu, scenario, contract=live.contract,
            run_id=live.run_id, execution_binding_sha256=live.execution_binding_sha256,
            max_cases=live.max_cases)


def test_backend_offer_waits_for_next_native_pre_and_same_edge_new_grant_keeps_keys(live):
    request(live)
    case = admit(live)
    step(live, i_rsp_ready=1)
    assert module().f6_instruction_fetch_receipts(live.cpu) == ()
    assert live.cpu.pending_responses == 1
    request(live, 4)
    first, = module().f6_instruction_fetch_receipts(live.cpu)
    assert first.address == case.source.address
    assert first.response_tick == first.backend_response_tick + 1
    assert first.response_pre['protocol_taps']['trace_obi_i_rvalid'] == 1
    assert first.response_pre['protocol_taps']['trace_obi_i_gnt'] == 1
    assert first.response_pre['protocol_taps']['trace_obi_i_addr'] == case.source.address+4
    step(live, i_rsp_ready=1)
    assert len(module().f6_instruction_fetch_receipts(live.cpu)) == 1
    step(live)
    old, new = module().f6_instruction_fetch_receipts(live.cpu)
    assert old is first and new.key != old.key and new.key.source_sequence == old.key.source_sequence+1
    assert new.address == case.source.address+4


def test_backend_offer_without_next_native_response_pre_never_issues(live):
    request(live)
    admit(live)
    step(live, i_rsp_ready=1)
    assert module().f6_instruction_fetch_receipts(live.cpu) == ()
    def drop(payload):
        payload['samples'][0]['pre']['protocol_taps']['trace_obi_i_rvalid'] = 0
    live._test_mutate_payload = drop
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live)
    assert not [e for e in live.runner.events if e.get('kind') == 'compiled_F6_instruction_fetch_completion']


@pytest.mark.parametrize('phase', ['backend_response_pre', 'backend_response_post'])
def test_runner_refuses_tampered_backend_phase_before_native_completion(live, phase):
    request(live)
    admit(live)
    step(live, i_rsp_ready=1)
    raw_phase = 'pre' if phase.endswith('_pre') else 'post'
    record = next(e for e in reversed(live.runner.events) if e.get('kind') == 'local_tick_sample'
        and e.get('component') == live.cpu_id and e.get('phase') == raw_phase)
    live.runner._event_ref_by_id(record['event_id'])['outputs']['protocol_taps']['trace_obi_i_rdata'] ^= 1
    with pytest.raises(ValueError, match='PRE/step|POST/step'):
        step(live)
    assert not [e for e in live.runner.events if e.get('kind') == 'compiled_F6_instruction_fetch_completion']


@pytest.mark.parametrize('accessor', ['event_by_id', 'events'])
def test_runner_accessor_drift_cannot_rebind_original_raw_journal(live, monkeypatch, accessor):
    request(live)
    admit(live)
    step(live, i_rsp_ready=1)
    if accessor == 'event_by_id':
        original = live.runner.event_by_id
        monkeypatch.setattr(live.runner, accessor, lambda event_id: original(event_id))
    else:
        cls = type(live.runner)
        original = cls.events.fget
        monkeypatch.setattr(cls, accessor, property(lambda self: original(self)))
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        step(live)


def test_reset_reports_cancellation_of_frozen_backend_response_candidate(live):
    request(live)
    admit(live)
    step(live, i_rsp_ready=1)
    assert module().f6_instruction_fetch_receipts(live.cpu) == ()
    assert live.cpu.pending_responses == 1
    outcome = live.cpu.reset_local()
    assert outcome['cancelled_responses'] == 1
    assert live.cpu.pending_responses == 0
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        module().f6_instruction_fetch_receipts(live.cpu)



def test_instruction_read_only_backend_request_wdata_is_zero(live):
    # This is a backend output fixed by READ_ONLY=1, not an instruction OBI pin.
    def contradict(payload):
        payload['pre_backend']['i_req_wdata'] = 1
    live._test_mutate_payload = contradict
    with pytest.raises(ValueError, match='F6 instruction fetch'):
        request(live)


@pytest.mark.parametrize('mode,expected',[('snapshot',1),('legacy',7)])
def test_completion_reads_original_journal_only_once(live,mode,expected):
    """Count original methods without replacing any issuer-pinned callback."""
    import sys
    from myfuzz.scenario.runner import _EventLog
    iterations=[]
    drain_code=module()._drain_f6_instruction_fetches.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is _EventLog.__iter__.__code__:
            caller=frame.f_back
            while caller is not None:
                if caller.f_code is drain_code:
                    iterations.append(1);break
                caller=caller.f_back
    previous=sys.getprofile();sys.setprofile(profile)
    try:
        with module().f6_instruction_fetch_scan_scope(mode):
            complete(live)
    finally:sys.setprofile(previous)
    assert len(iterations)==expected


@pytest.mark.parametrize('mode',['snapshot','legacy'])
def test_duplicate_original_request_sample_still_refuses(live,mode):
    request(live);admit(live)
    raw=next(e for e in live.runner.events if e.get('kind')=='local_tick_sample'
        and e.get('component')==live.cpu_id and e.get('phase')=='pre')
    duplicate=deepcopy(raw);duplicate['event_id']=live.runner.event_count+1
    live.runner._events._records.append(duplicate)
    with module().f6_instruction_fetch_scan_scope(mode), pytest.raises(ValueError,match='unique original Runner reference'):
        step(live,i_rsp_ready=1);step(live)


def test_source_binding_reads_only_new_journal_tail(live):
    import sys
    from myfuzz.scenario.runner import _EventLog
    request(live)
    whole_reads=[]
    code=module()._bind_f6_instruction_source.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is _EventLog.__iter__.__code__:
            caller=frame.f_back
            while caller is not None:
                if caller.f_code is code:whole_reads.append(1);break
                caller=caller.f_back
    previous=sys.getprofile();sys.setprofile(profile)
    try:admit(live)
    finally:sys.setprofile(previous)
    assert whole_reads==[]


def test_source_binding_refuses_replaced_tail_accessor(live,monkeypatch):
    request(live)
    original=live.runner._event_refs_since
    monkeypatch.setattr(live.runner,'_event_refs_since',lambda index,stop=None:original(index,stop=stop))
    with pytest.raises(ValueError,match='F6 instruction fetch'):
        admit(live)


@pytest.mark.parametrize('kind',['source_admission','instruction_source'])
def test_source_binding_keeps_tail_duplicate_rejection(live,kind):
    import sys
    from myfuzz.scenario.runner import ScenarioRunner
    request(live);injected=[]
    bind_code=module()._bind_f6_instruction_source.__code__
    def profile(frame,event,arg):
        if injected:return
        admission_ready=kind=='source_admission' and event=='call' and frame.f_code is bind_code
        service_ready=(kind=='instruction_source' and event=='return'
            and frame.f_code is ScenarioRunner._append_external_events.__code__
            and frame.f_back is not None and frame.f_back.f_code is bind_code)
        if not (admission_ready or service_ready):return
        original=next(e for e in reversed(live.runner.events) if e.get('kind')==kind)
        duplicate=deepcopy(original);duplicate['event_id']=live.runner.event_count+1
        live.runner._events._records.append(duplicate);injected.append(1)
    previous=sys.getprofile();sys.setprofile(profile)
    try:
        with pytest.raises(ValueError,match='journal'):
            admit(live)
    finally:sys.setprofile(previous)
    assert injected==[1]


def test_install_uses_registered_native_CPU_artifact_verifier(inputs,tmp_path,monkeypatch):
    from myfuzz.local_harness import native_irq_receipt_contract as provider
    original=provider.verify_native_irq_receipt_artifact
    calls=[]
    def verify(artifact,*,base_dir):
        result=original(artifact,base_dir=base_dir)
        import sys
        if sys._getframe(1).f_code.co_name=='install_f6_instruction_fetch':calls.append(artifact)
        return result
    monkeypatch.setattr(provider,'verify_native_irq_receipt_artifact',verify)
    runtime=make_live(inputs,tmp_path,monkeypatch)
    assert runtime.cpu.artifact in calls
    assert getattr(runtime.cpu,'_f6_instruction_fetch',None) is not None
