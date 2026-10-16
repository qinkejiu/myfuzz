"""Independent actual callback/token boundaries; no restored caller evidence."""
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session, observed_factory
from tests.scenario.test_register_program_runtime import request


def test_actual_result_store_before_read_is_not_a_read_result_proof(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    base = observed_factory(actual_factory)
    def factory():
        runner = base()
        perform_read = runner.step_batch
        def step(order):
            cpu = runner.sessions['cpu']
            # Real service callback and issuance token, but before the MMIO read.
            cpu._serve('data', 1, 0x10004, 17, 15)
            runner._append_external_events('cpu', len(runner._events))
            cpu._pending_data = None
            perform_read(order)
        runner.step_batch = step
        return runner
    result = session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result)
    verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read',
        value=None, result_address=0x10004, allow_side_effect=False))
    seals = result.runner._ordinary_apb_access_evidence.completed_accesses()
    assert len(seals) == 1 and seals[0]['cpu_response'][0] == 17
    commit, = [e for e in result.runner.events if e.get('kind') == 'memory_write_commit']
    assert commit['event_id'] < seals[0]['association']['delivery_event_id']
    assert commit['transaction']['source_sequence'] < seals[0]['association']['source_transaction']['source_sequence']
    report = verifier.report()
    assert report['historical_certificates'] == []
    assert report['current_certificates'] == []
    assert verifier.snapshot('gpio_a').operations == ()


def test_actual_after_read_store_with_other_case_is_not_the_read_result(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    base = observed_factory(actual_factory)
    def factory():
        runner = base()
        perform_read = runner.step_batch
        def step(order):
            perform_read(order)
            cpu = runner.sessions['cpu']
            cpu._pending_data = None
            original_case = cpu._case_id
            cpu._case_id = 'different-actual-cpu-case'
            old_sequence = cpu._sequences['data']
            cpu._sequences['data'] = 0  # New actual ledger testcase/channel starts at one.
            cpu._serve('data', 1, 0x10004, 17, 15)
            runner._append_external_events('cpu', len(runner._events))
            cpu._case_id = original_case
            cpu._sequences['data'] = old_sequence
        runner.step_batch = step
        return runner
    result = session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result)
    verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read',
        value=None, result_address=0x10004, allow_side_effect=False))
    read, = result.runner._ordinary_apb_access_evidence.completed_accesses()
    commit, = [e for e in result.runner.events if e.get('kind') == 'memory_write_commit']
    assert commit['event_id'] > read['association']['delivery_event_id']
    assert commit['transaction']['testcase_id'] != read['association']['source_transaction']['testcase_id']
    assert verifier.report()['historical_certificates'] == []


def test_foreign_actual_cpu_case_write_is_not_attributed_to_admitted_write_request(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.local_harness.test_ordinary_apb_access_receipts import software_transport
    def factory():
        runner = actual_factory()
        begin = runner.begin_test
        def start(case_id):
            begin(case_id)
            software_transport(runner.sessions['gpio_a'], rdata=1)
        runner.begin_test = start
        def step(order):
            cpu = runner.sessions['cpu']; target = runner.sessions['gpio_a']
            window = next(w for w in cpu.router.windows if w.target is target)
            original_case = cpu._case_id
            original_sequence = cpu._sequences.get('data', 0)
            for writing in (True, False):
                cpu._case_id = 'other-writer-case' if writing else original_case
                cpu._sequences['data'] = 0 if writing else original_sequence
                cpu._pending_data = None
                cpu._serve('data', int(writing), window.base + 12, 1 if writing else 0, 15)
                runner._ordinary_apb_access_evidence.preflight_access(cpu.router, target)
                cpu.router.drain_one('gpio_a')
                runner._append_external_events('cpu', len(runner._events))
                runner._drain_ordinary_apb_events(1)
                runner.local_ticks['gpio_a'] = target.local_ticks
                runner._drain_tick_samples(1)
                runner._finalize_ordinary_apb_access(cpu.router, target)
        runner.step_batch = step
        return runner
    result = session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result); verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', allow_side_effect=False))
    writer, reader = result.runner._ordinary_apb_access_evidence.completed_accesses()
    assert writer['association']['source_transaction']['testcase_id'] == 'other-writer-case'
    assert reader['association']['source_transaction']['testcase_id'] != 'other-writer-case'
    assert verifier.report()['historical_certificates'] == []


def test_actual_callback_failure_keeps_history_but_clears_current_qualification(actual_factory):
    import pytest
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_register_program_verifier import read_result_factory
    result = session(read_result_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result); verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read',
        value=None, result_address=0x10004, allow_side_effect=False))
    before = verifier.report()
    assert len(before['current_certificates']) == 1
    assert len(verifier.snapshot('gpio_a').operations) == 1
    runner = result.runner; cpu = runner.sessions['cpu']; target = runner.sessions['gpio_a']
    window = next(w for w in cpu.router.windows if w.target is target)
    cpu._pending_data = None
    cpu._serve('data', 1, window.base + 16, 1, 15)
    cpu.mmio_write_count = 'bad'
    observer = runner._ordinary_apb_access_evidence
    observer.preflight_access(cpu.router, target)
    with pytest.raises(TypeError):
        cpu.router.drain_one('gpio_a')
    runner._append_external_events('cpu', len(runner._events))
    runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a'] = target.local_ticks
    runner._drain_tick_samples(1)
    runner._finalize_ordinary_apb_access(cpu.router, target, failure='TypeError')
    assert observer.snapshot()['status'] == 'incomplete'
    after = verifier.report()
    assert after['historical_certificates'] == before['historical_certificates']
    assert after['current_certificates'] == []
    assert verifier.snapshot('gpio_a').operations == ()
