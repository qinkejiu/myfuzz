"""F6 evidence borrows journal rows and detaches every row it keeps.

``capture_f6_case`` used to detach the whole Runner journal per case
(``events_since(0)`` in ``declared_edges``) and to detach each case slice a
second time (``protocol``, the CPU tick-sample index and the protocol-checker
report assembly).  Those readers are now served by
``compiled_f4._borrow_events`` under the documented "no mutate, no retain,
detach outputs" rule.

These tests hold that rule at the shapes the consumer uses: one whole-archive
read, the case-scoped reads, and the documents built from them.  The borrowed
drive must produce the same documents as the detaching drive, the case slice
must be the only range the case-scoped consumers can use, and no returned
document may keep a borrowed row.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from tests.integration.f6_compiled_support import inputs, make_case  # noqa: F401
from tests.integration.test_compiled_f6_contract import source_inputs
from tests.scenario.test_f6_instruction_fetch_receipt import make_live


def api(name='myfuzz.integration.compiled_f6_consumer'):
    import importlib
    return importlib.import_module(name)


def _json(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _identities(value, found=None):
    """Ids of every mutable container reachable in a document."""
    found = set() if found is None else found
    if isinstance(value, dict):
        found.add(id(value))
        for item in value.values():
            _identities(item, found)
    elif isinstance(value, (list, tuple)):
        found.add(id(value))
        for item in value:
            _identities(item, found)
    return found


def _attach_runner(runtime, attempt, *, pre_case=0):
    """Give the synthetic F6 fixture the real pinned Runner evidence reads.

    ``pre_case`` puts rows before the case start: they are part of the archive
    (``declared_edges`` must see them) but not part of the case slice.
    """
    from myfuzz.scenario.runner import ScenarioRunner

    cpu_id = runtime.cpu.source_component
    journal = [dict(event_id=index + 1, producer_event_id=0,
        kind='local_tick_sample', component=cpu_id, local_tick=1, phase='pre',
        outputs={}) for index in range(pre_case)]
    for sample in runtime.cpu._physical_tick_samples:
        producer_event_id = len(journal) + 1
        journal.append(dict(event_id=producer_event_id, component=cpu_id,
            local_tick=sample['local_tick'], inputs={}, outputs={}))
        for phase in ('pre', 'post'):
            journal.append(dict(event_id=len(journal) + 1,
                producer_event_id=producer_event_id, kind='local_tick_sample',
                component=cpu_id, local_tick=sample['local_tick'],
                phase=phase, outputs=deepcopy(sample[phase])))
    runner = object.__new__(ScenarioRunner)
    runner.sessions = {cpu_id: runtime.cpu,
        runtime.dma.source_component: runtime.dma}
    runner._events = journal
    runtime.runner = runner
    attempt['_runner_event_start'] = pre_case
    return runner, journal


def _reject_detaching_read(runner):
    def reject(start, *, stop=None):
        raise AssertionError('the detaching whole-journal reader was used')
    runner.events_since = reject


def test_borrow_events_returns_the_rows_a_detaching_read_would_copy():
    from myfuzz.integration.compiled_f4 import _borrow_events
    from tests.scenario.test_session_runtime_paths import factory

    runner = factory()
    for index in (1, 2):
        runner._events.append(dict(event_id=index, kind='fixture', component='a'))
    borrowed = _borrow_events(runner)
    detached = runner.events_since(0)
    assert borrowed == detached
    assert len(borrowed) == 2
    # Borrowed rows are the journal's own objects; a detaching read copies.
    assert all(left is right for left, right in zip(borrowed, runner._events))
    assert all(left is not right for left, right in zip(detached, runner._events))
    assert _borrow_events(runner, 1) == runner.events_since(1)


def test_borrow_events_falls_back_to_a_fixture_runner_reader():
    from myfuzz.integration.compiled_f4 import _borrow_events

    journal = [dict(event_id=1, kind='fixture'), dict(event_id=2, kind='fixture')]
    stub = SimpleNamespace(
        events_since=lambda index: tuple(deepcopy(journal[index:])))
    borrowed = _borrow_events(stub)
    assert borrowed == tuple(journal)
    assert borrowed[0] is not journal[0]
    journal[0]['kind'] = 'mutated'
    assert borrowed[0]['kind'] == 'fixture'


def test_borrow_events_keeps_the_detaching_reader_when_the_pinned_reader_is_replaced():
    from myfuzz.integration.compiled_f4 import _borrow_events
    from tests.scenario.test_session_runtime_paths import factory

    runner = factory()
    runner._events.append(dict(event_id=1, kind='fixture', component='a'))
    runner._event_refs_since = None
    assert _borrow_events(runner) == runner.events_since(0)
    assert _borrow_events(runner)[0] is not runner._events[0]


def test_borrow_events_rejects_a_runner_without_any_journal_reader():
    from myfuzz.integration.compiled_f4 import _borrow_events

    for runner in (SimpleNamespace(), None):
        with pytest.raises(ValueError, match='compiled-event-reader-unavailable'):
            _borrow_events(runner)


def test_case_tick_samples_are_scoped_to_the_case_start(inputs, tmp_path, monkeypatch):
    runtime, attempt = make_case(inputs, tmp_path, monkeypatch)
    runner, _journal = _attach_runner(runtime, attempt, pre_case=1)
    # The pre-case row is invalid (producer 0 is not an event) and would be
    # rejected by the whole-archive reader; the case-scoped index never reads
    # it because it starts at the attempt's event cursor.
    _reject_detaching_read(runner)
    case = api()._Case(runtime, attempt)
    assert case.cpu_tick_samples[0] == 'runner'
    groups = case.cpu_tick_samples[1]
    expected = {sample['local_tick']: sample
        for sample in runtime.cpu._physical_tick_samples}
    assert set(groups) == set(expected)
    for tick, phases in groups.items():
        assert phases['pre']['outputs'] == expected[tick]['pre']
        assert phases['post']['outputs'] == expected[tick]['post']
    tick = min(expected)
    assert case.cpu_tick_sample(tick)['pre'] == expected[tick]['pre']


def test_case_tick_sample_outputs_are_detached_from_the_borrowed_rows(
        inputs, tmp_path, monkeypatch):
    runtime, attempt = make_case(inputs, tmp_path, monkeypatch)
    _runner, journal = _attach_runner(runtime, attempt)
    case = api()._Case(runtime, attempt)
    tick = min(case.cpu_tick_samples[1])
    phases = case.cpu_tick_samples[1][tick]
    # The index keeps the journal's own rows; the sample it returns must not.
    assert any(phases['pre'] is row for row in journal)
    sample = case.cpu_tick_sample(tick)
    frozen_sample = deepcopy(sample)
    frozen_evidence = deepcopy(case.raw_evidence)
    for row in journal:
        if row.get('local_tick') == tick:
            row['outputs'].clear()
            row['outputs']['forged'] = True
    assert sample == frozen_sample
    assert case.raw_evidence == frozen_evidence
    assert 'forged' not in _json(sample)


def test_protocol_checker_report_is_identical_for_both_readers(
        inputs, tmp_path, monkeypatch):
    from myfuzz.scenario.runner import ScenarioRunner
    from tests.integration.test_compiled_f6_consumer import (
        install_synthetic_dma_checker_report)

    borrowed_case = make_case(inputs, tmp_path, monkeypatch)
    detached_case = make_case(inputs, tmp_path, monkeypatch)
    reports = []
    for runtime, attempt in (detached_case, borrowed_case):
        journal = []
        attempt['_runner_event_start'] = 0
        install_synthetic_dma_checker_report(runtime, attempt, journal)
        reports.append(runtime.protocol_checker_case_report)
    assert reports[0] == reports[1]
    # The production assembler no longer falls back to the detaching slice.
    control, control_attempt = make_case(inputs, tmp_path, monkeypatch)
    monkeypatch.setattr(ScenarioRunner, 'events_since',
        lambda self, index, *, stop=None: (_ for _ in ()).throw(
            AssertionError('the detaching whole-journal reader was used')))
    journal = []
    control_attempt['_runner_event_start'] = 0
    install_synthetic_dma_checker_report(control, control_attempt, journal)
    assert control.protocol_checker_case_report == reports[0]


def test_evidence_reads_the_whole_archive_once_and_each_case_slice(
        inputs, tmp_path, monkeypatch):
    runtime, attempt = make_case(inputs, tmp_path, monkeypatch)
    _attach_runner(runtime, attempt, pre_case=1)
    starts = []
    real_borrow = api()._borrow_events

    def spy(runner, start=0):
        starts.append(start)
        return real_borrow(runner, start)

    monkeypatch.setattr(api(), '_borrow_events', spy)
    api().capture_f6_case(runtime, attempt)
    # The tick-sample index reads only the case; declared_edges needs the whole
    # archive because the shared-slot projection re-checks earlier cases.
    assert starts == [1, 0]


def test_real_case_capture_is_identical_for_both_readers(
        tmp_path, monkeypatch):
    """The production F6 case: real Runner journal, real case event cursor."""
    from tests.integration.test_compiled_f6_consumer import (
        make_live_f6_fetch_attempt)

    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch,
        fetch_offsets=range(0, 32, 4))
    event_count = runtime.runner.event_count
    case_start = attempt['_runner_event_start']
    assert 0 < case_start < event_count
    starts = []
    real_borrow = api()._borrow_events

    def spy(runner, start=0):
        starts.append(start)
        return real_borrow(runner, start)

    monkeypatch.setattr(api(), '_borrow_events', spy)
    borrowed = api().capture_f6_case(runtime, attempt)
    assert starts == [case_start, 0]
    monkeypatch.setattr(api(), '_borrow_events',
        lambda runner, start=0: runner.events_since(start))
    detached = api().capture_f6_case(runtime, attempt)
    monkeypatch.setattr(api(), '_borrow_events', real_borrow)
    assert _json(borrowed) == _json(detached)
    projection = borrowed['evidence_inventory'][
        borrowed['observations'][
            'cross_component.declared_edge_hops']['evidence_refs'][0]]['details']
    assert projection['raw_evidence']
    # Nothing the case kept is a borrowed journal container.
    journal_identities = _identities(
        [row for row in runtime.runner._events])
    assert _identities(borrowed).isdisjoint(journal_identities)
    frozen = _json(borrowed)
    for row in runtime.runner._events:
        row['outputs'] = {'forged': True}
        row['local_tick'] = 0
    assert _json(borrowed) == frozen


def test_receipt_state_still_refuses_artifact_owner_drift(
        tmp_path, monkeypatch):
    """The receipt renders one document twice only when it is one object.

    A production session keeps its own deep copy of the artifact document, so
    the shortcut cannot fire there and both owners are still rendered and
    compared against the installed material.  Tampering with the artifact
    object's own document must still revoke the issuer; the first refusal
    revokes it permanently, so each direction needs its own runtime.
    """
    from myfuzz.scenario.f6_instruction_fetch_receipt import (
        f6_instruction_fetch_receipts)

    runtime = make_live(source_inputs(), tmp_path, monkeypatch)
    cpu = runtime.cpu
    assert f6_instruction_fetch_receipts(cpu) == ()
    assert cpu._artifact_document is not cpu.artifact.runtime_document
    cpu.artifact.runtime_document['drift'] = True
    with pytest.raises(ValueError, match='owner/configuration drift'):
        f6_instruction_fetch_receipts(cpu)
    cpu.artifact.runtime_document.pop('drift')
    with pytest.raises(ValueError, match='issuer revoked'):
        f6_instruction_fetch_receipts(cpu)
