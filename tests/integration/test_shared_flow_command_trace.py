"""Per-component command traces on the shared-slot acceptance entry path.

The CV32E40P six-flow run saved no per-component local command trace because
``scripts/run_shared_all_flows.py`` (and the subset entry) never opened
``record_local_commands()`` and passed ``command_trace=None``.  These tests pin
the two halves of the fix without starting RTL:

* the entry CLI now forwards an actual recording object to ``run_descriptor``
  when ``--record-local-commands`` is given, and ``None`` otherwise;
* the exact join the shared-slot kernel performs (``recorded_command_documents``
  with audited execution identities) produces a ``local_command_trace.v1``
  document from an already saved session, and that document is immediately
  accepted by the offline replay selector.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
DECLARED = ROOT / ('research/input-strategy-audit-20261027/runs/'
                   'declared-irq-f5-20261030')
IBEX_DESCRIPTOR = (ROOT / 'configs/scenarios/'
                   'compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json')


def _fake_summary(case_root):
    return {'case_count': 8, 'f6_case_count': 2,
            'flow_case_counts': {flow: 1 for flow in
                                 ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')},
            'replay_matches': True, 'evidence_dir': str(case_root)}


def _invoke(monkeypatch, module, argv):
    """Run one entry CLI against a stub runtime and capture its trace argument."""
    from myfuzz.local_harness import session as session_module
    captured = {}

    def fake_run_descriptor(descriptor, **kwargs):
        captured['kwargs'] = kwargs
        captured['trace'] = kwargs.get('command_trace')
        captured['active'] = session_module._local_command_trace.get()
        return _fake_summary(kwargs['case_root'])

    monkeypatch.setattr('myfuzz.runtime.generic_campaign.run_descriptor',
                        fake_run_descriptor)
    monkeypatch.setattr(sys, 'argv', argv)
    module.main()
    return captured


def test_all_flows_entry_without_the_flag_passes_no_trace(monkeypatch, tmp_path):
    import scripts.run_shared_all_flows as entry
    captured = _invoke(monkeypatch, entry, [
        'run_shared_all_flows.py', '--output', str(tmp_path / 'run'), '--native'])
    assert captured['trace'] is None
    assert captured['active'] is None


def test_all_flows_entry_flag_forwards_an_active_recording(monkeypatch, tmp_path):
    import scripts.run_shared_all_flows as entry
    captured = _invoke(monkeypatch, entry, [
        'run_shared_all_flows.py', '--output', str(tmp_path / 'run'), '--native',
        '--record-local-commands'])
    trace = captured['trace']
    assert trace is not None
    # The recording context is active while the runtime executes, so the
    # sessions see it through the session-level ContextVar.
    assert captured['active'] is trace
    assert captured['kwargs']['flow'] == 'mixed'


def test_subset_entry_flag_forwards_an_active_recording(monkeypatch, tmp_path):
    import scripts.run_shared_slot_subset as entry
    captured = _invoke(monkeypatch, entry, [
        'run_shared_slot_subset.py', '--output', str(tmp_path / 'run'), '--native',
        '--descriptor', str(IBEX_DESCRIPTOR), '--records', 'F4:55000000',
        '--record-local-commands'])
    assert captured['trace'] is not None
    assert captured['active'] is captured['trace']


def _saved_f5_session():
    """One already saved run: trace sessions plus the summary identities."""
    run = DECLARED / 'wb-timer' / 'original'
    trace_path = run / 'original' / 'local-command-trace.json'
    summary_path = run / 'summary.json'
    if not trace_path.is_file() or not summary_path.is_file():
        pytest.skip('declared-IRQ F5 saved session unavailable')
    return run, (json.loads(trace_path.read_text(encoding='utf-8')),
                 json.loads(summary_path.read_text(encoding='utf-8')))


def _rows_and_executions(trace, summary):
    rows = [dict(session) for session in trace['sessions'].values()]
    executions = {'original': {
        row['component']: {key: row[key] for key in (
            'component', 'execution_nonce', 'pid', 'artifact_digest',
            'build_digest', 'binary_sha256')}
        for row in summary['processes']}}
    return rows, executions


def test_saved_session_export_is_a_replayable_component_trace():
    run, (trace, summary) = _saved_f5_session()
    from myfuzz.runtime.recorded_commands import recorded_command_documents
    rows, executions = _rows_and_executions(trace, summary)
    documents = recorded_command_documents(rows, scope='mixed', audited=True,
                                           executions=executions)
    document = documents['original']
    assert document['schema_version'] == 'local_command_trace.v1'
    assert 'original actual session commands' in document['scope']
    assert set(document['sessions']) == set(trace['sessions'])
    for component, session in document['sessions'].items():
        assert session['complete'] is True
        assert session['records'] == trace['sessions'][component]['records']

    # The exported document is exactly what the offline replay tool consumes.
    from scripts.measure_local_coverage import select_recorded_session
    target = next(row for row in summary['processes']
                  if row['component'] == 'wb_timer_active')
    commands, replies, binary = select_recorded_session(
        document, 'wb_timer_active', target['build_digest'])
    measurement = run.parent / 'coverage-target'
    if not measurement.is_dir():
        pytest.skip('saved target measurement unavailable')
    assert binary == target['binary_sha256']
    assert (measurement / 'commands.txt').read_text(encoding='ascii') == \
        '\n'.join([*commands, 'END', ''])
    saved_replies = [line for line in (measurement / 'replies.txt').read_text(
        encoding='utf-8').splitlines() if line.startswith('RESULT ')]
    assert saved_replies == replies


def test_saved_session_export_refuses_a_mismatched_process_identity():
    _run, (trace, summary) = _saved_f5_session()
    from myfuzz.runtime.recorded_commands import recorded_command_documents
    rows, executions = _rows_and_executions(trace, summary)
    executions['original']['cpu']['pid'] = 1
    with pytest.raises(ValueError, match='process identity mismatch'):
        recorded_command_documents(rows, scope='mixed', audited=True,
                                   executions=executions)
