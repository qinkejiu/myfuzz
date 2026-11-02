"""Software-only regression of native-control helpers; no native construction.

The actual ScenarioSession property is exercised. Other runtime effects are
explicit software doubles; this file cannot establish native authority.
"""
from copy import deepcopy
import inspect
import json
from types import SimpleNamespace

import pytest

from myfuzz.scenario.session_runtime import ScenarioSession
from tests.integration import test_compiled_f2_rfuzz_native as controls


def software_runtime():
    assert isinstance(inspect.getattr_static(ScenarioSession, 'manifest_document'), property)
    session = ScenarioSession.__new__(ScenarioSession)
    session._manifest_document = {'schema_version': 'software_property_surface.v1', 'rows': []}
    session.encode_plan = lambda: b'{}'
    memory = SimpleNamespace(state_summary=lambda: {'software': True},
                             identity_document=lambda: {'software_slots': []})
    target = SimpleNamespace(native_reset_observation_commands=lambda: (),
                             _sequence=0, reset_epoch=0)
    runtime = SimpleNamespace(run_id='software-control', cursor=0, attempts=[], records=[], target_id='ip', cpu_id='cpu',
        runner=SimpleNamespace(sessions={'cpu': SimpleNamespace(memory=memory), 'ip': target},
                               local_ticks={'cpu': 0, 'ip': 0}, events_since=lambda index: ()),
        authority=SimpleNamespace(writes=lambda: []), session=session,
        finished=False, finish_diagnostic=None,
        assertion_results=lambda: {'software_typed_fixture': True},
        assertion_case_evidence=lambda: [], build_audit_snapshot=lambda: {'software_build': True})
    def finish():
        runtime.finished = True
        return {'software_prefix': True}
    runtime.finish = finish
    runtime.execution_audit = lambda: dict(closed=runtime.finished,
        identities={'cpu': {}, 'ip': {}},
        exits={name: dict(returncode=0, reaped=True) for name in ('cpu', 'ip')})
    return runtime


def suite(tmp_path):
    root = tmp_path / 'software-evidence'
    root.mkdir()
    return dict(root=root, artifacts={}, inputs={}, cache=tmp_path / 'unused-cache')


def patch_constructor(monkeypatch, runtime):
    monkeypatch.setattr(controls, 'CompiledF2Runtime', lambda **kwargs: runtime)
    monkeypatch.setattr(controls, 'build_compiled_f2_rfuzz_executor',
        lambda *args, **kwargs: SimpleNamespace(receipts=[], online_decisions=[]))


def test_no_effect_snapshot_uses_actual_manifest_property():
    runtime = software_runtime()
    before = deepcopy(runtime.session._manifest_document)
    snapshot = controls._no_effect_snapshot(runtime)
    assert snapshot['manifest'] == before
    snapshot['manifest']['rows'].append('detached')
    assert runtime.session.manifest_document == before


def test_terminal_export_reads_actual_manifest_property(monkeypatch, tmp_path):
    runtime = software_runtime()
    patch_constructor(monkeypatch, runtime)
    values = suite(tmp_path)
    with controls._runtime(values, 'property-export'):
        pass
    directory = values['root'] / 'property-export'
    assert runtime.finished is True
    assert json.loads((directory / 'session-manifest.json').read_bytes()) == runtime.session.manifest_document
    terminal = json.loads((directory / 'terminal.json').read_bytes())
    assert terminal['primary'] is None and terminal['export_errors'] == []
    assert 'session-manifest.json' in terminal['initial_output_sha256']


def test_unavailable_manifest_preserves_primary_and_attempts_other_exports(monkeypatch, tmp_path):
    runtime = software_runtime()
    runtime.session._manifest_document = None
    patch_constructor(monkeypatch, runtime)
    values = suite(tmp_path)
    primary = RuntimeError('software original primary')
    with pytest.raises(RuntimeError) as caught:
        with controls._runtime(values, 'property-unavailable'):
            raise primary
    assert caught.value is primary
    directory = values['root'] / 'property-unavailable'
    assert runtime.finished is True
    for filename in ('events.json', 'assertions.json', 'execution-audit.json', 'session-plan.json'):
        assert (directory / filename).is_file()
    terminal = json.loads((directory / 'terminal.json').read_bytes())
    assert terminal['primary'] == repr(primary)
    assert [row['stage'] for row in terminal['export_errors']] == ['session-manifest.json']
    assert any('session-manifest.json' in note for note in primary.__notes__)


def test_replay_export_failure_preserves_primary_and_attempts_all_envelopes(monkeypatch, tmp_path):
    runtime = software_runtime()
    primary = RuntimeError('software actual replay primary')
    def replay(plan, *, audit_sink):
        audit_sink({'actual_events': [{'software_partial': 1}]})
        audit_sink({'actual_events': [{'software_partial': 2}]})
        raise primary
    runtime.replay = replay
    save = controls._save
    attempted = []
    def exporter(path, document):
        attempted.append(path.name)
        if path.name == 'fresh-replay-0.json':
            raise OSError('software first replay export fault')
        return save(path, document)
    monkeypatch.setattr(controls, '_save', exporter)
    with pytest.raises(RuntimeError) as caught:
        controls._finish_and_replay(runtime, tmp_path)
    assert caught.value is primary
    assert attempted == ['prefix.json', 'fresh-replay-0.json', 'fresh-replay-1.json']
    assert json.loads((tmp_path / 'fresh-replay-1.json').read_bytes()) == {
        'actual_events': [{'software_partial': 2}]}
    assert any('software first replay export fault' in note for note in primary.__notes__)


def test_replay_export_failure_without_primary_keeps_first_export_error(monkeypatch, tmp_path):
    runtime = software_runtime()
    first = OSError('software first replay export fault')
    second = OSError('software second replay export fault')
    def replay(plan, *, audit_sink):
        audit_sink({'software_envelope': 1})
        audit_sink({'software_envelope': 2})
        return {'software_replay': True}
    runtime.replay = replay
    save = controls._save
    attempted = []
    def exporter(path, document):
        attempted.append(path.name)
        if path.name == 'fresh-replay-0.json':
            raise first
        if path.name == 'fresh-replay-1.json':
            raise second
        return save(path, document)
    monkeypatch.setattr(controls, '_save', exporter)
    with pytest.raises(OSError) as caught:
        controls._finish_and_replay(runtime, tmp_path)
    assert caught.value is first
    assert attempted == ['prefix.json', 'fresh-replay-0.json', 'fresh-replay-1.json']
    assert any('software second replay export fault' in note for note in first.__notes__)
