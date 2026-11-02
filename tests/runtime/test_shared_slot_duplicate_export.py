"""The duplicated prefix export stays byte-identical and renders once.

``run_shared_slot_descriptor`` publishes the same prefix document to
``prefix.json`` and ``compiled_f6_prefix.json``.  They must stay byte-identical
(the 20261029 A/B recorded 211 425 765 bytes each) and the document must be
rendered with ``indent=2, sort_keys=True`` exactly once.
"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import json
import pytest


def test_json_republishes_identical_bytes_without_rendering(tmp_path):
    from myfuzz.runtime.generic_campaign import _json
    document = {'records': [{'raw8_hex': '00' * 8}],
                'flow_records': [], 'nested': {'b': 1, 'a': [1, 2, None]}}
    rendered = _json(document, tmp_path / 'prefix.json')
    assert rendered == (tmp_path / 'prefix.json').read_text()
    _json(document, tmp_path / 'compiled_f6_prefix.json', rendered=rendered)
    _json(document, tmp_path / 'rendered-again.json')
    assert ((tmp_path / 'compiled_f6_prefix.json').read_bytes()
            == (tmp_path / 'prefix.json').read_bytes())
    assert ((tmp_path / 'rendered-again.json').read_bytes()
            == (tmp_path / 'prefix.json').read_bytes())


def test_json_rejects_republishing_a_summary_document(tmp_path):
    from myfuzz.runtime.generic_campaign import _json
    with pytest.raises(ValueError, match='never republished'):
        _json({'status': 'completed'}, tmp_path / 'summary.json', rendered='{}\n')


@pytest.mark.parametrize('execution_mode', ['search', 'acceptance'])
def test_shared_slot_run_renders_the_prefix_once_and_writes_it_twice(
        tmp_path, monkeypatch, execution_mode):
    import myfuzz.runtime.preparation as preparation
    import myfuzz.runtime.generic_campaign as campaign
    import myfuzz.integration.compiled_f6 as f6
    import myfuzz.local_harness.build as build
    import myfuzz.local_harness.execution_validation as validation
    import myfuzz.composition.component_profile as profiles
    import myfuzz.runtime.flows.shared_slots as slots
    monkeypatch.setattr(profiles, 'supervisor_available', lambda: (False, 'test-host'))
    monkeypatch.setattr(build, 'host_source_discovery_scope', lambda **kw: nullcontext())
    monkeypatch.setattr(build, 'harness_validation_scope', lambda: nullcontext())
    monkeypatch.setattr(validation, 'execution_validation_scope', nullcontext)

    class Preparation:
        artifacts = {}

        def assert_current(self): pass

        def compiled_inputs(self): return {}

        def attach_runtime(self, **kwargs): pass

        def register_prepared_paths(self, **kwargs): pass

        def close(self): pass

    monkeypatch.setattr(preparation, 'create_preparation', lambda **kwargs: Preparation())

    class Runtime:
        def __init__(self, **kwargs):
            self.contract = {'program_contract': {
                'shared_slots': {'enabled_flows': ['F4', 'F6']}, 'slot_count': 2}}
            self.session = SimpleNamespace(_runtime_prepared=SimpleNamespace(
                runtime_paths=(), graph=object()))
            self.runner = SimpleNamespace(sessions={}, failure_status=None,
                                         event_count=0, events_since=lambda i: ())
            self.execution_binding = {}
            self.execution_binding_sha256 = 'a' * 64
            self.shared_storage_raw = {}
            self.shared_read_raw = {}
            self.rows = []

        def begin(self): pass

        def submit(self, raw, *, flow):
            self.rows.append({'flow': flow})
            return {'status': 'passed'}

        def finish(self):
            return {'records': [], 'flow_records': self.rows,
                    'original_execution_audit': {'identities': {}}}

        def replay(self, prefix, *, audit_sink):
            result = {'matches': True, 'execution_audit': {'identities': {}}}
            audit_sink(result)
            return result

    monkeypatch.setattr(f6, 'CompiledF6Runtime', Runtime)
    renders = []
    real_dumps = campaign.json.dumps

    def counting_dumps(value, *args, **kwargs):
        if isinstance(value, dict) and 'flow_records' in value:
            renders.append(True)
        return real_dumps(value, *args, **kwargs)

    monkeypatch.setattr(campaign.json, 'dumps', counting_dumps)
    replay_writes = []
    real_json = campaign._json
    def counting_export(value, path, **kwargs):
        if path.name == 'replay.json':
            replay_writes.append(True)
        return real_json(value, path, **kwargs)
    monkeypatch.setattr(campaign, '_json', counting_export)
    descriptor = SimpleNamespace(capability=Path('cap'), compose=Path('compose'),
                                 supplement=Path('supplement'),
                                 flow_ids=('F4', 'F6'), scenario_id='shared')
    result = slots.run_shared_slot_descriptor(
        descriptor, cases=[('F4', '55000000')], mode='original',
        case_root=tmp_path, base=tmp_path, cache=None, rounds=1, capacity=2,
        execution_mode=execution_mode, max_wall_seconds=None, record_selector=None,
        selected_count=None, expected_records=None, command_trace=None)
    out = tmp_path / 'original'
    assert len(renders) == 1
    assert len(replay_writes) == (1 if execution_mode == 'acceptance' else 0)
    assert result['replay_scope'] == ('within_invocation' if execution_mode == 'acceptance' else 'not-requested')
    assert (out / 'prefix.json').read_bytes() == (out / 'compiled_f6_prefix.json').read_bytes()
    # The consumer that reads the duplicate document still sees the prefix.
    duplicate = json.loads((out / 'compiled_f6_prefix.json').read_text())
    assert duplicate['original_execution_audit']['identities'] == {}
    assert duplicate['flow_records'] == [{'flow': 'F4'}]
    assert (out / 'shared_storage_raw.json').is_file()
