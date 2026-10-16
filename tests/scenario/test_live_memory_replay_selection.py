"""Saved trusted policy configuration is selected only from verified manifest bytes."""
import copy
import hashlib
import json
import pytest


@pytest.fixture(scope='module')
def manifest(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    runner = make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('live-replay'),
        memory_commit_receipts=True, persistent_memory_runtime_contract_sha256='a' * 64)()
    return dict(runner=runner.identity_document(), runtime_paths={'contract_sha256': 'a' * 64})


def saved(tmp_path, document):
    raw = json.dumps(document).encode()
    (tmp_path / 'online_session_manifest.json').write_bytes(raw)
    return {'artifacts': {'online_session_manifest.json': hashlib.sha256(raw).hexdigest()}}


def test_saved_actual_factory_policy_returns_exact_contract_identity(tmp_path, manifest):
    from myfuzz.integration.ibex_pulp_online import _saved_persistent_memory_mode
    assert _saved_persistent_memory_mode(tmp_path, saved(tmp_path, manifest)) == 'a' * 64


def test_legacy_manifest_keeps_default_off(tmp_path):
    from myfuzz.integration.ibex_pulp_online import _saved_persistent_memory_mode
    assert _saved_persistent_memory_mode(tmp_path, None) is None
    assert _saved_persistent_memory_mode(tmp_path, saved(tmp_path, {'runner': {}})) is None


@pytest.mark.parametrize('change', ['digest', 'contract', 'read', 'write', 'budget', 'slot', 'policy'])
def test_changed_or_incomplete_saved_policy_is_rejected(tmp_path, manifest, change):
    from myfuzz.integration.ibex_pulp_online import _saved_persistent_memory_mode
    document = copy.deepcopy(manifest)
    runner = document['runner']
    if change == 'contract': document['runtime_paths']['contract_sha256'] = 'b' * 64
    if change == 'read': del runner['sessions']['cpu']['identity']['memory_read_issuance']
    if change == 'write': del runner['sessions']['cpu']['identity']['memory_commit_stream']
    if change == 'budget': runner['memory_dependency_evidence']['max_event_gap'] = True
    if change == 'slot': runner['persistent_memory_prerequisites']['instruction_slot_policy']['last_address'] += 4
    if change == 'policy': runner['persistent_memory_prerequisites']['dynamic_ram_policy']['declaration']['writer_kinds'] = ['INITIAL_IMAGE']
    verified = saved(tmp_path, document)
    if change == 'digest': (tmp_path / 'online_session_manifest.json').write_bytes(b'{}')
    with pytest.raises(ValueError):
        _saved_persistent_memory_mode(tmp_path, verified)


def test_replay_reselects_trusted_factory_from_verified_manifest(tmp_path, manifest, monkeypatch):
    from myfuzz.integration import ibex_pulp_online as module
    verified = saved(tmp_path, manifest)
    plan = tmp_path / 'online_plan.json'
    plan.write_bytes(b'{}')
    trace = tmp_path / 'online_final_trace.json'
    trace.write_text(json.dumps(dict(genome_sha256='0' * 64, status='complete', events=[],
                                    local_ticks={}, semantic_sha256='0' * 64, manifest_sha256='0' * 64)))
    monkeypatch.setattr(module, '_verify_online_run_identity', lambda *a, **k: verified)
    for name in ('_saved_cpu_retirement_mode', '_saved_gpio_consumption_mode', '_saved_pin8_native_irq_mode'):
        monkeypatch.setattr(module, name, lambda *a: False)
    monkeypatch.setattr(module, 'replay_online_session', lambda *a, **k: 'stopped-before-rtl')
    captured = {}
    def builder(*args, **kwargs):
        captured.update(kwargs)
        return lambda: None
    assert module.replay_pulp_dual_source_online_files(cache_dir=tmp_path / 'cache',
        plan_path=plan, trace_path=trace, factory_builder=builder) == 'stopped-before-rtl'
    assert captured['persistent_memory_runtime_contract_sha256'] == 'a' * 64
    assert captured['source_actions'] is True and captured['memory_commit_receipts'] is True
