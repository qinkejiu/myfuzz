from copy import deepcopy

import pytest

from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
from myfuzz.scenario.runtime_path_contract import RuntimePathContract
from tests.scenario.test_gpio_consumption_versions import access
from tests.scenario.test_gpio_register_evidence import read


def configuration():
    return dict(out=dict(level='L2', provider='gpio_register_version.v1',
        parameters=dict(component='gpio', register='out', bit_lo=0, width=2)),
        completion=dict(level='L3', provider='unavailable_completion.v1', parameters={}))


def consumer(config=None, **bounds):
    c = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    method = getattr(c, 'configure_semantic_events', None)
    if method:
        method(configuration() if config is None else config, **bounds)
    return c


def report(c):
    method = getattr(c, 'semantic_evidence_report', None)
    return method() if method else dict(operations=dict(out=dict(counts=dict(verified=0))))


@pytest.mark.parametrize('chunked', [True, False])
def test_shared_ingest_keeps_register_and_missing_function_scopes_separate(chunked):
    c = consumer()
    if chunked:
        c.ingest([access()])
        c.ingest([read()])
    else:
        c.ingest([access(), read()])
    result = report(c)
    assert result['operations']['out']['counts']['verified'] == 1
    assert result['operations']['out']['scope'] == 'register_version'
    assert result['operations']['out']['evidence']['ledger']['records']['verified'][0]['validity'] == 'historical'
    assert result['operations']['completion']['status'] == 'unknown'
    assert result['operations']['completion']['counts']['verified'] == 0
    assert c.report()['edges'] == []
    assert result['counts'] == {'register_version': 1, 'functional_consumption': 0}


@pytest.mark.parametrize('provider', ['register', 'sync'])
@pytest.mark.parametrize('chunked', [True, False])
def test_shared_ingest_reset_barrier_preserves_history_without_new_old_epoch_proof(provider, chunked):
    from tests.scenario.test_gpio_sync_evidence import rows as sync_rows
    if provider == 'register':
        config = dict(level='L2', provider='gpio_register_version.v1',
            parameters=dict(component='gpio', register='out', bit_lo=0, width=2))
        events = [access(), read(), dict(event_id=3, kind='reset_barrier', policy='warm_all'),
                  dict(read(3), event_id=4)]
    else:
        config = dict(level='L3', provider='gpio_sync_consumption.v1',
            parameters=dict(component='gpio', bit_lo=0, width=1))
        events = sync_rows()[:2] + [dict(event_id=3, kind='reset_barrier', policy='cold_all'),
                                   dict(sync_rows()[2], event_id=4)]
    snapshots = []
    for _ in range(2):  # Fresh software ingest; no certificate enrollment.
        c = consumer({'operation': config})
        if chunked:
            for event in events:
                c.ingest([deepcopy(event)])
        else:
            c.ingest(deepcopy(events))
        result = report(c)
        operation = result['operations']['operation']
        assert operation['counts']['verified'] == 1
        assert operation['status'] == 'incomplete'
        assert operation['evidence']['awaiting_native_reset'] is True
        assert operation['evidence']['ledger']['records']['verified'][0]['validity'] == 'historical'
        snapshots.append(result)
    assert snapshots[0] == snapshots[1]


def test_protocol_accept_and_forged_semantic_annotation_do_not_upgrade_unknown_provider():
    c = consumer()
    c.ingest([dict(event_id=1, kind='ip_request_accept', component='gpio'),
        dict(event_id=2, kind='ip_function_event', component='gpio',
             operation='completion', status='verified', proof_scope='functional_consumption')])
    r = report(c)
    assert r['operations']['completion']['status'] == 'unknown'
    assert r['counts']['functional_consumption'] == 0
    assert r['counts']['register_version'] == 0


def test_configuration_and_report_are_detached():
    config = configuration()
    c = consumer(config)
    config['out']['parameters']['component'] = 'other'
    c.ingest([access(), read()])
    r = report(c)
    r['operations']['out']['evidence']['certificates'].clear()
    assert report(c)['operations']['out']['counts']['verified'] == 1
    assert report(c)['configuration_sha256'] == r['configuration_sha256']


def test_unknown_provider_journal_conflict_is_incomplete_even_without_plugin():
    c = consumer({'missing': dict(level='L3', provider=None, parameters={})})
    c.ingest([dict(event_id=1, kind='other'), dict(event_id=1, kind='changed')])
    r = report(c)
    assert not r['journal_integrity']
    assert r['operations']['missing']['status'] == 'incomplete'


def test_configure_once_before_even_rejected_ingest():
    c = consumer()
    with pytest.raises(ValueError):
        c.configure_semantic_events(configuration())
    c = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    c.ingest([None])
    with pytest.raises(ValueError):
        c.configure_semantic_events(configuration())


@pytest.mark.parametrize('change', [dict(level='L1'), dict(level='L3'),
    dict(provider=''), dict(parameters=[]), dict(parameters={'component': 'x' * 1025}),
    dict(extra=True)])
def test_bad_or_incompatible_provider_configuration_rejected(change):
    config = configuration()
    config['out'].update(change)
    c = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    with pytest.raises(ValueError):
        c.configure_semantic_events(config)


@pytest.mark.parametrize('bounds', [dict(max_operations=0), dict(max_records=True),
    dict(max_records=65537), dict(max_event_gap=0), dict(max_accesses=False)])
def test_invalid_budget_rejected(bounds):
    c = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    with pytest.raises(ValueError):
        c.configure_semantic_events(configuration(), **bounds)


def test_failed_configuration_can_be_corrected_before_ingest():
    c = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    bad = configuration()
    bad['out']['parameters']['register'] = 'DONE'
    with pytest.raises(ValueError):
        c.configure_semantic_events(bad)
    c.configure_semantic_events(configuration())
    c.ingest([access(), read()])
    assert report(c)['counts']['register_version'] == 1


def test_missing_plugin_works_when_all_functional_imports_are_denied():
    import subprocess
    import sys
    script = '''
import importlib.abc, sys
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.rsplit('.', 1)[-1] in {'gpio_consumption', 'gpio_register_evidence', 'gpio_sync_evidence', 'uart_consumption'}:
            raise AssertionError(fullname)
sys.meta_path.insert(0, Deny())
from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
from myfuzz.scenario.runtime_path_contract import RuntimePathContract
c = EdgeProvenanceConsumer(RuntimePathContract('a'*64, (), ()))
c.configure_semantic_events({'unknown': {'level':'L3', 'provider':None, 'parameters':{}}})
c.ingest([{'event_id':1,'kind':'ip_request_accept'}])
assert c.semantic_evidence_report()['operations']['unknown']['status'] == 'unknown'
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
