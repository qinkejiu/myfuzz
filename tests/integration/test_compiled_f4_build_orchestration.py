"""Constructor errors must keep their original exception and partial build join."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.integration.compiled_rfuzz import run_compiled_f4_rfuzz_session
from tests.integration.test_compiled_f4_storage_producer import timer_loaded

ROOT=Path(__file__).resolve().parents[2]


def test_failed_original_constructor_persists_available_join(tmp_path):
    generated=tmp_path/'generated';generated.mkdir()
    artifacts,inputs=timer_loaded(generated)
    cache=tmp_path/'cache';cache.mkdir()
    output=tmp_path/'output';output.mkdir()
    partial={'receipts':{},'preparation_observations':{'peripheral':{'failure_stage':'compile'}},
        'execution_audit':{'identities':{},'exits':{},'closed':True}}
    original=ValueError('fixture-build-failed')
    def refuse(**kwargs):
        assert 'build_audit_sink' in kwargs, 'constructor audit sink missing'
        kwargs['build_audit_sink'](partial)
        raise original
    with patch('myfuzz.integration.compiled_rfuzz.CompiledF4Runtime',side_effect=refuse):
        with pytest.raises(ValueError) as caught:
            run_compiled_f4_rfuzz_session(artifacts=artifacts,compiled_inputs=inputs,
                base_dir=ROOT,cache_dir=cache,run_id='failedbuild',session_dir=tmp_path/'session',
                output_dir=output,client_binary=tmp_path/'client',budget_seconds=1,max_tests=1,
                search_seed=1,max_runs_per_batch=1)
    assert caught.value is original
    document=json.loads((output/'compiled_f4_build_join.v1.json').read_text())
    assert document['status']=='refused'
    assert document['original']==partial
    assert document['fresh']=={}


def test_original_snapshot_failure_writes_refused_join_with_previous_capture(tmp_path):
    generated=tmp_path/'generated';generated.mkdir()
    artifacts,inputs=timer_loaded(generated)
    cache=tmp_path/'cache';cache.mkdir()
    output=tmp_path/'output';output.mkdir()
    primary=ValueError('original-primary')
    partial={'receipts':{'processor':{'observed':True}},
        'execution_audit':{'identities':{'processor':{'pid':42}},
                           'exits':{'processor':{'returncode':0,'reaped':True}},'closed':True}}
    class FailedOriginal:
        finished=False
        execution_binding=type('Binding',(),{'document':lambda self:None})()
        def __init__(self,**kwargs):kwargs['build_audit_sink'](deepcopy(partial))
        def finish(self):self.finished=True;raise primary
        def build_audit_snapshot(self):raise RuntimeError('original-snapshot-secondary')
    from copy import deepcopy
    with patch('myfuzz.integration.compiled_rfuzz.CompiledF4Runtime',FailedOriginal), patch(
            'myfuzz.integration.compiled_rfuzz.build_compiled_rfuzz_executor',return_value=object()), patch(
            'myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live',side_effect=primary):
        with pytest.raises(ValueError) as caught:
            run_compiled_f4_rfuzz_session(artifacts=artifacts,compiled_inputs=inputs,
                base_dir=ROOT,cache_dir=cache,run_id='failedoriginal',session_dir=tmp_path/'session',
                output_dir=output,client_binary=tmp_path/'client',budget_seconds=1,max_tests=1,
                search_seed=1,max_runs_per_batch=1)
    assert caught.value is primary
    document=json.loads((output/'compiled_f4_build_join.v1.json').read_text())
    assert document['status']=='refused'
    assert document['original']['receipts']==partial['receipts']
    assert document['original']['execution_audit']==partial['execution_audit']
    assert document['original']['unavailable']
    assert any('original-snapshot-secondary' in note for note in primary.__notes__)


def test_original_pin_drift_persists_partial_rows_and_current_cleanup(tmp_path):
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from tests.integration.test_compiled_f4_build_failure_audit import DiagnosticLocal
    generated=tmp_path/'generated';generated.mkdir()
    artifacts,inputs=timer_loaded(generated)
    cache=tmp_path/'cache';cache.mkdir()
    output=tmp_path/'output';output.mkdir()
    primary=ValueError('original-pin-primary')
    instances=[]
    class PinDriftOriginal:
        finished=False
        execution_binding=type('Binding',(),{'document':lambda self:None})()
        def __init__(self,**kwargs):
            self.cpu_id='processor'
            self._build_sessions={'processor':DiagnosticLocal(42),'peripheral':DiagnosticLocal(43)}
            kwargs['build_audit_sink'](self.build_audit_snapshot())
            instances.append(self)
        def build_audit_snapshot(self):return CompiledF4Runtime.build_audit_snapshot(self)
        def finish(self):
            self.finished=True
            for local in self._build_sessions.values():local.row.update(returncode=0,reaped=True)
    def refuse(**kwargs):
        instances[0]._build_sessions['processor'].broken=True
        raise primary
    with patch('myfuzz.integration.compiled_rfuzz.CompiledF4Runtime',PinDriftOriginal), patch(
            'myfuzz.integration.compiled_rfuzz.build_compiled_rfuzz_executor',return_value=object()), patch(
            'myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live',side_effect=refuse):
        with pytest.raises(ValueError) as caught:
            run_compiled_f4_rfuzz_session(artifacts=artifacts,compiled_inputs=inputs,
                base_dir=ROOT,cache_dir=cache,run_id='originalpin',session_dir=tmp_path/'session',
                output_dir=output,client_binary=tmp_path/'client',budget_seconds=1,max_tests=1,
                search_seed=1,max_runs_per_batch=1)
    assert caught.value is primary
    document=json.loads((output/'compiled_f4_build_join.v1.json').read_text())
    assert document['status']=='refused'
    original=document['original']
    assert set(original['receipts'])==set(original['preparation_observations'])=={'processor','peripheral'}
    assert original['execution_audit']['identities']['peripheral']['pid']==43
    assert original['execution_audit']['exits']['processor']==dict(returncode=0,reaped=True)
    assert original['unavailable']['processor']
    assert any('diagnostics unavailable' in note for note in primary.__notes__)
