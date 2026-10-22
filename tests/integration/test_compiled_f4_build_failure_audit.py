"""Secondary diagnostic failures cannot hide the original fresh error."""
from copy import deepcopy

import pytest

from myfuzz.integration.compiled_f4 import CompiledF4Runtime


PLAN={'records':[{'raw':'00'}]}


class ReplayFixture(CompiledF4Runtime):
    def __init__(self, **kwargs):
        self.is_fresh=bool(kwargs)
        self.finished=False
        self.audit_broken=False
        self.artifacts={};self.inputs={};self.base_dir='.';self.cache_dir='.'
        self.run_id='audit';self.rounds=1;self.max_cases=1
        self._built_receipts={};self._replay_identities=[]
        self._process_identities={'cpu':dict(component='cpu',role='cpu',artifact_digest='a',
            pid=2 if self.is_fresh else 1,execution_nonce='fresh' if self.is_fresh else 'original')}
        self.runner=type('Runner',(),{'events_since':lambda self,index:()})()
    def _stable(self,**kwargs):pass
    def finish(self):self.finished=True;return deepcopy(PLAN)
    def execution_audit(self):
        if self.audit_broken:raise RuntimeError('audit-drift')
        return {'identities':self._process_identities,'exits':{},'closed':self.finished}
    def submit(self,raw):
        self.audit_broken=True
        raise ValueError('primary-candidate-failure')
    def build_audit_snapshot(self,**kwargs):
        return {'available_partial':True}


def test_fresh_audit_drift_keeps_primary_error_and_partial_sink():
    runtime=ReplayFixture();saved=[]
    with pytest.raises(ValueError,match='primary-candidate-failure') as caught:
        runtime.replay(PLAN,audit_sink=saved.append)
    assert saved and saved[-1]['fresh_build']=={'available_partial':True}
    assert any('audit-drift' in note for note in caught.value.__notes__)


def test_failed_constructor_sink_does_not_mask_primary():
    primary=ValueError('fresh-constructor-failure')
    class FailedFresh(ReplayFixture):
        def __init__(self,**kwargs):
            if kwargs:raise primary
            super().__init__()
    def failed_sink(snapshot):raise OSError('sink-failure')
    with pytest.raises(ValueError) as caught:
        FailedFresh().replay(PLAN,audit_sink=failed_sink)
    assert caught.value is primary
    assert any('sink-failure' in note for note in primary.__notes__)


class DiagnosticLocal:
    def __init__(self, pid):
        self.broken=False
        self.row=dict(pid=pid,execution_nonce=str(pid),returncode=None,reaped=False)
    def read(self, value):
        if self.broken:raise ValueError('receipt-pin-drift')
        return deepcopy(value)
    def built_executable_receipt_document(self):return self.read({'binary_sha256':'saved'})
    def build_preparation_observation_document(self):return self.read({'outcome':'cache_hit'})
    def built_executable_launch_observations(self):return self.read((self.row,))
    def _built_executable_launch_diagnostics(self):return (deepcopy(self.row),)


def test_snapshot_pin_refusal_retains_each_component_and_current_close_evidence():
    runtime=object.__new__(CompiledF4Runtime)
    cpu=DiagnosticLocal(1);target=DiagnosticLocal(2)
    runtime.cpu_id='cpu';runtime._build_sessions={'cpu':cpu,'target':target}
    previous=runtime.build_audit_snapshot()
    cpu.broken=True;cpu.row.update(returncode=0,reaped=True)
    current=runtime.build_audit_snapshot(closed=True)
    assert current['receipts']==previous['receipts']
    assert current['preparation_observations']==previous['preparation_observations']
    assert current['execution_audit']['identities']['target']['pid']==2
    assert current['execution_audit']['exits']['cpu']==dict(returncode=0,reaped=True)
    assert set(current['unavailable']['cpu'])=={'receipt','preparation','launches'}
    current['receipts']['cpu']['binary_sha256']='changed'
    assert runtime.build_audit_snapshot()['receipts']['cpu']['binary_sha256']=='saved'


def test_constructor_snapshot_failure_keeps_previous_capture_and_primary():
    from myfuzz.integration.compiled_f4 import _capture_build_construction
    primary=ValueError('constructor-primary')
    saved=[]
    class Failed:
        @_capture_build_construction
        def __init__(self, **kwargs):
            self._build_audit_previous={'receipts':{'cpu':{'saved':True}}}
            raise primary
        def build_audit_snapshot(self,**kwargs):raise RuntimeError('snapshot-secondary')
    with pytest.raises(ValueError) as caught:Failed(build_audit_sink=saved.append)
    assert caught.value is primary
    assert saved[-1]['receipts']['cpu']=={'saved':True}
    assert saved[-1]['unavailable']
    assert any('snapshot-secondary' in note for note in primary.__notes__)


def test_fresh_later_snapshot_failure_keeps_startup_capture_and_primary():
    primary=ValueError('fresh-primary')
    class LaterFailure(ReplayFixture):
        def build_audit_snapshot(self, **kwargs):
            if self.audit_broken:raise RuntimeError('fresh-snapshot-secondary')
            return dict(startup_observed=True)
        def submit(self, raw):
            self.audit_broken=True
            raise primary
    saved=[]
    with pytest.raises(ValueError) as caught:LaterFailure().replay(PLAN,audit_sink=saved.append)
    assert caught.value is primary
    assert saved[-1]['fresh_build']['startup_observed'] is True
    assert saved[-1]['fresh_build']['unavailable']
    assert any('fresh-snapshot-secondary' in note for note in primary.__notes__)


def test_fresh_pin_drift_exports_unaffected_and_current_reap_material():
    primary=ValueError('fresh-pin-primary')
    class PinDriftReplay(ReplayFixture):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.cpu_id='cpu'
            self._build_sessions={'cpu':DiagnosticLocal(2 if kwargs else 1),
                                  'target':DiagnosticLocal(4 if kwargs else 3)}
        def build_audit_snapshot(self, **kwargs):
            return CompiledF4Runtime.build_audit_snapshot(self,**kwargs)
        def submit(self,raw):
            self._build_sessions['cpu'].broken=True
            raise primary
        def finish(self):
            self.finished=True
            for local in self._build_sessions.values():local.row.update(returncode=0,reaped=True)
            return deepcopy(PLAN)
    saved=[]
    with pytest.raises(ValueError) as caught:PinDriftReplay().replay(PLAN,audit_sink=saved.append)
    assert caught.value is primary
    fresh=saved[-1]['fresh_build']
    assert set(fresh['receipts'])==set(fresh['preparation_observations'])=={'cpu','target'}
    assert fresh['execution_audit']['identities']['target']['pid']==4
    assert fresh['execution_audit']['exits']['cpu']==dict(returncode=0,reaped=True)
    assert fresh['unavailable']['cpu']
