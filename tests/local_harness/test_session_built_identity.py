"""Opted session pins and Linux live executable lifecycle checks."""
import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from myfuzz.local_harness.session import GeneratedLocalSession

D = 'a' * 64

class Result:
    def __init__(self, path):
        self.binary_path = path
        self.raw = path.read_bytes()
        self.receipt = dict(schema_version='local_harness_built_receipt.v1', artifact_digest=D,
                            build_digest='b'*64, build_identity={'build_digest':'b'*64},
                            binary_sha256=hashlib.sha256(self.raw).hexdigest())
        self.receipt_sha256 = hashlib.sha256(json.dumps(self.receipt,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def receipt_document(self): return copy.deepcopy(self.receipt)
    def observation_document(self): return {'outcome':'compiled_published'}
    def validate_current(self, artifact, *, base_dir, cache_dir):
        if self.binary_path.read_bytes() != self.raw: raise ValueError('binary drift')
        return self.binary_path

@pytest.fixture
def setup(tmp_path):
    document = dict(schema_version='local_runtime_artifact.v1', driver_schema_version='local_driver_generation.v1',
        status='driver_generated', driver_status='generated', artifact_digest=D, kind='apb_gpio',
        driver_reset=dict(schema_version='generated_local_reset.v1',reset_assert_ticks=8,reset_release_ticks=4))
    session = GeneratedLocalSession(SimpleNamespace(runtime_document=document),base_dir=tmp_path,cache_dir=tmp_path/'cache')
    return session, tmp_path

def prepare(session, path):
    result = Result(path)
    session.configure_built_executable_receipt()
    with patch('myfuzz.local_harness.session.build_local_harness_with_receipt',return_value=result,create=True) as build:
        session.prepare_local()
        session.prepare_local()
        assert build.call_count == 1
    return result

def test_early_irreversible_optin_and_failed_prepare(setup):
    s,p=setup
    with pytest.raises((RuntimeError,ValueError)): s.built_executable_receipt_document()
    with patch('myfuzz.local_harness.session.build_local_harness',side_effect=ValueError('failure')):
        with pytest.raises(ValueError): s.prepare_local()
    with pytest.raises((RuntimeError,ValueError)): s.configure_built_executable_receipt()

def test_fixed_pin_detached_views_and_binary_drift(setup):
    s,p=setup; binary=p/'binary'; shutil.copy('/bin/cat',binary)
    result=prepare(s,binary)
    s.built_executable_receipt_document()['binary_sha256']='bad'
    assert s.validate_built_executable_receipt()==result.receipt_document()
    assert s.build_preparation_observation_document()=={'outcome':'compiled_published'}
    with pytest.raises((RuntimeError,ValueError)): s.configure_built_executable_receipt()
    s._binary=p/'other'
    with pytest.raises((RuntimeError,ValueError)): s.validate_built_executable_receipt()
    s._binary=binary; binary.write_bytes(b'changed')
    with patch('myfuzz.local_harness.session.subprocess.Popen') as popen:
        with pytest.raises(ValueError): s.begin_case('case')
        popen.assert_not_called()

def native(p,ready=True,bad_reply=False):
    source=p/'driver.c'; binary=p/'driver'
    source.write_text('#include <stdio.h>\n#include <unistd.h>\nint main(){ puts("READY local_driver.v1 '+(D if ready else 'f'*64)+' 8 4"); fflush(stdout); char b[32]; while(fgets(b,sizeof b,stdin)) { if(b[0]==\'E\') break; '+('puts("BAD"); fflush(stdout);' if bad_reply else '')+' } return 0;}')
    subprocess.run(['cc',str(source),'-o',str(binary)],check=True)
    return binary

@pytest.mark.parametrize('ready',[True,False])
def test_native_live_check_and_retained_exit(setup,ready):
    s,p=setup; result=prepare(s,native(p,ready))
    try:
        if ready: s.begin_case('case')
        else:
            with pytest.raises(ValueError): s.begin_case('case')
    finally: s.end_case()
    row,=s.built_executable_launch_observations()
    assert row['pid']>0 and row['execution_nonce'] and row['argv']
    assert row['observed_executable_sha256']==result.receipt['binary_sha256']
    assert row['reaped'] is True and row['returncode'] is not None
    assert row['ready_artifact_digest']==(D if ready else None)
    assert row['failure_stage']==(None if ready else 'ready')

def test_script_interpreter_refused_before_ready(setup):
    s,p=setup; script=p/'script'; script.write_text('#!/bin/sh\nsleep 10\n');script.chmod(0o755)
    prepare(s,script)
    with patch('myfuzz.local_harness.session.read_startup_ready') as ready:
        with pytest.raises((ValueError,RuntimeError)): s.begin_case('case')
        ready.assert_not_called()
    row,=s.built_executable_launch_observations()
    assert row['failure_stage']=='live_executable' and row['reaped']

def test_ordinary_identity_keeps_existing_shape(setup):
    s,p=setup
    with patch('myfuzz.local_harness.session.local_build_identity',return_value={'build_digest':'b'*64}):
        assert set(s.identity_document())=={'schema_version','runtime_artifact','build_identity','command_timeout_seconds'}

def test_opted_identity_and_launch_views_are_detached(setup):
    s,p=setup; result=prepare(s,native(p))
    with patch('myfuzz.local_harness.session.local_build_identity',return_value=result.receipt['build_identity']):
        identity=s.identity_document()
    assert identity['built_executable_receipt']==result.receipt
    assert 'outcome' not in json.dumps(identity)
    s.begin_case('case');s.end_case()
    rows=s.built_executable_launch_observations(); rows[0]['argv'].append('bad')
    assert s.built_executable_launch_observations()[0]['argv']==[str(result.binary_path)]

def test_revalidation_failure_and_missing_binary_cannot_launch(setup):
    s,p=setup; binary=p/'binary'; shutil.copy('/bin/cat',binary)
    result=prepare(s,binary)
    with patch.object(result,'validate_current',side_effect=ValueError('manifest/input drift')):
        with patch('myfuzz.local_harness.session.subprocess.Popen') as popen:
            with pytest.raises(ValueError,match='drift'): s.begin_case('case')
            popen.assert_not_called()
    s._binary=None
    with patch('myfuzz.local_harness.session.build_local_harness_with_receipt') as build:
        with pytest.raises(ValueError,match='path'): s.prepare_local()
        build.assert_not_called()

def test_artifact_numeric_type_drift_refused(setup):
    s,p=setup; binary=p/'binary'; shutil.copy('/bin/cat',binary);prepare(s,binary)
    s.artifact.runtime_document['driver_reset']['reset_assert_ticks']=8.0
    with pytest.raises(ValueError,match='changed'):s.validate_built_executable_receipt()

def test_failed_opted_builder_retains_detached_observation(setup):
    s,p=setup;s.configure_built_executable_receipt()
    error=ValueError('compile failed');error.preparation_observation={'failure_stage':'compile'}
    with patch('myfuzz.local_harness.session.build_local_harness_with_receipt',side_effect=error):
        with pytest.raises(ValueError):s.prepare_local()
    view=s.build_preparation_observation_document();view['failure_stage']='changed'
    assert s.build_preparation_observation_document()=={'failure_stage':'compile'}
    with pytest.raises(ValueError):s.built_executable_receipt_document()
    with pytest.raises(ValueError):s.configure_built_executable_receipt()

@pytest.mark.parametrize('operation',['identity','prepare','begin','validate','receipt','observation'])
def test_removed_private_pin_cannot_downgrade_opted_session(setup,operation):
    from myfuzz.local_harness import session as module
    s,p=setup; binary=p/'binary';shutil.copy('/bin/cat',binary);prepare(s,binary)
    del module._BUILT_SESSION_PINS[s]
    operations=dict(identity=s.identity_document,prepare=s.prepare_local,
                    begin=lambda:s.begin_case('case'),validate=s.validate_built_executable_receipt,
                    receipt=s.built_executable_receipt_document,
                    observation=s.build_preparation_observation_document)
    with patch('myfuzz.local_harness.session.local_build_identity',return_value={}):
        with patch('myfuzz.local_harness.session.build_local_harness',return_value=binary) as old_build:
            with patch('myfuzz.local_harness.session.subprocess.Popen') as popen:
                with pytest.raises(ValueError,match='pin|receipt'):operations[operation]()
                old_build.assert_not_called();popen.assert_not_called()


def test_post_ready_bad_reply_preserves_primary_failure_and_reap(setup):
    s,p=setup;prepare(s,native(p,bad_reply=True));s.begin_case('case')
    with pytest.raises(ValueError) as primary:s.command('STEP_GPIO',(0,))
    assert s.process is None
    row,=s.built_executable_launch_observations()
    assert row['failure_stage']=='command'
    assert row['error']==repr(primary.value)
    assert row['ready_artifact_digest']==D and row['aborted'] and row['reaped']

def test_replaced_private_pin_cannot_reissue_identity(setup):
    from myfuzz.local_harness import session as module
    s,p=setup; binary=p/'binary';shutil.copy('/bin/cat',binary);prepare(s,binary)
    old=module._BUILT_SESSION_PINS[s]
    module._BUILT_SESSION_PINS[s]=tuple(list(old))
    with pytest.raises(ValueError,match='pin'):s.validate_built_executable_receipt()


@pytest.mark.parametrize('pin_drift',['removed','replaced'])
def test_pin_drift_keeps_actual_close_in_diagnostic_rows(setup,pin_drift):
    from myfuzz.local_harness import session as module
    s,p=setup;prepare(s,native(p));s.begin_case('case')
    if pin_drift=='removed':del module._BUILT_SESSION_PINS[s]
    else:module._BUILT_SESSION_PINS[s]=tuple(list(module._BUILT_SESSION_PINS[s]))
    try:
        with pytest.raises(ValueError,match='pin|receipt'):s.built_executable_launch_observations()
    finally:s.end_case()
    assert s.process is None
    assert s._built_launches[-1]['reaped'] is True
    assert s._built_launches[-1]['returncode']==0
    diagnostic=s._built_executable_launch_diagnostics()
    diagnostic[0]['reaped']=False
    assert s._built_executable_launch_diagnostics()[0]['reaped'] is True
    with pytest.raises(ValueError,match='pin|receipt'):s.built_executable_receipt_document()
