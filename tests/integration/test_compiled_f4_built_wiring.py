"""Build receipt ordering and constructor failure audits without native startup."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.integration.compiled_f4 import CompiledF4Runtime
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.integration.test_compiled_f4_storage_producer import timer_loaded

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def material(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('built-f4-wiring'))


class StopBeforeNative(Exception):
    pass


@contextmanager
def fake_preparation():
    """Replace only compilation/output verification; keep sealed session methods."""
    import shutil
    from myfuzz.local_harness.build import _prepare, build_local_harness_with_receipt, _canonical
    records={}; order=[]
    def build(artifact,*,base_dir,cache_dir):
        name=artifact.plan.request.instance_id
        order.append(('prepare',name))
        identity,snapshots=_prepare(artifact,base_dir)
        directory=Path(cache_dir).resolve()/identity['build_digest']
        directory.mkdir(parents=True,exist_ok=True)
        for source,raw in snapshots.items():
            output=directory/'inputs'/source
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_bytes(raw)
        # Source-backed cache material is real; only compiler output is a fixture.
        binary=directory/'harness'
        shutil.copy2('/usr/bin/true',binary)
        manifest={'schema_version':'local_harness_build_cache.v1','identity':identity,
            'binary_sha256':sha256(binary.read_bytes()).hexdigest(),
            'actual_build_argv':['fixture-no-native-start']}
        (directory/'manifest.json').write_bytes(_canonical(manifest))
        result=build_local_harness_with_receipt(artifact,base_dir=base_dir,cache_dir=cache_dir)
        records[name]=result.receipt_document()
        return result
    with patch('myfuzz.local_harness.session.build_local_harness_with_receipt',build,create=True):
        yield order, records


def test_receipts_are_prepared_and_bound_before_real_session_begin(material,tmp_path):
    artifacts,inputs=material
    captured=[]
    def inspect(session):
        runtime=session.checker.__self__
        document=runtime.execution_binding.document()
        assert set(document.get('built_executable_receipts',{}))=={'processor','peripheral'}, 'missing live built receipts'
        for name,local in runtime.runner.sessions.items():
            assert document['built_executable_receipts'][name]==local.built_executable_receipt_document()
        captured.append(document)
        raise StopBeforeNative
    with fake_preparation() as (order,_), patch.object(ScenarioSession,'begin',inspect):
        with pytest.raises(StopBeforeNative):
            CompiledF4Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,cache_dir=tmp_path/'cache')
    assert len(captured)==1
    assert sorted(x[1] for x in order if x[0]=='prepare')==['peripheral','processor']


def test_fresh_expected_receipt_mismatch_refuses_before_begin(material,tmp_path):
    artifacts,inputs=material
    with fake_preparation(), patch.object(ScenarioSession,'begin',side_effect=AssertionError('must not start')) as begin:
        with pytest.raises(ValueError,match='built.*identity|build.*receipt'):
            CompiledF4Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,
                cache_dir=tmp_path/'cache',expected_built_receipts={})
    begin.assert_not_called()


def test_constructor_failure_publishes_partial_build_audit(material,tmp_path):
    artifacts,inputs=material
    audits=[]
    with fake_preparation(), patch.object(ScenarioSession,'begin',side_effect=StopBeforeNative):
        with pytest.raises(StopBeforeNative):
            CompiledF4Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,
                cache_dir=tmp_path/'cache',build_audit_sink=audits.append)
    assert audits and set(audits[-1]['receipts'])=={'processor','peripheral'}
    assert audits[-1]['execution_audit']['closed'] is True
