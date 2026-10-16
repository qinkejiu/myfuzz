"""Real renamed profile source gate/rendering; no simulation or fact stubs."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import pytest
from tests.composition.test_register_alias_capability import documents
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.local_harness.request import load_local_harness_request
from myfuzz.local_harness.plan import plan_local_harness
from myfuzz.local_harness.renderer import render_local_harness
from myfuzz.local_harness.source_lock import verify_local_source_lock
from myfuzz.local_harness.runtime_renderer import render_local_runtime
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation


@pytest.fixture(scope='module')
def source_verified_generic_artifact(tmp_path_factory, request):
    workspace=Path(__file__).resolve().parents[2]
    base=tmp_path_factory.mktemp('actual-generic-source-root')
    raw,profile,sidecar=documents(renamed=True)
    assert profile.component_id=='generic_register_device'
    source_root=raw['source']['root']
    shutil.copytree(workspace/source_root,base/source_root)
    # Runtime/driver rendering authenticates current in-tree adapter/header bytes
    # separately from the selected IP Git tree. Keep real copies under base.
    for relative in ('src/myfuzz/protocols/rtl', 'src/myfuzz/local_harness/rtl', 'src/myfuzz/scenario/rtl'):
        shutil.copytree(workspace/relative, base/relative)
    lock=json.loads((workspace/'configs/soc/sources.lock.json').read_bytes())
    record=deepcopy(next(row for row in lock['components'] if row['id']=='pulp_gpio'))
    record['id']=profile.component_id
    evidence_path=record['elaboration']['evidence']
    evidence=json.loads((workspace/evidence_path).read_bytes())
    evidence['component']=profile.component_id
    evidence_bytes=(json.dumps(evidence,sort_keys=True,indent=2)+'\n').encode()
    destination=base/evidence_path;destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(evidence_bytes)
    record['elaboration']['evidence_sha256']=hashlib.sha256(evidence_bytes).hexdigest()
    lock['components']=[record]
    (base/'configs/soc/sources.lock.json').write_text(json.dumps(lock,sort_keys=True))
    profile_directory=TemporaryDirectory(dir=workspace/'configs',prefix='.generic-test-')
    request.addfinalizer(profile_directory.cleanup)
    relative=(Path(profile_directory.name)/'component_profile.json').relative_to(workspace).as_posix()
    profile_bytes=json.dumps(raw,sort_keys=True).encode()
    (workspace/relative).write_bytes(profile_bytes)
    path=base/relative;path.parent.mkdir(parents=True)
    path.write_bytes(profile_bytes)
    assert (workspace/relative).read_bytes()==path.read_bytes()
    capability=load_ip_test_capability(sidecar,profile=profile)
    assert len(capability.register_semantics)==72 and len(capability.register_aliases)==2
    harness_request=load_local_harness_request(dict(schema_version='local_harness.v2',profile_path=relative,
        instance_id='generic_target',reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16,
        tuning={'raw_tick_stream':[{'sampling':'pre_post'}]}))
    plan=plan_local_harness(harness_request,base_dir=base)
    structural=render_local_harness(plan)
    verified=verify_local_source_lock(plan.profile,base_dir=base)
    runtime=render_local_runtime(plan,structural,verified,base_dir=base)
    artifact=render_local_driver(runtime,base_dir=base)
    return base,artifact,capability


def test_fully_renamed_component_has_real_source_verification_and_native_render(source_verified_generic_artifact):
    base,artifact,capability=source_verified_generic_artifact
    assert artifact.plan.profile.component_id=='generic_register_device'
    assert artifact.plan.request.instance_id=='generic_target'
    assert artifact.source_verification['source_status']=='source_verified'
    assert artifact.source_verification['elaboration_status']=='elaboration_verified'
    assert verify_native_physical_observation(artifact) is True
    assert artifact.runtime_document['kind']=='apb_gpio'
    assert {row.operation for row in capability.register_aliases}=={'set_bits','clear_bits'}
    fresh=verify_local_source_lock(artifact.plan.profile,base_dir=base)
    assert fresh==artifact.source_verification


def test_real_verifier_rejects_changed_copied_source_bytes(source_verified_generic_artifact):
    base,artifact,_=source_verified_generic_artifact
    path=base/artifact.plan.profile.source.source_root/'rtl/apb_gpio.sv'
    raw=path.read_bytes()
    try:
        path.write_bytes(raw+b'\n// changed actual source bytes\n')
        with pytest.raises(ValueError):verify_local_source_lock(artifact.plan.profile,base_dir=base)
    finally:path.write_bytes(raw)
