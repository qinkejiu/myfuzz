"""Profile-local source manifests reuse the ordinary source verifier."""
import copy
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.source_lock import verify_local_source_lock

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def declared_profile():
    profile = json.loads((ROOT / 'configs/cpus/cv32e20/component_profile.json').read_text())
    lock = json.loads((ROOT / 'configs/soc/sources.lock.json').read_text())
    record = copy.deepcopy(next(item for item in lock['components'] if item['id'] == 'cv32e20'))
    profile['component_id'] = record['id'] = 'profile_boot_manifest_cpu'
    closure = json.loads((ROOT / record['elaboration']['evidence']).read_text())
    closure['component'] = record['id']
    with tempfile.TemporaryDirectory(prefix='profile-source-manifest-') as directory:
        base = Path(directory)
        source = base / record['source']['root']
        source.parent.mkdir(parents=True)
        shutil.copytree(ROOT / record['source']['root'], source)
        evidence = base / 'closure.json'
        evidence.write_text(json.dumps(closure))
        record['elaboration']['evidence'] = str(evidence.relative_to(base))
        record['elaboration']['evidence_sha256'] = hashlib.sha256(evidence.read_bytes()).hexdigest()
        profile.setdefault('evidence', {})['local_source_manifest'] = {
            'schema_version': 'soc_sources.v1', 'components': [record]}
        yield profile, base


def test_new_component_source_manifest_needs_no_central_registry(declared_profile):
    document, base = declared_profile
    profile = load_component_profile(document)
    result = verify_local_source_lock(profile, base_dir=base)
    assert result['id'] == 'profile_boot_manifest_cpu'
    assert result['source_status'] == 'source_verified'
    assert result['elaboration_status'] == 'elaboration_verified'
    assert result['runtime_status'] == 'runtime_unverified'


@pytest.mark.parametrize('mutation', ['missing', 'hash', 'closure', 'wrong_id', 'wrong_source'])
def test_new_component_source_manifest_refuses_missing_or_changed_evidence(declared_profile, mutation):
    document, base = declared_profile
    manifest = document['evidence']['local_source_manifest']
    record = manifest['components'][0]
    if mutation == 'missing':
        del document['evidence']['local_source_manifest']
    elif mutation == 'hash':
        record['selected_content_hash'] = '0' * 64
    elif mutation == 'closure':
        record['elaboration']['evidence_sha256'] = '0' * 64
    elif mutation == 'wrong_id':
        record['id'] = 'another_cpu'
    else:
        record['source']['top_module'] = 'another_top'
    with pytest.raises((ValueError, OSError)):
        verify_local_source_lock(load_component_profile(document), base_dir=base)


def inline_profile():
    document = json.loads((ROOT / 'configs/cpus/cv32e20/component_profile.json').read_text())
    lock = json.loads((ROOT / 'configs/soc/sources.lock.json').read_text())
    record = copy.deepcopy(next(item for item in lock['components'] if item['id'] == 'cv32e20'))
    document['component_id'] = record['id'] = 'inline_manifest_cpu'
    closure = json.loads((ROOT / record['elaboration']['evidence']).read_text())
    closure['component'] = record['id']
    raw = json.dumps(closure, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    record['elaboration']['evidence'] = 'inline-closure.json'
    record['elaboration']['evidence_sha256'] = hashlib.sha256(raw).hexdigest()
    document.setdefault('evidence', {})['local_source_manifest'] = {
        'schema_version': 'soc_sources.v1', 'components': [record],
        'elaboration_closures': {record['id']: closure}}
    return document


def test_inline_profile_closure_works_in_git_workspace_without_extra_file():
    result = verify_local_source_lock(load_component_profile(inline_profile()), base_dir=ROOT)
    assert result['id'] == 'inline_manifest_cpu'
    assert result['elaboration_status'] == 'elaboration_verified'
    assert result['runtime_status'] == 'runtime_unverified'


@pytest.mark.parametrize('change', ['missing', 'changed', 'wrong_source_hash'])
def test_inline_profile_closure_refuses_missing_and_tampered_evidence(change):
    document = inline_profile()
    manifest = document['evidence']['local_source_manifest']
    record = manifest['components'][0]
    closure = manifest['elaboration_closures']['inline_manifest_cpu']
    if change == 'missing':
        del manifest['elaboration_closures']['inline_manifest_cpu']
    elif change == 'changed':
        closure['top_module'] = 'not_the_top'
    else:
        closure['closure_files'][0]['sha256'] = '0' * 64
        raw = json.dumps(closure, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        record['elaboration']['evidence_sha256'] = hashlib.sha256(raw).hexdigest()
    with pytest.raises((ValueError, OSError)):
        verify_local_source_lock(load_component_profile(document), base_dir=ROOT)


def test_zipdma_existing_source_manifest_metadata_is_not_treated_as_inline_lock():
    profile = load_component_profile(ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json')
    result = verify_local_source_lock(profile, base_dir=ROOT)
    assert result['schema_version'] == 'zipdma_selected_profile_contract.v1'
