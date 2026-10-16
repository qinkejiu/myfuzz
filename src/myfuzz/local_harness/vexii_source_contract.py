"""Pin generated Vexii source and its successful generator/lint evidence."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.source_crawler import _content_hash

DIRECTORY = 'configs/cpus/vexiiriscv/'
CLOSURE_SHA256 = '8ad3e4716da28b7e641439aa778a87f2aca16693f4fb4a378843f9edb75d67ed'


def verify_vexii_source_contract(profile, *, base_dir: Path):
    root = Path(base_dir).resolve()
    def read(name):
        path = root / name
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            raise ValueError('vexii-source-path:' + name)
        return path.read_bytes()
    raw = read(DIRECTORY+'closure.json')
    if hashlib.sha256(raw).hexdigest() != CLOSURE_SHA256:
        raise ValueError('vexii-closure-changed')
    closure = json.loads(raw)
    profile_raw = read(DIRECTORY+'component_profile.json')
    if (hashlib.sha256(profile_raw).hexdigest() != closure['profile_sha256']
            or load_component_profile(json.loads(profile_raw)) != profile):
        raise ValueError('vexii-profile-changed')
    selected = {}
    for row in closure['closure_files']:
        data = read(row['path'])
        if row['root'] != '.' or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('vexii-source-changed:' + row['path'])
        selected[row['path']] = data
    if (set(selected) != set(profile.source_document['files'])
            or _content_hash(selected) != profile.source.revision
            or profile.source.revision != closure['source_revision']):
        raise ValueError('vexii-source-revision')
    for row in closure['authenticated_inputs']:
        if hashlib.sha256(read(row['path'])).hexdigest() != row['sha256']:
            raise ValueError('vexii-evidence-changed:' + row['path'])
    manifest = json.loads(read(DIRECTORY+'generated/manifest.json'))
    if (manifest['lint']['exit_code'] != 0 or manifest['generator_exit_code'] != 0
            or manifest['generated_sha256'] != closure['closure_files'][0]['sha256']
            or manifest['top_port_count'] != 48):
        raise ValueError('vexii-generation-evidence')
    return {'schema_version':'local_source_lock_verification.v1',
            'source_status':'source_verified','elaboration_status':'elaboration_verified',
            'profile_union_revision':profile.source.revision,
            'closure_sha256':CLOSURE_SHA256,
            'lock_sha256':hashlib.sha256(read('configs/soc/sources.lock.json')).hexdigest(),
            'closure_record':{'id':profile.component_id,'elaboration':{
                'evidence':DIRECTORY+'closure.json','evidence_sha256':CLOSURE_SHA256}},
            'authenticated_inputs':closure['authenticated_inputs']}
