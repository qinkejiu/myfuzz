"""One source-backed CPU observation adapter; no IRQ or F6 authority."""
from pathlib import Path
from dataclasses import replace
from hashlib import sha256
import json
from myfuzz.composition.component_profile import load_component_profile,elaborate_profile
from myfuzz.composition.source_crawler import _content_hash

_PINS={'configs/cpus/cv32e40p_rvfi_local/component_profile.json': 'fc070f6779cee320f6b008e5cfc8bbe6f7768290a7fd5268fd10876c046c6806', 'configs/cpus/cv32e40p_rvfi_local/cv32e40p_rvfi_local_top.sv': '72e023451984470a154b4143cedb7f38248ea36eadc9b5a6cd9408afb6e10a28', 'configs/cpus/cv32e40p/component_profile.json': '21d04c8ad75d2e6cc1feff72b22dc1d7656b129cddd70d55bb981973d0db3e45', 'external_designs/cv32e40p/bhv/cv32e40p_tb_wrapper.sv': '591124e7637913dacd62424a33910736cec555ad63c8b6c90fca2808a8f6816b', 'external_designs/cv32e40p/bhv/cv32e40p_rvfi.sv': 'dba0bea30f40fafd7361acc86adc3b6e898a0d025f2242cc482741920ef166d6', 'external_designs/cv32e40p/bhv/pipe_freeze_trace.sv': 'ebe391cad03230401840a20a9ea9cecccc898bb7f6fd12e1b9475e9a98d9509f', 'external_designs/cv32e40p/bhv/insn_trace.sv': '31b72b252e56b62263cf7ac411402e4925d26307ebb063845170ad3c5a330a39', 'external_designs/cv32e40p/bhv/include/cv32e40p_rvfi_pkg.sv': '55ed3c9fb98b29d986d064c7ac84bc6081d07a348072d30c03af5ce09ca7a675', 'external_designs/cv32e40p/bhv/include/cv32e40p_tracer_pkg.sv': '44f2498df7c028cb07142c9eb875b8499fcc16866d2ff018deb33e1419ad212c'}
_PROFILE='configs/cpus/cv32e40p_rvfi_local/component_profile.json'
_BASE='configs/cpus/cv32e40p/component_profile.json'
_FIELDS={'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32}


def observation_fields():return dict(_FIELDS)


def cv32e40p_profile_matches(profile, *, base_dir):
    """Accept only a timing extension over the pinned CPU contract."""
    baseline = load_component_profile(Path(base_dir) / _PROFILE)
    evidence = dict(profile.evidence)
    present = 'local_harness' in evidence
    timing = evidence.pop('local_harness', None)
    if present and (type(timing) is not dict or set(timing) != {
            'reset_assert_ticks', 'reset_release_ticks', 'max_wait_cycles'}
            or any(type(timing[key]) is not int or not low <= timing[key] <= 1024
                   for key, low in (('reset_assert_ticks', 1),
                                    ('reset_release_ticks', 0), ('max_wait_cycles', 1)))):
        return False
    return (replace(profile, evidence=evidence) == baseline
            and profile.source_document == baseline.source_document)


def verify_cv32e40p_rvfi_source_contract(profile,*,base_dir):
    from .source_lock import verify_local_source_lock
    root=Path(base_dir).resolve()
    for name,expected in _PINS.items():
        path=root/name
        if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest()!=expected:
            raise ValueError('cv32e40p-rvfi-source-changed:'+name)
    if not cv32e40p_profile_matches(profile,base_dir=root):raise ValueError('cv32e40p-rvfi-profile-object-mismatch')
    upstream=verify_local_source_lock(load_component_profile(root/_BASE),base_dir=root)
    selected={}
    for name in profile.source_document['files']:
        path=root/name
        if path.is_symlink() or not path.resolve().is_relative_to(root):raise ValueError('cv32e40p-rvfi-source-path')
        selected[name]=path.read_bytes()
    for directory in profile.source_document['include_roots']:
        for path in (root/directory).rglob('*'):
            if path.is_file():
                if path.is_symlink() or not path.resolve().is_relative_to(root):raise ValueError('cv32e40p-rvfi-include-path')
                selected[path.relative_to(root).as_posix()]=path.read_bytes()
    if _content_hash(selected)!=profile.source.revision:raise ValueError('cv32e40p-rvfi-source-union-changed')
    facts=elaborate_profile(profile,base_dir=root,mode='direct')
    actual={p.name:p.width for p in facts.ports if p.name.startswith('rvfi_') and p.direction=='output'}
    if actual!=_FIELDS:raise ValueError('cv32e40p-rvfi-observed-fields-changed')
    lock=json.loads((root/'configs/soc/sources.lock.json').read_text())
    record=next(r for r in lock['components'] if r['id']=='cv32e40p')
    return dict(schema_version='local_source_lock_verification.v1',source_status='source_verified',
        elaboration_status='elaboration_verified',lock_sha256=upstream['lock_sha256'],closure_record=record,
        upstream_record=upstream,profile_sha256=_PINS[_PROFILE],profile_union_revision=profile.source.revision,
        authenticated_inputs=[dict(path=p,sha256=s) for p,s in sorted(_PINS.items())],
        observation_scope='official_monitor_assigned_valid_order_insn_pc_only',observation_fields=observation_fields(),
        irq_source_authority=False,F6_authority=False)
