"""Reusable component profile, request and capability inputs for scenario generators."""
import json

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.local_harness.request import load_local_harness_request


def _member(base, value):
    path = (base / value).resolve()
    if not path.is_relative_to(base) or not path.is_file():
        raise ValueError('request or capability must be an existing file under base_dir')
    return path


def _request(base, value):
    path = _member(base, value)
    request = load_local_harness_request(json.loads(path.read_text()))
    profile = load_component_profile(_member(base, request.profile_path))
    return path, request, profile


def _component_request(declaration, name, base, out):
    request_key, profile_key = name + '_request', name + '_profile'
    if (request_key in declaration) == (profile_key in declaration):
        raise ValueError(name + ' requires exactly one of request or profile')
    if request_key in declaration:
        path, request, profile = _request(base, declaration[request_key])
        return path, request, profile, None
    profile_path = _member(base, declaration[profile_key])
    profile = load_component_profile(profile_path)
    timing = declaration.get(name + '_timing', profile.evidence.get('local_harness'))
    if not isinstance(timing, dict) or set(timing) != {
            'reset_assert_ticks', 'reset_release_ticks', 'max_wait_cycles'}:
        raise ValueError(name + ' profile requires explicit local_harness timing')
    document = dict(schema_version='local_harness.v1',
                    profile_path=str(profile_path.relative_to(base)), instance_id=name, **timing)
    request = load_local_harness_request(document)
    return out / (name + '_request.json'), request, profile, document


def _capability(profile, explicit, name, base, out):
    reference = explicit if explicit is not None else profile.evidence.get('test_capability')
    if reference is not None:
        if not isinstance(reference, str):
            raise ValueError(name + ' test capability path required')
        path = _member(base, reference)
        return path, load_ip_test_capability(path, profile=profile), None
    embedded = profile.evidence.get('embedded_test_capability')
    if not isinstance(embedded, dict) or {'component_id', 'profile_fingerprint'} & set(embedded):
        raise ValueError(name + ' requires an identity-free embedded test capability')
    document = {**embedded, 'component_id': profile.component_id,
                'profile_fingerprint': profile.profile_fingerprint}
    typed = load_ip_test_capability(document, profile=profile)
    return out / (name + '_test_capability.json'), typed, document


