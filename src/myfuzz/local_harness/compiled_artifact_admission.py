"""P7 declaration consistency admission, without admitting runtime enforcement.

Recompile from the trusted path request, bind its profiles to actually loaded
artifacts and check explicit physical ownership. No component names choose an
executor, and a compatible result does not establish decoder/checker support.
"""
from __future__ import annotations

from collections.abc import Mapping

from .runtime_artifact import LocalRuntimeArtifact
from myfuzz.scenario.compiled_paths import PathCompileRequest, compile_paths
from myfuzz.scenario.ownership import OwnershipMap


def _difference(expected, observed, pointer=''):
    """First differing JSON pointer, preserving numeric/boolean distinctions."""
    if type(expected) is not type(observed):
        return pointer
    if isinstance(expected, dict):
        for key in sorted(set(expected) | set(observed), key=str):
            child = pointer + '/' + str(key).replace('~', '~0').replace('/', '~1')
            if key not in expected or key not in observed:
                return child
            result = _difference(expected[key], observed[key], child)
            if result is not None:
                return result
    elif isinstance(expected, list):
        if len(expected) != len(observed):
            return pointer
        for index, (left, right) in enumerate(zip(expected, observed)):
            result = _difference(left, right, pointer + '/' + str(index))
            if result is not None:
                return result
    elif expected != observed:
        return pointer
    return None


def admit_compiled_artifacts(*, artifacts, request, compiled, ownership,
                             physical_port_map) -> dict:
    """Return structured compatibility/refusal for artifacts and compiled inputs.

    physical_port_map maps (instance, ownership-port) to the explicit DUT port.
    Bound physical producers are refused in this initial slice: proving their
    delivery requires the later execution wiring admission. Image/transaction
    source constraints and bound protocol responses are checked by recompilation,
    not mistaken for mutable physical DUT inputs.
    """
    result = dict(schema_version='compiled_artifact_admission.v1',
        scope='compiled_artifact_consistency', status='refused', refusals=[],
        artifact_digests={}, runtime_enforcement='not_admitted',
        not_claimed=['decoder/checker constraint enforcement', 'RTL operational',
                     'cross-component accepted', 'coverage-guided searched'])
    def refuse(code, pointer, detail=None):
        result['refusals'].append(dict(code=code, pointer=pointer, detail=detail))
    if not isinstance(request, PathCompileRequest):
        refuse('compile-request-required', '/request')
        return result
    if not isinstance(artifacts, Mapping):
        refuse('loaded-artifacts-required', '/artifacts')
        return result
    components = request.components()
    instances = [component.instance_id for component in components]
    if set(artifacts) != set(instances) or len(set(instances)) != len(instances):
        refuse('artifact-instance-set-mismatch', '/artifacts')
        return result
    for component in components:
        instance = component.instance_id
        artifact = artifacts[instance]
        pointer = '/artifacts/' + instance
        if not isinstance(artifact, LocalRuntimeArtifact):
            refuse('loaded-artifact-required', pointer)
            continue
        if artifact.plan.request.instance_id != instance:
            refuse('artifact-instance-mismatch', pointer)
        if artifact.plan.profile.profile_fingerprint != component.profile.profile_fingerprint:
            refuse('artifact-profile-mismatch', pointer + '/profile_fingerprint')
        result['artifact_digests'][instance] = artifact.runtime_document['artifact_digest']
    if result['refusals']:
        return result
    try:
        expected = compile_paths(request)
    except (ValueError, RuntimeError) as error:
        refuse('compile-request-refused', '/request', str(error))
        return result
    difference = _difference(expected, compiled)
    if difference is not None:
        refuse('compiled-document-mismatch', difference or '/',
               'supplied document differs from current trusted compilation')
        return result
    if not isinstance(ownership, OwnershipMap) or not isinstance(physical_port_map, Mapping):
        refuse('physical-ownership-map-required', '/ownership')
        return result
    fields = ownership.document()['fields']
    keys = {(row['component_id'], row['port']) for row in fields}
    if set(physical_port_map) != keys:
        refuse('ownership-port-map-mismatch', '/physical_port_map')
        return result
    if any(type(port) is not str or not port for port in physical_port_map.values()):
        refuse('ownership-port-map-invalid', '/physical_port_map')
        return result
    physical_inputs = {}
    for field in fields:
        key = (field['component_id'], field['port'])
        artifact = artifacts.get(key[0])
        physical_port = physical_port_map[key]
        rows = ([] if artifact is None else [row for row in artifact.structural.abi_document['ports']
                if row['physical_port'] == physical_port])
        # Protocol pins belong to the actual protocol producer/consumer. An
        # ownership declaration cannot turn them into random external inputs.
        if (not rows or any(row['direction'] != 'input' or any(endpoint.endpoint_id == row['endpoint_id'] and endpoint.protocol is not None
                    for endpoint in artifact.plan.profile.endpoints) for row in rows)
                or sum(row['width'] for row in rows) != field['width']):
            refuse('ownership-input-not-physical', '/ownership/' + key[0] + '/' + key[1])
            continue
        identity = (key[0], physical_port)
        if identity in physical_inputs:
            refuse('ownership-physical-port-duplicate', '/physical_port_map')
        physical_inputs[identity] = key
    sources = {}
    for index, path in enumerate(compiled['paths']):
        if path['status'] != 'executable':
            continue
        for source in path['sources']:
            if source['kind'] == 'external_pin':
                identity = (source['component'], source['port'], source['bit_offset'], source['width'])
                sources[identity] = (source, path['direction'], index)
    used_sources = set()
    for index, owner in enumerate(ownership.document()['owners']):
        pointer = '/ownership/owners/' + str(index)
        key = (owner['component_id'], owner['port'])
        physical_port = physical_port_map[key]
        if owner['kind'] == 'bound':
            refuse('ownership-bound-producer-not-admitted', pointer,
                   'physical delivery producer requires execution wiring admission')
        elif owner['kind'] == 'source':
            identity = (key[0], physical_port, owner['bit_offset'], owner['width'])
            declaration = sources.get(identity)
            if declaration is None or declaration[0]['source_id'] != owner['producer_ref']:
                refuse('ownership-source-uncompiled', pointer)
            elif declaration[0]['mask'] != (1 << owner['width']) - 1:
                refuse('ownership-source-mask-not-representable', pointer,
                       'physical bit ownership cannot grant reserved mask bits')
            else:
                used_sources.add(identity)
    for identity, (_, _, index) in sources.items():
        if identity not in used_sources:
            refuse('compiled-physical-source-unowned', f'/paths/{index}/sources', list(identity))
    if not result['refusals']:
        result['status'] = 'compatible'
    return result
