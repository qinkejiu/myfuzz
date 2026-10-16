"""P7-B: generate one independent harness per component plus a wiring contract.

The plan's P7-B deliverable is a *composition-level* entry point: given a set of
trusted profiles, produce several independent harnesses and one contract that
declares how transactions travel between them.  Two rules shape this module.

**Template selection is the only way a protocol is chosen.**  Every protocol
endpoint of every component must match a registered template through
``select_template_contract``.  An endpoint whose shape matches nothing is
refused *by name*, and no harness is produced for any component: falling back to
a template with a similar name is exactly the failure the plan's "old component"
negative is meant to catch.

**Nothing here generates a bus, bridge or arbiter.**  Components are linked only
by declared transaction-level delivery, so the wiring contract states who
produces, who consumes, which window and which declared endpoint - it never
implies a global cycle-accurate interconnect.

An accepted set is therefore only ever reported as ``generated``: whether the
harnesses actually exchange transactions is a separate claim that requires the
cross-component acceptance evidence this module does not produce.
"""
from __future__ import annotations

from collections.abc import Mapping
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile

from myfuzz.local_harness import (build_local_harness, load_local_harness_request,
                                  plan_local_harness, render_local_driver,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.template_contracts import select_template_contract

#: Version of the generated harness-set document.
HARNESS_SET_SCHEMA_VERSION = 'harness_set.v1'
#: Version of the declared delivery contract between the generated harnesses.
WIRING_CONTRACT_SCHEMA_VERSION = 'wiring_contract.v1'

#: The capability tier a successfully generated set has reached. One tier never
#: implies the next, so this is deliberately not a configurable label.
GENERATED_TIER = 'generated'


class HarnessSetRefused(ValueError):
    """The set cannot be generated. The message names the offending declaration."""

    def __init__(self, code: str, pointer: str, detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code, pointer, detail=None):
    raise HarnessSetRefused(code, pointer, detail)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def _require(document, keys, pointer, optional=()):
    """A compose document is a closed declaration, not an open bag.

    ``optional`` names fields a document may carry but need not.  They are still
    part of the closed vocabulary, so a misspelt optional field is refused like
    any other unknown key rather than being silently ignored.
    """
    missing = sorted(set(keys) - set(document))
    unknown = sorted(set(document) - set(keys) - set(optional))
    if missing:
        _refuse('compose-field-missing', pointer, {'missing': missing})
    if unknown:
        _refuse('compose-field-unknown', pointer, {'unknown': unknown})
    return document


def _text(value, pointer, code='compose-field-type'):
    if type(value) is not str or not value.strip():
        _refuse(code, pointer, {'value': value})
    return value


def load_compose(path, *, base_dir):
    """Read a closed composition declaration.

    The declaration must name the roles explicitly.  Nothing is inferred from a
    profile's directory, file name or component id, because a generator that
    guesses roles is a generator that can silently swap a CPU for a peripheral.
    """
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(document, dict):
        _refuse('compose-document-required', '')
    top = _require(document, {'schema_version', 'cpu', 'devices'},
                   '', optional={'memory'})
    if top['schema_version'] != 'harness_compose.v1':
        _refuse('compose-schema-version', '/schema_version',
                {'expected': 'harness_compose.v1',
                 'observed': top['schema_version']})
    if not isinstance(top['cpu'], Mapping):
        _refuse('compose-cpu-object-required', '/cpu')
    cpu = _require(dict(top['cpu']),
                   {'instance_id', 'request', 'data_endpoint'}, '/cpu')
    cpu['instance_id'] = _text(cpu['instance_id'], '/cpu/instance_id')
    cpu['request'] = _text(cpu['request'], '/cpu/request')
    cpu['data_endpoint'] = _text(cpu['data_endpoint'], '/cpu/data_endpoint')
    devices = top['devices']
    if not isinstance(devices, list) or not devices:
        _refuse('compose-devices-required', '/devices')
    rows = []
    for index, raw in enumerate(devices):
        pointer = f'/devices/{index}'
        if not isinstance(raw, Mapping):
            _refuse('compose-device-object-required', pointer)
        row = _require(dict(raw),
                       {'device_id', 'instance_id', 'request', 'bus_endpoint',
                        'base', 'size'}, pointer)
        row['device_id'] = _text(row['device_id'], pointer + '/device_id')
        row['instance_id'] = _text(row['instance_id'], pointer + '/instance_id')
        row['request'] = _text(row['request'], pointer + '/request')
        row['bus_endpoint'] = _text(row['bus_endpoint'],
                                    pointer + '/bus_endpoint')
        for name in ('base', 'size'):
            value = row[name]
            if type(value) is not int or value < 0:
                _refuse('compose-window-field-invalid', pointer + '/' + name,
                        {'value': value})
        if row['size'] == 0:
            _refuse('compose-window-empty', pointer + '/size')
        rows.append(row)
    seen = set()
    for row in rows:
        if row['device_id'] in seen:
            _refuse('compose-device-id-duplicate', '/devices',
                    {'device_id': row['device_id']})
        seen.add(row['device_id'])
    cpu['devices'] = rows
    cpu['memory'] = _memory(cpu['instance_id'], rows, top.get('memory', []))
    return cpu


#: The permissions a memory resource must state explicitly.  Nothing is defaulted:
#: a region whose ``execute`` the author never wrote must not silently become the
#: CPU's program image just because its address range happens to contain the
#: reset vector.
MEMORY_PERMISSIONS = ('read', 'write', 'execute')


def _memory(cpu_instance_id, devices, raw):
    """Read the declared memory resources, or refuse by name.

    ``component_instance`` is checked against the instances this same document
    declares - the CPU included, because the CPU is a legitimate owner of its own
    instruction memory.  A resource that names nobody is refused, because "which
    component really serves this region" is exactly the fact an address range
    does not carry.
    """
    if not isinstance(raw, list):
        _refuse('compose-memory-array-required', '/memory')
    known = {cpu_instance_id} | {row['instance_id'] for row in devices}
    resources = []
    seen = set()
    for index, item in enumerate(raw):
        pointer = f'/memory/{index}'
        if not isinstance(item, Mapping):
            _refuse('compose-memory-object-required', pointer)
        # Permissions are demanded separately, just below, so that leaving one out
        # is reported as a missing permission rather than as a missing field.
        row = _require(dict(item), {'resource_id', 'base', 'size'},
                       pointer, optional={'component_instance',
                                          'initialization_policy',
                                          *MEMORY_PERMISSIONS})
        row['resource_id'] = _text(row['resource_id'], pointer + '/resource_id')
        if row['resource_id'] in seen:
            _refuse('compose-memory-id-duplicate', '/memory',
                    {'resource_id': row['resource_id']})
        seen.add(row['resource_id'])
        for name in ('base', 'size'):
            value = row[name]
            if type(value) is not int or value < 0:
                _refuse('compose-memory-field-invalid', pointer + '/' + name,
                        {'value': value})
        if row['size'] == 0:
            _refuse('compose-memory-empty', pointer + '/size')
        for name in MEMORY_PERMISSIONS:
            if name not in row:
                _refuse('compose-memory-permission-missing', pointer,
                        {'missing': name, 'required': list(MEMORY_PERMISSIONS),
                         'requires': 'state read/write/execute explicitly; a '
                                     'permission the author did not write is not '
                                     'inferred from the address range'})
            if type(row[name]) is not bool:
                _refuse('compose-memory-field-invalid', pointer + '/' + name,
                        {'value': row[name]})
        instance = row.get('component_instance')
        if instance is None:
            _refuse('compose-memory-owner-missing', pointer + '/component_instance',
                    {'resource_id': row['resource_id'],
                     'requires': 'the instance_id that really serves this region, '
                                 'declared by this same composition; an address '
                                 'range alone does not say who returns the bytes'})
        row['component_instance'] = _text(instance,
                                          pointer + '/component_instance',
                                          'compose-memory-owner')
        if row['component_instance'] not in known:
            _refuse('compose-memory-owner-undeclared',
                    pointer + '/component_instance',
                    {'component_instance': row['component_instance'],
                     'declared_instances': sorted(known)})
        resources.append({
            'resource_id': row['resource_id'],
            'component_instance': row['component_instance'],
            'base': row['base'],
            'size': row['size'],
            'read': row['read'],
            'write': row['write'],
            'execute': row['execute'],
            'initialization_policy': row.get('initialization_policy'),
        })
    return resources


def _admit_endpoints(plan, instance_id, declared_role, endpoint_id, pointer):
    """Match the declared endpoint to a template, or refuse by name.

    ``declared_role`` names what the compose document says this endpoint is for
    (``cpu-data`` or ``device-bus``).  It is used only to decide *which*
    declared endpoint must match a template, never to pick the template.
    """
    endpoint = next((row for row in plan.binding.endpoints
                     if row.endpoint_id == endpoint_id), None)
    if endpoint is None:
        _refuse('component-endpoint-undeclared', pointer,
                {'instance_id': instance_id, 'endpoint_id': endpoint_id,
                 'declared': sorted(row.endpoint_id
                                    for row in plan.binding.endpoints)})
    try:
        selected = select_template_contract(endpoint, plan.profile.capabilities)
    except ValueError as error:
        _refuse('protocol-shape-not-admitted', pointer,
                {'instance_id': instance_id, 'endpoint_id': endpoint_id,
                 'protocol': list(endpoint.protocol or ()),
                 'declared_role': declared_role, 'error': str(error)})
    contract = selected.contract
    return {'instance_id': instance_id, 'endpoint_id': endpoint_id,
            'declared_role': declared_role, 'protocol': list(endpoint.protocol or ()),
            'template_id': contract.template_id,
            'template_version': contract.template_version,
            'variant_id': contract.variant_id,
            'identity_sha256': contract.identity_sha256}


def generate_component(request_path, *, base_dir, output, build_cache=None):
    """Plan, render, write and optionally build one component harness."""
    if output.exists() or output.is_symlink():
        _refuse('harness-output-exists', '', {'output': str(output)})
    if not output.parent.is_dir():
        _refuse('harness-output-parent-missing', '', {'output': str(output)})
    document = json.loads(Path(request_path).read_text(encoding='utf-8'))
    request = load_local_harness_request(document)
    plan = plan_local_harness(request, base_dir=base_dir)
    verified = verify_local_source_lock(plan.profile, base_dir=base_dir)
    structural = render_local_harness(plan)
    runtime = render_local_runtime(plan, structural, verified, base_dir=base_dir)
    artifact = render_local_driver(runtime, base_dir=base_dir)
    files = {
        'wrapper.sv': structural.wrapper_sv.encode('utf-8'),
        'runtime.sv': artifact.runtime_sv.encode('utf-8'),
        'driver.cpp': artifact.cpp_text.encode('utf-8'),
        'artifact.json': _json_bytes(artifact.runtime_document),
        'abi.json': _json_bytes(structural.abi_document),
        'source_verification.json': _json_bytes(verified),
    }
    staging = Path(tempfile.mkdtemp(prefix='.' + output.name + '.',
                                    dir=output.parent))
    try:
        for name, data in files.items():
            (staging / name).write_bytes(data)
        if output.exists() or output.is_symlink():
            _refuse('harness-output-exists', '', {'output': str(output)})
        os.rename(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    built = None
    if build_cache is not None:
        built = str(build_local_harness(artifact, base_dir=base_dir,
                                        cache_dir=Path(build_cache).resolve()))
    return {'plan': plan, 'artifact': artifact, 'structural': structural,
            'output': str(output), 'binary': built}


def generate_harness_set(compose, *, base_dir, output_root, compose_base=None,
                         build_cache=None, review=None):
    """Generate every declared component, or refuse the whole set.

    The set is admitted only after *every* declared protocol endpoint matched a
    registered template.  A refusal therefore produces no harness at all - not a
    partial set with a warning.

    ``base_dir`` locates the trusted repository (profiles and source locks);
    ``compose_base`` locates the compose document's own request paths, and
    defaults to ``base_dir`` when a caller keeps them together.
    """
    base_dir = Path(base_dir)
    compose_base = Path(compose_base) if compose_base is not None else base_dir
    output_root = Path(output_root)
    cpu = copy.deepcopy(compose)
    admitted = []
    plans = {}

    for row in [cpu] + list(cpu['devices']):
        request_path = compose_base / row['request']
        if not request_path.is_file():
            _refuse('component-request-missing', '',
                    {'instance_id': row['instance_id'],
                     'request': row['request']})
        document = json.loads(request_path.read_text(encoding='utf-8'))
        request = load_local_harness_request(document)
        plan = plan_local_harness(request, base_dir=base_dir)
        if plan.request.instance_id != row['instance_id']:
            _refuse('component-instance-id-mismatch',
                    '', {'declared': row['instance_id'],
                         'request': plan.request.instance_id,
                         'request_path': row['request']})
        plans[row['instance_id']] = plan
        if 'data_endpoint' in row:
            admitted.append(_admit_endpoints(
                plan, row['instance_id'], 'cpu-data', row['data_endpoint'],
                '/cpu/data_endpoint'))
        else:
            admitted.append(_admit_endpoints(
                plan, row['instance_id'], 'device-bus', row['bus_endpoint'],
                f"/devices/{cpu['devices'].index(row)}/bus_endpoint"))

    if review is not None:
        blocking = [component for component in review['components']
                    if component['status'] != 'ok']
        if blocking:
            _refuse('declaration-review-refused', '',
                    {'components': [component['component_id']
                                    for component in blocking]})

    if output_root.exists() or output_root.is_symlink():
        _refuse('harness-set-output-exists', '', {'output': str(output_root)})
    if not output_root.parent.is_dir():
        _refuse('harness-set-output-parent-missing', '',
                {'output': str(output_root)})

    staging = Path(tempfile.mkdtemp(prefix='.' + output_root.name + '.',
                                    dir=output_root.parent))
    rows = []
    try:
        ordered = [cpu] + list(cpu['devices'])
        for index, row in enumerate(ordered):
            directory = staging / row['instance_id']
            record = generate_component(compose_base / row['request'],
                                        base_dir=base_dir, output=directory,
                                        build_cache=build_cache)
            rows.append({
                'instance_id': row['instance_id'],
                'role': 'cpu' if index == 0 else 'device',
                'device_id': row.get('device_id'),
                'request': row['request'],
                'harness': row['instance_id'],
                'kind': record['artifact'].runtime_document['kind'],
                'artifact_digest':
                    record['artifact'].runtime_document['artifact_digest'],
                'binary': record['binary'],
                'template': admitted[index],
            })
        wiring = {
            'schema_version': WIRING_CONTRACT_SCHEMA_VERSION,
            'delivery': 'transaction_level_explicit',
            'global_interconnect': False,
            'cycle_accurate': False,
            'cpu': {'instance_id': cpu['instance_id'],
                    'endpoint_id': cpu['data_endpoint'],
                    'template': rows[0]['template']['template_id'],
                    'variant_id': rows[0]['template']['variant_id']},
            'windows': [{
                'device_id': row['device_id'],
                'target_instance': row['instance_id'],
                'base': row['base'],
                'size': row['size'],
                'endpoint_id': row['bus_endpoint'],
                'template': rows[index + 1]['template']['template_id'],
                'variant_id': rows[index + 1]['template']['variant_id'],
            } for index, row in enumerate(cpu['devices'])],
        }
        if cpu['memory']:
            wiring['resources'] = [{
                'resource_id': row['resource_id'],
                'component_instance': row['component_instance'],
                'base': row['base'],
                'size': row['size'],
                'read': row['read'],
                'write': row['write'],
                'execute': row['execute'],
                **({'initialization_policy': row['initialization_policy']}
                   if row['initialization_policy'] is not None else {}),
            } for row in cpu['memory']]
        document = {
            'schema_version': HARNESS_SET_SCHEMA_VERSION,
            'tier': GENERATED_TIER,
            'tier_scope': 'harnesses were generated and admitted by template',
            'not_claimed': ['cross_component_accepted', 'rtl_operational',
                            'coverage_guided_searched', 'bug_confirmed'],
            'components': rows,
            'wiring': wiring,
        }
        (staging / 'harness_set.json').write_bytes(_json_bytes(document))
        (staging / 'wiring_contract.json').write_bytes(_json_bytes(wiring))
        if review is not None:
            (staging / 'declaration_review.json').write_bytes(_json_bytes(review))
        if output_root.exists() or output_root.is_symlink():
            _refuse('harness-set-output-exists', '', {'output': str(output_root)})
        os.rename(staging, output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return document
