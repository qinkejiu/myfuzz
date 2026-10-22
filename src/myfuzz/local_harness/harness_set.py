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
import hashlib
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


def _static_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


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
    version = document.get('schema_version')
    if version == 'harness_compose.v1':
        top = _require(document, {'schema_version', 'cpu', 'devices'},
                       '', optional={'memory', 'fixed_inputs'})
    elif version == 'harness_compose.v2':
        top = _require(document, {'schema_version', 'cpu', 'devices',
                                  'dma_master_routes', 'dma_master_route_bindings'},
                       '', optional={'memory', 'fixed_inputs'})
    else:
        _refuse('compose-schema-version', '/schema_version',
                {'expected': ['harness_compose.v1', 'harness_compose.v2'],
                 'observed': version})
    if not isinstance(top['cpu'], Mapping):
        _refuse('compose-cpu-object-required', '/cpu')
    cpu = _require(dict(top['cpu']),
                   {'instance_id', 'request', 'data_endpoint'}, '/cpu',
                   optional={'template'} if version == 'harness_compose.v2' else ())
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
                        'base', 'size'}, pointer,
                       optional={'template'} if version == 'harness_compose.v2' else ())
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
    for row, pointer in [(cpu, '/cpu')] + [
            (row, f'/devices/{index}') for index, row in enumerate(rows)]:
        if 'template' in row:
            row['template'] = _template_declaration(row['template'], pointer + '/template')
    seen = set()
    for row in rows:
        if row['device_id'] in seen:
            _refuse('compose-device-id-duplicate', '/devices',
                    {'device_id': row['device_id']})
        seen.add(row['device_id'])
    cpu['devices'] = rows
    cpu['memory'] = _memory(cpu['instance_id'], rows, top.get('memory', []))
    if 'fixed_inputs' in top:
        cpu['fixed_inputs'] = _fixed_inputs(
            top['fixed_inputs'],
            instances={cpu['instance_id']} | {row['instance_id'] for row in rows})
    if version == 'harness_compose.v2':
        from myfuzz.scenario.dma_route_intent import (
            parse_dma_master_route_intents, dma_master_route_intents_document)
        try:
            routes = parse_dma_master_route_intents(
                top['dma_master_routes'], pointer='/dma_master_routes')
        except ValueError as error:
            _refuse('compose-dma-route-invalid', '/dma_master_routes',
                    {'error': str(error)})
        if not routes:
            _refuse('compose-dma-routes-required', '/dma_master_routes/routes')
        cpu['dma_master_routes'] = dma_master_route_intents_document(routes)
        cpu['dma_master_route_bindings'] = _route_binding_declarations(
            top['dma_master_route_bindings'], cpu['dma_master_routes']['routes'])
    return cpu


def _route_binding_declarations(raw, route_rows):
    if not isinstance(raw, list):
        _refuse('compose-dma-route-bindings-array-required',
                '/dma_master_route_bindings')
    route_targets = {row['route_id']: row['target']['kind'] for row in route_rows}
    bindings = {}
    for index, item in enumerate(raw):
        pointer = f'/dma_master_route_bindings/{index}'
        if not isinstance(item, Mapping):
            _refuse('compose-dma-route-binding-object-required', pointer)
        route_id = _text(item.get('route_id'), pointer + '/route_id')
        if route_id not in route_targets or route_id in bindings:
            _refuse('compose-dma-route-binding-id-invalid', pointer + '/route_id',
                    {'route_id': route_id})
        peripheral = route_targets[route_id] == 'peripheral'
        _require(item, {'route_id', 'initiator_template'} |
                 ({'target_template'} if peripheral else set()), pointer)
        row = {'route_id': route_id}
        for name in ('initiator_template', 'target_template'):
            if name not in item:
                continue
            row[name] = _template_declaration(item[name], pointer + '/' + name)
        bindings[route_id] = row
    if set(bindings) != set(route_targets):
        _refuse('compose-dma-route-binding-missing', '/dma_master_route_bindings',
                {'missing': sorted(set(route_targets) - set(bindings))})
    return [bindings[key] for key in sorted(bindings)]


def _template_declaration(raw, pointer):
    if not isinstance(raw, Mapping):
        _refuse('compose-template-object-required', pointer)
    _require(raw, {'template_id', 'template_version', 'variant_id'}, pointer)
    return {key: _text(raw[key], pointer + '/' + key)
            for key in ('template_id', 'template_version', 'variant_id')}


#: The closed vocabulary of one declared constant input range.
FIXED_INPUT_KEYS = frozenset(('component_instance', 'port', 'width', 'constant'))
#: Optional keys of one declared constant input range.
FIXED_INPUT_OPTIONAL_KEYS = frozenset(('bit_offset',))


def _fixed_inputs(raw, *, instances) -> list:
    """Read the declared constant environment inputs, or refuse by name.

    A ``fixed_inputs`` row is the composition's own statement about one physical
    input bit range: this component instance, this port, these bits, this
    constant.  Nothing here decides *why* the bits are constant - that is the
    ownership compiler's job (``scenario.compiled_ownership``) - but the record
    itself is closed and typed, and its owner must be an instance this same
    composition declares.
    """
    if not isinstance(raw, list):
        _refuse('compose-fixed-input-array-required', '/fixed_inputs')
    records = []
    seen = set()
    for index, item in enumerate(raw):
        pointer = f'/fixed_inputs/{index}'
        if not isinstance(item, Mapping):
            _refuse('compose-fixed-input-object-required', pointer)
        row = _require(dict(item), FIXED_INPUT_KEYS, pointer,
                       optional=FIXED_INPUT_OPTIONAL_KEYS)
        instance = _text(row['component_instance'],
                         pointer + '/component_instance',
                         'compose-fixed-input-component')
        port = _text(row['port'], pointer + '/port', 'compose-fixed-input-port')
        offset = row.get('bit_offset', 0)
        if type(offset) is not int or offset < 0:
            _refuse('compose-fixed-input-field-invalid', pointer + '/bit_offset',
                    {'value': offset})
        width = row['width']
        if type(width) is not int or width < 1:
            _refuse('compose-fixed-input-field-invalid', pointer + '/width',
                    {'value': width})
        constant = row['constant']
        if type(constant) is not int or constant < 0:
            _refuse('compose-fixed-input-field-invalid', pointer + '/constant',
                    {'value': constant})
        if constant >= 1 << width:
            _refuse('compose-fixed-input-constant-exceeds-width',
                    pointer + '/constant',
                    {'constant': constant, 'width': width})
        if instance not in instances:
            _refuse('compose-fixed-input-owner-undeclared',
                    pointer + '/component_instance',
                    {'component_instance': instance,
                     'declared_instances': sorted(instances)})
        identity = (instance, port, offset, width)
        if identity in seen:
            _refuse('compose-fixed-input-duplicate', pointer,
                    {'component_instance': instance, 'port': port,
                     'bit_offset': offset, 'width': width})
        seen.add(identity)
        records.append({'component_instance': instance, 'port': port,
                        'bit_offset': offset, 'width': width,
                        'constant': constant})
    return records


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


def _endpoint_capabilities(plan, endpoint):
    capabilities = dict(plan.profile.capabilities)
    if endpoint.function in ('memory_master', 'processor_memory_master',
                             'instruction_memory_master', 'data_memory_master'):
        for source, destination in (
                ('master_address_width', 'address_width'),
                ('master_address_units', 'address_units'),
                ('master_has_error', 'has_error'),
                ('master_byte_enable', 'byte_enable')):
            if source in capabilities:
                capabilities[destination] = capabilities[source]
    return capabilities


def _select_endpoint(plan, endpoint, selection, pointer):
    try:
        return select_template_contract(endpoint, _endpoint_capabilities(plan, endpoint),
                                        **(selection or {}))
    except ValueError as error:
        _refuse('dma-route-template-not-admitted', pointer,
                {'endpoint_id': endpoint.endpoint_id, 'error': str(error)})


def _profile_endpoint_sha256(plan, endpoint_id):
    return _static_sha256({'profile_fingerprint': plan.profile.profile_fingerprint,
                           'endpoint_id': endpoint_id})


def _binding_endpoint(plan, endpoint, selected):
    return {'profile_endpoint_sha256':
            _profile_endpoint_sha256(plan, endpoint.endpoint_id),
            'template_id': selected.contract.template_id,
            'template_version': selected.contract.template_version,
            'variant_id': selected.contract.variant_id,
            'contract_sha256': selected.contract.identity_sha256,
            'selection_sha256': selected.identity_sha256}


def _preflight_dma_routes(cpu, plans):
    routes = cpu['dma_master_routes']['routes']
    declarations = {row['route_id']: row for row in cpu['dma_master_route_bindings']}
    ordered = [cpu] + list(cpu['devices'])
    instances = [row['instance_id'] for row in ordered]
    if len(instances) != len(set(instances)):
        _refuse('dma-route-instance-ambiguous', '/devices')
    result = []
    for index, route in enumerate(routes):
        pointer = f'/dma_master_routes/routes/{index}'
        initiator_id = route['initiator_instance']
        if initiator_id not in plans:
            _refuse('dma-route-initiator-undeclared',
                    pointer + '/initiator_instance', {'instance_id': initiator_id})
        initiator_plan = plans[initiator_id]
        initiator = next((endpoint for endpoint in initiator_plan.binding.endpoints
                          if endpoint.endpoint_id == route['initiator_endpoint_id']), None)
        if initiator is None:
            _refuse('dma-route-initiator-endpoint-undeclared',
                    pointer + '/initiator_endpoint_id')
        if initiator.function not in ('memory_master', 'processor_memory_master',
                                      'instruction_memory_master', 'data_memory_master'):
            _refuse('dma-route-initiator-not-master',
                    pointer + '/initiator_endpoint_id',
                    {'function': initiator.function})
        declaration = declarations[route['route_id']]
        selected = _select_endpoint(initiator_plan, initiator,
                                    declaration['initiator_template'],
                                    f'/dma_master_route_bindings/{index}/initiator_template')
        capabilities = _endpoint_capabilities(initiator_plan, initiator)
        if capabilities.get('master_fixed_byte_enable', route['byte_enable']) != route['byte_enable']:
            _refuse('dma-route-byte-enable-mismatch', pointer + '/byte_enable')
        binding = {'route_id': route['route_id'],
                   'initiator': _binding_endpoint(initiator_plan, initiator, selected)}
        target = route['target']
        if target['kind'] == 'peripheral':
            matches = [row for row in cpu['devices']
                       if row['device_id'] == target['device_id'] and
                       row['instance_id'] == target['component_instance']]
            if len(matches) != 1:
                _refuse('dma-route-target-window-undeclared', pointer + '/target')
            window = matches[0]
            target_plan = plans[window['instance_id']]
            endpoint = next((item for item in target_plan.binding.endpoints
                             if item.endpoint_id == target['endpoint_id']), None)
            if endpoint is None or endpoint.function != 'mmio_slave':
                _refuse('dma-route-target-not-slave', pointer + '/target/endpoint_id')
            if target['endpoint_id'] != window['bus_endpoint']:
                _refuse('dma-route-target-endpoint-mismatch', pointer + '/target/endpoint_id')
            if not window['base'] <= route['base'] or route['base'] + route['size'] > window['base'] + window['size']:
                _refuse('dma-route-aperture-outside-target', pointer + '/base')
            for permission in route['permissions']:
                if target_plan.profile.capabilities.get(permission) is not True:
                    _refuse('dma-route-target-permission-unsupported',
                            pointer + '/permissions', {'permission': permission})
            registers = ({register.offset: register
                          for register in target_plan.profile.address.registers}
                         if target_plan.profile.address is not None else {})
            for permission, field in (('read', 'readable_offsets'),
                                      ('write', 'writable_offsets')):
                for offset in route[field]:
                    register_offset = route['base'] - window['base'] + offset
                    register = registers.get(register_offset)
                    if register is None:
                        _refuse('dma-route-target-register-undeclared',
                                pointer + '/' + field,
                                {'offset': offset, 'register_offset': register_offset})
                    if permission == 'read' and register.access not in ('ro', 'rw'):
                        _refuse('dma-route-target-register-permission',
                                pointer + '/' + field, {'offset': offset})
                    if permission == 'write' and register.access not in ('wo', 'rw'):
                        _refuse('dma-route-target-register-permission',
                                pointer + '/' + field, {'offset': offset})
            selected_target = _select_endpoint(
                target_plan, endpoint, declaration['target_template'],
                f'/dma_master_route_bindings/{index}/target_template')
            binding['target'] = _binding_endpoint(target_plan, endpoint, selected_target)
        else:
            matches = [row for row in cpu['memory']
                       if row['resource_id'] == target['resource_id'] and
                       row['component_instance'] == target['component_instance']]
            if len(matches) != 1:
                _refuse('dma-route-target-resource-undeclared', pointer + '/target')
            resource = matches[0]
            if not resource['base'] <= route['base'] or route['base'] + route['size'] > resource['base'] + resource['size']:
                _refuse('dma-route-aperture-outside-target', pointer + '/base')
            for permission in route['permissions']:
                if resource.get(permission) is not True:
                    _refuse('dma-route-target-permission-unsupported',
                            pointer + '/permissions', {'permission': permission})
            normalized = {key: resource[key] for key in
                          ('resource_id', 'component_instance', 'base', 'size',
                           'read', 'write', 'execute')}
            if resource['initialization_policy'] is not None:
                normalized['initialization_policy'] = resource['initialization_policy']
            binding['target'] = {
                'kind': 'persistent_memory',
                'owner_profile_fingerprint':
                    plans[resource['component_instance']].profile.profile_fingerprint,
                'resource_sha256': _static_sha256(normalized)}
        result.append(binding)
    return result


def _admit_endpoints(plan, instance_id, declared_role, endpoint_id, pointer,
                     selection=None):
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
        selected = select_template_contract(
            endpoint, _endpoint_capabilities(plan, endpoint), **(selection or {}))
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
    """Plan, render, write and optionally build one component harness.

    Every planning/rendering/verification ``ValueError`` is a *named* refusal
    (``component-render-refused``) that carries the instance id, the request that
    failed and the renderer's own message.  Letting it escape as a bare
    ``ValueError`` left the caller above this module with a traceback instead of a
    ``code`` + ``pointer`` (and, before the driver's fail-closed fix, with a
    ``complete`` run next to that traceback).
    """
    if output.exists() or output.is_symlink():
        _refuse('harness-output-exists', '', {'output': str(output)})
    if not output.parent.is_dir():
        _refuse('harness-output-parent-missing', '', {'output': str(output)})
    document = json.loads(Path(request_path).read_text(encoding='utf-8'))
    instance_id = (document.get('instance_id')
                   if isinstance(document, Mapping) else None) or output.name
    pointer = f'/{instance_id}/request'
    try:
        request = load_local_harness_request(document)
        plan = plan_local_harness(request, base_dir=base_dir)
        verified = verify_local_source_lock(plan.profile, base_dir=base_dir)
        structural = render_local_harness(plan)
        runtime = render_local_runtime(plan, structural, verified, base_dir=base_dir)
        artifact = render_local_driver(runtime, base_dir=base_dir)
    except ValueError as error:
        _refuse('component-render-refused', pointer,
                {'instance_id': instance_id, 'request': str(request_path),
                 'error': str(error),
                 'requires': 'a request and a pinned profile the plan/render/verify '
                             'stages admit; the renderer refused this component'})
    files = {
        # Persist the exact admitted request for independent loading/replay.
        'request.json': _json_bytes(document),
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
                '/cpu/data_endpoint', row.get('template')))
        else:
            admitted.append(_admit_endpoints(
                plan, row['instance_id'], 'device-bus', row['bus_endpoint'],
                f"/devices/{cpu['devices'].index(row)}/bus_endpoint",
                row.get('template')))

    route_bindings = (_preflight_dma_routes(cpu, plans)
                      if 'dma_master_routes' in cpu else None)

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
        # A composition that declares constant environment inputs publishes them
        # in the contract.  The section is only written when it was declared, so
        # a composition without one keeps producing the exact old bytes.
        if cpu.get('fixed_inputs'):
            wiring['fixed_inputs'] = [dict(row) for row in cpu['fixed_inputs']]
        if route_bindings is not None:
            wiring['schema_version'] = 'wiring_contract.v2'
            wiring['dma_master_routes'] = cpu['dma_master_routes']
            wiring['dma_master_routes_sha256'] = _static_sha256(cpu['dma_master_routes'])
            wiring['dma_master_route_bindings'] = route_bindings
        document = {
            'schema_version': ('harness_set.v2' if route_bindings is not None
                               else HARNESS_SET_SCHEMA_VERSION),
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
