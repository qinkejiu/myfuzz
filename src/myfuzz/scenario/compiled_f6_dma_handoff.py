"""Join the static compiled F6 refusal to one live D4 DMA topology bind.

This module carries evidence between the P7-C compiler and the existing D4
DMA topology binder.  It does not turn static F6 into an executable path and
does not grant transaction or target-provider authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from collections.abc import Mapping

from myfuzz.composition.input_constraints import INPUT_CONSTRAINT_SCHEMA

from .compiled_paths import (
    COMPILED_PATHS_SCHEMA, FLOW_DEFINITIONS, FLOW_IDS, PATH_STATUSES,
    STATUS_EXECUTABLE, STATUS_UNSUPPORTED,
    compiled_document_sha256, load_path_wiring,
)
from .dependency import DependencyGraph
from .dma_intent_topology_binding import (
    BoundDmaIntentTopology,
    PreparedDmaIntentBinding,
    bind_dma_intent_topology,
)
from .dma_route_intent import parse_dma_master_route_intents
from .runtime_path_contract import RuntimePathContract, _RELATIONS


_HANDOFF_SCHEMA = 'compiled_f6_dma_handoff.v1'
_BOUND_SCHEMA = 'bound_compiled_f6_dma_handoff.v1'
_REFUSAL = 'dma-route-live-topology-binding-required'
_HANDOFF_KEYS = {
    'schema_version', 'compiled_paths', 'compiled_paths_sha256',
    'declaration', 'declaration_sha256', 'f6', 'wiring', 'identity_sha256',
}
_F6_KEYS = {'path_id', 'status', 'reason_code', 'route_ids'}
_WIRING_KEYS = {
    'schema_version', 'dma_master_routes_sha256',
    'dma_master_route_bindings_sha256',
}
_BOUND_KEYS = {
    'schema_version', 'compiled_f6_handoff', 'topology_binding',
    'identity_sha256',
}
_COMPILED_KEYS = {
    'schema_version', 'identity', 'flow_definitions', 'paths', 'counts',
    'declared_source_claims', 'declared_register_field_constraints',
    'input_constraints', 'runtime_dependency_graph', 'runtime_path_contract',
    'runtime_path_contract_omissions', 'gaps', 'not_claimed',
}
_COMPILER_IDENTITY_KEYS = {'cpu', 'devices', 'wiring', 'request_sha256'}
_COMPILER_WIRING_IDENTITY_KEYS = {
    'schema_version', 'declared_sections', 'absent_sections',
    'dma_master_routes_sha256', 'dma_master_route_bindings_sha256',
}
_PATH_ROW_KEYS = {
    'path_id', 'flow_id', 'flow_name', 'definition', 'status', 'reason',
    'target', 'direction', 'endpoints', 'sources', 'bound_inputs',
    'constraints', 'prerequisites', 'termination_observation', 'seed',
    'assertions', 'runtime_path_identity', 'not_claimed',
}
_REASON_KEYS = {'code', 'pointer', 'detail', 'missing'}
_INPUT_CONSTRAINT_KEYS = {
    'schema_version', 'policy_hash', 'drive_profile', 'bus_owner',
    'layout_hash', 'layout', 'rules', 'closure', 'cycles',
    'dut_owned_inputs', 'gaps',
}
_PATH_CONSTRAINT_KEYS = {
    'schema_version', 'policy_hash', 'layout_hash', 'rule_ids', 'rules',
    'register_field_constraints', 'source_constraints',
}
_RULE_REQUIRED_KEYS = {
    'rule_id', 'category', 'owner', 'primitive', 'phase', 'fields',
    'read_set', 'write_set', 'basis', 'state_bits', 'budget',
    'failure_class', 'checker',
}
_RULE_OPTIONAL_KEYS = {'raw_bits', 'parameters', 'applies_in_modes'}
_LAYOUT_FIELD_KEYS = {
    'field_id', 'owner', 'role', 'width', 'raw_lo', 'raw_hi',
    'encoding', 'constraint', 'dependency_group', 'binding', 'evidence',
}
_SOURCE_CONSTRAINT_KEYS = {
    'source_id', 'origin', 'kind', 'width', 'bit_offset', 'mask',
    'alignment', 'range', 'constraint_basis',
}
_NORMALIZED_LAYOUT_CONSTRAINT_KEYS = {
    'range', 'alignment', 'enum', 'mask', 'randomizable', 'gated_by',
    'byte_enable_width',
}
_REGISTER_CLAIM_BASE_KEYS = {
    'source_id', 'flow_id', 'component', 'endpoint_id', 'register', 'field',
    'lsb', 'width', 'write_mask', 'read_mask', 'side_effect', 'pointer',
    'component_instance', 'constraint_basis',
}
_REGISTER_CLAIM_OPTIONAL_KEYS = {'origin', 'mask', 'range', 'alignment'}
_REGISTER_ACCESS_KEYS = {
    'schema_version', 'source_component', 'source_endpoint',
    'target_component', 'target_endpoint', 'device_id', 'register',
    'field', 'register_offset', 'address', 'window_base', 'window_size',
    'window_alignment', 'access_alignment', 'width_bytes',
    'byte_enable_domain', 'allowed_byte_enables', 'operation',
    'value_origin', 'register_origin', 'value_mask',
}
_COMPONENT_IDENTITY_KEYS = {
    'instance_id', 'component_id', 'kind', 'profile_fingerprint',
    'sidecar_fingerprint', 'sidecar_schema_version',
}
_TOPOLOGY_KEYS = {
    'schema_version', 'declaration_sha256', 'prepared_sha256',
    'runtime_contract_sha256', 'runtime_compilation_sha256',
    'topology_sha256', 'artifact_links', 'routes', 'tier',
    'identity_sha256',
}


class CompiledF6DmaHandoffError(ValueError):
    """Stable refusal code and JSON pointer for an invalid handoff."""

    def __init__(self, code: str, pointer: str = '/'):
        self.code = code
        self.pointer = pointer
        super().__init__(f'{code} at {pointer}')


def _fail(code: str, pointer: str = '/') -> None:
    raise CompiledF6DmaHandoffError(code, pointer)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-invalid-json', '/') from error


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _json_copy(value: object, pointer: str) -> dict:
    if type(value) is not dict:
        _fail('compiled-f6-handoff-invalid-document', pointer)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
        copied = json.loads(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-invalid-json', pointer) from error
    if type(copied) is not dict:
        _fail('compiled-f6-handoff-invalid-document', pointer)
    return copied


def _closed(document: object, keys: set[str], pointer: str) -> dict:
    if type(document) is not dict or set(document) != keys:
        _fail('compiled-f6-handoff-schema-invalid', pointer)
    return document


def _valid_compiled_rule(row: object) -> bool:
    if (type(row) is not dict
            or not _RULE_REQUIRED_KEYS <= set(row)
            or not set(row) <= _RULE_REQUIRED_KEYS | _RULE_OPTIONAL_KEYS
            or any(type(row[key]) is not str for key in (
                'rule_id', 'category', 'owner', 'primitive', 'phase',
                'basis', 'failure_class', 'checker'))
            or any(type(row[key]) is not int for key in ('state_bits', 'budget'))
            or any(type(row[key]) is not list or any(type(item) is not str
                for item in row[key]) for key in ('fields', 'read_set', 'write_set'))):
        return False
    return (all(key not in row or type(row[key]) is list
                and all(type(item) is list and len(item) == 2
                        and all(type(bit) is int for bit in item)
                        for item in row[key]) for key in ('raw_bits',))
            and ('parameters' not in row or type(row['parameters']) is list
                 and all(type(item) is list and len(item) == 2
                         and type(item[0]) is str for item in row['parameters']))
            and ('applies_in_modes' not in row
                 or type(row['applies_in_modes']) is list
                 and all(type(item) is str
                         for item in row['applies_in_modes'])))


def _valid_layout_field(row: object) -> bool:
    if (type(row) is not dict
            or not _LAYOUT_FIELD_KEYS <= set(row)
            or not set(row) <= _LAYOUT_FIELD_KEYS | {'provenance'}
            or any(type(row[key]) is not str for key in (
                'field_id', 'owner', 'role', 'encoding'))
            or any(type(row[key]) is not int for key in (
                'width', 'raw_lo', 'raw_hi'))
            or not _valid_layout_constraint(row['constraint'])
            or type(row['evidence']) is not list
            or any(type(item) is not str for item in row['evidence'])
            or (row['dependency_group'] is not None
                and type(row['dependency_group']) is not str)
            or ('provenance' in row and (
                type(row['provenance']) is not dict
                or not {'file', 'line'} <= set(row['provenance'])
                or not set(row['provenance']) <= {'file', 'line', 'column'}
                or type(row['provenance']['file']) is not str
                or not row['provenance']['file']
                or type(row['provenance']['line']) is not int
                or row['provenance']['line'] <= 0
                or ('column' in row['provenance'] and (
                    type(row['provenance']['column']) is not int
                    or row['provenance']['column'] <= 0))))):
        return False
    binding = row['binding']
    packed = {'member_path', 'raw_lo', 'raw_hi', 'container_width'}
    if (type(binding) is not dict
            or not {'port', 'direction', 'signed'} <= set(binding)
            or not set(binding) <= {'port', 'direction', 'signed'} | packed
            or (set(binding) & packed and set(binding) & packed != packed)
            or type(binding['port']) is not str
            or type(binding['direction']) is not str
            or type(binding['signed']) is not bool):
        return False
    return not packed <= set(binding) or (
        type(binding['member_path']) is list
        and all(type(item) is str for item in binding['member_path'])
        and all(type(binding[key]) is int for key in (
            'raw_lo', 'raw_hi', 'container_width')))


def _valid_layout_constraint(row: object) -> bool:
    if type(row) is not dict or not set(row) <= _NORMALIZED_LAYOUT_CONSTRAINT_KEYS:
        return False
    for key in ('range', 'enum'):
        if key in row and (type(row[key]) is not list
                           or (key == 'range' and len(row[key]) != 2)
                           or any(type(value) is not int for value in row[key])):
            return False
    return (all(key not in row or type(row[key]) is int for key in (
                'alignment', 'mask', 'byte_enable_width'))
            and ('randomizable' not in row
                 or type(row['randomizable']) is bool)
            and ('gated_by' not in row or type(row['gated_by']) is str))


def _valid_register_claim(row: object) -> bool:
    return (type(row) is dict
            and _REGISTER_CLAIM_BASE_KEYS <= set(row)
            and set(row) <= _REGISTER_CLAIM_BASE_KEYS | _REGISTER_CLAIM_OPTIONAL_KEYS
            and row['flow_id'] in FLOW_IDS
            and all(type(row[key]) is str for key in (
                'source_id', 'flow_id', 'component', 'endpoint_id',
                'register', 'field', 'side_effect', 'pointer',
                'component_instance', 'constraint_basis'))
            and all(type(row[key]) is int for key in (
                'lsb', 'width', 'write_mask', 'read_mask'))
            and all(key not in row or type(row[key]) is int
                    for key in ('mask', 'alignment'))
            and ('origin' not in row or type(row['origin']) is str)
            and ('range' not in row or type(row['range']) is list
                 and len(row['range']) == 2
                 and all(type(value) is int for value in row['range'])))


def _valid_source_constraint(row: object) -> bool:
    if (type(row) is not dict
            or not _SOURCE_CONSTRAINT_KEYS <= set(row)
            or not set(row) <= _SOURCE_CONSTRAINT_KEYS | {'register_access'}
            or any(type(row[key]) is not str for key in (
                'source_id', 'origin', 'kind', 'constraint_basis'))
            or any(type(row[key]) is not int for key in (
                'width', 'bit_offset', 'mask', 'alignment'))
            or (row['range'] is not None and (
                type(row['range']) is not list or len(row['range']) != 2
                or any(type(value) is not int for value in row['range'])))):
        return False
    if 'register_access' not in row:
        return True
    access = row['register_access']
    return (type(access) is dict and set(access) == _REGISTER_ACCESS_KEYS
            and access['schema_version'] == 'register_source_access.v1'
            and all(type(access[key]) is str for key in (
                'source_component', 'source_endpoint', 'target_component',
                'target_endpoint', 'device_id', 'register', 'field',
                'byte_enable_domain', 'operation', 'value_origin',
                'register_origin'))
            and all(type(access[key]) is int for key in (
                'register_offset', 'address', 'window_base', 'window_size',
                'window_alignment', 'access_alignment', 'width_bytes',
                'value_mask'))
            and type(access['allowed_byte_enables']) is list
            and all(type(value) is int
                    for value in access['allowed_byte_enables']))


def _declaration(document: object, *, runtime_paths=None) -> PreparedDmaIntentBinding:
    try:
        return PreparedDmaIntentBinding.from_document(
            document, prepared_runtime_paths=runtime_paths)
    except (TypeError, ValueError, AttributeError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-declaration-invalid', '/declaration') from error


def validate_compiled_f6_static(compiled: dict, static_wiring: dict) -> dict:
    """Validate the complete detached D3 F6 refusal against one D2 wiring."""
    if (type(compiled) is not dict or set(compiled) != _COMPILED_KEYS
            or compiled.get('schema_version') != COMPILED_PATHS_SCHEMA):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths')
    identity = compiled.get('identity')
    identity_wiring = identity.get('wiring') if type(identity) is dict else None
    if (type(identity) is not dict
            or set(identity) != _COMPILER_IDENTITY_KEYS
            or type(identity_wiring) is not dict
            or set(identity_wiring) != _COMPILER_WIRING_IDENTITY_KEYS):
        _fail('compiled-f6-handoff-wiring-mismatch',
              '/compiled_paths/identity/wiring')
    cpu_identity = identity['cpu']
    device_identities = identity['devices']
    def valid_component(row):
        return (type(row) is dict and set(row) == _COMPONENT_IDENTITY_KEYS
                and all(type(row[key]) is str and row[key]
                        for key in ('instance_id', 'component_id', 'kind',
                                    'profile_fingerprint'))
                and all(row[key] is None or type(row[key]) is str
                        for key in ('sidecar_fingerprint',
                                    'sidecar_schema_version')))
    if (not valid_component(cpu_identity)
            or type(device_identities) is not list
            or any(not valid_component(row) for row in device_identities)):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/identity')
    component_ids = [cpu_identity['instance_id']] + [
        row['instance_id'] for row in device_identities]
    if len(set(component_ids)) != len(component_ids):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/identity/devices')
    for key, kind in (
            ('declared_source_claims', list),
            ('declared_register_field_constraints', list),
            ('input_constraints', dict),
            ('runtime_path_contract_omissions', list),
            ('gaps', list), ('not_claimed', list)):
        if type(compiled[key]) is not kind:
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/' + key)
    input_constraints = compiled['input_constraints']
    layout = input_constraints.get('layout')
    if (set(input_constraints) != _INPUT_CONSTRAINT_KEYS
            or input_constraints['schema_version'] != INPUT_CONSTRAINT_SCHEMA
            or type(input_constraints['policy_hash']) is not str
            or not input_constraints['policy_hash']
            or type(input_constraints['drive_profile']) is not str
            or type(input_constraints['bus_owner']) is not str
            or (input_constraints['layout_hash'] is not None
                and type(input_constraints['layout_hash']) is not str)
            or (layout is None) != (input_constraints['layout_hash'] is None)
            or (layout is not None and (type(layout) is not dict
                or set(layout) != {'schema_version', 'raw_width', 'fields',
                                   'layout_hash'}
                or layout['schema_version'] != 'input_layout.v1'
                or type(layout['raw_width']) is not int
                or type(layout['fields']) is not list
                or layout['layout_hash'] != input_constraints['layout_hash']))
            or any(type(input_constraints[key]) is not list for key in (
                'rules', 'closure', 'cycles', 'dut_owned_inputs', 'gaps'))
            or any(not _valid_compiled_rule(row)
                   for row in input_constraints['rules'])
            or len({row['rule_id'] for row in input_constraints['rules']})
                != len(input_constraints['rules'])
            or (layout is not None and any(not _valid_layout_field(row)
                for row in layout['fields']))
            or any(type(row) is not list or len(row) != 2
                   or type(row[0]) is not str
                   or type(row[1]) not in (list, tuple)
                   or any(type(item) is not str for item in row[1])
                   for row in input_constraints['closure'])
            or {row[0] for row in input_constraints['closure']}
                != {row['rule_id'] for row in input_constraints['rules']}
            or len(input_constraints['closure'])
                != len(input_constraints['rules'])
            or any(type(row) not in (list, tuple)
                   or any(type(item) is not str for item in row)
                   for row in input_constraints['cycles'])
            or any(type(row) is not str
                   for row in input_constraints['dut_owned_inputs'])
            or input_constraints['dut_owned_inputs'] != sorted({
                name for rule in input_constraints['rules']
                if rule['owner'] == 'dut' for name in rule['read_set']})
            or any(type(row) is not str for row in input_constraints['gaps'])):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/input_constraints')

    try:
        route_document = static_wiring['dma_master_routes']
        route_rows = route_document['routes']
        binding_rows = static_wiring['dma_master_route_bindings']
        if (type(route_document) is not dict
                or route_document.get('schema_version') != 'dma_master_route_intent.v1'
                or type(route_rows) is not list or not route_rows
                or type(binding_rows) is not list):
            raise TypeError
        route_ids = [row['route_id'] for row in route_rows]
        route_digest = static_wiring['dma_master_routes_sha256']
    except (KeyError, TypeError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-declaration-invalid', '/declaration/wiring') from error

    if (len(set(route_ids)) != len(route_ids)
            or route_ids != sorted(route_ids)):
        _fail('compiled-f6-handoff-route-set-mismatch',
              '/declaration/wiring/dma_master_routes/routes')
    computed_route_digest = _sha256(route_document)
    computed_binding_digest = _sha256(binding_rows)
    if (route_digest != computed_route_digest
            or identity_wiring.get('dma_master_routes_sha256') != computed_route_digest
            or identity_wiring.get('dma_master_route_bindings_sha256')
                != computed_binding_digest
            or identity_wiring.get('schema_version') != static_wiring.get('schema_version')):
        _fail('compiled-f6-handoff-wiring-mismatch',
              '/compiled_paths/identity/wiring')
    try:
        parsed_wiring = load_path_wiring(static_wiring)
    except ValueError as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-declaration-invalid', '/declaration/wiring') from error
    if (type(identity_wiring.get('declared_sections')) is not list
            or type(identity_wiring.get('absent_sections')) is not list
            or identity_wiring['declared_sections']
                != list(parsed_wiring.declared_sections)
            or identity_wiring['absent_sections']
                != list(parsed_wiring.absent_sections)):
        _fail('compiled-f6-handoff-wiring-mismatch',
              '/compiled_paths/identity/wiring')

    if any(not _valid_register_claim(row)
           for row in compiled['declared_register_field_constraints']):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/declared_register_field_constraints')
    paths = compiled.get('paths')
    definitions = compiled['flow_definitions']
    if (type(definitions) is not dict
            or definitions != {flow: FLOW_DEFINITIONS[flow]
                               for flow in FLOW_IDS}):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/flow_definitions')
    if type(paths) is not list or len(paths) != len(FLOW_IDS):
        _fail('compiled-f6-handoff-static-f6-required', '/compiled_paths/paths')
    if ([row.get('flow_id') if type(row) is dict else None for row in paths]
            != list(FLOW_IDS)):
        _fail('compiled-f6-handoff-static-f6-required', '/compiled_paths/paths')
    f6 = paths[-1]
    f6_reason = f6.get('reason')
    if (f6.get('status') != STATUS_UNSUPPORTED
            or 'runtime_path_identity' not in f6
            or f6['runtime_path_identity'] is not None
            or type(f6_reason) is not dict
            or 'missing' not in f6_reason):
        _fail('compiled-f6-handoff-static-f6-required',
              '/compiled_paths/paths/F6')
    path_ids = set()
    for index, row in enumerate(paths):
        pointer = f'/compiled_paths/paths/{index}'
        flow = row['flow_id']
        f2_executable = flow == 'F2' and row.get('status') == STATUS_EXECUTABLE
        expected_keys = _PATH_ROW_KEYS | ({'execution_contract'} if f2_executable else set())
        if (set(row) != expected_keys
                or type(row['path_id']) is not str
                or not row['path_id'].startswith(flow + ':')
                or row['path_id'] in path_ids
                or row['flow_name'] != FLOW_DEFINITIONS[flow]['name']
                or row['definition'] != FLOW_DEFINITIONS[flow]
                or row['status'] not in PATH_STATUSES
                or type(row['reason']) is not dict
                or set(row['reason']) != _REASON_KEYS
                or type(row['reason']['missing']) is not list
                or type(row['target']) is not dict
                or row['target'].get('component') not in component_ids
                or type(row['constraints']) is not dict
                or set(row['constraints']) != _PATH_CONSTRAINT_KEYS
                or row['constraints']['schema_version'] != INPUT_CONSTRAINT_SCHEMA
                or row['constraints']['policy_hash']
                    != input_constraints['policy_hash']
                or row['constraints']['layout_hash']
                    != input_constraints['layout_hash']
                or any(type(row['constraints'][key]) is not list for key in (
                    'rule_ids', 'rules', 'register_field_constraints',
                    'source_constraints'))
                or row['constraints']['rule_ids'] != [
                    rule.get('rule_id') if type(rule) is dict else None
                    for rule in row['constraints']['rules']]
                or any(rule not in input_constraints['rules']
                       for rule in row['constraints']['rules'])
                or row['constraints']['register_field_constraints'] != [
                    item for item in compiled['declared_register_field_constraints']
                    if type(item) is dict and item.get('flow_id') == flow]
                or row['constraints']['source_constraints'] != [
                    {key: item.get(key) for key in _SOURCE_CONSTRAINT_KEYS}
                    | ({'register_access': item['register_access']}
                       if 'register_access' in item else {})
                    for item in row['sources'] if type(item) is dict]
                or any(not _valid_source_constraint(item)
                       for item in row['constraints']['source_constraints'])
                or any(type(item) is not dict for item in row['sources'])
                or type(row['termination_observation']) is not dict
                or type(row['assertions']) is not list
                or type(row['direction']) is not str
                or any(type(row[key]) is not list for key in (
                    'endpoints', 'sources', 'bound_inputs', 'prerequisites',
                    'not_claimed'))):
            _fail('compiled-f6-handoff-compiler-schema-invalid', pointer)
        if f2_executable:
            from .f2_read_contract import validate_f2_read_contract
            try:
                validate_f2_read_contract(row)
            except (TypeError, ValueError, KeyError) as error:
                raise CompiledF6DmaHandoffError(
                    'compiled-f6-handoff-compiler-schema-invalid', pointer) from error
        path_ids.add(row['path_id'])
    counts = compiled['counts']
    expected_counts = {
        STATUS_EXECUTABLE: sum(row['status'] == STATUS_EXECUTABLE
                               for row in paths),
        STATUS_UNSUPPORTED: sum(row['status'] == STATUS_UNSUPPORTED
                                for row in paths),
        'total': len(paths),
    }
    if (type(counts) is not dict or set(counts) != set(expected_counts)
            or any(type(counts[key]) is not int
                   or counts[key] != value
                   for key, value in expected_counts.items())):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/counts')
    f6_rows = [row for row in paths
               if type(row) is dict and row.get('flow_id') == 'F6']
    if len(f6_rows) != 1:
        _fail('compiled-f6-handoff-static-f6-required', '/compiled_paths/paths')
    f6 = f6_rows[0]
    reason = f6.get('reason')
    detail = reason.get('detail') if type(reason) is dict else None
    if (type(detail) is dict and detail.get('route_ids') != route_ids):
        _fail('compiled-f6-handoff-route-set-mismatch',
              '/compiled_paths/paths/F6/reason/detail/route_ids')
    if (f6.get('status') != 'unsupported'
            or 'runtime_path_identity' not in f6
            or f6['runtime_path_identity'] is not None
            or type(reason) is not dict
            or reason.get('code') != _REFUSAL
            or reason.get('pointer') != '/wiring/dma_master_routes'
            or type(detail) is not dict
            or detail.get('intent_sha256') != computed_route_digest
            or not isinstance(f6.get('path_id'), str)
            or not f6['path_id']):
        _fail('compiled-f6-handoff-static-f6-required',
              '/compiled_paths/paths/F6')

    missing = reason.get('missing')
    if (type(missing) is not list or len(missing) != 1
            or type(missing[0]) is not dict
            or set(missing[0]) != {'code', 'pointer', 'detail'}
            or missing[0]['code'] != reason['code']
            or missing[0]['pointer'] != reason['pointer']
            or missing[0]['detail'] != detail):
        _fail('compiled-f6-handoff-static-f6-required',
              '/compiled_paths/paths/F6/reason/missing')

    for graph_pointer in ('runtime_dependency_graph', 'runtime_path_contract'):
        graph = compiled.get(graph_pointer)
        if type(graph) is not dict:
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/' + graph_pointer)
        edges = graph.get('edges') if type(graph) is dict else None
        if type(edges) is not list:
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/' + graph_pointer + '/edges')
        for index, edge in enumerate(edges):
            if type(edge) is not dict:
                _fail('compiled-f6-handoff-compiler-schema-invalid',
                      '/compiled_paths/' + graph_pointer + '/edges/' + str(index))
            if (edge.get('kind') == 'DMA_MASTER_TRANSFER'
                    or edge.get('relation') in (
                        'DMA_MASTER_TRANSFER', 'dma_master_route')):
                _fail('compiled-f6-handoff-static-f6-required',
                      '/compiled_paths/' + graph_pointer + '/edges/' + str(index))

    try:
        dependency_graph = DependencyGraph.from_edge_document(
            compiled['runtime_dependency_graph'])
    except (TypeError, ValueError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-compiler-schema-invalid',
            '/compiled_paths/runtime_dependency_graph') from error
    if any(rule.kind == 'DMA_MASTER_TRANSFER'
           for rule in dependency_graph.ordered_rules):
        _fail('compiled-f6-handoff-static-f6-required',
              '/compiled_paths/runtime_dependency_graph/rules')

    try:
        runtime_contract = RuntimePathContract.from_document(
            compiled['runtime_path_contract'])
    except (TypeError, ValueError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-compiler-schema-invalid',
            '/compiled_paths/runtime_path_contract') from error
    if runtime_contract.dma_master_routes:
        _fail('compiled-f6-handoff-static-f6-required',
              '/compiled_paths/runtime_path_contract/dma_master_routes')
    graph_document = dependency_graph.edge_document()
    if runtime_contract.graph_sha256 != _sha256(graph_document):
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/runtime_path_contract/graph_sha256')
    graph_edges = {(edge['rule_index'], edge['prerequisite_index']): edge
                   for edge in graph_document['edges']}
    graph_nodes = set(dependency_graph.sources)
    for edge in graph_edges.values():
        graph_nodes.update((edge['prerequisite'], edge['target']))
    if {node.node_id for node in runtime_contract.nodes} != graph_nodes:
        _fail('compiled-f6-handoff-compiler-schema-invalid',
              '/compiled_paths/runtime_path_contract/nodes')
    nodes_by_id = {node.node_id: node for node in runtime_contract.nodes}
    for node in runtime_contract.nodes:
        if node.component not in component_ids:
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/runtime_path_contract/nodes')
    for source_id, source in dependency_graph.sources.items():
        node = nodes_by_id[source_id]
        if (node.component != source.component
                or (source.kind == 'memory_image' and node.kind != 'state')
                or (source.kind == 'source' and (
                    node.kind != 'physical' or node.port != source.port
                    or node.bit_offset != source.bit_offset
                    or node.width != source.width))):
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/runtime_path_contract/nodes')
        flow_id = source_id.split('.', 1)[0]
        path = next((row for row in paths if row['flow_id'] == flow_id), None)
        if source.kind == 'memory_image':
            matching_paths = [row for row in paths
                              if row['flow_id'] == flow_id]
            images = [] if len(matching_paths) != 1 else [
                row for row in matching_paths[0]['sources']
                if type(row) is dict
                and row.get('kind') == 'instruction_image']
            if (flow_id not in FLOW_IDS
                    or source_id != f'{flow_id}.program_image'
                    or len(matching_paths) != 1
                    or matching_paths[0]['status'] != STATUS_EXECUTABLE
                    or len(images) != 1
                    or tuple(source.directions) != ('CPU_TO_IP',)
                    or any(images[0].get(key) != value for key, value in (
                        ('component', source.component), ('port', source.port),
                        ('bit_offset', source.bit_offset),
                        ('width', source.width)))):
                _fail('compiled-f6-handoff-compiler-schema-invalid',
                      '/compiled_paths/runtime_dependency_graph/sources')
        if source.kind == 'source':
            pins = [] if path is None else [
                row for row in path['sources']
                if type(row) is dict and row.get('kind') == 'external_pin']
            if (source_id != 'F5.pin_event'
                    or path is None
                    or path['status'] != STATUS_EXECUTABLE
                    or len(pins) != 1
                    or any(pins[0].get(key) != value for key, value in (
                        ('component', source.component), ('port', source.port),
                        ('bit_offset', source.bit_offset),
                        ('width', source.width)))
                    or tuple(source.directions) != (path['direction'],)):
                _fail('compiled-f6-handoff-compiler-schema-invalid',
                      '/compiled_paths/runtime_dependency_graph/sources')
    contract_edges = {edge.key: edge for edge in runtime_contract.edges}
    f5_uncontracted_edges = [edge for edge in graph_edges.values()
        if edge['kind'] == 'EVENT_ORDER'
        and edge['prerequisite'] == 'F5.pin_event'
        and edge['target'] == 'F5.ip_irq']
    for key, graph_edge in graph_edges.items():
        compiler_f5_uncontracted = (
            graph_edge['kind'] == 'EVENT_ORDER'
            and graph_edge['prerequisite'] == 'F5.pin_event'
            and graph_edge['target'] == 'F5.ip_irq'
            and graph_edge['prerequisite_index'] == 0
            and len(f5_uncontracted_edges) == 1
            and dependency_graph.sources.get('F5.pin_event') is not None
            and dependency_graph.sources['F5.pin_event'].kind == 'source')
        if key not in contract_edges and not compiler_f5_uncontracted:
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/runtime_path_contract/edges')
    for index, edge in enumerate(runtime_contract.edges):
        graph_edge = graph_edges.get(edge.key)
        if (graph_edge is None
                or edge.relation not in _RELATIONS.get(graph_edge['kind'], set())):
            _fail('compiled-f6-handoff-compiler-schema-invalid',
                  '/compiled_paths/runtime_path_contract/edges/' + str(index))

    return {
        'path_id': f6.get('path_id'),
        'status': f6['status'],
        'reason_code': reason['code'],
        'route_ids': route_ids,
    }


def _validate_compiled(compiled: dict, declaration: PreparedDmaIntentBinding) -> dict:
    declaration_document = declaration.document()
    f6 = validate_compiled_f6_static(compiled, declaration_document['wiring'])
    if [row['route_id'] for row in declaration_document['route_links']] != f6['route_ids']:
        _fail('compiled-f6-handoff-route-set-mismatch', '/declaration/route_links')
    return f6


def _build_document(compiled: dict, declaration: PreparedDmaIntentBinding) -> dict:
    f6 = _validate_compiled(compiled, declaration)
    declaration_document = declaration.document()
    wiring = declaration_document['wiring']
    identity_wiring = compiled['identity']['wiring']
    document = {
        'schema_version': _HANDOFF_SCHEMA,
        'compiled_paths': compiled,
        'compiled_paths_sha256': compiled_document_sha256(compiled),
        'declaration': declaration_document,
        'declaration_sha256': declaration.identity_sha256,
        'f6': f6,
        'wiring': {
            'schema_version': identity_wiring['schema_version'],
            'dma_master_routes_sha256': identity_wiring['dma_master_routes_sha256'],
            'dma_master_route_bindings_sha256': identity_wiring[
                'dma_master_route_bindings_sha256'],
        },
    }
    document['identity_sha256'] = _sha256(document)
    return document


@dataclass(frozen=True)
class CompiledF6DmaHandoff:
    """Detached compiler/declaration identity with its one prepared graph."""

    _document_bytes: bytes
    _declaration: PreparedDmaIntentBinding = field(repr=False, compare=False)

    @classmethod
    def _validated(cls, document: dict, declaration: PreparedDmaIntentBinding):
        result = object.__new__(cls)
        object.__setattr__(result, '_document_bytes', _canonical(document))
        object.__setattr__(result, '_declaration', declaration)
        return result

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self) -> str:
        return self.document()['identity_sha256']

    def validate(self) -> None:
        document = self.document()
        declaration = _declaration(
            document.get('declaration'),
            runtime_paths=self._declaration._prepared_runtime_paths)
        rebuilt = _build_document(document.get('compiled_paths'), declaration)
        if (_canonical(rebuilt) != self._document_bytes
                or declaration.document() != self._declaration.document()
                or declaration._prepared_runtime_paths
                    is not self._declaration._prepared_runtime_paths):
            _fail('compiled-f6-handoff-identity-mismatch', '/')

    @classmethod
    def from_document(cls, document: object) -> CompiledF6DmaHandoff:
        row = _closed(document, _HANDOFF_KEYS, '/')
        if row['schema_version'] != _HANDOFF_SCHEMA:
            _fail('compiled-f6-handoff-schema-invalid', '/schema_version')
        declaration = _declaration(row['declaration'])
        compiled = _json_copy(row['compiled_paths'], '/compiled_paths')
        rebuilt = _build_document(compiled, declaration)
        if _canonical(rebuilt) != _canonical(row):
            _fail('compiled-f6-handoff-identity-mismatch', '/')
        return cls._validated(rebuilt, declaration)


def prepare_compiled_f6_dma_handoff(
        compiled_paths: Mapping[str, object],
        declaration: PreparedDmaIntentBinding) -> CompiledF6DmaHandoff:
    """Validate and freeze one exact compiler result and D4 declaration."""
    if not isinstance(declaration, PreparedDmaIntentBinding):
        _fail('compiled-f6-handoff-declaration-invalid', '/declaration')
    copied = _json_copy(dict(compiled_paths), '/compiled_paths')
    try:
        checked_declaration = _declaration(
            declaration.document(),
            runtime_paths=declaration._prepared_runtime_paths)
    except AttributeError as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-declaration-invalid', '/declaration') from error
    if checked_declaration is not declaration:
        # The parser returns a byte-identical wrapper; retain the caller's
        # object so D4 sees its exact already-prepared graph once.
        if (checked_declaration.document() != declaration.document()
                or checked_declaration._prepared_runtime_paths
                    is not declaration._prepared_runtime_paths):
            _fail('compiled-f6-handoff-declaration-invalid', '/declaration')
        checked_declaration = declaration
    document = _build_document(copied, checked_declaration)
    return CompiledF6DmaHandoff._validated(document, checked_declaration)


@dataclass(frozen=True)
class BoundCompiledF6DmaHandoff:
    """Compiled handoff plus the existing live, guarded D4 topology binding."""

    _document_bytes: bytes
    _handoff: CompiledF6DmaHandoff = field(repr=False, compare=False)
    topology_binding: BoundDmaIntentTopology = field(repr=False, compare=False)

    @classmethod
    def _validated(cls, document: dict, handoff: CompiledF6DmaHandoff,
                   topology_binding: BoundDmaIntentTopology):
        result = object.__new__(cls)
        object.__setattr__(result, '_document_bytes', _canonical(document))
        object.__setattr__(result, '_handoff', handoff)
        object.__setattr__(result, 'topology_binding', topology_binding)
        return result

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self) -> str:
        return self.document()['identity_sha256']

    def validate_topology(self) -> None:
        self._handoff.validate()
        try:
            self.topology_binding.validate_topology()
        except ValueError as error:
            raise CompiledF6DmaHandoffError(
                'compiled-f6-handoff-topology-changed', '/') from error
        expected = _bound_document(self._handoff, self.topology_binding)
        if _canonical(expected) != self._document_bytes:
            _fail('compiled-f6-handoff-identity-mismatch', '/')

    def match_dma_master_route(self, *args, **kwargs):
        """Proxy the guarded per-beat route lookup used by D4 admission."""
        return self.topology_binding.match_dma_master_route(*args, **kwargs)

    @classmethod
    def from_document(cls, document: object, *, handoff: CompiledF6DmaHandoff,
                      topology_binding: BoundDmaIntentTopology):
        row = _closed(document, _BOUND_KEYS, '/')
        if row['schema_version'] != _BOUND_SCHEMA:
            _fail('compiled-f6-handoff-schema-invalid', '/schema_version')
        handoff.validate()
        try:
            topology_binding.validate_topology()
        except ValueError as error:
            raise CompiledF6DmaHandoffError(
                'compiled-f6-handoff-topology-changed', '/') from error
        expected = _bound_document(handoff, topology_binding)
        if _canonical(expected) != _canonical(row):
            _fail('compiled-f6-handoff-identity-mismatch', '/')
        return cls._validated(expected, handoff, topology_binding)


def _bound_document(handoff: CompiledF6DmaHandoff,
                    topology_binding: BoundDmaIntentTopology) -> dict:
    if not isinstance(handoff, CompiledF6DmaHandoff):
        _fail('compiled-f6-handoff-invalid-document', '/compiled_f6_handoff')
    if not isinstance(topology_binding, BoundDmaIntentTopology):
        _fail('compiled-f6-handoff-invalid-document', '/topology_binding')
    _validate_topology_join(handoff, topology_binding)
    document = {
        'schema_version': _BOUND_SCHEMA,
        'compiled_f6_handoff': handoff.document(),
        'topology_binding': topology_binding.document(),
    }
    document['identity_sha256'] = _sha256(document)
    return document


def _validate_topology_join(handoff: CompiledF6DmaHandoff,
                            topology_binding: BoundDmaIntentTopology) -> None:
    handoff_document = handoff.document()
    topology_document = topology_binding.document()
    if (type(topology_document) is not dict
            or set(topology_document) != _TOPOLOGY_KEYS
            or topology_document.get('schema_version')
                != 'dma_intent_topology_binding.v1'
            or topology_document.get('tier') != 'topology_bound'):
        _fail('compiled-f6-handoff-topology-mismatch', '/topology_binding')
    topology_identity = topology_document['identity_sha256']
    without_identity = {key: value for key, value in topology_document.items()
                        if key != 'identity_sha256'}
    if (topology_identity != _sha256(without_identity)
            or topology_document.get('declaration_sha256')
                != handoff_document['declaration_sha256']):
        _fail('compiled-f6-handoff-topology-mismatch', '/topology_binding')
    route_credentials = topology_document.get('routes')
    if type(route_credentials) is not list:
        _fail('compiled-f6-handoff-topology-mismatch',
              '/topology_binding/routes')
    try:
        static_routes = parse_dma_master_route_intents(
            handoff_document['declaration']['wiring']['dma_master_routes'])
        route_links = handoff_document['declaration']['route_links']
        expected_links = {row['route_id']: row for row in route_links}
        static_by_id = {row.route_id: row for row in static_routes}
    except (KeyError, TypeError, ValueError) as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-declaration-invalid', '/declaration') from error
    if (len(expected_links) != len(route_links)
            or set(expected_links) != set(static_by_id)
            or len(route_credentials) != len(static_by_id)):
        _fail('compiled-f6-handoff-topology-mismatch',
              '/topology_binding/routes')
    credentials_by_id = {}
    expected_fields = {
        'route_id', 'intent_sha256', 'rule_index', 'prerequisite_index',
        'runtime_route_sha256', 'endpoint_link_sha256',
    }
    for row in route_credentials:
        if (type(row) is not dict or set(row) != expected_fields
                or not isinstance(row.get('route_id'), str)
                or row['route_id'] in credentials_by_id):
            _fail('compiled-f6-handoff-topology-mismatch',
                  '/topology_binding/routes')
        credentials_by_id[row['route_id']] = row
    for route_id, static_route in static_by_id.items():
        link = expected_links[route_id]
        credential = credentials_by_id.get(route_id)
        if (credential is None
                or credential['intent_sha256'] != static_route.identity_sha256
                or credential['rule_index'] != link['rule_index']
                or credential['prerequisite_index'] != link['prerequisite_index']
                or credential['runtime_route_sha256']
                    != link['runtime_route_sha256']
                or credential['endpoint_link_sha256']
                    != _sha256(link['endpoint_link'])):
            _fail('compiled-f6-handoff-topology-mismatch',
                  '/topology_binding/routes/' + route_id)


def bind_compiled_f6_dma_handoff(
        handoff: CompiledF6DmaHandoff, runner, *, artifact_links) -> BoundCompiledF6DmaHandoff:
    """Bind the retained prepared graph through the existing D4 binder once."""
    if not isinstance(handoff, CompiledF6DmaHandoff):
        _fail('compiled-f6-handoff-invalid-document', '/')
    handoff.validate()
    declaration = handoff._declaration
    if declaration._prepared_runtime_paths is None:
        _fail('compiled-f6-handoff-prepared-graph-required',
              '/declaration/prepared_runtime_paths')
    try:
        topology = bind_dma_intent_topology(
            declaration, runner, artifact_links=artifact_links)
    except ValueError as error:
        raise CompiledF6DmaHandoffError(
            'compiled-f6-handoff-topology-bind-failed',
            getattr(error, 'pointer', '/topology')) from error
    document = _bound_document(handoff, topology)
    return BoundCompiledF6DmaHandoff._validated(document, handoff, topology)
