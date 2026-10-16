"""Versioned, non-executable test capability sidecars for component profiles.

The existing ``component_profile.v1`` remains a source/interface contract.
Optional test capabilities live in a separately versioned document so old
profiles cannot acquire new semantics through ignored JSON fields.  v1 holds
protocol, register and observation declarations; v2 adds a data-only feature
provider contract that names every L3 operation and its required observations.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from os import PathLike
from pathlib import Path
import re
from types import MappingProxyType

from .component_profile import ComponentProfile


IP_TEST_CAPABILITY_SCHEMA = 'ip_test_capability.v1'
IP_TEST_CAPABILITY_SCHEMA_V2 = 'ip_test_capability.v2'
IP_TEST_CAPABILITY_SCHEMA_V3 = 'ip_test_capability.v3'
_ROOT_KEYS_V1 = frozenset((
    'schema_version', 'component_id', 'profile_fingerprint', 'endpoint_capabilities',
    'register_semantics', 'observation_mappings',
))
_ROOT_KEYS_V2 = _ROOT_KEYS_V1 | frozenset(('feature_contract',))
IP_TEST_OPERATIONS = frozenset((
    'request', 'accept', 'response', 'error', 'wait', 'drive', 'sample',
    'observe', 'deliver', 'read', 'write', 'retire',
))
_OPERATIONS = IP_TEST_OPERATIONS
_FEATURE_OPERATIONS = frozenset((
    'transfer', 'interrupt', 'state_transition', 'completion',
))
_OBSERVATION_KINDS = frozenset((
    'port_sample', 'signal_change', 'binding_delivery', 'input_sample',
    'reset_observation', 'clock_domain_progress',
))
_ACCESS = frozenset(('ro', 'rw', 'wo'))
_SIDE_EFFECTS = frozenset((
    'none', 'channel_enable_and_idle_polarity',
    'configuration_latched_while_disabled', 'hardware_latched_by_strap_sampling',
    'hardware_set_by_strap_sampling', 'read_clears', 'read_pops_fifo',
    'read_pops_rx_fifo', 'read_rearms_interrupt', 'self_clearing',
    'starts_transfer', 'write_drives_output_enable', 'write_drives_pads',
    'write_loads_divider', 'write_mask_gated_lanes', 'write_one_clears',
    'write_one_clears_event_bits', 'write_one_clears_fifo', 'write_one_sets',
    'write_one_to_clear', 'write_pulses_alert_test',
    'write_pulses_interrupt_test', 'write_pushes_fifo', 'write_pushes_tx_fifo',
    'write_resets_count', 'write_resets_uart_state', 'write_starts_transfer',
    'write_stops_or_starts_countdown', 'transmit_byte', 'write_1_to_clear',
))
_FORBIDDEN_KEYS = frozenset((
    'python', 'script', 'callback', 'hook', 'plugin', 'code', 'exec', 'eval',
    'module_path', 'callable', 'lambda', 'import', 'source_code', 'patch',
))
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
_TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
_PROFILE_FINGERPRINT = re.compile(r'sha256:[0-9a-f]{64}\Z')


class IPTestCapabilityError(ValueError):
    """A versioned capability sidecar is malformed or disagrees with its profile."""


@dataclass(frozen=True, slots=True)
class EndpointTestCapability:
    endpoint_id: str
    operations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegisterFieldSemantics:
    register: str
    field: str
    lsb: int
    width: int
    access: str
    read_mask: int
    write_mask: int
    reset_value: int | None
    side_effect: str
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class ObservationMapping:
    mapping_id: str
    endpoint_id: str
    role: str
    observation_kind: str
    evidence_ref: str
    bit_range: tuple[int, int] | None = None
    endianness: str | None = None


@dataclass(frozen=True, slots=True)
class FeatureOperationDeclaration:
    endpoint_id: str
    operation: str
    required_observation_mappings: tuple[str, ...]
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class FeaturePluginContract:
    provider_id: str
    provider_version: str
    operations: tuple[FeatureOperationDeclaration, ...]


@dataclass(frozen=True, slots=True)
class RegisterAliasRelation:
    endpoint_id: str
    source_register: str
    source_field: str
    destination_register: str
    destination_field: str
    operation: str
    bus_width: int
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class IPTestCapability:
    schema_version: str
    component_id: str
    profile_fingerprint: str
    endpoint_capabilities: tuple[EndpointTestCapability, ...]
    register_semantics: tuple[RegisterFieldSemantics, ...]
    observation_mappings: tuple[ObservationMapping, ...]
    feature_contract: FeaturePluginContract | None
    source_document: Mapping[str, object]
    sidecar_fingerprint: str
    register_aliases: tuple[RegisterAliasRelation, ...] = ()


@dataclass(frozen=True, slots=True)
class RegisterOperationPlan:
    register: str
    field: str
    operation: str
    offset: int
    field_width: int
    bus_mask: int
    bus_value: int | None
    side_effect: str
    evidence_ref: str


def plan_register_operation(
    profile: ComponentProfile,
    capability: IPTestCapability,
    *,
    register: str,
    field: str,
    operation: str,
    value: int | None = None,
    allow_side_effect: bool = False,
) -> RegisterOperationPlan:
    """Resolve one field-scoped L2 access against the pinned register contract.

    Writes are restricted by the field's effective write mask.  Reads and
    writes with declared side effects require an explicit caller opt-in; the
    plan records the declared effect but never executes it.
    """
    if not isinstance(profile, ComponentProfile):
        _fail('component-profile-required')
    try:
        capability = _revalidate_ip_test_capability(capability, profile=profile)
    except IPTestCapabilityError:
        raise
    if not isinstance(allow_side_effect, bool):
        _fail('invalid-register-side-effect-authorization')
    if operation not in ('register_read', 'register_write'):
        _fail(f'invalid-register-operation:{operation}')
    if profile.address is None:
        _fail('register-operation-requires-address-map')
    register_record = next((item for item in profile.address.registers
                            if item.name == register), None)
    if register_record is None:
        _fail(f'unknown-register-reference:{register}')
    semantics = next((item for item in capability.register_semantics
                      if item.register == register and item.field == field), None)
    if semantics is None:
        _fail(f'register-field-semantics-not-declared:{register}.{field}')

    if operation == 'register_read':
        if value is not None:
            _fail('register-read-value-not-allowed')
        if semantics.access not in ('ro', 'rw') or semantics.read_mask == 0:
            _fail(f'register-field-not-readable:{register}.{field}')
        bus_mask = semantics.read_mask << semantics.lsb
        bus_value = None
    else:
        if semantics.access not in ('wo', 'rw') or semantics.write_mask == 0:
            _fail(f'register-field-not-writable:{register}.{field}')
        if type(value) is not int or value < 0 or value >= (1 << semantics.width):
            _fail('register-field-value-outside-width')
        if value & ~semantics.write_mask:
            _fail('register-field-value-exceeds-write-mask')
        bus_mask = semantics.write_mask << semantics.lsb
        bus_value = value << semantics.lsb

    if semantics.side_effect != 'none' and not allow_side_effect:
        _fail(f'register-side-effect-requires-explicit-authorization:{semantics.side_effect}')
    return RegisterOperationPlan(
        register, field, operation, register_record.offset, semantics.width,
        bus_mask, bus_value, semantics.side_effect, semantics.evidence_ref)


def _fail(reason: str) -> None:
    raise IPTestCapabilityError(reason)


def _read_document(document_or_path: object) -> dict[str, object]:
    if isinstance(document_or_path, Mapping):
        if any(not isinstance(key, str) for key in document_or_path):
            _fail('invalid-test-capability-document')
        return copy.deepcopy(dict(document_or_path))
    if isinstance(document_or_path, (str, PathLike)):
        try:
            document = json.loads(Path(document_or_path).read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IPTestCapabilityError('cannot-read-test-capability-document') from exc
        if not isinstance(document, dict) or any(not isinstance(key, str) for key in document):
            _fail('invalid-test-capability-document')
        return document
    _fail('invalid-test-capability-document')


def _canonical_value(value: object) -> object:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            _fail('invalid-test-capability-document')
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_value(item) for item in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    _fail('invalid-test-capability-document')


def _document_fingerprint(document: Mapping[str, object]) -> str:
    try:
        canonical = json.dumps(_canonical_value(document), sort_keys=True,
                               separators=(',', ':'), ensure_ascii=False,
                               allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise IPTestCapabilityError('test-capability-not-canonical-json') from exc
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()


def _reject_programming_keys(value: object, pointer: str = 'sidecar') -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
                _fail(f'embedded-program:{pointer}/{key}')
            _reject_programming_keys(item, f'{pointer}/{key}')
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_programming_keys(item, f'{pointer}/{index}')


def _object(value: object, reason: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail(reason)
    return value


def _freeze(value: object) -> object:
    """Freeze validated JSON containers so a loaded identity cannot drift."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze(item) for item in value)
    return value


def _array(value: object, reason: str) -> list[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(reason)
    return list(value)


def _text(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(reason)
    return value


def _integer(value: object, reason: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(reason)
    return value


def _keys(row: Mapping[str, object], required: set[str], optional: set[str],
          reason: str) -> None:
    actual = set(row)
    missing = required - actual
    unknown = actual - required - optional
    if missing:
        _fail(f'missing-{reason}-field:{min(missing)}')
    if unknown:
        _fail(f'unknown-{reason}-field:{min(unknown)}')


def _strings(value: object, reason: str, allowed: frozenset[str]) -> tuple[str, ...]:
    rows = _array(value, reason)
    if not rows:
        _fail(reason)
    values = tuple(_text(item, reason) for item in rows)
    if len(set(values)) != len(values):
        _fail(f'duplicate-{reason}')
    unknown = sorted(set(values) - allowed)
    if unknown:
        _fail(f'unsupported-{reason}:{unknown[0]}')
    return values


def load_ip_test_capability(document_or_path: object, *,
                            profile: ComponentProfile) -> IPTestCapability:
    """Load one sidecar and bind every claim to an existing profile identity.

    This stage validates declaration shape and references only. It does not
    promote a declaration to an effective or verified capability; those checks
    belong to the preflight and evidence stages.
    """
    if not isinstance(profile, ComponentProfile):
        _fail('component-profile-required')
    document = _read_document(document_or_path)
    _reject_programming_keys(document)
    schema_version = document.get('schema_version')
    if schema_version == IP_TEST_CAPABILITY_SCHEMA:
        _keys(document, set(_ROOT_KEYS_V1), set(), 'test-capability')
    elif schema_version == IP_TEST_CAPABILITY_SCHEMA_V2:
        _keys(document, set(_ROOT_KEYS_V2), set(), 'test-capability')
    elif schema_version == IP_TEST_CAPABILITY_SCHEMA_V3:
        if 'register_aliases' not in document:
            _fail('register-aliases-required')
        _keys(document, set(_ROOT_KEYS_V1) | {'register_aliases'},
              {'feature_contract'}, 'test-capability')
    else:
        _fail(f"unsupported-test-capability-schema:{schema_version}")
    component_id = _text(document.get('component_id'), 'invalid-test-capability-component')
    if component_id != profile.component_id:
        _fail('test-capability-component-mismatch')
    profile_fingerprint = _text(document.get('profile_fingerprint'),
                                 'invalid-test-capability-profile-fingerprint')
    if _PROFILE_FINGERPRINT.fullmatch(profile_fingerprint) is None:
        _fail('invalid-test-capability-profile-fingerprint')
    if profile_fingerprint != profile.profile_fingerprint:
        _fail('test-capability-profile-mismatch')

    endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
    endpoint_capabilities = []
    seen_endpoints = set()
    for index, value in enumerate(_array(document['endpoint_capabilities'],
                                         'invalid-endpoint-capabilities')):
        row = _object(value, f'invalid-endpoint-capability:{index}')
        _keys(row, {'endpoint_id', 'operations'}, set(), 'endpoint-capability')
        endpoint_id = _text(row.get('endpoint_id'), 'invalid-endpoint-capability-id')
        if endpoint_id not in endpoint_ids:
            _fail(f'unknown-capability-endpoint:{endpoint_id}')
        if endpoint_id in seen_endpoints:
            _fail(f'duplicate-capability-endpoint:{endpoint_id}')
        operations = _strings(row.get('operations'), 'endpoint-operations', _OPERATIONS)
        endpoint_capabilities.append(EndpointTestCapability(endpoint_id, operations))
        seen_endpoints.add(endpoint_id)

    registers_by_name = ({item.name: item for item in profile.address.registers}
                         if profile.address is not None else {})
    register_semantics = []
    seen_register_fields: dict[str, list[tuple[int, int, str]]] = {}
    for index, value in enumerate(_array(document['register_semantics'],
                                         'invalid-register-semantics')):
        row = _object(value, f'invalid-register-semantics:{index}')
        _keys(row, {'register', 'field', 'lsb', 'width', 'access', 'read_mask',
                    'write_mask', 'side_effect', 'evidence_ref'},
              {'reset_value'}, 'register-semantics')
        register = _text(row.get('register'), 'invalid-register-reference')
        base = registers_by_name.get(register)
        if base is None:
            _fail(f'unknown-register-reference:{register}')
        field_name = _text(row.get('field'), 'invalid-register-field-name')
        if _IDENTIFIER.fullmatch(field_name) is None:
            _fail('invalid-register-field-name')
        lsb = _integer(row.get('lsb'), 'invalid-register-field-lsb')
        width = _integer(row.get('width'), 'invalid-register-field-width', minimum=1)
        if lsb + width > base.width:
            _fail('register-field-outside-width')
        access = _text(row.get('access'), 'invalid-register-field-access')
        if access not in _ACCESS:
            _fail('invalid-register-field-access')
        if ((base.access == 'ro' and access != 'ro')
                or (base.access == 'wo' and access != 'wo')):
            _fail('register-field-access-exceeds-profile')
        mask_limit = (1 << width) - 1
        read_mask = _integer(row.get('read_mask'), 'invalid-register-field-read-mask')
        write_mask = _integer(row.get('write_mask'), 'invalid-register-field-write-mask')
        if read_mask > mask_limit or write_mask > mask_limit:
            _fail('register-field-mask-outside-width')
        if access == 'ro' and write_mask:
            _fail('register-field-write-mask-on-read-only-field')
        if access == 'wo' and read_mask:
            _fail('register-field-read-mask-on-write-only-field')
        writable = base.writable_bits if base.writable_bits is not None else (
            (1 << base.width) - 1 if base.access != 'ro' else 0)
        if write_mask << lsb & ~writable:
            _fail('register-field-write-mask-exceeds-profile')
        reset_value = row.get('reset_value')
        if reset_value is not None:
            reset_value = _integer(reset_value, 'invalid-register-field-reset-value')
            if reset_value > mask_limit:
                _fail('register-field-reset-value-outside-width')
            if base.reset_value is not None and reset_value != (base.reset_value >> lsb) & mask_limit:
                _fail('register-field-reset-value-conflicts-with-profile')
        side_effect = _text(row.get('side_effect'), 'invalid-register-field-side-effect')
        if side_effect not in _SIDE_EFFECTS:
            _fail(f'unsupported-register-field-side-effect:{side_effect}')
        if side_effect != base.side_effect:
            _fail('register-field-side-effect-conflicts-with-profile')
        evidence_ref = _text(row.get('evidence_ref'), 'register-field-evidence-required')
        interval = (lsb, lsb + width - 1)
        occupied = seen_register_fields.setdefault(register, [])
        if any(interval[0] <= high and low <= interval[1] for low, high, _ in occupied):
            _fail(f'overlapping-register-fields:{register}:{field_name}')
        if any(name == field_name for _, _, name in occupied):
            _fail(f'duplicate-register-field:{register}:{field_name}')
        occupied.append((*interval, field_name))
        register_semantics.append(RegisterFieldSemantics(
            register, field_name, lsb, width, access, read_mask, write_mask,
            reset_value, side_effect, evidence_ref))

    endpoints_by_id = {endpoint.endpoint_id: endpoint for endpoint in profile.endpoints}
    observation_mappings = []
    seen_mapping_ids = set()
    for index, value in enumerate(_array(document['observation_mappings'],
                                         'invalid-observation-mappings')):
        row = _object(value, f'invalid-observation-mapping:{index}')
        _keys(row, {'mapping_id', 'endpoint_id', 'role', 'observation_kind',
                    'evidence_ref'}, {'bit_range', 'endianness'}, 'observation-mapping')
        mapping_id = _text(row.get('mapping_id'), 'invalid-observation-mapping-id')
        if _TOKEN.fullmatch(mapping_id) is None:
            _fail('invalid-observation-mapping-id')
        if mapping_id in seen_mapping_ids:
            _fail(f'duplicate-observation-mapping:{mapping_id}')
        endpoint_id = _text(row.get('endpoint_id'), 'invalid-observation-endpoint')
        endpoint = endpoints_by_id.get(endpoint_id)
        if endpoint is None:
            _fail(f'unknown-observation-endpoint:{endpoint_id}')
        role = _text(row.get('role'), 'invalid-observation-role')
        field = next((item for item in endpoint.fields if item.role == role), None)
        if field is None:
            _fail(f'unknown-observation-role:{endpoint_id}:{role}')
        observation_kind = _text(row.get('observation_kind'),
                                 'invalid-observation-kind')
        if observation_kind not in _OBSERVATION_KINDS:
            _fail(f'unsupported-observation-kind:{observation_kind}')
        bit_range = row.get('bit_range')
        normalized_range = None
        if bit_range is not None:
            span = _array(bit_range, 'invalid-observation-bit-range')
            if len(span) != 2:
                _fail('invalid-observation-bit-range')
            low = _integer(span[0], 'invalid-observation-bit-range')
            high = _integer(span[1], 'invalid-observation-bit-range')
            if high < low:
                _fail('invalid-observation-bit-range')
            if field.width is not None and high >= field.width:
                _fail('observation-bit-range-outside-profile-width')
            normalized_range = (low, high)
        endianness = row.get('endianness')
        if endianness is not None and endianness not in ('little', 'big'):
            _fail('invalid-observation-endianness')
        if (observation_kind == 'input_sample' and field.direction is not None
                and field.direction != 'input'):
            _fail('input-sample-requires-input-role')
        evidence_ref = _text(row.get('evidence_ref'), 'observation-evidence-required')
        observation_mappings.append(ObservationMapping(
            mapping_id, endpoint_id, role, observation_kind, evidence_ref,
            normalized_range, endianness))
        seen_mapping_ids.add(mapping_id)

    register_aliases = []
    if schema_version == IP_TEST_CAPABILITY_SCHEMA_V3:
        fields = {(item.register, item.field): item for item in register_semantics}
        seen_alias_sources = set()
        alias_keys = {'endpoint_id', 'source_register', 'source_field',
                      'destination_register', 'destination_field', 'operation',
                      'bus_width', 'evidence_ref'}
        for value in _array(document['register_aliases'], 'invalid-register-aliases'):
            row = _object(value, 'invalid-register-alias')
            _keys(row, alias_keys, set(), 'register-alias')
            text = {key: _text(row[key], f'invalid-register-alias-{key}')
                    for key in alias_keys - {'bus_width'}}
            if type(row['bus_width']) is not int or row['bus_width'] != 32:
                _fail('invalid-register-alias-bus-width')
            endpoint = endpoints_by_id.get(text['endpoint_id'])
            declared_endpoint = next((item for item in endpoint_capabilities
                                      if item.endpoint_id == text['endpoint_id']), None)
            if (endpoint is None or endpoint.function != 'mmio_slave'
                    or endpoint.protocol != ('apb', '3')
                    or type(profile.capabilities.get('data_width')) is not int
                    or profile.capabilities.get('data_width') != 32
                    or profile.capabilities.get('read') is not True
                    or profile.capabilities.get('write') is not True
                    or declared_endpoint is None
                    or not {'read', 'write'}.issubset(declared_endpoint.operations)):
                _fail('invalid-register-alias-endpoint')
            source_key = (text['source_register'], text['source_field'])
            destination_key = (text['destination_register'], text['destination_field'])
            source = fields.get(source_key)
            destination = fields.get(destination_key)
            if source is None or destination is None:
                _fail('unknown-register-alias-field')
            if source_key in seen_alias_sources:
                _fail('duplicate-register-alias-source')
            source_base = registers_by_name[source.register]
            destination_base = registers_by_name[destination.register]
            effect = {'set_bits': 'write_one_sets',
                      'clear_bits': 'write_one_clears'}.get(text['operation'])
            if (effect is None or source.side_effect != effect
                    or source.access != 'wo' or source.read_mask != 0
                    or source.lsb != 0 or source.width != 32
                    or source.write_mask != 0xffffffff or source_base.width != 32):
                _fail('invalid-register-alias-source-semantics')
            if (destination.access not in ('ro', 'rw')
                    or destination.side_effect != 'none'
                    or destination.lsb != 0 or destination.width != 32
                    or destination.read_mask != 0xffffffff
                    or destination_base.width != 32):
                _fail('invalid-register-alias-destination-semantics')
            if (source.register == destination.register
                    or source_base.offset == destination_base.offset
                    or profile.address is None
                    or any(base.offset % 4 or base.offset + 4 > profile.address.window_size
                           for base in (source_base, destination_base))):
                _fail('invalid-register-alias-address')
            for previous in register_aliases:
                if previous.endpoint_id != text['endpoint_id']:
                    continue
                previous_source = registers_by_name[previous.source_register].offset
                previous_destination = registers_by_name[previous.destination_register].offset
                if (source_base.offset in (previous_source, previous_destination)
                        or destination_base.offset == previous_source):
                    _fail('ambiguous-register-alias-address')
            # Provenance is closed declaration data, never a file/provider selector.
            # Current source bytes are authenticated separately by the assembly.
            if text['evidence_ref'] != source.evidence_ref:
                _fail('register-alias-evidence-mismatch')
            register_aliases.append(RegisterAliasRelation(
                text['endpoint_id'], *source_key, *destination_key,
                text['operation'], 32, text['evidence_ref']))
            seen_alias_sources.add(source_key)

    feature_contract = None
    if schema_version == IP_TEST_CAPABILITY_SCHEMA_V2 or (
            schema_version == IP_TEST_CAPABILITY_SCHEMA_V3 and 'feature_contract' in document):
        row = _object(document['feature_contract'], 'invalid-feature-contract')
        _keys(row, {'provider_id', 'provider_version', 'operations'}, set(),
              'feature-contract')
        provider_id = _text(row.get('provider_id'), 'invalid-feature-provider-id')
        if _TOKEN.fullmatch(provider_id) is None:
            _fail('invalid-feature-provider-id')
        provider_version = _text(row.get('provider_version'),
                                 'invalid-feature-provider-version')
        if _TOKEN.fullmatch(provider_version) is None:
            _fail('invalid-feature-provider-version')
        feature_operations = []
        seen_feature_operations = set()
        for index, value in enumerate(_array(row.get('operations'),
                                             'invalid-feature-operations')):
            operation_row = _object(value, f'invalid-feature-operation:{index}')
            _keys(operation_row, {'endpoint_id', 'operation',
                                  'required_observation_mappings', 'evidence_ref'},
                  set(), 'feature-operation')
            endpoint_id = _text(operation_row.get('endpoint_id'),
                                 'invalid-feature-endpoint')
            if endpoint_id not in endpoint_ids:
                _fail(f'unknown-feature-endpoint:{endpoint_id}')
            operation = _text(operation_row.get('operation'),
                              'invalid-feature-operation-name')
            if operation not in _FEATURE_OPERATIONS:
                _fail(f'unsupported-feature-operation:{operation}')
            key = (endpoint_id, operation)
            if key in seen_feature_operations:
                _fail(f'duplicate-feature-operation:{endpoint_id}:{operation}')
            required_value = _array(
                operation_row.get('required_observation_mappings'),
                'feature-observation-mappings-required')
            if not required_value:
                _fail('feature-observation-mappings-required')
            required_mappings = tuple(
                _text(item, 'invalid-feature-observation-mapping')
                for item in required_value)
            if len(set(required_mappings)) != len(required_mappings):
                _fail('duplicate-feature-observation-mapping')
            for mapping_id in required_mappings:
                if mapping_id not in seen_mapping_ids:
                    _fail(f'unknown-feature-observation-mapping:{mapping_id}')
            evidence_ref = _text(operation_row.get('evidence_ref'),
                                 'feature-operation-evidence-required')
            feature_operations.append(FeatureOperationDeclaration(
                endpoint_id, operation, required_mappings, evidence_ref))
            seen_feature_operations.add(key)
        if not feature_operations:
            _fail('feature-contract-operations-required')
        feature_contract = FeaturePluginContract(
            provider_id, provider_version, tuple(feature_operations))

    return IPTestCapability(
        schema_version, component_id, profile_fingerprint,
        tuple(endpoint_capabilities),
        tuple(register_semantics), tuple(observation_mappings), feature_contract,
        MappingProxyType({key: _freeze(value) for key, value in document.items()}),
        _document_fingerprint(document), tuple(register_aliases))


def _revalidate_ip_test_capability(capability: IPTestCapability, *,
                                   profile: ComponentProfile) -> IPTestCapability:
    """Rebuild a loaded sidecar and reject drift between its typed view and source.

    Frozen dataclasses can still be copied with ``dataclasses.replace``.  Reparse
    the retained immutable document at trust boundaries so a replaced typed
    field cannot keep reusing the original cached fingerprint.
    """
    if not isinstance(capability, IPTestCapability):
        _fail('loaded-test-capability-required')
    if not isinstance(capability.source_document, Mapping):
        _fail('invalid-test-capability-document')
    document = _canonical_value(capability.source_document)
    if not isinstance(document, dict):
        _fail('invalid-test-capability-document')
    canonical = load_ip_test_capability(document, profile=profile)
    if capability.sidecar_fingerprint != canonical.sidecar_fingerprint:
        _fail('test-capability-fingerprint-mismatch')
    if (
        capability.schema_version != canonical.schema_version
        or capability.component_id != canonical.component_id
        or capability.profile_fingerprint != canonical.profile_fingerprint
        or capability.endpoint_capabilities != canonical.endpoint_capabilities
        or capability.register_semantics != canonical.register_semantics
        or capability.observation_mappings != canonical.observation_mappings
        or capability.feature_contract != canonical.feature_contract
        or capability.register_aliases != canonical.register_aliases
        or type(capability.register_aliases) is not tuple
        or any(type(item) is not RegisterAliasRelation or type(item.bus_width) is not int
               for item in capability.register_aliases)
    ):
        _fail('test-capability-typed-contract-mismatch')
    return canonical


__all__ = [
    'IP_TEST_CAPABILITY_SCHEMA', 'IP_TEST_CAPABILITY_SCHEMA_V2', 'IP_TEST_CAPABILITY_SCHEMA_V3',
    'IPTestCapabilityError', 'EndpointTestCapability', 'RegisterFieldSemantics',
    'ObservationMapping', 'FeatureOperationDeclaration', 'FeaturePluginContract',
    'RegisterOperationPlan', 'RegisterAliasRelation', 'plan_register_operation',
    'IP_TEST_OPERATIONS', 'IPTestCapability', 'load_ip_test_capability',
]
