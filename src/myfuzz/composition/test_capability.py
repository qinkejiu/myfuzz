"""Versioned, non-executable test capability sidecars for component profiles.

The existing ``component_profile.v1`` remains a source/interface contract.
Optional test capabilities live in a separately versioned document so old
profiles cannot acquire new semantics through ignored JSON fields.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
from os import PathLike
from pathlib import Path
import re
from types import MappingProxyType

from .component_profile import ComponentProfile


IP_TEST_CAPABILITY_SCHEMA = 'ip_test_capability.v1'
_ROOT_KEYS = frozenset((
    'schema_version', 'component_id', 'profile_fingerprint', 'endpoint_capabilities',
    'register_semantics', 'observation_mappings',
))
_OPERATIONS = frozenset((
    'request', 'accept', 'response', 'error', 'wait', 'drive', 'sample',
    'observe', 'deliver', 'read', 'write', 'retire',
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
class IPTestCapability:
    schema_version: str
    component_id: str
    profile_fingerprint: str
    endpoint_capabilities: tuple[EndpointTestCapability, ...]
    register_semantics: tuple[RegisterFieldSemantics, ...]
    observation_mappings: tuple[ObservationMapping, ...]
    source_document: Mapping[str, object]


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
    _keys(document, set(_ROOT_KEYS), set(), 'test-capability')
    if document.get('schema_version') != IP_TEST_CAPABILITY_SCHEMA:
        _fail(f"unsupported-test-capability-schema:{document.get('schema_version')}")
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

    return IPTestCapability(
        IP_TEST_CAPABILITY_SCHEMA, component_id, profile_fingerprint,
        tuple(endpoint_capabilities),
        tuple(register_semantics), tuple(observation_mappings),
        MappingProxyType({key: _freeze(value) for key, value in document.items()}))


__all__ = [
    'IP_TEST_CAPABILITY_SCHEMA', 'IPTestCapabilityError',
    'EndpointTestCapability', 'RegisterFieldSemantics', 'ObservationMapping',
    'IPTestCapability', 'load_ip_test_capability',
]
