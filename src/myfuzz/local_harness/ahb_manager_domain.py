"""Versioned manager-domain observation contract for the AHB-Lite CPU boundary.

Why this module exists
    CVW's external-bus trace declares ``hready`` = ``HREADYEXT``: the *external
    subordinate's* ready input.  It is not the manager's aggregate ``HREADY``
    output, which is the value that actually accepts an address and advances the
    data phase.  The actual bus reset is the synchronized ``HRESETn`` output, not
    the external driver reset command.  Treating the external roles as the
    manager domain produced the preserved attempt1 failure
    (``ahb_address_hold`` at startup edge 11).

    This module adds a second, non-protocol *observation* endpoint with exactly
    two one-bit output roles, ``manager_ready`` and ``bus_reset_n``.  The profile
    binds them to the already exported ``HREADY``/``HRESETn`` physical outputs.
    The generated runtime document carries the resulting versioned contract, and
    :func:`authenticate_manager_domain` proves it against the structural ABI,
    the physical exports, the protocol-trace clock and the declared reset
    provenance.  Nothing here branches on a CPU name, infers a role from a port
    name, falls back to the external ready role, or inverts a reset.

    The contract only describes evidence.  It grants no transaction, retirement
    or protocol-completion authority: every event remains ``observation_only``.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

SCHEMA = 'ahb_manager_domain_contract.v1'
PROJECTION_SCHEMA = 'ahb_manager_domain_projection.v1'
ROLES = ('bus_reset_n', 'manager_ready')
OBSERVER_VERSION = 3
SAMPLING_DOMAIN = ('external_thirteen_role_rows_separate_from_measured_'
                   'manager_ready_and_bus_reset_pre_rows')
SOURCES = ('generated_profile_binding',
           'saved_native_artifact_software_projection',
           'software_control')
SAMPLING = {
    'measured_phase': 'pre',
    'post': 'raw_retained_not_a_phase',
    'address_acceptance': 'manager_ready_pre',
    'completion': 'manager_ready_pre_and_external_selected_ready_pre',
    'reset': 'bus_reset_n_pre',
    'prefix': 'observed_assertion_then_release',
    'synchronizer_latency': 'not_claimed',
}
SCOPE = {
    'response': 'owned_external_selected_data_phase_only',
    'other_slave_context': 'unvalidated',
    'aggregate_hresp_exported': False,
    'aggregate_hrdata_exported': False,
}
EXTERNAL_READY_ROLE = 'hready'


def _error(reason: str) -> None:
    raise ValueError('ahb-manager-domain-' + reason)


def _text(value, reason: str) -> str:
    if not isinstance(value, str) or not value:
        _error(reason)
    return value


def _mapping(value, keys, reason: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        _error(reason)
    return value


def _strict_equal(left, right, reason: str) -> None:
    if json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) != \
            json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False):
        _error(reason)


def manager_domain_endpoint(profile):
    """Return the one declared observation endpoint with the two measured roles."""
    candidates = [endpoint for endpoint in profile.endpoints
                  if endpoint.function == 'observation'
                  and {field.role for field in endpoint.fields} == set(ROLES)]
    if len(candidates) != 1:
        _error('endpoint')
    endpoint = candidates[0]
    if endpoint.protocol is not None:
        _error('endpoint-protocol')
    if len(endpoint.fields) != 2:
        _error('endpoint-fields')
    if not isinstance(endpoint.clock, str) or not endpoint.clock:
        _error('endpoint-clock')
    if not isinstance(endpoint.reset, str) or not endpoint.reset:
        _error('endpoint-reset')
    for field in endpoint.fields:
        if field.direction != 'output' or field.width != 1:
            _error('endpoint-role-shape')
        if len(field.aliases) != 1:
            _error('endpoint-role-alias')
    return endpoint


def _profile_endpoint(endpoint) -> dict:
    fields = []
    for field in sorted(endpoint.fields, key=lambda item: item.role):
        fields.append(dict(role=field.role, physical_port=field.aliases[0],
                           direction='output', width=1))
    return dict(endpoint_id=endpoint.endpoint_id, function='observation',
                clock=endpoint.clock, reset=endpoint.reset, fields=fields)


def _role_rows(document_abi, endpoint_id: str, role: str) -> list[dict]:
    return [row for row in document_abi
            if row.get('endpoint_id') == endpoint_id and row.get('role') == role]


def _export_rows(exports, endpoint_id: str, role: str) -> list[dict]:
    return [row for row in exports
            if row.get('endpoint_id') == endpoint_id and row.get('role') == role]


def _clock_and_reset(profile, endpoint, clock_schedule) -> tuple[dict, dict]:
    clocks = {row['domain']: row for row in clock_schedule['clocks']}
    resets = {row['domain']: row for row in clock_schedule['resets']}
    if endpoint.clock not in clocks:
        _error('clock-domain')
    if endpoint.reset not in resets:
        _error('reset-domain')
    clock = clocks[endpoint.clock]
    external = resets[endpoint.reset]
    return (
        dict(domain=clock['domain'], signal=clock['signal'],
             source='profile_endpoint_clock_bound_to_protocol_trace'),
        dict(external_command=dict(domain=external['domain'], port=external['port'],
                                   signal=external['signal'],
                                   polarity=external['polarity'],
                                   synchronous=external['synchronous']),
             bus=dict(role='bus_reset_n', polarity='active_low',
                      measured_phase='pre', synchronizer_latency='not_claimed',
                      source='actual_dut_output_not_external_reset_proxy')),
    )


def build_manager_domain_contract(profile, clock_schedule, abi_rows, exports, *,
                                  protocol_endpoint_id: str,
                                  source: str = 'generated_profile_binding') -> dict:
    """Materialise the versioned contract from the bound profile and real ABI."""
    endpoint = manager_domain_endpoint(profile)
    clock, reset = _clock_and_reset(profile, endpoint, clock_schedule)
    roles = {}
    for field in sorted(endpoint.fields, key=lambda item: item.role):
        abi = _role_rows(abi_rows, endpoint.endpoint_id, field.role)
        export = _export_rows(exports, endpoint.endpoint_id, field.role)
        if len(abi) != 1 or len(export) != 1:
            _error('binding-rows')
        abi_row, export_row = abi[0], export[0]
        if (abi_row.get('physical_port'), abi_row.get('bit_lo'), abi_row.get('bit_hi'),
                abi_row.get('width'), abi_row.get('direction'),
                abi_row.get('disposition')) != (
                field.aliases[0], 0, 0, 1, 'output', 'observe'):
            _error('abi-role')
        if (export_row.get('physical_port'), export_row.get('wrapper_name'),
                export_row.get('runtime_name'), export_row.get('width'),
                export_row.get('direction'), export_row.get('disposition'),
                export_row.get('bit_lo'), export_row.get('bit_hi'),
                export_row.get('encoding'), export_row.get('hex_digits')) != (
                field.aliases[0], abi_row.get('wrapper_name'),
                'rt_' + abi_row.get('wrapper_name'), 1, 'output', 'observe',
                0, 0, 'integer', 1):
            _error('export-role')
        roles[field.role] = dict(
            width=1, direction='output', physical_port=field.aliases[0],
            wrapper_name=abi_row['wrapper_name'],
            runtime_name=export_row['runtime_name'],
            source_wire=field.aliases[0], clock_domain=endpoint.clock)
    contract = dict(
        schema_version=SCHEMA, endpoint_id=endpoint.endpoint_id,
        function='observation', protocol_endpoint_id=protocol_endpoint_id,
        profile_endpoint=_profile_endpoint(endpoint), roles=roles,
        clock=clock, reset=reset, sampling=copy.deepcopy(SAMPLING),
        scope=copy.deepcopy(SCOPE), external_ready_role=EXTERNAL_READY_ROLE,
        source=source, authority='observation_only')
    validate_manager_domain_contract(contract)
    return contract


def validate_manager_domain_contract(contract) -> dict:
    """Strict shape and semantics; unknown keys, widths or fallbacks are refused."""
    _mapping(contract, ('schema_version', 'endpoint_id', 'function',
                        'protocol_endpoint_id', 'profile_endpoint', 'roles',
                        'clock', 'reset', 'sampling', 'scope',
                        'external_ready_role', 'source', 'authority'),
             'contract-shape')
    if contract['schema_version'] != SCHEMA:
        _error('schema')
    endpoint_id = _text(contract['endpoint_id'], 'endpoint-id')
    protocol_id = _text(contract['protocol_endpoint_id'], 'protocol-endpoint-id')
    if endpoint_id == protocol_id:
        _error('endpoint-alias')
    if contract['function'] != 'observation' or contract['authority'] != 'observation_only':
        _error('authority')
    if contract['source'] not in SOURCES:
        _error('source')
    if contract['external_ready_role'] != EXTERNAL_READY_ROLE:
        _error('external-ready-role')
    _strict_equal(contract['sampling'], SAMPLING, 'sampling')
    _strict_equal(contract['scope'], SCOPE, 'scope')

    profile_endpoint = _mapping(contract['profile_endpoint'],
                                ('endpoint_id', 'function', 'clock', 'reset', 'fields'),
                                'profile-endpoint')
    if (profile_endpoint['endpoint_id'] != endpoint_id
            or profile_endpoint['function'] != 'observation'):
        _error('profile-endpoint-identity')
    if profile_endpoint['clock'] != contract['clock']['domain'] \
            or profile_endpoint['reset'] != contract['reset']['external_command']['domain']:
        _error('profile-endpoint-provenance')
    fields = profile_endpoint['fields']
    if not isinstance(fields, list) or len(fields) != 2:
        _error('profile-endpoint-fields')
    declared_roles = []
    for field in fields:
        _mapping(field, ('role', 'physical_port', 'direction', 'width'),
                 'profile-endpoint-field')
        if field['role'] not in ROLES or field['direction'] != 'output' \
                or field['width'] != 1:
            _error('profile-endpoint-role')
        _text(field['physical_port'], 'profile-endpoint-port')
        declared_roles.append(field['role'])
    if sorted(declared_roles) != list(ROLES):
        _error('profile-endpoint-roles')

    roles = _mapping(contract['roles'], ROLES, 'roles')
    used_ports = set()
    used_runtime = set()
    used_source = set()
    for role in ROLES:
        row = _mapping(roles[role], ('width', 'direction', 'physical_port',
                                     'wrapper_name', 'runtime_name',
                                     'source_wire', 'clock_domain'), 'role')
        if row['width'] != 1 or row['direction'] != 'output':
            _error('role-shape')
        for key in ('physical_port', 'wrapper_name', 'runtime_name', 'source_wire',
                    'clock_domain'):
            _text(row[key], 'role-' + key)
        for value, seen in ((row['physical_port'], used_ports),
                            (row['runtime_name'], used_runtime),
                            (row['source_wire'], used_source)):
            if value in seen:
                _error('role-duplicate')
            seen.add(value)
        field = next(item for item in fields if item['role'] == role)
        if field['physical_port'] != row['physical_port']:
            _error('profile-role-port')
        if row['source_wire'] != row['physical_port']:
            _error('source-wire')

    clock = _mapping(contract['clock'], ('domain', 'signal', 'source'), 'clock')
    _text(clock['domain'], 'clock-domain')
    _text(clock['signal'], 'clock-signal')
    if clock['source'] != 'profile_endpoint_clock_bound_to_protocol_trace':
        _error('clock-provenance')
    if any(roles[role]['clock_domain'] != clock['domain'] for role in ROLES):
        _error('role-clock')

    reset = _mapping(contract['reset'], ('external_command', 'bus'), 'reset')
    external = _mapping(reset['external_command'],
                        ('domain', 'port', 'signal', 'polarity', 'synchronous'),
                        'reset-external')
    for key in ('domain', 'port', 'signal'):
        _text(external[key], 'reset-external-' + key)
    if external['polarity'] not in ('active_high', 'active_low') \
            or type(external['synchronous']) is not bool:
        _error('reset-external-polarity')
    bus = _mapping(reset['bus'], ('role', 'polarity', 'measured_phase',
                                  'synchronizer_latency', 'source'), 'reset-bus')
    if bus['role'] != 'bus_reset_n' or bus['polarity'] != 'active_low' \
            or bus['measured_phase'] != 'pre' \
            or bus['synchronizer_latency'] != 'not_claimed' \
            or bus['source'] != 'actual_dut_output_not_external_reset_proxy':
        _error('reset-bus')
    if bus['role'] in roles and roles[bus['role']]['physical_port'] == external['port']:
        _error('reset-proxy')
    if bus['role'] in roles and roles[bus['role']]['physical_port'] == clock['signal']:
        _error('reset-clock')
    if external['port'] in used_ports:
        _error('reset-external-alias')
    if protocol_id == endpoint_id:
        _error('protocol-alias')
    return copy.deepcopy(dict(contract))


def _single_export(exports, physical_port: str, endpoint_id: str, role: str) -> dict:
    rows = [row for row in exports if row.get('physical_port') == physical_port]
    if len(rows) != 1:
        _error('physical-export')
    row = rows[0]
    if (row.get('endpoint_id'), row.get('role'), row.get('width'),
            row.get('direction'), row.get('disposition'), row.get('bit_lo'),
            row.get('bit_hi'), row.get('encoding'), row.get('hex_digits')) != (
            endpoint_id, role, 1, 'output', 'observe', 0, 0, 'integer', 1):
        _error('physical-export-binding')
    return row


def authenticate_manager_domain(document) -> dict:
    """Prove the document's domain contract against real structural facts."""
    contract = validate_manager_domain_contract(document.get('manager_domain'))
    trace = document['base_protocol_traces']['traces'][0]
    if contract['protocol_endpoint_id'] != trace.get('endpoint_id'):
        _error('protocol-endpoint')
    schedule = document.get('clock_schedule')
    if not isinstance(schedule, dict):
        _error('clock-schedule')
    clock = contract['clock']
    clocks = {row['domain']: row for row in schedule.get('clocks', [])}
    if clock['domain'] != trace.get('clock_domain') \
            or clock['domain'] != schedule.get('primary_clock_domain') \
            or clock['domain'] not in clocks \
            or clocks[clock['domain']].get('signal') != clock['signal']:
        _error('clock-provenance')
    resets = {row['domain']: row for row in schedule.get('resets', [])}
    external = contract['reset']['external_command']
    expected_reset = resets.get(schedule.get('primary_reset_domain'))
    if expected_reset is None:
        _error('reset-schedule')
    for key in ('domain', 'port', 'signal', 'polarity', 'synchronous'):
        if external[key] != expected_reset.get(key):
            _error('reset-provenance')
    if external['port'] == clock['signal']:
        _error('reset-clock-alias')

    abi = document.get('structural_abi', {}).get('ports', [])
    exports = document.get('physical_exports', [])
    taps = document.get('protocol_tap_ports', [])
    tap_wires = {row.get('source_wire') for row in taps}
    external_ready = [row for row in taps
                      if row.get('role') == EXTERNAL_READY_ROLE
                      and row.get('endpoint_id') == contract['protocol_endpoint_id']]
    if len(external_ready) != 1:
        _error('external-ready-tap')
    plan_rows = (document.get('plan') or {}).get('ports', [])
    for role in ROLES:
        row = contract['roles'][role]
        port = row['physical_port']
        abi_rows = [item for item in abi if item.get('physical_port') == port]
        if len(abi_rows) != 1:
            _error('abi-port')
        abi_row = abi_rows[0]
        if (abi_row.get('endpoint_id'), abi_row.get('role'),
                abi_row.get('wrapper_name'), abi_row.get('bit_lo'),
                abi_row.get('bit_hi'), abi_row.get('width'),
                abi_row.get('direction'), abi_row.get('disposition')) != (
                contract['endpoint_id'], role, row['wrapper_name'], 0, 0, 1,
                'output', 'observe'):
            _error('abi-binding')
        export = _single_export(exports, port, contract['endpoint_id'], role)
        if (export.get('wrapper_name'), export.get('runtime_name')) != (
                row['wrapper_name'], row['runtime_name']):
            _error('export-binding')
        if document.get('plan') is not None:
            plan_rows_role = [item for item in plan_rows
                              if item.get('endpoint_id') == contract['endpoint_id']
                              and item.get('role') == role]
            if len(plan_rows_role) != 1:
                _error('plan-binding')
            plan_row = plan_rows_role[0]
            if (plan_row.get('port'), plan_row.get('direction'),
                    plan_row.get('disposition'), plan_row.get('port_width'),
                    plan_row.get('bits', {}).get('lo'),
                    plan_row.get('bits', {}).get('hi')) != (
                    port, 'output', 'observe', 1, 0, 0):
                _error('plan-binding')
        if port in tap_wires or row['source_wire'] in tap_wires:
            _error('protocol-tap-alias')
    if contract['roles']['manager_ready']['physical_port'] == \
            contract['roles']['bus_reset_n']['physical_port']:
        _error('role-alias')
    if contract['roles']['manager_ready']['source_wire'] == \
            external_ready[0].get('source_wire'):
        _error('external-ready-fallback')
    if contract['reset']['external_command']['port'] in {
            contract['roles']['manager_ready']['physical_port'],
            contract['roles']['bus_reset_n']['physical_port']}:
        _error('reset-role-alias')

    projection = document.get('domain_projection')
    if projection is not None:
        _mapping(projection, ('schema_version', 'provenance',
                              'source_artifact_digest', 'source_profile_sha256',
                              'domain_profile_sha256', 'domain_profile_path',
                              'note'), 'projection')
        if projection['schema_version'] != PROJECTION_SCHEMA \
                or projection['provenance'] != 'saved_native_artifact_software_projection':
            _error('projection-provenance')
        if contract['source'] != 'saved_native_artifact_software_projection':
            _error('projection-source')
        if projection['source_artifact_digest'] != document.get('artifact_digest'):
            _error('projection-digest')
        plan = document.get('plan') or {}
        if projection['source_profile_sha256'] != plan.get('profile_sha256'):
            _error('projection-source-profile')
        _text(projection['domain_profile_sha256'], 'projection-profile')
        _text(projection['domain_profile_path'], 'projection-path')
        _text(projection['note'], 'projection-note')
    elif contract['source'] == 'saved_native_artifact_software_projection':
        _error('projection-metadata')
    return copy.deepcopy(contract)


def project_saved_manager_domain(artifact, profile_path) -> dict:
    """Bind the current profile's declared domain to a frozen native artifact.

    The saved bytes stay untouched: no sample, receipt or raw row is edited.  Only
    the artifact's *metadata* gains the declared endpoint/role facts, and the
    projection is labelled as software-only.  This is not a new native run and
    grants no identity claim against the current profile.
    """
    if not isinstance(artifact, dict) or not isinstance(artifact.get('plan'), dict):
        _error('saved-artifact')
    from myfuzz.composition.component_profile import load_component_profile
    path = Path(profile_path)
    raw = path.read_bytes()
    profile = load_component_profile(json.loads(raw))
    endpoint = manager_domain_endpoint(profile)
    if artifact.get('manager_domain') is not None:
        _error('saved-artifact-already-declared')
    projected = copy.deepcopy(artifact)
    abi = projected.get('structural_abi', {}).get('ports')
    exports = projected.get('physical_exports')
    plan_rows = projected.get('plan', {}).get('ports')
    runtime_ports = projected.get('runtime_ports', [])
    if not isinstance(abi, list) or not isinstance(exports, list) \
            or not isinstance(plan_rows, list):
        _error('saved-artifact-facts')
    tap_wires = {row.get('source_wire') for row in projected.get('protocol_tap_ports', [])}
    for field in endpoint.fields:
        port = field.aliases[0]
        if port in tap_wires:
            _error('saved-external-alias')
        export = [row for row in exports if row.get('physical_port') == port]
        if len(export) != 1:
            _error('saved-physical-export')
        export = export[0]
        if (export.get('endpoint_id'), export.get('role'), export.get('width'),
                export.get('direction'), export.get('disposition')) != (
                None, None, 1, 'output', 'observe'):
            _error('saved-physical-export-binding')
        abi_rows = [row for row in abi if row.get('physical_port') == port]
        if len(abi_rows) != 1 or (abi_rows[0].get('endpoint_id'),
                                  abi_rows[0].get('role')) != (None, None):
            _error('saved-abi-binding')
        runtime = [row for row in runtime_ports
                   if row.get('name') == export['runtime_name']]
        if len(runtime) != 1 or (runtime[0].get('width'), runtime[0].get('direction')) != (
                1, 'output'):
            _error('saved-runtime-port')
        export['endpoint_id'] = endpoint.endpoint_id
        export['role'] = field.role
        abi_rows[0]['endpoint_id'] = endpoint.endpoint_id
        abi_rows[0]['role'] = field.role
        plan_rows_role = [row for row in plan_rows if row.get('port') == port]
        if len(plan_rows_role) != 1 or (plan_rows_role[0].get('endpoint_id'),
                                        plan_rows_role[0].get('role')) != (None, None):
            _error('saved-plan-binding')
        plan_rows_role[0]['endpoint_id'] = endpoint.endpoint_id
        plan_rows_role[0]['role'] = field.role
    trace = projected['base_protocol_traces']['traces'][0]
    contract = build_manager_domain_contract(
        profile, projected['clock_schedule'], abi, exports,
        protocol_endpoint_id=trace['endpoint_id'],
        source='saved_native_artifact_software_projection')
    sha = hashlib.sha256(raw).hexdigest()
    projected['manager_domain'] = contract
    projected['domain_projection'] = dict(
        schema_version=PROJECTION_SCHEMA,
        provenance='saved_native_artifact_software_projection',
        source_artifact_digest=artifact.get('artifact_digest'),
        source_profile_sha256=artifact['plan'].get('profile_sha256'),
        domain_profile_sha256=sha,
        domain_profile_path=artifact['plan'].get('profile_path', ''),
        note='declared current-profile domain binding applied to frozen saved '
             'native bytes for software replay only; not a native execution, '
             'new artifact identity or protocol-completion claim')
    authenticate_manager_domain(projected)
    return projected


def measured_domain_rows(sample, contract) -> dict:
    """Extract the explicit measured PRE/POST domain rows from physical outputs."""
    roles = contract['roles']
    try:
        return {phase: {role: sample[phase]['physical'][row['runtime_name']]
                        for role, row in roles.items()}
                for phase in ('pre', 'post')}
    except (KeyError, TypeError):
        _error('measured-rows')


def validate_domain_rows(rows) -> dict:
    """Require exactly two explicit measured one-bit PRE/POST rows."""
    if not isinstance(rows, dict) or set(rows) != {'pre', 'post'}:
        _error('rows-shape')
    result = {}
    for phase in ('pre', 'post'):
        row = rows[phase]
        if not isinstance(row, dict) or set(row) != set(ROLES):
            _error('rows-shape')
        result[phase] = {}
        for role in ROLES:
            value = row[role]
            if type(value) is not int or not 0 <= value < 2:
                _error('rows-value')
            result[phase][role] = value
    return result


def software_manager_domain_contract(*, protocol_endpoint_id: str = 'bus') -> dict:
    """Code-owned domain contract for direct observer controls (no artifact)."""
    roles = {
        'manager_ready': dict(width=1, direction='output',
                              physical_port='HREADY', wrapper_name='lh_p_6_0_0',
                              runtime_name='rt_lh_p_6_0_0', source_wire='HREADY',
                              clock_domain='core'),
        'bus_reset_n': dict(width=1, direction='output',
                            physical_port='HRESETn', wrapper_name='lh_p_8_0_0',
                            runtime_name='rt_lh_p_8_0_0', source_wire='HRESETn',
                            clock_domain='core'),
    }
    contract = dict(
        schema_version=SCHEMA, endpoint_id='cpu.manager_domain',
        function='observation', protocol_endpoint_id=protocol_endpoint_id,
        profile_endpoint=dict(endpoint_id='cpu.manager_domain',
                              function='observation', clock='core', reset='sys_rst',
                              fields=[dict(role='bus_reset_n', physical_port='HRESETn',
                                           direction='output', width=1),
                                      dict(role='manager_ready', physical_port='HREADY',
                                           direction='output', width=1)]),
        roles=roles,
        clock=dict(domain='core', signal='clk',
                   source='profile_endpoint_clock_bound_to_protocol_trace'),
        reset=dict(external_command=dict(domain='sys_rst', port='reset_ext',
                                         signal='reset', polarity='active_high',
                                         synchronous=False),
                   bus=dict(role='bus_reset_n', polarity='active_low',
                            measured_phase='pre', synchronizer_latency='not_claimed',
                            source='actual_dut_output_not_external_reset_proxy')),
        sampling=copy.deepcopy(SAMPLING), scope=copy.deepcopy(SCOPE),
        external_ready_role=EXTERNAL_READY_ROLE, source='software_control',
        authority='observation_only')
    return validate_manager_domain_contract(contract)


__all__ = [
    'EXTERNAL_READY_ROLE', 'OBSERVER_VERSION', 'PROJECTION_SCHEMA', 'ROLES',
    'SAMPLING', 'SAMPLING_DOMAIN', 'SCHEMA', 'SCOPE',
    'authenticate_manager_domain', 'build_manager_domain_contract',
    'manager_domain_endpoint', 'measured_domain_rows',
    'project_saved_manager_domain', 'software_manager_domain_contract',
    'validate_domain_rows', 'validate_manager_domain_contract',
]
