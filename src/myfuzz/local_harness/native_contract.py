"""Typed runtime admission for completion memory; no component-name inference."""
import hashlib
import json
from pathlib import Path

from .template_contracts import select_template_contract


def native_completion_contract(endpoint, capabilities):
    required = dict(completion_semantics='completion', address_units='byte',
                    address_width=32, data_width=32, byte_enable=True,
                    max_outstanding=1, error_response=False)
    for name, expected in required.items():
        if type(capabilities.get(name)) is not type(expected) or capabilities[name] != expected:
            raise ValueError('runtime-native-typed-fact-required:' + name)
    return select_template_contract(endpoint, capabilities, template_id='cpu.native-memory',
        template_version='1', variant_id='completion-no-error')


def native_completion_observation_binding(plan, structural_abi, exports, primary_clock):
    """Project only admitted CPU-side wires and the declared physical marker.

    This is a generation/admission description, not a completion observation or
    a source/retirement authority. Adapter backend signals cannot stand in for
    any of the six native endpoint roles.
    """
    from .runtime_renderer import _NATIVE, _shape
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if (len(endpoints) != 1 or endpoints[0].protocol != ('ready-valid-memory', '1')
            or endpoints[0].function not in ('memory_master', 'processor_memory_master')):
        raise ValueError('native-completion-observation-endpoint')
    endpoint = endpoints[0]
    native_completion_contract(endpoint, plan.profile.capabilities)
    for row in structural_abi['ports']:
        if any(type(row.get(name)) is not int for name in ('width', 'bit_lo', 'bit_hi')):
            raise ValueError('native-completion-observation-abi-integer')
    if any(type(field.width) is not int for field in endpoint.fields):
        raise ValueError('native-completion-observation-role-integer')
    wires = _shape(endpoint, _NATIVE, structural_abi['ports'])
    clocks = [e.clock or primary_clock for e in plan.profile.endpoints
              if e.endpoint_id == endpoint.endpoint_id]
    if len(clocks) != 1 or type(clocks[0]) is not str or not clocks[0]:
        raise ValueError('native-completion-observation-clock')
    # These are the unchanged non-adapted ABI exports. No bus input becomes
    # fuzzable, and no synthetic physical alias is installed.
    expected_exports = [{**row, 'runtime_name': 'rt_' + row['wrapper_name'],
        'encoding': 'fixed_width_hex' if row['width'] > 64 else 'integer',
        'hex_digits': (row['width'] + 3) // 4}
        for row in structural_abi['ports'] if row['endpoint_id'] != endpoint.endpoint_id]
    canonical = lambda value: json.dumps(value, sort_keys=True, allow_nan=False)
    if canonical(exports) != canonical(expected_exports):
        raise ValueError('native-completion-observation-physical-exports')
    marker = plan.profile.capabilities.get('instruction_identity_port')
    rows = [row for row in exports if row['physical_port'] == marker
            and row['direction'] == 'output' and row['disposition'] == 'observe'
            and type(row['width']) is int and row['width'] == 1
            and type(row['bit_lo']) is int and row['bit_lo'] == 0
            and type(row['bit_hi']) is int and row['bit_hi'] == 0]
    if type(marker) is not str or not marker or len(rows) != 1:
        raise ValueError('native-completion-observation-instruction-marker')
    ports = [dict(name='cpu_native_trace_' + role, direction='output', width=width,
                  role=role, endpoint_id=endpoint.endpoint_id, source_wire=wires[role])
             for role, (_, width) in _NATIVE.items()]
    declared_wait = plan.profile.capabilities.get('max_wait_cycles', plan.request.max_wait_cycles)
    if type(declared_wait) is not int or declared_wait < 1:
        raise ValueError('native-completion-observation-wait')
    effective_wait = min(declared_wait, plan.request.max_wait_cycles)
    if type(effective_wait) is not int or not 1 <= effective_wait <= 1024:
        raise ValueError('native-completion-observation-wait')
    trace = dict(schema_version='ip_protocol_trace.v1', protocol='ready-valid-memory',
        endpoint_id=endpoint.endpoint_id, clock_domain=clocks[0],
        signals={row['role']: row['name'] for row in ports},
        signal_widths={role: width for role, (_, width) in _NATIVE.items()},
        sample_group='protocol_taps', boundary='cpu_physical_abi',
        max_outstanding=1, max_wait_cycles=effective_wait)
    contract = dict(schema_version='native_completion_observation.v1',
        endpoint_id=endpoint.endpoint_id, clock_domain=clocks[0], sampling='pre_post',
        sample_group='protocol_taps', boundary='cpu_physical_abi',
        completion=dict(phase='pre', valid_role='valid', ready_role='ready',
                        read_zero_strobe=True),
        instruction_marker=dict(sample_group='physical', physical_port=marker,
                                signal=rows[0]['runtime_name'], width=1),
        grants_source_authority=False, grants_retirement=False,
        generic_protocol_checker_supported=False)
    return dict(ports=ports, trace=trace, contract=contract)


def verify_native_completion_observation(artifact):
    """Strict passive projection; never infer real completion from metadata."""
    from .clock_schedule import build_local_clock_schedule
    from .native_physical_observation import native_physical_observation_requested
    from .renderer import render_local_harness
    from .runtime_renderer import _render_admitted_runtime
    document, plan = artifact.runtime_document, artifact.plan
    try:
        if (document.get('kind') != 'native_memory_cpu'
                or not native_physical_observation_requested(plan.request)
                or document.get('base_event_schema_version') != 'ip_base_event.v1'
                or document.get('raw_observation_schema_version') != 'ip_raw_observation.v1'
                or 'base_protocol_trace' in document):
            raise ValueError('kind-or-selection')
        structure = render_local_harness(plan)
        if structure != artifact.structural:
            raise ValueError('structural-projection')
        schedule = build_local_clock_schedule(plan.profile.clocks, plan.profile.resets,
            reset_assert_ticks=plan.request.reset_assert_ticks,
            reset_release_ticks=plan.request.reset_release_ticks)
        binding = native_completion_observation_binding(plan, structure.abi_document,
            document['physical_exports'], schedule['primary_clock_domain'])
        expected_trace_set = dict(schema_version='ip_protocol_trace_set.v1',
            sampling='pre_post', sample_group='protocol_taps', traces=[binding['trace']])
        expected = {
            'structural_abi': structure.abi_document,
            'clock_schedule': schedule,
            'protocol_tap_ports': binding['ports'],
            'base_protocol_traces': expected_trace_set,
            'native_completion_observation': binding['contract'],
            'instruction_identity_observation': binding['contract']['instruction_marker']['signal'],
        }
        equal = lambda left, right: json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)
        if any(not equal(document.get(key), value) for key, value in expected.items()):
            raise ValueError('observation-metadata-projection')
        names = {row['name'] for row in binding['ports']}
        if names & {row['name'] for row in document['backend_ports']}:
            raise ValueError('passive-tap-in-backend')
        # Re-render the entire source-owned runtime rather than accepting one
        # matching assign beside an extra driver or a replacement backend net.
        projection = _render_admitted_runtime(plan, structure,
            artifact.source_verification, Path(__file__).resolve().parents[3], native_raw=True)
        if (projection.runtime_sv != artifact.runtime_sv
                or document.get('runtime_sv_sha256') != hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()):
            raise ValueError('runtime-wiring-projection')
        for key in ('runtime_ports', 'backend_ports', 'physical_exports', 'adapted_endpoint_ids',
                    'selected_template', 'effective_max_wait_cycles',
                    'native_physical_observation_mapping', 'native_physical_observation_contract'):
            if not equal(document.get(key), projection.runtime_document.get(key)):
                raise ValueError('runtime-metadata-projection:' + key)
    except (AttributeError, KeyError, TypeError, StopIteration, ValueError) as error:
        raise ValueError('native-completion-observation-contract-mismatch') from error
    return True
