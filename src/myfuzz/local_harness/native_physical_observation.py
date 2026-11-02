"""Closed native raw observation policy; no protocol or functional inference."""
import hashlib
import json
from copy import deepcopy

from .request import LocalHarnessRequestV2
from .tuning import load_local_harness_tuning


def native_physical_observation_requested(request):
    if not isinstance(request, LocalHarnessRequestV2):
        return False
    tuning = request.tuning
    if load_local_harness_tuning(tuning.document()) != tuning:
        raise ValueError('native-physical-observation-noncanonical-tuning')
    rows = [row for row in tuning.records if row.kind == 'raw_tick_stream']
    if not rows:
        return False
    if len(rows) != 1 or any(row.kind != 'raw_tick_stream' for row in tuning.records):
        raise ValueError('native-physical-observation-unsupported-tuning')
    return True


def native_physical_observation_mapping(plan, kind, exports, primary_clock):
    """Describe aliases used by the admitted native executor, never by names alone."""
    projected = deepcopy(exports)
    clocks = {e.endpoint_id: e.clock or primary_clock for e in plan.profile.endpoints}
    if kind == 'native_memory_cpu':
        # Native memory has no implied IRQ input or aliases. The independent
        # completion contract binds its own declared instruction sideband.
        return dict(schema_version='native_physical_observation_mapping.v1',
                    aliases=[], physical_exports=projected, endpoint_clock_domains=clocks)
    if kind == 'obi_cpu':
        cpu = plan.profile.cpu
        # A declared CPU IRQ endpoint may be a real one-bit slice of a wider
        # physical vector, so its host-facing port is the exported one-bit
        # value at whatever bit position the profile declares; only the width
        # is fixed.  The alias names the runtime port, never a DUT bit offset.
        rows = [row for row in projected if row['endpoint_id'] == cpu.irq_entry_endpoint
                and row['role'] == cpu.irq_entry_role and row['direction'] == 'input'
                and row['width'] == 1]
    elif kind == 'apb_gpio':
        # The admitted STEP_GPIO executor exports this exact native pulse as
        # its scenario `irq` output. A profile observe action authorizes only
        # physical sampling; no interrupt-source capability is inferred.
        actions = [a for a in plan.profile.port_actions
                   if a.port == 'interrupt' and a.action == 'observe'
                   and not a.member_path and not a.bits]
        rows = [row for row in projected if row['physical_port'] == 'interrupt'
                and row['direction'] == 'output' and row['bit_lo'] == 0
                and row['width'] == 1]
        if len(rows) == 1 and rows[0]['disposition'] == 'observe':
            if (len(actions) != 1 or 'local_observed_ports' in clocks
                    or rows[0]['endpoint_id'] is not None or rows[0]['role'] is not None):
                raise ValueError('native-physical-observation-alias-unsupported')
            rows[0].update(endpoint_id='local_observed_ports', role='interrupt')
            clocks['local_observed_ports'] = primary_clock
        elif (len(rows) != 1 or actions or rows[0]['disposition'] != 'functional'
              or rows[0]['endpoint_id'] != 'gpio.interrupts' or rows[0]['role'] != 'irq'):
            raise ValueError('native-physical-observation-alias-unsupported')
    else:
        raise ValueError('native-physical-observation-runtime-unsupported')
    if len(rows) != 1 or rows[0]['endpoint_id'] not in clocks:
        raise ValueError('native-physical-observation-alias-unsupported')
    return dict(schema_version='native_physical_observation_mapping.v1',
                aliases=[dict(port='irq', physical_port=rows[0]['physical_port'])],
                physical_exports=projected, endpoint_clock_domains=clocks)


def native_physical_observation_contract(exports, mapping=None):
    raw = json.dumps(exports, sort_keys=True, separators=(',', ':')).encode()
    contract = dict(schema_version='native_physical_observation.v1', sampling='pre_post',
                    exports_sha256=hashlib.sha256(raw).hexdigest())
    if mapping is not None:
        contract['mapping_sha256'] = hashlib.sha256(json.dumps(
            mapping, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return contract


def verify_native_physical_observation(artifact):
    document = artifact.runtime_document
    recorded = document.get('native_physical_observation_contract')
    requested = native_physical_observation_requested(artifact.plan.request)
    if 'native_completion_observation' in document and document.get('kind') != 'native_memory_cpu':
        raise ValueError('native-completion-observation-kind-mismatch')
    if recorded is None and not requested:
        if document.get('kind') == 'native_memory_cpu' and any(key in document for key in (
                'native_completion_observation', 'base_protocol_traces', 'protocol_tap_ports')):
            raise ValueError('native-completion-observation-not-requested')
        return False
    if (not requested or document.get('kind') not in ('obi_cpu', 'apb_gpio', 'native_memory_cpu')
            or document.get('base_event_schema_version') != 'ip_base_event.v1'
            or document.get('raw_observation_schema_version') != 'ip_raw_observation.v1'
            or not isinstance(document.get('physical_exports'), list)
            or not isinstance(document.get('native_physical_observation_mapping'), dict)):
        raise ValueError('native-physical-observation-contract-mismatch')
    if document.get('kind') == 'native_memory_cpu':
        from .native_contract import verify_native_completion_observation
        verify_native_completion_observation(artifact)
    elif 'base_protocol_traces' in document or 'protocol_tap_ports' in document:
        verify_cpu_obi_protocol_traces(artifact)
    mapping = native_physical_observation_mapping(artifact.plan, document['kind'],
        document['physical_exports'], document['clock_schedule']['primary_clock_domain'])
    if (mapping != document['native_physical_observation_mapping']
            or recorded != native_physical_observation_contract(document['physical_exports'], mapping)):
        raise ValueError('native-physical-observation-contract-mismatch')
    if document['kind'] == 'apb_gpio':
        _verify_native_apb_trace(artifact)
    elif 'base_protocol_trace' in document:
        raise ValueError('native-physical-observation-contract-mismatch')
    return True


def _verify_native_apb_trace(artifact):
    """Authenticate the closed passive trace against admitted ABI and wiring."""
    from .runtime_renderer import _APB, _shape
    from .clock_schedule import build_local_clock_schedule
    document, plan = artifact.runtime_document, artifact.plan
    try:
        endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
        if len(endpoints) != 1 or endpoints[0].protocol != ('apb', '3'):
            raise ValueError('endpoint')
        endpoint = endpoints[0]
        if document['structural_abi'] != artifact.structural.abi_document:
            raise ValueError('abi')
        wires = _shape(endpoint, _APB, artifact.structural.abi_document['ports'])
        schedule = build_local_clock_schedule(plan.profile.clocks, plan.profile.resets,
            reset_assert_ticks=plan.request.reset_assert_ticks,
            reset_release_ticks=plan.request.reset_release_ticks)
        if document['clock_schedule'] != schedule:
            raise ValueError('clock')
        clock = next(e.clock for e in plan.profile.endpoints
                     if e.endpoint_id == endpoint.endpoint_id) or schedule['primary_clock_domain']
        declared_wait = plan.profile.capabilities['max_wait_cycles']
        if type(declared_wait) is not int or declared_wait < 1:
            raise ValueError('wait')
        wait = min(declared_wait, plan.request.max_wait_cycles)
        expected = dict(schema_version='ip_protocol_trace.v1', protocol='apb3',
            endpoint_id=endpoint.endpoint_id, clock_domain=clock,
            signals={role: 'trace_' + role for role in _APB},
            signal_widths={role: width for role, (_, width) in _APB.items()},
            max_wait_cycles=wait)
        if (json.dumps(document.get('base_protocol_trace'), sort_keys=True)
                != json.dumps(expected, sort_keys=True)
                or type(document['effective_max_wait_cycles']) is not int
                or document['effective_max_wait_cycles'] != wait):
            raise ValueError('trace')
        trace_rows = [dict(name='trace_' + role, direction='output', width=width,
                           role=role, channel='ip_protocol_trace')
                      for role, (_, width) in _APB.items()]
        if json.dumps([r for r in document['backend_ports'] if r.get('channel') == 'ip_protocol_trace'], sort_keys=True) != json.dumps(trace_rows, sort_keys=True):
            raise ValueError('backend')
        for row in trace_rows:
            name, width, role = row['name'], row['width'], row['role']
            if ([r for r in document['backend_ports'] if r['name'] == name] != [row]
                    or [r for r in document['runtime_ports'] if r['name'] == name]
                    != [dict(name=name, direction='output', width=width)]
                    or artifact.runtime_sv.count(f'assign {name} = {wires[role]};') != 1):
                raise ValueError('wiring')
    except (AttributeError, KeyError, TypeError, StopIteration, ValueError) as exc:
        raise ValueError('native-physical-observation-contract-mismatch') from exc


def verify_apb_register_trace(artifact):
    """Verify generated APB wire projection, without granting live authority.

    Generic register sessions have no synthetic IRQ alias or GPIO storage
    contract. Their already-declared passive bus taps are checked directly
    against the admitted endpoint ABI. Execution and storage are separate facts.
    """
    document = artifact.runtime_document
    kind = document.get('kind')
    if kind == 'apb_gpio':
        return verify_native_physical_observation(artifact)
    if kind != 'apb3_register_observe':
        return False
    from .apb3_register_template import register_observe_policy
    from .runtime_renderer import _APB, _render_admitted_runtime
    from .renderer import render_local_harness
    from pathlib import Path
    import re
    try:
        if (document.get('base_event_schema_version') != 'ip_base_event.v1'
                or document.get('raw_observation_schema_version') != 'ip_raw_observation.v1'
                or document.get('functional_scope') != 'apb3_register_only_pin_observe_no_peer'
                or document.get('runtime_sv_sha256') != hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()):
            raise ValueError('schema')
        register_observe_policy(artifact.plan, artifact.structural.abi_document['ports'])
        expected_structure = render_local_harness(artifact.plan)
        if expected_structure != artifact.structural:
            raise ValueError('structural-projection')
        expected = _render_admitted_runtime(artifact.plan, expected_structure,
            artifact.source_verification, Path(__file__).resolve().parents[3], native_raw=False)
        if expected.runtime_sv != artifact.runtime_sv:
            raise ValueError('runtime-projection')
        for key in ('storage_startup_selection', 'storage_observation', 'storage_probe_ports', 'base_protocol_trace', 'backend_ports', 'runtime_ports',
                    'structural_abi', 'clock_schedule', 'physical_exports',
                    'fixed_physical_inputs', 'dynamic_physical_inputs',
                    'bound_physical_inputs', 'functional_scope',
                    'effective_max_wait_cycles', 'boot_contract', 'plan'):
            if json.dumps(document.get(key), sort_keys=True, allow_nan=False) != json.dumps(
                    expected.runtime_document.get(key), sort_keys=True, allow_nan=False):
                raise ValueError('metadata-projection:' + key)
        if document.get('storage_startup_selection') is not None and document.get('driver_status')=='generated':
            from .apb_storage_startup import contract_from_document
            contract_from_document(document)
        elif ('storage_startup_capture' in document or document.get('driver_schema_version')=='local_driver_generation.apb_storage_startup.v2'):
            raise ValueError('storage-startup-driver-projection')
        _verify_native_apb_trace(artifact)
        # JSON equality preserves bool/int distinctions and catches duplicate
        # runtime declarations. The existing trace validator checks backend rows.
        for role, (_, width) in _APB.items():
            name = 'trace_' + role
            actual = [r for r in document['runtime_ports'] if r['name'] == name]
            expected = [dict(name=name, direction='output', width=width)]
            if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise ValueError('runtime-port')
            if len(re.findall(r'\bassign\s+' + re.escape(name) + r'\s*=', artifact.runtime_sv)) != 1:
                raise ValueError('multiple-trace-drivers')
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError('generic-APB-register-trace-mismatch') from exc
    return True


def physical_observation_parameters(artifact):
    """Return the exact projector configuration shared by Runner and preflight."""
    document, profile = artifact.runtime_document, artifact.plan.profile
    if verify_native_physical_observation(artifact):
        mapping = document['native_physical_observation_mapping']
        clocks, exports = mapping['endpoint_clock_domains'], mapping['physical_exports']
    else:
        clocks = {e.endpoint_id: e.clock or document['clock_schedule']['primary_clock_domain']
                  for e in profile.endpoints}
        exports = document.get('physical_exports', ())
    return dict(endpoint_clock_domains=clocks, physical_exports=exports,
                bound_physical_inputs=document.get('bound_physical_inputs', ()))


def verify_cpu_obi_protocol_traces(artifact):
    """Authenticate passive CPU wires independently of adapter beat signals."""
    from .runtime_renderer import _obi_shape, _OBI_READ, _OBI_READ_BASE
    document, plan = artifact.runtime_document, artifact.plan
    if document.get('kind') != 'obi_cpu':
        raise ValueError('cpu-obi-protocol-trace-kind')
    expected_traces, expected_ports = [], []
    for endpoint in sorted((e for e in plan.binding.endpoints if e.protocol is not None),
                           key=lambda e:e.function):
        instruction = endpoint.function == 'instruction_memory_master'
        prefix = 'i' if instruction else 'd'
        error = plan.profile.capabilities.get('error_response')
        wires = _obi_shape(endpoint, artifact.structural.abi_document['ports'],
                           read_only=instruction, error_response=error)
        shape = dict(_OBI_READ if error else _OBI_READ_BASE)
        if not instruction:
            shape.update(we=('output',1),wdata=('output',32),be=('output',4))
        signals = {}
        for role, (_, width) in shape.items():
            name = 'trace_obi_'+prefix+'_'+role
            signals[role] = name
            expected_ports.append(dict(name=name,direction='output',width=width,
                role=role,endpoint_id=endpoint.endpoint_id,source_wire=wires[role]))
            if f'assign {name} = {wires[role]};' not in artifact.runtime_sv:
                raise ValueError('cpu-obi-protocol-trace-wiring')
        expected_traces.append(dict(schema_version='ip_protocol_trace.v1',protocol='obi',
            endpoint_id=endpoint.endpoint_id,
            clock_domain=next(e.clock for e in plan.profile.endpoints
                if e.endpoint_id == endpoint.endpoint_id) or document['clock_schedule']['primary_clock_domain'],
            max_wait_cycles=plan.request.max_wait_cycles,max_outstanding=1,
            signals=signals,signal_widths={r:w for r,(_,w) in shape.items()},
            sample_group='protocol_taps',boundary='cpu_physical_abi'))
    expected = dict(schema_version='ip_protocol_trace_set.v1',sampling='pre_post',
                    sample_group='protocol_taps',traces=expected_traces)

    # Python considers bool equal to its integer values (True == 1). Reject
    # malformed JSON-shaped inventories before comparing them with generated
    # expectations, so an artifact cannot substitute booleans for widths.
    tap_ports = document.get('protocol_tap_ports')
    port_fields = {'name', 'direction', 'width', 'role', 'endpoint_id', 'source_wire'}
    tap_ports_well_typed = (type(tap_ports) is list and all(
        type(row) is dict and set(row) == port_fields
        and all(type(row.get(name)) is str for name in
            ('name', 'direction', 'role', 'endpoint_id', 'source_wire'))
        and type(row.get('width')) is int
        for row in tap_ports))

    traces_doc = document.get('base_protocol_traces')
    trace_set_fields = {'schema_version', 'sampling', 'sample_group', 'traces'}
    trace_fields = {'schema_version', 'protocol', 'endpoint_id', 'clock_domain',
        'max_wait_cycles', 'max_outstanding', 'signals', 'signal_widths',
        'sample_group', 'boundary'}
    traces_well_typed = (type(traces_doc) is dict
        and set(traces_doc) == trace_set_fields
        and all(type(traces_doc.get(name)) is str for name in
            ('schema_version', 'sampling', 'sample_group'))
        and type(traces_doc.get('traces')) is list
        and all(type(row) is dict and set(row) == trace_fields
            and all(type(row.get(name)) is str for name in
                ('schema_version', 'protocol', 'endpoint_id', 'clock_domain',
                 'sample_group', 'boundary'))
            and all(type(row.get(name)) is int for name in
                ('max_wait_cycles', 'max_outstanding'))
            and type(row.get('signals')) is dict
            and all(type(role) is str and type(signal) is str
                for role, signal in row.get('signals', {}).items())
            and type(row.get('signal_widths')) is dict
            and all(type(role) is str and type(width) is int
                for role, width in row.get('signal_widths', {}).items())
            for row in traces_doc.get('traces', ())))

    backend_ports = document.get('backend_ports')
    runtime_ports = document.get('runtime_ports')
    simple_ports_well_typed = (
        type(backend_ports) is list and type(runtime_ports) is list
        and all(type(row) is dict and type(row.get('name')) is str
            and type(row.get('direction')) is str and type(row.get('width')) is int
            for row in backend_ports)
        and all(type(row) is dict and set(row) == {'name', 'direction', 'width'}
            and type(row.get('name')) is str and type(row.get('direction')) is str
            and type(row.get('width')) is int for row in runtime_ports))

    if (len(expected_traces) != 2 or not tap_ports_well_typed
            or not traces_well_typed or not simple_ports_well_typed
            or traces_doc != expected or tap_ports != expected_ports
            or {p['name'] for p in expected_ports} & {p['name'] for p in backend_ports}
            or any(dict(name=p['name'],direction='output',width=p['width'])
                   not in runtime_ports for p in expected_ports)):
        raise ValueError('cpu-obi-protocol-trace-contract-mismatch')
    return True
