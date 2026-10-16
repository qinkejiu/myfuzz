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
    if kind == 'obi_cpu':
        cpu = plan.profile.cpu
        rows = [row for row in projected if row['endpoint_id'] == cpu.irq_entry_endpoint
                and row['role'] == cpu.irq_entry_role and row['direction'] == 'input'
                and row['bit_lo'] == 0 and row['width'] == 1]
    elif kind == 'apb_gpio':
        # The admitted STEP_GPIO executor exports this exact native pulse as
        # its scenario `irq` output. A profile observe action authorizes only
        # physical sampling; no interrupt-source capability is inferred.
        actions = [a for a in plan.profile.port_actions
                   if a.port == 'interrupt' and a.action == 'observe'
                   and not a.member_path and not a.bits]
        rows = [row for row in projected if row['physical_port'] == 'interrupt'
                and row['direction'] == 'output' and row['disposition'] == 'observe'
                and row['bit_lo'] == 0 and row['width'] == 1]
        if len(actions) != 1 or 'local_observed_ports' in clocks:
            raise ValueError('native-physical-observation-alias-unsupported')
        if len(rows) == 1 and rows[0]['endpoint_id'] is None and rows[0]['role'] is None:
            rows[0].update(endpoint_id='local_observed_ports', role='interrupt')
            clocks['local_observed_ports'] = primary_clock
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
    if recorded is None and not requested:
        return False
    if (not requested or document.get('kind') not in ('obi_cpu', 'apb_gpio')
            or document.get('base_event_schema_version') != 'ip_base_event.v1'
            or document.get('raw_observation_schema_version') != 'ip_raw_observation.v1'
            or not isinstance(document.get('physical_exports'), list)
            or not isinstance(document.get('native_physical_observation_mapping'), dict)):
        raise ValueError('native-physical-observation-contract-mismatch')
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
