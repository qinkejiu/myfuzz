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


def _f5_irq_bound(path, request, compiled, artifacts, owner, physical_port):
    """Check one F5 bound bit against the same compiled physical IRQ edge."""
    from myfuzz.scenario.compiled_paths import _selected_interrupt_shape

    if path.get('flow_id') != 'F5' or path.get('runtime_path_identity') is None:
        return False
    rows = path.get('bound_inputs', [])
    producers = [row for row in rows if row.get('kind') == 'ip_irq']
    targets = [row for row in rows if row.get('kind') == 'cpu_irq_input']
    if len(producers) != 1 or len(targets) != 1:
        return False
    producer, target = producers[0], targets[0]
    cpu, ip = target.get('component'), producer.get('component')
    if (owner.get('component_id') != cpu or owner.get('producer_ref') != producer.get('input_id')
            or type(owner.get('bit_offset')) is not int or owner['bit_offset'] < 0
            or type(owner.get('width')) is not int or owner['width'] != 1):
        return False
    component = next((item for item in request.devices if item.instance_id == ip), None)
    if component is None or request.cpu.instance_id != cpu:
        return False
    endpoint = component.endpoint(producer.get('endpoint_id'))
    cpu_profile = request.cpu.profile.cpu
    if (endpoint is None or endpoint.function != 'interrupt_source' or cpu_profile is None
            or cpu_profile.irq_entry_endpoint != target.get('endpoint_id')):
        return False
    cpu_endpoint = request.cpu.endpoint(target.get('endpoint_id'))
    cpu_fields = ([field for field in cpu_endpoint.fields
                   if field.role == cpu_profile.irq_entry_role]
                  if cpu_endpoint is not None and cpu_endpoint.function == 'interrupt_entry' else [])
    if len(cpu_fields) != 1 or cpu_fields[0].aliases != (physical_port,):
        return False
    deliveries = [row for row in request.wiring.deliveries
        if row.consumer_instance == cpu and row.consumer_endpoint_id == target.get('endpoint_id')]
    selected = [row for row in deliveries if row.producer_instance == ip
                and row.producer_endpoint_id == producer.get('endpoint_id')]
    if len(selected) != 1:
        return False
    delivery = selected[0]
    selected_endpoint = endpoint
    declared_plan = None
    def selected_shape(device, endpoint, route):
        shape = _selected_interrupt_shape(device, endpoint, route)
        if shape is not None:
            return shape
        # A vector export can name several profile IRQs. Only an explicit
        # declared-output group member supplies the selected physical bit.
        if (type(declared_plan) is not dict or route.producer_instance != declared_plan.get('component')
                or route.producer_signal != declared_plan.get('source',{}).get('port')):
            return None
        bit = declared_plan.get('source',{}).get('bit_offset')
        roles = {field.role: field for field in endpoint.fields}
        choices = [item for item in device.profile.interrupts
            if item.endpoint_id == endpoint.endpoint_id and item.bit == bit
            and route.producer_signal in getattr(roles.get(item.role),'aliases',())]
        return choices[0] if len(choices)==1 else None
    if len(deliveries) != 1:
        # Several declared deliveries are admitted only when the same F6
        # contract reconstructs the exact physical IRQ group. This is topology
        # admission, not evidence of delivery, causality or source attribution.
        f6 = [row.get('execution_contract') for row in compiled.get('paths', [])
              if row.get('flow_id') == 'F6' and row.get('status') == 'executable']
        if len(f6) != 1 or type(f6[0]) is not dict:
            return False
        declared_plan=f6[0].get('program_contract',{}).get('declared_irq')
        from myfuzz.integration.shared_f6_assembly import shared_irq_group
        group = shared_irq_group(f6[0], artifacts, base_dir=request.base_dir)
        if (group is None or group.target_component != cpu or group.target_port != physical_port
                or len(group.members) != len(deliveries)):
            return False
        seen = set()
        for route in deliveries:
            source = request.device(route.producer_instance)
            endpoint = source.endpoint(route.producer_endpoint_id) if source is not None else None
            if endpoint is None or endpoint.function != 'interrupt_source':
                return False
            irq_shape = selected_shape(source, endpoint, route)
            if (irq_shape is None or route.trigger != irq_shape.trigger
                    or irq_shape.polarity != cpu_profile.irq_entry_polarity):
                return False
            fields = [field for field in endpoint.fields if field.role == irq_shape.role]
            if len(fields) != 1 or len(fields[0].aliases) != 1:
                return False
            source_port = fields[0].aliases[0]
            source_bit = 0 if irq_shape.bit is None else irq_shape.bit
            if type(source_bit) is not int or source_bit < 0:
                return False
            expected_port = ('irq' if route.producer_instance == f6[0]['dma']['instance_id']
                             and route.producer_signal == f6[0]['irq']['producer_port'] else source_port)
            members = [member for member in group.members if member.source_component == route.producer_instance
                       and member.source_port == expected_port and member.source_bit_offset == source_bit
                       and member.mode == route.trigger]
            if len(members) != 1 or members[0].source_id in seen:
                return False
            seen.add(members[0].source_id)
            source_artifact = artifacts.get(route.producer_instance)
            if source_artifact is None:
                return False
            def actual(rows):
                return [row for row in rows if row.get('physical_port') == source_port
                    and row.get('endpoint_id') == endpoint.endpoint_id and row.get('role') == irq_shape.role
                    and row.get('direction') == 'output' and type(row.get('bit_lo')) is int
                    and type(row.get('bit_hi')) is int and row['bit_lo'] <= source_bit <= row['bit_hi']]
            abi = actual(source_artifact.structural.abi_document.get('ports', []))
            exports = actual(source_artifact.runtime_document.get('physical_exports', []))
            if (len(abi) != 1 or len(exports) != 1 or any(abi[0].get(k) != exports[0].get(k)
                    for k in ('direction','role','endpoint_id','bit_lo','bit_hi','width'))):
                return False
    endpoint = selected_endpoint
    shape = selected_shape(component, endpoint, delivery)
    if (shape is None or shape.trigger not in ('level', 'pulse')
            or delivery.trigger != shape.trigger or shape.polarity != cpu_profile.irq_entry_polarity):
        return False
    fields = [row for row in endpoint.fields if row.role == shape.role]
    if len(fields) != 1 or len(fields[0].aliases) != 1 or type(shape.bit) is not int:
        return False
    if fields[0].bit_range is not None and not fields[0].bit_range[0] <= shape.bit <= fields[0].bit_range[1]:
        return False
    producer_port = fields[0].aliases[0]
    contract = compiled.get('runtime_path_contract')
    if type(contract) is not dict:
        return False
    nodes = contract.get('nodes', [])
    pnodes = [row for row in nodes if row.get('node_id') == 'F5.ip_irq']
    cnodes = [row for row in nodes if row.get('node_id') == 'F5.cpu_irq_entry']
    if len(pnodes) != 1 or len(cnodes) != 1:
        return False
    pnode, cnode = pnodes[0], cnodes[0]
    if (pnode.get('kind') != 'physical' or pnode.get('component') != ip
            or pnode.get('port') != producer_port or pnode.get('bit_offset') != shape.bit
            or type(pnode.get('bit_offset')) is not int or pnode.get('width') != 1
            or cnode.get('kind') != 'physical' or cnode.get('component') != cpu
            or cnode.get('port') != physical_port or cnode.get('width') != 1
            or type(cnode.get('bit_offset')) is not int):
        return False
    edge_refs = [row for row in path['runtime_path_identity'].get('edges', [])
        if row.get('prerequisite') == 'F5.ip_irq' and row.get('target') == 'F5.cpu_irq_entry']
    if len(edge_refs) != 1:
        return False
    edge = edge_refs[0]
    if len([row for row in contract.get('edges', []) if row.get('relation') == 'direct_binding'
            and row.get('rule_index') == edge.get('rule_index')
            and row.get('prerequisite_index') == edge.get('prerequisite_index')]) != 1:
        return False

    def physical(artifact, port, endpoint_id, role, direction, bit):
        if type(bit) is not int or bit < 0:
            return False
        def candidates(rows):
            return [row for row in rows if type(row) is dict and row.get('physical_port') == port
                and row.get('endpoint_id') == endpoint_id and row.get('role') == role
                and row.get('direction') == direction and type(row.get('bit_lo')) is int
                and type(row.get('bit_hi')) is int and type(row.get('width')) is int
                and row['width'] == row['bit_hi'] - row['bit_lo'] + 1
                and row['bit_lo'] <= bit <= row['bit_hi']]
        abi = candidates(artifact.structural.abi_document.get('ports', []))
        exports = candidates(artifact.runtime_document.get('physical_exports', []))
        return (len(abi) == len(exports) == 1
            and all(abi[0].get(key) == exports[0].get(key)
                for key in ('bit_lo', 'bit_hi', 'width', 'direction', 'role', 'endpoint_id'))
            and type(exports[0].get('runtime_name')) is str and bool(exports[0]['runtime_name']))

    cpu_artifact, ip_artifact = artifacts[cpu], artifacts[ip]
    # Ownership offsets index the exposed ABI spans, while graph offsets use
    # absolute physical bit numbers (e.g. a one-bit slice of a vector IRQ).
    spans = sorted((row['bit_lo'], row['bit_hi'])
        for row in cpu_artifact.structural.abi_document.get('ports', [])
        if row.get('physical_port') == physical_port and row.get('direction') == 'input'
        and row.get('endpoint_id') == target['endpoint_id'] and row.get('role') == cpu_profile.irq_entry_role
        and type(row.get('bit_lo')) is int and type(row.get('bit_hi')) is int)
    position = owner['bit_offset']; selected_bit = None; previous_high = -1
    for lo, hi in spans:
        if lo < 0 or hi < lo or lo <= previous_high:
            return False
        size = hi - lo + 1
        if selected_bit is None and position < size:
            selected_bit = lo + position
        elif selected_bit is None:
            position -= size
        previous_high = hi
    return (selected_bit == cnode['bit_offset']
        and physical(cpu_artifact, physical_port, target['endpoint_id'],
                     cpu_profile.irq_entry_role, 'input', cnode['bit_offset'])
        and physical(ip_artifact, producer_port, producer['endpoint_id'],
                     shape.role, 'output', shape.bit))


def admit_compiled_artifacts(*, artifacts, request, compiled, ownership,
                             physical_port_map, flow_ids=None) -> dict:
    """Return structured compatibility/refusal for artifacts and compiled inputs.

    physical_port_map maps (instance, ownership-port) to the explicit DUT port.
    A statically declared F5 IRQ bound bit may be checked against both loaded
    artifacts and the unique compiled delivery; this does not admit runtime
    delivery enforcement. Other bound physical producers remain refused. Image/transaction
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
    if flow_ids is not None:
        if (type(flow_ids) not in (tuple, list) or not flow_ids
                or any(type(flow) is not str for flow in flow_ids)
                or len(set(flow_ids)) != len(flow_ids)
                or any(flow not in ('F1','F2','F3','F4','F5','F6') for flow in flow_ids)
                or any(not any(path.get('flow_id') == flow and path.get('status') == 'executable'
                    for path in compiled['paths']) for flow in flow_ids)):
            refuse('compiled-flow-selection-invalid', '/flow_ids')
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
        if path['status'] != 'executable' or (flow_ids is not None and path['flow_id'] not in flow_ids):
            continue
        for source in path['sources']:
            if source['kind'] == 'external_pin':
                identity = (source['component'], source['port'], source['bit_offset'], source['width'])
                sources[identity] = (source, path['direction'], index)
    used_sources = set()
    f5_paths = [path for path in compiled['paths'] if path['flow_id']=='F5'
        and path['status']=='executable' and (flow_ids is None or 'F5' in flow_ids)]
    used_f5_bound = False
    for index, owner in enumerate(ownership.document()['owners']):
        pointer = '/ownership/owners/' + str(index)
        key = (owner['component_id'], owner['port'])
        physical_port = physical_port_map[key]
        if owner['kind'] == 'bound':
            try:
                accepted = sum(_f5_irq_bound(path, request, compiled, artifacts, owner, physical_port)
                    for path in f5_paths) == 1
            except (KeyError, TypeError, ValueError, AttributeError, IndexError):
                accepted = False
            if accepted:
                used_f5_bound = True
            else:
                refuse('ownership-bound-producer-not-admitted', pointer,
                       'only the uniquely compiled F5 IRQ physical delivery is admitted')
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
    if flow_ids is not None and 'F5' in flow_ids and f5_paths and not used_f5_bound:
        refuse('compiled-irq-bound-unowned', '/paths/F5/bound_inputs')
    if not result['refusals']:
        result['status'] = 'compatible'
    return result
