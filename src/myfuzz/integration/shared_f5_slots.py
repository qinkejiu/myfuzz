"""Typed pin source and fixed NOP support for the existing shared slot session.

The slot/fetch registry must explicitly bind this fixed support; these pure
byte declarations grant neither F6 enrollment nor execution permission.
"""
from hashlib import sha256


def declare_shared_pin(compiled_inputs,layout,admission,*,raw,slot_index):
    if type(raw) is not bytes or len(raw)!=8 or type(slot_index) is not int or slot_index<0:
        raise ValueError('shared-F5-raw8-slot-required')
    p=admission['execution_contract']['program_contract']
    if ('F5' not in layout['enabled_flows'] or 'gpio_irq' not in p or slot_index>=p['slot_count']
            or p['online_prefix_bytes']!=128 or p['slot_bytes']!=256):
        raise ValueError('shared-F5-declared-capability-required')
    paths=[r for r in compiled_inputs['compiled']['paths'] if r['flow_id']=='F5' and r['status']=='executable']
    if len(paths)!=1:raise ValueError('shared-F5-real-path-required')
    pins=[s for s in paths[0]['sources'] if s['kind']=='external_pin' and s['origin']=='fuzzable' and s['width']==1]
    if len(pins)!=1:raise ValueError('shared-F5-single-physical-source-required')
    pin=pins[0];d=p['gpio_irq']
    if (pin['component'],pin['bit_offset'])!=(d['component'],d['pin']):
        raise ValueError('shared-F5-IRQ-companion-source-mismatch')
    selected=admission['shared_flow_paths']['F5'];support=admission['shared_flow_paths']['F1']
    address=p['slot_base']+p['slot_bytes']*slot_index
    if (support['cpu_component']!=admission['execution_contract']['cpu']['instance_id']
            or not support['base']<=address<address+128<=support['base']+support['size']):
        raise ValueError('shared-F5-fixed-support-image-range')
    code=bytes.fromhex('13000000')*32
    return dict(schema_version='shared_F5_pin_slot_declaration.v1',flow_id='F5',raw_hex=raw.hex(),value=raw[3]&1,
        source_id=selected['source_id'],path_id=selected['path_id'],direction='IP_TO_CPU',
        component=pin['component'],port=pin['port'],bit_offset=pin['bit_offset'],width=1,
        instruction_address=address,code_hex=code.hex(),code_sha256=sha256(code).hexdigest(),
        support_path_id=support['path_id'],support_source_id=support['source_id'],support_memory_id=support['memory_id'],
        scope='typed_F5_pin_with_fixed_support_in_shared_slot')


def extend_shared_pin_path(graph,contract,compiled,*,irq_group):
    """Copy the real F5 D3 path, replacing its IRQ hop by explicit OR membership."""
    from dataclasses import replace
    import json
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
    from myfuzz.scenario.dependency import DependencyGraph,DependencyPath,DependencyEdge
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    custom=type(irq_group) is dict and irq_group.get('schema_version')=='shared_custom_gpio_irq_route.v1'
    if type(irq_group) is dict and not custom:irq_group=IrqDeliveryGroup.from_document(irq_group)
    if not custom and type(irq_group) is not IrqDeliveryGroup:raise ValueError('shared-F5-explicit-IRQ-group-required')
    matches=[p for p in compiled['paths'] if p['flow_id']=='F5' and p['status']=='executable']
    if len(matches)!=1:raise ValueError('shared-F5-real-path-required')
    row=matches[0];identity=row['runtime_path_identity']
    source_graph=DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    source_contract=RuntimePathContract.from_document(compiled['runtime_path_contract'])
    selected=tuple(DependencyEdge(**e) for e in identity['edges'])
    sources=dict(graph.sources);rules=list(graph.ordered_rules);nodes={n.node_id:n for n in contract.nodes};edges=list(contract.edges)
    indexes={old:len(rules)+i for i,old in enumerate(dict.fromkeys(e.rule_index for e in selected))}
    for old,new in indexes.items():rules.append(source_graph.ordered_rules[old])
    needed=set(identity['source_ids'])|{e.target for e in selected}|{e.prerequisite for e in selected}
    for source in identity['source_ids']:
        if source in sources and sources[source]!=source_graph.sources[source]:raise ValueError('shared-F5-source-collision')
        sources[source]=source_graph.sources[source]
    selected_nodes={n.node_id:n for n in source_contract.nodes if n.node_id in needed}
    for name,node in selected_nodes.items():
        if name in nodes and nodes[name]!=node:raise ValueError('shared-F5-node-collision')
        nodes[name]=node
    group_hops=0
    for edge in source_contract.edges:
        if edge.rule_index not in indexes:continue
        updated=replace(edge,rule_index=indexes[edge.rule_index])
        if edge.relation=='direct_binding':
            route=next(e for e in selected if (e.rule_index,e.prerequisite_index)==(edge.rule_index,edge.prerequisite_index))
            origin,target=selected_nodes[route.prerequisite],selected_nodes[route.target]
            if custom:
                if ((origin.component,origin.port,origin.bit_offset,target.component,target.port,target.bit_offset)
                    != (irq_group['source_component'],irq_group['source_port'],irq_group['source_bit_offset'],
                        irq_group['target_component'],irq_group['target_port'],irq_group['target_bit_offset'])):
                    raise ValueError('shared-F5-custom-IRQ-endpoint-mismatch')
                group_hops+=1
                edges.append(updated)
                continue
            # Contract nodes carry DUT coordinates; the group carries the
            # port-local host bit. Map one to the other with the verified
            # export base the group records, never by assuming bit zero.
            host_target_bit=target.bit_offset-irq_group.target_input_bit_lo
            # The producer end is already port-local here: the GPIO interrupt is
            # a whole one-bit output port, so its DUT bit and host offset are
            # both zero. A future sliced producer would need the same mapping.
            members=[m for m in irq_group.members if (m.source_component,m.source_port,m.source_bit_offset)==(origin.component,origin.port,origin.bit_offset)]
            if (len(members)!=1 or host_target_bit<0
                    or (target.component,target.port,host_target_bit)!=(irq_group.target_component,irq_group.target_port,irq_group.target_bit_offset)):
                raise ValueError('shared-F5-actual-IRQ-group-endpoint-mismatch')
            updated=replace(updated,relation='irq_delivery_group',irq_group_id=irq_group.group_id,irq_group_sha256=irq_group.identity_sha256)
            group_hops+=1
        edges.append(updated)
    if group_hops!=1:raise ValueError('shared-F5-one-IRQ-group-hop-required')
    union=DependencyGraph(sources=tuple(sources.values()),rules=tuple(rules))
    digest=sha256(json.dumps(union.edge_document(),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    united=RuntimePathContract(digest,tuple(nodes.values()),tuple(edges),contract.dma_master_routes)
    path=DependencyPath(row['target']['node'],tuple(identity['source_ids']),tuple(replace(e,rule_index=indexes[e.rule_index]) for e in selected))
    pin,=[s for s in row['sources'] if s['kind']=='external_pin' and s['origin']=='fuzzable']
    metadata=dict(flow_id='F5',logical_path_id=row['path_id'],path_id=union.path_identity(path,direction=row['direction']),
        source_id=path.source_ids[0],logical_source_id=pin['source_id'],component=pin['component'],cpu_component=(irq_group['target_component'] if custom else irq_group.target_component),
        direction=row['direction'],pin=dict(component=pin['component'],port=pin['port'],bit_offset=pin['bit_offset'],width=pin['width']),
        support_flow_id='F1',irq_group=(irq_group if custom else irq_group.document()))
    return union,united,(row['direction'],path),metadata


def submit_pin(runtime,raw,mapping,declaration):
    """Execute a pin case through the existing session and typed support issuer."""
    from dataclasses import asdict
    from copy import deepcopy
    from myfuzz.scenario.session_runtime import OnlineCase,OnlineInstruction
    from myfuzz.scenario.batch import BatchSourceEvent
    from myfuzz.scenario.f6_instruction_fetch_receipt import validate_shared_fixed_support
    from .compiled_f6 import _f6_runtime_case_advances
    from .shared_f6_slots import seal_case
    from .shared_gpio_irq_isr import observe_shared_gpio_irq
    p=runtime.contract['program_contract'];case_id=mapping['case_id'];address=declaration['instruction_address']
    if mapping['flow']!='F5' or declaration!=declare_shared_pin(runtime.compiled_inputs,p['shared_slots'],
            runtime.runtime_path_admission,raw=raw,slot_index=mapping['slot_index']):
        raise ValueError('shared-F5-canonical-slot-declaration-required')
    support=OnlineInstruction(case_id+':fixed-support',runtime.cpu_id,address,declaration['code_hex'])
    source=BatchSourceEvent(case_id+':pin',declaration['component'],declaration['port'],declaration['value'],
        declaration['bit_offset'],declaration['width'])
    case=OnlineCase(case_id,'IP_TO_CPU',declaration['path_id'],source,_f6_runtime_case_advances(runtime),(support,))
    next_slot=mapping['slot_index']+1
    expected=p['slot_base']+256*next_slot if next_slot<p['slot_count'] else p['park_address']
    receipt=runtime.session.submit_case(case,
        stop_after_advance=lambda _index:runtime.cpu.waiting_instruction_address==expected,stop_on_runner_failure=True)
    if receipt.status!='running' or receipt.violations or runtime.cpu.waiting_instruction_address!=expected:
        raise ValueError('shared-F5-actual-slot-boundary-missing')
    bound=validate_shared_fixed_support(runtime.cpu,case_id=case_id)
    if (bound['source']!=asdict(support) or bound['slot_index']!=mapping['slot_index']
            or bound['session_case_index']!=mapping['session_case_index']
            or bound['support_path_id']!=declaration['support_path_id'] or bound['support_source_id']!=declaration['support_source_id']
            or bound['role']!='fixed_support' or bound['fuzz_authority'] is not False or bound['F6_authority'] is not False):
        raise ValueError('shared-F5-actual-fixed-support-binding-mismatch')
    request=runtime.cpu._request_evidence['instr']
    if (runtime.cpu._waiting_instr is None or runtime.cpu.pending_responses!=1 or runtime.cpu._queued_mmio
            or runtime.cpu._pending_data is not None or request['address']!=expected):
        raise ValueError('shared-F5-nonquiescent-native-boundary')
    boundary=dict(kind='native_fetch_boundary',address=expected,execution=runtime.cpu._execution,
        native_testcase_id=runtime.cpu._case_id,reset_epoch=runtime.cpu.reset_epoch,
        transaction=runtime._jsonable(request['transaction']),local_tick=request['acceptance_tick'])
    observed=observe_shared_gpio_irq(runtime,receipt,mapping,declaration)
    certificate=dict(schema_version='compiled_shared_F5_slot_case.v1',flow_id='F5',status='certified',
        proof_scope='actual_F5_pin_admission_fixed_support_and_native_slot_boundary',
        case_id=case_id,value=declaration['value'],slot_index=mapping['slot_index'],runtime_path_id=declaration['path_id'],
        execution_binding_sha256=runtime.execution_binding_sha256,instruction_address=address,
        instruction_sha256=declaration['code_sha256'],fixed_support=bound,irq_isr=observed,
        irq_consumption=observed['status'],next_fetch=boundary,F6_enrollment=False)
    seal_case(runtime,case_id,certificate,boundary)
    if not hasattr(runtime,'shared_gpio_raw'):runtime.shared_gpio_raw={}
    runtime.shared_gpio_raw[case_id]=dict(fixed_support=deepcopy(bound),irq_isr=deepcopy(observed))
    runtime._drain_observer_view()
    return deepcopy(certificate)
