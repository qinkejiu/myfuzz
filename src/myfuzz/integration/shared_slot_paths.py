"""Pure union builder for typed instruction paths in an existing F6 session."""
from dataclasses import replace
from hashlib import sha256
import json


def build_shared_flow_paths(graph, contract, compiled, flows, *, irq_group=None):
    from myfuzz.scenario.dependency import DependencyGraph,DependencyEdge,DependencyPath
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    source_graph = DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    source_contract = RuntimePathContract.from_document(compiled['runtime_path_contract'])
    sources, rules = dict(graph.sources), list(graph.ordered_rules)
    nodes = {node.node_id:node for node in contract.nodes}
    edges = list(contract.edges)
    remap, selected, declarations = {}, [], {}
    declared_f5 = any(row['flow_id'] == 'F5' and row['status'] == 'executable'
        and row['direction'] == 'CPU_TO_IP' for row in compiled['paths'])
    # Preserve the existing F4 extension ordering for old shared declarations.
    for flow in (flow for flow in ('F4','F1','F2','F3','F5')
                 if flow in flows and (flow != 'F5' or declared_f5)):
        matches = [row for row in compiled['paths'] if row['flow_id']==flow and row['status']=='executable']
        if len(matches)!=1:
            raise ValueError('shared-slot-one-executable-required:'+flow)
        row = matches[0]
        identity = row['runtime_path_identity']
        old_edges = tuple(DependencyEdge(**edge) for edge in identity['edges'])
        for index in dict.fromkeys(edge.rule_index for edge in old_edges):
            if index not in remap:
                remap[index] = len(rules)
                rules.append(source_graph.ordered_rules[index])
                for edge in source_contract.edges:
                    if edge.rule_index != index:
                        continue
                    updated = replace(edge, rule_index=remap[index])
                    if flow == 'F5' and edge.relation == 'direct_binding':
                        from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
                        group = IrqDeliveryGroup.from_document(irq_group) if type(irq_group) is dict else irq_group
                        if type(group) is not IrqDeliveryGroup:
                            raise ValueError('shared-F5-explicit-IRQ-group-required')
                        rule = source_graph.ordered_rules[index]
                        by_name = {node.node_id: node for node in source_contract.nodes}
                        origin, target = by_name[rule.prerequisites[0]], by_name[rule.target]
                        members = [m for m in group.members if (m.source_component, m.source_port, m.source_bit_offset)
                                   == (origin.component, origin.port, origin.bit_offset)]
                        if (len(members) != 1 or target.component != group.target_component
                                or target.port != group.target_port
                                or target.bit_offset - group.target_input_bit_lo != group.target_bit_offset):
                            raise ValueError('shared-F5-actual-IRQ-group-endpoint-mismatch')
                        updated = replace(updated, relation='irq_delivery_group',
                            irq_group_id=group.group_id, irq_group_sha256=group.identity_sha256)
                    edges.append(updated)
        for name in identity['source_ids']:
            source = source_graph.sources[name]
            if name in sources and sources[name] != source:
                raise ValueError('shared-slot-source-collision:'+name)
            sources[name] = source
        needed = set(identity['source_ids']) | {edge.target for edge in old_edges} | {edge.prerequisite for edge in old_edges}
        for node in source_contract.nodes:
            if node.node_id in needed:
                if node.node_id in nodes and nodes[node.node_id] != node:
                    raise ValueError('shared-slot-node-collision:'+node.node_id)
                nodes[node.node_id] = node
        path = DependencyPath(row['target']['node'],tuple(identity['source_ids']),
            tuple(replace(edge,rule_index=remap[edge.rule_index]) for edge in old_edges))
        images = [source for source in row['sources'] if source['kind']=='instruction_image']
        if len(images)!=1 or row['direction']!='CPU_TO_IP':
            raise ValueError('shared-slot-instruction-path-required:'+flow)
        image = images[0]
        targets = [source['register_access']['target_component'] for source in row['sources']
            if source.get('register_access')]
        declarations[flow] = dict(flow_id=flow, logical_path_id=row['path_id'],
            source_id=path.source_ids[0],logical_source_id=image['source_id'],
            cpu_component=image['component'],component=targets[0] if targets else image['component'],
            memory_id=image['port'],base=image['range'][0],size=image['range'][1]-image['range'][0]+1)
        if flow == 'F5':
            from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
            group = IrqDeliveryGroup.from_document(irq_group) if type(irq_group) is dict else irq_group
            declarations[flow]['component'] = next(e['instance_id'] for e in row['endpoints']
                                                    if e['declared_role'] == 'interrupt_producer')
            # Group members are tuples in memory and arrays in saved JSON.
            # Keep the admission identical across live and archived rebuilds.
            declarations[flow]['irq_group'] = json.loads(json.dumps(group.document()))
        selected.append((flow,row['direction'],path))
    union = DependencyGraph(sources=tuple(sources.values()),rules=tuple(rules))
    digest = sha256(json.dumps(union.edge_document(),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    union_contract = RuntimePathContract(digest,tuple(nodes.values()),tuple(edges),contract.dma_master_routes)
    for flow,direction,path in selected:
        declarations[flow]['path_id'] = union.path_identity(path,direction=direction)
    selected_paths = tuple((direction,path) for _,direction,path in selected)
    if 'F5' in flows and not declared_f5:
        from .shared_f5_slots import extend_shared_pin_path
        union,union_contract,pin_path,pin_mapping = extend_shared_pin_path(
            union,union_contract,compiled,irq_group=irq_group)
        selected_paths += (pin_path,)
        # Admission metadata is a JSON document in both live and saved proofs.
        declarations['F5'] = json.loads(json.dumps(pin_mapping))
    # Path identities include the final union graph, including the pin branch.
    for flow,direction,path in selected:
        declarations[flow]['path_id'] = union.path_identity(path,direction=direction)
    return union,union_contract,selected_paths,declarations


def shared_f6_base(graph, contract):
    """Recover the unchanged F6 subgraph; extras cannot redefine its names."""
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    rules = graph.ordered_rules[:4]
    base_edges = [edge for edge in graph.edge_document()['edges'] if edge['rule_index'] < 4]
    names = {edge['prerequisite'] for edge in base_edges}|{edge['target'] for edge in base_edges}
    base = DependencyGraph(sources=tuple(source for name,source in graph.sources.items() if name in names),rules=rules)
    digest = sha256(json.dumps(base.edge_document(),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    return base,RuntimePathContract(digest,tuple(node for node in contract.nodes if node.node_id in names),
        tuple(edge for edge in contract.edges if edge.rule_index < 4),contract.dma_master_routes)


def validate_shared_flow_admission(admission):
    """Rebuild the entire union from the same-pass D3 compilation evidence."""
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract,PreparedRuntimePathContract
    from myfuzz.scenario.compiled_paths import compiled_document_sha256
    compiled = admission['shared_flow_compilation']
    if compiled_document_sha256(compiled) != admission['compiled_document_sha256']:
        raise ValueError('shared-slot-compiled-evidence-digest')
    graph = DependencyGraph.from_edge_document(admission['runtime_graph'])
    contract = RuntimePathContract.from_document(admission['runtime_contract'])
    prepared = PreparedRuntimePathContract.from_document(admission['prepared_runtime_paths'])
    base_graph,base_contract = shared_f6_base(graph,contract)
    if 'F5' in admission['shared_flow_paths']:
        program = admission['execution_contract']['program_contract']
        irq = program.get('declared_irq') or program.get('gpio_irq')
        route=admission['shared_flow_paths']['F5']['irq_group']
        if route.get('schema_version')=='shared_custom_gpio_irq_route.v1':
            valid=(irq is not None and 'custom_irq' in program
                and route.get('source_component')==irq['component']
                and route.get('target_bit_offset')==irq.get('irq_bit')
                and route.get('target_component')==admission['execution_contract']['cpu']['instance_id'])
        else:
            valid=irq is not None and route.get('group_id')==irq['group_id']
        if not valid:
            raise ValueError('shared-slot-IRQ-group-contract-mismatch')
    execution = admission['execution_contract']
    flows = execution['program_contract']['shared_slots']['enabled_flows']
    expected_graph,expected_contract,paths,mapping = build_shared_flow_paths(base_graph,base_contract,compiled,flows,
        irq_group=admission['shared_flow_paths'].get('F5',{}).get('irq_group'))
    expected = PreparedRuntimePathContract(expected_graph,expected_contract,prepared.runtime_paths[:2]+paths)
    resource = execution['memory']['resource']
    mapping['F6'] = dict(flow_id='F6',path_id=expected.path_ids[1],
        source_id=execution['instruction_source_id'],logical_source_id=execution['instruction_source_id'],
        cpu_component=execution['cpu']['instance_id'],component=execution['dma']['instance_id'],
        memory_id=resource['resource_id'],base=resource['base'],size=resource['size'])
    if (expected_graph.edge_document() != graph.edge_document() or expected_contract.document()!=contract.document()
            or expected.document()!=prepared.document() or list(expected.path_ids)!=admission['runtime_path_ids']
            or mapping != admission['shared_flow_paths'] or set(mapping)!=set(flows)):
        raise ValueError('shared-slot-union-rebuild-mismatch')
    return expected_graph,expected_contract,expected,mapping
