"""Independent archived slot-map checks; these facts never issue live authority."""
from hashlib import sha256
import json


def saved_slot_mapping(attempt, contract, events, context=None):
    logical = attempt['case_index']
    program = contract['program_contract']
    if 'shared_slots' not in program:
        return dict(slot_index=logical, session_case_index=logical, previous_case=(
            dict(case_id=attempt['case_id'].rsplit(':', 1)[0]+':'+str(logical-1), case_index=logical-1)
            if logical else None))

    def require(value, reason):
        if not value:
            raise ValueError('saved-shared-slot-'+reason)

    def digest(value):
        return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()

    require(type(context) is dict and set(context) == {'online_plan','flow_records','binding'},
        'independent-plan-and-ledger-required')
    plan, rows, binding = (context[key] for key in ('online_plan','flow_records','binding'))
    require(type(binding) is dict and binding.get('binding_sha256') == digest(
        {key:value for key,value in binding.items() if key != 'binding_sha256'}), 'binding-digest')
    admission = binding['runtime_path_admission']
    require(admission['execution_contract'] == contract and admission['execution_contract_sha256'] == digest(contract)
        and admission['admission_sha256'] == digest({key:value for key,value in admission.items()
            if key != 'admission_sha256'}), 'contract-scope')
    shared = admission['shared_storage_path']
    flow_paths = admission.get('shared_flow_paths')
    if flow_paths is not None:
        from .shared_slot_paths import validate_shared_flow_admission
        validate_shared_flow_admission(admission)
    else:
        flow_paths = {'F4':shared,'F6':dict(path_id=admission['runtime_path_ids'][1],source_id=contract['instruction_source_id'])}
    require(type(rows) is list and 1 <= len(rows) <= program['slot_count']
        and type(plan) is dict and len(plan['cases']) == sum(1+len(row.get('auxiliary_sources',[])) for row in rows), 'global-prefix')
    require(plan['runtime_paths']['declaration'] == admission['prepared_runtime_paths'], 'prepared-plan')
    declared = {(row[1],row[2]) for row in plan['instruction_slots'] if row[0] == contract['cpu']['instance_id']}
    require(all((program['slot_base']+program['slot_bytes']*index,32) in declared
        for index in range(program['slot_count'])), 'declared-slots')
    seen, f6_index, chosen, previous = set(), 0, None, None
    session_index = 0
    compiled = admission.get('shared_flow_compilation')
    for index,row in enumerate(rows):
        raw = bytes.fromhex(row['raw_hex'])
        expected_aux = []
        if compiled is not None:
            from .shared_slot_auxiliary import expected_auxiliary_rows,source_value
            expected_aux = expected_auxiliary_rows(compiled,admission,flow=row['flow'],raw=raw,
                case_id=row['case_id'],first_session_index=session_index)
        require(row.get('auxiliary_sources',[]) == expected_aux,'auxiliary-declaration')
        for auxiliary in expected_aux:
            case = plan['cases'][session_index]
            require(case['case_id']==auxiliary['case_id'] and case['direction']==auxiliary['direction']
                and case['path_id']==auxiliary['path_id'] and case['source_role']=='fuzz_source'
                and not case['support_instructions'] and case['advances']==[[auxiliary['component']]],
                'auxiliary-plan-case')
            source = source_value(auxiliary)
            material = dict(source,kind='source_event')
            require({key:value for key,value in case['source'].items() if key!='scheduled_local_tick'}==material,
                'auxiliary-source-fields')
            actual_aux = [event['admission'] for event in events if event.get('kind')=='source_admission'
                and event.get('admission',{}).get('case_id')==auxiliary['case_id']]
            require(len(actual_aux)==1 and all(actual_aux[0].get(key)==value for key,value in dict(
                case_id=auxiliary['case_id'],case_index=session_index,path_id=auxiliary['path_id'],
                direction=auxiliary['direction'],source_id=auxiliary['source_id'],component=auxiliary['component'],
                action_id=auxiliary['action_id'],role='fuzz_source',input_kind='source_event',
                input_sha256=digest(material)).items()),'auxiliary-actual-admission')
            steps = [event for event in events if event.get('component')==auxiliary['component']
                and type(event.get('inputs')) is dict and type(event.get('outputs')) is dict
                and 'kind' not in event and event.get('provenance',{}).get('observed_case')==dict(
                    case_id=auxiliary['case_id'],case_index=session_index)]
            require(len(steps)==1 and type(steps[0]['inputs'].get(auxiliary['port'])) is int
                and (steps[0]['inputs'][auxiliary['port']] >> auxiliary['bit_offset']) & ((1 << auxiliary['width'])-1)==auxiliary['value'],
                'auxiliary-native-input')
            require(not any(event.get('component')==contract['cpu']['instance_id']
                and type(event.get('inputs')) is dict and type(event.get('outputs')) is dict and 'kind' not in event
                and event.get('provenance',{}).get('observed_case')==dict(case_id=auxiliary['case_id'],case_index=session_index)
                for event in events),'auxiliary-CPU-not-advanced')
            session_index += 1
        case = plan['cases'][session_index]
        require(row['flow'] in flow_paths and row['case_id'] not in seen
            and row['case_id'] == case['case_id'] and row['session_case_index'] == session_index
            and row['slot_index'] == index and type(row['slot_index']) is int
            and type(row['session_case_index']) is int, 'case-order')
        seen.add(row['case_id'])
        is_f6 = row['flow'] == 'F6'
        require(row['f6_case_index'] == (f6_index if is_f6 else None), 'DMA-ordinal')
        expected_id = (binding['run_id']+':case:'+str(f6_index) if is_f6
            else binding['run_id']+':'+row['flow']+':'+str(session_index))
        require(row['case_id'] == expected_id, 'case-family')
        path = flow_paths[row['flow']]['path_id']
        source_id = flow_paths[row['flow']]['source_id']
        source = case['source']
        address = program['slot_base']+program['slot_bytes']*index
        is_pin = row['flow']=='F5' and 'declared_irq' not in program
        require(case['path_id'] == path and case['source_role'] == 'fuzz_source', 'typed-plan-source')
        raw = bytes.fromhex(row['raw_hex'])
        expected_length = 8 if row['flow'] in ('F5','F6') else 4
        if row['flow']=='F4' and compiled is not None:
            from .compiled_candidate_layout import compile_candidate_layout
            path_row, = [item for item in compiled['paths'] if item['flow_id']=='F4' and item['status']=='executable']
            expected_length = compile_candidate_layout(path_row).byte_length
        require(len(raw)==expected_length,'raw-flow-family')
        if is_pin:
            pin = flow_paths['F5']['pin']
            require(case['direction']=='IP_TO_CPU' and source['kind']=='source_event'
                and all(source[key]==pin[key] for key in ('component','port','bit_offset','width'))
                and source['value']==(raw[3]&1) and len(case['support_instructions'])==1,
                'typed-pin-source')
            support = case['support_instructions'][0]
            require(support['component']==contract['cpu']['instance_id'] and support['address']==address
                and support['data_hex']=='13000000'*32, 'typed-fixed-support')
        else:
            require(case['direction']=='CPU_TO_IP' and not case['support_instructions']
                and source['kind']=='bound_instruction' and source['source_id']==source_id
                and source['component']==contract['cpu']['instance_id'] and source['address']==address
                and len(bytes.fromhex(source['data_hex']))==128, 'typed-plan-source')
            if row['flow']=='F5':
                from .shared_declared_irq import compile_declared_irq_slot
                declared = compile_declared_irq_slot(program['declared_irq'], index)
                require(source['data_hex'] == declared['code_hex'], 'typed-declared-irq-source')
        if is_f6:
            from .compiled_f6_firmware import build_f6_firmware
            from .compiled_f6_layout import F6Candidate
            packed = int.from_bytes(raw, 'little')
            build_f6_firmware(contract).validate_prefix(bytes.fromhex(source['data_hex']),
                F6Candidate(raw,tuple((packed >> (11*i)) & 2047 for i in range(4))), case_index=f6_index)
        actual = [event['admission'] for event in events if event.get('kind')=='source_admission'
            and event.get('admission', {}).get('case_id') == row['case_id']
            and event['admission'].get('role')=='fuzz_source']
        material = {key:value for key,value in source.items() if key not in ('kind','scheduled_local_tick')}
        material['kind'] = 'source_event' if is_pin else 'instruction'
        require(len(actual) == 1 and all(actual[0].get(key) == value for key,value in dict(
            case_id=row['case_id'],case_index=session_index,path_id=path,source_id=source_id,
            component=source['component'],action_id=source['action_id'],direction=case['direction'],
            role='fuzz_source',input_kind=material['kind'],input_sha256=digest(material)).items()),
            'actual-source-admission')
        if is_pin:
            fixed = [event['admission'] for event in events if event.get('kind')=='source_admission'
                and event.get('admission',{}).get('case_id')==row['case_id']
                and event['admission'].get('role')=='fixed_support']
            require(len(fixed)==1 and all(fixed[0].get(key)==value for key,value in dict(
                case_id=row['case_id'],case_index=session_index,path_id=path,direction=case['direction'],
                source_id=support['component']+'.fixed_support',component=support['component'],
                action_id=support['action_id'],role='fixed_support',input_kind='instruction',
                input_sha256=digest(dict(support,kind='instruction'))).items()), 'actual-fixed-support-admission')
        if row['case_id'] == attempt['case_id']:
            require(is_f6 and row['f6_case_index'] == logical and row['raw_hex'] == attempt['raw8_hex']
                and row['slot_index'] == attempt['slot_index']
                and row['session_case_index'] == attempt['session_case_index']
                and attempt['instruction_address'] == address
                and attempt['prefix_hex'] == source['data_hex'], 'attempt-map')
            chosen = dict(slot_index=index,session_case_index=session_index,previous_case=previous)
        previous = dict(case_id=row['case_id'],case_index=session_index)
        f6_index += int(is_f6)
        session_index += 1
    require(chosen is not None, 'missing-F6-case')
    return chosen


def saved_shared_union(contract, binding):
    """Allow only the declared storage path beside the exact F6 subgraph."""
    if 'shared_slots' not in contract['program_contract']:
        return dict(edges=[], relations=[], nodes={}, sources=set(), selection_count=2)
    path = binding['runtime_path_admission']
    if 'shared_flow_paths' in path:
        from .shared_slot_paths import validate_shared_flow_admission,shared_f6_base
        graph,contract_doc,prepared,mapping = validate_shared_flow_admission(path)
        base_graph,base_contract = shared_f6_base(graph,contract_doc)
        base_names = {node.node_id for node in base_contract.nodes}
        return dict(edges=graph.edge_document()['edges'][4:],
            relations=[(edge.rule_index,edge.prerequisite_index,edge.relation) for edge in contract_doc.edges if edge.rule_index>=4],
            nodes={node.node_id:(node.component,node.kind) for node in contract_doc.nodes if node.node_id not in base_names},
            sources=set(graph.sources)-set(base_graph.sources),selection_count=len(prepared.runtime_paths))
    shared = path['shared_storage_path']
    selection, = path['prepared_runtime_paths']['selections'][2:]
    source = shared['source_id']
    storage = contract['program_contract']['shared_slots']['component']
    cpu, resource = contract['cpu']['instance_id'], contract['memory']['resource']
    companion = binding['issuer_contracts']['shared_companions'][storage]
    window = companion['window']
    edges = selection['edges']
    expected = [dict(rule_index=4, prerequisite_index=0, prerequisite=source,
        target='F4.mmio_access', kind='PERSISTENT_STATE_RULE'),
        dict(rule_index=5, prerequisite_index=0, prerequisite='F4.mmio_access',
        target='F4.device_register_response', kind='DATA_BINDING')]
    if not (selection['direction'] == 'CPU_TO_IP' and selection['source_ids'] == [source]
            and selection['target'] == 'F4.device_register_response' and edges == expected
            and selection['path_id'] == shared['path_id'] == path['runtime_path_ids'][2]
            and shared['component'] == storage and shared['cpu_component'] == cpu
            and shared['memory_id'] == resource['resource_id']
            and companion['register'] == contract['program_contract']['shared_slots']['register']):
        raise ValueError('saved-shared-slot-union-selection')
    extras = path['runtime_contract']['edges'][4:]
    expected_relations = [dict(rule_index=4, prerequisite_index=0, relation='persistent_state',
        resource_component=cpu, resource_id=resource['resource_id'], initiator_component=None,
        device_id=None, base=None, size=None),
        dict(rule_index=5, prerequisite_index=0, relation='mmio_route', resource_component=None,
        resource_id=None, initiator_component=cpu, device_id=storage, base=window['base'], size=window['size'])]
    if extras != expected_relations:
        raise ValueError('saved-shared-slot-union-route')
    return dict(edges=expected, relations=[(4,0,'persistent_state'),(5,0,'mmio_route')],
        nodes={source:(cpu,'state'), 'F4.mmio_access':(cpu,'logical'),
            'F4.device_register_response':(storage,'logical')},
        sources={source}, selection_count=3)
