"""Actual, non-mutating register compiler preflight; no execution certification."""
from dataclasses import asdict
import hashlib
import json

from myfuzz.composition.ip_test_levels import RuntimeCapabilitySnapshot, assess_ip_test_level
from myfuzz.composition.test_capability import load_ip_test_capability, IP_TEST_OPERATIONS
from .register_program import compile_register_program
from .rv32i_sources import MmioWindow


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _storage(adapter, memory, router, gate):
    spans = [(address, 4*words) for component,address,words in adapter.session._instruction_slots
             if component == adapter.cpu_component]
    spans += [(image.address,len(image.data)) for image in adapter.session.template.initial_images
              if image.component == adapter.cpu_component]
    spans += [(window.base,window.size) for window in router.windows]
    spans += [(action.payload['address'],len(bytes.fromhex(action.payload['words_hex'])))
              for action in gate._actions.values() if action.kind == 'instruction'
              and action.component == adapter.cpu_component and 'words_hex' in action.payload]
    for region in memory._regions:
        if not region.writable or region.aliases:
            continue
        candidates = {((region.base+3)//4)*4}
        candidates.update(((start+length+3)//4)*4 for start,length in spans)
        for address in sorted(candidates):
            if not region.base <= address or address+4 > min(region.base+region.size,1<<32):
                continue
            if any(address < start+length and start < address+4 for start,length in spans):
                continue
            memory_id,_,offset = memory.resolve_span(address,4)
            cells = [memory.inspect_byte(memory_id,offset+lane) for lane in range(4)]
            if not any(cell is not None and cell.writer_kind in ('INITIAL_IMAGE','INSTRUCTION_SOURCE') for cell in cells):
                return address
    return None


def capability_preflight(adapter, *, requested_minimum_level=None):
    from .register_program_runtime import RegisterProgramRuntime
    if type(adapter) is not RegisterProgramRuntime:
        raise ValueError('register-capability-actual-adapter-required')
    if requested_minimum_level is not None and (type(requested_minimum_level) is not str
            or requested_minimum_level not in ('L1','L2','L3')):
        raise ValueError('invalid-requested-minimum-level')
    adapter.validate()
    cpu,memory,router,gate,policy,*_ = adapter._objects
    slots = []
    for component,address,words in adapter.session._instruction_slots:
        if component != adapter.cpu_component:
            continue
        # Enumerate declared slots, not a saved/current waiting fetch.
        for start in range(address,address+4*words,4):
            size = min(adapter.max_program_bytes,address+4*words-start,policy.last_address-start)
            if start < policy.first_address or size < 16:
                continue
            if all(memory.instruction_slot_unmaterialized(word) for word in range(start,start+size,4)):
                slots.append((start,size))
                break
    if len(gate._actions) >= gate.max_actions or len(adapter._records) >= adapter.max_records:
        slots = []
    result = _storage(adapter,memory,router,gate)
    targets = {}
    for alias,path in sorted(adapter.sidecars.items()):
        target = adapter.runner.sessions[alias]
        profile = target.artifact.plan.profile
        sidecar = load_ip_test_capability(path,profile=profile)
        endpoints = [e for e in target.artifact.plan.binding.endpoints if e.function == 'mmio_slave']
        routes = [w for w in router.windows if w.target is target and w.device_id == alias]
        operations, conditions, protocols = {}, [], []
        if len(endpoints) == len(routes) == 1 and routes[0].size == profile.address.window_size:
            endpoint,window = endpoints[0],routes[0]
            declared = next((e.operations for e in sidecar.endpoint_capabilities if e.endpoint_id == endpoint.endpoint_id),())
            # Validated actual native APB trace establishes the basic transaction path.
            if target.artifact.runtime_document.get('base_protocol_trace') is not None:
                protocol = profile.endpoint(endpoint.endpoint_id).protocol
                if protocol is not None:
                    protocols.append(protocol)
                    operations[endpoint.endpoint_id] = ['request','accept','response']
            for field in (sidecar.register_semantics if protocols else ()):
                for operation in ('register_read','register_write'):
                    permission = 'read' if operation == 'register_read' else 'write'
                    if permission not in declared or operation == 'register_read' and result is None:
                        continue
                    for rmw in (False,True) if operation == 'register_write' else (False,):
                        if rmw and 'read' not in declared:
                            continue
                        for address,size in slots:
                            try:
                                compiled = compile_register_program(profile,sidecar,
                                    register=field.register,field=field.field,operation=operation,
                                    value=0 if operation == 'register_write' else None,
                                    allow_side_effect=field.side_effect != 'none',read_modify_write=rmw,
                                    address_base=window.base,windows=(MmioWindow(window.base,window.size),),
                                    cpu_component=adapter.cpu_component,action_id='capability-probe',
                                    program_address=address,program_size=size,program_regions=memory._regions,
                                    result_address=result if operation == 'register_read' else None,
                                    result_regions=memory._regions if operation == 'register_read' else ())
                            except ValueError:
                                continue
                            scope = field.register+'.'+field.field
                            operations.setdefault(endpoint.endpoint_id,[]).append((operation,scope))
                            conditions.append(dict(endpoint_id=endpoint.endpoint_id,operation=operation,scope=scope,
                                allow_side_effect=field.side_effect != 'none',read_modify_write=rmw,
                                program_bytes=len(compiled.fragment)))
                            break
                        else:
                            continue
                        break
        snapshot = RuntimeCapabilitySnapshot.from_mapping(profile,sidecar=sidecar,
            supported_protocols=protocols,endpoint_operations=operations)
        assessment = assess_ip_test_level(profile,sidecar=sidecar,runtime_support=snapshot,
            requested_minimum_level=requested_minimum_level)
        assessment.require_minimum()
        targets[alias] = dict(target_instance=alias,runtime_support=asdict(snapshot),
            assessment=assessment.to_document(),operation_conditions=conditions)
    adapter.validate()
    return json.loads(_canonical(dict(schema_version='register_program_capability_preflight.v1',
        configuration_sha256=hashlib.sha256(_canonical(adapter.configuration()).encode()).hexdigest(),
        requested_minimum_level=requested_minimum_level,targets=targets,
        verification=None,grants_functional=False)))


def validate_register_capability_preflight_document(document, *, configuration=None):
    """Closed saved JSON check. Saved claims remain comparison data, not authority."""
    import re
    def fail():
        raise ValueError('invalid-register-capability-preflight-document')
    def keys(value, expected):
        if type(value) is not dict or set(value) != set(expected): fail()
    def text(value):
        if type(value) is not str or not value or len(value) > 512: fail()
    def level(value):
        if value is not None and (type(value) is not str or value not in ('L1','L2','L3')): fail()
    def scope(value):
        text(value)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*',value): fail()
    def operation(value):
        text(value)
        if value not in IP_TEST_OPERATIONS | {'register_read','register_write','transfer','interrupt','state_transition','completion'}: fail()
    def strings(value):
        if type(value) is not list or len(value)>4096: fail()
        for item in value: text(item)
    # JSON detachment rejects non-JSON provider objects; strict checks follow.
    try: document = json.loads(_canonical(document))
    except (TypeError,ValueError): fail()
    keys(document,('schema_version','configuration_sha256','requested_minimum_level','targets','verification','grants_functional'))
    if (document['schema_version'] != 'register_program_capability_preflight.v1'
            or type(document['configuration_sha256']) is not str
            or not re.fullmatch('[0-9a-f]{64}',document['configuration_sha256'])
            or document['verification'] is not None or document['grants_functional'] is not False): fail()
    level(document['requested_minimum_level'])
    targets = document['targets']
    if type(targets) is not dict or not 1 <= len(targets) <= 4096: fail()
    if configuration is not None:
        if (document['configuration_sha256'] != hashlib.sha256(_canonical(configuration).encode()).hexdigest()
                or set(targets) != set(configuration['sidecars'])): fail()
    for alias,target in targets.items():
        text(alias)
        keys(target,('target_instance','runtime_support','assessment','operation_conditions'))
        if target['target_instance'] != alias: fail()
        snapshot = target['runtime_support']
        keys(snapshot,('component_id','profile_fingerprint','supported_protocols','endpoint_operations','sidecar_fingerprint','observation_mappings'))
        text(snapshot['component_id'])
        for name in ('profile_fingerprint','sidecar_fingerprint'):
            if type(snapshot[name]) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',snapshot[name]): fail()
        if type(snapshot['supported_protocols']) is not list or len(snapshot['supported_protocols'])>256: fail()
        for pair in snapshot['supported_protocols']:
            if type(pair) is not list or len(pair)!=2: fail()
            for item in pair: text(item)
        strings(snapshot['observation_mappings'])
        if snapshot['observation_mappings']: fail()  # No functional mapping provider in this preflight.
        claims = snapshot['endpoint_operations']
        if type(claims) is not list or len(claims)>4096: fail()
        claim_set = set()
        for claim in claims:
            keys(claim,('endpoint_id','operation','scope'))
            text(claim['endpoint_id'])
            if claim['operation'] not in ('request','accept','response','register_read','register_write'): fail()
            if claim['scope'] is not None: scope(claim['scope'])
            if (claim['operation'].startswith('register_')) != (claim['scope'] is not None): fail()
            key = (claim['endpoint_id'],claim['operation'],claim['scope'])
            if key in claim_set: fail()
            claim_set.add(key)
        assessment = target['assessment']
        keys(assessment,('schema_version','component_id','profile_fingerprint','sidecar_fingerprint','declared_level','effective_level','verified_level','requested_minimum_level','minimum_level_met','support_matrix','gaps'))
        if assessment['schema_version'] != 'ip_test_level_assessment.v1': fail()
        for name in ('component_id','profile_fingerprint','sidecar_fingerprint'):
            if assessment[name] != snapshot[name]: fail()
        if configuration is not None and snapshot['profile_fingerprint'] != configuration['artifacts'][alias]['current_profile_fingerprint']: fail()
        for name in ('declared_level','effective_level'): level(assessment[name])
        if assessment['verified_level'] is not None or assessment['requested_minimum_level'] != document['requested_minimum_level']: fail()
        if document['requested_minimum_level'] is None:
            if assessment['minimum_level_met'] is not None: fail()
        elif (assessment['minimum_level_met'] is not True or assessment['effective_level'] is None
                or ('L1','L2','L3').index(assessment['effective_level']) < ('L1','L2','L3').index(document['requested_minimum_level'])): fail()
        if (assessment['effective_level'] is not None and (assessment['declared_level'] is None
                or ('L1','L2','L3').index(assessment['effective_level']) > ('L1','L2','L3').index(assessment['declared_level']))): fail()
        strings(assessment['gaps'])
        rows = assessment['support_matrix']
        if type(rows) is not list or len(rows)>4096: fail()
        effective = set(); row_ids = set()
        for row in rows:
            keys(row,('endpoint_id','operation','scope','level','declared','effective','verified','gaps','evidence_refs'))
            text(row['endpoint_id']); operation(row['operation']); level(row['level'])
            if row['level'] is None: fail()
            expected_level = ('L2' if row['operation'].startswith('register_') else
                'L3' if row['operation'] in ('transfer','interrupt','state_transition','completion') else 'L1')
            if row['level'] != expected_level: fail()
            if row['level'] == 'L2': scope(row['scope'])
            elif row['scope'] is not None: text(row['scope'])
            if any(type(row[name]) is not bool for name in ('declared','effective','verified')): fail()
            if row['verified'] or row['evidence_refs'] != []: fail()
            strings(row['gaps'])
            key = (row['endpoint_id'],row['operation'],row['scope'])
            if key in row_ids: fail()
            row_ids.add(key)
            if row['effective']:
                if not row['declared'] or key not in claim_set: fail()
                effective.add(key)
        conditions = target['operation_conditions']
        if type(conditions) is not list or len(conditions)>4096: fail()
        conditioned = set()
        for condition in conditions:
            keys(condition,('endpoint_id','operation','scope','allow_side_effect','read_modify_write','program_bytes'))
            text(condition['endpoint_id']); operation(condition['operation']); scope(condition['scope'])
            key = (condition['endpoint_id'],condition['operation'],condition['scope'])
            if key not in effective or key in conditioned or condition['operation'] not in ('register_read','register_write'): fail()
            if type(condition['allow_side_effect']) is not bool or type(condition['read_modify_write']) is not bool: fail()
            # Saved conditions are structural comparisons. Fresh preflight recompiles
            # the exact field; narrow READs add shift and mask instructions.
            lengths = ({16,20,24,28,32} if condition['operation']=='register_read'
                       else {36} if condition['read_modify_write'] else {16})
            size = condition['program_bytes']
            if type(size) is not int or size not in lengths: fail()
            if condition['operation'] == 'register_read' and condition['read_modify_write']: fail()
            if configuration is not None and size > configuration['max_program_bytes']: fail()
            conditioned.add(key)
        if conditioned != {key for key in effective if key[1].startswith('register_')}: fail()
    return document
