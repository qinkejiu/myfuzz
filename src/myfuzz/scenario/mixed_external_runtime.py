"""Closed pin operations for the opt-in register/pin runtime.

Declarations bind actual decoder objects and their compiled source paths. Saved
manifests never install ownership, reserve slots, or authorize a submission.
"""
from dataclasses import asdict, dataclass
import json
import hashlib
from .batch import BatchAdvance, BatchSourceEvent
from .ledger import TransactionKey
from .source_actions import SourceAction, TerminationObservation, instruction_slot_unmaterialized_prerequisite


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def manifest_configuration_sha256(configuration):
    """Match the runtime's pinned canonical configuration; no authority lookup."""
    return hashlib.sha256(canonical(configuration).encode()).hexdigest()


def normalize_manifest_configuration(manifest, configuration, *, expected_sha256=None):
    """Resolve closed v2 comparison references against a caller's actual config.

    Internal callers may pass a digest already computed from their pinned or
    validated outer configuration. A saved digest is never that trusted input.
    The shallow normalized view is transient; serialized records stay compact.
    """
    versions={'register_program_runtime_manifest.v1':'register_program_runtime_manifest.v2',
              'external_pin_runtime_manifest.v1':'external_pin_runtime_manifest.v2'}
    if type(manifest) is not dict:
        raise ValueError('invalid runtime manifest configuration')
    schema=manifest.get('schema_version')
    if schema in versions:
        if ('configuration_sha256' in manifest or 'configuration' not in manifest
                or canonical(manifest['configuration'])!=canonical(configuration)):
            raise ValueError('runtime manifest configuration mismatch')
        return manifest
    reverse={v:k for k,v in versions.items()}
    if (schema not in reverse or not configuration.get('external_sources')
            or 'configuration' in manifest or 'configuration_sha256' not in manifest):
        raise ValueError('invalid compact runtime manifest configuration')
    digest=manifest['configuration_sha256']
    if (type(digest) is not str or len(digest)!=64
            or any(c not in '0123456789abcdef' for c in digest)
            or digest!=(manifest_configuration_sha256(configuration) if expected_sha256 is None else expected_sha256)):
        raise ValueError('runtime manifest configuration reference mismatch')
    result={key:value for key,value in manifest.items() if key!='configuration_sha256'}
    result.update(schema_version=reverse[schema],configuration=configuration)
    return result


@dataclass(frozen=True)
class ExternalPinSource:
    """Live declaration binding; serialized dictionaries cannot install it."""
    decoder: object
    declaration_json: str
    decoder_json: str

    def document(self):
        return json.loads(self.declaration_json)


def _decoder_rows(decoder):
    from .online_case_decoder import OnlineCaseDecoder
    if not isinstance(decoder, OnlineCaseDecoder):
        raise ValueError('mixed-runtime-actual-decoder-required')
    rows = []
    for source in decoder.sources:
        if source.kind != 'source':
            continue
        if source.source_id in decoder.source_actions:
            raise ValueError('mixed-runtime-external-source-extra-prerequisites-unsupported')
        node = decoder.graph.sources.get(source.source_id)
        if (node is None or (node.kind,node.component,node.port,node.bit_offset,node.width) !=
                (source.kind,source.component,source.port,source.bit_offset,source.width)
                or source.direction not in node.directions
                or not any(source.source_id in path.source_ids for path in decoder.paths_for(source.path_id,direction=source.direction))):
            raise ValueError('mixed-runtime-actual-declared-source-path-required')
        producer = decoder.ownership.mutation_source(source.component, source.port,
            source.bit_offset, source.width, direction=source.direction)
        rows.append(dict(schema_version='external_pin_declaration.v1', source=asdict(source),
            producer=producer, flow_id=decoder.flow_by_target[source.path_id],
            support_words=decoder.support_words,support_component=decoder._instruction_component,
            runtime_contract_sha256=decoder.runtime_contract.identity_sha256))
    return validate_external_sources(json.loads(canonical(rows)))


def external_pin_sources_from_decoder(decoder):
    from .online_case_decoder import OnlineCaseDecoder
    rows = _decoder_rows(decoder)
    identity = canonical(OnlineCaseDecoder.document(decoder))
    return tuple(ExternalPinSource(decoder, canonical(row), identity) for row in rows)


def bind_external_sources(bindings):
    from .online_case_decoder import OnlineCaseDecoder
    if type(bindings) is not tuple or any(type(b) is not ExternalPinSource for b in bindings):
        raise ValueError('mixed-runtime-live-external-declarations-required')
    rows = []
    for binding in bindings:
        actual = _decoder_rows(binding.decoder)
        if (canonical(OnlineCaseDecoder.document(binding.decoder)) != binding.decoder_json
                or not any(canonical(row)==binding.declaration_json for row in actual)):
            raise ValueError('mixed-runtime-external-decoder-binding-drift')
        rows.append(binding.document())
    return validate_external_sources(rows)


def validate_external_sources(rows):
    """Validate closed comparison data without constructing runtime authority."""
    from .online_case_decoder import OnlineSource
    if type(rows) not in (tuple, list) or len(rows)>256:
        raise ValueError('mixed-runtime-closed-external-declarations-required')
    seen = set()
    for row in rows:
        if (type(row) is not dict or set(row)!={'schema_version','source','producer','flow_id','support_words','support_component','runtime_contract_sha256'}
                or row['schema_version']!='external_pin_declaration.v1'
                or type(row['producer']) is not str or not row['producer']
                or row['flow_id'] != 'F5'
                or type(row['support_component']) is not str or not row['support_component']
                or type(row['support_words']) is not int or not 1 <= row['support_words'] <= 4096
                or type(row['runtime_contract_sha256']) is not str or len(row['runtime_contract_sha256'])!=64
                or any(c not in '0123456789abcdef' for c in row['runtime_contract_sha256'])
                or type(row['source']) is not dict or set(row['source']) != set(OnlineSource.__dataclass_fields__)):
            raise ValueError('mixed-runtime-invalid-external-declaration')
        source = dict(row['source'])
        if (any(type(source[k]) is not str or not 1 <= len(source[k]) <= 256 or source[k].strip()!=source[k]
                for k in ('source_id','component','direction','path_id','port'))
                or type(source['coverage_target_ids']) is not list):
            raise ValueError('mixed-runtime-invalid-external-source')
        source['coverage_target_ids']=tuple(source['coverage_target_ids'])
        source = OnlineSource(**source)
        if source.kind!='source' or source.width!=1 or source.source_id in seen:
            raise ValueError('mixed-runtime-external-single-pin-source-required')
        seen.add(source.source_id)
    return tuple(json.loads(canonical(rows)))


def validate_external_ownership(configuration):
    """Check saved ownership comparisons; never attach this map to execution."""
    from .ownership import InputField, InputOwner, compile_ownership
    if (type(configuration.get('provider')) is not dict
            or 'runtime_contract_sha256' not in configuration['provider']
            or type(configuration.get('cpu_component')) is not str):
        raise ValueError('invalid mixed external configuration binding')
    document=configuration.get('external_ownership')
    if (type(document) is not dict or set(document)!={'fields','owners'}
            or any(type(document[k]) is not list or len(document[k])>4096 for k in ('fields','owners'))):
        raise ValueError('invalid mixed external ownership')
    for rows,fields in ((document['fields'],set(InputField.__dataclass_fields__)),
                        (document['owners'],set(InputOwner.__dataclass_fields__))):
        if any(type(row) is not dict or set(row)!=fields for row in rows):
            raise ValueError('invalid mixed external ownership row')
    if (any(any(type(row[k]) is not str or not row[k] for k in ('component_id','port'))
                for row in document['fields'])
            or any(any(type(row[k]) is not str or not row[k] for k in ('component_id','port','producer_ref','kind'))
                   for row in document['owners'])):
        raise ValueError('invalid mixed external ownership identity')
    if (any(type(row['width']) is not int or not 1<=row['width']<=65536 for row in document['fields'])
            or sum(row['width'] for row in document['fields'])>1048576):
        raise ValueError('invalid mixed external ownership width')
    ownership=compile_ownership(tuple(InputField(**row) for row in document['fields']),
                                tuple(InputOwner(**row) for row in document['owners']))
    if canonical(ownership.document())!=canonical(document):
        raise ValueError('invalid mixed external ownership projection')
    for declaration in validate_external_sources(configuration.get('external_sources',())):
        source=declaration['source']
        if (ownership.mutation_source(source['component'],source['port'],source['bit_offset'],source['width'],
                direction=source['direction'])!=declaration['producer']
                or declaration['support_component']!=configuration['cpu_component']
                or declaration['runtime_contract_sha256']!=configuration['provider']['runtime_contract_sha256']):
            raise ValueError('invalid mixed external ownership binding')


def validate_external_request(request):
    if (type(request) is not dict or set(request) != {'schema_version','case_id','action_id','source_id','value'}
            or request['schema_version'] != 'external_pin_request.v1'
            or any(type(request[key]) is not str or not 1 <= len(request[key]) <= 256
                   or request[key].strip() != request[key] for key in ('case_id','action_id','source_id'))
            or type(request['value']) is not int or request['value'] not in (0, 1)):
        raise ValueError('mixed-runtime-closed-external-request-required')
    return json.loads(canonical(request))


def external_case(request, declaration, context, configuration):
    from .session_runtime import OnlineCase, OnlineInstruction
    source = declaration['source']
    support = OnlineInstruction(request['action_id'] + ':fixed-support', configuration['cpu_component'],
        context['waiting_instruction_address'], (b'\x13\x00\x00\x00' * declaration['support_words']).hex())
    return OnlineCase(request['case_id'], source['direction'], source['path_id'],
        BatchSourceEvent(request['action_id'], source['component'], source['port'], request['value'],
                         source['bit_offset'], source['width']),
        tuple(BatchAdvance(tuple(configuration['template']['schedule_order']))
              for _ in range(configuration['advance_rounds'])), support_instructions=(support,))


def external_actions(case, declaration, configuration):
    budget = sum(len(a.schedule) for a in case.advances)
    source = case.source
    action = SourceAction(action_id=source.action_id, kind='external_event', component=source.component,
        source_id=declaration['source']['source_id'], ownership='fuzzable', flow_id=declaration['flow_id'],
        payload=dict(port=source.port, bit_offset=source.bit_offset, width=source.width, value=source.value),
        termination_observation=TerminationObservation('incomplete','',declaration['flow_id']), local_step_budget=budget)
    return action



def external_support_action(case, declaration, configuration):
    fragment=case.support_instructions[0]
    prefix=configuration['policy']['reservation_ref_prefix']
    return SourceAction(action_id=fragment.action_id,kind='instruction',component=fragment.component,
        source_id='fixed_instruction_support',ownership='fixed',flow_id=declaration['flow_id'],payload={},
        termination_observation=TerminationObservation('incomplete','',declaration['flow_id']),
        local_step_budget=sum(len(a.schedule) for a in case.advances),
        prerequisites=tuple(instruction_slot_unmaterialized_prerequisite(fragment.component,word,
            f'{prefix}:{word:#010x}') for word in range(fragment.address,fragment.address+len(fragment.data),4)))


def prepare_external(runtime, request, expected_manifest=None):
    from .register_program_runtime import PreparedRegisterProgram
    runtime.validate()
    runtime.session._register_capability_preflight()
    request = validate_external_request(request)
    declarations = validate_external_sources(runtime.external_sources)
    matches = [d for d in declarations if d['source']['source_id'] == request['source_id']]
    if len(matches) != 1:
        raise ValueError('mixed-runtime-external-source-not-enabled')
    declaration = matches[0]; source = declaration['source']
    cpu, memory, router, gate, policy, *_ = runtime._objects
    session = runtime.session
    if (not session._begun or session._finished or session._halted or runtime.runner._status != 'running'):
        raise ValueError('mixed-runtime-active-session-required')
    if (declaration['support_component'] != runtime.cpu_component
            or declaration['runtime_contract_sha256'] != gate.tracker._consumer._runtime
            or source['component'] not in runtime.runner.sessions
            or source['bit_offset']+source['width'] > runtime.runner.ownership.field_width(source['component'],source['port'])):
        raise ValueError('mixed-runtime-actual-source-binding-required')
    if runtime.runner.ownership.mutation_source(source['component'],source['port'],source['bit_offset'],
            source['width'],direction=source['direction']) != declaration['producer']:
        raise ValueError('mixed-runtime-ownership-drift')
    address = cpu.waiting_instruction_address; waiting = cpu._waiting_instr
    if (type(waiting) is not tuple or len(waiting)!=2 or type(waiting[0]) is not TransactionKey
            or waiting[0].source_component != runtime.cpu_component or waiting[0].source_epoch != cpu.reset_epoch
            or cpu._request_evidence.get('instr',{}).get('transaction') != asdict(waiting[0])
            or cpu._request_evidence.get('instr',{}).get('aligned_address') != address):
        raise ValueError('mixed-runtime-real-waiting-transaction-required')
    size = 4 * declaration['support_words']
    if (type(address) is not int or address % 4 or not policy.first_address <= address
            or address + size > policy.last_address
            or not any(c==runtime.cpu_component and start<=address and address+size<=start+4*count
                       for c,start,count in session._instruction_slots)
            or any(not memory.instruction_slot_unmaterialized(word) for word in range(address,address+size,4))):
        raise ValueError('mixed-runtime-unmaterialized-waiting-slots-required')
    ids = (request['action_id'], request['action_id']+':fixed-support')
    if (len(runtime._records)>=runtime.max_records or request['case_id'] in session._receipts
            or any(i in session._source_ids or i in gate.action_ids for i in ids)
            or len(gate.action_ids)+2 > gate.max_actions):
        raise ValueError('mixed-runtime-capacity-or-duplicate')
    context = dict(generation=memory.generation,reset_epoch=cpu.reset_epoch,tracker_epoch=gate.tracker._epoch,
        waiting_transaction=asdict(waiting[0]),command_epoch=runtime.runner.command_epoch,
        waiting_instruction_address=address,target_reset_epoch=runtime.runner.sessions[source['component']].reset_epoch)
    config = runtime.configuration()
    case = external_case(request,declaration,context,config)
    if sum(len(a.schedule) for a in case.advances)>session.template.max_steps:
        raise ValueError('mixed-runtime-schedule-capacity')
    action = external_actions(case,declaration,config)
    fragment = case.support_instructions[0]
    support = external_support_action(case,declaration,config)
    doc = dict(schema_version='external_pin_runtime_manifest.v2',request=request,
        configuration_sha256=runtime.configuration_sha256,
        context=context,source_action=action.document(),admitted_action=action.document(),support_actions=[support.document()])
    if expected_manifest is not None and canonical(expected_manifest)!=canonical(doc):
        raise ValueError('mixed-runtime-saved-manifest-mismatch')
    return PreparedRegisterProgram(case.source,case,canonical(doc))


def validate_external_manifest(manifest, configuration, *, expected_sha256=None):
    manifest=normalize_manifest_configuration(manifest,configuration,expected_sha256=expected_sha256)
    if (type(manifest) is not dict or set(manifest) != {'schema_version','request','configuration','context',
            'source_action','admitted_action','support_actions'}
            or manifest['schema_version'] != 'external_pin_runtime_manifest.v1'):
        raise ValueError('invalid mixed external manifest')
    request=validate_external_request(manifest['request'])
    declarations=validate_external_sources(configuration.get('external_sources', ()))
    matches=[d for d in declarations if d['source']['source_id']==request['source_id']]
    if len(matches)!=1:
        raise ValueError('invalid mixed external source')
    context=manifest['context']
    if (type(context) is not dict or set(context)!={'generation','reset_epoch','tracker_epoch','waiting_transaction',
            'command_epoch','waiting_instruction_address','target_reset_epoch'}
            or any(type(context[k]) is not int or context[k]<0 for k in context if k!='waiting_transaction')):
        raise ValueError('invalid mixed external context')
    transaction=context['waiting_transaction']
    if (type(transaction) is not dict or set(transaction)!=set(TransactionKey.__dataclass_fields__)
            or any(type(transaction[k]) is not str or not transaction[k] for k in
                   ('execution_id','testcase_id','source_component','channel_id'))
            or any(type(transaction[k]) is not int or transaction[k]<0 for k in ('source_epoch','source_sequence'))):
        raise ValueError('invalid mixed external waiting transaction')
    address=context['waiting_instruction_address'];size=4*matches[0]['support_words']
    if (address % 4 or not configuration['policy']['first_address']<=address
            or address+size>configuration['policy']['last_address']
            or not any(c==configuration['cpu_component'] and start<=address and address+size<=start+4*count
                       for c,start,count in configuration['slots'])):
        raise ValueError('invalid mixed external support slot')
    key=TransactionKey(**transaction)
    if key.source_component != configuration['cpu_component'] or key.source_epoch != context['reset_epoch']:
        raise ValueError('invalid mixed external waiting transaction')
    case=external_case(request,matches[0],context,configuration)
    action=external_actions(case,matches[0],configuration)
    if canonical(action.document())!=canonical(manifest['source_action']) or manifest['source_action']!=manifest['admitted_action']:
        raise ValueError('invalid mixed external action')
    if type(manifest['support_actions']) is not list or len(manifest['support_actions'])!=1:
        raise ValueError('invalid mixed external supports')
    expected_support=external_support_action(case,matches[0],configuration)
    if canonical(manifest['support_actions'])!=canonical([expected_support.document()]):
        raise ValueError('invalid mixed external fixed support')
    return request,case.source
