"""Pure F2 online material validation. Saved bytes confer no native authority."""
from hashlib import sha256
import json

from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
from myfuzz.integration.generated_register_reader import XOR_CONSTANT
from myfuzz.scenario.f2_read_contract import validate_f2_read_contract
from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
from myfuzz.scenario.session_runtime import BoundOnlineInstruction
from myfuzz.scenario.rv32i_sources import Rv32iInstruction,fragment_bytes,_split_address


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode()


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _require(condition,code):
    if not condition:raise ValueError('compiled-F2-online-material-'+code)


def _reader_code(address,result):
    """The admitted generated reader, using the existing RV32I encoder/constants."""
    high,low=_split_address(address);result_high,result_low=_split_address(result)
    return fragment_bytes((Rv32iInstruction('LUI',rd=1,immediate=high),
        Rv32iInstruction('ADDI',rd=1,rs1=1,immediate=low),Rv32iInstruction('LW',rd=3,rs1=1),
        Rv32iInstruction('XORI',rd=3,rs1=3,immediate=XOR_CONSTANT),
        Rv32iInstruction('LUI',rd=4,immediate=result_high),
        Rv32iInstruction('ADDI',rd=4,rs1=4,immediate=result_low),Rv32iInstruction('SW',rs1=4,rs2=3),
        *(Rv32iInstruction('NOP') for _ in range(4)))).hex()


def verify_f2_instruction_image_material(decoder,manifest,plan):
    """Join F2 logical/layout identities to prepared binding and actual plan bytes."""
    try:_verify(decoder,manifest,plan)
    except (KeyError,TypeError,StopIteration,AttributeError) as error:
        raise ValueError('compiled-F2-online-material-shape') from error


def _verify(decoder,manifest,plan):
    _require(type(decoder) is dict and decoder.get('schema_version')=='compiled_F2_decoder.v1'
        and decoder.get('flow_id')=='F2','decoder-schema')
    admission=decoder.get('runtime_path_admission')
    _require(type(admission) is dict and admission.get('schema_version')=='compiled_F2_runtime_path_admission.v1','admission-schema')
    _require(_digest({k:v for k,v in admission.items() if k!='binding_sha256'})==admission.get('binding_sha256'),'admission-digest')
    prepared=PreparedRuntimePathContract.from_document(admission['prepared'])
    selected=admission['selected_path'];contract=validate_f2_read_contract(selected)
    layout=compile_f2_candidate_layout(selected)
    binding=InstructionImageSourceBinding.from_document(admission['source_binding'])
    binding.validate_prepared(prepared)
    images=[row for row in selected['sources'] if row['kind']=='instruction_image']
    streams=[row for row in selected['sources'] if row['kind']=='cpu_load_stream']
    _require(len(images)==1 and len(streams)==1 and len(selected['sources'])==2,'source-shape')
    image,stream=images[0],streams[0]
    _require(selected.get('flow_id')=='F2' and selected.get('status')=='executable','selected-F2')
    _require(_digest(selected)==admission.get('selected_path_sha256')
        and _digest(image)==admission.get('instruction_image_sha256')
        and _digest(stream)==admission.get('cpu_load_stream_sha256'),'selected-source-digests')
    _require(admission.get('instruction_image')==image and admission.get('cpu_load_stream')==stream
        and admission.get('execution_contract')==contract,'admitted-source-crosswalk')
    _require(decoder.get('path_id')==selected['path_id']
        and decoder.get('source_id')==stream['source_id']
        and decoder.get('instruction_source_id')==image['source_id']==binding.logical_source_id
        and decoder.get('direction')==selected['direction']==binding.direction
        and decoder.get('address')==contract['address'] and decoder.get('register')==contract['register'],'decoder-source-crosswalk')
    _require((image['component'],image['port'],image['range'],image['width'])==
        (binding.component,binding.memory_id,[binding.base,binding.base+binding.size-1],binding.size*8),'image-range')
    _require(decoder.get('candidate_layout')==layout.document() and decoder.get('candidate_layout_sha256')==layout.digest
        and decoder.get('candidate_bytes')==layout.byte_length==4
        and decoder.get('wire_record_bytes')==decoder.get('max_input_bytes')==8
        and decoder.get('unbound_wire_bytes')==4 and decoder.get('max_records')==8,'decoder-layout')
    result=decoder.get('result_address')
    _require(type(result) is int and result%4==0 and binding.base<=result<=binding.base+binding.size-4
        and decoder.get('instruction_address_range')==[binding.base,result],'result-range')
    declaration=prepared.document();selection=declaration['selections'][0]
    expected_identity={key:selection[key] for key in ('direction','path_id','source_ids','edges')}
    target=next(node for node in prepared.contract.nodes if node.node_id==selection['target'])
    _require(prepared.path_ids==(binding.path_id,)
        and selected['runtime_path_identity']==expected_identity==admission.get('runtime_path_identity')
        and selected['target']=={'node':selection['target'],'component':target.component}
        and admission.get('path_mapping')=={'logical_path_id':decoder['path_id'],'runtime_path_id':binding.path_id},'runtime-selection')
    _require(admission.get('compiled_document_sha256')==decoder.get('compiled_sha256')
        and admission.get('graph_sha256')==prepared.contract.graph_sha256
        and admission.get('contract_sha256')==prepared.contract.identity_sha256
        and decoder.get('graph')==prepared.graph.edge_document()
        and decoder.get('runtime_contract')==prepared.contract.document()
        and decoder.get('path_mapping')==declaration['selections'],'runtime-contract')
    expected_bindings=[binding.document()]
    _require(decoder.get('instruction_image_bindings')==expected_bindings
        and manifest.get('instruction_image_bindings')==expected_bindings
        and plan.get('instruction_image_bindings')==expected_bindings,'session-bindings')
    _require(manifest.get('runtime_paths',{}).get('declaration')==declaration
        and plan.get('runtime_paths')==manifest.get('runtime_paths')
        and type(plan.get('schema_version')) is int and plan['schema_version'] in (24,25),'session-plan')
    code=_reader_code(contract['address'],result)
    case_ids=set()
    for case in plan.get('cases',()):
        raw=case.get('source')
        _require(case.get('case_id') not in case_ids and type(case.get('case_id')) is str,'case-identity')
        case_ids.add(case['case_id'])
        _require(case.get('path_id')==binding.path_id and case.get('direction')==binding.direction
            and type(raw) is dict and raw.get('kind')=='bound_instruction'
            and set(raw)=={'kind','source_id','action_id','component','address','data_hex'},'case-source')
        source=BoundOnlineInstruction(**{k:v for k,v in raw.items() if k!='kind'})
        binding.validate_instruction(source,instruction_slots=plan.get('instruction_slots'))
        _require(source.data_hex==code and source.address+len(source.data)<=result,'case-program')
