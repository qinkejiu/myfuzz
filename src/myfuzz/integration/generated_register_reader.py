"""F2 RV32I load and dependent RAM store; grants no native proof."""
from hashlib import sha256
import json

from myfuzz.scenario.register_source_access import validate_register_candidate
from myfuzz.scenario.rv32i_sources import Rv32iInstruction, fragment_bytes, _split_address
from .compiled_f2_layout import compile_f2_candidate_layout

XOR_CONSTANT = 0x5a5


def declare_reader(request, compiled, *, source_id, address, result_address):
    paths=[p for p in compiled['paths'] if p.get('flow_id')=='F2' and
           p.get('status')=='executable' and any(s.get('source_id')==source_id
           for s in p.get('sources',[]))]
    if len(paths)!=1:
        raise ValueError('generated-reader-F2-source-missing')
    path=paths[0]; layout=compile_f2_candidate_layout(path)
    contract=path['execution_contract']
    if source_id!=contract['load_source_id']:
        raise ValueError('generated-reader-source-owner-mismatch')
    candidate=validate_register_candidate(request,compiled,source_id=source_id,
        source_component=contract['source_component'],source_endpoint=contract['source_endpoint'],
        target_component=contract['target_component'],address=address,
        write=False,value=0,byte_enable=15)
    cpu=request.component(contract['source_component']).profile.cpu
    # The fragment is plain RV32I bytes: every opcode it uses (LUI/ADDI/LW/
    # XORI/SW/NOP) has the same encoding and the same register-width effect
    # on an RV64 core, where ``LW``/``SW`` still move exactly 32 bits.  A
    # 64-bit core is therefore admissible; nothing here widens the fragment.
    if cpu is None or cpu.xlen not in (32,64) or 'I' not in {e.upper() for e in cpu.extensions}:
        raise ValueError('generated-reader-RV32I-required')
    if type(result_address) is not int or not 0<=result_address<=0xfffffffc or result_address%4:
        raise ValueError('generated-reader-result-address-invalid')
    resources=[r for r in request.wiring.resources if r.component_instance==contract['source_component']
        and r.write is True and r.base is not None and r.size is not None
        and r.base<=result_address and result_address+4<=r.base+r.size]
    if len(resources)!=1:
        raise ValueError('generated-reader-result-RAM-undeclared')
    if any(result_address<w.base+w.size and w.base<result_address+4 for w in request.wiring.windows):
        raise ValueError('generated-reader-result-overlaps-MMIO')
    high,low=_split_address(address); result_high,result_low=_split_address(result_address)
    code=fragment_bytes((Rv32iInstruction('LUI',rd=1,immediate=high),
        Rv32iInstruction('ADDI',rd=1,rs1=1,immediate=low),
        Rv32iInstruction('LW',rd=3,rs1=1),
        Rv32iInstruction('XORI',rd=3,rs1=3,immediate=XOR_CONSTANT),
        Rv32iInstruction('LUI',rd=4,immediate=result_high),
        Rv32iInstruction('ADDI',rd=4,rs1=4,immediate=result_low),
        Rv32iInstruction('SW',rs1=4,rs2=3),
        *(Rv32iInstruction('NOP') for _ in range(4))))
    source=next(s for s in path['sources'] if s['source_id']==source_id)
    canonical=lambda doc:json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return dict(schema_version='generated_register_reader.v1',candidate=candidate,
        source_id=source_id,instruction_source_id=contract['instruction_source_id'],
        address=address,result_address=result_address,xor_constant=XOR_CONSTANT,
        code_hex=code.hex(),code_sha256=sha256(code).hexdigest(),
        source_sha256=sha256(canonical(source)).hexdigest(),
        compiled_sha256=sha256(canonical(compiled)).hexdigest(),layout_digest=layout.digest,
        functional_offsets={'load':8,'xor':12,'store':24},
        required_instruction_span_bytes=len(code),required_result_span_bytes=4,runtime_admitted=False)
