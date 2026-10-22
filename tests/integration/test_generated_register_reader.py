"""Generated F2 load has no peripheral setup write."""
from copy import deepcopy
import pytest
from myfuzz.integration.generated_register_reader import declare_reader
from tests.integration.test_compiled_f2_layout import f2_inputs,f2_path

def reader(inputs,path,**changes):
    c=path['execution_contract']
    return declare_reader(inputs['request'],inputs['compiled'],source_id=c['load_source_id'],
                          address=c['address'],result_address=changes.get('result_address',0x30000))

def test_native_load_xor_dependent_store(f2_inputs,f2_path):
    d=reader(f2_inputs,f2_path)
    words=[int.from_bytes(bytes.fromhex(d['code_hex'])[i:i+4],'little') for i in range(0,len(bytes.fromhex(d['code_hex'])),4)]
    assert [w&127 for w in words[:7]]==[0x37,0x13,0x03,0x13,0x37,0x13,0x23]
    assert sum(w&127==0x23 for w in words)==1
    assert (words[2]>>7)&31==3
    assert (words[3]>>20)==0x5a5 and (words[3]>>15)&31==3
    assert d['functional_offsets']=={'load':8,'xor':12,'store':24}
    assert d['required_instruction_span_bytes']==len(words)*4
    assert d['candidate']['value']==0 and d['candidate']['access']['operation']=='read'

@pytest.mark.parametrize('address',[True,1,0x40001000,0xffffffff])
def test_result_storage_refusal(f2_inputs,f2_path,address):
    with pytest.raises(ValueError):reader(f2_inputs,f2_path,result_address=address)

def test_changed_compiled_document_refuses(f2_inputs,f2_path):
    inputs=dict(f2_inputs,compiled=deepcopy(f2_inputs['compiled']))
    inputs['compiled']['paths'][0]['status']='tampered'
    with pytest.raises(ValueError): reader(inputs,f2_path)
