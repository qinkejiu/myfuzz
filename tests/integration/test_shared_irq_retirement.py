from copy import deepcopy
import pytest


def witness():
    code=b''.join(i.to_bytes(4,'little') for i in (19,23,27,31))
    document={'entry_address':0x100,'stages':{'dma_dispatch_path':[0x100,0x108],
        'dma':{'address':0x10c}}}
    rows=[dict(pc=pc,instruction=int.from_bytes(code[pc-0x100:pc-0x100+4],'little'),
        rvfi_order=i+3,receipt_id={'execution':'a','sequence':i+8})
        for i,pc in enumerate((0x100,0x108,0x10c))]
    return document,code,rows


def test_dma_dispatch_requires_actual_branch_and_child_entry():
    from myfuzz.integration.shared_irq_retirement import validate_dma_dispatch_retirements
    doc,code,rows=witness()
    assert validate_dma_dispatch_retirements(doc,code,rows) is None


@pytest.mark.parametrize('mutation', ['skip','gpio','instruction','order','receipt','short_bytes'])
def test_dma_dispatch_rejects_missing_or_diverted_retirement(mutation):
    from myfuzz.integration.shared_irq_retirement import validate_dma_dispatch_retirements
    doc,code,rows=witness()
    if mutation=='skip':rows.pop(1)
    elif mutation=='gpio':rows[-1]['pc']=0x200
    elif mutation=='instruction':rows[1]['instruction']^=1
    elif mutation=='order':rows[1]['rvfi_order']+=1
    elif mutation=='receipt':rows[1]['receipt_id']['execution']='b'
    elif mutation=='short_bytes':code=code[:8]
    with pytest.raises(ValueError):validate_dma_dispatch_retirements(doc,code,rows)
