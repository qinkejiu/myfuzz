"""An additional control request must belong to the authenticated clear."""
from copy import deepcopy
from myfuzz.integration.compiled_f6_saved_semantics import _saved_clear_request


def world():
    case={'case_id':'c','case_index':0}
    key={'source_component':'cpu','source_epoch':0,'testcase_id':'native','execution_id':'local-execution','channel_id':'data','source_sequence':9}
    def row(i,kind,component,**kw):return dict(event_id=i,kind=kind,component=component,provenance={'observed_case':case},**kw)
    receipt=dict(source_transaction=key,address=256,offset=0,write=True,value=0x80000000,byte_enable=15,edge_ticks=[8,9,10])
    events=[row(1,'cpu_external_irq_taken','cpu',reset_epoch=0),
        row(2,'data_accept','cpu',transaction=key,address=256,write=1,wdata=0x80000000,be=15,acceptance_tick=5),
        row(3,'mmio_acceptance','cpu',source_transaction=key,address=256,write=True,byte_enable=15,write_value=0x80000000,device_id='d'),
        row(4,'mmio_delivery','cpu',source_transaction=key,address=256,write=True,byte_enable=15,write_value=0x80000000,device_id='d',dma_control_receipt=receipt),
        row(5,'data_response','cpu',transaction=key,address=256,write=1,wdata=0x80000000,be=15,error=0),
        row(6,'dma_edge','dma',tick=8,payload={'pre_backend':{'swb_cyc':1,'swb_stb':1,'swb_we':1,'swb_adr':0,'swb_dat_w':0x80000000,'swb_sel':15}}),
        row(7,'dma_edge','dma',tick=9,payload={'pre_backend':{'swb_ack':1}}),
        row(8,'dma_edge','dma',tick=10,payload={'pre_backend':{'swb_cyc':0,'swb_stb':0}})]
    events.append(row(9,'local_tick_sample','cpu',phase='pre',local_tick=5,outputs={'backend':{'d_req_valid':1,'d_req_ready':1,'d_req_write':1,'d_req_addr':256,'d_req_be':15,'d_req_wdata':0x80000000}}))
    contract={'control':{'base':256,'device_id':'d'},'dma':{'behavior':{'irq_clear':{'method':'write','offset':0,'value':0x80000000,'byte_enable':15}}}}
    return contract,events,case


def test_only_actual_distinct_clear_receipt_owns_extra_request():
    contract,events,case=world()
    assert _saved_clear_request(contract,events,case,'cpu','dma',dma_tick=8)
    assert _saved_clear_request(contract,events,case,'cpu','dma',cpu_tick=5)
    assert not _saved_clear_request(contract,events,case,'cpu','dma',dma_tick=11)
    for change in (lambda x:x[3]['dma_control_receipt'].__setitem__('edge_ticks',[9,10,11]),
                   lambda x:x[1].__setitem__('wdata',7),
                   lambda x:x.append(deepcopy(x[5])),
                   lambda x:x.pop(4)):
        broken=deepcopy(events);change(broken)
        assert not _saved_clear_request(contract,broken,case,'cpu','dma',dma_tick=8)
