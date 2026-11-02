from copy import deepcopy
from myfuzz.integration.custom_irq_observations import project_custom_irq_events


def _events():
    result=[]
    def key(component,channel,seq):
        return dict(execution_id='e',testcase_id='t',source_component=component,
                    source_epoch=0,channel_id=channel,source_sequence=seq)
    def commit(component,key,offset,value,version):
        cells=[dict(byte_offset=offset+i,value=value>>(8*i)&255,version=[0,version],
                    writer_event_id=str(key),writer_kind='STORE') for i in range(4)]
        return dict(component=component,kind='memory_write_commit',transaction=key,
            commit_document=dict(fullkey=key,memory_id='ram',byte_offset=offset,generation=0,
                width_bytes=4,byte_enable=15,version=[0,version],enabled_byte_cells=cells,
                commit_status='complete',performed_effect=True))
    for i in range(4):
        value=i+1;source=key('cpu','data',i+1);read=key('dma','dma-memory',i+1);write=key('dma','dma-memory',i+5)
        result.extend([commit('cpu',source,0x100+4*i,value,i+1),
          dict(component='dma',kind='dma_edge',accepted=dict(address=0x100+4*i,write=False,byte_enable=15,transaction=read)),
          dict(component='dma',kind='memory_read',transaction=read,address=0x100+4*i,width_bytes=4,
               memory_id='ram',generation=0,value=value,data_hex=value.to_bytes(4,'little').hex(),
               versions=([0,i+1],)*4,writer_event_ids=(str(source),)*4),
          dict(component='dma',kind='dma_edge',response=dict(transaction=read,error=0,rdata=value)),
          dict(component='dma',kind='dma_edge',accepted=dict(address=0x200+4*i,write=True,value=value,byte_enable=15,transaction=write)),
          commit('dma',write,0x200+4*i,value,i+10),
          dict(component='dma',kind='dma_edge',response=dict(transaction=write,error=0,rdata=0))])
    for i,event in enumerate(result):event['event_id']=i+1
    return result


def _project(events):
    contract=dict(program_contract=dict(source_address=0x100,destination_address=0x200),
                  memory=dict(resource=dict(resource_id='ram',base=0)))
    return project_custom_irq_events(events,cpu_id='cpu',dma_id='dma',dma_irq_name='irq',
        dma_irq_bit=3,transfer_contract=contract,transfer_words=(1,2,3,4))['dma_word_consistency']


def test_word_join_correlates_actual_transaction_and_versions_without_certification():
    result=_project(_events())
    assert result['status']=='observed_consistent'
    assert len(result['words'])==4 and result['words'][0]['event_refs']['memory_read']==3
    assert result['live_issuance']=='not_verified' and result['irq_causality']=='unknown'
    assert result['transfer_certificate']=='not_granted' and result['reward_eligible'] is False


def test_missing_and_contradictory_byte_versions_never_grant_consistency():
    events=_events();del events[2]
    assert _project(events)['words'][0]['status']=='unknown'
    events=_events();events[2]['versions']=([0,99],)*4
    result=_project(events)
    assert result['status']=='unknown' and result['words'][0]['status']=='inconsistent'
    events=_events();events.append(deepcopy(events[2]))
    assert _project(events)['words'][0]['status']=='unknown'
