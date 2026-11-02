from myfuzz.integration.custom_irq_observations import project_custom_irq_events


def test_custom_irq_projection_keeps_actual_facts_without_inferred_completion():
    events=[
        {'event_id':1,'component':'dma','kind':'dma_edge','accepted':
            {'address':0x200,'write':False,'value':0,'byte_enable':15,'transaction':{'source_sequence':1}},
         'payload':{'observations':{'physical':{'dma_irq':1}}}},
        {'event_id':2,'component':'dma','kind':'memory_write_commit',
         'transaction':{'source_sequence':2},'commit_id':'actual-commit'},
        {'event_id':7,'component':'dma','kind':'memory_read',
         'transaction':{'channel_id':'dma-memory','source_sequence':1},'address':0x200,
         'width_bytes':4,'memory_id':'ram','generation':1,'byte_offset':0x200,
         'value':0x1234,'data_hex':'34120000','versions':(3,3,3,3),
         'writer_event_ids':('writer',)*4,'writer_kinds':('cpu',)*4},
        {'event_id':3,'component':'gpio','kind':'gpio_input_applied','status':'observed',
         'actual_input_value':256,'requested_input_value':256,'local_tick':4},
        {'event_id':4,'component':'gpio','kind':'local_tick_sample','phase':'post',
         'outputs':{'physical':{'gpio_irq':1}}},
        {'event_id':5,'component':'cpu','outputs':{'custom_irq_observation':
         {'irq_pre':24,'irq_post':24,'eoi_pre':0,'eoi_post':16}}},
        {'event_id':6,'kind':'dataflow_delivery','source':('gpio','interrupt'),
         'target':('cpu','irq'),'value':1,'target_bit_offset':4},
    ]
    result=project_custom_irq_events(events,cpu_id='cpu',dma_id='dma',dma_irq_name='dma_irq',
        dma_irq_bit=3,gpio_id='gpio',gpio_irq_name='gpio_irq',gpio_irq_port='interrupt',gpio_irq_bit=4)
    assert result['facts']['dma_requests'][0]['address']==0x200
    assert result['facts']['dma_memory_writes'][0]['commit_id']=='actual-commit'
    read,=result['facts']['dma_memory_reads']
    assert read['kind']=='memory_read' and read['address']==0x200 and read['value']==0x1234
    assert read['transaction']=={'channel_id':'dma-memory','source_sequence':1}
    assert read['versions']==(3,3,3,3) and read['writer_event_ids']==('writer',)*4
    assert result['facts']['gpio_input_samples'][0]['actual_input_value']==256
    assert result['first_high_samples']['gpio_irq_high']['event_id']==4
    assert result['first_high_samples']['cpu_gpio_eoi_high']['event_id']==5
    assert result['first_high_samples']['cpu_dma_eoi_high'] is None
    assert result['facts']['irq_deliveries'][0]['target_bit_offset']==4
    assert result['source_attribution']==result['retirement']==result['transfer_completion']=='unknown'
    assert result['certificate']=='not_granted' and not result['reward_eligible']


def test_custom_irq_projection_bounds_records_and_keeps_counts():
    events=[{'event_id':i,'component':'dma','kind':'dma_edge',
             'accepted':{'address':i,'write':True},'payload':{}} for i in range(5)]
    result=project_custom_irq_events(events,cpu_id='cpu',dma_id='dma',dma_irq_name='irq',
                                      dma_irq_bit=3,limit=2)
    assert len(result['facts']['dma_requests'])==2
    assert result['counts']['dma_requests']==5 and result['truncated']['dma_requests']
    assert result['first_high_samples']['dma_irq_high'] is None
    assert result['counts']['dma_memory_reads']==0 and result['facts']['dma_memory_reads']==[]


def test_shared_projection_includes_case_scoped_cpu_bus_facts():
    events=[{'event_id':1,'component':'cpu','outputs':{'data_req_accepted':1,
        'driver_samples':[{'pre':{'wb_cyc':1},'post':{'wb_ack':0}}]}}]
    result=project_custom_irq_events(events,cpu_id='cpu',dma_id='dma',dma_irq_name='irq',
        dma_irq_bit=3,flow='F4')
    cpu=result['cpu_case']
    assert cpu['facts']['wishbone_samples'][0]['event_id']==1
    assert cpu['retirement']=='unknown' and cpu['certificate']=='not_granted'
