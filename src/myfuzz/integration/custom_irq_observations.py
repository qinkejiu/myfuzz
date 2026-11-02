"""Bounded projections of actual shared-session events; never grant certificates."""
from copy import deepcopy


def project_custom_irq_events(events, *, cpu_id, dma_id, dma_irq_name, dma_irq_bit,
                              gpio_id=None, gpio_irq_name=None, gpio_irq_port=None,
                              gpio_irq_bit=None, limit=32, transfer_contract=None, transfer_words=None,
                              flow=None):
    """Read one case's receipt once and retain compact measured event facts.

    A high IRQ or EOI is an electrical observation only, not proof of its
    cause, instruction retirement, handler completion, or a DMA transfer.
    """
    if type(limit) is not int or not 1<=limit<=256:
        raise ValueError('custom-observation-limit')
    names=('dma_requests','dma_responses','dma_memory_reads','dma_memory_writes',
           'irq_deliveries','gpio_input_samples')
    rows={name:[] for name in names}; counts={name:0 for name in names}
    first={'dma_irq_high':None,'gpio_irq_high':None,
           'cpu_dma_irq_high':None,'cpu_dma_eoi_high':None,
           'cpu_gpio_irq_high':None,'cpu_gpio_eoi_high':None}
    join=None
    if transfer_contract is not None:
        from .custom_dma_observed_join import CustomDmaObservedJoin
        join=CustomDmaObservedJoin(cpu_id=cpu_id,dma_id=dma_id,
            contract=transfer_contract,words=transfer_words)
    cpu_observer=None
    if flow in ('F1','F2','F3','F4'):
        from .custom_cpu_observations import CustomCpuCaseObserver
        cpu_observer=CustomCpuCaseObserver(cpu_id=cpu_id,flow=flow,limit=limit)
    gpio_observer=None
    if flow=='F5' and gpio_id is not None and type(gpio_irq_bit) is int:
        from .custom_gpio_irq_evidence import CustomGpioIrqObserver
        gpio_observer=CustomGpioIrqObserver(cpu_id=cpu_id,gpio_id=gpio_id,
            gpio_irq_port=gpio_irq_port,gpio_irq_name=gpio_irq_name,gpio_irq_bit=gpio_irq_bit)
    def add(name,row):
        counts[name]+=1
        if len(rows[name])<limit:
            rows[name].append(row)
    def sample(name,event,**facts):
        if first[name] is None:
            first[name]=dict(event_id=event.get('event_id'),component=event.get('component'),
                local_tick=event.get('local_tick',event.get('tick')),phase=event.get('phase'),**facts)
    for event in events:
        if join is not None:join.observe(event)
        if cpu_observer is not None:cpu_observer.observe(event)
        if gpio_observer is not None:gpio_observer.observe(event)
        if type(event) is not dict:continue
        kind=event.get('kind');component=event.get('component');event_id=event.get('event_id')
        if component==dma_id and kind=='dma_edge':
            accepted=event.get('accepted')
            if type(accepted) is dict:
                add('dma_requests',dict(event_id=event_id,**{k:deepcopy(accepted.get(k))
                    for k in ('address','write','value','byte_enable','transaction')}))
            response=event.get('response')
            if type(response) is dict:
                add('dma_responses',dict(event_id=event_id,**{k:deepcopy(response.get(k))
                    for k in ('transaction','rdata','error')}))
            physical=event.get('payload',{}).get('observations',{}).get('physical',{})
            if physical.get(dma_irq_name)==1:sample('dma_irq_high',event,port=dma_irq_name,value=1)
        if component==dma_id and kind in ('memory_read','memory_read_issuance','memory_write_commit'):
            target='dma_memory_writes' if kind=='memory_write_commit' else 'dma_memory_reads'
            fact=dict(event_id=event_id,kind=kind,
                transaction=deepcopy(event.get('transaction',event.get('fullkey'))))
            if kind=='memory_read':
                fact.update({key:deepcopy(event[key]) for key in
                    ('address','width_bytes','memory_id','generation','byte_offset','value',
                     'data_hex','versions','writer_event_ids','writer_kinds') if key in event})
            elif kind=='memory_write_commit':
                fact['commit_id']=event.get('commit_id')
            add(target,fact)
        if kind in ('dataflow_delivery','source_start','pulse_start','cpu_irq_input'):
            source=event.get('source');target=event.get('target')
            if source in ((dma_id,'irq'),(gpio_id,gpio_irq_port)) and target==(cpu_id,'irq'):
                add('irq_deliveries',{k:deepcopy(event.get(k)) for k in
                    ('event_id','kind','source','target','value','target_bit_offset','cpu_tick','producer_event_id')})
        if gpio_id is not None and component==gpio_id:
            if kind=='gpio_input_applied':
                add('gpio_input_samples',{k:deepcopy(event.get(k)) for k in
                    ('event_id','status','local_tick','actual_input_value','requested_input_value')})
            if kind=='local_tick_sample':
                physical=event.get('outputs',{}).get('physical',{})
                if physical.get(gpio_irq_name)==1:sample('gpio_irq_high',event,port=gpio_irq_name,value=1)
        if component==cpu_id:
            observation=event.get('outputs',{}).get('custom_irq_observation')
            if type(observation) is dict:
                for prefix,bit in (('dma',dma_irq_bit),('gpio',gpio_irq_bit)):
                    if type(bit) is not int:continue
                    for kind_name in ('irq','eoi'):
                        if any(type(observation.get(kind_name+'_'+phase)) is int and
                               observation[kind_name+'_'+phase] & (1<<bit) for phase in ('pre','post')):
                            sample('cpu_'+prefix+'_'+kind_name+'_high',event,bit=bit,
                                pre=observation.get(kind_name+'_pre'),post=observation.get(kind_name+'_post'))
    result=dict(schema_version='custom_irq_case_observations.v1',facts=rows,counts=counts,
        first_high_samples=first,truncated={name:counts[name]>limit for name in names},
        scope='raw_events_in_case_interval',source_attribution='unknown',retirement='unknown',
        transfer_completion='unknown',certificate='not_granted',reward_eligible=False)
    if join is not None:result['dma_word_consistency']=join.finish()
    if cpu_observer is not None:result['cpu_case']=cpu_observer.result
    if gpio_observer is not None:result['gpio_irq_chain']=gpio_observer.result
    return result
