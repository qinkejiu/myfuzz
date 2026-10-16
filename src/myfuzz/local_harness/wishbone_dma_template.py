"""Explicit dual-role Wishbone DMA admission; ordinary register policy stays strict."""
from .wishbone_dma_fields import DMA_CONTROL_SHAPE, DMA_MASTER_SHAPE
from .template_contracts import select_template_contract


def dma_edge_policy(plan, abi=None):
    c = plan.profile.capabilities
    if (plan.profile.kind != 'peripheral' or
            c.get('local_runtime_variant') != 'wishbone_dma_edge_v1' or
            (c.get('address_width'), c.get('data_width'), c.get('master_address_width'),
             c.get('byte_enable'), c.get('partial_write'), c.get('has_error'),
             c.get('master_has_error'), c.get('address_units'),
             c.get('master_address_units'), c.get('master_fixed_byte_enable')) !=
            (2,32,30,False,False,False,True,'word','word',15)):
        raise ValueError('dma-edge-capabilities-unsupported')
    if plan.profile.address is None or plan.profile.address.window_size != 16:
        raise ValueError('dma-control-window-unsupported')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    targets = [e for e in endpoints if e.function == 'mmio_slave']
    masters = [e for e in endpoints if e.function == 'memory_master']
    if len(endpoints)!=2 or len(targets)!=1 or len(masters)!=1:
        raise ValueError('dma-dual-endpoint-required')
    target, master = targets[0], masters[0]
    for endpoint, shape in ((target,DMA_CONTROL_SHAPE),(master,DMA_MASTER_SHAPE)):
        if endpoint.protocol != ('wishbone','pipelined') or {
                f.role:(f.direction,f.width) for f in endpoint.fields} != shape:
            raise ValueError('dma-endpoint-shape-unsupported')
    irqs = [f for e in plan.binding.endpoints if e.protocol is None
            and e.function == 'interrupt_source' for f in e.fields]
    owned = [r for r in plan.dispositions if r.direction == 'input'
             and r.endpoint_id not in {target.endpoint_id, master.endpoint_id}
             and r.role not in ('clock', 'reset')]
    if (len(owned)!=1 or owned[0].disposition!='constant' or owned[0].value!=0
            or owned[0].width!=32 or owned[0].bit_lo!=0 or owned[0].bit_hi!=31):
        raise ValueError('dma-trigger-must-be-fixed-zero')
    if len(irqs)!=1 or (irqs[0].role,irqs[0].direction,irqs[0].width)!=('irq','output',1):
        raise ValueError('dma-native-irq-required')
    permitted = {target.endpoint_id,master.endpoint_id,irqs[0].endpoint_id}
    if {e.endpoint_id for e in plan.binding.endpoints} != permitted:
        raise ValueError('dma-extra-endpoint-unsupported')
    if abi is not None:
        nonbus = [r for r in abi if r['endpoint_id'] not in {target.endpoint_id,master.endpoint_id}]
        if len(nonbus)!=1 or (nonbus[0]['endpoint_id'],nonbus[0]['role'],nonbus[0]['direction'],nonbus[0]['width']) != (irqs[0].endpoint_id,'irq','output',1):
            raise ValueError('dma-nonbus-ownership-unsupported')
    contracts = []
    for endpoint, side, has_error, width in ((target,'target',False,2),(master,'master',True,30)):
        capabilities = {**c,'address_width':width,'has_error':has_error}
        contracts.append(select_template_contract(endpoint, capabilities,
            template_id=side+'.wishbone-pipelined',template_version='1',
            variant_id='dma-full-word-no-select').document())
    return target, master, irqs[0], contracts
