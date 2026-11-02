"""Explicit dual-role Wishbone DMA admission; ordinary register policy stays strict."""
from .wishbone_dma_fields import (DMA_CONTROL_SHAPE, DMA_MASTER_SHAPE,
    DMA_SELECTED_CONTROL_SHAPE, DMA_SELECTED_MASTER_SHAPE, dma_control_shape, dma_select_modes)
from .template_contracts import select_template_contract


def dma_edge_policy(plan, abi=None):
    c = plan.profile.capabilities
    control_selected, master_selected = dma_select_modes(c)
    control_width=c.get('address_width')
    if (plan.profile.kind != 'peripheral' or
            type(control_width) is not int or not 2 <= control_width <= 30 or
            (c.get('data_width'), c.get('master_address_width'),
             c.get('byte_enable'), c.get('partial_write'), c.get('has_error'),
             c.get('master_has_error'), c.get('address_units'),
             c.get('master_address_units'), c.get('master_fixed_byte_enable')) !=
            (32,30,control_selected,control_selected,False,True,'word','word',None if master_selected else 15)
            or c.get('master_byte_enable', master_selected) is not master_selected):
        raise ValueError('dma-edge-capabilities-unsupported')
    if (plan.profile.address is None or not 16 <= plan.profile.address.window_size <= (1 << control_width)*4):
        raise ValueError('dma-control-window-unsupported')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    targets = [e for e in endpoints if e.function == 'mmio_slave']
    masters = [e for e in endpoints if e.function == 'memory_master']
    if len(endpoints)!=2 or len(targets)!=1 or len(masters)!=1:
        raise ValueError('dma-dual-endpoint-required')
    target, master = targets[0], masters[0]
    for endpoint, shape in ((target,dma_control_shape(control_width,selected=control_selected)),
                            (master,DMA_SELECTED_MASTER_SHAPE if master_selected else DMA_MASTER_SHAPE)):
        if endpoint.protocol != ('wishbone','pipelined') or {
                f.role:(f.direction,f.width) for f in endpoint.fields} != shape:
            raise ValueError('dma-endpoint-shape-unsupported')
    irqs = [f for e in plan.binding.endpoints if e.protocol is None
            and e.function == 'interrupt_source' for f in e.fields]
    owned = [r for r in plan.dispositions if r.direction == 'input'
             and r.endpoint_id not in {target.endpoint_id, master.endpoint_id}
             and r.role not in ('clock', 'reset')]
    if any(r.disposition != 'constant' or r.target != 'const'
            or type(r.value) is not int or r.bit_lo < 0 or r.bit_hi < r.bit_lo
            or r.bit_hi >= r.width or not 0 <= r.value < (1 << (r.bit_hi-r.bit_lo+1))
            for r in owned):
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
    for endpoint, side, has_error, width in ((target,'target',False,control_width),(master,'master',True,30)):
        capabilities = {**c,'address_width':width,'has_error':has_error}
        selected = control_selected if side == 'target' else master_selected
        capabilities.update(byte_enable=selected,partial_write=selected)
        contracts.append(select_template_contract(endpoint, capabilities,
            template_id=side+'.wishbone-pipelined',template_version='1',
            variant_id='dma-selected' if selected else 'dma-full-word-no-select').document())
    return target, master, irqs[0], contracts
