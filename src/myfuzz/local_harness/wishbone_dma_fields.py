"""Fixed Slice B edge transport; addresses remain physical Wishbone words."""

DMA_CONTROL_SHAPE = {role: (direction, width) for role, direction, width in (
    ('cyc','input',1), ('stb','input',1), ('we','input',1), ('adr','input',2),
    ('dat_w','input',32), ('stall','output',1), ('ack','output',1), ('dat_r','output',32))}
DMA_MASTER_SHAPE = {role: (direction, width) for role, direction, width in (
    ('cyc','output',1), ('stb','output',1), ('we','output',1), ('adr','output',30),
    ('dat_w','output',32), ('stall','input',1), ('ack','input',1), ('dat_r','input',32), ('err','input',1))}
DMA_STEP_PORTS = ('swb_cyc','swb_stb','swb_we','swb_adr','swb_dat_w',
                  'mwb_stall','mwb_ack','mwb_dat_r','mwb_err')
DMA_STEP_MAXIMA = (1, 1, 1, 3, 0xffffffff, 1, 1, 0xffffffff, 1)


def dma_edge_contract():
    return {'schema_version':'wishbone_dma_edge.v1', 'operation':'STEP_WB_DMA',
        'input_order':list(DMA_STEP_PORTS), 'input_maxima':list(DMA_STEP_MAXIMA),
        'local_edges':1, 'master_address_units':'word', 'master_address_shift':2,
        'master_fixed_byte_enable':15, 'environment_max_outstanding':1,
        'request_acceptance':'cyc && stb && !stall before edge',
        'response_completion':'cyc && (ack || err) before edge',
        'same_edge_accept_and_complete':False,
        'completion_edge_policy':'stall new acceptance while delivering prior response',
        'control_address_units':'word_index', 'control_byte_offsets':[0,4,8,12],
        'partial_control_writes':False, 'runtime_scope':'edge_transport_only_no_memory_service'}
