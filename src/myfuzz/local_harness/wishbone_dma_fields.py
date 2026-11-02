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
DMA_SELECTED_CONTROL_SHAPE = {**DMA_CONTROL_SHAPE, 'sel': ('input', 4)}
DMA_SELECTED_MASTER_SHAPE = {**DMA_MASTER_SHAPE, 'sel': ('output', 4)}
DMA_SELECTED_STEP_PORTS = (*DMA_STEP_PORTS[:5], 'swb_sel', *DMA_STEP_PORTS[5:])
DMA_SELECTED_STEP_MAXIMA = (*DMA_STEP_MAXIMA[:5], 15, *DMA_STEP_MAXIMA[5:])


def dma_select_modes(capabilities):
    modes = {
        'wishbone_dma_edge_v1': (False, False),
        'wishbone_dma_selected_edge_v1': (True, True),
        'wishbone_dma_control_selected_edge_v1': (True, False),
        'wishbone_dma_master_selected_edge_v1': (False, True),
    }
    try:
        return modes[capabilities.get('local_runtime_variant')]
    except KeyError:
        raise ValueError('dma-edge-capabilities-unsupported') from None


#: The master address shifts a 32-bit byte-addressed CSR can declare onto a
#: word-addressed Wishbone master.  The value is a profile capability fact
#: (``master_address_shift``); the pinned DMA sources declare 2, and the host
#: converts a sampled master word address back to a byte address with the same
#: declared shift, so anything else is refused instead of being guessed.
MASTER_ADDRESS_SHIFTS = (2,)


def declared_master_address_shift(capabilities):
    """The declared shift of the DMA master's address lines, or the default."""
    value = capabilities.get('master_address_shift', 2)
    if type(value) is not int or value not in MASTER_ADDRESS_SHIFTS:
        raise ValueError('dma-master-address-shift-unsupported')
    return value


def dma_profile_edge_contract(capabilities):
    control, master = dma_select_modes(capabilities)
    width = capabilities['address_width']
    shift = declared_master_address_shift(capabilities)
    contract = (selected_dma_edge_contract(control_address_width=width) if control
                else dma_edge_contract(control_address_width=width))
    contract['master_address_shift'] = shift
    if control != master:
        contract['schema_version'] = ('wishbone_dma_control_selected_edge' if control
            else 'wishbone_dma_master_selected_edge') + ('.v1' if width == 2 else '.v2')
        if master:
            contract.pop('master_fixed_byte_enable')
            contract['master_byte_enable_signal'] = 'mwb_sel'
        else:
            contract['master_fixed_byte_enable'] = 15
            contract.pop('master_byte_enable_signal')
    return contract


def dma_control_shape(width, *, selected=False):
    if type(width) is not int or not 2 <= width <= 30:
        raise ValueError('DMA control address width must be in 2..30')
    shape = dict(DMA_SELECTED_CONTROL_SHAPE if selected else DMA_CONTROL_SHAPE)
    shape['adr'] = ('input', width)
    return shape


def dma_edge_contract(*, control_address_width=2):
    dma_control_shape(control_address_width)
    contract = {'schema_version':'wishbone_dma_edge.v1', 'operation':'STEP_WB_DMA',
        'input_order':list(DMA_STEP_PORTS), 'input_maxima':list(DMA_STEP_MAXIMA),
        'local_edges':1, 'master_address_units':'word', 'master_address_shift':2,
        'master_fixed_byte_enable':15, 'environment_max_outstanding':1,
        'request_acceptance':'cyc && stb && !stall before edge',
        'response_completion':'cyc && (ack || err) before edge',
        'same_edge_accept_and_complete':False,
        'completion_edge_policy':'stall new acceptance while delivering prior response',
        'control_address_units':'word_index', 'control_byte_offsets':[0,4,8,12],
        'partial_control_writes':False, 'runtime_scope':'edge_transport_only_no_memory_service'}
    if control_address_width != 2:
        contract.update(schema_version='wishbone_dma_edge.v2', operation='STEP_WB_DMA_WIDE',
            control_address_width=control_address_width,
            control_max_byte_offset=((1 << control_address_width)-1)*4)
        contract['input_maxima'][3]=(1 << control_address_width)-1
        del contract['control_byte_offsets']
    return contract


def selected_dma_edge_contract(*, control_address_width=2):
    contract = dma_edge_contract(control_address_width=control_address_width)
    wide=control_address_width != 2
    maxima=list(DMA_SELECTED_STEP_MAXIMA)
    maxima[3]=(1 << control_address_width)-1
    contract.update(schema_version='wishbone_dma_selected_edge.v2' if wide else 'wishbone_dma_selected_edge.v1',
        operation='STEP_WB_DMA_SEL_WIDE' if wide else 'STEP_WB_DMA_SEL',
        input_order=list(DMA_SELECTED_STEP_PORTS), input_maxima=maxima,
        master_byte_enable_signal='mwb_sel', control_byte_enable_signal='swb_sel',
        partial_control_writes=True)
    del contract['master_fixed_byte_enable']
    return contract
