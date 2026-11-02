"""Small DMA behavior description consumed by the common F6 firmware."""
from copy import deepcopy


def validate_f6_dma_behavior(value, *, control_size):
    """Validate length encoding and an optional full-word IRQ clear write."""
    if value is None:
        value = {'length_unit':'words', 'irq_clear':{'method':'none'}}
    if (type(value) is not dict or set(value) != {'length_unit','irq_clear'}
            or value['length_unit'] not in ('words','bytes')
            or type(value['irq_clear']) is not dict):
        raise ValueError('compiled-F6-firmware-dma-behavior')
    clear = value['irq_clear']
    if clear.get('method') == 'none':
        if set(clear) != {'method'}:
            raise ValueError('compiled-F6-firmware-irq-clear')
    elif clear.get('method') == 'write':
        if (set(clear) != {'method','offset','value','byte_enable'}
                or type(control_size) is not int or control_size < 4
                or type(clear['offset']) is not int or clear['offset'] % 4
                or not 0 <= clear['offset'] <= min(2044,control_size-4)
                or type(clear['value']) is not int or not 0 <= clear['value'] <= 0xffffffff
                or type(clear['byte_enable']) is not int or clear['byte_enable'] != 15):
            raise ValueError('compiled-F6-firmware-irq-clear')
    else:
        raise ValueError('compiled-F6-firmware-irq-clear')
    return deepcopy(value)


def f6_dma_semantics_from_source(source):
    """Translate an admitted DMA source contract to the common F6 semantics."""
    if type(source) is not dict:
        raise ValueError('compiled-F6-source-behavior-required')
    schema=source.get('schema_version')
    if schema == 'declared_f6_dma_source_contract.v1':
        if (source.get('semantics_origin') != 'component_profile_declared'
                or type(source.get('csr')) is not dict
                or source.get('irq_trigger') not in ('pulse', 'level')
                or type(source.get('control_size')) is not int
                or type(source.get('source_verification')) is not dict):
            raise ValueError('compiled-F6-source-behavior-unsupported')
        return deepcopy(source['csr']), validate_f6_dma_behavior(
            source.get('behavior'), control_size=source['control_size'])
    if schema == 'wbdmac_source_contract.v1':
        if (source.get('irq',{}).get('trigger') != 'native_pulse'
                or source.get('readback',{}).get('length_encoding') != '30_bit_word_count'):
            raise ValueError('compiled-F6-source-behavior-unsupported')
        return deepcopy(source['csr']), validate_f6_dma_behavior(None,control_size=16)
    if schema == 'zipdma_selected_profile_contract.v1':
        source_behavior=source['behavior'];registers=source_behavior['registers']
        if (source_behavior['length_unit']!='bytes'
                or source_behavior['source_address_unit']!='bytes'
                or source_behavior['destination_address_unit']!='bytes'
                or source_behavior['irq']!='level_until_control_write'
                or source['irq_clear']!='idle and SEL[3] and (data[29] or not data[30])'
                or source['control_select']!='i_swb_sel' or source['master_select']!='o_mwb_sel'):
            raise ValueError('compiled-F6-source-behavior-unsupported')
        csr=dict(offsets=dict(control=registers['control'],source=registers['source'],
            destination=registers['destination'],length=registers['length_bytes']),
            configuration_order=['source','destination','length','control'],
            start_key=0,start_word=source_behavior['start'],length_words=4,block_words=4,
            increment_source=True,increment_destination=True,
            source_destination_units='byte_address',master_address_units='word',
            master_byte_enable=15,status_error_mask=source_behavior['error_mask'])
        behavior=validate_f6_dma_behavior(dict(length_unit='bytes',irq_clear=dict(method='write',
            offset=registers['control'],value=source_behavior['clear_interrupt'],byte_enable=15)),
            control_size=16)
        return csr,behavior
    raise ValueError('compiled-F6-source-behavior-unsupported')


def f6_dma_irq_trigger(source):
    """Return the declared IRQ mode after validating the F6 behavior."""
    f6_dma_semantics_from_source(source)
    schema = source['schema_version']
    if schema == 'declared_f6_dma_source_contract.v1':
        return source['irq_trigger']
    return 'level' if schema == 'zipdma_selected_profile_contract.v1' else 'pulse'
