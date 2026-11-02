"""Select F6 DMA semantics from a verified component profile, not CPU pairs."""
from dataclasses import dataclass
from copy import deepcopy

from myfuzz.integration.f6_dma_behavior import f6_dma_semantics_from_source


@dataclass(frozen=True)
class F6DmaSourceProvider:
    source: dict
    csr: dict
    behavior: dict
    master_endpoint_id: str
    control_endpoint_id: str
    irq_endpoint_id: str
    irq_port: str
    irq_trigger: str


def select_f6_dma_source_provider(profile, *, base_dir):
    """Verify the selected profile's RTL contract before deriving F6 facts."""
    top = profile.source_document.get('top_module')
    declaration = profile.evidence.get('f6_dma')
    if declaration is not None:
        if (type(declaration) is not dict
                or set(declaration) != {'schema_version','csr','behavior','irq_trigger'}
                or declaration['schema_version'] != 'f6_dma_behavior.v1'
                or declaration['irq_trigger'] not in ('pulse','level')
                or profile.address is None):
            raise ValueError('f6-dma-profile-declaration-invalid')
        from myfuzz.local_harness.source_lock import verify_local_source_lock
        verified = verify_local_source_lock(profile, base_dir=base_dir)
        source = dict(schema_version='declared_f6_dma_source_contract.v1',
            semantics_origin='component_profile_declared',
            profile_fingerprint=profile.profile_fingerprint,
            source_verification=deepcopy(verified), control_size=profile.address.window_size,
            csr=deepcopy(declaration['csr']), behavior=deepcopy(declaration['behavior']),
            irq_trigger=declaration['irq_trigger'])
        csr, behavior = f6_dma_semantics_from_source(source)
        fixed = dict(configuration_order=['source','destination','length','control'],
            length_words=4,block_words=4,increment_source=True,increment_destination=True,
            master_address_units='word',master_byte_enable=15)
        variable = {'offsets','start_key','start_word','status_error_mask','source_destination_units'}
        offsets = csr.get('offsets')
        registers = {r.offset:r for r in profile.address.registers}
        if (set(csr) != set(fixed) | variable
                or any(type(csr[k]) is not type(v) or csr[k] != v for k,v in fixed.items())
                or csr['source_destination_units'] not in ('byte_address','byte_address_shift_right_2')
                or any(type(csr[k]) is not int or not 0 <= csr[k] <= 0xffffffff
                       for k in ('start_key','start_word','status_error_mask'))
                or csr['status_error_mask'] == 0
                or type(offsets) is not dict
                or set(offsets) != {'control','source','destination','length'}
                or any(type(v) is not int or v % 4 or v < 0 or v > 2044
                       or v + 4 > profile.address.window_size or v not in registers
                       or registers[v].width != 32
                       or registers[v].access not in (('rw',) if name == 'control' else ('rw','wo'))
                       for name,v in offsets.items())
                or len(set(offsets.values())) != 4
                or (declaration['irq_trigger'] == 'level' and behavior['irq_clear']['method'] != 'write')
                or (behavior['irq_clear']['method'] == 'write' and
                    (behavior['irq_clear']['offset'] not in registers
                     or registers[behavior['irq_clear']['offset']].width != 32
                     or registers[behavior['irq_clear']['offset']].access not in ('rw','wo')))):
            raise ValueError('f6-dma-declared-csr-invalid')
        # If the selected source has an existing checked implementation, a
        # declaration must agree with it. For other locked sources these facts
        # remain component declarations, subject to actual runtime evidence.
        checked = None
        if verified.get('schema_version') == 'zipdma_selected_profile_contract.v1':
            checked = verified
        elif top == 'wbdmac':
            from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
            checked = verify_wbdmac_source_contract(profile, base_dir=base_dir)
        if checked is not None and (csr, behavior) != f6_dma_semantics_from_source(checked):
            raise ValueError('f6-dma-declaration-source-drift')
        expected_trigger = declaration['irq_trigger']
    elif top == 'wbdmac':
        from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
        source = verify_wbdmac_source_contract(profile, base_dir=base_dir)
        expected_trigger = 'pulse'
    elif top == 'zipdma':
        from myfuzz.local_harness.zipdma_profile_session import verify_zipdma_profile
        source = verify_zipdma_profile(profile, base_dir=base_dir)
        expected_trigger = 'level'
    else:
        raise ValueError('f6-dma-source-provider-unsupported')
    csr, behavior = f6_dma_semantics_from_source(source)
    def endpoint(function):
        rows = [row for row in profile.endpoints if row.function == function]
        if len(rows) != 1:
            raise ValueError('f6-dma-endpoint-not-unique')
        return rows[0]
    master, control, irq = (endpoint(name) for name in ('memory_master','mmio_slave','interrupt_source'))
    fields = [field for field in irq.fields if field.role == 'irq' and field.direction == 'output'
              and field.width == 1 and len(field.aliases) == 1]
    declarations = [row for row in profile.interrupts if row.endpoint_id == irq.endpoint_id
                    and row.role == 'irq']
    if (len(fields) != 1 or len(declarations) != 1
            or declarations[0].trigger != expected_trigger
            or declarations[0].polarity != 'active_high'):
        raise ValueError('f6-dma-source-irq-unsupported')
    return F6DmaSourceProvider(source,csr,behavior,master.endpoint_id,
        control.endpoint_id,irq.endpoint_id,fields[0].aliases[0],expected_trigger)


def f6_dma_static_bindings(provider, profile, *, base_dir):
    """Return registered physical bindings; a profile is not an artifact."""
    if provider.source['schema_version'] == 'wbdmac_source_contract.v1':
        from myfuzz.local_harness.wbdmac_source_contract import (
            wbdmac_declared_endpoint_link, wbdmac_declared_control_template)
        return (wbdmac_declared_endpoint_link(profile,base_dir=base_dir),
                wbdmac_declared_control_template(profile,base_dir=base_dir))
    from myfuzz.composition.component_profile import bind_profile, elaborate_profile
    from myfuzz.local_harness.template_contracts import select_template_contract
    from myfuzz.local_harness.renderer import _sha
    # A source-verified profile alone is not physical evidence: bind the actual
    # elaborated ports before selecting either declared template.
    bound = bind_profile(profile, elaborate_profile(profile, base_dir=base_dir))
    masters = [row for row in bound.endpoints if row.endpoint_id == provider.master_endpoint_id]
    controls = [row for row in bound.endpoints if row.endpoint_id == provider.control_endpoint_id]
    if len(masters) != 1 or len(controls) != 1:
        raise ValueError('f6-selected-dma-physical-endpoint-missing')
    master,control = masters[0],controls[0]
    from myfuzz.local_harness.wishbone_dma_fields import dma_select_modes
    control_selected,master_selected=dma_select_modes(profile.capabilities)
    def selected(endpoint, side):
        caps = dict(profile.capabilities)
        has_select = control_selected if side == 'target' else master_selected
        caps.update(byte_enable=has_select,partial_write=has_select)
        if side == 'master':
            caps.update(address_width=caps['master_address_width'],
                        has_error=caps['master_has_error'],
                        address_units=caps['master_address_units'])
        choice = select_template_contract(endpoint,caps,
            template_id=side+'.wishbone-pipelined',template_version='1',
            variant_id='dma-selected' if has_select else 'dma-full-word-no-select')
        return dict(profile_endpoint_sha256=_sha(dict(profile_fingerprint=profile.profile_fingerprint,
            endpoint_id=endpoint.endpoint_id)),template_id=choice.contract.template_id,
            template_version=choice.contract.template_version,variant_id=choice.contract.variant_id,
            contract_sha256=choice.contract.identity_sha256,selection_sha256=choice.identity_sha256)
    roles=[dict(role=field.role,direction=field.direction,width=field.width,physical_port=field.port,
        member_path=list(field.member_path),raw_lo=field.raw_lo,raw_hi=field.raw_hi,
        port_width=field.port_width,backend_port='mwb_'+field.role)
        for field in sorted(master.fields,key=lambda field:field.role)]
    return dict(link_id='mwb',endpoint_id=master.endpoint_id,function=master.function,
        protocol_side='master',backend_channel='mwb',template_binding=selected(master,'master'),
        roles=roles),selected(control,'target')
