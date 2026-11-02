"""Code-owned CSR semantics of the pinned, dual-role ZipCPU DMA RTL.

This is a static source admission contract. It issues no native receipt.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

from .source_lock import verify_local_source_lock

SOURCE_SHA256 = 'a948bab4a155ddc42be1d9b2ee588c1b8b9c9ab587d9e5125e24870c2169aacd'
PROVIDER_ID = 'zipcpu-wbdmac-csr.v1'
_PARAMETERS = {'ADDRESS_WIDTH':'30','BUS_WIDTH':'32','SLV_WIDTH':'32','LGMEMLEN':'10'}
_CSR = dict(offsets=dict(control=0,length=4,source=8,destination=12),
    configuration_order=['source','destination','length','control'],
    start_key=0xfed,start_word=0x0fed0004,length_words=4,block_words=4,
    increment_source=True,increment_destination=True,
    source_destination_units='byte_address_shift_right_2',master_address_units='word',
    master_byte_enable=15,status_error_mask=0x40000000,
    )
_READBACK = dict(status_busy_mask=0x80000000,block_length_encoding='low_10_bits_minus_one',
    length_encoding='30_bit_word_count',increment_disable_bits=[29,28],
    control_readback='busy_error_increment_flags_read_count_trigger_blocklen_minus_one',
    length_readback='remaining_word_count',address_readback='word_address_shift_left_2',
    completion_irq='last_write_ack_or_nonidle_native_error_pulse',
    error_status='native_bus_error_or_abort_latched_until_next_start')
#: CSR-semantic facts a profile may declare.  The profile states them in its
#: capability block; the allowed values below are derived from the pinned readback
#: facts (:23-28), and every declared value is cross-checked against them, so a
#: declaration can neither move the host onto another address unit nor claim a
#: software clear the RTL does not implement.
_DECLARED_UNITS = ('byte_address','byte_address_shift_right_2')
#: Both admitted spellings store a byte address.  Only
#: ``byte_address_shift_right_2`` also states that the RTL derives the word address
#: itself, which is the ``master_address_shift`` fact cross-checked below.
_HOST_UNITS = {'byte_address':'byte_address','byte_address_shift_right_2':'byte_address'}
_LENGTH_UNIT_OF_ENCODING = {'30_bit_word_count':'words','30_bit_byte_count':'bytes'}
_SHIFT_OF_READBACK = {'word_address_shift_left_2':2}


def _supported_declarations():
    """The declaration values the pinned readback facts allow, derived from them."""
    length = _LENGTH_UNIT_OF_ENCODING.get(_READBACK['length_encoding'])
    shift = _SHIFT_OF_READBACK.get(_READBACK['address_readback'])
    # A completion IRQ that is a native pulse is not a register the host writes, so
    # there is nothing left for software to clear.
    clear = ('none',) if 'pulse' in _READBACK['completion_irq'] else ('write',)
    return {'source_destination_units':_DECLARED_UNITS,
            'master_address_units':('word',),
            'master_address_shift':() if shift is None else (shift,),
            'length_unit':() if length is None else (length,),
            'irq_clear':clear}


_SUPPORTED = _supported_declarations()
_DEFAULTS = {'source_destination_units':_CSR['source_destination_units'],
    'master_address_units':_CSR['master_address_units'],
    'master_address_shift':_SHIFT_OF_READBACK[_READBACK['address_readback']],
    'length_unit':_LENGTH_UNIT_OF_ENCODING[_READBACK['length_encoding']],
    'irq_clear':'none'}


def declared_csr_semantics(profile):
    """Read the declared CSR units/clear facts and cross-check the pinned source.

    Each key is optional, so an undeclared profile keeps the pinned value, but a
    declared value must be one these bytes implement.  The check is per field so
    the refusal names the field that drifted.
    """
    capabilities=profile.capabilities
    declared=dict(_DEFAULTS)
    for name,supported in _SUPPORTED.items():
        if name not in capabilities:
            continue
        value=capabilities[name]
        if type(value) is bool or type(value) not in (str,int) or value not in supported:
            raise ValueError('wbdmac-declaration-source-drift:'+name)
        declared[name]=value
    return declared


def verify_wbdmac_source_contract(profile, *, base_dir):
    """Pin actual source, parameters and CSR declarations; never infer by name."""
    source = profile.source_document
    parameters = {p['name']:p['value'] for p in source.get('elaboration',{}).get('parameters',[])}
    if (source.get('root')!='third_party/soc-zipcpu' or source.get('top_module')!='wbdmac'
            or source.get('revision')!='git:42606d2d6ef55df313772232977621b2d72f0159'
            or source.get('files')!=['rtl/peripherals/wbdmac.v'] or source.get('include_roots')
            or parameters != _PARAMETERS or source.get('elaboration',{}).get('defines')):
        raise ValueError('wbdmac-source-or-parameters-unsupported')
    path=Path(base_dir)/source['root']/'rtl/peripherals/wbdmac.v'
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=SOURCE_SHA256:
        raise ValueError('wbdmac-source-drift')
    triggers=[action for action in profile.port_actions if action.port=='i_dev_ints']
    if len(triggers)!=1 or triggers[0].action!='constant' or triggers[0].value!=0:
        raise ValueError('wbdmac-trigger-must-be-fixed-zero')
    verified=verify_local_source_lock(profile,base_dir=Path(base_dir))
    address=profile.address
    expected=[(0,32,'rw','keyed_start_or_abort'),(4,32,'rw','word_count'),
        (8,32,'rw','byte_address_to_master_word_address'),(12,32,'rw','byte_address_to_master_word_address')]
    actual=[] if address is None else [(r.offset,r.width,r.access,r.side_effect) for r in address.registers]
    if actual!=expected or address.window_size!=16 or address.alignment!=16:
        raise ValueError('wbdmac-csr-declarations-unsupported')
    expected_caps=dict(data_width=32,address_width=2,address_units='word',master_address_width=30,
        master_address_units='word',master_fixed_byte_enable=15,master_has_error=True,
        master_byte_enable=False,byte_enable=False,read=True,write=True)
    if any(type(profile.capabilities.get(k)) is not type(v) or profile.capabilities.get(k)!=v
           for k,v in expected_caps.items()):
        raise ValueError('wbdmac-capability-unsupported')
    # The CSR units, the length unit, the clear semantics and the master shift are
    # declared by the profile and cross-checked against the pinned readback facts.
    # The offsets, start key, error mask and block shape stay pinned: the address
    # map is already a checked profile declaration (:47-52) and the keyed start
    # encoding is a byte-level source fact the F6 host must not be able to restate.
    declared=declared_csr_semantics(profile)
    from .wishbone_dma_fields import dma_profile_edge_contract
    edge=dma_profile_edge_contract(dict(profile.capabilities))
    if (edge.get('master_address_units')!=declared['master_address_units']
            or edge.get('master_address_shift')!=declared['master_address_shift']):
        raise ValueError('wbdmac-declaration-source-drift:master_address_shift')
    csr=deepcopy(_CSR)
    csr['source_destination_units']=_HOST_UNITS[declared['source_destination_units']]
    csr['master_address_units']=declared['master_address_units']
    return dict(schema_version='wbdmac_source_contract.v1',provider_id=PROVIDER_ID,
        source=dict(root=source['root'],revision=source['revision'],top_module=source['top_module'],
            files={'rtl/peripherals/wbdmac.v':SOURCE_SHA256},parameters=dict(_PARAMETERS)),
        csr=csr,readback=deepcopy(_READBACK),irq=dict(physical_port='o_interrupt',width=1,polarity='active_high',
            trigger='native_pulse'),
        declared=dict(declared,host_source_destination_units=csr['source_destination_units'],
            checked_against='pinned wbdmac.v CSR readback facts'),
        source_verification=verified)


def _saved_binding(profile, *, base_dir):
    """Compile the pinned saved physical ABI, without running an HDL frontend."""
    import json
    from myfuzz.composition.component_profile import PhysicalFacts, bind_profile
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    verify_wbdmac_source_contract(profile,base_dir=base_dir)
    raw=(Path(base_dir)/'configs/peripherals/zipcpu_wbdmac/evidence/elaborated_ports.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='07bae8b9d37832758d20088d9e1a5e398cf63dd2c07184d7a267db5f03f8cd3f':
        raise ValueError('wbdmac-physical-abi-drift')
    ports=tuple(ElaboratedPortFact(name=r['name'],direction=r['direction'],width=r['width'],signed=r['signed'],
        source_file=r['source']['file'],line=r['source']['line'],column=r['source']['column']) for r in json.loads(raw)['ports'])
    facts=PhysicalFacts(top_module=profile.source.top_module,ports=ports,content_hash=profile.source.revision,
        revision=profile.source.revision,files=profile.source.files,include_roots=profile.source.include_roots)
    return bind_profile(profile,facts)


def wbdmac_declared_endpoint_link(profile, *, base_dir):
    """Static physical master link from source-verified saved elaboration."""
    import json
    from types import SimpleNamespace
    from .dma_artifact_endpoint_links import _master_selection
    bound=_saved_binding(profile,base_dir=base_dir)
    masters=[e for e in bound.endpoints if e.function=='memory_master']
    if len(masters)!=1:
        raise ValueError('wbdmac-master-unsupported')
    master=masters[0]
    selection=_master_selection(SimpleNamespace(profile=profile),master)
    sha=lambda v:hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    binding=dict(profile_endpoint_sha256=sha(dict(profile_fingerprint=profile.profile_fingerprint,endpoint_id=master.endpoint_id)),
        template_id=selection.contract.template_id,template_version=selection.contract.template_version,
        variant_id=selection.contract.variant_id,contract_sha256=selection.contract.identity_sha256,
        selection_sha256=selection.identity_sha256)
    roles=[dict(role=f.role,direction=f.direction,width=f.width,physical_port=f.port,member_path=list(f.member_path),
        raw_lo=f.raw_lo,raw_hi=f.raw_hi,port_width=f.port_width,backend_port='mwb_'+f.role)
        for f in sorted(master.fields,key=lambda f:f.role)]
    return dict(link_id='mwb',endpoint_id=master.endpoint_id,function=master.function,protocol_side='master',
        backend_channel='mwb',template_binding=binding,roles=roles)


def wbdmac_declared_control_template(profile, *, base_dir):
    """Bind the second role to its registered full-word control template."""
    import json
    from .template_contracts import select_template_contract
    binding=_saved_binding(profile,base_dir=base_dir)
    controls=[e for e in binding.endpoints if e.function=='mmio_slave']
    if len(controls)!=1:
        raise ValueError('wbdmac-control-unsupported')
    endpoint=controls[0]
    selection=select_template_contract(endpoint,profile.capabilities,
        template_id='target.wishbone-pipelined',template_version='1',variant_id='dma-full-word-no-select')
    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    return dict(profile_endpoint_sha256=hashlib.sha256(canonical(dict(
        profile_fingerprint=profile.profile_fingerprint,endpoint_id=endpoint.endpoint_id))).hexdigest(),
        template_id=selection.contract.template_id,template_version=selection.contract.template_version,
        variant_id=selection.contract.variant_id,contract_sha256=selection.contract.identity_sha256,
        selection_sha256=selection.identity_sha256)
