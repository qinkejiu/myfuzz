"""Read-only protocol contracts; no driver, rendering or DUT adherence claim."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json

from myfuzz.composition.component_profile import ResolvedEndpoint


def _words(value):
    return tuple(sorted(value.split()))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@dataclass(frozen=True, slots=True)
class ProtocolTemplateContract:
    template_id: str
    template_version: str
    variant_id: str
    protocol: tuple[str, str]
    side: str
    required_roles: tuple[str, ...]
    optional_roles: tuple[str, ...]
    host_to_device_roles: tuple[str, ...]
    limits: tuple[tuple[str, str | int | bool | tuple[int, ...]], ...]
    required_profile_facts: tuple[tuple[str, str | int | bool], ...] = ()
    optional_role_groups: tuple[tuple[str, ...], ...] = ()
    semantic_selection: str = 'shape'
    optional_profile_facts: tuple[tuple[str, str | int | bool], ...] = ()

    def document(self):
        return {'schema_version': 'local_protocol_template_contract.v1',
            'template_id': self.template_id, 'template_version': self.template_version,
            'variant_id': self.variant_id, 'protocol': list(self.protocol), 'side': self.side,
            'required_roles': list(self.required_roles), 'optional_roles': list(self.optional_roles),
            'host_to_device_roles': list(self.host_to_device_roles),
            'limits': {key:list(value) if isinstance(value,tuple) else value for key,value in self.limits},
            'required_profile_facts': dict(self.required_profile_facts),
            'optional_profile_facts': dict(self.optional_profile_facts),
            'optional_role_groups': [list(group) for group in self.optional_role_groups],
            'role_shapes': {role:_role_shape(role) for role in sorted(set(self.required_roles)|set(self.optional_roles))},
            'semantic_selection': self.semantic_selection,
            'runtime_effective': False, 'dut_semantics_verified': False}

    @property
    def identity_sha256(self):
        return hashlib.sha256(_canonical(self.document())).hexdigest()


def _contract(identifier, variant, protocol, side, request, response, *, optional='',
              optional_request='', facts=None, optional_facts=None, limits=None, groups=(), semantics='shape'):
    common = {'max_outstanding': 1, 'outstanding_scope':'endpoint', 'clock_crossing': False, 'pipelining': False,
              'supported_data_widths':(32,), 'address_width_min':1, 'address_width_max':64,
              'max_wait_cycles_limit':1024, 'max_field_width':4096}
    common.update(limits or {})
    if 'byte_enable' in common:
        common.setdefault('partial_write',common['byte_enable'])
    return ProtocolTemplateContract(identifier, '1', variant, protocol, side,
        _words(request + ' ' + response), _words(optional), _words(request + ' ' + optional_request),
        tuple(sorted(common.items())), tuple(sorted((facts or {}).items())), groups, semantics,
        tuple(sorted((optional_facts or {}).items())))


_AXI_REQUEST = 'awid awaddr awlen awsize awburst awvalid wdata wstrb wlast wvalid bready arid araddr arlen arsize arburst arvalid rready'
_AXI_RESPONSE = 'awready wready bid bresp bvalid arready rid rdata rresp rlast rvalid'
_AXI_OPTIONAL = 'awlock awcache awprot awqos awregion awatop awuser wuser buser arlock arcache arprot arqos arregion aruser ruser'
_USER_GROUP = _words('awuser wuser buser aruser ruser')
_WB_FACTS = {'address_units': 'word', 'has_error': False}
_TEMPLATES = (
    _contract('cpu.obi', 'read-only', ('obi','1'), 'cpu', 'req addr', 'gnt rvalid rdata error',
        limits={'write':False,'byte_enable':False,'completion':'grant_then_response','error_policy':'propagate_error','error_response':True}),
    _contract('cpu.obi', 'read-write', ('obi','1'), 'cpu', 'req addr we wdata be', 'gnt rvalid rdata error',
        limits={'write':True,'byte_enable':True,'completion':'grant_then_response','error_policy':'propagate_error','error_response':True}),
    _contract('cpu.axi4', 'single-beat-id', ('axi4','1'), 'cpu', _AXI_REQUEST, _AXI_RESPONSE,
        optional=_AXI_OPTIONAL, optional_request='awlock awcache awprot awqos awregion awatop awuser wuser arlock arcache arprot arqos arregion aruser',
        facts={'bursts':False},groups=(_USER_GROUP,),
        limits={'supported_data_widths':(32,64),'single_beat':True,'bursts':False,'exclusive':False,'atomics':False,'id_roundtrip':True,'error_response':True,
                'byte_enable':True,'completion':'independent_channels_response',
                'unsupported_transfer_policy':'reject_with_axi_error_completion',
                'burst_length_policy':'len_zero_only','burst_kind_policy':'fixed_or_incr_only',
                'transfer_size_policy':'not_above_native_beat','write_last_required':True,
                'metadata_policy':'accept_ignore_cache_prot_qos_region_user',
                'lock_policy':'reject_nonzero','atop_policy':'reject_nonzero'}),
    _contract('cpu.axi4-lite','no-response-code',('axi4-lite','1'),'cpu',
        'awaddr awprot awvalid wdata wstrb wvalid bready araddr arprot arvalid rready',
        'awready wready bvalid arready rdata rvalid',
        limits={'byte_enable':True,'bursts':False,'ids':False,'completion':'independent_channels_response',
                'error_response':False,'response_code_policy':'absent_physical_pins_success_only','backend_error_policy':'terminate_without_success'}),
    _contract('cpu.wishbone','no-err-stall',('wishbone','classic'),'cpu',
        'cyc stb we adr dat_w sel','ack dat_r',semantics='byte-address-explicit-or-typed',
        optional_facts={'address_units':'byte'},
        limits={'error_response':False,'address_units':'byte','byte_enable':True,'read_zero_sel':'full_word_read',
                'completion':'cycle_strobe_held_until_ack','backend_error_policy':'terminate_without_ack'}),
    _contract('cpu.native-memory','completion-no-error',('ready-valid-memory','1'),'cpu',
        'valid addr wdata wstrb','ready rdata',semantics='explicit-only',
        optional_facts={'completion_semantics':'completion'},
        limits={'error_response':False,'byte_enable':True,'completion':'valid_and_ready','early_ready':False,
                'read_zero_strobe':True,'backend_error_policy':'terminate_without_ready'}),
    _contract('target.tl-ul','user-integrity',('tl-ul','1'), 'target',
        'a_valid a_opcode a_param a_size a_source a_address a_mask a_data a_user d_ready',
        'a_ready d_valid d_opcode d_param d_size d_source d_sink d_data d_user d_error',
        facts={'integrity':'required'},limits={'byte_enable':True,'source_roundtrip':True,
             'has_error':True,'get':True,'put_full':True,'put_partial':True,'integrity_encoding':'source_defined_required',
             'error_policy':'observe_real_d_error','completion':'a_accept_then_d_response'}),
    _contract('target.apb3','full-word',('apb','3'),'target',
        'paddr psel penable pwrite pwdata','pready prdata pslverr',
        facts={'byte_enable':False,'partial_write':False},limits={'byte_enable':False,
                'partial_write':False,'has_error':True,'completion':'setup_access_response','error_policy':'observe_pslverr_on_completion'}),
    _contract('target.wishbone','word-addressed-registered-ack',('wishbone','classic'),'target',
        'cyc stb we adr dat_w sel','ack dat_r',optional='stall',
        facts={**_WB_FACTS,'has_address_port':True,'sel_implemented':True,'ack_requires_cyc':True,
            'wishbone_flavour':'registered-ack','byte_enable':True,'partial_write':True},
        limits={'address_units':'word','byte_enable':True,'has_error':False,'request_phase':'one_cycle_stb_pulse',
                'cyc_policy':'hold_through_ack','stall_policy':'observed_zero_only',
                'completion':'registered_ack','backend_error_policy':'local_error_no_err_pin'}),
    _contract('target.wishbone','addressless-select-ignored',('wishbone','classic'),'target',
        'cyc stb we dat_w sel','ack dat_r',optional='stall',
        facts={**_WB_FACTS,'has_address_port':False,'sel_implemented':False,'ack_requires_cyc':False,
            'wishbone_flavour':'registered-ack-cyc-ignored','byte_enable':False,'partial_write':False},
        limits={'address_units':'word','byte_enable':False,'partial_write':False,'address_port':False,
                'has_error':False,'request_phase':'one_cycle_stb_pulse','cyc_policy':'not_used_by_dut',
                'select_policy':'ignored_full_word','stall_policy':'observed_zero_only',
                'completion':'registered_ack','backend_error_policy':'local_error_no_err_pin'}),
)


def list_template_contracts() -> tuple[ProtocolTemplateContract, ...]:
    return _TEMPLATES


@dataclass(frozen=True, slots=True)
class SelectedTemplateContract:
    contract: ProtocolTemplateContract
    _canonical_binding: bytes

    def document(self):
        return {'schema_version':'local_protocol_template_selection.v1','contract':self.contract.document(),
                'contract_sha256':self.contract.identity_sha256,
                'binding':json.loads(self._canonical_binding),
                'runtime_effective':False,'dut_semantics_verified':False}

    @property
    def identity_sha256(self):
        return hashlib.sha256(_canonical(self.document())).hexdigest()


_CPU_FUNCTIONS = frozenset(('memory_master','processor_memory_master','instruction_memory_master','data_memory_master'))
_CONTROL = frozenset('req gnt we rvalid error valid ready awvalid awready wvalid wready wlast bvalid bready arvalid arready rvalid rready rlast cyc stb ack err stall psel penable pwrite pready pslverr a_valid a_ready d_valid d_ready d_error'.split())
_FIXED = {'awlen':8,'arlen':8,'awsize':3,'arsize':3,'awburst':2,'arburst':2,'awlock':1,'arlock':1,
          'bresp':2,'rresp':2,'awprot':3,'arprot':3,'awcache':4,'arcache':4,'awqos':4,'arqos':4,
          'awregion':4,'arregion':4,'awatop':6,'a_opcode':3,'d_opcode':3,'a_param':3,'d_param':3}
_DATA = frozenset('wdata rdata dat_w dat_r pwdata prdata a_data d_data'.split())
_ADDRESS = frozenset('addr adr awaddr araddr paddr a_address'.split())
_LANES = frozenset(('be','wstrb','sel','a_mask'))


def _role_shape(role):
    if role in _CONTROL:
        return {'width':1}
    if role in _FIXED:
        return {'width':_FIXED[role]}
    if role in _DATA:
        return {'width':'data_width'}
    if role in _ADDRESS:
        return {'width':'address_width'}
    if role in _LANES:
        return {'width':'data_width/8'}
    if role in ('awid','arid','bid','rid','a_source','d_source','d_sink'):
        return {'width':'roundtrip_or_profile_width','max_width':32}
    if role in ('a_size','d_size'):
        return {'width':'roundtrip_size_width','max_width':3}
    return {'width':'source_defined','max_width':4096}


def _match(contract, endpoint, capabilities, explicit):
    cpu = endpoint.function in _CPU_FUNCTIONS
    if contract.protocol != endpoint.protocol or (contract.side=='cpu') != cpu or (
            not cpu and endpoint.function!='mmio_slave'):
        raise ValueError('template-protocol-or-side-mismatch')
    by_role={field.role:field for field in endpoint.fields}
    if len(by_role)!=len(endpoint.fields):
        raise ValueError('template-duplicate-role')
    roles=set(by_role)
    if not set(contract.required_roles)<=roles or roles-set(contract.required_roles)-set(contract.optional_roles):
        raise ValueError('template-missing-or-unknown-roles')
    for group in contract.optional_role_groups:
        if roles.intersection(group) and not set(group)<=roles:
            raise ValueError('template-incomplete-optional-group')
    for key,expected in contract.required_profile_facts:
        if key not in capabilities or type(capabilities[key]) is not type(expected) or capabilities[key]!=expected:
            raise ValueError('template-profile-fact-mismatch:'+key)
    for key,expected in contract.optional_profile_facts:
        if key in capabilities and (type(capabilities[key]) is not type(expected) or capabilities[key]!=expected):
            raise ValueError('template-profile-fact-mismatch:'+key)
    if contract.semantic_selection=='explicit-only' and not explicit:
        raise ValueError('template-explicit-selection-required')
    if contract.semantic_selection=='byte-address-explicit-or-typed':
        if not explicit and capabilities.get('address_units')!='byte':
            raise ValueError('template-explicit-selection-required:address_units')
    if 'max_wait_cycles' in capabilities and (type(capabilities['max_wait_cycles']) is not int or not 1<=capabilities['max_wait_cycles']<=dict(contract.limits)['max_wait_cycles_limit']):
        raise ValueError('template-wait-limit-mismatch')
    for name in ('max_outstanding',):
        if name in capabilities and (type(capabilities[name]) is not int or capabilities[name]!=1):
            raise ValueError('template-capability-mismatch:'+name)
    spans={}
    for field in endpoint.fields:
        if field.endpoint_id!=endpoint.endpoint_id:
            raise ValueError('template-field-endpoint-mismatch')
        for low,high in spans.setdefault(field.port,[]):
            if field.raw_lo<=high and low<=field.raw_hi:
                raise ValueError('template-overlapping-physical-fields')
        spans[field.port].append((field.raw_lo,field.raw_hi))
        expected='output' if (field.role in contract.host_to_device_roles)==cpu else 'input'
        if field.direction!=expected or field.signed or type(field.width) is not int or field.width<1 or field.width>4096:
            raise ValueError('template-field-shape:'+field.role)
        if field.raw_lo<0 or field.raw_hi-field.raw_lo+1!=field.width or field.raw_hi>=(field.port_width or field.width):
            raise ValueError('template-field-span:'+field.role)
        width=1 if field.role in _CONTROL else _FIXED.get(field.role)
        if field.width>_role_shape(field.role).get('max_width',4096):
            raise ValueError('template-field-width-outside-limit:'+field.role)
        if width is not None and field.width!=width:
            raise ValueError('template-field-width:'+field.role)
    data={f.width for f in endpoint.fields if f.role in _DATA}
    addresses={f.width for f in endpoint.fields if f.role in _ADDRESS}
    if len(data)!=1 or next(iter(data)) not in dict(contract.limits)['supported_data_widths'] or len(addresses)>1:
        raise ValueError('template-data-or-address-width-mismatch')
    data_width=next(iter(data))
    if addresses and not dict(contract.limits)['address_width_min']<=next(iter(addresses))<=dict(contract.limits)['address_width_max']:
        raise ValueError('template-address-width-outside-limit')
    for field in endpoint.fields:
        if field.role in _LANES and field.width!=data_width//8:
            raise ValueError('template-byte-enable-width')
    for group in (('awid','arid','bid','rid'),('a_source','d_source'),('a_size','d_size'),_USER_GROUP):
        values={by_role[role].width for role in group if role in by_role}
        if len(values)>1:
            raise ValueError('template-roundtrip-width-mismatch')
    for role,key in (('awid','id_width'),('awuser','user_width'),('a_source','source_width'),('d_sink','sink_width'),
                     ('a_size','size_width'),('a_user','user_width'),('d_user','d_user_width')):
        if role in by_role and key in capabilities and (type(capabilities[key]) is not int or capabilities[key]!=by_role[role].width):
            raise ValueError('template-capability-width-mismatch:'+key)
    for key,actual in (('data_width',data_width),('address_width',next(iter(addresses)) if addresses else None)):
        if key in capabilities and (type(capabilities[key]) is not int or capabilities[key]!=actual):
            raise ValueError('template-capability-width-mismatch:'+key)
    limits=dict(contract.limits)
    for key in ('byte_enable','partial_write','error_response','has_error'):
        if key in limits and key in capabilities and not (contract.side=='cpu' and limits.get('write') is False and key in ('byte_enable','partial_write')) and (type(capabilities[key]) is not bool or capabilities[key]!=limits[key]):
            raise ValueError('template-capability-mismatch:'+key)
    return {'endpoint_id':endpoint.endpoint_id,'function':endpoint.function,'protocol':list(endpoint.protocol),
            'roles':[{'role':f.role,'physical_port':f.port,'member_path':list(f.member_path),'direction':f.direction,
                'width':f.width,'raw_lo':f.raw_lo,'raw_hi':f.raw_hi,'port_width':f.port_width} for f in sorted(endpoint.fields,key=lambda item:item.role)],
            'selection_mode':'explicit' if explicit else 'automatic','data_width':data_width,
            'address_width':next(iter(addresses)) if addresses else None,
            'typed_profile_facts':{key:capabilities[key] for key in sorted(capabilities) if key!='evidence'}}


def select_template_contract(endpoint: ResolvedEndpoint, capabilities: Mapping, *,
                             template_id=None, template_version=None, variant_id=None) -> SelectedTemplateContract:
    if not isinstance(endpoint,ResolvedEndpoint) or not isinstance(capabilities,Mapping):
        raise ValueError('template-bound-endpoint-required')
    supplied=(template_id,template_version,variant_id)
    explicit=any(value is not None for value in supplied)
    if explicit and not all(isinstance(value,str) and value for value in supplied):
        raise ValueError('template-incomplete-selection')
    candidates=[c for c in _TEMPLATES if not explicit or (c.template_id,c.template_version,c.variant_id)==supplied]
    if not candidates:
        raise ValueError('template-unregistered-selection')
    matches=[]
    errors=[]
    for contract in candidates:
        try:
            payload=_match(contract,endpoint,capabilities,explicit)
            matches.append(SelectedTemplateContract(contract,_canonical(payload)))
        except ValueError as error:
            errors.append(str(error))
    if len(matches)!=1:
        detail=next((error for error in errors if 'explicit' in error),'no_unique_compatible_contract')
        raise ValueError('template-selection-refused:'+detail)
    return matches[0]
