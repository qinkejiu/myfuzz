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
# TileLink 1.0 CPU-side endpoints.  These two variants are derived from the only
# real TileLink 1.0 declaration in this repository: the BOOM semantic interface
# description (configs/cpus/boom/interface_description.json, endpoints
# ``cpu.instruction_memory`` and ``cpu.data_memory``, declared protocol
# ``["tilelink","1"]``).  They mirror that declaration's role vocabulary
# verbatim, nothing more:
#   cpu.instruction_memory -> address read_data request response
#   cpu.data_memory        -> address write_data read_data request response
# The declaration names abstract roles only and deliberately leaves directions,
# widths, signedness and hierarchy to the HDL crawler, so these contracts claim
# a role shape and no channel semantics.  They are *not* a TileLink A/B/C/D/E
# five-channel contract: no channel mapping, mask/byte-enable, burst,
# source/sink or coherence claim is made, and the boolean-looking limits below
# must not be read as claims about TileLink itself (see
# ``undeclared_capability_policy``).
#
# ``target.tl-ul`` is a different inventory entry: the TileLink-UL *peripheral
# target* contract, protocol ``('tl-ul','1')``, side='target'.  This pair is the
# TileLink 1.0 *CPU endpoint* contract, protocol ``('tilelink','1')``,
# side='cpu'; the two are never interchangeable, and the declared role
# vocabulary here (address/request/read_data/response/write_data) is not the
# TL-UL channel vocabulary (a_valid/a_ready/d_valid/d_ready/...).
_TL_CPU_LIMITS = {'error_response':False,'byte_enable':False,'partial_write':False,
    'completion':'declared_request_then_response_roles',
    'role_declaration':'configs/cpus/boom/interface_description.json',
    'channel_vocabulary':'declared_abstract_roles_only_no_a_b_c_d_e_mapping',
    'undeclared_capability_policy':'not_declared_not_claimed',
    # The declaration leaves widths to the crawler, so the contract accepts the
    # two memory widths this repository's CPU adapters already use rather than
    # inventing a TileLink width rule.
    'supported_data_widths':(32,64)}
_TEMPLATES = (
    _contract('cpu.obi', 'read-only', ('obi','1'), 'cpu', 'req addr', 'gnt rvalid rdata error',
        limits={'write':False,'byte_enable':False,'completion':'grant_then_response','error_policy':'propagate_error','error_response':True}),
    _contract('cpu.obi', 'read-write', ('obi','1'), 'cpu', 'req addr we wdata be', 'gnt rvalid rdata error',
        limits={'write':True,'byte_enable':True,'completion':'grant_then_response','error_policy':'propagate_error','error_response':True}),
    # OBI without bus-error pins.  OBI does not require an error channel, and the
    # pinned CV32E40P core really has none: its profile says so in both prose and
    # in ``capabilities.evidence`` ("It has no instr_err_i/data_err_i physical
    # pins"), and ``instr_err_i`` appears in third_party only in the Ibex vendor
    # docs.  Without these variants a CPU that conforms to OBI but cannot
    # represent an error matches nothing, which is a gap in the contract set
    # rather than a defect in the CPU.
    #
    # Both variants require the ``error_response`` profile fact.  Two distinct
    # mechanisms keep the pairs apart, and this comment names the right one
    # because an earlier draft of it claimed the wrong one:
    #   * the *role set* is what separates them today.  ``read-only``/
    #     ``read-write`` require an ``error`` role and the no-error pair does not,
    #     and ``_match`` rejects any declared role that is in neither the required
    #     nor the optional set - so an endpoint declaring ``error`` can never
    #     match the no-error pair, and one that does not declare it can never match
    #     the error-capable pair.  No capability is consulted for that.
    #   * the required *fact* is what makes the no-error pair state its
    #     precondition.  ``_match`` compares a limit against the capability only
    #     when the profile declares that capability, so a CPU that simply omits
    #     ``error_response`` would otherwise match the no-error pair silently.
    #     Requiring the fact turns "we did not say" into a refusal instead of an
    #     assumption.  It is *not* what discriminates the two pairs on the two CPUs
    #     in this repository - both declare the capability explicitly.
    _contract('cpu.obi', 'read-only-no-error-pins', ('obi','1'), 'cpu', 'req addr',
        'gnt rvalid rdata',
        facts={'error_response':False},
        limits={'write':False,'byte_enable':False,'completion':'grant_then_response',
                'error_response':False,
                'error_policy':'cpu_cannot_represent_a_bus_error_adapter_must_fail_stop',
                'backend_error_policy':'fail_stop_no_error_pin_to_raise'}),
    _contract('cpu.obi', 'read-write-no-error-pins', ('obi','1'), 'cpu',
        'req addr we wdata be', 'gnt rvalid rdata',
        facts={'error_response':False},
        limits={'write':True,'byte_enable':True,'completion':'grant_then_response',
                'error_response':False,
                'error_policy':'cpu_cannot_represent_a_bus_error_adapter_must_fail_stop',
                'backend_error_policy':'fail_stop_no_error_pin_to_raise'}),
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
    _contract('cpu.pipelined-memory', 'single-outstanding-completion-edge',
        ('pipelined-completion-memory','1'), 'cpu',
        'addr read_request write_request write_data write_strobe',
        'read_response read_data write_response', semantics='explicit-only',
        facts={'completion_semantics':'completion'},
        limits={'byte_enable':True,'error_response':False,'max_outstanding':1,
                'pipelining':False,'completion':'registered_completion_next_request_allowed',
                'request_exclusion':'read_write_mutually_exclusive',
                'held_request_policy':'single_until_completion'}),
    # TileLink 1.0 CPU-side endpoints taken from the real BOOM declaration; see
    # ``_TL_CPU_LIMITS`` above for what these limits do and do not claim, and
    # why this pair is not ``target.tl-ul``.
    _contract('cpu.tilelink','declared-four-role',('tilelink','1'),'cpu',
        'address request','read_data response', limits={'write':False,**_TL_CPU_LIMITS}),
    _contract('cpu.tilelink','declared-five-role-write-capable',('tilelink','1'),'cpu',
        'address request write_data','read_data response', limits={'write':True,**_TL_CPU_LIMITS}),
    # AHB-Lite CPU-side endpoint, derived from the only real AHB-Lite boundary in
    # this repository: CORE-V Wally's external bus
    # (configs/cpus/cvw/interface_description.json, endpoint ``cpu.external_bus``,
    # declared protocol ``["ahb-lite","1"]``).  The roles below are that
    # declaration's role vocabulary verbatim.
    #
    # Two facts about the real boundary shape this contract, and a contract
    # written from a textbook AHB-Lite signal list would get both wrong:
    #   * read data arrives at the CPU boundary as ``HRDATAEXT``, not ``HRDATA``
    #     (``src/ebu/ebu.sv`` deliberately has no HRDATA port);
    #   * ``HSELEXT`` is a CVW chip-select extension, not an AHB-Lite signal.
    # ``AHBW``/``PA_BITS``/``XLEN`` are ``cvw_t`` fields set by the chosen CVW
    # config, so this contract accepts a parameterised width range rather than
    # claiming concrete numbers, and it has NOT been elaborated against the RTL.
    _contract('cpu.ahb-lite','cvw-external-bus',('ahb-lite','1'),'cpu',
        'htrans haddr hwrite hwdata hwstrb',
        'hready hrdata hresp',
        # ``optional`` is the role-optionality set and ``optional_request`` is the
        # direction set; they are orthogonal, so a host-driven optional role has
        # to appear in both (the selector derives each declared role's expected
        # direction from ``host_to_device_roles``, and rejects any declared role
        # that is in neither the required nor the optional set).
        optional='hsize hburst hprot hmastlock hsel',
        optional_request='hsize hburst hprot hmastlock hsel',
        limits={'write':True,'byte_enable':True,'partial_write':True,
                'error_response':True,'bursts':True,'ids':False,
                'completion':'address_phase_then_ready_completion',
                'error_policy':'observe_real_hresp_on_completion',
                'read_data_name_policy':'cpu_boundary_signal_is_hrdataext',
                'select_policy':'hselext_is_a_cvw_extension_not_ahb_lite',
                'width_parameterisation':'cvw_t_fields_ahbw_pa_bits_xlen',
                'elaboration_status':'not-elaborated',
                'supported_data_widths':(32,64)}),
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
        'cyc stb we adr dat_w sel','ack dat_r stall',
        facts={**_WB_FACTS,'has_address_port':True,'sel_implemented':True,'ack_requires_cyc':True,
            'wishbone_flavour':'registered-ack','byte_enable':True,'partial_write':True},
        limits={'address_units':'word','byte_enable':True,'has_error':False,'request_phase':'one_cycle_stb_pulse',
                'cyc_policy':'hold_through_ack','stall_policy':'observed_zero_only',
                'completion':'registered_ack','backend_error_policy':'local_error_no_err_pin'}),
    _contract('target.wishbone','addressless-select-ignored',('wishbone','classic'),'target',
        'cyc stb we dat_w sel','ack dat_r stall',
        facts={**_WB_FACTS,'has_address_port':False,'sel_implemented':False,'ack_requires_cyc':False,
            'wishbone_flavour':'registered-ack-cyc-ignored','byte_enable':False,'partial_write':False},
        limits={'address_units':'word','byte_enable':False,'partial_write':False,'address_port':False,
                'has_error':False,'request_phase':'one_cycle_stb_pulse','cyc_policy':'not_used_by_dut',
                'select_policy':'ignored_full_word','stall_policy':'observed_zero_only',
                'completion':'registered_ack','backend_error_policy':'local_error_no_err_pin'}),
    # The AXI4-Lite slave side is its own shape: a real slave declares both
    # response codes, while the CPU-side contract declares neither. A write is
    # two independently handshaken channels, so neither AW alone nor W alone is
    # a write the slave could act on.
    _contract('target.axi4-lite','single-outstanding-error-codes',('axi4-lite','1'),'target',
        'awvalid awaddr awprot wvalid wdata wstrb bready arvalid araddr arprot rready',
        'awready wready bvalid bresp arready rvalid rdata rresp',
        facts={'bursts':False,'ids':False,'byte_enable':True,'partial_write':True,
               'has_error':True},
        optional_facts={'has_error':True,'write_response_code':True,
                        'read_response_code':True},
        limits={'byte_enable':True,'partial_write':True,'bursts':False,'ids':False,
                'supported_data_widths':(32,),'address_units':'byte',
                'write_accept_policy':'address_and_data_channels_independently_handshaken',
                'channel_order_policy':'aw_and_w_either_order',
                'completion':'independent_channels_response',
                'has_error':True,'error_policy':'observe_native_response_code',
                'response_code_policy':'report_measured_code_and_name_nonzero_as_error',
                # `has_error` here means the slave *declares* response-code
                # pins, which is a property of the port list. It does not mean
                # this particular device can ever drive a non-OKAY code: the
                # pinned axiluart ties BRESP/RRESP to OKAY. Every projection
                # therefore reports the measured code, and a non-OKAY code is
                # reported as a protocol error when one is really observed.
                'response_code_reachability':'declared_pins_only_not_claimed_drivable',
                'outstanding_scope':'endpoint','max_outstanding':1}),
)


def list_template_contracts() -> tuple[ProtocolTemplateContract, ...]:
    return _TEMPLATES


# These are identities of existing admitted code branches, not additional
# generic protocol capabilities. In particular the burst and packed AXI tops
# cannot truthfully use the declarative single-beat AXI contract above.
_GENERATED_EXECUTOR_KINDS = frozenset((
    'obi_cpu', 'native_memory_cpu', 'rvx_memory_cpu', 'wishbone_cpu',
    'axi4_lite_cpu', 'axi4_cpu', 'cva6_packed_axi4_cpu', 'axi4_lite_uart',
    'ahb_lite_cpu',
    'wishbone_register_observe', 'wishbone_timer', 'wishbone_uart',
    'tlul_register_observe', 'tlul_gpio', 'tlul_timer', 'tlul_spi_host',
    'tlul_uart', 'tlul_i2c', 'tlul_spi_device', 'apb3_register_observe',
    'axi4lite_register_observe',
    'apb_gpio', 'apb_spi', 'apb_timer', 'apb_i2c',
))


def generated_executor_selection(document, endpoints, capabilities, *,
                                 protocol_templates=(), implementation_sources=()):
    """Bind a versioned existing top generator to its actual admitted inputs.

    Called only during artifact generation. The enclosing artifact and later
    build identities continue to authenticate the generated driver and tools.
    No additional runtime behavior is selected by this declaration.
    """
    kind = document['kind']
    if kind not in _GENERATED_EXECUTOR_KINDS:
        raise ValueError('template-unregistered-generated-executor')
    contract = {
        'schema_version': 'local_generated_executor_contract.v1',
        'template_id': 'local.generated.' + kind,
        'template_version': '1', 'variant_id': kind,
        'scope': 'generated_executor_only',
        'generation_stage': 'source_admitted_runtime_top',
        'protocol_capability_claim': False,
        'dut_semantics_verified': False,
    }
    binding = {
        'profile_sha256': document['plan']['profile_sha256'],
        'endpoints': [
            {'endpoint_id': endpoint.endpoint_id, 'function': endpoint.function,
             'protocol': list(endpoint.protocol),
             'roles': [{'role': field.role, 'physical_port': field.port,
                        'member_path': list(field.member_path),
                        'direction': field.direction, 'width': field.width,
                        'raw_lo': field.raw_lo, 'raw_hi': field.raw_hi,
                        'port_width': field.port_width}
                       for field in sorted(endpoint.fields, key=lambda row: row.role)]}
            for endpoint in sorted(endpoints, key=lambda row: row.endpoint_id)],
        'declared_profile_facts': {key: capabilities[key]
                                   for key in sorted(capabilities) if key != 'evidence'},
        'parameter_overrides': document['structural_build']['parameter_overrides'],
        'effective_max_wait_cycles': document['effective_max_wait_cycles'],
        'boot_contract': document['boot_contract'],
        'clock_schedule': document['clock_schedule'],
        'adapter_sources': document['adapter_sources'],
        'runtime_sv_sha256': document['runtime_sv_sha256'],
        'implementation_sources': list(implementation_sources),
        'physical_input_policy': {
            key: document[key] for key in (
                'functional_scope', 'fixed_physical_inputs', 'dynamic_physical_inputs',
                'bound_physical_inputs', 'serial_peer') if key in document},
    }
    if 'gpio_observation_contract' in document:
        from .pulp_gpio_probe_contract import validate_pulp_gpio_observation_contract, pulp_gpio_probe_document
        validate_pulp_gpio_observation_contract(document['gpio_observation_contract'])
        if kind != 'apb_gpio' or capabilities.get('gpio_observation_variant') != 'pulp_gpio_causal_v1':
            raise ValueError('pulp-gpio-observation-executor-selection')
        contract.update(template_id='pulp.gpio.causal', template_version='1', variant_id='pulp_gpio_causal_v1')
        binding['gpio_observation_contract'] = document['gpio_observation_contract']
        binding['gpio_probe_contract'] = pulp_gpio_probe_document()
    elif capabilities.get('gpio_observation_variant') is not None:
        raise ValueError('pulp-gpio-observation-executor-contract-required')
    if 'uart_fifo_observation_contract' in document:
        from .opentitan_uart_fifo_contract import validate_uart_fifo_observation_contract, uart_fifo_probe_document
        validate_uart_fifo_observation_contract(document['uart_fifo_observation_contract'])
        if kind != 'tlul_uart' or capabilities.get('uart_fifo_observation_variant') != 'opentitan_uart_rx_fifo_v1':
            raise ValueError('uart-fifo-observation-executor-selection')
        contract.update(template_id='opentitan.uart.rx_fifo', template_version='1', variant_id='opentitan_uart_rx_fifo_v1')
        binding['uart_fifo_observation_contract'] = document['uart_fifo_observation_contract']
        binding['uart_fifo_probe_contract'] = uart_fifo_probe_document()
    elif capabilities.get('uart_fifo_observation_variant') is not None:
        raise ValueError('uart-fifo-observation-executor-contract-required')
    result = {'schema_version': 'local_generated_executor_selection.v1',
              'contract': contract, 'contract_sha256': hashlib.sha256(_canonical(contract)).hexdigest(),
              'binding': binding, 'protocol_templates': list(protocol_templates),
              'runtime_effective': False, 'dut_semantics_verified': False}
    result['identity_sha256'] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


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
_CONTROL = frozenset('req gnt we rvalid error valid ready awvalid awready wvalid wready wlast bvalid bready arvalid arready rvalid rready rlast cyc stb ack err stall psel penable pwrite pready pslverr a_valid a_ready d_valid d_ready d_error read_request read_response write_request write_response'.split())
# AHB-Lite roles the CVW external bus really declares (configs/cpus/cvw/
# interface_description.json).  They are listed here rather than left to the
# ``source_defined`` fallback on purpose: an unclassified role escapes the
# per-field width check, so a wrong AHB width would go unnoticed.
#   * ``hready``/``hwrite``/``hresp`` are single-bit control lines;
#   * ``htrans`` is 2 bits, ``hsize``/``hburst`` 3, ``hprot`` 4 -- these are
#     defined by AHB-Lite itself, not by CVW;
#   * ``haddr``/``hwdata``/``hwstrb`` reuse the generic addr/data/lane roles
#     (the declaration maps HADDR/HWDATA/HWSTRB onto them), so they are already
#     covered by ``_ADDRESS``/``_DATA``/``_LANES`` above.
_CONTROL = _CONTROL | frozenset(('hready', 'hwrite', 'hresp'))
# AHB-native data/address/lane roles reuse the generic width classes below.
_FIXED = {'awlen':8,'arlen':8,'awsize':3,'arsize':3,'awburst':2,'arburst':2,'awlock':1,'arlock':1,
          'bresp':2,'rresp':2,'awprot':3,'arprot':3,'awcache':4,'arcache':4,'awqos':4,'arqos':4,
          'awregion':4,'arregion':4,'awatop':6,'a_opcode':3,'d_opcode':3,'a_param':3,'d_param':3,
          'htrans':2,'hsize':3,'hburst':3,'hprot':4,'hmastlock':1,'hsel':1}
_DATA = frozenset('wdata rdata dat_w dat_r pwdata prdata a_data d_data read_data write_data hwdata hrdata'.split())
# ``address`` is the address role name a real declaration already uses: the
# BOOM TileLink 1.0 interface description
# (configs/cpus/boom/interface_description.json).  Without it here the address
# width of that declared endpoint would escape both the per-field width check
# and the ``address_width`` capability comparison.
_ADDRESS = frozenset('addr adr awaddr araddr paddr a_address address haddr'.split())
_LANES = frozenset(('be','wstrb','sel','a_mask','write_strobe','hwstrb'))


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
