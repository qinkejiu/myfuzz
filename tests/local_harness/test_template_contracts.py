"""Contract-only selection has no executable RTL or runtime capability claim."""
from dataclasses import replace
from pathlib import Path
import importlib
import unittest
from myfuzz.composition.component_profile import ResolvedEndpoint, ResolvedField


def registry():
    return importlib.import_module('myfuzz.local_harness.template_contracts')


def endpoint(protocol, request, response, widths=None, function='memory_master'):
    widths = widths or {}
    fields = []
    for role in sorted(set(request) | set(response)):
        width = widths.get(role, 1)
        direction = 'output' if role in request else 'input'
        if function == 'mmio_slave':
            direction = 'input' if role in request else 'output'
        fields.append(ResolvedField('bus', role, 'physical_' + role, (), direction, width,
                                   0, width - 1, False, 'source.sv', 1, width))
    return ResolvedEndpoint('bus', function, protocol, tuple(fields))


def obi():
    return endpoint(('obi', '1'), {'req','addr','we','wdata','be'}, {'gnt','rvalid','rdata','error'},
                    {'addr':32,'wdata':32,'rdata':32,'be':4})


def native():
    return endpoint(('ready-valid-memory','1'), {'valid','addr','wdata','wstrb'}, {'ready','rdata'},
                    {'addr':32,'wdata':32,'rdata':32,'wstrb':4})


class TemplateContractTests(unittest.TestCase):
    def test_inventory_versioned_frozen_and_no_runtime_claim(self):
        contracts = registry().list_template_contracts()
        # Fourteen contracts: nine CPU-side and five target-side.  The target
        # AXI4-Lite contract is the slave counterpart of ``cpu.axi4-lite`` and
        # is the only one whose request spans two independently handshaken
        # channels, so it is a separate shape rather than a CPU-side reuse.
        # The two newest entries are the intentional inventory change this
        # repository's real TileLink 1.0 declaration requires:
        # ``cpu.tilelink``/``declared-four-role`` and
        # ``cpu.tilelink``/``declared-five-role-write-capable`` mirror the role
        # vocabulary of configs/cpus/boom/interface_description.json
        # (``cpu.instruction_memory`` and ``cpu.data_memory``, protocol
        # ``["tilelink","1"]``).  They are CPU-side entries and are not
        # ``target.tl-ul``, which is the TileLink-UL peripheral target contract.
        #
        # 17 = 14 + the two OBI variants without bus-error pins (2026-10-13,
        # derived from the pinned CV32E40P core, which has no instr_err_i/
        # data_err_i) + the AHB-Lite CPU-side entry (cpu.ahb-lite/
        # cvw-external-bus, derived from CVW's real wallypipelinedsoc boundary).
        self.assertEqual(len(contracts), 17)
        ids = [(c.template_id,c.template_version,c.variant_id) for c in contracts]
        self.assertEqual(len(ids),len(set(ids)))
        for contract in contracts:
            self.assertFalse(contract.document()['runtime_effective'])
            self.assertEqual(contract.template_version,'1')

    def test_target_axi4_lite_is_the_slave_side_not_a_cpu_reuse(self):
        """The slave contract must differ from the CPU one, not duplicate it."""
        cpu = next(c for c in registry().list_template_contracts()
                   if (c.template_id, c.variant_id) == ('cpu.axi4-lite', 'no-response-code'))
        target = next(c for c in registry().list_template_contracts()
                      if c.template_id == 'target.axi4-lite')
        self.assertEqual(target.side, 'target')
        # A real slave drives the response codes the CPU-side contract omits.
        self.assertIn('bresp', target.required_roles + target.optional_roles)
        self.assertIn('rresp', target.required_roles + target.optional_roles)
        self.assertNotIn('bresp', cpu.required_roles + cpu.optional_roles)
        self.assertEqual(dict(target.limits)['has_error'], True)
        self.assertEqual(dict(cpu.limits)['error_response'], False)
        self.assertEqual(dict(target.limits)['channel_order_policy'],
                         'aw_and_w_either_order')
        # The address half is a request role on both sides of the boundary.
        self.assertIn('awaddr', target.host_to_device_roles)
        self.assertIn('araddr', target.host_to_device_roles)
        self.assertNotIn('awready', target.host_to_device_roles)

    def test_obi_selects_by_fields_not_physical_names(self):
        ep=obi()
        selected=registry().select_template_contract(ep,{'data_width':32,'address_width':32})
        self.assertEqual(selected.contract.variant_id,'read-write')
        renamed=replace(ep,fields=tuple(replace(f,port='different_'+f.role) for f in ep.fields))
        other=registry().select_template_contract(renamed,{'data_width':32,'address_width':32})
        self.assertEqual(selected.contract,other.contract)
        self.assertNotEqual(selected.identity_sha256,other.identity_sha256)
        read_only=replace(ep,fields=tuple(f for f in ep.fields if f.role not in {'we','wdata','be'}))
        self.assertEqual(registry().select_template_contract(read_only,{}).contract.variant_id,'read-only')

    def test_missing_unknown_direction_width_and_id_mismatches_refuse(self):
        ep=obi()
        variants=[replace(ep,fields=ep.fields[1:]),
                  replace(ep,fields=ep.fields+(replace(ep.fields[0],role='mystery'),)),
                  replace(ep,fields=(replace(ep.fields[0],direction='input'),)+ep.fields[1:]),
                  replace(ep,fields=tuple(replace(f,width=3,raw_hi=2,port_width=3) if f.role=='be' else f for f in ep.fields))]
        for bad in variants:
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                registry().select_template_contract(bad,{})

    def test_native_requires_explicit_completion_contract(self):
        with self.assertRaisesRegex(ValueError,'explicit'):
            registry().select_template_contract(native(),{})
        selected=registry().select_template_contract(native(),{},template_id='cpu.native-memory',
            template_version='1',variant_id='completion-no-error')
        self.assertEqual(dict(selected.contract.limits)['completion'],'valid_and_ready')
        self.assertFalse(selected.document()['dut_semantics_verified'])

    def test_unknown_id_or_version_or_partial_selection_refuse(self):
        for kwargs in ({'template_id':'cpu.obi'}, {'template_id':'cpu.obi','template_version':'2','variant_id':'read-write'},
                       {'template_id':'cpu.obi','template_version':'1','variant_id':'unregistered'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                registry().select_template_contract(obi(),{},**kwargs)

    def test_axi_lite_missing_responses_and_wishbone_missing_error_are_explicit(self):
        ax=endpoint(('axi4-lite','1'),{'awvalid','awaddr','awprot','wvalid','wdata','wstrb','bready','arvalid','araddr','arprot','rready'},
            {'awready','wready','bvalid','arready','rvalid','rdata'},
            {'awaddr':32,'araddr':32,'wdata':32,'rdata':32,'wstrb':4,'awprot':3,'arprot':3})
        self.assertEqual(registry().select_template_contract(ax,{}).contract.variant_id,'no-response-code')
        with self.assertRaises(ValueError):
            registry().select_template_contract(replace(ax,fields=ax.fields+(ResolvedField('bus','bresp','bresp',(), 'input',2,0,1,False,'x',1,2),)),{})
        wb=endpoint(('wishbone','classic'),{'cyc','stb','we','adr','dat_w','sel'},{'ack','dat_r'},
            {'adr':32,'dat_w':32,'dat_r':32,'sel':4})
        with self.assertRaisesRegex(ValueError,'explicit'):
            registry().select_template_contract(wb,{})
        self.assertEqual(registry().select_template_contract(wb,{},template_id='cpu.wishbone',
            template_version='1',variant_id='no-err-stall').contract.variant_id,'no-err-stall')

    def test_ip_apb_has_no_byte_enable(self):
        ep=endpoint(('apb','3'),{'paddr','psel','penable','pwrite','pwdata'},{'pready','prdata','pslverr'},
            {'paddr':12,'pwdata':32,'prdata':32},function='mmio_slave')
        selected=registry().select_template_contract(ep,{'byte_enable':False,'partial_write':False})
        self.assertFalse(dict(selected.contract.limits)['byte_enable'])
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{'byte_enable':True,'partial_write':True})

    def test_target_wishbone_semantics_require_typed_facts(self):
        ep=endpoint(('wishbone','classic'),{'cyc','stb','we','adr','dat_w','sel'},{'ack','stall','dat_r'},
            {'adr':2,'dat_w':32,'dat_r':32,'sel':4},function='mmio_slave')
        caps={'address_units':'word','has_address_port':True,'sel_implemented':True,'ack_requires_cyc':True,
              'wishbone_flavour':'registered-ack','byte_enable':True,'partial_write':True,'has_error':False}
        self.assertEqual(registry().select_template_contract(ep,caps).contract.variant_id,'word-addressed-registered-ack')
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{})
        timer=replace(ep,fields=tuple(f for f in ep.fields if f.role!='adr'))
        caps.update(has_address_port=False,sel_implemented=False,ack_requires_cyc=False,
                    wishbone_flavour='registered-ack-cyc-ignored',byte_enable=False,partial_write=False)
        result=registry().select_template_contract(timer,caps)
        self.assertEqual(result.contract.variant_id,'addressless-select-ignored')
        self.assertEqual(dict(result.contract.limits)['request_phase'],'one_cycle_stb_pulse')

    def test_axi4_limits_ids_and_optional_groups(self):
        request='awid awaddr awlen awsize awburst awvalid wdata wstrb wlast wvalid bready arid araddr arlen arsize arburst arvalid rready'.split()
        response='awready wready bid bresp bvalid arready rid rdata rresp rlast rvalid'.split()
        widths={'awaddr':64,'araddr':64,'wdata':64,'rdata':64,'wstrb':8,'awid':4,'arid':4,'bid':4,'rid':4,
                'awlen':8,'arlen':8,'awsize':3,'arsize':3,'awburst':2,'arburst':2,'bresp':2,'rresp':2}
        ep=endpoint(('axi4','1'),request,response,widths)
        result=registry().select_template_contract(ep,{'bursts':False,'id_width':4})
        self.assertFalse(dict(result.contract.limits)['bursts'])
        self.assertFalse(dict(result.contract.limits)['atomics'])
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{'bursts':True})
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{})
        bad=replace(ep,fields=tuple(replace(f,width=5,raw_hi=4,port_width=5) if f.role=='rid' else f for f in ep.fields))
        with self.assertRaises(ValueError):
            registry().select_template_contract(bad,{'bursts':False})
        extra=ResolvedField('bus','awuser','user',(), 'output',64,0,63,False,'x',1,64)
        with self.assertRaises(ValueError):
            registry().select_template_contract(replace(ep,fields=ep.fields+(extra,)),{'bursts':False})
        users=tuple(ResolvedField('bus',role,role,(),'input' if role in ('buser','ruser') else 'output',
            64,0,63,False,'x',1,64) for role in ('awuser','wuser','buser','aruser','ruser'))
        with self.assertRaises(ValueError):
            registry().select_template_contract(replace(ep,fields=ep.fields+users),{'bursts':False,'user_width':23})

    def test_opentitan_tlul_requires_users_integrity_and_roundtrip(self):
        request='a_valid a_opcode a_param a_size a_source a_address a_mask a_data a_user d_ready'.split()
        response='a_ready d_valid d_opcode d_param d_size d_source d_sink d_data d_user d_error'.split()
        widths={'a_opcode':3,'a_param':3,'d_opcode':3,'d_param':3,'a_size':2,'d_size':2,'a_source':8,
                'd_source':8,'a_address':32,'a_data':32,'d_data':32,'a_mask':4,'a_user':23,'d_user':14}
        ep=endpoint(('tl-ul','1'),request,response,widths,function='mmio_slave')
        caps={'integrity':'required','user_width':23,'d_user_width':14}
        selected=registry().select_template_contract(ep,caps)
        self.assertEqual(selected.contract.variant_id,'user-integrity')
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{})
        with self.assertRaises(ValueError):
            registry().select_template_contract(replace(ep,fields=tuple(f for f in ep.fields if f.role!='a_user')),caps)
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{**caps,'d_user_width':23})

    def test_field_endpoint_overlap_and_wrong_capability_type_refuse(self):
        ep=obi()
        cases=[replace(ep,fields=(replace(ep.fields[0],endpoint_id='elsewhere'),)+ep.fields[1:]),
               replace(ep,fields=(replace(ep.fields[0],port=ep.fields[1].port),)+ep.fields[1:])]
        for bad in cases:
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                registry().select_template_contract(bad,{})
        with self.assertRaises(ValueError):
            registry().select_template_contract(ep,{'max_outstanding':True})


def policy_fixture():
    from tests.local_harness.test_tuning import bound_fixture
    from myfuzz.composition.component_profile import EndpointSpec,ProfileField,bind_profile
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    profile,binding=bound_fixture()
    bus=obi()
    declared=EndpointSpec('bus','memory_master',('obi','1'),tuple(
        ProfileField(f.role,direction=f.direction,width=f.width,aliases=(f.port,)) for f in bus.fields))
    ports=tuple(ElaboratedPortFact(f.port,f.direction,f.width,False,'source.sv',1,1) for f in bus.fields)
    profile=replace(profile,endpoints=profile.endpoints+(declared,),capabilities={'data_width':32,'address_width':32})
    facts=replace(binding.facts,ports=binding.facts.ports+ports)
    return profile,bind_profile(profile,facts)


class EndpointPolicyTests(unittest.TestCase):
    def validate(self,policy):
        from myfuzz.local_harness.tuning import load_local_harness_tuning,validate_local_harness_tuning
        profile,binding=policy_fixture()
        return validate_local_harness_tuning(load_local_harness_tuning({'endpoint_policies':[policy]}),
                                             profile=profile,binding=binding)

    def test_policy_is_contract_configuration_only(self):
        policy={'endpoint_id':'bus','template_id':'cpu.obi','template_version':'1',
                'variant_id':'read-write','max_outstanding':1}
        result=self.validate(policy)
        self.assertFalse(result.document()['runtime_effective'])
        self.assertEqual(result.document()['endpoint_contracts'][0]['contract']['template_id'],'cpu.obi')

    def test_wrong_version_variant_or_concurrency_refuse(self):
        policy={'endpoint_id':'bus','template_id':'cpu.obi','template_version':'1',
                'variant_id':'read-write','max_outstanding':1}
        for changes in ({'template_version':'2'},{'variant_id':'read-only'},{'max_outstanding':2}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.validate({**policy,**changes})


class CapabilityBoundaryTests(unittest.TestCase):
    def test_no_error_pin_contract_refuses_claimed_error_response(self):
        with self.assertRaises(ValueError):
            registry().select_template_contract(native(),{'error_response':True},
                template_id='cpu.native-memory',template_version='1',variant_id='completion-no-error')

    def test_contract_document_contains_field_shape_rules_and_is_fresh(self):
        contract=registry().select_template_contract(obi(),{}).contract
        self.assertEqual(contract.document()['role_shapes']['req'],{'width':1})
        self.assertEqual(contract.document()['role_shapes']['be'],{'width':'data_width/8'})
        doc=contract.document()
        doc['limits']['supported_data_widths'].append(128)
        self.assertEqual(contract.document()['limits']['supported_data_widths'],[32])

    def test_profile_wait_limit_and_width_limits_are_finite(self):
        with self.assertRaises(ValueError):
            registry().select_template_contract(obi(),{'max_wait_cycles':1025})

    def test_explicit_semantics_cannot_contradict_typed_profile_facts(self):
        with self.assertRaises(ValueError):
            registry().select_template_contract(native(),{'completion_semantics':'request_acceptance'},
                template_id='cpu.native-memory',template_version='1',variant_id='completion-no-error')
        read_only=replace(obi(),fields=tuple(f for f in obi().fields if f.role not in {'we','wdata','be'}))
        self.assertEqual(registry().select_template_contract(read_only,{'byte_enable':True}).contract.variant_id,'read-only')
        with self.assertRaises(ValueError):
            registry().select_template_contract(read_only,{'error_response':False})

    def test_optional_semantic_facts_are_declared_in_versioned_contract(self):
        selected=registry().select_template_contract(native(),{},template_id='cpu.native-memory',
            template_version='1',variant_id='completion-no-error')
        self.assertEqual(selected.contract.document()['optional_profile_facts'],{'completion_semantics':'completion'})


class RegisteredOperationTests(unittest.TestCase):
    """A kind's driver commands must come from its registered operation table.

    The driver's command whitelist used to be restated by hand next to the
    registry, so the AXI4-Lite register member could send ACCESS_ but not
    SOURCE_/BIND_ even though its table declares all four. Deriving the
    whitelist from the table removes the possibility of the two disagreeing.
    """

    @staticmethod
    def operations(kind):
        module = importlib.import_module('myfuzz.local_harness.session')
        return module.registered_operations(kind)

    def test_the_axi4lite_register_member_offers_its_source_and_bind_commands(self):
        operations = self.operations('axi4lite_register_observe')
        self.assertIn('ACCESS_AXIL_REG', operations)
        self.assertIn('SOURCE_AXIL_REG', operations)
        self.assertIn('BIND_AXIL_REG', operations)

    def test_wishbone_register_observation_genuinely_has_no_source_or_bind(self):
        """Deriving the list must not invent operations a kind never declared."""
        operations = self.operations('wishbone_register_observe')
        self.assertIn('ACCESS_WB_REG', operations)
        self.assertFalse([name for name in operations
                          if name.startswith(('SOURCE_', 'BIND_'))])

    def test_an_unknown_kind_offers_nothing(self):
        self.assertEqual(frozenset(), self.operations('not_a_registered_kind'))


class Axi4LiteRegisterPolicyShapeTests(unittest.TestCase):
    """The AXI4-Lite register policy must answer with one fixed shape.

    It gained two facts when the serial peer became declarable, and one of its
    two return paths was missed. A caller then unpacked five names from a
    three-tuple and failed at render time instead of at the policy boundary.
    """

    @staticmethod
    def plan(*, with_peer=False):
        from myfuzz.local_harness import (load_local_harness_request,
                                          plan_local_harness)
        tuning = {
            'endpoint_policies': [dict(endpoint_id='uart.bus',
                                       template_id='target.axi4-lite',
                                       template_version='1',
                                       variant_id='single-outstanding-error-codes',
                                       max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n', value=0)]}
        if with_peer:
            tuning['environment_bindings'] = [dict(endpoint_id='uart.pins',
                                                   role='rx',
                                                   source_id='serial_rx_frame')]
            tuning['uart_8n1_peers'] = [dict(endpoint_id='uart.pins',
                                             rx_role='rx', tx_role='tx',
                                             source_id='serial_rx_frame',
                                             format='8N1',
                                             clocks_per_bit=32, idle_bits=17)]
            tuning['startup_writes'] = [dict(sequence=1, offset=0, value=25)]
        request = load_local_harness_request(dict(
            schema_version='local_harness.v2',
            profile_path='configs/peripherals/zipcpu_axiluart/component_profile.json',
            instance_id='policy_shape', reset_assert_ticks=8,
            reset_release_ticks=8, max_wait_cycles=16, tuning=tuning))
        return plan_local_harness(request, base_dir=Path(__file__).resolve().parents[2])

    def test_both_return_paths_report_the_same_arity(self):
        module = importlib.import_module(
            'myfuzz.local_harness.axi4lite_register_template')
        plan = self.plan()
        without_abi = module.register_observe_policy(plan)
        abi = [{'endpoint_id': 'uart.pins', 'role': 'cts_n', 'width': 1,
                'direction': 'input', 'disposition': 'external',
                'wrapper_name': 'lh_p_1_0_0'}]
        with_abi = module.register_observe_policy(plan, abi)
        self.assertEqual(5, len(without_abi))
        self.assertEqual(len(without_abi), len(with_abi))

    def test_a_declared_peer_is_reported_with_its_own_schema_and_startup(self):
        module = importlib.import_module(
            'myfuzz.local_harness.axi4lite_register_template')
        _, dynamic, _, peer, startup = module.register_observe_policy(
            self.plan(with_peer=True))
        self.assertEqual({('uart.pins', 'rx'): 'serial_rx_frame'}, dynamic)
        self.assertEqual('generated_axi4lite_uart_8n1_tuning.v1',
                         peer['schema_version'],
                         'the peer document must not be labelled as TL-UL')
        self.assertEqual('uart.pins.rx', peer['rx_port'])
        self.assertEqual(((0, 25),), startup)

    def test_without_a_declared_peer_there_is_no_peer_and_no_startup(self):
        module = importlib.import_module(
            'myfuzz.local_harness.axi4lite_register_template')
        _, dynamic, _, peer, startup = module.register_observe_policy(self.plan())
        self.assertEqual({}, dynamic)
        self.assertIsNone(peer)
        self.assertEqual((), startup)
