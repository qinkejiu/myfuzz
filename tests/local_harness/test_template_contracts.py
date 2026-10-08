"""Contract-only selection has no executable RTL or runtime capability claim."""
from dataclasses import replace
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
        self.assertEqual(len(contracts), 11)
        ids = [(c.template_id,c.template_version,c.variant_id) for c in contracts]
        self.assertEqual(len(ids),len(set(ids)))
        for contract in contracts:
            self.assertFalse(contract.document()['runtime_effective'])
            self.assertEqual(contract.template_version,'1')

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
