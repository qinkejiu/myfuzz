"""Detached selected DMA links remain distinct from live artifact authority."""
from copy import deepcopy
import pytest
from myfuzz.local_harness import dma_artifact_endpoint_links as links
from myfuzz.local_harness.template_contracts import list_template_contracts
from myfuzz.local_harness.wishbone_dma_fields import DMA_SELECTED_MASTER_SHAPE


def document():
    provider=links._SELECTED_PROVIDER_CONTRACT
    contract,= [c for c in list_template_contracts() if c.template_id=='master.wishbone-pipelined'
                and c.variant_id=='dma-selected']
    binding=dict(profile_endpoint_sha256='1'*64,template_id=contract.template_id,
        template_version=contract.template_version,variant_id=contract.variant_id,
        contract_sha256=contract.identity_sha256,selection_sha256='2'*64)
    roles=[]
    for role,(direction,width) in sorted(DMA_SELECTED_MASTER_SHAPE.items()):
        roles.append(dict(role=role,direction=direction,width=width,physical_port='port_'+role,
            member_path=[],raw_lo=0,raw_hi=width-1,port_width=width,backend_port='mwb_'+role))
    link=dict(link_id='mwb',endpoint_id='dma.memory',function='memory_master',
        protocol_side='master',backend_channel='mwb',template_binding=binding,roles=roles)
    doc=dict(schema_version='dma_artifact_endpoint_links.v1',provider_id=links.PROVIDER_ID,
        provider_version='1',provider_contract_sha256=links._sha(provider),
        runtime_artifact_sha256='3'*64,runtime_sv_sha256='4'*64,cpp_sha256='5'*64,links=[link])
    doc['identity_sha256']=links._sha(doc)
    return doc


def test_selected_link_requires_sel_and_selected_contract():
    doc=document();parsed=links.parse_dma_artifact_endpoint_links(doc)
    assert parsed.document()['links'][0]['template_binding']['variant_id']=='dma-selected'
    assert any(r['role']=='sel' and r['width']==4 for r in doc['links'][0]['roles'])
    for bad in ('missing-sel','wrong-digest','legacy-template'):
        changed=deepcopy(doc)
        if bad=='missing-sel': changed['links'][0]['roles']=[r for r in changed['links'][0]['roles'] if r['role']!='sel']
        elif bad=='wrong-digest':changed['provider_contract_sha256']=links._sha(links._PROVIDER_CONTRACT)
        else:changed['links'][0]['template_binding']['variant_id']='dma-full-word-no-select'
        changed['identity_sha256']=links._sha({k:v for k,v in changed.items() if k!='identity_sha256'})
        with pytest.raises(ValueError):links.parse_dma_artifact_endpoint_links(changed)
    # Parsing a detached declaration alone cannot satisfy live artifact admission.
    with pytest.raises(ValueError):links.validate_dma_artifact_endpoint_links(doc,object())


def test_selected_generated_link_matches_source_bound_f6_provider():
    from pathlib import Path
    from dataclasses import replace
    from myfuzz.local_harness import (load_local_harness_request,plan_local_harness,
        render_local_harness,verify_local_source_lock)
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider,f6_dma_static_bindings
    from myfuzz.composition.component_profile import elaboration_mode_scope
    root=Path(__file__).resolve().parents[2]
    request=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipdma_smoke/component_profile.json',
        instance_id='dma',reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16))
    with elaboration_mode_scope('direct'):
        plan=plan_local_harness(request,base_dir=root)
        structural=render_local_harness(plan)
        verified=verify_local_source_lock(plan.profile,base_dir=root)
        linked=links.render_dma_linked_runtime(plan,structural,verified,base_dir=root,provider_id=links.PROVIDER_ID)
        provider=select_f6_dma_source_provider(plan.profile,base_dir=root)
        static_master,control=f6_dma_static_bindings(provider,plan.profile,base_dir=root)
    generated,=linked.endpoint_links_document()['links']
    assert static_master==generated
    assert control['variant_id']=='dma-selected'
    assert any(row['physical_port']=='o_mwb_sel' and row['backend_port']=='mwb_sel'
               for row in generated['roles'])
    with pytest.raises(ValueError):
        links.validate_dma_artifact_endpoint_links(linked.endpoint_links_document(),
            replace(linked.artifact,runtime_sv=linked.artifact.runtime_sv+'\n'))


def test_f6_static_compiler_accepts_source_bound_selected_dma():
    from pathlib import Path
    from dataclasses import replace
    from myfuzz.composition.component_profile import load_component_profile,elaboration_mode_scope
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.compiled_paths import PathComponent,load_path_wiring
    from myfuzz.scenario.f6_execution_contract import compile_f6_execution_contract
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider,f6_dma_static_bindings
    from tests.integration.test_compiled_f6_contract import source_inputs
    root=Path(__file__).resolve().parents[2]
    request,_,_=source_inputs()
    profile=load_component_profile(root/'configs/peripherals/zipdma_smoke/component_profile.json')
    sidecar=dict(schema_version='ip_test_capability.v2',component_id=profile.component_id,
        profile_fingerprint=profile.profile_fingerprint,
        endpoint_capabilities=[dict(endpoint_id='dma.control',operations=['request','accept','response','read','write','wait']),
            dict(endpoint_id='dma.memory',operations=['request','accept','response','read','write'])],
        register_semantics=[],observation_mappings=[dict(mapping_id='native-master',
            endpoint_id='dma.memory',role='adr',observation_kind='port_sample',evidence_ref='source:zipdma')],
        feature_contract=dict(provider_id='zipdma.transfer.v1',provider_version='1',operations=[dict(
            endpoint_id='dma.memory',operation='transfer',required_observation_mappings=['native-master'],
            evidence_ref='source:zipdma')]))
    capability=load_ip_test_capability(sidecar,profile=profile)
    provider=select_f6_dma_source_provider(profile,base_dir=root)
    with elaboration_mode_scope('direct'):
        master,_=f6_dma_static_bindings(provider,profile,base_dir=root)
        wiring=deepcopy(request.wiring.document)
        for row in wiring['dma_master_route_bindings']:row['initiator']=deepcopy(master['template_binding'])
        wiring['deliveries'][0]['trigger']='level'
        selected=replace(request,devices=(PathComponent('dma',profile,capability,()),),
                         wiring=load_path_wiring(wiring))
        contract=compile_f6_execution_contract(selected,base_dir=root)
        wrong_irq=deepcopy(wiring);wrong_irq['deliveries'][0]['trigger']='pulse'
        with pytest.raises(ValueError,match='f6-native-irq-binding-required'):
            compile_f6_execution_contract(replace(selected,wiring=load_path_wiring(wrong_irq)),base_dir=root)
        wrong_sel=deepcopy(wiring)
        wrong_sel['dma_master_route_bindings'][0]['initiator']['variant_id']='dma-full-word-no-select'
        with pytest.raises(ValueError,match='contract-drift'):
            compile_f6_execution_contract(replace(selected,wiring=load_path_wiring(wrong_sel)),base_dir=root)
    assert contract['dma']['behavior']['length_unit']=='bytes'
    assert contract['dma']['selected_template']['master']['variant_id']=='dma-selected'
    assert contract['irq']['delivery_policy']=='level'
    assert contract['irq']['clear_policy']=='software_write'
