"""Actual E20 preparation and generic RVFI transport; no native execution."""
from pathlib import Path
from contextlib import closing

ROOT=Path(__file__).resolve().parents[2]


def test_actual_e20_declared_rvfi_is_available_without_irq_authority(tmp_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session,rvfi_observation_contract
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.router import DataflowRouter,DeviceWindow
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    descriptor=load_descriptor(ROOT/'configs/scenarios/compiled-f4-obi-apb-timer-cv32e20/generic_scenario.json',base_dir=ROOT)
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        with closing(create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
                capability_paths=(descriptor.capability,),supplement_path=descriptor.supplement,
                generated_dir=tmp_path/'generated',flow_ids=descriptor.flow_ids)) as preparation:
            artifact=preparation.artifacts['processor']
            contract=rvfi_observation_contract(artifact)
            assert contract['schema_version']=='rvfi_observation.v1'
            assert len(contract['fields'])==27
            assert contract['fields']['rvfi_order']==64
            assert 'rvfi_ext_irq_valid' not in contract['fields']
            target=GeneratedApb3RegisterSession(preparation.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path/'cache')
            cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=tmp_path/'cache',
                memory=PersistentMemory(regions=(MemoryRegion('ram',65536,196608),),
                    initialization_seed=0,max_initialized_bytes=196608),router=DataflowRouter((DeviceWindow('peripheral',0x40001000,4096,target),)))
            assert cpu._rvfi_enabled and not cpu.native_irq_receipts_enabled
            assert cpu.process is None
            # The generated driver snapshots every admitted export already;
            # no CPU-specific generator or artificial RVFI field is required.
            names={r['physical_port']:r['runtime_name'] for r in artifact.runtime_document['physical_exports']}
            driver=(tmp_path/'generated/processor/driver.cpp').read_text()
            assert all(names[name] in driver for name in contract['fields'])
            from unittest.mock import patch
            from tests.local_harness.test_cpu_session import make_receipt
            from myfuzz.local_harness.session import GeneratedLocalSession
            def measured_command(op,fields):
                receipt=make_receipt(cpu,fields,{})
                outputs={r['runtime_name']:(('0'*r['hex_digits']) if r['width']>64 else 0)
                    for r in artifact.runtime_document['physical_exports'] if r['direction']=='output'}
                outputs.update({names[n]:v for n,v in dict(rvfi_valid=1,rvfi_order=7,
                    rvfi_insn=0x13,rvfi_pc_rdata=65536).items()})
                receipt.payload['observations']['physical']=outputs
                receipt.payload['samples'][0]['post']['physical']=outputs
                return receipt
            with patch.object(GeneratedLocalSession,'command',side_effect=measured_command):
                cpu.step_local({})
            event=cpu.cpu_events[-1]
            assert event['order']==7 and event['pc_rdata']==65536
            assert 'irq_serial_observation' not in event
            assert 'observation_contract' not in event
