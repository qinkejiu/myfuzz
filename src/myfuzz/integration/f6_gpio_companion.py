"""Causal GPIO companion admission for the existing shared F6 assembly.

GPIOEN storage and native PADIN sampling retain distinct contracts and issuers.
No process, IRQ delivery or source authority is created by these documents.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

CONTRACT_ID='pulp-gpio-causal-register-bank.v1'


def _require(ok,reason):
    if not ok:raise ValueError('compiled-F6-GPIO-companion-'+reason)


def select_gpio_companion_source(profile,*,base_dir,selection):
    from myfuzz.local_harness.pulp_gpio_probe_contract import (
        verify_pulp_gpio_source_contract,pulp_gpio_probe_document,pulp_gpio_observation_contract)
    _require(selection==dict(contract_id=CONTRACT_ID,register='GPIOEN'),'source-selection')
    verify_pulp_gpio_source_contract(profile,base_dir=Path(base_dir))
    source=pulp_gpio_probe_document()['source']
    document=dict(schema_version='gpio_shared_source_contract.v1',kind='gpio.register-bank.v1',contract_id=CONTRACT_ID,
        profile_fingerprint=profile.profile_fingerprint,source=deepcopy(source),
        register=dict(name='GPIOEN',canonical_offset=4,width=32,read_mask=0xffffffff,write_mask=0xffffffff,
                      semantics='stable_gpioen_word_with_separate_pin_configuration_effects'),
        read_register=dict(name='PADIN',canonical_offset=8,width=32,read_mask=0xffffffff,write_mask=0,
                           semantics='read_only_native_synchronizer_latch',version_basis='native_sample_version'),
        irq_registers=dict(INTEN=24,INTTYPE_LOW=28,INTTYPE_HIGH=32,INTSTATUS=36,
                           status_ack='read_clear_unless_new_trigger'),
        observation_contract=pulp_gpio_observation_contract())
    document['digest']=sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return document


def gpio_companion_document(name,artifact,window,*,base_dir):
    from myfuzz.runtime.adapters.gpio_storage import bank_contract_facts,GPIO_TEMPLATE
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    from .compiled_storage_producer import _module_source
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    _require(artifact.runtime_document.get('kind')=='apb_gpio' and verify_native_physical_observation(artifact),
             'actual-causal-observation-required')
    source=select_gpio_companion_source(artifact.plan.profile,base_dir=base_dir,
        selection=dict(contract_id=CONTRACT_ID,register='GPIOEN'))
    bank=bank_contract_facts(artifact,base_dir=base_dir,endpoint_id=window.endpoint_id,template=GPIO_TEMPLATE)
    _require(bank.supports(register='GPIOEN',operation='write',offset=4)
        and bank.supports(register='PADIN',operation='read',offset=8),'register-bank')
    irq=[r for r in artifact.runtime_document['physical_exports'] if r['role']=='irq' and r['direction']=='output'
         and r['width']==1 and r['bit_lo']==r['bit_hi']==0]
    _require(len(irq)==1,'native-IRQ-export')
    return dict(schema_version='compiled_F6_gpio_companion.v1',component=name,
        artifact_digest=artifact.runtime_document['artifact_digest'],profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        window=dict(device_id=name,base=window.base,size=window.size,endpoint=window.endpoint_id),
        register='GPIOEN',read_register='PADIN',source_contract=source,semantic_bank_sha256=bank.sha256_hex,
        irq_source_port=irq[0]['physical_port'],session_source_sha256=_module_source(GeneratedPulpGpioSession),
        storage_operations='not_claimed_by_assembly',irq_consumption='unknown')


def create_gpio_companion(artifact,*,base_dir,cache_dir):
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    return GeneratedPulpGpioSession(artifact,base_dir=base_dir,cache_dir=cache_dir)


def gpio_companion_authority(local):
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority,_AUTHORITIES
    _require(type(local) is GeneratedPulpGpioSession,'exact-session-required')
    authority=_AUTHORITIES.get(local)
    if authority is None:authority=GpioRegisterVersionAuthority(local)
    _require(type(authority) is GpioRegisterVersionAuthority and authority.target is local,'exact-authority-owner')
    return authority


def validate_gpio_companion_session(document,artifact,local):
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    _require(type(local) is GeneratedPulpGpioSession and local.artifact is artifact,'exact-session-owner')
    _require(local.routed_register_access_enabled and local.identity_document()['runtime_artifact']==artifact.runtime_document,
             'live-causal-session')
    _require(document['register']=='GPIOEN' and document['read_register']=='PADIN','distinct-register-scopes')
