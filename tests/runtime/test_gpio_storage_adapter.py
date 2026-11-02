"""Real GPIOEN artifact admission and exact-session bound authority, no RTL."""
import pytest
from tests.integration.test_shared_f5_runtime import prepared, ROOT
from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.adapters.gpio_storage import (
    GPIO_STORAGE_ADAPTER_ID, artifact_contract_facts, bind_gpio_storage_adapter,
)


def test_actual_gpio_artifact_has_distinct_causal_storage_admission(prepared):
    artifact = prepared.artifacts['peripheral']
    component = verify_component(artifact, preparation=prepared, base_dir=ROOT)
    endpoint = component.endpoints()[0]
    assert artifact.runtime_document['kind'] == 'apb_gpio'
    assert endpoint['template'] == ['pulp.gpio.causal','1','pulp_gpio_causal_v1']
    assert endpoint['semantic_kind'] == 'gpio.register-bank.v1'
    assert component.document()['source_verifier']['id'] == 'gpio.causal-storage.admission.v1'
    from myfuzz.runtime.registry import registrations
    matched = [r for r in registrations() if tuple(endpoint['template']) in r.templates]
    assert [r.adapter_id for r in matched] == [GPIO_STORAGE_ADAPTER_ID]


def test_gpio_semantics_are_gpioen_only_and_use_actual_issuer(prepared):
    semantic = artifact_contract_facts(prepared.artifacts['peripheral'], base_dir=ROOT,
        endpoint_id='gpio.bus', template=('pulp.gpio.causal','1','pulp_gpio_causal_v1'))
    doc = semantic.document()
    assert doc['decode']['mask'] == 124 and doc['decode']['value'] == 4
    assert doc['issuer_contract']['issuer_id'] == 'GpioRegisterVersionAuthority'
    assert doc['issuer_contract']['authority'] is False
    assert doc['endpoint']['template'] != ['target.apb3','1','full-word']


def test_bound_gpio_uses_exact_session_and_existing_real_authority(prepared,tmp_path):
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    from myfuzz.runtime.registry import select_adapter
    from tests.runtime.test_registry import requirement_for
    component=verify_component(prepared.artifacts['peripheral'],preparation=prepared,base_dir=ROOT)
    selection=select_adapter(component,requirement_for(component.endpoints()[0]),preparation=prepared)
    target=GeneratedPulpGpioSession(prepared.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path)
    with pytest.raises(ValueError,match='installed-gpioen-authority'):
        bind_gpio_storage_adapter(component=component,session=target,selection=selection,
                                  preparation=prepared,endpoint_id='gpio.bus')
    authority=GpioRegisterVersionAuthority(target)
    bound=bind_gpio_storage_adapter(component=component,session=target,selection=selection,
                                  preparation=prepared,endpoint_id='gpio.bus')
    assert bound._authority is authority
    bound.assert_current()
    with pytest.raises(ValueError,match='current-state-unavailable'):
        bound.current()  # No native process or sample can be invented.
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    with pytest.raises(GenericRuntimeRefused):bound.provider.prepare(None,None)
    bound.close()
    with pytest.raises(ValueError):bound.assert_current()


def test_gpio_static_pins_are_reused_only_inside_execution_scope(monkeypatch):
    from myfuzz.runtime.adapters import gpio_storage
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    calls=[]
    monkeypatch.setattr(gpio_storage,'_pin_uncached',lambda:calls.append('read') or 'a'*64)
    with execution_validation_scope():
        assert gpio_storage._pin()==gpio_storage._pin()
        assert len(calls)==1
    assert len(calls)==2  # Entry/exit actual validation, no timestamp cache.


def test_factory_private_snapshot_binds_gpio_and_checks_every_artifact_field(prepared,tmp_path,monkeypatch):
    from dataclasses import replace
    from unittest.mock import patch
    from myfuzz.local_harness.generated_execution_admission import create_compiled_execution
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.integration import compiled_f4
    from myfuzz.runtime.registry import select_adapter
    from tests.runtime.test_registry import requirement_for
    from types import SimpleNamespace
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    # Stub build-only work while retaining the actual factory/private snapshot.
    # Restore producer methods before installing and testing the real authority.
    with monkeypatch.context() as build_only:
        build_only.setattr(GeneratedLocalSession,'prepare_local',lambda self:None)
        build_only.setattr(GeneratedLocalSession,'configure_built_executable_receipt',lambda self:None)
        build_only.setattr(GeneratedLocalSession,'validate_built_executable_receipt',lambda self:{})
        build_only.setattr(compiled_f4,'validate_built_receipts',lambda *args:None)
        build_only.setattr(compiled_f4,'build_storage_producer',
            lambda binding,artifact,base_dir,cache_dir,max_cases:
            (GeneratedPulpGpioSession(artifact,base_dir=base_dir,cache_dir=cache_dir),SimpleNamespace()))
        with patch('subprocess.Popen',side_effect=AssertionError('native launch forbidden')):
            runtime=create_compiled_execution(artifacts=prepared.artifacts,compiled_inputs=prepared.compiled_inputs(),
                executor='compiled_f4_obi_apb',base_dir=ROOT,cache_dir=tmp_path,
                mixed_flows=True,memory_flows=True,f5_preparation=prepared,defer_begin=True)
    target=runtime.runner.sessions[runtime.target_id]
    runtime.authority=GpioRegisterVersionAuthority(target)
    original=prepared.artifacts[runtime.target_id]
    assert target.artifact is not original and target.artifact == original
    component=verify_component(original,preparation=prepared,base_dir=ROOT)
    selection=select_adapter(component,requirement_for(component.endpoints()[0]),preparation=prepared)
    bound=bind_gpio_storage_adapter(component=component,session=target,selection=selection,
        preparation=prepared,endpoint_id='gpio.bus')
    bound.assert_current()
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    with execution_validation_scope():
        bound.assert_current()
        bound.assert_current()
    # Every LocalRuntimeArtifact field belongs to the comparison, including
    # generated source text, not only the runtime_document artifact digest.
    private=target.artifact
    target.artifact=replace(private,cpp_text=private.cpp_text+'\n// changed')
    with pytest.raises(ValueError):bound.assert_current()
    with pytest.raises(ValueError,match='artifact-snapshot-mismatch'):
        bind_gpio_storage_adapter(component=component,session=target,selection=selection,
            preparation=prepared,endpoint_id='gpio.bus')
    target.artifact=private


def test_execution_exit_static_callback_survives_closed_preparation(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    from myfuzz.runtime.registry import select_adapter
    from tests.runtime.test_registry import requirement_for
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    config=ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    local=create_preparation(base_dir=ROOT,compose_path=config/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json',generated_dir=tmp_path/'generated',
        flow_ids=('F1','F3','F4','F5'))
    try:
        artifact=local.artifacts['peripheral']
        component=verify_component(artifact,preparation=local,base_dir=ROOT)
        selection=select_adapter(component,requirement_for(component.endpoints()[0]),preparation=local)
        target=GeneratedPulpGpioSession(artifact,base_dir=ROOT,cache_dir=tmp_path/'cache')
        GpioRegisterVersionAuthority(target)
        bound=bind_gpio_storage_adapter(component=component,session=target,selection=selection,
            preparation=local,endpoint_id='gpio.bus')
        with execution_validation_scope() as validation:
            bound.assert_current()
            bound.close()
            local.close()
            (tmp_path/'generated').rename(tmp_path/'archived-generated')
        assert validation['status']=='verified'
        assert local.closed
        with pytest.raises(ValueError):bound.assert_current()
        # Static bytes are still checked after live authorization is closed.
        from myfuzz.local_harness.execution_validation import static_validation, ExecutionValidationError
        old_digest=artifact.runtime_document['artifact_digest']
        try:
            with pytest.raises(ExecutionValidationError,match='static-artifact-bytes-changed'):
                with execution_validation_scope():
                    static_validation(('closed-gpio-bytes',bound),bound._validate_artifact_bytes)
                    artifact.runtime_document['artifact_digest']='0'*64
        finally:
            artifact.runtime_document['artifact_digest']=old_digest
    finally:
        local.close()


def test_gpio_register_bank_keeps_independent_dynamic_padin_read_only_contract(prepared):
    from myfuzz.runtime.adapters.gpio_storage import bank_contract_facts
    bank=bank_contract_facts(prepared.artifacts['peripheral'],base_dir=ROOT,
        endpoint_id='gpio.bus',template=('pulp.gpio.causal','1','pulp_gpio_causal_v1'))
    document=bank.document()
    assert document['kind']=='gpio.register-bank.v1'
    assert document['registers']['GPIOEN']['kind']=='storage.rw.v1'
    padin=document['registers']['PADIN']
    assert padin['kind']=='gpio.padin.read-only.v1'
    assert padin['operations']==['read'] and padin['canonical_offset']==8
    assert padin['value_origin']=='native_synchronizer_latch'
    assert padin['version_basis']=='native_sample_version'
    assert bank.supports(register='PADIN',operation='read',offset=8)
    assert not bank.supports(register='PADIN',operation='write',offset=8)
    assert not bank.supports(register='PADIN',operation='read',offset=4)
    assert not bank.supports(register='GPIOEN',operation='read',offset=8)


def test_bound_current_explicit_register_never_borrows_gpioen_token():
    from types import SimpleNamespace
    from myfuzz.runtime.adapters.gpio_storage import BoundGpioStorageAdapter
    calls=[]
    bound=object.__new__(BoundGpioStorageAdapter)
    bound.assert_current=lambda:None
    bound._session=SimpleNamespace(reset_epoch=3)
    bound._authority=SimpleNamespace(issue=lambda **kw:calls.append(kw) or kw,
        consume=lambda token:token)
    assert bound.current(register='PADIN')['register']=='PADIN'
    assert bound.current()['register']=='GPIOEN'
    assert calls==[{'register':'PADIN','reset_epoch':3},{'register':'GPIOEN','reset_epoch':3}]
    with pytest.raises(ValueError):bound.current(register='PADOUT')
    assert len(calls)==2
