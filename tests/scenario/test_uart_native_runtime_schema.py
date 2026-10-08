"""Structural schema accepts actual additive observers; Python authenticates bytes."""
import json
from copy import deepcopy
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, ValidationError
from myfuzz.scenario.ibex_pulp_dual_source import _artifact
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from tests.local_harness import test_cpu_native_irq_receipt as cpu_tests
ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture(scope='module')
def identities():
    cpu_tests.CpuNativeIrqReceiptTests.setUpClass()
    cpu=cpu_tests.CpuNativeIrqReceiptTests().cpu()
    uart=GeneratedOpentitanUartSession(_artifact('configs/peripherals/opentitan_uart_fifo_local/component_profile.json','uart'),base_dir=ROOT,cache_dir=Path('/tmp/schema-unused'),cpu_routed_mode=True,source=None)
    gpio=GeneratedPulpGpioSession(_artifact('configs/peripherals/pulp_gpio_causal_local/component_profile.json','gpio'),base_dir=ROOT,cache_dir=Path('/tmp/schema-unused'))
    return [dict(type=type(x).__module__+'.'+type(x).__name__,identity=x.identity_document()) for x in (cpu,uart,gpio)]

def validate(session):
    schema=json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
    branch=schema['properties']['runner_identity']['properties']['sessions']['additionalProperties']
    Draft202012Validator({**branch,'$defs':schema['$defs']}).validate(session)

@pytest.mark.parametrize('index',[0,1,2])
def test_actual_generated_observer_identity(index,identities):
    validate(identities[index])

@pytest.mark.parametrize('index,field',[(0,'cpu_native_irq_receipt_contract'),(1,'uart_fifo_observation_contract'),(2,'gpio_observation_contract')])
def test_changed_observer_contract_rejected(index,field,identities):
    session=deepcopy(identities[index]);session['identity'][field]['schema_version']='forged'
    with pytest.raises(ValidationError):validate(session)

def test_native_cpu_requires_rvfi_observation(identities):
    session=deepcopy(identities[0]);session['identity'].pop('cpu_observation_schema_version')
    with pytest.raises(ValidationError):validate(session)

def test_fifo_requires_provenance_and_correct_profile(identities):
    for mutation in ('provenance','profile'):
        session=deepcopy(identities[1])
        if mutation=='provenance':session['identity'].pop('uart_source_provenance')
        else:session['identity']['runtime_artifact']['plan']['component_id']='opentitan_uart_local'
        with pytest.raises(ValidationError):validate(session)

@pytest.mark.parametrize('version',[2,3,4])
def test_legacy_uart_versions_preserve_old_optional_shapes(version,identities):
    session=deepcopy(identities[1]);identity=session['identity']
    identity.pop('uart_fifo_observation_contract');identity.pop('uart_source_provenance')
    identity['runtime_artifact']['plan']['component_id']='opentitan_uart_local'
    identity['tlul_uart_service_schema_version']=f'generated_tlul_uart_8n1.v{version}'
    if version<4:identity.pop('cpu_routed_mode')
    if version==2:identity.pop('source_mode')
    validate(session)


def test_native_irq_not_granted_to_other_cpu_or_non_cpu(identities):
    for index in (0,2):
        session=deepcopy(identities[index])
        if index==0:session['identity']['runtime_artifact']['plan']['component_id']='ibex_obi_local'
        else:session['identity']['cpu_native_irq_receipt_contract']=deepcopy(identities[0]['identity']['cpu_native_irq_receipt_contract'])
        with pytest.raises(ValidationError):validate(session)


def test_rvfi_observation_pair_and_gpio_pair_required(identities):
    for index,field in ((0,'cpu_retirement_sampling_edge'),(2,'gpio_target_context_schema_version')):
        session=deepcopy(identities[index]);session['identity'].pop(field)
        with pytest.raises(ValidationError):validate(session)
