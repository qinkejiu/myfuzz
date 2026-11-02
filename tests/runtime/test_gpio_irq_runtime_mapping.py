"""Actual generated wire names stay distinct from runner observation ports."""
import pytest
from tests.integration.test_shared_f5_runtime import prepared, ROOT
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.gpio_irq_dependency_evidence import gpio_irq_runtime_port


def test_real_artifact_irq_export_maps_wire_name_to_physical_runner_port(prepared, tmp_path):
    target = GeneratedPulpGpioSession(prepared.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path)
    export = next(r for r in target.artifact.runtime_document['physical_exports'] if r['role']=='irq')
    assert export['physical_port']=='interrupt'
    assert export['runtime_name'] != export['physical_port']
    observed = target._normalized_physical({'physical':{export['runtime_name']:1}})
    assert observed == {'interrupt':1}
    assert gpio_irq_runtime_port(target) == 'interrupt'


def test_changed_session_projection_cannot_install_irq_mapping(prepared, tmp_path):
    target = GeneratedPulpGpioSession(prepared.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path)
    target._normalized_physical = lambda raw: {'guessed_alias':1}
    with pytest.raises(ValueError, match='projection'):
        gpio_irq_runtime_port(target)
