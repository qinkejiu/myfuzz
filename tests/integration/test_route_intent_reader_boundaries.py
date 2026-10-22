"""Route-bearing schemas must not pass through v1-only downstream readers."""
import json

import pytest

from myfuzz.local_harness import auto_harness_test, generated_artifact_admission
from myfuzz.scenario import capability_report


ROUTE_DOCUMENT = {
    'schema_version': 'dma_master_route_intent.v1',
    'routes': [{'route_id': 'copy.destination'}],
}


def test_generated_artifact_admission_refuses_harness_set_v2_with_route_code(tmp_path):
    generated = tmp_path / 'generated'
    generated.mkdir()
    (generated / 'harness_set.json').write_text(json.dumps({
        'schema_version': 'harness_set.v2',
        'components': [{'instance_id': 'mover'}],
        'wiring': {'schema_version': 'wiring_contract.v2',
                   'dma_master_routes': ROUTE_DOCUMENT},
    }))

    with pytest.raises(generated_artifact_admission.GeneratedArtifactRefused) as error:
        generated_artifact_admission.load_generated_artifacts(
            generated_root=generated, base_dir=tmp_path)

    assert error.value.code == 'generated-artifact-route-intent-unsupported'
    assert error.value.pointer == '/wiring/dma_master_routes'


def test_capability_report_refuses_harness_set_v2_with_route_code():
    with pytest.raises(capability_report.CapabilityReportRefused) as error:
        capability_report._validate_harness_set({
            'schema_version': 'harness_set.v2', 'tier': 'generated',
            'components': [], 'wiring': {
                'schema_version': 'wiring_contract.v2',
                'dma_master_routes': ROUTE_DOCUMENT,
            },
        })

    assert error.value.code == 'capability-report-route-intent-unsupported'
    assert error.value.pointer == '/wiring/dma_master_routes'


def test_auto_harness_fixed_input_reader_refuses_v2_routes(tmp_path):
    (tmp_path / 'wiring_contract.json').write_text(json.dumps({
        'schema_version': 'wiring_contract.v2',
        'dma_master_routes': ROUTE_DOCUMENT,
        'fixed_inputs': [],
    }))

    with pytest.raises(auto_harness_test.AutoHarnessRefused) as error:
        auto_harness_test._wiring_fixed_inputs(tmp_path)

    assert error.value.code == 'wiring-contract-route-intent-unsupported'
    assert error.value.pointer == '/dma_master_routes'


def test_auto_harness_fixed_input_reader_rejects_unknown_v1_fields(tmp_path):
    (tmp_path / 'wiring_contract.json').write_text(json.dumps({
        'schema_version': 'wiring_contract.v1', 'delivery': 'none',
        'global_interconnect': False, 'cycle_accurate': False,
        'cpu': {'instance_id': 'cpu', 'endpoint_id': 'cpu.data'},
        'windows': [], 'dma_master_routes': ROUTE_DOCUMENT,
    }))

    with pytest.raises(auto_harness_test.AutoHarnessRefused) as error:
        auto_harness_test._wiring_fixed_inputs(tmp_path)

    assert error.value.code == 'wiring-contract-route-intent-unsupported'
