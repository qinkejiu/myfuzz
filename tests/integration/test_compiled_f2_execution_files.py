"""Public compiled F2 executor selection, support report and saved-file pinning.

No native process is started here.  The Timer source fixture is generated for
selection only; the real RTL first/fresh gates are run separately through
`scripts/run_compiled_dataflow.py`.
"""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.integration.compiled_execution_files import (
    _FLOW_BY_EXECUTOR, _pin_saved_document, run_compiled_execution_files)
from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f2_support
from tests.integration.test_compiled_f4_storage_producer import ROOT, timer_loaded


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f2-public-entry'))


def f2_row(inputs):
    return next(path for path in inputs['compiled']['paths']
                if path['flow_id'] == 'F2' and path['status'] == 'executable')


def test_public_factory_maps_each_executor_to_one_flow():
    assert _FLOW_BY_EXECUTOR == {'compiled_f4_obi_apb': 'F4',
                                 'compiled_f2_obi_apb': 'F2'}


def test_f2_support_report_is_source_backed_without_live_authority(generated):
    artifacts, inputs = generated
    support = assess_compiled_f2_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert support['schema_version'] == 'compiled_F2_support.v1'
    assert support['execution_supported'] == 1
    assert support['runtime_admitted'] is False
    assert support['status'] == 'supported_requires_actual_startup'
    assert support['executor'] == 'compiled_f2_obi_apb'
    assert support['flow_id'] == 'F2'
    assert support['path_id'] == f2_row(inputs)['path_id']
    assert support['producer_binding']['register']['operation'] == 'read'
    assert support['producer_binding']['producer']['grants_reset_prerequisite'] is False
    assert support['producer_binding']['live_authority'] == 'not_claimed'
    assert 'actual_native_current_register_version_token' in support['startup_requires']
    assert 'dependent_XOR_result_RAM_store' in support['startup_requires']
    # Only the selected F2 row is executable here; other flows are not silently
    # claimed by the F2 report.
    assert all(row['flow_id'] == 'F2' for row in support['unsupported_paths'])


def test_f2_support_refuses_a_document_without_the_admitted_read_path(generated):
    artifacts, inputs = generated
    compiled = deepcopy(inputs['compiled'])
    row = next(path for path in compiled['paths']
               if path['flow_id'] == 'F2' and path['status'] == 'executable')
    row['status'] = 'unsupported'
    support = assess_compiled_f2_support(artifacts=artifacts,
        compiled_inputs={**inputs, 'compiled': compiled}, base_dir=ROOT)
    assert support['execution_supported'] == 0
    assert support['runtime_admitted'] is False
    assert support['status'] == 'unsupported'
    assert support['reason'].startswith('compiled-runtime-input-refused')


def test_public_factory_dispatches_f2_and_counts_its_own_four_byte_records(generated):
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    artifacts, inputs = generated
    access = next(source for source in f2_row(inputs)['sources']
                  if source['kind'] == 'cpu_load_stream')['register_access']
    record = access['address'].to_bytes(4, 'little').hex()
    layout = compile_f2_candidate_layout(f2_row(inputs))
    assert len(record) == 8 and layout.byte_length == 4
    assert layout.classify(bytes.fromhex(record)).accepted is True
    assert layout.classify(bytes.fromhex('00000000')).accepted is False


def test_public_factory_refuses_unknown_executor_without_constructing_anything():
    from myfuzz.local_harness.generated_execution_admission import (
        create_compiled_execution)
    from myfuzz.local_harness.generated_execution_admission import (
        GeneratedExecutionRefused)
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        with pytest.raises(GeneratedExecutionRefused, match='executor-unsupported'):
            create_compiled_execution(artifacts={}, compiled_inputs={},
                executor='compiled_unknown_flow')


def test_public_entry_refuses_f2_before_generation_with_typed_report(tmp_path):
    output = tmp_path / 'evidence'
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        with pytest.raises(OSError):
            run_compiled_execution_files(base_dir=ROOT,
                compose_path=tmp_path / 'missing-compose.json', capability_paths=(),
                supplement_path=tmp_path / 'missing-supplement.json',
                records_path=tmp_path / 'missing-records.json',
                output_dir=output, cache_dir=tmp_path / 'cache',
                executor='compiled_f2_obi_apb',
                heavy_lock=tmp_path / 'not-acquired.lock')
    report = json.loads((output / 'report.json').read_text())
    assert report['executor'] == 'compiled_f2_obi_apb'
    assert report['flow'] == 'F2'
    assert report['status'] == 'refused'
    assert report['runtime_admitted'] is False
    assert (output / '.incomplete').is_file()
    assert not (tmp_path / 'not-acquired.lock').exists()


def test_saved_file_pinning_rejects_a_coherently_rehashed_swap(tmp_path):
    output = tmp_path / 'evidence'
    output.mkdir()
    expected = {'schema_version': 'unit.v1', 'value': 1}
    (output / 'doc.json').write_text(json.dumps(expected))
    assert _pin_saved_document(output, 'doc.json', expected)
    switched = {'schema_version': 'unit.v1', 'value': 2}
    (output / 'doc.json').write_text(json.dumps(switched))
    with pytest.raises(ValueError, match='saved-output-mismatch'):
        _pin_saved_document(output, 'doc.json', expected)
