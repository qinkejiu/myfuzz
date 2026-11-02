"""Typed compiled assertions join independent runtime inventory, never tier grants.

Fixtures generate source declarations only. These tests start no native processes
and their synthetic observations do not claim real execution evidence.
"""
from copy import deepcopy
from hashlib import sha256
import json

import pytest

from myfuzz.integration.compiled_f2 import derive_f2_execution_binding
from myfuzz.scenario.capability_report import (
    CapabilityReportRefused, build_capability_report)
from myfuzz.scenario.compiled_assertion_results import build_assertion_results
from myfuzz.scenario.compiled_paths import compiled_document_sha256
from tests.integration.test_compiled_f4_storage_producer import ROOT, timer_loaded


def digest(value, *, ascii=True):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=ascii, allow_nan=False).encode()).hexdigest()


@pytest.fixture(scope='module')
def admitted(tmp_path_factory):
    artifacts, inputs = timer_loaded(tmp_path_factory.mktemp('capability-f2'))
    binding = derive_f2_execution_binding(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT).document()
    return inputs['compiled'], binding


def inputs(admitted, statuses=('passed', 'passed')):
    compiled, binding = deepcopy(admitted)
    path = binding['runtime_path_admission']['selected_path']
    evidence = dict(execution_binding=binding, path_id=path['path_id'],
                    run_id='observed-run', cases=[])
    scope = dict(compiled_document_sha256=compiled_document_sha256(compiled),
                 binding_sha256=binding['binding_sha256'],
                 path_sha256=digest(path), run_id=evidence['run_id'], case_id='case-1')
    inventory, observations = {}, {}
    for index, assertion in enumerate(path['assertions']):
        eid = assertion['expectation_id']; status = statuses[index]
        if status == 'missing':
            continue
        ref = f'observed-{index}'
        inventory[ref] = dict(kind=eid, outcome=status,
            scope=dict(scope, expectation_id=eid), details={'sample_id': index})
        observations[eid] = dict(status=status, reason='collected sample',
                                  evidence_refs=[ref])
    evidence['cases'] = [dict(case_id='case-1', observations=observations,
                             evidence_inventory=inventory)]
    document = build_assertion_results(
        compiled_document_sha256=scope['compiled_document_sha256'],
        binding_sha256=binding['binding_sha256'], path=path,
        run_id=evidence['run_id'], cases=evidence['cases'])
    return compiled, dict(assertion_results=document, assertion_evidence=evidence)


def selected(report, path_id):
    return next(path for path in report['paths'] if path['path_id'] == path_id)


def test_typed_passes_project_with_case_run_refs_and_no_tier_upgrade(admitted):
    compiled, kwargs = inputs(admitted)
    baseline = build_capability_report(compiled)
    report = build_capability_report(compiled, **kwargs)
    path_id = kwargs['assertion_evidence']['path_id']
    path = selected(report, path_id)
    assert path['tiers'] == selected(baseline, path_id)['tiers']
    assert len(path['assertion_results']) == 2
    for row in path['assertion_results']:
        assert row['case_id'] == 'case-1'
        assert row['run_id'] == 'observed-run'
        assert row['path_id'] == path_id
        assert row['status'] == 'passed'
        assert row['evidence_refs']
    assert all(not row['assertion_results'] for row in report['paths']
               if row['path_id'] != path_id)
    assert report['assertion_results'] == path['assertion_results']
    assert report['inputs']['assertion_results']['supplied'] is True
    assert report['inputs']['assertion_results']['sha256']
    assert report['inputs']['assertion_evidence']['sha256']


def test_failed_and_missing_results_are_retained(admitted):
    compiled, kwargs = inputs(admitted, ('failed', 'missing'))
    report = build_capability_report(compiled, **kwargs)
    rows = selected(report, kwargs['assertion_evidence']['path_id'])['assertion_results']
    assert [row['status'] for row in rows] == ['failed', 'missing']
    assert rows[0]['reason'] == 'collected sample'
    assert rows[1]['evidence_refs'] == []


def test_checker_findings_remain_separate_without_assertion_authority(admitted):
    compiled, binding = admitted
    finding = dict(finding_id='checker-1', flow_id='F2',
                   path_id=binding['path_id'], classification='natural')
    report = build_capability_report(compiled, checker_findings={'findings': [finding]})
    path = selected(report, binding['path_id'])
    assert path['assertion_results'] == []
    assert path['checker_findings'] == [finding]
    assert report['assertion_results'] == []
    assert report['inputs']['assertion_results']['supplied'] is False


@pytest.mark.parametrize('missing', ['assertion_results', 'assertion_evidence'])
def test_typed_input_and_independent_evidence_must_be_supplied_together(admitted, missing):
    compiled, kwargs = inputs(admitted)
    del kwargs[missing]
    with pytest.raises(CapabilityReportRefused):
        build_capability_report(compiled, **kwargs)


@pytest.mark.parametrize('change', [
    'unknown_expectation', 'omitted_expectation', 'duplicate_expectation',
    'relabel_case', 'omit_case', 'duplicate_case', 'relabel_run',
    'changed_inventory', 'unknown_reference', 'cross_expectation_reference',
    'compiled_document', 'binding_digest', 'binding_schema', 'evidence_extra',
    'evidence_path', 'binding_path', 'runtime_path', 'admission_path',
    'admission_schema', 'admission_digest', 'admission_compiled',
    'prepared_selection', 'source_binding', 'admission_image', 'prepared_bool',
    'source_base', 'source_readable', 'source_writable',
    'admission_contract_float', 'runtime_identity_float',
    'rehash_selected_path', 'assertion_schema', 'cases_from_serialized_output'])
def test_refuses_unjoined_assertions_even_when_saved_data_is_rehashed(admitted, change):
    compiled, kwargs = inputs(admitted)
    document = kwargs['assertion_results']; evidence = kwargs['assertion_evidence']
    binding = evidence['execution_binding']; admission = binding['runtime_path_admission']
    case = document['cases'][0]; row = case['assertions'][0]
    if change == 'unknown_expectation': row['expectation_id'] = 'unknown'
    if change == 'omitted_expectation': case['assertions'].pop()
    if change == 'duplicate_expectation': case['assertions'].append(deepcopy(row))
    if change == 'relabel_case': case['case_id'] = 'other'
    if change == 'omit_case': document['cases'] = []
    if change == 'duplicate_case': document['cases'].append(deepcopy(case))
    if change == 'relabel_run': document['run_id'] = 'other'
    if change == 'changed_inventory': case['evidence_inventory']['observed-0']['details']['sample_id'] = 99
    if change == 'unknown_reference': row['evidence_refs'] = ['uncollected']
    if change == 'cross_expectation_reference': row['evidence_refs'] = ['observed-1']
    if change == 'compiled_document': compiled['audit_note'] = 'changed complete document'
    if change == 'binding_digest': binding['binding_sha256'] = 'a' * 64
    if change == 'binding_schema': binding['schema_version'] = 'compiled_F4_execution_binding.v1'
    if change == 'evidence_extra': evidence['serialized_cases'] = document['cases']
    if change == 'evidence_path': evidence['path_id'] = 'unknown'
    if change == 'binding_path': binding['path_id'] = 'unknown'
    if change == 'runtime_path': binding['runtime_path_id'] = 'unknown'
    if change == 'admission_path': admission['path_mapping']['logical_path_id'] = 'unknown'
    if change == 'admission_schema': admission['schema_version'] = 'compiled_F4_runtime_path_admission.v1'
    if change == 'admission_digest': admission['binding_sha256'] = 'b' * 64
    if change == 'admission_compiled': admission['compiled_document_sha256'] = 'c' * 64
    if change == 'prepared_bool': admission['prepared']['graph']['sources'][0]['bit_offset'] = False
    if change == 'prepared_selection': admission['prepared']['selections'][0]['path_id'] = 'unknown'
    if change == 'admission_contract_float': admission['execution_contract']['width_bytes'] = 4.0
    if change == 'runtime_identity_float':
        admission['runtime_path_identity']['edges'][0]['rule_index'] = float(
            admission['runtime_path_identity']['edges'][0]['rule_index'])
    if change == 'source_base': admission['source_binding']['base'] += 4
    if change == 'source_readable': admission['source_binding']['readable'] = False
    if change == 'source_writable': admission['source_binding']['writable'] = False
    if change == 'source_binding': admission['source_binding']['path_id'] = 'unknown'
    if change == 'admission_image': admission['instruction_image']['port'] = 'unknown'
    if change == 'rehash_selected_path':
        admission['selected_path']['audit_note'] = 'changed full path'
        admission['selected_path_sha256'] = digest(admission['selected_path'], ascii=False)
        binding['selected_path_sha256'] = digest(admission['selected_path'])
    if change == 'assertion_schema': document['schema'] = 'future.v1'
    if change == 'cases_from_serialized_output': evidence['cases'] = deepcopy(document['cases'])
    # Preserve the mutated field's own claimed hash for attacks on cross joins.
    admission_changes = {
        'admission_path', 'admission_schema', 'admission_compiled',
        'rehash_selected_path', 'prepared_selection', 'source_binding',
        'admission_image', 'prepared_bool', 'source_base', 'source_readable',
        'source_writable', 'admission_contract_float', 'runtime_identity_float'}
    if change in admission_changes:
        admission['binding_sha256'] = digest(
            {k:v for k,v in admission.items() if k != 'binding_sha256'}, ascii=False)
        binding['runtime_path_admission_sha256'] = admission['binding_sha256']
    if change != 'binding_digest':
        binding['binding_sha256'] = digest(
            {k:v for k,v in binding.items() if k != 'binding_sha256'})
    if change in admission_changes | {
            'binding_schema', 'binding_path', 'runtime_path', 'admission_digest'}:
        # Rehash typed rows and both inventories too. Only the independent
        # binding-to-compiled identity joins can reject these coherent swaps.
        document['binding_sha256'] = binding['binding_sha256']
        for collection in (evidence['cases'], document['cases']):
            for collected in collection:
                for item in collected['evidence_inventory'].values():
                    item['scope']['binding_sha256'] = binding['binding_sha256']
    with pytest.raises(CapabilityReportRefused):
        build_capability_report(compiled, **kwargs)


def test_json_file_descriptor_pins_typed_input_bytes_semantically(admitted, tmp_path):
    compiled, kwargs = inputs(admitted)
    typed = tmp_path / 'assertions.json'
    typed.write_text(json.dumps(kwargs['assertion_results']), encoding='utf-8')
    kwargs['assertion_results'] = typed
    report = build_capability_report(compiled, **kwargs)
    assert report['inputs']['assertion_results']['source'] == 'file'
    assert report['inputs']['assertion_results']['path'] == str(typed)


def test_unicode_full_document_and_path_use_each_runtime_canonical_encoding(admitted):
    compiled, binding = deepcopy(admitted)
    path = next(path for path in compiled['paths'] if path['path_id'] == binding['path_id'])
    path['audit_note'] = '完整路径'
    compiled['audit_note'] = '完整文档'
    admission = binding['runtime_path_admission']
    admission['selected_path'] = json.loads(json.dumps(path))
    admission['selected_path_sha256'] = digest(path, ascii=False)
    admission['compiled_document_sha256'] = compiled_document_sha256(compiled)
    admission['binding_sha256'] = digest(
        {k:v for k,v in admission.items() if k != 'binding_sha256'}, ascii=False)
    binding.update(selected_path_sha256=digest(path),
        compiled_document_sha256=compiled_document_sha256(compiled),
        runtime_path_admission_sha256=admission['binding_sha256'])
    binding['binding_sha256'] = digest(
        {k:v for k,v in binding.items() if k != 'binding_sha256'})
    compiled, kwargs = inputs((compiled, binding))
    report = build_capability_report(compiled, **kwargs)
    assert len(report['assertion_results']) == 2
