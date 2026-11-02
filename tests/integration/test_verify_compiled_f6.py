"""Saved F6 evidence audit API and fail-closed byte mutations."""
from pathlib import Path
from copy import deepcopy
import importlib.util
import inspect
import json
import os

import pytest


ROOT = Path(__file__).resolve().parents[2]


def auditor_module():
    path = ROOT / 'scripts/verify_compiled_f6.py'
    assert path.is_file(), 'F6 saved-evidence auditor missing'
    spec = importlib.util.spec_from_file_location('f6_saved_auditor', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_saved_auditor_has_only_output_and_invocation_inputs():
    api = auditor_module()
    assert callable(api.verify_saved_f6)
    signature = inspect.signature(api.verify_saved_f6)
    assert list(signature.parameters) == ['output', 'invocation']
    assert signature.parameters['invocation'].kind is inspect.Parameter.KEYWORD_ONLY


def test_saved_auditor_does_not_accept_a_caller_selected_trust_mode():
    api = auditor_module()
    with pytest.raises(TypeError):
        api.verify_saved_f6(Path('run'), invocation=Path('invocation'), mode='completed')


def test_attempt_audit_refuses_when_any_saved_f6_document_is_missing(tmp_path):
    api = auditor_module()
    with pytest.raises(ValueError):
        api._audit_attempt(tmp_path, tmp_path,
                           {'outcome': 'completed'}, {})


def _write_declaration(tmp_path, document):
    invocation = tmp_path / 'invocation'
    invocation.mkdir(exist_ok=True)
    (invocation / 'declaration.json').write_bytes(
        (json.dumps(document, sort_keys=True, indent=2,
                    ensure_ascii=False, allow_nan=False) + '\n').encode())
    return invocation


def test_saved_declaration_is_closed_and_binds_expected_error_selector(tmp_path):
    api = auditor_module()
    document = {
        'schema_version': 'compiled_F6_saved_declaration.v1',
        'outcome': 'expected_error', 'output_path': 'run',
        'invocation_path': 'invocation', 'expected_exit_code': 0,
        'command_sha256': 'a' * 64,
        'fault_selector': {'case_index': 3, 'operation': 'read',
            'word_index': 2},
    }
    loaded = api._declaration(_write_declaration(tmp_path, document))
    assert loaded == document

    document['fault_selector']['execution_binding_sha256'] = 'b' * 64
    with pytest.raises(ValueError):
        api._declaration(_write_declaration(tmp_path, document))


def test_saved_origin_audit_supports_declared_source_symlinks(tmp_path, monkeypatch):
    api = auditor_module()
    source_root = tmp_path / 'source-root'
    source_root.mkdir()
    target = source_root / 'target.cpp'
    target.write_text('int main() { return 0; }\n')
    link = source_root / 'third_party' / 'soc' / 'sim.cpp'
    link.parent.mkdir(parents=True)
    link.symlink_to(Path('..') / '..' / 'target.cpp')
    relative = 'third_party/soc/sim.cpp'
    checksum = api.file_hash(link)

    invocation = tmp_path / 'invocation'
    invocation.mkdir()
    origin = {relative: {
        'is_symlink': True,
        'resolved_path': link.resolve(strict=True).as_posix(),
        'link_target': os.readlink(link),
        'content_sha256': checksum,
    }}
    for name, document in (
            ('source-origins-before.json', origin),
            ('source-origins-after.json', origin),
            ('unavailable-symlinks-before.json', {}),
            ('unavailable-symlinks-after.json', {})):
        (invocation / name).write_text(json.dumps(
            document, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
    monkeypatch.setattr(api, 'ROOT', source_root)
    api._verify_origins(invocation, {relative: checksum}, {
        'source_origins_unchanged': True,
        'unavailable_symlinks_unchanged': True,
    })


def test_saved_origin_audit_supports_unavailable_symlink_map(tmp_path, monkeypatch):
    api = auditor_module()
    source_root = tmp_path / 'source-root'
    link = source_root / 'third_party' / 'soc' / 'missing.cpp'
    link.parent.mkdir(parents=True)
    link.symlink_to('missing-target.cpp')
    relative = 'third_party/soc/missing.cpp'
    unavailable = {relative: {
        'is_symlink': True,
        'link_target': os.readlink(link),
        'resolved_path': link.resolve(strict=False).as_posix(),
        'content_sha256': None,
        'unavailable_reason': 'target_missing',
        'declared_source_file': False,
    }}

    invocation = tmp_path / 'invocation'
    invocation.mkdir()
    for name, document in (
            ('source-origins-before.json', {}),
            ('source-origins-after.json', {}),
            ('unavailable-symlinks-before.json', unavailable),
            ('unavailable-symlinks-after.json', unavailable)):
        (invocation / name).write_text(json.dumps(
            document, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
    monkeypatch.setattr(api, 'ROOT', source_root)
    api._verify_origins(invocation, {}, {
        'source_origins_unchanged': True,
        'unavailable_symlinks_unchanged': True,
    })


def test_saved_declaration_rejects_caller_mode_and_flat_refusal_fields(tmp_path):
    api = auditor_module()
    document = {
        'schema_version': 'compiled_F6_saved_declaration.v1',
        'outcome': 'refusal', 'output_path': 'run',
        'invocation_path': 'invocation', 'expected_exit_code': 1,
        'command_sha256': 'a' * 64, 'mode': 'refusal',
        'stage': 'path_compilation', 'code': 'unsupported', 'pointer': '/irq',
        'proof_path': 'proof.json', 'proof_sha256': 'b' * 64,
    }
    with pytest.raises(ValueError):
        api._declaration(_write_declaration(tmp_path, document))


def test_cli_saved_refusal_keeps_native_f6_opt_in_disabled():
    api = auditor_module()
    expected = {
        'PYTHONPATH': 'src:.',
        'MYFUZZ_SCENARIO_RFUZZ_LIVE': '1',
        'MYFUZZ_RUN_NATIVE_F6': '0',
    }
    assert api._expected_cli_environment('refusal') == expected
    assert api._expected_cli_environment('completed') == {
        **expected, 'MYFUZZ_RUN_NATIVE_F6': '1'}
    with pytest.raises(ValueError):
        api._expected_cli_environment('expected_error')


def _prefix_trace_material(api):
    import hashlib
    from myfuzz.scenario.session_runtime import _trace_semantic_sha256

    events = [{'event_id': 1, 'kind': 'step'}]
    ticks = {'cpu': 1, 'dma': 2}
    online_plan = {'schema_version': 24, 'cases': []}
    return {
        'trace_status': 'complete',
        'trace_events_source': 'actual_events',
        'trace_events': None,
        'actual_events': events,
        'trace_local_ticks': ticks,
        'semantic_hash': _trace_semantic_sha256('complete', events, ticks),
        'original_execution_audit': {'identities': {'cpu': {}, 'dma': {}}},
        'online_plan': online_plan,
        'trace_genome_sha256': hashlib.sha256(api.canonical(online_plan)).hexdigest(),
        'trace_manifest_sha256': 'a' * 64,
    }


def test_saved_prefix_trace_join_recomputes_events_ticks_and_plan_identity():
    api = auditor_module()
    api._verify_prefix_trace(_prefix_trace_material(api))


@pytest.mark.parametrize('field', (
    'actual_events', 'trace_local_ticks', 'semantic_hash',
    'trace_genome_sha256', 'trace_events_source', 'trace_tick_key',
    'trace_manifest_sha256'))
def test_saved_prefix_trace_join_rejects_mutated_trace_material(field):
    from copy import deepcopy

    api = auditor_module()
    prefix = _prefix_trace_material(api)
    if field == 'actual_events':
        prefix[field][0]['kind'] = 'mutated'
    elif field == 'trace_local_ticks':
        prefix[field]['cpu'] = 3
    elif field == 'trace_events_source':
        prefix[field] = 'unknown'
    elif field == 'trace_tick_key':
        prefix['trace_local_ticks'].pop('dma')
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256
        prefix['semantic_hash'] = _trace_semantic_sha256('complete',
            prefix['actual_events'], prefix['trace_local_ticks'])
    elif field == 'trace_manifest_sha256':
        prefix[field] = 'g' * 64
    else:
        prefix[field] = 'b' * 64
    with pytest.raises(ValueError):
        api._verify_prefix_trace(deepcopy(prefix))


@pytest.mark.parametrize('field', ('events', 'status', 'local_ticks',
                                  'semantic_sha256'))
def test_saved_prefix_rejects_online_trace_disagreement(field):
    from copy import deepcopy
    from myfuzz.scenario.replay import ScenarioTrace

    api = auditor_module()
    prefix = _prefix_trace_material(api)
    trace = ScenarioTrace(prefix['trace_genome_sha256'],
        prefix['trace_status'], deepcopy(prefix['actual_events']),
        deepcopy(prefix['trace_local_ticks']), prefix['semantic_hash'],
        prefix['trace_manifest_sha256'])
    changed = dict(vars(trace))
    if field == 'events':
        changed[field][0]['kind'] = 'other'
    elif field == 'local_ticks':
        changed[field]['cpu'] += 1
    else:
        changed[field] = 'other'
    with pytest.raises(ValueError):
        api._verify_prefix_online_trace(prefix, ScenarioTrace(**changed))


def test_saved_prefix_accepts_matching_online_trace():
    from myfuzz.scenario.replay import ScenarioTrace

    api = auditor_module()
    prefix = _prefix_trace_material(api)
    trace = ScenarioTrace(prefix['trace_genome_sha256'],
        prefix['trace_status'], prefix['actual_events'],
        prefix['trace_local_ticks'], prefix['semantic_hash'],
        prefix['trace_manifest_sha256'])
    api._verify_prefix_online_trace(prefix, trace)


def _case_join_material():
    cpu, dma = 'cpu', 'dma'
    source = {'component': dma, 'event_id': 10, 'kind': 'source_start',
        'source_output_key': [dma, 2, 'o_interrupt', 12]}
    delivery = {'component': cpu, 'event_id': 11,
        'kind': 'binding_delivery', 'source_event_id': 10,
        'source_output_key': source['source_output_key'],
        'target_epoch': 3, 'start_local_tick': 94, 'end_local_tick': 110}
    take = {'component': cpu, 'event_id': 12,
        'kind': 'cpu_external_irq_taken', 'runner_event_id': 2,
        'reset_epoch': 3, 'local_tick': 95, 'sample_event_id': 4,
        'binding_delivery_event_id': 11,
        'source_output_key': source['source_output_key'],
        'take_key': [cpu, 3, 1],
        'receipt_id': {'execution': 'local-driver:cpu:1', 'sequence': 1}}
    returned = {'component': cpu, 'event_id': 13,
        'kind': 'native_f6_isr_return.v1', 'case_id': 'run:case:0',
        'case_index': 0, 'reset_epoch': 3, 'execution': 'a' * 32,
        'native_testcase_id': 'run:native', 'irq_take_key': take['take_key'],
        'take_receipt_id': {'execution': 'a' * 32, 'sequence': 1},
        'successor_local_tick': 111, 'successor_receipt_id': {
            'execution': 'a' * 32, 'sequence': 4}}
    boundary = {'component': cpu, 'event_id': 14,
        'kind': 'native_fetch_boundary', 'address': 0x3100,
        'boundary': 'next_prefix_or_park', 'local_tick': 112,
        'reset_epoch': 3, 'execution': 'a' * 32,
        'native_testcase_id': 'run:native',
        'transaction': {'testcase_id': 'run:native',
            'source_component': cpu, 'source_epoch': 3}}
    rows = [source, delivery, take, returned, boundary]
    index = {(row['component'], row['event_id']): row for row in rows}
    samples = [{'event_id': i + 3, 'component': cpu,
        'kind': 'cpu_external_irq_sample', 'reset_epoch': 3,
        'local_tick': 94 + i, 'binding_delivery_event_id': 11,
        'source_output_key': source['source_output_key']}
        for i in range(16)]
    attempt = {'case_id': 'run:case:0', 'case_index': 0,
        'irq_output': 10, 'irq_delivery': 11, 'irq': 12,
        'return': 13, 'next_fetch': boundary}
    prefix = {'attempts': [attempt]}
    contract = {'cpu': {'instance_id': cpu}, 'dma': {'instance_id': dma},
        'program_contract': {'slot_base': 0x3000,
            'slot_count': 2, 'park_address': 0x5000}}
    owners = {key: {'run:case:0'} for key in index}
    return prefix, contract, index, owners, samples


@pytest.mark.parametrize('mutation', ('boundary_address', 'boundary_ref',
    'delivery_ref', 'take_sample', 'boundary_order', 'case_owner'))
def test_saved_case_join_rejects_detached_irq_and_boundary(mutation):
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    attempt = prefix['attempts'][0]
    if mutation == 'boundary_address':
        index[('cpu', 14)]['address'] = 0x4000
    elif mutation == 'boundary_ref':
        attempt['next_fetch'] = {**attempt['next_fetch'], 'event_id': 99}
    elif mutation == 'delivery_ref':
        attempt['irq_delivery'] = 99
    elif mutation == 'take_sample':
        index[('cpu', 12)]['sample_event_id'] = 99
    elif mutation == 'boundary_order':
        index[('cpu', 14)]['local_tick'] = 111
        attempt['next_fetch'] = index[('cpu', 14)]
    else:
        owners[('cpu', 14)] = {'run:case:1'}
    with pytest.raises(ValueError):
        api._verify_f6_case_joins(prefix, contract, index, owners, samples)


def test_saved_case_join_accepts_separate_dma_and_cpu_epochs():
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    api._verify_f6_case_joins(prefix, contract, index, owners, samples)


def test_saved_case_join_accepts_production_integer_next_fetch_reference():
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    attempt = prefix['attempts'][0]
    attempt['next_fetch'] = attempt['next_fetch']['event_id']

    api._verify_f6_case_joins(prefix, contract, index, owners, samples)


def test_saved_case_join_rejects_unknown_integer_next_fetch_reference():
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    prefix['attempts'][0]['next_fetch'] = 999

    with pytest.raises(ValueError):
        api._verify_f6_case_joins(prefix, contract, index, owners, samples)


def test_saved_case_join_uses_error_island_address_and_label():
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    prefix['attempts'][0]['status_kind'] = 'expected_error'
    boundary = index[('cpu', 14)]
    boundary['address'] = contract['program_contract']['slot_base'] + 128
    boundary['boundary'] = 'error_current_island'
    api._verify_f6_case_joins(prefix, contract, index, owners, samples)
    boundary['boundary'] = 'next_prefix_or_park'
    with pytest.raises(ValueError):
        api._verify_f6_case_joins(prefix, contract, index, owners, samples)


@pytest.mark.parametrize('kind,component', (
    ('native_fetch_boundary', 'cpu'), ('binding_delivery', 'cpu'),
    ('source_start', 'dma'), ('native_f6_isr_return.v1', 'cpu')))
def test_saved_case_join_rejects_unclaimed_derived_row(kind, component):
    api = auditor_module()
    prefix, contract, index, owners, samples = _case_join_material()
    row = {'component': component, 'event_id': 99, 'kind': kind}
    index[(component, 99)] = row
    owners[(component, 99)] = {'run:case:0'}
    with pytest.raises(ValueError):
        api._verify_f6_case_joins(prefix, contract, index, owners, samples)


def test_saved_raw_trace_rejects_duplicate_observer_id_across_components():
    api = auditor_module()
    prefix, contract, binding = _raw_evidence_trace_material()
    dma_event = {'event_id': 3, 'component': 'dma', 'kind': 'dma_edge'}
    prefix['actual_events'].append(dma_event)
    prefix['attempts'][0]['case_material']['evidence_inventory']['response'][
        'details']['raw_evidence'].append({**dma_event, 'event_id': 41,
            'runner_event_id': 3})
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding)


def test_saved_raw_trace_keeps_direct_runner_tick_out_of_observer_namespace():
    api = auditor_module()
    prefix, contract, binding = _raw_evidence_trace_material()
    projected = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'response']['details']['raw_evidence'][0]
    projected['event_id'] = 2  # Same number as an independent Runner tick ID.
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding)
    assert index[('cpu', 2)]['kind'] == 'data_response'


def test_saved_passed_irq_expectation_cannot_borrow_attempt_ref_from_other_expectation():
    api = auditor_module()
    fields = ('irq_output', 'irq_delivery', 'irq', 'return', 'status',
              'status_store', 'terminal', 'next_fetch')
    attempt = {field: index for index, field in enumerate(fields, start=1)}
    attempt['case_id'] = 'run:case:0'
    attempt['readbacks'] = [9, 10, 11, 12]
    attempt['results'] = [13, 14, 15, 16]
    attempt['word_commits'] = [17, 18, 19, 20]
    kinds = {'irq_output': ('dma', 'source_start'),
             'irq_delivery': ('cpu', 'binding_delivery'),
             'irq': ('cpu', 'cpu_external_irq_taken'),
             'return': ('cpu', 'native_f6_isr_return.v1'),
             'status': ('cpu', 'data_response'),
             'status_store': ('cpu', 'memory_write'),
             'terminal': ('cpu', 'memory_write'),
             'next_fetch': ('cpu', 'native_fetch_boundary'),
             'readbacks': ('cpu', 'data_response'),
             'results': ('cpu', 'memory_write'),
             'word_commits': ('dma', 'memory_write_commit')}
    attempt['next_fetch'] = {'event_id': 8}
    refs = []
    for field in fields + ('readbacks', 'results', 'word_commits'):
        values = attempt[field] if isinstance(attempt[field], list) else [
            attempt[field]['event_id'] if isinstance(attempt[field], dict)
            else attempt[field]]
        refs.extend({'component': kinds[field][0], 'event_id': value,
                     'kind': kinds[field][1]} for value in values)
    # A different expectation can cite the terminal row; the IRQ row must
    # still carry its own reference.
    irq_refs = [row for row in refs if row['event_id'] != 7]
    attempt['case_material'] = {'evidence_inventory': {
        'irq': {'kind': 'dma.irq_isr_completion', 'outcome': 'passed',
                'details': {'raw_references': irq_refs}},
        'cross': {'kind': 'cross_component.declared_edge_hops',
                  'outcome': 'failed',
                  'details': {'raw_references': refs}}}}
    with pytest.raises(ValueError):
        api._verify_f6_expectation_attempt_refs([attempt], 'cpu', 'dma')
    attempt['case_material']['evidence_inventory']['irq']['details'][
        'raw_references'] = refs
    api._verify_f6_expectation_attempt_refs([attempt], 'cpu', 'dma')


def test_saved_typed_audit_passes_complete_assertion_material_to_validator(monkeypatch):
    api = auditor_module()
    from myfuzz.integration import compiled_f6_saved_semantics
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.scenario.f6_assertion_evidence import _build

    binding = {
        'compiled_document_sha256': '1' * 64,
        'binding_sha256': '2' * 64,
        'path_sha256': '3' * 64,
        'execution_binding_sha256': '4' * 64,
        'path_id': 'path', 'run_id': 'run',
    }
    case = {
        'case_id': 'run:case:0',
        'observations': {
            expectation: {
                'status': 'missing', 'reason': 'no captured observation',
                'evidence_refs': [],
            }
            for expectation in EXPECTATION_IDS
        },
        'evidence_inventory': {},
    }
    config_ref = 'cpu-configuration-missing'
    case['evidence_inventory'][config_ref] = dict(kind='dma.cpu_configuration',
        outcome='missing',
        scope=dict(binding, case_id=case['case_id'],
                   expectation_id='dma.cpu_configuration'),
        details={'raw_references': [], 'raw_evidence': []})
    case['observations']['dma.cpu_configuration']['evidence_refs'] = [config_ref]
    word_ref = 'dma-word-transfer-missing'
    case['evidence_inventory'][word_ref] = dict(kind='dma.word_transfer_join',
        outcome='missing',
        scope=dict(binding, case_id=case['case_id'],
                   expectation_id='dma.word_transfer_join'),
        details={'raw_references': [], 'raw_evidence': []})
    irq_ref = 'dma-irq-isr-missing'
    case['evidence_inventory'][irq_ref] = dict(kind='dma.irq_isr_completion',
        outcome='missing',
        scope=dict(binding, case_id=case['case_id'],
                   expectation_id='dma.irq_isr_completion'),
        details={'raw_references': [], 'raw_evidence': []})
    case['observations']['dma.irq_isr_completion']['evidence_refs'] = [irq_ref]
    material = _build(binding, [case])
    monkeypatch.setattr(api, '_verify_f6_expectation_attempt_refs',
                        lambda *_args: None)
    monkeypatch.setattr(api, '_verify_f6_raw_evidence_trace',
                        lambda *_args: {})
    monkeypatch.setattr(api, '_verify_f6_case_joins',
                        lambda *_args: None)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_cpu_configuration', lambda **_kwargs: {
            'kind': 'dma.cpu_configuration', 'outcome': 'missing', 'details': {}})
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)
    attempt = {'case_id': case['case_id'], 'case_material': case,
               'feedback': [0] * 5}

    result = api._audit_f6_typed(
        {'assertion_material': material,
         'attempts': [attempt],
         'actual_events': []},
        {'assertion_material': material, 'attempts': [attempt],
         'actual_events': []},
        material['assertions'],
        {'execution_binding': binding, 'path_id': binding['path_id'],
         'run_id': binding['run_id'], 'cases': [case]},
        binding, False,
        {'cpu': {'instance_id': 'cpu'}, 'dma': {'instance_id': 'dma'}},
        {}, {},
    )
    assert result == {}


def _saved_cross_edge_projection_fixture():
    """Small closed typed prefix for testing original/fresh edge reprojection."""
    api = auditor_module()
    binding = {
        'compiled_document_sha256': '1' * 64,
        'binding_sha256': '2' * 64,
        'path_sha256': '3' * 64,
        'execution_binding_sha256': '4' * 64,
        'path_id': 'path', 'run_id': 'run',
        'runtime_path_admission': {},
    }
    contract = {
        'cpu': {'instance_id': 'cpu'},
        'dma': {'instance_id': 'dma'},
        'irq': {'producer_port': 'dma_irq'},
    }
    case_id = 'run:case:0'
    scope = dict(api._f6_assertion_binding_scope(binding), case_id=case_id)
    edge_rows = [dict(rule_index=index, prerequisite_index=0)
        for index in range(4)]
    declared = dict(kind='cross_component.declared_edge_hops',
        outcome='missing', details=dict(edges=edge_rows,
            raw_references=[], raw_evidence=[]))
    component_rows = {
        'dma.cpu_configuration': dict(kind='dma.cpu_configuration',
            outcome='missing', details={}),
        'dma.word_transfer_join': dict(kind='dma.word_transfer_join',
            outcome='missing', details={}),
        'dma.irq_isr_completion': dict(kind='dma.irq_isr_completion',
            outcome='missing', details={}),
    }
    inventory = {}
    observations = {}
    for expectation, row in component_rows.items():
        reference = expectation + ':evidence'
        inventory[reference] = dict(kind=expectation, outcome='missing',
            scope=dict(scope, expectation_id=expectation),
            details={'raw_references': [], 'raw_evidence': []})
        observations[expectation] = dict(status='missing',
            evidence_refs=[reference])
    component_evidence = {
        'configuration': {'status': 'missing'},
        'words': {'status': 'missing'},
        'irq': {'status': 'missing'},
    }
    cross_details = dict(component_evidence=component_evidence,
        edges=edge_rows, declared_edge_projection=declared['details'],
        raw_references=[], raw_evidence=[])
    cross_reference = 'cross_component.declared_edge_hops:evidence'
    inventory[cross_reference] = dict(kind='cross_component.declared_edge_hops',
        outcome='missing', scope=dict(scope,
            expectation_id='cross_component.declared_edge_hops'),
        details=cross_details)
    observations['cross_component.declared_edge_hops'] = dict(status='missing',
        evidence_refs=[cross_reference])
    case = dict(case_id=case_id, observations=observations,
        evidence_inventory=inventory)
    attempt = dict(case_id=case_id, case_material=deepcopy(case), feedback=[0] * 5)
    prefix = dict(attempts=[attempt], actual_events=[],
        assertion_material={'assertion_evidence': {'cases': [deepcopy(case)]}},
        _test_local_by_id={})
    fresh = deepcopy(prefix)
    return dict(api=api, binding=binding, contract=contract,
        original=prefix, fresh=fresh, declared=declared,
        component_rows=component_rows)


def test_saved_cross_edge_irq_receives_same_cpu_artifact(monkeypatch):
    from myfuzz.integration import compiled_f6_saved_semantics as semantics
    fixture = _saved_cross_edge_projection_fixture()
    artifact = object()
    seen = []
    for name, row in fixture['component_rows'].items():
        method = {'dma.cpu_configuration': 'project_saved_cpu_configuration',
            'dma.word_transfer_join': 'project_saved_word_transfer',
            'dma.irq_isr_completion': 'project_saved_irq_isr'}[name]
        def project(_row=row, **kwargs):
            if _row['kind'] == 'dma.irq_isr_completion':
                seen.append(kwargs.get('cpu_artifact'))
            return deepcopy(_row)
        monkeypatch.setattr(semantics, method, project)
    monkeypatch.setattr(semantics, 'project_saved_cross_component_edges',
        lambda **kwargs: deepcopy(fixture['declared']))
    monkeypatch.setattr(fixture['api'], '_f6_dma_irq_runtime_name',
        lambda artifacts, contract: 'dma_irq')
    prefix = fixture['original']
    fixture['api']._reproject_f6_cross_component_edges(prefix,
        prefix['_test_local_by_id'], fixture['contract'], fixture['binding'],
        artifacts={'cpu': artifact})
    assert seen == [artifact]


def _run_saved_cross_edge_reprojection(monkeypatch, fixture, *, fail_fresh=False):
    from myfuzz.integration import compiled_f6_saved_semantics

    api = fixture['api']
    for name, row in fixture['component_rows'].items():
        monkeypatch.setattr(compiled_f6_saved_semantics,
            {'dma.cpu_configuration': 'project_saved_cpu_configuration',
             'dma.word_transfer_join': 'project_saved_word_transfer',
             'dma.irq_isr_completion': 'project_saved_irq_isr'}[name],
            lambda _row=row, **_kwargs: deepcopy(_row), raising=False)
    seen = []

    def project(*, attempt, contract, binding, events, local_by_id,
                cpu_artifact=None):
        seen.append((attempt, events, local_by_id))
        row = deepcopy(fixture['declared'])
        if fail_fresh and events is fixture['fresh']['actual_events']:
            row['outcome'] = 'failed'
        return row

    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_cross_component_edges', project, raising=False)
    for prefix in (fixture['original'], fixture['fresh']):
        api._reproject_f6_cross_component_edges(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])
    return seen


def test_saved_cross_edge_projector_rebuilds_original_and_fresh_independently(
        monkeypatch):
    fixture = _saved_cross_edge_projection_fixture()
    seen = _run_saved_cross_edge_reprojection(monkeypatch, fixture)

    assert len(seen) == 2
    assert seen[0][1] is fixture['original']['actual_events']
    assert seen[1][1] is fixture['fresh']['actual_events']
    assert seen[0][2] is fixture['original']['_test_local_by_id']
    assert seen[1][2] is fixture['fresh']['_test_local_by_id']


def test_saved_cross_edge_projector_refuses_a_fresh_only_outcome_drift(monkeypatch):
    fixture = _saved_cross_edge_projection_fixture()
    with pytest.raises(ValueError, match='saved-cross-edge-semantic-reprojection'):
        _run_saved_cross_edge_reprojection(monkeypatch, fixture, fail_fresh=True)


def _saved_receipt_cross_edge_prefix(archive, binding, cpu_artifact):
    from myfuzz.integration import compiled_f6_saved_semantics as projector

    attempt = deepcopy(archive['attempt'])
    events = deepcopy(archive['events'])
    local_by_id = deepcopy(archive['local_by_id'])
    runner = {row['event_id']: row for row in events}
    cpu = archive['contract']['cpu']['instance_id']
    unprovenanced_ids = set()
    for reference in attempt.get('configuration', []):
        observed = local_by_id.get((cpu, reference))
        runner_row = (runner.get(observed.get('runner_event_id'))
            if type(observed) is dict else None)
        if type(runner_row) is dict:
            unprovenanced_ids.add(runner_row['event_id'])
            runner_row.pop('provenance', None)
            observed.pop('provenance', None)
    root_fields = ('service_event_id', 'memory_read_event_id',
        'instr_response_event_id', 'request_pre_event_id',
        'request_producer_event_id', 'backend_response_pre_event_id',
        'backend_response_producer_event_id', 'backend_response_post_event_id',
        'response_pre_event_id', 'response_producer_event_id',
        'response_post_event_id')
    for receipt in events:
        if receipt.get('kind') != 'compiled_F6_instruction_fetch_completion':
            continue
        receipt.pop('provenance', None)
        unprovenanced_ids.add(receipt['event_id'])
        for field in root_fields:
            root = runner.get(receipt.get(field))
            if type(root) is dict:
                unprovenanced_ids.add(root['event_id'])
                root.pop('provenance', None)
    for observed in local_by_id.values():
        if observed.get('runner_event_id') in unprovenanced_ids:
            observed.pop('provenance', None)
    declared = projector.project_saved_cross_component_edges(
        attempt=attempt, contract=archive['contract'], binding=binding,
        events=events, local_by_id=local_by_id, cpu_artifact=cpu_artifact)
    assert declared['details']['edges'][3]['outcome'] == 'passed'
    scope = _saved_receipt_cross_edge_scope(binding)
    case_id = attempt['case_id']
    case_scope = dict(scope, case_id=case_id)
    component_rows = {
        'dma.cpu_configuration': ('configuration', 'missing'),
        'dma.word_transfer_join': ('words', 'missing'),
        'dma.irq_isr_completion': ('irq', 'missing'),
    }
    inventory = {}
    observations = {}
    component_evidence = {}
    for expectation, (component, status) in component_rows.items():
        reference = expectation + ':receipt-edge-test'
        inventory[reference] = dict(kind=expectation, outcome=status,
            scope=dict(case_scope, expectation_id=expectation),
            details={'raw_references': [], 'raw_evidence': []})
        observations[expectation] = dict(status=status, evidence_refs=[reference])
        component_evidence[component] = {'status': status}

    raw_references = deepcopy(declared['details']['raw_references'])
    raw_evidence = [deepcopy(local_by_id[(row['component'], row['event_id'])])
        for row in raw_references]
    cross_reference = 'cross_component.declared_edge_hops:receipt-edge-test'
    cross_details = dict(component_evidence=component_evidence,
        edges=deepcopy(declared['details']['edges']),
        declared_edge_projection=deepcopy(declared['details']),
        raw_references=raw_references, raw_evidence=raw_evidence)
    inventory[cross_reference] = dict(kind='cross_component.declared_edge_hops',
        outcome='missing', scope=dict(case_scope,
            expectation_id='cross_component.declared_edge_hops'),
        details=cross_details)
    observations['cross_component.declared_edge_hops'] = dict(
        status='missing', evidence_refs=[cross_reference])
    case = dict(case_id=case_id, observations=observations,
        evidence_inventory=inventory)
    attempt['case_material'] = deepcopy(case)
    prefix = dict(attempts=[attempt], actual_events=events,
        assertion_material={'assertion_evidence': {'cases': [deepcopy(case)]}},
        _test_local_by_id=local_by_id)
    return prefix


def _saved_receipt_cross_edge_scope(binding):
    return dict(compiled_document_sha256='1' * 64,
        binding_sha256=binding['binding_sha256'], path_sha256='3' * 64,
        execution_binding_sha256=binding['binding_sha256'],
        path_id=binding['path_id'], run_id=binding['run_id'])


def _saved_receipt_cross_edge_verifier_fixture():
    from tests.integration import test_compiled_f6_saved_semantics as saved

    base = saved.archive.__wrapped__()
    word_archive = saved.word_transfer_archive.__wrapped__(base)
    cpu_artifact = saved.cpu_obi_artifact.__wrapped__()
    edge = saved.edge_archive.__wrapped__(word_archive, cpu_artifact)
    archive = saved._saved_fetch_archive(edge)
    return dict(api=auditor_module(), contract=archive['contract'],
        binding=archive['binding'],
        artifacts={archive['contract']['cpu']['instance_id']: cpu_artifact},
        original=_saved_receipt_cross_edge_prefix(archive, archive['binding'],
            cpu_artifact),
        fresh=_saved_receipt_cross_edge_prefix(archive, archive['binding'],
            cpu_artifact))


def _run_saved_receipt_cross_edge_verifier(monkeypatch, fixture):
    from myfuzz.integration import compiled_f6_saved_semantics

    for name in ('project_saved_cpu_configuration', 'project_saved_irq_isr'):
        kind = {'project_saved_cpu_configuration': 'dma.cpu_configuration',
            'project_saved_irq_isr': 'dma.irq_isr_completion'}[name]
        monkeypatch.setattr(compiled_f6_saved_semantics, name,
            lambda _kind=kind, **_kwargs: dict(kind=_kind, outcome='missing',
                details={}), raising=False)
    api = fixture['api']
    monkeypatch.setattr(api, '_f6_dma_irq_runtime_name',
        lambda _artifacts, _contract: 'o_interrupt')
    monkeypatch.setattr(api, '_f6_assertion_binding_scope',
        _saved_receipt_cross_edge_scope)
    for prefix in (fixture['original'], fixture['fresh']):
        api._reproject_f6_cross_component_edges(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'],
            artifacts=fixture.get('artifacts'))


def test_saved_receipt_cross_edge_reprojects_original_and_fresh_archives(monkeypatch):
    fixture = _saved_receipt_cross_edge_verifier_fixture()
    for prefix in (fixture['original'], fixture['fresh']):
        case = prefix['attempts'][0]['case_material']
        cross = next(row for row in case['evidence_inventory'].values()
            if row.get('kind') == 'cross_component.declared_edge_hops')
        declared = cross['details']['declared_edge_projection']
        edge = declared['edges'][3]
        raw_ids = {row['event_id'] for row in declared['raw_evidence']}
        edge_ids = set(edge['runner_event_ids'])
        receipt_root_ids = set()
        assert edge_ids <= raw_ids
        for item in edge['evidence']:
            receipt_root_ids.update(item['root_refs'].values())
            receipt_root_ids.add(item['completion_event_id'])
        assert receipt_root_ids <= edge_ids
        runner = {row['event_id']: row for row in prefix['actual_events']}
        assert all('provenance' not in runner[root_id]
            for root_id in receipt_root_ids)
    _run_saved_receipt_cross_edge_verifier(monkeypatch, fixture)


def test_saved_receipt_cross_edge_rejects_fresh_only_native_sample_tamper(monkeypatch):
    fixture = _saved_receipt_cross_edge_verifier_fixture()
    fresh = fixture['fresh']
    receipt = next(row for row in fresh['actual_events']
        if row.get('kind') == 'compiled_F6_instruction_fetch_completion')
    sample = next(row for row in fresh['actual_events']
        if row.get('event_id') == receipt['response_pre_event_id'])
    artifact = fixture['artifacts']['processor_alpha']
    instruction_trace = next(trace for trace in
        artifact.runtime_document['base_protocol_traces']['traces']
        if trace['endpoint_id'] ==
            fixture['contract']['cpu']['instruction_endpoint_id'])
    signal = instruction_trace['signals']['rdata']
    sample['outputs']['protocol_taps'][signal] ^= 1
    with pytest.raises(ValueError):
        _run_saved_receipt_cross_edge_verifier(monkeypatch, fixture)


def test_saved_cross_edge_reprojection_requires_the_bound_cpu_artifact():
    fixture = _saved_receipt_cross_edge_verifier_fixture()
    with pytest.raises(ValueError, match='saved-cross-edge-bound-cpu-artifact'):
        fixture['api']._reproject_f6_cross_component_edges(
            fixture['original'], fixture['original']['_test_local_by_id'],
            fixture['contract'], fixture['binding'], artifacts=None)


def _saved_cpu_configuration_audit_fixture(*, configuration_rows=1,
                                           all_missing=False):
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.scenario.f6_assertion_evidence import _build
    from tests.integration.test_compiled_f6_saved_semantics import archive as saved_archive

    archived = saved_archive.__wrapped__()
    semantic_attempt = deepcopy(archived['attempt'])
    events = deepcopy(archived['events'])
    local_by_id = deepcopy(archived['local_by_id'])
    binding = {
        'compiled_document_sha256': '1' * 64,
        'binding_sha256': '2' * 64,
        'path_sha256': '3' * 64,
        'execution_binding_sha256': '4' * 64,
        'path_id': 'path', 'run_id': 'run',
    }
    raw_rows = []
    for field in ('operands', 'configuration', 'deliveries'):
        for event_id in semantic_attempt[field]:
            row = local_by_id[('processor_alpha', event_id)]
            raw_rows.append(deepcopy(row))
    raw_references = [dict(component=row['component'], event_id=row['event_id'],
        kind=row['kind']) for row in raw_rows]

    case_id = semantic_attempt['case_id']
    case = dict(case_id=case_id, observations={}, evidence_inventory={})
    if all_missing:
        for expectation in EXPECTATION_IDS:
            case['observations'][expectation] = dict(status='missing',
                reason='saved evidence unavailable', evidence_refs=[])
    else:
        for expectation in EXPECTATION_IDS:
            if expectation == 'dma.word_transfer_join':
                reference = 'dma.word-transfer-missing'
                scope = dict(binding, case_id=case_id,
                             expectation_id=expectation)
                case['evidence_inventory'][reference] = dict(kind=expectation,
                    outcome='missing', scope=scope,
                    details=dict(raw_references=[], raw_evidence=[]))
                case['observations'][expectation] = dict(status='missing',
                    reason='synthetic configuration archive has no word-transfer rows',
                    evidence_refs=[])
                continue
            if expectation == 'dma.irq_isr_completion':
                reference = 'dma-irq-isr-missing'
                scope = dict(binding, case_id=case_id,
                             expectation_id=expectation)
                case['evidence_inventory'][reference] = dict(kind=expectation,
                    outcome='missing', scope=scope,
                    details=dict(raw_references=[], raw_evidence=[]))
                case['observations'][expectation] = dict(status='missing',
                    reason='synthetic configuration archive has no IRQ/ISR rows',
                    evidence_refs=[reference])
                continue
            count = (configuration_rows if expectation == 'dma.cpu_configuration'
                     else 1)
            references = []
            for index in range(count):
                reference = f'{expectation}:{index}'
                references.append(reference)
                scope = dict(binding, case_id=case_id,
                             expectation_id=expectation)
                details = (dict(findings=[], observation_count=1,
                    raw_references=[], raw_evidence=[])
                    if expectation == 'protocol_checker.receipt_violations'
                    else dict(raw_references=deepcopy(raw_references),
                              raw_evidence=deepcopy(raw_rows)))
                case['evidence_inventory'][reference] = dict(kind=expectation,
                    outcome='passed', scope=scope, details=details)
            case['observations'][expectation] = dict(status='passed',
                reason='complete saved observation', evidence_refs=references)
    irq_rows = [reference for reference, row in case['evidence_inventory'].items()
        if type(row) is dict and row.get('kind') == 'dma.irq_isr_completion']
    if not irq_rows:
        reference = 'dma-irq-isr-missing'
        case['evidence_inventory'][reference] = dict(
            kind='dma.irq_isr_completion', outcome='missing',
            scope=dict(binding, case_id=case_id,
                       expectation_id='dma.irq_isr_completion'),
            details=dict(raw_references=[], raw_evidence=[]))
        case['observations']['dma.irq_isr_completion'] = dict(
            status='missing', reason='synthetic archive has no IRQ/ISR rows',
            evidence_refs=[reference])
    semantic_attempt['case_material'] = case
    semantic_attempt['feedback'] = [0] * 5
    material = _build(binding, [case])

    def prefix(events_copy, index_copy):
        return dict(assertion_material=deepcopy(material),
            attempts=[deepcopy(semantic_attempt)], actual_events=events_copy,
            _test_local_by_id=index_copy)

    original = prefix(events, local_by_id)
    fresh = prefix(deepcopy(events), deepcopy(local_by_id))
    typed_evidence = dict(execution_binding=binding, path_id=binding['path_id'],
        run_id=binding['run_id'], cases=material['assertion_evidence']['cases'])
    return dict(api=auditor_module(), binding=binding, contract=archived['contract'],
        original=original, fresh=fresh, typed_results=material['assertions'],
        typed_evidence=typed_evidence, completed=False)


def _run_saved_cpu_configuration_audit(monkeypatch, fixture):
    api = fixture['api']
    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(api, '_verify_f6_expectation_attempt_refs',
                        lambda *_args: None)
    monkeypatch.setattr(api, '_verify_f6_raw_evidence_trace',
                        lambda prefix, *_args: prefix['_test_local_by_id'])
    monkeypatch.setattr(api, '_verify_f6_case_joins', lambda *_args: None)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)
    return api._audit_f6_typed(
        fixture['original'], fixture['fresh'], fixture['typed_results'],
        fixture['typed_evidence'], fixture['binding'], fixture['completed'],
        fixture['contract'], {}, {})


def _tamper_first_configuration_response(events, local_by_id):
    config_ref = local_by_id[('processor_alpha',
        next(row['event_id'] for row in local_by_id.values()
             if row.get('kind') == 'data_accept'))]
    transaction = config_ref['transaction']
    response = next(row for row in events if row.get('component') == 'processor_alpha'
        and row.get('kind') == 'data_response'
        and row.get('transaction') == transaction)
    tick = response['response_tick']
    producer = next(row for row in events if row.get('component') == 'processor_alpha'
        and row.get('kind') is None and row.get('local_tick') == tick)
    producer['outputs']['data_rsp_rdata'] = 1
    for sample in events:
        if (sample.get('component') == 'processor_alpha'
                and sample.get('kind') == 'local_tick_sample'
                and sample.get('local_tick') == tick):
            sample['outputs']['backend']['d_rsp_rdata'] = 1


def test_saved_typed_audit_reprojects_original_cpu_configuration_payload(monkeypatch):
    fixture = _saved_cpu_configuration_audit_fixture()
    _tamper_first_configuration_response(fixture['original']['actual_events'],
        fixture['original']['_test_local_by_id'])

    with pytest.raises(ValueError):
        _run_saved_cpu_configuration_audit(monkeypatch, fixture)


def test_saved_typed_audit_reprojects_fresh_cpu_configuration_independently(monkeypatch):
    fixture = _saved_cpu_configuration_audit_fixture()
    _tamper_first_configuration_response(fixture['fresh']['actual_events'],
        fixture['fresh']['_test_local_by_id'])

    with pytest.raises(ValueError):
        _run_saved_cpu_configuration_audit(monkeypatch, fixture)


def test_saved_typed_audit_requires_one_cpu_configuration_inventory_row(monkeypatch):
    fixture = _saved_cpu_configuration_audit_fixture(all_missing=True)

    with pytest.raises(ValueError):
        _run_saved_cpu_configuration_audit(monkeypatch, fixture)


def test_saved_typed_audit_rejects_duplicate_cpu_configuration_inventory_rows(monkeypatch):
    fixture = _saved_cpu_configuration_audit_fixture(configuration_rows=2)

    with pytest.raises(ValueError):
        _run_saved_cpu_configuration_audit(monkeypatch, fixture)


def _saved_word_transfer_audit_fixture():
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.scenario.f6_assertion_evidence import _build

    fixture = _saved_cpu_configuration_audit_fixture(all_missing=True)
    case = fixture['original']['attempts'][0]['case_material']
    for expectation in ('dma.cpu_configuration', 'dma.word_transfer_join'):
        reference = expectation+':missing'
        case['evidence_inventory'][reference] = dict(kind=expectation,
            outcome='missing',
            scope=dict(fixture['binding'], case_id=case['case_id'],
                       expectation_id=expectation),
            details=dict(raw_references=[], raw_evidence=[]))
    material = _build(fixture['binding'], [case])
    for prefix in (fixture['original'], fixture['fresh']):
        prefix['assertion_material'] = deepcopy(material)
        prefix['attempts'][0]['case_material'] = deepcopy(case)
        prefix['attempts'][0]['feedback'] = [0] * len(EXPECTATION_IDS)
    fixture['typed_results'] = material['assertions']
    fixture['typed_evidence'] = dict(execution_binding=fixture['binding'],
        path_id=fixture['binding']['path_id'], run_id=fixture['binding']['run_id'],
        cases=material['assertion_evidence']['cases'])
    fixture['completed'] = False
    return fixture


def _run_saved_word_transfer_audit(monkeypatch, fixture, *, bad_prefix=None):
    api = fixture['api']
    from myfuzz.integration import compiled_f6_saved_semantics

    monkeypatch.setattr(api, '_verify_f6_expectation_attempt_refs',
                        lambda *_args: None)
    monkeypatch.setattr(api, '_verify_f6_raw_evidence_trace',
        lambda prefix, *_args: prefix['_test_local_by_id'])
    monkeypatch.setattr(api, '_verify_f6_case_joins', lambda *_args: None)
    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)
    monkeypatch.setattr(api, '_reproject_f6_cpu_configuration',
                        lambda *_args: None)
    projections = []

    def project(*, attempt, contract, binding, events, local_by_id):
        projections.append((attempt, binding, events, local_by_id))
        outcome = 'failed' if events is bad_prefix else 'missing'
        return dict(kind='dma.word_transfer_join', outcome=outcome, details={})

    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', project, raising=False)
    result = api._audit_f6_typed(
        fixture['original'], fixture['fresh'], fixture['typed_results'],
        fixture['typed_evidence'], fixture['binding'], fixture['completed'],
        fixture['contract'], {}, {})
    return result, projections


def test_saved_typed_audit_reprojects_word_transfer_for_original_and_fresh(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    result, projections = _run_saved_word_transfer_audit(monkeypatch, fixture)

    assert result is fixture['original']['_test_local_by_id']
    assert len(projections) == 2
    assert projections[0][1] is fixture['binding']
    assert projections[1][1] is fixture['binding']
    assert projections[0][2] is fixture['original']['actual_events']
    assert projections[1][2] is fixture['fresh']['actual_events']
    assert projections[0][3] is fixture['original']['_test_local_by_id']
    assert projections[1][3] is fixture['fresh']['_test_local_by_id']


def test_saved_word_transfer_projection_accepts_rebuilt_pass(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    word_rows = [row for row in case['evidence_inventory'].values()
        if row.get('kind') == 'dma.word_transfer_join']
    assert len(word_rows) == 1
    word_rows[0]['outcome'] = 'passed'
    case['observations']['dma.word_transfer_join']['status'] = 'passed'
    prefix['attempts'][0]['case_material'] = deepcopy(case)

    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'passed', 'details': {}},
        raising=False)

    fixture['api']._reproject_f6_word_transfer(prefix,
        prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


@pytest.mark.parametrize('cardinality', [0, 2])
def test_saved_word_transfer_projection_requires_exact_inventory_row_count(
        monkeypatch, cardinality):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    inventory = case['evidence_inventory']
    word_refs = [ref for ref, row in inventory.items()
        if row.get('kind') == 'dma.word_transfer_join']
    assert len(word_refs) == 1
    saved = inventory[word_refs[0]]
    if cardinality == 0:
        inventory.pop(word_refs[0])
    else:
        inventory[word_refs[0] + ':duplicate'] = deepcopy(saved)
    prefix['attempts'][0]['case_material'] = deepcopy(case)

    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)

    with pytest.raises(ValueError):
        fixture['api']._reproject_f6_word_transfer(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


def test_saved_word_transfer_projection_rejects_observation_outcome_mismatch(
        monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    case['observations']['dma.word_transfer_join']['status'] = 'passed'
    prefix['attempts'][0]['case_material'] = deepcopy(case)

    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)

    with pytest.raises(ValueError):
        fixture['api']._reproject_f6_word_transfer(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


def _run_saved_irq_isr_audit(monkeypatch, fixture, *, bad_prefix=None):
    api = fixture['api']
    from myfuzz.integration import compiled_f6_saved_semantics

    monkeypatch.setattr(api, '_verify_f6_expectation_attempt_refs',
                        lambda *_args: None)
    monkeypatch.setattr(api, '_verify_f6_raw_evidence_trace',
        lambda prefix, *_args: prefix['_test_local_by_id'])
    monkeypatch.setattr(api, '_verify_f6_case_joins', lambda *_args: None)
    monkeypatch.setattr(api, '_reproject_f6_cpu_configuration', lambda *_args: None)
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_word_transfer', lambda **_kwargs: {
            'kind': 'dma.word_transfer_join', 'outcome': 'missing', 'details': {}},
        raising=False)
    projections = []

    def project(*, attempt, contract, binding, events, local_by_id,
                dma_irq_runtime_name, cpu_artifact=None):
        projections.append((attempt, contract, binding, events, local_by_id,
                            dma_irq_runtime_name))
        outcome = 'failed' if events is bad_prefix else 'missing'
        return dict(kind='dma.irq_isr_completion', outcome=outcome, details={})

    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', project, raising=False)
    result = api._audit_f6_typed(
        fixture['original'], fixture['fresh'], fixture['typed_results'],
        fixture['typed_evidence'], fixture['binding'], fixture['completed'],
        fixture['contract'], {}, {})
    return result, projections


def test_saved_typed_audit_reprojects_irq_isr_for_original_and_fresh(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    result, projections = _run_saved_irq_isr_audit(monkeypatch, fixture)

    assert result is fixture['original']['_test_local_by_id']
    assert len(projections) == 2
    assert projections[0][2] is fixture['binding']
    assert projections[1][2] is fixture['binding']
    assert projections[0][3] is fixture['original']['actual_events']
    assert projections[1][3] is fixture['fresh']['actual_events']
    assert projections[0][4] is fixture['original']['_test_local_by_id']
    assert projections[1][4] is fixture['fresh']['_test_local_by_id']


@pytest.mark.parametrize('side', ['original', 'fresh'])
def test_saved_typed_audit_rejects_irq_isr_outcome_mismatch(monkeypatch, side):
    fixture = _saved_word_transfer_audit_fixture()

    with pytest.raises(ValueError):
        _run_saved_irq_isr_audit(monkeypatch, fixture,
            bad_prefix=fixture[side]['actual_events'])


@pytest.mark.parametrize('cardinality', [0, 2])
def test_saved_irq_isr_projection_requires_exact_inventory_row_count(
        monkeypatch, cardinality):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    inventory = case['evidence_inventory']
    irq_refs = [ref for ref, row in inventory.items()
        if row.get('kind') == 'dma.irq_isr_completion']
    assert len(irq_refs) == 1
    saved = inventory[irq_refs[0]]
    if cardinality == 0:
        inventory.pop(irq_refs[0])
    else:
        inventory[irq_refs[0] + ':duplicate'] = deepcopy(saved)
    prefix['attempts'][0]['case_material'] = deepcopy(case)

    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)

    with pytest.raises(ValueError):
        fixture['api']._reproject_f6_irq_isr(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


def test_saved_irq_isr_projection_uses_compiled_binding_scope_subset(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    logical_path = dict(path_id='path', execution_contract={})
    fixture['binding'] = dict(schema_version='compiled_F6_execution_binding.v1',
        compiled_document_sha256='1' * 64, binding_sha256='2' * 64,
        path_id='path', run_id='run', runtime_path_admission=dict(
            logical_path=logical_path), cpu={'instance_id': 'cpu'},
        dma={'instance_id': 'dma'}, contract_sha256='5' * 64)
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    irq_row = next(row for row in case['evidence_inventory'].values()
        if row.get('kind') == 'dma.irq_isr_completion')
    irq_row['scope'] = dict(fixture['api']._f6_assertion_binding_scope(
        fixture['binding']), case_id=case['case_id'],
        expectation_id='dma.irq_isr_completion')
    prefix['attempts'][0]['case_material'] = deepcopy(case)
    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)

    fixture['api']._reproject_f6_irq_isr(prefix,
        prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


def test_saved_irq_isr_projection_uses_admitted_physical_runtime_alias(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    fixture['contract']['irq'] = dict(producer_port='o_interrupt',
        producer_endpoint_id='dma.interrupt')
    from types import SimpleNamespace
    cpu_artifact = object()
    artifacts = {fixture['contract']['cpu']['instance_id']: cpu_artifact,
        'mover_beta': SimpleNamespace(runtime_document={
        'physical_exports': [dict(physical_port='o_interrupt',
            endpoint_id='dma.interrupt', direction='output', role='irq',
            width=1, disposition='functional', runtime_name='wrapper_irq')]
    })}
    from myfuzz.integration import compiled_f6_saved_semantics
    captured = []

    def project(**kwargs):
        captured.append((kwargs['dma_irq_runtime_name'], kwargs.get('cpu_artifact')))
        return {'kind': 'dma.irq_isr_completion', 'outcome': 'missing',
                'details': {}}

    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', project, raising=False)
    fixture['api']._reproject_f6_irq_isr(prefix,
        prefix['_test_local_by_id'], fixture['contract'], fixture['binding'],
        artifacts=artifacts)

    assert captured == [('wrapper_irq', cpu_artifact)]


def test_saved_typed_audit_validates_closed_execution_binding_scope(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    from myfuzz.scenario.f6_assertion_evidence import _build
    logical_path = dict(path_id='path', execution_contract={})
    full_binding = dict(schema_version='compiled_F6_execution_binding.v1',
        compiled_document_sha256='1' * 64, binding_sha256='2' * 64,
        path_id='path', run_id='run', runtime_path_admission=dict(
            logical_path=logical_path), cpu={'instance_id': 'cpu'},
        dma={'instance_id': 'dma'})
    assertion_scope = fixture['api']._f6_assertion_binding_scope(full_binding)
    source_case = fixture['original']['assertion_material'][
        'assertion_evidence']['cases'][0]
    case = deepcopy(source_case)
    for row in case['evidence_inventory'].values():
        row['scope'] = dict(assertion_scope, case_id=case['case_id'],
                            expectation_id=row['kind'])
    material = _build(assertion_scope, [case])
    for prefix in (fixture['original'], fixture['fresh']):
        prefix['assertion_material'] = deepcopy(material)
        prefix['attempts'][0]['case_material'] = deepcopy(case)
    fixture['binding'] = full_binding
    fixture['typed_results'] = material['assertions']
    fixture['typed_evidence'] = dict(execution_binding=full_binding,
        path_id='path', run_id='run',
        cases=material['assertion_evidence']['cases'])
    # This test exercises the six-field assertion binding projection. Its
    # synthetic binding has no admitted runtime graph, covered separately by
    # the saved cross-edge reprojection tests below.
    monkeypatch.setattr(fixture['api'], '_reproject_f6_cross_component_edges',
        lambda *_args, **_kwargs: None)

    result, projections = _run_saved_irq_isr_audit(monkeypatch, fixture)

    assert result is fixture['original']['_test_local_by_id']
    assert len(projections) == 2


def test_saved_irq_isr_projection_rejects_wrong_binding_scope(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    row = next(row for row in case['evidence_inventory'].values()
        if row.get('kind') == 'dma.irq_isr_completion')
    row['scope']['path_id'] = 'other-path'
    prefix['attempts'][0]['case_material'] = deepcopy(case)
    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)

    with pytest.raises(ValueError):
        fixture['api']._reproject_f6_irq_isr(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


def test_saved_irq_isr_projection_rejects_observation_outcome_mismatch(monkeypatch):
    fixture = _saved_word_transfer_audit_fixture()
    prefix = fixture['original']
    case = prefix['assertion_material']['assertion_evidence']['cases'][0]
    case['observations']['dma.irq_isr_completion']['status'] = 'passed'
    prefix['attempts'][0]['case_material'] = deepcopy(case)

    from myfuzz.integration import compiled_f6_saved_semantics
    monkeypatch.setattr(compiled_f6_saved_semantics,
        'project_saved_irq_isr', lambda **_kwargs: {
            'kind': 'dma.irq_isr_completion', 'outcome': 'missing', 'details': {}},
        raising=False)

    with pytest.raises(ValueError):
        fixture['api']._reproject_f6_irq_isr(prefix,
            prefix['_test_local_by_id'], fixture['contract'], fixture['binding'])


@pytest.mark.parametrize('side', ['original', 'fresh'])
def test_saved_typed_audit_rejects_word_transfer_outcome_mismatch(monkeypatch, side):
    fixture = _saved_word_transfer_audit_fixture()

    with pytest.raises(ValueError):
        _run_saved_word_transfer_audit(monkeypatch, fixture,
            bad_prefix=fixture[side]['actual_events'])


def _expected_error_native_scope_material(dma_case_id='run:native'):
    api = auditor_module()
    run_id, cpu, dma, binding_sha = 'run', 'cpu', 'dma', 'b' * 64
    source, destination, control, slot, result, isr = (
        0x2000, 0x3000, 0x1000, 0x4000, 0x5000, 0x6000)
    tx0 = {'execution_id': 'dma-execution', 'testcase_id': dma_case_id,
        'source_component': dma, 'source_epoch': 0,
        'channel_id': 'dma-memory', 'source_sequence': 1}
    tx1 = {**tx0, 'source_sequence': 2}
    status_tx = {'execution_id': 'cpu-execution',
        'testcase_id': 'cpu-native', 'source_component': cpu,
        'source_epoch': 0, 'channel_id': 'data', 'source_sequence': 1}
    selected_receipt = {'schema_version': 'f6_dma_environment_error_receipt.v1',
        'owner': dma, 'source_transaction': tx1, 'error': 1,
        'target_effect': False, 'timing': 'before_target_effect',
        'reason': 'declared_f6_response_fault', 'address': source + 4,
        'write': False, 'byte_enable': 15,
        'selector': {'case_index': 0, 'operation': 'read', 'word_index': 1},
        'execution_binding_sha256': binding_sha}
    rows = {
        (dma, 1): {'event_id': 1, 'component': dma, 'kind': 'dma_edge',
            'tick': 10, 'accepted': {'address': source, 'write': False,
                'transaction': tx0}},
        (dma, 2): {'event_id': 2, 'component': dma, 'kind': 'dma_edge',
            'tick': 11, 'accepted': {'address': source + 4, 'write': False,
                'transaction': tx1}, 'environment_error_receipt': selected_receipt},
        (dma, 3): {'event_id': 3, 'component': dma, 'kind': 'dma_edge',
            'tick': 12, 'response': {'transaction': tx0, 'error': 0}},
        (dma, 4): {'event_id': 4, 'component': dma, 'kind': 'dma_edge',
            'tick': 13, 'response': {'transaction': tx1, 'error': 1}},
        (dma, 5): {'event_id': 5, 'component': dma, 'kind': 'memory_read',
            'transaction': tx0},
        (cpu, 6): {'event_id': 6, 'component': cpu, 'kind': 'data_response',
            'address': control, 'rdata': 1, 'transaction': status_tx},
        (cpu, 7): {'event_id': 7, 'component': cpu,
            'schema_version': 'native_f6_isr_return.v1', 'case_id': 'run:case:0',
            'case_index': 0, 'execution_binding_sha256': binding_sha,
            'pc_rdata': isr + 4, 'return_receipt_id': {'execution': 'cpu',
                'sequence': 3}, 'successor_receipt_id': {'execution': 'cpu',
                'sequence': 4}, 'execution': 'cpu-execution',
            'native_testcase_id': 'cpu-native', 'reset_epoch': 0},
        (cpu, 8): {'event_id': 8, 'component': cpu,
            'kind': 'native_fetch_boundary', 'address': slot + 128,
            'boundary': 'error_current_island', 'execution': 'cpu-execution',
            'native_testcase_id': 'cpu-native', 'reset_epoch': 0},
        (cpu, 9): {'event_id': 9, 'component': cpu, 'kind': 'memory_write',
            'address': result + 20, 'value': 2},
        (cpu, 10): {'event_id': 10, 'component': cpu,
            'kind': 'cpu_external_irq_taken', 'take_key': [cpu, 0, 1],
            'actual_pre_input': 1, 'actual_post_input': 1,
            'irq_masked_pre': 0, 'irq_taken_pre': 1},
    }
    completion = {'terminal_marker': 2, 'actual_status_word': 1,
        'next_address': slot + 128, 'status_transaction': status_tx,
        'mret_pc': isr + 4, 'return_receipt_id': {'execution': 'cpu',
            'sequence': 3}, 'next_fetch': 8,
        'successor_receipt_id': {'execution': 'cpu', 'sequence': 4},
        'irq_take_key': [cpu, 0, 1]}
    case = {'case_id': 'run:case:0', 'case_index': 0,
        'status_kind': 'expected_error', 'expected_error': True,
        'feedback': [0] * 5, 'reads': [1, 2, None, None],
        'read_responses': [3, 4, None, None],
        'read_snapshots': [5, None, None, None],
        'word_commits': [None] * 4, 'status': 6, 'return': 7,
        'next_fetch': rows[(cpu, 8)], 'terminal': 9, 'irq': 10,
        'case_material': {
            'observations': {'dma.irq_isr_completion': {
                'status': 'failed', 'evidence_refs': ['irq-evidence']}},
            'evidence_inventory': {'irq-evidence': {
                'kind': 'dma.irq_isr_completion', 'outcome': 'failed',
                'details': {'error_completion': completion}}}}}
    prefix = {'run_id': run_id, 'attempts': [case], 'records': [dict()]}
    contract = {'cpu': {'instance_id': cpu}, 'dma': {
        'instance_id': dma, 'csr': {'status_error_mask': 1}},
        'control': {'base': control}, 'program_contract': {
            'source_address': source, 'destination_address': destination,
            'slot_base': slot, 'result_base': result}}
    firmware = {'isr': {'mret_addresses': [isr, isr + 4]}}
    binding = {'binding_sha256': binding_sha}
    return api, prefix, contract, firmware, binding, case, rows


def test_saved_expected_error_accepts_first_dma_case_native_scope():
    api, prefix, contract, firmware, binding, _case, rows = (
        _expected_error_native_scope_material())
    api._audit_f6_expected_error(prefix, contract, firmware, binding,
        {'case_index': 0, 'operation': 'read', 'word_index': 1}, rows)


def test_saved_expected_error_accepts_production_integer_next_fetch_reference():
    api, prefix, contract, firmware, binding, case, rows = (
        _expected_error_native_scope_material())
    case['next_fetch'] = case['next_fetch']['event_id']

    api._audit_f6_expected_error(prefix, contract, firmware, binding,
        {'case_index': 0, 'operation': 'read', 'word_index': 1}, rows)


def test_saved_expected_error_rejects_unknown_integer_next_fetch_reference():
    api, prefix, contract, firmware, binding, case, rows = (
        _expected_error_native_scope_material())
    case['next_fetch'] = 999

    with pytest.raises(ValueError):
        api._audit_f6_expected_error(prefix, contract, firmware, binding,
            {'case_index': 0, 'operation': 'read', 'word_index': 1}, rows)


def test_saved_expected_error_rejects_non_native_first_dma_scope():
    api, prefix, contract, firmware, binding, _case, rows = (
        _expected_error_native_scope_material('run:dma:0'))
    with pytest.raises(ValueError):
        api._audit_f6_expected_error(prefix, contract, firmware, binding,
            {'case_index': 0, 'operation': 'read', 'word_index': 1}, rows)


def _transitioned_dma_scope_material():
    api = auditor_module()
    dma = 'dma'
    previous = {'case_id': 'run:case:0', 'case_index': 0,
        'status_kind': 'passed', 'expected_error': False,
        'feedback': [1] * 5, 'reads': [1, 2, 3, 4],
        'writes': [5, 6, 7, 8],
        'scope_transition': {'previous_case_id': 'run:native',
            'testcase_id': 'run:dma:1', 'case_id': 'run:case:1',
            'case_index': 1}}
    rows = {}
    for event_id in range(1, 9):
        rows[(dma, event_id)] = {'component': dma, 'event_id': event_id,
            'kind': 'dma_edge', 'accepted': {'transaction': {
                'testcase_id': 'run:native'}}}
    prefix = {'run_id': 'run', 'attempts': [previous,
        {'case_id': 'run:case:1', 'case_index': 1}]}
    return api, prefix, rows


def test_saved_expected_error_rebuilds_dma_scope_from_native_transition_chain():
    api, prefix, rows = _transitioned_dma_scope_material()
    assert api._expected_error_dma_testcase_id(
        prefix, 1, 'dma', rows) == 'run:dma:1'


def test_saved_expected_error_rejects_detached_dma_scope_transition():
    api, prefix, rows = _transitioned_dma_scope_material()
    prefix['attempts'][0]['scope_transition']['previous_case_id'] = 'run:dma:0'
    with pytest.raises(ValueError):
        api._expected_error_dma_testcase_id(prefix, 1, 'dma', rows)


def _raw_evidence_trace_material():
    runner_event = {
        'event_id': 1, 'component': 'cpu', 'kind': 'data_response',
        'address': 0x1000, 'rdata': 0x1234, 'write': 0,
    }
    projected = {
        **runner_event, 'event_id': 41, 'runner_event_id': 1,
    }
    local_tick = {
        'event_id': 2, 'component': 'cpu', 'kind': 'local_tick_sample',
        'local_tick': 1, 'phase': 'pre',
    }
    case = {
        'case_id': 'run:case:0',
        'evidence_inventory': {
            'response': {'kind': 'response', 'outcome': 'passed',
                'details': {'raw_evidence': [projected, local_tick]}},
        },
    }
    prefix = {
        'actual_events': [runner_event, local_tick],
        'attempts': [{'case_id': 'run:case:0', 'case_material': case}],
    }
    contract = {
        'cpu': {'instance_id': 'cpu'},
        'dma': {'instance_id': 'dma'},
        'irq': {'producer_port': 'o_interrupt', 'delivery_id': 'done'},
    }
    binding = {'binding_sha256': 'a' * 64}
    return prefix, contract, binding


def test_saved_typed_evidence_raw_rows_join_exact_runner_events():
    api = auditor_module()
    prefix, contract, binding = _raw_evidence_trace_material()
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding)
    assert index[('cpu', 41)]['kind'] == 'data_response'


def test_saved_raw_trace_rejects_two_observer_rows_aliasing_one_runner_event():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _raw_evidence_trace_material()
    prefix = deepcopy(prefix)
    evidence = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'response']['details']['raw_evidence']
    evidence.append({**evidence[0], 'event_id': 42})
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding)


def _irq_delivery_trace_material():
    from types import SimpleNamespace

    dma_edge = {
        'event_id': 1, 'component': 'dma', 'kind': 'dma_edge',
        'tick': 12, 'reset_epoch': 0,
        'payload': {'observations': {'physical': {'dma_irq': 1}}},
    }
    source_start = {
        'component': 'dma', 'event_id': 10, 'kind': 'source_start',
        'source_output_key': ['dma', 0, 'o_interrupt', 12],
        'source': ['dma', 'irq'], 'target': ['cpu', 'irq'],
        'producer_event_id': 9, 'source_event_id': 9,
    }
    delivery = {
        'component': 'cpu', 'event_id': 11, 'kind': 'binding_delivery',
        'source_event_id': 10,
        'source_output_key': ['dma', 0, 'o_interrupt', 12],
        'delivery_id': 'done', 'target_component': 'cpu', 'target_epoch': 0,
        'start_local_tick': 94, 'end_local_tick': 110,
    }
    events = [dma_edge]
    for tick in range(94, 110):
        events.append({
            'event_id': len(events) + 1, 'component': 'cpu',
            'kind': 'cpu_external_irq_sample',
            'local_tick': tick, 'reset_epoch': 0, 'expected_input': 1,
            'actual_pre_input': 1, 'actual_post_input': 1,
            'binding_delivery_event_id': 11,
            'source_output_key': ['dma', 0, 'o_interrupt', 12],
            'input_context': {
                'binding_delivery_event_id': 11,
                'source_output_key': ['dma', 0, 'o_interrupt', 12],
            },
        })
    events.append({
        'event_id': len(events) + 1, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'local_tick': 110,
        'reset_epoch': 0,
        'expected_input': 0, 'actual_pre_input': 0,
        'actual_post_input': 0,
    })
    raw_rows = [
        {**dma_edge, 'event_id': 9, 'runner_event_id': 1},
        source_start, delivery,
    ]
    raw_rows.extend({**event, 'event_id': 30 + i,
                     'runner_event_id': event['event_id']}
                    for i, event in enumerate(events[1:], start=1))
    case = {'case_id': 'run:case:0', 'evidence_inventory': {
        'irq': {'kind': 'irq', 'outcome': 'passed',
                'details': {'raw_evidence': raw_rows}},
    }}
    prefix = {'actual_events': events,
        'attempts': [{'case_id': 'run:case:0', 'case_material': case}]}
    contract = {'cpu': {'instance_id': 'cpu'},
        'dma': {'instance_id': 'dma'},
        'irq': {'producer_port': 'o_interrupt',
            'producer_endpoint_id': 'dma-irq', 'delivery_id': 'done'}}
    artifact = SimpleNamespace(runtime_document={'physical_exports': [{
        'physical_port': 'o_interrupt', 'endpoint_id': 'dma-irq',
        'direction': 'output', 'role': 'irq', 'width': 1,
        'disposition': 'functional', 'runtime_name': 'dma_irq'}]})
    binding = {'binding_sha256': 'a' * 64}
    return prefix, contract, binding, {'dma': artifact}


def test_saved_raw_irq_derived_rows_rejoin_source_and_pulse_trace():
    api = auditor_module()
    prefix, contract, binding, artifacts = _irq_delivery_trace_material()
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding,
                                               artifacts)
    assert index[('cpu', 11)]['kind'] == 'binding_delivery'


def test_saved_raw_irq_derived_row_rejects_trace_sample_mismatch():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding, artifacts = _irq_delivery_trace_material()
    prefix = deepcopy(prefix)
    prefix['actual_events'][1]['actual_post_input'] = 0
    projected = next(row for row in prefix['attempts'][0]['case_material'][
        'evidence_inventory']['irq']['details']['raw_evidence']
        if row.get('runner_event_id') == 2)
    projected['actual_post_input'] = 0
    # The raw projected row still matches the trace exactly. The derived
    # delivery claim fails because the trace says the pulse dropped early.
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding, artifacts)


def test_saved_irq_expiry_uses_cpu_target_epoch():
    api = auditor_module()
    prefix, contract, binding, artifacts = _irq_delivery_trace_material()
    prefix['actual_events'].append({
        'event_id': len(prefix['actual_events']) + 1, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'local_tick': 110,
        'reset_epoch': 1, 'expected_input': 0,
        'actual_pre_input': 0, 'actual_post_input': 0})
    api._verify_f6_raw_evidence_trace(prefix, contract, binding, artifacts)


def _isr_return_trace_material():
    nonce = 'f' * 32
    normalized = 'local-driver:cpu:1'
    binding_sha = 'a' * 64
    serial_take = {'decision': {'status': 'observed', 'value': 7}}
    serial_handler = {'retirement': {'status': 'observed', 'value': 7}}
    serial_return = {'retirement': {'status': 'observed', 'value': 0}}
    serial_successor = {'retirement': {'status': 'observed', 'value': 0}}

    def retire(event_id, sequence, order, tick, *, insn, pc, intr, serial,
               pc_wdata=0):
        return {
            'event_id': event_id, 'component': 'cpu', 'kind': 'cpu_retire',
            'reset_epoch': 0, 'local_tick': tick, 'phase': 'post',
            'execution_id': 'local-execution',
            'receipt_id': {'execution': normalized, 'sequence': sequence},
            'receipt_ticks': {'tick_before': tick - 1, 'tick_after': tick,
                'new_ticks': 1, 'local_tick_base': 0},
            'order': order, 'insn': insn, 'pc_rdata': pc,
            'pc_wdata': pc_wdata, 'intr': intr,
            'irq_serial_observation': serial,
        }

    take = {'event_id': 1, 'component': 'cpu',
        'kind': 'cpu_external_irq_taken', 'reset_epoch': 0,
        'take_key': ['cpu', 0, 1], 'testcase_id': 'run:native',
        'receipt_id': {'execution': normalized, 'sequence': 1},
        'local_tick': 1, 'sample_event_id': 2,
        'irq_serial_observation': serial_take}
    take_sample = {'event_id': 2, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'reset_epoch': 0,
        'local_tick': 1,
        'receipt_id': {'execution': normalized, 'sequence': 1}}
    handler = retire(3, 2, 2, 2, insn=0x13, pc=0x2000,
                     intr=1, serial=serial_handler)
    handler_sample = {'event_id': 4, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'reset_epoch': 0,
        'local_tick': 2,
        'receipt_ticks': handler['receipt_ticks'],
        'receipt_id': {'execution': normalized, 'sequence': 2}}
    returned = retire(5, 3, 3, 3, insn=0x30200073, pc=0x2010,
                      intr=0, serial=serial_return, pc_wdata=0x3000)
    return_sample = {'event_id': 6, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'reset_epoch': 0,
        'local_tick': 3,
        'receipt_ticks': returned['receipt_ticks'],
        'receipt_id': {'execution': normalized, 'sequence': 3}}
    successor = retire(7, 4, 4, 4, insn=0x13, pc=0x3000,
                       intr=0, serial=serial_successor)
    response_doc = {
        'kind': 'instr_response', 'component': 'cpu',
        'source_component': 'cpu', 'execution_id': 'local-execution',
        'reset_epoch': 0, 'source_epoch': 0, 'tick': 4,
        'address': 0x3000, 'transaction': {
            'execution_id': 'local-execution', 'testcase_id': 'run:native',
            'source_component': 'cpu', 'source_epoch': 0,
            'channel_id': 'instr', 'source_sequence': 4},
        'rdata': 0x13, 'error': 0, 'response_tick': 4,
    }
    response = {**response_doc, 'event_id': 8, 'producer_event_id': 7,
        'provenance': {'schema_version': 'event_source_provenance.v1'}}
    successor_sample = {'event_id': 9, 'component': 'cpu',
        'kind': 'cpu_external_irq_sample', 'reset_epoch': 0,
        'local_tick': 4,
        'receipt_ticks': successor['receipt_ticks'],
        'receipt_id': {'execution': normalized, 'sequence': 4}}
    returned_row = {
        'schema_version': 'native_f6_isr_return.v1', 'component': 'cpu',
        'event_id': 50,
        'execution': nonce, 'reset_epoch': 0,
        'case_id': 'run:case:0', 'case_index': 0,
        'native_testcase_id': 'run:native', 'irq_take_key': ['cpu', 0, 1],
        'take_receipt_id': {'execution': nonce, 'sequence': 1},
        'take_irq_serial_observation': serial_take,
        'handler_entry_receipt_id': {'execution': nonce, 'sequence': 2},
        'handler_entry_rvfi_order': 2, 'handler_entry_pc_rdata': 0x2000,
        'handler_entry_irq_serial_observation': serial_handler,
        'return_receipt_id': {'execution': nonce, 'sequence': 3},
        'return_receipt_ticks': returned['receipt_ticks'],
        'local_tick': 3, 'phase': 'post', 'rvfi_order': 3,
        'instruction': 0x30200073, 'pc_rdata': 0x2010,
        'pc_wdata': 0x3000, 'irq_serial_observation': serial_return,
        'isr_sha256': 'b' * 64, 'execution_binding_sha256': binding_sha,
        'successor_receipt_id': {'execution': nonce, 'sequence': 4},
        'successor_rvfi_order': 4, 'successor_local_tick': 4,
        'successor_pc_rdata': 0x3000, 'successor_instruction': 0x13,
        'successor_irq_serial_observation': serial_successor,
        'successor_instruction_response': response_doc,
        'successor_instruction_response_receipt_id': {
            'execution': nonce, 'sequence': 4},
        'return_target': 0x3000,
        'return_target_source':
            'first_subsequent_valid_RVFI_pc_rdata_with_instruction_response',
        'return_target_authority':
            'inferred_architectural_successor_after_MRET',
    }
    case = {'case_id': 'run:case:0', 'evidence_inventory': {
        'return': {'kind': 'return', 'outcome': 'passed',
            'details': {'raw_evidence': [returned_row]}},
    }}
    prefix = {'actual_events': [take, take_sample, handler, handler_sample,
            returned, return_sample, successor, response, successor_sample],
        'attempts': [{'case_id': 'run:case:0', 'case_index': 0,
            'case_material': case}],
        'original_execution_audit': {'identities': {'cpu': {
            'execution_nonce': nonce}}}}
    contract = {'cpu': {'instance_id': 'cpu'},
        'dma': {'instance_id': 'dma'}, 'irq': {}}
    firmware = {'isr': {'address': 0x2000,
        'mret_addresses': [0x2010], 'sha256': 'b' * 64}}
    return prefix, contract, {'binding_sha256': binding_sha}, firmware


def test_saved_native_isr_return_rejoins_retirements_and_response():
    api = auditor_module()
    prefix, contract, binding, firmware = _isr_return_trace_material()
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding,
                                               firmware_document=firmware)
    assert index[('cpu', 50)]['schema_version'] == 'native_f6_isr_return.v1'


@pytest.mark.parametrize('mutation', ['none', 'wrong_nonce', 'wrong_producer',
                                      'wrong_case', 'wrong_transaction'])
def test_saved_native_isr_take_without_testcase_joins_raw_command_scope(mutation):
    api = auditor_module()
    prefix, contract, binding, firmware = _isr_return_trace_material()
    events = prefix['actual_events']; take, sample = events[:2]
    take.pop('testcase_id')
    case = {'case_id': 'run:case:0', 'case_index': 0}
    scope = {'component': 'cpu', 'reset_epoch': 0, 'command_sequence': 1}
    ticks = {'tick_before': 0, 'tick_after': 1, 'new_ticks': 1, 'local_tick_base': 0}
    outputs = {'physical': {'probe_irq_taken_pre': 1}}
    producer = {'event_id': 10, 'component': 'cpu', 'local_tick': 1,
        'inputs': {}, 'outputs': {'driver_samples': [{'local_tick': 1,
            'pre': deepcopy(outputs), 'post': deepcopy(outputs)}]},
        'provenance': {'observed_case': deepcopy(case)}}
    for row in (take, sample):
        row.update(command_scope=deepcopy(scope), receipt_ticks=deepcopy(ticks),
            producer_event_id=10, provenance={'observed_case': deepcopy(case)})
    take['sample_ref'] = {'command_scope': deepcopy(scope), 'local_tick': 1}
    nonce = prefix['original_execution_audit']['identities']['cpu']['execution_nonce']
    samples = [dict(event_id=11+i, component='cpu', kind='local_tick_sample',
        local_tick=1, phase=phase, producer_event_id=10,
        f6_obi_scope=[nonce, 1, 0, 1], outputs=deepcopy(outputs),
        provenance={'observed_case': deepcopy(case)})
        for i, phase in enumerate(('pre', 'post'))]
    events.extend([producer]+samples)
    if mutation == 'wrong_nonce': samples[0]['f6_obi_scope'][0] = 'foreign'
    elif mutation == 'wrong_producer': samples[0]['producer_event_id'] = 99
    elif mutation == 'wrong_case': take['provenance']['observed_case']['case_id'] = 'foreign'
    elif mutation == 'wrong_transaction':
        events[7]['transaction']['testcase_id'] = 'foreign'
        prefix['attempts'][0]['case_material']['evidence_inventory']['return']['details']['raw_evidence'][0]['successor_instruction_response']['transaction']['testcase_id'] = 'foreign'
    if mutation == 'none':
        api._verify_f6_raw_evidence_trace(prefix, contract, binding, firmware_document=firmware)
    else:
        with pytest.raises(ValueError):
            api._verify_f6_raw_evidence_trace(prefix, contract, binding, firmware_document=firmware)


def test_saved_native_isr_return_rejects_detached_pc_claim():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding, firmware = _isr_return_trace_material()
    prefix = deepcopy(prefix)
    raw_return = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'return']['details']['raw_evidence'][0]
    raw_return['pc_rdata'] = 0x2020
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding,
                                           firmware_document=firmware)


def _fetch_boundary_trace_material():
    sample = {'event_id': 1, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 9, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 1,
            'i_req_addr': 0x3000}}}
    boundary = {'address': 0x3000, 'execution': 'a' * 32,
        'reset_epoch': 0, 'native_testcase_id': 'run:native',
        'transaction': {'execution_id': 'local-execution',
            'testcase_id': 'run:native', 'source_component': 'cpu',
            'source_epoch': 0, 'channel_id': 'instr', 'source_sequence': 1},
        'local_tick': 9, 'boundary': 'next_prefix_or_park',
        'component': 'cpu', 'event_id': 20, 'kind': 'native_fetch_boundary'}
    case = {'case_id': 'run:case:0', 'evidence_inventory': {
        'boundary': {'kind': 'boundary', 'outcome': 'passed',
            'details': {'raw_evidence': [sample, boundary]}},
    }}
    prefix = {'actual_events': [sample], 'attempts': [{
        'case_id': 'run:case:0', 'case_material': case}],
        'original_execution_audit': {'identities': {'cpu': {
            'execution_nonce': 'a' * 32}}}}
    contract = {'cpu': {'instance_id': 'cpu'},
        'dma': {'instance_id': 'dma'}, 'irq': {}}
    binding = {'binding_sha256': 'b' * 64}
    return prefix, contract, binding


def test_saved_fetch_boundary_rejoins_actual_pre_request_handshake():
    api = auditor_module()
    prefix, contract, binding = _fetch_boundary_trace_material()
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding)
    assert index[('cpu', 20)]['kind'] == 'native_fetch_boundary'


def test_saved_fetch_boundary_counts_only_accepted_pre_handshakes():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _fetch_boundary_trace_material()
    prefix = deepcopy(prefix)
    accepted_before = {'event_id': 1, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 7, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 1,
            'i_req_addr': 0x2000}}}
    stalled = {'event_id': 2, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 8, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 0,
            'i_req_addr': 0x2800}}}
    selected = {'event_id': 3, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 9, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 1,
            'i_req_addr': 0x3000}}}
    prefix['actual_events'] = [accepted_before, stalled, selected]
    raw_rows = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'boundary']['details']['raw_evidence']
    raw_rows[0] = selected.copy()
    raw_rows[1]['transaction']['source_sequence'] = 2
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding)
    assert index[('cpu', 20)]['kind'] == 'native_fetch_boundary'


def test_saved_fetch_boundary_resets_sequence_at_cpu_reset_epoch():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _fetch_boundary_trace_material()
    prefix = deepcopy(prefix)
    previous_epoch = {'event_id': 1, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 7, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 1,
            'i_req_addr': 0x2000}}}
    reset = {'event_id': 2, 'component': 'cpu', 'kind': 'cpu_reset',
        'reset_epoch': 1}
    current_epoch = {'event_id': 3, 'component': 'cpu',
        'kind': 'local_tick_sample', 'local_tick': 9, 'phase': 'pre',
        'outputs': {'backend': {'i_req_valid': 1, 'i_req_ready': 1,
            'i_req_addr': 0x3000}}}
    prefix['actual_events'] = [previous_epoch, reset, current_epoch]
    raw_rows = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'boundary']['details']['raw_evidence']
    raw_rows[0] = current_epoch.copy()
    boundary = raw_rows[1]
    boundary['reset_epoch'] = 1
    boundary['transaction']['source_epoch'] = 1
    boundary['transaction']['source_sequence'] = 1
    index = api._verify_f6_raw_evidence_trace(prefix, contract, binding)
    assert index[('cpu', 20)]['transaction']['source_sequence'] == 1


def test_saved_fetch_boundary_rejects_detached_handshake_sequence():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _fetch_boundary_trace_material()
    prefix = deepcopy(prefix)
    boundary = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'boundary']['details']['raw_evidence'][1]
    boundary['transaction']['source_sequence'] = 2
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding)


def test_saved_fetch_boundary_rejects_wrong_handshake_address():
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _fetch_boundary_trace_material()
    prefix = deepcopy(prefix)
    prefix['attempts'][0]['case_material']['evidence_inventory'][
        'boundary']['details']['raw_evidence'][1]['address'] = 0x4000
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding)


@pytest.mark.parametrize('mutation', ('detached', 'payload', 'runner_id'))
def test_saved_typed_evidence_rejects_raw_rows_detached_from_runner_trace(mutation):
    from copy import deepcopy

    api = auditor_module()
    prefix, contract, binding = _raw_evidence_trace_material()
    prefix = deepcopy(prefix)
    row = prefix['attempts'][0]['case_material']['evidence_inventory'][
        'response']['details']['raw_evidence'][0]
    if mutation == 'detached':
        row['runner_event_id'] = 99
    elif mutation == 'payload':
        row['rdata'] = 0x9999
    else:
        row['runner_event_id'] = True
    with pytest.raises(ValueError):
        api._verify_f6_raw_evidence_trace(prefix, contract, binding)


def test_d3_refusal_audit_requires_downstream_stages_absent(tmp_path,
                                                          monkeypatch):
    """A path-compilation refusal returns before the driver reaches D4."""
    api = auditor_module()
    root = tmp_path / 'repo'
    output = root / 'run'
    invocation = root / 'invocation'
    root.mkdir()
    output.mkdir()
    invocation.mkdir()
    monkeypatch.setattr(api, 'ROOT', root)

    fixture = root / 'fixture.json'
    fixture.write_text('{}\n')
    fixture_sha256 = api.file_hash(fixture)
    guard_source = root / 'guard.py'
    guard_source.write_text('# guard source\n')
    guard_source_sha256 = api.file_hash(guard_source)
    guard_sources = {'guard.py': guard_source_sha256}
    proof = {
        'schema_version': api.GUARD_SCHEMA,
        'control_id': 'f6-unsupported-irq-form',
        'fixture_path': 'fixture.json', 'fixture_sha256': fixture_sha256,
        'guard_sources': guard_sources,
        'guard_sources_sha256': api.digest(guard_sources),
        'guard_mode': 'runtime_constructor_sentinel',
        'constructor_called': False, 'native_process_count': 0,
        'status': 'refused', 'stage': 'path_compilation',
        'code': 'f6-native-irq-binding-required',
        'pointer': '/wiring/deliveries',
    }
    proof_path = root / 'proof.json'
    proof_path.write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    proof_sha256 = api.file_hash(proof_path)
    (invocation / 'command.json').write_text(json.dumps({
        'command_kind': 'auto_harness_cli',
        'gate_mode': 'f6-unsupported-irq',
    }, sort_keys=True, indent=2) + '\n')
    (output / '.incomplete').write_text(json.dumps({
        'status': 'started', 'output': str(output.resolve()),
    }, sort_keys=True, indent=2) + '\n')
    (output / 'run-summary.json').write_text(json.dumps({
        'status': 'refused', 'exit_code': 1,
        'output': str(output.resolve()),
        'refusals': [{
            'stage': 'path_compilation',
            'code': 'f6-native-irq-binding-required',
            'pointer': '/wiring/deliveries',
        }],
        'stages': {
            'path_compilation': {'status': 'refused'},
            'session': {'status': 'absent'},
            'fresh_verification': {'status': 'absent'},
        },
    }, sort_keys=True, indent=2) + '\n')

    declaration = {'refusal': {
        'proof_path': 'proof.json', 'proof_sha256': proof_sha256,
        'stage': 'path_compilation',
        'code': 'f6-native-irq-binding-required',
        'pointer': '/wiring/deliveries',
    }}
    result = api._audit_refusal(output, invocation, declaration, {
        'proof.json': proof_sha256, 'fixture.json': fixture_sha256,
        'guard.py': guard_source_sha256,
    })
    assert result['status'] == 'ok'
    assert result['scope'] == 'preconstruction_only'

    summary_path = output / 'run-summary.json'
    summary = json.loads(summary_path.read_text())
    summary['stages']['session']['status'] = 'not_requested'
    summary['stages']['fresh_verification']['status'] = 'not_requested'
    summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    with pytest.raises(ValueError, match='refusal-stage-scope'):
        api._audit_refusal(output, invocation, declaration, {
            'proof.json': proof_sha256, 'fixture.json': fixture_sha256,
            'guard.py': guard_source_sha256,
        })
