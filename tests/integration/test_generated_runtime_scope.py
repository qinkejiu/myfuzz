from unittest.mock import patch
import pytest
from myfuzz.local_harness.generated_execution_admission import (
    GeneratedExecutionRefused,select_execution_artifacts)


def test_scope_is_explicit_and_never_discards_compiled_inputs():
    with pytest.raises(GeneratedExecutionRefused,match='generated-runtime-scope-invalid'):
        select_execution_artifacts(artifacts={},compiled_inputs=None,scope='automatic')
    with pytest.raises(GeneratedExecutionRefused,match='compiled-inputs-not-executed'):
        select_execution_artifacts(artifacts={},compiled_inputs={},scope='loaded_artifacts')
    with pytest.raises(GeneratedExecutionRefused,match='generated-runtime-input-required'):
        select_execution_artifacts(artifacts=None,compiled_inputs=None,scope='loaded_artifacts')


def test_loaded_scope_returns_exact_supplied_objects_without_authorizing_d3():
    supplied={'cpu':object()}
    assert select_execution_artifacts(artifacts=supplied,compiled_inputs=None,
        scope='loaded_artifacts') is supplied


def test_cli_cannot_start_family_defaults_when_d2_d3_are_missing(tmp_path):
    from myfuzz.local_harness.auto_harness_test import run_live_session,runtime_family,AutoHarnessRefused
    client=tmp_path/'client';client.write_bytes(b'not executed')
    cache=tmp_path/'cache';cache.mkdir()
    with patch('subprocess.Popen',side_effect=AssertionError('must refuse before startup')):
        with pytest.raises(AutoHarnessRefused,match='compiled-runtime-input-required'):
            run_live_session(family=runtime_family('cv32e40p-pulp-dual-source'),
                session_dir=tmp_path/'session',client_binary=client,cache_dir=cache,
                run_id='missing-inputs',budget_seconds=1,max_tests=1,search_seed=1,
                max_runs_per_batch=1,base_dir=tmp_path)


def test_projection_gap_inventory_names_semantics_without_granting_execution():
    from myfuzz.local_harness.generated_execution_admission import runtime_projection_gaps
    rows=runtime_projection_gaps({'paths':[dict(status='executable',path_id='p',flow_id='F4',
        sources=[{'source_id':'cpu.mmio'}],bound_inputs=[{'input_id':'real.response'}],
        prerequisites=[{'kind':'ip_register_version'}],
        assertions=[{'expectation_id':'exact.chain'}],seed=None,
        constraints={'policy_hash':'sha256:policy'})]})
    assert rows[0]['runtime_admitted'] is False
    assert {r['obligation'] for r in rows[0]['gaps']}=={
        'sources','bound_inputs','prerequisites','assertions','constraints'}
    assert {r['pointer'] for r in rows[0]['gaps']}=={
        '/paths/0/sources/0','/paths/0/bound_inputs/0','/paths/0/prerequisites/0',
        '/paths/0/assertions/0','/paths/0/constraints'}
