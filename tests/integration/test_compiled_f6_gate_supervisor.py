"""Software-only checks for the prepared F6 frozen gate supervisor."""
import importlib.util
import json
from pathlib import Path
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
GATES = ROOT / '.superpowers/sdd/compiled-f6-20261024/gates'
RUNNER = GATES / 'run_gate.py'
MATRIX = GATES / 'inputs/control-matrix.json'


def runner_module():
    spec = importlib.util.spec_from_file_location('compiled_f6_gate_supervisor', RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_control_matrix_has_exact_plan_gate_modes():
    from_runner = runner_module()
    document = json.loads(MATRIX.read_text())
    assert tuple(row['id'] for row in document['gate_modes']) == from_runner.MODES
    assert from_runner.MODES == (
        'software', 'native-controls', 'f6-positive', 'f6-renamed',
        'f6-unsupported-irq', 'f6-wrong-route', 'f6-controlled-err-read',
        'f6-controlled-err-write', 'f2-timer', 'f2-spi', 'f4-timer', 'f4-spi')
    assert document['status'] == 'draft_pending_freeze_review_execution'
    assert document['freeze']['inputs_prepared'] is True
    assert document['freeze']['source_and_tool_archive_prepared'] is True
    assert document['freeze']['independent_freeze_review'] == 'pending'
    assert document['freeze']['execution_started'] is False
    assert document['freeze']['literal_argv_must_be_archived_before_launch'] is True


def test_control_matrix_requires_complete_exact_task8_control_id_to_mode_mapping():
    from_runner = runner_module()
    document = json.loads(MATRIX.read_text())
    assert from_runner.validate_control_matrix(document)
    incomplete = json.loads(json.dumps(document))
    incomplete['controls'].pop()
    with pytest.raises(ValueError, match='control-matrix-control-set-or-mapping'):
        from_runner.validate_control_matrix(incomplete)
    remapped = json.loads(json.dumps(document))
    next(row for row in remapped['controls'] if row['id'] == 'two-record-refusal')['gate_mode'] = 'f6-positive'
    with pytest.raises(ValueError, match='control-matrix-control-set-or-mapping'):
        from_runner.validate_control_matrix(remapped)


def test_control_matrix_binds_all_native_nodes_to_controls_and_exact_modes():
    from_runner = runner_module()
    document = json.loads(MATRIX.read_text())
    source_shape_node = (
        'tests/integration/test_compiled_f6_native.py::'
        'test_preconstruction_refuses_source_incompatible_dma_provider_before_runtime_construction')
    native_controls = [
        source_shape_node,
        'tests/integration/test_compiled_f6_native.py::test_preflight_refuses_reserved_operand_before_effects',
        'tests/integration/test_compiled_f6_native.py::test_preflight_refuses_duplicate_operands_before_effects',
        'tests/integration/test_compiled_f6_native.py::test_preflight_refuses_two_records_before_effects',
        'tests/integration/test_compiled_f6_native.py::test_copied_observation_missing_read_snapshot_marks_attempt_and_zero_feedback',
        'tests/integration/test_compiled_f6_native.py::test_copied_observation_missing_destination_commit_marks_attempt_and_zero_feedback',
        'tests/integration/test_compiled_f6_native.py::test_copied_observation_missing_irq_marks_attempt_and_zero_feedback',
        'tests/integration/test_compiled_f6_native.py::test_copied_observation_missing_mret_marks_attempt_and_zero_feedback',
        'tests/integration/test_compiled_f6_native.py::test_copied_observation_missing_successor_marks_attempt_and_zero_feedback',
    ]
    read_error = ['tests/integration/test_compiled_f6_native.py::test_controlled_read_err_persists_failed_prefix_for_supervisor_audit']
    write_error = ['tests/integration/test_compiled_f6_native.py::test_controlled_write_err_persists_failed_prefix_for_supervisor_audit']
    assert document['native_test_nodes_by_mode'] == {
        'native-controls': native_controls,
        'f6-controlled-err-read': read_error,
        'f6-controlled-err-write': write_error,
    }
    expected = native_controls + read_error + write_error
    assert document['native_test_nodeids'] == expected
    assert document['freeze']['planned_pytest_nodeids'] == expected
    source_control = next(row for row in document['controls']
        if row['id'] == 'f6-source-shape-refusal')
    assert source_control['pytest_nodeid'] == source_shape_node
    assert source_control['native_evidence_path'] == 'source-shape-refusal.json'
    native_gate = next(row for row in document['gate_modes'] if row['id'] == 'native-controls')
    assert 'source-shape-refusal' in native_gate['covers']
    assert 'exact node IDs are frozen from implementation' in native_gate['command_source']
    assert from_runner.validate_control_matrix(document)


def test_control_matrix_rejects_missing_native_control_node_binding():
    from_runner = runner_module()
    document = json.loads(MATRIX.read_text())
    source_control = next(row for row in document['controls']
        if row['id'] == 'f6-source-shape-refusal')
    source_control.pop('pytest_nodeid', None)
    with pytest.raises(ValueError, match='control-matrix-native-control-node-bindings'):
        from_runner.validate_control_matrix(document)


def test_controlled_error_controls_repeat_the_closed_selected_node_ids():
    from_runner = runner_module()
    document = json.loads(MATRIX.read_text())
    for control_id, mode in (
            ('f6-controlled-err-middle-read', 'f6-controlled-err-read'),
            ('f6-controlled-err-middle-write', 'f6-controlled-err-write')):
        control = next(row for row in document['controls'] if row['id'] == control_id)
        assert control['pytest_nodeid'] == document['native_test_nodes_by_mode'][mode][0]
        changed = json.loads(json.dumps(document))
        changed_control = next(row for row in changed['controls'] if row['id'] == control_id)
        changed_control['pytest_nodeid'] = 'tests/integration/test_compiled_f6_native.py::unrelated_node'
        with pytest.raises(ValueError, match='control-matrix-native-control-node-bindings'):
            from_runner.validate_control_matrix(changed)


def test_raw8_native_control_fixtures_are_in_frozen_map_and_archive(tmp_path, monkeypatch):
    from_runner = runner_module()
    names = (
        '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/raw-controls/reserved-bit.raw8',
        '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/raw-controls/duplicate-operands.raw8',
        '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/raw-controls/two-records.raw8',
    )
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    monkeypatch.setattr(from_runner, 'GATES', tmp_path / '.superpowers/sdd/compiled-f6-20261024/gates')
    monkeypatch.setattr(from_runner, 'INPUTS', from_runner.GATES / 'inputs')
    monkeypatch.setattr(from_runner, 'TASK_ROOT', from_runner.GATES.parent)
    monkeypatch.setattr(from_runner, 'INPUT_TOPS', ())
    monkeypatch.setattr(from_runner, 'CLIENT', tmp_path / 'missing-kfuzz')
    for index, name in enumerate(names):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes([index + 1]) * (8 if index < 2 else 16))
    for index, name in enumerate(from_runner.EXPLICIT_INPUTS):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(f'explicit-input-{index}\n'.encode())

    frozen_map = from_runner.snapshot()
    assert set(names) <= set(frozen_map)
    archive = tmp_path / 'frozen-inputs.tar.gz'
    from_runner.archive_regular_inputs(archive, frozen_map)
    from_runner.verify_regular_archive(archive, frozen_map)
    with tarfile.open(archive, 'r:gz') as source_archive:
        members = {member.name: member for member in source_archive.getmembers()}
        assert set(names) <= set(members)
        assert all(members[name].isfile() for name in names)
        assert {name: from_runner.digest(tmp_path / name) for name in names} == {
            name: frozen_map[name] for name in names}


def test_frozen_inventory_includes_exact_rvfi_export_manifest(tmp_path, monkeypatch):
    from_runner = runner_module()
    name = 'runs/task4-ibex-retire/rvfi-export-manifest.json'
    path = tmp_path / name
    path.parent.mkdir(parents=True)
    path.write_text('{"schema_version":"rvfi_export_manifest.v1"}\n')
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    monkeypatch.setattr(from_runner, 'GATES', tmp_path / '.superpowers/gates')
    monkeypatch.setattr(from_runner, 'INPUTS', tmp_path / '.superpowers/gates/inputs')
    monkeypatch.setattr(from_runner, 'TASK_ROOT', tmp_path / '.superpowers')
    monkeypatch.setattr(from_runner, 'INPUT_TOPS', ())
    monkeypatch.setattr(from_runner, 'EXPLICIT_INPUTS', (name,))
    monkeypatch.setattr(from_runner, 'F6_RAW_CONTROL_INPUTS', ())
    monkeypatch.setattr(from_runner, 'CLIENT', tmp_path / 'missing-kfuzz')

    frozen_map = from_runner.snapshot()

    assert set(frozen_map) == {name}
    assert frozen_map[name] == from_runner.digest(path)


def test_frozen_inventory_includes_profile_filelists_and_excludes_git_pointer_files(
        tmp_path, monkeypatch):
    from_runner = runner_module()
    profile_dir = tmp_path / 'configs/cpus/demo'
    profile_dir.mkdir(parents=True)
    (profile_dir / 'component_profile.json').write_text(json.dumps({
        'schema_version': 'component_profile.v1',
        'source': {
            'root': 'third_party/demo-cpu',
            'filelist': 'rtl/demo.flist',
            'include_roots': ['.'],
        },
    }))
    peripheral_profile = tmp_path / 'configs/peripherals/demo/component_profile.json'
    peripheral_profile.parent.mkdir(parents=True)
    peripheral_profile.write_text(json.dumps({
        'schema_version': 'component_profile.v1',
        'source': {
            'root': 'external_designs/demo-ip',
            'files': ['rtl/demo.sv'],
            'include_roots': ['.'],
        },
    }))
    cpu_root = tmp_path / 'third_party/demo-cpu'
    (cpu_root / 'rtl').mkdir(parents=True)
    filelist = cpu_root / 'rtl/demo.flist'
    filelist.write_text('rtl/demo.sv\n')
    ip_root = tmp_path / 'external_designs/demo-ip'
    (ip_root / 'rtl').mkdir(parents=True)
    (ip_root / 'rtl/demo.sv').write_text('module demo; endmodule\n')
    (ip_root / '.git').write_text('gitdir: /unavailable/project/.git/modules/demo-ip\n')
    (cpu_root / '.git').mkdir()
    (cpu_root / '.git/config').write_text('[core]\nrepositoryformatversion = 0\n')
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    monkeypatch.setattr(from_runner, 'GATES', tmp_path / '.superpowers/gates')
    monkeypatch.setattr(from_runner, 'INPUTS', tmp_path / '.superpowers/gates/inputs')
    monkeypatch.setattr(from_runner, 'TASK_ROOT', tmp_path / '.superpowers')
    monkeypatch.setattr(from_runner, 'INPUT_TOPS', ('third_party', 'external_designs'))
    monkeypatch.setattr(from_runner, 'EXPLICIT_INPUTS', ())
    monkeypatch.setattr(from_runner, 'F6_RAW_CONTROL_INPUTS', ())
    monkeypatch.setattr(from_runner, 'CLIENT', tmp_path / 'missing-kfuzz')

    paths, _ = from_runner._input_inventory()
    names = {path.relative_to(tmp_path).as_posix() for path in paths}

    assert 'third_party/demo-cpu/rtl/demo.flist' in names
    assert 'external_designs/demo-ip/rtl/demo.sv' in names
    assert 'external_designs/demo-ip/.git' not in names
    assert 'third_party/demo-cpu/.git/config' not in names


def test_prepare_freeze_archives_regular_source_bytes_and_binds_origins(tmp_path, monkeypatch):
    from_runner = runner_module()
    source = tmp_path / 'source.py'
    source.write_bytes(b'print(1)\n')
    alias = tmp_path / 'alias.py'
    alias.symlink_to(source)
    byte_map = {'source.py': from_runner.digest(source), 'alias.py': from_runner.digest(alias)}
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    archive = tmp_path / 'inputs.tar.gz'
    origins = from_runner.source_origins(byte_map)
    from_runner.archive_regular_inputs(archive, byte_map)
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        assert {member.name for member in members} == set(byte_map)
        assert all(member.isfile() for member in members)
        assert {member.name: tar.extractfile(member).read() for member in members} == {
            'source.py': b'print(1)\n', 'alias.py': b'print(1)\n'}
    assert origins['alias.py']['is_symlink'] is True
    assert origins['alias.py']['link_target'] == str(source)
    assert origins['alias.py']['content_sha256'] == byte_map['alias.py']


def test_freeze_review_must_bind_archive_source_manifest_matrix_and_commands(tmp_path):
    from_runner = runner_module()
    source_map = {'src/a.py': 'a' * 64}
    archive_sha = 'b' * 64
    manifest_sha = 'c' * 64
    matrix_sha = 'd' * 64
    commands_sha = 'e' * 64
    review = {
        'schema_version': 'compiled_F6_independent_freeze_review.v1',
        'result': 'PASS',
        'source_map_sha256': from_runner.canonical_sha256(source_map),
        'archive_sha256': archive_sha,
        'manifest_sha256': manifest_sha,
        'control_matrix_sha256': matrix_sha,
        'command_selection_sha256': commands_sha,
    }
    assert from_runner.validate_freeze_review(review,
        source_map_sha256=from_runner.canonical_sha256(source_map),
        archive_sha256=archive_sha, manifest_sha256=manifest_sha,
        control_matrix_sha256=matrix_sha, command_selection_sha256=commands_sha)
    changed = dict(review, command_selection_sha256='f' * 64)
    with pytest.raises(ValueError, match='freeze-review'):
        from_runner.validate_freeze_review(changed,
            source_map_sha256=from_runner.canonical_sha256(source_map),
            archive_sha256=archive_sha, manifest_sha256=manifest_sha,
            control_matrix_sha256=matrix_sha, command_selection_sha256=commands_sha)
    with pytest.raises(ValueError, match='freeze-review'):
        from_runner.validate_freeze_review(dict(review, caller_trust=True),
            source_map_sha256=from_runner.canonical_sha256(source_map), archive_sha256=archive_sha,
            manifest_sha256=manifest_sha, control_matrix_sha256=matrix_sha,
            command_selection_sha256=commands_sha)


def test_f6_positive_command_uses_frozen_literal_and_4096_rounds():
    from_runner = runner_module()
    attempt = ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt1'
    command = from_runner.command_for('f6-positive', attempt)
    assert command['expected_exit_code'] == 0
    assert command['argv'] == [
        from_runner.PYTHON, 'scripts/auto_harness_test.py',
        '--executor', 'compiled-f6-rfuzz',
        '--f6-execution', '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/f6_execution.json',
        '--f6-deliveries', '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/f6_deliveries.json',
        '--cpu', 'configs/cpus/ibex_rvfi_local/component_profile.json',
        '--ip', 'configs/peripherals/zipcpu_wbdmac/component_profile.json',
        '--compose', '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/compose.json',
        '--ip-capability', '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/test_capability.json',
        '--client-binary', 'third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz',
        '--cache-dir', '.superpowers/cache/compiled-f6-20261024',
        '--output', '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt1/run',
        '--budget-seconds', '30', '--max-tests', '4', '--max-runs-per-batch', '1',
        '--search-seed', '1', '--rounds-per-case', '4096']


def test_refusal_cli_commands_follow_matrix_and_disable_native_optin():
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    for mode, control_id, fixture_dir in (
            ('f6-unsupported-irq', 'f6-unsupported-irq-form', 'gates/inputs/f6-ram/unsupported-irq'),
            ('f6-wrong-route', 'f6-wrong-route', 'gates/inputs/f6-ram/wrong-route')):
        control = next(row for row in matrix['controls'] if row['id'] == control_id)
        control['fixture_dir'] = fixture_dir
        control['expected_control_exit'] = 1
        command = from_runner.command_for(mode, ROOT / '.superpowers/sdd/test-refusal', matrix)
        assert command['native_opt_in'] is False
        assert command['environment_overrides']['MYFUZZ_RUN_NATIVE_F6'] == '0'


def test_native_error_command_uses_compiled_output_contract_without_invocation_env():
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    out = ROOT / 'docs/reports/evidence/f6-test-attempt'
    command = from_runner.command_for('f6-controlled-err-read', out, matrix)
    env = command['environment_overrides']
    assert env['MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE'] == \
        'docs/reports/evidence/f6-test-attempt/native-controls'
    assert env['MYFUZZ_COMPILED_F6_NATIVE_CACHE'] == '.superpowers/cache/compiled-f6-20261024'
    assert env['MYFUZZ_COMPILED_F6_NATIVE_OUTPUT'] == \
        'docs/reports/evidence/f6-test-attempt/run'
    assert 'MYFUZZ_F6_INVOCATION' not in env
    assert command['selected_nodes'] == matrix['native_test_nodes_by_mode']['f6-controlled-err-read']


def test_expected_error_declaration_uses_only_production_fault_selector_fields(tmp_path, monkeypatch):
    from_runner = runner_module()
    control = {'fault_selector': {'case_index': 1, 'operation': 'read', 'word_index': 2}}
    monkeypatch.setattr(from_runner, '_control_row', lambda matrix, control_id: control)
    declaration = from_runner._declaration_for('f6-controlled-err-read',
        {'expected_exit_code': 0}, 'a' * 64, {})
    assert declaration['fault_selector'] == control['fault_selector']
    assert set(declaration['fault_selector']) == {'case_index', 'operation', 'word_index'}


def test_frozen_source_inventory_keeps_declared_core_files_under_include_roots(tmp_path, monkeypatch):
    from_runner = runner_module()
    root = tmp_path
    profile = root / 'configs/cpus/ibex/component_profile.json'
    profile.parent.mkdir(parents=True)
    profile.write_text(json.dumps({
        'schema_version': 'component_profile.v1',
        'source': {
            'root': 'third_party/rfuzz/upstream/ibex',
            'files': ['rtl/declared-source.core'],
            'include_roots': ['vendor/lowrisc_ip/dv/sv/dv_utils'],
        },
    }))
    source_root = root / 'third_party/rfuzz/upstream/ibex'
    include_root = source_root / 'vendor/lowrisc_ip/dv/sv/dv_utils'
    include_root.mkdir(parents=True)
    (include_root / 'dv_utils.core').write_text('core include\n')
    (include_root / 'README.md').write_text('README include\n')
    (source_root / 'rtl').mkdir()
    (source_root / 'rtl/declared-source.core').write_text('declared source\n')
    for index, name in enumerate(from_runner.F6_RAW_CONTROL_INPUTS):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes([index]) * 8)
    gates = root / '.superpowers/sdd/compiled-f6-20261024/gates'
    monkeypatch.setattr(from_runner, 'ROOT', root)
    monkeypatch.setattr(from_runner, 'GATES', gates)
    monkeypatch.setattr(from_runner, 'INPUTS', gates / 'inputs')
    monkeypatch.setattr(from_runner, 'TASK_ROOT', gates.parent)
    monkeypatch.setattr(from_runner, 'INPUT_TOPS', ('third_party',))
    monkeypatch.setattr(from_runner, 'EXPLICIT_INPUTS', ())
    monkeypatch.setattr(from_runner, 'CLIENT', root / 'missing-client')
    paths, _ = from_runner._input_inventory()
    names = {path.relative_to(root).as_posix() for path in paths}
    assert 'third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/dv/sv/dv_utils/dv_utils.core' in names
    assert 'third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/dv/sv/dv_utils/README.md' in names
    assert 'third_party/rfuzz/upstream/ibex/rtl/declared-source.core' in names


def test_source_shape_control_evidence_joins_frozen_profile_and_request(tmp_path, monkeypatch):
    from_runner = runner_module()
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    evidence_root = tmp_path / 'attempt/native-controls'
    evidence_root.mkdir(parents=True)
    profile_name = 'configs/peripherals/zipcpu_wbdmac/component_profile.json'
    request_name = '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/base/path_compile_request.json'
    profile_path = tmp_path / profile_name
    request_path = tmp_path / request_name
    profile_path.parent.mkdir(parents=True)
    request_path.parent.mkdir(parents=True)
    profile_path.write_text(json.dumps({'source': {'revision': 'git:original'}}))
    request_path.write_text('{"request":"prepared"}\n')
    profile_sha = from_runner.digest(profile_path)
    request_sha = from_runner.digest(request_path)
    document = {
        'schema_version': 'compiled_F6_native_source_shape_refusal.v1',
        'control_id': 'f6-source-shape-refusal',
        'refusal': {'code': 'f6-source-provider-unsupported',
            'pointer': '/artifacts', 'detail': 'source mismatch'},
        'source_profile': profile_name, 'source_profile_sha256': profile_sha,
        'prepared_request_sha256': request_sha,
        'original_revision': 'git:original',
        'incompatible_revision': 'git:0000000000000000000000000000000000000000',
        'profile_endpoints_unchanged': True, 'd2_artifacts_loaded': True,
        'runtime_constructed': False, 'native_processes_started': False,
        'launches': [], 'case_ids': [], 'replay': None,
    }
    (evidence_root / 'source-shape-refusal.json').write_text(json.dumps(document))
    matrix = {'controls': [{
        'id': 'f6-source-shape-refusal', 'gate_mode': 'native-controls',
        'pytest_nodeid': 'tests/integration/test_compiled_f6_native.py::'
            'test_preconstruction_refuses_source_incompatible_dma_provider_before_runtime_construction',
        'native_evidence_path': 'source-shape-refusal.json',
        'native_source_profile_path': profile_name,
        'native_prepared_request_path': request_name,
    }], 'native_test_nodes_by_mode': json.loads(MATRIX.read_text())[
        'native_test_nodes_by_mode']}
    selected_nodes = matrix['native_test_nodes_by_mode']['native-controls']
    frozen = {profile_name: profile_sha, request_name: request_sha}
    verified = from_runner.verify_native_control_evidence(
        'native-controls', out=tmp_path / 'attempt', frozen_map=frozen, matrix=matrix,
        selected_nodes=selected_nodes)
    assert verified['control_id'] == 'f6-source-shape-refusal'
    assert verified['fixture_pins'] == {
        profile_name: profile_sha, request_name: request_sha}
    document['prepared_request_sha256'] = '0' * 64
    (evidence_root / 'source-shape-refusal.json').write_text(json.dumps(document))
    with pytest.raises(ValueError, match='native-control-evidence-source-pin'):
        from_runner.verify_native_control_evidence(
            'native-controls', out=tmp_path / 'attempt', frozen_map=frozen, matrix=matrix,
            selected_nodes=selected_nodes)


def test_native_control_evidence_schema_key_ledger_has_no_duplicates():
    from_runner = runner_module()
    keys = from_runner.NATIVE_CONTROL_EVIDENCE_KEYS
    assert len(keys) == len(set(keys))
    assert set(keys) == {
        'schema_version', 'control_id', 'refusal', 'source_profile',
        'source_profile_sha256', 'prepared_request_sha256', 'original_revision',
        'incompatible_revision', 'profile_endpoints_unchanged', 'd2_artifacts_loaded',
        'runtime_constructed', 'native_processes_started', 'launches', 'case_ids', 'replay',
    }


def test_saved_audit_is_a_separate_recorded_post_child_phase(tmp_path, monkeypatch):
    from_runner = runner_module()
    out = tmp_path / 'attempt'
    invocation = out / 'invocation'
    invocation.mkdir(parents=True)
    (out / 'run').mkdir()
    frozen = {'src/a.py': 'a' * 64}
    (invocation / 'declaration.json').write_text(json.dumps({
        'outcome': 'completed', 'output_path': 'run', 'invocation_path': 'invocation'}))
    command = {
        'command_kind': 'auto_harness_cli', 'gate_mode': 'f6-positive',
        'output_path': 'run', 'invocation_path': 'invocation', 'selected_nodes': []}
    command_path = invocation / 'command.json'
    command_path.write_text(json.dumps(command))
    (invocation / 'terminal.json').write_text(json.dumps({
        'output_path': 'run', 'invocation_path': 'invocation',
        'command_sha256': from_runner.digest(command_path)}))
    (invocation / 'output-final.json').write_text('{}')
    for name in ('source-origins-before.json', 'source-origins-after.json',
            'unavailable-symlinks-before.json', 'unavailable-symlinks-after.json'):
        (invocation / name).write_text('{}')
    monkeypatch.setattr(from_runner, 'snapshot', lambda: frozen)
    monkeypatch.setattr(from_runner, 'output_map', lambda path: {})
    monkeypatch.setattr(from_runner, 'source_origins', lambda byte_map: {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks', lambda: {})

    class FinishedProcess:
        pid = 4242
        def poll(self): return 0
        def wait(self, timeout=None): return 0

    calls = []
    def fake_popen(argv, *, cwd, env, stdout, stderr, start_new_session):
        calls.append((argv, cwd, env, start_new_session))
        stdout.write(b'{"status":"ok","outcome":"completed","scope":"full"}\n')
        return FinishedProcess()
    monkeypatch.setattr(from_runner.subprocess, 'Popen', fake_popen)
    command_doc = {'post_child_saved_audit': from_runner._saved_audit_command('f6-positive', out)}
    audit = from_runner._run_saved_audit('f6-positive', out=out,
        invocation=invocation, frozen_map=frozen, command_doc=command_doc)
    assert audit['status'] == 'ok'
    assert audit['returncode'] == 0 and audit['reaped'] is True
    assert audit['stdout_sha256'] == from_runner.digest(invocation / 'saved-audit.stdout.log')
    assert calls[0][0] == [from_runner.PYTHON, 'scripts/verify_compiled_f6.py',
        '--output', str(out / 'run'), '--invocation', str(invocation)]
    receipt = json.loads((invocation / 'saved-audit.json').read_text())
    assert receipt['result']['status'] == 'ok'
    assert receipt['source_origins_unchanged'] is True
    assert receipt['unavailable_symlinks_unchanged'] is True
    assert receipt['argv'] == calls[0][0]
    assert receipt['stdout_path'] == 'saved-audit.stdout.log'
    assert receipt['stderr_path'] == 'saved-audit.stderr.log'
    assert (invocation / receipt['stdout_path']).is_file()
    assert (invocation / receipt['stderr_path']).is_file()


@pytest.mark.parametrize('drift_kind', ['source_origins', 'unavailable_symlinks'])
def test_saved_audit_rechecks_origin_and_unavailable_maps_after_auditor(
        tmp_path, monkeypatch, drift_kind):
    from_runner = runner_module()
    out = tmp_path / 'attempt'
    invocation = out / 'invocation'
    invocation.mkdir(parents=True)
    (out / 'run').mkdir()
    frozen = {'src/a.py': 'a' * 64}
    (invocation / 'declaration.json').write_text(json.dumps({
        'outcome': 'completed', 'output_path': 'run', 'invocation_path': 'invocation'}))
    command = {'command_kind': 'auto_harness_cli', 'gate_mode': 'f6-positive',
        'output_path': 'run', 'invocation_path': 'invocation', 'selected_nodes': []}
    command_path = invocation / 'command.json'
    command_path.write_text(json.dumps(command))
    (invocation / 'terminal.json').write_text(json.dumps({
        'output_path': 'run', 'invocation_path': 'invocation',
        'command_sha256': from_runner.digest(command_path)}))
    (invocation / 'output-final.json').write_text('{}')
    for name in ('source-origins-before.json', 'source-origins-after.json',
            'unavailable-symlinks-before.json', 'unavailable-symlinks-after.json'):
        (invocation / name).write_text('{}')
    monkeypatch.setattr(from_runner, 'snapshot', lambda: frozen)
    monkeypatch.setattr(from_runner, 'output_map', lambda path: {})
    monkeypatch.setattr(from_runner, 'source_origins',
        lambda byte_map: {'changed': True} if drift_kind == 'source_origins' else {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks',
        lambda: {'changed': True} if drift_kind == 'unavailable_symlinks' else {})

    class FinishedProcess:
        pid = 4243
        def poll(self): return 0
        def wait(self, timeout=None): return 0

    def fake_popen(argv, *, cwd, env, stdout, stderr, start_new_session):
        stdout.write(b'{"status":"ok","outcome":"completed","scope":"full"}\n')
        return FinishedProcess()

    monkeypatch.setattr(from_runner.subprocess, 'Popen', fake_popen)
    command_doc = {'post_child_saved_audit': from_runner._saved_audit_command('f6-positive', out)}
    audit = from_runner._run_saved_audit('f6-positive', out=out,
        invocation=invocation, frozen_map=frozen, command_doc=command_doc)
    assert audit['status'] == 'failed'
    assert audit[drift_kind + '_unchanged'] is False


def test_expected_error_saved_audit_binds_the_exact_selected_pytest_case(tmp_path, monkeypatch):
    from_runner = runner_module()
    out = tmp_path / 'attempt'
    invocation = out / 'invocation'
    invocation.mkdir(parents=True)
    (out / 'run').mkdir()
    node = ('tests/integration/test_compiled_f6_native.py::'
        'test_controlled_read_err_persists_failed_prefix_for_supervisor_audit')
    (invocation / 'declaration.json').write_text(json.dumps({
        'outcome': 'expected_error', 'output_path': 'run', 'invocation_path': 'invocation'}))
    command = {'command_kind': 'pytest_native_case', 'gate_mode': 'f6-controlled-err-read',
        'output_path': 'run', 'invocation_path': 'invocation', 'selected_nodes': [node]}
    command['environment_overrides'] = {
        'MYFUZZ_COMPILED_F6_NATIVE_OUTPUT': from_runner._outpath(out, 'run')}
    command_path = invocation / 'command.json'
    command_path.write_text(json.dumps(command))
    terminal = {'output_path': 'run', 'invocation_path': 'invocation',
        'command_sha256': from_runner.digest(command_path), 'pytest_policy_ok': True,
        'pytest_result': {'cases': [[
            'tests.integration.test_compiled_f6_native',
            'test_controlled_read_err_persists_failed_prefix_for_supervisor_audit']]}}
    (invocation / 'terminal.json').write_text(json.dumps(terminal))
    (invocation / 'output-final.json').write_text('{}')
    for name in ('source-origins-before.json', 'source-origins-after.json',
            'unavailable-symlinks-before.json', 'unavailable-symlinks-after.json'):
        (invocation / name).write_text('{}')
    frozen = {'src/a.py': 'a' * 64}
    monkeypatch.setattr(from_runner, 'snapshot', lambda: frozen)
    monkeypatch.setattr(from_runner, 'output_map', lambda path: {})
    monkeypatch.setattr(from_runner, 'source_origins', lambda byte_map: {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks', lambda: {})

    class FinishedProcess:
        pid = 4343
        def poll(self): return 0
        def wait(self, timeout=None): return 0

    monkeypatch.setattr(from_runner, '_matrix_document', lambda: json.loads(MATRIX.read_text()))
    def fake_popen(argv, *, cwd, env, stdout, stderr, start_new_session):
        stdout.write(b'{"status":"ok","outcome":"expected_error","scope":"failed_prefix_full"}\n')
        return FinishedProcess()
    monkeypatch.setattr(from_runner.subprocess, 'Popen', fake_popen)
    command_doc = {'post_child_saved_audit': from_runner._saved_audit_command(
        'f6-controlled-err-read', out)}
    audit = from_runner._run_saved_audit('f6-controlled-err-read', out=out,
        invocation=invocation, frozen_map=frozen, command_doc=command_doc)
    assert audit['status'] == 'ok'
    assert audit['pytest_node_ids'] == [node]
    terminal['pytest_result']['cases'][0][1] = 'unrelated_test'
    (invocation / 'terminal.json').write_text(json.dumps(terminal))
    with pytest.raises(ValueError, match='saved-audit-pytest-node-binding'):
        from_runner._run_saved_audit('f6-controlled-err-read', out=out,
            invocation=invocation, frozen_map=frozen, command_doc=command_doc)


def test_gate_result_requires_saved_audit_ok():
    from_runner = runner_module()
    observed = {'status': 'observed', 'terminal': {}}
    assert from_runner._bind_saved_audit(observed, {'status': 'ok'})['status'] == 'observed'
    assert from_runner._bind_saved_audit(observed, {'status': 'failed'})['status'] == 'failed'


def test_execute_runs_saved_audit_after_primary_terminal_and_audit_failure_fails_gate(
        tmp_path, monkeypatch, capsys):
    from_runner = runner_module()
    freeze = tmp_path / 'freeze'
    freeze.mkdir()
    base = tmp_path / 'attempts'
    monkeypatch.setattr(from_runner, 'BASE', base)
    matrix = json.loads(MATRIX.read_text())
    out = base / 'f6-positive-attempt1'
    command = from_runner.command_for('f6-positive', out, matrix)
    command['attempt_path'] = from_runner._root_arg(out)
    command_doc = {'modes': [command]}
    frozen = {'src/example.py': 'a' * 64}
    monkeypatch.setattr(from_runner, '_load_and_verify_freeze',
        lambda path: (freeze, frozen, {}, {}, command_doc, {}))
    monkeypatch.setattr(from_runner, '_verify_review_bundle', lambda *args: {'result': 'PASS'})
    calls = []
    monkeypatch.setattr(from_runner, 'materialize_git_source_metadata',
        lambda frozen_map: calls.append(('materialize', frozen_map)), raising=False)
    def supervised_child(row, *, out, invocation, freeze, frozen_map):
        calls.append('primary-child')
        (invocation / 'terminal.json').write_text('{}')
        return {'status': 'observed', 'terminal': {}}
    def saved_audit(mode, *, out, invocation, frozen_map, command_doc):
        assert (invocation / 'terminal.json').is_file()
        calls.append('saved-audit')
        return {'status': 'failed', 'returncode': 1, 'reaped': True,
            'stdout_path': 'saved-audit.stdout.log'}
    monkeypatch.setattr(from_runner, '_run_one', supervised_child)
    monkeypatch.setattr(from_runner, '_run_saved_audit', saved_audit)
    result = from_runner.main(['f6-positive', '--freeze', str(freeze), '--execute'])
    assert result == 1
    assert calls == [('materialize', frozen), 'primary-child', 'saved-audit']
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'


def test_native_mode_refuses_without_explicit_freeze_review(tmp_path):
    from_runner = runner_module()
    with pytest.raises(ValueError, match='freeze-review-required'):
        from_runner.authorize_execution('f6-positive', freeze_review=None,
            freeze_bundle=tmp_path, control_matrix=json.loads(MATRIX.read_text()))


def test_default_cli_is_plan_only_and_does_not_launch_child():
    from_runner = runner_module()
    assert from_runner.DEFAULT_MODE == 'software'
    assert from_runner.REVIEW_SCHEMA == 'compiled_F6_independent_freeze_review.v1'
    assert from_runner.NATIVE_OPT_IN == 'MYFUZZ_RUN_NATIVE_F6=1'


def test_frozen_commands_use_the_archived_python_support_root():
    from_runner = runner_module()
    assert 'pythonlib' in from_runner.INPUT_TOPS
    for mode in ('software', 'native-controls', 'f6-positive', 'f2-timer'):
        command = from_runner.command_for(mode,
            ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt-pythonlib')
        assert command['environment_overrides']['PYTHONPATH'] == 'pythonlib:src:.'
    positive = from_runner.command_for('f6-positive',
        ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt-pythonlib')
    assert positive['post_child_saved_audit']['environment_overrides']['PYTHONPATH'] == 'pythonlib:src:.'


def test_frozen_inventory_scans_git_metadata_archives():
    from_runner = runner_module()
    assert 'source-git-metadata' in from_runner.INPUT_TOPS


def test_prepare_freeze_validates_and_materializes_git_metadata_before_bundle(tmp_path, monkeypatch):
    from_runner = runner_module()
    freeze = tmp_path / 'freeze'
    frozen = {'source-git-metadata/index.json': 'a' * 64}
    calls = []
    monkeypatch.setattr(from_runner, 'validate_control_matrix', lambda value: value)
    monkeypatch.setattr(from_runner, '_matrix_document', lambda: {'schema_version': 'test'})
    monkeypatch.setattr(from_runner, 'command_selection', lambda attempt, matrix: [])
    monkeypatch.setattr(from_runner, 'snapshot', lambda: dict(frozen))
    monkeypatch.setattr(from_runner, 'validate_git_source_metadata',
        lambda byte_map: calls.append(('validate', byte_map)))
    monkeypatch.setattr(from_runner, 'materialize_git_source_metadata',
        lambda byte_map: calls.append(('materialize', byte_map)))
    monkeypatch.setattr(from_runner, 'validate_command_inputs', lambda commands, byte_map: None)
    monkeypatch.setattr(from_runner, 'source_origins', lambda byte_map: {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks', lambda: {})
    monkeypatch.setattr(from_runner, 'digest', lambda path: 'b' * 64)
    monkeypatch.setattr(from_runner, 'archive_regular_inputs',
        lambda path, byte_map: Path(path).write_bytes(b'archive'))
    monkeypatch.setattr(from_runner, 'verify_regular_archive', lambda path, byte_map: None)
    monkeypatch.setattr(from_runner, 'executables', lambda: {})

    result = from_runner.archive_freeze(freeze, control_matrix={'schema_version': 'test'})

    assert result['status'] == 'prepared_pending_independent_review'
    assert calls == [('validate', frozen), ('materialize', frozen)]
    assert (freeze / 'inputs.tar.gz').read_bytes() == b'archive'


def test_prepare_freeze_refuses_existing_destination_before_materializing_git(tmp_path, monkeypatch):
    from_runner = runner_module()
    freeze = tmp_path / 'already-prepared'
    freeze.mkdir()
    calls = []
    monkeypatch.setattr(from_runner, 'validate_control_matrix', lambda value: value)
    monkeypatch.setattr(from_runner, '_matrix_document', lambda: {'schema_version': 'test'})
    monkeypatch.setattr(from_runner, 'command_selection', lambda attempt, matrix: [])
    monkeypatch.setattr(from_runner, 'snapshot', lambda: {})
    monkeypatch.setattr(from_runner, 'validate_git_source_metadata',
        lambda byte_map: calls.append('validate'))
    monkeypatch.setattr(from_runner, 'materialize_git_source_metadata',
        lambda byte_map: calls.append('materialize'))
    monkeypatch.setattr(from_runner, 'validate_command_inputs', lambda commands, byte_map: None)
    monkeypatch.setattr(from_runner, 'source_origins', lambda byte_map: {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks', lambda: {})

    with pytest.raises(ValueError, match='freeze-bundle-already-exists'):
        from_runner.archive_freeze(freeze, control_matrix={'schema_version': 'test'})

    assert calls == []


def test_frozen_software_command_includes_session_and_dma_replay_regressions():
    from_runner = runner_module()
    command = from_runner.command_for('software',
        ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt-session-runtime')
    modules = (
        'tests/scenario/test_session_runtime_paths.py',
        'tests/scenario/test_online_session_partial_replay.py',
        'tests/scenario/test_f6_instruction_fetch_receipt.py',
        'tests/local_harness/test_obi_cpu_protocol_taps.py',
        'tests/integration/test_dma_bound_online_session.py',
        'tests/integration/test_dma_intent_binding_replay.py',
    )
    assert all(module in command['selected_modules'] for module in modules)
    assert all(module in command['argv'] for module in modules)
    assert command['native_opt_in'] is False
    assert command['environment_overrides']['MYFUZZ_RUN_NATIVE_F6'] == '0'


def test_auto_harness_native_command_records_application_owned_shared_lock():
    from_runner = runner_module()
    attempt = ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt-lock'
    command = from_runner.command_for('f6-positive', attempt)
    assert command['lock_owner'] == 'myfuzz.local_harness.auto_harness_test._heavy_worker_lock'
    assert command['shared_lock'] == str(ROOT / '.superpowers/sdd/stage2-heavy-worker.lock')
    assert command['environment_overrides']['MYFUZZ_RUN_NATIVE_F6'] == '1'


def test_freeze_native_lock_policy_matches_command_lock_owners():
    from_runner = runner_module()
    assert from_runner.NATIVE_LOCK_POLICY == (
        'Supervisor owns native pytest children; declared direct auto_harness_test.py '
        'modes own the canonical lock inside their child.')


def test_saved_command_paths_are_attempt_relative_while_argv_is_literal():
    from_runner = runner_module()
    attempt = ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/test-attempt-paths'
    command = from_runner.command_for('f6-positive', attempt)
    assert command['output_path'] == 'run'
    assert command['invocation_path'] == 'invocation'
    output_index = command['argv'].index('--output')
    assert command['argv'][output_index + 1] == str(attempt.relative_to(ROOT) / 'run')


def test_refusal_declaration_uses_nested_closed_receipt(tmp_path, monkeypatch):
    from_runner = runner_module()
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    proof = tmp_path / 'guard-proof.json'
    proof.write_text('{}\n')
    control = {
        'proof_path': 'guard-proof.json',
        'proof_sha256': from_runner.digest(proof),
        'expected_refusal': {'stage': 'preflight', 'code': 'wrong_route', 'pointer': '/route'},
    }
    monkeypatch.setattr(from_runner, '_control_row', lambda matrix, control_id: control)
    command = {'expected_exit_code': 2}
    declaration = from_runner._declaration_for(
        'f6-wrong-route', command, 'a' * 64, {'controls': []},
        frozen_map={'guard-proof.json': from_runner.digest(proof)})
    assert declaration == {
        'schema_version': 'compiled_F6_saved_declaration.v1',
        'outcome': 'refusal', 'output_path': 'run', 'invocation_path': 'invocation',
        'expected_exit_code': 2, 'command_sha256': 'a' * 64,
        'refusal': {
            'stage': 'preflight', 'code': 'wrong_route', 'pointer': '/route',
            'proof_path': 'guard-proof.json', 'proof_sha256': from_runner.digest(proof),
        },
    }


def test_refusal_declaration_rejects_proof_outside_workspace_or_frozen_map(tmp_path, monkeypatch):
    from_runner = runner_module()
    root = tmp_path / 'workspace'
    root.mkdir()
    outside = tmp_path / 'outside.json'
    outside.write_text('{}\n')
    monkeypatch.setattr(from_runner, 'ROOT', root)
    controls = {
        'proof_path': '../outside.json',
        'proof_sha256': from_runner.digest(outside),
        'expected_refusal': {'stage': 'preflight', 'code': 'wrong_route', 'pointer': '/route'},
    }
    monkeypatch.setattr(from_runner, '_control_row', lambda matrix, control_id: controls)
    with pytest.raises(ValueError, match='refusal-guard-proof-path-invalid'):
        from_runner._declaration_for('f6-wrong-route', {'expected_exit_code': 1},
            'a' * 64, {'controls': []}, frozen_map={})

    proof = root / 'guard-proof.json'
    proof.write_text('{}\n')
    controls['proof_path'] = 'guard-proof.json'
    controls['proof_sha256'] = from_runner.digest(proof)
    with pytest.raises(ValueError, match='refusal-guard-proof-not-frozen'):
        from_runner._declaration_for('f6-wrong-route', {'expected_exit_code': 1},
            'a' * 64, {'controls': []}, frozen_map={})


def test_source_map_stability_and_rss_unavailable_have_closed_fields():
    from_runner = runner_module()
    source_fields = from_runner._source_stability_fields(
        {'a.py': '1'}, {'a.py': '2'}, {'a.py': {}}, {'a.py': {}}, {}, {})
    assert source_fields == {
        'source_map_unchanged': False,
        'inputs_unchanged': False,
        'source_origins_unchanged': True,
        'unavailable_symlinks_unchanged': True,
    }
    assert from_runner._rss_terminal_fields(False, None) == {
        'rss_samples_available': False, 'peak_process_group_rss_bytes': None}
    assert from_runner._rss_terminal_fields(True, 4096) == {
        'rss_samples_available': True, 'peak_process_group_rss_bytes': 4096}


def test_native_pytest_mode_requires_frozen_exact_node_ids():
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    incomplete = json.loads(json.dumps(matrix))
    incomplete['native_test_nodes_by_mode'].pop('native-controls')
    with pytest.raises(ValueError, match='control-matrix-exact-pytest-nodeids-required'):
        from_runner.command_for('native-controls', ROOT / '.superpowers/sdd/test-attempt', incomplete)
    command = from_runner.command_for('native-controls', ROOT / '.superpowers/sdd/test-attempt', matrix)
    assert command['selected_nodes'] == matrix['native_test_nodes_by_mode']['native-controls']
    assert command['environment_overrides']['MYFUZZ_RUN_NATIVE_F6'] == '1'
    assert command['environment_overrides']['MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE'] == \
        '.superpowers/sdd/test-attempt/native-controls'
    assert command['environment_overrides']['MYFUZZ_COMPILED_F6_NATIVE_CACHE'] == \
        '.superpowers/cache/compiled-f6-20261024'
    assert command['lock_owner'] == 'supervisor'
    assert from_runner._supervisor_lock_owner(command) is True
    with pytest.raises(ValueError, match='mode-lock-owner-not-registered'):
        from_runner._supervisor_lock_owner(dict(command,
            lock_owner='tests.integration.test_compiled_f6_native._worker_lock'))
    error_command = from_runner.command_for('f6-controlled-err-read',
        ROOT / '.superpowers/sdd/test-attempt', matrix)
    assert error_command['lock_owner'] == 'supervisor'
    assert from_runner._supervisor_lock_owner(error_command) is True
    assert error_command['environment_overrides']['MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE'] == \
        '.superpowers/sdd/test-attempt/native-controls'
    invalid_node = 'tests/integration/test_compiled_f6_contract.py::test_reserved_refusal'
    with pytest.raises(ValueError, match='control-matrix-native-node-path-invalid'):
        from_runner._pytest_nodes({'native_test_nodes_by_mode': {'native-controls': [invalid_node]}},
            'native-controls')


def test_native_pytest_supervisor_holds_shared_lock_and_precreates_evidence_root(tmp_path, monkeypatch):
    from_runner = runner_module()
    root = tmp_path
    monkeypatch.setattr(from_runner, 'ROOT', root)
    lock = root / 'shared.lock'
    lock.write_bytes(b'')
    monkeypatch.setattr(from_runner, 'LOCK', lock)
    freeze = root / 'freeze'
    freeze.mkdir()
    (freeze / 'manifest.json').write_text('{}\n')
    out = root / 'attempt'
    out.mkdir()
    invocation = out / 'invocation'
    invocation.mkdir()
    monkeypatch.setattr(from_runner, 'snapshot', lambda: {})
    monkeypatch.setattr(from_runner, 'source_origins', lambda byte_map: {})
    monkeypatch.setattr(from_runner, 'unavailable_symlinks', lambda: {})
    monkeypatch.setattr(from_runner, 'archive_regular_inputs',
        lambda path, byte_map: Path(path).write_bytes(b'archive'))
    monkeypatch.setattr(from_runner, 'verify_regular_archive', lambda *args: None)
    monkeypatch.setattr(from_runner, 'executables', lambda: {})
    monkeypatch.setattr(from_runner, 'verify_pytest_result',
        lambda *args, **kwargs: {'cases': [], 'skips': [], 'failures': 0, 'errors': 0})
    monkeypatch.setattr(from_runner, '_matrix_document', lambda: {'controls': []})
    monkeypatch.setattr(from_runner, 'verify_native_control_evidence',
        lambda *args, **kwargs: {'control_id': 'f6-source-shape-refusal'})
    monkeypatch.setattr(from_runner, '_wait_child', lambda proc, timeout: dict(
        returncode=0, reaped=True, timed_out=False,
        **from_runner._rss_terminal_fields(False, None), elapsed_seconds=0.0))
    selected_node = 'tests/integration/test_compiled_f6_native.py::test_preflight'
    command = dict(argv=[from_runner.PYTHON, '-m', 'pytest'],
        environment_overrides={
            'PYTHONPATH': 'pythonlib:src:.', 'MYFUZZ_RUN_NATIVE_F6': '1',
            'MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE': 'attempt/native-controls'},
        expected_exit_code=0, timeout_seconds=10, child_kind='pytest_gate',
        command_kind='pytest_gate', selected_nodes=[selected_node], selected_modules=[],
        lock_owner='supervisor', shared_lock=str(lock), native_opt_in=True,
        gate_mode='native-controls', output_path=None, invocation_path=None)

    class FinishedProcess:
        pid = 5252
        def poll(self): return 0
        def wait(self, timeout=None): return 0

    observations = {}
    def fake_popen(argv, *, cwd, env, stdout, stderr, start_new_session):
        evidence = root / env['MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE']
        observations['evidence_root_exists'] = evidence.is_dir()
        with lock.open('a+b') as stream:
            try:
                from_runner.fcntl.flock(stream.fileno(), from_runner.fcntl.LOCK_EX | from_runner.fcntl.LOCK_NB)
            except BlockingIOError:
                observations['lock_contended'] = True
            else:
                from_runner.fcntl.flock(stream.fileno(), from_runner.fcntl.LOCK_UN)
                observations['lock_contended'] = False
        (out / 'pytest-results.xml').write_text('<testsuite/>')
        return FinishedProcess()

    monkeypatch.setattr(from_runner.subprocess, 'Popen', fake_popen)
    result = from_runner._run_one(command, out=out, invocation=invocation,
        freeze=freeze, frozen_map={})
    assert result['status'] == 'observed'
    assert observations == {'evidence_root_exists': True, 'lock_contended': True}


def test_output_map_refuses_symlinks(tmp_path):
    from_runner = runner_module()
    out = tmp_path / 'attempt'
    out.mkdir()
    target = tmp_path / 'outside.txt'
    target.write_text('outside')
    (out / 'alias.txt').symlink_to(target)
    with pytest.raises(ValueError, match='output-map-symlink'):
        from_runner.output_map(out)


def test_output_map_excludes_only_the_top_level_supervisor_invocation(tmp_path):
    from_runner = runner_module()
    out = tmp_path / 'attempt'
    supervisor = out / 'invocation'
    child = out / 'run/invocation'
    supervisor.mkdir(parents=True)
    child.mkdir(parents=True)
    (supervisor / 'terminal.json').write_text('{"owner":"supervisor"}\n')
    child_output = child / 'child.json'
    child_output.write_text('{"owner":"child"}\n')

    mapped = from_runner.output_map(out)

    assert 'invocation/terminal.json' not in mapped
    assert mapped == {'run/invocation/child.json': from_runner.digest(child_output)}


def test_software_pytest_accepts_only_all_exact_native_optin_skips(tmp_path):
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    assert len(matrix['native_test_nodeids']) == 11
    command = dict(gate_mode='software', selected_modules=[
        'tests/integration/test_compiled_f6_contract.py',
        'tests/integration/test_compiled_f6_native.py'])
    result = tmp_path / 'pytest.xml'
    def skip_xml(reason):
        rows = ['<testcase classname="tests.integration.test_compiled_f6_contract" name="test_contract"/>']
        for node in matrix['native_test_nodeids']:
            classname, name = from_runner._node_to_junit(node)
            rows.append(f'<testcase classname="{classname}" name="{name}"><skipped message="{reason}"/></testcase>')
        return f'<testsuite tests="12" skipped="11">{"".join(rows)}</testsuite>'
    result.write_text(skip_xml('requires MYFUZZ_RUN_NATIVE_F6=1 opt-in'))
    assert from_runner.verify_pytest_result(result, command_doc=command, matrix=matrix)['testcase_count'] == 12
    result.write_text(skip_xml('unrelated skip'))
    with pytest.raises(ValueError, match='pytest-native-skip-reason-mismatch'):
        from_runner.verify_pytest_result(result, command_doc=command, matrix=matrix)


def test_software_pytest_accepts_test_class_names_under_selected_modules(tmp_path):
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    module = 'tests/integration/test_scenario_rfuzz_terminal_identity.py'
    native_module = 'tests/integration/test_compiled_f6_native.py'
    command = dict(gate_mode='software', selected_modules=[module, native_module])
    result = tmp_path / 'pytest.xml'

    def write_xml(extra=''):
        rows = [
            '<testcase classname="tests.integration.test_scenario_rfuzz_terminal_identity.TerminalIdentityTests" name="test_identity"/>',
            '<testcase classname="tests.integration.test_compiled_f6_native" name="test_software_case"/>',
        ]
        for node in matrix['native_test_nodeids']:
            classname, name = from_runner._node_to_junit(node)
            rows.append(f'<testcase classname="{classname}" name="{name}"><skipped message="requires MYFUZZ_RUN_NATIVE_F6=1 opt-in"/></testcase>')
        rows.extend(extra)
        result.write_text(f'<testsuite tests="{len(rows)}" skipped="11">{"".join(rows)}</testsuite>')

    write_xml()
    assert from_runner.verify_pytest_result(
        result, command_doc=command, matrix=matrix)['testcase_count'] == 13

    write_xml(['<testcase classname="tests.integration.unselected_module" name="test_extra"/>'])
    with pytest.raises(ValueError, match='pytest-selected-module-set-mismatch'):
        from_runner.verify_pytest_result(result, command_doc=command, matrix=matrix)


def test_software_pytest_rejects_missing_or_unrelated_native_skip(tmp_path):
    from_runner = runner_module()
    matrix = json.loads(MATRIX.read_text())
    command = dict(gate_mode='software', selected_modules=[
        'tests/integration/test_compiled_f6_native.py'])
    xml = tmp_path / 'pytest.xml'
    xml.write_text('<testsuite tests="1" skipped="0"><testcase '
        'classname="tests.integration.test_compiled_f6_native" name="test_other"/></testsuite>')
    with pytest.raises(ValueError, match='pytest-native-skip-set-mismatch'):
        from_runner.verify_pytest_result(xml, command_doc=command, matrix=matrix)


def test_freeze_command_inputs_must_exist_and_appear_in_source_map(tmp_path, monkeypatch):
    from_runner = runner_module()
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    source = tmp_path / 'configs' / 'compose.json'
    source.parent.mkdir()
    source.write_text('{}')
    frozen = {'configs/compose.json': from_runner.digest(source)}
    command = {'gate_mode': 'software', 'argv': [
        'python3', 'scripts/auto_harness_test.py', '--compose', 'configs/compose.json']}
    assert from_runner.validate_command_inputs([command], frozen) == ('configs/compose.json',)
    command['argv'][-1] = 'configs/missing.json'
    with pytest.raises(ValueError, match='command-input-missing'):
        from_runner.validate_command_inputs([command], frozen)
    command['argv'][-1] = 'configs/compose.json'
    with pytest.raises(ValueError, match='command-input-not-frozen'):
        from_runner.validate_command_inputs([command], {})


def test_saved_auditor_argv_and_script_are_part_of_frozen_selection(tmp_path, monkeypatch):
    from_runner = runner_module()
    monkeypatch.setattr(from_runner, 'ROOT', tmp_path)
    script = tmp_path / 'scripts/verify_compiled_f6.py'
    script.parent.mkdir()
    script.write_text('# frozen test auditor\n')
    attempt = tmp_path / 'docs/reports/evidence/f6-attempt1'
    command = {
        'gate_mode': 'f6-positive', 'attempt_path': str(attempt),
        'argv': [from_runner.PYTHON], 'selected_nodes': [], 'selected_modules': [],
        'post_child_saved_audit': from_runner._saved_audit_command('f6-positive', attempt),
    }
    byte_map = {'scripts/verify_compiled_f6.py': from_runner.digest(script)}
    assert from_runner.validate_command_inputs([command], byte_map) == (
        'scripts/verify_compiled_f6.py',)
    command['post_child_saved_audit']['argv'][3] = 'other/run'
    with pytest.raises(ValueError, match='saved-audit-command-binding'):
        from_runner.validate_command_inputs([command], byte_map)
