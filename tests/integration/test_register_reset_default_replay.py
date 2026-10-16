"""Task5 trusted reset-default assembly/file selector channel: closed software TDD.

Software scope only: no RTL, no Verilator, no native build, no native execution
and no synthetic native eligibility exist in this module.  Installed Task2
evidence pins the actual ``ScenarioRunner`` method table, so the accepted
software ``begin_test``/``step_batch`` overrides cannot be installed and a begun
reset-default session is outside this software boundary; the joined
reset/readback positive is the Task5 supervised native gate.

The closed reset-default document produced here is a genuine refusal document
(no certificates, no grants).  It is comparison data only: no saved dictionary,
token or wrapper in this module installs authority.
"""
import importlib.util
import hashlib
import io
import json
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
from myfuzz.scenario.session_runtime import ScenarioSession, _online_manifest
from tests.integration.test_register_reset_resume_replay import (
    captured_register_model, resume_shape)  # noqa: F401 (reused closed-model seams)
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory  # noqa: F401 (fixture)
from tests.scenario.test_native_reset_evidence import configured_runner

RESET_DEFAULT = {'max_records': 8, 'max_commands': 128}
ADVANCE_ROUNDS = 1
MAX_RECORDS = 4

DEFAULT_KEYS = ['advance_rounds', 'checker', 'cpu_component', 'cpu_retirement',
                'gpio_consumption', 'max_program_bytes', 'max_records',
                'memory_commit_receipts', 'native_irq_receipts',
                'native_physical_observations', 'persistent_memory_prerequisites',
                'runtime_contract_sha256', 'schema_version', 'selector',
                'sidecar_selector', 'source_actions']

#: Frozen default-off coverage closure (measured 38 rows before this channel).
BASE_CLOSURE = (
    'src/myfuzz/integration/ibex_pulp_register_replay.py',
    'scripts/run_ibex_pulp_online.py',
    'configs/peripherals/pulp_gpio/test_capability.json',
    'src/myfuzz/scenario/register_program_runtime.py',
    'src/myfuzz/scenario/register_program.py', 'src/myfuzz/scenario/rv32i_sources.py',
    'src/myfuzz/composition/test_capability.py', 'src/myfuzz/scenario/session_runtime.py',
    'src/myfuzz/scenario/ibex_pulp_dual_source.py',
    'src/myfuzz/integration/scenario_rfuzz_live.py',
    'src/myfuzz/integration/scenario_rfuzz_replay.py',
    'src/myfuzz/integration/ibex_pulp_online.py',
    'src/myfuzz/scenario/event_journal.py',
    'src/myfuzz/scenario/replay.py', 'src/myfuzz/scenario/genome.py',
    'src/myfuzz/scenario/source_actions.py',
    'src/myfuzz/scenario/live_memory_prerequisites.py',
    'src/myfuzz/scenario/dependency_lifecycle.py',
    'src/myfuzz/scenario/memory_dependency_evidence.py',
    'src/myfuzz/scenario/memory_commit_authority.py',
    'src/myfuzz/scenario/memory_read_authority.py',
    'src/myfuzz/scenario/memory_authority_distribution.py',
    'src/myfuzz/scenario/memory_service.py', 'src/myfuzz/scenario/memory.py',
    'src/myfuzz/scenario/router.py', 'src/myfuzz/scenario/ledger.py',
    'src/myfuzz/scenario/runner.py',
    'src/myfuzz/scenario/ip_base_events.py',
    'src/myfuzz/scenario/ip_protocol_events.py',
    'src/myfuzz/scenario/ip_protocol_checker.py',
    'src/myfuzz/local_harness/runtime_renderer.py',
    'src/myfuzz/local_harness/driver_renderer.py',
    'src/myfuzz/local_harness/native_physical_observation.py',
    'src/myfuzz/local_harness/cpu_session.py', 'src/myfuzz/local_harness/gpio_session.py',
    'src/myfuzz/composition/component_profile.py',
    'configs/cpus/ibex_obi_local/component_profile.json',
    'configs/peripherals/pulp_gpio/component_profile.json')

#: Every module the enabled channel must pin; the last one is already pinned.
RESET_DEFAULT_MODULES = ('src/myfuzz/scenario/register_reset_default_verifier.py',
                         'src/myfuzz/scenario/native_reset_evidence.py',
                         'src/myfuzz/local_harness/native_reset_observation.py',
                         'src/myfuzz/scenario/register_program_runtime.py')
NEW_RESET_DEFAULT_MODULES = RESET_DEFAULT_MODULES[:3]


def make_enabled_assembly(**overrides):
    arguments = dict(advance_rounds=ADVANCE_ROUNDS, max_records=MAX_RECORDS,
                     ordinary_apb_access_evidence={'max_records': 4},
                     register_reset_default=dict(RESET_DEFAULT))
    arguments.update(overrides)
    return api.make_register_assembly(**arguments)


def channel_session(native_factory, tmp_path):
    """Actual Task1 producers and a real scenario session; nothing is begun."""
    runner = configured_runner(native_factory, tmp_path, lifecycles=8, commands=128)
    session = ScenarioSession(ScenarioGenome('directed', 'CPU_TO_IP', 'register_program',
                                             ('cpu', 'gpio_a', 'gpio_b'), 144, ()), runner)
    session.runner._test_session = session
    session.declare_instruction_slots('cpu', 0x11000, 32)
    return session


@pytest.fixture(scope='module')
def installed(native_factory, tmp_path_factory):
    """Full closed channel installed through the production installer.

    Read-only for every consumer: the drift and mutation cases below own
    separate sessions so this one can never be poisoned by a negative test.
    """
    session = channel_session(native_factory, tmp_path_factory.mktemp('channel-installed'))
    assembly = make_enabled_assembly(register_program_verifier={'max_records': 4})
    adapter = api.make_register_runtime_factory(assembly)(session)
    return SimpleNamespace(session=session, assembly=assembly, adapter=adapter)


@pytest.fixture
def mutable_installed(native_factory, tmp_path):
    session = channel_session(native_factory, tmp_path)
    assembly = make_enabled_assembly(register_program_verifier={'max_records': 4})
    adapter = api.make_register_runtime_factory(assembly)(session)
    return SimpleNamespace(session=session, assembly=assembly, adapter=adapter)


def channel_verifier_arguments(installed):
    """Real runtime configuration, closed document and manifest, never saved bytes."""
    session = installed.session
    configuration = session._register_configuration()
    document = {'register_programs': {
        'configuration': configuration,
        'register_reset_default': session.register_reset_default_document()}}
    manifest = _online_manifest(session.runner, None,
        register_program_configuration=configuration,
        register_reset_default_configuration=session._register_reset_default_configuration(),
        register_reset_default_source_files=json.loads(session._register_reset_default_sources_json))
    return document, manifest


def cli_module():
    spec = importlib.util.spec_from_file_location('register_reset_default_cli',
                                                  Path('scripts/run_ibex_pulp_online.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cli_result(*, matches=True, reset_default=None):
    return SimpleNamespace(matches=matches, verification_scope=('register_program_reconstruction',),
                           comparison=SimpleNamespace(first_difference=None, difference_context={},
                                                      actual_trace=SimpleNamespace(events=({},),
                                                                                   semantic_sha256='a' * 64)),
                           register_reset_default=reset_default)


# ---------------------------------------------------------------------------
# Closed assembly field and default-off byte layout
# ---------------------------------------------------------------------------

def test_default_off_assembly_and_closure_layout_is_byte_frozen():
    default = api.make_register_assembly()
    assert sorted(default) == DEFAULT_KEYS
    expected = dict(schema_version='register_program_assembly.v1', selector='ibex_pulp_ordinary_gpio',
        sidecar_selector='pulp_gpio_declared', checker=None, cpu_component='cpu', source_actions=True,
        native_physical_observations=True, memory_commit_receipts=True,
        persistent_memory_prerequisites=True, gpio_consumption=False, cpu_retirement=False,
        native_irq_receipts=False, advance_rounds=48, max_program_bytes=64, max_records=4096,
        runtime_contract_sha256=api._contract())
    assert api._json(default) == api._json(expected)
    rows = api._sources(default)
    assert [row['path'] for row in rows] == list(BASE_CLOSURE)
    assert len(rows) == 38
    assert not set(RESET_DEFAULT_MODULES[:3]) & set(BASE_CLOSURE)


def test_optional_reset_default_assembly_field_is_closed():
    assembly = make_enabled_assembly()
    assert assembly['register_reset_default'] == RESET_DEFAULT
    assert sorted(api.make_register_assembly()) == DEFAULT_KEYS
    assert 'register_reset_default' not in api.make_register_assembly()


def test_enabled_closure_unions_the_reset_default_channel_and_keeps_default_38():
    from myfuzz.scenario.session_runtime import _register_reset_default_source_files
    default_paths = [row['path'] for row in api._sources(api.make_register_assembly())]
    assert default_paths == list(BASE_CLOSURE)
    closure = {row['path'] for row in _register_reset_default_source_files()}
    enabled = api._sources(make_enabled_assembly())
    assert [row['path'] for row in enabled] == sorted(set(BASE_CLOSURE) | closure)
    assert len(enabled) > 38 and set(RESET_DEFAULT_MODULES) <= set(closure)
    for row in enabled:
        assert row['sha256'] == hashlib.sha256((api._ROOT / row['path']).read_bytes()).hexdigest()


@pytest.mark.parametrize('configuration', [
    {'max_records': True, 'max_commands': 128},
    {'max_records': 8, 'max_commands': True},
    {'max_records': 8.0, 'max_commands': 128},
    {'max_records': 8, 'max_commands': 1.0},
    {'max_records': 0, 'max_commands': 128},
    {'max_records': 65537, 'max_commands': 128},
    {'max_records': 8, 'max_commands': 0},
    {'max_records': 8, 'max_commands': 65537},
    {'max_records': 8},
    {'max_records': 8, 'max_commands': 128, 'nonce': '0' * 32},
    {'max_records': 8, 'max_commands': 128, 'pid': 4711},
    'not-a-mapping',
    ['max_records', 'max_commands'],
])
def test_reset_default_assembly_value_is_closed_and_typed(configuration):
    with pytest.raises(ValueError):
        api.make_register_assembly(advance_rounds=ADVANCE_ROUNDS, max_records=MAX_RECORDS,
            ordinary_apb_access_evidence={'max_records': 4}, register_reset_default=configuration)


def test_reset_default_assembly_requires_ordinary_evidence():
    with pytest.raises(ValueError, match='reset default requires ordinary APB evidence'):
        api.make_register_assembly(register_reset_default=dict(RESET_DEFAULT))
    default = api.make_register_assembly()
    with pytest.raises(ValueError, match='complete closed fields'):
        api.validate_register_assembly(dict(default, nonce='0' * 32))
    with pytest.raises(ValueError, match='complete closed fields'):
        api.validate_register_assembly({name: value for name, value in default.items()
                                        if name != 'advance_rounds'})


# ---------------------------------------------------------------------------
# Production installer order (Root correction of the plan prose)
# ---------------------------------------------------------------------------

def test_installer_builds_reset_default_channel_in_corrected_order(installed):
    session, adapter = installed.session, installed.adapter
    verifier = session._register_reset_default_verifier
    assert verifier is not None and verifier.runtime is adapter
    assert session.runner._register_reset_default_verifier is verifier
    assert session.runner._register_program_verifier is not None
    assert set(session.runner._memory_commit_authority._consumers) == {
        'default', 'dependency_evidence', 'register_reset_default_verifier',
        'register_program_verifier'}
    evidence = session.runner._native_reset_evidence
    assert (evidence.configuration()['max_records'],
            evidence.configuration()['max_commands']) == (8, 128)
    for name in ('gpio_a', 'gpio_b'):
        observer = session.runner.sessions[name]._native_reset_observation
        assert observer.configuration()['max_commands'] == 128
    document = session.register_reset_default_document()
    assert set(document) == {'schema_version', 'configuration', 'state'}
    assert document['schema_version'] == 'register_reset_default_session.v1'
    assert document['state']['current_certificates'] == []
    assert document['state']['historical_certificates'] == []
    assert document['configuration']['max_records'] == 8


def test_installer_configures_task1_observers_when_absent(native_factory, tmp_path):
    runner = native_factory()
    session = ScenarioSession(ScenarioGenome('directed', 'CPU_TO_IP', 'register_program',
                                             ('cpu', 'gpio_a', 'gpio_b'), 144, ()), runner)
    session.runner._test_session = session
    session.declare_instruction_slots('cpu', 0x11000, 32)
    for name in ('gpio_a', 'gpio_b'):
        worker = tmp_path / f'{name}-worker.py'
        digest, asserted, released, _ = runner.sessions[name]._expected_ready()
        worker.write_text('#!/usr/bin/env python3\nimport sys\nprint('
            + repr(f'READY local_driver.v1 {digest} {asserted:x} {released:x}')
            + ',flush=True)\nfor line in sys.stdin:\n if line.strip()=="END":break\n')
        worker.chmod(0o700)
        runner.sessions[name]._binary = worker
    api.make_register_runtime_factory(
        make_enabled_assembly(register_program_verifier={'max_records': 4}))(session)
    for name in ('gpio_a', 'gpio_b'):
        configuration = runner.sessions[name]._native_reset_observation.configuration()
        assert configuration['max_commands'] == 128
        assert configuration['max_lifecycles'] == 256


def test_plan_prose_order_is_refused_and_leaves_no_half_consumer(native_factory, tmp_path):
    """The plan's line-227 prose order cannot satisfy the frozen Task3 constructor."""
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    session = channel_session(native_factory, tmp_path)
    assembly = make_enabled_assembly(register_program_verifier={'max_records': 4})
    declared = api.validate_register_assembly(assembly)
    session.configure_ordinary_apb_access_evidence(**declared['ordinary_apb_access_evidence'])
    adapter = RegisterProgramRuntime(session, cpu_component='cpu',
        sidecars={'gpio_a': api._ROOT / api.SIDECAR, 'gpio_b': api._ROOT / api.SIDECAR},
        **{name: declared[name] for name in api._LIMITS})
    session.runner.install_native_reset_evidence(
        max_records=declared['register_reset_default']['max_records'],
        max_commands=declared['register_reset_default']['max_commands'])
    before = set(session.runner._memory_commit_authority._consumers)
    # Plan line 227 order: the optional RegisterProgramVerifier first.
    session.configure_register_program_verifier(max_records=4)
    with pytest.raises(ValueError,
                       match='reset-default-same-unused-authority-before-register-verifier-required'):
        RegisterResetDefaultVerifier(adapter, max_records=8)
    with pytest.raises(ValueError,
                       match='reset-default-same-unused-authority-before-register-verifier-required'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    after = set(session.runner._memory_commit_authority._consumers)
    assert after == before | {'register_program_verifier'}
    assert 'register_reset_default_verifier' not in after
    assert session.runner._register_reset_default_verifier is None
    assert session._register_reset_default_verifier is None


def test_default_off_installer_installs_no_reset_default_producer(native_factory, tmp_path):
    runner = native_factory()
    session = ScenarioSession(ScenarioGenome('directed', 'CPU_TO_IP', 'register_program',
                                             ('cpu', 'gpio_a', 'gpio_b'), 144, ()), runner)
    session.runner._test_session = session
    session.declare_instruction_slots('cpu', 0x11000, 32)
    before = set(runner._memory_commit_authority._consumers)
    api.make_register_runtime_factory(api.make_register_assembly(advance_rounds=1))(session)
    assert runner._native_reset_evidence is None
    assert runner._register_reset_default_verifier is None
    assert session._register_reset_default_verifier is None
    assert not any(target.native_reset_observation_enabled
                   for target in runner.sessions.values())
    assert set(runner._memory_commit_authority._consumers) == before
    assert session.register_reset_default_document() is None


# ---------------------------------------------------------------------------
# Selector channel verification: declaration, capacity, source and drift
# ---------------------------------------------------------------------------

def test_channel_verifier_accepts_the_real_closed_channel(installed):
    document, manifest = channel_verifier_arguments(installed)
    assert api._verify_register_reset_default_channel(
        installed.assembly, document, manifest) is None


@pytest.mark.parametrize('variant', ['plan_presence', 'manifest_configuration', 'manifest_sources',
                                     'installed_max_records', 'installed_max_commands',
                                     'declared_max_records', 'declared_max_commands',
                                     'channel_max_records'])
def test_channel_verifier_refuses_declaration_capacity_and_source_mismatch(installed, variant,
                                                                          monkeypatch):
    document, manifest = channel_verifier_arguments(installed)
    assembly = installed.assembly
    if variant == 'plan_presence':
        del document['register_programs']['register_reset_default']
    elif variant == 'manifest_configuration':
        manifest['register_reset_default_configuration']['max_records'] = 9
    elif variant == 'manifest_sources':
        manifest['register_reset_default_source_files'] = []
    elif variant == 'installed_max_records':
        manifest['runner']['native_reset_evidence']['max_records'] = 9
    elif variant == 'installed_max_commands':
        manifest['runner']['native_reset_evidence']['max_commands'] = 129
    elif variant == 'declared_max_records':
        assembly = make_enabled_assembly(register_program_verifier={'max_records': 4},
                                         register_reset_default={'max_records': 9,
                                                                 'max_commands': 128})
    elif variant == 'declared_max_commands':
        assembly = make_enabled_assembly(register_program_verifier={'max_records': 4},
                                         register_reset_default={'max_records': 8,
                                                                 'max_commands': 64})
    else:
        document['register_programs']['register_reset_default']['configuration']['max_records'] = 9
    with pytest.raises(ValueError):
        api._verify_register_reset_default_channel(assembly, document, manifest)


def test_channel_verifier_refuses_a_channel_that_the_assembly_did_not_declare(installed):
    document, manifest = channel_verifier_arguments(installed)
    default_assembly = make_enabled_assembly(register_program_verifier={'max_records': 4})
    del default_assembly['register_reset_default']
    with pytest.raises(ValueError, match='presence mismatch'):
        api._verify_register_reset_default_channel(
            api.validate_register_assembly(default_assembly), document, manifest)


def test_channel_verifier_refuses_late_source_closure_drift(installed, monkeypatch):
    from myfuzz.scenario import session_runtime
    document, manifest = channel_verifier_arguments(installed)
    rows = session_runtime._register_reset_default_source_files()
    assert manifest['register_reset_default_source_files'] == rows
    drifted = [dict(row) for row in rows]
    drifted[0] = dict(drifted[0], sha256='0' * 64)
    monkeypatch.setattr(session_runtime, '_register_reset_default_source_files', lambda paths=None: drifted)
    with pytest.raises(ValueError, match='configuration or source mismatch'):
        api._verify_register_reset_default_channel(installed.assembly, document, manifest)
    monkeypatch.setattr(session_runtime, '_register_reset_default_source_files',
                        lambda paths=None: rows + [dict(path='src/myfuzz/scenario/memory.py',
                                                        sha256='1' * 64)])
    with pytest.raises(ValueError, match='configuration or source mismatch'):
        api._verify_register_reset_default_channel(installed.assembly, document, manifest)


def test_closed_channel_document_refuses_nonce_bool_hole_and_swapped_rule(installed):
    from myfuzz.scenario.register_reset_default_verifier import (
        validate_register_reset_default_session_document)
    configuration = installed.session._register_configuration()
    original = installed.session.register_reset_default_document()
    assert validate_register_reset_default_session_document(
        deepcopy(original), configuration=configuration) == original

    def rehashed(document):
        """A forger who keeps the closed wrapper internally consistent."""
        document['state']['configuration'] = deepcopy(document['configuration'])
        return document

    mutations = {}
    mutations['wrapper_nonce'] = rehashed(dict(deepcopy(original), nonce='0' * 32))
    mutations['state_pid'] = rehashed(dict(deepcopy(original),
        state=dict(deepcopy(original['state']), pid=4711)))
    mutations['bool_max_records'] = rehashed(dict(deepcopy(original),
        configuration=dict(deepcopy(original['configuration']), max_records=True)))
    mutations['unknown_gap_reason'] = rehashed(dict(deepcopy(original), state=dict(
        deepcopy(original['state']),
        gaps=[dict(original['state']['gaps'][0], reason='looks-fine')])))
    mutations['dropped_gap_target'] = rehashed(dict(deepcopy(original), state=dict(
        deepcopy(original['state']), gaps=original['state']['gaps'][1:])))
    swapped = deepcopy(original)
    rules = swapped['configuration']['rules']
    rules['gpio_a'], rules['gpio_b'] = deepcopy(rules['gpio_b']), deepcopy(rules['gpio_a'])
    mutations['swapped_target_rule'] = rehashed(swapped)

    for name, document in mutations.items():
        with pytest.raises(ValueError):
            validate_register_reset_default_session_document(
                deepcopy(document), configuration=configuration)
        with pytest.raises(ValueError):
            api._verify_register_reset_default_channel(installed.assembly,
                {'register_programs': {'configuration': configuration,
                                       'register_reset_default': deepcopy(document)}},
                channel_verifier_arguments(installed)[1])
    assert len(original['state']['gaps']) == 2


def test_channel_document_refuses_late_target_binary_drift(mutable_installed):
    session = mutable_installed.session
    assert session.register_reset_default_document() is not None
    binary = session.runner.sessions['gpio_a']._binary
    binary.write_bytes(binary.read_bytes() + b'\n# late binary drift\n')
    with pytest.raises(ValueError, match='binary drift'):
        session.register_reset_default_document()


def test_saved_reset_cursor_holes_are_refused_by_the_closed_plan_validator(captured_register_model):
    """Reused closed-model seam: the saved reset cursor may not decrease or vanish."""
    plan, state, assembly, manifest = resume_shape(captured_register_model)
    plan['reset_operations'].append(dict(plan['reset_operations'][0], after_cases=0))
    with pytest.raises(ValueError):
        api._validate_saved_register_documents(plan, state)
    plan, state, assembly, manifest = resume_shape(captured_register_model)
    plan['reset_operations'].append(dict(plan['reset_operations'][0], after_cases=-1))
    with pytest.raises(ValueError):
        api._validate_saved_register_documents(plan, state)


# ---------------------------------------------------------------------------
# CLI: the authenticated bundle stays the only declaration
# ---------------------------------------------------------------------------

def test_cli_returns_reset_default_state_and_preserves_the_default_off_layout(installed):
    module = cli_module()
    state = {'schema_version': 'register_reset_default_state.v1', 'current_certificates': []}
    with patch.object(module, 'replay_ibex_pulp_register_files', return_value=cli_result()):
        output = io.StringIO()
        with redirect_stdout(output):
            assert module.main(['replay-register-programs', '--cache-dir', 'c',
                                '--run-dir', 'r']) == 0
        assert 'register_reset_default' not in json.loads(output.getvalue())
    with patch.object(module, 'replay_ibex_pulp_register_files',
                      return_value=cli_result(reset_default=state)):
        output = io.StringIO()
        with redirect_stdout(output):
            assert module.main(['replay-register-programs', '--cache-dir', 'c',
                                '--run-dir', 'r']) == 0
        assert json.loads(output.getvalue())['register_reset_default'] == state
    with patch.object(module, 'replay_ibex_pulp_register_files',
                      return_value=cli_result(matches=False, reset_default=state)):
        output = io.StringIO()
        with redirect_stdout(output):
            assert module.main(['replay-register-programs', '--cache-dir', 'c',
                                '--run-dir', 'r']) == 2


def test_cli_require_flag_is_a_fail_closed_demand():
    module = cli_module()
    state = {'schema_version': 'register_reset_default_state.v1'}
    with patch.object(module, 'replay_ibex_pulp_register_files',
                      return_value=cli_result(reset_default=state)):
        output = io.StringIO()
        with redirect_stdout(output):
            assert module.main(['replay-register-programs', '--cache-dir', 'c', '--run-dir', 'r',
                                '--require-register-reset-default']) == 0
        assert json.loads(output.getvalue())['register_reset_default'] == state
    with patch.object(module, 'replay_ibex_pulp_register_files', return_value=cli_result()):
        output = io.StringIO()
        with redirect_stdout(output):
            assert module.main(['replay-register-programs', '--cache-dir', 'c', '--run-dir', 'r',
                                '--require-register-reset-default']) == 1
        assert output.getvalue() == ''
