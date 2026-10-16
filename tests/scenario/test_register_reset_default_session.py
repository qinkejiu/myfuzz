"""Task4 Session opt-in reset-default wrapper: software mechanics and refusal.

No native build, no RTL execution and no synthetic native eligibility exists in
this module.  Producers are the genuine Task1/Task2/Task3 actual objects; the
accepted software lifecycle factory supplies CPU bootstrap sequencing for the
default-off layout controls only.

Boundary: with Task2 evidence installed the actual ``ScenarioRunner`` method
table is pinned, so the accepted software ``begin_test``/``step_batch``
overrides cannot be installed, and the real ``begin_test`` compiles the RTL via
``prepare_local``.  A begun reset-default session is therefore outside this
software scope; the joined reset/resume positive is the Task5 native gate.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
from myfuzz.scenario.session_runtime import (ScenarioSession, _online_manifest,
                                             replay_online_session)
from tests.composition.test_pulp_gpio_test_capability import SIDECAR
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.scenario.test_native_reset_evidence import configured_runner
from tests.scenario.test_register_program_replay import (actual_factory, adapter,
                                                      recorded)
from tests.scenario.test_register_program_runtime import request

ROOT = Path(__file__).resolve().parents[2]
SIDECARS = {'gpio_a': ROOT / SIDECAR, 'gpio_b': ROOT / SIDECAR}


class ActualResetSession:
    """Actual Task1/Task2/Task3 producers plus per-run isolated workers."""

    def __init__(self, *, native_factory, tmp_path):
        self.native_factory = native_factory
        self.tmp_path = tmp_path
        self._runner_count = 0
        # The plan sketch names these two attributes directly.
        self.runner_factory = self._runner_factory
        self.trusted_installer = self.install

    def _runner_factory(self):
        self._runner_count += 1
        directory = self.tmp_path / f'runner-{self._runner_count}'
        directory.mkdir()
        return configured_runner(self.native_factory, directory,
                                 lifecycles=8, commands=128)

    def session(self, *, install=True, reset_default=True, max_records=8,
                max_commands=128, ordinary=False):
        session = ScenarioSession(ScenarioGenome(
            'directed', 'CPU_TO_IP', 'register_program',
            ('cpu', 'gpio_a', 'gpio_b'), 144, ()), self.runner_factory())
        session.declare_instruction_slots('cpu', 0x11000, 32)
        if ordinary:
            session.configure_ordinary_apb_access_evidence(max_records=4)
        if install:
            self.install(session, reset_default=reset_default,
                         max_records=max_records, max_commands=max_commands)
        return session

    def evidence_only(self, session):
        # ``configured_runner`` already installed the actual Task1 observers.
        return session.runner.install_native_reset_evidence(
            max_records=8, max_commands=128)

    def runtime(self, session):
        return RegisterProgramRuntime(
            session, cpu_component='cpu', sidecars=dict(SIDECARS), advance_rounds=1)

    def install(self, session, *, reset_default=True, max_records=8, max_commands=128):
        session.runner._test_session = session
        self.evidence_only(session)
        adapter = self.runtime(session)
        if reset_default:
            session.configure_register_reset_default(
                max_records=max_records, max_commands=max_commands)
        return adapter


@pytest.fixture
def actual_reset_session(native_factory, tmp_path):
    return ActualResetSession(native_factory=native_factory, tmp_path=tmp_path)


WRITE = dict(case_id='write', action_id='write-action', target_instance='gpio_a',
             register='INTEN', field='value', operation='register_write',
             value=0x80000000, allow_side_effect=True, result_address=None)
READ = dict(case_id='read', action_id='read-action', target_instance='gpio_a',
            register='INTEN', field='value', operation='register_read', value=None,
            allow_side_effect=False, result_address=0x10004)


def consumers(session):
    return set(session.runner._memory_commit_authority._consumers)


def assert_no_half_install(session, before):
    runner = session.runner
    assert session._register_reset_default_verifier is None
    assert runner._register_reset_default_verifier is None
    assert consumers(session) == before
    assert 'register_reset_default_verifier' not in consumers(session)
    assert session._register_reset_default_binding is None
    assert session._register_reset_default_configuration_json is None


# --------------------------------------------------------------------------
# Genuine missing-API RED -> GREEN
# --------------------------------------------------------------------------

def test_configure_register_reset_default_requires_actual_api(actual_reset_session):
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    adapter = actual_reset_session.runtime(session)
    before = consumers(session)
    configuration = session.configure_register_reset_default(
        max_records=8, max_commands=128)
    from myfuzz.scenario.register_reset_default_verifier import (
        RegisterResetDefaultVerifier)
    assert configuration['schema_version'] == 'register_reset_default_configuration.v1'
    assert configuration['max_records'] == 8
    assert all(configuration[name] is False for name in
               ('grants_storage', 'grants_version_dependency', 'grants_prerequisites',
                'grants_functional'))
    verifier = session._register_reset_default_verifier
    assert type(verifier) is RegisterResetDefaultVerifier
    assert session.runner._register_reset_default_verifier is verifier
    assert verifier.runtime is adapter
    assert consumers(session) == before | {'register_reset_default_verifier'}
    assert session._register_reset_default_configuration_json is not None
    # A second configuration of the same session is refused with no half state.
    with pytest.raises(ValueError, match='prebegin'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert session._register_reset_default_verifier is verifier


def test_configure_adopts_only_an_actual_preinstalled_verifier(actual_reset_session):
    """Plan install order: Task3 verifier may be constructed before the wrapper."""
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    adapter = actual_reset_session.runtime(session)
    from myfuzz.scenario.register_reset_default_verifier import (
        RegisterResetDefaultVerifier)
    verifier = RegisterResetDefaultVerifier(adapter, max_records=4)
    configuration = session.configure_register_reset_default(
        max_records=4, max_commands=128)
    assert session._register_reset_default_verifier is verifier
    assert configuration == verifier.configuration()
    # A foreign object in the private slot is refused before anything else.
    other = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(other)
    actual_reset_session.runtime(other)
    foreign = object()
    other.runner._register_reset_default_verifier = foreign
    before = consumers(other)
    with pytest.raises(ValueError, match='foreign-installed-verifier'):
        other.configure_register_reset_default(max_records=8, max_commands=128)
    assert other.runner._register_reset_default_verifier is foreign  # untouched
    assert other._register_reset_default_verifier is None
    assert other._register_reset_default_binding is None
    assert consumers(other) == before
    assert 'register_reset_default_verifier' not in consumers(other)


def test_configure_requires_actual_task2_evidence_first(actual_reset_session):
    session = actual_reset_session.session(install=False)
    actual_reset_session.runtime(session)
    before = consumers(session)
    with pytest.raises(ValueError, match='task2-evidence-required'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert_no_half_install(session, before)


def test_configure_rejects_events_before_begin(actual_reset_session):
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    actual_reset_session.runtime(session)
    target = session.runner.sessions['gpio_a']
    target.begin_case('mechanical')
    try:
        session.runner.native_reset_evidence_snapshot()
        assert session.runner.event_count > 0
        before = consumers(session)
        with pytest.raises(ValueError, match='prebegin-required'):
            session.configure_register_reset_default(max_records=8, max_commands=128)
        assert_no_half_install(session, before)
    finally:
        target.end_case()


def test_configure_rejects_begun_session(default_off_session):
    """Genuine begun default-off session; the only failing condition is _begun."""
    session, _ = default_off_session
    assert session._begun is True and session.runner._status == 'running'
    assert session._register_program_runtime is not None
    before = consumers(session)
    with pytest.raises(ValueError, match='prebegin-required'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert session._register_reset_default_verifier is None
    assert session.runner._register_reset_default_verifier is None
    assert consumers(session) == before


def test_configure_rejects_foreign_runtime(actual_reset_session):
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    other = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(other)
    foreign = actual_reset_session.runtime(other)
    session._register_program_runtime = foreign
    before = consumers(session)
    try:
        with pytest.raises(ValueError, match='actual-runtime-required'):
            session.configure_register_reset_default(max_records=8, max_commands=128)
        assert_no_half_install(session, before)
    finally:
        session._register_program_runtime = None


def test_configure_rejects_capacity_and_unknown_consumers(actual_reset_session):
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    actual_reset_session.runtime(session)
    before = consumers(session)
    with pytest.raises(ValueError, match='invalid-capacity'):
        session.configure_register_reset_default(max_records=True, max_commands=128)
    with pytest.raises(ValueError, match='invalid-capacity'):
        session.configure_register_reset_default(max_records=8, max_commands=0)
    with pytest.raises(ValueError, match='command-capacity'):
        session.configure_register_reset_default(max_records=8, max_commands=129)
    assert_no_half_install(session, before)
    session.runner._memory_commit_authority.register_consumer('foreign_consumer')
    before = consumers(session)
    with pytest.raises(ValueError, match='unknown-startup-consumer'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert_no_half_install(session, before)
    assert 'foreign_consumer' in consumers(session)


def test_configure_rejects_method_drift_without_half_install(actual_reset_session, monkeypatch):
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    actual_reset_session.runtime(session)
    before = consumers(session)
    original = ScenarioSession.configure_register_reset_default

    def wrapper(self, **kwargs):
        return original(self, **kwargs)

    monkeypatch.setattr(ScenarioSession, 'configure_register_reset_default', wrapper)
    with pytest.raises(ValueError, match='configure-method-drift'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert_no_half_install(session, before)
    monkeypatch.undo()
    session.configure_register_reset_default(max_records=8, max_commands=128)
    assert session._register_reset_default_verifier is not None
    # Any instance or class shadow of the code-owned guard is refused.
    session._guard_register_reset_default_configuration = lambda *a, **k: None
    with pytest.raises(ValueError, match='guard-method-drift'):
        session.register_reset_default_document()
    del session.__dict__['_guard_register_reset_default_configuration']
    original_guard = ScenarioSession._guard_register_reset_default_configuration
    monkeypatch.setattr(ScenarioSession, '_guard_register_reset_default_configuration',
                        lambda *a, **k: None)
    with pytest.raises(ValueError, match='guard-method-drift'):
        session.register_reset_default_document()
    monkeypatch.setattr(ScenarioSession, '_guard_register_reset_default_configuration',
                        original_guard)
    assert session._register_reset_default_incomplete is False


def test_configure_rejects_foreign_verifier_implementation(actual_reset_session, monkeypatch):
    from myfuzz.scenario import register_reset_default_verifier as verifier_module
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    actual_reset_session.runtime(session)
    before = consumers(session)
    monkeypatch.setattr(verifier_module, 'RegisterResetDefaultVerifier', object)
    with pytest.raises(ValueError, match='foreign-verifier-implementation'):
        session.configure_register_reset_default(max_records=8, max_commands=128)
    assert_no_half_install(session, before)


# --------------------------------------------------------------------------
# Closed detached document, plan row and manifest channel
# --------------------------------------------------------------------------

def test_register_reset_default_document_is_detached_and_closed(actual_reset_session):
    from myfuzz.scenario.register_reset_default_verifier import (
        validate_register_reset_default_session_document)
    session = actual_reset_session.session()
    verifier = session._register_reset_default_verifier
    document = session.register_reset_default_document()
    assert document == verifier.session_document()
    assert validate_register_reset_default_session_document(
        document, configuration=session._register_program_runtime.configuration()) == document
    # Frozen Task3b schema: the maximal rule scope always lives in the
    # configuration, and the refusal scope is a property of the state.
    assert document['configuration']['proof_scope'] == (
        'observed_source_bound_reset_default_readback')
    assert document['state']['proof_scope'] in (
        'source_bound_reset_default_refusal_only',
        'observed_source_bound_reset_default_readback')
    if document['state']['current_certificates']:
        assert document['state']['proof_scope'] == (
            'observed_source_bound_reset_default_readback')
    else:
        assert document['state']['proof_scope'] == (
            'source_bound_reset_default_refusal_only')
    # The wrapper passes the verifier's certificate projection through
    # detached, whatever its arity: it fabricates nothing and stores nothing.
    assert (document['state']['current_certificates']
            == verifier.report()['current_certificates'])
    assert sorted(row['target_instance'] for row in document['state']['gaps']) == [
        'gpio_a', 'gpio_b']
    # A detached mutation is not retained and never becomes verifier state.
    document['state']['gaps'].clear()
    document['state']['current_certificates'].append(dict(status='verified'))
    document['state']['historical_certificates'].append(dict(status='verified'))
    fresh = session.register_reset_default_document()
    assert fresh == verifier.session_document()
    assert fresh['state']['current_certificates'] == []
    assert fresh['state']['historical_certificates'] == []
    assert fresh['state']['gaps']
    # Saved-data certificate tampering is refused even when rehashed.
    forged = session.register_reset_default_document()
    forged['state']['current_certificates'].append(dict(status='verified'))
    with pytest.raises(ValueError):
        validate_register_reset_default_session_document(
            forged, configuration=session._register_program_runtime.configuration())


def test_plan_row_and_manifest_channel_are_closed_and_startup_bound(actual_reset_session):
    session = actual_reset_session.session()
    document = json.loads(session.encode_plan())
    assert document['schema_version'] == 16
    row = document['register_programs']['register_reset_default']
    assert set(row) == {'schema_version', 'configuration', 'state'}
    assert row['schema_version'] == 'register_reset_default_session.v1'
    assert row == session.register_reset_default_document()
    configuration = session._register_reset_default_configuration()
    sources = json.loads(session._register_reset_default_sources_json)
    manifest = _online_manifest(
        session.runner, None,
        register_program_configuration=session._register_configuration(),
        register_reset_default_configuration=configuration,
        register_reset_default_source_files=sources)
    assert manifest['register_reset_default_configuration'] == configuration
    assert manifest['register_reset_default_source_files'] == sources
    assert {row['path'] for row in sources} >= {
        'src/myfuzz/scenario/register_reset_default_verifier.py',
        'src/myfuzz/scenario/native_reset_evidence.py',
        'src/myfuzz/scenario/register_program_runtime.py',
        'src/myfuzz/scenario/session_runtime.py',
        'src/myfuzz/local_harness/native_reset_observation.py'}
    # The same builder without the opt-in channel keeps the historical layout.
    control = _online_manifest(session.runner, None,
        register_program_configuration=session._register_configuration())
    assert not any(name.startswith('register_reset_default') for name in control)


def _layout_normalize(value):
    """Drop third-party parse output, never a Task4 layout field.

    ``*.current_binding.facts`` is produced by the composition source parser
    against an untracked third-party RTL tree that other owners regenerate
    concurrently; it is not part of the Session/register channel layout.
    """
    if isinstance(value, dict):
        return {key: _layout_normalize(item) for key, item in value.items()
                if key != 'facts'}
    if isinstance(value, list):
        return [_layout_normalize(item) for item in value]
    return value


def _layout_digest(document):
    masked = re.sub(r'[0-9a-f]{64}', '<sha>',
                    json.dumps(_layout_normalize(document), sort_keys=True,
                               separators=(',', ':')))
    return hashlib.sha256(masked.encode()).hexdigest()


# List lengths are layout-meaningful only at the Session/register channel paths.
# Artifact and elaboration lists depend on the host toolchain and are excluded.
_LAYOUT_LENGTH_PATHS = frozenset({
    '', 'cases', 'instruction_slots', 'warmup_advances', 'prerequisite_admissions',
    'reset_operations', 'register_programs', 'register_programs.case_manifests'})


def _layout_skeleton(value, path=''):
    """Environment-independent key/type/arity projection of the plan document."""
    if isinstance(value, dict):
        return {key: _layout_skeleton(item, f'{path}.{key}' if path else key)
                for key, item in sorted(value.items()) if key != 'facts'}
    if isinstance(value, list):
        items = [_layout_skeleton(item, f'{path}[]') for item in value]
        return {'#arity': len(value), '#items': items} if path in _LAYOUT_LENGTH_PATHS \
            else {'#items': items}
    return type(value).__name__


def _layout_skeleton_digest(document):
    text = json.dumps(_layout_skeleton(document), sort_keys=True,
                      separators=(',', ':'))
    return hashlib.sha256(text.encode()).hexdigest()


def test_default_off_layout_is_byte_identical_after_change(actual_factory):
    """Default-off plan layout is unchanged: same schema, no key added or moved.

    The load-bearing evidence is the environment-independent structural
    skeleton below: every key path, value type and layout-meaningful list arity
    of the emitted schema16 plan.  A pre-change probe with this same fixture
    produced byte-identical skeleton bytes (280875 bytes, digest
    ``57d719dc263d8be9284d12a030be927ad8885a4e10eb04cf729460046597d656``); the
    digest comparison of raw bytes is reported separately as an
    environment-qualified observation because the composition elaboration path
    differs between probe environments.
    """
    session, plan, _ = recorded(actual_factory)
    document = json.loads(plan)
    assert document['schema_version'] == 16
    assert sorted(document) == ["cases", "instruction_slots", "prerequisite_admissions",
                                "register_programs", "reset_operations", "schema_version",
                                "template", "warmup_advances"]
    assert sorted(document['register_programs']) == ["case_manifests", "configuration",
                                                     "gate_state", "schema_version",
                                                     "terminal_attempt"]
    assert _layout_skeleton_digest(document) == (
        '57d719dc263d8be9284d12a030be927ad8885a4e10eb04cf729460046597d656')
    manifest = session.manifest_document
    assert sorted(manifest) == ["checker", "online_source_files",
                                "register_program_configuration",
                                "register_program_source_files", "runner",
                                "schema_version"]
    assert sorted(manifest['runner']) == ["bindings", "host_sources", "irq_pulses",
                                          "memories", "memory_dependency_evidence",
                                          "ownership",
                                          "persistent_memory_prerequisites",
                                          "schema_version", "sessions", "windows"]
    assert _layout_digest(document) == (
        '4fab5c62c70e54352ec36d9f686fffb3cfd7554531122049de3c47e5e8770c18')
    assert 'register_reset_default' not in json.dumps(document)
    assert not any(name.startswith('register_reset_default') for name in manifest)


def test_default_off_uncertain_layout_is_unchanged(actual_factory):
    session, plan, _ = recorded(actual_factory, failure='step')
    document = json.loads(plan)
    assert document['schema_version'] == 17
    assert sorted(document) == ["cases", "instruction_slots", "prerequisite_admissions",
                                "register_programs", "reset_operations", "schema_version",
                                "template", "terminal_failure", "warmup_advances"]
    assert sorted(document['register_programs']) == ["case_manifests", "configuration",
                                                     "gate_state", "schema_version",
                                                     "terminal_attempt"]
    assert sorted(session.manifest_document) == ["checker", "online_source_files",
                                                 "register_program_configuration",
                                                 "register_program_source_files",
                                                 "runner", "schema_version"]


def test_default_off_optional_subrow_presence_is_unchanged(actual_factory):
    """Existing optional sub-rows keep their exact presence/absence pattern."""
    session, plan, _ = recorded(actual_factory)
    circuits = [json.loads(plan)['register_programs']]
    failing, failing_plan, _ = recorded(actual_factory, failure='step')
    circuits.append(json.loads(failing_plan)['register_programs'])
    for registers in circuits:
        assert {'schema_version', 'configuration', 'case_manifests',
                'terminal_attempt', 'gate_state'} <= set(registers)
        assert not ({'capability_preflight', 'ordinary_apb_access_evidence',
                     'register_program_verifier', 'register_reset_default'}
                    & set(registers))
    for manifest_names in (session.manifest_document, failing.manifest_document):
        assert not any(name.startswith('register_reset_default')
                       for name in manifest_names)


# --------------------------------------------------------------------------
# Guard call sites
# --------------------------------------------------------------------------

def _incomplete_evidence(session):
    """Actual standalone Task1 reset outside any Runner barrier; never synthetic."""
    target = session.runner.sessions['gpio_a']
    target.begin_case('mechanical')
    target.reset_local()
    state = session.runner.native_reset_evidence_snapshot()
    assert state['status'] == 'incomplete'
    return target


def test_runtime_prepare_guard_precedes_registration(actual_reset_session):
    session = actual_reset_session.session()
    adapter = session._register_program_runtime
    target = _incomplete_evidence(session)
    try:
        with pytest.raises(ValueError, match='incomplete'):
            adapter.prepare(dict(request(**WRITE)))
        assert adapter._records == []
        assert adapter._active_submission is None
        assert session.cases == ()
        assert session.runner.sessions['gpio_a']._sequence >= 0
        gate = session.runner.persistent_memory_prerequisite_gate
        assert 'write-action' not in gate.action_ids
    finally:
        target.end_case()
    # Differential control: with complete evidence the same call reaches the
    # later begin precondition, proving the pinned guard ran first and passed.
    session2 = actual_reset_session.session()
    with pytest.raises(ValueError, match='active-directed-session-required'):
        session2._register_program_runtime.prepare(dict(request(**WRITE)))


def test_runtime_native_guard_entry_is_module_pinned(actual_reset_session, monkeypatch):
    from myfuzz.scenario import register_program_runtime as runtime_module
    session = actual_reset_session.session()
    guard = runtime_module._guard_native_reset_operation
    assert guard(session.runner, new_operation=False) is None

    def replaced(runner, **kwargs):
        raise AssertionError('replaced module alias must never be called')

    monkeypatch.setattr(runtime_module, 'guard_native_reset_evidence', replaced)
    with pytest.raises(ValueError, match='native-reset-guard-drift'):
        guard(session.runner, new_operation=False)


def test_unselected_commit_is_refused_and_never_truncated(actual_reset_session):
    """A real issued host-memory commit outside any selected READ result span.

    The transaction-key execution label is fixture-supplied because no session
    begin is reachable in software; the commit itself is actually issued and
    authenticated by the installed service and MemoryCommitAuthority.
    """
    from myfuzz.scenario.ledger import TransactionKey
    session = actual_reset_session.session()
    runner = session.runner
    verifier = session._register_reset_default_verifier
    before_consumers = consumers(session)
    key = TransactionKey('software-prebegin', 'software-prebegin', 'cpu', 0, 'data', 1)
    receipt = runner.sessions['cpu'].service.write(
        key, 0x10004, 0x80000000, width_bytes=4, byte_enable=15)
    assert receipt is not None
    runner._append_external_events('cpu', len(runner._events))
    assert len(verifier._commits) == 1
    retained = dict(verifier._commits)
    # No selected request exists, so this is an unselected/bootstrap write.
    with pytest.raises(ValueError, match='unselected-commit'):
        session.register_reset_default_document()
    assert session._register_reset_default_selected == {}
    assert session._register_reset_default_unmatched == tuple(retained)
    assert verifier._commits == retained           # never truncated or skipped
    assert session._register_reset_default_incomplete is True
    assert consumers(session) == before_consumers
    # The refusal document records the gap instead of healing the state.
    state = verifier.report()
    assert state['current_certificates'] == []
    assert state['gaps'][0]['reason'] == 'missing_native_reset_default_readback'
    assert session._register_reset_default_incomplete is True


# --------------------------------------------------------------------------
# Selected READ result span/commit address space: the missing positive match
# --------------------------------------------------------------------------

def _software_read_manifest(actual_factory):
    """One byte-exact production manifest for a real selected READ request.

    A begun reset-default session is unreachable in software (installed Task2
    evidence pins the actual Runner method table, so ``begin_test`` would
    compile RTL), so the manifest is captured from a real
    ``RegisterProgramRuntime.submit`` on the accepted software lifecycle
    factory and installed into the reset-default session's own record store.
    The commit matched below is issued by the real service on that same
    session's own CPU persistent memory.
    """
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_ordinary_apb_access_session import session as software_session
    from tests.scenario.test_register_program_verifier import read_result_factory
    source = software_session(read_result_factory(actual_factory))
    source.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(source)
    RegisterProgramVerifier(runtime, max_records=4)
    source.begin()
    runtime.submit(dict(request(**READ)))
    return json.loads(json.dumps(runtime._records[0]['manifest']))


def _selected_read_session(actual_reset_session, actual_factory, **options):
    """Reset-default session holding one real selected READ manifest."""
    manifest = _software_read_manifest(actual_factory)
    session = actual_reset_session.session(**options)
    assert manifest['request']['operation'] == 'register_read'
    assert manifest['request']['result_address'] == 0x10004
    session._register_program_runtime._records.append(
        dict(manifest=manifest, status='submitted', phase='session_submission',
             case_index=0))
    return session, manifest


def _issue_commit(session, address, sequence, value=0x80000000):
    """Issue one real host persistent-memory commit through the real service."""
    from myfuzz.scenario.ledger import TransactionKey
    runner = session.runner
    key = TransactionKey('software-prebegin', 'software-prebegin', 'cpu', 0,
                         'data', sequence)
    receipt = runner.sessions['cpu'].service.write(
        key, address, value, width_bytes=4, byte_enable=15)
    assert receipt is not None
    runner._append_external_events('cpu', len(runner._events))
    return key


def _issued_registry_value(session, index=0):
    """The exact JSON string the pinned Task3 registry stores per commit."""
    verifier = session._register_reset_default_verifier
    return list(verifier._commits.values())[index]


def test_selected_read_result_span_is_in_the_owning_memory_address_space(
        actual_reset_session, actual_factory):
    """The missing positive case: a legitimate selected READ result commit matches.

    The declared request carries an absolute ``result_address`` (0x10004) while
    the commit document carries a memory-relative ``byte_offset`` (4).  The
    selected span must therefore be built in the owning memory's address space
    with the same resolver ``memory_service.write`` uses for that offset.
    """
    session, manifest = _selected_read_session(actual_reset_session, actual_factory)
    memory = session.runner.sessions['cpu'].memory
    assert memory.resolve_span(0x10004, 4, write=True) == ('ram', 0, 4)
    _issue_commit(session, 0x10004, 1)
    spans = session._register_reset_default_selected_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span['address'] == 4                 # owning-memory relative offset
    assert span['width'] == 4
    assert span['memory_ids'] == ('ram',)       # the owning memory only
    assert span['context'] == manifest['context']
    selected = session._register_reset_default_selected_commit(
        _issued_registry_value(session), spans)
    assert selected is not None
    assert selected['result_span'] == [4, 4]    # same address space as the span
    assert selected['memory_id'] == 'ram'
    assert selected['generation'] == 0
    assert selected['cpu_component'] == 'cpu'
    assert selected['context'] == manifest['context']


def test_selected_read_result_commit_is_retained_by_the_pinned_guard(
        actual_reset_session, actual_factory):
    """The native-gate symptom: the guard must not refuse its own selected read.

    Both frozen native gates reached the reset with exactly one commit - the
    selected READ result itself - and were refused by
    ``session_runtime.py:1004`` with ``register-reset-default-unselected-commit``
    before ``session.reset()`` could run.
    """
    session, manifest = _selected_read_session(actual_reset_session, actual_factory)
    verifier = session._register_reset_default_verifier
    _issue_commit(session, 0x10004, 1)
    commit_id = next(iter(verifier._commits))
    try:
        document = session.register_reset_default_document()
    except ValueError as error:
        # Any later refusal is the unbegun session's native-reset
        # incompleteness, never the selected-span address-space refusal.
        assert 'unselected-commit' not in str(error)
    else:
        # The unbegun software session still exports the closed wrapper.
        assert document['schema_version'] == 'register_reset_default_session.v1'
        assert document['configuration']['grants_storage'] is False
    assert session._register_reset_default_unmatched == ()
    assert list(session._register_reset_default_selected) == [commit_id]
    selected = session._register_reset_default_selected[commit_id]
    assert selected['result_span'] == [4, 4]
    assert selected['memory_id'] == 'ram'
    assert selected['context'] == manifest['context']


def test_pinned_task3_registry_envelope_is_the_matched_commit_input(
        actual_reset_session, actual_factory):
    """``session_runtime.py:977-981`` iterates the Task3 registry itself.

    ``register_reset_default_verifier.py:434`` reads each registry value as the
    exact ``{'certificate', 'logged'}`` envelope, so the matcher must consume
    that same envelope.  Anything else must stay unmatched (fail-closed).
    """
    session, manifest = _selected_read_session(actual_reset_session, actual_factory)
    verifier = session._register_reset_default_verifier
    _issue_commit(session, 0x10004, 1)
    raw = next(iter(verifier._commits.values()))
    assert type(raw) is str
    entry = json.loads(raw)
    assert set(entry) == {'certificate', 'logged'}
    span = dict(address=4, width=4, memory_ids=('ram',),
                context=manifest['context'])
    selected = session._register_reset_default_selected_commit(raw, [span])
    assert selected is not None
    assert selected['result_span'] == [4, 4]
    assert selected['memory_id'] == 'ram'
    assert selected['cpu_component'] == 'cpu'
    # The decoded envelope is accepted under the same strict contract.
    assert session._register_reset_default_selected_commit(
        entry, [span]) is not None
    # Fail-closed on every shape the pinned registry never produces.
    certificate = entry['certificate']
    for malformed in (
            json.dumps(dict(entry, extra=True)),          # extra key
            json.dumps(dict(certificate=certificate)),    # missing key
            json.dumps(dict(logged=entry['logged'])),     # missing key
            json.dumps(dict(certificate=None, logged=entry['logged'])),
            json.dumps(dict(certificate=certificate, logged=None)),
            json.dumps(dict(certificate=list(certificate), logged=entry['logged'])),
            json.dumps(certificate),                      # bare certificate
            json.dumps([entry]), json.dumps(7), json.dumps('x'),
            '{not json', 'null', ''):
        assert session._register_reset_default_selected_commit(
            malformed, [span]) is None, malformed
    for malformed in (dict(entry, extra=True), dict(certificate=certificate),
                      dict(logged=entry['logged']),
                      dict(certificate=certificate, logged=None), certificate,
                      [entry], 7, None, b'{}'):
        assert session._register_reset_default_selected_commit(
            malformed, [span]) is None, malformed


def test_both_fixes_are_independently_required(actual_reset_session, actual_factory):
    """Neither half alone selects the selected READ result commit.

    (a) address space corrected but the envelope unwrapped nowhere, (b) the
    envelope unwrapped but the span left absolute, (c) both fixed.  (a) is
    data-level here because the pre-fix matcher no longer exists in the live
    bytes: its outcome is the byte-bound RED receipt on ``5dbd9c94...``, where
    the same real registry value with a relative span returned ``None``.
    """
    session, manifest = _selected_read_session(actual_reset_session, actual_factory)
    verifier = session._register_reset_default_verifier
    _issue_commit(session, 0x10004, 1)
    raw = next(iter(verifier._commits.values()))
    entry = json.loads(raw)
    context = manifest['context']
    relative = [dict(address=4, width=4, memory_ids=('ram',), context=context)]
    absolute = [dict(address=0x10004, width=4, memory_ids=('ram',),
                     context=context)]
    # (b) envelope unwrapped, span still in the declared absolute address space.
    assert session._register_reset_default_selected_commit(raw, absolute) is None
    # (a) the registry value has no top-level certificate fields, so the pre-fix
    #     matcher contract cannot consume it whatever the span address space is;
    #     and a bare certificate is refused by the strict contract in force now.
    assert 'commit_document' not in entry and 'fullkey' not in entry
    assert session._register_reset_default_selected_commit(
        json.dumps(entry['certificate']), relative) is None
    # (c) both fixed: the real registry value and the resolved span agree.
    selected = session._register_reset_default_selected_commit(raw, relative)
    assert selected is not None
    assert selected['result_span'] == [4, 4]
    assert selected['memory_id'] == 'ram'
    assert selected['context'] == context


def test_malformed_registry_values_keep_the_guard_refusing(
        actual_reset_session, actual_factory):
    """A malformed registry value must reach the refusal path, never a match."""
    session, manifest = _selected_read_session(actual_reset_session, actual_factory,
                                               max_records=16)
    verifier = session._register_reset_default_verifier
    commits = session._register_reset_default_commits
    _issue_commit(session, 0x10004, 1)
    real_id = next(iter(verifier._commits))
    raw = verifier._commits[real_id]
    certificate = json.loads(raw)['certificate']
    malformed = {
        'not-json': '{not json',
        'extra-key': json.dumps(dict(certificate=certificate, logged={}, extra=1)),
        'missing-logged': json.dumps(dict(certificate=certificate)),
        'null-certificate': json.dumps(dict(certificate=None, logged={})),
        'list-certificate': json.dumps(dict(certificate=[], logged={})),
        'bare-certificate': json.dumps(certificate),
        'json-null': 'null',
    }
    for name, encoded in malformed.items():
        assert session._register_reset_default_selected_commit(
            encoded, session._register_reset_default_selected_spans()) is None, name
        commits[name] = encoded
    with pytest.raises(ValueError, match='unselected-commit'):
        session.register_reset_default_document()
    # Only the one genuine selected READ result commit is selected; every
    # malformed value stayed on the refusal path.
    assert set(session._register_reset_default_selected) == {real_id}
    assert set(session._register_reset_default_unmatched) == set(malformed)
    assert session._register_reset_default_incomplete is True
    assert session._register_reset_default_reason == 'unselected_commit'


def test_selected_span_boundaries_never_over_match(actual_reset_session, actual_factory):
    """Offsets outside the span, other memories, generations and components."""
    session, manifest = _selected_read_session(actual_reset_session, actual_factory)
    verifier = session._register_reset_default_verifier
    _issue_commit(session, 0x10000, 1)      # offset 0: before the selected span
    _issue_commit(session, 0x10004, 2)      # offset 4: the selected span
    _issue_commit(session, 0x10008, 3)      # offset 8: after the selected span
    spans = session._register_reset_default_selected_spans()
    assert len(spans) == 1
    assert (spans[0]['address'], spans[0]['width']) == (4, 4)
    entries = [json.loads(encoded) for encoded in verifier._commits.values()]
    assert len(entries) == 3
    assert [row['certificate']['commit_document']['byte_offset']
            for row in entries] == [0, 4, 8]
    matched = [session._register_reset_default_selected_commit(row, spans)
               for row in entries]
    assert [row is not None for row in matched] == [False, True, False]
    # A commit the service actually issued for another memory id is never
    # selected: the span pins the resolved owning memory, not every memory.
    foreign = json.loads(json.dumps(entries[1]))
    foreign['certificate']['commit_document']['memory_id'] = 'foreign'
    assert session._register_reset_default_selected_commit(foreign, spans) is None
    # A commit older than the selected request's recorded generation is never
    # selected (the guard compares against the request context generation).
    stale = json.loads(json.dumps(entries[1]))
    raised = [dict(address=4, width=4, memory_ids=('ram',),
                   context=dict(manifest['context'], generation=1))]
    assert session._register_reset_default_selected_commit(stale, raised) is None
    # A commit attributed to a non-CPU component is never selected.
    foreign_component = json.loads(json.dumps(entries[1]))
    foreign_component['certificate']['component'] = 'gpio_a'
    assert session._register_reset_default_selected_commit(
        foreign_component, spans) is None
    # A commit whose transaction key belongs to another component fails too.
    foreign_key = json.loads(json.dumps(entries[1]))
    foreign_key['certificate']['fullkey']['source_component'] = 'gpio_a'
    assert session._register_reset_default_selected_commit(
        foreign_key, spans) is None
    # Fail-closed at the guard: unselected commits are retained, never skipped.
    with pytest.raises(ValueError, match='unselected-commit'):
        session.register_reset_default_document()
    assert len(session._register_reset_default_selected) == 1
    assert len(session._register_reset_default_unmatched) == 2
    assert verifier._commits != {}


def test_capacity_preflight_refuses_before_truncating(actual_reset_session):
    from myfuzz.scenario.ledger import TransactionKey
    session = actual_reset_session.session(install=False)
    actual_reset_session.evidence_only(session)
    actual_reset_session.runtime(session)
    session.configure_register_reset_default(max_records=1, max_commands=128)
    runner = session.runner
    verifier = session._register_reset_default_verifier
    key = TransactionKey('software-prebegin', 'software-prebegin', 'cpu', 0, 'data', 1)
    runner.sessions['cpu'].service.write(
        key, 0x10004, 0x80000000, width_bytes=4, byte_enable=15)
    runner._append_external_events('cpu', len(runner._events))
    retained = dict(verifier._commits)
    assert len(retained) == 1
    with pytest.raises(ValueError, match='capacity'):
        session.register_reset_default_document()
    assert verifier._commits == retained           # no truncation, no silent skip
    assert session._register_reset_default_reason == 'capacity'


def test_submit_case_guard_refuses_before_session_state_check(actual_reset_session):
    """The pinned Session guard is entered at submit_case before _begun checks."""
    from myfuzz.scenario.batch import BatchAdvance
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.session_runtime import OnlineCase, OnlineInstruction
    session = actual_reset_session.session()
    runner = session.runner
    key = TransactionKey('software-prebegin', 'software-prebegin', 'cpu', 0, 'data', 1)
    runner.sessions['cpu'].service.write(
        key, 0x10004, 0x80000000, width_bytes=4, byte_enable=15)
    runner._append_external_events('cpu', len(runner._events))
    case = OnlineCase('case', 'CPU_TO_IP', 'register_program',
                      OnlineInstruction('action', 'cpu', 0x11000, '13000000' * 4),
                      (BatchAdvance(('cpu', 'gpio_a', 'gpio_b')),))
    # Not begun: without the pinned guard this would raise the later
    # active-session precondition instead of the reset-default refusal.
    with pytest.raises(ValueError, match='unselected-commit'):
        session.submit_case(case)
    assert session.cases == ()


def test_tampered_saved_reset_default_row_never_reaches_factory(actual_reset_session):
    from dataclasses import replace
    from myfuzz.scenario.replay import ScenarioTrace
    session = actual_reset_session.session()
    plan = session.encode_plan()
    for mutate in ('configuration', 'certificate', 'alias'):
        document = json.loads(plan)
        row = document['register_programs']['register_reset_default']
        if mutate == 'configuration':
            row['configuration']['max_records'] = 64
        elif mutate == 'certificate':
            row['state']['current_certificates'].append(dict(status='verified'))
        else:
            row['state']['gaps'][0]['reason'] = 'saved_authority'
        changed = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
        reference = ScenarioTrace(hashlib.sha256(changed).hexdigest(), 'running', (),
                                  {}, '', '')
        def forbidden(*args, **kwargs):
            raise AssertionError('saved bytes cannot authorize reset-default fresh runs')
        with pytest.raises(ValueError):
            replay_online_session(changed, forbidden, reference,
                                  register_runtime_factory=forbidden)
    # The untampered plan is still accepted by the closed plan validator.
    from myfuzz.scenario.session_runtime import validate_register_program_plan
    validate_register_program_plan(json.loads(plan))


def test_joined_reset_positive_is_outside_software_scope(actual_reset_session):
    """Honest boundary: a begun reset-default session needs the native build."""
    session = actual_reset_session.session()
    runner = session.runner
    assert session._begun is False and runner._status == 'created'
    original = runner.begin_test
    runner.begin_test = lambda *args: None
    try:
        with pytest.raises(ValueError, match='Runner method drift'):
            runner._native_reset_evidence.validate()
    finally:
        del runner.__dict__['begin_test']
    assert runner.begin_test == original
    assert session._begun is False
    with pytest.raises(RuntimeError, match='before begin'):
        session.manifest_document


# --------------------------------------------------------------------------
# Default-off lifecycle control (accepted software fixture, no Task2/Task3)
# --------------------------------------------------------------------------

@pytest.fixture
def default_off_session(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_stream_bootstrap)
    from tests.scenario.test_register_reset_resume import lifecycle_factory
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    assembly = api.make_register_assembly(advance_rounds=1)
    factory = lifecycle_factory(
        api.make_register_factory(cache_dir=tmp_path / 'render', assembly=assembly),
        tmp_path)
    session = ScenarioSession(bootstrap.template, factory())
    session.runner._test_session = session
    session.declare_instruction_slots(
        'cpu', bootstrap.instruction_start, bootstrap.instruction_count)
    adapter = RegisterProgramRuntime(
        session, cpu_component='cpu', sidecars=dict(SIDECARS), advance_rounds=1)
    session.begin()
    try:
        yield session, adapter
    finally:
        for target in session.runner.sessions.values():
            if target.process is not None:
                target.end_case()
