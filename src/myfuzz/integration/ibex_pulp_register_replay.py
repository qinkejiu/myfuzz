"""Trusted, closed ordinary GPIO register-program bundle selection.

Saved documents are comparison evidence. Only local code selects runtime authority.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .scenario_rfuzz_live import _verify_online_run_identity, _write_online_run_identity
from .scenario_rfuzz_replay import _candidate_reference

_ROOT = Path(__file__).resolve().parents[3]
_MINIMUM_UNSET = object()
ASSEMBLY_SCHEMA = 'register_program_assembly.v1'
SIDECAR = 'configs/peripherals/pulp_gpio/test_capability.json'
_FIXED = dict(schema_version=ASSEMBLY_SCHEMA, selector='ibex_pulp_ordinary_gpio',
    sidecar_selector='pulp_gpio_declared', checker=None, cpu_component='cpu',
    source_actions=True, native_physical_observations=True, memory_commit_receipts=True,
    persistent_memory_prerequisites=True, gpio_consumption=False,
    cpu_retirement=False, native_irq_receipts=False)
_LIMITS = dict(advance_rounds=(1,4096), max_program_bytes=(16,4096), max_records=(1,65536))


def _json(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _contract():
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    return make_ibex_pulp_dual_source_online_decoder().runtime_contract.identity_sha256


def make_register_assembly(*, advance_rounds=48, max_program_bytes=64, max_records=4096,
                           requested_minimum_level=_MINIMUM_UNSET, ordinary_apb_access_evidence=_MINIMUM_UNSET,
                           register_program_verifier=_MINIMUM_UNSET, register_reset_default=_MINIMUM_UNSET,
                           bootstrap_selector=None):
    """Build one closed assembly; ``bootstrap_selector`` is the only opt-in here.

    ``bootstrap_selector`` stays ``None`` by default and then this document is
    byte for byte the shipped one.  Asked for, it must name one closed selector
    value and the matching declaration is *recomputed from code and from the
    produced fixture bytes* -- a caller names the selector, never the
    declaration, so no saved or caller-supplied bytes can install authority.
    """
    document=dict(_FIXED, advance_rounds=advance_rounds,
        max_program_bytes=max_program_bytes, max_records=max_records,
        runtime_contract_sha256=_contract())
    if requested_minimum_level is not _MINIMUM_UNSET:
        document["requested_minimum_level"]=requested_minimum_level
    if ordinary_apb_access_evidence is not _MINIMUM_UNSET:
        document["ordinary_apb_access_evidence"]=ordinary_apb_access_evidence
    if register_program_verifier is not _MINIMUM_UNSET:
        document["register_program_verifier"]=register_program_verifier
    if register_reset_default is not _MINIMUM_UNSET:
        document["register_reset_default"]=register_reset_default
    if bootstrap_selector is not None:
        from myfuzz.scenario.ibex_pulp_dual_source import minimal_bootstrap_declaration
        document["bootstrap_selector"]=bootstrap_selector
        document["bootstrap_declaration"]=minimal_bootstrap_declaration()
    return validate_register_assembly(document)


def validate_register_assembly(document):
    fields=set(_FIXED)|set(_LIMITS)|{'runtime_contract_sha256'}
    if type(document) is dict and 'requested_minimum_level' in document:
        fields.add('requested_minimum_level')
        minimum=document['requested_minimum_level']
        if minimum is not None and (type(minimum) is not str or minimum not in ('L1','L2','L3')):
            raise ValueError('register assembly invalid requested minimum level')
    if type(document) is dict and 'ordinary_apb_access_evidence' in document:
        fields.add('ordinary_apb_access_evidence')
        config=document['ordinary_apb_access_evidence']
        if (type(config) is not dict or set(config)!={'max_records'}
                or type(config['max_records']) is not int or not 1<=config['max_records']<=65536):
            raise ValueError('register assembly invalid ordinary APB evidence')
    if type(document) is dict and 'register_program_verifier' in document:
        fields.add('register_program_verifier')
        config=document['register_program_verifier']
        if (type(config) is not dict or set(config)!={'max_records'}
                or type(config['max_records']) is not int or not 1<=config['max_records']<=65536):
            raise ValueError('register assembly invalid register program verifier')
        if 'ordinary_apb_access_evidence' not in document:
            raise ValueError('register verifier requires ordinary APB evidence')
    if type(document) is dict and 'register_reset_default' in document:
        fields.add('register_reset_default')
        config=document['register_reset_default']
        if (type(config) is not dict or set(config)!={'max_records','max_commands'}
                or type(config['max_records']) is not int or not 1<=config['max_records']<=65536
                or type(config['max_commands']) is not int or not 1<=config['max_commands']<=65536):
            raise ValueError('register assembly invalid reset default channel')
        if 'ordinary_apb_access_evidence' not in document:
            raise ValueError('reset default requires ordinary APB evidence')
    if type(document) is dict and 'bootstrap_selector' in document:
        fields.add('bootstrap_selector')
        if 'bootstrap_declaration' not in document:
            raise ValueError('register assembly minimal bootstrap requires its declaration')
        from myfuzz.scenario.ibex_pulp_dual_source import (
            MINIMAL_BOOTSTRAP_SELECTOR, validate_minimal_bootstrap_declaration)
        if document['bootstrap_selector']!=MINIMAL_BOOTSTRAP_SELECTOR:
            raise ValueError('register assembly unsupported bootstrap_selector')
        # The saved declaration is comparison data only: it is compared with a
        # fresh rebuild of the code-owned fixture (which itself re-decodes the
        # produced image and re-checks the negative write list).
        validate_minimal_bootstrap_declaration(document['bootstrap_declaration'])
    if type(document) is dict and 'bootstrap_declaration' in document:
        fields.add('bootstrap_declaration')
        if 'bootstrap_selector' not in document:
            raise ValueError('register assembly bootstrap declaration requires its selector')
    if type(document) is not dict or set(document)!=fields:
        raise ValueError('register assembly requires complete closed fields')
    for name, expected in _FIXED.items():
        if type(document[name]) is not type(expected) or document[name]!=expected:
            raise ValueError('register assembly unsupported '+name)
    for name,(low,high) in _LIMITS.items():
        if type(document[name]) is not int or not low<=document[name]<=high:
            raise ValueError('register assembly invalid '+name)
    if document['max_program_bytes']%4:
        raise ValueError('register assembly word aligned budget required')
    if type(document['runtime_contract_sha256']) is not str or document['runtime_contract_sha256']!=_contract():
        raise ValueError('register assembly current runtime contract required')
    return json.loads(_json(document))


def make_register_factory(*, cache_dir, assembly):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    d=validate_register_assembly(assembly)
    return make_ibex_pulp_dual_source_factory(Path(cache_dir), source_actions=True,
        gpio_consumption=False, physical_observations=True, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256=d['runtime_contract_sha256'])


def _install_reset_default_producers(session, adapter, configuration):
    """Task1 observers then Task2 evidence then the Task3 verifier, before begin.

    Root's recorded install order corrects the plan's prose: the Session opt-in
    channel is configured after the optional RegisterProgramVerifier, so the
    Task3 one-shot recipient must already exist here.  The frozen Task3
    constructor refuses when ``runner._register_program_verifier`` is set and
    ``RegisterProgramVerifier`` snapshots the complete recipient set at
    construction.
    """
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    for name, target in session.runner.sessions.items():
        if type(target) is not GeneratedPulpGpioSession:
            continue
        if not target.native_reset_observation_enabled:
            target.configure_native_reset_observation(max_commands=configuration['max_commands'])
    session.runner.install_native_reset_evidence(max_records=configuration['max_records'],
        max_commands=configuration['max_commands'])
    verifier=RegisterResetDefaultVerifier(adapter,max_records=configuration['max_records'])
    if session.runner._register_reset_default_verifier is not verifier:
        raise ValueError('register reset default verifier installation binding required')
    return verifier


def make_register_runtime_factory(assembly):
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    d=validate_register_assembly(assembly)
    def install(session):
        if 'ordinary_apb_access_evidence' in d:
            session.configure_ordinary_apb_access_evidence(**d['ordinary_apb_access_evidence'])
        adapter = RegisterProgramRuntime(session, cpu_component='cpu',
        sidecars={'gpio_a':_ROOT/SIDECAR,'gpio_b':_ROOT/SIDECAR},
        **{name:d[name] for name in _LIMITS})
        if 'requested_minimum_level' in d:
            session.configure_register_capability_preflight(d['requested_minimum_level'])
        if 'register_reset_default' in d:
            _install_reset_default_producers(session,adapter,d['register_reset_default'])
        if 'register_program_verifier' in d:
            session.configure_register_program_verifier(**d['register_program_verifier'])
        if 'register_reset_default' in d:
            session.configure_register_reset_default(**d['register_reset_default'])
        return adapter
    return install


def _sources(assembly=None):
    """Own fixed selector closure supplements the Session's actual source closure."""
    paths=('src/myfuzz/integration/ibex_pulp_register_replay.py',
        'scripts/run_ibex_pulp_online.py',SIDECAR,
        'src/myfuzz/scenario/register_program_runtime.py',
        'src/myfuzz/scenario/register_program.py','src/myfuzz/scenario/rv32i_sources.py',
        'src/myfuzz/composition/test_capability.py','src/myfuzz/scenario/session_runtime.py',
        'src/myfuzz/scenario/ibex_pulp_dual_source.py',
        'src/myfuzz/integration/scenario_rfuzz_live.py',
        'src/myfuzz/integration/scenario_rfuzz_replay.py',
        'src/myfuzz/integration/ibex_pulp_online.py',
        'src/myfuzz/scenario/event_journal.py',
        'src/myfuzz/scenario/replay.py','src/myfuzz/scenario/genome.py',
        'src/myfuzz/scenario/source_actions.py',
        'src/myfuzz/scenario/live_memory_prerequisites.py',
        'src/myfuzz/scenario/dependency_lifecycle.py',
        'src/myfuzz/scenario/memory_dependency_evidence.py',
        'src/myfuzz/scenario/memory_commit_authority.py',
        'src/myfuzz/scenario/memory_read_authority.py',
        'src/myfuzz/scenario/memory_authority_distribution.py',
        'src/myfuzz/scenario/memory_service.py','src/myfuzz/scenario/memory.py',
        'src/myfuzz/scenario/router.py','src/myfuzz/scenario/ledger.py',
        'src/myfuzz/scenario/runner.py',
        'src/myfuzz/scenario/ip_base_events.py',
        'src/myfuzz/scenario/ip_protocol_events.py',
        'src/myfuzz/scenario/ip_protocol_checker.py',
        'src/myfuzz/local_harness/runtime_renderer.py',
        'src/myfuzz/local_harness/driver_renderer.py',
        'src/myfuzz/local_harness/native_physical_observation.py',
        'src/myfuzz/local_harness/cpu_session.py','src/myfuzz/local_harness/gpio_session.py',
        'src/myfuzz/composition/component_profile.py',
        'configs/cpus/ibex_obi_local/component_profile.json',
        'configs/peripherals/pulp_gpio/component_profile.json')
    if assembly is not None and 'requested_minimum_level' in validate_register_assembly(assembly):
        paths += ('src/myfuzz/scenario/register_program_capabilities.py','src/myfuzz/composition/ip_test_levels.py')
    if assembly is not None and 'ordinary_apb_access_evidence' in validate_register_assembly(assembly):
        from myfuzz.scenario.session_runtime import _ordinary_apb_access_source_files
        paths=tuple(sorted(set(paths)|{row['path'] for row in _ordinary_apb_access_source_files()}))
    if assembly is not None and 'register_program_verifier' in validate_register_assembly(assembly):
        from myfuzz.scenario.session_runtime import _register_program_verifier_source_files
        paths=tuple(sorted(set(paths)|{row['path'] for row in _register_program_verifier_source_files()}))
    if assembly is not None and 'register_reset_default' in validate_register_assembly(assembly):
        from myfuzz.scenario.session_runtime import _register_reset_default_source_files
        paths=tuple(sorted(set(paths)|{row['path'] for row in _register_reset_default_source_files()}))
    if assembly is not None and 'bootstrap_selector' in validate_register_assembly(assembly):
        # The minimal bootstrap's own declaration names the sources its
        # removed-write claim is recomputed from -- the module, the pinned GPIO
        # profile and the pinned RTL -- so the enabled closure pins exactly those
        # rows.  Off, this branch is not taken and the default closure is the
        # shipped tuple above, unchanged.
        from myfuzz.scenario.ibex_pulp_dual_source import minimal_bootstrap_declaration
        paths=tuple(sorted(set(paths)|{row['path']
                                       for row in minimal_bootstrap_declaration()['source_files']}))
    return [dict(path=p,sha256=hashlib.sha256((_ROOT/p).read_bytes()).hexdigest()) for p in paths]


def _verify_capability_channel(assembly, document, manifest):
    registers=document['register_programs']
    enabled='requested_minimum_level' in assembly
    if (('capability_preflight' in registers) != enabled
            or ('register_capability_preflight' in manifest) != enabled):
        raise ValueError('register capability channel presence mismatch')
    if enabled:
        from myfuzz.scenario.register_program_capabilities import validate_register_capability_preflight_document
        report=validate_register_capability_preflight_document(registers['capability_preflight'],configuration=registers['configuration'])
        if (_json(report)!=_json(manifest['register_capability_preflight'])
                or report['requested_minimum_level']!=assembly['requested_minimum_level']):
            raise ValueError('register capability declaration mismatch')
        from myfuzz.scenario.session_runtime import _register_capability_source_files
        if manifest.get('register_program_source_files',[])[-2:] != _register_capability_source_files():
            raise ValueError('register capability source closure mismatch')


def _verify_register_verifier_channel(assembly, document, manifest):
    registers=document['register_programs']
    enabled='register_program_verifier' in assembly
    names=('register_program_verifier_configuration','register_program_verifier_source_files')
    if (('register_program_verifier' in registers) != enabled
            or any((name in manifest) != enabled for name in names)):
        raise ValueError('register verifier channel presence mismatch')
    if enabled:
        from myfuzz.scenario.register_program_verifier import validate_register_program_verifier_session_document
        from myfuzz.scenario.session_runtime import _register_program_verifier_source_files
        channel=validate_register_program_verifier_session_document(
            registers['register_program_verifier'],configuration=registers['configuration'])
        if (channel['configuration']['max_records']!=assembly['register_program_verifier']['max_records']
                or _json(channel['configuration'])!=_json(manifest[names[0]])
                or _json(manifest[names[1]])!=_json(_register_program_verifier_source_files())):
            raise ValueError('register verifier channel configuration or source mismatch')


def _verify_ordinary_channel(assembly, document, manifest):
    registers=document['register_programs']
    enabled='ordinary_apb_access_evidence' in assembly
    names=('ordinary_apb_access_evidence_configuration','ordinary_apb_access_source_files')
    if (('ordinary_apb_access_evidence' in registers) != enabled
            or any((name in manifest) != enabled for name in names)
            or ('ordinary_apb_access_evidence' in manifest.get('runner',{})) != enabled):
        raise ValueError('ordinary APB channel presence mismatch')
    if enabled:
        from myfuzz.scenario.session_runtime import (
            validate_ordinary_apb_access_session_document, _ordinary_apb_access_source_files)
        channel=validate_ordinary_apb_access_session_document(registers['ordinary_apb_access_evidence'])
        config=channel['configuration']
        if (config['max_records']!=assembly['ordinary_apb_access_evidence']['max_records']
                or _json(config)!=_json(manifest[names[0]])
                or _json(config)!=_json(manifest['runner']['ordinary_apb_access_evidence'])
                or _json(manifest[names[1]])!=_json(_ordinary_apb_access_source_files())):
            raise ValueError('ordinary APB channel configuration or source mismatch')


def _verify_register_reset_default_channel(assembly, document, manifest):
    registers=document['register_programs']
    enabled='register_reset_default' in assembly
    names=('register_reset_default_configuration','register_reset_default_source_files')
    if (('register_reset_default' in registers) != enabled
            or any((name in manifest) != enabled for name in names)):
        raise ValueError('reset default channel presence mismatch')
    if enabled:
        from myfuzz.scenario.register_reset_default_verifier import (
            validate_register_reset_default_session_document)
        from myfuzz.scenario.session_runtime import _register_reset_default_source_files
        channel=validate_register_reset_default_session_document(
            registers['register_reset_default'],configuration=registers['configuration'])
        declared=assembly['register_reset_default']
        evidence=manifest.get('runner',{}).get('native_reset_evidence')
        if (type(evidence) is not dict
                or evidence.get('max_records')!=declared['max_records']
                or evidence.get('max_commands')!=declared['max_commands']
                or channel['configuration']['max_records']!=declared['max_records']
                or _json(channel['configuration'])!=_json(manifest[names[0]])
                or _json(manifest[names[1]])!=_json(_register_reset_default_source_files())):
            raise ValueError('reset default channel configuration or source mismatch')


def _verify_assembly_configuration(assembly,configuration):
    for name in ('cpu_component',*tuple(_LIMITS)):
        if _json(configuration.get(name))!=_json(assembly[name]):
            raise ValueError('register assembly adapter configuration mismatch: '+name)
    expected={name:dict(path=str((_ROOT/SIDECAR).resolve()),
        sha256=hashlib.sha256((_ROOT/SIDECAR).read_bytes()).hexdigest()) for name in ('gpio_a','gpio_b')}
    if (_json(configuration.get('sidecars'))!=_json(expected) or
        configuration.get('provider',{}).get('runtime_contract_sha256')!=assembly['runtime_contract_sha256']):
        raise ValueError('register assembly sidecar/provider mismatch')


def _verify_ordinary_gpio_identity(name, identity, configuration):
    from myfuzz.scenario.contracts import _verify_generated_session
    base=dict(identity)
    extension=base.pop('ordinary_apb_access_receipts',None)
    trace=base.get('runtime_artifact',{}).get('base_protocol_trace')
    if (type(extension) is not dict or type(configuration) is not dict
            or _json(extension)!=_json(configuration)
            or extension.get('target_instance')!=name or trace is None
            or extension.get('native_trace_sha256')!=hashlib.sha256(_json(trace).encode()).hexdigest()):
        raise ValueError('register ordinary target observation identity mismatch')
    if 'gpio_observation_contract' in base or 'gpio_target_context_schema_version' in base:
        raise ValueError('register ordinary target cannot use causal observation')
    _verify_generated_session(base)


def _verify_persistent_mode(manifest,contract):
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_pulp_dual_source_source_action_gate,pulp_live_memory_policy_declaration,
        result_slot_ram_location,dual_source_wiring,CPU_PROFILE)
    component=dual_source_wiring(cpu_profile=CPU_PROFILE).memory_component
    memory_id,offset=result_slot_ram_location()
    runner=manifest['runner']
    evidence=dict(schema_version='memory_dependency_configuration.v1',runtime_contract_sha256=contract,
        components=[component],max_records=256,max_writer_versions=4096,max_event_gap=4096)
    gate=dict(schema_version='persistent_memory_prerequisite_configuration.v1',max_actions=256,
        instruction_slot_policy=make_pulp_dual_source_source_action_gate(component=component).declaration(),
        dynamic_ram_policy=pulp_live_memory_policy_declaration(component=component,memory_id=memory_id,byte_offset=offset))
    cpu=runner['sessions'][component]['identity']
    if (_json(runner.get('memory_dependency_evidence'))!=_json(evidence) or
        _json(runner.get('persistent_memory_prerequisites'))!=_json(gate) or
        _json(cpu.get('memory_commit_stream'))!=_json(dict(schema_version='memory_write_commit_stream.v1',capacity=256)) or
        _json(cpu.get('memory_read_issuance'))!=_json(dict(schema_version='memory_read_authority.v1',capacity=256))):
        raise ValueError('register persistent memory identity mismatch')


def _authenticated_bytes(output,name,identity):
    path=output/name
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output.resolve()):
        raise ValueError('register authenticated artifact path mismatch: '+name)
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=identity.get('artifacts',{}).get(name):
        raise ValueError('register authenticated artifact changed: '+name)
    return raw


def _validate_saved_register_documents(document,state):
    from myfuzz.scenario.session_runtime import validate_register_program_plan,validate_register_program_state
    registers=validate_register_program_plan(document)
    return validate_register_program_state(state,registers)


def _bootstrap_selection(assembly=None):
    """The validated minimal-bootstrap declaration, or ``None`` for the shipped one.

    The selector is read only from the closed assembly the authenticated bundle
    declared, and ``None`` is the shipped bootstrap and the pre-selector call
    shape.  No path, name or saved byte ever selects anything: the declaration
    that comes back is a rebuild of the current code-owned fixture.
    """
    if assembly is None:
        return None
    from myfuzz.scenario.ibex_pulp_dual_source import validate_minimal_bootstrap_declaration
    document=validate_register_assembly(assembly)
    if 'bootstrap_selector' not in document:
        return None
    return validate_minimal_bootstrap_declaration(document['bootstrap_declaration'])


def _verify_bootstrap_plan(document,assembly=None):
    """Rebuild the selected code-owned bootstrap and compare the saved plan.

    ``assembly`` is the closed register assembly the authenticated bundle
    declared; ``None`` is the shipped bootstrap, which is also the pre-existing
    call shape.  Both branches rebuild from current code -- saved bytes are
    comparison data only -- and the minimal branch additionally re-decodes its
    produced fixture through :func:`minimal_bootstrap_declaration` and compares
    the result with the declaration the assembly pinned, so a selector that
    cannot deliver the declared bytes (including a reintroduced removed write)
    is refused instead of quietly running the shipped image.
    """
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_minimal_bootstrap,
        make_ibex_pulp_dual_source_stream_bootstrap,minimal_bootstrap_declaration)
    from myfuzz.scenario.genome import GenomeCodec
    declared=_bootstrap_selection(assembly)
    if declared is None:
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    else:
        bootstrap=make_ibex_pulp_dual_source_minimal_bootstrap()
        if _json(minimal_bootstrap_declaration(bootstrap))!=_json(declared):
            raise ValueError('register minimal bootstrap declaration mismatch')
    template=json.loads(GenomeCodec.encode(bootstrap.template))
    slots=[['cpu',bootstrap.instruction_start,bootstrap.instruction_count]]
    if _json(document.get('template'))!=_json(template) or _json(document.get('instruction_slots'))!=_json(slots):
        raise ValueError('register selector requires fixed bootstrap and instruction slots')


def _verified_register_bundle(output,identity,plan):
    if identity is None or identity.get('execution_mode')!='register_programs':
        raise ValueError('register replay requires verified register bundle')
    try:
        config=identity['run_config']
        if set(config)!= {'register_program_assembly','register_program_source_files','register_program_state_sha256','rfuzz_client_executed'} or config['rfuzz_client_executed'] is not False:
            raise ValueError('register bundle run configuration mismatch')
        assembly=validate_register_assembly(config['register_program_assembly'])
        if _json(config['register_program_source_files'])!=_json(_sources(assembly)):
            raise ValueError('register selector source identity mismatch')
        manifest=json.loads(_authenticated_bytes(output,'online_session_manifest.json',identity))
        document=json.loads(plan)
        if type(document.get('schema_version')) is not int or document['schema_version'] not in (16,17,18,19):
            raise ValueError('register selector requires schema16/17/18/19')
        if manifest.get('checker') is not None or manifest.get('runtime_paths') is not None:
            raise ValueError('register selector requires directed checker-free Session')
        _verify_capability_channel(assembly,document,manifest)
        _verify_ordinary_channel(assembly,document,manifest)
        _verify_register_verifier_channel(assembly,document,manifest)
        _verify_register_reset_default_channel(assembly,document,manifest)
        configuration=document['register_programs']['configuration']
        _verify_assembly_configuration(assembly,configuration)
        if _json(configuration)!=_json(manifest['register_program_configuration']):
            raise ValueError('register plan and manifest configuration mismatch')
        state_path=output/'corpus/register_program_state.json'
        raw=_authenticated_bytes(output,'corpus/register_program_state.json',identity)
        if hashlib.sha256(raw).hexdigest()!=config['register_program_state_sha256']:
            raise ValueError('register terminal state digest mismatch')
        state=_validate_saved_register_documents(document,json.loads(raw))
        _verify_bootstrap_plan(document,assembly)
        if _json(state['configuration'])!=_json(configuration):
            raise ValueError('register state configuration mismatch')
        if _json(json.loads(_authenticated_bytes(output,'corpus/register_program_assembly.json',identity)))!=_json(assembly):
            raise ValueError('register saved assembly mismatch')
        # Profile paths are enrolled local selectors, never saved file authority.
        from myfuzz.scenario.ibex_pulp_dual_source import CPU_PROFILE,GPIO_PROFILE
        sessions=manifest['runner']['sessions']
        if set(sessions)!= {'cpu','gpio_a','gpio_b'}:
            raise ValueError('register three-session composition required')
        for name,record in sessions.items():
            artifact=record['identity']['runtime_artifact']; artifact_plan=artifact['plan']
            if (artifact['kind']!=('obi_cpu' if name=='cpu' else 'apb_gpio') or
                artifact_plan['profile_path']!=(CPU_PROFILE if name=='cpu' else GPIO_PROFILE) or
                artifact_plan['instance_id']!=name or
                artifact_plan['request_schema_version']!='local_harness.v2' or
                artifact_plan['tuning']['raw_tick_stream']!=[{'sampling':'pre_post'}]):
                raise ValueError('register native ordinary profile mode mismatch')
        from . import ibex_pulp_online as online
        ordinary='ordinary_apb_access_evidence' in assembly
        if ordinary:
            # The legacy generated-session verifier intentionally has no new
            # optional observation identity. Validate that extension separately,
            # then regenerate every unchanged base artifact through its verifier.
            targets=document['register_programs']['ordinary_apb_access_evidence']['configuration']['targets']
            for name in ('gpio_a','gpio_b'):
                _verify_ordinary_gpio_identity(name,sessions[name]['identity'],targets[name])
        for helper,expected in ((online._saved_cpu_retirement_mode,False),
                (online._saved_gpio_consumption_mode,False),(online._saved_pin8_native_irq_mode,False),
                (online._saved_memory_commit_mode,True)):
            if ordinary and helper is online._saved_gpio_consumption_mode:
                continue
            if helper(output,identity) is not expected:
                raise ValueError('register observation mode mismatch')
        _verify_persistent_mode(manifest,assembly['runtime_contract_sha256'])
        return assembly,state
    except (KeyError,TypeError) as error:
        raise ValueError('register bundle missing or malformed') from error


@dataclass(frozen=True)
class RegisterReplayResult:
    comparison: object
    capability_preflight: object = None
    verification_scope: tuple = ('register_program_reconstruction','register_program_admission','online_complete_prefix')
    ordinary_apb_access_evidence: object = None
    register_program_verifier: object = None
    register_reset_default: object = None

    @property
    def matches(self):
        return self.comparison.matches


def _validate_reference(trace):
    from myfuzz.scenario.session_runtime import _trace_semantic_sha256
    if _trace_semantic_sha256(trace.status,trace.events,dict(trace.local_ticks))!=trace.semantic_sha256:
        raise ValueError('register reference trace semantic mismatch')


def _fresh_register_verifier(session, registers):
    expected=registers.get('register_program_verifier')
    actual=session.register_program_verifier_document() if expected is not None else None
    if _json(actual)!=_json(expected):
        raise ValueError('register verifier fresh terminal state mismatch')
    return actual


def _fresh_register_reset_default(session, registers):
    expected=registers.get('register_reset_default')
    actual=session.register_reset_default_document() if expected is not None else None
    if _json(actual)!=_json(expected):
        raise ValueError('register reset default fresh terminal state mismatch')
    return actual


def _register_file_preflight(*, output):
    from myfuzz.local_harness.build import host_source_discovery_scope
    with host_source_discovery_scope():
        return _register_file_preflight_unscoped(output=output)


def _register_file_preflight_unscoped(*, output):
    output=Path(output)
    trace_path,reference=_candidate_reference(output)
    identity=_verify_online_run_identity(output,plan_path=output/'online_plan.json',
        trace_path=trace_path,trace=reference)
    if identity is None:
        raise ValueError('register replay requires verified bundle')
    # Validate declaration before any factory construction or harness command.
    validate_register_assembly(identity.get('run_config',{}).get('register_program_assembly'))
    plan=_authenticated_bytes(output,'online_plan.json',identity)
    assembly,state=_verified_register_bundle(output,identity,plan)
    _validate_reference(reference)
    return reference,plan,assembly,state


def replay_ibex_pulp_register_files(*,cache_dir,output_dir):
    from myfuzz.scenario.session_runtime import replay_online_session
    reference,plan,assembly,state=_register_file_preflight(output=output_dir)
    factory=make_register_factory(cache_dir=cache_dir,assembly=assembly)
    captured=[]
    reports=[]
    install=make_register_runtime_factory(assembly)
    def runtime_factory(session):
        adapter=install(session);captured.append(adapter);reports.append(session._register_capability_preflight());return adapter
    comparison=replay_online_session(plan,factory,reference,checker=None,
        register_runtime_factory=runtime_factory)
    if len(captured)!=1 or _json(captured[0].snapshot())!=_json(state):
        raise ValueError('register fresh terminal state mismatch')
    expected=json.loads(plan)['register_programs'].get('ordinary_apb_access_evidence')
    ordinary=captured[0].session.runner.ordinary_apb_access_evidence_snapshot() if expected is not None else None
    if expected is not None and _json(ordinary)!=_json(expected['state']):
        raise ValueError('ordinary APB fresh terminal state mismatch')
    verifier=_fresh_register_verifier(captured[0].session,json.loads(plan)['register_programs'])
    reset_default=_fresh_register_reset_default(captured[0].session,json.loads(plan)['register_programs'])
    return RegisterReplayResult(comparison, reports[0], ordinary_apb_access_evidence=ordinary,
        register_program_verifier=verifier, register_reset_default=reset_default)


def save_ibex_pulp_register_bundle(*,output_dir,assembly,session_manifest,plan_bytes,trace,runtime_state):
    """Authenticate an owned directed prefix, with invocation-local source discovery."""
    from myfuzz.local_harness.build import host_source_discovery_scope
    with host_source_discovery_scope():
        return _save_ibex_pulp_register_bundle(output_dir=output_dir,assembly=assembly,
            session_manifest=session_manifest,plan_bytes=plan_bytes,trace=trace,runtime_state=runtime_state)


def _save_ibex_pulp_register_bundle(*,output_dir,assembly,session_manifest,plan_bytes,trace,runtime_state):
    """Save an owned directed prefix, authenticated by the existing run envelope.

    The transport compatibility files declare no RFuzz execution or causal decoder.
    """
    import sys
    d=validate_register_assembly(assembly)
    _validate_reference(trace)
    _verify_assembly_configuration(d,runtime_state['configuration'])
    document=json.loads(plan_bytes)
    runtime_state=_validate_saved_register_documents(document,runtime_state)
    if (type(document.get('schema_version')) is not int or document['schema_version'] not in (16,17,18,19) or
        _json(document['register_programs']['configuration'])!=_json(runtime_state['configuration']) or
        _json(session_manifest.get('register_program_configuration'))!=_json(runtime_state['configuration']) or
        session_manifest.get('checker') is not None or session_manifest.get('runtime_paths') is not None):
        raise ValueError('register writer configuration mismatch')
    _verify_capability_channel(d,document,session_manifest)
    _verify_ordinary_channel(d,document,session_manifest)
    _verify_register_verifier_channel(d,document,session_manifest)
    _verify_register_reset_default_channel(d,document,session_manifest)
    if 'ordinary_apb_access_evidence' in d:
        try:
            targets=document['register_programs']['ordinary_apb_access_evidence']['configuration']['targets']
            for name in ('gpio_a','gpio_b'):
                _verify_ordinary_gpio_identity(name,session_manifest['runner']['sessions'][name]['identity'],targets[name])
        except (KeyError,TypeError) as error:
            raise ValueError('register ordinary target observation identity mismatch') from error
    output=Path(output_dir)
    output.mkdir(parents=True,exist_ok=False)
    (output/'corpus').mkdir()
    def write(name,value):
        raw=(_json(value)+'\n').encode();(output/name).write_bytes(raw);return hashlib.sha256(raw).hexdigest()
    (output/'online_plan.json').write_bytes(plan_bytes)
    write('online_final_trace.json',dict(genome_sha256=trace.genome_sha256,status=trace.status,
        events=[dict(row) for row in trace.events],local_ticks=dict(trace.local_ticks),
        semantic_sha256=trace.semantic_sha256,manifest_sha256=trace.manifest_sha256))
    write('corpus/register_program_assembly.json',d)
    state_hash=write('corpus/register_program_state.json',runtime_state)
    write('decoder_manifest.json',dict(schema_version='directed_register_program_decoder.v1',
        decoder_executed=False,scope='original_register_requests_only'))
    write('targets.json',[])
    (output/'rfuzz.toml').write_text('# Compatibility artifact only; RFuzz client was not executed.\n')
    (output/'seed.bin').write_bytes(b'')
    identity_sha256=_write_online_run_identity(output,session_manifest=session_manifest,
        plan_bytes=plan_bytes,trace=trace,client_binary=Path(sys.executable),
        frozen_inputs=dict(collector=None,source_files=[],client=None),execution_mode='register_programs',
        run_config=dict(register_program_assembly=d,register_program_source_files=_sources(d),
            register_program_state_sha256=state_hash,rfuzz_client_executed=False))
    write('report.json',dict(online_run_identity_sha256=identity_sha256,
        scope='directed_register_program_saved_prefix',rfuzz_client_executed=False,
        functional_completion_verified=False,verified_level=None))
    return identity_sha256
