"""Closed declarations for the trusted local Ibex/PULP candidate assembly.

Declarations contain data only; they never select imported code or restore
candidate scores. Runtime selection is a separate admission step.
"""
import re
import hashlib
import json
from pathlib import Path


ASSEMBLY_SCHEMA = 'ibex_pulp_candidate_assembly.v1'
ASSEMBLY_SCHEMA_V2 = 'ibex_pulp_feedback_assembly.v2'
_BOOLEAN_FIELDS = frozenset((
    'cpu_retirement', 'gpio_consumption', 'native_irq_receipts',
    'source_actions', 'memory_commit_receipts', 'persistent_memory_prerequisites',
    'ip_cross_case', 'result_slot_byte_store', 'closed_loop_energy',
    'path_switch', 'initial_ram_data',
))
_FIELDS = _BOOLEAN_FIELDS | frozenset((
    'schema_version', 'run_id', 'feedback_interval', 'max_warmup_rounds',
    'candidate_exploration_max_cases', 'initial_ram_data_source',
    'initial_ram_record_hex',
))


def validate_candidate_assembly(document):
    """Return a detached, closed declaration or reject it before construction."""
    def reject(reason):
        raise ValueError('candidate assembly: ' + reason)

    version2 = type(document) is dict and document.get('schema_version') == ASSEMBLY_SCHEMA_V2
    fields = _FIELDS | {'candidate_exploration', 'classified_feedback', 'classified_feedback_max_records'} if version2 else _FIELDS
    if type(document) is not dict or set(document) != fields:
        reject('expected the complete closed field set')
    if document['schema_version'] not in (ASSEMBLY_SCHEMA, ASSEMBLY_SCHEMA_V2):
        reject('unsupported schema')
    if type(document['run_id']) is not str or not document['run_id']:
        reject('run_id must be a nonempty string')
    if version2:
        for key in ('candidate_exploration', 'classified_feedback'):
            if type(document[key]) is not bool: reject(key + ' must be boolean')
        if not (document['candidate_exploration'] or document['classified_feedback']): reject('at least one feedback channel required')
        if type(document['classified_feedback_max_records']) is not int or not 1 <= document['classified_feedback_max_records'] <= 65536: reject('classified feedback capacity invalid')
    for field in _BOOLEAN_FIELDS:
        if type(document[field]) is not bool:
            reject(field + ' must be boolean')
    for field in ('feedback_interval', 'max_warmup_rounds'):
        if type(document[field]) is not int or document[field] < 1:
            reject(field + ' must be a positive integer')
    cap = document['candidate_exploration_max_cases']
    if type(cap) is not int or not 1 <= cap <= 65536:
        reject('candidate_exploration_max_cases must be 1..65536')
    source = document['initial_ram_data_source']
    if type(source) is not str or source not in ('default', 'constructor', 'environment'):
        reject('unsupported initial RAM source')
    if source == 'default' and document['initial_ram_data']:
        reject('default initial RAM declaration must be disabled')
    raw = document['initial_ram_record_hex']
    if type(raw) is not str or re.fullmatch(r'(?:[0-9a-f]{2})+', raw) is None:
        reject('initial RAM record must be nonempty lowercase byte hex')
    if document['native_irq_receipts'] and not document['cpu_retirement']:
        reject('native IRQ receipts require RVFI retirement')
    if document['persistent_memory_prerequisites'] and not (
            document['source_actions'] and document['memory_commit_receipts']):
        reject('persistent memory requires source actions and commit receipts')
    return dict(document)


def _verified_assembly(output, identity):
    """Select only the shipped local composition from verified data."""
    from . import ibex_pulp_online as online
    from myfuzz.scenario.ibex_pulp_dual_source import CPU_PROFILE, RVFI_CPU_PROFILE
    from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
    from myfuzz.scenario.session_runtime import _checker_identity
    try:
        config = identity['run_config']
        declaration = validate_candidate_assembly(config['online_assembly'])
        if ((declaration.get('candidate_exploration', True) != ('candidate_exploration' in config))
                or declaration.get('classified_feedback', False) != ('classified_feedback' in config)):
            raise ValueError('feedback assembly switch disagrees with run configuration')
        for field in ('run_id', 'feedback_interval', 'closed_loop_energy', 'path_switch'):
            if type(config[field]) is not type(declaration[field]) or config[field] != declaration[field]:
                raise ValueError('candidate assembly disagrees with run configuration')
        path = output / 'online_session_manifest.json'
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != identity['artifacts'][path.name]:
            raise ValueError('candidate assembly manifest changed after verification')
        manifest = json.loads(raw)
        if manifest['checker'] != _checker_identity(IbexPulpOnlineChecker(), configuration_only=True):
            raise ValueError('candidate assembly requires the shipped checker')
        sessions = manifest['runner']['sessions']
        if set(sessions) != {'cpu', 'gpio_a', 'gpio_b'}:
            raise ValueError('candidate assembly requires the shipped three sessions')
        cpu = sessions['cpu']['identity']
        cpu_plan = cpu['runtime_artifact']['plan']
        if cpu_plan['profile_path'] != (RVFI_CPU_PROFILE if declaration['cpu_retirement'] else CPU_PROFILE):
            raise ValueError('candidate assembly CPU profile is unsupported')
        for component, session in sessions.items():
            artifact = session['identity']['runtime_artifact']
            if (artifact['kind'] != ('obi_cpu' if component == 'cpu' else 'apb_gpio')
                    or artifact['plan']['instance_id'] != component
                    or artifact['plan']['request_schema_version'] != 'local_harness.v2'
                    or artifact['plan']['tuning']['raw_tick_stream'] != [{'sampling': 'pre_post'}]
                    or artifact['base_event_schema_version'] != 'ip_base_event.v1'
                    or artifact['raw_observation_schema_version'] != 'ip_raw_observation.v1'
                    or artifact['native_physical_observation_contract']['schema_version']
                       != 'native_physical_observation.v1'):
                raise ValueError('candidate assembly requires native physical observations')
        if cpu.get('cpu_physical_tick_stream') != {
                'schema_version': 'cpu_physical_tick_stream.v1', 'capacity': 256,
                'sampling': 'pre_post'}:
            raise ValueError('candidate assembly requires the CPU physical tick stream')
        for field, helper in (
            ('cpu_retirement', online._saved_cpu_retirement_mode),
            ('gpio_consumption', online._saved_gpio_consumption_mode),
            ('native_irq_receipts', online._saved_pin8_native_irq_mode),
            ('memory_commit_receipts', online._saved_memory_commit_mode),
        ):
            if helper(output, identity) != declaration[field]:
                raise ValueError('candidate assembly observation mode mismatch: ' + field)
        if (online._saved_persistent_memory_mode(output, identity) is not None
                ) != declaration['persistent_memory_prerequisites']:
            raise ValueError('candidate assembly persistent memory mode mismatch')
        return declaration
    except (KeyError, TypeError) as exc:
        raise ValueError('candidate assembly is missing or malformed') from exc


def _fresh_executor(cache_dir, declaration):
    from .ibex_pulp_online import make_pulp_dual_source_online_runtime
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_stream_bootstrap,
        make_ibex_pulp_dual_source_online_decoder, make_ibex_pulp_dual_source_factory,
    )
    d = validate_candidate_assembly(declaration)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=bootstrap, result_slot_readback=True, ip_cross_case=d['ip_cross_case'],
        **({'result_slot_byte_store': True} if d['result_slot_byte_store'] else {}))
    factory = make_ibex_pulp_dual_source_factory(Path(cache_dir),
        cpu_retirement=d['cpu_retirement'], gpio_consumption=d['gpio_consumption'],
        physical_observations=True, source_actions=d['source_actions'],
        **({'native_irq_receipts': True} if d['native_irq_receipts'] else {}),
        **({'memory_commit_receipts': True} if d['memory_commit_receipts'] else {}),
        **({'persistent_memory_runtime_contract_sha256': decoder.runtime_contract.identity_sha256}
           if d['persistent_memory_prerequisites'] else {}))
    runtime = make_pulp_dual_source_online_runtime(
        bootstrap=bootstrap, decoder=decoder, factory=factory, run_id=d['run_id'],
        feedback_interval=d['feedback_interval'], max_warmup_rounds=d['max_warmup_rounds'],
        source_actions=d['source_actions'], candidate_exploration=d.get('candidate_exploration', True),
        classified_feedback=d.get('classified_feedback', False),
        classified_feedback_max_records=d.get('classified_feedback_max_records', 4096),
        candidate_exploration_max_cases=d['candidate_exploration_max_cases'],
        initial_ram_record=bytes.fromhex(d['initial_ram_record_hex']),
        initial_ram_data_resolution=(d['initial_ram_data'], d['initial_ram_data_source']),
        closed_loop_energy=d['closed_loop_energy'], path_switch=d['path_switch'])
    try:
        runtime.executor.set_online_assembly_configuration(d)
    except BaseException as error:
        try:
            runtime.session.finish()
        except BaseException as cleanup:
            error.add_note('candidate assembly cleanup failed: ' + str(cleanup))
        raise
    return runtime.executor


def replay_ibex_pulp_candidate_files(*, cache_dir, output_dir):
    """Verify the bundle, then recompute selection and scoring with local code."""
    from .scenario_rfuzz_replay import _candidate_reference, replay_candidate_exploration_files
    from .scenario_rfuzz_live import _verify_online_run_identity
    output = Path(output_dir)
    trace_path, reference = _candidate_reference(output)
    identity = _verify_online_run_identity(output, plan_path=output / 'online_plan.json',
                                         trace_path=trace_path, trace=reference)
    if (identity is None or identity.get('execution_mode') != 'online_cases'
            or not any(k in identity.get('run_config', {}) for k in ('candidate_exploration', 'classified_feedback'))):
        raise ValueError('candidate assembly requires a verified enabled online bundle')
    declaration = _verified_assembly(output, identity)
    return replay_candidate_exploration_files(output,
        executor_factory=lambda: _fresh_executor(cache_dir, declaration))
