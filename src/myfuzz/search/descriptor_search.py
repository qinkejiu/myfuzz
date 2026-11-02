"""Descriptor search routing, with explicit unknown-state catalog fallback.

Only registered APB storage has a live state provider. Other executors retain
all admission/replay checks of generic_campaign; scheduling there is documentary.
"""
from dataclasses import asdict, replace
from hashlib import sha256
import json
import math
from pathlib import Path

from .actions import Action, Catalog
from .model import Condition, Goal, Snapshot
from .policy import Policy


def _save(path, value):
    from .workflow import candidate_summary
    if Path(path).name == 'search-summary.json':
        value = candidate_summary(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def _remember_failure(output, context, error):
    if not output.is_dir():
        return
    try:
        _save(output / 'failure-context.json', context)
    except (OSError, ValueError, TypeError) as capture_error:
        error.add_note('failure input context unavailable: ' + str(capture_error))


def _reproduce_failure(output, error):
    from .failure_replay import export_failure_specimen, launch_failure_replay
    context_path = output / 'failure-context.json'
    if not context_path.is_file():
        return
    context = json.loads(context_path.read_text())
    specimen = export_failure_specimen(output, error=error, **context)
    if specimen['status'] == 'ready':
        result = launch_failure_replay(output / 'failure-specimen.json', output / 'failure-reproduction')
    else:
        result = {'status': 'refused', 'reason': specimen.get('reason'), 'accepted': False, 'dut_bug': False}
    _save(output / 'failure-replay.json', result)


def _live(descriptor, flow):
    return (flow in (None, 'mixed') and set(descriptor.flow_ids) == {'F2', 'F4'}
            and descriptor.executor('F2') == 'compiled_f2_obi_apb'
            and descriptor.executor('F4') == 'compiled_f4_obi_apb')


def _flow(descriptor, flow):
    if flow is not None:
        return flow
    return descriptor.flow_ids[0] if len(descriptor.flow_ids) == 1 else 'mixed'


def _memory_records(flow, records):
    """Map single memory inputs to the existing mixed runtime's typed records."""
    if not records:
        raise ValueError('single memory flow requires explicit records')
    rows = [row if ':' in row else f'{flow}:{row}' for row in records]
    if any(not row.startswith(flow + ':') for row in rows):
        raise ValueError('record flow differs from requested memory flow')
    return rows


class RecordSelector:
    """Choose one public record at a time; unknown results earn no reward."""
    def __init__(self, descriptor, *, flow, records, policy, seed, cases):
        rows = (list(records) if records else [f'{f}:{r}' for f in
                (descriptor.flow_ids if flow == 'mixed' else (flow,)) for r in descriptor.records(f)])
        self.rows = list(dict.fromkeys(row if ':' in row else f'{flow}:{row}' for row in rows))
        if not self.rows or len(self.rows) > 64:
            raise ValueError('fallback requires 1..64 distinct public records')
        self.catalog = Catalog(tuple(Action(f'record:{i}:{sha256(row.encode()).hexdigest()}', row.split(':', 1)[0],
            row.split(':', 1)[0], ('execution-observation',), (), (i,)) for i, row in enumerate(self.rows)))
        self.goal = Goal('descriptor-execution', 'execution-observation', (Condition('execution-observation'),))
        self.scheduler = Policy(seed=seed, mode=policy, max_decisions=max(cases, 1))
        self.sequence, self.decisions, self.pending = [], [], None

    def checkpoint(self):
        from copy import deepcopy
        return deepcopy(self.scheduler)

    def restore(self, checkpoint):
        self.scheduler, self.pending = checkpoint, None

    def choose(self):
        if self.pending is not None:
            raise ValueError('previous decision pending')
        decision = self.scheduler.choose(self.goal, Snapshot(len(self.sequence), {}), self.catalog)
        row = self.rows[decision.value]
        self.pending = (row, decision)
        return row

    def settle(self, row):
        if self.pending is None or self.pending[0] != row:
            raise ValueError('unexpected completed record')
        _, decision = self.pending
        self.scheduler.settle(decision.id, {}, 1, censored=True)
        self.sequence.append(row)
        self.decisions.append(decision.document())
        self.pending = None

    def document(self):
        return {'sequence': list(self.sequence), 'decisions': list(self.decisions),
                'catalog_sha256': self.catalog.identity, 'catalog': [asdict(a) for a in self.catalog.actions],
                'state_observation': 'unknown', 'live_state_conditioned': False,
                'statistics': self.scheduler.statistics()}


def select_records(descriptor, *, flow, records, policy, seed, cases):
    """Select finite record indices; never interpret packed records as uint32."""
    selector = RecordSelector(descriptor, flow=flow, records=records, policy=policy, seed=seed, cases=cases)
    for _ in range(cases):
        selector.settle(selector.choose())
    return selector.document()


def preflight_scenario(config, root):
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    root = Path(root).resolve()
    descriptor = load_descriptor(root / config['descriptor'], base_dir=root)
    flow = _flow(descriptor, config.get('flow'))
    live = _live(descriptor, flow) and not config.get('records')
    from .ram_case_adapter import ram_records
    ram_live = flow == 'mixed' and ram_records(config.get('records'))
    from .pin_case_adapter import pin_records
    pin_live=flow=='mixed' and {'F2','F5'} <= set(descriptor.flow_ids) and pin_records(config.get('records'))
    from .single_storage import supports_single_storage, SingleStorageRecordSelector
    single_live = supports_single_storage(descriptor, flow)
    from .shared_slot_ram_adapter import shared_slot_records
    shared_live = descriptor.shared_slots and flow == 'mixed' and shared_slot_records(config.get('records'))
    shared_pin = shared_live
    if shared_live:
        supplement = json.loads(descriptor.supplement.read_text())
        marker = supplement.get('request_supplements', {}).get('f6_execution', {})
        slots = marker.get('shared_slots', {})
        if 'read_register' in slots:
            shared_pin = (slots['read_register'] == 'PADIN'
                and slots.get('component') == marker.get('gpio_irq', {}).get('component'))
    if single_live:
        SingleStorageRecordSelector(descriptor, flow=flow, records=config.get('records'), policy='state', seed=7, cases=1)
    if not live:
        rows = config.get('records')
        if flow in ('F1', 'F3'):
            select_case_records(descriptor, flow='mixed', records=_memory_records(flow, rows))
        elif flow in ('F5', 'F6') and rows:
            for row in rows:
                select_case_records(descriptor, flow=flow, records=[row])
        else:
            if flow == 'mixed' and not rows:
                rows = [f'{f}:{r}' for f in descriptor.flow_ids for r in descriptor.records(f)]
            if rows and flow not in ('mixed', 'F5', 'F6'):
                select_records(descriptor, flow=flow, records=rows, policy='state', seed=7, cases=1)
            else:
                select_case_records(descriptor, flow=flow, records=rows)
    return {'scenario': descriptor.scenario_id, 'flow': flow,
            'backend': 'storage' if live or single_live else 'pin' if pin_live else 'ram' if ram_live else 'descriptor',
            'search_backend': ('live-shared-ram-pin' if shared_pin else 'live-shared-ram-target') if shared_live else 'live-storage' if live else 'live-gpio-pin' if pin_live else 'live-ram' if ram_live else 'live-storage-single-flow' if single_live else 'record-catalog',
            'state_observation': 'live' if live or ram_live or single_live or pin_live or shared_live else 'unknown',
            'live_state_conditioned': live or ram_live or single_live or pin_live or shared_live, 'native_executed': False,  'shared_catalog_identity': None if live else 'sha256:' + sha256(json.dumps(config.get('records') or [descriptor.records(f) for f in descriptor.flow_ids], sort_keys=True).encode()).hexdigest(),
            'catalog_materialized': False,
            'catalog_identity_scope': 'awaiting-compiled-source-binding' if live else 'descriptor-record-domain',
            'consumption_provider': ('installed_shared_slot_ram_and_PADIN.v1' if shared_pin else 'installed_shared_slot_ram.v1') if shared_live else 'installed_GPIO_PADIN_native_read.v1' if pin_live else 'installed_host_ram_versions_with_native_obi_read.v1' if ram_live else None,
            'cross_testcase_consumption': 'unsupported-no-read-only-flow' if single_live else 'not-assessed',
            'capabilities': {'incremental_state': live or ram_live or single_live or pin_live or shared_live, 'executor_within_invocation_replay': True,
                             'strict_cross_invocation_replay': True,
                             'wall_budget': True,
                             'max_cases': 4096 if pin_live else 16 if descriptor.shared_slots or flow in ('F5', 'F6') else 65536 if live else 65535}}


def _configured_files(descriptor, base):
    """Read configured component profiles and their declared source material.

    These content identities describe the selected inputs. Runtime admission
    remains the executor's responsibility; file hashes issue no certificate.
    """
    compose = json.loads(descriptor.compose.read_text())
    files, profiles = set(), set()
    def member(parent, value):
        path = (parent / value).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            raise ValueError('configured identity file missing or outside base_dir: ' + str(path))
        return path
    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get('request'), str):
                request = member(descriptor.compose.parent, value['request'])
                files.add(request)
                document = json.loads(request.read_text())
                profile = member(base, document['profile_path'])
                files.add(profile)
                profiles.add(profile)
                source = json.loads(profile.read_text())['source']
                source_root = (base / source['root']).resolve()
                for name in source.get('files', ()):
                    files.add(member(source_root, name))
                for name in source.get('include_roots', ()):
                    include = (source_root / name).resolve()
                    if not include.is_relative_to(base) or not include.is_dir():
                        raise ValueError('configured include root missing or outside base_dir')
                    files.update(p.resolve() for p in include.rglob('*')
                                 if p.is_file() and p.suffix in ('.v', '.sv', '.vh', '.svh', '.h'))
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(compose)
    if not profiles:
        raise ValueError('configured component profiles unavailable')
    return files, profiles


def _identity(descriptor, frozen, profiles, catalog_sha256):
    encoded = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    profile_rows = [{'path': str(p), 'sha256': sha256(p.read_bytes()).hexdigest()}
                    for p in sorted(profiles)]
    return {'target': descriptor.scenario_id,
            'source': 'sha256:' + sha256(encoded(frozen)).hexdigest(),
            'profile': 'sha256:' + sha256(encoded(profile_rows)).hexdigest(),
            'catalog_sha256': catalog_sha256, 'coverage_metric': None}


def _unknown_metrics(mode):
    return {'certified_events': None, 'useful_case_events': None,
            'interaction_status': 'unknown-no-timed-certified-evidence',
            'fresh': {'status': 'verified' if mode == 'fresh' else 'not-run'}}


def _live_coverage_metric(live_kind, selection):
    if live_kind == 'shared':
        return ('certified-shared-ram-and-gpio-consumption.v1'
                if selection['search_backend'] == 'live-shared-ram-pin'
                else 'certified-shared-ram-consumption.v1')
    return 'certified-gpio-pin-padin-read.v1' if live_kind == 'pin' else 'certified-ram-dut-read.v1'


def _manifest(descriptor, descriptor_path, base):
    capabilities = descriptor.capability if isinstance(descriptor.capability, tuple) else (descriptor.capability,)
    files = [Path(descriptor_path), descriptor.compose, descriptor.supplement, *capabilities]
    configured, _ = _configured_files(descriptor, base)
    files.extend(configured)
    files += sorted((base / 'src/myfuzz').rglob('*.py'))
    record_sidecar = descriptor.root / 'f2_read_records.json'
    if record_sidecar.is_file():
        files.append(record_sidecar)
    return [{'path': str(p.resolve()), 'sha256': sha256(p.read_bytes()).hexdigest()}
            for p in sorted(set(files))]


def _execution_index(rows, minimum=2):
    if not isinstance(rows, (list, tuple)) or not rows:
        raise ValueError('actual native execution identities unavailable')
    groups, nonces = {}, set()
    fields = ('build_digest', 'binary_sha256', 'artifact_digest', 'manifest_sha256')
    for row in rows:
        component, nonce = row.get('component'), row.get('execution_nonce')
        if not isinstance(component, str) or not component:
            raise ValueError('actual native component missing')
        if (type(nonce) is not str or len(nonce) != 32
                or any(c not in '0123456789abcdef' for c in nonce) or nonce in nonces):
            raise ValueError('actual native nonce invalid or reused')
        nonces.add(nonce)
        if (row.get('reaped') is not True or type(row.get('exit_code')) is not int
                or row['exit_code'] != 0 or type(row.get('pid')) is not int or row['pid'] <= 0):
            raise ValueError('actual native exit not cleanly reaped')
        if any(type(row.get(k)) is not str or len(row[k]) != 64
               or any(c not in '0123456789abcdef' for c in row[k]) for k in fields):
            raise ValueError('actual native build binding missing')
        groups.setdefault(component, []).append(tuple(row[k] for k in fields))
    if any(len(values) < minimum or len(set(values)) != 1 for values in groups.values()):
        raise ValueError('original/fresh native build binding missing or inconsistent')
    return {key: (len(value), value[0]) for key, value in groups.items()}, nonces


def validate_execution_prefixes(original, fresh, *, original_replay=True, fresh_replay=True):
    """Compare observed, completed executions; saved rows grant no authority."""
    old, old_nonces = _execution_index(original, 2 if original_replay else 1)
    new, new_nonces = _execution_index(fresh, 2 if fresh_replay else 1)
    if old_nonces & new_nonces:
        raise ValueError('cross-invocation native nonce reused')
    if (old != new if original_replay == fresh_replay else
            {key: value[1] for key, value in old.items()} != {key: value[1] for key, value in new.items()}):
        raise ValueError('cross-invocation component/build binding differs')


def _prefix_identity(out, flow, summary):
    if flow == 'F5' and json.loads((out / 'prefix.json').read_text()).get('schema_version') != 'compiled_storage_mixed_prefix.v1':
        prefix = json.loads((out / 'prefix.json').read_text())
        document = {'semantic_sha256': prefix['semantic_sha256'],
                    'genome_sha256': prefix['genome_sha256'],
                    'manifest_sha256': prefix['manifest_sha256'],
                    'plan_sha256': sha256((out / 'online_plan.json').read_bytes()).hexdigest()}
    elif flow == 'F6' or summary.get('shared_slots') is True:
        from myfuzz.integration.compiled_f6 import _canonical, _normalized_f6_prefix
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256

        prefix = json.loads((out / 'compiled_f6_prefix.json').read_text())
        if summary.get('shared_slots') is True:
            records = prefix.get('flow_records')
            if type(records) is not list or len(records) != summary.get('case_count'):
                raise ValueError('shared slot actual flow count differs from its summary')
        # Authenticate the raw trace before applying the same narrow nonce and
        # commit projection as the existing full native F6 replay. Raw semantic
        # hashes bind actual process nonces and cannot be compared directly.
        if _trace_semantic_sha256(prefix['trace_status'], prefix['actual_events'],
                                 prefix['trace_local_ticks']) != prefix['semantic_hash']:
            raise ValueError('F6 actual semantic hash does not bind its trace')
        plan_sha256 = sha256(_canonical(prefix['online_plan']).encode('utf-8')).hexdigest()
        if plan_sha256 != prefix['trace_genome_sha256']:
            raise ValueError('F6 actual genome hash does not bind its online plan')
        normalized = _normalized_f6_prefix(prefix)
        document = {
            'normalized_prefix_sha256': sha256(_canonical(normalized).encode('utf-8')).hexdigest(),
            'trace_genome_sha256': prefix['trace_genome_sha256'],
            'trace_manifest_sha256': prefix['trace_manifest_sha256'],
            'compiled_document_sha256': prefix['compiled_document_sha256'],
            'plan_sha256': plan_sha256}
    else:
        prefix = json.loads((out / 'prefix.json').read_text())
        document = {'semantic_hash': prefix['semantic_hash'],
                    'plan_sha256': summary['plan_identity_sha256']}
    if any(not isinstance(value, str) or len(value) != 64
           or any(c not in '0123456789abcdef' for c in value) for value in document.values()):
        raise ValueError('actual semantic prefix or plan digest unavailable')
    return document


def execute(*, descriptor_path, base_dir, output, mode='original', policy='state',
            cases=6, seconds=None, seed=7, cache=None, flow=None, rounds=None,
            records=None, record_local_commands=False, execution_mode=None):
    from myfuzz.local_harness.session import record_local_commands as capture
    from .workflow import run_boundary
    out = Path(output) / mode
    preexisting = out.exists() or out.is_symlink()
    with capture(capture_records=record_local_commands) as trace:
        arguments = dict(descriptor_path=descriptor_path, base_dir=base_dir, output=output,
            mode=mode, policy=policy, cases=cases, seconds=seconds, seed=seed,
            cache=cache, flow=flow, rounds=rounds, records=records, command_trace=trace)
        if execution_mode is not None:
            arguments['execution_mode'] = execution_mode
        run = lambda: _execute(**arguments)
        try:
            return run_boundary(out, run, execution_mode=execution_mode, mode=mode) if execution_mode is not None else run()
        except Exception as error:
            if execution_mode == 'search' and mode == 'original' and not preexisting:
                try:
                    _reproduce_failure(out, error)
                except Exception as replay_error:
                    error.add_note('failure reproduction unavailable: ' + repr(replay_error))
            raise


def _execute(*, descriptor_path, base_dir, output, mode='original', policy='state',
            cases=6, seconds=None, seed=7, cache=None, flow=None, rounds=None, records=None, command_trace=None,
            execution_mode=None):
    """Execute a descriptor with common policy/configuration and refusal gates."""
    if mode not in ('original', 'fresh') or policy not in ('state', 'uniform', 'legacy'):
        raise ValueError('invalid mode or policy')
    if type(cases) is not int or not 1 <= cases <= 65536 or type(seed) is not int:
        raise ValueError('invalid cases or seed')
    if seconds is not None and (type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0):
        raise ValueError('seconds must be finite and positive')
    base, output = Path(base_dir).resolve(), Path(output).resolve()
    if (output / mode).exists() or (output / mode).is_symlink():
        raise ValueError('existing output must never be overwritten')
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor, select_case_records
    descriptor_path = Path(descriptor_path)
    if not descriptor_path.is_absolute():
        descriptor_path = base / descriptor_path
    descriptor = load_descriptor(descriptor_path, base_dir=base)
    flow = _flow(descriptor, flow)
    frozen = _manifest(descriptor, descriptor_path, base)
    _, profiles = _configured_files(descriptor, base)
    live = _live(descriptor, flow) and not records
    from .workflow import requires_replay
    perform_replay = requires_replay(execution_mode, mode)
    if mode == 'fresh':
        sidecar = output / 'original/search-summary.json'
        if sidecar.is_file():
            saved = json.loads(sidecar.read_text())
            boundary = saved.get('verification', {}).get('session_boundary')
            if boundary is not None and (boundary.get('status') != 'verified' or boundary.get('matches') is not True):
                raise ValueError('original execution boundary is not verified')
    if live:
        from .native import execute as native_execute
        if mode == 'fresh':
            reference = json.loads((output / 'original' / 'descriptor-manifest.json').read_text())
            if reference['sources'] != frozen:
                raise ValueError('fresh descriptor/source manifest mismatch')
            if sha256((output / 'original' / 'summary.json').read_bytes()).hexdigest() != reference['summary_sha256']:
                raise ValueError('fresh original summary binding mismatch')
        try:
            result = native_execute(descriptor_path=descriptor_path, case_root=output,
                mode=mode, seed=seed, cases=cases, strategy=policy,
                rounds=descriptor.rounds if rounds is None else rounds, base_dir=base,
                restrict_output=False, cache_dir=cache, seconds=seconds, command_trace=command_trace,
                **({'execution_mode': execution_mode} if execution_mode is not None else {}))
        except Exception as error:
            if execution_mode == 'search' and mode == 'original':
                _remember_failure(output / mode, dict(descriptor_path=str(descriptor_path),
                    sources=frozen, flow=flow, rounds=descriptor.rounds if rounds is None else rounds,
                    capacity=cases, preparation_memory_flows=False, base_dir=str(base),
                    cache_dir=str(cache) if cache is not None else str(output/'cache')), error)
            raise
        if _manifest(descriptor, descriptor_path, base) != frozen:
            raise ValueError('source changed during descriptor search')
        _save(output / mode / 'descriptor-manifest.json', {'sources': frozen,
            'summary_sha256': sha256((output / mode / 'summary.json').read_bytes()).hexdigest()})
        normalized = dict(result, execution_status=result['status'],
            status='budget-ended' if result['status'] == 'budget-ended' else 'completed',
            mode=mode, seed=seed, policy=policy, ablation='none',
            planned_case_count=cases, executed_case_count=result['cases'],
            budget={**result.get('budget', {}), 'cases': cases, 'seconds': seconds},
            search_backend='live-storage', live_state_conditioned=True, state_observation='live')
        catalog_document = json.loads((output / mode / 'public-catalog.json').read_text())
        normalized['identity'] = _identity(descriptor, frozen, profiles, catalog_document['sha256'])
        normalized['metrics'] = result.get('metrics') or _unknown_metrics(mode)
        if normalized['metrics']['certified_events'] is not None:
            normalized['identity']['coverage_metric'] = 'certified-storage-write-read.v1'
        normalized['coverage'] = {'status': 'unavailable'}
        _save(output / mode / 'search-summary.json', normalized)
        return normalized
    if flow in ('F5', 'F6') and cases > 16:
        raise ValueError('standalone executor supports at most 16 cases')
    runtime_flow = 'mixed' if flow in ('F1', 'F3') else flow
    selected_records = _memory_records(flow, records) if flow in ('F1', 'F3') else records
    from .ram_case_adapter import RamRecordSelector, ram_records
    from .pin_case_adapter import PinRecordSelector,pin_records
    from .single_storage import SingleStorageRecordSelector, supports_single_storage
    single_live = supports_single_storage(descriptor, flow)
    from .shared_slot_ram_adapter import SharedSlotSelector,shared_slot_records
    shared_live = descriptor.shared_slots and flow=='mixed' and shared_slot_records(selected_records)
    selector_type = (SharedSlotSelector if shared_live else PinRecordSelector if flow=='mixed' and pin_records(selected_records) else
                     SingleStorageRecordSelector if single_live else
                     RamRecordSelector if flow == 'mixed' and ram_records(selected_records) else RecordSelector)
    selector = (selector_type(descriptor, flow=flow, records=selected_records, policy=policy, seed=seed, cases=cases)
                if single_live or flow in ('F1', 'F3', 'mixed', 'F5', 'F6') else None)
    selection = selector.document() if selector is not None else select_records(
        descriptor, flow=flow, records=selected_records, policy=policy, seed=seed, cases=cases)
    live_kind='shared' if isinstance(selector,SharedSlotSelector) else 'pin' if isinstance(selector,PinRecordSelector) else 'ram' if isinstance(selector,RamRecordSelector) else None
    sequence = list(selector.rows) if selector is not None else selection['sequence']
    selected_count, expected_records = cases, None
    preparation_memory_flows = any(row.split(':', 1)[0] in ('F1', 'F3') for row in sequence)
    requested = {'policy': policy, 'seed': seed, 'cases': cases, 'seconds': seconds,
                 'flow': flow, 'rounds': descriptor.rounds if rounds is None else rounds}
    original = output / 'original'
    original_budget_ended = False
    if mode == 'fresh':
        reference = json.loads((original / 'search-manifest.json').read_text())
        old_selection = reference['selection']
        if live_kind:
            measurement_path = original / (live_kind+'-measurements.json')
            if sha256(measurement_path.read_bytes()).hexdigest() != reference.get(live_kind+'_measurements_sha256'):
                raise ValueError('fresh original live measurement binding mismatch')
        same_selection = (old_selection['catalog_sha256'] == selection['catalog_sha256'] and
                          old_selection['catalog'] == json.loads(json.dumps(selection['catalog']))) if selector else (
                          old_selection == json.loads(json.dumps(selection)))
        if reference['sources'] != frozen or reference['request'] != requested or not same_selection:
            raise ValueError('fresh source, request or decision manifest mismatch')
        if sha256((original / 'summary.json').read_bytes()).hexdigest() != reference['summary_sha256']:
            raise ValueError('fresh original summary binding mismatch')
        if sha256((original / 'execution-identities.json').read_bytes()).hexdigest() != reference['executions_sha256']:
            raise ValueError('fresh original execution identity binding mismatch')
        if _prefix_identity(original, flow, json.loads((original / 'summary.json').read_text())) != reference['prefix_identity']:
            raise ValueError('fresh original prefix binding mismatch')
        actual_cases = reference['executed_case_count']
        if type(actual_cases) is not int or not 0 <= actual_cases <= cases:
            raise ValueError('invalid original executed case count')
        if selector is not None:
            selected_count = actual_cases
            expected_records = old_selection['sequence']
            if isinstance(selector, (RamRecordSelector, SingleStorageRecordSelector)):
                selector.replay_costs(old_selection['transitions'])
            if len(expected_records) != actual_cases:
                raise ValueError('original decision count differs from executed count')
        else:
            sequence = sequence[:actual_cases]
        original_budget_ended = reference['budget_ended']
    if runtime_flow not in ('mixed', 'F5', 'F6'):
        # Existing executor consumes descriptor records for one selected flow.
        descriptor = replace(descriptor, **{flow.lower() + '_records': tuple(row.split(':', 1)[1] for row in sequence)})
        if flow == 'F2' and (descriptor.root / 'f2_read_records.json').is_file():
            raise ValueError('F2 sidecar overrides record selection; use registered mixed live search')
        selected = None if sequence else []
    else:
        selected = sequence
    if sequence and not single_live:
        if selector is not None:
            for row in selected:
                select_case_records(descriptor, flow=runtime_flow, records=[row])
        else:
            select_case_records(descriptor, flow=runtime_flow, records=selected)
    try:
        summary = run_descriptor(descriptor, flow=runtime_flow, mode=mode, case_root=output,
            base_dir=base, cache_dir=cache, sequence=selected, rounds=rounds, command_trace=command_trace,
            max_wall_seconds=seconds if mode == 'original' else None,
            preparation_memory_flows=preparation_memory_flows, execution_case_capacity=cases,
            **({'record_selector': selector, 'selected_count': selected_count,
                'expected_records': expected_records} if selector is not None else {}),
            **({'execution_mode': execution_mode} if execution_mode is not None else {}),
            **({'allow_empty_sequence': True} if not sequence else {}), log=lambda _: None)
    except Exception as error:
        if execution_mode == 'search' and mode == 'original':
            _remember_failure(output / mode, dict(descriptor_path=str(descriptor_path), sources=frozen,
                flow=runtime_flow, rounds=descriptor.rounds if rounds is None else rounds, capacity=cases,
                sequence=sequence, preparation_memory_flows=preparation_memory_flows, base_dir=str(base),
                cache_dir=str(cache) if cache is not None else None), error)
        raise
    if selector is not None:
        if isinstance(selector, (RamRecordSelector, SingleStorageRecordSelector)):
            selector.finish()
        selection = selector.document()
        if mode == 'fresh' and json.loads(json.dumps(selection)) != old_selection:
            raise ValueError('replay decision history differs from original')
    if perform_replay and summary.get('replay_matches') is not True:
        raise ValueError('complete executor replay verification failed')
    if _manifest(descriptor, descriptor_path, base) != frozen:
        raise ValueError('source changed during descriptor search')
    out = output / mode
    executions = command_trace.export_executions()
    _execution_index(executions, 2 if perform_replay else 1)
    prefix_identity = _prefix_identity(out, flow, summary)
    if mode == 'fresh':
        old_executions = json.loads((original / 'execution-identities.json').read_text())
        validate_execution_prefixes(old_executions, executions,
            original_replay=reference.get('within_invocation_replay', True), fresh_replay=perform_replay)
        if prefix_identity != reference['prefix_identity']:
            raise ValueError('cross-invocation semantic prefix or plan differs')
    _save(out / 'execution-identities.json', executions)
    result = dict(summary, search_schema='descriptor_search.v1', search_backend='record-catalog',
        live_state_conditioned=False, state_observation='unknown', search_statistics=selection['statistics'],
        native_authority=False, mode=mode, seed=seed, policy=policy, ablation='none',
        execution_status=summary.get('status'),
        status='budget-ended' if summary.get('budget_ended') or original_budget_ended else 'completed',
        planned_case_count=cases, executed_case_count=summary['case_count'],
        budget={'cases': cases, 'seconds': seconds})
    if isinstance(selector,SharedSlotSelector):
        result.update(search_backend=selection['search_backend'],live_state_conditioned=True,state_observation='live',
            consumption_provider=selection['provider'],irq_consumption='unknown',
            certified_relation_count=len({feature for transition in selection['transitions']
                for feature in transition['credited_relations']}))
    elif isinstance(selector,PinRecordSelector):
        result.update(search_backend='live-gpio-pin',live_state_conditioned=True,state_observation='live',
            consumption_provider=selection['provider'],irq_consumption='unknown',
            certified_relation_count=len({feature for transition in selection['transitions'] for feature in transition['credited_relations']}))
        _save(out/'pin-evidence.json',selector.evidence())
    elif isinstance(selector, RamRecordSelector):
        result.update(search_backend='live-ram', live_state_conditioned=True, state_observation='live',
                      consumption_provider=selection['provider'], retirement='unknown', source_origin='unknown',
                      certified_relation_count=len({feature for transition in selection['transitions']
                          for feature in transition['credited_relations']}))
    if isinstance(selector, SingleStorageRecordSelector):
        result.update(search_backend=selection['search_backend'], live_state_conditioned=True,
            state_observation='live', current_provider=selection['provider'],
            same_case_readback_status='reported-per-case',
            cross_testcase_consumption=selection['cross_testcase_consumption'])
    if flow in ('F1', 'F3'):
        result['flow'] = flow
    result['execution_mode'] = execution_mode
    result['verification'] = dict(summary.get('verification', {}))
    result['verification']['cross_invocation'] = {'status': 'verified' if mode == 'fresh' else 'not-requested',
        'matches': True if mode == 'fresh' else None}
    result['fresh_verification_scope'] = ('strict-cross-invocation' if mode == 'fresh' else
        'executor-within-invocation' if perform_replay else 'not-requested')
    result['strict_cross_invocation_ready'] = True
    result['identity'] = _identity(descriptor, frozen, profiles, selection['catalog_sha256'])
    result['metrics'] = _unknown_metrics(mode)
    ram_measurement_binding = {}
    if live_kind:
        measurement = selector.measurements(mode=mode)
        semantic_keys = sorted({row['semantic_key'] for row in measurement['certified_events']})
        if mode == 'fresh' and semantic_keys != reference.get(live_kind+'_metric_semantic_keys'):
            raise ValueError('fresh actual live interaction metric set differs')
        measurement_path=out/(live_kind+'-measurements.json')
        _save(measurement_path, measurement)
        ram_measurement_binding = {live_kind+'_measurements_sha256':sha256(measurement_path.read_bytes()).hexdigest(),
                                  live_kind+'_metric_semantic_keys':semantic_keys}
        result['metrics'] = measurement
        result['identity']['coverage_metric'] = _live_coverage_metric(live_kind, selection)
    result['coverage'] = {'status': 'unavailable'}
    _save(out / 'search-manifest.json', {'sources': frozen, 'request': requested,
        **ram_measurement_binding,
        'selection': selection, 'executed_case_count': summary['case_count'],
        'budget_ended': result['status'] == 'budget-ended',
        'within_invocation_replay': perform_replay,
        'prefix_identity': prefix_identity,
        'executions_sha256': sha256((out / 'execution-identities.json').read_bytes()).hexdigest(), 'summary_sha256': sha256((out / 'summary.json').read_bytes()).hexdigest()})
    _save(out / 'search-summary.json', result)
    return result
