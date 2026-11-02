"""Live installed host-RAM resources and actual-session case attribution.

Current state queries inspect retained authority byte cells without issuing a
RAM read or advancing RTL. Saved documents cannot construct an installation.
Consumption additionally requires a completed physical DUT OBI read.
"""
from weakref import WeakKeyDictionary
from copy import deepcopy

from .ram_actions import ram_identity
from .gpio_relations import _bind_case_session, _read_case_attribution


_INSTALLATIONS = WeakKeyDictionary()


def _unknown(reason):
    return dict(status='unknown', reason=reason, byte_resources=[],
        reset_epoch=0, writer_attributed=False, execution_authority=False)


class _Installation:
    def current_state(self): return read_ram_current(self)
    def observe_case(self, case_id): return read_ram_relations(self, case_id=case_id)


def install_ram_consumer(runtime):
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    if type(runtime) is not CompiledF4Runtime or runtime._memory_flows is not True:
        raise ValueError('actual mixed RAM runtime required')
    runner = runtime.runner
    cpu = runner.sessions[runtime.cpu_id]
    provider = runner._memory_dependency_consumer
    if (type(runner) is not ScenarioRunner or type(cpu) is not GeneratedCve2Session
            or type(provider) is not MemoryDependencyEvidenceConsumer):
        raise ValueError('actual installed RAM callback provider required')
    handle = _Installation()
    _INSTALLATIONS[handle] = dict(runtime=runtime, runner=runner, cpu=cpu, provider=provider,
        session=runtime.session, case_session=_bind_case_session(runtime.session, runner),
        tracker=LiveMemoryEffectTracker(consumer=provider), cursor=0,
        events_since=ScenarioRunner.events_since, event_by_id=ScenarioRunner.event_by_id,
        stable=CompiledF4Runtime._stable, process=None)
    return handle


def _live(handle):
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        raise ValueError('missing_live_ram_installation')
    state = _INSTALLATIONS[handle]
    runtime, runner, cpu = state['runtime'], state['runner'], state['cpu']
    if (runtime.runner is not runner or runtime.session is not state['session']
            or runner.sessions.get(runtime.cpu_id) is not cpu
            or runner._memory_dependency_consumer is not state['provider']
            or CompiledF4Runtime._stable is not state['stable']
            or 'events_since' in vars(runner) or 'event_by_id' in vars(runner)
            or ScenarioRunner.events_since is not state['events_since']
            or ScenarioRunner.event_by_id is not state['event_by_id']
            or runner._status != 'running' or not runtime._begun):
        raise ValueError('live_ram_scope_changed')
    state['stable'](runtime)
    process = cpu.process
    if (process is None or process.poll() is not None
            or runtime._native_processes.get(runtime.cpu_id) is not process):
        raise ValueError('missing_live_cpu_process')
    if state['process'] is None: state['process'] = process
    if state['process'] is not process:
        raise ValueError('live_cpu_process_changed')
    count = runner.event_count
    for event in state['events_since'](runner, state['cursor']):
        state['tracker'].consume_event(event)
    state['cursor'] = count
    return state, count


def read_ram_current(handle):
    try:
        state, count = _live(handle)
        runtime, runner, cpu = state['runtime'], state['runner'], state['cpu']
        memory_id = runtime.image['port']
        address = runtime.result - 4
        offset = address - runtime.image['range'][0]
        resources = []
        for lane in range(4):
            witnesses = state['tracker'].retained_ram_witnesses(memory_id, offset + lane)
            if len(witnesses) != 1:
                return _unknown('no_exact_current_store_version')
            witness = witnesses[0]
            resources.append(dict(byte_offset=offset + lane, version=list(witness.version),
                value=witness.value,
                observation_event_id=witness.event_id, evidence_ref=witness.evidence_ref))
        needed = {r['observation_event_id'] for r in resources}
        observed = _read_case_attribution(state['case_session'], runner, state, needed)
        writers = [observed.get(r['observation_event_id'], {}).get('case_id') for r in resources]
        if runner.event_count != count:
            return _unknown('ram_journal_changed_during_query')
        return dict(status='observed', component=runtime.cpu_id, memory_id=memory_id,
            address=address, reset_epoch=cpu.reset_epoch,
            value=sum(r['value'] << (8*i) for i, r in enumerate(resources)),
            byte_resources=resources, writer_case_ids=writers,
            writer_attributed=bool(writers) and all(writers),
            proof_scope='current_installed_host_memory_bytes', execution_authority=False,
            retirement='unknown', source_origin='unknown')
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as error:
        return _unknown('live_ram_state_unavailable:' + str(error)[:512])


def read_ram_relations(handle, *, case_id):
    unknown = dict(status='unknown', relations=[], retirement='unknown', source_origin='unknown')
    try:
        state, count = _live(handle)
        current = read_ram_current(handle)
        if current.get('status') != 'observed': return unknown
        runtime, runner = state['runtime'], state['runner']
        receipt = state['session'].case_receipt(case_id)
        if receipt is None: return unknown
        from myfuzz.runtime.flows.memory import observe_ram_read_documentary
        from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
        observation = observe_ram_read_documentary(
            events=state['events_since'](runner, 0), receipt=receipt, cpu=runtime.cpu_id,
            address=current['address'], memory_id=current['memory_id'],
            memory_base=runtime.image['range'][0], memory_generation=state['cpu'].memory.generation,
            traces=runtime.traces, error_policy=runtime.error_policy,
            report=MemoryDependencyEvidenceConsumer.report(state['provider']))
        if observation is None: return unknown
        resources = current['byte_resources']
        rows = observation['byte_relations']
        if any((row['byte_offset'], row['byte_version'], row['value'], row['write_event_id']) !=
               (r['byte_offset'], r['version'], r['value'], r['observation_event_id'])
               for row, r in zip(rows, resources, strict=True)):
            return unknown
        needed = {r['write_event_id'] for r in rows} | {rows[0]['read_event_id']}
        observed = _read_case_attribution(state['case_session'], runner, state, needed)
        writers = [observed.get(r['write_event_id'], {}).get('case_id') for r in rows]
        reader = observed.get(rows[0]['read_event_id'], {}).get('case_id')
        if not all(writers) or reader != case_id or any(v == reader for v in writers):
            return unknown
        if runner.event_count != count: return unknown
        relation = dict(status='verified', reward_eligible=True, read_case_id=reader,
            writer_case_ids=writers, resource_identity=ram_identity(current),
            component=current['component'], memory_id=current['memory_id'],
            address=current['address'], value=current['value'],
            native_read_observation=deepcopy(observation),
            retirement='unknown', source_origin='unknown', grants_prerequisites=False)
        return dict(unknown, status='verified', relations=[relation])
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        return unknown
