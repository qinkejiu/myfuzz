"""Scope live shared providers to a measured whole-runner reset."""
from myfuzz.scenario.runner import ScenarioRunner


def capture_epoch(runtime):
    runner=runtime.runner
    if type(runner) is not ScenarioRunner or runner._status!='running':
        raise ValueError('shared-provider-running-runner-required')
    processes={name:session.process for name,session in runner.sessions.items()}
    if any(p is None or p.poll() is not None or runtime._native_processes.get(name) is not p
           for name,p in processes.items()):
        raise ValueError('shared-provider-live-process-required')
    return dict(runner=runner,memory=runtime.memory,sessions=dict(runner.sessions),
        command_epoch=runner.command_epoch,event_floor=runner.event_count,
        epochs={name:session.reset_epoch for name,session in runner.sessions.items()},
        executions={name:session._execution for name,session in runner.sessions.items()},
        processes=processes,memory_generation=runtime.memory.generation,
        barrier_event_id=None)


def rebind_epoch(runtime,previous,*,barrier_event_id):
    """Validate one measured warm/cold barrier and its rebound live processes."""
    runner=runtime.runner
    if (runner is not previous['runner'] or runtime.memory is not previous['memory']
            or runner.sessions.keys()!=previous['sessions'].keys()
            or any(runner.sessions[name] is not session
                   for name,session in previous['sessions'].items())):
        raise ValueError('shared-provider-reset-owner-mismatch')
    if type(barrier_event_id) is not int or barrier_event_id<=previous['event_floor']:
        raise ValueError('shared-provider-reset-barrier-required')
    barrier=runner.event_by_id(barrier_event_id)
    if (not isinstance(barrier,dict) or barrier.get('event_id')!=barrier_event_id
            or barrier.get('kind')!='reset_barrier'
            or barrier.get('policy') not in ('warm_all','cold_all')):
        raise ValueError('shared-provider-reset-barrier-required')
    current=capture_epoch(runtime)
    if (current['command_epoch']!=previous['command_epoch']+1
            or current['epochs'].keys()!=previous['epochs'].keys()
            or any(current['epochs'][name]!=epoch+1 for name,epoch in previous['epochs'].items())
            or any(current['processes'][name] is previous['processes'][name]
                   or current['executions'][name]==previous['executions'][name]
                   for name in previous['epochs'])):
        raise ValueError('shared-provider-reset-epoch-or-process-mismatch')
    expected=previous['memory_generation']+(barrier['policy']=='cold_all')
    if (current['memory_generation']!=expected
            or any(barrier.get('memory_generations',{}).get(name)!=expected
                   for name in runtime.memory.memory_ids)):
        raise ValueError('shared-provider-reset-memory-generation-mismatch')
    current['barrier_event_id']=barrier_event_id
    return current
