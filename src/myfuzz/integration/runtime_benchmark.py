"""Targeted CPython timing observation; never patches measured functions."""
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from copy import deepcopy
import inspect
import math
import sys
import time


class RuntimeTimings:
    """Inclusive spans and existing command/runner timings on one workload.

    Local sys.monitoring events avoid global function-call profiling. Runtime
    and command labels overlap enclosing spans and are never summed as wall.
    """
    def __init__(self, *, clock=time.monotonic):
        self.clock=clock;self.calls=[];self._groups={'runtime':{},'command':{}}
        self._stack=ContextVar('benchmark_spans',default=())
        self._counts={};self._targets={};self._active=False

    def _start(self,code,_offset):
        phase=self._targets[code];stack=self._stack.get()
        invocation='fresh' if phase=='fresh_replay' or any(r['invocation']=='fresh' for r in stack) else 'original'
        index=None
        if phase=='submit':
            index=self._counts.get(invocation,0);self._counts[invocation]=index+1
        elif phase=='selector_settle':
            index=max(0,self._counts.get(invocation,0)-1)
        self._stack.set(stack+(dict(phase=phase,invocation=invocation,case_index=index,started=self.clock()),))

    def _end(self,code,_offset,_value,status):
        stack=self._stack.get()
        if not stack or stack[-1]['phase']!=self._targets[code]:
            raise RuntimeError('benchmark timing scope lost')
        row=dict(stack[-1]);self._stack.set(stack[:-1])
        row['seconds']=max(0.,self.clock()-row.pop('started'));row['status']=status
        self.calls.append(row)

    def _return(self,code,offset,value):self._end(code,offset,value,'complete')
    def _unwind(self,code,offset,error):
        if code in self._targets:self._end(code,offset,error,'error')

    def _observe(self,kind,label,seconds):
        if type(label) is not str or not isinstance(seconds,(int,float)) or not math.isfinite(seconds) or seconds<0:
            raise ValueError('invalid observed timing')
        stack=self._stack.get();context=stack[-1] if stack else {}
        key=(context.get('invocation','original'),context.get('phase','outside_target'),context.get('case_index'),label)
        row=self._groups[kind].setdefault(key,dict(invocation=key[0],phase=key[1],case_index=key[2],label=label,count=0,seconds=0.,max_seconds=0.))
        row['count']+=1;row['seconds']+=seconds;row['max_seconds']=max(row['max_seconds'],seconds)

    def observe_runtime(self,label,seconds):self._observe('runtime',label,seconds)
    def observe_command(self,label,seconds):self._observe('command',label,seconds)

    @contextmanager
    def observe(self,targets,*,observer_contexts=None):
        if self._active:raise ValueError('benchmark observer already active')
        if not hasattr(sys,'monitoring'):raise RuntimeError('targeted benchmark requires CPython 3.12+')
        selected={}
        for label,function in targets.items():
            raw=inspect.unwrap(function)
            if not inspect.isfunction(raw) or inspect.isgeneratorfunction(raw) or inspect.iscoroutinefunction(raw):
                raise ValueError('synchronous Python target required')
            if raw.__code__ in selected:raise ValueError('ambiguous code target')
            selected[raw.__code__]=label
        if not selected:raise ValueError('nonempty timing targets required')
        mon=sys.monitoring;tool=next((i for i in range(5,-1,-1) if mon.get_tool(i) is None),None)
        if tool is None:raise RuntimeError('no sys.monitoring tool slot available')
        if observer_contexts is None:
            from myfuzz.scenario.runner import observe_runtime_timings
            from myfuzz.local_harness.session import observe_local_command_timings
            observer_contexts=(observe_runtime_timings,observe_local_command_timings)
        if len(observer_contexts)!=2:raise ValueError('runtime and command observer contexts required')
        self._targets=selected;self._active=True
        mon.use_tool_id(tool,'myfuzz-runtime-benchmark')
        events=mon.events;mask=events.PY_START|events.PY_RETURN
        try:
            mon.register_callback(tool,events.PY_START,self._start)
            mon.register_callback(tool,events.PY_RETURN,self._return)
            mon.register_callback(tool,events.PY_UNWIND,self._unwind)
            mon.set_events(tool,events.PY_UNWIND)  # exception-only event is not local in CPython 3.12
            with ExitStack() as scope:
                scope.enter_context(observer_contexts[0](self.observe_runtime))
                scope.enter_context(observer_contexts[1](self.observe_command))
                for code in selected:mon.set_local_events(tool,code,mask)
                yield self
        finally:
            mon.set_events(tool,0)
            for code in selected:mon.set_local_events(tool,code,0)
            for event in (events.PY_START,events.PY_RETURN,events.PY_UNWIND):mon.register_callback(tool,event,None)
            mon.free_tool_id(tool);self._active=False

    def document(self,*,wall_seconds):
        if self._active or self._stack.get():raise ValueError('completed timing scope required')
        if not math.isfinite(wall_seconds) or wall_seconds<0:raise ValueError('nonnegative wall required')
        return deepcopy(dict(schema_version='shared_workload_timings.v1',wall_seconds=wall_seconds,
            mechanism='sys.monitoring_local_code_events_plus_existing_observers',
            timing_semantics='inclusive_not_additive',calls=self.calls,
            runtime_inclusive=list(self._groups['runtime'].values()),
            command_roundtrips=list(self._groups['command'].values()),
            note='Enclosing phases, runner labels and command times overlap; do not add them.'))


def workload_identity(prefix):
    """Count the executed work, independently of host timing and process IDs."""
    from collections import Counter
    from hashlib import sha256
    import json
    rows=prefix.get('flow_records',[])
    records=[r['flow']+':'+r['raw_hex'] for r in rows]
    events=prefix.get('actual_events',prefix.get('trace_events',[]))
    if type(events) is not list or any(type(e) is not dict for e in events):
        raise ValueError('actual event list required')
    if any(r.get('status')!='passed' for r in rows):raise ValueError('completed workload required')
    return dict(records=records,records_sha256=sha256(json.dumps(records,separators=(',',':')).encode()).hexdigest(),
        main_case_count=len(records),session_case_count=len(prefix.get('online_plan',{}).get('cases',[])),
        local_ticks=prefix.get('trace_local_ticks'),event_count=len(events),
        event_kind_counts=dict(sorted(Counter(str(e.get('kind')) for e in events).items())),
        semantic_hash=prefix.get('semantic_hash'),
        semantic_hash_scope='full sealed prefix; host source changes can change this hash')
