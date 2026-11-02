"""Measure a just-executed component prefix with existing RTL coverage tools.

Instrumentation and replay run outside the search budget on a fresh cache copy.
This is offline Verilator DUT line/block coverage, not interaction counts,
source-branch coverage, online feedback or fixed-time coverage AUC.
"""
from hashlib import sha256
import json
from pathlib import Path
from time import monotonic

from myfuzz.local_harness.coverage import measure_cached_harness,coverage_budget,requested_coverage_overrides
from scripts.attach_search_coverage import attach
from scripts.measure_local_coverage import select_recorded_session


def _save(path,value):
    with path.open('x',encoding='utf8') as stream:
        json.dump(value,stream,indent=2,sort_keys=True)
        stream.write('\n')


def measure_search_prefix(search, *, component, cache_root, output,max_commands=512,
                          max_input_bytes=64*1024*1024,max_output_bytes=64*1024*1024,max_wall_seconds=60):
    """Measure rather than import; every recorded command is replayed exactly.

    The existing selector refuses incomplete/oversized traces (512 commands
    by default, expanded only through explicit bounded parameters). The existing measurer verifies the cache and original replies;
    attachment then validates the instrumented artifact and DUT point universe.
    No truncation or guessed cache/source identity is allowed.
    """
    budget=coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    options=requested_coverage_overrides(budget)
    search,cache_root,output=Path(search).resolve(),Path(cache_root).resolve(),Path(output).resolve()
    if output.exists() or output.is_symlink(): raise ValueError('coverage-pipeline-output-must-be-new')
    summary_path=(search/'search-summary.json' if (search/'search-summary.json').exists()
                  else search/'summary.json') if search.is_dir() else search
    original_summary=summary_path.read_bytes()
    trace_path=summary_path.parent/'local_commands.json'
    if not trace_path.exists(): trace_path=summary_path.parent/'local-commands.json'
    trace=json.loads(trace_path.read_text(encoding='utf8'))
    try: digest=trace['sessions'][component]['identity']['build_digest']
    except (KeyError,TypeError): raise ValueError('recorded-component-build-missing') from None
    if (type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)):
        raise ValueError('invalid-recorded-build-digest')
    cache=cache_root if cache_root.name==digest else cache_root/digest
    commands,replies,binary=select_recorded_session(trace,component,digest,**options)
    if sha256((cache/'harness').read_bytes()).hexdigest()!=binary:
        raise ValueError('recorded-binary-mismatch')
    if trace['sessions'][component]['identity'].get('component')!=component:
        raise ValueError('recorded-component-mismatch')
    output.mkdir(parents=True,exist_ok=False)
    started=monotonic()
    measurement=output/'measurement'
    measured=measure_cached_harness(cache,measurement,commands,expected_replies=replies,**options)
    measured_at=monotonic()
    summary=attach(summary_path,component,measurement,cache,**options)
    attached_at=monotonic()
    if summary_path.read_bytes()!=original_summary:
        raise ValueError('search-summary-changed-during-coverage')
    cost=dict(outside_search_budget=True,
        instrumentation_and_replay_seconds=measured_at-started,
        attachment_validation_seconds=attached_at-measured_at,
        total_seconds=attached_at-started, instrumentation_build_seconds=None,
        scope='instrumented build plus plain/instrumented full-prefix replay and artifact validation')
    summary['coverage']['measurement_cost']=cost
    summary.setdefault('metrics',{})['coverage']=summary['coverage']
    summary_output=output/'search-summary.coverage.json'
    result=dict(schema_version='automatic_search_coverage.v1',status='measured',
        component=component,summary=summary,summary_path=str(summary_output),
        original_summary_sha256=sha256(original_summary).hexdigest(),
        trace_sha256=sha256(trace_path.read_bytes()).hexdigest(),
        original_cache=str(cache),original_build_digest=digest,
        coverage_kind=measured['coverage_kind'],source_selection=measured['source_selection'],
        source_selection_sha256=sha256(json.dumps(measured['source_selection'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        denominator_sha256=summary['coverage']['denominator_sha256'],
        replay=measured['replay'],replay_budget=budget,cost=cost)
    _save(summary_output,summary)
    _save(output/'coverage-pipeline.json',{key:value for key,value in result.items() if key!='summary'})
    return result
