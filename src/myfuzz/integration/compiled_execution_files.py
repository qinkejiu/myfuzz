"""Explicit file declarations for the experimental compiled dataflow executor.

JSON is an input/evidence transport. It never reconstructs live authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import fcntl
import json
from pathlib import Path
import re
import time
import tempfile
import sys

from myfuzz.local_harness.harness_set import load_compose, generate_harness_set
from myfuzz.local_harness.auto_harness_test import load_composition, build_path_compile_request
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.local_harness.generated_execution_admission import create_compiled_execution
from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f4_support
from myfuzz.scenario.compiled_paths import load_path_compile_request, compile_paths
from .compiled_candidate_layout import compile_candidate_layout, MAX_CANDIDATE_BITS
from .compiled_f4 import _layout_document
from myfuzz.composition.component_profile import _source_locator
from myfuzz.composition.source_crawler import _declared_files, SourceCrawlError
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership


def _no_symlinks(path):
    """Reject lexical symlink components before resolving or opening inputs."""
    path=Path(path)
    lexical=path if path.is_absolute() else Path.cwd()/path
    current=Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current=current/part
        if current.is_symlink():raise ValueError('compiled-files-source-symlink-refused:'+str(current))
    return lexical


def _read(path):
    return json.loads(_no_symlinks(path).read_text(encoding='utf-8'))


def _save(path, document):
    # Atomic replacement never overwrites any hard-linked source inode.
    path=Path(path)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,
                                     prefix='.'+path.name+'.',delete=False) as handle:
        temporary=Path(handle.name)
        try:handle.write(json.dumps(document,sort_keys=True,indent=2,allow_nan=False)+'\n')
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)


def _save_new(path, document):
    if path.exists() or path.is_symlink():raise ValueError('compiled-files-output-artifact-exists')
    _save(path,document)


def _closed(document, required, optional=()):
    if type(document) is not dict or not set(required)<=set(document) or set(document)-set(required)-set(optional):
        raise ValueError('compiled-files-declaration-keys')
    return document


def _source_paths(base, compose_path, capability_paths, supplement_path, records_path):
    """Pin declarations and their explicitly referenced native source files."""
    paths={_no_symlinks(compose_path),_no_symlinks(supplement_path),
           *(_no_symlinks(p) for p in capability_paths)}
    if records_path is not None:paths.add(_no_symlinks(records_path))
    document=_read(compose_path)
    for component in [document['cpu'],*document['devices']]:
        request=_no_symlinks(Path(compose_path).parent/component['request']);paths.add(request)
        profile=_no_symlinks(base/_read(request)['profile_path']);paths.add(profile)
        source=_read(profile)['source'];root=_no_symlinks(base/source['root'])
        if not root.resolve().is_relative_to(Path(base).resolve()):
            raise ValueError('compiled-files-source-root-escape')
        locator=_source_locator(source)
        for name in locator.files:_no_symlinks(root/name)
        if locator.filelist is not None:_no_symlinks(root/locator.filelist)
        def read_source(path):
            path=_no_symlinks(path);paths.add(path)
            return path.read_bytes()
        try:
            _,include_roots,_=_declared_files(root.resolve(),locator,read_source)
        except SourceCrawlError as error:
            if 'symlink' in str(error):
                raise ValueError('compiled-files-source-symlink-refused:'+str(error)) from error
            raise
        # Include lookup is a declared directory input. Pin every member and
        # re-enumerate it before startup/replay so added headers cannot hide.
        for name in include_roots:
            for path in (root/name).rglob('*'):
                _no_symlinks(path)
                if path.is_file():paths.add(path)
    # The executor's own closure also guards live execution. This outer pin
    # covers renderer/adapter inputs before startup and fresh replay.
    paths.add(_no_symlinks(base/'scripts/run_compiled_dataflow.py'))
    for path in (base/'src/myfuzz').rglob('*'):
        _no_symlinks(path)
        if path.is_file() and path.suffix in {'.py','.sv','.cpp','.h','.json'}:paths.add(path)
    return sorted(paths)


def _hashes(paths):
    return {str(path):dict(resolved_path=str(_no_symlinks(path).resolve()),
                           sha256=sha256(path.read_bytes()).hexdigest()) for path in paths}


def _unchanged(paths, expected, source_arguments):
    if _source_paths(*source_arguments)!=paths or _hashes(paths)!=expected:raise ValueError('compiled-files-source-input-changed')


def prepare_compiled_execution_files(*, base_dir, compose_path, capability_paths,
                                     supplement_path, generated_dir):
    """Generate D2 and admit exact D3/ownership from explicit declarations.

    This creates source artifacts only. It starts no native child process and
    does not grant runtime admission. Callers must separately pin source inputs.
    """
    base=_no_symlinks(base_dir).resolve();compose_path=_no_symlinks(compose_path).resolve()
    capabilities=tuple(_no_symlinks(p).resolve() for p in capability_paths)
    _source_paths(base,compose_path,capabilities,supplement_path,None)
    if not capabilities:raise ValueError('compiled-files-explicit-capability-required')
    supplement=_closed(_read(supplement_path),
        {'schema_version','request_supplements','ownership','physical_port_map'})
    if supplement['schema_version']!='compiled_execution_file_supplement.v1':
        raise ValueError('compiled-files-supplement-schema')
    additions=_closed(supplement['request_supplements'],set(),
                      {'environment_links','memory','deliveries','sources'})
    supplied_generated=Path(generated_dir)
    if supplied_generated.exists() or supplied_generated.is_symlink():
        raise ValueError('compiled-files-generated-directory-must-be-new')
    generated=supplied_generated.resolve()
    if generated.exists() or generated.is_symlink():raise ValueError('compiled-files-generated-directory-must-be-new')
    compose=load_compose(compose_path,base_dir=base)
    generate_harness_set(compose,base_dir=base,compose_base=compose_path.parent,output_root=generated)
    composition=load_composition(compose_path,base_dir=base)
    document,sidecars=build_path_compile_request(composition,
        wiring_path=generated/'wiring_contract.json',ip_capabilities=capabilities)
    # Refuse an implicit sibling sidecar even if the composition loader found it.
    declared_capabilities={str(p) for p in capabilities}
    for device in document['devices']:
        if device.get('test_capability') is None or str((base/Path(device['test_capability'])).resolve()) not in declared_capabilities:
            raise ValueError('compiled-files-implicit-capability-refused')
    for name,value in additions.items():
        if name in document:raise ValueError('compiled-files-supplement-overwrite')
        document[name]=value
    request=load_path_compile_request(document,base_dir=base);compiled=compile_paths(request)
    artifacts=load_generated_artifacts(generated_root=generated,base_dir=base)
    ownership_doc=_closed(supplement['ownership'],{'fields','owners'})
    ownership=compile_ownership(tuple(InputField(**row) for row in ownership_doc['fields']),
                                tuple(InputOwner(**row) for row in ownership_doc['owners']))
    physical={}
    for row in supplement['physical_port_map']:
        _closed(row,{'component_id','port','physical_port'})
        key=(row['component_id'],row['port'])
        if key in physical:raise ValueError('compiled-files-duplicate-physical-map')
        physical[key]=row['physical_port']
    inputs=dict(request=request,compiled=compiled,ownership=ownership,physical_port_map=physical)
    support=assess_compiled_f4_support(artifacts=artifacts,compiled_inputs=inputs,base_dir=base)
    _save_new(generated.parent/'path_compile_request.json',document)
    _save_new(generated.parent/'compiled_paths.json',compiled)
    _save_new(generated.parent/'capability_selection.json',sidecars)
    return artifacts,inputs,support


@contextmanager
def _worker_lock(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:raise ValueError('compiled-files-heavy-worker-lock-held') from error
        try:yield
        finally:fcntl.flock(handle,fcntl.LOCK_UN)


def _save_runtime_failure(output,runtime):
    failures={}
    for key,filename,read in (
            ('partial_events','partial_events.json',lambda:list(runtime.runner.events_since(0))),
            ('execution_audit','execution_audit.json',runtime.execution_audit)):
        try:_save(output/filename,read())
        except BaseException as error:failures[key]=str(error)
    return failures


def run_compiled_execution_files(*, base_dir, compose_path, capability_paths,
        supplement_path, records_path, output_dir, cache_dir, executor,
        run_id='compiled-dataflow', rounds_per_case=128, max_cases=64, replay_count=1, heavy_lock=None):
    """Run explicit declaration-sized records continuously and replay fresh RTL.

    This is directed candidate execution, not coverage-guided search. Saved
    plans are compared against this live prefix before the trusted runtime
    reconstructs fresh processes and re-admits the private source declarations.
    """
    base=_no_symlinks(base_dir).resolve();supplied_output=Path(output_dir)
    lock_path=(Path(heavy_lock) if heavy_lock is not None else base/'.superpowers/heavy-worker.lock').resolve()
    if supplied_output.exists() or supplied_output.is_symlink():
        raise ValueError('compiled-files-output-directory-must-be-new')
    output=supplied_output.resolve()
    if output.exists() or output.is_symlink():raise ValueError('compiled-files-output-directory-must-be-new')
    output.mkdir(parents=True,exist_ok=False);marker=output/'.incomplete';marker.write_text('execution not complete\n')
    started=time.monotonic();runtime=None
    report=dict(schema_version='compiled_execution_files_report.v1',status='incomplete',
        executor=executor,runtime_admitted=False,heavy_lock=str(lock_path),
        scope='experimental_directed_continuous_F4_candidates_and_fresh_prefix_replay',
        coverage_guided=False,general_instruction_search=False,full_D4_accepted=False)
    try:
        if executor!='compiled_f4_obi_apb':raise ValueError('compiled-files-executor-unsupported')
        for value,limit in ((rounds_per_case,4096),(max_cases,256),(replay_count,2)):
            if type(value) is not int or not 1<=value<=limit:raise ValueError('compiled-files-budget-invalid')
        if type(run_id) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,96}',run_id) is None:
            raise ValueError('compiled-files-run-id-invalid')
        # Bound bytes before parsing; records are explicit, never generated here.
        records_file=Path(records_path)
        if records_file.stat().st_size>max_cases*(MAX_CANDIDATE_BITS//4+4)+1024:raise ValueError('compiled-files-record-file-budget')
        records=_read(records_file)
        if type(records) is not list or not 1<=len(records)<=max_cases:
            raise ValueError('compiled-files-record-count-invalid')
        if any(type(row) is not str or re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,128}',row) is None for row in records):
            raise ValueError('compiled-files-bounded-hex-record-required')
        capabilities=tuple(_no_symlinks(p) for p in capability_paths)
        source_arguments=(base,compose_path,capabilities,supplement_path,records_path)
        paths=_source_paths(*source_arguments)
        source_hashes=_hashes(paths)
        if (_source_paths(base,compose_path,capabilities,supplement_path,records_path)!=paths
                or _read(records_path)!=records):
            raise ValueError('compiled-files-source-input-changed')
        _save(output/'source_input_hashes.json',source_hashes)
        # Preserve the exact declarations for review, never as authority objects.
        _save(output/'input_declarations.json',dict(compose=_read(compose_path),
            supplement=_read(supplement_path),records=records,
            capabilities={str(p):_read(p) for p in capabilities}))
        _unchanged(paths,source_hashes,source_arguments)
        generation_start=time.monotonic()
        artifacts,inputs,support=prepare_compiled_execution_files(base_dir=base,
            compose_path=compose_path,capability_paths=capabilities,supplement_path=supplement_path,
            generated_dir=output/'generated')
        report['generation_seconds']=time.monotonic()-generation_start
        report['capability']=support
        _save(output/'capability_report.json',support)
        if support['execution_supported']!=1:raise ValueError('compiled-files-runtime-support-refused')
        path=next(p for p in inputs['compiled']['paths'] if p['flow_id']=='F4' and p['status']=='executable')
        layout=compile_candidate_layout(path)
        for row in records:layout.decode(bytes.fromhex(row))
        _save(output/'candidate_layout.json',_layout_document(layout))
        _unchanged(paths,source_hashes,source_arguments)
        with _worker_lock(lock_path):
            try:
                _unchanged(paths,source_hashes,source_arguments)
                startup=time.monotonic()
                runtime=create_compiled_execution(artifacts=artifacts,compiled_inputs=inputs,
                    executor=executor,base_dir=base,cache_dir=Path(cache_dir).resolve(),
                    run_id=run_id,rounds_per_case=rounds_per_case,max_cases=max_cases)
                report['startup_seconds']=time.monotonic()-startup
                case_timings=[]
                for index,row in enumerate(records):
                    _unchanged(paths,source_hashes,source_arguments);case_start=time.monotonic()
                    certificate=runtime.submit(bytes.fromhex(row))
                    case_timings.append(dict(index=index,wall_seconds=time.monotonic()-case_start,
                        certified=certificate['status']=='certified'))
                    _save(output/'case_timings.json',case_timings)
                plan=runtime.finish();_save(output/'prefix.json',plan)
                _save(output/'events.json',list(runtime.trace.events))
                _save(output/'execution_audit.json',runtime.execution_audit())
                replays=[]
                for replay_index in range(replay_count):
                    _unchanged(paths,source_hashes,source_arguments);replay_start=time.monotonic()
                    replay_dir=output/f'fresh-{replay_index+1}'
                    replay_dir.mkdir()
                    def save_fresh(envelope):
                        for key,filename in (('actual_prefix','prefix.json'),('actual_events','events.json'),
                                ('execution_audit','execution_audit.json')):
                            if key in envelope:_save(replay_dir/filename,envelope[key])
                        summary={k:v for k,v in envelope.items() if k not in {'actual_prefix','actual_events'}}
                        _save(replay_dir/'comparison.json',summary)
                        _save(replay_dir/'artifact_hashes.json',_hashes(sorted(replay_dir.glob('*.json'))))
                    result=runtime.replay(plan,audit_sink=save_fresh)
                    result={k:v for k,v in result.items() if k not in {'actual_prefix','actual_events'}}
                    result['artifact_directory']=str(replay_dir)
                    result['wall_seconds']=time.monotonic()-replay_start;replays.append(result)
                    _save(output/'replays.json',replays)
                    if result.get('matches') is not True:raise ValueError('compiled-files-fresh-prefix-mismatch')
                _unchanged(paths,source_hashes,source_arguments)
                useful_seconds=sum(row['wall_seconds'] for row in case_timings)
                report.update(status='completed',runtime_admitted=True,cases=len(records),
                    certified_cases=sum(row['certified'] for row in case_timings),
                    case_wall_seconds=useful_seconds,
                    useful_cases_per_second=(len(records)/useful_seconds if useful_seconds else None),
                    replays=len(replays),semantic_hash=plan['semantic_hash'])
            finally:
                primary_error=sys.exc_info()[1]
                if runtime is not None and not runtime.finished:
                    try:runtime.finish()
                    except BaseException as cleanup_error:
                        report['cleanup_failure']=dict(error_type=type(cleanup_error).__name__,error=str(cleanup_error))
                        if primary_error is None:raise
        report['total_wall_seconds']=time.monotonic()-started
        _save(output/'report.json',report);marker.unlink()
        return report
    except BaseException as error:
        report.update(status='refused' if runtime is None else 'incomplete',
            error_type=type(error).__name__,error=str(error),total_wall_seconds=time.monotonic()-started)
        if runtime is None:report['startup_partial_trace_available']=False
        # Keep partial native evidence and the incomplete marker on every failure.
        if runtime is not None:
            report['failure_evidence_errors']=_save_runtime_failure(output,runtime)
        _save(output/'report.json',report)
        raise
