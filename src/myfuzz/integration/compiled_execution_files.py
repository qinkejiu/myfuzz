"""Explicit file declarations for the experimental compiled dataflow executor.

JSON is an input/evidence transport. It never reconstructs live authority.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from contextlib import contextmanager
from hashlib import sha256
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import tempfile
import sys

from myfuzz.local_harness.harness_set import load_compose, generate_harness_set
from myfuzz.local_harness.auto_harness_test import load_composition, build_path_compile_request
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.local_harness.generated_execution_admission import create_compiled_execution
from myfuzz.local_harness.compiled_execution_projection import (
    assess_compiled_f2_support, assess_compiled_f4_support)
from myfuzz.scenario.compiled_paths import (
    load_path_compile_request, compile_paths, compiled_document_sha256)
from .compiled_candidate_layout import compile_candidate_layout, MAX_CANDIDATE_BITS
from .compiled_f2_layout import compile_f2_candidate_layout
from .compiled_f4 import _diagnostic_build_snapshot
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
    if path.name == 'summary.json':
        from myfuzz.search.workflow import candidate_summary
        document = candidate_summary(document)
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


@dataclass(frozen=True)
class _IncludeFileLink:
    path: Path
    source_root: Path

    def __str__(self):
        return str(self.path)


@dataclass(frozen=True)
class _IncludeDirectory:
    path: Path

    def __str__(self):
        return str(self.path)


def _include_directory_pin(directory):
    path=_no_symlinks(directory.path)
    if not path.is_dir():
        raise ValueError('compiled-files-source-directory-changed:'+str(path))
    return dict(resolved_path=str(path.resolve()),kind='directory')


def _include_link_pin(link):
    """Pin one include-root leaf link and an in-root, non-link file target."""
    path=link.path
    _no_symlinks(path.parent)
    if not path.is_symlink():
        raise ValueError('compiled-files-source-symlink-changed:'+str(path))
    literal=os.readlink(path)
    target=Path(literal)
    if not target.is_absolute():target=path.parent/target
    try:
        _no_symlinks(target)
        resolved=target.resolve(strict=True)
        if not resolved.is_relative_to(link.source_root.resolve(strict=True)) or not resolved.is_file():
            raise ValueError('compiled-files-source-symlink-target-invalid:'+str(path))
        digest=sha256(resolved.read_bytes()).hexdigest()
    except (OSError, RuntimeError) as error:
        raise ValueError('compiled-files-source-symlink-target-invalid:'+str(path)) from error
    return dict(resolved_path=str(resolved),sha256=digest,link_target=literal)


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
            directory=root/name
            paths.add(_IncludeDirectory(directory))
            for path in directory.rglob('*'):
                mode=path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    link=_IncludeFileLink(path,root)
                    _include_link_pin(link)
                    paths.add(link)
                    continue
                _no_symlinks(path)
                if stat.S_ISREG(mode):paths.add(path)
                elif stat.S_ISDIR(mode):paths.add(_IncludeDirectory(path))
                else:raise ValueError('compiled-files-source-special-file:'+str(path))
    # The executor's own closure also guards live execution. This outer pin
    # covers renderer/adapter inputs before startup and fresh replay.
    paths.add(_no_symlinks(base/'scripts/run_compiled_dataflow.py'))
    for path in (base/'src/myfuzz').rglob('*'):
        _no_symlinks(path)
        if path.is_file() and path.suffix in {'.py','.sv','.cpp','.h','.json'}:paths.add(path)
    return sorted(paths,key=str)


def _hashes(paths):
    return {str(path):(_include_link_pin(path) if isinstance(path,_IncludeFileLink)
            else _include_directory_pin(path) if isinstance(path,_IncludeDirectory)
            else dict(resolved_path=str(_no_symlinks(path).resolve()),
                      sha256=sha256(path.read_bytes()).hexdigest())) for path in paths}


def _unchanged(paths, expected, source_arguments):
    if _source_paths(*source_arguments)!=paths or _hashes(paths)!=expected:raise ValueError('compiled-files-source-input-changed')



def _artifact_fixed_input_ownership(artifacts):
    """Exact ownership rows/owners/physical ports for D2 fixed physical inputs.

    A registered target such as the PULP SPI carries profile-constant sideband
    inputs.  The ScenarioRunner requires those bits to be owned explicitly, so
    the file entry derives them from the validated artifact's own fixed rows and
    physical exports instead of accepting an unowned physical input.
    """
    fields=[];owners=[];physical={};seen=set()
    for component,artifact in sorted(artifacts.items()):
        document=artifact.runtime_document
        rows=document.get('fixed_physical_inputs',[])
        if type(rows) is not list:
            raise ValueError('compiled-files-fixed-artifact-input-invalid')
        for index,row in enumerate(rows):
            if type(row) is not dict:
                raise ValueError('compiled-files-fixed-artifact-input-invalid')
            endpoint=row.get('endpoint_id');role=row.get('role')
            runtime_name=row.get('runtime_name');width=row.get('width')
            value=row.get('value');input_name=row.get('input_name')
            if input_name is None and type(endpoint) is str and type(role) is str:
                input_name=endpoint+'.'+role
            if (type(endpoint) is not str or not endpoint
                    or type(role) is not str or not role
                    or type(input_name) is not str or not input_name
                    or type(runtime_name) is not str or not runtime_name
                    or type(width) is not int or not 1<=width<=64
                    or type(value) is not int or not 0<=value<2**width):
                raise ValueError('compiled-files-fixed-artifact-input-invalid')
            key=(component,input_name)
            if key in seen:
                raise ValueError('compiled-files-fixed-artifact-input-invalid')
            seen.add(key)
            exports=[item for item in document.get('physical_exports',())
                     if item.get('endpoint_id')==endpoint
                     and item.get('role')==role]
            if (len(exports)!=1 or exports[0].get('direction')!='input'
                    or exports[0].get('runtime_name')!=runtime_name
                    or exports[0].get('width')!=width
                    or type(exports[0].get('physical_port')) is not str
                    or not exports[0]['physical_port']):
                raise ValueError('compiled-files-fixed-artifact-input-invalid')
            fields.append(dict(component_id=component,port=input_name,width=width))
            owners.append(dict(component_id=component,port=input_name,bit_offset=0,
                width=width,kind='fixed',producer_ref='profile_constant'))
            physical[key]=exports[0]['physical_port']
    return fields,owners,physical


@dataclass(frozen=True, slots=True)
class PreparedCompiledInputs:
    """One D2 generation plus one D3 request/ownership build for several flows."""

    artifacts: dict
    inputs: dict
    supports: dict
    generated_dir: Path
    request_document: dict
    capability_selection: dict


def prepare_compiled_execution_inputs(*, base_dir, compose_path, capability_paths,
                                      supplement_path, generated_dir, flow_ids):
    """Generate D2 once and build D3/ownership once, then assess every flow.

    Every flow assessment consumes the same artifact mapping and the same
    request/compiled/ownership/physical_port_map objects created here.  This is
    the only supported way to claim a same-preparation F2/F4 pair; calling the
    single-flow wrapper twice and comparing hashes is not that claim.  No native
    child process is started and no runtime admission is granted.
    """
    flow_ids=tuple(flow_ids)
    if not flow_ids or len(set(flow_ids))!=len(flow_ids) or any(
            flow not in ('F1','F2','F3','F4','F5','F6') for flow in flow_ids):
        raise ValueError('compiled-files-flow-selection-invalid')
    f6='F6' in flow_ids
    shared_f6 = f6 and {'F4','F6'} <= set(flow_ids) and not set(flow_ids)-{'F1','F2','F3','F4','F5','F6'}
    if f6 and flow_ids!=('F6',) and not shared_f6:
        raise ValueError('compiled-files-mixed-f6-unsupported')
    base=_no_symlinks(base_dir).resolve();compose_path=_no_symlinks(compose_path).resolve()
    capabilities=tuple(_no_symlinks(p).resolve() for p in capability_paths)
    _source_paths(base,compose_path,capabilities,supplement_path,None)
    if not capabilities:raise ValueError('compiled-files-explicit-capability-required')
    supplement=_closed(_read(supplement_path),
        {'schema_version','request_supplements','ownership','physical_port_map'})
    if supplement['schema_version']!='compiled_execution_file_supplement.v1':
        raise ValueError('compiled-files-supplement-schema')
    additions=_closed(supplement['request_supplements'],set(),
                      {'environment_links','memory','deliveries','sources','fixed_inputs','f6_execution'} if f6 else
                      {'environment_links','memory','deliveries','sources','fixed_inputs'})
    supplied_generated=Path(generated_dir)
    if supplied_generated.exists() or supplied_generated.is_symlink():
        raise ValueError('compiled-files-generated-directory-must-be-new')
    generated=supplied_generated.resolve()
    if generated.exists() or generated.is_symlink():raise ValueError('compiled-files-generated-directory-must-be-new')
    compose=load_compose(compose_path,base_dir=base)
    provider_kwargs={}
    if f6:
        from myfuzz.local_harness.dma_artifact_endpoint_links import PROVIDER_ID
        provider_kwargs={'dma_endpoint_provider':PROVIDER_ID}
    generate_harness_set(compose,base_dir=base,compose_base=compose_path.parent,output_root=generated,**provider_kwargs)
    composition=load_composition(compose_path,base_dir=base)
    document,sidecars=build_path_compile_request(composition,
        wiring_path=generated/'wiring_contract.json',ip_capabilities=capabilities)
    if f6:
        # Generated output locations are provenance, not wiring semantics.
        # Load this invocation's real contract through the existing inline API.
        document['wiring'] = _read(generated / 'wiring_contract.json')
    # Refuse an implicit sibling sidecar even if the composition loader found it.
    declared_capabilities={str(p) for p in capabilities}
    for device in document['devices']:
        if device.get('test_capability') is None or str((base/Path(device['test_capability'])).resolve()) not in declared_capabilities:
            raise ValueError('compiled-files-implicit-capability-refused')
    for name,value in additions.items():
        if name in document:raise ValueError('compiled-files-supplement-overwrite')
        document[name]=value
    request=load_path_compile_request(document,base_dir=base);compiled=compile_paths(request)
    if shared_f6 and 'shared_slots' not in document.get('f6_execution', {}):
        raise ValueError('compiled-files-mixed-f6-explicit-shared-slots-required')
    artifacts=load_generated_artifacts(generated_root=generated,base_dir=base,**({'flow':'F6'} if f6 else {}))
    try:
        ownership_doc=_closed(supplement['ownership'],{'fields','owners'})
        fields=[dict(row) for row in ownership_doc['fields']]
        owners=[dict(row) for row in ownership_doc['owners']]
        physical={}
        for row in supplement['physical_port_map']:
            _closed(row,{'component_id','port','physical_port'})
            key=(row['component_id'],row['port'])
            if key in physical:raise ValueError('compiled-files-duplicate-physical-map')
            physical[key]=row['physical_port']
        fixed_fields,fixed_owners,fixed_physical=_artifact_fixed_input_ownership(artifacts)
        declared={(row['component_id'],row['port']) for row in fields}
        for row in fixed_fields:
            key=(row['component_id'],row['port'])
            if key in declared:raise ValueError('compiled-files-duplicate-fixed-input')
            fields.append(row)
        owners.extend(fixed_owners)
        for key,port in fixed_physical.items():
            if key in physical:raise ValueError('compiled-files-duplicate-physical-map')
            physical[key]=port
        ownership=compile_ownership(tuple(InputField(**row) for row in fields),
                                    tuple(InputOwner(**row) for row in owners))
        inputs=dict(request=request,compiled=compiled,ownership=ownership,physical_port_map=physical)
        supports={}
        if any(flow in ('F1','F3') for flow in flow_ids):
            from myfuzz.runtime.flows.memory import prepare_memory_paths
            memory_paths, memory_bindings = prepare_memory_paths(request=request, compiled=compiled)
            f4_support=(dict(execution_supported=1) if shared_f6 else
                assess_compiled_f4_support(artifacts=artifacts,compiled_inputs=inputs,base_dir=base))
            if f4_support.get('execution_supported') != 1:
                raise ValueError('compiled-files-shared-memory-host-unsupported')
        for flow in flow_ids:
            if flow in ('F1','F2','F3','F4','F5','F6') and shared_f6:
                from .compiled_f6_runtime_path import admit_compiled_f6_runtime_path
                joint = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=inputs, base_dir=base)
                if flow not in joint['shared_flow_paths']:
                    raise ValueError('compiled-files-shared-flow-not-declared:'+flow)
                supports[flow]=dict(schema_version='shared_slot_support.v1', execution_supported=1,
                    runtime_admitted=False, status='supported_requires_actual_startup',
                    executor='compiled_f6_cpu_dma', runtime_path_id=joint['shared_flow_paths'][flow]['path_id'],
                    support_scope='same_preparation_typed_online_storage_DMA_slots')
            elif flow=='F4':
                supports[flow]=assess_compiled_f4_support(artifacts=artifacts,compiled_inputs=inputs,base_dir=base)
            elif flow=='F6':
                from .compiled_f6_rfuzz_session import assess_compiled_f6_support
                supports[flow]=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=inputs,base_dir=base)
            elif flow=='F5':
                paths=[row for row in compiled['paths'] if row['flow_id']=='F5']
                if len(paths)!=1:
                    raise ValueError('compiled-files-f5-path-ambiguous')
                path=paths[0]
                supports[flow]=dict(schema_version='compiled_f5_static_support.v1',
                    execution_supported=0,runtime_admitted=False,path_id=path['path_id'],
                    static_path_status=path['status'],
                    status='runtime_not_implemented',
                    reason='serial_source_and_physical_irq_binding_not_admitted')
                if len(request.devices)==1:
                    try:
                        from .shared_f5_runtime import admit_shared_f5_declaration
                        irq_port=admit_shared_f5_declaration(artifacts=artifacts,compiled_inputs=inputs)
                    except ValueError:
                        pass
                    else:
                        supports[flow].update(execution_supported=1,
                            status='supported_requires_actual_startup',executor='compiled_f4_obi_apb',
                            support_scope='declared_shared_pin_and_physical_irq_topology',
                            producer_binding={'path_identity':path['runtime_path_identity'],'cpu_irq_port':irq_port},
                            startup_requires=['actual_shared_runner_binding','live_preparation_currentness',
                                              'physical_irq_adapter','unmaterialized_fixed_support_slots'])
            elif flow in ('F1','F3'):
                selected=next(row for row in compiled['paths'] if row['flow_id']==flow and row['status']=='executable')
                binding=next(item for item in memory_bindings if item.source_id==flow+'.program_image')
                supports[flow]=dict(schema_version='compiled_memory_support.v1',execution_supported=1,
                    runtime_admitted=False,status='supported_requires_actual_startup',
                    executor='compiled_f4_obi_apb',path_id=selected['path_id'],
                    producer_binding=binding.document(),
                    support_scope='shared_cpu_persistent_memory_requires_live_execution',
                    startup_requires=['native_first_fetch_inside_instruction_image',
                                      'exact_private_input_readmission'])
            else:
                supports[flow]=assess_compiled_f2_support(artifacts=artifacts,compiled_inputs=inputs,base_dir=base)
        _save_new(generated.parent/'path_compile_request.json',document)
        _save_new(generated.parent/'compiled_paths.json',compiled)
        _save_new(generated.parent/'capability_selection.json',sidecars)
        return PreparedCompiledInputs(artifacts=artifacts,inputs=inputs,supports=supports,
            generated_dir=generated,request_document=document,capability_selection=sidecars)
    except BaseException:
        if f6:
            from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
            release_f6_provider_credentials(artifacts)
        raise


def prepare_compiled_execution_files(*, base_dir, compose_path, capability_paths,
                                     supplement_path, generated_dir, flow='F4'):
    """Single-flow compatible wrapper over :func:`prepare_compiled_execution_inputs`.

    The tuple return is preserved for existing callers.  A caller that needs F2
    and F4 from one preparation must call the shared function once, not this
    wrapper twice.
    """
    if flow not in ('F2','F4','F6'):
        raise ValueError('compiled-files-flow-unsupported')
    prepared=prepare_compiled_execution_inputs(base_dir=base_dir,compose_path=compose_path,
        capability_paths=capability_paths,supplement_path=supplement_path,
        generated_dir=generated_dir,flow_ids=(flow,))
    return prepared.artifacts,prepared.inputs,prepared.supports[flow]


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
    exports=[
            ('partial_events','partial_events.json',lambda:list(runtime.runner.events_since(0))),
            ('execution_audit','execution_audit.json',runtime.execution_audit)]
    if callable(getattr(runtime,'assertion_results',None)):
        exports.append(('assertions','assertions.json',runtime.assertion_results))
    for key,filename,read in exports:
        try:_save(output/filename,read())
        except BaseException as error:failures[key]=str(error)
    return failures


_FLOW_BY_EXECUTOR = {'compiled_f4_obi_apb': 'F4', 'compiled_f2_obi_apb': 'F2', 'compiled_f6_cpu_dma': 'F6'}


def _canonical_document(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _pin_saved_document(output, name, expected):
    """Saved bytes must equal this same call's document; return their digest."""
    raw = (output / name).read_bytes()
    parsed = json.loads(raw)
    if _canonical_document(parsed) != _canonical_document(expected):
        raise ValueError('compiled-files-saved-output-mismatch:' + name)
    return sha256(raw).hexdigest()


def _save_f2_runtime_report(output, *, compiled, runtime, harness_set,
                            fresh_verification):
    """Save and re-read same-call typed evidence before final report pinning."""
    from .compiled_runtime_report import capture_f2_report_material
    material = capture_f2_report_material(compiled=compiled, runtime=runtime,
        harness_set=harness_set, fresh_verification=fresh_verification)
    documents = {
        'capability_report.json': material['capability_report'],
        'compiled_assertion_results.v1.json': material['assertions'],
        'compiled_assertion_evidence.v1.json': material['assertion_evidence'],
    }
    for filename, document in documents.items():
        _save(output / filename, document)
    for filename, document in documents.items():
        _pin_saved_document(output, filename, document)
    return material


def run_compiled_execution_files(*, base_dir, compose_path, capability_paths,
        supplement_path, records_path, output_dir, cache_dir, executor,
        run_id='compiled-dataflow', rounds_per_case=128, max_cases=64, replay_count=1, heavy_lock=None, max_wall_seconds=None, execution_mode=None, mode="original",
        record_selector=None, selected_count=None, expected_records=None):
    """Run explicit declaration-sized records continuously and replay fresh RTL.

    This is directed candidate execution, not coverage-guided search. Saved
    plans are compared against this live prefix before the trusted runtime
    reconstructs fresh processes and re-admits the private source declarations.
    The F2 executor consumes four-byte address records; F4 consumes its own
    writer records.  Every selected flow gets its typed capability report,
    saved-file pinning and a run-level build join where the executor supports it.
    """
    if execution_mode is not None:
        from myfuzz.search.workflow import requires_replay
        wanted = requires_replay(execution_mode, mode)
        replay_count = max(1, replay_count) if wanted else 0
    if max_wall_seconds is not None and (type(max_wall_seconds) not in (int, float)
            or not math.isfinite(max_wall_seconds) or max_wall_seconds <= 0):
        raise ValueError("compiled-files-wall-budget-invalid")
    if max_wall_seconds is not None and executor != "compiled_f6_cpu_dma":
        raise ValueError("compiled-files-wall-budget-executor-unsupported")
    base = _no_symlinks(base_dir).resolve(); supplied_output = Path(output_dir)
    lock_path = (Path(heavy_lock) if heavy_lock is not None
                 else base / '.superpowers/heavy-worker.lock').resolve()
    if supplied_output.exists() or supplied_output.is_symlink():
        raise ValueError('compiled-files-output-directory-must-be-new')
    output = supplied_output.resolve()
    if output.exists() or output.is_symlink():
        raise ValueError('compiled-files-output-directory-must-be-new')
    output.mkdir(parents=True, exist_ok=False)
    marker = output / '.incomplete'
    marker.write_text('execution not complete\n')
    started = time.monotonic(); runtime = None; flow = _FLOW_BY_EXECUTOR.get(executor)
    build_evidence = {'original': {}, 'fresh': {}}
    construction_started = False
    f6_artifacts=None
    report = dict(schema_version='compiled_execution_files_report.v1', status='incomplete',
        executor=executor, flow=flow, execution_mode=execution_mode, runtime_admitted=False, heavy_lock=str(lock_path),
        scope=('experimental_directed_continuous_%s_candidates_and_fresh_prefix_replay'
               % (flow or 'unsupported')),
        coverage_guided=False, general_instruction_search=False, full_D4_accepted=False)
    try:
        if flow is None:
            raise ValueError('compiled-files-executor-unsupported')
        if type(replay_count) is not int or not (0 if flow == "F6" else 1) <= replay_count <= 2:
            raise ValueError("compiled-files-replay-count-invalid")
        for value, limit in ((rounds_per_case, 4096), (max_cases, 256)):
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError('compiled-files-budget-invalid')
        if type(run_id) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', run_id) is None:
            raise ValueError('compiled-files-run-id-invalid')
        records_file = Path(records_path)
        if record_selector is not None and (flow != 'F6' or type(selected_count) is not int or
                                            not 1 <= selected_count <= max_cases or
                                            (expected_records is not None and len(expected_records) != selected_count)):
            raise ValueError('compiled-files-selector-invalid')
        domain_limit = 64 if record_selector is not None else max_cases
        if records_file.stat().st_size > domain_limit * (MAX_CANDIDATE_BITS // 4 + 4) + 1024:
            raise ValueError('compiled-files-record-file-budget')
        records = _read(records_file)
        if type(records) is not list or not 1 <= len(records) <= domain_limit:
            raise ValueError('compiled-files-record-count-invalid')
        if any(type(row) is not str or re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,128}', row) is None
               for row in records):
            raise ValueError('compiled-files-bounded-hex-record-required')
        capabilities = tuple(_no_symlinks(p) for p in capability_paths)
        source_arguments = (base, compose_path, capabilities, supplement_path, records_path)
        paths = _source_paths(*source_arguments)
        source_hashes = _hashes(paths)
        if (_source_paths(base, compose_path, capabilities, supplement_path, records_path) != paths
                or _read(records_path) != records):
            raise ValueError('compiled-files-source-input-changed')
        _save(output / 'source_input_hashes.json', source_hashes)
        _save(output / 'input_declarations.json', dict(compose=_read(compose_path),
            supplement=_read(supplement_path), records=records,
            capabilities={str(p): _read(p) for p in capabilities}))
        _unchanged(paths, source_hashes, source_arguments)
        generation_start = time.monotonic()
        artifacts, inputs, support = prepare_compiled_execution_files(base_dir=base,
            compose_path=compose_path, capability_paths=capabilities,
            supplement_path=supplement_path, generated_dir=output / 'generated',
            flow=flow)
        if flow=='F6':f6_artifacts=artifacts
        report['generation_seconds'] = time.monotonic() - generation_start
        report['capability'] = support
        if flow == 'F2':
            from myfuzz.scenario.capability_report import build_capability_report
            _save(output / 'execution_support.json', support)
            _save(output / 'capability_report.json', build_capability_report(
                inputs['compiled'], harness_set=_read(output / 'generated/harness_set.json')))
        else:
            _save(output / 'capability_report.json', support)
        if support['execution_supported'] != 1:
            raise ValueError('compiled-files-runtime-support-refused')
        path = next(p for p in inputs['compiled']['paths']
                    if p['flow_id'] == flow and p['status'] == 'executable')
        if flow == 'F6':
            from .compiled_f6_layout import compile_f6_candidate_layout
            layout=compile_f6_candidate_layout(path)
            for row in records:layout.decode(bytes.fromhex(row))
            layout_document=layout.document()
        elif flow == 'F2':
            layout = compile_f2_candidate_layout(path)
            for row in records:
                selection = layout.classify(bytes.fromhex(row))
                if not selection.accepted:
                    raise ValueError('compiled-files-candidate-' + str(selection.reason))
            layout_document = layout.document()
        else:
            layout = compile_candidate_layout(path)
            for row in records:
                layout.decode(bytes.fromhex(row))
            layout_document = _layout_document(layout)
        _save(output / 'candidate_layout.json', layout_document)
        _unchanged(paths, source_hashes, source_arguments)
        if flow == 'F6':
            return _run_f6_file_route(output=output,marker=marker,report=report,artifacts=artifacts,inputs=inputs,
                base=base,cache_dir=cache_dir,run_id=run_id,rounds=rounds_per_case,max_cases=max_cases,
                replay_count=replay_count,records=records,lock_path=lock_path, max_wall_seconds=max_wall_seconds,
                check_sources=lambda:_unchanged(paths,source_hashes,source_arguments),
                **({'record_selector':record_selector, 'selected_count':selected_count,
                    'expected_records':expected_records} if record_selector is not None else {}))
        with _worker_lock(lock_path):
            try:
                _unchanged(paths, source_hashes, source_arguments)
                startup = time.monotonic()
                construction_started = True
                runtime = create_compiled_execution(artifacts=artifacts, compiled_inputs=inputs,
                    executor=executor, base_dir=base, cache_dir=Path(cache_dir).resolve(),
                    run_id=run_id, rounds_per_case=rounds_per_case, max_cases=max_cases,
                    build_audit_sink=lambda snapshot: build_evidence.update(original=snapshot))
                report['startup_seconds'] = time.monotonic() - startup
                case_timings = []
                for index, row in enumerate(records):
                    _unchanged(paths, source_hashes, source_arguments)
                    case_start = time.monotonic()
                    certificate = runtime.submit(bytes.fromhex(row))
                    case_timings.append(dict(index=index,
                        wall_seconds=time.monotonic() - case_start,
                        certified=certificate['status'] == 'certified'))
                    _save(output / 'case_timings.json', case_timings)
                plan = runtime.finish()
                _save(output / 'prefix.json', plan)
                original_events = deepcopy(list(runtime.trace.events))
                _save(output / 'events.json', original_events)
                original_audit = runtime.execution_audit()
                _save(output / 'execution_audit.json', original_audit)
                initial_pins = {name: _pin_saved_document(output, name, document)
                    for name, document in {'prefix.json':plan, 'events.json':original_events,
                        'execution_audit.json':original_audit}.items()}
                replays = []
                fresh_documents = {}
                for replay_index in range(replay_count):
                    _unchanged(paths, source_hashes, source_arguments)
                    replay_start = time.monotonic()
                    replay_dir = output / f'fresh-{replay_index + 1}'
                    replay_dir.mkdir()
                    def save_fresh(envelope):
                        envelope = deepcopy(envelope)
                        documents = {}
                        for key, filename in (('actual_prefix', 'prefix.json'),
                                ('actual_events', 'events.json'),
                                ('execution_audit', 'execution_audit.json')):
                            if key in envelope:
                                documents[filename] = deepcopy(envelope[key])
                        if envelope.get('original_build') is not None:
                            build_evidence['original'] = envelope['original_build']
                        if envelope.get('fresh_build') is not None:
                            build_evidence['fresh'] = envelope['fresh_build']
                        summary = {k: v for k, v in envelope.items()
                                   if k not in {'actual_prefix', 'actual_events'}}
                        documents['comparison.json'] = deepcopy(summary)
                        for filename, document in documents.items():
                            _save(replay_dir / filename, deepcopy(document))
                        pins = {filename: _pin_saved_document(replay_dir, filename, document)
                                for filename, document in documents.items()}
                        documents['artifact_hashes.json'] = deepcopy(pins)
                        _save(replay_dir / 'artifact_hashes.json', deepcopy(pins))
                        pins['artifact_hashes.json'] = _pin_saved_document(
                            replay_dir, 'artifact_hashes.json', documents['artifact_hashes.json'])
                        for filename, document in documents.items():
                            relative = str((replay_dir / filename).relative_to(output))
                            fresh_documents[relative] = document
                            initial_pins[relative] = pins[filename]
                    result = runtime.replay(plan, audit_sink=save_fresh)
                    result = {k: v for k, v in result.items()
                              if k not in {'actual_prefix', 'actual_events'}}
                    result['artifact_directory'] = str(replay_dir)
                    result['wall_seconds'] = time.monotonic() - replay_start
                    replays.append(result)
                    _save(output / 'replays.json', replays)
                    if result.get('matches') is not True:
                        raise ValueError('compiled-files-fresh-prefix-mismatch')
                _unchanged(paths, source_hashes, source_arguments)
                original_build = build_evidence['original'] or _diagnostic_build_snapshot(
                    runtime)
                if flow == 'F2':
                    binding = runtime.execution_binding.document()
                    from .compiled_f2_build_join import (
                        build_compiled_f2_build_join, verify_compiled_f2_build_join)
                    fresh_build = build_evidence['fresh']
                    build_join = build_compiled_f2_build_join(
                        artifacts=artifacts, execution_binding=binding,
                        compiled_document_sha256=compiled_document_sha256(
                            inputs['compiled']),
                        runtime_path_id=binding.get('runtime_path_id'),
                        logical_path_id=binding.get('path_id'),
                        original=original_build, fresh=fresh_build)
                    verify_compiled_f2_build_join(build_join, artifacts=artifacts,
                        execution_binding=binding, original=original_build,
                        fresh=fresh_build)
                    _save(output / 'compiled_f2_build_join.v1.json', build_join)
                    report['build_join'] = dict(schema_version=build_join['schema_version'],
                        status=build_join['status'],
                        sha256=sha256((output / 'compiled_f2_build_join.v1.json')
                                      .read_bytes()).hexdigest())
                capability_document = support
                assertion_material = None
                if flow == 'F2':
                    # Every replay was checked above; the report describes these
                    # independently rerun assertions without promoting tiers.
                    assertion_material = _save_f2_runtime_report(output,
                        compiled=inputs['compiled'], runtime=runtime,
                        harness_set=_read(output / 'generated/harness_set.json'),
                        fresh_verification=dict(matches=True, first_difference=None,
                            verification_scope='full'))
                    capability_document = assertion_material['capability_report']
                expected = {
                    'capability_report.json': capability_document,
                    'candidate_layout.json': layout_document,
                    'prefix.json': plan,
                    'execution_audit.json': original_audit,
                    'events.json': original_events,
                    'case_timings.json': case_timings,
                    'replays.json': replays,
                }
                if flow == 'F2':
                    expected['compiled_f2_build_join.v1.json'] = build_join
                    expected['execution_support.json'] = support
                    expected['compiled_assertion_results.v1.json'] = assertion_material['assertions']
                    expected['compiled_assertion_evidence.v1.json'] = assertion_material['assertion_evidence']
                expected.update(fresh_documents)
                expected_pins = {name: _pin_saved_document(output, name, document)
                                 for name, document in expected.items()}
                if any(expected_pins.get(name) != digest
                       for name, digest in initial_pins.items()):
                    raise ValueError('compiled-files-final-saved-output-drift')
                saved_hashes = {str(p.relative_to(output)):
                                sha256(p.read_bytes()).hexdigest()
                                for p in sorted(output.rglob('*.json'))}
                if any(saved_hashes.get(name) != digest
                       for name, digest in expected_pins.items()):
                    raise ValueError('compiled-files-final-saved-output-drift')
                _save(output / 'saved_file_hashes.json', saved_hashes)
                report['saved_file_hashes'] = saved_hashes
                report['capability_report_sha256'] = saved_hashes['capability_report.json']
                if flow == 'F2':
                    report['assertion_results_sha256'] = saved_hashes['compiled_assertion_results.v1.json']
                    report['assertion_evidence_sha256'] = saved_hashes['compiled_assertion_evidence.v1.json']
                useful_seconds = sum(row['wall_seconds'] for row in case_timings)
                report.update(status='completed', runtime_admitted=True,
                    cases=len(records),
                    certified_cases=sum(row['certified'] for row in case_timings),
                    case_wall_seconds=useful_seconds,
                    useful_cases_per_second=(len(records) / useful_seconds
                                             if useful_seconds else None),
                    replays=len(replays), semantic_hash=plan['semantic_hash'])
            finally:
                primary_error = sys.exc_info()[1]
                if runtime is not None and not runtime.finished:
                    try:
                        runtime.finish()
                    except BaseException as cleanup_error:
                        report['cleanup_failure'] = dict(
                            error_type=type(cleanup_error).__name__,
                            error=str(cleanup_error))
                        if primary_error is None:
                            raise
        report['total_wall_seconds'] = time.monotonic() - started
        _save(output / 'report.json', report); marker.unlink()
        return report
    except BaseException as error:
        report.update(status='refused' if runtime is None else 'incomplete',
            error_type=type(error).__name__, error=str(error),
            total_wall_seconds=time.monotonic() - started)
        if runtime is None:
            report['startup_partial_trace_available'] = False
        if runtime is not None:
            report['failure_evidence_errors'] = _save_runtime_failure(output, runtime)
        if flow == 'F2' and construction_started:
            try:
                from .compiled_f2_build_join import build_compiled_f2_build_join
                binding = None
                if runtime is not None:
                    try:
                        binding = runtime.execution_binding.document()
                    except BaseException as binding_error:
                        error.add_note('compiled-F2 failed binding export: ' + repr(binding_error))
                    build_evidence['original'] = _diagnostic_build_snapshot(runtime,
                        previous=build_evidence['original'], error=error)
                report['startup_build_observations_available'] = bool(build_evidence['original'])
                _save(output / 'compiled_f2_build_join.v1.json',
                      build_compiled_f2_build_join(artifacts=artifacts,
                          execution_binding=binding,
                          compiled_document_sha256=compiled_document_sha256(inputs['compiled']),
                          runtime_path_id=binding.get('runtime_path_id') if binding else None,
                          logical_path_id=binding.get('path_id') if binding else None,
                          original=build_evidence['original'],
                          fresh=build_evidence['fresh'], error=error))
            except BaseException as audit_error:
                error.add_note('compiled-F2 refused build join: ' + repr(audit_error))
        try:
            _save(output / 'report.json', report)
        except BaseException as report_error:
            error.add_note('compiled-files failure report export: ' + repr(report_error))
        raise

    finally:
        if f6_artifacts is not None:
            from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
            release_f6_provider_credentials(f6_artifacts)


def _submit_f6_records(runtime, records, *, check_sources, max_wall_seconds,
                       record_selector=None, selected_count=None, expected_records=None):
    requested_count = len(records) if record_selector is None else selected_count
    executed = []
    started = time.monotonic()
    for index in range(requested_count):
        if executed and max_wall_seconds is not None and time.monotonic()-started >= max_wall_seconds:
            break
        selected = record_selector.choose() if record_selector is not None else None
        if selected is not None and expected_records is not None and selected != expected_records[index]:
            raise ValueError('F6 replay decision differs from original')
        row = records[index] if selected is None else selected.split(':', 1)[1]
        check_sources()
        runtime.submit(bytes.fromhex(row))
        if record_selector is not None:
            record_selector.settle(selected)
        executed.append(row)
    return executed, time.monotonic()-started


def _run_f6_file_route_owned(*,output,marker,report,artifacts,inputs,base,cache_dir,run_id,
        rounds,max_cases,replay_count,records,lock_path,check_sources,max_wall_seconds=None,
        record_selector=None,selected_count=None,expected_records=None):
    """Closed directed F6 route; shares file pin/lock primitives only."""
    from .compiled_f6 import CompiledF6Runtime
    from .compiled_f6_saved_outputs import write_pinned_json,save_f6_replay_outputs,verify_pins
    from .compiled_f6_rfuzz_session import f6_fresh_verification
    from .compiled_f6_build_join import build_compiled_f6_build_join,verify_compiled_f6_build_join
    from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material
    from myfuzz.scenario.capability_report import build_capability_report
    runtime=None;primary=None;pins={}
    from myfuzz.local_harness.generated_artifact_admission import validated_f6_provider_credentials,release_f6_provider_credentials
    pins.update(validated_f6_provider_credentials(artifacts,include_files=True)['file_pins'])
    if max_cases>16:raise ValueError('compiled-F6-file-slot-budget')
    try:
        with _worker_lock(lock_path):
            check_sources()
            runtime=CompiledF6Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=base,
                cache_dir=Path(cache_dir),run_id=run_id,rounds_per_case=rounds,max_cases=max_cases)
            requested_count = len(records) if record_selector is None else selected_count
            records, execution_seconds = _submit_f6_records(runtime, records,
                check_sources=check_sources, max_wall_seconds=max_wall_seconds,
                record_selector=record_selector, selected_count=selected_count,
                expected_records=expected_records)
            report.update(requested_case_count=requested_count, budget_ended=len(records)<requested_count,
                max_wall_seconds=max_wall_seconds, first_case_always_admitted=True, execution_seconds=execution_seconds,
                wall_budget_overrun_seconds=max(0,execution_seconds-max_wall_seconds) if max_wall_seconds is not None else 0)
            plan=runtime.finish()
            write_pinned_json(output/'compiled_f6_prefix.json',plan,pins)
            replay=None
            for index in range(replay_count):
                check_sources()
                if index==0:
                    replay=runtime.replay(plan,audit_sink=lambda envelope:save_f6_replay_outputs(output,envelope,pins))
                else:
                    directory=output/f'fresh-{index+1}';extra_pins={}
                    runtime.replay(plan,audit_sink=lambda envelope:save_f6_replay_outputs(directory,envelope,extra_pins))
                    verify_pins(directory,extra_pins)
            verification = None
            joined = None
            if replay is not None:
                verification=f6_fresh_verification(replay,plan,route='directed_file')
                joined=build_compiled_f6_build_join(artifacts=artifacts,execution_binding=runtime.execution_binding,
                    original=plan['original_build'],fresh=replay['fresh_build'])
                verify_compiled_f6_build_join(joined,artifacts=artifacts,execution_binding=runtime.execution_binding,
                    original=plan['original_build'],fresh=replay['fresh_build'])
            material=build_f6_assertion_material(runtime)
            evidence=dict(execution_binding=runtime.execution_binding,path_id=runtime.path['path_id'],
                run_id=run_id,cases=material['assertion_evidence']['cases'])
            from .compiled_f6_layout import compile_f6_candidate_layout
            layout=compile_f6_candidate_layout(runtime.path)
            mappings=[]
            if len(records)!=len(plan['records']):raise ValueError('compiled-F6-file-record-bijection')
            for index,(raw_hex,record) in enumerate(zip(records,plan['records'])):
                candidate=layout.decode(bytes.fromhex(raw_hex))
                if (record['raw8_hex']!=candidate.raw.hex() or record['words']!=list(candidate.words)
                        or record.get('prefix_hex')!=runtime.program.prefix(candidate,case_index=index).hex()):
                    raise ValueError('compiled-F6-file-candidate-program-bijection')
                mappings.append(dict(case_id=record['case_id'],raw8_hex=candidate.raw.hex(),words=list(candidate.words),
                    prefix_hex=record['prefix_hex'],source_ids=[s['source_id'] for s in runtime.path['sources']]))
            if [m['case_id'] for m in mappings]!=[c['case_id'] for c in material['assertions']['cases']]:
                raise ValueError('compiled-F6-file-typed-bijection')
            receipt_join=dict(schema_version='compiled_F6_receipt_join.v1',scope='directed_file_records',
                status='ok',raw_transport_receipts_present=False,path_id=runtime.path['path_id'],run_id=run_id,
                rows=len(mappings),case_count=len(mappings),cases=mappings)
            documents={'compiled_f6_receipt_join.v1.json':receipt_join,
                'compiled_assertion_results.v1.json':material['assertions'],
                'compiled_assertion_evidence.v1.json':evidence,
                'compiled_f6_raw8_records.json':records}
            if verification is not None:
                documents.update({'compiled_f6_fresh_verification.json':verification,
                    'compiled_f6_build_join.v1.json':joined})
            for name,value in documents.items():write_pinned_json(output/name,value,pins)
            capability=build_capability_report(inputs['compiled'],harness_set=_read(output/'generated/harness_set.json'),
                fresh_verification=verification,assertion_results=material['assertions'],assertion_evidence=evidence)
            write_pinned_json(output/'capability_report_final.json',capability,pins)
            check_sources();verify_pins(output,pins)
            report.update(status='complete' if plan['completed'] else 'failed_prefix_full',
                runtime_admitted=True,case_count=len(plan['records']),fresh_verification=verification,
                replay_matches=None if verification is None else verification.get('matches'),
                verification={'within_invocation': {'status': 'not-requested' if verification is None else 'verified' if verification.get('matches') is True else 'failed',
                    'matches': None if verification is None else verification.get('matches')},
                    'cross_invocation': {'status': 'not-requested', 'matches': None}},
                saved_output_hashes=dict(pins),useful_search_benefit_claimed=False,search_diversity=None)
            _save(output/'report.json',report)
            if plan['completed']:marker.unlink()
            return report
    except BaseException as error:
        primary=error
        raise
    finally:
        if runtime is not None:
            if not runtime.finished:
                try:runtime.finish()
                except BaseException as error:
                    if primary is None:raise
                    if error is not primary:primary.add_note('F6 file finish: '+repr(error))
            if primary is not None:
                from .compiled_process_audit import diagnostic_build_snapshot
                exports=[('compiled_f6_build_join.v1.json',lambda:build_compiled_f6_build_join(
                    artifacts=artifacts,execution_binding=runtime.execution_binding,
                    original=diagnostic_build_snapshot(runtime,error=primary),fresh={},error=primary)),
                    ('compiled_f6_partial_prefix.json',lambda:getattr(runtime,'_finish_document',None)),
                    ('compiled_f6_partial_events.json',lambda:list(runtime.runner.events_since(0))),
                    ('compiled_f6_execution_audit.json',runtime.execution_audit),
                    ('compiled_assertion_results.v1.json',lambda:build_f6_assertion_material(runtime)['assertions']),
                    ('compiled_assertion_evidence.v1.json',lambda:build_f6_assertion_material(runtime)['assertion_evidence'])]
                for name,capture in exports:
                    if name in pins:continue
                    try:write_pinned_json(output/name,capture(),pins)
                    except BaseException as error:primary.add_note('F6 file export: '+repr(error))


def _run_f6_file_route(*,output,marker,report,artifacts,inputs,base,cache_dir,run_id,
        rounds,max_cases,replay_count,records,lock_path,check_sources,max_wall_seconds=None,
        record_selector=None,selected_count=None,expected_records=None):
    from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
    try:
        return _run_f6_file_route_owned(output=output,marker=marker,report=report,artifacts=artifacts,
            inputs=inputs,base=base,cache_dir=cache_dir,run_id=run_id,rounds=rounds,max_cases=max_cases,
            replay_count=replay_count,records=records,lock_path=lock_path, max_wall_seconds=max_wall_seconds,check_sources=check_sources,
            record_selector=record_selector,selected_count=selected_count,expected_records=expected_records)
    finally:
        release_f6_provider_credentials(artifacts)
