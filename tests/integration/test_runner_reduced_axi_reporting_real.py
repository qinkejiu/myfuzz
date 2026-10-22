"""Reviewed-only native gate: normal Runner, two real independent RAM processes.

Collection never builds/launches RTL. MYFUZZ_VEXII_REAL=1 AND a supervisor freeze
manifest are required. All failed attempts remain in the supervisor directory.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
import pytest
from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
from myfuzz.local_harness import session as transport
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import OwnershipMap
from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.integration.scenario_rfuzz_live import _write_online_trace_jsonl,_write_online_trace_zlib
from scripts.verify_runner_reduced_axi_reporting import (archive_files,verify_archive,
    compare_runs,verify_native_join,semantic_digest,verify_durable,digest,require,
    freeze_declared_build,verify_build_snapshot,archive_validated_cache,
    verify_validated_cache_archive,capture_transaction_preimages)
from tests.local_harness.test_vexii_generated_cpu import artifact,PROGRAM,BOOT,ROOT

ALIAS='observed-engine'
# 500 receipt ops + begin + seal, two spare terminal-control slots.
SOURCE=dict(max_operations=504,max_pending_operations=4,
    max_pending_bytes=4*65536,max_operation_bytes=65536)
# <=11 originals/edge, raw ref lifetime <=500, <=4 completions/edge,
# <=1 scope, <=30 global rows/edge plus32 control/cleanup rows.
CONSUMER=dict(max_streams=1,max_scopes=1,max_raw_mappings=500,max_pending=8,
    max_expected_records=11,max_retained_records=4*500+4,max_input_bytes=262144,
    max_total_input_bytes=1024*1024*1024,max_events=30*500+32,max_event_gap=32)
BUDGET=ResourceBudget(max_local_cycles_per_component=500,max_scheduler_steps=500,
    max_materialized_bytes_per_memory=65536,max_source_actions=4,max_transactions=4096,
    max_semantic_records=30*500+32,max_evidence_bytes=512*1024*1024,
    evidence_termination_reserve_bytes=64*1024*1024,max_wall_time_ms=240000,
    max_quiesce_steps=0,build_workers=1)


def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')


@contextmanager
def wire_capture(cpu,rows):
    """Passive delegate around actual transport boundaries; no synthetic data."""
    write=transport.write_local_command;read=cpu._reader.readline
    def observed_write(handle,line):
        rows.append(dict(direction='host',text=line))
        return write(handle,line)
    def observed_read(handle):
        line=read(handle)
        rows.append(dict(direction='native',text=line))
        return line
    transport.write_local_command=observed_write
    cpu._reader.readline=observed_read
    try:yield
    finally:
        transport.write_local_command=write;cpu._reader.readline=read


def closure_files():
    return sorted({Path(m.__file__).resolve() for m in sys.modules.values()
        if m is not None and getattr(m,'__file__',None)
        and Path(m.__file__).is_file()})


def run_one(a,cache,directory,freeze,prebuild,prebuild_directory):
    directory.mkdir(parents=True,exist_ok=False)
    memory=PersistentMemory(regions=(MemoryRegion('ram',BOOT,0x100000),),
        initialization_seed=0,max_initialized_bytes=65536)
    memory.preload(BOOT,b''.join(w.to_bytes(4,'little') for w in PROGRAM))
    cpu=GeneratedReducedAxiCpuSession(a,base_dir=ROOT,cache_dir=cache,
        memory=memory,command_timeout_seconds=120)
    # Configure the actual observer before irreversible admission, retaining its
    # exact implementation and supported contract, with an explicit finite scope.
    cpu._axi_observer=ReducedAxiObserver(component_id=cpu.source_component,
        max_edges=500,max_bytes=500*8192,max_scopes=1)
    cpu.runtime_events=cpu._axi_observer.events
    r=ScenarioRunner(sessions={ALIAS:cpu},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={ALIAS:dict(source=SOURCE,consumer=CONSUMER)})
    r.enable_event_journal(chunk_size=128);r.set_resource_budget(BUDGET)
    config=r.identity_document()['reduced_axi_observation_streams'][0]
    record=config['max_journal_record_bytes'];growth=config['max_report_growth_bytes']
    r.arm_evidence_meter(len(json.dumps(r.identity_document()).encode()),{},
        max_final_state_growth_bytes_per_operation=growth,max_evidence_record_bytes=record)
    save(directory/'limits.json',dict(source=SOURCE,consumer=CONSUMER,budget=BUDGET.to_document(),
        observer=config['binding']['observer_contract']['budgets'],record_bound=record,
        report_growth_bound=growth,tail_formula_bytes=2*growth+3*record,
        derivation='500 measured edges;11 originals/edge;4 completions/edge;30 global rows/edge+32;64KiB source op refusal;8KiB raw/edge refusal'))
    initial_memory_preimages={ALIAS:[[mid,offset,cell.value,cell.version,cell.writer_kind,cell.writer_event_id]
        for (mid,offset),cell in sorted(memory._bytes.items())]}
    wire=[];samples=[];proc=None;error=None;started=time.time()
    result={}
    try:
        verify_archive(freeze['directory'],freeze['manifest'],originals=True)
        verify_build_snapshot(prebuild_directory,prebuild,originals=True)
        cpu.prepare_local()  # One serial validated cache/build path, outer lock owned.
        require(cpu._binary is not None,'build returned no executable')
        build=archive_validated_cache(cpu._binary,prebuild,directory/'build-bytes',prebuild_directory)
        save(directory/'build-manifest.json',build)
        verify_validated_cache_archive(directory/'build-bytes',build,prebuild,prebuild_directory,originals=True)
        result['expected_ready']=list(cpu._expected_ready())
        with wire_capture(cpu,wire):
            r.begin_test('reduced-axi-runner-ram')
            proc=cpu.process
            require(proc is not None and proc.poll() is None,'actual launch missing')
            result.update(execution=cpu._execution,process=dict(pid=proc.pid,
                execution=cpu._execution,start_time=time.time(),binary=str(cpu._binary)))
            save(directory/'launch.json',result['process'])
            for _ in range(500):
                r.step(ALIAS);samples.extend(deepcopy(cpu.last_samples))
                if cpu.write_responses==2:break
            else:raise AssertionError('500 measured edge bound exceeded')
            # Stop due to host counter only after independent physical verification.
            from scripts.verify_runner_reduced_axi_reporting import verify_physical
            verify_physical(samples)
            result['ram_values']=[memory.read(BOOT+offset,4,transaction_id=f'audit-{offset}').value for offset in (0x100,0x104)]
            require(result['ram_values']==[53,54],'physical program RAM mismatch')
            r.finalize()
    except BaseException as exc:
        error=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())
        raise
    finally:
        try:r.finalize()
        finally:
            result.update(wire=wire,samples=samples,events=json.loads(json.dumps(list(r.events),allow_nan=False)),config=config,
                runtime=deepcopy(a.runtime_document),report=r.reduced_axi_observation_reports()[ALIAS],
                identity=r.identity_document(),final_state=r.final_state_document(),
                local_ticks=dict(r.local_ticks),error=error,start_time=started,end_time=time.time(),
                memory_preimages={ALIAS:[[mid,offset,cell.value,cell.version,cell.writer_kind,cell.writer_event_id]
                    for (mid,offset),cell in sorted(memory._bytes.items())]},
                transaction_key_preimages=capture_transaction_preimages(cpu.service),initial_memory_preimages=initial_memory_preimages)
            if proc is not None:
                result['process'].update(returncode=proc.poll(),reaped=proc.poll() is not None,end_time=time.time())
            save(directory/'run.json',result)
    require(cpu.process is None and proc.poll() is not None,'native process not reaped')
    verify_native_join(result)
    trace=ScenarioTrace('0'*64,'complete',r.events,r.local_ticks,'','1'*64)
    for name,writer in [('jsonl',_write_online_trace_jsonl),('zlib',_write_online_trace_zlib)]:
        target=directory/name;target.mkdir();saved=writer(target,trace)
        require(saved.semantic_sha256==semantic_digest(result['events'],result['local_ticks'],'complete'),'writer semantic digest differs')
    verify_validated_cache_archive(directory/'build-bytes',build,prebuild,prebuild_directory,originals=True)
    verify_build_snapshot(prebuild_directory,prebuild,originals=True)
    verify_archive(freeze['directory'],freeze['manifest'],originals=True)
    return result


@pytest.mark.skipif(os.environ.get('MYFUZZ_VEXII_REAL')!='1',reason='explicit reviewed native gate')
def test_real_generated_runner_reduced_axi_first_fresh():
    output=Path(os.environ['MYFUZZ_VEXII_EVIDENCE']);output.mkdir(parents=True,exist_ok=False)
    freeze=json.loads(Path(os.environ['MYFUZZ_TASK5_FREEZE']).read_text())
    verify_archive(freeze['directory'],freeze['manifest'],originals=True)
    # Imported external modules plus all declared repository inputs are frozen
    # before preparation/native launch. Later imports must already be selected.
    a=artifact();save(output/'runtime.json',a.runtime_document)
    (output/'runtime.sv').write_text(a.runtime_sv)
    (output/'driver.cpp').write_text(a.cpp_text)
    (output/'wrapper.sv').write_text(a.structural.wrapper_sv)
    save(output/'abi.json',a.structural.abi_document)
    save(output/'build-plan.json',a.structural.build_document)
    save(output/'program.json',dict(words=list(PROGRAM),bytes_hex=b''.join(w.to_bytes(4,'little') for w in PROGRAM).hex()))
    rendered=archive_files([output/name for name in ('runtime.json','runtime.sv','driver.cpp','wrapper.sv','abi.json','build-plan.json','program.json')],output/'rendered-bytes')
    save(output/'rendered-manifest.json',rendered)
    prebuild=freeze_declared_build(a,ROOT,output/'prebuild-inputs')
    save(output/'prebuild-input-manifest.json',prebuild)
    imported=archive_files(closure_files(),output/'python-closure')
    save(output/'python-closure-manifest.json',imported)
    save(output/'python-runtime.json',dict(version=sys.version,executable=sys.executable,implementation=sys.implementation.name,pid=os.getpid()))
    cache=Path(os.environ['MYFUZZ_VEXII_CACHE'])
    first=run_one(a,cache,output/'first',freeze,prebuild,output/'prebuild-inputs')
    fresh=run_one(a,cache,output/'fresh',freeze,prebuild,output/'prebuild-inputs')
    comparison=compare_runs(first,fresh)
    save(output/'comparison.json',comparison)
    verify_build_snapshot(output/'prebuild-inputs',prebuild,originals=True)
    verify_archive(output/'rendered-bytes',rendered,originals=True)
    verify_archive(output/'python-closure',imported,originals=True)
    allowed={m['source'] for m in imported['members']}|{m['source'] for m in freeze['manifest']['members']}
    require(set(map(str,closure_files()))<=allowed,'unfrozen late imported Python module')
    save(output/'native-test-success.json',dict(schema_version='task5_native_test_success.v1',
        native_tests_executed=1,pytest_process_pid=os.getpid(),independent_native_processes=2,comparison_sha256=digest(comparison),
        authority='observation_only',runtime_accepted=False,semantic_accepted=False))
