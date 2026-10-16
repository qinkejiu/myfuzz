"""Prepare or explicitly execute the bounded, observation-only BOOM MEIP gate.

Default/freeze paths never construct a session or invoke a tool. Native execution
requires a separately authorized new output, source freeze and canonical lock.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from dataclasses import asdict, is_dataclass
import fcntl
import gzip
import hashlib
import json
from pathlib import Path
import threading

STEPS=6000
QUIESCE=512
CAUSE=(1<<63)|11
ISR=0x80000400
SCHEMA='boom_irq_gate_source.v1'
_CAPTURE_LOCK=threading.Lock()


def plain(value):
    if is_dataclass(value):return plain(asdict(value))
    if isinstance(value,dict):return {k:plain(v) for k,v in value.items()}
    if isinstance(value,(tuple,list)):return [plain(v) for v in value]
    return value


def encoded(value):return (json.dumps(plain(value),sort_keys=True,allow_nan=False,separators=(',',':'))+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()


def confined(path,root=Path('/root/fanzehui')):
    path=Path(path).absolute();root=Path(root).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('symlink in gate path')
    path=path.resolve()
    if not path.is_relative_to(root.resolve()):raise ValueError('gate path outside allowed root')
    return path


def write_new(path,data):
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('symlink output')
    with path.open('xb') as stream:stream.write(data)


def save_run(path,document):
    with path.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as zipped:zipped.write(encoded(document))


def prepare_freeze(repo):
    from myfuzz.local_harness.build import _discover_host_sources
    repo=Path(repo).resolve()
    names={*_discover_host_sources(),'src/myfuzz/scenario/boom_gpio_irq_verification.py',
           'tests/local_harness/test_boom_irq_verification.py',
           'configs/cpus/boom/component_profile.json','configs/soc/sources.lock.json',
           'configs/soc/closures/pulp_gpio_causal_local.json'}
    for relative in ('configs/cpus/boom_irq','configs/cpus/boom/generated','configs/cpus/boom/runtime',
                     'configs/peripherals/pulp_gpio_causal_local','third_party/soc-pulp-apb-gpio'):
        for path in (repo/relative).rglob('*'):
            if path.is_symlink():raise ValueError('source freeze contains symlink')
            if path.is_file():names.add(path.relative_to(repo).as_posix())
    return dict(schema_version=SCHEMA,steps=STEPS,quiesce=QUIESCE,native_run=False,
        files={name:sha(confined(Path(repo)/name,Path(repo)).read_bytes()) for name in sorted(names)})


def verify_freeze(repo,freeze):
    if freeze!=prepare_freeze(repo):raise ValueError('gate source freeze differs')


def qualified_return(row,mepc):
    from myfuzz.local_harness.boom_irq_contract import observed_mret
    return bool(observed_mret(row) and row.get('csr_evec')==mepc and row.get('mepc')==mepc)


def validate_pulse(events,samples,*,suppressed):
    pulses=[r for r in events if r.get('kind')=='pulse_start']
    if len(pulses)!=1:raise ValueError('exactly one actual IRQ pulse required')
    start,end=pulses[0]['start_cpu_tick'],pulses[0]['end_cpu_tick_exclusive']
    if type(start) is not int or type(end) is not int or end-start!=64:raise ValueError('pulse is not fixed64')
    if [s['cycle'] for s in samples]!=list(range(1,len(samples)+1)) or len(samples)<end:
        raise ValueError('actual CPU prefix incomplete')
    for sample in samples:
        expected=0 if suppressed else int(start<=sample['cycle']<end)
        if (type(sample.get('irq_input')) is not int or sample['irq_input']!=expected
            or sample['probes_pre']['meip']!=expected or sample['probes_post']['meip']!=expected):
            raise ValueError('actual IRQ/MEIP differs from declared delivery')
    return start,end


def normalize_rows(rows,identities):
    """Only direct documentary scope slots, never recurse into payloads."""
    result=deepcopy(rows);replacements={v:'declared:'+k for k,v in identities.items()}
    for row in result:
        for key in ('execution_id','execution','previous_execution_id','raw_event_scope','stream_id'):
            if isinstance(row.get(key),str) and row[key] in replacements:row[key]=replacements[row[key]]
        stream=identities.get('coherent_stream')
        if stream and isinstance(row.get('local_event_id'),str) and row['local_event_id'].startswith(stream+'|'):
            row['local_event_id']=replacements[stream]+row['local_event_id'][len(stream):]
        for key in ('source_transaction',):
            nested=row.get(key)
            if isinstance(nested,dict) and nested.get('execution_id') in replacements:
                nested['execution_id']=replacements[nested['execution_id']]
        for key in ('target_request','target_response','target_apb_access'):
            target=row.get(key)
            transaction=target.get('source_transaction') if isinstance(target,dict) else None
            if isinstance(transaction,dict) and transaction.get('execution_id') in replacements:
                transaction['execution_id']=replacements[transaction['execution_id']]
        receipt=row.get('receipt')
        if row.get('schema_version')=='boom_irq_gate_command.v1' and isinstance(receipt,dict):
            if receipt.get('execution') in replacements:receipt['execution']=replacements[receipt['execution']]
    return result


def _accepted(run):
    return [r['native_event'] for r in run['runtime_events'] if r.get('kind')=='coherent_accepted_raw']


def _word(row):return row['data']>>((row['address']&7)*8)&0xffffffff


def validate_transport(run):
    samples=run['cpu_samples'];execution=run['identities']['cpu_execution']
    commands=[r for r in run['cpu_commands'] if r['operation']=='STEP_IRQ']
    if len(commands)!=len(samples):raise ValueError('actual STEP command count differs')
    for command,sample in zip(commands,samples):
        if (command['execution_id']!=execution or command['args']!=[sample['irq_input']]
            or command.get('response')!=sample):raise ValueError('actual command/edge binding differs')
    actual=[(r['local_tick'],r['native_event']) for r in run['runtime_events'] if r.get('kind')=='coherent_accepted_raw']
    expected=[(s['cycle'],event) for s in samples for event in s['events']]
    if actual!=expected:raise ValueError('accepted raw journal differs from actual edge receipts')
    if any(r['execution_id']!=execution for r in run['runtime_events'] if r.get('kind')=='coherent_accepted_raw'):
        raise ValueError('raw accepted execution differs')
    passive=[r for r in run['source_events'] if r.get('kind')=='boom_irq_passive_sample']
    if len(passive)!=len(samples):raise ValueError('actual passive sample count differs')
    for row,sample in zip(passive,samples):
        if (row['local_tick']!=sample['cycle'] or row['irq_input']!=sample['irq_input']
            or row['probes_pre']!=sample['probes_pre'] or row['probes_post']!=sample['probes_post']):
            raise ValueError('actual passive samples differ')


def validate_run(run,*,suppressed):
    """Refuse incomplete chains. Saved samples are observations, not authority."""
    try:
        if run['error'] is not None or run['status']!='complete':raise ValueError('run did not complete')
        validate_transport(run)
        if len(run['lifecycles']['cpu'])!=2 or len(run['lifecycles']['gpio'])!=1:
            raise ValueError('startup/measured process inventory differs')
        for rows in run['lifecycles'].values():
            if not rows or any(type(r['pid']) is not int or r['pid']<=0 or type(r['exit']) is not int or r['exit']!=0 or r['closed'] is not True for r in rows):
                raise ValueError('actual native lifecycle not reaped0')
        report=run['coherent_report']
        if report['structural_error'] or report.get('normalization_poisoned') or not report['stream_closed'] or run['uncertain_keys']:
            raise ValueError('coherent stream incomplete/uncertain')
        samples=run['cpu_samples'];start,end=validate_pulse(run['events'],samples,suppressed=suppressed)
        injections=[r for r in run['events'] if r.get('kind')=='source_injection' and r.get('action_id')=='pin-rise']
        if len(injections)!=1 or injections[0].get('component')!='gpio' or injections[0].get('port')!='gpio_in' or injections[0].get('value')!=1:
            raise ValueError('actual pin-rise action missing')
        injection_index=run['events'].index(injections[0])
        if not any(r.get('component')=='cpu' and r.get('outputs',{}).get('boot_ready')==1 for r in run['events'][:injection_index]):
            raise ValueError('source rise lacks preceding actual boot ready')
        physical=[r for r in run['gpio_events'] if r.get('kind')=='gpio_tick_observation']
        rises=[r for r in physical if r['pre'].get('interrupt')==0 and r['post'].get('interrupt')==1]
        if len(rises)!=1 or rises[0]['post'].get('gpio_in')!=1:raise ValueError('one actual GPIO IRQ edge required')
        source=[r for r in run['events'] if r.get('kind')=='source_start']
        if len(source)!=1 or source[0]['source_tick']!=rises[0]['local_tick']:raise ValueError('GPIO/binding tick differs')
        deliveries=run['delivery_control']
        if len(deliveries)!=len(samples) or sum(r['requested_irq'] for r in deliveries)!=64:
            raise ValueError('delivery control prefix differs')
        if any(r['requested_irq']!=int(start<=s['cycle']<end) or r['cycle']!=s['cycle'] or r['delivered_irq']!=s['irq_input'] for r,s in zip(deliveries,samples)):
            raise ValueError('controlled delivery differs from real samples')
        accesses=[r for r in run['gpio_events'] if r.get('kind')=='gpio_apb_access']
        queued=[r for r in run['source_events'] if r.get('kind')=='boom_external_a_queued']
        consumed=[r for r in run['source_events'] if r.get('kind')=='boom_external_d_accepted']
        if not (len(accesses)==len(queued)==len(consumed)==len(run['router_deliveries'])):
            raise ValueError('target/source delivery count differs')
        native_rows=_accepted(run)
        native_a=[r for r in native_rows if r['channel']=='A' and 0x4000<=r.get('address',0)<0x5000]
        native_d=[r for r in native_rows if r['channel']=='D' and r.get('external') is True]
        if len(native_a)!=len(queued) or len(native_d)!=len(consumed):raise ValueError('actual external A/D count differs')
        for a,q,c,d,actual_a,actual_d in zip(accesses,queued,consumed,run['router_deliveries'],native_a,native_d):
            key=q['source_transaction'];request=q['native_request'];response=c['native_response']
            if (any(request.get(k)!=v for k,v in actual_a.items()) or response!=actual_d
                or key!=a['source_transaction'] or key!=c['source_transaction'] or key!=d['source_transaction']
                or key['execution_id']!=run['identities']['cpu_execution']
                or d['target_access_id']!=a['access_id'] or d['target_apb_access']!=a
                or a['status']!='observed' or response['source']!=request['source'] or response['size']!=request['size']
                or response['data']!=(0 if a['write'] else d['read_value'])):
                raise ValueError('actual source/target/response identity differs')
        reads=[r for r in accesses if r['write'] is False and r['decoded_offset']==0x24]
        expected=[0] if suppressed else [0,1,0]
        if [r['read_rdata'] for r in reads]!=expected:raise ValueError('actual GPIO status/clear reads differ')
        outputs=run['last_cpu_outputs'];raw=_accepted(run)
        stores=[r for r in raw if r['channel']=='A' and r['opcode'] in (0,1) and 0x3010<=r['address']<0x3030]
        probe_rows=[(s['cycle'],phase,s[phase]) for s in samples for phase in ('probes_pre','probes_post')]
        interrupts=[(tick,p) for tick,_,p in probe_rows if (p['rob_exception'] and p['rob_cause']==CAUSE) or (p['csr_exception'] and p['csr_cause']==CAUSE)]
        mrets=[(tick,p) for tick,phase,p in probe_rows if phase=='probes_pre' and qualified_return(p,outputs.get('ram_3018'))]
        if suppressed:
            if interrupts or mrets or stores or outputs.get('ram_3028')!=0 or outputs.get('ram_3020')!=0:
                raise ValueError('suppressed delivery unexpectedly reached ISR')
        else:
            mepc=outputs['ram_3018']
            if (outputs.get('ram_3010')!=CAUSE or outputs.get('ram_3020')!=1
                or outputs.get('ram_3028')!=(1<<32)|1 or not 0x80000000<=mepc<ISR):
                raise ValueError('actual ISR RAM/foreground result differs')
            rob=[t for t,_,p in probe_rows if p['rob_exception'] and p['rob_cause']==CAUSE]
            csr=[t for t,_,p in probe_rows if p['csr_exception'] and p['csr_cause']==CAUSE and p['csr_evec']==ISR]
            if not rob or not csr or not mrets or len(mrets)!=1 or not start<=min(rob)<=end or min(csr)<min(rob):
                raise ValueError('actual trap/qualified MRET chain missing')
            tick=mrets[0][0]
            if not any(t>tick and 0x80000000<=p['csr_pc']<ISR for t,_,p in probe_rows):
                raise ValueError('actual foreground PC after return missing')
            if not any(r['address']==0x3010 and r['data']==CAUSE for r in stores) or not any(r['address']==0x3018 and r['data']==mepc for r in stores):
                raise ValueError('actual accepted cause/MEPC stores missing')
            resumed_ticks=[s['cycle'] for s in samples for r in s['events'] if r['channel']=='A' and r.get('opcode') in (0,1) and r.get('address')==0x302c and _word(r)==1]
            if not resumed_ticks or min(resumed_ticks)<=tick:raise ValueError('foreground store precedes actual MRET')
            expected_words={0x3020:1,0x3024:0,0x3028:1,0x302c:1}
            if any(not any(r['address']==addr and _word(r)==value for r in stores) for addr,value in expected_words.items()):
                raise ValueError('actual accepted ISR/foreground stores missing')
        return dict(suppressed=suppressed,pulse_start=start,pulse_end=end,status_reads=expected)
    except (KeyError,TypeError,IndexError) as error:
        raise ValueError('actual IRQ evidence chain missing') from error


def normalize_gpio_wire(rows,identities):
    result=normalize_rows(rows,identities)
    execution=identities['gpio_execution']
    for row in result:
        line=row.get('raw_line')
        if not isinstance(line,str):continue
        header,separator,body=line.partition(' ')
        if header not in ('RESULT','ERROR','ACKED'):continue
        nonce,separator,tail=body.partition(' ')
        if nonce!=execution or not separator:raise ValueError('GPIO wire execution differs from actual process')
        row['raw_line']=header+' declared:gpio_execution '+tail
    return result


def compare_fresh(first,fresh):
    if first['fault_mode']!=fresh['fault_mode']:raise ValueError('fresh fault mode differs')
    for key,value in first['identities'].items():
        if not value or value==fresh['identities'].get(key):raise ValueError('fresh declared identity reused')
    if first.get('identity')!=fresh.get('identity'):raise ValueError('fresh source/artifact identity differs')
    for side in ('cpu','gpio'):
        if set(r['pid'] for r in first['lifecycles'][side]) & set(r['pid'] for r in fresh['lifecycles'][side]):
            raise ValueError('fresh native PID reused')
    for side in ('cpu','gpio'):
        a=[{k:v for k,v in row.items() if k!='pid'} for row in first['lifecycles'][side]]
        b=[{k:v for k,v in row.items() if k!='pid'} for row in fresh['lifecycles'][side]]
        if normalize_rows(a,first['identities'])!=normalize_rows(b,fresh['identities']):
            raise ValueError('fresh native lifecycle differs: '+side)
    fields=('cpu_samples','delivery_control','cpu_outputs','last_cpu_outputs','gpio_samples')
    for field in fields:
        if first[field]!=fresh[field]:raise ValueError('fresh full prefix differs: '+field)
    if normalize_gpio_wire(first['gpio_transport_reads'],first['identities'])!=normalize_gpio_wire(fresh['gpio_transport_reads'],fresh['identities']):
        raise ValueError('fresh whole GPIO transport prefix differs')
    for field in ('coherent_report','coherent_coverage'):
        if normalize_rows([first[field]],first['identities'])!=normalize_rows([fresh[field]],fresh['identities']):
            raise ValueError('fresh coherent documentary scope differs: '+field)
    for field in ('events','runtime_events','source_events','gpio_events','router_deliveries','cpu_commands','gpio_commands','cpu_transport_reads'):
        a=normalize_rows(first[field],first['identities']);b=normalize_rows(fresh[field],fresh['identities'])
        if a!=b:
            index=next((i for i,(x,y) in enumerate(zip(a,b)) if x!=y),min(len(a),len(b)))
            raise ValueError('fresh full prefix differs: '+field+' at '+str(index))


def _run_one(*,repo,cpu_output,cache_dir,suppressed=False):
    """Only called by explicit native entry; global factory substitution is locked.

    Scoped capture subclasses preserve all base transport logic and are restored
    even on failure. No guessed sample fields or replacement target are added.
    """
    from myfuzz.local_harness import boom_irq_scenario_session as adapter_module
    from myfuzz.scenario import boom_gpio_irq_runner as factory_module
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.replay import _record_with_runner
    from myfuzz.local_harness.boom_irq_contract import validate_probe_inventory
    commands=[];gpio_commands=[];reads=[];gpio_reads=[];lives={'cpu':[],'gpio':[]};delivery=[];outputs=[]
    original_native=adapter_module.GeneratedBoomIrqCpuSession
    original_gpio=factory_module.GeneratedPulpGpioSession
    if not _CAPTURE_LOCK.acquire(blocking=False):raise RuntimeError('capture factory already active')
    class Native(original_native):
        def _read(self):
            proc=self._process
            row=next((r for r in lives['cpu'] if r['pid']==proc.pid),None)
            if row is None:
                row=dict(pid=proc.pid,args=list(proc.args),execution_id=self.execution_id,closed=False,exit=None,
                         binary_sha256=sha(Path(proc.args[0]).read_bytes()))
                lives['cpu'].append(row)
            try:line=self._reader.readline(self._process.stdout)
            except BaseException as exc:
                reads.append(dict(execution_id=self.execution_id,error=dict(type=type(exc).__name__,detail=str(exc)),partial_buffer_hex=self._reader._buffer.hex()));raise
            raw_record=dict(execution_id=self.execution_id,raw_line=line)
            reads.append(raw_record)
            value=json.loads(line)
            raw_record['response']=deepcopy(value)
            if 'ready' in value:
                validate_probe_inventory(value['probes']);row['ready']=deepcopy(value)
            return value
        def _command(self,operation,*args):
            record=dict(schema_version='boom_irq_gate_command.v1',execution_id=self.execution_id,
                        operation=operation,args=list(args),wire_line=' '.join(map(str,(operation,*args)))+'\n')
            commands.append(record)
            if len(commands)>100000:raise RuntimeError('native command record bound exceeded')
            try:
                value=super()._command(operation,*args);record['response']=deepcopy(value);return value
            except BaseException as exc:
                record['error']=dict(type=type(exc).__name__,detail=str(exc));raise
        def close(self):
            proc=getattr(self,'_process',None)
            try:return super().close()
            finally:
                if proc is not None:
                    row=next((r for r in lives['cpu'] if r['pid']==proc.pid),None)
                    if row is None:
                        row=dict(pid=proc.pid,args=list(proc.args),execution_id=getattr(self,'execution_id',None));lives['cpu'].append(row)
                    row.update(closed=self._process is None and proc.poll() is not None,exit=proc.poll())
    class Gpio(original_gpio):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            readline=self._reader.readline
            def captured_readline(stream):
                record=dict(execution_id=self._execution)
                gpio_reads.append(record)
                if len(gpio_reads)>30000:raise RuntimeError('GPIO raw record bound exceeded')
                try:
                    line=readline(stream);record['raw_line']=line;return line
                except BaseException as exc:
                    record.update(error=dict(type=type(exc).__name__,detail=str(exc)),partial_buffer_hex=self._reader._buffer.hex());raise
            self._reader.readline=captured_readline
        def command(self,operation,fields=()):
            record=dict(schema_version='boom_irq_gate_command.v1',operation=operation,fields=list(fields))
            gpio_commands.append(record)
            if len(gpio_commands)>20000:raise RuntimeError('GPIO command record bound exceeded')
            try:
                receipt=super().command(operation,fields);record['receipt']=plain(receipt);return receipt
            except BaseException as exc:
                record['error']=dict(type=type(exc).__name__,detail=str(exc));raise
        def _abort(self):
            proc=self.process
            try:return super()._abort()
            finally:
                if proc is not None:
                    row=next((r for r in lives['gpio'] if r['pid']==proc.pid),None)
                    if row is None:
                        row=dict(pid=proc.pid,args=list(proc.args),execution_id=getattr(self,'_execution',None));lives['gpio'].append(row)
                    row.update(closed=self.process is None and proc.poll() is not None,exit=proc.poll())
        def begin_case(self,name):
            super().begin_case(name)
            lives['gpio'].append(dict(pid=self.process.pid,args=list(self.process.args),execution_id=self._execution,closed=False,exit=None))
        def end_case(self):
            proc=self.process
            try:return super().end_case()
            finally:
                if proc is not None:
                    row=next((r for r in lives['gpio'] if r['pid']==proc.pid),None)
                    if row is None:
                        row=dict(pid=proc.pid,args=list(proc.args),execution_id=self._execution);lives['gpio'].append(row)
                    row.update(closed=self.process is None and proc.poll() is not None,exit=proc.poll())
    adapter_module.GeneratedBoomIrqCpuSession=Native
    factory_module.GeneratedPulpGpioSession=Gpio
    runner=None;cpu=None;gpio=None;error=None;trace=None;identities={};identity=None
    try:
        runner=factory_module.make_boom_gpio_irq_runner(repo=repo,cpu_output=cpu_output,cache_dir=cache_dir)
        cpu,gpio=runner.sessions['cpu'],runner.sessions['gpio']
        step=cpu.step_local
        def measured(inputs):
            requested=inputs['irq'];delivered=0 if suppressed else requested
            record=dict(cycle=cpu.local_ticks+1,requested_irq=requested,delivered_irq=delivered)
            delivery.append(record)
            value=step({'irq':delivered});outputs.append(deepcopy(value))
            identities.update(cpu_execution=cpu._native.execution_id,cpu_startup_execution=lives['cpu'][0]['execution_id'],coherent_stream=cpu._stream.stream_id,
                              gpio_execution=gpio._execution,runner_execution=runner.execution_id)
            return value
        cpu.step_local=measured
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=300000,max_scheduler_steps=STEPS,
            max_quiesce_steps=QUIESCE,max_local_cycles_per_component=20000))
        identity=runner.identity_document()
        trace=_record_with_runner(factory_module.make_boom_gpio_irq_genome(max_steps=STEPS),runner)
    except BaseException as exc:error=dict(type=type(exc).__name__,detail=str(exc))
    finally:
        if runner is not None:
            try:runner.finalize()
            except BaseException as exc:error=error or dict(type=type(exc).__name__,detail=str(exc))
        adapter_module.GeneratedBoomIrqCpuSession=original_native
        factory_module.GeneratedPulpGpioSession=original_gpio
        _CAPTURE_LOCK.release()
    return plain(dict(schema_version='boom_irq_gate_run.v1',error=error,
        status=None if trace is None else trace.status,fault_mode='suppressed_delivery' if suppressed else 'positive',
        controlled_environment_fault=suppressed,identities=identities,identity=identity,lifecycles=lives,
        cpu_commands=commands,cpu_transport_reads=reads,gpio_commands=gpio_commands,gpio_transport_reads=gpio_reads,
        cpu_samples=[r['response'] for r in commands if r['operation']=='STEP_IRQ' and 'response' in r],
        gpio_samples=[s for r in gpio_commands for s in r.get('receipt',{}).get('payload',{}).get('samples',[])],
        delivery_control=delivery,cpu_outputs=outputs,last_cpu_outputs=outputs[-1] if outputs else {},
        events=[] if runner is None else list(runner.events),
        runtime_events=[] if cpu is None else cpu.runtime_events,
        source_events=[] if cpu is None else cpu.source_events,
        gpio_events=[] if gpio is None else gpio.gpio_events,
        router_deliveries=[] if cpu is None else cpu.router.deliveries,
        uncertain_keys=[] if cpu is None else [str(k) for k in cpu.mmio_ledger.uncertain_keys],
        coherent_report={} if cpu is None else cpu.coherent_report(),
        coherent_coverage={} if cpu is None else cpu.coherent_coverage(),
        source_authority=False,isa_retirement_authority=False,new_cpp_build=False))


def verify(*,repo,cpu_output,cache_dir,output,freeze_path,freeze_sha256,artifact_sha256,heavy_lock):
    from myfuzz.local_harness.build import host_source_discovery_scope
    repo=confined(repo);cpu_output=confined(cpu_output);cache_dir=confined(cache_dir)
    output=confined(output);heavy_lock=confined(heavy_lock);freeze_path=confined(freeze_path)
    if repo!=Path(__file__).resolve().parents[3]:raise ValueError('gate source checkout differs')
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (repo,cpu_output,cache_dir,heavy_lock)):
        raise ValueError('gate output exists or overlaps inputs')
    raw=freeze_path.read_bytes()
    if sha(raw)!=freeze_sha256:raise ValueError('source freeze SHA differs')
    artifact=(cpu_output/'irq-session-artifact.json').read_bytes()
    if sha(artifact)!=artifact_sha256:raise ValueError('reviewed artifact SHA differs')
    manifest=json.loads(artifact)
    if (manifest.get('runtime_verified') is not False or manifest.get('source_authority') is not False
        or manifest.get('metadata_finalization',{}).get('new_cpp_build') is not False):
        raise ValueError('expected explicit metadata-only origin')
    before={name:sha(confined(cpu_output/name,cpu_output).read_bytes()) for name in manifest['session_files']}
    if before!=manifest['session_files']:raise ValueError('artifact closure bytes differ')
    with heavy_lock.open('a') as lock,host_source_discovery_scope():
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        verify_freeze(repo,json.loads(raw))
        output.mkdir(parents=True,exist_ok=False)
        write_new(output/'incomplete.json',encoded(dict(status='incomplete')))
        write_new(output/'source-freeze.json',raw);write_new(output/'irq-session-artifact.json',artifact)
        summary=dict(schema_version='boom_irq_native_gate.v1',status='failed',source_authority=False,
                     isa_retirement_authority=False,full_P6=False,new_cpp_build=False)
        try:
            runs={}
            for name,suppressed in [('first',False),('fresh',False),('suppressed',True)]:
                run=_run_one(repo=repo,cpu_output=cpu_output,cache_dir=cache_dir,suppressed=suppressed)
                save_run(output/(name+'.json.gz'),run)
                validate_run(run,suppressed=suppressed);runs[name]=run
            compare_fresh(runs['first'],runs['fresh'])
            verify_freeze(repo,json.loads(raw))
            if (cpu_output/'irq-session-artifact.json').read_bytes()!=artifact or any(sha((cpu_output/n).read_bytes())!=h for n,h in before.items()):
                raise ValueError('artifact changed during gate')
            summary.update(status='pass',full_fresh_prefix_equal=True,suppressed_delivery_rejected=True,
                artifact_sha256=artifact_sha256,freeze_sha256=freeze_sha256,
                identities={name:r['identities'] for name,r in runs.items()})
        except BaseException as exc:summary['error']=dict(type=type(exc).__name__,detail=str(exc))
        finally:
            audit=dict(before_artifact_files=before,before_manifest_sha256=sha(artifact))
            try:
                verify_freeze(repo,json.loads(raw))
                after={name:sha(confined(cpu_output/name,cpu_output).read_bytes()) for name in before}
                audit.update(source_after_matches=True,after_artifact_files=after,after_manifest_sha256=sha((cpu_output/'irq-session-artifact.json').read_bytes()))
                if after!=before or audit['after_manifest_sha256']!=sha(artifact):raise ValueError('input artifact changed')
            except BaseException as exc:
                audit['error']=dict(type=type(exc).__name__,detail=str(exc));summary.update(status='failed',input_audit_failed=True)
            write_new(output/'input-audit.json',encoded(audit))
        write_new(output/'summary.json',encoded(summary))
        if summary['status']=='pass':(output/'incomplete.json').unlink()
        else:raise RuntimeError('IRQ native gate failed; original prefixes retained at '+str(output))
        return summary


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-native',action='store_true');parser.add_argument('--write-freeze',type=Path)
    for name in ('repo','cpu-output','cache-dir','output','freeze-path','heavy-lock'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--freeze-sha256');parser.add_argument('--artifact-sha256')
    args=parser.parse_args(argv)
    if args.write_freeze:
        if args.run_native or args.repo is None:parser.error('freeze requires repo and no native execution')
        write_new(args.write_freeze,encoded(prepare_freeze(args.repo)));return 0
    if not args.run_native:
        print(json.dumps(dict(native='not_executed',source_only=True)));return 0
    values=vars(args);values.pop('run_native');values.pop('write_freeze')
    if any(v is None for v in values.values()):parser.error('all native paths and pins required')
    print(json.dumps(verify(**values),sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
