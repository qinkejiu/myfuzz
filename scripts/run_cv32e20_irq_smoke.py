#!/usr/bin/env python3
"""Fixed-ROM CPU IRQ/retirement smoke, without F5/F6 source authority."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def fixed_program(boot):
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load,_addi,_sw,_jal
    vector=0x10200;handler=0x10400;marker=0x20000
    def csr(address,source,operation=1,destination=0):
        return address<<20|source<<15|operation<<12|destination<<7|0x73
    words=[*_lui_addi_load(3,vector|1),csr(0x305,3),*_lui_addi_load(3,1<<11),csr(0x304,3,2),
        _addi(3,0,8),csr(0x300,3,3),*_lui_addi_load(1,marker),_addi(2,0,1),_sw(2,1,0),
        *([0x13]*16),csr(0x300,3,2),_addi(6,0,9)]
    park=boot+4*len(words);words.append(_jal(park,park))
    isr=[*_lui_addi_load(4,marker),csr(0x341,0,2,7),_sw(7,4,4),_addi(5,0,42),_sw(5,4,0),0x30200073]
    def encode(rows):return b''.join(word.to_bytes(4,'little') for word in rows)
    images={boot:encode(words),vector:encode([_jal(vector,handler)]),
        vector+11*4:encode([_jal(vector+11*4,handler)]),handler:encode(isr)}
    return dict(boot=boot,vector=vector,handler=handler,marker=marker,park=park,
        mret=handler+4*(len(isr)-1),images={str(k):v.hex() for k,v in images.items()})


def inspect_evidence(events,program,marker,mepc):
    """Check documentary joins against actual parsed/native Runner observations."""
    from myfuzz.scenario.irq_return_successor import validate_return_successor
    responses=[e for e in events if e.get('kind')=='instr_response']
    if not responses or responses[0].get('address')!=program['boot']:
        raise ValueError('actual-first-fetch-does-not-match-source-backed-boot')
    samples=[e for e in events if e.get('kind')=='cpu_external_irq_sample']
    if not any(e.get('actual_pre_input')==1 and e.get('irq_masked_pre')==1 for e in samples):
        raise ValueError('actual-high-IRQ-while-masked-not-observed')
    takes=[e for e in events if e.get('kind')=='cpu_external_irq_taken']
    if len(takes)!=1:raise ValueError('one-actual-native-take-required')
    take=takes[0];serial=take.get('irq_serial_observation',{}).get('decision',{})
    token=serial.get('value')
    if serial.get('status')!='observed' or type(token) is not int or token<=0:
        raise ValueError('actual-native-decision-serial-required')
    retired=[e for e in events if e.get('kind')=='cpu_retire']
    linked=[e for e in retired if e.get('irq_serial_observation',{}).get('retirement',{}).get('value')==token]
    if len(linked)!=1 or linked[0].get('intr')!=1:
        raise ValueError('unique-real-retirement-serial-join-required')
    mrets=[e for e in retired if e.get('pc_rdata')==program['mret'] and e.get('insn')==0x30200073]
    if len(mrets)!=1:raise ValueError('actual-MRET-retirement-required')
    following=[e for e in retired if e['order']>mrets[0]['order']]
    if not following:raise ValueError('actual-MRET-successor-required')
    successor=following[0]
    pc=validate_return_successor(mrets[0],successor,start=program['boot'],end=0x11000)
    if pc!=mepc:raise ValueError('actual-MRET-successor-does-not-match-saved-mepc')
    code={int(base)+offset:int.from_bytes(bytes.fromhex(data)[offset:offset+4],'little')
        for base,data in program['images'].items() for offset in range(0,len(bytes.fromhex(data)),4)}
    fetched=[e for e in responses if e.get('address')==pc and e.get('rdata')==code.get(pc)
        and e.get('local_tick',e.get('response_tick',0))<=successor['local_tick']]
    if successor.get('insn')!=code.get(pc) or not fetched:
        raise ValueError('actual-successor-fetch-bytes-required')
    writes=[e for e in events if e.get('kind')=='memory_write' and e.get('address')==program['marker']]
    if marker!=42 or not any(e.get('value')==42 for e in writes):
        raise ValueError('actual-ISR-RAM-marker-required')
    stores=[e for e in retired if e.get('mem_addr')==program['marker'] and e.get('mem_wmask')==15
        and e.get('mem_wdata')==42 and e.get('insn',0)&0x7f==0x23]
    if len(stores)!=1:raise ValueError('actual-ISR-store-retirement-required')
    if not any(e.get('local_tick',0)>take['local_tick'] and e.get('actual_pre_input')==0 for e in samples):
        raise ValueError('actual-IRQ-low-after-take-required')
    return dict(first_fetch=program['boot'],marker=marker,mepc=mepc,return_pc=pc,
        decision_serial=token,linked_retirement_pc=linked[0]['pc_rdata'],
        retirements=[{key:e.get(key) for key in ('order','pc_rdata','insn','intr','mem_addr','mem_wmask','mem_wdata')} for e in retired],
        source_authority='unknown-host-driven-IRQ',grants_F5=False,grants_F6=False)


def _save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def execute_once(artifact,program,*,base,cache,output,max_steps):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    output.mkdir();memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),initialization_seed=0,max_initialized_bytes=0x20000)
    memory.preload(program['marker'],bytes(8))
    for address,data in program['images'].items():memory.preload(int(address),bytes.fromhex(data))
    router=DataflowRouter(())
    cpu=GeneratedCve2Session(artifact,base_dir=base,cache_dir=cache,memory=memory,router=router,native_irq_receipts=True,physical_tick_samples=True)
    cpu.configure_built_executable_receipt()
    ownership=compile_ownership((InputField('cpu','irq',1),),(InputOwner('cpu','irq',0,1,'source','host-irq'),))
    runner=ScenarioRunner(sessions={'cpu':cpu},ownership=ownership,bindings=())
    events=[];stage='begin';result=None
    with record_local_commands() as recording:
        try:
            runner.begin_test('fixed-cpu-irq-smoke');runner.inject_source('cpu','irq',0,direction='IP_TO_CPU');level=0;taken=False
            cursor=0;stage='steps'
            for _ in range(max_steps):
                runner.step('cpu');new=runner.events_since(cursor);events.extend(new);cursor=runner.event_count
                if not taken and any(e.get('kind')=='cpu_external_irq_taken' for e in new):
                    taken=True;level=0;runner.inject_source('cpu','irq',0,direction='IP_TO_CPU')
                marker=memory.read(program['marker'],4,transaction_id='smoke-monitor').value
                if marker==1 and level==0 and not taken:
                    runner.inject_source('cpu','irq',1,direction='IP_TO_CPU');level=1
                mrets=[e for e in events if e.get('kind')=='cpu_retire' and e.get('pc_rdata')==program['mret']]
                if mrets and any(e.get('kind')=='cpu_retire' and e.get('order',0)>mrets[0]['order'] for e in events):break
            else:raise ValueError('fixed-CPU-IRQ-smoke-step-budget-exhausted')
            stage='checks';mepc=memory.read(program['marker']+4,4,transaction_id='smoke-mepc-monitor').value
            result=inspect_evidence(events,program,marker,mepc)
        except BaseException as error:
            _save(output/'failure.json',dict(stage=stage,error_type=type(error).__name__,error=str(error)));raise
        finally:
            try:runner.finalize()
            finally:
                _save(output/'events.json',list(runner.events));_save(output/'local_commands.json',recording.export_sessions())
                _save(output/'executions.json',recording.export_executions())
    identities=recording.export_executions()
    if len(identities)!=1 or identities[0].get('exit_code')!=0 or not identities[0].get('reaped'):
        raise ValueError('actual-native-process-clean-exit-required')
    _save(output/'result.json',result)
    return result,identities[0]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--native',action='store_true',required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--max-steps',type=int,default=1000);args=parser.parse_args();base=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(base/'src'))
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    if args.output.exists():raise ValueError('smoke output must not exist')
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        artifact=_artifact('configs/cpus/cv32e20/component_profile.json','cpu')
        boot=source_backed_boot_fetch(artifact.plan.profile,base_dir=base,configured_boot_base=artifact.runtime_document['boot_contract']['configured_boot_base'])
        program=fixed_program(boot);_save(args.output/'program.json',program)
        original,old=execute_once(artifact,program,base=base,cache=args.cache,output=args.output/'original',max_steps=args.max_steps)
        fresh,new=execute_once(artifact,program,base=base,cache=args.cache,output=args.output/'fresh',max_steps=args.max_steps)
        if (type(old.get('pid')) is not int or type(new.get('pid')) is not int
                or old['pid']==new['pid'] or not old.get('execution_nonce')
                or not new.get('execution_nonce') or old['execution_nonce']==new['execution_nonce']):
            raise ValueError('fresh-independent-native-process-required')
        if original!=fresh:raise ValueError('fresh-fixed-CPU-semantic-mismatch')
    _save(args.output/'summary.json',dict(status='verified',fresh_matches=True,processes=[old,new],
        semantic_sha256=sha256(json.dumps(original,sort_keys=True).encode()).hexdigest(),scope='CPU-IRQ-retirement-smoke-only',grants_F5=False,grants_F6=False))
    print(json.dumps(dict(status='verified',output=str(args.output))))


if __name__=='__main__':main()
