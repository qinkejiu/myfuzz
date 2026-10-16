"""Actual generated-session lifecycle, software fetched-word driver; never RTL."""
import json
from pathlib import Path
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap, IBEX_STREAM_CPU_PROGRAM
from tests.scenario.test_register_alias_verifier import alias_factory
from tests.scenario.test_register_program_runtime import request


def lifecycle_factory(factory, directory):
    """READY/END real processes; actual _serve fetches each bootstrap word."""
    create_base=alias_factory(factory)
    def create():
        runner=create_base();begin_base=runner.begin_test;case_steps=runner.step_batch
        cpu=runner.sessions['cpu'];registers=[0]*32;fetch={'address':IBEX_STREAM_CPU_PROGRAM.first_fetch,'epoch':None}
        for name,target in runner.sessions.items():
            digest,asserted,released,_=target._expected_ready()
            binary=directory/(name+'-lifecycle.py')
            binary.write_text('#!/usr/bin/env python3\nimport sys\nprint('+repr(f'READY local_driver.v1 {digest} {asserted:x} {released:x}')+',flush=True)\nfor line in sys.stdin:\n if line.strip()=="END":break\n')
            binary.chmod(0o700);target._binary=binary
        def begin(case_id):
            begin_base(case_id)
            for target in runner.sessions.values():target.begin_case(case_id)
        def steps(order):
            active=runner._test_session._register_program_runtime._active_submission
            if active is not None:return case_steps(order)
            if cpu.waiting_instruction_address is not None:return
            if fetch['epoch']!=cpu.reset_epoch:
                fetch['epoch']=cpu.reset_epoch;fetch['address']=IBEX_STREAM_CPU_PROGRAM.first_fetch;registers[:]=[0]*32
            address=fetch['address'];cpu._pending_instr=None
            response=cpu._serve('instr',0,address,0,15)
            runner._append_external_events('cpu',len(runner._events))
            if response is None:return
            word=response[0];op=word&127;rd=word>>7&31;rs1=word>>15&31;rs2=word>>20&31;next_address=address+4
            if op==0x37:registers[rd]=word&0xfffff000
            elif op==0x13:
                assert word>>12&7==0
                imm=word>>20;imm-=4096 if imm&2048 else 0
                registers[rd]=(registers[rs1]+imm)&0xffffffff
            elif op in (0x03,0x23):
                assert word>>12&7==2
                imm=(word>>25<<5)|(word>>7&31) if op==0x23 else word>>20
                imm-=4096 if imm&2048 else 0
                bus=(registers[rs1]+imm)&0xffffffff;cpu._pending_data=None
                response=cpu._serve('data',int(op==0x23),bus,registers[rs2] if op==0x23 else 0,15)
                runner._append_external_events('cpu',len(runner._events))
                if cpu.router.owns(bus):
                    window=next(w for w in cpu.router.windows if w.base<=bus<w.base+w.size)
                    runner._step_once(window.device_id);response=cpu._pending_data
                assert response is not None
                if op==0x03:registers[rd]=response[0]
                cpu._pending_data=None
            elif op==0x73:assert word>>12&7 in (1,2)  # bootstrap CSR state has no authority role here
            elif op==0x6f:
                imm=((word>>31&1)<<20)|((word>>12&255)<<12)|((word>>20&1)<<11)|((word>>21&1023)<<1)
                imm-=1<<21 if imm&(1<<20) else 0
                registers[rd]=address+4;next_address=address+imm
            else:raise AssertionError('unexpected real bootstrap word '+hex(word))
            registers[0]=0;fetch['address']=next_address;cpu._pending_instr=None
        runner.begin_test=begin;runner.step_batch=steps
        def finish():
            for target in runner.sessions.values():target.end_case()
        runner.finalize=finish
        return runner
    return create


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_reset_requires_recorded_actual_bootstrap_resume(tmp_path,policy):
    assembly=api.make_register_assembly(advance_rounds=1,ordinary_apb_access_evidence={'max_records':32},register_program_verifier={'max_records':8})
    factory=lifecycle_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly),tmp_path)
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=api.make_register_runtime_factory(assembly)(session)
    try:
        with pytest.raises(RuntimeError):session.advance_after_reset(bootstrap.template.schedule_order)
        session.begin()
        with pytest.raises(RuntimeError):session.advance_after_reset(bootstrap.template.schedule_order)
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address==bootstrap.instruction_start:break
            session.advance_initial(bootstrap.template.schedule_order)
        else:raise AssertionError('real software boot did not reach deferred fetch')
        runtime.submit(request(case_id='before',action_id='before-read',target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
        with pytest.raises(RuntimeError):session.advance_after_reset(bootstrap.template.schedule_order)
        epochs={name:target.reset_epoch for name,target in session.runner.sessions.items()}
        session.reset(policy)
        assert all(target.reset_epoch==epochs[name]+1 for name,target in session.runner.sessions.items())
        assert session.runner.sessions['cpu'].waiting_instruction_address is None
        before=(session.runner.event_count,{name:target._sequence for name,target in session.runner.sessions.items()})
        with pytest.raises(ValueError):session.advance_after_reset(('foreign',))
        assert before==(session.runner.event_count,{name:target._sequence for name,target in session.runner.sessions.items()})
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address is not None:break
            session.advance_after_reset(bootstrap.template.schedule_order)
        else:raise AssertionError('reset bootstrap did not reach deferred fetch')
        runtime.submit(request(case_id='after',action_id='after-read',target_instance='gpio_a',operation='register_read',value=None,result_address=0x10008,allow_side_effect=False))
        plan,trace=session.finish_export()
        assert json.loads(plan)['schema_version']==18
        assert trace.status=='complete'
        with pytest.raises(RuntimeError):session.advance_after_reset(bootstrap.template.schedule_order)
        assert any(row.get('kind')=='reset_barrier' for row in trace.events)
        def install(fresh):
            fresh.runner._test_session=fresh
            return api.make_register_runtime_factory(assembly)(fresh)
        comparison=replay_online_session(plan,factory,trace,register_runtime_factory=install)
        assert comparison.matches
    finally:
        for target in session.runner.sessions.values():target.end_case()
