"""Declared request refusals on actual private objects, software transport only.

These are pre-command policy tests, not GPIO hardware error-response oracles.
Prepared only: execute after the owner announces the next stable source window.
"""
from copy import deepcopy
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from tests.integration.test_register_field_read_replay import field_factory
from tests.scenario.test_register_program_runtime import request


@pytest.fixture(scope='module')
def actual_context(tmp_path_factory):
    assembly=api.make_register_assembly(advance_rounds=1,max_program_bytes=64)
    factory=field_factory(api.make_register_factory(cache_dir=tmp_path_factory.mktemp('permission-render'),assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=api.make_register_runtime_factory(assembly)(session)
    session.begin()
    yield runtime,session
    session.finish()


def before_effects(session):
    runner=session.runner;cpu=runner.sessions['cpu'];ledger=cpu.service.ledger
    return deepcopy(dict(commands={name:(target._sequence,target.local_ticks) for name,target in runner.sessions.items()},
        events=list(runner._events),gate=session.prerequisite_gate.document(),
        waiting=cpu.waiting_instruction_address,memory=cpu.memory.state_summary(),
        slots=frozenset(cpu.memory._instruction_slots),ledger=ledger._entries,
        channel_sequences=ledger._next_channel_sequence,target_sequences=ledger._next_target_sequence))


@pytest.mark.parametrize('changes',[
    dict(register='PADIN',value=1),dict(register='INTSTATUS',value=1),
    dict(register='PADOUTSET',field='bits',operation='register_read',value=None,result_address=0x10004),
    dict(register='PADOUTCLR',field='bits',operation='register_read',value=None,result_address=0x10004),
    dict(value=True),dict(value=-1),dict(value=0x100000000),
    dict(register='INTTYPE_HIGH',field='pin31',read_modify_write=True,value=4),
    dict(register='PADCFG_0',field='pin7',read_modify_write=True,value=16),
    dict(field='absent'),dict(endpoint_id='foreign.bus'),
    dict(register='PADCFG_0',field='pin7',value=3,read_modify_write=False),
    dict(register='INTSTATUS',operation='register_read',value=None,result_address=0x10004,allow_side_effect=True),
    dict(register='PADDIR',operation='register_read',value=None,result_address=0x10005),
])
def test_declared_permission_width_mask_refusal_precedes_any_command(actual_context,changes):
    runtime,session=actual_context
    snapshot=before_effects(session)
    with pytest.raises(ValueError):
        runtime.prepare(request(target_instance='gpio_a',**changes))
    assert before_effects(session)==snapshot
