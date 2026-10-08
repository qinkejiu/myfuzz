"""Cold-reset identity survives immediate actual GPIO evidence draining."""
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from tests.scenario.test_runner_source_provenance import configured_runner


def test_cold_reset_ram_invalidation_points_to_reset_barrier_after_gpio_facts():
    runner,_,_=configured_runner(gpio_causal=True)
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x1000,64),),
                            initialization_seed=7,max_initialized_bytes=64)
    service=MemoryService(memory,TransactionLedger())
    key=TransactionKey('reset-review','case','a',0,'data',1)
    service.write(key,0x1000,0xa5,width_bytes=4,byte_enable=15)
    runner.sessions['a'].memory=memory
    runner.state_dependencies.ingest(service.events)
    for session in runner.sessions.values():
        session.reset_local=lambda:{'cancelled_responses':0}
    def actual_gpio_reset():
        runner.sessions['b'].gpio_events=[dict(kind='gpio_reset',component='b',
            reset_epoch=1,source_epoch=1,local_tick=4)]
        return {'cancelled_responses':0}
    runner.sessions['b'].reset_local=actual_gpio_reset
    runner._status='running'
    runner.reset_all('cold_all')
    barrier=next(e for e in runner.events if e.get('kind')=='reset_barrier')
    gpio_reset=next(e for e in runner.events if e.get('kind')=='gpio_reset_resource')
    assert gpio_reset['event_id']>barrier['event_id']
    invalidations=[e for e in runner.events if e.get('kind')=='state_dependency'
                   and e.get('edge_kind')=='INVALIDATE']
    assert len(invalidations)==4
    assert all(e['target']==f"reset:{barrier['event_id']}" for e in invalidations)
    assert all(e['producer_event_id']==barrier['event_id'] for e in invalidations)
    assert all(e['generation']==0 for e in invalidations)
    assert memory.generation==1
