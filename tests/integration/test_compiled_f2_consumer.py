from pathlib import Path
import pytest
from tests.integration.test_compiled_f4_storage_producer import timer_loaded, ROOT


def test_registered_read_selector(tmp_path):
    from myfuzz.integration.compiled_f2_consumer import select_f2_read_producer
    artifacts, inputs = timer_loaded(tmp_path)
    binding = select_f2_read_producer(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    assert binding.document()['register']['operation'] == 'read'
    assert binding.document()['producer']['grants_reset_prerequisite'] is False


def test_serialized_before_cannot_grant_version():
    from myfuzz.integration.compiled_f2_consumer import check_f2_read_observation
    with pytest.raises(ValueError,match='authority-required'):
        check_f2_read_observation({},None,target_artifact=None,authority=object(),
            token=object(),before={},register='CTRL',reset_epoch=0,prior_writes=0)


def test_binding_cannot_be_forged():
    from myfuzz.integration.compiled_f2_consumer import F2ReadProducerBinding, build_f2_read_producer
    with pytest.raises(ValueError,match='binding-required'):
        build_f2_read_producer(F2ReadProducerBinding('{}'),artifact=None,base_dir=ROOT,
            cache_dir=None,max_cases=1)


def test_serialized_before_cannot_be_captured():
    from myfuzz.integration.compiled_f2_consumer import capture_f2_read_version
    with pytest.raises(ValueError,match='authority-required'):
        capture_f2_read_version(object(),register='CTRL',reset_epoch=0)


def test_missing_read_hop_refuses():
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    with pytest.raises(ValueError,match='exactly-one-read'):
        check_f2_exact_hops(events=[],declaration={},image={},stream={},traces={},address=0,
            source_event_id=1,joins=[],declared_edges=[],instruction_snapshots=[],ram_event_id=1)


def native_step(event_id, **pins):
    return dict(event_id=event_id,component='cpu',local_tick=event_id,
        outputs={'driver_samples':[{'local_tick':event_id,'pre':{'protocol_taps':pins}}]})


@pytest.mark.parametrize('events,reason',[
    ([native_step(1,rvalid=1,error=0)],'response-unowned'),
    ([native_step(1,req=1,gnt=1),native_step(2,req=1,gnt=1)],'outstanding-overlap'),
    ([native_step(1,req=1,gnt=1),native_step(2,rvalid=1,error=1)],'response-error'),
])
def test_native_obi_counterfactuals(events,reason):
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    traces={'data':{k:k for k in ('req','gnt','rvalid','error','addr','rdata','we','wdata','be')}}
    with pytest.raises(ValueError,match=reason):
        collect_native_obi_beats(events,cpu='cpu',traces=traces,
            error_policy={'native_error_observation':True})


def test_native_obi_exact_outstanding_and_legacy_diagnostics():
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    traces={'data':{k:k for k in ('req','gnt','rvalid','error','addr','rdata','we','wdata','be')}}
    events=[native_step(1,req=1,gnt=1,addr=0x8000,we=0,be=15),
        native_step(2,rvalid=1,error=0,rdata=0x123)]
    beats=collect_native_obi_beats(events,cpu='cpu',traces=traces,error_policy={'native_error_observation':True})
    assert beats[('data',1)]['rdata']==0x123
    assert beats[('data',1)]['acceptance_event']==1
    with pytest.raises(ValueError,match='compiled-F4-native-response-unowned'):
        collect_native_obi_beats(events[1:],cpu='cpu',traces=traces,
            error_policy={'native_error_observation':True},error_prefix='compiled-F4')
