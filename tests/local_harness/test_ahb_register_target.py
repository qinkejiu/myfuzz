"""Generated AHB target transport contracts and real Caliptra register access."""
from pathlib import Path
import os

import pytest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver, verify_local_source_lock)

ROOT = Path(__file__).resolve().parents[2]


def artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path='configs/peripherals/caliptra_sha256/component_profile.json',
        instance_id='sha', reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='sha256.bus', template_id='target.ahb-lite',
            template_version='1', variant_id='full-word-single', max_outstanding=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)


def test_generated_target_drives_real_ahb_and_both_reset_ports():
    a = artifact()
    assert a.runtime_document['kind'] == 'ahb_lite_register_observe'
    assert 'ahb_lite_mmio_target' in a.runtime_sv
    assert 'ACCESS_AHB_REG' in a.cpp_text
    assert a.runtime_document['base_protocol_trace']['signals']['hreadyin']
    assert a.runtime_document['base_protocol_trace']['signals']['hreadyout']
    assert len(a.runtime_document['clock_schedule']['resets']) == 2


def _exercise_real(a, cache, *, case_id):
    import hashlib
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    session = GeneratedAhbLiteRegisterSession(a, base_dir=ROOT, cache_dir=cache)
    accesses, protocol_events = [], []
    from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
    from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
    projection = IpProtocolEventNormalizer(component_id=a.plan.profile.component_id,
        instance_id='sha', protocol_trace=a.runtime_document['base_protocol_trace'])
    checker = IpProtocolChecker(component_id=a.plan.profile.component_id,
        instance_id='sha', protocol_trace=a.runtime_document['base_protocol_trace'])
    trace = a.runtime_document['base_protocol_trace']['signals']
    def access(offset, *, write=False, value=0):
        observed = session._access(write, offset, value)
        samples = session.drain_tick_samples()
        accepted = []
        for index, sample in enumerate(samples):
            raw = dict(event_id=sample['local_tick'], kind='local_tick_sample',
                local_tick=sample['local_tick'], phase='pre', outputs=sample['pre'])
            protocol_events.extend(projection.consume_local_tick(raw, reset_epoch=0))
            assert not checker.consume_local_tick(raw, reset_epoch=0)
            pins = {role: sample['pre']['backend'][name] for role, name in trace.items()}
            if pins['hsel'] and pins['hreadyin'] and pins['htrans'] & 2:
                accepted.append((index, pins))
        assert len(accepted) == 1, 'exactly one actual AHB address acceptance per access'
        index, address = accepted[0]
        assert address['haddr'] == offset and address['hwrite'] == int(write)
        assert address['hsize'] == 2
        # The manager waits a distinct edge for the data phase. Never compare
        # address-phase HWDATA or read the idle response as the transaction data.
        assert index + 1 < len(samples)
        data = {role: samples[index+1]['pre']['backend'][name] for role,name in trace.items()}
        assert data['hreadyout'] == 1 and data['hresp'] == 0
        assert data['htrans'] == 0
        assert data['hwdata'] == value if write else data['hrdata'] == observed
        accesses.append(dict(offset=offset, write=write, value=value,
                             rdata=observed, samples=samples))
        return observed
    try:
        session.begin_case(case_id)
        execution = session._execution
        assert access(0) == 0x61327368
        assert access(4) == 0x35362d32
        assert access(0x18) & 1
        digests = []
        for payload in (b'abc', b'abd'):
            block = [int.from_bytes(payload+b'\x80', 'big')] + [0] * 14 + [24]
            for index, value in enumerate(block):
                access(0x80+index*4, write=True, value=value)
            # Pinned RTL/RDL makes BLOCK and CTRL software write-only.
            assert access(0x80) == 0
            assert access(0xbc) == 0
            access(0x10, write=True, value=5)
            for _ in range(128):
                if access(0x18) & 2:
                    break
            else:
                pytest.fail('real SHA256 valid status did not arrive')
            digest = b''.join(access(0x100+i*4).to_bytes(4,'big') for i in range(8))
            assert digest == hashlib.sha256(payload).digest()
            digests.append(digest.hex())
        assert digests[0] != digests[1], 'payload negative control must change real digest'
        before = session.local_ticks
        with pytest.raises(ValueError):
            session._access(True, 0x80, 1, 1)
        with pytest.raises(ValueError):
            session._access(True, 0x81, 1, 15)
        assert session.local_ticks == before
        from collections import Counter
        assert Counter(event['event_type'] for event in protocol_events) == {
            'transaction_request': len(accesses), 'transaction_accept': len(accesses),
            'transaction_response': len(accesses)}
        return dict(execution=execution, accesses=accesses, digests=digests,
                    identity=session.identity_document(), protocol_events=protocol_events,
                    protocol_violations=[])
    finally:
        session.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_CALIPTRA_REAL') != '1', reason='explicit real Caliptra gate')
def test_real_name_block_status_and_hash(tmp_path):
    import json
    a = artifact()
    cache = Path(os.environ.get('MYFUZZ_CALIPTRA_CACHE', str(tmp_path/'cache')))
    first = _exercise_real(a, cache, case_id='caliptra-sha256-directed')
    fresh = _exercise_real(a, cache, case_id='caliptra-sha256-directed')
    assert first['execution'] != fresh['execution']
    assert first['accesses'] == fresh['accesses']
    assert first['digests'] == fresh['digests']
    assert first['identity'] == fresh['identity']
    assert first['protocol_events'] == fresh['protocol_events']
    evidence = Path(os.environ.get('MYFUZZ_CALIPTRA_EVIDENCE', str(tmp_path/'evidence')))
    evidence.mkdir(parents=True, exist_ok=True)
    for name, document in [('first',first),('fresh',fresh),('artifact',a.runtime_document)]:
        (evidence/(name+'.json')).write_text(json.dumps(document,sort_keys=True,indent=2)+'\n')
