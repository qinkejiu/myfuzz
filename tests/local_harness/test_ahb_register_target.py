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


@pytest.mark.skipif(os.environ.get('MYFUZZ_CALIPTRA_REAL') != '1', reason='explicit real Caliptra gate')
def test_real_name_block_status_and_hash(tmp_path):
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    session = GeneratedAhbLiteRegisterSession(artifact(), base_dir=ROOT,
        cache_dir=Path(os.environ.get('MYFUZZ_CALIPTRA_CACHE', str(tmp_path/'cache'))))
    try:
        session.begin_case('caliptra-sha256-abc')
        assert session.read_register(0) == 0x61327368
        assert session.read_register(4) == 0x35362d32
        assert session.read_register(0x18) & 1
        block = [0x61626380] + [0] * 14 + [0x18]
        for index, value in enumerate(block):
            session.write_register(0x80 + index * 4, value)
        assert session.read_register(0x80) == block[0]
        assert session.read_register(0xbc) == 0x18
        session.write_register(0x10, 5)
        for _ in range(128):
            if session.read_register(0x18) & 2:
                break
        else:
            pytest.fail('real SHA256 valid status did not arrive')
        assert [session.read_register(0x100+i*4) for i in range(8)] == [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
            0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad]
        with pytest.raises(ValueError):
            session._access(True, 0x80, 1, 1)
    finally:
        session.end_case()
