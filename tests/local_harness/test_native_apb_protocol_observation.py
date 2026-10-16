"""Native APB trace admission: construction only, never execute RTL."""
from copy import deepcopy
from dataclasses import replace

import pytest

from tests.local_harness.test_renderer import real_plan, ROOT
from tests.local_harness.test_native_physical_observation import make_request
from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.plan import plan_local_harness
from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation


@pytest.fixture(scope='module')
def artifacts():
    path = 'configs/peripherals/pulp_gpio/component_profile.json'
    old = real_plan(path, 'subject')
    new = plan_local_harness(make_request(path, {'raw_tick_stream': [{'sampling': 'pre_post'}]}), base_dir=ROOT)
    def render(plan):
        return render_local_runtime(plan, render_local_harness(plan), verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render(old), render(new)


def test_native_apb_closed_passive_trace(artifacts):
    old, new = artifacts
    assert 'base_protocol_trace' not in old.runtime_document
    assert 'trace_paddr' not in old.runtime_sv
    trace = new.runtime_document['base_protocol_trace']
    assert trace['protocol'] == 'apb3'
    assert trace['signal_widths'] == dict(paddr=12, psel=1, penable=1, pwrite=1, pwdata=32, pready=1, prdata=32, pslverr=1)
    assert trace['max_wait_cycles'] == new.runtime_document['effective_max_wait_cycles']
    assert new.runtime_document['physical_exports'] == old.runtime_document['physical_exports']
    assert verify_native_physical_observation(new)


@pytest.mark.parametrize('tamper', ['missing', 'extra', 'clock', 'wait', 'width', 'bool_width', 'signal', 'backend', 'abi', 'assignment', 'effective_wait'])
def test_native_apb_rejects_trace_tampering(artifacts, tamper):
    _, original = artifacts
    document = deepcopy(original.runtime_document)
    trace = document.setdefault('base_protocol_trace', {})
    runtime = original.runtime_sv
    if tamper == 'missing': document.pop('base_protocol_trace')
    elif tamper == 'extra': trace['arbitrary'] = True
    elif tamper == 'clock': trace['clock_domain'] = 'wrong'
    elif tamper == 'wait': trace['max_wait_cycles'] = 99
    elif tamper == 'width': trace.setdefault('signal_widths', {})['paddr'] = 32
    elif tamper == 'bool_width': trace['signal_widths']['psel'] = True
    elif tamper == 'signal': trace.setdefault('signals', {})['paddr'] = 'gpio_rsp_rdata'
    elif tamper == 'backend': document['backend_ports'] = [r for r in document['backend_ports'] if r['name'] != 'trace_paddr']
    elif tamper == 'abi':
        next(r for r in document['structural_abi']['ports'] if r['role'] == 'paddr')['width'] = 32
    elif tamper == 'assignment': runtime = runtime.replace('assign trace_paddr =', 'assign corrupted_paddr =')
    elif tamper == 'effective_wait': document['effective_max_wait_cycles'] = 99
    with pytest.raises(ValueError):
        verify_native_physical_observation(replace(original, runtime_document=document, runtime_sv=runtime))
