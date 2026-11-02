"""A CPU without error pins exposes no OBI error tap; absence is not a zero.

The CV32E40P ABI declares ``error_response=False`` and its generated OBI
adapter has no error role.  The F6 fetch receipt may therefore require only the
real roles, but it must never accept a trace whose error tap contradicts the
declared capability.
"""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))


def test_declared_error_tap_returns_the_real_role_only_when_required():
    from myfuzz.scenario.f6_instruction_fetch_receipt import declared_error_tap
    with_error = {'signals': {'req': 'i_req', 'gnt': 'i_gnt', 'addr': 'i_addr',
                              'rvalid': 'i_rvalid', 'rdata': 'i_rdata',
                              'error': 'i_error'}}
    without_error = {'signals': {'req': 'i_req', 'gnt': 'i_gnt', 'addr': 'i_addr',
                                 'rvalid': 'i_rvalid', 'rdata': 'i_rdata'}}
    assert declared_error_tap(with_error, True) == 'i_error'
    assert declared_error_tap(without_error, False) is None


@pytest.mark.parametrize('trace,capability', [
    ({'signals': {'req': 'i_req', 'rvalid': 'i_rvalid'}}, True),
    ({'signals': {'req': 'i_req', 'rvalid': 'i_rvalid', 'error': 'i_error'}}, False),
])
def test_a_trace_whose_error_role_contradicts_the_abi_is_refused(trace, capability):
    from myfuzz.scenario.f6_instruction_fetch_receipt import declared_error_tap
    with pytest.raises(ValueError, match='differs from the declared capability'):
        declared_error_tap(trace, capability)


@pytest.mark.parametrize('capability', [None, 0, 1, 'false'])
def test_the_capability_must_be_an_explicit_boolean(capability):
    from myfuzz.scenario.f6_instruction_fetch_receipt import declared_error_tap
    with pytest.raises(ValueError, match='explicit OBI error capability'):
        declared_error_tap({'signals': {'req': 'i_req'}}, capability)


@pytest.mark.parametrize('trace', [None, {}, {'signals': ()}, {'signals': {'req': ''}}])
def test_a_malformed_trace_never_yields_an_error_tap(trace):
    from myfuzz.scenario.f6_instruction_fetch_receipt import declared_error_tap
    with pytest.raises(ValueError):
        declared_error_tap(trace, False)


def test_the_real_profile_capabilities_are_explicit_booleans():
    from myfuzz.composition.component_profile import load_component_profile
    profiles = {
        'configs/cpus/ibex_rvfi_local/component_profile.json': True,
        'configs/cpus/cv32e20/component_profile.json': True,
        'configs/cpus/cv32e40p_rvfi_local/component_profile.json': False,
    }
    for path, expected in profiles.items():
        profile = load_component_profile(ROOT / path)
        assert profile.capabilities.get('error_response') is expected
