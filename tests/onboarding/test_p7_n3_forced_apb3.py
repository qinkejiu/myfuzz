"""P7 I5 N3: forcing a bus template cannot invent GPIO input ownership."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.local_harness.harness_set import HarnessSetRefused, generate_component


ROOT = Path(__file__).resolve().parents[2]


def test_forced_apb3_gpio_without_input_owner_emits_no_harness(tmp_path):
    """Use the real profile, planner, source lock and renderer admission.

    GPIO has the admitted APB3 bus shape, but its physical ``gpio.pins.in``
    still needs an explicit input owner. Selecting ``target.apb3`` grants no
    such owner. No admission method or frontend result is replaced here.
    """
    request_path = tmp_path / 'gpio.json'
    request_path.write_text(json.dumps({
        'schema_version': 'local_harness.v2',
        'profile_path': 'configs/peripherals/pulp_gpio/component_profile.json',
        'instance_id': 'gpio',
        'reset_assert_ticks': 2,
        'reset_release_ticks': 2,
        'max_wait_cycles': 16,
        'tuning': {'endpoint_policies': [{
            'endpoint_id': 'gpio.bus',
            'template_id': 'target.apb3',
            'template_version': '1',
            'variant_id': 'full-word',
            'max_outstanding': 1,
        }]},
    }), encoding='utf-8')
    output = tmp_path / 'harness'

    with pytest.raises(HarnessSetRefused) as raised:
        generate_component(request_path, base_dir=ROOT, output=output)

    refusal = raised.value
    assert refusal.code == 'component-render-refused'
    assert refusal.pointer == '/gpio/request'
    assert refusal.detail['instance_id'] == 'gpio'
    assert refusal.detail['request'] == str(request_path)
    error_code, separator, physical_input = refusal.detail['error'].partition(':')
    assert error_code == 'apb3-register-unowned-input'
    assert separator == ':' and physical_input
    assert not output.exists(), 'refused generation must emit no harness'
    assert not list(tmp_path.glob('.harness.*')), 'no partial staging output'
    assert not list(tmp_path.rglob('runtime.sv'))
    assert not list(tmp_path.rglob('driver.cpp'))
    assert not list(tmp_path.rglob('artifact.json'))
