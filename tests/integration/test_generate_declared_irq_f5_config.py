import json
from pathlib import Path

import pytest

from scripts.generate_declared_irq_f5_config import generate
from myfuzz.integration.declared_irq_consumption import admit_declared_irq_consumption
from scripts.run_declared_irq_f5 import f5_fields


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('behavior,scenario', [
    ('configs/peripherals/pulp_timer/irq_behavior.json', 'declared-irq-f5-pulp-timer'),
    ('configs/peripherals/pulp_spi_irq/irq_behavior.json', 'declared-irq-f5-apb-spi'),
    ('configs/peripherals/zipcpu_timer_irq/irq_behavior.json', 'declared-irq-f5-wb-timer'),
])
@pytest.mark.parametrize('cpu', [
    'configs/cpus/ibex_rvfi_local/component_profile.json',
    'configs/cpus/cv32e40p_rvfi_local/component_profile.json',
])
def test_component_behavior_and_cpu_create_admitted_reusable_config(behavior, scenario, cpu):
    result = generate(cpu, json.loads((ROOT / behavior).read_text()), base=ROOT)
    reference = json.loads((ROOT / 'configs/scenarios' / scenario / 'config.json').read_text())
    for key in ('source_request', 'source_adapter', 'source_port', 'source_bit_offset',
                'pulse_width_ticks', 'trigger_writes', 'status_offsets',
                'status_registers', 'clear_writes', 'status_cause_bits', 'target_window'):
        assert result[key] == reference[key]
    assert result['cpu_profile'] == cpu
    admission = admit_declared_irq_consumption(result, base_dir=ROOT)
    assert admission['status'] == 'admitted'
    assert f5_fields(result, admission)['status_offsets'] == reference['status_offsets']


def test_behavior_requires_explicit_trigger_and_correct_schema():
    behavior = json.loads((ROOT / 'configs/peripherals/pulp_timer/irq_behavior.json').read_text())
    for key in ('trigger_writes', 'source_port'):
        invalid = dict(behavior)
        invalid.pop(key)
        with pytest.raises(ValueError):
            generate('configs/cpus/ibex_rvfi_local/component_profile.json', invalid, base=ROOT)
    behavior['schema_version'] = 'unknown'
    with pytest.raises(ValueError):
        generate('configs/cpus/ibex_rvfi_local/component_profile.json', behavior, base=ROOT)
