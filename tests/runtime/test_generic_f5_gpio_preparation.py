"""Production GPIO inputs preserve the selected pin and constant ownership."""
from pathlib import Path

from myfuzz.runtime.preparation import create_preparation

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/compiled-f5-ibex-pulp-gpio'
CAPABILITY = ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json'


def test_gpio_f5_production_preparation_keeps_real_pin_and_constants(tmp_path):
    context = create_preparation(base_dir=ROOT, compose_path=SCENARIO / 'compose.json',
        capability_paths=(CAPABILITY,), supplement_path=SCENARIO / 'execution_supplement.json',
        generated_dir=tmp_path / 'generated', flow_ids=('F5',))
    try:
        path = next(row for row in context.d3_document()['paths'] if row['flow_id'] == 'F5')
        assert path['status'] == 'executable'
        source, = [row for row in path['sources'] if row['kind'] == 'external_pin']
        assert (source['component'], source['port'], source['bit_offset'], source['width']) == (
            'gpio_b', 'gpio_in', 8, 1)
        fixed = context.compiled_inputs()['request'].wiring.fixed_inputs
        assert {(row.component_instance, row.port, row.bit_offset, row.width, row.constant)
                for row in fixed} == {('gpio_a', 'gpio_in', 0, 32, 0),
                                     ('gpio_b', 'gpio_in', 0, 8, 0),
                                     ('gpio_b', 'gpio_in', 9, 23, 0)}
        assert context.flow_support('F5')['runtime_admitted'] is False
        context.assert_current()
    finally:
        context.close()
