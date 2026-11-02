"""Production F5 declarations reach static preparation, with no native claim."""
from pathlib import Path

from myfuzz.runtime.preparation import create_preparation

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/compiled-f5-obi-tlul-uart'


def test_uart_f5_production_preparation_preserves_physical_path(tmp_path):
    context = create_preparation(base_dir=ROOT, compose_path=SCENARIO / 'compose.json',
        capability_paths=(SCENARIO / 'test_capability.json',),
        supplement_path=SCENARIO / 'execution_supplement.json',
        generated_dir=tmp_path / 'generated', flow_ids=('F5',))
    try:
        assert set(context.artifacts) == {'processor', 'peripheral'}
        compiled = context.d3_document()
        path = next(row for row in compiled['paths'] if row['flow_id'] == 'F5')
        assert path['status'] == 'executable'
        assert path['runtime_path_identity'] is not None
        source = next(row for row in path['sources'] if row['kind'] == 'external_pin')
        assert (source['component'], source['port'], source['width']) == (
            'peripheral', 'cio_rx_i', 1)
        nodes = {row['node_id']: row for row in compiled['runtime_path_contract']['nodes']}
        assert nodes['F5.ip_irq']['port'] == 'intr_rx_watermark_o'
        assert nodes['F5.cpu_irq_entry']['port'] == 'irq_external_i'
        support = context.flow_support('F5')
        assert support['execution_supported'] == 0
        assert support['runtime_admitted'] is False
        assert support['path_id'] == path['path_id']
        context.assert_current()
    finally:
        context.close()
