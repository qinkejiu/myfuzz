"""The SPI IRQ smoke is only configuration of the existing APB sampler."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_actual_spi_request_keeps_plain_apb_and_declared_observed_event_vector():
    from scripts.run_timer_irq_smoke import timer_artifact, source_options, timer_program
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    config = json.loads((ROOT / 'configs/peripherals/pulp_spi_irq/smoke.json').read_text())
    options = source_options(config)
    artifact = timer_artifact(ROOT, options['source_request'], options['active_id'])
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=Path('/tmp/unused-spi-declared-irq'))
    assert artifact.runtime_document['kind'] == 'apb3_register_observe'
    exports = [row for row in artifact.runtime_document['physical_exports'] if row['physical_port'] == 'events_o']
    assert len(exports) == 1 and exports[0]['width'] == 2 and exports[0]['disposition'] == 'observe'
    assert session._outputs['events_o'] == (exports[0]['runtime_name'], 2)
    pads = artifact.runtime_document['fixed_physical_inputs']
    assert {row['role'] for row in pads} == {'sdi0', 'sdi1', 'sdi2', 'sdi3'}
    assert all(row['width'] == 1 and row['value'] == 0 for row in pads)
    assert 'storage_observations' not in artifact.runtime_document
    assert options['source_adapter'] == 'declared-output.v1'
    assert options['trigger_writes'] == ((36, 0x80000000),)
    timer_program(0x10080, options['active_base'], trigger_writes=options['trigger_writes'])
