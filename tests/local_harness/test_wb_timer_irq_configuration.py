"""The existing Wishbone Timer is selected through the shared smoke factory."""
import json
from pathlib import Path
from dataclasses import replace
import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_actual_WB_source_config_uses_native_sampler_and_four_byte_window(tmp_path):
    from scripts.run_timer_irq_smoke import source_options, timer_artifact, target_session, timer_program
    from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.ownership import compile_ownership
    config = json.loads((ROOT / 'configs/peripherals/zipcpu_timer_irq/smoke.json').read_text())
    options = source_options(config)
    artifact = timer_artifact(ROOT, options['source_request'], options['active_id'])
    source = target_session(artifact, base=ROOT, cache=tmp_path)
    assert type(source) is GeneratedWishboneRegisterSession
    assert source._window == artifact.plan.profile.address.window_size == 4
    assert artifact.runtime_document['base_protocol_trace']['protocol'] == 'wishbone'
    assert options['trigger_writes'] == ((0, 8),)
    assert options['source_port'] == 'o_int' and options['source_bit_offset'] == 0
    mapping = declared_irq_runtime_mapping(source, physical_port='o_int', source_bit_offset=0)
    assert mapping['transport_only'] is True and mapping['source_width'] == 1
    runner = ScenarioRunner(sessions={options['active_id']: source},
                            ownership=compile_ownership((), ()), bindings=())
    assert runner.install_protocol_checker(options['active_id']) is not None
    assert source.process is None
    timer_program(0x10080, options['active_base'], trigger_writes=options['trigger_writes'])
    bad = replace(artifact, runtime_document={**artifact.runtime_document, 'kind': 'unsupported-target'})
    with pytest.raises(ValueError): target_session(bad, base=ROOT, cache=tmp_path)
