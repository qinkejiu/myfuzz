"""Real WB/AHB artifact admission only; no target IRQ or CPU run is claimed."""
from pathlib import Path
import pytest

from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('protocol,port', [('wishbone', 'o_int'),
                                          ('ahb-lite', 'error_intr'),
                                          ('ahb-lite', 'notif_intr')])
def test_real_cross_protocol_source_export_maps_to_original_registered_sampler(protocol, port, tmp_path):
    if protocol == 'wishbone':
        from tests.local_harness.test_generic_wishbone_register_real import artifact, request
        from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
        built = artifact(request('zipcpu_timer'))
        session = GeneratedWishboneRegisterSession(built, base_dir=ROOT, cache_dir=tmp_path)
    else:
        from tests.local_harness.test_ahb_register_target import artifact
        from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
        built = artifact()
        session = GeneratedAhbLiteRegisterSession(built, base_dir=ROOT, cache_dir=tmp_path)
    from scripts.run_timer_irq_smoke import target_session
    selected = target_session(built, base=ROOT, cache=tmp_path)
    assert type(selected) is type(session) and selected.process is None
    mapping = declared_irq_runtime_mapping(session, physical_port=port, source_bit_offset=0)
    exports = [row for row in built.runtime_document['physical_exports']
               if row['physical_port'] == port and row['direction'] == 'output']
    assert len(exports) == 1
    assert mapping['runtime_name'] == exports[0]['runtime_name']
    assert mapping['source_width'] == exports[0]['width'] == 1
    assert session._outputs[port] == (mapping['runtime_name'], 1)
    assert mapping['source_profile_fingerprint'] == built.plan.profile.profile_fingerprint
    assert mapping['transport_only'] is True and mapping['cause'] == 'unknown'
    assert mapping['reward_eligible'] is mapping['grants_prerequisites'] is False
    assert session.process is None
    with pytest.raises(ValueError, match='unique-real-output'):
        declared_irq_runtime_mapping(session, physical_port=port, source_bit_offset=1)
    session._outputs[port] = ('invented-wire', 1)
    with pytest.raises(ValueError, match='projection-mismatch'):
        declared_irq_runtime_mapping(session, physical_port=port, source_bit_offset=0)
