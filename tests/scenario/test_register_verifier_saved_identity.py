"""Startup target identities bind even empty saved operation projections."""
from tests.scenario.test_register_program_replay import actual_factory,adapter
from tests.scenario.test_ordinary_apb_access_session import session


def test_actual_startup_configuration_pins_target_profile_and_sidecar(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);v=RegisterProgramVerifier(runtime,max_records=4)
    actual=v._preflight['targets']['gpio_a']['runtime_support']
    assert v.configuration()['target_identities']=={'gpio_a':{
        'component_id':actual['component_id'],'profile_fingerprint':actual['profile_fingerprint'],
        'sidecar_fingerprint':actual['sidecar_fingerprint']}}
