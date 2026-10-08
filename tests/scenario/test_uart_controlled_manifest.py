"""The controlled bootstrap identity is verified before starting RTL."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

import pytest

from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_factory


@lru_cache(maxsize=1)
def identity_and_timings():
    runner = make_ibex_uart_online_factory(Path('/tmp/uart-controlled-manifest-no-build'),
        cpu_retirement=True, uart_fifo=True)()
    timings = {}
    for component, session in runner.sessions.items():
        document = session.artifact.runtime_document
        timings[component] = {
            'schema_version': 'generated_local_reset.v1',
            'artifact_digest': document['artifact_digest'],
            'driver_sha256': document['cpp_sha256'],
            'hold_cycles': document['driver_reset']['reset_assert_ticks'],
            'release_cycles': document['driver_reset']['reset_release_ticks']}
    return runner.identity_document(), timings


def verify(identity, timings):
    return ScenarioManifest.from_runner_identity(identity,
        scenario_id='uart-controlled-manifest', schedule_order=('cpu', 'uart'),
        scheduler_policy_id='stable-local-v1', budget=ResourceBudget(),
        reset_timings=timings)


def test_actual_controlled_bootstrap_configuration_preflights():
    identity, timings = identity_and_timings()
    assert json.dumps(verify(identity, timings).to_document()['runner_identity'],
        sort_keys=True) == json.dumps(identity, sort_keys=True)


@pytest.mark.parametrize('field,value', [
    ('instruction_start', 0x12000), ('instruction_end', True),
    ('entry_pc', 0x10130)])
def test_tampered_controlled_bootstrap_configuration_rejected(field, value):
    identity, timings = identity_and_timings()
    changed = deepcopy(identity)
    changed['controlled_uart_bootstrap_configuration'][field] = value
    with pytest.raises(ValueError):
        verify(changed, timings)
