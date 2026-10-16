"""A core whose single memory port carries both fetches and data is not refused.

CVW's AHB external bus is one port: the EBU arbitrates the IFU and LSU controllers
onto it, so instruction fetches and data accesses both leave through
``cpu.external_bus``.  picorv32's ready/valid memory port is the same shape.

The pipeline used to require a dedicated ``instruction_memory_master`` (and, for
data flows, a dedicated ``data_memory_master``).  An accurate unified-memory
declaration therefore came back as ``cpu-instruction-master-ambiguous`` /
``cpu-instruction-master-missing``, and every flow of such a CPU was reported
``unsupported`` - not because the hardware cannot do it, but because the
declaration was being read as "this core has no fetch path".

These tests pin the acceptance rules in both places that decide them, and pin the
refusals that must survive:

* a unified master is accepted when it is the profile's *sole* endpoint;
* a profile with several masters must still name the right one;
* a core with an instruction master keeps using it (no regression).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CVW_PROFILE = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'

pytestmark = pytest.mark.skipif(
    not CVW_PROFILE.is_file(), reason='the CVW profile is not present')


def _endpoint(function, endpoint_id='cpu.bus'):
    return {'endpoint_id': endpoint_id, 'function': function, 'direction': 'output',
            'protocol': ['ahb-lite', '1'], 'fields': []}


class _FakeProfile:
    def __init__(self, endpoints):
        self.endpoints = [type('E', (), row)() for row in endpoints]
        self.component_id = 'fake'


class _FakeComponent:
    def __init__(self, endpoints, component_id='fake'):
        self._endpoints = endpoints
        self.component_id = component_id

    def endpoints(self):
        return self._endpoints

    def endpoints_with_function(self, function):
        return [row for row in self._endpoints if row.function == function]


def _need_recorder():
    from myfuzz.scenario.compiled_paths import _Assessment

    assessment = _Assessment.__new__(_Assessment)
    assessment.needs = []
    assessment.notes = []
    assessment.declared = {}
    assessment.endpoint_rows = []

    def need(code, pointer, detail=None):
        assessment.needs.append((code, pointer, detail))

    def note(code, pointer, detail=None):
        assessment.notes.append((code, pointer, detail))

    def endpoint(component, row, function):
        assessment.endpoint_rows.append((component.component_id, row.endpoint_id, function))

    assessment.need = need
    assessment.note = note
    assessment.endpoint = endpoint
    return assessment


def _endpoint_row(function, endpoint_id='cpu.bus'):
    return type('E', (), {'endpoint_id': endpoint_id, 'function': function})()


def test_a_sole_unified_master_satisfies_both_cpu_roles():
    from myfuzz.scenario.compiled_paths import (FUNCTION_DATA_MASTER,
                                                FUNCTION_INSTRUCTION_MASTER,
                                                _cpu_master)

    component = _FakeComponent([_endpoint_row('memory_master')])
    for function in (FUNCTION_INSTRUCTION_MASTER, FUNCTION_DATA_MASTER):
        assessment = _need_recorder()
        resolved = _cpu_master(assessment, component, function, 'some-missing-code')
        assert resolved is not None, assessment.needs
        assert not assessment.needs
        assert assessment.endpoint_rows == [('fake', 'cpu.bus', function)]


def test_a_unified_master_among_several_masters_is_still_refused():
    """Acceptance is only for the *sole* endpoint, so the role stays unambiguous."""
    from myfuzz.scenario.compiled_paths import (FUNCTION_INSTRUCTION_MASTER,
                                                _cpu_master)

    component = _FakeComponent([_endpoint_row('memory_master', 'cpu.bus'),
                                _endpoint_row('memory_master', 'cpu.other')])
    assessment = _need_recorder()
    assert _cpu_master(assessment, component, FUNCTION_INSTRUCTION_MASTER,
                       'cpu-instruction-master-missing') is None
    assert [code for code, _, _ in assessment.needs] == ['cpu-instruction-master-missing']


def test_a_dedicated_instruction_master_still_wins():
    from myfuzz.scenario.compiled_paths import (FUNCTION_INSTRUCTION_MASTER,
                                                _cpu_master)

    component = _FakeComponent([_endpoint_row('instruction_memory_master', 'cpu.i'),
                                _endpoint_row('data_memory_master', 'cpu.d')])
    assessment = _need_recorder()
    resolved = _cpu_master(assessment, component, FUNCTION_INSTRUCTION_MASTER,
                           'cpu-instruction-master-missing')
    assert resolved is not None and resolved.endpoint_id == 'cpu.i'
    assert not assessment.needs


def test_the_cvw_profile_declares_its_bus_as_a_unified_master():
    """The declaration itself, so a regression to `data_memory_master` is loud."""
    document = json.loads((ROOT / 'configs' / 'cpus' / 'cvw'
                           / 'interface_description.json').read_text(encoding='utf-8'))
    functions = [row['function'] for row in document['endpoints']]
    assert functions == ['memory_master'], functions
    profile = json.loads(CVW_PROFILE.read_text(encoding='utf-8'))
    assert [row['function'] for row in profile['endpoints']] == ['memory_master']
    assert profile['cpu']['master_endpoints'] == ['cpu.external_bus']
    # The bus is still AHB-Lite, and it is still the manager side.
    assert document['endpoints'][0]['protocol'] == ['ahb-lite', '1']
    assert any('unified' in note.lower() for note in document['notes']), \
        'the declaration must say why the port is declared unified'


def test_the_planner_accepts_the_unified_master_for_the_boot_image():
    """End to end through the planner: D1..D4 complete and F1..F4 are executable."""
    from myfuzz.local_harness.auto_harness_test import (load_composition,
                                                       run_auto_harness_test)
    import tempfile

    compose = ROOT / 'configs' / 'scenarios' / 'cvw-pulp-gpio' / 'compose.json'
    if not compose.is_file():
        pytest.skip('the CVW composition is not present')
    composition = load_composition(compose, base_dir=ROOT)
    instruction = composition.instruction_master('cpu')
    assert instruction.endpoint_id == 'cpu.external_bus'
    with tempfile.TemporaryDirectory(prefix='.cvw-unified-', dir=ROOT) as temporary:
        output = Path(temporary) / 'run'
        summary = run_auto_harness_test(
            cpu=CVW_PROFILE,
            ips=[ROOT / 'configs' / 'peripherals' / 'pulp_gpio' / 'component_profile.json'],
            compose=compose, output=output, base_dir=ROOT, skip_session=True,
            label='cvw-unified-master')
        assert summary['status'] == 'complete', summary['refusals']
        document = json.loads((output / 'compiled_paths.v1.json').read_text(encoding='utf-8'))
        statuses = {row['path_id']: row['status'] for row in document['paths']}
        # The four memory-image flows are the ones a unified memory master serves.
        for flow in ('F1', 'F2', 'F3', 'F4'):
            assert any(statuses[key] == 'executable'
                       for key in statuses if key.startswith(flow + ':')), (flow, statuses)
        # The two that stay unsupported must stay unsupported for their own real
        # reasons, not because of the master shape.
        for flow, expected in (('F5', 'interrupt-consumer-missing'),
                               ('F6', 'dma-master-not-declared')):
            reasons = [row['reason']['code'] for row in document['paths']
                       if row['path_id'].startswith(flow + ':')]
            assert expected in reasons, (flow, reasons)
