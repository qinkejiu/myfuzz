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
        # ``_cpu_master`` reads the shared predicate through ``.profile``, whose
        # ``.endpoints`` is a declared tuple in production; the fake matches it.
        self.profile = type('FakeProfileView', (), {'endpoints': endpoints})()

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


def _path_request_document(*, data_endpoint, instruction_endpoint='cpu.external_bus',
                           cpu_profile=CVW_PROFILE):
    """The smallest closed ``path_compile_request.v1`` that reaches the role check.

    The CPU's role pointers are validated before any device or wiring fact is
    read, so a minimal declared wiring is enough: this test is about the pointer
    rule, not about compiling paths.
    """
    return {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': str(cpu_profile),
                'data_endpoint': data_endpoint,
                'instruction_endpoint': instruction_endpoint},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'profile': 'configs/peripherals/pulp_gpio/component_profile.json'}],
        'wiring': {'schema_version': 'path_wiring.v1',
                   'cpu': {'instance_id': 'cpu'}},
    }


def test_a_sole_unified_master_beside_a_non_master_endpoint_is_accepted():
    """Observation/configuration endpoints never make the bus ambiguous.

    CVW really declares ``cpu.manager_domain`` next to its AHB external bus, and
    that endpoint is a passive observation: it is not a second master.  The
    shared predicate must count only master-capable endpoints, and both the
    request loader and the per-flow resolver must use it.
    """
    from myfuzz.scenario.compiled_paths import (_sole_unified_master,
                                                load_path_compile_request)

    profile = _FakeProfile([_endpoint('memory_master'),
                            _endpoint('observation', 'cpu.obs'),
                            _endpoint('configuration', 'cpu.cfg')])
    assert _sole_unified_master(profile) == 'cpu.bus'

    request = load_path_compile_request(
        _path_request_document(data_endpoint='cpu.external_bus'), base_dir=ROOT)
    assert request.cpu.instance_id == 'cpu'
    assert request.role_pointer('data_memory_master') == 'cpu.external_bus'
    assert request.role_pointer('instruction_memory_master') == 'cpu.external_bus'
    # The same declaration the request just accepted is the real CVW profile.
    from myfuzz.composition.component_profile import load_component_profile
    real = load_component_profile(CVW_PROFILE)
    assert _sole_unified_master(real) == 'cpu.external_bus'


def test_two_master_capable_endpoints_are_not_a_sole_unified_master(tmp_path):
    """A second master keeps the unified role ambiguous, in both places.

    The acceptance is only for the *sole* master: with two master-capable
    endpoints ``_sole_unified_master`` resolves nothing, the per-flow resolver
    refuses, and the request pointer is refused at ``/cpu/data_endpoint``.
    """
    from myfuzz.scenario.compiled_paths import (FUNCTION_DATA_MASTER,
                                                FUNCTION_INSTRUCTION_MASTER,
                                                PathCompilationError,
                                                _cpu_master,
                                                _sole_unified_master,
                                                load_path_compile_request)

    profile = _FakeProfile([_endpoint('memory_master', 'cpu.bus'),
                            _endpoint('memory_master', 'cpu.other')])
    assert _sole_unified_master(profile) is None
    component = _FakeComponent([_endpoint_row('memory_master', 'cpu.bus'),
                                _endpoint_row('memory_master', 'cpu.other')])
    for function in (FUNCTION_INSTRUCTION_MASTER, FUNCTION_DATA_MASTER):
        assessment = _need_recorder()
        assert _cpu_master(assessment, component, function,
                           'cpu-instruction-master-missing') is None
        assert [code for code, _, _ in assessment.needs] == [
            'cpu-instruction-master-missing']

    scratch = _two_master_profile(tmp_path)
    with pytest.raises(PathCompilationError) as raised:
        load_path_compile_request(
            _path_request_document(data_endpoint='cpu.external_bus',
                                   cpu_profile=scratch), base_dir=ROOT)
    assert raised.value.code == 'cpu-master-role-pointer-mismatch'
    assert raised.value.pointer == '/cpu/data_endpoint'


def _two_master_profile(tmp_path):
    """The real CVW declaration plus one second master-capable endpoint.

    The second endpoint gets its own physical port aliases: reusing the bus's
    ports would be an illegal declaration (one physical pin cannot belong to two
    endpoints), and this test is about the *master count*, not about port
    uniqueness.
    """
    document = json.loads(CVW_PROFILE.read_text(encoding='utf-8'))
    document['endpoints'].append({
        'endpoint_id': 'cpu.data_bus',
        'function': 'memory_master',
        'protocol': ['ahb-lite', '1'],
        'clock': 'core',
        'reset': 'sys_rst',
        'fields': [
            {'role': 'haddr', 'aliases': ['D2_HADDR'], 'direction': 'output',
             'width': 34},
            {'role': 'hrdata', 'aliases': ['D2_HRDATA'], 'direction': 'input',
             'width': 32},
        ],
    })
    scratch = tmp_path / 'two_masters' / 'component_profile.json'
    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.write_text(json.dumps(document, indent=1), encoding='utf-8')
    return scratch


def test_the_data_endpoint_pointer_cannot_name_an_observation_endpoint(tmp_path):
    """A pointer is a role claim: an observation endpoint is not the data master."""
    from myfuzz.scenario.compiled_paths import (PathCompilationError,
                                                load_path_compile_request)

    scratch = _two_master_profile(tmp_path)
    with pytest.raises(PathCompilationError) as raised:
        load_path_compile_request(
            _path_request_document(data_endpoint='cpu.external_bus',
                                   cpu_profile=scratch), base_dir=ROOT)
    assert raised.value.code == 'cpu-master-role-pointer-mismatch'
    assert raised.value.pointer == '/cpu/data_endpoint'

    # The real CVW profile's observation endpoint is not a data master either.
    with pytest.raises(PathCompilationError) as observed:
        load_path_compile_request(
            _path_request_document(data_endpoint='cpu.manager_domain'),
            base_dir=ROOT)
    assert observed.value.code == 'cpu-master-role-pointer-mismatch'
    assert observed.value.pointer == '/cpu/data_endpoint'


def test_the_cvw_profile_declares_its_bus_as_a_unified_master():
    """The declaration itself, so a regression to `data_memory_master` is loud."""
    document = json.loads((ROOT / 'configs' / 'cpus' / 'cvw'
                           / 'interface_description.json').read_text(encoding='utf-8'))
    functions = [row['function'] for row in document['endpoints']]
    assert functions == ['memory_master'], functions
    profile = json.loads(CVW_PROFILE.read_text(encoding='utf-8'))
    # The manager-domain observation endpoint is deliberately separate from the
    # bus.  Only master-capable endpoints participate in the unified-master
    # rule; an observation endpoint must not make the single bus ambiguous.
    from myfuzz.scenario.compiled_paths import MASTER_FUNCTIONS
    masters = [row['function'] for row in profile['endpoints']
               if row['function'] in MASTER_FUNCTIONS]
    assert masters == ['memory_master'], profile['endpoints']
    assert [row['function'] for row in profile['endpoints']].count('observation') == 1
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
