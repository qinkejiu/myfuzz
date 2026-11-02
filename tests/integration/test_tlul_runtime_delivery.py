"""Declared TL-UL target bus pins: mapping, identity and refusal.

No RTL is started here.  The subject is the declaration class that lets F2/F4
admit the TL-UL target IP's own A-channel pins without ever driving a top-level
input: the pins are consumed by the generated ``beat_to_tlul`` adapter, so the
host may only record the declared candidate value as an observation.

The scenario is the real GPIO one (``configs/scenarios/compiled-f2-f4-obi-tlul-gpio``)
but every document below is synthesized from its declared facts, so this suite
runs without Verilator, a generated wrapper or a runner process.
"""
from __future__ import annotations

import json

import pytest

from myfuzz.integration.compiled_f4_runtime_path import CompiledF4RuntimePathAdmission
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ENDPOINT = 'opentitan_gpio.mmio'
COMPONENT = 'peripheral'
_UL_INPUTS = (
    ('a_valid', 'a_valid_i', 1), ('a_opcode', 'a_opcode_i', 3),
    ('a_param', 'a_param_i', 3), ('a_size', 'a_size_i', 2),
    ('a_source', 'a_source_i', 8), ('a_address', 'a_address_i', 32),
    ('a_mask', 'a_mask_i', 4), ('a_data', 'a_data_i', 32),
    ('a_user', 'a_user_i', 23), ('d_ready', 'd_ready_i', 1),
)


def _artifact_document(*, kind='tlul_register_observe', protocol='tl-ul',
                       roles=_UL_INPUTS, adapted=None, endpoint=ENDPOINT):
    ports = []
    for role, port, width in roles:
        ports.append({
            'bits': {'hi': width - 1, 'lo': 0}, 'component_id': 'opentitan_gpio_local',
            'direction': 'input', 'disposition': 'functional',
            'endpoint_id': endpoint, 'instance_id': COMPONENT, 'port': port,
            'port_width': width, 'role': role})
    ports.append({
        'bits': {'hi': 31, 'lo': 0}, 'component_id': 'opentitan_gpio_local',
        'direction': 'output', 'disposition': 'functional',
        'endpoint_id': endpoint, 'instance_id': COMPONENT, 'port': 'd_data_o',
        'port_width': 32, 'role': 'd_data'})
    ports.append({
        'bits': {'hi': 31, 'lo': 0}, 'component_id': 'opentitan_gpio_local',
        'direction': 'input', 'disposition': 'functional',
        'endpoint_id': 'gpio.pins', 'instance_id': COMPONENT, 'port': 'gpio_i',
        'port_width': 32, 'role': 'in'})
    return {'kind': kind,
            'adapted_endpoint_ids': [endpoint] if adapted is None else adapted,
            'base_protocol_trace': {'schema_version': 'ip_protocol_trace.v1',
                                    'protocol': protocol, 'endpoint_id': endpoint},
            'plan': {'ports': ports}}


class _Artifact:
    def __init__(self, document):
        self.runtime_document = document


def _compiled_pin_sources(*, ports=_UL_INPUTS, endpoint=ENDPOINT,
                          component=COMPONENT):
    return [{'source_id': f'{component}.{role}.external', 'kind': 'external_pin',
             'component': component, 'endpoint_id': endpoint, 'port': port,
             'bit_offset': 0, 'width': width, 'mask': (1 << width) - 1,
             'origin': 'fuzzable', 'range': None, 'alignment': 1,
             'register': None, 'field': None}
            for role, port, width in ports]


# -- declaration authority --------------------------------------------------
def test_tlul_target_bus_pins_map_to_one_declaration_each():
    from myfuzz.scenario.target_bus_pins import (
        TLUL_TARGET_BUS_INPUT_WIDTHS, artifact_declared_bus_pins,
        declaration_identity, pin_identity)
    pins = artifact_declared_bus_pins(_Artifact(_artifact_document()))
    assert {pin['port'] for pin in pins} == {port for _, port, _ in _UL_INPUTS}
    assert sorted(pin['width'] for pin in pins) == list(TLUL_TARGET_BUS_INPUT_WIDTHS)
    assert {pin['endpoint_id'] for pin in pins} == {ENDPOINT}
    assert {pin['component'] for pin in pins} == {COMPONENT}
    for pin in pins:
        assert pin['bit_offset'] == 0 and pin['direction'] == 'CPU_TO_IP'
        assert declaration_identity(pin) == pin['identity']
        assert pin['identity'] == pin_identity(component=COMPONENT,
            port=pin['port'], bit_offset=0, width=pin['width'])


def test_compiled_pin_set_must_equal_the_declared_bus_input_set():
    from myfuzz.scenario.target_bus_pins import tlul_declared_bus_pins
    rows = tlul_declared_bus_pins(_compiled_pin_sources(), direction='CPU_TO_IP',
        target_component=COMPONENT, target_endpoint=ENDPOINT)
    assert len(rows) == 10
    assert {row['source']['source_id'] for row in rows} == {
        f'{COMPONENT}.{role}.external' for role, _, _ in _UL_INPUTS}

    # A single pin (the pre-existing F5 shared shape) is not a bus input set.
    for broken in (
            _compiled_pin_sources(ports=_UL_INPUTS[:1]),                 # subset
            _compiled_pin_sources(ports=_UL_INPUTS + (('d_error', 'd_error_i', 1),)),  # superset
            _compiled_pin_sources(ports=_UL_INPUTS[:-1] + (('d_ready', 'd_ready_i', 2),)),  # width
            [_compiled_pin_sources()[0] | {'endpoint_id': 'gpio.pins'}],   # foreign endpoint
            [_compiled_pin_sources()[0] | {'component': 'processor'}],     # foreign component
            [_compiled_pin_sources()[0] | {'mask': 3}],                    # mask
            [_compiled_pin_sources()[0] | {'bit_offset': 1, 'mask': 2}],   # offset
            [_compiled_pin_sources()[0] | {'origin': 'bound'}],            # ownership
            [_compiled_pin_sources()[0] | {'range': [0, 1]}],              # random domain
            [_compiled_pin_sources()[0] | {'port': ''}],                   # empty port
            [_compiled_pin_sources()[0] | {'port': 'a_valid_i'}]*2,        # duplicate port
    ):
        with pytest.raises(ValueError):
            tlul_declared_bus_pins(broken, direction='CPU_TO_IP',
                target_component=COMPONENT, target_endpoint=ENDPOINT)


def test_artifact_declaration_requires_the_exact_adapter_consumed_inputs():
    from myfuzz.scenario.target_bus_pins import artifact_declared_bus_pins
    # A non-TL-UL / non-register artifact keeps its ordinary host pin path.
    assert artifact_declared_bus_pins(_Artifact({'kind': 'apb_gpio'})) == ()
    assert artifact_declared_bus_pins(_Artifact(_artifact_document(kind='apb_gpio'))) == ()
    for document in (
            _artifact_document(protocol='apb'),                 # protocol
            _artifact_document(adapted=[]),                     # not consumed by an adapter
            _artifact_document(roles=_UL_INPUTS[1:]),           # missing role
            _artifact_document(roles=_UL_INPUTS + (('d_error', 'd_error_i', 1),)),
            _artifact_document(roles=_UL_INPUTS[:-1] + (('d_ready', 'd_ready_i', 8),))):
        with pytest.raises(ValueError):
            artifact_declared_bus_pins(_Artifact(document))


def test_bus_pin_registry_refuses_a_duplicate_declaration():
    from myfuzz.scenario.target_bus_pins import bus_pin_registry
    by_id, by_field = bus_pin_registry([
        (COMPONENT, _Artifact(_artifact_document())),
        ('processor', _Artifact(_artifact_document(kind='obi_cpu')))])
    assert len(by_id) == len(by_field) == 10
    with pytest.raises(ValueError):
        bus_pin_registry([(COMPONENT, _Artifact(_artifact_document())),
                          (COMPONENT, _Artifact(_artifact_document())),
                          (COMPONENT, _Artifact(_artifact_document()))])


# -- runtime delivery -------------------------------------------------------
def _registry():
    from myfuzz.scenario.target_bus_pins import bus_pin_registry
    return bus_pin_registry([(COMPONENT, _Artifact(_artifact_document()))])


def _session():
    from myfuzz.scenario.session_runtime import ScenarioSession
    by_id, by_field = _registry()
    session = object.__new__(ScenarioSession)
    session._declared_bus_pins = dict(by_id)
    session._declared_bus_pin_fields = dict(by_field)
    return session


def _online_pin_case(session, *, action_id='pin-0', value=1, port='a_valid_i',
                     component=COMPONENT, bit_offset=0, width=None,
                     direction='CPU_TO_IP', path_id=None, support=()):
    declaration = session._declared_bus_pin_fields[(COMPONENT, port, 0,
        declaration_width(port))]
    width = declaration['width'] if width is None else width
    from myfuzz.scenario.session_runtime import OnlineCase
    return OnlineCase('case-' + action_id, direction,
        declaration['identity'] if path_id is None else path_id,
        BatchSourceEvent(action_id, component, port, value, bit_offset, width),
        (BatchAdvance((component,)),), tuple(support))


def declaration_width(port):
    return next(width for _, candidate, width in _UL_INPUTS if candidate == port)


def test_session_accepts_only_the_declared_pin_case():
    session = _session()
    case = _online_pin_case(session)
    declaration = session._declared_target_bus_pin(case)
    assert declaration is not None and declaration['port'] == 'a_valid_i'
    assert declaration['component'] == COMPONENT

    # An unrelated path id is an ordinary host case, not a declaration.
    unrelated = _online_pin_case(session, path_id='0' * 64)
    assert session._declared_target_bus_pin(unrelated) is None

    for broken in (
            lambda: _online_pin_case(session, port='a_opcode_i', width=1),  # field mismatch
            lambda: _online_pin_case(session, component='processor'),       # foreign component
            lambda: _online_pin_case(session, direction='IP_TO_CPU'),       # direction
            lambda: _online_pin_case(session, value=2),                     # value range
            lambda: _online_pin_case(session, bit_offset=1),                # offset
            lambda: _online_pin_case(session, support=(object(),))):        # support input
        with pytest.raises(ValueError):
            session._declared_target_bus_pin(broken())


def test_session_registry_is_derived_from_the_real_artifact_documents():
    from types import SimpleNamespace
    from myfuzz.scenario.session_runtime import ScenarioSession
    session = object.__new__(ScenarioSession)
    session.runner = SimpleNamespace(sessions={
        'processor': SimpleNamespace(artifact=_Artifact({'kind': 'obi_cpu'})),
        'peripheral': SimpleNamespace(artifact=_Artifact(_artifact_document()))})
    session._declared_bus_pins = {}
    session._declared_bus_pin_fields = {}
    session._install_declared_bus_pins()
    assert len(session._declared_bus_pins) == len(session._declared_bus_pin_fields) == 10
    assert {row['port'] for row in session._declared_bus_pins.values()} == {
        port for _, port, _ in _UL_INPUTS}


def test_runner_records_the_declaration_without_touching_inputs():
    from myfuzz.scenario.target_bus_pins import declaration
    fields = (InputField(COMPONENT, 'gpio.pins.in', 32),)
    owners = (InputOwner(COMPONENT, 'gpio.pins.in', 0, 32, 'fixed', 'profile_constant'),)
    runner = ScenarioRunner(sessions={'processor': object(), 'peripheral': object()},
                            ownership=compile_ownership(fields, owners), bindings=())
    runner._status = 'running'
    pin = declaration(component=COMPONENT, endpoint_id=ENDPOINT,
                      port='a_valid_i', bit_offset=0, width=1)
    event_id = runner.declare_target_bus_pin(component=COMPONENT, port='a_valid_i',
        value=1, bit_offset=0, width=1, direction='CPU_TO_IP', declaration=pin)
    event = runner.events[-1]
    assert event['event_id'] == event_id
    assert event['kind'] == 'declared_target_bus_pin'
    assert event['declaration_id'] == pin['identity']
    assert event['delivery'] == 'target_adapter_internal_observed_only'
    assert runner._inputs == {'processor': {}, 'peripheral': {}}
    with pytest.raises(ValueError):
        runner.declare_target_bus_pin(component=COMPONENT, port='a_valid_i',
            value=2, bit_offset=0, width=1, direction='CPU_TO_IP', declaration=pin)
    with pytest.raises(ValueError):
        runner.declare_target_bus_pin(component='processor', port='a_valid_i',
            value=1, bit_offset=0, width=1, direction='CPU_TO_IP', declaration=pin)


# -- admission documents ----------------------------------------------------
def _admission(pin_rows):
    from myfuzz.scenario.target_bus_pins import declaration
    sources = []
    for port, width in (('a_valid_i', 1), ('a_opcode_i', 3)):
        pin = declaration(component=COMPONENT, endpoint_id=ENDPOINT,
                          port=port, bit_offset=0, width=width)
        sources.append({'source_id': f'{COMPONENT}.{port}.external',
                        'kind': 'external_pin', 'component': COMPONENT,
                        'endpoint_id': ENDPOINT, 'port': port,
                        'bit_offset': 0, 'width': width, 'mask': (1 << width) - 1})
    document = {'selected_path': {'direction': 'CPU_TO_IP', 'sources': sources},
                'external_pin_paths': pin_rows}
    return CompiledF4RuntimePathAdmission(
        None, None, 'F4:ram.image', 'f' * 64,
        json.dumps(document, sort_keys=True, separators=(',', ':')).encode())


def _rows():
    from myfuzz.scenario.target_bus_pins import declaration
    rows = []
    for port, width in (('a_valid_i', 1), ('a_opcode_i', 3)):
        pin = declaration(component=COMPONENT, endpoint_id=ENDPOINT,
                          port=port, bit_offset=0, width=width)
        rows.append({'source_id': f'{COMPONENT}.{port}.external',
                     'direction': 'CPU_TO_IP', 'declaration': pin,
                     'path_id': pin['identity']})
    return rows


def test_admission_exposes_a_declaration_identity_per_pin():
    rows = _rows()
    admission = _admission(rows)
    direction, path_id = admission.external_pin_path(f'{COMPONENT}.a_valid_i.external')
    assert (direction, path_id) == ('CPU_TO_IP', rows[0]['path_id'])
    with pytest.raises(ValueError):
        admission.external_pin_path('peripheral.unknown.external')

    # The declaration must re-derive from the selected path source.
    admission._validate_external_pin_documents(admission.document())
    tampered = [dict(rows[0], path_id='0' * 64), rows[1]]
    with pytest.raises(ValueError, match='external-pin-declaration-drift'):
        broken = _admission(tampered)
        broken._validate_external_pin_documents(broken.document())
    incomplete = _admission(rows)
    with pytest.raises(ValueError):
        incomplete._validate_external_pin_documents(
            {**incomplete.document(), 'external_pin_paths': rows[:1]})
