"""The renderer's AHB-Lite shape must match CVW's real declared boundary.

`runtime_renderer._AHB_LITE` is what the generated runtime uses to bind the
DUT's AHB-Lite ports, so it is a *second* place the boundary is written down -
the first being `configs/cpus/cvw/interface_description.json`.  Two copies of one
fact drift, and the class of drift that matters here is silent: a wrong width or
a wrong direction would still lint, still elaborate, and only show up as a broken
harness much later.

These checks compare the renderer's shape against the declaration (role names and
directions) and against CVW's own configuration headers (widths), so a change to
either has to be made deliberately in both places.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from myfuzz.local_harness import runtime_renderer

ROOT = Path(__file__).resolve().parents[2]
DECLARATION = ROOT / 'configs' / 'cpus' / 'cvw' / 'interface_description.json'
CVW_CONFIG = ROOT / 'third_party' / 'cvw_upstream_reference' / 'config'

#: Directions in the shape are the DUT's own, exactly as in `_APB` (where the DUT
#: is a target and therefore *receives* the address side).  Here the DUT is the
#: AHB manager, so the roles it drives are outputs.  An earlier version of this
#: test asserted the opposite and so pinned the bug rather than the fact.
_HOST_ROLES = frozenset({'htrans', 'haddr', 'hwrite', 'hwdata', 'hwstrb',
                         'hsize', 'hburst', 'hprot', 'hmastlock', 'hsel'})


def declaration_roles() -> dict[str, str]:
    document = json.loads(DECLARATION.read_text(encoding='utf-8'))
    assert len(document['endpoints']) == 1
    return {field['role']: field['aliases'][0]
            for field in document['endpoints'][0]['fields']}


def real_widths(config: str = 'rv32imc') -> dict[str, int]:
    """Read XLEN/AHBW/PA_BITS the way CVW's own headers derive them."""
    def localparams(relative):
        text = (CVW_CONFIG / relative).read_text(encoding='utf-8')
        found = {}
        for line in text.splitlines():
            line = line.split('//', 1)[0].strip()
            if not line.startswith('localparam '):
                continue
            for part in line[len('localparam '):].rstrip(';').split(','):
                if '=' not in part:
                    continue
                name, _, expression = part.partition('=')
                found[name.strip().split()[-1]] = re.sub(
                    r"32'd", '', expression.strip())
        return found

    local = localparams(f'{config}/config.vh')
    shared = localparams('shared/config-shared.vh')
    xlen = int(local['XLEN'])
    ahbw = int(local['AHBW'].strip('()')) if local['AHBW'].strip('()').isdigit() else xlen
    pa_bits = int(shared['PA_BITS'].split('?')[1].split(':')[0].strip())
    return {'XLEN': xlen, 'AHBW': ahbw, 'PA_BITS': pa_bits}


def test_the_shape_covers_exactly_the_declared_roles():
    assert sorted(runtime_renderer._AHB_LITE) == sorted(declaration_roles())


def test_the_shape_directions_are_the_duts_own():
    """The shape must match what a real bound endpoint carries.

    The convention is the DUT's perspective (`_APB` gives a target's address pins
    as ``input``), so an AHB *manager* drives them.  This is checked against the
    real CVW profile's extracted directions when that profile is present, which is
    how the earlier inverted version of this test was caught.
    """
    for role, (direction, _width) in runtime_renderer._AHB_LITE.items():
        expected = 'output' if role in _HOST_ROLES else 'input'
        assert direction == expected, (role, direction)

    profile_path = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'
    if not profile_path.is_file():
        pytest.skip('the CVW profile is not present in this checkout')
    profile = json.loads(profile_path.read_text(encoding='utf-8'))
    declared = {field['role']: (field['direction'], field['width'])
                for field in profile['endpoints'][0]['fields']}
    assert declared == dict(runtime_renderer._AHB_LITE), (
        'the renderer shape and the extracted profile facts have diverged')


def test_the_shape_widths_are_the_real_cvw_values():
    if not (CVW_CONFIG / 'rv32imc' / 'config.vh').is_file():
        pytest.skip('the CVW reference source is not present in this checkout')
    real = real_widths('rv32imc')
    assert real == {'XLEN': 32, 'AHBW': 32, 'PA_BITS': 34}
    shape = runtime_renderer._AHB_LITE
    assert shape['haddr'] == ('output', real['PA_BITS'])
    assert shape['hwdata'] == ('output', real['AHBW'])
    assert shape['hwstrb'] == ('output', real['AHBW'] // 8)
    assert shape['hrdata'] == ('input', real['AHBW'])
    # The asymmetry is the point: a shape that tied the address width to the data
    # width would bind 32 bits where CVW drives 34.
    assert shape['haddr'][1] != shape['hwdata'][1]


def test_the_shape_roles_are_the_ones_the_adapter_drives():
    """The adapter's port names are the shape's roles, uppercased where CVW is.

    The adapter drives `HTRANS`/`HADDR`/... and reads `HREADYEXT`/`HRDATAEXT`/
    `HRESPEXT`, so every shape role must have a matching adapter port.  This is
    what keeps the renderer's wiring table and the RTL in step.
    """
    adapter = (ROOT / 'src' / 'myfuzz' / 'protocols' / 'rtl'
               / 'beat_to_ahb_lite.sv').read_text(encoding='utf-8')
    for role in runtime_renderer._AHB_LITE:
        name = role.upper()
        # CVW suffixes the subordinate-driven signals with EXT at the CPU boundary.
        candidates = [name, name + 'EXT']
        assert any(re.search(rf'\b{candidate}\b', adapter) for candidate in candidates), (
            f'no adapter port matches shape role {role!r}')


def test_the_renderer_binds_the_real_extracted_endpoint():
    """Drive the real ``_shape`` gate with the profile's own facts.

    The constant comparison above can only catch a shape that no longer matches
    the declaration; this calls the function the renderer actually calls, on a
    resolved endpoint built from the extracted directions and widths.  It is the
    check that failed with
    ``runtime-endpoint-width-direction:cpu.external_bus:haddr`` while the shape
    still carried the inverted directions, so it is the guard that matters.
    """
    from myfuzz.composition.component_profile import ResolvedEndpoint, ResolvedField

    profile_path = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'
    if not profile_path.is_file():
        pytest.skip('the CVW profile is not present in this checkout')
    profile = json.loads(profile_path.read_text(encoding='utf-8'))
    source = profile['endpoints'][0]

    resolved, abi = [], []
    for field in source['fields']:
        role, width = field['role'], field['width']
        port = field['aliases'][0]
        resolved.append(ResolvedField(
            source['endpoint_id'], role, port, (), field['direction'],
            width, 0, width - 1, False, 'wallypipelinedsoc.sv', 1, width))
        abi.append({'endpoint_id': source['endpoint_id'], 'role': role,
                    'physical_port': port, 'bit_lo': 0, 'bit_hi': width - 1,
                    'width': width, 'direction': field['direction'],
                    'disposition': 'functional', 'wrapper_name': f'w_{port}'})
    endpoint = ResolvedEndpoint(source['endpoint_id'], source['function'],
                                tuple(source['protocol']), tuple(resolved))

    wires = runtime_renderer._shape(endpoint, runtime_renderer._AHB_LITE, abi)
    assert sorted(wires) == sorted(runtime_renderer._AHB_LITE)
    assert wires['haddr'] == 'link_w_HADDR'
    assert wires['hrdata'] == 'link_w_HRDATAEXT'
