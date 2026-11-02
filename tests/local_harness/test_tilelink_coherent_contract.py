"""TileLink coherent client: contract, role table and harness taps.

The authoritative tables are three and they must agree item by item:

* the bundled protocol plugin ``tilelink-coherent@1``
  (``src/myfuzz/protocols/plugins/tilelink-coherent.json``),
* ``myfuzz.integration.cpu_tlul.ROLE_WIDTHS`` - the coherent-client role map the
  BOOM seam publishes,
* the pinned derived ``BoomTile`` top, through its stored port evidence
  (``configs/cpus/boom/generated/source_manifest.json`` ->
  ``evidence/derived-20261017/physical_ports.json``).

These tests read the real pinned profile (the stored-evidence path keeps this to
a few seconds; the 18 MB top is hashed, never parsed by a frontend).
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import (
    bind_profile, elaborate_profile, load_component_profile,
)
from myfuzz.integration.cpu_tlul import ROLE_WIDTHS
from myfuzz.local_harness import template_contracts as tc
from myfuzz.local_harness.runtime_renderer import _expose_tl_coherent_trace
from myfuzz.local_harness.tilelink_coherent_fields import (
    CHANNELS, DATA_WIDTH, INSTRUCTION_HOP_REFUSAL, PROTOCOL, TAP_PREFIX,
    TL_COHERENT_SHAPE, channel_document,
)

_ROOT = Path(__file__).resolve().parents[2]
_PROFILE = _ROOT / 'configs/cpus/boom/component_profile.json'
_GENERATED = _ROOT / 'configs/cpus/boom/generated'


def _profile():
    if not _PROFILE.is_file() or not (_GENERATED / 'source_manifest.json').is_file():
        pytest.skip('pinned BOOM derived source is not checked out')
    return load_component_profile(_PROFILE)


def _bound_endpoint():
    profile = _profile()
    facts = elaborate_profile(profile, base_dir=_ROOT)
    binding = bind_profile(profile, facts)
    endpoints = [row for row in binding.endpoints if row.protocol is not None]
    assert len(endpoints) == 1
    return profile, facts, endpoints[0]


def _capabilities(profile):
    """The declared profile capabilities the endpoint matcher receives.

    BOOM declares none of the ``master_*`` aliases ``_endpoint_capabilities``
    remaps, so the declared mapping is already the effective one.
    """
    return dict(profile.capabilities)


class TestRoleTable:
    def test_plugin_table_is_the_coherent_client_map(self):
        plugin = json.loads((_ROOT / 'src/myfuzz/protocols/plugins/'
                             'tilelink-coherent.json').read_text())
        declared = {row['field_id']: int(row['width']) for row in plugin['fields']}
        assert set(declared) == set(ROLE_WIDTHS)
        assert declared == dict(ROLE_WIDTHS)
        # And the derived shape (renderer/contract input) is the same table.
        assert {role: width for role, (_, width) in TL_COHERENT_SHAPE.items()} == declared

    def test_contract_roles_are_the_plugin_roles(self):
        contract = [row for row in tc.list_template_contracts()
                    if row.template_id == 'cpu.tilelink-coherent']
        assert len(contract) == 1
        contract = contract[0]
        assert contract.protocol == PROTOCOL
        assert contract.side == 'cpu'
        # 39 roles, and the host-to-device (CPU-driven) half is the plugin's own
        # host_to_device direction - not a hand-typed split.
        assert len(contract.required_roles) == 39
        assert set(contract.required_roles) == set(ROLE_WIDTHS)
        plugin = json.loads((_ROOT / 'src/myfuzz/protocols/plugins/'
                             'tilelink-coherent.json').read_text())
        driven = {row['field_id'] for row in plugin['fields']
                  if row['direction'] == 'host_to_device'}
        assert set(contract.host_to_device_roles) == driven
        assert set(contract.host_to_device_roles) == set(tc._TL_COHERENT_HOST_TO_DEVICE)


class TestBoundProfile:
    def test_pinned_top_declares_exactly_the_39_role_shape(self):
        _, facts, endpoint = _bound_endpoint()
        # 47 physical ports = 39 client roles + clock + reset + 6 constants.
        assert len(facts.ports) == 47
        described = {field.role: (field.direction, field.width)
                     for field in endpoint.fields}
        assert described == dict(TL_COHERENT_SHAPE)

    def test_contract_is_selected_uniquely_for_the_bound_endpoint(self):
        profile, _, endpoint = _bound_endpoint()
        selected = tc.select_template_contract(endpoint, _capabilities(profile))
        assert selected.contract.template_id == 'cpu.tilelink-coherent'
        binding = selected.document()['binding']
        assert len(binding['roles']) == 39
        assert binding['data_width'] == DATA_WIDTH
        assert binding['address_width'] == 32

    def _contract(self):
        rows = [row for row in tc.list_template_contracts()
                if row.template_id == 'cpu.tilelink-coherent']
        assert len(rows) == 1
        return rows[0]

    def test_missing_role_is_refused_by_name(self):
        profile, _, endpoint = _bound_endpoint()
        trimmed = replace(endpoint, fields=tuple(
            field for field in endpoint.fields if field.role != 'd_bits_denied'))
        # ``_match`` names the reason; the public selector only reports that no
        # contract matched, which is the API's fixed shape.
        with pytest.raises(ValueError, match='template-missing-or-unknown-roles'):
            tc._match(self._contract(), trimmed, _capabilities(profile), False)
        with pytest.raises(ValueError, match='no_unique_compatible_contract'):
            tc.select_template_contract(trimmed, _capabilities(profile))
        assert 'd_bits_denied' in self._contract().required_roles

    def test_wrong_fixed_width_is_refused_by_name(self):
        profile, _, endpoint = _bound_endpoint()
        fields = []
        for field in endpoint.fields:
            if field.role == 'a_bits_opcode':
                fields.append(replace(field, width=2, raw_hi=1))
            else:
                fields.append(field)
        with pytest.raises(ValueError, match='template-field-width:a_bits_opcode'):
            tc._match(self._contract(), replace(endpoint, fields=tuple(fields)),
                      _capabilities(profile), False)
        with pytest.raises(ValueError, match='no_unique_compatible_contract'):
            tc.select_template_contract(replace(endpoint, fields=tuple(fields)),
                                        _capabilities(profile))

    def test_wrong_direction_is_refused_by_name(self):
        profile, _, endpoint = _bound_endpoint()
        fields = [replace(field, direction='input' if field.direction == 'output'
                          else 'output') if field.role == 'a_valid' else field
                  for field in endpoint.fields]
        with pytest.raises(ValueError, match='template-field-shape:a_valid'):
            tc._match(self._contract(), replace(endpoint, fields=tuple(fields)),
                      _capabilities(profile), False)
        with pytest.raises(ValueError, match='no_unique_compatible_contract'):
            tc.select_template_contract(replace(endpoint, fields=tuple(fields)),
                                        _capabilities(profile))


class TestHarnessTap:
    def _render(self):
        wires = {role: 'link_' + role for role in TL_COHERENT_SHAPE}
        ports, statements, taps, traces = [], [], [], []
        trace = _expose_tl_coherent_trace('cpu.coherent_memory', 'core',
                                         wires, ports, statements, taps, 16)
        return trace, ports, statements, taps

    def test_five_channels_are_published_with_their_real_widths(self):
        trace, ports, statements, taps = self._render()
        assert trace['protocol'] == 'tilelink-coherent'
        assert len(taps) == len(ports) == len(statements) == 39
        assert len(trace['signals']) == 39
        assert trace['channels'] == channel_document()
        # Channel sizes and widths come from the declaration, per channel.
        assert {channel: len(rows) for channel, rows in trace['channels'].items()} == {
            'a': 9, 'b': 9, 'c': 8, 'd': 10, 'e': 3}
        assert trace['channels']['a']['bits_data'] == DATA_WIDTH
        assert trace['channels']['a']['bits_mask'] == DATA_WIDTH // 8
        assert trace['channels']['d']['bits_data'] == DATA_WIDTH
        assert trace['channels']['e'] == {'ready': 1, 'valid': 1, 'bits_sink': 3}
        assert trace['channels']['d']['bits_sink'] == 3
        assert trace['signal_widths']['a_bits_address'] == 32
        assert [name for name, _, _ in ports] == [TAP_PREFIX + role
                                                  for role in sorted(TL_COHERENT_SHAPE)]

    def test_instruction_hop_is_refused_by_name_not_by_silence(self):
        trace, _, _, _ = self._render()
        assert trace['instruction_hop_refusal'] == INSTRUCTION_HOP_REFUSAL
        assert 'boom_cpu_session.py' in trace['instruction_hop_refusal']
        # No fabricated instruction hop is published in its place.
        assert 'instruction_hops' not in trace
