"""TileLink coherent CPU seam: declared roles, honest gaps, named refusal.

Synthetic only: no RTL, no Verilator build, no native session is started.  The
profile document read here is the repository's real pinned BOOM profile, so the
role map is checked against the actual 39 declared coherent fields.
"""
import json
from pathlib import Path

import pytest

from myfuzz.integration import cpu_tlul
from myfuzz.integration import extension_plugins
from myfuzz.integration.mmio_cpu_adapter import select_mmio_cpu
from myfuzz.local_harness.boom_cpu_session import GeneratedBoomCpuSession

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'configs/cpus/boom/component_profile.json'


def profile_document():
    return json.loads(PROFILE.read_text())


def endpoint(fields=None, *, protocol=None, endpoint_id='cpu.coherent_memory'):
    document = {'endpoints': [{
        'endpoint_id': endpoint_id, 'function': 'memory_master',
        'protocol': protocol if protocol is not None else ['tilelink-coherent', '1'],
        'fields': fields if fields is not None else [
            {'role': role, 'aliases': [cpu_tlul.PORT_PREFIX + role]}
            for role in cpu_tlul.ROLES]}]}
    return document


class _Artifact:
    """Minimal stand-in: only ``runtime_document`` is read by the seam."""

    def __init__(self, kind='tilelink_coherent_cpu'):
        self.runtime_document = {'kind': kind}


# ---------------------------------------------------------------------------
# declared role map
# ---------------------------------------------------------------------------
def test_real_profile_declares_all_39_roles():
    mapping = cpu_tlul.tl_role_map(profile_document())
    assert len(mapping) == 39
    assert set(mapping) == set(cpu_tlul.ROLES)
    assert mapping['a_bits_address'] == 'auto_tl_other_masters_out_a_bits_address'
    assert mapping['e_bits_sink'] == 'auto_tl_other_masters_out_e_bits_sink'
    assert all(port == cpu_tlul.PORT_PREFIX + role for role, port in mapping.items())


def test_traces_group_every_channel_with_declared_widths():
    traces = cpu_tlul.tl_traces(profile_document())
    assert traces['endpoint_id'] == 'cpu.coherent_memory'
    assert set(traces['a']) == {'ready', 'valid', 'bits_opcode', 'bits_param',
                               'bits_size', 'bits_source', 'bits_address',
                               'bits_mask', 'bits_data'}
    assert set(traces['d']) == {'ready', 'valid', 'bits_opcode', 'bits_param',
                               'bits_size', 'bits_source', 'bits_sink',
                               'bits_denied', 'bits_data', 'bits_corrupt'}
    assert set(traces['e']) == {'ready', 'valid', 'bits_sink'}
    assert set(traces['b']) == {'ready', 'valid', 'bits_opcode', 'bits_param',
                               'bits_size', 'bits_source', 'bits_address',
                               'bits_mask', 'bits_corrupt'}
    assert traces['widths']['a']['bits_address'] == 32
    assert traces['widths']['d']['bits_data'] == 64
    assert traces['widths']['e']['bits_sink'] == 3


def test_role_map_refuses_non_coherent_protocol():
    with pytest.raises(ValueError, match='tilelink-coherent-endpoint-required'):
        cpu_tlul.tl_role_map(endpoint(protocol=['tilelink', '1']))


def test_role_map_refuses_alias_that_is_not_the_generated_port():
    fields = [{'role': role, 'aliases': [cpu_tlul.PORT_PREFIX + role]}
              for role in cpu_tlul.ROLES]
    fields[0]['aliases'] = ['auto_tl_other_masters_out_b_ready']
    with pytest.raises(ValueError, match='tilelink-coherent-alias-mismatch'):
        cpu_tlul.tl_role_map(endpoint(fields))


def test_role_map_refuses_duplicate_and_unknown_roles():
    fields = [{'role': role, 'aliases': [cpu_tlul.PORT_PREFIX + role]}
              for role in cpu_tlul.ROLES]
    duplicate = fields + [dict(fields[0])]
    with pytest.raises(ValueError, match='tilelink-coherent-role-duplicated'):
        cpu_tlul.tl_role_map(endpoint(duplicate))
    unknown = fields[:-1] + [{'role': 'a_bits_user', 'aliases': ['x']}]
    with pytest.raises(ValueError, match='tilelink-coherent-role-unsupported'):
        cpu_tlul.tl_role_map(endpoint(unknown))


def test_role_map_refuses_incomplete_role_set():
    fields = [{'role': role, 'aliases': [cpu_tlul.PORT_PREFIX + role]}
              for role in cpu_tlul.ROLES[:-1]]
    with pytest.raises(ValueError, match='tilelink-coherent-roles-incomplete'):
        cpu_tlul.tl_role_map(endpoint(fields))


# ---------------------------------------------------------------------------
# the shipped session really is outside the generic lifecycle
# ---------------------------------------------------------------------------
def test_shipped_session_reports_the_four_structural_gaps():
    gaps = cpu_tlul.executor_gaps(GeneratedBoomCpuSession)
    assert gaps == ('session-router-keyword-missing',
                    'session-memory-keyword-missing',
                    'session-online-instruction-slots-missing',
                    'session-parked-fetch-address-missing',
                    'host-memory-authority-missing')
    assert not hasattr(GeneratedBoomCpuSession, 'INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE')


def test_executor_gaps_reads_the_frozen_image_and_ram_authority_attributes():
    class _Frozen:
        INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE = True

        def __init__(self, *, memory, router):
            self.memory, self.router = memory, router

        def declare_instruction_slots(self, address, count=1):
            raise NotImplementedError

        def accept_instructions(self, address, data, *, source_event_id):
            raise NotImplementedError

        @property
        def waiting_instruction_address(self):
            return None

    gaps = cpu_tlul.executor_gaps(_Frozen)
    assert 'instruction-image-frozen-before-first-edge' in gaps
    assert 'host-memory-authority-missing' in gaps
    assert 'session-router-keyword-missing' not in gaps

    class _HostAuthoritative(_Frozen):
        INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE = False
        HOST_MEMORY_AUTHORITY = True

    assert cpu_tlul.executor_gaps(_HostAuthoritative) == ()


# ---------------------------------------------------------------------------
# seam behaviour
# ---------------------------------------------------------------------------
def test_adapter_document_is_pure_and_never_admits():
    document = cpu_tlul.adapter_document(profile_document(),
                                         session_type=GeneratedBoomCpuSession)
    assert document['kind'] == 'tilelink_coherent_cpu'
    assert document['role_count'] == 39
    assert document['role_error'] is None
    assert document['runtime_admitted'] is False
    assert document['can_execute_flows'] == []
    assert document['refused_flows'] == ['F1', 'F2', 'F3', 'F4']
    assert len(document['session_gaps']) == len(cpu_tlul.SESSION_GAPS[cpu_tlul.KIND])
    assert 'session-router-keyword-missing' in document['structural_gaps']


def test_cpu_adapter_refuses_with_the_kind_and_every_gap():
    with pytest.raises(ValueError) as raised:
        cpu_tlul.cpu_adapter(_Artifact(), {}, {})
    message = str(raised.value)
    assert message.startswith('MMIO-CPU-adapter-unsupported:tilelink:'
                              'tilelink_coherent_cpu:')
    for token in ('no-generic-executor-adapter',
                  'session-router-keyword-missing',
                  'native-channel-identity-missing',
                  'generic-artifact-missing',
                  'rv64-f1-contract-missing'):
        assert token in message


def test_cpu_adapter_refuses_a_foreign_artifact_kind():
    with pytest.raises(ValueError, match='not-a-tilelink-coherent-cpu-artifact'):
        cpu_tlul.cpu_adapter(_Artifact('obi_cpu'), {}, {})


def test_select_mmio_cpu_surfaces_the_tilelink_refusal():
    with pytest.raises(ValueError, match='MMIO-CPU-adapter-unsupported:tilelink'):
        select_mmio_cpu(_Artifact(), {}, {})


def test_extension_seam_maps_the_real_kind_to_this_module():
    module = extension_plugins._CPU_MODULES.get('tilelink_coherent_cpu')
    assert module == 'myfuzz.integration.cpu_tlul'
    assert extension_plugins._module(module) is cpu_tlul
    # No dead mapping may remain for a kind that does not exist.
    assert 'boom_cpu' not in extension_plugins._CPU_MODULES
    assert all(extension_plugins._module(name) is not None
               for name in extension_plugins._CPU_MODULES.values())


def test_extension_cpu_adapter_delegates_and_propagates_the_refusal():
    with pytest.raises(ValueError, match='MMIO-CPU-adapter-unsupported:tilelink'):
        extension_plugins.cpu_adapter(_Artifact(), {}, {})
    assert extension_plugins.cpu_adapter(_Artifact('obi_cpu'), {}, {}) is None
