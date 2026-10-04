"""Pinned SPI source facts; deliberately independent of artifact acceptance.

The APB SPI profile requires the seven-file union of two locked repositories.
The current artifact source gate compares one source locator literally and
rejects this union. This verifier authenticates source facts and cannot grant
build acceptance, generation or runtime execution.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, _source_locator
from myfuzz.composition.source_crawler import _content_hash


_PINNED_UNION_REVISION = 'sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230'
_PINNED_PARAMETERS = {'APB_ADDR_WIDTH': '12', 'BUFFER_DEPTH': '10'}


def verify_pulp_spi_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict:
    """Authenticate the selected bytes/closure and the full-top union profile.

    Requires a repository checkout with scripts/verify_soc_sources.py. This
    explicit source-fact API is not called by any builder, session or renderer.
    """
    if not isinstance(profile, ComponentProfile):
        raise ValueError('pulp-spi-profile-required')
    if profile.source != _source_locator(profile.source_document):
        raise ValueError('pulp-spi-source-inconsistent')
    root = Path(base_dir).resolve()
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_pulp_spi_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('pulp-spi-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    records = {record['id']: record for record in lock['components']}
    selected = [records[name] for name in ('pulp_spi', 'pulp_spi_dependencies')]
    owners = verifier.document_owners(lock, root)
    allowed = verifier.document_roots(lock)
    verified = []
    for record in selected:
        if (record['source_status'], record['elaboration_status'], record['closure_status']) != (
                'source_verified', 'elaboration_verified', 'selected'):
            raise ValueError('pulp-spi-source-unverified')
        verified.append(verifier.verify_record(record, root, owners=owners,
                                               allowed_roots=allowed[record['id']], replay=False))
    record = records['pulp_spi']
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('pulp-spi-closure-changed')
    closure = json.loads(closure_raw)
    source = profile.source_document
    files = [str(Path(item['root']).relative_to('third_party') / item['path'])
             for item in closure['closure_files']]
    expected_parameters = {item['name']: item['value'] for item in record['typed_parameters']}
    settings = source.get('elaboration', {})
    parameters = {item['name']: item['value'] for item in settings.get('parameters', [])}
    if (profile.component_id != 'pulp_spi' or source['root'] != 'third_party'
            or source['top_module'] != 'apb_spi_master'
            or source.get('top_port_selection', 'all') != 'all'
            or sorted(source.get('files', [])) != sorted(files)
            or len(source.get('files', [])) != len(files)
            or source.get('filelist') or source.get('include_roots')
            or source.get('repositories') or source.get('filelist_variables')):
        raise ValueError('pulp-spi-union-source-mismatch')
    if (settings.get('frontend') != 'verilator-json' or settings.get('defines')
            or parameters != _PINNED_PARAMETERS
            or parameters != expected_parameters
            or parameters != {item['name']: item['value'] for item in closure['parameters']}):
        raise ValueError('pulp-spi-parameters-mismatch')
    contents = {relative: (root / 'third_party' / relative).read_bytes() for relative in files}
    if (source['revision'] != _PINNED_UNION_REVISION
            or source['revision'] != _content_hash(contents)):
        raise ValueError('pulp-spi-union-pin-mismatch')
    if (len(profile.clocks) != 1 or profile.clocks[0].port != 'HCLK'
            or len(profile.resets) != 1 or profile.resets[0].port != 'HRESETn'
            or profile.resets[0].polarity != 'active_low'
            or profile.resets[0].synchronous):
        raise ValueError('pulp-spi-clock-reset-mismatch')
    expected_capabilities = {'address_width': 12, 'data_width': 32,
                             'read': True, 'write': True, 'byte_enable': False,
                             'partial_write': False, 'has_error': True}
    if any(profile.capabilities.get(name) != value
           for name, value in expected_capabilities.items()):
        raise ValueError('pulp-spi-capability-mismatch')
    if profile.interrupts or not any(action.port == 'events_o' and action.action == 'observe'
                                     for action in profile.port_actions):
        raise ValueError('pulp-spi-native-event-observation-required')
    return {
        'schema_version': 'pulp_spi_native_contract.v1',
        'source_records': verified, 'closure_files': closure['closure_files'],
        'lock_sha256': hashlib.sha256(raw_lock).hexdigest(),
        'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
        'profile_union_revision': source['revision'],
        'artifact_source_gate_compatible': False,
        'artifact_source_gate_gap': 'seven-file-union-vs-two-file-git-locator',
        'runtime_effective': False, 'dut_semantics_verified': False,
        'clock_reset': {'clock': 'HCLK', 'reset': 'HRESETn',
                        'polarity': 'active_low', 'synchronous': False},
        'apb': {'template_id': 'target.apb3', 'template_version': '1',
                'variant_id': 'full-word', 'pready': 'constant_one',
                'pslverr': 'constant_zero', 'address_decode': 'PADDR[5:2]',
                'register_alias_bytes': 64, 'partial_write': False},
        'serial': {'cpol': 0, 'cpha': 0, 'bit_order': 'msb_first',
                   'sck': 'spi_clk', 'mosi': 'spi_sdo0', 'miso': 'spi_sdi1',
                   'chip_selects': ['spi_csn0', 'spi_csn1', 'spi_csn2', 'spi_csn3'],
                   'line_width_mode': 'spi_mode', 'supported_peer_mode': 'single_line_only',
                   'setup_mode_transient': 'mode_2_selected_idle_low_before_any_edge',
                   'hclk_cycles_per_sck': '2*(CLKDIV+1)',
                   'data_length_unit': 'bits', 'fifo_word_bits': 32,
                   'software_reset_scope': 'fifos_only'},
        'environment_sources': {'spi_sdi0': 'constant_zero', 'spi_sdi1': 'native_peer_miso',
                                'spi_sdi2': 'constant_zero', 'spi_sdi3': 'constant_zero'},
        'events': [
            {'port': 'events_o', 'bit': 0, 'trigger': 'native_pulse',
             'meaning': 'tx_or_rx_threshold', 'rearm_read_offset': 0x28,
             'rearm_read_value': 0, 'level_conversion': False},
            {'port': 'events_o', 'bit': 1, 'trigger': 'native_pulse',
             'meaning': 'end_of_transfer', 'level_conversion': False},
        ],
    }
