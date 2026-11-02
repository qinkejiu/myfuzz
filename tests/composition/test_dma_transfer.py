"""Tests for the pure DMA transfer declaration/planning layer.

Everything here is declaration/planning only: profiles and the generated edge
contract are read, configs are JSON, and the assertions are about normalized
facts and named refusals.  No RTL is elaborated, built or simulated.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.dma_transfer import (
    DMA_PLAN_SCHEMA,
    HOST_BLOCK_WORDS,
    DmaTransferError,
    dma_route_target,
    dma_transfer_declaration,
    validate_transfer_plan,
)
from myfuzz.local_harness.wishbone_dma_fields import dma_profile_edge_contract

ROOT = Path(__file__).resolve().parents[2]
BASE_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json'
LEN8_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-len8-f1f6.json'
DELAY_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-delay-f1f6.json'
FIFO_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-fifo-f1f6.json'
READ_CONFIG = ROOT / ('configs/scenarios/'
                      'inprocess-obi-apb-timer-i2c-dma-read-f1f6.json')
WBDMAC_CONFIG = ROOT / 'configs/scenarios/inprocess-generality-wbdmac-f1f6.json'
ZIPDMA_PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json'
WBDMAC_PROFILE = ROOT / 'configs/peripherals/zipcpu_wbdmac/component_profile.json'
ZIPDMA_BEHAVIOR = 'configs/behaviors/zipdma_f6.json'
LEN8_BEHAVIOR = 'configs/behaviors/zipdma_len8_f6.json'
WBDMAC_BEHAVIOR = 'configs/behaviors/wbdmac_f6.json'
ZIPDMA_CAPABILITY = ROOT / 'configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared/dma.test_capability.json'
SPI_WINDOW_BASE = 0x20002000
SPI_WINDOW = {'base': SPI_WINDOW_BASE, 'size': 4096}
SPI_SOC_WINDOW = {'base': 0x40002000, 'size': 4096}
TIMER_WINDOW = {'base': 0x40001000, 'size': 4096}
#: The read-route scenario maps the PULP I2C below 1 GiB so the pinned ZipDMA's
#: 30-bit byte-address SOURCE field can encode it; the timer keeps its SoC base.
I2C_READ_WINDOW = {'base': 0x20001000, 'size': 4096}


@pytest.fixture(scope='module')
def zipdma_profile():
    return load_component_profile(ZIPDMA_PROFILE)


@pytest.fixture(scope='module')
def wbdmac_profile():
    return load_component_profile(WBDMAC_PROFILE)


def _artifact(profile, **overrides):
    contract = dma_profile_edge_contract(dict(profile.capabilities))
    contract.update(copy.deepcopy(overrides))
    return {'dma_edge_contract': contract}


@pytest.fixture(scope='module')
def zipdma_artifact(zipdma_profile):
    return _artifact(zipdma_profile)


@pytest.fixture(scope='module')
def wbdmac_artifact(wbdmac_profile):
    return _artifact(wbdmac_profile)


def _config(path, **overrides):
    document = json.loads(Path(path).read_text())
    document.update(copy.deepcopy(overrides))
    return document


def _zipdma_plan(config, profile, artifact):
    return dma_transfer_declaration(config, profile, artifact, base_dir=ROOT)


def _wbdmac_plan(config, profile, artifact):
    return dma_transfer_declaration(config, profile, artifact, base_dir=ROOT)


def _refusal(reason, function):
    with pytest.raises(DmaTransferError) as captured:
        function()
    assert captured.value.reason == reason, str(captured.value)
    return captured.value


def _host_codes(report):
    return [row['code'] for row in report['host_limits']]


# ---------------------------------------------------------------------------
# plan normalization
# ---------------------------------------------------------------------------
def test_zipdma_plan_normalizes_the_four_word_declaration(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['schema_version'] == DMA_PLAN_SCHEMA
    assert plan['device']['family'] == 'zipdma'
    assert plan['block_words'] == 4
    assert plan['block_words_declared_by'] == 'scenario'
    assert plan['block_bytes'] == plan['length_value'] == 16
    assert plan['length_unit'] == 'bytes'
    assert plan['length_register'] == {'name': 'LENGTH', 'offset': 12,
                                       'bits': 32, 'unit': 'bytes'}
    assert plan['start']['word'] == 0
    assert plan['start']['encoding'] == 'zipdma_control_write'
    assert plan['start']['key'] == 0
    assert plan['start']['source'] == 'derived'
    assert plan['increment_source'] is True
    assert plan['increment_destination'] is True
    byte_enable = plan['master_byte_enable']
    assert byte_enable['kind'] == 'full_word'
    assert byte_enable['mask'] == 15
    assert byte_enable['lanes'] == [0, 1, 2, 3]
    assert byte_enable['sel_signal'] == 'mwb_sel'
    assert byte_enable['partial'] is False
    assert plan['byte_address_units']['source_destination'] == 'byte_address'
    assert plan['byte_address_units']['source_destination_bits'] == 30
    assert plan['byte_address_units']['master'] == 'word'
    assert plan['byte_address_units']['master_shift'] == 2
    assert plan['max_outstanding'] == 1
    assert plan['irq_trigger'] == 'level'
    assert plan['irq_clear'] == {'method': 'write', 'offset': 0,
                                 'value': 0x80000000, 'byte_enable': 15}
    assert plan['irq_pulse_ticks'] is None
    assert plan['status']['busy_bit'] == 31
    assert plan['status']['err_bit'] == 30
    assert plan['status']['source'] == 'builtin_zipdma_rtl_default'
    assert plan['route'] is None
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert report['host_limits'] == []
    assert report['host_supported'] is True


def test_behavior_file_declares_the_status_bits(zipdma_profile, zipdma_artifact):
    config = _config(BASE_CONFIG, dma_behavior=ZIPDMA_BEHAVIOR)
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    assert plan['block_words_declared_by'] == 'behavior'
    assert plan['block_words_declaration'].startswith('behavior:')
    assert plan['declaration']['behavior_declared_by'] == 'file'
    assert plan['status'] == {
        'kind': 'status', 'busy_bit': 31, 'err_bit': 30,
        'declared_by': 'file', 'source': ZIPDMA_BEHAVIOR,
        'evidence': 'declared by ' + ZIPDMA_BEHAVIOR,
    }


def test_wbdmac_plan_normalizes_keyed_start_and_pulse_irq(wbdmac_profile, wbdmac_artifact):
    plan = _wbdmac_plan(_config(WBDMAC_CONFIG), wbdmac_profile, wbdmac_artifact)
    assert plan['device']['family'] == 'wbdmac'
    assert plan['block_words'] == 4
    assert plan['length_unit'] == 'words'
    assert plan['length_value'] == 4
    assert plan['length_register']['name'] == 'TOTAL_LENGTH'
    assert plan['length_register']['bits'] == 30
    assert plan['start']['word'] == 0x0FED0004
    assert plan['start']['encoding'] == 'wbdmac_keyed_start'
    assert plan['start']['key'] == 0xFED
    assert plan['start']['key_bits'] == [16, 27]
    assert plan['start']['block_words_bits'] == [0, 9]
    byte_enable = plan['master_byte_enable']
    assert byte_enable['kind'] == 'full_word'
    assert byte_enable['mask'] == 15
    assert byte_enable['sel_signal'] is None
    assert byte_enable['sel_available'] is False
    assert plan['byte_address_units']['source_destination_bits'] == 32
    assert plan['irq_trigger'] == 'pulse'
    assert plan['irq_pulse_ticks'] == 16
    assert plan['irq_pulse_ticks_source'] == 'host_default'
    assert plan['irq_clear'] == {'method': 'none'}
    assert plan['status']['declared_by'] == 'file'
    assert plan['status']['source'] == WBDMAC_BEHAVIOR
    assert validate_transfer_plan(plan, wbdmac_profile, wbdmac_artifact)['host_limits'] == []


# ---------------------------------------------------------------------------
# the three new scenario files
# ---------------------------------------------------------------------------
def test_len8_config_is_declaration_valid_but_host_capped(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(LEN8_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['block_words'] == 8
    assert plan['block_bytes'] == 32
    assert plan['length_value'] == 32
    assert plan['start']['word'] == 0
    assert plan['status']['declared_by'] == 'file'
    assert plan['status']['source'] == LEN8_BEHAVIOR
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert report['host_supported'] is False
    assert _host_codes(report) == ['host-block-words-cap']
    limit = report['host_limits'][0]
    assert limit['kind'] == 'host_only'
    assert limit['plan_value'] == 8
    assert limit['host_limit'] == HOST_BLOCK_WORDS == 4
    facts = {row['fact']: row for row in report['declaration_facts']}
    assert facts['device_max_block_words']['value'] == 64
    assert facts['device_max_block_words']['kind'] == 'declaration'
    assert all(row['kind'] == 'declaration'
               for row in report['declaration_facts'])


def test_delay_config_declares_backpressure_and_observations(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(DELAY_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['block_words'] == 4
    delay = plan['response_delay']
    assert delay['ticks'] == 2
    assert delay['mode'] == 'host_stall_before_response'
    assert delay['source'] == 'scenario:dma_response_delay'
    assert delay['backpressure']['pattern'] == 'per_response_stall'
    assert delay['observation']['stall_ticks_min'] == 2
    assert delay['observation']['dma_writes'] == 4
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert _host_codes(report) == ['host-response-delay-absent']
    assert report['host_limits'][0]['kind'] == 'host_only'


def test_fifo_config_declares_fixed_register_route(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(FIFO_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['block_words'] == 8
    assert plan['increment_source'] is True
    assert plan['increment_destination'] is False
    assert plan['start']['word'] == 0x00400000
    route = plan['route']
    assert route['kind'] == 'fifo'
    assert route['is_fifo'] is True
    assert route['direction'] == 'write'
    assert route['target_index'] == 1
    assert route['target_name'] == 'pulp_spi_txfifo'
    assert route['offset'] == 24
    assert route['address_mode'] == 'fixed'
    assert route['register'] == {'name': 'TXFIFO', 'offset': 24,
                                 'access': 'wo', 'width': 32,
                                 'side_effect': 'write_pushes_fifo'}
    assert route['target_profile_facts']['window_size'] == 4096
    assert route['target_profile_facts']['alignment'] == 4096
    assert route['evidence']['kind'] == 'fifo_level'
    assert route['evidence']['bits'] == [28, 24]
    assert route['evidence']['depth'] == 10
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert _host_codes(report) == ['host-block-words-cap',
                                   'host-fixed-start-word',
                                   'host-dma-target-route-absent']


# ---------------------------------------------------------------------------
# block bounds and declaration completeness
# ---------------------------------------------------------------------------
def test_zipdma_block_bound(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG, dma_block_words=64),
                        zipdma_profile, zipdma_artifact)
    assert plan['block_words'] == 64
    assert plan['length_value'] == 256
    error = _refusal('block-beyond-declared-bound', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_block_words=65), zipdma_profile, zipdma_artifact))
    assert error.detail == 'zipdma:65>64'


def test_wbdmac_block_bound(wbdmac_profile, wbdmac_artifact):
    # The shared behavior file declares its own four-word block, so the bound
    # test states the length inline and drops the file to avoid a conflict.
    config = _config(WBDMAC_CONFIG, dma_block_words=1024)
    config.pop('dma_behavior')
    plan = _wbdmac_plan(config, wbdmac_profile, wbdmac_artifact)
    assert plan['block_words'] == 1024
    assert plan['length_value'] == 1024
    assert plan['start']['word'] == 0x0FED0000
    config = _config(WBDMAC_CONFIG, dma_block_words=1025)
    config.pop('dma_behavior')
    error = _refusal('block-beyond-declared-bound', lambda: _wbdmac_plan(
        config, wbdmac_profile, wbdmac_artifact))
    assert error.detail == 'wbdmac:1025>1024'


def test_block_words_must_be_declared(zipdma_profile, zipdma_artifact):
    config = _config(BASE_CONFIG)
    config.pop('dma_block_words')
    _refusal('block-words-not-declared',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


def test_behavior_block_conflict_is_refused_by_name(zipdma_profile, zipdma_artifact):
    config = _config(BASE_CONFIG, dma_behavior=ZIPDMA_BEHAVIOR, dma_block_words=5)
    error = _refusal('behavior-source-conflict:block_words',
                     lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))
    assert error.reason == 'behavior-source-conflict:block_words'


# ---------------------------------------------------------------------------
# byte enables
# ---------------------------------------------------------------------------
def test_zipdma_size_maps_to_lane_patterns(zipdma_profile, zipdma_artifact):
    two = _zipdma_plan(_config(BASE_CONFIG, dma_transfer_size_bytes=2),
                       zipdma_profile, zipdma_artifact)
    byte_enable = two['master_byte_enable']
    assert byte_enable['kind'] == 'size_derived_lanes'
    assert byte_enable['mask'] is None
    assert byte_enable['size_code'] == 2
    assert byte_enable['lane_pattern'] == [0b0011, 0b1100]
    assert byte_enable['beats_per_word'] == 2
    assert byte_enable['partial'] is True
    assert two['start']['word'] == 0x00220000
    report = validate_transfer_plan(two, zipdma_profile, zipdma_artifact)
    assert 'host-full-word-master-sel' in _host_codes(report)

    one = _zipdma_plan(_config(BASE_CONFIG, dma_transfer_size_bytes=1),
                       zipdma_profile, zipdma_artifact)
    byte_enable = one['master_byte_enable']
    assert byte_enable['kind'] == 'size_derived_lanes'
    assert byte_enable['size_code'] == 3
    assert byte_enable['lane_pattern'] == [0b0001, 0b0010, 0b0100, 0b1000]
    assert byte_enable['beats_per_word'] == 4
    assert one['start']['word'] == 0x00330000
    validate_transfer_plan(one, zipdma_profile, zipdma_artifact)

    _refusal('master-byte-enable-unsupported', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_transfer_size_bytes=3), zipdma_profile, zipdma_artifact))


def test_no_select_device_refuses_partial_byte_enable(wbdmac_profile, wbdmac_artifact):
    error = _refusal('partial-byte-enable-on-no-select-device', lambda: _wbdmac_plan(
        _config(WBDMAC_CONFIG, dma_master_byte_enable=3),
        wbdmac_profile, wbdmac_artifact))
    assert error.detail == 'wbdmac:declared-mask'
    plan = _wbdmac_plan(_config(WBDMAC_CONFIG, dma_master_byte_enable=15),
                        wbdmac_profile, wbdmac_artifact)
    assert plan['master_byte_enable']['kind'] == 'full_word'
    assert plan['master_byte_enable']['mask'] == 15


# ---------------------------------------------------------------------------
# increments and the start word
# ---------------------------------------------------------------------------
def test_increment_disable_is_encoded_in_the_start_word(zipdma_profile, zipdma_artifact,
                                                        wbdmac_profile, wbdmac_artifact):
    fixed_destination = _zipdma_plan(
        _config(BASE_CONFIG, dma_increment_destination=False),
        zipdma_profile, zipdma_artifact)
    assert fixed_destination['increment_source'] is True
    assert fixed_destination['increment_destination'] is False
    assert fixed_destination['start']['word'] == 0x00400000
    report = validate_transfer_plan(fixed_destination, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert 'host-fixed-start-word' in _host_codes(report)

    fixed_source = _zipdma_plan(_config(BASE_CONFIG, dma_increment_source=False),
                                zipdma_profile, zipdma_artifact)
    assert fixed_source['start']['word'] == 0x00040000
    validate_transfer_plan(fixed_source, zipdma_profile, zipdma_artifact)

    wb_fixed_source = _wbdmac_plan(
        _config(WBDMAC_CONFIG, dma_increment_source=False),
        wbdmac_profile, wbdmac_artifact)
    assert wb_fixed_source['start']['word'] == 0x2FED0004
    validate_transfer_plan(wb_fixed_source, wbdmac_profile, wbdmac_artifact)

    wb_fixed_destination = _wbdmac_plan(
        _config(WBDMAC_CONFIG, dma_increment_destination=False),
        wbdmac_profile, wbdmac_artifact)
    assert wb_fixed_destination['start']['word'] == 0x1FED0004


def test_non_incrementing_transfer_needs_start_encoding(zipdma_profile, zipdma_artifact,
                                                        wbdmac_profile, wbdmac_artifact):
    _refusal('non-incrementing-transfer-not-encoded-by-start-word',
             lambda: _zipdma_plan(_config(BASE_CONFIG, dma_increment_source=False,
                                          dma_start_word=0),
                                  zipdma_profile, zipdma_artifact))
    _refusal('non-incrementing-transfer-not-encoded-by-start-word',
             lambda: _wbdmac_plan(_config(WBDMAC_CONFIG, dma_increment_source=False,
                                          dma_start_word=0x0FED0004),
                                  wbdmac_profile, wbdmac_artifact))


def test_start_word_mismatch_is_refused(zipdma_profile, zipdma_artifact,
                                        wbdmac_profile, wbdmac_artifact):
    _refusal('start-word-mismatch', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_start_word=0x00220000),
        zipdma_profile, zipdma_artifact))
    _refusal('start-word-mismatch', lambda: _wbdmac_plan(
        _config(WBDMAC_CONFIG, dma_start_word=0x0FED0005),
        wbdmac_profile, wbdmac_artifact))


# ---------------------------------------------------------------------------
# response delay, outstanding and error injection
# ---------------------------------------------------------------------------
def test_response_delay_is_declared_while_the_host_lacks_it(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(
        _config(BASE_CONFIG, dma_response_delay=2,
                dma_backpressure={'pattern': 'per_response_stall',
                                  'applies_to': ['read', 'write'],
                                  'max_consecutive_ticks': 2},
                dma_observation_expectations={'stall_ticks_min': 2,
                                              'stall_ticks_max': 2}),
        zipdma_profile, zipdma_artifact)
    assert plan['response_delay']['ticks'] == 2
    assert plan['response_delay']['observation']['stall_ticks_min'] == 2
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert _host_codes(report) == ['host-response-delay-absent']
    _refusal('response-delay-not-declarable', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_response_delay=65), zipdma_profile, zipdma_artifact))
    _refusal('response-delay-not-declarable', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_response_delay='2'), zipdma_profile, zipdma_artifact))


def test_outstanding_is_single(zipdma_profile, zipdma_artifact):
    _refusal('outstanding-beyond-one', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_max_outstanding=2), zipdma_profile, zipdma_artifact))
    _refusal('outstanding-invalid', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_max_outstanding=0), zipdma_profile, zipdma_artifact))
    plan = _zipdma_plan(_config(BASE_CONFIG, dma_max_outstanding=1),
                        zipdma_profile, zipdma_artifact)
    assert plan['max_outstanding'] == 1


def test_error_injection_requires_the_artifact_error_path(zipdma_profile):
    no_injection = _artifact(zipdma_profile, error_injection=False)
    config = _config(BASE_CONFIG, dma_error_injection=True)
    plan = _zipdma_plan(config, zipdma_profile, no_injection)
    assert plan['error_injection']['requested'] is True
    assert plan['error_injection']['mode'] == 'host_drive_response_error'
    assert plan['error_injection']['available'] == 'absent'
    _refusal('error-injection-absent',
             lambda: validate_transfer_plan(plan, zipdma_profile, no_injection))

    declared = _zipdma_plan(config, zipdma_profile, _artifact(zipdma_profile))
    report = validate_transfer_plan(declared, zipdma_profile,
                                    _artifact(zipdma_profile))
    assert 'host-error-injection-absent' in _host_codes(report)
    _refusal('error-injection-invalid', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_error_injection='sometimes'),
        zipdma_profile, _artifact(zipdma_profile)))


# ---------------------------------------------------------------------------
# route shape and evidence
# ---------------------------------------------------------------------------
def test_route_target_describes_fixed_fifo_pushes(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(FIFO_CONFIG), zipdma_profile, zipdma_artifact)
    windows = [{'name': 'pulp_timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'pulp_spi_txfifo', 'index': 1, **SPI_WINDOW}]
    route = dma_route_target(plan, windows)
    assert route['kind'] == 'fifo'
    assert route['direction'] == 'write'
    assert route['target_index'] == 1
    assert route['target_name'] == 'pulp_spi_txfifo'
    assert route['target_window'] == SPI_WINDOW
    assert route['register'] == {'name': 'TXFIFO', 'offset': 24,
                                 'access': 'wo', 'width': 32,
                                 'side_effect': 'write_pushes_fifo'}
    assert route['offset_bounds'] == {'first': 24, 'last': 24, 'repeat': 8}
    assert route['byte_bounds'] == {'first': 0x20002018, 'last': 0x20002018}
    assert route['master_word_bounds'] == {'first': 0x20002018 >> 2,
                                           'last': 0x20002018 >> 2}
    assert route['beat_count'] == 8
    evidence = route['expected_evidence']
    assert evidence['kind'] == 'fifo_level'
    assert evidence['register'] == 'STATUS'
    assert evidence['bit_range'] == {'low': 24, 'high': 28}
    assert evidence['depth'] == 10
    assert evidence['source'].startswith('third_party/soc-pulp-apb-spi/')
    assert route['reachable']['device_max_byte_address'] == 0x3FFFFFFF
    assert route['reachable']['fits'] is True
    assert route['completion_claimed'] is False
    assert route['executed'] is False
    # The planner never claims completion; it names the entry that executes the
    # declared shape, and that entry's own run is the only completion witness.
    assert route['host_support']['status'] == 'executed_by_inprocess_f6_entry'
    assert route['host_support']['implemented_by']
    assert route['host_support']['completion_claimed'] is False


def test_route_target_refuses_the_current_host_windows(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(FIFO_CONFIG), zipdma_profile, zipdma_artifact)
    # The current host's declared_windows shape carries one target window only;
    # the declared route targets index 1, so it cannot be resolved there.
    error = _refusal('dma-route-target-not-declared', lambda: dma_route_target(
        plan, {'ip_base': TIMER_WINDOW['base'], 'ip_size': TIMER_WINDOW['size']}))
    assert error.detail == 'index:1'


def test_route_requires_fifo_evidence(zipdma_profile, zipdma_artifact):
    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route.pop('evidence')
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('fifo-route-not-declared',
                     lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))
    assert error.reason == 'fifo-route-not-declared'


def test_route_requires_a_target_window(zipdma_profile, zipdma_artifact):
    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route.pop('target_window')
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    _refusal('fifo-route-not-declared',
             lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))


def test_route_address_mode_matches_increment(zipdma_profile, zipdma_artifact):
    incrementing_fixed = _zipdma_plan(
        _config(FIFO_CONFIG, dma_increment_destination=True),
        zipdma_profile, zipdma_artifact)
    _refusal('fifo-route-address-mode-mismatch',
             lambda: validate_transfer_plan(incrementing_fixed, zipdma_profile,
                                            zipdma_artifact))

    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['address_mode'] = 'aperture'
    config['dma_route'] = route
    fixed_aperture = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    _refusal('fifo-route-address-mode-mismatch',
             lambda: validate_transfer_plan(fixed_aperture, zipdma_profile,
                                            zipdma_artifact))


def test_zipdma_route_above_one_gib_is_unreachable(zipdma_profile, zipdma_artifact):
    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['target_window'] = SPI_SOC_WINDOW
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('dma-route-target-unreachable',
                     lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))
    assert error.detail == 'zipdma:0x40002018>0x3fffffff'
    windows = [{'name': 'pulp_timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'pulp_spi_txfifo', 'index': 1, **SPI_SOC_WINDOW}]
    _refusal('dma-route-target-unreachable',
             lambda: dma_route_target(plan, windows))


def test_wbdmac_can_declare_the_soc_spi_window(wbdmac_profile, wbdmac_artifact):
    """wbdmac stores byte-address bits [31:2], so 0x40002000 is reachable."""
    config = _config(WBDMAC_CONFIG, dma_increment_destination=False)
    config['dma_route'] = {
        'kind': 'fifo', 'direction': 'write', 'target_name': 'pulp_spi_txfifo',
        'target_index': 1,
        'target_profile': 'configs/peripherals/pulp_spi/component_profile.json',
        'target_window': SPI_SOC_WINDOW, 'register': 'TXFIFO', 'offset': 24,
        'address_mode': 'fixed',
        'evidence': {'kind': 'fifo_level', 'register': 'STATUS', 'offset': 0,
                     'field': 'tx_fifo_level', 'bits': [28, 24], 'depth': 10},
    }
    plan = _wbdmac_plan(config, wbdmac_profile, wbdmac_artifact)
    assert plan['start']['word'] == 0x1FED0004
    report = validate_transfer_plan(plan, wbdmac_profile, wbdmac_artifact)
    assert report['status'] == 'declaration_valid'
    assert 'host-dma-target-route-absent' in _host_codes(report)
    windows = [{'name': 'pulp_timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'pulp_spi_txfifo', 'index': 1, **SPI_SOC_WINDOW}]
    route = dma_route_target(plan, windows)
    assert route['byte_bounds'] == {'first': 0x40002018, 'last': 0x40002018}
    assert route['reachable']['device_max_byte_address'] == 0xFFFFFFFF


def test_route_direction_matches_register_access(zipdma_profile, zipdma_artifact):
    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['direction'] = 'read'
    config['dma_route'] = route
    _refusal('dma-route-direction-unsupported',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


# ---------------------------------------------------------------------------
# the read route: a fixed register source and a RAM destination block
# ---------------------------------------------------------------------------
def test_read_route_plans_a_fixed_register_source(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(READ_CONFIG), zipdma_profile, zipdma_artifact)
    # The register is the *source*, so the source increment is the one disabled:
    # ZipDMA control bit 18 makes every read beat present the same address, and
    # the destination (the RAM block) increments.
    assert plan['increment_source'] is False
    assert plan['increment_destination'] is True
    assert plan['start']['word'] == 0x00040000
    assert plan['route']['direction'] == 'read'
    assert plan['route']['address_mode'] == 'fixed'
    assert plan['route']['kind'] == 'target_window'
    assert plan['route']['register'] == {'name': 'PRESCALER', 'offset': 0,
                                         'access': 'rw', 'width': 32,
                                         'side_effect': 'none'}
    assert plan['route']['evidence']['kind'] == 'register_readback'
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert 'host-dma-target-route-absent' in _host_codes(report)
    assert report['route'] == {'kind': 'target_window', 'direction': 'read',
                               'address_mode': 'fixed', 'beats': 4,
                               'first_offset': 0, 'last_offset': 0,
                               # The wire protocol of the routed target, from its
                               # own profile endpoint: the route assumes none.
                               'protocol': 'apb3'}
    windows = [{'name': 'timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'i2c', 'index': 1, **I2C_READ_WINDOW}]
    route = dma_route_target(plan, windows)
    assert route['direction'] == 'read'
    assert route['increment'] is False
    assert route['offset_bounds'] == {'first': 0, 'last': 0, 'repeat': 4}
    assert route['byte_bounds'] == {'first': 0x20001000, 'last': 0x20001000}
    assert route['target_window'] == I2C_READ_WINDOW
    assert route['expected_evidence']['kind'] == 'register_readback'
    # The read route's evidence is the returned word, not a changed field.
    expectation = route['expected_evidence']['expectation']
    assert 'master read must return that same word' in expectation
    assert 'change from its pre-transfer value' not in expectation
    assert route['completion_claimed'] is False
    assert route['executed'] is False


def test_read_route_refuses_unreadable_and_undeclared_registers(zipdma_profile,
                                                              zipdma_artifact):
    # A write-only register cannot be a read source.  The FIFO declaration names
    # TXFIFO (wo) and disables the destination increment; making it a read route
    # is refused while the route is normalized, before any plan exists.
    config = _config(FIFO_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['direction'] = 'read'
    route['address_mode'] = 'fixed'
    config['dma_route'] = route
    config['dma_increment_source'] = False
    config['dma_increment_destination'] = True
    error = _refusal('dma-route-direction-unsupported',
                     lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))
    assert error.detail == 'read-from-write-only'

    # A register the target profile does not declare is refused by name.
    config = _config(READ_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['register'] = 'NOPE'
    route.pop('offset')
    config['dma_route'] = route
    error = _refusal('dma-target-profile-mismatch',
                     lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))
    assert error.detail == 'register:NOPE'

    # A fixed route whose source would increment is not the declared shape: the
    # validation refuses it instead of silently serving an aperture read.
    config = _config(READ_CONFIG, dma_increment_source=True)
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    assert plan['start']['word'] == 0
    error = _refusal('fifo-route-address-mode-mismatch',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    assert error.detail == 'fixed-but-incrementing'


def test_route_window_bounds(zipdma_profile, zipdma_artifact):
    config = _config(BASE_CONFIG)
    config['dma_route'] = {
        'kind': 'target_window', 'direction': 'write', 'target_name': 'aperture',
        'target_index': 0, 'target_window': {'base': 0x20000000, 'size': 4096},
        'offset': 4088, 'address_mode': 'aperture',
        'evidence': {'kind': 'register_readback', 'register': 'STATUS', 'offset': 0},
    }
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    _refusal('dma-route-window-bounds',
             lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))
    windows = [{'name': 'aperture', 'index': 0, 'base': 0x20000000, 'size': 4096}]
    _refusal('dma-route-window-bounds', lambda: dma_route_target(plan, windows))


def test_route_target_index_and_name_must_agree(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(FIFO_CONFIG), zipdma_profile, zipdma_artifact)
    windows = [{'name': 'pulp_timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'other_fifo', 'index': 1, **SPI_WINDOW}]
    _refusal('dma-route-target-mismatch', lambda: dma_route_target(plan, windows))


def test_route_absent_is_refused(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)
    _refusal('dma-route-not-declared',
             lambda: dma_route_target(plan, [{'name': 'target', 'index': 0,
                                              **TIMER_WINDOW}]))


# ---------------------------------------------------------------------------
# artifacts and device/profile refusals
# ---------------------------------------------------------------------------
def test_artifact_shapes_are_normalized_or_refused(zipdma_profile, zipdma_artifact):
    base = _config(BASE_CONFIG)
    bare = dma_profile_edge_contract(dict(zipdma_profile.capabilities))
    plan = dma_transfer_declaration(base, zipdma_profile, bare, base_dir=ROOT)
    assert plan['artifact']['kind'] == 'edge_contract'
    assert validate_transfer_plan(plan, zipdma_profile, bare)['status'] == 'declaration_valid'

    capability = json.loads(ZIPDMA_CAPABILITY.read_text())
    plan = dma_transfer_declaration(base, zipdma_profile, capability, base_dir=ROOT)
    assert plan['artifact']['kind'] == 'test_capability_only'
    assert plan['artifact']['edge_present'] is False
    assert validate_transfer_plan(plan, zipdma_profile, capability)['host_supported'] is True

    _refusal('dma-artifact-invalid', lambda: dma_transfer_declaration(
        base, zipdma_profile, {'name': 'not-an-artifact'}, base_dir=ROOT))
    _refusal('dma-artifact-invalid', lambda: dma_transfer_declaration(
        base, zipdma_profile,
        _artifact(zipdma_profile, same_edge_accept_and_complete=True),
        base_dir=ROOT))


def test_plan_and_artifact_must_be_validated_together(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)
    _refusal('dma-plan-artifact-mismatch',
             lambda: validate_transfer_plan(plan, zipdma_profile, None))


def test_plan_device_must_match_the_profile(zipdma_profile, wbdmac_profile,
                                            zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)
    error = _refusal('dma-plan-device-mismatch',
                     lambda: validate_transfer_plan(plan, wbdmac_profile, zipdma_artifact))
    assert error.detail == 'family'


def test_unknown_device_is_refused_by_name():
    profile = {'component_id': 'not-a-dma',
               'source': {'top_module': 'otherdma', 'revision': 'git:' + '0' * 40,
                          'files': []},
               'capabilities': {}, 'address': None, 'interrupts': []}
    _refusal('dma-device-unsupported', lambda: dma_transfer_declaration(
        _config(BASE_CONFIG), profile, None, base_dir=ROOT))


def test_profile_source_drift_is_refused_by_name():
    document = json.loads(ZIPDMA_PROFILE.read_text())
    document['source']['revision'] = 'git:' + '0' * 40
    error = _refusal('dma-profile-source-drift',
                     lambda: dma_transfer_declaration(
                         _config(BASE_CONFIG), document, None, base_dir=ROOT))
    assert error.detail == 'zipdma:revision'

    document = json.loads(ZIPDMA_PROFILE.read_text())
    document['capabilities']['master_byte_enable'] = False
    error = _refusal('dma-profile-source-drift',
                     lambda: dma_transfer_declaration(
                         _config(BASE_CONFIG), document, None, base_dir=ROOT))
    assert error.detail == 'zipdma:master_byte_enable'


# ---------------------------------------------------------------------------
# validation re-checks a plan instead of trusting it
# ---------------------------------------------------------------------------
def test_validate_refuses_tampered_plans(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)

    tampered = copy.deepcopy(plan)
    tampered['block_words'] = 65
    _refusal('block-beyond-declared-bound',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))

    tampered = copy.deepcopy(plan)
    tampered['start']['word'] = 0x00400000
    _refusal('start-word-mismatch',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))

    tampered = copy.deepcopy(plan)
    tampered['length_value'] = 8
    _refusal('dma-plan-length-mismatch',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))

    tampered = copy.deepcopy(plan)
    tampered['max_outstanding'] = 2
    _refusal('outstanding-beyond-one',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))

    two_byte = _zipdma_plan(_config(BASE_CONFIG, dma_transfer_size_bytes=2),
                            zipdma_profile, zipdma_artifact)
    tampered = copy.deepcopy(two_byte)
    tampered['master_byte_enable']['size_code'] = 0
    _refusal('master-byte-enable-invalid',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))


def test_validate_rechecks_non_incrementing_start(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG, dma_increment_destination=False),
                        zipdma_profile, zipdma_artifact)
    assert plan['start']['word'] == 0x00400000
    tampered = copy.deepcopy(plan)
    tampered['start']['word'] = 0
    _refusal('non-incrementing-transfer-not-encoded-by-start-word',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))


def test_declaration_and_host_facts_are_tagged_separately(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(LEN8_CONFIG), zipdma_profile, zipdma_artifact)
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert all(row['kind'] == 'declaration' for row in report['declaration_facts'])
    assert all(row['kind'] == 'host_only' for row in report['host_limits'])
    assert len(report['host_limits']) == 1
    assert report['host_limits'][0]['host'] == 'inprocess_f6_host'
    assert report['host_limits'][0]['where']


# ---------------------------------------------------------------------------
# compatibility of the historical inline keys
# ---------------------------------------------------------------------------
def test_inline_keys_keep_the_existing_names(zipdma_profile, zipdma_artifact,
                                             wbdmac_profile, wbdmac_artifact):
    plan = _wbdmac_plan(_config(WBDMAC_CONFIG, dma_irq_pulse_ticks=4),
                        wbdmac_profile, wbdmac_artifact)
    assert plan['irq_pulse_ticks'] == 4
    assert plan['irq_pulse_ticks_source'] == 'scenario'
    assert plan['block_words_declared_by'] == 'behavior'
    assert plan['block_words_declaration'].startswith('behavior:')

    _refusal('block-words-invalid', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_block_words='8'), zipdma_profile, zipdma_artifact))
    _refusal('irq-pulse-ticks-invalid', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_irq_pulse_ticks=0),
        zipdma_profile, zipdma_artifact))


def test_master_byte_enable_and_size_must_agree(zipdma_profile, zipdma_artifact):
    _refusal('master-byte-enable-conflict', lambda: _zipdma_plan(
        _config(BASE_CONFIG, dma_transfer_size_bytes=2, dma_master_byte_enable=3),
        zipdma_profile, zipdma_artifact))


def test_route_without_evidence_is_refused_for_a_generic_target(zipdma_profile,
                                                                zipdma_artifact):
    config = _config(BASE_CONFIG)
    config['dma_route'] = {
        'kind': 'target_window', 'direction': 'write', 'target_name': 'window',
        'target_index': 0, 'target_window': {'base': 0x20000000, 'size': 4096},
        'offset': 8,
    }
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    _refusal('dma-route-evidence-absent',
             lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))


def test_route_target_describes_an_incrementing_aperture(zipdma_profile, zipdma_artifact):
    config = _config(BASE_CONFIG)
    config['dma_route'] = {
        'kind': 'target_window', 'direction': 'write', 'target_name': 'window',
        'target_index': 0, 'target_window': {'base': 0x20000000, 'size': 4096},
        'offset': 8, 'address_mode': 'aperture',
        'evidence': {'kind': 'register_readback', 'register': 'STATUS',
                     'offset': 0},
    }
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    assert validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)['status'] \
        == 'declaration_valid'
    windows = [{'name': 'window', 'index': 0, 'base': 0x20000000, 'size': 4096}]
    route = dma_route_target(plan, windows)
    assert route['address_mode'] == 'aperture'
    assert route['increment'] is True
    assert route['beat_count'] == 4
    assert route['offset_bounds'] == {'first': 8, 'last': 20, 'repeat': 1}
    assert route['byte_bounds'] == {'first': 0x20000008, 'last': 0x20000014}
    assert route['expected_evidence']['kind'] == 'register_readback'
    assert route['completion_claimed'] is False


def test_validate_rechecks_irq_facts(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(BASE_CONFIG), zipdma_profile, zipdma_artifact)
    tampered = copy.deepcopy(plan)
    tampered['irq_trigger'] = 'pulse'
    _refusal('dma-plan-irq-mismatch',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))
    tampered = copy.deepcopy(plan)
    tampered['irq_clear']['value'] = 0
    _refusal('dma-plan-irq-mismatch',
             lambda: validate_transfer_plan(tampered, zipdma_profile, zipdma_artifact))


# ---------------------------------------------------------------------------
# the FIFO read route: a port the pinned RTL pops on the read itself
# ---------------------------------------------------------------------------
FIFOREAD_CONFIG = ROOT / ('configs/scenarios/'
                          'inprocess-obi-apb-ibex-spi-dma-fiforead-f1f6.json')
APERTURE_CONFIG = ROOT / ('configs/scenarios/'
                          'inprocess-obi-apb-ibex-spi-dma-aperture-f1f6.json')
ERROR_CONFIG = ROOT / ('configs/scenarios/'
                       'inprocess-obi-apb-ibex-i2c-dma-read-error-f1f6.json')
SPI_FIFO_WINDOWS = [{'name': 'timer', 'index': 0, **TIMER_WINDOW},
                    {'name': 'pulp_spi_rxfifo', 'index': 1, **SPI_WINDOW}]


def test_fifo_read_route_declares_a_popping_port(zipdma_profile, zipdma_artifact):
    """The RX FIFO read: the routed port's own RTL pops on the read access."""
    plan = _zipdma_plan(_config(FIFOREAD_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['increment_source'] is False
    assert plan['increment_destination'] is True
    assert plan['start']['word'] == 0x00040000
    route = plan['route']
    assert route['kind'] == 'fifo'
    assert route['direction'] == 'read'
    assert route['address_mode'] == 'fixed'
    # The pop is the register's declared side effect, read from the profile.
    assert route['register']['name'] == 'RXFIFO'
    assert route['register']['access'] == 'ro'
    assert route['register']['side_effect'] == 'read_pops_fifo'
    evidence = route['evidence']
    assert evidence['kind'] == 'fifo_level'
    assert evidence['register'] == 'STATUS'
    assert evidence['bits'] == [20, 16]
    assert evidence['depth'] == 10
    assert evidence['expected_word'] == 0xFFFFFFFF
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert report['route'] == {'kind': 'fifo', 'direction': 'read',
                               'address_mode': 'fixed', 'beats': 8,
                               'first_offset': 32, 'last_offset': 32,
                               'protocol': 'apb3'}
    described = dma_route_target(plan, SPI_FIFO_WINDOWS)
    assert described['fifo_pop'] is True
    assert described['level_bounds'] == {'before': 8, 'after': 0, 'drop': 8}
    assert described['expected_word'] == 0xFFFFFFFF
    assert described['beat_count'] == 8
    assert described['expected_evidence']['level']['before'] == 8


def test_fifo_read_of_a_non_popping_port_is_refused(zipdma_profile, zipdma_artifact):
    """A readable register without the declared pop is not a FIFO read."""
    config = _config(FIFOREAD_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['register'] = 'STATUS'
    route['offset'] = 0
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('fifo-read-not-popping',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    # The port is readable, but its declared side effect is not a pop.
    assert error.detail == 'STATUS:write_starts_transfer'


def test_fifo_read_of_a_write_only_port_is_refused(zipdma_profile, zipdma_artifact):
    """The TX FIFO has no read arm at all: its access is write-only."""
    config = _config(FIFOREAD_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['register'] = 'TXFIFO'
    route['offset'] = 24
    config['dma_route'] = route
    _refusal('dma-route-direction-unsupported',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


def test_fifo_read_beyond_the_declared_depth_is_refused(zipdma_profile, zipdma_artifact):
    config = _config(FIFOREAD_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['evidence']['depth'] = 4
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('fifo-read-beyond-declared-depth',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    assert error.detail == '4<8'


def test_fifo_read_requires_level_evidence(zipdma_profile, zipdma_artifact):
    config = _config(FIFOREAD_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['evidence']['kind'] = 'register_readback'
    route['evidence'].pop('expected_word', None)
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('fifo-read-not-declared',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    assert error.detail == 'fifo-level-evidence'
    _refusal('fifo-read-not-declared',
             lambda: dma_route_target(plan, SPI_FIFO_WINDOWS))


def test_expected_word_is_only_a_fifo_fact(zipdma_profile, zipdma_artifact):
    config = _config(READ_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['evidence']['expected_word'] = 0x5A5A
    config['dma_route'] = route
    _refusal('dma-route-evidence-invalid',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


# ---------------------------------------------------------------------------
# the aperture read route: consecutive readable registers
# ---------------------------------------------------------------------------
def test_aperture_read_route_declares_every_register(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(APERTURE_CONFIG), zipdma_profile, zipdma_artifact)
    assert plan['increment_source'] is True
    assert plan['increment_destination'] is True
    assert plan['start']['word'] == 0
    route = plan['route']
    assert route['address_mode'] == 'aperture'
    assert route['direction'] == 'read'
    assert route['register']['name'] == 'CLKDIV'
    assert route['evidence']['words'] == 4
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['route'] == {'kind': 'target_window', 'direction': 'read',
                               'address_mode': 'aperture', 'beats': 4,
                               'first_offset': 4, 'last_offset': 16,
                               'protocol': 'apb3'}
    described = dma_route_target(
        plan, [{'name': 'timer', 'index': 0, **TIMER_WINDOW},
               {'name': 'pulp_spi_aperture', 'index': 1, **SPI_WINDOW}])
    assert described['aperture_words'] == 4
    assert described['offset_bounds'] == {'first': 4, 'last': 16, 'repeat': 1}
    assert described['byte_bounds'] == {'first': 0x20002004, 'last': 0x20002010}
    # Each declared word is a readable register of the target's own map.
    rows = described['expected_evidence']['aperture']
    assert [row['name'] for row in rows] == ['CLKDIV', 'SPICMD', 'SPIADR', 'SPILEN']


def test_aperture_read_words_must_equal_the_routed_beats(zipdma_profile,
                                                         zipdma_artifact):
    config = _config(APERTURE_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['evidence']['words'] = 2
    config['dma_route'] = route
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    _refusal('aperture-read-words-mismatch',
             lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))


def test_aperture_read_over_a_write_only_register_is_refused(zipdma_profile,
                                                             zipdma_artifact):
    """Every offset of the declared aperture has to be readable."""
    config = _config(APERTURE_CONFIG)
    route = copy.deepcopy(config['dma_route'])
    route['register'] = 'SPIDUM'
    route['offset'] = 20
    route['evidence']['register'] = 'SPIDUM'
    route['evidence']['offset'] = 20
    config['dma_route'] = route
    error = _refusal('dma-route-evidence-absent',
                     lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))
    assert error.detail == 'aperture-not-readable:0x18'


# ---------------------------------------------------------------------------
# the declared error injection
# ---------------------------------------------------------------------------
def test_error_injection_declares_a_routed_beat(zipdma_profile, zipdma_artifact):
    plan = _zipdma_plan(_config(ERROR_CONFIG), zipdma_profile, zipdma_artifact)
    injection = plan['error_injection']
    assert injection['requested'] is True
    assert injection['mode'] == 'host_drive_response_error'
    assert injection['kind'] == 'host_injected_master_response'
    assert injection['beat_index'] == 1
    assert injection['signal'] == 'mwb_err'
    assert injection['device_error_port'] is True
    assert injection['device_err_status_bit'] == 30
    assert injection['aborts_transfer'] is True
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['status'] == 'declaration_valid'
    assert 'host-error-injection-absent' in _host_codes(report)


def test_error_injection_beyond_the_block_is_refused(zipdma_profile, zipdma_artifact):
    config = _config(ERROR_CONFIG)
    config['dma_error_injection'] = {'beat_index': 4}
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('error-injection-beyond-block',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    assert error.detail == '4>=4'


def test_error_injection_direction_must_be_the_routes(zipdma_profile, zipdma_artifact):
    config = _config(ERROR_CONFIG)
    config['dma_error_injection'] = {'beat_index': 0, 'direction': 'write'}
    plan = _zipdma_plan(config, zipdma_profile, zipdma_artifact)
    error = _refusal('error-injection-direction-mismatch',
                     lambda: validate_transfer_plan(plan, zipdma_profile,
                                                    zipdma_artifact))
    assert error.detail == 'write!=read'


def test_error_injection_rejects_an_unknown_mode(zipdma_profile, zipdma_artifact):
    config = _config(ERROR_CONFIG)
    config['dma_error_injection'] = {'beat_index': 0, 'mode': 'target_pslverr'}
    _refusal('error-injection-invalid',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


# ---------------------------------------------------------------------------
# the two named refusals: multi-outstanding and a second channel/width
# ---------------------------------------------------------------------------
def test_multi_outstanding_is_refused_by_name(zipdma_profile, zipdma_artifact):
    """One master port and one response: the device declares one outstanding."""
    from myfuzz.composition.dma_transfer import DEVICE_FACTS
    fact = DEVICE_FACTS['zipdma']
    assert fact['max_outstanding'] == 1
    assert fact['master_has_error'] is True
    assert 'zipdma_ctrl.v:116-117' in fact['status_default']['evidence']
    config = _config(FIFOREAD_CONFIG, dma_max_outstanding=2)
    _refusal('outstanding-beyond-one',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))


def test_a_second_channel_or_beat_width_is_not_declarable(zipdma_profile,
                                                          zipdma_artifact):
    """The pinned device has one CONTROL/SOURCE/DESTINATION/LENGTH set only."""
    from myfuzz.composition.dma_transfer import DEVICE_FACTS
    fact = DEVICE_FACTS['zipdma']
    # One register set per transfer, no per-channel CSR pair.
    assert [row[0] for row in fact['registers']] == [
        'CONTROL_STATUS', 'SOURCE', 'DESTINATION', 'LENGTH']
    # A beat width is encoded in two bits with no 8-byte code at all.
    assert fact['size_codes'] == {1: 3, 2: 2, 4: 0}
    config = _config(FIFOREAD_CONFIG, dma_transfer_size_bytes=8)
    _refusal('master-byte-enable-unsupported',
             lambda: _zipdma_plan(config, zipdma_profile, zipdma_artifact))
    plan = _zipdma_plan(_config(FIFOREAD_CONFIG), zipdma_profile, zipdma_artifact)
    assert 'channel' not in plan
    assert plan['device']['max_outstanding'] == 1
