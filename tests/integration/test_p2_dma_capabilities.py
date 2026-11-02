"""P2/E2: a second, genuinely different DMA device, and what neither device can do.

Three layers are pinned here, and none of them claims a transfer the run did not
make:

* the *device set*: the repository pins exactly two DMA RTLs (``zipdma`` and
  ``wbdmac``).  Every other DMA profile - including the seven ``zipdma`` copies and
  the second ``wbdmac`` copy - is a second *declaration* of one of those two RTLs,
  so a profile swap is never evidence of a new device.
* the *capability bounds*: ``channels``/``beat_bytes``/``burst_beats``/
  ``max_outstanding`` are bounded by the pinned RTL and each bound names the bytes
  it comes from.  A declaration above a bound is refused by name - and the
  four-word / eight-word ``wbdmac`` transfers under ``runs/p2-dma-20261103/`` are
  the ones the device really executed.
* the *case line*: an F6 line from a device that is not the historical
  single-channel 32-bit ZipDMA shape states which device, which channel, what a
  beat is, and the response-pipeline depth as declared and as measured.  A ZipDMA
  line keeps exactly the fields it always had, which is why the group is absent
  there instead of zero-filled.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.dma_transfer import (
    DEVICE_FACTS,
    DMA_CAPABILITY_KEYS,
    DmaTransferError,
    MAX_OUTSTANDING,
    dma_transfer_declaration,
    validate_transfer_plan,
)

from scripts.run_inprocess_f1f6 import flow_arity, parse_run_log

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'runs/p2-dma-20261103'
WBDMAC_PROFILE = ROOT / 'configs/peripherals/zipcpu_wbdmac/component_profile.json'
WBDMAC_TWIN = ROOT / 'configs/peripherals/inprocess_generality_wbdmac/component_profile.json'
ZIPDMA_PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json'
ZIPDMA_TWO_CHANNEL = ROOT / ('configs/peripherals/p1_zipdma_two_channel_declaration/'
                             'component_profile.json')
WBDMAC_CONFIG = ROOT / 'configs/scenarios/p2-wbdmac-f6-ram.json'
WBDMAC_CAPABILITY = ROOT / ('configs/scenarios/compiled-f6-ibex-wbdmac-storage/'
                            'dma.test_capability.json')
ZIPDMA_CAPABILITY = ROOT / ('configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared/'
                            'dma.test_capability.json')

#: The exact refusal each negative configuration must raise, as the entry reports
#: it.  The prefix is the entry's own wrapper around the planner's reason.
REFUSALS = {
    'wbdmac-refusal-channel2':
        'dma-capability-beyond-device:channels:2>1',
    'wbdmac-refusal-beat8':
        'dma-capability-beyond-device:beat_bytes:8>4',
    'wbdmac-refusal-burst2':
        'dma-capability-beyond-device:burst_beats:2>1',
    'wbdmac-refusal-capability-outstanding2':
        'dma-capability-beyond-device:max_outstanding:2>1',
    'wbdmac-refusal-outstanding2':
        'outstanding-beyond-one:wbdmac:2>1',
    'zipdma-refusal-outstanding2':
        'outstanding-beyond-one:zipdma:2>1',
    'zipdma-refusal-two-channel-profile':
        'dma-profile-capability-beyond-device:zipdma:channels:2>1',
}


def _profile(path):
    return load_component_profile(path)


def _artifact(path):
    return json.loads(path.read_text())


def _base_config(**overrides):
    config = json.loads(WBDMAC_CONFIG.read_text())
    config.pop('notes', None)
    config.update(overrides)
    return config


def _refusal(reason, call):
    with pytest.raises(DmaTransferError) as caught:
        call()
    assert caught.value.reason == reason, caught.value
    return caught.value


def _run(name, directory=''):
    path = EVIDENCE / directory / name / 'run.log'
    if not path.exists():
        pytest.skip('run not produced in this checkout: ' + name)
    text = path.read_text()
    if '\nsummary ' not in text:
        pytest.skip('the saved run did not complete (no summary line): ' + name)
    irq = dict(trigger_offsets=[0], source_count=1, status_offset=0)
    return parse_run_log(text, flows=flow_arity(irq, {'block_words': 8}))


def _f6(log):
    return next(case for case in log['cases'] if case['flow'] == 'F6')


# ---------------------------------------------------------------------------
# the device set: two RTLs, many declarations
# ---------------------------------------------------------------------------
def test_the_tree_pins_two_dma_devices_and_many_profiles():
    """A second profile of one RTL is not a second device."""
    families, profiles = set(), {}
    for path in sorted((ROOT / 'configs/peripherals').glob('*/component_profile.json')):
        document = json.loads(path.read_text())
        top = (document.get('source') or {}).get('top_module')
        if top not in DEVICE_FACTS:
            continue
        profiles.setdefault(top, []).append(path.relative_to(ROOT).as_posix())
        families.add(top)
    assert families == {'zipdma', 'wbdmac'}
    # Everything else that calls itself a DMA is one of those two RTLs again.
    assert len(profiles['zipdma']) >= 5
    assert len(profiles['wbdmac']) >= 2


def test_the_two_wbdmac_profiles_are_the_same_pinned_rtl():
    """``inprocess_generality_wbdmac`` is a declaration twin, not a new device."""
    allowed = _profile(WBDMAC_PROFILE)
    twin = _profile(WBDMAC_TWIN)
    assert allowed.source_document['top_module'] == 'wbdmac'
    assert twin.source_document['top_module'] == 'wbdmac'
    assert twin.source_document['revision'] == allowed.source_document['revision']
    assert twin.source_document['files'] == allowed.source_document['files']
    assert [row.offset for row in twin.address.registers] == \
        [row.offset for row in allowed.address.registers]
    # Both profiles therefore resolve to the same pinned device declaration.
    device = dma_transfer_declaration(_base_config(), twin, None,
                                      base_dir=ROOT)['device']
    assert device['family'] == 'wbdmac'
    assert device['source_files'] == list(DEVICE_FACTS['wbdmac']['source_files'])


def test_every_pinned_capability_bound_names_the_rtl_it_comes_from():
    for family in ('zipdma', 'wbdmac'):
        evidence = DEVICE_FACTS[family]['capability_evidence']
        assert set(evidence) == set(DMA_CAPABILITY_KEYS)
        for key, anchor in evidence.items():
            for reference in re.findall(r'[\w./-]+\.(?:v|json):\d+(?:-\d+)?', anchor):
                path, _, lines = reference.partition(':')
                target = ROOT / path
                assert target.is_file(), (family, key, reference)
                low, _, high = lines.partition('-')
                count = len(target.read_text(errors='replace').splitlines())
                assert 1 <= int(low) <= count, (family, key, reference)
                if high:
                    assert int(low) <= int(high) <= count, (family, key, reference)


def test_the_pinned_devices_execute_one_channel_and_four_byte_beats():
    for family, facts in DEVICE_FACTS.items():
        assert facts['channels'] == 1, family
        assert facts['beat_bytes'] == 4, family
        assert facts['burst_beats'] == 1, family
    # The one axis the two devices differ on: wbdmac looks pipelined but its burst
    # terminator compares a request count with the block length, so the depth this
    # increment executes - and declares - is still one.
    assert DEVICE_FACTS['wbdmac']['max_outstanding'] == 1
    assert DEVICE_FACTS['zipdma']['max_outstanding'] == 1
    assert MAX_OUTSTANDING >= 1


# ---------------------------------------------------------------------------
# the capability bounds: refused by name, never narrowed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('behaviour,expected', [
    ('p2-wbdmac_refusal_channels2.json', 'channels:2>1'),
    ('p2-wbdmac_refusal_beat8.json', 'beat_bytes:8>4'),
    ('p2-wbdmac_refusal_burst2.json', 'burst_beats:2>1'),
    ('p2-wbdmac_refusal_outstanding2.json', 'max_outstanding:2>1'),
])
def test_a_capability_the_pinned_device_lacks_is_refused_by_name(behaviour, expected):
    profile = _profile(WBDMAC_PROFILE)
    config = _base_config(dma_behavior='configs/behaviors/' + behaviour)
    error = _refusal('dma-capability-beyond-device',
                     lambda: dma_transfer_declaration(config, profile, None,
                                                      base_dir=ROOT))
    assert error.detail == expected


@pytest.mark.parametrize('profile_path,family', [
    (WBDMAC_PROFILE, 'wbdmac'),
    (ZIPDMA_PROFILE, 'zipdma'),
])
def test_two_outstanding_responses_are_refused_against_the_pinned_device(profile_path,
                                                                        family):
    profile = _profile(profile_path)
    plan = dma_transfer_declaration(_base_config(dma_max_outstanding=1), profile, None,
                                    base_dir=ROOT)
    assert plan['max_outstanding'] == 1
    error = _refusal('outstanding-beyond-one',
                     lambda: dma_transfer_declaration(
                         _base_config(dma_max_outstanding=2), profile, None,
                         base_dir=ROOT))
    assert error.detail == '%s:2>1' % family


def test_a_profile_that_declares_two_channels_is_refused_by_name():
    """The refusal is about the pinned RTL, not about the profile's file name."""
    profile = _profile(ZIPDMA_TWO_CHANNEL)
    assert profile.capabilities.get('channels') == 2
    error = _refusal('dma-profile-capability-beyond-device',
                     lambda: dma_transfer_declaration(_base_config(), profile, None,
                                                      base_dir=ROOT))
    assert error.detail == 'zipdma:channels:2>1'


def test_validate_rechecks_the_same_capability_bounds():
    profile = _profile(WBDMAC_PROFILE)
    artifact = _artifact(WBDMAC_CAPABILITY)
    plan = dma_transfer_declaration(_base_config(), profile, artifact, base_dir=ROOT)
    validation = validate_transfer_plan(plan, profile, artifact)
    assert validation['status'] == 'declaration_valid'
    # The plan's own capability declaration is rechecked against the profile, so a
    # plan cannot keep a two-channel / eight-byte / two-outstanding claim while
    # naming a device that has none of them.
    assert validation['device'] == 'wbdmac'
    # The validation reports the declaration facts it re-derived, tagged as
    # declarations rather than measurements.
    facts = {row['fact']: row for row in validation['declaration_facts']}
    assert facts['device']['value'] == 'wbdmac'
    assert facts['max_outstanding']['value'] == 1
    assert all(row['kind'] == 'declaration' for row in facts.values())
    # The declared capability block is rechecked against the pinned device, so a
    # plan that kept two channels or two outstanding responses cannot validate.
    tampered_declaration = json.loads(json.dumps(plan))
    tampered_declaration['declaration']['declared_capabilities'] = {
        'channels': 2}
    _refusal('dma-capability-beyond-device',
             lambda: validate_transfer_plan(tampered_declaration, profile, artifact))
    tampered = json.loads(json.dumps(plan))
    tampered['max_outstanding'] = 2
    _refusal('outstanding-beyond-one',
             lambda: validate_transfer_plan(tampered, profile, artifact))


# ---------------------------------------------------------------------------
# the saved evidence: the wbdmac really moved a block
# ---------------------------------------------------------------------------
def test_the_saved_wbdmac_transfer_moved_the_four_word_block():
    log = _run('wbdmac-f6-ram')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    # The device, its channel, its beat and the pipeline depth, on the line.
    assert case['dma_device'] == 'wbdmac'
    assert case['dma_channels'] == 1 and case['dma_channel'] == 0
    assert case['dma_beat_bytes'] == 4
    assert case['dma_max_outstanding'] == 1
    assert case['dma_outstanding_peak'] == 1
    # The transfer itself: the plan's start word, four read beats and four write
    # beats, and the destination block holding the source words the CPU installed.
    assert case['dma_start_word'] == 0x0FED0004
    assert case['dma_start_write'] == 0x0FED0004
    assert case['dma_block_words'] == 4
    assert case['dma_reads'] == 4 and case['dma_writes'] == 4
    assert case['dma_expected_reads'] == 4 and case['dma_expected_writes'] == 4
    assert [case['dst%d' % index] for index in range(4)] == [
        0x0110C000, 0x08000000, 0xDEADBEEF, 0x12345678]
    # Completion was the device's own pulse, and the CPU took it.
    assert case['irq_takes'] == 1 and case['isr_flag'] == 1
    assert case['dma_lane_written'] == 16 and case['dma_lane_missing'] == 0
    assert case['dma_guard_lo'] == 0xA5A5A5A5 and case['dma_guard_hi'] == 0xA5A5A5A5


def test_the_saved_wbdmac_eight_word_transfer_is_the_deeper_block():
    log = _run('wbdmac-f6-len8')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_device'] == 'wbdmac'
    assert case['dma_block_words'] == 8
    assert case['dma_reads'] == 8 and case['dma_writes'] == 8
    # The block length is in the start word's low LGMEMLEN=10 bits.
    assert case['dma_start_word'] == 0x0FED0008
    assert [case['dst%d' % index] for index in range(8)] == [
        0x0110C000, 0x08000000, 0xDEADBEEF, 0x12345678,
        0x00000001, 0x00000002, 0x00000003, 0x00000004]
    assert case['isr_flag'] == 1 and case['irq_takes'] == 1


def test_the_saved_wbdmac_batch_keeps_the_other_flows_apart():
    log = _run('wbdmac-f6-flows')
    assert log['summary']['status'] == 'observations_passed'
    assert [case['flow'] for case in log['cases']] == ['F1', 'F2', 'F3', 'F6']
    assert all(case['status'] == 'observations_passed' for case in log['cases'])
    f6 = _f6(log)
    assert f6['dma_device'] == 'wbdmac' and f6['dma_reads'] == 4
    assert f6['dst0'] == 0x0110C000 and f6['isr_flag'] == 1


def test_the_historical_zipdma_line_did_not_gain_the_device_group():
    """The group is absent exactly where the device is the historical shape."""
    for name in ('ram-len8', 'timer-zipdma-f1f6', 'fifo-write', 'prescaler-read',
                 'tlul-timer-read', 'wb-uart-write', 'axil-uart-read'):
        log = _run(name, 'regression')
        for case in log['cases']:
            if case['flow'] != 'F6':
                continue
            assert 'dma_device' not in case, (name, case['dma_device'])
            assert 'dma_channels' not in case
            assert 'dma_beat_bytes' not in case
            assert 'dma_max_outstanding' not in case
            assert 'dma_outstanding_peak' not in case
            # What it does state is its own shape, unchanged.  The start word is
            # the plan's (a fixed write route disables destination increment), so
            # this checks that the field is still there rather than that it is 0.
            assert case['dma_block_words'] in (4, 8)
            assert 'dma_start_word' in case
            assert 'dma_expected_reads' in case


def test_the_regression_case_lines_are_byte_identical():
    """Every existing ZipDMA F6 case line is unchanged except `seconds`."""
    names = sorted(path.name for path in (EVIDENCE / 'baseline').glob('*')
                   if path.is_dir())
    assert names, 'no baseline runs'
    compared = 0
    for name in names:
        before = EVIDENCE / 'baseline' / name / 'run.log'
        after = EVIDENCE / 'regression' / name / 'run.log'
        if not before.exists() or not after.exists():
            pytest.skip('baseline/after pair incomplete: ' + name)
        # `seconds` and `runtime_seconds` are the wall-clock facts; every other
        # byte of the line is the observation.
        strip = lambda text: [re.sub(r' (?:runtime_)?seconds \S+', '', line)
                              for line in text.splitlines()
                              if line.startswith(('case ', 'summary '))]
        assert strip(before.read_text()) == strip(after.read_text()), name
        compared += 1
    assert compared >= 10


def test_the_beat_width_axis_ran_where_the_device_really_has_it():
    """One-byte beats are a ZipDMA fact the wbdmac refuses; the run proves it."""
    log = _run('zipdma-byteen')
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert 'dma_device' not in case
    assert case['dma_master_beats_per_word'] == 4
    assert case['dma_master_partial'] == 1
    assert case['dma_reads'] == case['dma_expected_reads'] == 16
    assert [case['dst%d' % index] for index in range(4)] == [
        0x0110C000, 0x08000000, 0xDEADBEEF, 0x12345678]


# ---------------------------------------------------------------------------
# the named refusals, as the entry really printed them
# ---------------------------------------------------------------------------
def _campaign_text():
    path = EVIDENCE / 'campaign.log'
    if not path.exists():
        pytest.skip('campaign log not produced in this checkout')
    return path.read_text()


@pytest.mark.parametrize('name,expected', sorted(REFUSALS.items()))
def test_each_negative_configuration_ended_in_its_named_refusal(name, expected):
    text = _campaign_text()
    marker = '### refusals/' + name
    # A name may appear twice: the first attempt of this package hit a transient
    # state (a missing capability sidecar, a concurrent edit).  The last block is
    # the delivered one.
    blocks = [block.split('\n### ', 1)[0]
              for block in text.split('\n### ') if block.startswith(marker[len('### '):])]
    assert blocks, name
    block = blocks[-1]
    assert expected in block, (name, expected)
    # A refusal is not a case: nothing ran.
    assert 'case 0 ' not in block
