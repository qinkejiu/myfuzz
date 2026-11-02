"""Per-epoch program entry: one declared rule, a real image, explicit refusals.

These are software gates.  The image is decoded and executed by the same pure
RV32I model ``tests/integration/test_compiled_f6_firmware.py`` uses; nothing
here is an RTL run, a native fetch or a pass.
"""
from copy import deepcopy
import json

import pytest

from myfuzz.integration.compiled_f6_firmware import (
    ENTRY_POLICY, ENTRY_SCHEMA_VERSION, F6Firmware, build_f6_firmware,
    declare_program_entry, render_epoch_program)
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
from tests.integration.test_compiled_f6_firmware import candidate, model, words


def contract(slot_count=2):
    return dict(program_contract=dict(schema_version='compiled_F6_program.v1',
        boot_address=0x10080, isr_address=0x1022c, park_address=0x10400,
        slot_base=0x11000, slot_count=slot_count, source_address=0x22804,
        destination_address=0x23808, result_base=0x2480c,
        slot_bytes=256, online_prefix_bytes=128, result_stride=24,
        operand_instruction_offsets=[40, 48, 56, 64],
        initial_image=[], initial_image_sha256=None, instruction_source_id='cpu.image'),
        control=dict(base=0x40000800), dma=dict(csr=dict(
            offsets=dict(control=0, length=4, source=8, destination=12),
            configuration_order=['source', 'destination', 'length', 'control'],
            start_key=0xfed, start_word=0x0fed0004, length_words=4, block_words=4,
            increment_source=True, increment_destination=True,
            source_destination_units='byte_address_shift_right_2',
            master_address_units='word', master_byte_enable=15, status_error_mask=0x40000000)))


def entry(epoch, slot, slot_count=2):
    return declare_program_entry(reset_epoch=epoch, slot=slot, slot_count=slot_count)


def jal_target(word, pc):
    """Decode the JAL immediate independently of the encoder."""
    offset = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) \
        | (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
    if offset & (1 << 20):
        offset -= 1 << 21
    return pc + offset


def last_jump(firmware):
    p = json.loads(firmware._program)
    boot = words(firmware.initial_images[p['boot_address']])
    address = p['boot_address'] + 4*(len(boot) - 1)
    assert boot[-1] & 0x7f == 0x6f and (boot[-1] >> 7) & 31 == 0, 'boot must end in jal x0'
    return jal_target(boot[-1], address)


# --------------------------------------------------------------------------- #
# The declared rule
# --------------------------------------------------------------------------- #

def test_the_first_rendering_is_still_the_original_image_and_declares_no_entry():
    implicit = build_f6_firmware(contract())
    declared = build_f6_firmware(contract(), entry=entry(0, 0))
    assert implicit.entry is None and declared.entry is not None
    assert implicit.initial_images == declared.initial_images
    assert implicit.manifest_sha256 == declared.manifest_sha256
    assert last_jump(implicit) == last_jump(declared) == 0x11000
    # only a declared entry adds a key, so every pinned first-epoch digest stays
    # exactly valid
    assert 'entry' not in implicit.document()
    assert declared.document()['entry'] == declared.entry_document()


@pytest.mark.parametrize('slot_count,epoch,slot', [(2, 1, 1), (3, 1, 1), (3, 1, 2),
                                                   (3, 2, 2), (2, 0, 0)])
def test_the_entry_rule_is_one_jump_to_slot_base_plus_slot_bytes_times_slot(
        slot_count, epoch, slot):
    firmware = build_f6_firmware(contract(slot_count), entry=entry(epoch, slot, slot_count))
    p = json.loads(firmware._program)
    assert last_jump(firmware) == p['slot_base'] + p['slot_bytes']*slot
    assert firmware.entry_document()['entry_address'] == last_jump(firmware)
    assert firmware.entry_document()['policy'] == ENTRY_POLICY
    assert firmware.entry_document()['schema_version'] == ENTRY_SCHEMA_VERSION


def test_only_the_boot_segment_changes_and_every_slot_payload_is_identical():
    p = contract(3)['program_contract']
    first = build_f6_firmware(contract(3), entry=entry(0, 0, 3))
    later = build_f6_firmware(contract(3), entry=entry(1, 2, 3))
    changed = [address for address in first.initial_images
               if first.initial_images[address] != later.initial_images[address]]
    assert changed == [p['boot_address']]
    assert set(first.initial_images) == set(later.initial_images)
    assert len(first.initial_images[p['boot_address']]) == len(later.initial_images[p['boot_address']])
    for address in sorted(set(first.initial_images) - {p['boot_address']}):
        assert first.initial_images[address] == later.initial_images[address]
    for index in range(3):
        assert first.prefix(candidate(), case_index=index) == later.prefix(candidate(), case_index=index)
    assert first.initial_segment_manifest != later.initial_segment_manifest
    assert first.manifest_sha256 != later.manifest_sha256


@pytest.mark.parametrize('slot_count,slot,walk', [(3, 1, 'next'), (3, 2, 'park'),
                                                   (2, 1, 'park')])
def test_a_later_epoch_boot_lands_on_the_declared_slot_and_walks_from_there(
        slot_count, slot, walk):
    c = contract(slot_count); p = c['program_contract']
    firmware = build_f6_firmware(c, entry=entry(1, slot, slot_count))
    entry_address = p['slot_base'] + 256*slot
    # the boot really reaches the declared entry; the CSRs it programs are the
    # same ones the first epoch programs
    pc, _regs, _ram, _stores, _loads, _returns, csrs = model(
        firmware.initial_images, p['boot_address'], stop=(entry_address,))
    assert pc == entry_address
    assert csrs == {0x305: (p['isr_address']-44) | 1, 0x304: 2048, 0x300: 8}
    # and the islands from there walk slot -> next slot -> park, unchanged
    target = (p['park_address'] if walk == 'park'
              else p['slot_base'] + 256*(slot + 1))
    registers = [0]*32
    registers[10] = registers[11] = 1
    pc, *_ = model(firmware.initial_images, entry_address + 128,
                   registers=registers, stop=(target,))
    assert pc == target
    registers[10] = 0                  # a mismatched completion never walks on
    pc, *_ = model(firmware.initial_images, entry_address + 128,
                   registers=registers, stop=(target,), limit=4)
    assert pc == entry_address + 128


# --------------------------------------------------------------------------- #
# Refusals: the rule is a policy, not a special case
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('epoch,slot,slot_count', [
    (0, 1, 2),        # a first epoch that skips slot 0 is not the pinned image
    (1, 0, 2),        # a later epoch never re-enters the pre-reset first slot
    (1, 2, 2),        # outside the arena
    (2, -1, 3),       # negative
    (2, True, 3),     # bool is not a slot
    (2, 1.0, 3),      # float is not a slot
    (-1, 1, 3),       # negative epoch
    (1, 1, 0),        # no arena at all
])
def test_the_declared_entry_rule_refuses_replays_and_impossible_slots(
        epoch, slot, slot_count):
    with pytest.raises(ValueError, match='compiled-F6-firmware-entry'):
        declare_program_entry(reset_epoch=epoch, slot=slot, slot_count=slot_count)


@pytest.mark.parametrize('change', [
    {'slot_count': 3},                       # the contract's arena is authoritative
    {'reset_epoch': 1}, {'slot': 1}, {'policy': 'first_slot'},
    {'schema_version': 'compiled_F6_entry.v2'}, {'extra': 1}, {'slot': None}])
def test_a_drifted_entry_document_is_re_refused_not_trusted(change):
    declared = dict(entry(0, 0), **change)
    with pytest.raises(ValueError, match='compiled-F6-firmware-entry'):
        build_f6_firmware(contract(), entry=declared)


def test_an_entry_container_that_is_not_a_plain_document_is_refused():
    class DerivedDict(dict):
        pass
    with pytest.raises(ValueError, match='compiled-F6-firmware-entry-fields'):
        build_f6_firmware(contract(), entry=DerivedDict(entry(1, 1)))


# --------------------------------------------------------------------------- #
# The per-epoch rendering and its own image pin
# --------------------------------------------------------------------------- #

def test_render_epoch_program_pins_its_own_image_and_keeps_the_pin_enforceable():
    c = contract(3)
    rendered = render_epoch_program(c, reset_epoch=1, slot=2)
    program, pinned = rendered['program'], rendered['contract']
    assert type(program) is F6Firmware
    assert rendered['entry'] == program.entry_document()
    assert rendered['entry']['slot'] == 2 and rendered['entry']['reset_epoch'] == 1
    assert pinned['program_contract']['initial_image_sha256'] == program.manifest_sha256
    assert pinned['program_contract']['initial_image'] == list(program.initial_segment_manifest)
    # the re-declared pin reproduces the rendering and refuses any other one
    again = render_epoch_program(pinned, reset_epoch=1, slot=2)
    assert again['program'].manifest_sha256 == program.manifest_sha256
    drift = deepcopy(pinned)
    drift['program_contract']['initial_image'][0]['sha256'] = '0'*64
    with pytest.raises(ValueError, match='initial-image-drift'):
        build_f6_firmware(drift, entry=entry(1, 2, 3))
    with pytest.raises(ValueError, match='initial-image-drift'):
        # a first-epoch pin cannot silently carry a later epoch's image
        build_f6_firmware(pinned, entry=entry(1, 1, 3))
    # the caller's contract is never mutated
    assert c['program_contract']['initial_image'] == []
    assert c['program_contract']['initial_image_sha256'] is None


def test_the_rendered_entry_document_is_detached_from_the_firmware():
    firmware = build_f6_firmware(contract(3), entry=entry(2, 1, 3))
    document = firmware.entry_document()
    document['slot'] = 99
    document['rule'] = 'changed'
    assert firmware.entry_document()['slot'] == 1
    assert firmware.entry_document()['rule'] == 'boot_jal_target = slot_base + slot_bytes*slot'
    assert firmware.entry == entry(2, 1, 3)
    json.dumps(firmware.document())


def test_the_epoch_prefix_stays_the_canonical_online_fragment():
    firmware = build_f6_firmware(contract(3), entry=entry(1, 2, 3))
    data = firmware.prefix(candidate(), case_index=2)
    validate_instruction_bytes(data)
    assert data == build_f6_firmware(contract(3)).prefix(candidate(), case_index=2)
