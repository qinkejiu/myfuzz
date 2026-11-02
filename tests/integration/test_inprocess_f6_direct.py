"""The minimal F6 path needs only the two component declarations."""
import io
import sys

import pytest

from scripts.run_inprocess_f6 import direct_program, direct_candidate, render_images, online_case_message, online_runner
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
from tests.integration.test_compiled_f6_firmware import contract
from tests.integration.test_compiled_f6_layout import raw


def test_direct_firmware_layout_uses_cpu_boot_and_explicit_ram():
    program, memory, control = direct_program(0x10080, {}, 16)
    assert program['boot_address'] == 0x10080
    assert memory == {'base': 0x10000, 'size': 0x20000}
    assert control == {'base': 0x40000000, 'size': 16}
    assert program['slot_base'] == 0x11000
    assert direct_candidate(bytes.fromhex('0110c00008000000')).words == (1, 2, 3, 4)


def test_direct_firmware_layout_rejects_unmapped_memory_and_overlap():
    with pytest.raises(ValueError, match='RAM'):
        direct_program(0x10080, {'ram_base': 0, 'ram_size': 0x10000}, 16)
    with pytest.raises(ValueError, match='overlap'):
        direct_program(0x10080, {'control_base': 0x10000}, 16)
    with pytest.raises(ValueError, match='duplicate'):
        direct_candidate(bytes(8))


def test_f6_batch_uses_the_existing_firmware_in_each_slot():
    c = contract()
    records = [raw((1, 2, 3, 4)), raw((5, 6, 7, 8))]
    candidates, images = render_images(c, records)
    reference = build_f6_firmware(c)
    start = c['program_contract']['slot_base']
    assert images[start] == reference.prefix(candidates[0], case_index=0)
    assert images[start + 256] == reference.prefix(candidates[1], case_index=1)
    assert candidates[0].words == (1, 2, 3, 4)
    assert candidates[1].words == (5, 6, 7, 8)
    with pytest.raises(ValueError, match='slot_count'):
        render_images(c, records + records)


def test_online_program_materializes_no_prefix_and_uses_canonical_compiler():
    c = contract()
    candidates, images = render_images(c, [], online=True)
    base = c['program_contract']['slot_base']
    assert not candidates and base not in images and base + 256 not in images
    firmware = build_f6_firmware(c)
    raw_bytes = raw((5, 6, 7, 8))
    tag, encoded, prefix = online_case_message(firmware, raw_bytes.hex(), 1).split()
    assert tag == 'CASE' and encoded == raw_bytes.hex()
    assert bytes.fromhex(prefix) == firmware.prefix(direct_candidate(raw_bytes), case_index=1)
    with pytest.raises(ValueError):
        online_case_message(firmware, '0000000000000000', 0)


def test_online_runner_waits_for_each_slot_and_handles_end(tmp_path, monkeypatch, capsys):
    firmware = build_f6_firmware(contract())
    first = raw((1, 2, 3, 4)).hex()
    monkeypatch.setattr(sys, 'stdin', io.StringIO('bad\n' + first + '\nEND\n'))
    child = ('import sys; print("NEED_RECORD 0",flush=True); s=input(); '
             'assert s.startswith("CASE ' + first + ' "); '
             'print("case 0 observations_passed",flush=True); '
             'print("NEED_RECORD 1",flush=True); assert input()=="END"')
    submitted=[]
    assert online_runner(firmware, submitted)([sys.executable, '-u', '-c', child], tmp_path/'run.log') == 0
    assert submitted == [first]
    assert 'case 0 observations_passed' in (tmp_path/'run.log').read_text()
    assert 'invalid F6 record' in capsys.readouterr().err
