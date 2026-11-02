"""Entry and C++ host mirror of the opt-in F1 computed-base address forms.

Two kinds of checks, both cheap and neither needing an RTL run:

  * the entry gate: ``validate_record`` admits a statically proven computed
    base only when the scenario declares ``f1_allow_address_forms``, keeps the
    legacy x18 refusal otherwise, and names every out-of-scope shape;
  * the C++ mirror: the provenance block in
    ``scripts/inprocess_obi_apb_f1f4_spike.cpp`` is extracted between its
    markers, compiled standalone with g++, and compared with the Python
    authority (``validate_program_words(..., allow_address_forms=True)``) on
    generated address programs and on hand-built refusals.

The fixed address batch and the fuzz batch are real-run evidence under
``runs/round1-f1-a/``; they are not reproduced here.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from myfuzz.fuzz.rv32_program import (
    generate_program, mutate_program, validate_program_words)
from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile
from scripts.run_inprocess_f1f6 import (PROGRAM_DATA_WORDS, build_layout,
                                       declared_windows, parse_record,
                                       render_bindings, validate_record)

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
ADDRESS_CONFIG = dict(CONFIG, f1_program_words=16, f1_allow_address_forms=True)
WINDOWS = declared_windows(CONFIG, 16)
LAYOUT = build_layout(WINDOWS, 0x10080)
ISA = IsaContract(32, ('I', 'M'), instruction_alignment=4)
PROFILE = RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0)
ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
WINDOW = PROGRAM_DATA_WORDS * 4
ADDRESS_FLAGS = dict(f1_program_words=16, f1_subword=False,
                     f1_allow_address_forms=True)


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def f1_text(words):
    return 'F1:' + ':'.join(format(value, '08x') for value in words)


def record(words, f1_words=16):
    return parse_record(f1_text(words), windows=WINDOWS, arity=ARITY,
                        f1_words=f1_words)


# The four sound templates, one image, in the order the gate proves them:
#   ADDI xd,x18,k                 (indices 1-3)
#   ADDI xm,x0,k; ADD xd,x18,xm   (indices 4-6)
#   LUI xm,0; ADDI; ADD           (indices 7-11)
#   ADDI xm,x0,c; ANDI; ADD       (indices 12-15)
TEMPLATES = (
    word('ADDI', rd=6, rs1=0, imm=0x123),
    word('ADDI', rd=5, rs1=18, imm=8),
    word('SW', rs1=5, rs2=6, imm=0),
    word('LW', rd=7, rs1=5, imm=0),
    word('ADDI', rd=10, rs1=0, imm=12),
    word('ADD', rd=11, rs1=18, rs2=10),
    word('SW', rs1=11, rs2=7, imm=0),
    word('LUI', rd=12, imm=0),
    word('ADDI', rd=12, rs1=12, imm=16),
    word('ADD', rd=13, rs1=18, rs2=12),
    word('LW', rd=14, rs1=13, imm=0),
    word('SW', rs1=13, rs2=14, imm=0),
    word('ADDI', rd=15, rs1=0, imm=44),
    word('ANDI', rd=15, rs1=15, imm=WINDOW - 4),
    word('ADD', rd=16, rs1=18, rs2=15),
    word('SW', rs1=16, rs2=7, imm=0),
)


# ---------------------------------------------------------------------------
# The entry gate: flags, acceptance and the legacy refusal
# ---------------------------------------------------------------------------


def test_the_legacy_program_gate_still_refuses_a_computed_base():
    computed = (word('ADDI', rd=5, rs1=18, imm=8),
                word('LW', rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match='must use x18 as its base'):
        validate_record(record(computed), isa=ISA, windows=WINDOWS, f1_words=16)


def test_the_declared_flag_admits_every_sound_address_template():
    parsed = record(TEMPLATES)
    assert validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=16,
                           f1_flags=ADDRESS_FLAGS)['flow'] == 'F1'
    # The same program under the reconstructed (flag-off) declaration is the
    # legacy gate and refuses the first computed base by name.
    with pytest.raises(ValueError, match='must use x18 as its base'):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=16)


def test_the_computed_bases_are_exactly_the_proven_ones():
    from myfuzz.fuzz.rv32_program import address_provenance_details
    details = address_provenance_details(TEMPLATES, window_bytes=WINDOW)
    assert [(row['index'], row['base_reg'], row['low'], row['high'])
            for row in details] == [
        (2, 5, 8, 8), (3, 5, 8, 8), (6, 11, 12, 12),
        (10, 13, 16, 16), (11, 13, 16, 16), (15, 16, 44, 44)]


@pytest.mark.parametrize('words,match', [
    # a proven base whose *offset* is outside the declared window
    ((word('ADDI', rd=5, rs1=18, imm=WINDOW),
      word('LW', rd=6, rs1=5, imm=0)), 'leaves the declared data window'),
    # an address derived from x0 is a constant, not a data-window address
    ((word('ADDI', rd=5, rs1=0, imm=8),
      word('LW', rd=6, rs1=5, imm=0)),
     'not a statically proven data-window address'),
    # masking the absolute address is unsound: ANDI after ADD clears data_base
    ((word('ADDI', rd=6, rs1=0, imm=8),
      word('ADD', rd=5, rs1=18, rs2=6),
      word('ANDI', rd=5, rs1=5, imm=WINDOW - 4),
      word('LW', rd=7, rs1=5, imm=0)),
     'not a statically proven data-window address'),
    # a computed base carries its displacement; a non-zero immediate is refused
    ((word('ADDI', rd=5, rs1=18, imm=8),
      word('LW', rd=6, rs1=5, imm=4)), 'computed base must use immediate 0'),
    # a 2-byte-aligned proven range is refused
    ((word('ADDI', rd=5, rs1=18, imm=2),
      word('LW', rd=6, rs1=5, imm=0)), 'not 4-byte aligned'),
    # branches, CSR/system words and compressed parcels stay out of scope
    ((word('ADDI', rd=5, rs1=18, imm=8),
      word('BEQ', rs1=0, rs2=0, imm=8)), 'control-flow or system'),
    ((word('ADDI', rd=5, rs1=18, imm=8), 0x00000073), 'control-flow or system'),
    ((word('ADDI', rd=5, rs1=18, imm=8), 0x00004501), 'compressed'),
])
def test_a_computed_base_outside_the_sound_templates_is_refused_by_name(words, match):
    # The record is built directly: ``parse_record`` already refuses a
    # compressed word, and this test pins the *program gate's* refusal.
    raw = {'flow': 'F1', 'fields': tuple(words), 'text': f1_text(words),
           'message': 'CASE ' + f1_text(words).replace(':', ' ')}
    with pytest.raises(ValueError, match=match):
        validate_record(raw, isa=ISA, windows=WINDOWS, f1_words=16,
                        f1_flags=ADDRESS_FLAGS)


def test_the_legacy_reserved_register_and_window_rules_still_apply():
    for words, match in (
            ((word('ADDI', rd=8, rs1=18, imm=4), word('SW', rs1=8, rs2=0, imm=0)),
             'reserved mailbox register x8'),
            ((word('LW', rd=9, rs1=18, imm=0),), 'reserved slot base register x9'),
            ((word('LW', rd=18, rs1=18, imm=0),),
             'reserved data-window base register x18'),
            ((word('LW', rd=6, rs1=18, imm=WINDOW),),
             'leaves the declared data window')):
        with pytest.raises(ValueError, match=match):
            validate_record(record(words), isa=ISA, windows=WINDOWS, f1_words=16,
                            f1_flags=ADDRESS_FLAGS)


def test_the_flag_is_read_from_the_scenario_declaration():
    from myfuzz.fuzz.f1_program_gate import f1_gate_flags_from_scenario
    flags = f1_gate_flags_from_scenario(ADDRESS_CONFIG)
    assert flags.allow_address_forms is True and flags.mode == 'address'
    assert flags.as_dict()['f1_allow_address_forms'] is True
    off = f1_gate_flags_from_scenario(CONFIG)
    assert off.allow_address_forms is False and off.mode == 'single'
    program = f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=16))
    assert program.allow_address_forms is False and program.mode == 'legacy'
    for bad in (dict(CONFIG, f1_allow_address_forms='yes'),
                dict(CONFIG, f1_program_words=1, f1_allow_address_forms=True),
                dict(CONFIG, f1_subword=True, f1_program_words=16,
                     f1_allow_address_forms=True)):
        with pytest.raises(ValueError):
            f1_gate_flags_from_scenario(bad)


def test_the_header_states_the_declared_address_form_fact():
    from tests.integration.test_inprocess_f1f6_entry import (cpu_document,
                                                             dma_document,
                                                             ip_document)
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(ROOT / CONFIG['cpu_profile'])
    on = render_bindings(ADDRESS_CONFIG, cpu_document(), ip_document(),
                         dma_document(), LAYOUT, profile, irq=None, dma=None,
                         dma_irq=None, f1_words=16)
    assert '#define F1_MAX_WORDS 16u' in on
    assert '#define F1_ALLOW_ADDRESS_FORMS 1' in on
    off = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                          LAYOUT, profile, irq=None, dma=None, dma_irq=None,
                          f1_words=1)
    assert '#define F1_ALLOW_ADDRESS_FORMS 0' in off


def test_the_entry_has_one_program_authority_and_no_private_copy():
    import scripts.run_inprocess_f1f6 as entry
    assert not hasattr(entry, '_validate_f1_program')
    assert entry.f1_flags_for_record(16, False, None).mode == 'legacy'
    assert entry.f1_flags_for_record(16, False, ADDRESS_FLAGS).mode == 'address'
    assert entry.f1_flags_for_record(
        16, False, {'f1_program_words': 16,
                    'f1_allow_address_forms': True}).mode == 'address'


# ---------------------------------------------------------------------------
# The fuzz strategy: address forms are drawn only when the flag is on
# ---------------------------------------------------------------------------


def _entry_gate(f1_words, flags):
    def gate(flow, fields):
        text = flow + ':' + ':'.join(format(int(value), '08x')
                                     for value in fields)
        parsed = parse_record(text, windows=WINDOWS, arity=ARITY,
                              f1_words=f1_words)
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=f1_words,
                        f1_flags=flags)
        return parsed['text'], parsed['message']
    return gate


def _computed_bases(words):
    return [index for index, item in enumerate(words)
            if item & 0x7F in (0x03, 0x23) and ((item >> 15) & 31) != 18]


def test_the_strategy_draws_address_forms_only_after_the_declaration():
    from myfuzz.fuzz.strategy import FuzzStrategy
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(16, ADDRESS_FLAGS),
        program_profile=PROFILE, f1_words=16, program_window=WINDOW, seed=11,
        f1_allow_address_forms=True)
    mutated_with_forms = 0
    for _ in range(20):
        fresh = strategy.fresh('F1')
        assert len(fresh.fields) >= 2
        assert _computed_bases(fresh.fields), fresh.text
        mutated = strategy.mutate(fresh)
        # A mutation may delete the memory word or replace it with an ALU word;
        # what must hold is that every mutation is legal for the declared shape
        # and that the address form survives often enough to be fuzzed.
        mutated_with_forms += int(bool(_computed_bases(mutated.fields)))
    assert mutated_with_forms >= 10, mutated_with_forms
    with pytest.raises(ValueError):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(1, {}),
                     program_profile=PROFILE, f1_words=1,
                     program_window=WINDOW, f1_allow_address_forms=True)


def test_a_flag_off_strategy_never_draws_a_computed_base():
    from myfuzz.fuzz.strategy import FuzzStrategy
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(16, {'f1_program_words': 16}),
        program_profile=PROFILE, f1_words=16, program_window=WINDOW, seed=11)
    for _ in range(40):
        assert not _computed_bases(strategy.fresh('F1').fields)


# ---------------------------------------------------------------------------
# The C++ host mirror
# ---------------------------------------------------------------------------

_HARNESS = '''#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
{block}
int main(int argc, char **argv) {{
  if (argc < 3) return 2;
  const unsigned window = unsigned(std::strtoul(argv[1], nullptr, 0));
  std::vector<uint32_t> words;
  for (int index = 2; index < argc; ++index)
    words.push_back(uint32_t(std::strtoul(argv[index], nullptr, 16)));
  const f1_provenance::Result result =
      f1_provenance::check(words.data(), unsigned(words.size()), window);
  std::printf("ok=%d index=%u message=%s\\n", int(result.ok), result.index,
              result.message.c_str());
  return 0;
}}
'''


def _provenance_block():
    source = HOST.read_text()
    begin = source.index('// BEGIN F1_ADDRESS_PROVENANCE')
    end = source.index('// END F1_ADDRESS_PROVENANCE')
    return source[begin:end + len('// END F1_ADDRESS_PROVENANCE')]


@pytest.fixture(scope='module')
def mirror(tmp_path_factory):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('g++ is required for the C++ provenance mirror')
    directory = tmp_path_factory.mktemp('f1-address-mirror')
    harness = directory / 'mirror.cpp'
    harness.write_text(_HARNESS.format(block=_provenance_block()))
    binary = directory / 'mirror'
    completed = subprocess.run(
        [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
         '-O2', str(harness), '-o', str(binary)],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    return binary


def _run_mirror(binary, words, window_words=PROGRAM_DATA_WORDS):
    completed = subprocess.run(
        [str(binary), str(window_words), *[format(value, '08x')
                                           for value in words]],
        capture_output=True, text=True, check=True)
    match = re.match(r'ok=(\d+) index=(\d+) message=(.*)', completed.stdout,
                     re.S)
    assert match is not None, completed.stdout
    return match.group(1) == '1', int(match.group(2)), match.group(3)


def _python_accepts(words):
    try:
        validate_program_words(PROFILE, tuple(words), window_size=WINDOW,
                               allow_address_forms=True)
    except ValueError:
        return False
    return True


def test_the_mirror_admits_the_fixed_template_program(mirror):
    ok, index, message = _run_mirror(mirror, TEMPLATES)
    assert ok, (index, message)
    assert _python_accepts(TEMPLATES)


def test_the_mirror_refuses_the_same_programs_the_python_gate_refuses(mirror):
    cases = (
        (word('ADDI', rd=5, rs1=18, imm=WINDOW),
         word('LW', rd=6, rs1=5, imm=0)),
        (word('ADDI', rd=5, rs1=0, imm=8), word('LW', rd=6, rs1=5, imm=0)),
        (word('ADDI', rd=6, rs1=0, imm=8),
         word('ADD', rd=5, rs1=18, rs2=6),
         word('ANDI', rd=5, rs1=5, imm=WINDOW - 4),
         word('LW', rd=7, rs1=5, imm=0)),
        (word('ADDI', rd=5, rs1=18, imm=8), word('LW', rd=6, rs1=5, imm=4)),
        (word('ADDI', rd=5, rs1=18, imm=2), word('LW', rd=6, rs1=5, imm=0)),
    )
    for words in cases:
        ok, _, message = _run_mirror(mirror, words)
        assert not ok, words
        assert _python_accepts(words) is False
        assert 'statically proven' in message or 'window' in message or \
            'immediate 0' in message or 'aligned' in message, message


def test_the_mirror_agrees_with_the_python_authority_on_generated_programs(mirror):
    accepted = refused = 0
    for seed in range(24):
        program = generate_program(
            PROFILE, seed=seed, max_words=8, window_size=WINDOW, min_words=2,
            style='address', allow_address_forms=True)
        mutated = mutate_program(
            PROFILE, program, seed=seed, max_words=8, window_size=WINDOW,
            allow_address_forms=True)
        for words in (tuple(program.words), tuple(mutated.words)):
            ok, index, message = _run_mirror(mirror, words)
            assert ok == _python_accepts(words), (seed, index, message, words)
            accepted += int(ok)
            refused += int(not ok)
    assert accepted >= 40, accepted
    # The generated corpus is legal, so the agreement it proves is on the
    # accepting side; the refusal side is the hand-built case above.
    assert refused == 0


def test_the_host_refuses_the_out_of_scope_shapes_by_name():
    source = HOST.read_text()
    assert re.search(r'#define F1_ALLOW_ADDRESS_FORMS 0', source)
    # Literal continuation splits the sentence across source lines, so the
    # fragments are checked separately.
    assert 'is a branch; the trampoline program is ' in source
    assert 'is a jump; the trampoline program is ' in source
    assert 'is a CSR or system word; the trampoline ' in source
    assert 'program executes no system instruction' in source
    assert 'is not one 32-bit word' in source
    assert 'f1_provenance::check(words, count, PROGRAM_DATA_WORDS)' in source
    assert 'must use x18, the declared data-window base' in source
    # The block is the one place the host mirrors the provenance rules.
    block = _provenance_block()
    assert 'ANDI' in block and 'Kind::kWindow' in block
    assert 'not a statically proven data-window address' in block
