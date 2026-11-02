"""Declaration-derived word spaces for F2..F6, from the real profiles.

Every address list here comes from the scenario JSON and the component
profile's ``address.registers`` rows; nothing is copied from the host script.
The tests are pure: no RTL, no Verilator and no subprocess.
"""

import json
import random
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.fuzz.word_spaces import DeclaredSpace, WordSpace

ROOT = Path(__file__).resolve().parents[2]
DATA_OFFSET = 0x4000
PROGRAM_DATA_WORDS = 16
MASK32 = 0xFFFFFFFF

TIMER_TARGET = 1073745920
TIMER_RAM = 81920
GPIO_TARGET = 1073741824
GPIO_RAM = 81920
GPIO_PADIN = GPIO_TARGET + 8

SYNTH_TARGET = 0x40000000
SYNTH_RAM = 0x2000
SYNTH_PADIN = SYNTH_TARGET + 4
SYNTH_PADOUT = SYNTH_TARGET + 8
SYNTH_PADOUTSET = SYNTH_TARGET + 12
SYNTH_PADOUTCLR = SYNTH_TARGET + 16
SYNTH_READONLY = SYNTH_TARGET + 24
SYNTH_WRITEONLY = SYNTH_TARGET + 28


def _load(relative):
    return json.loads((ROOT / relative).read_text())


TIMER_SCENARIO = _load(
    'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json')
TIMER_PROFILE = _load('configs/peripherals/pulp_timer_irq/component_profile.json')
GPIO_SCENARIO = _load('configs/scenarios/inprocess-obi-apb-gpio-pins.json')
GPIO_PROFILE = _load(
    'configs/peripherals/pulp_gpio_causal_local/component_profile.json')


def _trigger_rows(scenario):
    writes = scenario.get('trigger_writes') or ()
    if not writes:
        return ()
    return (tuple(row[1] for row in writes),)


def _build(scenario, profile, *, program_data_words=PROGRAM_DATA_WORDS):
    arity = {'F2': 1, 'F3': 2, 'F4': 2}
    if scenario.get('trigger_writes'):
        arity['F5'] = len(scenario['trigger_writes'])
    elif scenario.get('irq', {}).get('trigger_offsets'):
        arity['F5'] = len(scenario['irq']['trigger_offsets'])
    block = scenario.get('dma_block_words', 0)
    if block:
        arity['F6'] = block
    pins = None
    if scenario.get('pins'):
        pins = {'padin_offset': scenario['pins']['padin_offset'], 'width': 32}
    return DeclaredSpace(
        ram_base=scenario['image_start'],
        ram_size=scenario['image_end'] - scenario['image_start'],
        data_base=scenario['image_start'] + DATA_OFFSET,
        target_base=scenario['target_window']['base'],
        target_size=scenario['target_window']['size'],
        arity=arity,
        registers=tuple(profile['address']['registers']),
        pins=pins,
        trigger_values=_trigger_rows(scenario),
        block_words=block,
        program_data_words=program_data_words)


TIMER = _build(TIMER_SCENARIO, TIMER_PROFILE)
GPIO = _build(GPIO_SCENARIO, GPIO_PROFILE)

SYNTH_REGISTERS = (
    {'offset': 0, 'name': 'PADDIR', 'width': 32, 'access': 'rw'},
    {'offset': 4, 'name': 'PADIN', 'width': 32, 'access': 'ro'},
    {'offset': 8, 'name': 'PADOUT', 'width': 32, 'access': 'rw'},
    {'offset': 12, 'name': 'PADOUTSET', 'width': 32, 'access': 'wo'},
    {'offset': 16, 'name': 'PADOUTCLR', 'width': 32, 'access': 'wo'},
    {'offset': 20, 'name': 'NARROW', 'width': 16, 'access': 'rw'},
    {'offset': 24, 'name': 'READONLY', 'width': 32, 'access': 'ro'},
    {'offset': 28, 'name': 'WRITEONLY', 'width': 32, 'access': 'wo'},
)


def _synthetic(**overrides):
    values = dict(
        ram_base=0x1000,
        ram_size=0x4000,
        data_base=SYNTH_RAM,
        target_base=SYNTH_TARGET,
        target_size=0x1000,
        arity={'F2': 1, 'F3': 2, 'F4': 2, 'F5': 2, 'F6': 3},
        registers=SYNTH_REGISTERS,
        pins={'padin_offset': 4, 'width': 8},
        trigger_values=((0, 0xFFFFFFFF),),
        block_words=3,
        program_data_words=4)
    values.update(overrides)
    return DeclaredSpace(**values)


SYNTH = _synthetic()
SPACES = (TIMER, GPIO, SYNTH)
SPACE_IDS = ('timer', 'gpio', 'synthetic')


def _timer_targets():
    return {TIMER_TARGET + offset for offset in (0, 4, 8, 16, 20, 24)}


def _gpio_readable():
    return {GPIO_TARGET + offset
            for offset in (0, 4, 8, 12, 24, 28, 32, 36, 40, 44, 48, 52)}


def _gpio_writable():
    return {GPIO_TARGET + offset
            for offset in (0, 4, 12, 16, 20, 24, 28, 32, 40, 44, 48, 52)}


def _addresses(space, flow, rng, count):
    return [space.fresh(flow, rng)[0] for _ in range(count)]


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def test_real_timer_projection_has_six_readable_and_writable_registers():
    space = WordSpace(TIMER)
    readable = space.document()['readable_registers']
    assert [row['offset'] for row in readable] == [0, 4, 8, 16, 20, 24]
    assert [row['address'] for row in readable] == [
        TIMER_TARGET + offset for offset in (0, 4, 8, 16, 20, 24)]
    assert all(row['access'] == 'rw' and row['width'] == 32 for row in readable)
    assert space.candidates('F2')['target_read'] == 6
    assert space.candidates('F4')['target_write'] == 6


def test_real_gpio_projection_filters_access_and_width():
    space = WordSpace(GPIO)
    document = space.document()
    readable = [row['offset'] for row in document['readable_registers']]
    writable = [row['offset'] for row in document['writable_registers']]
    assert readable == [0, 4, 8, 12, 24, 28, 32, 36, 40, 44, 48, 52]
    assert writable == [0, 4, 12, 16, 20, 24, 28, 32, 40, 44, 48, 52]
    assert 8 in readable and 8 not in writable
    assert 36 in readable and 36 not in writable
    assert 16 in writable and 20 in writable


def test_ram_data_window_is_the_declared_program_window():
    for declaration, expected_base in ((TIMER, TIMER_RAM), (GPIO, GPIO_RAM)):
        space = WordSpace(declaration)
        document = space.document()
        addresses = document['ram_addresses']
        assert len(addresses) == PROGRAM_DATA_WORDS
        assert addresses[0] == expected_base
        assert addresses[-1] == expected_base + 4 * (PROGRAM_DATA_WORDS - 1)
        assert all(address % 4 == 0 for address in addresses)
        assert document['windows']['data']['words'] == PROGRAM_DATA_WORDS


def test_f2_candidate_counts_from_the_real_profiles():
    timer = WordSpace(TIMER)
    gpio = WordSpace(GPIO)
    assert timer.candidates('F2') == {'target_read': 6, 'pin_word': 0,
                                      'ram_read': 16, 'two_word': 0,
                                      'total': 22}
    assert gpio.candidates('F2') == {'target_read': 12, 'pin_word': 1,
                                     'ram_read': 16, 'two_word': 1,
                                     'total': 28}


def test_f4_candidate_counts_are_writable_registers_only():
    timer = WordSpace(TIMER)
    gpio = WordSpace(GPIO)
    assert timer.candidates('F4') == {'target_write': 6, 'total': 6}
    assert gpio.candidates('F4') == {'target_write': 12, 'total': 12}
    gpio_f4 = set(_addresses(gpio, 'F4', random.Random(1), 600))
    assert gpio_f4 == _gpio_writable()
    assert GPIO_PADIN not in gpio_f4
    assert GPIO_TARGET + 36 not in gpio_f4


def test_synthetic_candidate_derivation():
    space = WordSpace(SYNTH)
    assert space.candidates('F2') == {'target_read': 4, 'pin_word': 1,
                                      'ram_read': 4, 'two_word': 1,
                                      'total': 8}
    assert space.candidates('F3') == {'ram_write': 4, 'total': 4}
    assert space.candidates('F4') == {'target_write': 5, 'total': 5}
    assert space.candidates('F5') == {'words': 2, 'declared_rows': 1,
                                      'matching_rows': 1, 'total': 2}
    assert space.candidates('F6') == {'words': 3, 'block_words': 3,
                                      'example_words': 3, 'total': 3}
    document = space.document()
    assert [row['offset'] for row in document['readable_registers']] == [
        0, 4, 8, 24]
    assert [row['offset'] for row in document['writable_registers']] == [
        0, 8, 12, 16, 28]


def test_unaligned_and_out_of_window_registers_are_not_candidates():
    registers = SYNTH.registers + (
        {'offset': 2, 'name': 'UNALIGNED', 'width': 32, 'access': 'rw'},
        {'offset': 0x0FFE, 'name': 'CROSSING', 'width': 32, 'access': 'rw'},
        {'offset': 0x1000, 'name': 'AT_END', 'width': 32, 'access': 'rw'},
        {'offset': -4, 'name': 'BEFORE', 'width': 32, 'access': 'rw'},
    )
    space = WordSpace(_synthetic(registers=registers))
    assert space.candidates('F2')['target_read'] == 4
    assert space.candidates('F4')['target_write'] == 5
    assert space.candidates('F3')['ram_write'] == 4
    for address in (SYNTH_TARGET + 2, SYNTH_TARGET + 0x0FFE,
                    SYNTH_TARGET + 0x1000, SYNTH_TARGET - 4):
        assert not space.valid('F4', (address, 0))
        assert not space.valid('F2', (address,))


def test_f2_fresh_covers_every_timer_candidate():
    space = WordSpace(TIMER)
    seen = set(_addresses(space, 'F2', random.Random(2), 3000))
    assert seen == _timer_targets() | set(space.document()['ram_addresses'])


def test_f2_fresh_covers_gpio_target_and_ram():
    space = WordSpace(GPIO)
    seen = set(_addresses(space, 'F2', random.Random(3), 4000))
    assert seen == _gpio_readable() | set(space.document()['ram_addresses'])


def test_gpio_f2_pin_forms_obey_the_padin_rule():
    space = WordSpace(GPIO)
    rng = random.Random(4)
    draws = [space.fresh('F2', rng) for _ in range(4000)]
    two_word = [fields for fields in draws if len(fields) == 2]
    assert two_word
    assert all(fields[0] == GPIO_PADIN for fields in two_word)
    assert any(len(fields) == 1 for fields in draws)
    assert all(space.valid('F2', fields) for fields in draws)


def test_no_two_word_f2_exists_off_padin():
    timer = WordSpace(TIMER)
    gpio = WordSpace(GPIO)
    synth = WordSpace(SYNTH)
    timer_draws = [timer.fresh('F2', random.Random(5)) for _ in range(500)]
    assert all(len(fields) == 1 for fields in timer_draws)
    for space, padin in ((gpio, GPIO_PADIN), (synth, SYNTH_PADIN)):
        rng = random.Random(6)
        for _ in range(2000):
            fields = space.fresh('F2', rng)
            if len(fields) == 2:
                assert fields[0] == padin
            assert space.valid('F2', fields)


def test_pin_stimulus_is_masked_to_the_declared_width():
    space = WordSpace(SYNTH)
    rng = random.Random(7)
    stimuli = [fields[1] for fields in
               (space.fresh('F2', rng) for _ in range(3000))
               if len(fields) == 2]
    assert stimuli
    assert all(value <= 0xFF for value in stimuli)
    assert all(space.valid('F2', (SYNTH_PADIN, value)) for value in stimuli)


def test_f3_fresh_is_aligned_inside_the_data_window():
    space = WordSpace(TIMER)
    ram = set(space.document()['ram_addresses'])
    rng = random.Random(8)
    for _ in range(400):
        fields = space.fresh('F3', rng)
        assert len(fields) == 2
        assert fields[0] in ram
        assert fields[0] % 4 == 0
        assert 0 <= fields[1] <= MASK32
        assert space.valid('F3', fields)


def test_f4_fresh_is_writable_only():
    space = WordSpace(TIMER)
    writable = {row['address']
                for row in space.document()['writable_registers']}
    seen = set(_addresses(space, 'F4', random.Random(9), 400))
    assert seen == writable


def test_f4_pin_register_values_are_masked():
    space = WordSpace(SYNTH)
    rng = random.Random(10)
    masked = {SYNTH_PADOUT, SYNTH_PADOUTSET, SYNTH_PADOUTCLR}
    seen = set()
    for _ in range(1000):
        address, value = space.fresh('F4', rng)
        seen.add(address)
        if address in masked:
            assert value <= 0xFF
        assert space.valid('F4', (address, value))
    assert masked <= seen


def test_f5_arity_comes_from_the_declared_trigger_writes():
    for declaration, expected in ((TIMER, 3), (GPIO, 4), (SYNTH, 2)):
        space = WordSpace(declaration)
        assert space.candidates('F5')['words'] == expected
        rng = random.Random(11)
        for _ in range(100):
            fields = space.fresh('F5', rng)
            assert len(fields) == expected
            assert space.valid('F5', fields)


def test_f5_matching_trigger_row_is_seeded():
    space = WordSpace(TIMER)
    row = (0, 0, MASK32)
    assert TIMER.trigger_values == (row,)
    rng = random.Random(12)
    draws = [space.fresh('F5', rng) for _ in range(400)]
    assert all(len(values) == 3 for values in draws)
    exact = sum(1 for values in draws if values == row)
    assert 0 < exact < len(draws)


def test_f5_without_a_matching_row_still_generates_the_declared_length():
    declaration = replace(SYNTH,
                          arity={**SYNTH.arity, 'F5': 3},
                          trigger_values=((0, 1),))
    space = WordSpace(declaration)
    assert space.candidates('F5')['matching_rows'] == 0
    rng = random.Random(13)
    for _ in range(100):
        fields = space.fresh('F5', rng)
        assert len(fields) == 3
        assert space.valid('F5', fields)


def test_f6_first_fresh_is_the_declared_example():
    timer = WordSpace(TIMER)
    assert timer.fresh('F6', random.Random(14)) == (
        0xDEADBEEF, 0x11111111, 0x22222222, 0x33333333)
    synth = WordSpace(SYNTH)
    assert synth.fresh('F6', random.Random(14)) == (
        0xDEADBEEF, 0x11111111, 0x22222222)


def test_f6_arity_equals_the_declared_block_words():
    timer = WordSpace(TIMER)
    synth = WordSpace(SYNTH)
    assert timer.candidates('F6')['words'] == 4
    assert timer.candidates('F6')['block_words'] == 4
    assert synth.candidates('F6')['words'] == 3
    assert synth.candidates('F6')['block_words'] == 3
    rng = random.Random(15)
    for _ in range(50):
        assert len(timer.fresh('F6', rng)) == 4
        assert len(synth.fresh('F6', rng)) == 3


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_every_fresh_input_passes_valid(declaration):
    space = WordSpace(declaration)
    for flow in space.flows():
        rng = random.Random(21)
        for _ in range(250):
            fields = space.fresh(flow, rng)
            assert isinstance(fields, tuple)
            assert fields
            assert space.valid(flow, fields), (flow, fields)


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_every_mutated_input_passes_valid(declaration):
    space = WordSpace(declaration)
    for flow in space.flows():
        rng = random.Random(22)
        for _ in range(250):
            fields = space.fresh(flow, rng)
            mutated = space.mutate(flow, fields, rng)
            assert isinstance(mutated, tuple)
            assert mutated
            assert space.valid(flow, mutated), (flow, fields, mutated)


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_fresh_is_deterministic_per_seed(declaration):
    for flow in WordSpace(declaration).flows():
        for seed in range(10):
            first = WordSpace(declaration).fresh(flow, random.Random(seed))
            again = WordSpace(declaration).fresh(flow, random.Random(seed))
            assert first == again


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_mutate_is_deterministic_per_seed(declaration):
    space = WordSpace(declaration)
    for flow in space.flows():
        for seed in range(10):
            fields = WordSpace(declaration).fresh(flow, random.Random(seed))
            first = space.mutate(flow, fields, random.Random(seed + 1))
            again = space.mutate(flow, fields, random.Random(seed + 1))
            assert first == again


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_mutations_actually_change_the_input(declaration):
    space = WordSpace(declaration)
    for flow in space.flows():
        rng = random.Random(23)
        for _ in range(200):
            fields = space.fresh(flow, rng)
            mutated = space.mutate(flow, fields, rng)
            assert mutated != fields, (flow, fields)


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_mutations_keep_fixed_record_lengths(declaration):
    space = WordSpace(declaration)
    for flow in ('F3', 'F4', 'F5', 'F6'):
        if flow not in space.flows():
            continue
        rng = random.Random(24)
        for _ in range(100):
            fields = space.fresh(flow, rng)
            mutated = space.mutate(flow, fields, rng)
            assert len(mutated) == len(fields)


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_f2_mutations_keep_the_pin_rule(declaration):
    space = WordSpace(declaration)
    expected = None
    if declaration.pins is not None:
        expected = declaration.target_base + declaration.pins['padin_offset']
    rng = random.Random(25)
    for _ in range(400):
        fields = space.fresh('F2', rng)
        mutated = space.mutate('F2', fields, rng)
        if len(mutated) == 2:
            assert expected is not None
            assert mutated[0] == expected
        assert space.valid('F2', mutated)


def test_f2_pin_mutation_reaches_both_forms():
    space = WordSpace(GPIO)
    rng = random.Random(26)
    lengths = set()
    fields = (GPIO_PADIN,)
    for _ in range(200):
        fields = space.mutate('F2', fields, rng)
        lengths.add(len(fields))
        assert space.valid('F2', fields)
    assert lengths == {1, 2}


def test_valid_rejects_wrong_lengths():
    timer = WordSpace(TIMER)
    gpio = WordSpace(GPIO)
    assert not timer.valid('F3', (TIMER_RAM,))
    assert not timer.valid('F3', (TIMER_RAM, 0, 0))
    assert not timer.valid('F4', (TIMER_TARGET,))
    assert not timer.valid('F4', (TIMER_TARGET, 0, 0))
    assert timer.valid('F5', (0, 0, 0))
    assert not timer.valid('F5', (0, 0))
    assert not timer.valid('F5', (0, 0, 0, 0))
    assert timer.valid('F6', (0, 0, 0, 0))
    assert not timer.valid('F6', (0, 0, 0))
    assert not timer.valid('F6', (0, 0, 0, 0, 0))
    assert not timer.valid('F2', (TIMER_RAM, 0))
    assert gpio.valid('F2', (GPIO_PADIN, 1))
    assert not gpio.valid('F2', (GPIO_PADIN, 1, 2))


def test_valid_rejects_unaligned_words():
    timer = WordSpace(TIMER)
    gpio = WordSpace(GPIO)
    assert not timer.valid('F2', (TIMER_RAM + 2,))
    assert not timer.valid('F3', (TIMER_RAM + 2, 0))
    assert not timer.valid('F4', (TIMER_TARGET + 2, 0))
    assert not gpio.valid('F2', (GPIO_PADIN + 2, 0))
    assert not gpio.valid('F4', (GPIO_TARGET + 2, 0))


def test_valid_rejects_words_outside_the_declared_windows():
    timer = WordSpace(TIMER)
    beyond_program = TIMER_RAM + 4 * PROGRAM_DATA_WORDS
    assert not timer.valid('F3', (beyond_program, 0))
    assert not timer.valid('F2', (beyond_program,))
    assert not timer.valid('F4', (TIMER_TARGET + 4096, 0))
    assert not timer.valid('F2', (TIMER_TARGET + 4096,))
    assert not timer.valid('F4', (TIMER_TARGET + 28, 0))
    assert not timer.valid('F2', (TIMER_TARGET + 28,))


def test_valid_rejects_read_only_f4_and_write_only_f2():
    space = WordSpace(SYNTH)
    assert not space.valid('F4', (SYNTH_READONLY, 1))
    assert space.valid('F4', (SYNTH_WRITEONLY, 1))
    assert not space.valid('F2', (SYNTH_WRITEONLY,))
    assert space.valid('F2', (SYNTH_READONLY,))
    assert space.valid('F2', (SYNTH_PADOUT,))
    assert not space.valid('F4', (SYNTH_PADIN, 1))


def test_valid_rejects_pin_stimulus_beyond_the_declared_width():
    space = WordSpace(SYNTH)
    assert space.valid('F2', (SYNTH_PADIN, 0))
    assert space.valid('F2', (SYNTH_PADIN, 0xFF))
    assert not space.valid('F2', (SYNTH_PADIN, 0x100))
    assert not space.valid('F2', (SYNTH_PADIN, MASK32))


def test_valid_rejects_two_word_f2_off_padin():
    space = WordSpace(SYNTH)
    assert space.valid('F2', (SYNTH_PADIN, 1))
    assert not space.valid('F2', (SYNTH_PADOUT, 1))
    assert not space.valid('F2', (SYNTH_READONLY, 1))
    assert not space.valid('F2', (SYNTH_RAM, 1))


def test_valid_rejects_unknown_flows_and_malformed_words():
    timer = WordSpace(TIMER)
    assert not timer.valid('F1', (0,))
    assert not timer.valid('F7', (0,))
    assert not timer.valid('F2', (TIMER_RAM + 2,))
    assert not timer.valid('F3', (TIMER_RAM, True))
    assert not timer.valid('F3', (TIMER_RAM, -1))
    assert not timer.valid('F3', (TIMER_RAM, MASK32 + 1))
    assert not timer.valid('F3', (TIMER_RAM, '1'))
    assert not timer.valid('F3', 'not-a-record')


def test_fresh_refuses_an_unknown_flow():
    space = WordSpace(TIMER)
    with pytest.raises(ValueError, match='unsupported input flow: F7'):
        space.fresh('F7', random.Random(27))
    with pytest.raises(ValueError, match='unsupported input flow: F1'):
        space.fresh('F1', random.Random(27))
    with pytest.raises(ValueError, match='unsupported input flow: F7'):
        space.mutate('F7', (0,), random.Random(27))


def test_fresh_refuses_an_empty_candidate_set():
    no_writable = WordSpace(_synthetic(registers=(
        {'offset': 0, 'name': 'STATUS', 'width': 32, 'access': 'ro'},)))
    assert no_writable.candidates('F4') == {'target_write': 0, 'total': 0}
    with pytest.raises(ValueError, match='no writable target register for F4'):
        no_writable.fresh('F4', random.Random(28))

    no_ram = WordSpace(_synthetic(program_data_words=0))
    assert no_ram.candidates('F3') == {'ram_write': 0, 'total': 0}
    with pytest.raises(ValueError, match='no RAM data-window address for F3'):
        no_ram.fresh('F3', random.Random(28))

    no_f2 = WordSpace(_synthetic(program_data_words=0, registers=(),
                                 pins=None))
    assert no_f2.candidates('F2')['total'] == 0
    with pytest.raises(ValueError,
                       match='no readable target address or RAM data-window'):
        no_f2.fresh('F2', random.Random(28))


def test_mutate_refuses_an_empty_candidate_set():
    no_writable = WordSpace(_synthetic(registers=(
        {'offset': 0, 'name': 'STATUS', 'width': 32, 'access': 'ro'},)))
    with pytest.raises(ValueError, match='no writable target register for F4'):
        no_writable.mutate('F4', (0, 0), random.Random(29))
    no_ram = WordSpace(_synthetic(program_data_words=0))
    with pytest.raises(ValueError, match='no RAM data-window address for F3'):
        no_ram.mutate('F3', (0, 0), random.Random(29))
    no_f2 = WordSpace(_synthetic(program_data_words=0, registers=(),
                                 pins=None))
    with pytest.raises(ValueError,
                       match='no readable target address or RAM data-window'):
        no_f2.mutate('F2', (0,), random.Random(29))


def test_arity_mismatch_is_refused():
    cases = [
        (replace(TIMER, arity={**TIMER.arity, 'F3': 3}), 'F3',
         'F3 arity must be 2'),
        (replace(TIMER, arity={**TIMER.arity, 'F4': 1}), 'F4',
         'F4 arity must be 2'),
        (replace(TIMER, arity={**TIMER.arity, 'F2': 3}), 'F2',
         'F2 arity must be 1 or 2'),
        (replace(TIMER, arity={**TIMER.arity, 'F2': 2}), 'F2',
         'F2 arity 2 requires a declared PADIN register'),
        (replace(TIMER, arity={**TIMER.arity, 'F5': 0}), 'F5',
         'F5 arity must be at least 1'),
        (replace(TIMER, arity={**TIMER.arity, 'F6': 2}), 'F6',
         'F6 arity must be 4, declared 2'),
        (replace(TIMER, arity={'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3}), 'F6',
         'F6 arity must be 4, declared absent'),
        (replace(GPIO, arity={**GPIO.arity, 'F6': 4}), 'F6',
         'F6 arity is declared with no DMA block words'),
    ]
    for declaration, flow, match in cases:
        with pytest.raises(ValueError, match=match):
            WordSpace(declaration).fresh(flow, random.Random(30))


def test_flows_reflect_the_declared_components():
    assert WordSpace(TIMER).flows() == ('F2', 'F3', 'F4', 'F5', 'F6')
    assert WordSpace(GPIO).flows() == ('F2', 'F3', 'F4', 'F5')
    no_extra = WordSpace(replace(SYNTH,
                                 arity={'F2': 1, 'F3': 2, 'F4': 2},
                                 block_words=0))
    assert no_extra.flows() == ('F2', 'F3', 'F4')
    with pytest.raises(ValueError, match='unsupported input flow: F5'):
        no_extra.fresh('F5', random.Random(31))
    with pytest.raises(ValueError, match='unsupported input flow: F6'):
        no_extra.fresh('F6', random.Random(31))
    assert not no_extra.valid('F6', (0, 0, 0))


def test_document_is_json_ready_and_has_no_paths():
    for declaration in SPACES:
        document = WordSpace(declaration).document()
        text = json.dumps(document)
        assert json.loads(text) == document
        assert str(ROOT) not in text
        assert '/home/' not in text
        assert 'configs/' not in text
        for value in _strings(document):
            assert not value.startswith('/')


def test_document_reports_windows_registers_values_and_limits():
    timer = WordSpace(TIMER).document()
    assert timer['windows']['ram'] == {'base': 65536, 'size': 131072,
                                       'end': 196608}
    assert timer['windows']['target'] == {'base': TIMER_TARGET, 'size': 4096,
                                          'end': TIMER_TARGET + 4096}
    assert timer['windows']['data'] == {'base': TIMER_RAM, 'words': 16,
                                        'end': TIMER_RAM + 64}
    assert timer['arity'] == {'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
    assert timer['trigger_values'] == [[0, 0, MASK32]]
    assert timer['block_words'] == 4
    assert timer['pins'] is None
    assert 'F4 addresses are the declared writable 32-bit registers only' in (
        timer['limits'])
    assert 'F2 may carry an external pin word only at PADIN' in timer['limits']

    gpio = WordSpace(GPIO).document()
    assert gpio['pins'] == {'padin_offset': 8, 'padin_address': GPIO_PADIN,
                            'width': 32, 'stimulus_mask': MASK32,
                            'f2_words': [1, 2]}
    assert gpio['trigger_values'] == []
    assert gpio['block_words'] == 0
    assert gpio['flows'] == ['F2', 'F3', 'F4', 'F5']
    assert 'F6' not in gpio['candidates']


def test_candidate_counts_match_the_document():
    timer = WordSpace(TIMER)
    document = timer.document()
    assert document['candidates']['F2'] == timer.candidates('F2')
    assert document['candidates']['F3'] == {'ram_write': 16, 'total': 16}
    assert document['candidates']['F4'] == {'target_write': 6, 'total': 6}
    assert document['candidates']['F5']['matching_rows'] == 1
    assert document['candidates']['F6']['words'] == 4
    assert len(document['readable_registers']) == 6
    assert len(document['writable_registers']) == 6
    assert len(document['ram_addresses']) == 16


@pytest.mark.parametrize('declaration', SPACES, ids=SPACE_IDS)
def test_values_stay_32_bit(declaration):
    space = WordSpace(declaration)
    for flow in space.flows():
        rng = random.Random(32)
        for _ in range(150):
            fields = space.fresh(flow, rng)
            for word in fields:
                assert type(word) is int
                assert 0 <= word <= MASK32
            mutated = space.mutate(flow, fields, rng)
            for word in mutated:
                assert type(word) is int
                assert 0 <= word <= MASK32


def test_pin_width_32_accepts_a_full_stimulus_word():
    space = WordSpace(GPIO)
    assert space.valid('F2', (GPIO_PADIN, 0))
    assert space.valid('F2', (GPIO_PADIN, MASK32))
    assert not space.valid('F2', (GPIO_PADIN, MASK32 + 1))
    assert space.candidates('F2')['pin_word'] == 1


def test_the_real_host_record_gate_accepts_every_draw():
    from scripts.run_inprocess_f1f6 import parse_record

    for declaration, pin in ((TIMER, None),
                             (GPIO, {'padin_offset': 8, 'width': 32})):
        windows = {'ram_base': declaration.ram_base,
                   'ram_size': declaration.ram_size,
                   'ip_base': declaration.target_base,
                   'ip_size': declaration.target_size,
                   'data_base': declaration.data_base}
        space = WordSpace(declaration)
        rng = random.Random(33)
        for _ in range(80):
            for flow in space.flows():
                fields = space.fresh(flow, rng)
                for _ in range(3):
                    text = flow + ':' + ':'.join(
                        format(word, '08x') for word in fields)
                    parsed = parse_record(text, windows=windows,
                                          arity=declaration.arity, pin=pin)
                    assert parsed['fields'] == fields
                    fields = space.mutate(flow, fields, rng)

