"""Pure-Python integration tests for the fuzz mode of the unified entry.

These tests build the same collaborators ``main()`` builds (declared windows,
profiles, behavior declarations, gates, word/program spaces) but never start a
model or Verilator.  They assert the properties the closed loop depends on:
every generated input is accepted by the entry's own gate, the declared example
vectors are seeded first, and a scenario behavior file changes the declaration
the executor uses.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import (behavior_document, source_behavior)
from myfuzz.isa.constraints import f1_isa_from_profile
from scripts.run_inprocess_f1f6 import (dma_declaration, declared_windows, flow_arity,
                                       f5_declaration, fuzz_collaborators,
                                       parse_record, pin_declaration, profile_protocol,
                                       validate_record)

ROOT = Path(__file__).resolve().parents[2]
TIMER = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json').read_text())
TIMER_PLAIN = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
GPIO = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5-fuzz.json').read_text())
DMA = dict(block_words=4)


def context(config, *, dma=DMA, protocol='apb3'):
    profile = load_component_profile(ROOT / config['source_profile'])
    irq, reason = f5_declaration(config, profile, protocol)
    pins = pin_declaration(config, profile)
    windows = declared_windows(config, 16 if dma is not None else None)
    isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
    arity = flow_arity(irq, dma)
    return dict(profile=profile, irq=irq, reason=reason, pins=pins, windows=windows,
                isa=isa, arity=arity)


def collaborators(config, *, dma=DMA, f1_words=4, seed=3):
    ctx = context(config, dma=dma)
    return ctx, fuzz_collaborators(
        config, base_dir=ROOT, windows=ctx['windows'], arity=ctx['arity'],
        behavior_config=config, ip_profile=ctx['profile'], pins=ctx['pins'],
        dma=dma, f1_words=f1_words, isa=ctx['isa'], refusals=None,
        label='APB', seed=seed, cases=10, seconds=None)


def test_the_timer_scenario_offers_all_six_flows():
    ctx, fuzz = collaborators(TIMER)
    assert ctx['irq'] is not None
    assert set(fuzz['strategy'].flows) == {'F1', 'F2', 'F3', 'F4', 'F5', 'F6'}


def test_the_declared_example_and_seed_inputs_come_first():
    ctx, fuzz = collaborators(GPIO, dma=None)
    seeds = fuzz['strategy'].seed_inputs()
    assert seeds[0].text == 'F4:40000000:ffffffff'
    assert any(row.text == 'F5:ffffffff:00000001:00000001:0000002b'
               for row in seeds), [row.text for row in seeds]
    texts = [row.text for row in seeds]
    assert len(texts) == len(set(texts))


def test_every_generated_input_passes_the_entry_gate():
    ctx, fuzz = collaborators(TIMER)
    strategy = fuzz['strategy']
    for _ in range(120):
        generated = strategy.next_input()
        record = parse_record(generated.text, windows=ctx['windows'],
                              arity=ctx['arity'], pin=ctx['pins'], f1_words=4)
        validate_record(record, isa=ctx['isa'], windows=ctx['windows'], f1_words=4)
        assert record['text'] == generated.text


def test_f1_programs_stay_within_the_declared_length_and_read_the_data_window():
    ctx, fuzz = collaborators(TIMER)
    strategy = fuzz['strategy']
    lengths = set()
    for _ in range(60):
        generated = strategy.next_input()
        if generated.flow != 'F1':
            continue
        lengths.add(len(generated.fields))
        assert 1 <= len(generated.fields) <= 4
        for word in generated.fields:
            assert word & 3 == 3
    assert lengths and max(lengths) <= 4


def test_a_scenario_behavior_file_supplies_the_f5_facts(tmp_path):
    # The plain GPIO pin scenario states only trigger offsets in a nested block;
    # the behavior file supplies the trigger values and the pin model, so F5 is
    # offered without editing the executor.
    raw = dict(GPIO)
    raw.pop('trigger_writes', None)
    raw.pop('source_port', None)
    raw.pop('source_bit_offset', None)
    raw.pop('pulse_width_ticks', None)
    raw.pop('status_offsets', None)
    facts = source_behavior(raw, base_dir=ROOT)
    assert facts['declared_by'] == 'file'
    merged = dict(raw, **{key: facts[key] for key in
                          ('source_port', 'source_bit_offset', 'pulse_width_ticks',
                           'trigger_writes', 'status_offsets')})
    merged['pins'] = facts['pins']
    profile = load_component_profile(ROOT / raw['source_profile'])
    irq, reason = f5_declaration(merged, profile, 'apb3')
    assert reason is None and irq is not None
    assert irq['trigger_offsets'] == [4, 24, 28, 12]
    assert behavior_document(facts, None)['source']['declared_by'] == 'file'


def test_a_declared_dma_behavior_file_reports_the_status_bits(tmp_path):
    from tests.integration.test_inprocess_f1f6_entry import dma_artifact, zipdma_profile
    config = dict(TIMER_PLAIN, dma_behavior='configs/behaviors/zipdma_f6.json')
    declaration = dma_declaration(config, zipdma_profile(), dma_artifact())
    assert declaration['busy_bit'] == 31 and declaration['err_bit'] == 30
    assert declaration['status_bits_declared'] is True
    assert declaration['status_bits_source'] == 'configs/behaviors/zipdma_f6.json'
    plain = dma_declaration(TIMER_PLAIN, zipdma_profile(), dma_artifact())
    assert plain['status_bits_declared'] is False
    assert plain['status_bits_source'] == 'builtin_zipdma_rtl_default'


def test_a_seed_record_of_a_flow_the_components_cannot_serve_is_refused():
    with pytest.raises(ValueError, match='unsupported flow tag|no DMA|unsupported'):
        ctx = context(GPIO, dma=None)
        fuzz_collaborators(
            dict(GPIO, fuzz_seed_records=['F6:1:2:3:4']), base_dir=ROOT,
            windows=ctx['windows'], arity=ctx['arity'], behavior_config=GPIO,
            ip_profile=ctx['profile'], pins=ctx['pins'], dma=None, f1_words=4,
            isa=ctx['isa'], refusals={'F6': 'unsupported-f6:no-dma-model:APB'},
            label='APB', seed=1, cases=2, seconds=None)


def test_the_fuzz_input_document_states_its_declared_spaces():
    ctx, fuzz = collaborators(TIMER)
    document = fuzz['document']
    assert document['schema_version'] == 'inprocess_fuzz_inputs.v1'
    assert document['flows'] == ['F1', 'F2', 'F3', 'F4', 'F5', 'F6']
    assert document['f1_program_words'] == 4
    assert document['word_space']['flows'] == ['F2', 'F3', 'F4', 'F5', 'F6']
    json.dumps(document)
