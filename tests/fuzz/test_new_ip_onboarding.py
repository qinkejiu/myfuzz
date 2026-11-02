"""Pure-Python onboarding test for a new APB3 IP in the unified fuzz entry.

The two scenarios under test add the pinned PULP ``apb_i2c`` target to
``scripts/run_inprocess_f1f6.py`` by declaration only: a new scenario config
(CPU profile, target window, fixed serial-pad inputs) and no CPU x IP code.
These tests build the same collaborators ``main()`` builds but never start a
model or Verilator.  They assert the things the closed loop depends on:

* the target profile's one MMIO slave endpoint is APB3 and the entry's
  ``profile_protocol`` agrees;
* ``declared_windows`` returns the profile's 4 KiB window and the CPU's own RAM
  image, with no DMA window;
* ``flow_arity`` offers exactly F1-F4: the target declares no IRQ source, so F5
  is refused by name, and no DMA model exists, so F6 is refused by name; and
* every one of 100 generated inputs passes the entry's own
  ``parse_record``/``validate_record`` gate for both CPU buses.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import source_behavior
from myfuzz.isa.constraints import f1_isa_from_profile
from scripts.run_inprocess_f1f6 import (declared_windows, f5_declaration,
                                        flow_arity, fuzz_collaborators,
                                        parse_record, pin_declaration,
                                        profile_protocol, validate_record)

ROOT = Path(__file__).resolve().parents[2]
NEW_IP = 'configs/peripherals/pulp_i2c/component_profile.json'
I2C_FLOWS = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}

# (scenario, CPU bus, CPU IRQ width, RAM base, data base, expected F5 refusal)
SCENARIOS = [
    ('configs/scenarios/inprocess-obi-apb-pulp-i2c-fuzz.json', 'obi', 1,
     65536, 81920,
     'unsupported-f5:target-irq-semantics:apb3:'),
    ('configs/scenarios/inprocess-wb-apb-pulp-i2c-fuzz.json', 'wishbone', 32,
     0, 16384,
     'unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero'),
]


def load(name):
    return json.loads((ROOT / name).read_text())


def configuration(scenario, bus='obi', irq_bits=1):
    config = load(scenario)
    profile = load_component_profile(ROOT / config['source_profile'])
    _, f5_reason = f5_declaration(config, profile, 'apb3', cpu_bus_kind=bus,
                                  cpu_irq_bits=irq_bits)
    windows = declared_windows(config, None)
    arity = flow_arity(None, None)
    refusals = {'F5': f5_reason, 'F6': 'unsupported-f6:no-dma-model:APB'}
    isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
    fuzz = fuzz_collaborators(
        config, base_dir=ROOT, windows=windows, arity=arity,
        behavior_config=config, ip_profile=profile,
        pins=pin_declaration(config, profile), dma=None,
        f1_words=config['f1_program_words'], isa=isa, refusals=refusals,
        label='APB', seed=5, cases=10, seconds=None)
    return config, profile, windows, arity, refusals, isa, fuzz


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_the_new_ip_profile_is_one_apb3_mmio_target(scenario, bus, irq_bits,
                                                    ram_base, data_base, f5_prefix):
    config, profile, _, _, _, _, _ = configuration(scenario, bus, irq_bits)
    assert config['source_profile'] == NEW_IP
    # profile_protocol() reads the profile document, the way main() does.
    assert profile_protocol(load(config['source_profile'])) == 'apb3'
    endpoints = [endpoint for endpoint in profile.endpoints
                 if endpoint.function == 'mmio_slave']
    assert [endpoint.protocol for endpoint in endpoints] == [('apb', '3')]
    assert profile.address.window_size == 4096
    # The declaration names the two real pad inputs; no IRQ pin is declared.
    assert [row['role'] for row in config['source_fixed_inputs']] == [
        'scl_pad_i', 'sda_pad_i']
    assert {row['value'] for row in config['source_fixed_inputs']} == {1}
    assert profile.interrupts == ()
    # The IP declares no F5 facts, so there is no behavior file to consume.
    assert source_behavior(config, base_dir=ROOT) is None


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_declared_windows_follow_the_profile_and_the_cpu_boot_contract(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, _, windows, arity, refusals, _, _ = configuration(scenario, bus, irq_bits)
    assert windows == dict(ram_base=ram_base, ram_size=131072,
                           ip_base=1073741824, ip_size=4096,
                           dma_base=None, dma_size=None, data_base=data_base)
    # The profile's window is used verbatim and cannot overlap the RAM image.
    window = config['target_window']
    assert window == {'base': windows['ip_base'], 'size': windows['ip_size']}
    assert window['base'] >= ram_base + windows['ram_size']
    assert 'dma_profile' not in config and 'dma_window' not in config


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_flow_arity_is_f1_to_f4_and_f5_f6_are_refused_by_name(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, profile, _, arity, refusals, _, _ = configuration(scenario, bus, irq_bits)
    assert arity == I2C_FLOWS
    _, reason = f5_declaration(config, profile, 'apb3', cpu_bus_kind=bus,
                               cpu_irq_bits=irq_bits)
    assert reason is not None and reason.startswith(f5_prefix), reason
    assert refusals['F6'] == 'unsupported-f6:no-dma-model:APB'


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_one_hundred_generated_inputs_pass_the_entry_gate(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, _, windows, arity, refusals, isa, fuzz = configuration(scenario, bus, irq_bits)
    assert fuzz['document']['flows'] == ['F1', 'F2', 'F3', 'F4']
    assert fuzz['document']['f1_program_words'] == config['f1_program_words'] == 4
    strategy = fuzz['strategy']
    seen = set()
    for _ in range(100):
        generated = strategy.next_input()
        record = parse_record(generated.text, windows=windows, arity=arity,
                              label='APB', refusals=refusals, pin=None,
                              f1_words=config['f1_program_words'])
        validate_record(record, isa=isa, windows=windows,
                        f1_words=config['f1_program_words'])
        assert record['text'] == generated.text
        seen.add(generated.flow)
    assert seen == {'F1', 'F2', 'F3', 'F4'}
