"""Pure-Python onboarding test for the PULP SPI APB3 target in the unified fuzz entry.

Two scenarios add the pinned PULP ``apb_spi_master`` target (profile
``configs/peripherals/inprocess_verify_pulp_spi_irq``) to the closed loop of
``scripts/run_inprocess_f1f6.py --fuzz`` by declaration only: a CPU profile, the
profile's own window, four fixed serial-data inputs, and ``source_behavior``
naming ``configs/behaviors/pulp_spi_eot_f5.json``.  No executor, C++ host or
``src/myfuzz`` code is added for this CPU x IP combination.  These tests build
the same collaborators ``main()`` builds and never start a model or Verilator.

They assert:

* the target profile has one APB3 MMIO slave endpoint and exactly one declared
  interrupt source (the EOT pulse on ``events_o[1]``), and the scenario's
  ``source_behavior`` file repeats the facts already recorded for that RTL in
  ``configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json`` - no new trigger
  value or status offset is invented here;
* ``declared_windows`` returns the profile's 4 KiB window and the CPU's own RAM
  image, with no DMA window;
* the Ibex OBI declaration offers F1-F5 (the EOT pulse is declarable, unlike the
  PULP I2C profile) while the PicoRV32 Wishbone declaration offers F1-F4 and
  refuses F5 by the CPU's own name; both refuse F6 by name;
* every one of 100 generated inputs passes the entry's own
  ``parse_record``/``validate_record`` gate for both CPU buses; and
* the peripheral inventory still contains no unused APB3/AXI4-Lite register IP:
  every such profile belongs to a family that some ``inprocess-*.json`` scenario
  already selects, and every unused non-APB3/AXI4-Lite profile is refused by
  name before any RTL is built.  That last test is a tripwire, not a claim.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import source_behavior
from myfuzz.isa.constraints import f1_isa_from_profile
from scripts.run_inprocess_f1f6 import (declared_windows, f5_declaration, flow_arity,
                                        fuzz_collaborators,
                                        generic_target_request_from_profile,
                                        parse_record, pin_declaration,
                                        profile_protocol, validate_record)

ROOT = Path(__file__).resolve().parents[2]
SPI_PROFILE = 'configs/peripherals/inprocess_verify_pulp_spi_irq/component_profile.json'
SPI_BEHAVIOR = 'configs/behaviors/pulp_spi_eot_f5.json'
FIXED_SPI_SCENARIO = 'configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json'
APB3 = ('apb', '3')
AXI4LITE = ('axi4-lite', '1')
MMIO_PROTOCOLS = {APB3, AXI4LITE}

#: (scenario, CPU bus, CPU IRQ width, RAM base, data base, expected F5 refusal)
SCENARIOS = [
    ('configs/scenarios/inprocess-obi-apb-pulp-spi-fuzz.json', 'obi', 1,
     65536, 81920, None),
    ('configs/scenarios/inprocess-wb-apb-pulp-spi-fuzz.json', 'wishbone', 32,
     0, 16384, 'unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero'),
]
F5_FACTS = dict(source_port='events_o', source_bit_offset=1, pulse_width_ticks=16,
                trigger_writes=((16, 65536), (24, 171), (0, 2)),
                status_offsets=(40,), status_cause_bits=None, clear_writes=())

#: Profiles whose (source root, top module) family is already admitted to the
#: unified entry by one of the ``configs/scenarios/inprocess-*.json`` files.
ADMITTED_FAMILIES = {
    ('third_party/soc-pulp-apb-i2c', 'apb_i2c'),
    ('third_party', 'apb_spi_master'),
    ('third_party/soc-pulp-apb-timer', 'apb_timer'),
    ('third_party/soc-pulp-apb-gpio', 'apb_gpio'),
    ('third_party/soc-zipcpu-wbuart', 'axiluart'),
}
#: APB3/AXI4-Lite profiles no ``inprocess-*.json`` scenario names directly.  Each
#: one is an alias declaration over an already-admitted RTL family; a *new* family
#: appearing here would fail this test (the inventory tripwire).
UNREFERENCED_APB_AXI_PROFILES = {
    'configs/peripherals/embedded_profile_target/component_profile.json',
    'configs/peripherals/profile_only_i2c/component_profile.json',
    'configs/peripherals/profile_only_idle_i2c/component_profile.json',
    'configs/peripherals/shared_profile_target/component_profile.json',
    'configs/peripherals/pulp_timer/component_profile.json',
    'configs/peripherals/pulp_gpio/component_profile.json',
    'configs/peripherals/pulp_gpio_storage/component_profile.json',
}
#: Unused profiles this executor still has no target adapter for, with the gate
#: that refuses them before any RTL is built and the exact refusal word.  The
#: in-process executor now admits TL-UL, word-addressed classic Wishbone and
#: AHB-Lite register targets, so those candidates moved out of this list; only an
#: addressless classic Wishbone target remains genuinely blocked.
BLOCKED_PROTOCOL_PROFILES = [
    # The protocol itself is admitted now, but this profile's classic variant is
    # addressless (no ``adr`` port), so no case could print the offset the slave
    # really decoded.  The request builder refuses it by name, before any RTL.
    ('configs/peripherals/zipcpu_timer/component_profile.json', 'request',
     'unsupported-target-trace:wishbone:addressless:'
     'configs/peripherals/zipcpu_timer/component_profile.json'),
]
#: Profiles on the two protocols this increment added that are now admitted as
#: real register targets: the protocol mapping accepts them and their endpoint is
#: a genuine MMIO slave of that protocol (they are exercised by the new
#: ``inprocess-obi-*-f1f4.json`` scenarios, or are admissible by the same gate).
ADMITTED_NON_APB_AXI_PROFILES = [
    ('configs/peripherals/opentitan_pattgen_local/component_profile.json', 'tl-ul'),
    ('configs/peripherals/opentitan_rv_timer_local/component_profile.json', 'tl-ul'),
    ('configs/peripherals/zipcpu_uart/component_profile.json', 'wishbone'),
]


def load(name):
    return json.loads((ROOT / name).read_text())


def merged_behavior(config):
    """The config with a behavior file's facts merged in, as ``main()`` does."""
    behavior = dict(config)
    facts = source_behavior(config, base_dir=ROOT)
    for key in ('source_port', 'source_bit_offset', 'pulse_width_ticks',
                'trigger_writes', 'status_offsets', 'status_cause_bits',
                'clear_writes', 'pins'):
        if facts and key in facts:
            behavior[key] = facts[key]
    return behavior, facts


def configuration(scenario, bus='obi', irq_bits=1):
    config = load(scenario)
    profile = load_component_profile(ROOT / config['source_profile'])
    behavior, facts = merged_behavior(config)
    irq, f5_reason = f5_declaration(behavior, profile, 'apb3', cpu_bus_kind=bus,
                                    cpu_irq_bits=irq_bits)
    windows = declared_windows(config, None)
    arity = flow_arity(irq, None)
    refusals = {'F6': 'unsupported-f6:no-dma-model:APB'}
    if f5_reason is not None:
        refusals['F5'] = f5_reason
    isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
    pins = pin_declaration(behavior, profile)
    fuzz = fuzz_collaborators(
        config, base_dir=ROOT, windows=windows, arity=arity,
        behavior_config=behavior, ip_profile=profile,
        pins=pins, dma=None, f1_words=config['f1_program_words'], isa=isa,
        refusals=refusals, label='APB', seed=5, cases=10, seconds=None)
    return config, profile, behavior, facts, irq, windows, arity, refusals, isa, fuzz


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_the_spi_profile_is_one_apb3_mmio_target_with_the_declared_eot_pulse(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, profile, behavior, facts, irq, _, _, _, _, _ = configuration(
        scenario, bus, irq_bits)
    assert config['source_profile'] == SPI_PROFILE
    assert config['source_behavior'] == SPI_BEHAVIOR
    assert config['f1_program_words'] == 4
    assert config['handler_wait_iterations'] == 128
    assert config['assume_single_clock'] is True
    # profile_protocol() reads the profile document, the way main() does.
    assert profile_protocol(load(config['source_profile'])) == 'apb3'
    endpoints = [endpoint for endpoint in profile.endpoints
                 if endpoint.function == 'mmio_slave']
    assert [endpoint.protocol for endpoint in endpoints] == [APB3]
    assert profile.address.window_size == 4096
    # One declared interrupt source, the transfer-end pulse; the scenario does not
    # restate it inline, it names the shared behavior file.
    assert [row.source_id for row in profile.interrupts] == ['spi_eot']
    assert facts is not None
    assert facts['declared_by'] == 'file'
    assert facts['declaration_path'] == SPI_BEHAVIOR

    def normalized(value):
        if isinstance(value, (list, tuple)):
            return tuple(tuple(item) if isinstance(item, (list, tuple)) else item
                         for item in value)
        return value

    # The file's facts are the ones already recorded for this RTL in the fixed
    # record scenario; the new declaration invents no trigger value or offset.
    fixed = load(FIXED_SPI_SCENARIO)
    for key, value in F5_FACTS.items():
        assert normalized(facts[key]) == value
        assert normalized(fixed[key]) == value
        assert normalized(behavior[key]) == value
    target_irq = irq
    if target_irq is None:
        # The Wishbone variant is refused by the CPU's unwired IRQ vector, not by
        # the target: the same declaration yields the same source on an OBI CPU.
        target_irq, target_reason = f5_declaration(
            behavior, profile, 'apb3', cpu_bus_kind='obi', cpu_irq_bits=1)
        assert target_reason is None
    assert target_irq is not None
    assert (target_irq['port'], target_irq['bit'], target_irq['pulse_ticks']) == (
        'events_o', 1, 16)
    assert target_irq['status_offset'] == 40
    assert target_irq['trigger_offsets'] == [16, 24, 0]
    # The four serial data inputs are constants; the pad-driving model is not used.
    assert [row['role'] for row in config['source_fixed_inputs']] == [
        'sdi0', 'sdi1', 'sdi2', 'sdi3']
    assert {row['value'] for row in config['source_fixed_inputs']} == {0}
    assert config['source_tuning']['fixed_inputs'] == config['source_fixed_inputs']


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_declared_windows_follow_the_profile_and_the_cpu_boot_contract(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, _, _, _, _, windows, _, _, _, _ = configuration(scenario, bus, irq_bits)
    assert windows == dict(ram_base=ram_base, ram_size=131072,
                           ip_base=1073745920, ip_size=4096,
                           dma_base=None, dma_size=None, data_base=data_base)
    window = config['target_window']
    assert window == {'base': windows['ip_base'], 'size': windows['ip_size']}
    assert window['base'] >= ram_base + windows['ram_size']
    assert 'dma_profile' not in config and 'dma_window' not in config


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_flow_arity_follows_the_cpu_irq_wiring_and_f6_is_refused_by_name(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    _, profile, behavior, _, irq, _, arity, refusals, _, _ = configuration(
        scenario, bus, irq_bits)
    if bus == 'obi':
        assert arity == {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3}
        assert refusals == {'F6': 'unsupported-f6:no-dma-model:APB'}
    else:
        assert arity == {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
        assert refusals['F5'] == f5_prefix
        assert refusals['F6'] == 'unsupported-f6:no-dma-model:APB'
        # The target itself declares the EOT source; the CPU bus is what refuses.
        _, reason = f5_declaration(behavior, profile, 'apb3', cpu_bus_kind='obi',
                                   cpu_irq_bits=1)
        assert reason is None


@pytest.mark.parametrize('scenario,bus,irq_bits,ram_base,data_base,f5_prefix', SCENARIOS)
def test_one_hundred_generated_inputs_pass_the_entry_gate(
        scenario, bus, irq_bits, ram_base, data_base, f5_prefix):
    config, _, _, _, _, windows, arity, refusals, isa, fuzz = configuration(
        scenario, bus, irq_bits)
    expected = ['F1', 'F2', 'F3', 'F4', 'F5'] if bus == 'obi' else [
        'F1', 'F2', 'F3', 'F4']
    assert fuzz['document']['flows'] == expected
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
        if record['flow'] == 'F5':
            # F5 records carry one word per declared trigger write, in order; the
            # firmware's write offsets come from the behavior declaration.
            assert len(record['fields']) == arity['F5'] == 3
            assert all(0 <= value <= 0xffffffff for value in record['fields'])
        seen.add(generated.flow)
    assert seen == set(expected)


def _peripheral_profiles():
    return sorted(ROOT.glob('configs/peripherals/*/component_profile.json'))


def _mmio_protocols(document):
    return {tuple(endpoint['protocol'])
            for endpoint in document.get('endpoints', [])
            if endpoint.get('function') == 'mmio_slave'}


def _families(document):
    source = document.get('source') or {}
    return source.get('root'), source.get('top_module')


def _scenario_references():
    used = set()
    for path in sorted(ROOT.glob('configs/scenarios/inprocess-*.json')):
        document = json.loads(path.read_text())
        source_profile = document.get('source_profile')
        if source_profile:
            used.add((ROOT / source_profile).resolve())
        # A multi-target declaration (``targets`` list) names each target's
        # profile the same way; scanning only ``source_profile`` would report
        # every profile of a target-list scenario as un-onboarded.
        for target in document.get('targets') or ():
            profile = target.get('profile') if isinstance(target, dict) else None
            if profile:
                used.add((ROOT / profile).resolve())
    return used


def test_no_unused_apb3_or_axi4lite_register_ip_remains():
    """The inventory tripwire: a new same-protocol IP profile must fail this test.

    Every APB3/AXI4-Lite profile in ``configs/peripherals`` belongs to a family
    that an ``inprocess-*.json`` scenario already selects.  The profiles that no
    scenario names directly are exactly the known alias declarations over those
    same families.  If someone adds an un-onboarded register IP profile, the
    computed set changes and this test fails instead of silently passing.
    """
    used = _scenario_references()
    register_profiles, unreferenced, families = [], set(), set()
    for path in _peripheral_profiles():
        document = json.loads(path.read_text())
        if not (_mmio_protocols(document) & MMIO_PROTOCOLS):
            continue
        register_profiles.append(path)
        families.add(_families(document))
        if path.resolve() not in used:
            unreferenced.add(str(path.relative_to(ROOT)))
    assert families == ADMITTED_FAMILIES
    assert unreferenced == UNREFERENCED_APB_AXI_PROFILES
    # No APB3/AXI4-Lite family without at least one scenario reference.
    referenced_families = {_families(json.loads(path.read_text()))
                           for path in register_profiles
                           if path.resolve() in used}
    assert referenced_families == ADMITTED_FAMILIES
    # 13 families plus the PULP I2C level-IRQ profile added for the
    # 2026-11-02 IRQ generalization, the five declared PULP-timer rate variants
    # (25 MHz, 10 MHz, 10 MHz timed, plus the 30 MHz and 60 MHz variants) added
    # for the per-model clock increment, and the 32.768 kHz RTC variant added
    # for the 2026-11-03 asynchronous-grid refusal; each belongs to an admitted
    # family and is referenced by an inprocess scenario, so the tripwire count
    # moves with them.
    assert len(register_profiles) == 20


def _request_refusal(profile):
    config = dict(source_profile=profile, active_id='blocked',
                  source_timing=dict(reset_assert_ticks=2, reset_release_ticks=2,
                                     max_wait_cycles=16),
                  source_fixed_inputs=[], source_tuning={})
    protocol = profile_protocol(load(profile))
    generic_target_request_from_profile(config, load(profile), protocol)


@pytest.mark.parametrize('profile,gate,refusal', BLOCKED_PROTOCOL_PROFILES)
def test_every_blocked_candidate_is_refused_by_name_before_any_rtl(profile, gate, refusal):
    document = load(profile)
    with pytest.raises(ValueError) as caught:
        if gate == 'protocol':
            profile_protocol(document)
        else:
            _request_refusal(profile)
    assert str(caught.value) == refusal
    # And it is genuinely not an APB3/AXI4-Lite register IP.
    assert not (_mmio_protocols(document) & MMIO_PROTOCOLS)


@pytest.mark.parametrize('profile,protocol', ADMITTED_NON_APB_AXI_PROFILES)
def test_the_admitted_non_apb_axi_profiles_map_to_their_protocol(profile, protocol):
    """The candidates this increment admitted are real MMIO slaves of their bus."""
    document = load(profile)
    assert profile_protocol(document) == protocol
    assert _mmio_protocols(document) == {tuple(
        {'tl-ul': ('tl-ul', '1'), 'wishbone': ('wishbone', 'classic')}[protocol])}
    assert not (_mmio_protocols(document) & MMIO_PROTOCOLS)
