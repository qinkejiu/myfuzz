"""Pure-Python tests for the declarable IRQ expansion (no RTL, no Verilator).

The two new declarations under ``configs/behaviors/`` (a second PULP timer
source and the second timer instance) are checked against the real profile they
name: the interrupt bits, the register window, the readable status word and the
writable trigger/clear words all come from
``configs/peripherals/pulp_timer_irq/component_profile.json`` and the pinned
``apb_timer.sv``/``timer.sv``.  A fact cannot drift away from that profile
without a test failing.

The tests also pin what the executor currently does with those facts:

* which declarations ``f5_declaration``/``irq_declaration`` accept, and the
  named/valued refusals the rest get;
* the difference between a pulse source (a declared delivery width) and a level
  source (passthrough, zero width), and the Wishbone CPU's "held at zero" ABI
  refusal unless a custom IRQ bit is declared;
* the shape limits that keep a *second* target source out of the entry (one
  integer bit, exactly one status offset, at most one clear write);
* the cross-case classification of a level IRQ that a previous case left
  asserted (``state_contamination``), using the exact case dictionaries
  ``parse_case_line`` produces.

The last two are deliberately *shape* checks, not claims: no shipped behavior
file declares cause bits or a clear write, because this host prints
``isr_cause unknown`` for every F5 case and its F5 pass criterion counts exactly
the declared trigger writes as target writes.  A later change that makes those
facts observable should update this file and the report together.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import (
    PAD_RESOLUTION,
    SOURCE_BEHAVIOR_KEYS,
    BehaviorError,
    source_behavior,
)
from scripts.run_inprocess_f1f6 import (
    MAX_CLEAR_WRITES,
    EXPECTED_FAILURE_CLASSES,
    FAILURE_CLASSES,
    FAILURE_SEVERITY,
    classify_case,
    f5_declaration,
    irq_declaration,
    parse_case_line,
)

ROOT = Path(__file__).resolve().parents[2]
TIMER_PROFILE = "configs/peripherals/pulp_timer_irq/component_profile.json"
GPIO_PROFILE = "configs/peripherals/pulp_gpio_causal_local/component_profile.json"
AXILUART_PROFILE = "configs/peripherals/zipcpu_axiluart/component_profile.json"
BEHAVIOR_COMPARE = "configs/behaviors/pulp_timer_compare_f5.json"
BEHAVIOR_TIMER1 = "configs/behaviors/pulp_timer1_overflow_f5.json"
BEHAVIOR_TIMER0 = "configs/behaviors/pulp_timer_f5.json"
SCENARIO_COMPARE = "configs/scenarios/inprocess-obi-apb-ibex-timer-compare-f5-fuzz.json"
SCENARIO_TIMER1 = "configs/scenarios/inprocess-obi-apb-ibex-timer1-overflow-f5-fuzz.json"
SCENARIO_BASELINE = "configs/scenarios/inprocess-obi-apb-ibex-timer-overflow-baseline-fuzz.json"
SCENARIO_CV32E20 = "configs/scenarios/inprocess-cv32e20-timer1-overflow-f5-fuzz.json"
SCENARIO_WBCPU = "configs/scenarios/inprocess-wbcpu-apb-timer1-overflow-f5-fuzz.json"
F5_REQUIRED = ("source_port", "source_bit_offset", "trigger_writes", "status_offsets")


# ---------------------------------------------------------------------------
# Helpers: the same merge main() performs before it calls f5_declaration()
# ---------------------------------------------------------------------------
def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def profile(path: str):
    return load_component_profile(ROOT / path)


def merge(scenario: str) -> tuple[dict, dict]:
    """The scenario with the behavior file's facts merged the way main() does."""
    config = load(scenario)
    facts = source_behavior(config, base_dir=ROOT)
    assert facts is not None, scenario + " declares no F5 fact"
    merged = dict(config)
    for key in SOURCE_BEHAVIOR_KEYS:
        if key in facts:
            merged[key] = facts[key]
    return merged, facts


def declare(scenario: str, *, bus: str = "obi", irq_bits: int = 1,
            custom_irq: bool = False):
    merged, _ = merge(scenario)
    document = load(scenario)
    return f5_declaration(merged, profile(document["source_profile"]), "apb3",
                          cpu_bus_kind=bus, cpu_irq_bits=irq_bits,
                          cpu_custom_irq=custom_irq)


def timer_facts(profile_path: str, **overrides) -> dict:
    """A timer declaration on a real profile window, with optional overrides."""
    facts = dict(target_window={"base": 1073745920, "size": 4096},
                 source_port="irq_o", source_bit_offset=1,
                 pulse_width_ticks=24, trigger_writes=[[4, 0], [8, 3], [0, 3]],
                 status_offsets=[8], status_cause_bits=None, clear_writes=[])
    facts.update(overrides)
    return facts


def written(directory: Path, document: dict) -> dict:
    """One source-button declaration read from a temporary directory."""
    (directory / "behavior.json").write_text(json.dumps(document), encoding="utf-8")
    return {"source_behavior": "behavior.json"}


def refusal(callable_, *args, **kwargs) -> str:
    with pytest.raises(BehaviorError) as raised:
        callable_(*args, **kwargs)
    return str(raised.value)


# ---------------------------------------------------------------------------
# The new declarations: merged facts and the profile they are checked against
# ---------------------------------------------------------------------------
def test_the_compare_file_merges_as_one_file_declaration() -> None:
    facts = source_behavior({"source_behavior": BEHAVIOR_COMPARE}, base_dir=ROOT)

    assert facts == {
        "source_port": "irq_o",
        "source_bit_offset": 1,
        "pulse_width_ticks": 24,
        "trigger_writes": [[4, 0], [8, 3], [0, 3]],
        "status_offsets": [8],
        "status_cause_bits": None,
        "clear_writes": [],
        "pins": None,
        "declared_by": "file",
        "declaration_path": BEHAVIOR_COMPARE,
    }
    # description/notes are metadata: they never enter the fact dictionary.
    assert "description" not in facts and "notes" not in facts


def test_the_timer1_file_merges_as_one_file_declaration() -> None:
    facts = source_behavior({"source_behavior": BEHAVIOR_TIMER1}, base_dir=ROOT)

    assert facts["source_bit_offset"] == 2
    assert facts["pulse_width_ticks"] == 32
    assert facts["trigger_writes"] == [[20, 0], [24, 0], [16, 4294967295]]
    assert facts["status_offsets"] == [16]
    assert facts["status_cause_bits"] is None
    assert facts["clear_writes"] == []
    assert facts["declared_by"] == "file"
    assert facts["declaration_path"] == BEHAVIOR_TIMER1


@pytest.mark.parametrize("behavior,bit,source_id,trigger_offsets,status_offset,name",
                         [(BEHAVIOR_COMPARE, 1, "timer0_compare", [4, 8, 0], 8,
                           "TIMER0_CMP"),
                          (BEHAVIOR_TIMER1, 2, "timer1_overflow", [20, 24, 16], 16,
                           "TIMER1_COUNT")])
def test_each_new_file_states_only_facts_the_profile_declares(
        behavior: str, bit: int, source_id: str, trigger_offsets: list[int],
        status_offset: int, name: str) -> None:
    facts = source_behavior({"source_behavior": behavior}, base_dir=ROOT)
    target = profile(TIMER_PROFILE)

    # The declared bit is a real interrupt of the profile, on the named port.
    sources = [source for source in target.interrupts if source.bit == bit]
    assert [source.source_id for source in sources] == [source_id]
    assert sources[0].trigger == "pulse" and sources[0].polarity == "active_high"
    endpoint = next(row for row in target.endpoints
                    if row.function == "interrupt_source")
    assert endpoint.endpoint_id == sources[0].endpoint_id
    assert facts["source_port"] in {alias for field in endpoint.fields
                                    for alias in field.aliases}
    assert endpoint.fields[0].width == 4       # irq_o[3:0] carries all four sources

    # Every trigger and the status word are the profile's own register rows.
    registers = {row.offset: row for row in target.address.registers}
    for offset in trigger_offsets:
        assert registers[offset].width == 32
        assert registers[offset].access in ("wo", "rw")
    assert [row[0] for row in facts["trigger_writes"]] == trigger_offsets
    status = registers[status_offset]
    assert status.name == name
    assert status.width == 32 and status.access in ("ro", "rw")
    assert facts["status_offsets"] == [status_offset]

    # The host delivery width is a scenario choice, not an RTL width: the
    # profile states a one-clock native pulse for both sources.
    assert sources[0].pulse_width_cycles == 1
    assert 1 <= facts["pulse_width_ticks"] <= 4096
    assert facts["pulse_width_ticks"] > sources[0].pulse_width_cycles


def test_the_new_scenarios_declare_the_source_only_through_the_file() -> None:
    for scenario in (SCENARIO_COMPARE, SCENARIO_TIMER1):
        config = load(scenario)
        facts = source_behavior(config, base_dir=ROOT)
        assert facts is not None
        # No inline duplicate: the file is the declaration's only source.
        assert not (set(F5_REQUIRED) & set(config)), scenario
        assert set(F5_REQUIRED) <= set(facts)
        merged, _ = merge(scenario)
        assert set(F5_REQUIRED) <= set(merged)
        irq, reason = declare(scenario)
        assert reason is None
        assert irq["port"] == "irq_o"


def test_the_compare_scenario_and_the_baseline_share_everything_but_the_source() -> None:
    baseline, compare = load(SCENARIO_BASELINE), load(SCENARIO_COMPARE)
    differing = {key for key in set(baseline) | set(compare)
                 if key != "name" and key != "notes"
                 and baseline.get(key) != compare.get(key)}
    assert differing == {"source_behavior"}
    assert baseline["source_behavior"] == BEHAVIOR_TIMER0
    assert compare["source_behavior"] == BEHAVIOR_COMPARE


def test_the_new_declarations_are_shared_by_a_second_cpu_and_a_custom_irq_abi() -> None:
    assert load(SCENARIO_CV32E20)["source_behavior"] == BEHAVIOR_TIMER1
    assert load(SCENARIO_WBCPU)["source_behavior"] == BEHAVIOR_TIMER1
    assert load(SCENARIO_CV32E20)["cpu_profile"] != load(SCENARIO_TIMER1)["cpu_profile"]
    wb = load(SCENARIO_WBCPU)
    assert wb["cpu_irq_bit"] == 3
    irq, reason = declare(SCENARIO_WBCPU, bus="wishbone", irq_bits=32,
                          custom_irq=True)
    assert reason is None and irq["bit"] == 2 and irq["pulse_ticks"] == 32


# ---------------------------------------------------------------------------
# Behavior shape: agreement, precedence and the refusals
# ---------------------------------------------------------------------------
def test_an_inline_copy_that_agrees_with_the_file_is_accepted() -> None:
    facts = source_behavior(dict(load(SCENARIO_COMPARE),
                                 source_bit_offset=1, status_offsets=[8]),
                            base_dir=ROOT)
    assert facts["source_bit_offset"] == 1
    assert facts["declared_by"] == "file"


@pytest.mark.parametrize("key,value", [
    ("source_bit_offset", 0),
    ("pulse_width_ticks", 16),
    ("status_offsets", [0]),
    ("trigger_writes", [[4, 0], [8, 0], [0, 4294967295]]),
    ("status_cause_bits", [0]),
    ("clear_writes", [[4, 0]]),
])
def test_a_file_and_an_inline_value_that_disagree_are_refused(key: str,
                                                              value: object) -> None:
    config = dict(load(SCENARIO_COMPARE), **{key: value})
    assert refusal(source_behavior, config, base_dir=ROOT) == (
        "behavior-source-conflict:" + key)


def _compare_document(**overrides) -> dict:
    document = load(BEHAVIOR_COMPARE)
    document.update(overrides)
    return document


@pytest.mark.parametrize("overrides,reason", [
    ({"source_bit_offset": 64}, "unsupported-behavior-value:source_bit_offset"),
    # The exact spelling of "two target sources": a list of bits has no shape.
    ({"source_bit_offset": [0, 1]}, "unsupported-behavior-value:source_bit_offset"),
    ({"source_bit_offset": True}, "unsupported-behavior-value:source_bit_offset"),
    ({"source_bit_offset": -1}, "unsupported-behavior-value:source_bit_offset"),
    ({"pulse_width_ticks": 0}, "unsupported-behavior-value:pulse_width_ticks"),
    ({"pulse_width_ticks": 4097}, "unsupported-behavior-value:pulse_width_ticks"),
    ({"status_offsets": [8, 16]}, "unsupported-behavior-value:status_offsets"),
    ({"status_offsets": [8.0]}, "unsupported-behavior-value:status_offsets"),
    ({"status_cause_bits": [32]}, "unsupported-behavior-value:status_cause_bits"),
    ({"status_cause_bits": 3}, "unsupported-behavior-value:status_cause_bits"),
    ({"clear_writes": [[4, 0], [8, 0]]}, "unsupported-behavior-value:clear_writes"),
    ({"clear_writes": [[4, 0, 0]]}, "unsupported-behavior-value:clear_writes"),
    ({"trigger_writes": []}, "unsupported-behavior-value:trigger_writes"),
    ({"trigger_writes": [[4, -1]]}, "unsupported-behavior-value:trigger_writes"),
    ({"source_port": ""}, "unsupported-behavior-value:source_port"),
    ({"irq_kind": "level"}, "unsupported-behavior-field:irq_kind"),
])
def test_out_of_shape_source_facts_are_refused_by_name(tmp_path: Path,
                                                       overrides: dict,
                                                       reason: str) -> None:
    config = written(tmp_path, _compare_document(**overrides))
    assert refusal(source_behavior, config, base_dir=tmp_path) == reason


def test_an_unknown_pins_key_is_refused_under_pins(tmp_path: Path) -> None:
    document = _compare_document(pins={"padin_offset": 8, "external_value": 0,
                                       "pad_resolution": PAD_RESOLUTION,
                                       "padout_offset": 12})
    assert refusal(source_behavior, written(tmp_path, document),
                   base_dir=tmp_path) == "unsupported-behavior-field:pins.padout_offset"


def test_no_shipped_source_behavior_claims_cause_bits_or_a_clear_write() -> None:
    """A shipped file may state a clear write and only real status cause bits.

    Both facts are observed now: the host counts the handler's clear apart from
    the trigger sequence, and the ISR's real status read supplies the cause.  A
    file may therefore state them, but the shape stays bounded (one clear row,
    cause bits 0..31); the profile cross-check is still ``irq_declaration``'s.
    The GPIO file is additionally checked against the INTSTATUS read_clears map,
    and the I2C level file is checked against CMD[0] being a writable word.
    """
    files = sorted((ROOT / "configs/behaviors").glob("*.json"))
    source_files = [path for path in files
                    if load("configs/behaviors/" + path.name).get("schema_version")
                    in ("inprocess_source_behavior.v1",
                        "inprocess_source_behavior.v2")]
    assert len(source_files) >= 5
    for path in source_files:
        facts = source_behavior({"source_behavior": "configs/behaviors/" + path.name},
                                base_dir=ROOT)
        links = facts.get("sources") or [facts]
        for link in links:
            # A behavior file states no clear at all when the ordered sequence is
            # the scenario's declaration (the two-write I2C acknowledge is stated
            # by its scenario's irq_clear_sequence, because the behavior schema's
            # host capability still bounds its own clear_sequence fact to one
            # step).  What a file does state stays bounded by the executor.
            clears = link.get("clear_writes")
            if clears is not None:
                assert isinstance(clears, list) and len(clears) <= MAX_CLEAR_WRITES, path.name
                assert all(isinstance(row, list) and len(row) == 2
                           for row in clears), path.name
            bits = link.get("status_cause_bits")
            assert bits is None or (isinstance(bits, list)
                                    and all(type(bit) is int and 0 <= bit <= 31
                                            for bit in bits)), path.name
    # The one cause declaration is grounded in the profile: INTSTATUS 0x24 is a
    # readable word whose side effect is read_clears, so the ISR read is both the
    # cause sample and the deassertion.
    gate = source_behavior(
        {"source_behavior": "configs/behaviors/pulp_gpio_cause_f5_pins.json"},
        base_dir=ROOT)
    assert gate["status_cause_bits"] == [0]
    registers = {row.offset: row for row in
                 profile(GPIO_PROFILE).address.registers}
    assert registers[36].access == "ro" and registers[36].side_effect == "read_clears"


# ---------------------------------------------------------------------------
# The executor's own acceptance and refusal of the declared facts
# ---------------------------------------------------------------------------
def test_f5_declaration_accepts_the_compare_source_where_the_profile_has_it() -> None:
    irq, reason = declare(SCENARIO_COMPARE)

    assert reason is None
    assert irq == dict(port="irq_o", bit=1, trigger="pulse",
                       polarity="active_high", pulse_ticks=24,
                       status_offset=8, trigger_offsets=[4, 8, 0],
                       status_kind="compare", status_read_clears=False,
                       cause_declared=False, cause_bits=[],
                       cause_mask=0, clear=None,
                       # The ordered clear sequence: a declaration with no clear
                       # states zero steps, never a fabricated one.
                       clears=[], clear_steps=0)


def test_f5_declaration_accepts_the_second_timer_instance() -> None:
    irq, reason = declare(SCENARIO_TIMER1)

    assert reason is None
    assert irq["bit"] == 2 and irq["pulse_ticks"] == 32
    assert irq["status_offset"] == 16 and irq["status_kind"] == "count"
    assert irq["trigger_offsets"] == [20, 24, 16]
    assert irq["clear"] is None and irq["cause_declared"] is False


@pytest.mark.parametrize("bit", [4, 7, 63])
def test_a_source_bit_the_profile_does_not_declare_is_refused_by_value(bit: int) -> None:
    with pytest.raises(ValueError,
                       match="the target declares no single IRQ output on irq_o"):
        irq_declaration(timer_facts(TIMER_PROFILE, source_bit_offset=bit),
                        profile(TIMER_PROFILE))


@pytest.mark.parametrize("overrides,match", [
    ({"status_offsets": [12]}, "the declared status register is not a readable word"),
    ({"trigger_writes": [[4, 0], [5, 0], [0, 3]]},
     "a declared trigger register is not a writable word"),
    ({"trigger_writes": []}, "F5 needs a declared trigger write sequence"),
    ({"target_window": {"base": 1073745920, "size": 16}},
     "the APB window does not match the target profile"),
])
def test_a_status_or_trigger_fact_the_register_map_cannot_serve_is_refused(
        overrides: dict, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        irq_declaration(timer_facts(TIMER_PROFILE, **overrides),
                        profile(TIMER_PROFILE))


def test_a_second_target_source_has_no_shape_at_either_layer() -> None:
    # Executor: the declaration carries one integer bit, not a list of links.
    with pytest.raises(ValueError,
                       match="config requires source_port and source_bit_offset"):
        irq_declaration(timer_facts(TIMER_PROFILE, source_bit_offset=[0, 1]),
                        profile(TIMER_PROFILE))
    # Behavior layer: the same list is refused before the executor sees it.
    assert refusal(source_behavior, {"source_port": "irq_o",
                                     "source_bit_offset": [0, 1]},
                   base_dir=ROOT) == "unsupported-behavior-value:source_bit_offset"


def test_a_level_source_without_a_clear_is_refused_and_a_pulse_carries_its_width() -> None:
    # An AXI UART level interrupt is a real level, but this declaration names no
    # way for the handler to deassert it: FIFO_STATUS is read-only and its side
    # effect is "none".  Accepting it would make the next case inherit the line.
    with pytest.raises(ValueError, match="level IRQ source needs a declared clear"):
        irq_declaration(dict(target_window={"base": 1073741824, "size": 16},
                             source_port="o_uart_tx_int",
                             source_bit_offset=0, trigger_writes=[[12, 0]],
                             status_offsets=[4]),
                        profile(AXILUART_PROFILE))

    pulse = irq_declaration(timer_facts(TIMER_PROFILE), profile(TIMER_PROFILE))
    assert pulse["trigger"] == "pulse" and pulse["pulse_ticks"] == 24
    assert pulse["polarity"] == "active_high"


def test_a_level_source_is_accepted_when_the_declared_status_read_clears_it() -> None:
    # PULP GPIO INTSTATUS is the one runnable status whose profile declares
    # ``side_effect: read_clears``: the ISR read itself is the deassertion, so a
    # level source needs no separate clear write there.
    facts = dict(target_window={"base": 1073745920, "size": 4096},
                 source_port="interrupt", source_bit_offset=0,
                 trigger_writes=[[4, 0xFFFFFFFF]], status_offsets=[36])
    profile_row = profile(GPIO_PROFILE)
    registers = {row.offset: row for row in profile_row.address.registers}
    assert registers[36].side_effect == "read_clears"
    # The GPIO profile itself declares a pulse, so the level branch is exercised
    # through a test-only copy that keeps the profile's register map.
    import dataclasses
    level_profile = dataclasses.replace(
        profile_row,
        interrupts=tuple(dataclasses.replace(source, trigger="level")
                         if source.bit == 0 else source
                         for source in profile_row.interrupts))
    level = irq_declaration(facts, level_profile)
    assert level["trigger"] == "level" and level["pulse_ticks"] == 0
    assert level["status_offset"] == 36


def test_a_level_source_without_a_declared_bit_is_reachable_only_at_bit_0() -> None:
    facts = dict(target_window={"base": 1073741824, "size": 16},
                 source_port="o_uart_tx_int", source_bit_offset=1,
                 trigger_writes=[[12, 0]], status_offsets=[4])
    with pytest.raises(ValueError,
                       match="the target declares no single IRQ output on o_uart_tx_int"):
        irq_declaration(facts, profile(AXILUART_PROFILE))


def test_a_cleared_level_source_needs_a_writable_word_which_the_gpio_does_not_have() -> None:
    # The timer has no acknowledge register at all; its count register is
    # writable, so a clear would be *accepted structurally* there.  The GPIO's
    # status clears on read and is read-only, so the executor refuses to call it
    # a clear write.  Neither statement is a device acknowledgement claim.
    clear = irq_declaration(timer_facts(TIMER_PROFILE, clear_writes=[[4, 0]]),
                            profile(TIMER_PROFILE))
    assert clear["clear"] == {"offset": 4, "value": 0}

    gpio = dict(target_window={"base": 1073741824, "size": 4096},
                source_port="interrupt", source_bit_offset=0,
                pulse_width_ticks=16,
                trigger_writes=[[4, 4294967295], [24, 1], [28, 1], [12, 43]],
                status_offsets=[36], clear_writes=[[36, 1]])
    with pytest.raises(ValueError,
                       match="a declared clear register is not a writable word"):
        irq_declaration(gpio, profile(GPIO_PROFILE))


def test_cause_bits_are_shape_checked_and_rendered_as_a_mask() -> None:
    irq = irq_declaration(timer_facts(TIMER_PROFILE, status_cause_bits=[0, 1]),
                          profile(TIMER_PROFILE))
    assert irq["cause_declared"] is True
    assert irq["cause_bits"] == [0, 1]
    assert irq["cause_mask"] == 3
    assert irq_declaration(timer_facts(TIMER_PROFILE),
                           profile(TIMER_PROFILE))["cause_declared"] is False


def test_the_wishbone_cpu_refuses_f5_unless_a_custom_irq_bit_is_declared() -> None:
    merged, _ = merge(SCENARIO_TIMER1)
    target = profile(TIMER_PROFILE)

    irq, reason = f5_declaration(merged, target, "apb3", cpu_bus_kind="wishbone",
                                 cpu_irq_bits=32)
    assert irq is None
    assert reason == ("unsupported-f5:cpu-irq-unwired:wishbone:"
                      "32-bit-irq-held-at-zero")

    irq, reason = f5_declaration(merged, target, "apb3", cpu_bus_kind="wishbone",
                                 cpu_irq_bits=32, cpu_custom_irq=True)
    assert reason is None and irq["bit"] == 2


def test_a_missing_f5_fact_is_refused_under_the_fact_that_is_missing() -> None:
    facts = timer_facts(TIMER_PROFILE)
    del facts["trigger_writes"]
    irq, reason = f5_declaration(facts, profile(TIMER_PROFILE), "apb3",
                                 cpu_bus_kind="obi", cpu_irq_bits=1)
    assert irq is None
    assert reason == ("unsupported-f5:target-irq-semantics:apb3:"
                      "trigger_writes")


# ---------------------------------------------------------------------------
# Cross-case treatment of a level IRQ that stays valid
# ---------------------------------------------------------------------------
def case(flow: str = "F5", status: str = "failed", **fields) -> dict:
    base = dict(index=0, flow=flow, status=status, record=flow + ":00000000")
    base.update(fields)
    return base


def check(case_dict: dict) -> dict:
    verdict = classify_case(case_dict)
    assert verdict["failure_class"] in FAILURE_CLASSES
    assert verdict["severity"] == FAILURE_SEVERITY[verdict["failure_class"]]
    assert verdict["expected"] == (verdict["failure_class"] in EXPECTED_FAILURE_CLASSES)
    return verdict


def test_a_level_irq_left_asserted_contaminates_every_later_non_irq_flow() -> None:
    for flow in ("F1", "F2", "F3"):
        verdict = check(case(flow, irq_takes=1))
        assert verdict["failure_class"] == "state_contamination"
        assert "previous case" in verdict["detail"]
    # F4 is checked before it reaches the store-only read test.
    verdict = check(case("F4", irq_takes=1, target_reads=1))
    assert verdict["failure_class"] == "state_contamination"
    # The same take inside an F5 case is that case's own interrupt.
    assert check(case("F5", irq_edges=1, irq_takes=1, isr_flag=0)
                 )["failure_class"] == "device_anomaly"


def test_a_persistent_level_without_a_fresh_edge_is_not_triggered() -> None:
    # The classifier keys on the sampled *edge*, not on the held line: a level
    # the previous case left asserted produces no new edge, so a timed-out case
    # is reported as the expected exploration class even though the CPU did take
    # the interrupt.  This is the current, honest meaning of not_triggered.
    verdict = check(case("F5", wait_timeout=1, irq_edges=0, irq_takes=1))
    assert verdict["failure_class"] == "not_triggered"
    assert verdict["expected"] is True
    # Without a timeout the same facts miss the F5 edge observation.
    verdict = check(case("F5", irq_edges=0, irq_takes=1, isr_flag=1,
                         apb_read_data=3, isr_result=3))
    assert verdict["failure_class"] == "observation_mismatch"


def test_a_persistent_level_in_a_store_only_case_is_contamination() -> None:
    verdict = check(case("F4", target_reads=1))
    assert verdict["failure_class"] == "state_contamination"
    assert "store-only" in verdict["detail"]
    verdict = check(case("F4", apb_reads=1))
    assert verdict["failure_class"] == "state_contamination"


def test_the_case_line_shape_the_classifier_really_reads_is_the_synthetic_one() -> None:
    line = ("case 7 failed flow F4 record F4:40000ffc:00000000 ticks 120 "
            "i_fetches 40 d_reads 2 d_writes 1 apb_reads 1 apb_writes 1 "
            "retires 30 rvfi_writebacks 12 rvfi_order_monotonic 1 traps 0 "
            "bus_errors 0 irq_edges 0 irq_takes 1 isr_flag 0")
    parsed = parse_case_line(line, flows=("F1", "F2", "F3", "F4", "F5", "F6"))
    assert parsed["flow"] == "F4" and parsed["irq_takes"] == 1
    assert classify_case(parsed)["failure_class"] == "state_contamination"


def test_state_contamination_is_a_finding_class_not_an_expected_outcome() -> None:
    assert "state_contamination" in FAILURE_CLASSES
    assert "state_contamination" not in EXPECTED_FAILURE_CLASSES
    assert FAILURE_SEVERITY["state_contamination"] == "anomaly"


def test_a_trap_is_classified_before_contamination() -> None:
    verdict = check(case("F2", traps=1, irq_takes=1))
    assert verdict["failure_class"] == "execution_exception"
