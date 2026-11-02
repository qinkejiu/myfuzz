"""Pure-Python tests for the IRQ generalization increment (no RTL, no Verilator).

Three declarations are pinned here, each against the real profile it names:

* **arbitrary link topology** - a global table over several declaring targets and
  several links per target.  The numbering, the two-member synthetic row, the
  record arity gate and the "one link per member target" rule are checked without
  a model: they are declaration facts the host must not re-derive per device.
* **an ordered multi-step clear** - the PULP I2C's acknowledge is two register
  writes (``CMD=1`` clears ``irq_flag``, ``CMD=0`` releases the held ``iack``;
  ``apb_i2c.sv:128,189-193``).  The declaration is accepted as an ordered
  sequence, bounded to the handler's two cell pairs, and every malformed shape is
  refused by name.
* **a CPU with a multi-bit interrupt entry that can really take it** - the CVA6
  ``irq_i`` port.  The contract is admitted only when the built model exports the
  declared entry *and* the retirement face states a take witness, and the profile
  fact that ``irq_i[1]`` is held at a constant is reported as a *partial* vector
  instead of being counted as a vector.

Nothing here runs a model; the real RTL evidence is ``runs/p1-irq/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.multi_target import targets_for_f5
from scripts.run_inprocess_f1f6 import (
    AXI4_F5_REFUSAL,
    AXI4_F5_WITNESS_REFUSAL,
    IRQ_CPU_PARTIAL_VECTOR_PREFIX,
    MAX_CLEAR_WRITES,
    advanced_irq_refusals,
    cpu_irq_entry,
    f5_both_link,
    f5_both_selected,
    f5_case_link,
    f5_declaration,
    f5_link_table,
    f5_record_word_counts,
    irq_declaration,
    packed_axi4_irq_contract,
    parse_record,
)

ROOT = Path(__file__).resolve().parents[2]
TIMER_PROFILE = "configs/peripherals/pulp_timer_irq/component_profile.json"
I2C_PROFILE = "configs/peripherals/pulp_i2c_irq/component_profile.json"
SPI_PROFILE = "configs/peripherals/inprocess_verify_pulp_spi_irq/component_profile.json"
CVA6_PROFILE = "configs/cpus/cva6/component_profile.json"
IBEX_PROFILE = "configs/cpus/ibex_rvfi_local/component_profile.json"
WINDOWS = dict(data_base=0x10000, ram_base=0x10000, ram_size=0x20000,
               ip_targets=[dict(base=0x40001000, size=4096),
                           dict(base=0x40002000, size=4096),
                           dict(base=0x20002000, size=4096)],
               target_count=3)


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def profile(path: str):
    return load_component_profile(ROOT / path)


def timer_facts(window=0x40001000, **overrides) -> dict:
    facts = dict(target_window=dict(base=window, size=4096),
                 source_port="irq_o", source_bit_offset=0,
                 pulse_width_ticks=16, trigger_writes=[[4, 0], [8, 0], [0, 0xFFFFFFFF]],
                 status_offsets=[0], status_cause_bits=None, clear_writes=[])
    facts.update(overrides)
    return facts


def timer_link(base=0x40001000, bit=0) -> dict:
    irq = irq_declaration(timer_facts(base, source_bit_offset=bit),
                          profile(TIMER_PROFILE))
    return {**irq, "target_index": 0, "base": base}


def i2c_link(base=0x40002000, target=1) -> dict:
    irq = irq_declaration(
        dict(target_window=dict(base=base, size=4096), source_port="interrupt_o",
             source_bit_offset=0, trigger_writes=[[4, 0xC0], [16, 0x5A], [20, 0x10]],
             status_offsets=[12], status_cause_bits=[0], clear_writes=[[20, 1]]),
        profile(I2C_PROFILE))
    return {**irq, "target_index": target, "base": base}


def spi_link(base=0x20002000, target=2) -> dict:
    irq = irq_declaration(
        dict(target_window=dict(base=base, size=4096), source_port="events_o",
             source_bit_offset=1, pulse_width_ticks=16,
             trigger_writes=[[16, 0x10000], [24, 0xAB], [0, 2]],
             status_offsets=[40], status_cause_bits=None, clear_writes=[]),
        profile(SPI_PROFILE))
    return {**irq, "target_index": target, "base": base}


def numbered(*links) -> list[dict]:
    """The global numbering the entry performs: one index per physical link."""
    return [{**link, "index": index, "base": link.get("base")}
            for index, link in enumerate(links)]


# ---------------------------------------------------------------------------
# 1. Arbitrary topology: one global table over targets and links
# ---------------------------------------------------------------------------
def test_three_targets_number_three_global_links_and_pair_the_first_two() -> None:
    links = numbered(timer_link(), i2c_link(), spi_link())
    irq = dict(links=links, source_count=len(links), multi_target=True)

    table = f5_link_table(irq)
    assert [row["target_index"] for row in links] == [0, 1, 2]
    assert [row["index"] for row in table] == [0, 1, 2]
    # One record shape per link: the index followed by that link's three trigger
    # values, and the same shape for every row.
    assert f5_record_word_counts(table) == (4,)
    record = parse_record("F5:2:00010000:000000ab:00000002", windows=WINDOWS,
                          arity=dict(F5=4), f5_links=table,
                          f5_target_index=0)
    assert tuple(record["fields"]) == (2, 0x10000, 0xAB, 2)
    assert f5_case_link(irq, record)["target_index"] == 2
    assert f5_both_link(irq) is None


def test_a_two_member_pair_is_a_separate_row_and_is_not_a_physical_link() -> None:
    links = numbered(timer_link(), i2c_link(), spi_link())
    both = dict(index=3, mode="both", members=[links[0], links[1]],
                trigger_offsets=links[0]["trigger_offsets"] + links[1]["trigger_offsets"],
                status_offsets=[links[0]["status_offset"], links[1]["status_offset"]])
    irq = dict(links=links, both=both, source_count=len(links), multi_target=True)
    table = f5_link_table(irq)
    assert [row["index"] for row in table] == [0, 1, 2, 3]
    # The pair's record is longer, and the gate states both accepted shapes.
    assert f5_record_word_counts(table) == (4, 7)
    pair = parse_record(
        "F5:3:00000000:00000000:ffffffff:000000c0:0000005a:00000010",
        windows=WINDOWS, arity=dict(F5=4), f5_links=table, f5_target_index=0)
    assert pair["fields"][0] == 3
    assert f5_both_selected(irq, pair)
    assert f5_both_link(irq)["members"][0]["target_index"] == 0
    # A link's own record cannot borrow another row's length.
    with pytest.raises(ValueError, match="needs 4 or 7 word"):
        parse_record("F5:2:00010000:000000ab", windows=WINDOWS, arity=dict(F5=4),
                     f5_links=table, f5_target_index=0)
    with pytest.raises(ValueError, match="is not one of the 4 declared links"):
        parse_record("F5:4:0:0:0", windows=WINDOWS, arity=dict(F5=4),
                     f5_links=table, f5_target_index=0)


def test_two_links_on_one_target_are_numbered_but_cannot_be_a_pair() -> None:
    overflow = timer_link(bit=0)
    compare = timer_link(bit=1, base=0x40001000)
    compare = {**compare, "status_offset": 8, "trigger_offsets": [4, 8, 0]}
    links = numbered(overflow, compare, i2c_link(target=1))
    assert [row["target_index"] for row in links] == [0, 0, 1]
    # Every link still has its own global index and its own status word, which is
    # what the single-link path needs; the pair rule is stated by the entry
    # (unsupported-f5:both-needs-one-link-per-target) because the pair's
    # per-target read/clear counters cannot tell two links of one target apart.
    assert {row["target_index"] for row in links} == {0, 1}
    assert links[1]["status_offset"] == 8


def test_targets_for_f5_selects_only_targets_that_declare_the_facts() -> None:
    targets = [dict(index=0, name="timer", active_id="t"),
               dict(index=1, name="i2c", active_id="i"),
               dict(index=2, name="plain", active_id="p")]
    behaviors = [dict(source_port="irq_o", source_bit_offset=0,
                      trigger_writes=[[0, 0]], status_offsets=[0]),
                 dict(source_port="interrupt_o", source_bit_offset=0,
                      trigger_writes=[[0, 0]], status_offsets=[12]),
                 None]
    rows = targets_for_f5(targets, behaviors)
    assert [row["index"] for row in rows] == [0, 1]


# ---------------------------------------------------------------------------
# 2. The ordered multi-step clear
# ---------------------------------------------------------------------------
def two_step_facts(window=0x40000000) -> dict:
    return dict(target_window=dict(base=window, size=4096),
                source_port="interrupt_o", source_bit_offset=0,
                trigger_writes=[[4, 0xC0], [16, 0x5A], [20, 0x10]],
                status_offsets=[12], status_cause_bits=[0],
                clear_sequence=[[20, 1], [20, 0]])


def test_an_ordered_two_write_clear_is_accepted_and_keeps_its_first_step() -> None:
    irq = irq_declaration(two_step_facts(), profile(I2C_PROFILE))
    # ``clear`` is the first (acknowledging) write every saved case line names;
    # ``clears`` is the whole ordered sequence the handler performs.
    assert irq["clear"] == dict(offset=20, value=1)
    assert irq["clears"] == [dict(offset=20, value=1), dict(offset=20, value=0)]
    assert irq["clear_steps"] == 2
    assert irq["trigger"] == "level"


def test_the_ordered_clear_is_bounded_by_the_handler_cells() -> None:
    facts = two_step_facts()
    facts["clear_sequence"] = [[20, 1], [20, 0], [20, 0]]
    with pytest.raises(ValueError, match="at most 2 declared clear writes"):
        irq_declaration(facts, profile(I2C_PROFILE))
    assert MAX_CLEAR_WRITES == 2


def test_a_clear_sequence_that_names_a_read_step_is_refused_by_name() -> None:
    facts = two_step_facts()
    facts["clear_sequence"] = [{"kind": "read", "offset": 12}]
    with pytest.raises(ValueError, match="read step is not executed by this host"):
        irq_declaration(facts, profile(I2C_PROFILE))


def test_two_spellings_of_one_clear_are_the_ambiguous_form() -> None:
    facts = two_step_facts()
    facts["clear_writes"] = [[20, 1]]
    with pytest.raises(ValueError, match="both clear_writes and clear_sequence"):
        irq_declaration(facts, profile(I2C_PROFILE))


@pytest.mark.parametrize("sequence, match", [
    ([[20], [20, 0]], "a clear sequence pair needs offset and value"),
    ([{"kind": "poke", "offset": 20, "value": 1}], "read step is not executed"),
    ([{"kind": "write", "offset": 8, "value": 1}], "not a writable word"),
    ([{"kind": "write", "offset": 20}], "write step needs offset and value"),
    ("CMD=1", "must be a non-empty list"),
])
def test_every_malformed_clear_sequence_shape_is_refused(sequence, match) -> None:
    facts = two_step_facts()
    facts["clear_sequence"] = sequence
    with pytest.raises(ValueError, match=match):
        irq_declaration(facts, profile(I2C_PROFILE))


def test_the_shipped_two_step_scenario_declares_the_i2c_acknowledge_sequence() -> None:
    scenario = load("configs/scenarios/inprocess-obi-apb-pulp-i2c-two-step-clear-f5.json")
    behavior = load("configs/behaviors/pulp_i2c_level_two_step_f5.json")
    # The sequence is one declaration: the scenario states it (the executor's
    # spelling), and the behavior file documents the RTL facts without repeating
    # a single clear_writes row that would conflict with it.
    assert scenario["irq_clear_sequence"] == [[20, 1], [20, 0]]
    assert "clear_writes" not in behavior
    assert "clear_sequence" not in behavior
    registers = {row.offset: row for row in profile(I2C_PROFILE).address.registers}
    assert registers[20].name == "CMD" and registers[20].access == "rw"
    facts = dict(two_step_facts(0x40000000))
    facts.update(source_port=behavior["source_port"],
                 source_bit_offset=behavior["source_bit_offset"],
                 trigger_writes=behavior["trigger_writes"],
                 status_offsets=behavior["status_offsets"],
                 status_cause_bits=behavior["status_cause_bits"])
    irq = irq_declaration(facts, profile(I2C_PROFILE))
    assert irq["clear_steps"] == 2 and irq["clears"][1] == dict(offset=20, value=0)


# ---------------------------------------------------------------------------
# 3. The CPU's multi-bit interrupt entry
# ---------------------------------------------------------------------------
def cva6_document(*, irq_export=True, bundle=True, width=2) -> dict:
    exports = []
    if irq_export:
        exports.append(dict(physical_port="irq_i", direction="input",
                            width=width, runtime_name="irq_i",
                            endpoint_id="processor.interrupts",
                            role="machine_external"))
    if bundle:
        exports.append(dict(physical_port="rvfi_probes_o", direction="output",
                            width=6974, runtime_name="rvfi_probes_o"))
    return dict(module_name="local_runtime_processor", physical_exports=exports)


def test_the_cva6_contract_needs_both_a_driven_entry_and_a_take_witness() -> None:
    cpu_profile = profile(CVA6_PROFILE)
    contract = packed_axi4_irq_contract(cva6_document(), cpu_profile)
    assert contract == dict(width=2, runtime_name="irq_i", physical_port="irq_i")
    assert cpu_irq_entry(cva6_document(), cpu_profile.cpu)["width"] == 2
    # No entry: nothing can be driven.  Entry but no probe bundle: the line could
    # be driven, but the CPU's acceptance would have to be inferred from a store.
    assert packed_axi4_irq_contract(cva6_document(irq_export=False),
                                    cpu_profile) is None
    assert packed_axi4_irq_contract(cva6_document(bundle=False), cpu_profile) is None
    assert packed_axi4_irq_contract(cva6_document(width=0), cpu_profile) is None


def test_f5_on_the_packed_axi4_cpu_names_which_fact_is_missing() -> None:
    facts = timer_facts()
    irq, reason = f5_declaration(facts, profile(TIMER_PROFILE), "apb3",
                                 cpu_bus_kind="axi4", cpu_irq_bits=2,
                                 cpu_irq_witness=False,
                                 cpu_irq_refusal=AXI4_F5_WITNESS_REFUSAL)
    assert irq is None and reason == AXI4_F5_WITNESS_REFUSAL
    assert "no-take-witness" in reason
    irq, reason = f5_declaration(facts, profile(TIMER_PROFILE), "apb3",
                                 cpu_bus_kind="axi4", cpu_irq_bits=2,
                                 cpu_irq_witness=False)
    assert irq is None and reason == AXI4_F5_REFUSAL
    # With both facts the same declaration is accepted: the entry is admitted by
    # the wire it has, not by the wire another CPU has.
    irq, reason = f5_declaration(facts, profile(TIMER_PROFILE), "apb3",
                                 cpu_bus_kind="axi4", cpu_irq_bits=2,
                                 cpu_irq_witness=True)
    assert reason is None and irq["bit"] == 0


def test_the_cva6_profile_reports_a_partial_vector_not_a_vector() -> None:
    refusals = advanced_irq_refusals(load(CVA6_PROFILE), [load(TIMER_PROFILE)])
    # The entry port is multi-bit, but the profile itself holds irq_i[1] (the
    # supervisor-external line) at constant 0: only the machine-external bit is
    # driven and taken, so a per-source CPU vector is not claimed.
    assert refusals["cpu_vector"].startswith(IRQ_CPU_PARTIAL_VECTOR_PREFIX)
    assert "irq_i[1]=constant-0-not-taken" in refusals["cpu_vector"]
    assert refusals["cpu_vector_entry"]["held_bits"] == [
        dict(port="irq_i", bit=1, value=0)]
    assert refusals["cpu_vector_entry"]["role"] == "machine_external"
    # No NMI port at all and no PLIC endpoint: both stay named refusals, and the
    # PLIC refusal carries the RTL fact that no profile composes it.
    assert refusals["nmi"].startswith("unsupported-irq:nmi-uncomposed:cva6")
    assert refusals["plic"].startswith("unsupported-irq:plic-not-composed:cva6")
    assert refusals["plic_rtl"]["composed_by_profile"] is False
    assert refusals["plic_rtl"]["cpu_target_port"] is False
    assert "rv_plic.sv" in refusals["plic_rtl"]["rtl"]


def test_the_ibex_profile_reports_the_nmi_wire_it_holds_inactive() -> None:
    refusals = advanced_irq_refusals(load(IBEX_PROFILE), [load(TIMER_PROFILE)])
    assert refusals["nmi"] == "unsupported-irq:nmi-uncomposed:ibex_rvfi_local:" \
                              "irq_nm_i=constant-0"
    assert refusals["cpu_vector"].startswith("unsupported-irq:cpu-multibit-vector:")
    assert refusals["cpu_vector_entry"]["held_bits"] == []
