"""Tests for the replacement samples: three existing generic paths, config-only.

Nothing here runs RTL.  The assertions are the ones a *declaration* can support:

* the replacement CPU scenario differs from the Ibex baseline only in CPU-side
  keys, and the CPU profile it selects is the pinned Wishbone/custom-IRQ/RVFI one;
* the UART target declares the four F5 facts through a behavior file, the
  profile's own endpoint names the port the file declares, and the scenario
  declares no DMA (so F6 has to be refused by name, not skipped);
* the replacement DMA is the same pinned ZipDMA RTL behind a different profile,
  with its own behavior file whose declared capability block the planner accepts;
* a capability or clear/pad declaration beyond what the device or this host can
  do has its own, clearly named, refusal scenario.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.dma_transfer import dma_transfer_declaration
from myfuzz.composition.inprocess_behavior import (
    HOST_DMA_CAPABILITY,
    HOST_SOURCE_EXECUTION,
    MAX_PIN_GROUPS,
    SOURCE_BEHAVIOR_KEYS,
    BehaviorError,
    dma_behavior,
    execution_refusals,
    source_behavior,
)
from myfuzz.local_harness.wishbone_dma_fields import dma_profile_edge_contract

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "configs/scenarios/p1-replacements"
CPU_SCENARIO = SCENARIOS / "cpu-picorv32-wb-irq-rvfi-f1f6.json"
UART_SCENARIO = SCENARIOS / "ip-opentitan-uart-local-tlul-f1f5.json"
DMA_SCENARIO = SCENARIOS / "dma-shared-profile-dma-f6.json"
REFUSALS = {
    "serial-peer": SCENARIOS / "refused-opentitan-uart-serial-peer.json",
    "three-step-clear": SCENARIOS / "refused-pulp-i2c-three-step-clear.json",
    "two-channel-behavior": SCENARIOS / "refused-zipdma-two-channel-behavior.json",
    "two-channel-profile": SCENARIOS / "refused-zipdma-two-channel-profile.json",
}
BASELINE = ROOT / "configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json"
UART_PROFILE = ROOT / "configs/peripherals/opentitan_uart_local/component_profile.json"
SHARED_DMA_PROFILE = ROOT / "configs/peripherals/shared_profile_dma/component_profile.json"
ZIPDMA_SMOKE_PROFILE = ROOT / "configs/peripherals/zipdma_smoke/component_profile.json"
TWO_CHANNEL_PROFILE = ROOT / (
    "configs/peripherals/p1_zipdma_two_channel_declaration/component_profile.json")
#: The keys a CPU replacement is allowed to change.  Every one of them is a
#: property of the CPU, of its boot contract or of its tick cost - never of the IP.
#: ``image_start``/``image_end`` are the one 128 KiB image window placed at the
#: CPU's own boot base (0x10000 for Ibex, 0 for this Wishbone top), so they move
#: together and keep the same span.
CPU_SIDE_KEYS = ("name", "description", "notes", "cpu_profile", "cpu_timing",
                 "cpu_irq_bit", "image_start", "image_end",
                 "handler_wait_iterations", "case_tick_budget",
                 "pulse_width_ticks")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def refusal(function, *args, **kwargs) -> str:
    with pytest.raises(BehaviorError) as raised:
        function(*args, **kwargs)
    return str(raised.value)


# ---------------------------------------------------------------------------
# The CPU replacement
# ---------------------------------------------------------------------------
def test_the_cpu_replacement_is_the_baseline_declaration_plus_cpu_keys() -> None:
    replacement = load(CPU_SCENARIO)
    baseline = load(BASELINE)

    for key in CPU_SIDE_KEYS:
        replacement.pop(key, None)
        baseline.pop(key, None)
    assert replacement == baseline


def test_the_replacement_cpu_profile_is_the_pinned_wishbone_custom_irq_cpu() -> None:
    scenario = load(CPU_SCENARIO)
    profile = load_component_profile(ROOT / scenario["cpu_profile"])

    assert profile.kind == "cpu"
    assert scenario["cpu_profile"] == "configs/cpus/picorv32_wb_irq_rvfi/component_profile.json"
    # The custom IRQ ABI is what makes F5 possible at all on this CPU; the
    # scenario declares the external bit the profile says is free.
    document = json.loads((ROOT / scenario["cpu_profile"]).read_text())
    abi = document["evidence"]["custom_irq_abi"]
    assert abi["abi"] == "picorv32_custom0"
    assert abi["input_port"] == "irq"
    assert abi["width"] == 32
    assert 3 <= scenario["cpu_irq_bit"] < 32
    # RVFI retirement plus the Wishbone single master are the two capabilities
    # F1 and F2-F4 need; both are named by the profile, not by the entry.
    endpoints = {row["endpoint_id"]: row for row in document["endpoints"]}
    assert endpoints["processor.memory"]["protocol"] == ["wishbone", "classic"]
    observed = {row["port"] for row in document["port_actions"]
                if row["action"] == "observe"}
    assert {"rvfi_valid", "rvfi_order", "rvfi_insn", "rvfi_pc_rdata"} <= observed


def test_the_replacement_cpu_scenario_declares_f5_and_f6_components() -> None:
    scenario = load(CPU_SCENARIO)

    assert scenario["source_profile"].endswith("pulp_timer_irq/component_profile.json")
    assert scenario["dma_profile"].endswith("zipdma_smoke/component_profile.json")
    assert len(scenario["trigger_writes"]) == 3
    assert scenario["status_offsets"] == [0]
    assert scenario["target_window"]["base"] != scenario["dma_window"]["base"]


# ---------------------------------------------------------------------------
# The UART target replacement
# ---------------------------------------------------------------------------
def test_the_uart_target_declares_the_four_f5_facts_for_its_real_port() -> None:
    scenario = load(UART_SCENARIO)
    target = scenario["targets"][0]
    facts = source_behavior({"source_behavior": target["behavior"]}, base_dir=ROOT)

    for key in ("source_port", "source_bit_offset", "trigger_writes", "status_offsets"):
        assert key in facts, key
    profile = load_component_profile(ROOT / target["profile"])
    endpoints = {row.endpoint_id: row for row in profile.endpoints}
    aliases = set()
    for interrupt in profile.interrupts:
        endpoint = endpoints[interrupt.endpoint_id]
        for field in endpoint.fields:
            if field.role == interrupt.role:
                aliases.update(field.aliases)
    assert facts["source_port"] == "intr_tx_done_o"
    assert facts["source_port"] in aliases
    assert facts["source_bit_offset"] == 0
    assert facts["clear_writes"] == [[0, 4]]
    assert facts["status_cause_bits"] == [2]
    # The port bit and the register bit are different facts: the profile only
    # states the former, and the behavior file states the latter with its RTL
    # evidence.
    assert interrupt_bit_for(profile, "tx_done") == 0


def interrupt_bit_for(profile, role):
    return next(intr.bit for intr in profile.interrupts if intr.role == role)


def test_the_uart_window_and_pin_constants_are_the_profile_ones() -> None:
    scenario = load(UART_SCENARIO)
    target = scenario["targets"][0]
    profile = load_component_profile(ROOT / target["profile"])

    assert target["window"]["size"] == profile.address.window_size
    assert target["window"]["base"] % profile.address.alignment == 0
    fixed = {(row["endpoint_id"], row["role"]): row["value"]
             for row in target["fixed_inputs"]}
    assert fixed == {("uart.pins", "rx"): 1}
    assert "dma_profile" not in scenario


def test_the_uart_scenario_declares_no_dma_so_f6_is_refused_by_name() -> None:
    scenario = load(UART_SCENARIO)

    assert "dma_profile" not in scenario
    assert "dma_behavior" not in scenario
    # The refusal the entry names for a DMA-less declaration is a fact of the
    # declaration, stated here so a later edit cannot quietly add a DMA.
    assert scenario["targets"][0]["behavior"].endswith("opentitan_uart_tx_done_f5.json")


# ---------------------------------------------------------------------------
# The DMA replacement: same pinned RTL, different profile
# ---------------------------------------------------------------------------
def test_the_replacement_dma_is_the_same_pinned_device_as_the_baseline() -> None:
    shared = load_component_profile(SHARED_DMA_PROFILE)
    smoke = load_component_profile(ZIPDMA_SMOKE_PROFILE)

    assert shared.component_id == smoke.component_id == "zipdma_selected_wishbone"
    assert (shared.source.revision, shared.source.top_module) == (
        smoke.source.revision, smoke.source.top_module)
    assert tuple(shared.source.files) == tuple(smoke.source.files)
    # The declarations differ: this is a different profile, not a different RTL.
    assert (ROOT / "configs/peripherals/shared_profile_dma/test_capability.json").is_file()
    assert json.loads(SHARED_DMA_PROFILE.read_text()) != json.loads(
        ZIPDMA_SMOKE_PROFILE.read_text())


def test_the_dma_scenario_behavior_declares_the_device_capabilities() -> None:
    scenario = load(DMA_SCENARIO)
    facts = dma_behavior(scenario, base_dir=ROOT)

    assert facts["capabilities"] == {"channels": 1, "beat_bytes": 4,
                                     "max_outstanding": 1, "burst_beats": 1}
    assert facts["capability_refusals"] == []
    for key, bound in facts["capabilities"].items():
        assert facts["capabilities"][key] <= HOST_DMA_CAPABILITY[key]


def test_the_dma_scenario_plan_keeps_the_declared_capability_facts() -> None:
    scenario = load(DMA_SCENARIO)
    profile = load_component_profile(ROOT / scenario["dma_profile"])
    artifact = {"dma_edge_contract": dma_profile_edge_contract(
        dict(profile.capabilities))}
    plan = dma_transfer_declaration(scenario, profile, artifact, base_dir=ROOT)

    assert plan["block_words"] == 4
    assert plan["declaration"]["declared_capabilities"] == {
        "channels": 1, "beat_bytes": 4, "max_outstanding": 1, "burst_beats": 1}
    assert plan["declaration"]["device_capabilities"] == {
        "channels": 1, "beat_bytes": 4, "max_outstanding": 1, "burst_beats": 1}


def test_the_dma_scenario_declares_no_f5_facts_so_f5_is_refused_by_name() -> None:
    scenario = load(DMA_SCENARIO)

    assert source_behavior(scenario, base_dir=ROOT) is None
    for key in SOURCE_BEHAVIOR_KEYS:
        assert key not in scenario


# ---------------------------------------------------------------------------
# The declarations that must be refused
# ---------------------------------------------------------------------------
def test_every_refusal_scenario_names_its_own_refusal() -> None:
    for label, path in REFUSALS.items():
        scenario = load(path)
        assert scenario["name"].startswith("p1-refused-"), label
        assert any("refus" in note.lower() for note in scenario["notes"]), label
    assert (ROOT / load(REFUSALS["serial-peer"])["targets"][0]["behavior"]).is_file()
    assert (ROOT / load(REFUSALS["three-step-clear"])["source_behavior"]).is_file()
    assert (ROOT / load(REFUSALS["two-channel-behavior"])["dma_behavior"]).is_file()
    assert (ROOT / load(REFUSALS["two-channel-profile"])["dma_profile"]).is_file()


def test_the_refused_uart_peer_is_now_a_complete_declaration() -> None:
    # P2 gave this host a framed serial driver, so the declaration this sample
    # shipped as "refused by name" now normalizes as a complete declaration: the
    # pad word plus one 8n1 peer.  What it still cannot be is a *run* on the UART
    # target, whose profile exposes no dir-resolved pad endpoint: that is the
    # entry's refusal (unsupported-pins:pin_groups:no-pad-endpoint), covered in
    # tests/integration/test_p2_pins_serial.py.
    scenario = load(REFUSALS["serial-peer"])
    behavior = scenario["targets"][0]["behavior"]

    facts = source_behavior({"source_behavior": behavior}, base_dir=ROOT)
    assert facts["pin_group_count"] == 2
    assert facts["pin_groups"][1]["kind"] == "serial_peer"
    assert execution_refusals(facts) == []


def test_the_refused_i2c_clear_is_the_three_step_sequence() -> None:
    scenario = load(REFUSALS["three-step-clear"])

    assert refusal(source_behavior,
                   {"source_behavior": scenario["source_behavior"]},
                   base_dir=ROOT) == "unsupported-behavior-execution:multi_step_clear:3"


def test_the_refused_two_channel_behavior_and_profile_are_declaration_only() -> None:
    two_channel = load_component_profile(TWO_CHANNEL_PROFILE)
    assert two_channel.capabilities["channels"] == 2
    assert two_channel.capabilities["beat_bytes"] == 8
    assert HOST_DMA_CAPABILITY["channels"] == 1
    assert HOST_DMA_CAPABILITY["beat_bytes"] == 4
    # P2 raised the pad-group and serial bounds: four pad groups, and one framed
    # serial peer per target.  The DMA bounds this test is about are unchanged.
    assert HOST_SOURCE_EXECUTION["pin_groups"] == MAX_PIN_GROUPS == 4
    assert HOST_SOURCE_EXECUTION["serial_peer"] is True
    assert HOST_SOURCE_EXECUTION["serial_peers"] == 1
