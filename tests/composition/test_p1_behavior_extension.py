"""Tests for the behavior-schema extension and the replacement declarations.

Two layers are checked here and they are kept apart on purpose:

* the declaration layer (``myfuzz.composition.inprocess_behavior``) normalizes
  the new spellings - an ordered ``clear_sequence``, named ``pin_groups`` with a
  serial peer, and a DMA ``capabilities`` block - and refuses every shape it
  cannot execute *by name*, never by narrowing the declaration;
* the planner (``myfuzz.composition.dma_transfer``) is the authority that refuses
  a declared DMA capability above the selected device's pinned facts.

No RTL is elaborated, built or simulated by this file: every assertion is about a
normalized declaration or a named refusal.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.dma_transfer import (
    DmaTransferError,
    dma_transfer_declaration,
    validate_transfer_plan,
)
from myfuzz.composition.inprocess_behavior import (
    HOST_DMA_CAPABILITY,
    HOST_SOURCE_EXECUTION,
    PAD_RESOLUTION,
    SOURCE_BEHAVIOR_KEYS,
    SOURCE_BEHAVIOR_SCHEMA,
    BehaviorError,
    dma_behavior,
    dma_capabilities,
    dma_capability_refusals,
    execution_refusals,
    source_behavior,
)
from myfuzz.local_harness.wishbone_dma_fields import dma_profile_edge_contract

ROOT = Path(__file__).resolve().parents[2]
BEHAVIORS = "configs/behaviors"
DECLARATION_ONLY = BEHAVIORS + "/declaration-only"
UART_BEHAVIOR = BEHAVIORS + "/opentitan_uart_tx_done_f5.json"
ZIPDMA_CAPABILITY_BEHAVIOR = BEHAVIORS + "/zipdma_capability_f6.json"
TWO_CHANNEL_BEHAVIOR = DECLARATION_ONLY + "/zipdma_two_channel_f6.json"
THREE_STEP_BEHAVIOR = DECLARATION_ONLY + "/pulp_i2c_three_step_clear_f5.json"
SERIAL_PEER_BEHAVIOR = DECLARATION_ONLY + "/opentitan_uart_serial_peer_f5.json"
TWO_PAD_BEHAVIOR = DECLARATION_ONLY + "/two_pad_groups_f5.json"
#: P2 declaration-only files: the frame shapes and role sets the host's serial
#: driver still refuses by name.
TWO_STOP_BIT_BEHAVIOR = DECLARATION_ONLY + "/uart_two_stop_bits_peer_f5.json"
HALF_DUPLEX_BEHAVIOR = DECLARATION_ONLY + "/uart_half_duplex_peer_f5.json"
TWO_SERIAL_PEER_BEHAVIOR = DECLARATION_ONLY + "/uart_two_serial_peers_f5.json"
AMBIGUOUS_BEHAVIOR = DECLARATION_ONLY + "/ambiguous_clear_f5.json"
ZIPDMA_PROFILE = ROOT / "configs/peripherals/zipdma_smoke/component_profile.json"
TWO_CHANNEL_PROFILE = ROOT / (
    "configs/peripherals/p1_zipdma_two_channel_declaration/component_profile.json")
TIMER_SCENARIO = ROOT / "configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json"

MINIMAL = {
    "schema_version": SOURCE_BEHAVIOR_SCHEMA,
    "source_port": "irq_o",
    "source_bit_offset": 0,
    "trigger_writes": [[4, 0], [8, 0], [0, 4294967295]],
    "status_offsets": [0],
    "status_cause_bits": None,
}


def written(directory: Path, document: dict, name: str = "device.json") -> dict:
    (directory / name).write_text(json.dumps(document), encoding="utf-8")
    return {"source_behavior": name}


def refusal(function, *args, **kwargs) -> str:
    with pytest.raises(BehaviorError) as raised:
        function(*args, **kwargs)
    return str(raised.value)


def facts_of(path: str) -> dict:
    return source_behavior({"source_behavior": path}, base_dir=ROOT)


def pad_group(**overrides) -> dict:
    group = {"name": "pads", "kind": "dir_resolved_pad_word",
             "padin_offset": 8, "external_value": 0,
             "pad_resolution": PAD_RESOLUTION}
    group.update(overrides)
    return group


def serial_group(**overrides) -> dict:
    group = {"name": "serial0", "kind": "serial_peer", "rx_role": "rx",
             "tx_role": "tx", "idle_level": 1, "bit_ticks": 434, "frame": "8n1"}
    group.update(overrides)
    return group


# ---------------------------------------------------------------------------
# The minimal declaration still normalizes to exactly what it always did
# ---------------------------------------------------------------------------
def test_a_minimal_behavior_still_normalizes_without_new_keys(tmp_path: Path) -> None:
    facts = source_behavior(written(tmp_path, MINIMAL), base_dir=tmp_path)

    assert set(facts) <= set(SOURCE_BEHAVIOR_KEYS) | {
        "pins", "declared_by", "declaration_path"}
    assert facts["trigger_writes"] == MINIMAL["trigger_writes"]
    assert "clear_writes" not in facts
    assert "clear_sequence" not in facts and "pin_groups" not in facts
    assert facts["declared_by"] == "file"


def test_a_single_write_step_is_the_executor_single_clear_write(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_sequence=[{"kind": "write", "offset": 0, "value": 1}])
    facts = source_behavior(written(tmp_path, document), base_dir=tmp_path)

    # The declared sequence is kept and the flat fact the host consumes is
    # derived from it: one write step is one clear write, not a new mechanism.
    assert facts["clear_sequence"] == [{"kind": "write", "offset": 0, "value": 1}]
    assert facts["clear_writes"] == [[0, 1]]
    assert execution_refusals(facts) == []


def test_the_pair_shorthand_for_one_clear_write_normalizes(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_sequence=[[0, 1]])
    facts = source_behavior(written(tmp_path, document), base_dir=tmp_path)

    assert facts["clear_sequence"] == [{"kind": "write", "offset": 0, "value": 1}]
    assert facts["clear_writes"] == [[0, 1]]


# ---------------------------------------------------------------------------
# An ordered clear sequence: normalized, then refused by name if > one step
# ---------------------------------------------------------------------------
def test_two_clear_writes_normalize_and_are_refused_by_name(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_sequence=[[20, 1], [20, 0]])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "unsupported-behavior-execution:multi_step_clear:2")

    # The same declaration normalizes when the host's declared capability allows
    # it: the parser is reusable, the host bound is a reviewable fact.
    facts = source_behavior(
        written(tmp_path, dict(MINIMAL, clear_sequence=[[20, 1], [20, 0]]),
                name="two.json"), base_dir=tmp_path, limits={"clear_steps": 2,
                                                             "pin_groups": 1,
                                                             "pin_group_kinds": ("dir_resolved_pad_word",),
                                                             "serial_peer": False})
    assert [step["value"] for step in facts["clear_sequence"]] == [1, 0]
    assert facts["clear_writes"] == []


def test_a_read_step_is_refused_by_name(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_sequence=[{"kind": "read", "offset": 12}])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "unsupported-behavior-execution:clear_read_step")


def test_a_write_read_write_sequence_is_refused_for_its_length(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_sequence=[{"kind": "write", "offset": 20, "value": 1},
                                             {"kind": "read", "offset": 12},
                                             {"kind": "write", "offset": 20, "value": 0}])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "unsupported-behavior-execution:multi_step_clear:3")


@pytest.mark.parametrize("sequence,reason", [
    ([], "unsupported-behavior-value:clear_sequence"),
    ([[0, 1, 2]], "unsupported-behavior-value:clear_sequence"),
    ([{"kind": "pause", "offset": 0}], "unsupported-behavior-value:clear_sequence.kind"),
    ([{"kind": "write", "offset": 0}], "unsupported-behavior-value:clear_sequence.value"),
    ([{"kind": "write", "offset": -1, "value": 1}],
     "unsupported-behavior-value:clear_sequence.offset"),
    ([{"kind": "read", "offset": 0, "value": 1}],
     "unsupported-behavior-field:clear_sequence.value"),
    ([{"kind": "write", "offset": 0, "value": 1, "frobnicate": 1}],
     "unsupported-behavior-field:clear_sequence.frobnicate"),
    ([[0, 1], {"kind": "write", "offset": 0, "value": 1}],
     "unsupported-behavior-value:clear_sequence.mixed"),
])
def test_out_of_shape_clear_sequences_are_refused_by_name(tmp_path: Path,
                                                          sequence: list,
                                                          reason: str) -> None:
    document = dict(MINIMAL, clear_sequence=sequence)
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == reason


def test_stating_both_clear_spellings_is_refused_as_ambiguous(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_writes=[[0, 1]], clear_sequence=[[0, 1]])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "behavior-source-conflict:clear_writes")


def test_the_legacy_clear_writes_row_stays_bounded_to_one(tmp_path: Path) -> None:
    document = dict(MINIMAL, clear_writes=[[0, 1], [0, 0]])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "unsupported-behavior-value:clear_writes")


# ---------------------------------------------------------------------------
# Named pad groups and a serial peer
# ---------------------------------------------------------------------------
def test_one_dir_group_normalizes_and_is_executable(tmp_path: Path) -> None:
    document = dict(MINIMAL, pin_groups=[pad_group(direction="inout", hold_ticks=4)])
    facts = source_behavior(written(tmp_path, document), base_dir=tmp_path)

    assert facts["pin_group_count"] == 1
    assert facts["pin_groups"] == [{"name": "pads", "kind": "dir_resolved_pad_word",
                                    "direction": "inout", "hold_ticks": 4,
                                    "padin_offset": 8, "external_value": 0,
                                    "pad_resolution": PAD_RESOLUTION}]
    # The one pad word this host resolves is derived from the group, so the
    # group spelling is usable by the current host instead of being report-only.
    assert facts["pins"] == {"padin_offset": 8, "external_value": 0,
                             "pad_resolution": PAD_RESOLUTION}
    assert execution_refusals(facts) == []


def test_two_groups_are_normalized_and_executable(tmp_path: Path) -> None:
    # P2: the host now drives every declared pad group, in declaration order,
    # each for its own window, so two groups are a complete declaration instead
    # of a refusal.  The refusal name stays reachable by lowering the declared
    # capability, which is what a host with one pad word states.
    document = dict(MINIMAL, pin_groups=[pad_group(),
                                         pad_group(name="strobes", padin_offset=12)])
    facts = source_behavior({"pin_groups": document["pin_groups"]}, base_dir=tmp_path)
    assert [group["name"] for group in facts["pin_groups"]] == ["pads", "strobes"]
    assert facts["pin_group_count"] == 2
    assert execution_refusals(facts) == []

    narrowed = dict(HOST_SOURCE_EXECUTION, pin_groups=1)
    assert refusal(source_behavior, {"pin_groups": document["pin_groups"]},
                   base_dir=tmp_path,
                   limits=narrowed) == "unsupported-behavior-execution:pin_groups:2"


def test_a_serial_peer_is_normalized_and_executable(tmp_path: Path) -> None:
    # P2: the host has a framed serial driver, so a peer is executable; only a
    # host that declares no peer (or a narrower kind set) refuses it.
    document = dict(MINIMAL, pin_groups=[pad_group(),
                                         serial_group(tx_en_role="tx_en")])
    facts = source_behavior({"pin_groups": document["pin_groups"]}, base_dir=tmp_path)
    peer = facts["pin_groups"][1]
    assert peer == {"name": "serial0", "kind": "serial_peer", "rx_role": "rx",
                    "tx_role": "tx", "tx_en_role": "tx_en", "idle_level": 1,
                    "bit_ticks": 434, "frame": "8n1"}

    assert refusal(source_behavior, {"pin_groups": document["pin_groups"]},
                   base_dir=tmp_path,
                   limits=dict(HOST_SOURCE_EXECUTION,
                               pin_group_kinds=("dir_resolved_pad_word",))) == (
        "unsupported-behavior-execution:serial_peer")


@pytest.mark.parametrize("group,reason", [
    ({"kind": "spi_peer", "rx_role": "rx"}, "unsupported-behavior-value:pin_groups.kind"),
    (pad_group(padin_offset=-4), "unsupported-behavior-value:pin_groups.padin_offset"),
    (pad_group(external_value=1 << 32),
     "unsupported-behavior-value:pin_groups.external_value"),
    (pad_group(pad_resolution="host_only"), "unsupported-behavior-value:pin_groups.pad_resolution"),
    (pad_group(direction="sideways"), "unsupported-behavior-value:pin_groups.direction"),
    (pad_group(hold_ticks=70000), "unsupported-behavior-value:pin_groups.hold_ticks"),
    (serial_group(rx_role=""), "unsupported-behavior-value:pin_groups.rx_role"),
    (serial_group(bit_ticks=0), "unsupported-behavior-value:pin_groups.bit_ticks"),
    (serial_group(frame="7e2"), "unsupported-behavior-value:pin_groups.frame"),
    (serial_group(idle_level=2), "unsupported-behavior-value:pin_groups.idle_level"),
    (pad_group(padout_offset=12), "unsupported-behavior-field:pin_groups.padout_offset"),
])
def test_out_of_shape_pin_groups_are_refused_by_name(tmp_path: Path,
                                                    group: dict,
                                                    reason: str) -> None:
    document = dict(MINIMAL, pin_groups=[group])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == reason


def test_duplicate_group_names_are_refused(tmp_path: Path) -> None:
    document = dict(MINIMAL, pin_groups=[pad_group(), pad_group()])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "unsupported-behavior-value:pin_groups.name")


def test_the_pad_word_and_the_group_list_are_not_merged(tmp_path: Path) -> None:
    document = dict(MINIMAL, pins={"padin_offset": 8, "external_value": 0,
                                   "pad_resolution": PAD_RESOLUTION},
                    pin_groups=[pad_group()])
    assert refusal(source_behavior, written(tmp_path, document), base_dir=tmp_path) == (
        "behavior-source-conflict:pins")


def test_a_group_only_declaration_is_still_parsed(tmp_path: Path) -> None:
    # A pad group is a declaration this layer consumes, so it is not dropped as
    # "no F5 facts": it normalizes (and would be refused if it were serial).
    facts = source_behavior({"pin_groups": [pad_group()]}, base_dir=tmp_path)
    assert facts["pins"]["padin_offset"] == 8
    assert facts["declared_by"] == "inline"
    # The historical v1 pins block keeps its own rule: pads alone are not an F5
    # declaration and the executor's refusal path stays the authority.
    assert source_behavior({"pins": {"padin_offset": 8, "external_value": 0,
                                     "pad_resolution": PAD_RESOLUTION}},
                           base_dir=tmp_path) is None


def test_a_file_group_list_conflicting_with_an_inline_one_is_refused(tmp_path: Path) -> None:
    config = written(tmp_path, dict(MINIMAL, pin_groups=[pad_group()]))
    config["pin_groups"] = [pad_group(padin_offset=12)]
    assert refusal(source_behavior, config, base_dir=tmp_path) == (
        "behavior-source-conflict:pin_groups")


# ---------------------------------------------------------------------------
# The shipped declarations: one executable, the rest refused by name
# ---------------------------------------------------------------------------
def test_the_shipped_uart_behavior_normalizes_as_one_clear_write() -> None:
    facts = facts_of(UART_BEHAVIOR)

    assert facts["source_port"] == "intr_tx_done_o"
    assert facts["status_offsets"] == [0]
    assert facts["status_cause_bits"] == [2]
    assert facts["clear_sequence"] == [{"kind": "write", "offset": 0, "value": 4}]
    assert facts["clear_writes"] == [[0, 4]]
    assert execution_refusals(facts) == []


@pytest.mark.parametrize("path,reason", [
    (THREE_STEP_BEHAVIOR, "unsupported-behavior-execution:multi_step_clear:3"),
    # P2 keeps two shipped declaration-only files refused by name at this layer:
    # a frame shape the driver does not encode, and two peers on one target.
    (TWO_STOP_BIT_BEHAVIOR, "unsupported-behavior-value:pin_groups.frame"),
    (HALF_DUPLEX_BEHAVIOR,
     "unsupported-behavior-execution:serial_peer:half_duplex"),
    (TWO_SERIAL_PEER_BEHAVIOR,
     "unsupported-behavior-execution:serial_peer:count:2"),
    (AMBIGUOUS_BEHAVIOR, "behavior-source-conflict:clear_writes"),
])
def test_a_shipped_declaration_only_file_is_refused_by_name(path: str,
                                                            reason: str) -> None:
    assert (ROOT / path).is_file()
    assert refusal(facts_of, path) == reason


def test_the_two_shipped_group_declarations_now_normalize_as_complete() -> None:
    # The two files the P1 increment shipped as "declared but not executable" are
    # complete declarations for the P2 host: every group kind is executable, and
    # nothing is refused at the declaration layer.  What remains refusable about
    # them is an executor fact (a second pad word, a peer role the device does not
    # expose), so it is the entry's refusal, covered in
    # tests/integration/test_p2_pins_serial.py.
    for path in (SERIAL_PEER_BEHAVIOR, TWO_PAD_BEHAVIOR):
        facts = facts_of(path)
        assert facts["pin_group_count"] == 2
        assert execution_refusals(facts) == []


# ---------------------------------------------------------------------------
# DMA capabilities: declaration shape here, device bound in the planner
# ---------------------------------------------------------------------------
def test_dma_capabilities_normalize_within_the_shape_bound() -> None:
    assert dma_capabilities(None) is None
    assert dma_capabilities({}) == {}
    assert dma_capabilities({"channels": 2, "beat_bytes": 8,
                             "max_outstanding": 4, "burst_beats": 1}) == {
        "channels": 2, "beat_bytes": 8, "max_outstanding": 4, "burst_beats": 1}
    assert dma_capability_refusals({"channels": 2, "beat_bytes": 8}) == [
        "channels:2>1", "beat_bytes:8>4"]
    assert dma_capability_refusals({"channels": 1, "beat_bytes": 4}) == []
    assert dma_capability_refusals({"channels": 1},
                                   limit=dict(HOST_DMA_CAPABILITY, channels=2)) == []


@pytest.mark.parametrize("value,reason", [
    ([], "unsupported-behavior-value:capabilities"),
    ({"lanes": 2}, "unsupported-behavior-field:capabilities.lanes"),
    ({"channels": 0}, "unsupported-behavior-value:capabilities.channels"),
    ({"channels": True}, "unsupported-behavior-value:capabilities.channels"),
    ({"beat_bytes": 3}, "unsupported-behavior-value:capabilities.beat_bytes"),
    ({"max_outstanding": 17}, "unsupported-behavior-value:capabilities.max_outstanding"),
])
def test_out_of_shape_capabilities_are_refused_by_name(value, reason) -> None:
    assert refusal(dma_capabilities, value) == reason


def test_dma_behavior_reports_the_declared_capabilities(tmp_path: Path) -> None:
    facts = dma_behavior({"dma_behavior": ZIPDMA_CAPABILITY_BEHAVIOR}, base_dir=ROOT)
    assert facts["capabilities"] == {"channels": 1, "beat_bytes": 4,
                                     "max_outstanding": 1, "burst_beats": 1}
    assert facts["capability_refusals"] == []
    assert facts["capabilities_executable"] is True

    refused = dma_behavior({"dma_behavior": TWO_CHANNEL_BEHAVIOR}, base_dir=ROOT)
    assert refused["capabilities"] == {"channels": 2, "beat_bytes": 8,
                                       "max_outstanding": 2, "burst_beats": 4}
    assert refused["capability_refusals"] == [
        "unsupported-dma-capability:channels:2>1",
        "unsupported-dma-capability:beat_bytes:8>4",
        "unsupported-dma-capability:max_outstanding:2>1",
        "unsupported-dma-capability:burst_beats:4>1",
    ]
    assert refused["capabilities_executable"] is False


def test_a_legacy_dma_behavior_file_reports_no_capability_keys() -> None:
    facts = dma_behavior({"dma_behavior": BEHAVIORS + "/zipdma_f6.json"}, base_dir=ROOT)
    assert "capabilities" not in facts and "capability_refusals" not in facts


# ---------------------------------------------------------------------------
# The planner: a capability above the pinned device is refused by name
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def zipdma_profile():
    return load_component_profile(ZIPDMA_PROFILE)


@pytest.fixture(scope="module")
def zipdma_artifact(zipdma_profile):
    return {"dma_edge_contract": dma_profile_edge_contract(
        dict(zipdma_profile.capabilities))}


def scenario(**overrides) -> dict:
    document = json.loads(TIMER_SCENARIO.read_text())
    document.update(copy.deepcopy(overrides))
    return document


def plan_of(config, profile, artifact):
    return dma_transfer_declaration(config, profile, artifact, base_dir=ROOT)


def dma_refusal(reason, function) -> str:
    with pytest.raises(DmaTransferError) as captured:
        function()
    assert captured.value.reason == reason, str(captured.value)
    return str(captured.value)


def test_the_planner_reports_the_declared_capabilities(zipdma_profile, zipdma_artifact):
    plan = plan_of(scenario(dma_behavior=ZIPDMA_CAPABILITY_BEHAVIOR),
                   zipdma_profile, zipdma_artifact)

    declaration = plan["declaration"]
    assert declaration["declared_capabilities"] == {
        "channels": 1, "beat_bytes": 4, "max_outstanding": 1, "burst_beats": 1}
    assert declaration["device_capabilities"] == {
        "channels": 1, "beat_bytes": 4, "max_outstanding": 1, "burst_beats": 1}
    assert validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)


def test_a_two_channel_behavior_file_is_refused_by_the_planner(zipdma_profile,
                                                              zipdma_artifact):
    value = dma_refusal("dma-capability-beyond-device", lambda: plan_of(
        scenario(dma_behavior=TWO_CHANNEL_BEHAVIOR), zipdma_profile, zipdma_artifact))
    assert value == "dma-capability-beyond-device:channels:2>1"


def test_a_profile_that_declares_two_channels_is_refused_by_the_planner(zipdma_artifact):
    profile = load_component_profile(TWO_CHANNEL_PROFILE)
    value = dma_refusal("dma-profile-capability-beyond-device", lambda: plan_of(
        scenario(), profile, zipdma_artifact))
    assert "channels:2>1" in value


def test_a_plan_that_keeps_a_capability_it_cannot_have_is_refused(zipdma_profile,
                                                                 zipdma_artifact):
    plan = plan_of(scenario(dma_behavior=ZIPDMA_CAPABILITY_BEHAVIOR),
                   zipdma_profile, zipdma_artifact)
    plan["declaration"]["declared_capabilities"] = {"channels": 2}
    dma_refusal("dma-capability-beyond-device",
                lambda: validate_transfer_plan(plan, zipdma_profile, zipdma_artifact))
