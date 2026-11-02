"""Pure-Python tests for multi-IP MMIO target declarations and routing.

The two-IP scenario is checked against the real PULP timer and PULP I2C
component profiles and the real timer behavior file, and the multi-declaring
scenario is checked against both targets' real behavior files.  Nothing here
runs Verilator, builds a host, or claims that a model was executed: the tests
cover the declaration, the address route, the strict one-owner helper and the
multi-target `targets_for_f5` selection that feeds the global link table.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import source_behavior
from myfuzz.composition.multi_target import (
    F5_FACT_KEYS,
    MAX_TARGETS,
    TWO_IP_SCENARIO_PATH,
    MultiTargetError,
    declared_targets,
    route_address,
    single_irq_target,
    target_as_legacy_config,
    target_for_f5,
    target_windows,
    targets_for_f5,
    two_ip_scenario,
)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / TWO_IP_SCENARIO_PATH
#: The multi-declaring scenario: timer and I2C both state complete F5 facts.
MULTIF5_SCENARIO = ROOT / "configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-multif5-f1f6.json"
#: The multi-bit status-vector scenario: one GPIO target, two cause bits.
MULTIBIT_SCENARIO = ROOT / "configs/scenarios/inprocess-obi-apb-gpio-multibit-f5-pins.json"
PROFILE_TIMER = "configs/peripherals/pulp_timer_irq/component_profile.json"
PROFILE_I2C = "configs/peripherals/pulp_i2c/component_profile.json"
PROFILE_CPU = "configs/cpus/ibex_rvfi_local/component_profile.json"
BEHAVIOR_TIMER = "configs/behaviors/pulp_timer_f5.json"

TIMING = {"reset_assert_ticks": 2, "reset_release_ticks": 3, "max_wait_cycles": 16}
RAM = {"base": 0x10000, "size": 0x20000}
TIMER_WINDOW = {"base": 0x40001000, "size": 4096}
I2C_WINDOW = {"base": 0x40002000, "size": 4096}
DMA_WINDOW = {"base": 0x40003000, "size": 16}

F5_TIMER = {
    "source_port": "irq_o",
    "source_bit_offset": 0,
    "trigger_writes": [[4, 0], [8, 0], [0, 0xFFFFFFFF]],
    "status_offsets": [0],
}
I2C_FIXED = [
    {"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": 1},
    {"endpoint_id": "i2c.pins", "role": "sda_pad_i", "value": 1},
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def target_row(name: str, window: dict, **overrides) -> dict:
    row = {
        "name": name,
        "profile": PROFILE_TIMER,
        "active_id": name + "_active",
        "window": dict(window),
        "timing": dict(TIMING),
        "behavior": None,
        "pins": None,
        "fixed_inputs": [],
        "tuning": {},
    }
    row.update(overrides)
    return row


def two_target_config() -> dict:
    return {
        "targets": [
            target_row("timer", TIMER_WINDOW, behavior=BEHAVIOR_TIMER),
            target_row("i2c", I2C_WINDOW, profile=PROFILE_I2C,
                       fixed_inputs=copy.deepcopy(I2C_FIXED),
                       tuning={"fixed_inputs": copy.deepcopy(I2C_FIXED)}),
        ],
        "image_start": RAM["base"],
        "image_end": RAM["base"] + RAM["size"],
        "dma_window": dict(DMA_WINDOW),
    }


def legacy_config() -> dict:
    return {
        "source_profile": PROFILE_TIMER,
        "active_id": "pulp_timer_active",
        "target_window": dict(TIMER_WINDOW),
        "source_timing": dict(TIMING),
        "source_behavior": BEHAVIOR_TIMER,
        "source_fixed_inputs": [],
        "source_tuning": {},
    }


def refusal(function, *args, **kwargs) -> str:
    with pytest.raises(MultiTargetError) as raised:
        function(*args, **kwargs)
    return str(raised.value)


# ---------------------------------------------------------------------------
# 1. The legacy single-target shape and the new targets list
# ---------------------------------------------------------------------------
def test_legacy_shape_normalizes_to_one_target() -> None:
    targets = declared_targets(legacy_config())

    assert targets == [{
        "profile": PROFILE_TIMER,
        "active_id": "pulp_timer_active",
        "window": TIMER_WINDOW,
        "timing": TIMING,
        "behavior": BEHAVIOR_TIMER,
        "pins": None,
        "fixed_inputs": [],
        "tuning": {},
        "index": 0,
        "name": "source",
    }]


def test_legacy_shape_reads_a_real_existing_scenario() -> None:
    config = load(ROOT / "configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5.json")
    targets = declared_targets(config)

    assert len(targets) == 1
    assert targets[0]["profile"] == config["source_profile"]
    assert targets[0]["active_id"] == config["active_id"]
    assert targets[0]["window"] == config["target_window"]
    assert targets[0]["timing"] == config["source_timing"]
    assert targets[0]["pins"] == config["pins"]
    assert targets[0]["behavior"] is None  # inline facts stay the entry's concern
    assert targets[0]["name"] == "source"


def test_normalized_targets_do_not_share_the_config_objects() -> None:
    config = legacy_config()
    targets = declared_targets(config)
    targets[0]["window"]["base"] = 0
    targets[0]["timing"]["max_wait_cycles"] = 0
    targets[0]["fixed_inputs"].append(
        {"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": 1})

    assert config["target_window"]["base"] == TIMER_WINDOW["base"]
    assert config["source_timing"]["max_wait_cycles"] == TIMING["max_wait_cycles"]
    assert config["source_fixed_inputs"] == []


def test_two_targets_keep_declaration_order_and_fields() -> None:
    targets = declared_targets(two_target_config())

    assert [target["name"] for target in targets] == ["timer", "i2c"]
    assert [target["index"] for target in targets] == [0, 1]
    assert [target["window"] for target in targets] == [TIMER_WINDOW, I2C_WINDOW]
    assert targets[0]["behavior"] == BEHAVIOR_TIMER
    assert targets[1]["behavior"] is None
    assert targets[0]["profile"] == PROFILE_TIMER
    assert targets[1]["profile"] == PROFILE_I2C
    assert targets[1]["fixed_inputs"] == I2C_FIXED
    assert targets[1]["tuning"]["fixed_inputs"] == I2C_FIXED


def test_missing_target_names_default_to_the_declaration_index() -> None:
    first = target_row("timer", TIMER_WINDOW)
    second = target_row("i2c", I2C_WINDOW, profile=PROFILE_I2C)
    first.pop("name")
    second.pop("name")

    targets = declared_targets({"targets": [first, second]})

    assert [target["name"] for target in targets] == ["target0", "target1"]


TOO_MANY_TARGETS = [
    target_row("t%d" % index, {"base": 0x40000000 + 0x2000 * index, "size": 4096})
    for index in range(MAX_TARGETS + 1)
]


@pytest.mark.parametrize("rows", [[], TOO_MANY_TARGETS], ids=["too-few", "too-many"])
def test_target_count_is_one_to_eight(rows) -> None:
    assert refusal(declared_targets, {"targets": rows}) == "unsupported-targets-count"


def test_targets_must_be_a_list() -> None:
    assert refusal(declared_targets, {"targets": {}}) == "unsupported-targets-shape"


def test_duplicate_active_id_is_refused() -> None:
    first = target_row("timer", TIMER_WINDOW)
    second = target_row("i2c", I2C_WINDOW, profile=PROFILE_I2C)
    second["active_id"] = first["active_id"]

    assert refusal(declared_targets, {"targets": [first, second]}) == (
        "unsupported-target-active-id-duplicate:timer_active")


def test_duplicate_target_name_is_refused() -> None:
    first = target_row("timer", TIMER_WINDOW)
    second = target_row("i2c", I2C_WINDOW, profile=PROFILE_I2C)
    second["name"] = "timer"

    assert refusal(declared_targets, {"targets": [first, second]}) == (
        "unsupported-target-name-duplicate:timer")


@pytest.mark.parametrize("key", ["source_profile", "pins", "source_port"])
def test_targets_and_the_legacy_single_target_shape_are_ambiguous(key) -> None:
    config = two_target_config()
    config[key] = "legacy"

    assert refusal(declared_targets, config) == "unsupported-targets-ambiguous:" + key


@pytest.mark.parametrize("profile", ["", "/abs/profile.json", "../profile.json", 5])
def test_target_profile_must_be_a_relative_path_string(profile) -> None:
    row = target_row("timer", TIMER_WINDOW, profile=profile)

    assert refusal(declared_targets, {"targets": [row]}) == "unsupported-target-profile:0"


def test_target_profile_path_is_normalized() -> None:
    row = target_row("timer", TIMER_WINDOW, profile="./" + PROFILE_TIMER)

    assert declared_targets({"targets": [row]})[0]["profile"] == PROFILE_TIMER


def test_target_behavior_path_is_normalized_and_validated() -> None:
    row = target_row("timer", TIMER_WINDOW, behavior="./" + BEHAVIOR_TIMER)
    assert declared_targets({"targets": [row]})[0]["behavior"] == BEHAVIOR_TIMER

    row["behavior"] = "../escape.json"
    assert refusal(declared_targets, {"targets": [row]}) == "unsupported-target-behavior:0"


@pytest.mark.parametrize("window,reason", [
    ({"base": 0x40001002, "size": 4096}, "unsupported-target-window-alignment:0"),
    ({"base": 0x40001000, "size": 2}, "unsupported-target-window-range:0"),
    ({"base": -4, "size": 4096}, "unsupported-target-window-range:0"),
    ({"base": 0xFFFFFFF0, "size": 4096}, "unsupported-target-window-range:0"),
])
def test_unusable_target_windows_are_refused(window, reason) -> None:
    row = target_row("timer", window)

    assert refusal(declared_targets, {"targets": [row]}) == reason


@pytest.mark.parametrize("window", [None, {"base": 0x40001000}, {"base": "0", "size": 4096}])
def test_malformed_target_windows_are_refused(window) -> None:
    row = target_row("timer", TIMER_WINDOW)
    row["window"] = window

    assert refusal(declared_targets, {"targets": [row]}) == "unsupported-target-window:0"


def test_target_windows_may_not_overlap_each_other() -> None:
    second = dict(TIMER_WINDOW, base=TIMER_WINDOW["base"] + 0x800)
    rows = [target_row("timer", TIMER_WINDOW),
            target_row("i2c", second, profile=PROFILE_I2C)]

    assert refusal(declared_targets, {"targets": rows}) == (
        "unsupported-window-overlap:target[0]-target[1]")


def test_target_window_may_not_overlap_the_ram_image() -> None:
    config = legacy_config()
    config["image_start"] = TIMER_WINDOW["base"]
    config["image_end"] = TIMER_WINDOW["base"] + 0x1000

    assert refusal(declared_targets, config) == "unsupported-window-overlap:target[0]-ram"


def test_target_window_may_not_overlap_the_dma_window() -> None:
    config = two_target_config()
    config["dma_window"] = {"base": I2C_WINDOW["base"] + 0x800, "size": 16}

    assert refusal(declared_targets, config) == "unsupported-window-overlap:target[1]-dma"


def test_ram_and_dma_windows_may_not_overlap_each_other() -> None:
    config = two_target_config()
    config["dma_window"] = {"base": RAM["base"], "size": 16}

    assert refusal(declared_targets, config) == "unsupported-window-overlap:ram-dma"


def test_unknown_target_field_is_refused() -> None:
    row = target_row("timer", TIMER_WINDOW, target_windw={"base": 0, "size": 4})

    assert refusal(declared_targets, {"targets": [row]}) == (
        "unsupported-target-field:target_windw")


def test_fixed_inputs_are_normalized() -> None:
    row = target_row("i2c", I2C_WINDOW, profile=PROFILE_I2C,
                     fixed_inputs=copy.deepcopy(I2C_FIXED))
    target = declared_targets({"targets": [row]})[0]

    assert target["fixed_inputs"] == I2C_FIXED
    assert target["fixed_inputs"][0] is not row["fixed_inputs"][0]


@pytest.mark.parametrize("value", [
    [{"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": -1}],
    [{"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": 1},
     {"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": 0}],
    [{"endpoint_id": "i2c.pins", "value": 1}],
    [{"endpoint_id": "i2c.pins", "role": "scl_pad_i", "value": 1, "width": 1}],
])
def test_malformed_fixed_inputs_are_refused(value) -> None:
    row = target_row("i2c", I2C_WINDOW, fixed_inputs=value)

    assert refusal(declared_targets, {"targets": [row]}) == (
        "unsupported-target-fixed-inputs:0")


def test_malformed_timing_pins_and_tuning_are_refused() -> None:
    for key, reason in (("timing", "unsupported-target-timing:0"),
                        ("pins", "unsupported-target-pins:0"),
                        ("tuning", "unsupported-target-tuning:0")):
        value = {"reset_assert_ticks": 2} if key == "timing" else []
        row = target_row("timer", TIMER_WINDOW, **{key: value})
        assert refusal(declared_targets, {"targets": [row]}) == reason


# ---------------------------------------------------------------------------
# 2. The host address view
# ---------------------------------------------------------------------------
def test_target_windows_legacy_shape_keeps_first_target_compatibility() -> None:
    config = legacy_config()
    config["image_start"] = RAM["base"]
    config["image_end"] = RAM["base"] + RAM["size"]

    windows = target_windows(config)

    assert windows == {
        "ram_base": RAM["base"],
        "ram_size": RAM["size"],
        "ip_targets": [TIMER_WINDOW],
        "ip_base": TIMER_WINDOW["base"],
        "ip_size": TIMER_WINDOW["size"],
        "dma_base": None,
        "dma_size": None,
        "data_base": RAM["base"] + 0x4000,
        "target_count": 1,
    }


def test_target_windows_lists_every_target_and_the_dma_window() -> None:
    windows = target_windows(two_target_config())

    assert windows["ip_targets"] == [TIMER_WINDOW, I2C_WINDOW]
    assert windows["ip_base"] == TIMER_WINDOW["base"]
    assert windows["ip_size"] == TIMER_WINDOW["size"]
    assert windows["ram_base"] == RAM["base"]
    assert windows["ram_size"] == RAM["size"]
    assert windows["dma_base"] == DMA_WINDOW["base"]
    assert windows["dma_size"] == DMA_WINDOW["size"]
    assert windows["data_base"] == RAM["base"] + 0x4000
    assert windows["target_count"] == 2


def test_target_windows_accept_ram_and_dma_overrides() -> None:
    config = {"targets": two_target_config()["targets"]}

    windows = target_windows(config, ram=RAM, dma_window=DMA_WINDOW)

    assert windows["ram_base"] == RAM["base"]
    assert windows["dma_base"] == DMA_WINDOW["base"]
    assert windows["ip_targets"] == [TIMER_WINDOW, I2C_WINDOW]


def test_target_windows_override_wins_over_a_bad_config_ram() -> None:
    config = two_target_config()
    config["image_start"] = 0
    config["image_end"] = 4  # unusable as the host image, but the override is explicit

    windows = target_windows(config, ram=(RAM["base"], RAM["size"]))

    assert windows["ram_base"] == RAM["base"]
    assert windows["ram_size"] == RAM["size"]


@pytest.mark.parametrize("image_start,image_end,reason", [
    (None, None, "unsupported-ram:missing"),
    (RAM["base"], None, "unsupported-ram:type"),
    (RAM["base"] + 2, RAM["base"] + RAM["size"], "unsupported-ram:alignment"),
    (RAM["base"], RAM["base"], "unsupported-ram:range"),
    (RAM["base"], RAM["base"] + 0x7000, "unsupported-ram:too-small"),
])
def test_unusable_ram_is_refused(image_start, image_end, reason) -> None:
    config = {"targets": two_target_config()["targets"]}
    if image_start is not None:
        config["image_start"] = image_start
    if image_end is not None:
        config["image_end"] = image_end

    assert refusal(target_windows, config) == reason


def test_target_windows_refuses_misaligned_dma_window() -> None:
    config = two_target_config()
    config["dma_window"] = {"base": DMA_WINDOW["base"] + 8, "size": 16}

    assert refusal(target_windows, config) == "unsupported-dma-window:alignment"


def test_target_windows_refuses_unusable_dma_window() -> None:
    config = two_target_config()
    config["dma_window"] = {"base": DMA_WINDOW["base"], "size": 15}

    assert refusal(target_windows, config) == "unsupported-dma-window:range"


def test_target_windows_checks_the_declared_dma_window_size() -> None:
    config = two_target_config()

    assert refusal(target_windows, config, dma_window=32) == "unsupported-dma-window:size"
    assert target_windows(config, dma_window=16)["dma_size"] == 16


def test_target_windows_declared_dma_size_requires_the_config_window() -> None:
    config = {"targets": two_target_config()["targets"],
              "image_start": RAM["base"], "image_end": RAM["base"] + RAM["size"]}

    assert refusal(target_windows, config, dma_window=16) == (
        "unsupported-dma-window:missing")


def test_two_ip_config_replaces_the_entry_dma_size_check_with_the_real_profile() -> None:
    config = load(SCENARIO)
    dma_profile = load_component_profile(ROOT / config["dma_profile"])

    windows = target_windows(config, dma_window=dma_profile.address.window_size)

    assert windows["dma_size"] == dma_profile.address.window_size
    assert windows["dma_base"] == DMA_WINDOW["base"]


def test_target_windows_refuses_overlapping_targets_even_with_valid_ram() -> None:
    second = dict(TIMER_WINDOW, base=TIMER_WINDOW["base"] + 0x800)
    config = {"targets": [target_row("timer", TIMER_WINDOW),
                          target_row("i2c", second, profile=PROFILE_I2C)],
              "image_start": RAM["base"], "image_end": RAM["base"] + RAM["size"]}

    assert refusal(target_windows, config) == (
        "unsupported-window-overlap:target[0]-target[1]")


@pytest.mark.parametrize("mutation,reason", [
    ({"image_start": I2C_WINDOW["base"],
      "image_end": I2C_WINDOW["base"] + 0x20000},
     "unsupported-window-overlap:target[1]-ram"),
    ({"dma_window": {"base": I2C_WINDOW["base"] + 0x800, "size": 16}},
     "unsupported-window-overlap:target[1]-dma"),
])
def test_target_windows_refuses_target_overlaps_with_ram_and_dma(mutation, reason) -> None:
    config = two_target_config()
    config.update(mutation)

    assert refusal(target_windows, config) == reason


# ---------------------------------------------------------------------------
# 3. Address routing
# ---------------------------------------------------------------------------
def test_route_address_reaches_each_target() -> None:
    windows = target_windows(two_target_config())

    assert route_address(windows, TIMER_WINDOW["base"]) == (0, 0)
    assert route_address(windows, TIMER_WINDOW["base"] + 8) == (0, 8)
    assert route_address(windows, I2C_WINDOW["base"]) == (1, 0)
    assert route_address(windows, I2C_WINDOW["base"] + 20) == (1, 20)
    assert route_address(windows, I2C_WINDOW["base"] + 4092) == (1, 4092)


def test_route_address_returns_none_for_ram_dma_and_unmapped_words() -> None:
    windows = target_windows(two_target_config())

    assert route_address(windows, RAM["base"]) is None
    assert route_address(windows, RAM["base"] + RAM["size"] - 4) is None
    assert route_address(windows, DMA_WINDOW["base"]) is None
    assert route_address(windows, DMA_WINDOW["base"] + 12) is None
    assert route_address(windows, TIMER_WINDOW["base"] - 4) is None
    assert route_address(windows, I2C_WINDOW["base"] + I2C_WINDOW["size"]) is None
    assert route_address(windows, 0x50000000) is None


def test_route_address_requires_a_target_word() -> None:
    windows = target_windows(two_target_config())

    assert refusal(route_address, windows, TIMER_WINDOW["base"] + 2) == (
        "unsupported-address:unaligned")
    assert refusal(route_address, windows, I2C_WINDOW["base"] + 6) == (
        "unsupported-address:unaligned")


@pytest.mark.parametrize("address,reason", [
    (None, "unsupported-address:type"),
    (1.0, "unsupported-address:type"),
    (True, "unsupported-address:type"),
    (-4, "unsupported-address:range"),
    (1 << 32, "unsupported-address:range"),
])
def test_route_address_requires_a_32_bit_integer(address, reason) -> None:
    windows = target_windows(two_target_config())

    assert refusal(route_address, windows, address) == reason


def test_route_address_refuses_overlapping_target_windows() -> None:
    windows = {"ip_targets": [{"base": 0x1000, "size": 0x1000},
                              {"base": 0x1800, "size": 0x1000}]}

    assert refusal(route_address, windows, 0x1800) == "unsupported-route-windows:overlap"


def test_route_address_requires_target_windows() -> None:
    assert refusal(route_address, {}, 0x40000000) == "unsupported-route-windows"


# ---------------------------------------------------------------------------
# 4. The one IRQ line rule
# ---------------------------------------------------------------------------
def test_target_for_f5_selects_the_only_declaring_target() -> None:
    targets = declared_targets(two_target_config())

    assert target_for_f5(targets, [F5_TIMER, None])["name"] == "timer"
    assert target_for_f5(targets, [None, dict(F5_TIMER)])["name"] == "i2c"


def test_target_for_f5_returns_none_when_no_target_declares_facts() -> None:
    targets = declared_targets(two_target_config())

    assert target_for_f5(targets, [None, None]) is None
    assert target_for_f5(targets, [{"source_port": "irq_o"}, None]) is None


def test_two_targets_declaring_f5_facts_are_refused_by_name() -> None:
    targets = declared_targets(two_target_config())

    assert refusal(target_for_f5, targets, [F5_TIMER, dict(F5_TIMER)]) == (
        "unsupported-f5:multiple-target-irq-sources")


def test_a_v2_sources_link_is_an_f5_declaration() -> None:
    targets = declared_targets(two_target_config())
    behavior = {"sources": [dict(F5_TIMER)], "source_count": 1}

    assert target_for_f5(targets, [behavior, None])["name"] == "timer"


def test_single_irq_target_is_the_same_selection() -> None:
    targets = declared_targets(two_target_config())

    assert single_irq_target(targets, [F5_TIMER, None])["name"] == "timer"
    assert single_irq_target(targets, [None, None]) is None


def test_behaviors_may_be_keyed_by_index_name_or_active_id() -> None:
    targets = declared_targets(two_target_config())

    assert target_for_f5(targets, {"timer": F5_TIMER})["name"] == "timer"
    assert target_for_f5(targets, {1: F5_TIMER})["name"] == "i2c"
    assert target_for_f5(targets, {"i2c_active": F5_TIMER})["name"] == "i2c"
    assert target_for_f5(targets, {0: F5_TIMER, "timer": F5_TIMER})["name"] == "timer"


def test_behavior_sequence_must_match_the_target_count() -> None:
    targets = declared_targets(two_target_config())

    assert refusal(target_for_f5, targets, [F5_TIMER]) == (
        "unsupported-f5:behaviors-shape")


def test_behavior_entries_must_be_mappings() -> None:
    targets = declared_targets(two_target_config())

    assert refusal(target_for_f5, targets, ["not facts", None]) == (
        "unsupported-f5:behavior-shape")


def test_unknown_behavior_mapping_keys_are_refused() -> None:
    targets = declared_targets(two_target_config())

    assert refusal(target_for_f5, targets, {"missing": F5_TIMER}) == (
        "unsupported-f5:behaviors-shape")


def test_a_raw_behavior_mapping_is_only_unambiguous_for_one_target() -> None:
    one = declared_targets(legacy_config())
    assert target_for_f5(one, F5_TIMER)["name"] == "source"

    two = declared_targets(two_target_config())
    assert refusal(target_for_f5, two, F5_TIMER) == (
        "unsupported-f5:behaviors-shape")


# ---------------------------------------------------------------------------
# 5. The legacy adapter the integration calls per target
# ---------------------------------------------------------------------------
def test_target_as_legacy_config_omits_absent_optional_keys() -> None:
    targets = declared_targets(two_target_config())

    timer = target_as_legacy_config(targets[0])
    i2c = target_as_legacy_config(targets[1])

    assert timer["source_behavior"] == BEHAVIOR_TIMER
    assert "pins" not in timer
    assert "pins" not in i2c
    assert "source_behavior" not in i2c
    assert i2c["source_fixed_inputs"] == I2C_FIXED
    assert i2c["source_tuning"]["fixed_inputs"] == I2C_FIXED
    assert i2c["source_timing"] == TIMING


def test_target_as_legacy_config_round_trips_through_declared_targets() -> None:
    for target in declared_targets(two_target_config()):
        round_tripped = declared_targets(target_as_legacy_config(target))[0]
        for key in ("profile", "active_id", "window", "timing", "behavior",
                    "pins", "fixed_inputs", "tuning"):
            assert round_tripped[key] == target[key]


# ---------------------------------------------------------------------------
# 6. The checked-in two-IP scenario and its real profiles
# ---------------------------------------------------------------------------
def test_two_ip_config_uses_the_new_targets_shape() -> None:
    config = load(SCENARIO)

    assert config["cpu_profile"] == PROFILE_CPU
    assert config["image_start"] == RAM["base"]
    assert config["image_end"] == RAM["base"] + RAM["size"]
    assert len(config["targets"]) == 2
    for key in ("source_profile", "active_id", "target_window", "source_timing",
                "source_behavior", "pins", "source_fixed_inputs", "source_tuning"):
        assert key not in config


def test_two_ip_config_normalizes_and_routes_both_targets() -> None:
    config = load(SCENARIO)
    targets = declared_targets(config)
    windows = target_windows(config)

    assert [target["name"] for target in targets] == ["timer", "i2c"]
    assert windows["ip_targets"] == [TIMER_WINDOW, I2C_WINDOW]
    assert windows["dma_base"] == DMA_WINDOW["base"]
    assert windows["dma_size"] == DMA_WINDOW["size"]
    assert route_address(windows, TIMER_WINDOW["base"] + 4) == (0, 4)
    assert route_address(windows, I2C_WINDOW["base"] + 20) == (1, 20)
    assert route_address(windows, DMA_WINDOW["base"]) is None
    assert route_address(windows, RAM["base"] + 0x40) is None


def test_two_ip_config_targets_are_real_apb3_profiles_with_matching_windows() -> None:
    for target in declared_targets(load(SCENARIO)):
        profile = load_component_profile(ROOT / target["profile"])
        slaves = [endpoint for endpoint in profile.endpoints
                  if endpoint.function == "mmio_slave"]
        assert len(slaves) == 1
        assert slaves[0].protocol == ("apb", "3")
        assert profile.address is not None
        assert target["window"]["size"] == profile.address.window_size
        assert target["window"]["base"] % profile.address.alignment == 0


def test_two_ip_config_timer_f5_facts_match_the_real_profile() -> None:
    targets = declared_targets(load(SCENARIO))
    facts = source_behavior(target_as_legacy_config(targets[0]), base_dir=ROOT)
    profile = load_component_profile(ROOT / PROFILE_TIMER)

    assert facts is not None
    assert {key: facts[key] for key in F5_FACT_KEYS} == F5_TIMER
    assert facts["clear_writes"] == []
    assert facts["source_port"] == "irq_o"

    endpoints = {endpoint.endpoint_id: endpoint for endpoint in profile.endpoints}
    source = [item for item in profile.interrupts
              if (item.bit if item.bit is not None else 0) == facts["source_bit_offset"]]
    assert len(source) == 1
    assert source[0].endpoint_id == "timer.interrupts"
    assert source[0].role == "irq"
    assert source[0].trigger == "pulse"
    assert any(field.role == "irq" and facts["source_port"] in field.aliases
               for field in endpoints[source[0].endpoint_id].fields)

    registers = {row.offset: row for row in profile.address.registers}
    for offset, _ in facts["trigger_writes"]:
        assert offset in registers
        assert registers[offset].width == 32
        assert registers[offset].access in ("wo", "rw")
    assert facts["status_offsets"][0] in registers
    assert registers[facts["status_offsets"][0]].width == 32
    assert registers[facts["status_offsets"][0]].access in ("ro", "rw")


def test_two_ip_config_i2c_has_no_irq_and_keeps_idle_pad_inputs() -> None:
    targets = declared_targets(load(SCENARIO))
    i2c = targets[1]
    facts = source_behavior(target_as_legacy_config(i2c), base_dir=ROOT)
    profile = load_component_profile(ROOT / PROFILE_I2C)

    assert facts is None
    assert profile.interrupts == ()
    pins = [endpoint for endpoint in profile.endpoints
            if endpoint.function == "external_pins"]
    assert len(pins) == 1
    roles = {field.role for field in pins[0].fields}
    assert {row["role"] for row in i2c["fixed_inputs"]} == {"scl_pad_i", "sda_pad_i"}
    assert all(row["endpoint_id"] == pins[0].endpoint_id for row in i2c["fixed_inputs"])
    assert all(row["role"] in roles for row in i2c["fixed_inputs"])
    assert all(row["value"] == 1 for row in i2c["fixed_inputs"])
    assert i2c["tuning"]["fixed_inputs"] == i2c["fixed_inputs"]


def test_two_ip_config_selects_only_the_timer_for_f5() -> None:
    config = load(SCENARIO)
    targets = declared_targets(config)
    behaviors = [source_behavior(target_as_legacy_config(target), base_dir=ROOT)
                 for target in targets]

    assert target_for_f5(targets, behaviors)["name"] == "timer"
    assert refusal(target_for_f5, targets, [dict(F5_TIMER), dict(F5_TIMER)]) == (
        "unsupported-f5:multiple-target-irq-sources")


def test_targets_for_f5_returns_every_declaring_target_in_declaration_order() -> None:
    targets = declared_targets(two_target_config())

    both = targets_for_f5(targets, [F5_TIMER, dict(F5_TIMER)])
    assert [target["name"] for target in both] == ["timer", "i2c"]
    assert [target["index"] for target in both] == [0, 1]
    assert [target["name"] for target in targets_for_f5(targets, [None, F5_TIMER])] == [
        "i2c"]
    assert targets_for_f5(targets, [None, None]) == []


def test_targets_for_f5_keeps_the_one_target_compatibility_path() -> None:
    targets = declared_targets(two_target_config())

    selected = targets_for_f5(targets, [F5_TIMER, None])
    assert selected == [target_for_f5(targets, [F5_TIMER, None])]
    assert [target["name"] for target in selected] == ["timer"]
    # The strict helper keeps the historical one-owner refusal; only the
    # multi-target selector lists both declaring targets.
    assert refusal(target_for_f5, targets, [F5_TIMER, dict(F5_TIMER)]) == (
        "unsupported-f5:multiple-target-irq-sources")
    assert len(targets_for_f5(targets, [F5_TIMER, dict(F5_TIMER)])) == 2


def test_targets_for_f5_still_validates_the_behavior_shape() -> None:
    targets = declared_targets(two_target_config())

    assert refusal(targets_for_f5, targets, [F5_TIMER]) == (
        "unsupported-f5:behaviors-shape")
    assert refusal(targets_for_f5, targets, {"missing": F5_TIMER}) == (
        "unsupported-f5:behaviors-shape")
    assert refusal(targets_for_f5, targets, ["not facts", None]) == (
        "unsupported-f5:behavior-shape")


def test_the_multi_f5_scenario_normalizes_both_declaring_targets() -> None:
    config = load(MULTIF5_SCENARIO)
    targets = declared_targets(config)
    behaviors = [source_behavior(target_as_legacy_config(target), base_dir=ROOT)
                 for target in targets]
    declaring = targets_for_f5(targets, behaviors)

    assert [target["name"] for target in declaring] == ["timer", "i2c"]
    assert [target["index"] for target in declaring] == [0, 1]
    # One F5 record shape serves every link, so the two declarations have to
    # agree on the trigger-write count the record carries.
    counts = {len(behavior["trigger_writes"]) for behavior in behaviors}
    assert counts == {3}
    # The I2C target declares a real level interrupt with a write clear; the
    # timer declares a pulse with no acknowledge register.
    i2c = source_behavior(target_as_legacy_config(targets[1]), base_dir=ROOT)
    assert i2c["clear_writes"] == [[20, 1]]
    assert i2c["status_offsets"] == [12]


def test_the_multibit_gpio_scenario_is_one_f5_target_with_two_cause_bits() -> None:
    config = load(MULTIBIT_SCENARIO)
    targets = declared_targets(config)
    assert len(targets) == 1
    behavior = source_behavior(target_as_legacy_config(targets[0]), base_dir=ROOT)
    assert behavior["status_cause_bits"] == [0, 1]
    assert behavior["status_offsets"] == [36]
    assert behavior["pins"]["padin_offset"] == 8
    # The one target declares F5, so the historical single-owner selector keeps
    # working for this scenario; the two bits are status content, not a second
    # IRQ link.
    assert targets_for_f5(targets, [behavior]) == targets
    assert target_for_f5(targets, [behavior]) == targets[0]


def test_two_ip_scenario_helper_loads_the_checked_in_document() -> None:
    assert two_ip_scenario() == load(SCENARIO)
    assert two_ip_scenario(base_dir=ROOT) == load(SCENARIO)
