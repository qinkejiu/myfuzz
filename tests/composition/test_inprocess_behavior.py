"""Tests for the declarative device-behavior layer of the in-process F1-F6 entry.

The behavior files under ``configs/behaviors/`` are checked against the scenario
configs they were copied from, so a value cannot drift away from its source
without a test noticing.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from myfuzz.composition.inprocess_behavior import (
    BEHAVIOR_DOCUMENT_SCHEMA,
    BUILTIN_STATUS_SOURCE,
    DMA_BEHAVIOR_SCHEMA,
    PAD_RESOLUTION,
    SOURCE_BEHAVIOR_KEYS,
    SOURCE_BEHAVIOR_SCHEMA,
    BehaviorError,
    behavior_document,
    dma_behavior,
    read_behavior_file,
    source_behavior,
)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_TIMER = ROOT / "configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json"
SCENARIO_SPI = ROOT / "configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json"
SCENARIO_GPIO = ROOT / "configs/scenarios/inprocess-obi-apb-gpio-pins.json"
SCENARIO_GPIO_F1F5 = ROOT / "configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5.json"
SCENARIO_WBDMAC = ROOT / "configs/scenarios/inprocess-generality-wbdmac-f1f6.json"
BEHAVIOR_TIMER = "configs/behaviors/pulp_timer_f5.json"
BEHAVIOR_SPI = "configs/behaviors/pulp_spi_eot_f5.json"
BEHAVIOR_GPIO = "configs/behaviors/pulp_gpio_f5_pins.json"
BEHAVIOR_GPIO_MULTIBIT = "configs/behaviors/pulp_gpio_multibit_f5_pins.json"
BEHAVIOR_ZIPDMA = "configs/behaviors/zipdma_f6.json"

TIMER_FACTS = {
    "source_port": "irq_o",
    "source_bit_offset": 0,
    "pulse_width_ticks": 16,
    "trigger_writes": [[4, 0], [8, 0], [0, 4294967295]],
    "status_offsets": [0],
    "status_cause_bits": None,
    "clear_writes": [],
    "pins": None,
    "declared_by": "file",
    "declaration_path": BEHAVIOR_TIMER,
}
SPI_FACTS = {
    "source_port": "events_o",
    "source_bit_offset": 1,
    "pulse_width_ticks": 16,
    "trigger_writes": [[16, 65536], [24, 171], [0, 2]],
    "status_offsets": [40],
    "status_cause_bits": None,
    "clear_writes": [],
    "pins": None,
    "declared_by": "file",
    "declaration_path": BEHAVIOR_SPI,
}
GPIO_FACTS = {
    "source_port": "interrupt",
    "source_bit_offset": 0,
    "pulse_width_ticks": 16,
    "trigger_writes": [[4, 4294967295], [24, 1], [28, 1], [12, 43]],
    "status_offsets": [36],
    "status_cause_bits": None,
    "clear_writes": [],
    "pins": {
        "padin_offset": 8,
        "external_value": 0,
        "pad_resolution": PAD_RESOLUTION,
    },
    "declared_by": "file",
    "declaration_path": BEHAVIOR_GPIO,
}
ZIPDMA_FACTS = {
    "block_words": 4,
    "irq_pulse_ticks": None,
    "busy_bit": 31,
    "err_bit": 30,
    "status_kind": "status",
    "status_bits_declared": True,
    "status_bits_source": BEHAVIOR_ZIPDMA,
    "declared_by": "file",
    "declaration_path": BEHAVIOR_ZIPDMA,
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_document(directory: Path, name: str, document: dict) -> str:
    (directory / name).write_text(json.dumps(document), encoding="utf-8")
    return name


def refusal(function, *args, **kwargs) -> str:
    """The named reason a declaration is refused."""
    with pytest.raises(BehaviorError) as raised:
        function(*args, **kwargs)
    return str(raised.value)


def facts_of(path: str) -> dict:
    return source_behavior({"source_behavior": path}, base_dir=ROOT)


# ---------------------------------------------------------------------------
# Inline declarations and the refusal path the executor keeps
# ---------------------------------------------------------------------------
def test_inline_keys_are_returned_unchanged() -> None:
    config = load(SCENARIO_TIMER)
    facts = source_behavior(config, base_dir=ROOT)

    assert facts == dict({key: config[key] for key in SOURCE_BEHAVIOR_KEYS},
                         pins=None, declared_by="inline", declaration_path=None)
    assert set(facts) == set(SOURCE_BEHAVIOR_KEYS) | {
        "pins", "declared_by", "declaration_path"}


def test_source_behavior_is_none_without_any_f5_fact() -> None:
    assert source_behavior({}, base_dir=ROOT) is None
    assert source_behavior({"name": "a scenario that declares no F5"}, base_dir=ROOT) is None


def test_pins_alone_are_not_an_f5_declaration() -> None:
    pins = load(SCENARIO_GPIO)["pins"]
    assert source_behavior({"pins": pins}, base_dir=ROOT) is None


def test_inline_pins_model_is_normalized_and_reported() -> None:
    config = load(SCENARIO_GPIO)
    facts = source_behavior({"source_port": config["irq"]["source_port"],
                             "pins": config["pins"]}, base_dir=ROOT)

    assert facts["pins"] == {"padin_offset": 8, "external_value": 0,
                             "pad_resolution": PAD_RESOLUTION}
    assert facts["declared_by"] == "inline"


# ---------------------------------------------------------------------------
# A file declaration: provenance, precedence, metadata
# ---------------------------------------------------------------------------
def test_a_file_declaration_needs_no_inline_keys(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "description": "metadata is accepted",
        "notes": ["and never becomes a fact"],
        "source_port": "irq_o",
        "source_bit_offset": 3,
        "pulse_width_ticks": 8,
        "trigger_writes": [[0, 1]],
        "status_offsets": [4],
        "status_cause_bits": [0, 1],
        "clear_writes": [[4, 1]],
    })
    facts = source_behavior({"source_behavior": path}, base_dir=tmp_path)

    assert facts == {
        "source_port": "irq_o",
        "source_bit_offset": 3,
        "pulse_width_ticks": 8,
        "trigger_writes": [[0, 1]],
        "status_offsets": [4],
        "status_cause_bits": [0, 1],
        "clear_writes": [[4, 1]],
        "pins": None,
        "declared_by": "file",
        "declaration_path": path,
    }
    assert "description" not in facts and "notes" not in facts


def test_agreeing_inline_value_is_accepted_and_the_file_reports_itself(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "source_port": "irq_o",
        "source_bit_offset": 3,
        "pulse_width_ticks": 8,
    })
    facts = source_behavior({"source_behavior": path, "source_bit_offset": 3,
                             "pulse_width_ticks": 8}, base_dir=tmp_path)

    assert facts["pulse_width_ticks"] == 8
    assert facts["declared_by"] == "file"
    assert facts["declaration_path"] == path


def test_declaration_path_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "device.json").write_text(
        json.dumps({"schema_version": SOURCE_BEHAVIOR_SCHEMA, "source_port": "irq_o"}),
        encoding="utf-8")

    assert facts_of("./" + BEHAVIOR_TIMER)["declaration_path"] == BEHAVIOR_TIMER
    facts = source_behavior({"source_behavior": "./device.json"}, base_dir=tmp_path)
    assert facts["declaration_path"] == "device.json"


def test_conflicting_inline_value_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "pulse_width_ticks": 8,
    })

    assert refusal(source_behavior, {"source_behavior": path, "pulse_width_ticks": 16},
                   base_dir=tmp_path) == "behavior-source-conflict:pulse_width_ticks"


def test_conflicting_inline_trigger_sequence_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "trigger_writes": [[0, 1]],
    })

    assert refusal(source_behavior,
                   {"source_behavior": path, "trigger_writes": [[4, 0]]},
                   base_dir=tmp_path) == "behavior-source-conflict:trigger_writes"


def test_conflicting_inline_pins_model_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "source_port": "interrupt",
        "pins": {"padin_offset": 8, "external_value": 0,
                 "pad_resolution": PAD_RESOLUTION},
    })
    inline = {"padin_offset": 8, "external_value": 1,
              "pad_resolution": PAD_RESOLUTION}

    assert refusal(source_behavior, {"source_behavior": path, "pins": inline},
                   base_dir=tmp_path) == "behavior-source-conflict:pins"


def test_unknown_file_field_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA,
        "source_port": "irq_o",
        "frobnicate": 1,
    })

    assert refusal(source_behavior, {"source_behavior": path},
                   base_dir=tmp_path) == "unsupported-behavior-field:frobnicate"


def test_wrong_schema_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "device.json", {
        "schema_version": "declared_irq_behavior.v1",
        "source_port": "irq_o",
    })
    missing = write_document(tmp_path, "missing.json", {"source_port": "irq_o"})

    assert refusal(source_behavior, {"source_behavior": path},
                   base_dir=tmp_path) == (
        "unsupported-behavior-schema:declared_irq_behavior.v1")
    assert refusal(source_behavior, {"source_behavior": missing},
                   base_dir=tmp_path) == "unsupported-behavior-schema:missing"


def test_absolute_behavior_path_is_refused() -> None:
    assert refusal(source_behavior, {"source_behavior": str(ROOT / BEHAVIOR_TIMER)},
                   base_dir=ROOT) == "unsupported-behavior-path"


def test_escaping_behavior_path_is_refused() -> None:
    assert refusal(source_behavior, {"source_behavior": "../outside.json"},
                   base_dir=ROOT) == "unsupported-behavior-path"
    assert refusal(read_behavior_file, "configs/../../etc/passwd",
                   base_dir=ROOT) == "unsupported-behavior-path"


def test_symlink_escaping_the_base_directory_is_refused(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = write_document(tmp_path, "outside.json", {
        "schema_version": SOURCE_BEHAVIOR_SCHEMA, "source_port": "irq_o"})
    (base / "link.json").symlink_to(tmp_path / outside)

    assert refusal(read_behavior_file, "link.json", base_dir=base) == "unsupported-behavior-path"


def test_missing_behavior_file_is_refused_clearly() -> None:
    assert refusal(source_behavior,
                   {"source_behavior": "configs/behaviors/absent_behavior.json"},
                   base_dir=ROOT) == (
        "unsupported-behavior-file:configs/behaviors/absent_behavior.json")


def test_non_json_behavior_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")

    assert refusal(read_behavior_file, "bad.json",
                   base_dir=tmp_path) == "unsupported-behavior-json:bad.json"


def test_non_object_behavior_document_is_refused(tmp_path: Path) -> None:
    (tmp_path / "list.json").write_text("[1, 2]", encoding="utf-8")

    assert refusal(read_behavior_file, "list.json",
                   base_dir=tmp_path) == "unsupported-behavior-document:list.json"


def test_read_behavior_file_returns_the_raw_document() -> None:
    document = read_behavior_file(BEHAVIOR_TIMER, base_dir=ROOT)

    assert document["schema_version"] == SOURCE_BEHAVIOR_SCHEMA
    assert isinstance(document["description"], str)
    assert isinstance(document["notes"], list)


# ---------------------------------------------------------------------------
# The four behavior files, checked against their scenario sources
# ---------------------------------------------------------------------------
def test_timer_behavior_file_matches_the_scenario() -> None:
    facts = facts_of(BEHAVIOR_TIMER)
    scenario = load(SCENARIO_TIMER)

    assert facts == TIMER_FACTS
    for key in SOURCE_BEHAVIOR_KEYS:
        assert facts[key] == scenario[key]


def test_spi_behavior_file_matches_the_scenario() -> None:
    facts = facts_of(BEHAVIOR_SPI)
    scenario = load(SCENARIO_SPI)

    assert facts == SPI_FACTS
    for key in SOURCE_BEHAVIOR_KEYS:
        assert facts[key] == scenario[key]


def test_gpio_behavior_file_matches_the_scenario() -> None:
    facts = facts_of(BEHAVIOR_GPIO)
    scenario = load(SCENARIO_GPIO)
    declared = scenario["irq"]

    assert facts == GPIO_FACTS
    assert facts["source_port"] == declared["source_port"]
    assert facts["source_bit_offset"] == declared["source_bit_offset"]
    assert facts["pulse_width_ticks"] == declared["pulse_width_ticks"]
    assert facts["status_offsets"] == [declared["status_offset"]]
    assert [row[0] for row in facts["trigger_writes"]] == declared["trigger_offsets"]
    assert declared["clear"] is None
    assert facts["clear_writes"] == []
    assert facts["pins"] == scenario["pins"]


def test_gpio_trigger_values_match_the_reviewed_f1f5_scenario() -> None:
    facts = facts_of(BEHAVIOR_GPIO)
    reviewed = load(SCENARIO_GPIO_F1F5)

    assert facts["trigger_writes"] == reviewed["trigger_writes"]
    assert facts["pins"] == reviewed["pins"]
    assert [row[0] for row in facts["trigger_writes"]] == (
        load(SCENARIO_GPIO)["irq"]["trigger_offsets"])


def test_zipdma_behavior_file_declares_the_status_bits() -> None:
    facts = dma_behavior({"dma_behavior": BEHAVIOR_ZIPDMA}, base_dir=ROOT)

    assert facts == ZIPDMA_FACTS
    assert facts["status_bits_declared"] is True
    assert facts["status_bits_source"] == BEHAVIOR_ZIPDMA
    assert (facts["busy_bit"], facts["err_bit"]) == (31, 30)


# ---------------------------------------------------------------------------
# The DMA default: a reported built-in, never an anonymous constant
# ---------------------------------------------------------------------------
def test_dma_default_reports_the_builtin_zipdma_bits() -> None:
    facts = dma_behavior({"dma_block_words": 4, "dma_irq_pulse_ticks": 16},
                         base_dir=ROOT)

    assert facts == {
        "block_words": 4,
        "irq_pulse_ticks": 16,
        "busy_bit": 31,
        "err_bit": 30,
        "status_kind": "status",
        "status_bits_declared": False,
        "status_bits_source": BUILTIN_STATUS_SOURCE,
        "declared_by": "inline",
        "declaration_path": None,
    }
    assert facts["status_bits_source"] == "builtin_zipdma_rtl_default"


def test_dma_behavior_keeps_undeclared_values_as_none() -> None:
    facts = dma_behavior({}, base_dir=ROOT)

    assert facts["block_words"] is None
    assert facts["irq_pulse_ticks"] is None
    assert facts["status_kind"] == "status"
    assert facts["status_bits_declared"] is False


def test_wbdmac_uses_its_own_declared_status_bits() -> None:
    scenario = load(SCENARIO_WBDMAC)

    facts = dma_behavior(scenario, base_dir=ROOT)
    assert facts["block_words"] == scenario["dma_block_words"] == 4
    assert facts["status_bits_declared"] is True
    assert facts["status_bits_source"] == "configs/behaviors/wbdmac_f6.json"
    assert (facts["busy_bit"], facts["err_bit"]) == (31, 30)


def test_dma_file_conflicting_with_inline_block_words_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "block_words": 2,
    })

    assert refusal(dma_behavior,
                   {"dma_behavior": path, "dma_block_words": 4},
                   base_dir=tmp_path) == "behavior-source-conflict:block_words"


def test_dma_file_conflicting_with_inline_pulse_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "irq_pulse_ticks": 8,
    })

    assert refusal(dma_behavior,
                   {"dma_behavior": path, "dma_irq_pulse_ticks": 16},
                   base_dir=tmp_path) == "behavior-source-conflict:irq_pulse_ticks"


def test_dma_busy_bit_equal_to_err_bit_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "busy_bit": 7,
        "err_bit": 7,
    })

    assert refusal(dma_behavior, {"dma_behavior": path},
                   base_dir=tmp_path) == "unsupported-behavior-value:err_bit"


def test_dma_partial_status_bit_declaration_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "busy_bit": 7,
    })

    assert refusal(dma_behavior, {"dma_behavior": path},
                   base_dir=tmp_path) == "unsupported-behavior-value:status_bits"


@pytest.mark.parametrize("block_words", (0, 5))
def test_dma_block_words_out_of_range_is_refused(block_words: int) -> None:
    assert refusal(dma_behavior, {"dma_block_words": block_words},
                   base_dir=ROOT) == "unsupported-behavior-value:block_words"


@pytest.mark.parametrize("pulse_ticks", (0, 4097))
def test_dma_irq_pulse_ticks_out_of_range_is_refused(pulse_ticks: int) -> None:
    assert refusal(dma_behavior, {"dma_irq_pulse_ticks": pulse_ticks},
                   base_dir=ROOT) == "unsupported-behavior-value:irq_pulse_ticks"


def test_dma_unknown_status_kind_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "status_kind": "interrupt",
    })

    assert refusal(dma_behavior, {"dma_behavior": path},
                   base_dir=tmp_path) == "unsupported-behavior-value:status_kind"


def test_dma_unknown_file_field_is_refused(tmp_path: Path) -> None:
    path = write_document(tmp_path, "dma.json", {
        "schema_version": DMA_BEHAVIOR_SCHEMA,
        "completion_bit": 1,
    })

    assert refusal(dma_behavior, {"dma_behavior": path},
                   base_dir=tmp_path) == "unsupported-behavior-field:completion_bit"


# ---------------------------------------------------------------------------
# Bad F5 shapes are refused, not coerced
# ---------------------------------------------------------------------------
BAD_SOURCE_SHAPES = (
    ({"source_port": ""}, "unsupported-behavior-value:source_port"),
    ({"source_port": 0}, "unsupported-behavior-value:source_port"),
    ({"source_bit_offset": -1}, "unsupported-behavior-value:source_bit_offset"),
    ({"source_bit_offset": 64}, "unsupported-behavior-value:source_bit_offset"),
    ({"source_bit_offset": True}, "unsupported-behavior-value:source_bit_offset"),
    ({"pulse_width_ticks": 0}, "unsupported-behavior-value:pulse_width_ticks"),
    ({"pulse_width_ticks": 4097}, "unsupported-behavior-value:pulse_width_ticks"),
    ({"trigger_writes": []}, "unsupported-behavior-value:trigger_writes"),
    ({"trigger_writes": [[4]]}, "unsupported-behavior-value:trigger_writes"),
    ({"trigger_writes": [[0, 1 << 32]]}, "unsupported-behavior-value:trigger_writes"),
    ({"trigger_writes": [[0, -1]]}, "unsupported-behavior-value:trigger_writes"),
    ({"clear_writes": [[0, 1], [4, 2]]}, "unsupported-behavior-value:clear_writes"),
    ({"status_offsets": [0, 4]}, "unsupported-behavior-value:status_offsets"),
    ({"status_offsets": "0"}, "unsupported-behavior-value:status_offsets"),
    ({"status_cause_bits": [32]}, "unsupported-behavior-value:status_cause_bits"),
    ({"status_cause_bits": "abc"}, "unsupported-behavior-value:status_cause_bits"),
    ({"source_port": "irq_o",
      "pins": {"padin_offset": 8, "external_value": 0,
               "pad_resolution": "host_always"}},
     "unsupported-behavior-value:pins.pad_resolution"),
    ({"source_port": "irq_o",
      "pins": {"padin_offset": 8, "external_value": 1 << 32,
               "pad_resolution": PAD_RESOLUTION}},
     "unsupported-behavior-value:pins.external_value"),
    ({"source_port": "irq_o",
      "pins": {"padin_offset": -1, "external_value": 0,
               "pad_resolution": PAD_RESOLUTION}},
     "unsupported-behavior-value:pins.padin_offset"),
    ({"source_port": "irq_o",
      "pins": {"padin_offset": 8, "pad_resolution": PAD_RESOLUTION}},
     "unsupported-behavior-value:pins.external_value"),
    ({"source_port": "irq_o",
      "pins": {"padin_offset": 8, "external_value": 0,
               "pad_resolution": PAD_RESOLUTION, "extra": 1}},
     "unsupported-behavior-field:pins.extra"),
)


@pytest.mark.parametrize("config,reason", BAD_SOURCE_SHAPES,
                         ids=[reason.split(":", 1)[1] for _, reason in BAD_SOURCE_SHAPES])
def test_bad_source_shape_is_refused(config: dict, reason: str) -> None:
    assert refusal(source_behavior, config, base_dir=ROOT) == reason


def test_status_cause_bits_and_one_clear_write_are_accepted() -> None:
    facts = source_behavior({"source_port": "irq_o", "source_bit_offset": 0,
                             "trigger_writes": [[0, 1]],
                             "status_cause_bits": [0, 31],
                             "clear_writes": [[4, 0]]}, base_dir=ROOT)

    assert facts["status_cause_bits"] == [0, 31]
    assert facts["clear_writes"] == [[4, 0]]


# ---------------------------------------------------------------------------
# The summary document, determinism and non-mutation
# ---------------------------------------------------------------------------
def test_behavior_document_is_json_serialisable_and_reports_provenance() -> None:
    source = facts_of(BEHAVIOR_TIMER)
    dma = dma_behavior({"dma_behavior": BEHAVIOR_ZIPDMA}, base_dir=ROOT)
    document = behavior_document(source, dma)

    assert set(document) == {"schema_version", "source", "dma"}
    assert document["schema_version"] == BEHAVIOR_DOCUMENT_SCHEMA
    assert document["source"] == source
    assert document["dma"] == dma
    assert document["source"]["declared_by"] == "file"
    assert document["dma"]["status_bits_declared"] is True
    assert json.loads(json.dumps(document, sort_keys=True)) == document


def test_behavior_document_keeps_an_absent_source() -> None:
    dma = dma_behavior({"dma_block_words": 4}, base_dir=ROOT)
    document = behavior_document(None, dma)

    assert document["source"] is None
    assert document["dma"]["status_bits_source"] == BUILTIN_STATUS_SOURCE
    assert json.loads(json.dumps(document)) == document


def test_behavior_document_copies_its_inputs() -> None:
    source = facts_of(BEHAVIOR_GPIO)
    dma = dma_behavior({"dma_block_words": 4}, base_dir=ROOT)
    document = behavior_document(source, dma)

    document["source"]["pins"]["external_value"] = 99
    document["source"]["trigger_writes"].append([0, 0])
    document["dma"]["busy_bit"] = 0

    assert source["pins"]["external_value"] == 0
    assert source["trigger_writes"][-1] == [12, 43]
    assert dma["busy_bit"] == 31


def test_source_behavior_is_deterministic_and_does_not_mutate_the_config() -> None:
    config = load(SCENARIO_TIMER)
    snapshot = copy.deepcopy(config)

    first = source_behavior(config, base_dir=ROOT)
    second = source_behavior(config, base_dir=ROOT)
    assert first == second
    assert config == snapshot

    first["trigger_writes"].append([0, 0])
    assert second["trigger_writes"][-1] == [0, 4294967295]


def test_dma_behavior_is_deterministic_and_does_not_mutate_the_config(tmp_path: Path) -> None:
    config = {"dma_block_words": 4, "dma_irq_pulse_ticks": 16}
    snapshot = copy.deepcopy(config)

    first = dma_behavior(config, base_dir=tmp_path)
    assert first == dma_behavior(config, base_dir=tmp_path)
    assert config == snapshot


def test_the_multibit_gpio_behavior_states_two_cause_bits_and_a_plain_read() -> None:
    facts = source_behavior({"source_behavior": BEHAVIOR_GPIO_MULTIBIT},
                            base_dir=ROOT)
    assert facts["source_port"] == "interrupt"
    assert facts["source_bit_offset"] == 0
    assert facts["pulse_width_ticks"] == 16
    assert facts["status_offsets"] == [36]
    assert facts["status_cause_bits"] == [0, 1]
    # Reading INTSTATUS is the device's own clear (profile side_effect
    # read_clears); the behavior therefore declares no write clear.
    assert facts["clear_writes"] == []
    assert facts["trigger_writes"] == [[4, 4294967295], [24, 3], [28, 5], [12, 3]]
    assert facts["pins"]["padin_offset"] == 8
    assert facts["declared_by"] == "file"
    assert facts["declaration_path"] == BEHAVIOR_GPIO_MULTIBIT
