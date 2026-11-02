"""P2 pins and serial peers: the declaration half and the recorded batch.

Two independent groups of assertions, and neither of them fabricates a fact:

* the pure-Python half exercises the executor's declaration checks - which pad
  word the bound endpoint exposes, which pad roles a serial peer may own, which
  F2 record shapes carry a stimulus - and the exact named refusal for every form
  the host still cannot run;
* the evidence half reads the batch committed under
  ``runs/p2-pins-serial-20261103/`` and asserts the per-case fields *this run*
  printed, and the tick-level serial waveform it logged.  Those assertions are
  skipped when the evidence directory is absent (a checkout without the run), so
  the declaration half stays runnable everywhere.

Nothing here builds a model.  The real batch, its exact commands and its limits
are stated in ``runs/p2-pins-serial-20261103/README.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import (
    HOST_SOURCE_EXECUTION,
    MAX_PIN_GROUPS,
    PAD_RESOLUTION,
    BehaviorError,
    execution_refusals,
    source_behavior,
)
from scripts.run_inprocess_f1f6 import (
    declared_windows,
    case_document,
    case_observation_keys,
    parse_case_line,
    parse_record,
    pin_group_case_keys,
    pin_group_declaration,
    serial_peer_case_keys,
)

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "runs/p2-pins-serial-20261103"
UART_PROFILE = ROOT / "configs/peripherals/opentitan_uart_local/component_profile.json"
GPIO_PROFILE = ROOT / "configs/peripherals/pulp_gpio_causal_local/component_profile.json"
UART_BEHAVIOR = ROOT / "configs/behaviors/opentitan_uart_serial_peer_f5.json"
GPIO_GROUPS_BEHAVIOR = ROOT / "configs/behaviors/pulp_gpio_two_groups_f5_pins.json"
GPIO_DIRECTION_BEHAVIOR = ROOT / (
    "configs/behaviors/pulp_gpio_direction_groups_f5_pins.json")
DECLARATION_ONLY = ROOT / "configs/behaviors/declaration-only"

#: The two pad-role runtime names the built OpenTitan UART artifact exports.  They
#: are the wrapper's own ``rt_`` names, which is what the generated header binds.
UART_EXPORTS = [
    dict(endpoint_id="uart.pins", role="rx", direction="input", width=1,
         runtime_name="rt_lh_p_11_0_0"),
    dict(endpoint_id="uart.pins", role="tx", direction="output", width=1,
         runtime_name="rt_lh_p_13_0_0"),
    dict(endpoint_id="uart.pins", role="tx_en", direction="output", width=1,
         runtime_name="rt_lh_p_12_0_0"),
]
GPIO_EXPORTS = [
    dict(endpoint_id="gpio.pins", role="in", direction="input", width=32,
         runtime_name="rt_lh_p_2_31_0"),
    dict(endpoint_id="gpio.pins", role="out", direction="output", width=32,
         runtime_name="rt_lh_p_3_31_0"),
    dict(endpoint_id="gpio.pins", role="dir", direction="output", width=32,
         runtime_name="rt_lh_p_4_31_0"),
    dict(endpoint_id="gpio.pins", role="in_sync", direction="output", width=32,
         runtime_name="rt_lh_p_5_31_0"),
]


def artifact(exports: list[dict]) -> dict:
    return dict(schema_version="local_harness_runtime.v1",
                physical_exports=exports)


def behavior_groups(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["pin_groups"]


def refusal(function, *args, **kwargs) -> str:
    with pytest.raises(ValueError) as raised:
        function(*args, **kwargs)
    return str(raised.value)


# ---------------------------------------------------------------------------
# What the host states it can execute
# ---------------------------------------------------------------------------
def test_the_declared_host_execution_admits_groups_and_one_peer() -> None:
    assert HOST_SOURCE_EXECUTION["pin_groups"] == MAX_PIN_GROUPS == 4
    assert HOST_SOURCE_EXECUTION["pin_group_kinds"] == (
        "dir_resolved_pad_word", "serial_peer")
    assert HOST_SOURCE_EXECUTION["serial_peer"] is True
    assert HOST_SOURCE_EXECUTION["serial_peers"] == 1
    # The clear-step bound is another increment's fact and is untouched here.
    assert HOST_SOURCE_EXECUTION["clear_steps"] == 1


def test_the_shipped_two_group_behavior_is_executable() -> None:
    facts = source_behavior(
        {"source_behavior": "configs/behaviors/pulp_gpio_two_groups_f5_pins.json"},
        base_dir=ROOT)
    assert [group["name"] for group in facts["pin_groups"]] == [
        "phase_low", "phase_high"]
    assert facts["pin_group_count"] == 2
    assert execution_refusals(facts) == []
    # The pad word the host resolves is the first group's; the declaration keeps
    # both groups, which is what the entry walks.
    assert facts["pins"] == {"padin_offset": 8, "external_value": 4369,
                             "pad_resolution": PAD_RESOLUTION}


def test_the_shipped_serial_peer_behavior_is_executable() -> None:
    facts = source_behavior(
        {"source_behavior": "configs/behaviors/opentitan_uart_serial_peer_f5.json"},
        base_dir=ROOT)
    peer = facts["pin_groups"][0]
    assert peer["kind"] == "serial_peer"
    assert (peer["rx_role"], peer["tx_role"], peer["tx_en_role"]) == (
        "rx", "tx", "tx_en")
    assert peer["bit_ticks"] == 32 and peer["frame"] == "8n1"
    assert facts["pins"] is None
    assert execution_refusals(facts) == []


# ---------------------------------------------------------------------------
# The executor's declaration checks
# ---------------------------------------------------------------------------
def test_two_pad_groups_bind_the_one_pad_word_and_keep_their_order() -> None:
    groups = behavior_groups(GPIO_GROUPS_BEHAVIOR)
    declaration = pin_group_declaration(
        {"pin_groups": groups}, load_component_profile(GPIO_PROFILE),
        artifact(GPIO_EXPORTS), bus="obi", target_count=1)

    assert [group["name"] for group in declaration["groups"]] == [
        "phase_low", "phase_high"]
    assert [group["hold_ticks"] for group in declaration["groups"]] == [2, 3]
    assert [group["direction"] for group in declaration["groups"]] == [
        "inout", "inout"]
    assert declaration["serial"] is None
    # The direction is part of the declaration the host executes; the port the
    # pad word lives on is the artifact's, not a name this layer guesses.
    assert declaration["groups"][0]["padin_offset"] == 8


def test_a_second_pad_word_is_refused_by_name() -> None:
    document = json.loads((
        DECLARATION_ONLY / "gpio_two_pad_words_groups_f5.json").read_text())
    assert refusal(pin_group_declaration, document, load_component_profile(GPIO_PROFILE),
                   artifact(GPIO_EXPORTS), bus="obi", target_count=1) == (
        "unsupported-pins:pin_groups:second-pad-word")


def test_a_serial_peer_binds_the_profile_roles_it_names() -> None:
    declaration = pin_group_declaration(
        {"pin_groups": behavior_groups(UART_BEHAVIOR)},
        load_component_profile(UART_PROFILE), artifact(UART_EXPORTS), bus="obi",
        target_count=1)

    peer = declaration["serial"]
    assert peer["frame_code"] == 0 and peer["frame_bits"] == 10
    assert peer["ports"]["rx"] == dict(runtime_name="rt_lh_p_11_0_0", width=1,
                                       direction="input")
    assert peer["ports"]["tx"] == dict(runtime_name="rt_lh_p_13_0_0", width=1,
                                       direction="output")
    assert peer["ports"]["tx_en"] == dict(runtime_name="rt_lh_p_12_0_0", width=1,
                                          direction="output")


def test_a_missing_pad_role_is_refused_by_name() -> None:
    document = json.loads((
        DECLARATION_ONLY / "uart_serial_peer_missing_role_f5.json").read_text())
    assert refusal(pin_group_declaration, document, load_component_profile(UART_PROFILE),
                   artifact(UART_EXPORTS), bus="obi", target_count=1) == (
        "unsupported-serial:role:rts_n")


def test_a_serial_peer_on_a_packed_axi4_or_ahb_cpu_is_refused() -> None:
    # Those hosts own their own CPU/adapter clock edge, so they cannot park the
    # CPU while the peer drives a frame.  The refusal names the bus.
    for bus in ("axi4", "ahb"):
        assert refusal(pin_group_declaration, {"pin_groups": behavior_groups(UART_BEHAVIOR)},
                       load_component_profile(UART_PROFILE), artifact(UART_EXPORTS),
                       bus=bus, target_count=1) == (
            "unsupported-serial:cpu-clock-not-parkable:" + bus)


def test_a_serial_peer_on_a_multitarget_build_is_refused() -> None:
    assert refusal(pin_group_declaration, {"pin_groups": behavior_groups(UART_BEHAVIOR)},
                   load_component_profile(UART_PROFILE), artifact(UART_EXPORTS),
                   bus="obi", target_count=2) == "unsupported-pins:multiple-targets"


def test_a_dir_group_without_a_pad_endpoint_is_refused() -> None:
    # The UART exposes no in/out/dir endpoint, so a dir-resolved group on it is a
    # declaration about a pad word the model does not have.
    assert refusal(pin_group_declaration, {"pin_groups": behavior_groups(GPIO_GROUPS_BEHAVIOR)},
                   load_component_profile(UART_PROFILE), artifact(UART_EXPORTS),
                   bus="obi", target_count=1) == (
        "unsupported-pins:pin_groups:no-pad-endpoint")


# ---------------------------------------------------------------------------
# The F2 stimulus word, on both kinds of target
# ---------------------------------------------------------------------------
def windows() -> dict:
    """The address view one target declares: the UART window and the image RAM.

    It is built here from the same numbers the scenario states (the profile's own
    4 KiB window at 0x40003000 and the fixed 0x10000..0x30000 image), so the
    record parser is exercised without building a model.
    """
    return dict(ram_base=0x10000, ram_size=0x20000, data_base=0x14000,
                ip_base=0x40003000, ip_size=4096, dma_base=None, dma_size=None)


def test_the_f2_stimulus_word_is_the_peer_byte_and_is_one_byte() -> None:
    record = parse_record("F2:40003024:000000a5", windows=windows(),
                          arity={"F1": 1, "F2": 1, "F3": 2, "F4": 2, "F5": 3, "F6": 4},
                          serial={"name": "serial0"})
    assert record["fields"] == (0x40003024, 0xa5)

    with pytest.raises(ValueError):
        parse_record("F2:40003024:000001a5", windows=windows(),
                     arity={"F1": 1, "F2": 1, "F3": 2, "F4": 2, "F5": 3, "F6": 4},
                     serial={"name": "serial0"})
    # Without a pad model or a peer the second word is still refused: nothing
    # would consume it.
    with pytest.raises(ValueError):
        parse_record("F2:40003024:000000a5", windows=windows(),
                     arity={"F1": 1, "F2": 1, "F3": 2, "F4": 2, "F5": 3, "F6": 4})


def test_the_case_document_carries_one_block_per_declared_group_and_peer() -> None:
    groups = [{"name": "phase_low"}, {"name": "phase_high"}]
    keys = case_observation_keys("F2", "apb3", pins=False,
                                 groups=groups, serial=True)
    assert "pin_group0_changes" in keys and "pin_group1_ticks" in keys
    assert "serial_rx_byte" in keys and "serial_tx_byte" in keys
    assert set(pin_group_case_keys(groups)) <= set(keys)
    assert set(serial_peer_case_keys()) <= set(keys)
    # A build that declares neither keeps its historical key set exactly.
    plain = case_observation_keys("F2", "apb3")
    assert not [key for key in plain if key.startswith(("pin_group", "serial_"))]

    record = {"flow": "F2", "text": "F2:40003024:000000a5",
              "fields": [0x40003024, 0xa5]}
    case = {"index": 1, "flow": "F2", "status": "observations_passed",
            "pin_group1_ticks": 5, "serial_rx_byte": "0x000000a5"}
    document = case_document(record, case, groups=groups, serial=True)
    assert document["pin_groups"]["pin_group1_ticks"] == 5
    assert document["serial_peer"]["serial_rx_byte"] == "0x000000a5"
    assert document["pin_groups"]["pin_group0_kind"] == "unknown"


# ---------------------------------------------------------------------------
# The recorded batch (skipped when the evidence directory is not present)
# ---------------------------------------------------------------------------
def case_rows(run: str) -> list[dict]:
    log = EVIDENCE / run / "run.log"
    if not log.is_file():
        pytest.skip("no recorded batch under " + str(EVIDENCE / run))
    rows = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.startswith("case "):
            rows.append(parse_case_line(line, flows={"F1", "F2", "F3", "F4", "F5", "F6"}))
    return rows


def test_the_recorded_serial_batch_receives_and_transmits_a_byte() -> None:
    rows = case_rows("serial-8n1")
    assert [row["status"] for row in rows] == ["observations_passed"] * 5
    assert rows[0]["record"] == "F4:40003010:80000003"

    # The peer's complete 8n1 frame: ten bit times of the declared 32 ticks.
    receive = rows[1]
    assert receive["record"] == "F2:40003024:000000a5"
    assert (receive["serial_rx_frames"], receive["serial_rx_bits"]) == (1, 10)
    assert receive["serial_rx_byte"] == 0xa5
    assert receive["serial_rx_levels"] == 0x34a
    assert receive["serial_rx_framing_ok"] == 1
    assert receive["serial_rx_cpu_held_ticks"] == 320
    assert receive["serial_rx_last_tick"] - receive["serial_rx_first_tick"] == 319
    # The device's own RX FIFO level rose by exactly one entry: RXLVL is bits 23:16
    # of FIFO_STATUS (0x24), so one received byte reads 0x00010000.
    assert receive["read_value"] == 0x00010000
    # The data register then hands the CPU the very byte the peer clocked in, and
    # the level returns to zero after that pop.
    assert rows[2]["read_value"] == 0xa5
    assert rows[3]["read_value"] == 0x0

    # The device transmits: the host decoded its tx line and the device's own
    # tx_done interrupt was delivered and taken.
    transmit = rows[4]
    assert transmit["serial_tx_frames"] == 1
    assert transmit["serial_tx_byte"] == 0x5a
    assert transmit["serial_tx_levels"] == 0x2b4
    assert transmit["serial_tx_framing_ok"] == 1
    assert transmit["serial_tx_bits"] == 10
    assert transmit["irq_takes"] == 1
    assert transmit["isr_flag"] == 1
    # INTR_STATE after the send: tx_watermark (bit 0), tx_done (bit 2) and
    # tx_empty (bit 8) - the byte really left the FIFO.
    assert transmit["isr_read_value"] == 0x105


def test_the_recorded_serial_batch_logs_every_bit_time() -> None:
    log = EVIDENCE / "serial-8n1" / "run.log"
    if not log.is_file():
        pytest.skip("no recorded batch under " + str(EVIDENCE / "serial-8n1"))
    text = log.read_text(encoding="utf-8")
    rx_ticks = sorted({int(line.split()[2]) for line in text.splitlines()
                       if line.startswith("serial rx ") and " bit " in line})
    tx_ticks = sorted({int(line.split()[2]) for line in text.splitlines()
                       if line.startswith("serial tx ") and " bit " in line})
    # Nine interior bit boundaries plus the frame's end: one per 32-tick bit time.
    assert len(rx_ticks) == 9 and len(tx_ticks) == 10
    assert all(b - a == 32 for a, b in zip(rx_ticks, rx_ticks[1:]))
    assert all(b - a == 32 for a, b in zip(tx_ticks, tx_ticks[1:]))
    # The two frames are the declared ten bits each, one sample per bit time.
    assert "serial rx" in text and "frame end byte 0x000000a5" in text
    assert "serial tx" in text and "frame end byte 0x0000005a" in text


@pytest.mark.parametrize("run,frame,ctrl,levels,parity,bits,held", [
    ("serial-8e1", "8e1", "0x80000043", 0x54a, 0, 11, 352),
    ("serial-8o1", "8o1", "0x800000c3", 0x74a, 1, 11, 352),
])
def test_the_recorded_parity_frames_are_really_eleven_bit_times(run: str, frame: str,
                                                               ctrl: str, levels: int,
                                                               parity: int, bits: int,
                                                               held: int) -> None:
    rows = case_rows(run)
    assert [row["status"] for row in rows] == ["observations_passed"] * 4
    assert rows[0]["record"] == "F4:40003010:" + ctrl[2:]
    receive = rows[1]
    assert receive["serial_peer_frame"] == frame
    assert (receive["serial_rx_bits"], receive["serial_rx_cpu_held_ticks"]) == (bits, held)
    assert receive["serial_rx_levels"] == levels
    assert receive["serial_rx_parity_bit"] == parity
    # The device accepted the frame (its own parity check is PARITY_EN in CTRL), so
    # the byte reached the RX FIFO and came back out of the data register.
    assert receive["read_value"] == 0x10000
    assert rows[2]["read_value"] == 0xa5
    # And the device's own transmission carries the same frame shape and parity.
    transmit = rows[3]
    assert transmit["serial_tx_byte"] == 0xa5
    assert transmit["serial_tx_levels"] == levels
    assert transmit["serial_tx_parity_bit"] == parity
    assert transmit["serial_tx_framing_ok"] == 1
    assert transmit["irq_takes"] == 1


def test_the_recorded_group_batch_executes_every_group_in_order() -> None:
    rows = case_rows("groups-order")
    assert [row["status"] for row in rows] == ["observations_passed"] * 7
    for row in rows:
        assert row["pin_groups_declared"] == 2
        assert row["pin_groups_executed"] == 2
        assert row["pin_group0_name"] == "phase_low"
        assert row["pin_group1_name"] == "phase_high"
        assert row["pin_group0_hold_ticks"] == 2
        assert row["pin_group1_hold_ticks"] == 3
        assert row["pin_group0_ticks"] == 2
        assert row["pin_group1_ticks"] > 2

    # The wire really took each group's declared word in declaration order.
    first = rows[1]
    assert (first["pin_group0_ext"], first["pin_group0_pad_after"]) == (
        0x1111, 0x1111)
    assert (first["pin_group1_ext"], first["pin_group1_pad_after"]) == (
        0x2222, 0x2222)
    assert first["read_value"] == 0x2222
    # A case's own stimulus word overrides the first group and nothing else.
    stimulus = rows[2]
    assert stimulus["pin_stimulus_group"] == 0
    assert stimulus["pin_group0_ext"] == 0xf0f0
    assert stimulus["pin_group1_ext"] == 0x2222
    # The inout resolution follows the device once the CPU makes every pin an
    # output: the wire becomes the device's own PADOUT word, and the CPU's PADIN
    # read returns it (GPIOEN was enabled in the first case, so the RTL's input
    # synchronizer really tracks the pin).
    assert rows[5]["read_value"] == 0x2a
    # And every group's declared direction was witnessed by the device's dir port.
    assert rows[-1]["pin_groups_direction_conflicts"] == 0


def test_the_recorded_direction_batch_reports_a_falsifiable_witness() -> None:
    rows = case_rows("groups-direction")
    assert [row["status"] for row in rows] == ["observations_passed"] * 5
    # The first case is the PADDIR write itself: the output group holds the wire
    # for its first two ticks while the device still says every pin is an input,
    # so the declaration is contradicted by exactly 32 bits and the line says so.
    assert rows[0]["pin_group0_direction"] == "out"
    assert rows[0]["pin_group0_direction_witness"] == "contradicted"
    assert rows[0]["pin_groups_direction_conflicts"] == 32
    # From the next case on the witness is honoured, and the inout group never
    # claims one.
    for row in rows[1:]:
        assert row["pin_group0_direction_witness"] == "honoured"
        assert row["pin_groups_direction_conflicts"] == 0
        assert row["pin_group1_direction_witness"] == "honoured"


def test_the_recorded_refusals_are_the_exact_named_ones() -> None:
    expected = {
        "refused-uart-serial-two-stop-bits":
            "unsupported-behavior-value:pin_groups.frame",
        "refused-uart-serial-half-duplex":
            "unsupported-behavior-execution:serial_peer:half_duplex",
        "refused-uart-two-serial-peers":
            "unsupported-behavior-execution:serial_peer:count:2",
        "refused-gpio-second-pad-word":
            "unsupported-pins:pin_groups:second-pad-word",
        "refused-uart-serial-role-missing":
            "unsupported-serial:role:rts_n",
    }
    for name, reason in expected.items():
        capture = EVIDENCE / "refusals" / (name + ".stdout")
        if not capture.is_file():
            pytest.skip("no recorded refusal under " + str(capture))
        text = capture.read_text(encoding="utf-8")
        assert reason in text, (name, reason)
        assert "Traceback" in text  # the run exited, it did not silently skip
