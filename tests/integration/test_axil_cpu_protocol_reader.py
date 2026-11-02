"""The admitted AXI4-Lite CPU witness reader over the real sampled taps.

Scope: the *readers* of ``integration/axil_cpu_protocol_observations`` -- the
instruction-fetch witness and the completed-beat projection -- and the declared
read data granularity they record.  Everything here is built from a real rendered
artifact's own role names, so the fixtures cannot drift from the harness the
native campaign actually runs; no beat, address, strobe or fetch is fabricated.

The one deliberately synthetic part is the *event stream*: this module composes
the exact ``driver_samples[*].pre`` shape the generated driver emits, which is
what lets the refusal paths be proven without a native process.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.integration.axil_cpu_protocol_observations import (
    STEP_PREFIX, AxilProtocolObservationRefused, axi4lite_cpu_protocol_observations,
    collect_axi4lite_cpu_beats, collect_axi4lite_cpu_fetches)
from myfuzz.local_harness.axi_lite_session import (
    FULL_WORD_BYTE_ENABLE, READ_TRANSFER_DECLARATION, GeneratedAxiLiteMemorySession)

ROOT = Path(__file__).resolve().parents[2]
CPU_ARTIFACT = Path("runs/axil-generic-prepare-20261029/generated/cpu/artifact.json")


@pytest.fixture(scope="module")
def document():
    """The real rendered runtime document of the pinned PicoRV32 AXI4-Lite CPU."""
    path = ROOT / CPU_ARTIFACT
    if not path.is_file():
        pytest.skip("no rendered AXI4-Lite artifact in this workspace")
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def observation(document):
    return axi4lite_cpu_protocol_observations(document)


def _taps(observation, **values):
    """A sampled tap row with every role idle except the named ones."""
    taps = {name: 0 for name in observation["signals"].values()}
    by_role = observation["signals"]
    taps[by_role["rready"]] = 1
    taps[by_role["bready"]] = 1
    for role, value in values.items():
        taps[by_role[role]] = value
    return taps


def _backend(**values):
    row = dict(m_req_valid=0, m_req_ready=0, m_req_write=0, m_req_addr=0,
               m_req_wdata=0, m_req_be=0, m_rsp_valid=0, m_rsp_ready=0,
               m_rsp_rdata=0, m_rsp_error=0)
    row.update(values)
    return row


def _step(event_id, tick, *, taps, backend):
    return {"event_id": event_id, "component": "cpu", "local_tick": tick,
            "outputs": {"driver_samples": [{"local_tick": tick,
                                           "pre": {"backend": backend,
                                                   "protocol_taps": taps},
                                           "post": {"backend": backend,
                                                    "protocol_taps": taps}}]}}


def _read_beat(observation, *, address=0x1000, prot=0, rdata=0x12345678,
               fetch_qualified=True):
    """AR handshake, backend acceptance, R reply -- the real three-tick shape."""
    taps = _taps(observation)  # noqa: F841 - documentation of the shape
    handshake_taps = _taps(observation, arvalid=1, arready=1, araddr=address,
                           arprot=prot, wstrb=0)
    accept_taps = _taps(observation, araddr=address, arprot=prot, wstrb=0)
    reply_taps = _taps(observation, araddr=address, arprot=prot, wstrb=0,
                       rvalid=1, rready=1, rdata=rdata)
    return [
        _step(1, 1, taps=handshake_taps, backend=_backend()),
        _step(2, 2, taps=accept_taps,
              backend=_backend(m_req_valid=1, m_req_ready=1, m_req_addr=address,
                               m_req_be=0)),
        _step(3, 3, taps=reply_taps,
              backend=_backend(m_rsp_valid=1, m_rsp_ready=1,
                               m_rsp_rdata=rdata)),
    ]


def _write_beat(observation, *, address=0x2000, value=0x0BADF00D, be=15):
    handshake_taps = _taps(observation, awvalid=1, awready=1, awaddr=address,
                           wvalid=1, wready=1, wdata=value, wstrb=be)
    accept_taps = _taps(observation, awaddr=address, wdata=value, wstrb=be)
    reply_taps = _taps(observation, awaddr=address, wdata=value, wstrb=be,
                       bvalid=1, bready=1)
    return [
        _step(1, 1, taps=handshake_taps, backend=_backend()),
        _step(2, 2, taps=accept_taps,
              backend=_backend(m_req_valid=1, m_req_ready=1, m_req_write=1,
                               m_req_addr=address, m_req_wdata=value,
                               m_req_be=be)),
        _step(3, 3, taps=reply_taps, backend=_backend()),
    ]


# ---------------------------------------------------------------------------
# The declared read data granularity
# ---------------------------------------------------------------------------

def test_read_transfer_is_declared_once_and_states_the_semantics():
    declaration = READ_TRANSFER_DECLARATION
    assert declaration["protocol"] == "axi4-lite"
    assert declaration["granularity"] == "whole_addressed_word"
    assert declaration["transfer_bytes"] == 4
    assert declaration["statement"] == (
        "read transfers the whole addressed word; the sampled wstrb is 0 because "
        "AXI4-Lite has no read strobe")
    assert declaration["sampled_read_strobe"] == 0
    assert declaration["router_request_byte_enable"] == 15
    assert declaration["write_byte_enable_source"] == "sampled_write_strobe"
    assert "picorv32.v:2777" in declaration["sampled_read_strobe_basis"]
    assert "protocol_taps" in declaration["sampled_strobe_evidence"]
    # The session's own pin fact and the declared router access are distinct.
    assert GeneratedAxiLiteMemorySession.read_request_be == 0
    assert FULL_WORD_BYTE_ENABLE == 15


def test_observation_echoes_the_declaration(observation):
    assert observation["read_transfer"] == READ_TRANSFER_DECLARATION
    assert observation["fetch_observation"]["role"] == "arprot"
    assert observation["fetch_observation"]["qualified_by"] == ["arvalid", "arready"]


# ---------------------------------------------------------------------------
# Instruction-fetch witness
# ---------------------------------------------------------------------------

def test_fetch_witness_is_qualified_by_the_ar_handshake(observation):
    events = _read_beat(observation, address=0x1000, prot=0b100)
    fetches = collect_axi4lite_cpu_fetches(events, cpu="cpu",
                                           observation=observation)
    # One fetch, witnessed at the AR acceptance event, never duplicated at the
    # backend request that follows it.
    assert fetches == [(1, 0x1000)]


def test_data_read_is_not_a_fetch(observation):
    events = _read_beat(observation, address=0x40001000, prot=0)
    assert collect_axi4lite_cpu_fetches(events, cpu="cpu",
                                        observation=observation) == []
    beats = collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    beat, = beats.values()
    assert beat["channel"] == "data" and beat["fetch"] is False
    assert beat["rdata"] == 0x12345678


def test_reset_window_fetch_is_qualified_by_the_held_pins(observation):
    """The driver's reset window consumes the first transaction unsampled.

    The AR pin is already acknowledged, but the CPU holds ``araddr``/``arprot``
    until ``mem_ready``, so the request can still be joined to the declared
    fetch bit -- and the beat says which rule qualified it.
    """
    address, prot = 0, 0b100
    events = [
        _step(1, 1,
              taps=_taps(observation, araddr=address, arprot=prot, wstrb=0),
              backend=_backend(m_req_valid=1, m_req_ready=1, m_req_addr=address,
                               m_req_be=0)),
        _step(2, 2,
              taps=_taps(observation, araddr=address, arprot=prot, wstrb=0,
                         rvalid=1, rready=1, rdata=0x00000013),
              backend=_backend(m_rsp_valid=1, m_rsp_ready=1,
                               m_rsp_rdata=0x00000013)),
    ]
    fetches = collect_axi4lite_cpu_fetches(events, cpu="cpu",
                                           observation=observation)
    assert fetches == [(1, 0)]
    beats = collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    beat, = beats.values()
    assert beat["channel"] == "instr"
    assert beat["qualified_by"] == "held_pins_after_reset_window"
    assert beat["sampled_wstrb"] == 0
    assert beat["byte_enable"] == 0


# ---------------------------------------------------------------------------
# Completed beats
# ---------------------------------------------------------------------------

def test_read_beat_keeps_the_sampled_strobe_and_the_session_sequence(observation):
    events = _read_beat(observation, address=0x40001000, rdata=85)
    beats = collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    assert set(beats) == {("data", 1)}
    beat = beats[("data", 1)]
    assert (beat["address"], beat["write"], beat["rdata"]) == (0x40001000,
                                                               False, 85)
    # The sampled wstrb of a read is recorded as sampled: 0, not rewritten to 15.
    assert beat["byte_enable"] == 0 and beat["sampled_wstrb"] == 0
    assert beat["acceptance_event"] == 2 and beat["response_event"] == 3
    assert beat["qualified_by"] == "ar_handshake"


def test_write_beat_uses_the_sampled_write_strobe(observation):
    events = _write_beat(observation)
    beats = collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    beat, = beats.values()
    assert beat["channel"] == "data" and beat["write"] is True
    assert (beat["address"], beat["value"], beat["byte_enable"]) == (
        0x2000, 0x0BADF00D, 15)
    assert beat["rdata"] is None
    assert beat["qualified_by"] == "aw_w_handshake"


def test_instruction_and_data_beats_share_one_sequence(observation):
    """Unified channel: a fetch and a data read are two sequence numbers."""
    events = (_read_beat(observation, address=0x1000, prot=0b100)
              + _read_beat(observation, address=0x40001000, rdata=170))
    # Renumber the second transaction's events so the stream is one session.
    for index, event in enumerate(events[3:], start=4):
        event["event_id"] = index
        event["local_tick"] = index
        event["outputs"]["driver_samples"][0]["local_tick"] = index
    beats = collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    assert set(beats) == {("instr", 1), ("data", 2)}
    assert beats[("data", 2)]["rdata"] == 170


# ---------------------------------------------------------------------------
# Refusals: named, never repaired
# ---------------------------------------------------------------------------

def _refusal(events, observation):
    with pytest.raises(ValueError) as refusal:
        collect_axi4lite_cpu_beats(events, cpu="cpu", observation=observation)
    assert str(refusal.value).startswith(STEP_PREFIX)
    return str(refusal.value)


def test_unowned_read_response_is_refused(observation):
    taps = _taps(observation, rvalid=1, rready=1, rdata=1)
    message = _refusal([_step(1, 1, taps=taps, backend=_backend())], observation)
    assert message.endswith("-native-unowned-read-response")


def test_unowned_write_response_is_refused(observation):
    taps = _taps(observation, bvalid=1, bready=1)
    message = _refusal([_step(1, 1, taps=taps, backend=_backend())], observation)
    assert message.endswith("-native-unowned-write-response")


def test_read_request_whose_pins_disagree_is_refused(observation):
    """The adapter request must carry the address the CPU's pins still hold."""
    taps = _taps(observation, araddr=0)
    message = _refusal([_step(1, 1, taps=taps,
                              backend=_backend(m_req_valid=1, m_req_ready=1,
                                               m_req_addr=0x1000))], observation)
    assert message.endswith("-native-read-request-mismatch")


def test_unaligned_sampled_read_address_is_refused(observation):
    taps = _taps(observation, araddr=0x1002)
    message = _refusal([_step(1, 1, taps=taps,
                              backend=_backend(m_req_valid=1, m_req_ready=1,
                                               m_req_addr=0x1002))], observation)
    assert message.endswith("-native-read-request-mismatch")


def test_write_request_without_a_witnessed_transaction_is_refused(observation):
    taps = _taps(observation, awaddr=0x2000)
    message = _refusal([_step(1, 1, taps=taps,
                              backend=_backend(m_req_valid=1, m_req_ready=1,
                                               m_req_write=1, m_req_addr=0x2000,
                                               m_req_be=15))], observation)
    assert message.endswith("-native-unowned-write-request")


def test_write_request_must_carry_the_sampled_strobe_and_value(observation):
    events = _write_beat(observation)
    events[1]["outputs"]["driver_samples"][0]["pre"]["backend"]["m_req_be"] = 3
    message = _refusal(events, observation)
    assert message.endswith("-native-write-request-mismatch")


def test_backend_request_must_match_the_sampled_address(observation):
    events = _read_beat(observation, address=0x1000)
    events[1]["outputs"]["driver_samples"][0]["pre"]["protocol_taps"][
        observation["signals"]["araddr"]] = 0x2000
    message = _refusal(events, observation)
    assert message.endswith("-native-read-request-mismatch")


def test_read_whose_adapter_strobe_is_not_zero_is_refused(observation):
    events = _read_beat(observation)
    events[1]["outputs"]["driver_samples"][0]["pre"]["backend"]["m_req_be"] = 15
    message = _refusal(events, observation)
    assert message.endswith("-native-read-strobe-mismatch")


def test_read_handshake_whose_sampled_strobe_is_not_declared_is_refused(observation):
    events = _read_beat(observation)
    events[0]["outputs"]["driver_samples"][0]["pre"]["protocol_taps"][
        observation["signals"]["wstrb"]] = 15
    message = _refusal(events, observation)
    assert message.endswith("-read-strobe-not-declared")


def test_two_outstanding_reads_are_refused(observation):
    events = _read_beat(observation)
    second = _step(2, 2,
                   taps=_taps(observation, arvalid=1, arready=1, araddr=0x3000,
                              arprot=0b100, wstrb=0),
                   backend=_backend())
    message = _refusal(events[:1] + [second] + events[2:], observation)
    assert message.endswith("-native-overlapping-read")


def test_unobserved_adapter_request_is_refused_after_one_short_read(observation):
    events = _read_beat(observation)
    message = _refusal(events[:1] + events[2:], observation)
    assert message.endswith("-native-unowned-read-response")


@pytest.mark.parametrize("defect", ["sample-count", "tick", "missing-taps",
                                    "missing-backend"])
def test_sample_shape_defects_are_refused(observation, defect):
    events = _read_beat(observation)
    sample = events[0]["outputs"]["driver_samples"]
    if defect == "sample-count":
        sample.append(dict(sample[0]))
    elif defect == "tick":
        sample[0]["local_tick"] = 99
    elif defect == "missing-taps":
        sample[0]["pre"].pop("protocol_taps")
    else:
        sample[0]["pre"].pop("backend")
    message = _refusal(events, observation)
    assert message.endswith("-native-CPU-sample-shape")


def test_missing_tap_value_is_refused(observation):
    events = _read_beat(observation)
    events[0]["outputs"]["driver_samples"][0]["pre"]["protocol_taps"].pop(
        observation["signals"]["arvalid"])
    message = _refusal(events, observation)
    assert "-native-CPU-sample-missing-tap:" in message


def test_taps_of_other_components_are_ignored(observation):
    events = _read_beat(observation)
    for event in events:
        event["component"] = "peripheral"
    assert collect_axi4lite_cpu_beats(events, cpu="cpu",
                                      observation=observation) == {}
    assert collect_axi4lite_cpu_fetches(events, cpu="cpu",
                                        observation=observation) == []


def test_reader_reports_its_own_step_prefix(observation):
    broken = [_step(1, 1, taps=_taps(observation, rvalid=1, rready=1, rdata=1),
                    backend=_backend())]
    with pytest.raises(ValueError) as refusal:
        collect_axi4lite_cpu_beats(broken, cpu="cpu", observation=observation,
                                   error_prefix="custom-prefix")
    assert str(refusal.value) == "custom-prefix-native-unowned-read-response"
