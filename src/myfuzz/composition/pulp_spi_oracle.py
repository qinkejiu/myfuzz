"""Independent, fail-closed wire/transaction oracle for pinned PULP APB SPI.

This oracle covers one finite 32-bit standard-mode phase at a time. PULP's
controller selects either its TXFIFO-to-MOSI path or its receive-to-RXFIFO
path; it does not transfer both directions in one phase. Wire expectations
come from accepted APB TXFIFO writes or recorded peer-arm input words, never
from DUT outputs or peer counters.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


_EXPECTED_PROFILE = {
    "component_id": "pulp_spi",
    "top_module": "apb_spi_master",
    "source_revision": "sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230",
}
_RTL_PARAMETERS = {
    "BUFFER_DEPTH": 10,
    "APB_ADDR_WIDTH": 12,
}
_TRANSFER_CONTRACT = {
    "BITS": 32,
    "CPOL": 0,
    "CPHA": 0,
    "CS_ACTIVE_LOW": 1,
}
_CAPTURE_STREAMS = (
    "apb_transactions", "peer_arms", "wire_trace", "rx_reads", "source_requests",
)
_ROLES = (
    "sck", "csn0", "csn1", "csn2", "csn3", "mode",
    "sdo0", "sdo1", "sdo2", "sdo3",
    "sdi0", "sdi1", "sdi2", "sdi3",
)
_BASE_PROPERTIES = (
    "SPI.CS_WINDOW", "SPI.SCK_IDLE_MODE0", "SPI.MODE0_EDGE_COUNT", "SPI.STD_LANES",
)


def _result(verdict: str, reason: str, *, property_ids: Sequence[str] = (),
            failed_property_ids: Sequence[str] = (), expected: Mapping[str, object] | None = None,
            observed: Mapping[str, object] | None = None) -> dict[str, object]:
    expected_doc = dict(expected or {"mosi_words": None, "miso_words": None})
    observed_doc = dict(observed or {
        "mosi_words": None, "miso_words": None, "rxfifo_words": [],
    })
    return {
        "verdict": verdict,
        "status": verdict,
        "reason": reason,
        "profile": dict(_EXPECTED_PROFILE),
        "contract": dict(_TRANSFER_CONTRACT),
        "property_ids": list(property_ids),
        "failed_property_ids": list(failed_property_ids),
        "not_assessed_reason": reason if verdict == "not_assessed" else None,
        "expected": expected_doc,
        "observed": observed_doc,
    }


def _not_assessed(reason: str) -> dict[str, object]:
    return _result("not_assessed", reason)


def _mismatch(reason: str, property_id: str, *,
              expected: Mapping[str, object], observed: Mapping[str, object],
              property_ids: Sequence[str]) -> dict[str, object]:
    return _result("mismatch", reason, property_ids=property_ids,
                   failed_property_ids=(property_id,), expected=expected,
                   observed=observed)


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _bit(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if value in (0, 1):
        return int(value)
    if value in ("0", "1"):
        return int(value)
    return None


def _mode(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 3:
        return value
    if isinstance(value, str) and value in ("00", "01", "10", "11"):
        return int(value, 2)
    return None


def _parse_wire(trace: object) -> tuple[list[dict[str, int]] | None, str | None]:
    if not _is_sequence(trace) or not trace:
        return None, "spi-wire-trace-missing"
    rows: list[dict[str, int]] = []
    previous_cycle = -1
    for index, raw in enumerate(trace):
        if not isinstance(raw, Mapping):
            return None, f"spi-wire-record-invalid:{index}"
        cycle = _integer(raw.get("cycle"))
        if cycle is None or cycle < 0 or cycle <= previous_cycle:
            return None, f"spi-wire-cycle-invalid:{index}"
        previous_cycle = cycle
        row = {"cycle": cycle}
        for role in _ROLES:
            value = _mode(raw.get(role)) if role == "mode" else _bit(raw.get(role))
            if value is None:
                return None, f"spi-wire-value-invalid:{index}:{role}"
            row[role] = value
        rows.append(row)
    return rows, None


def _parse_apb(rows: object) -> tuple[list[dict[str, int | bool]] | None, str | None]:
    if not _is_sequence(rows):
        return None, "spi-apb-records-invalid"
    parsed: list[dict[str, int | bool]] = []
    previous_cycle = -1
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            return None, f"spi-apb-record-invalid:{index}"
        cycle = _integer(raw.get("cycle"))
        address = _integer(raw.get("address"))
        accepted = raw.get("accepted")
        write_value = raw.get("write")
        if cycle is None or cycle < 0 or cycle <= previous_cycle:
            return None, f"spi-apb-cycle-invalid:{index}"
        previous_cycle = cycle
        if address is None or not 0 <= address < (1 << _RTL_PARAMETERS["APB_ADDR_WIDTH"]):
            return None, f"spi-apb-address-invalid:{index}"
        if not isinstance(accepted, bool) or not isinstance(write_value, bool):
            return None, f"spi-apb-control-invalid:{index}"
        # PULP decodes PADDR[5:2]. Higher address bits and PADDR[1:0] alias.
        offset = address & 0x3C
        item: dict[str, int | bool] = {
            "cycle": cycle, "address": address, "offset": offset,
            "accepted": accepted, "write": write_value,
        }
        if accepted and write_value:
            request_id = _integer(raw.get("source_request_id"))
            if request_id is None or request_id < 0:
                return None, f"spi-apb-source-request-missing:{index}"
            item["source_request_id"] = request_id
        if write_value:
            wdata = _integer(raw.get("wdata"))
            if wdata is None or not 0 <= wdata <= 0xFFFF_FFFF:
                return None, f"spi-apb-wdata-invalid:{index}"
            item["wdata"] = wdata
        else:
            rdata = _integer(raw.get("rdata"))
            if raw.get("accepted") is True and rdata is None:
                return None, f"spi-apb-rdata-invalid:{index}"
            item["rdata"] = -1 if rdata is None else rdata
        pslverr = raw.get("pslverr", 0)
        if _bit(pslverr) is None:
            return None, f"spi-apb-pslverr-invalid:{index}"
        item["pslverr"] = int(_bit(pslverr) or 0)
        if accepted and item["pslverr"]:
            return None, "spi-apb-error-response"
        parsed.append(item)
    return parsed, None


def _parse_source_requests(rows: object) -> tuple[dict[int, dict[str, int]] | None, str | None]:
    if not _is_sequence(rows):
        return None, "spi-source-request-records-invalid"
    parsed: dict[int, dict[str, int]] = {}
    previous_cycle = -1
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            return None, f"spi-source-request-record-invalid:{index}"
        request_id = _integer(raw.get("request_id"))
        cycle = _integer(raw.get("cycle"))
        address = _integer(raw.get("address"))
        source_id = _integer(raw.get("source_id"))
        accepted = raw.get("accepted")
        write_value = raw.get("write")
        byte_enable = _integer(raw.get("byte_enable"))
        wdata = _integer(raw.get("wdata"))
        if request_id is None or request_id < 0 or request_id in parsed:
            return None, f"spi-source-request-id-invalid:{index}"
        if cycle is None or cycle < 0 or cycle < previous_cycle:
            return None, f"spi-source-request-cycle-invalid:{index}"
        if address is None or not 0 <= address <= 0xFFFF_FFFF:
            return None, f"spi-source-request-address-invalid:{index}"
        if source_id is None or source_id < 0:
            return None, f"spi-source-request-source-invalid:{index}"
        if accepted is not True or not isinstance(write_value, bool):
            return None, f"spi-source-request-control-invalid:{index}"
        if write_value:
            if byte_enable is None or not 0 <= byte_enable <= 0xF:
                return None, f"spi-source-request-byte-enable-invalid:{index}"
            if wdata is None or not 0 <= wdata <= 0xFFFF_FFFF:
                return None, f"spi-source-request-wdata-invalid:{index}"
        else:
            byte_enable = -1 if byte_enable is None else byte_enable
            wdata = -1 if wdata is None else wdata
        parsed[request_id] = {
            "request_id": request_id, "cycle": cycle, "address": address,
            "source_id": source_id, "byte_enable": byte_enable, "wdata": wdata,
            "write": int(write_value),
        }
        previous_cycle = cycle
    return parsed, None


def _parse_peer_arms(rows: object) -> tuple[list[dict[str, int]] | None, str | None]:
    if not _is_sequence(rows):
        return None, "spi-peer-arm-records-invalid"
    parsed: list[dict[str, int]] = []
    previous_cycle = -1
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            return None, f"spi-peer-arm-record-invalid:{index}"
        cycle = _integer(raw.get("cycle"))
        payload = _integer(raw.get("payload"))
        if cycle is None or cycle < 0 or cycle <= previous_cycle:
            return None, f"spi-peer-arm-cycle-invalid:{index}"
        if payload is None or not 0 <= payload <= 0xFFFF_FFFF:
            return None, f"spi-peer-arm-payload-invalid:{index}"
        previous_cycle = cycle
        parsed.append({"cycle": cycle, "payload": payload})
    return parsed, None


def _parse_rx_reads(rows: object) -> tuple[list[dict[str, int]] | None, str | None]:
    if not _is_sequence(rows):
        return None, "spi-rx-read-records-invalid"
    parsed: list[dict[str, int]] = []
    previous_cycle = -1
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            return None, f"spi-rx-read-record-invalid:{index}"
        cycle = _integer(raw.get("cycle"))
        address = _integer(raw.get("address"))
        accepted = raw.get("accepted")
        value = _integer(raw.get("rdata"))
        if cycle is None or cycle < 0 or cycle <= previous_cycle:
            return None, f"spi-rx-read-cycle-invalid:{index}"
        if address is None or not 0 <= address < (1 << _RTL_PARAMETERS["APB_ADDR_WIDTH"]):
            return None, f"spi-rx-read-address-invalid:{index}"
        if not isinstance(accepted, bool):
            return None, f"spi-rx-read-control-invalid:{index}"
        if value is None or not 0 <= value <= 0xFFFF_FFFF:
            return None, f"spi-rx-read-data-invalid:{index}"
        previous_cycle = cycle
        parsed.append({"cycle": cycle, "address": address & 0x3C,
                       "accepted": int(accepted), "rdata": value})
    return parsed, None


def _capture_problem(metadata: object, streams: Mapping[str, object]) -> str | None:
    if not isinstance(metadata, Mapping):
        return "spi-capture-completeness-missing:apb_transactions"
    for stream in _CAPTURE_STREAMS:
        if stream not in metadata:
            return f"spi-capture-completeness-missing:{stream}"
        status = metadata[stream]
        records = streams.get(stream)
        if not isinstance(status, Mapping):
            return f"spi-capture-status-invalid:{stream}"
        captured = _integer(status.get("captured"))
        total = _integer(status.get("total"))
        truncated = status.get("truncated")
        if (captured is None or total is None or captured < 0 or total < captured
                or not isinstance(truncated, bool)):
            return f"spi-capture-status-invalid:{stream}"
        if not _is_sequence(records):
            return f"spi-capture-stream-invalid:{stream}"
        if captured != len(records):
            return f"spi-capture-count-mismatch:{stream}"
        if truncated != (total > captured):
            return f"spi-capture-status-invalid:{stream}"
        if truncated:
            return f"spi-capture-truncated:{stream}"
    return None


def _correlate_apb_source_requests(
        apb: Sequence[Mapping[str, Any]], source_requests: Mapping[int, Mapping[str, int]],
        *, window_base: int, cpu_data_source_ids: frozenset[int]) -> str | None:
    used: set[int] = set()
    for row in apb:
        if row["accepted"] is not True or row["write"] is not True:
            continue
        request_id = int(row["source_request_id"])
        request = source_requests.get(request_id)
        if request is None:
            return "spi-apb-source-request-missing"
        if request_id in used:
            return "spi-apb-source-request-ambiguous"
        if (not request["write"] or request["cycle"] > int(row["cycle"])
                or request["address"] != window_base + int(row["address"])
                or request["wdata"] != int(row["wdata"])):
            return "spi-apb-source-request-mismatch"
        if request["source_id"] not in cpu_data_source_ids:
            return "spi-apb-source-not-cpu-data"
        if request["byte_enable"] != 0xF:
            return ("spi-txfifo-partial-write" if row["offset"] == 0x18
                    else "spi-apb-partial-write")
        used.add(request_id)
    for request_id, request in source_requests.items():
        if (request["write"] and window_base <= request["address"] <
                window_base + (1 << _RTL_PARAMETERS["APB_ADDR_WIDTH"])):
            if request_id not in used:
                return "spi-source-request-unmatched"
    return None


def _one_accepted_write(rows: Sequence[Mapping[str, Any]],
                        offset: int) -> tuple[Mapping[str, Any] | None, str | None]:
    found = [row for row in rows
             if row["accepted"] is True and row["write"] is True and row["offset"] == offset]
    if not found:
        return None, f"spi-apb-setup-missing:0x{offset:02x}"
    if len(found) != 1:
        return None, f"spi-apb-setup-ambiguous:0x{offset:02x}"
    return found[0], None


def _sample_word(bits: Sequence[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _decode_frame(rows: Sequence[Mapping[str, int]], direction: str,
                  ) -> tuple[dict[str, object] | None, tuple[str, str] | None]:
    idle = 1
    previous = rows[0]
    if previous["sck"] != 0 or any(previous[f"csn{i}"] != idle for i in range(4)):
        return None, ("not_assessed:spi-wire-initial-idle-missing", "")
    observed: dict[str, object] = {
        "mosi_words": None, "miso_words": None, "rxfifo_words": [],
    }
    active = False
    closed = False
    sample_edges = 0
    shift_edges = 0
    mosi_bits: list[int] = []
    miso_bits: list[int] = []
    selection_cycle: int | None = None
    deselection_cycle: int | None = None
    mode_transient_seen = False

    def fail(status: str, reason: str, property_id: str) -> tuple[None, tuple[str, str]]:
        return None, (f"{status}:{reason}", property_id)

    for current in rows[1:]:
        old_cs = tuple(previous[f"csn{i}"] for i in range(4))
        new_cs = tuple(current[f"csn{i}"] for i in range(4))
        old_any = any(level == 0 for level in old_cs)
        new_any = any(level == 0 for level in new_cs)

        if not old_any and new_any:
            if active or closed:
                return fail("mismatch", "spi-cs-selection-count-mismatch", "SPI.CS_WINDOW")
            if new_cs[0] != 0 or any(level != 1 for level in new_cs[1:]):
                return fail("mismatch", "spi-wrong-chip-select", "SPI.CS_WINDOW")
            if previous["sck"] != 0 or current["sck"] != 0:
                return fail("mismatch", "spi-sck-not-idle-at-select", "SPI.SCK_IDLE_MODE0")
            active = True
            selection_cycle = current["cycle"]
        elif old_any and not new_any:
            if not active:
                return fail("mismatch", "spi-cs-window-invalid", "SPI.CS_WINDOW")
            if previous["sck"] != 0 or current["sck"] != 0:
                return fail("mismatch", "spi-sck-not-idle-at-deselect", "SPI.SCK_IDLE_MODE0")
            if sample_edges != 32 or shift_edges != 32:
                return fail("mismatch", "spi-wire-incomplete-frame", "SPI.MODE0_EDGE_COUNT")
            active = False
            closed = True
            deselection_cycle = current["cycle"]
        elif new_any:
            if not active or new_cs[0] != 0 or any(level != 1 for level in new_cs[1:]):
                return fail("mismatch", "spi-wrong-chip-select", "SPI.CS_WINDOW")
        elif not new_any and current["sck"] != 0:
            return fail("mismatch", "spi-sck-not-idle-mode0", "SPI.SCK_IDLE_MODE0")

        if active and current["mode"] != 0:
            # The pinned controller may show QUAD_RX once while CS is being
            # asserted. That single setup sample is tolerated before the first
            # edge; a nonstandard mode during clocking is a protocol mismatch.
            if (not mode_transient_seen and previous["sck"] == current["sck"]
                    and sample_edges == 0 and shift_edges == 0):
                mode_transient_seen = True
                previous = current
                continue
            return fail("mismatch", "spi-standard-mode-violation",
                        "SPI.STD_LANES")

        if active and previous["sck"] != current["sck"]:
            if previous["sck"] == 0 and current["sck"] == 1:
                if direction == "tx":
                    if previous["sdo0"] != current["sdo0"]:
                        return fail("mismatch", "spi-mode0-data-edge-violation",
                                    "SPI.MODE0_EDGE_COUNT")
                    # PULP drives sdo1..3 from adjacent shift-register bits
                    # even in standard mode. Only sdo0 is normative MOSI.
                    mosi_bits.append(current["sdo0"])
                else:
                    if previous["sdi1"] != current["sdi1"]:
                        return fail("mismatch", "spi-mode0-data-edge-violation",
                                    "SPI.MODE0_EDGE_COUNT")
                    # Only sdi1 is the selected standard-mode MISO input;
                    # unused input lane levels are outside this contract.
                    miso_bits.append(current["sdi1"])
                sample_edges += 1
                if sample_edges > 32:
                    return fail("mismatch", "spi-wire-too-many-sample-edges",
                                "SPI.MODE0_EDGE_COUNT")
            else:
                shift_edges += 1
                if shift_edges > 32:
                    return fail("mismatch", "spi-wire-too-many-shift-edges",
                                "SPI.MODE0_EDGE_COUNT")
        previous = current

    if active:
        return None, ("not_assessed:spi-wire-trace-truncated", "")
    if not closed or selection_cycle is None or deselection_cycle is None:
        return None, ("not_assessed:spi-cs-window-missing", "")
    if direction == "tx":
        observed["mosi_words"] = [_sample_word(mosi_bits)]
    else:
        observed["miso_words"] = [_sample_word(miso_bits)]
    observed["selection_cycle"] = selection_cycle
    observed["deselection_cycle"] = deselection_cycle
    return observed, None


def audit_pulp_spi_run(*, apb_transactions: Sequence[Mapping[str, object]],
                       peer_arms: Sequence[Mapping[str, object]],
                       wire_trace: Sequence[Mapping[str, object]],
                       rx_reads: Sequence[Mapping[str, object]],
                       source_requests: Sequence[Mapping[str, object]],
                       parameters: Mapping[str, int],
                       profile_identity: Mapping[str, object],
                       spi_window_base: int,
                       cpu_data_source_ids: Sequence[int],
                       capture_status: Mapping[str, Mapping[str, object]]
                       ) -> dict[str, object]:
    """Audit one complete, finite TX-only or RX-only PULP SPI phase.

    ``apb_transactions`` is the complete accepted/rejected APB record stream.
    Each row has ``cycle``, 12-bit ``address``, boolean ``write``/``accepted``;
    writes carry ``source_request_id`` and ``wdata``; reads carry ``rdata``.
    The separately captured accepted OBI request stream in ``source_requests``
    supplies the actual write byte enables and is linked by request ID, address,
    data, source, and cycle. ``peer_arms`` records raw arm inputs with cycle and payload.
    ``wire_trace`` contains one HCLK observation per row and all 14 PULP pin
    roles. ``rx_reads`` is a duplicate evidence view of accepted RXFIFO reads
    and must match the corresponding APB records exactly. ``profile_identity``
    must identify the pinned sources and ``capture_status`` must provide
    captured/total/truncated counts that agree with each supplied stream.

    Returns ``pass`` only when APB setup, phase direction, CS0 mode-0 framing,
    role lanes, literal wire data, and any RXFIFO read all agree. Unsupported
    profiles, incomplete evidence, partial writes, or ambiguous direction are
    ``not_assessed``; a complete normative behavior mismatch is ``mismatch``.
    """
    streams = {
        "apb_transactions": apb_transactions,
        "peer_arms": peer_arms,
        "wire_trace": wire_trace,
        "rx_reads": rx_reads,
        "source_requests": source_requests,
    }
    problem = _capture_problem(capture_status, streams)
    if problem:
        return _not_assessed(problem)
    if not isinstance(profile_identity, Mapping):
        return _not_assessed("spi-profile-identity-invalid")
    for name, required in _EXPECTED_PROFILE.items():
        if profile_identity.get(name) != required:
            return _not_assessed(f"spi-profile-identity-unsupported:{name}")
    extras = set(profile_identity) - set(_EXPECTED_PROFILE)
    if extras:
        if any(not isinstance(item, str) for item in extras):
            return _not_assessed("spi-profile-identity-invalid")
        return _not_assessed(f"spi-profile-identity-unsupported:{sorted(extras)[0]}")
    if (_integer(spi_window_base) is None or not 0 <= int(spi_window_base) <= 0xFFFF_FFFF
            or int(spi_window_base) % (1 << _RTL_PARAMETERS["APB_ADDR_WIDTH"]) != 0):
        return _not_assessed("spi-window-base-invalid")
    if (not _is_sequence(cpu_data_source_ids) or not cpu_data_source_ids
            or any(_integer(item) is None or int(item) < 0 for item in cpu_data_source_ids)
            or len(set(cpu_data_source_ids)) != len(cpu_data_source_ids)):
        return _not_assessed("spi-cpu-data-source-ids-invalid")
    if not isinstance(parameters, Mapping):
        return _not_assessed("spi-profile-parameters-invalid")
    for name, required in _RTL_PARAMETERS.items():
        value = parameters.get(name)
        if _integer(value) != required:
            return _not_assessed(f"spi-profile-unsupported:{name}")
    extras = set(parameters) - set(_RTL_PARAMETERS)
    if extras:
        if any(not isinstance(item, str) for item in extras):
            return _not_assessed("spi-profile-parameters-invalid")
        return _not_assessed(f"spi-profile-unsupported:{sorted(extras)[0]}")

    apb, error = _parse_apb(apb_transactions)
    if error:
        return _not_assessed(error)
    arms, error = _parse_peer_arms(peer_arms)
    if error:
        return _not_assessed(error)
    rows, error = _parse_wire(wire_trace)
    if error:
        return _not_assessed(error)
    reads, error = _parse_rx_reads(rx_reads)
    if error:
        return _not_assessed(error)
    source, error = _parse_source_requests(source_requests)
    if error:
        return _not_assessed(error)
    assert (apb is not None and arms is not None and rows is not None and reads is not None
            and source is not None)

    setup: dict[int, Mapping[str, Any]] = {}
    for offset in (0x04, 0x08, 0x0C, 0x10, 0x14, 0x00):
        row, error = _one_accepted_write(apb, offset)
        if error:
            return _not_assessed(error)
        assert row is not None
        setup[offset] = row
    if not (setup[0x04]["cycle"] < setup[0x08]["cycle"] <
            setup[0x0C]["cycle"] < setup[0x10]["cycle"] <
            setup[0x14]["cycle"] < setup[0x00]["cycle"]):
        return _not_assessed("spi-apb-setup-order-invalid")
    if int(setup[0x04]["wdata"]) > 0xFF:
        return _not_assessed("spi-clkdiv-value-unsupported")
    for offset in (0x08, 0x0C, 0x14):
        if int(setup[offset]["wdata"]) != 0:
            return _not_assessed(f"spi-apb-setup-value-unsupported:0x{offset:02x}")
    if int(setup[0x10]["wdata"]) != 0x0020_0000:
        return _not_assessed("spi-data-length-unsupported")

    status_word = int(setup[0x00]["wdata"])
    direction_bits = status_word & 0x3
    if direction_bits == 0x3:
        return _not_assessed("spi-mixed-rx-tx-transfer-unsupported")
    if direction_bits not in (0x1, 0x2):
        return _not_assessed("spi-transfer-direction-unsupported")
    direction = "rx" if direction_bits == 0x1 else "tx"
    if status_word != (0x0101 if direction == "rx" else 0x0102):
        return _not_assessed("spi-status-mode-unsupported")

    tx_writes = [row for row in apb
                 if row["accepted"] is True and row["write"] is True and row["offset"] == 0x18]
    accepted_reads = [row for row in apb
                      if row["accepted"] is True and row["write"] is False and row["offset"] == 0x20]
    if direction == "rx" and tx_writes:
        return _not_assessed("spi-mixed-rx-tx-transfer-unsupported")
    if direction == "tx" and (accepted_reads or reads):
        return _not_assessed("spi-mixed-rx-tx-transfer-unsupported")
    source_error = _correlate_apb_source_requests(
        apb, source, window_base=int(spi_window_base),
        cpu_data_source_ids=frozenset(int(item) for item in cpu_data_source_ids))
    if source_error:
        return _not_assessed(source_error)
    if direction == "tx":
        if not tx_writes:
            return _not_assessed("spi-txfifo-write-missing")
        if len(tx_writes) != 1:
            return _not_assessed("spi-txfifo-write-ambiguous")
        if int(tx_writes[0]["cycle"]) >= int(setup[0x00]["cycle"]):
            return _not_assessed("spi-txfifo-write-after-start")
        if arms:
            return _not_assessed("spi-unexpected-peer-arm-for-tx")
        tx_word = int(tx_writes[0]["wdata"])
        miso_word = None
        if reads:
            return _not_assessed("spi-rxfifo-read-unexpected")
    else:
        if not arms:
            return _not_assessed("spi-peer-arm-missing")
        if len(arms) != 1:
            return _not_assessed("spi-peer-arm-ambiguous")
        tx_word = None
        miso_word = arms[0]["payload"]
        if not reads or not accepted_reads:
            return _not_assessed("spi-rxfifo-read-missing")
        if len(reads) != 1 or len(accepted_reads) != 1:
            return _not_assessed("spi-rxfifo-read-ambiguous")
        apb_read = accepted_reads[0]
        duplicate_read = reads[0]
        if (duplicate_read["accepted"] != 1 or duplicate_read["address"] != 0x20 or
                duplicate_read["cycle"] != apb_read["cycle"] or
                duplicate_read["rdata"] != apb_read["rdata"]):
            return _not_assessed("spi-rxfifo-record-mismatch")

    if (rows[0]["sck"] != 0 or any(rows[0][f"csn{i}"] != 1 for i in range(4)) or
            rows[-1]["sck"] != 0 or any(rows[-1][f"csn{i}"] != 1 for i in range(4))):
        return _not_assessed("spi-wire-trace-not-bracketed-by-idle")
    first_select = next((row["cycle"] for row in rows
                         if row["csn0"] == 0 or any(row[f"csn{i}"] == 0 for i in range(1, 4))), None)
    if first_select is None:
        return _not_assessed("spi-cs-window-missing")
    if direction == "rx" and arms[0]["cycle"] >= first_select:
        return _not_assessed("spi-peer-arm-after-selection")
    if int(setup[0x00]["cycle"]) >= first_select:
        return _not_assessed("spi-status-after-selection")

    property_ids = list(_BASE_PROPERTIES)
    phase_property = "SPI.MOSI_MSB_FIRST" if direction == "tx" else "SPI.MISO_TO_RXFIFO"
    property_ids.append(phase_property)
    expected_doc = {
        "mosi_words": [tx_word] if tx_word is not None else None,
        "miso_words": [miso_word] if miso_word is not None else None,
    }
    decoded, decode_error = _decode_frame(rows, direction)
    if decode_error:
        encoded, property_id = decode_error
        verdict, reason = encoded.split(":", 1)
        if verdict == "not_assessed":
            return _not_assessed(reason)
        return _mismatch(reason, property_id, expected=expected_doc,
                         observed={"mosi_words": None, "miso_words": None,
                                   "rxfifo_words": [int(reads[0]["rdata"])] if reads else []},
                         property_ids=property_ids)
    assert decoded is not None
    if direction == "rx" and int(reads[0]["cycle"]) <= int(decoded["deselection_cycle"]):
        return _not_assessed("spi-rxfifo-read-before-deselection")
    observed_mosi = decoded.get("mosi_words")
    observed_miso = decoded.get("miso_words")
    observed_doc = {
        "mosi_words": observed_mosi,
        "miso_words": observed_miso,
        "rxfifo_words": [int(reads[0]["rdata"])] if reads else [],
    }

    if direction == "tx" and observed_mosi != [tx_word]:
        return _mismatch("spi-mosi-word-mismatch", "SPI.MOSI_MSB_FIRST",
                         expected=expected_doc, observed=observed_doc,
                         property_ids=property_ids)
    if direction == "rx" and observed_miso != [miso_word]:
        return _mismatch("spi-miso-word-mismatch", "SPI.MISO_TO_RXFIFO",
                         expected=expected_doc, observed=observed_doc,
                         property_ids=property_ids)
    if direction == "rx" and observed_doc["rxfifo_words"] != [miso_word]:
        return _mismatch("spi-rxfifo-word-mismatch", "SPI.MISO_TO_RXFIFO",
                         expected=expected_doc, observed=observed_doc,
                         property_ids=property_ids)
    return _result("pass", "spi-transfer-verified", property_ids=property_ids,
                   expected=expected_doc, observed=observed_doc)
