"""Literal-vector tests for the independent PULP SPI wire/transaction oracle."""

from __future__ import annotations

import copy
import unittest

from myfuzz.composition.pulp_spi_oracle import audit_pulp_spi_run


# These words are test-owned expectations. They are not read from a DUT result
# or from any peer observation/counter.
MOSI_WORD = 0xA5C3_96F0
MISO_WORD = 0x5A3C_C3A5

PROFILE_PARAMETERS = {
    "BUFFER_DEPTH": 10,
    "APB_ADDR_WIDTH": 12,
}
TRANSFER_CONTRACT = {
    "BITS": 32,
    "CPOL": 0,
    "CPHA": 0,
    "CS_ACTIVE_LOW": 1,
}
PROFILE_IDENTITY = {
    "component_id": "pulp_spi",
    "top_module": "apb_spi_master",
    "source_revision": (
        "sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230"
    ),
}
SPI_WINDOW_BASE = 0x4000_1000


class _ApbRecords(list):
    def __init__(self, rows, source_requests):
        super().__init__(rows)
        self.source_requests = source_requests


def _wire_row(cycle: int, *, sck: int = 0, csn0: int = 1,
              csn1: int = 1, csn2: int = 1, csn3: int = 1,
              mode: int = 0, sdo0: int = 0, sdo1: int = 0,
              sdo2: int = 0, sdo3: int = 0, sdi0: int = 0,
              sdi1: int = 0, sdi2: int = 0, sdi3: int = 0) -> dict:
    return {
        "cycle": cycle, "sck": sck,
        "csn0": csn0, "csn1": csn1, "csn2": csn2, "csn3": csn3,
        "mode": mode,
        "sdo0": sdo0, "sdo1": sdo1, "sdo2": sdo2, "sdo3": sdo3,
        "sdi0": sdi0, "sdi1": sdi1, "sdi2": sdi2, "sdi3": sdi3,
    }


def _mode0_trace(mosi: int | None = MOSI_WORD,
                 miso: int | None = MISO_WORD, *,
                 transfer_bits: int = 32, setup_mode: int = 0) -> list[dict]:
    """Build a complete public-pin trace with data changing on falling edges."""
    mosi_bits = ([(mosi >> shift) & 1
                  for shift in range(31, 31 - transfer_bits, -1)]
                 if mosi is not None else [0] * transfer_bits)
    miso_bits = ([(miso >> shift) & 1
                  for shift in range(31, 31 - transfer_bits, -1)]
                 if miso is not None else [0] * transfer_bits)
    # APB setup, STATUS start and peer arm all precede this selection window.
    rows = [_wire_row(cycle) for cycle in range(8)]
    rows.append(_wire_row(8, csn0=0, mode=setup_mode,
                          sdo0=mosi_bits[0] if mosi_bits else 0,
                          sdi1=miso_bits[0] if miso_bits else 0))
    cycle = 9
    for index, (tx_bit, rx_bit) in enumerate(zip(mosi_bits, miso_bits)):
        rows.append(_wire_row(cycle, sck=1, csn0=0, mode=0,
                              sdo0=tx_bit, sdi1=rx_bit))
        next_tx = mosi_bits[index + 1] if index + 1 < len(mosi_bits) else 0
        next_rx = miso_bits[index + 1] if index + 1 < len(miso_bits) else 0
        rows.append(_wire_row(cycle + 1, csn0=0, mode=0,
                              sdo0=next_tx, sdi1=next_rx))
        cycle += 2
    rows.append(_wire_row(cycle, csn0=1))
    return rows


def _apb_transactions(direction: str, *, txfifo: bool = True,
                      txfifo_accepted: bool = True,
                      txfifo_byte_enable: int = 0xF,
                      rx_read_word: int | None = MISO_WORD) -> list[dict]:
    """Return recorded accepted APB writes that configure one 32-bit phase."""
    rows = [
        {"cycle": 0, "address": 0x04, "write": True, "accepted": True,
         "wdata": 0, "byte_enable": 0xF},  # CLKDIV = 0
        {"cycle": 1, "address": 0x08, "write": True, "accepted": True,
         "wdata": 0, "byte_enable": 0xF},  # no command phase
        {"cycle": 2, "address": 0x0C, "write": True, "accepted": True,
         "wdata": 0, "byte_enable": 0xF},  # no address phase
        {"cycle": 3, "address": 0x10, "write": True, "accepted": True,
         "wdata": 0x0020_0000, "byte_enable": 0xF},  # 32 data bits
        {"cycle": 4, "address": 0x14, "write": True, "accepted": True,
         "wdata": 0, "byte_enable": 0xF},  # no dummy phase
    ]
    if direction == "tx" and txfifo:
        rows.append({
            "cycle": 5, "address": 0x18, "write": True,
            "accepted": txfifo_accepted, "wdata": MOSI_WORD,
            "byte_enable": txfifo_byte_enable,
        })
    rows.append({
        "cycle": 6, "address": 0x00, "write": True, "accepted": True,
        "wdata": 0x0101 if direction == "rx" else 0x0102,
        "byte_enable": 0xF,
    })
    if direction == "rx" and rx_read_word is not None:
        rows.append({
            "cycle": 80, "address": 0x20, "write": False,
            "accepted": True, "rdata": rx_read_word,
        })
    # APB3 has no byte-enable pins.  The upstream accepted OBI request is
    # retained as separate evidence and linked by request_id for writes.
    source_requests = []
    for request_id, row in enumerate(rows):
        byte_enable = row.pop("byte_enable", 0xF)
        if row["write"] and row["accepted"]:
            row["source_request_id"] = request_id
            source_requests.append({
                "request_id": request_id,
                "cycle": max(0, row["cycle"] - 1),
                "address": SPI_WINDOW_BASE + row["address"],
                "write": True,
                "wdata": row["wdata"],
                "byte_enable": byte_enable,
                "source_id": 1,
                "accepted": True,
            })
    return _ApbRecords(rows, source_requests)


def _evidence(*, transactions=None, arms=None, trace=None, rx_reads=None,
              source_requests=None, parameters=None, capture_status=None,
              profile_identity=None, spi_window_base=SPI_WINDOW_BASE) -> dict:
    transactions = _apb_transactions("rx") if transactions is None else transactions
    if source_requests is None:
        # `_apb_transactions` is the fixture source of accepted OBI records.
        source_requests = list(getattr(transactions, "source_requests", ()))
    arms = ([{"cycle": 5, "payload": MISO_WORD}] if arms is None else arms)
    trace = (_mode0_trace(mosi=None, miso=MISO_WORD) if trace is None else trace)
    rx_reads = ([{
        "cycle": 80, "address": 0x20, "accepted": True,
        "rdata": MISO_WORD,
    }] if rx_reads is None else rx_reads)
    streams = {
        "apb_transactions": transactions,
        "peer_arms": arms,
        "wire_trace": trace,
        "rx_reads": rx_reads,
        "source_requests": source_requests,
    }
    return {
        **streams,
        "parameters": (dict(PROFILE_PARAMETERS) if parameters is None
                       else parameters),
        "profile_identity": (dict(PROFILE_IDENTITY) if profile_identity is None
                             else profile_identity),
        "spi_window_base": spi_window_base,
        "cpu_data_source_ids": (1,),
        "capture_status": ({
            name: {"captured": len(rows), "total": len(rows), "truncated": False}
            for name, rows in streams.items()
        } if capture_status is None else capture_status),
    }


def _audit(**changes) -> dict:
    return audit_pulp_spi_run(**_evidence(**changes))


def _tx_only(**changes) -> dict:
    tx_transactions = _apb_transactions("tx")
    inputs = _evidence(
        transactions=tx_transactions,
        arms=[], trace=_mode0_trace(mosi=MOSI_WORD, miso=None), rx_reads=[],
        source_requests=list(tx_transactions.source_requests),
    )
    # Keep the short names used by the RX helper convenient in TX cases.
    if "transactions" in changes:
        changes["apb_transactions"] = changes.pop("transactions")
        # The changed APB fixture also updates its independently recorded OBI
        # source requests; pass those rather than synthesizing BE from APB data.
        changes.setdefault(
            "source_requests",
            list(getattr(changes["apb_transactions"], "source_requests", ())),
        )
    if "trace" in changes:
        changes["wire_trace"] = changes.pop("trace")
    if "capture_status" not in changes:
        for stream in ("apb_transactions", "peer_arms", "wire_trace", "rx_reads",
                       "source_requests"):
            records = changes.get(stream, inputs[stream])
            inputs["capture_status"][stream] = {
                "captured": len(records), "total": len(records), "truncated": False,
            }
    inputs.update(changes)
    return audit_pulp_spi_run(**inputs)


class PulpSpiOracleGoldenTests(unittest.TestCase):
    def test_rx_only_mode0_msb_first_transfer_matches_arm_and_rxfifo(self):
        result = _audit()

        self.assertEqual("pass", result["verdict"], result)
        self.assertEqual("pass", result["status"], result)
        self.assertEqual("spi-transfer-verified", result["reason"])
        self.assertEqual("pulp_spi", result["profile"]["component_id"])
        self.assertEqual("apb_spi_master", result["profile"]["top_module"])
        self.assertIn("SPI.MISO_TO_RXFIFO", result["property_ids"])
        self.assertNotIn("SPI.MOSI_MSB_FIRST", result["property_ids"])
        self.assertIsNone(result["expected"]["mosi_words"])
        self.assertEqual([MISO_WORD], result["expected"]["miso_words"])
        self.assertEqual([MISO_WORD], result["observed"]["miso_words"])
        self.assertEqual([MISO_WORD], result["observed"]["rxfifo_words"])
        self.assertEqual([], result["failed_property_ids"])
        self.assertIsNone(result["not_assessed_reason"])

    def test_tx_only_mode0_msb_first_transfer_uses_accepted_txfifo_word(self):
        result = _tx_only()

        self.assertEqual("pass", result["verdict"], result)
        self.assertEqual([MOSI_WORD], result["expected"]["mosi_words"])
        self.assertEqual([MOSI_WORD], result["observed"]["mosi_words"])
        self.assertIsNone(result["expected"]["miso_words"])
        self.assertIn("SPI.MOSI_MSB_FIRST", result["property_ids"])
        self.assertNotIn("SPI.MISO_TO_RXFIFO", result["property_ids"])

    def test_idle_spi_mode_output_transient_before_first_edge_is_ignored(self):
        # The pinned controller can briefly expose QUAD_RX while CS is selected
        # but before its first SCK edge; the supported transfer settles to STD.
        trace = _mode0_trace(setup_mode=2)
        self.assertEqual("pass", _audit(trace=trace)["verdict"])

    def test_non_mosi_tx_output_lanes_may_carry_shift_register_bits(self):
        trace = _mode0_trace(mosi=MOSI_WORD, miso=None)
        for row in trace:
            if row["csn0"] == 0:
                row["sdo1"] = 1
                row["sdo2"] = 0
                row["sdo3"] = 1
        self.assertEqual("pass", _tx_only(trace=trace)["verdict"])


class PulpSpiOracleWireFailureTests(unittest.TestCase):
    def assert_mismatch(self, result, reason, property_id):
        self.assertEqual("mismatch", result["verdict"], result)
        self.assertEqual(reason, result["reason"])
        self.assertIn(property_id, result["failed_property_ids"])

    def test_inverted_mode0_data_edge_is_reported(self):
        trace = copy.deepcopy(_mode0_trace())
        for index in range(1, len(trace) - 1):
            before, row, after = trace[index - 1:index + 2]
            if row["csn0"] == 0 and before["sck"] == 0 and row["sck"] == 1:
                row["sdo0"] = after["sdo0"]
                row["sdi1"] = after["sdi1"]
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-mode0-data-edge-violation",
                             "SPI.MODE0_EDGE_COUNT")

    def test_wrong_chip_select_is_reported(self):
        trace = copy.deepcopy(_mode0_trace())
        for row in trace:
            if row["csn0"] == 0:
                row["csn0"] = 1
                row["csn1"] = 0
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-wrong-chip-select", "SPI.CS_WINDOW")

    def test_miso_on_an_unused_lane_does_not_satisfy_sdi1_contract(self):
        trace = copy.deepcopy(_mode0_trace())
        for row in trace:
            if row["csn0"] == 0:
                row["sdi0"] = row["sdi1"]
                row["sdi1"] = 0
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-miso-word-mismatch", "SPI.MISO_TO_RXFIFO")

    def test_nonstandard_mode_during_clocking_is_a_protocol_mismatch(self):
        trace = _mode0_trace()
        trace[9]["mode"] = 2
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-standard-mode-violation", "SPI.STD_LANES")

    def test_mosi_bit_flip_is_reported_against_accepted_txfifo_write(self):
        trace = copy.deepcopy(_mode0_trace(mosi=MOSI_WORD, miso=None))
        # Change bit 0 at its setup row and the following rising sample row.
        trace[8]["sdo0"] = 0
        trace[9]["sdo0"] = 0
        result = _tx_only(trace=trace)
        self.assert_mismatch(result, "spi-mosi-word-mismatch", "SPI.MOSI_MSB_FIRST")

    def test_miso_bit_flip_is_reported_against_independent_arm(self):
        trace = copy.deepcopy(_mode0_trace())
        # The literal begins with zero, so invert it to inject a real change.
        trace[8]["sdi1"] = 1
        trace[9]["sdi1"] = 1
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-miso-word-mismatch", "SPI.MISO_TO_RXFIFO")

    def test_closed_short_frame_is_reported(self):
        trace = _mode0_trace(transfer_bits=31)
        result = _audit(trace=trace)
        self.assert_mismatch(result, "spi-wire-incomplete-frame", "SPI.MODE0_EDGE_COUNT")

    def test_rxfifo_word_mismatch_is_reported(self):
        wrong_word = 0x5A3C_C3A4
        reads = [{"cycle": 80, "address": 0x20, "accepted": True,
                  "rdata": wrong_word}]
        transactions = _apb_transactions("rx", rx_read_word=wrong_word)
        result = _audit(rx_reads=reads, transactions=transactions)
        self.assert_mismatch(result, "spi-rxfifo-word-mismatch", "SPI.MISO_TO_RXFIFO")

    def test_rxfifo_read_before_frame_close_is_not_assessed(self):
        reads = [{"cycle": 70, "address": 0x20, "accepted": True,
                  "rdata": MISO_WORD}]
        transactions = _apb_transactions("rx")
        transactions[-1]["cycle"] = 70
        result = _audit(rx_reads=reads, transactions=transactions)
        self.assertEqual("not_assessed", result["verdict"])
        self.assertEqual("spi-rxfifo-read-before-deselection", result["reason"])


class PulpSpiOracleEvidenceRefusalTests(unittest.TestCase):
    def assert_not_assessed(self, result, reason):
        self.assertEqual("not_assessed", result["verdict"], result)
        self.assertEqual("not_assessed", result["status"], result)
        self.assertEqual(reason, result["reason"])
        self.assertEqual(reason, result["not_assessed_reason"])
        self.assertEqual([], result["failed_property_ids"])

    def test_missing_peer_arm_is_not_assessed(self):
        self.assert_not_assessed(_audit(arms=[]), "spi-peer-arm-missing")

    def test_missing_txfifo_write_is_not_assessed(self):
        self.assert_not_assessed(
            _tx_only(transactions=_apb_transactions("tx", txfifo=False)),
            "spi-txfifo-write-missing",
        )

    def test_partial_txfifo_write_is_not_assessed(self):
        transactions = _apb_transactions("tx", txfifo_byte_enable=0x7)
        self.assert_not_assessed(_tx_only(transactions=transactions),
                                 "spi-txfifo-partial-write")

    def test_missing_rxfifo_read_is_not_assessed(self):
        transactions = _apb_transactions("rx", rx_read_word=None)
        self.assert_not_assessed(
            _audit(rx_reads=[], transactions=transactions),
            "spi-rxfifo-read-missing")

    def test_missing_length_setup_is_not_assessed(self):
        transactions = [row for row in _apb_transactions("rx")
                        if row["address"] != 0x10]
        self.assert_not_assessed(
            _audit(transactions=transactions), "spi-apb-setup-missing:0x10")

    def test_reserved_status_bits_are_not_assessed(self):
        transactions = _apb_transactions("rx")
        transactions[5]["wdata"] |= 0x4
        self.assert_not_assessed(
            _audit(transactions=transactions), "spi-status-mode-unsupported")

    def test_missing_or_unknown_wire_trace_is_not_assessed(self):
        self.assert_not_assessed(_audit(trace=[]), "spi-wire-trace-missing")
        trace = _mode0_trace()
        trace[8]["sdi1"] = "x"
        self.assert_not_assessed(_audit(trace=trace), "spi-wire-value-invalid:8:sdi1")

    def test_unsupported_profile_parameters_are_not_assessed(self):
        parameters = dict(PROFILE_PARAMETERS, CPHA=1)
        self.assert_not_assessed(_audit(parameters=parameters),
                                 "spi-profile-unsupported:CPHA")

    def test_peer_arm_after_chip_select_is_not_assessed(self):
        arms = [{"cycle": 9, "payload": MISO_WORD}]
        self.assert_not_assessed(_audit(arms=arms), "spi-peer-arm-after-selection")

    def test_unaccepted_txfifo_write_is_not_used_as_expectation(self):
        transactions = _apb_transactions(
            "tx", txfifo_accepted=False)
        self.assert_not_assessed(_tx_only(transactions=transactions),
                                 "spi-txfifo-write-missing")

    def test_mixed_tx_and_rx_evidence_is_not_assessed(self):
        transaction = {
            "cycle": 5, "address": 0x18, "write": True, "accepted": True,
            "wdata": MOSI_WORD, "source_request_id": 99,
        }
        transactions = _apb_transactions("rx")
        transactions.insert(5, transaction)
        self.assert_not_assessed(
            _audit(transactions=transactions),
            "spi-mixed-rx-tx-transfer-unsupported",
        )

    def test_every_capture_stream_must_be_explicitly_complete(self):
        evidence = _evidence()
        for stream, records in ((name, evidence[name]) for name in (
                "apb_transactions", "peer_arms", "wire_trace", "rx_reads",
                "source_requests")):
            with self.subTest(stream=stream):
                status = copy.deepcopy(evidence["capture_status"])
                status[stream]["truncated"] = True
                status[stream]["total"] += 1
                self.assert_not_assessed(
                    _audit(capture_status=status),
                    f"spi-capture-truncated:{stream}",
                )

    def test_missing_capture_completeness_metadata_is_not_assessed(self):
        self.assert_not_assessed(
            _audit(capture_status={}),
            "spi-capture-completeness-missing:apb_transactions",
        )

    def test_capture_counts_must_match_the_actual_streams(self):
        status = _evidence()["capture_status"]
        status["wire_trace"]["captured"] -= 1
        self.assert_not_assessed(
            _audit(capture_status=status),
            "spi-capture-count-mismatch:wire_trace",
        )

    def test_actual_profile_identity_must_match_the_pinned_source(self):
        identity = dict(PROFILE_IDENTITY, source_revision="sha256:wrong")
        self.assert_not_assessed(
            _audit(profile_identity=identity),
            "spi-profile-identity-unsupported:source_revision",
        )

    def test_accepted_apb_write_requires_an_correlated_source_request(self):
        evidence = _evidence()
        evidence["source_requests"] = []
        evidence["capture_status"]["source_requests"] = {
            "captured": 0, "total": 0, "truncated": False,
        }
        self.assert_not_assessed(
            audit_pulp_spi_run(**evidence),
            "spi-apb-source-request-missing",
        )

    def test_source_request_byte_enable_is_the_partial_write_authority(self):
        transactions = _apb_transactions("tx")
        source_requests = list(transactions.source_requests)
        tx_request = next(row for row in source_requests
                          if row["address"] == SPI_WINDOW_BASE + 0x18)
        tx_request["byte_enable"] = 0x7
        evidence = _evidence(
            transactions=transactions,
            arms=[], trace=_mode0_trace(mosi=MOSI_WORD, miso=None), rx_reads=[],
            source_requests=source_requests,
        )
        result = audit_pulp_spi_run(**evidence)
        self.assert_not_assessed(result, "spi-txfifo-partial-write")

    def test_source_request_must_match_the_apb_write_address_and_data(self):
        transactions = _apb_transactions("tx")
        source_requests = copy.deepcopy(transactions.source_requests)
        source_requests[-1]["address"] += 4
        evidence = _evidence(
            transactions=transactions,
            arms=[], trace=_mode0_trace(mosi=MOSI_WORD, miso=None), rx_reads=[],
            source_requests=source_requests,
        )
        result = audit_pulp_spi_run(**evidence)
        self.assert_not_assessed(result, "spi-apb-source-request-mismatch")

    def test_source_request_must_come_from_a_cpu_data_lane(self):
        transactions = _apb_transactions("tx")
        source_requests = copy.deepcopy(transactions.source_requests)
        source_requests[0]["source_id"] = 0
        evidence = _evidence(
            transactions=transactions,
            arms=[], trace=_mode0_trace(mosi=MOSI_WORD, miso=None), rx_reads=[],
            source_requests=source_requests,
        )
        result = audit_pulp_spi_run(**evidence)
        self.assert_not_assessed(result, "spi-apb-source-not-cpu-data")


if __name__ == "__main__":
    unittest.main()
