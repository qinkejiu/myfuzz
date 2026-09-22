"""Independent SPI checks use wire edges, never peer counters."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from myfuzz.composition.soc_peer_oracle import audit_peer_run, spi_wire_expectation
from myfuzz.composition.soc_failure_evidence import _comparison_fields


def _frame(mosi: int = 0xA5, miso: int = 0x5A, *, bits: int = 8,
           cpol: int = 0, cs_active_low: int = 1) -> list[dict]:
    idle = str(cpol)
    active = str(1 - cpol)
    deselected = str(cs_active_low)
    selected = str(1 - cs_active_low)
    trace = [{"cycle": 0, "sck": idle, "cs": deselected, "mosi": "0", "miso": "0"},
             {"cycle": 1, "sck": idle, "cs": selected, "mosi": "0", "miso": "0"}]
    cycle = 2
    for shift in range(bits - 1, -1, -1):
        tx = str((mosi >> shift) & 1)
        rx = str((miso >> shift) & 1)
        trace.append({"cycle": cycle, "sck": idle, "cs": selected,
                      "mosi": tx, "miso": rx})
        trace.append({"cycle": cycle + 1, "sck": active, "cs": selected,
                      "mosi": tx, "miso": rx})
        trace.append({"cycle": cycle + 2, "sck": idle, "cs": selected,
                      "mosi": tx, "miso": rx})
        cycle += 3
    trace.append({"cycle": cycle, "sck": idle, "cs": deselected,
                  "mosi": "0", "miso": "0"})
    return trace


class SpiWireOracleTests(unittest.TestCase):
    def check(self, trace: list[dict], *, mosi: int = 0xA5,
              miso: int = 0x5A) -> dict:
        return spi_wire_expectation(trace, bits=8, cpol=0, cpha=0,
                                    cs_active_low=1, mosi_words=[mosi],
                                    miso_words=[miso])

    def test_complete_frame_passes(self) -> None:
        result = self.check(_frame())
        self.assertEqual("pass", result["status"], result)
        self.assertEqual([0xA5], result["observed_mosi_words"])
        self.assertEqual([0x5A], result["observed_miso_words"])

    def test_all_four_spi_modes_and_both_chip_select_polarities(self) -> None:
        for cpol in (0, 1):
            for cpha in (0, 1):
                for active_low in (0, 1):
                    with self.subTest(cpol=cpol, cpha=cpha, active_low=active_low):
                        result = spi_wire_expectation(
                            _frame(cpol=cpol, cs_active_low=active_low),
                            bits=8, cpol=cpol, cpha=cpha,
                            cs_active_low=active_low,
                            mosi_words=[0xA5], miso_words=[0x5A])
                        self.assertEqual("pass", result["status"], result)

    def test_mosi_bit_flip_fails(self) -> None:
        self.assertEqual("mismatch", self.check(_frame(mosi=0xA4))["status"])

    def test_deselected_clock_fails(self) -> None:
        trace = _frame()
        trace.append({"cycle": 30, "sck": "1", "cs": "1",
                      "mosi": "0", "miso": "0"})
        self.assertEqual("mismatch", self.check(trace)["status"])

    def test_missing_or_partial_wire_trace_is_not_a_pass(self) -> None:
        self.assertEqual("not_assessed", self.check([])["status"])
        self.assertNotEqual("pass", self.check(_frame()[:-5])["status"])

    def test_unknown_wire_level_is_not_a_pass(self) -> None:
        trace = _frame()
        trace[3]["mosi"] = "x"
        self.assertEqual("not_assessed", self.check(trace)["status"])

    def test_run_audit_uses_observed_bus_write_and_external_contract(self) -> None:
        build = SimpleNamespace(
            peer_slots=({"index": 0, "instance_id": "spi0", "peer_id": "spi",
                         "slot": "spi.arm_byte",
                         "parameters": {"BITS": 8, "CPOL": 0, "CPHA": 0,
                                        "CS_ACTIVE_LOW": 1}},),
            peer_observations=(),
            cpu_data_sources=(0,),
            spi_wire_contracts={"spi0": {"txdata_address": 0x1008,
                                         "basis": "independent fixture register norm"}})
        sample = SimpleNamespace(peer_events=({"slot": 0, "cycle": 0,
                                               "payload": 0x5A},))
        result = SimpleNamespace(
            cycles=100,
            peer_applied=({"cycle": 0, "instance": "spi0",
                           "slot": "spi.arm_byte", "value": 0x5A},),
            peer_wire_trace=tuple(dict(item, instance_id="spi0") for item in _frame()),
            peer_wire_status=({"instance_id": "spi0", "count": len(_frame()),
                               "truncated": False},),
            requests=({"cycle": 0, "addr": 0x1008, "write": 1,
                       "wdata": 0xA5, "be": 0xF, "source": 0},),
            counters={}, observations={})
        audit = audit_peer_run(build, sample, result)
        wire = next(item for item in audit["checks"]
                    if item["check_id"] == "spi-transfer-wire")
        self.assertEqual("pass", wire["status"], wire)
        result.requests = ({"cycle": 50, "addr": 0x1008, "write": 1,
                            "wdata": 0xA5, "be": 0xF, "source": 0},)
        late = audit_peer_run(build, sample, result)
        self.assertTrue(any(item["check_id"] == "spi-transfer-wire"
                            for item in late["unassessed"]), late)

    def test_replay_compares_wire_and_cpu_request_evidence(self) -> None:
        fields = _comparison_fields({
            "peer_wire_trace": [{"instance_id": "spi0", "cycle": 7,
                                 "sck": "1", "cs": "0", "mosi": "1", "miso": "0"}],
            "peer_wire_status": [{"instance_id": "spi0", "count": 1,
                                  "truncated": False}],
            "fabric_requests": [{"cycle": 4, "addr": 0x1008, "write": 1,
                                 "wdata": 0xA5, "be": 0xF, "source": 0}],
            "fabric_requests_truncated": False})
        self.assertEqual("1", fields["peer_wire[7].spi0.sck"])
        self.assertEqual(0xA5, fields["fabric_request[0].0x1008.wdata"])


if __name__ == "__main__":
    unittest.main()
