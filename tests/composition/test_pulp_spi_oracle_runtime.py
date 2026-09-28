"""Runtime evidence must reach the independent PULP SPI oracle."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from myfuzz.composition.soc_peer_oracle import audit_peer_run
from tests.composition.test_pulp_spi_oracle import (
    MISO_WORD,
    PROFILE_IDENTITY,
    PROFILE_PARAMETERS,
    SPI_WINDOW_BASE,
    _apb_transactions,
    _mode0_trace,
)


def _records():
    apb = _apb_transactions("rx")
    apb_rows = [
        {"instance_id": "spi0", "local_address": row["address"], **row}
        for row in apb
    ]
    arms = [{"cycle": 5, "payload": MISO_WORD}]
    trace = [{"instance_id": "spi0", **row} for row in _mode0_trace(
        mosi=None, miso=MISO_WORD)]
    rx_reads = [{"cycle": 80, "address": 0x20, "accepted": True,
                 "rdata": MISO_WORD}]
    requests = list(apb.source_requests)
    return apb_rows, arms, trace, rx_reads, requests


def _runtime_objects(*, raw=(), peer_events=None, peer_applied=None,
                     apb=None, arms=None, trace=None, rx_reads=None,
                     requests=None, apb_truncated=False):
    default_apb, default_arms, default_trace, default_reads, default_requests = _records()
    apb = default_apb if apb is None else apb
    arms = default_arms if arms is None else arms
    trace = default_trace if trace is None else trace
    rx_reads = default_reads if rx_reads is None else rx_reads
    requests = default_requests if requests is None else requests
    if not raw:
        raw = (0,) * 100
    slot = {
        "index": 0, "instance_id": "spi0", "peer_id": "pulp_spi",
        "slot": "spi.arm_word", "kind": "pulse_word", "width": 32,
        "peer_module": "soc_pulp_spi_peer", "peer_source": "peer.sv",
        "peer_protocol": ["spi", "1"], "minimum_gap_cycles": 2,
        "signals": [
            {"peer_port": "arm_word_i", "top_port": "spi0__arm_word_i",
             "width": 32, "source": "payload"},
            {"peer_port": "arm_valid_i", "top_port": "spi0__arm_valid_i",
             "width": 1, "source": "pulse"},
        ],
    }
    raw_layout_dir = tempfile.TemporaryDirectory()
    tb = Path(raw_layout_dir.name) / "tb.sv"
    tb.write_text(
        "assign spi0__arm_word_i = spi0__arm_word_i__event_active ? "
        "spi0__arm_word_i__event : raw_bits[31:0];\n"
        "assign spi0__arm_valid_i = spi0__arm_valid_i__event_active ? "
        "spi0__arm_valid_i__event : raw_bits[32:32];\n",
        encoding="utf-8")
    build = SimpleNamespace(
        peer_slots=(slot,),
        raw_width=33,
        testbench_path=tb,
        spi_wire_contracts={"spi0": {
            "profile_identity": dict(PROFILE_IDENTITY),
            "parameters": dict(PROFILE_PARAMETERS),
            "spi_window_base": SPI_WINDOW_BASE,
        }},
        peer_wires=(),
        cpu_data_sources=(1,),
        _raw_layout_dir=raw_layout_dir,
    )
    sample = SimpleNamespace(raw=tuple(raw), peer_events=tuple(peer_events or ()))
    peer_status = [{"instance_id": "spi0", "captured": len(trace),
                    "total": len(trace), "truncated": False}]
    apb_status = [{"instance_id": "spi0", "captured": len(apb),
                   "total": len(apb) + int(apb_truncated),
                   "truncated": apb_truncated}]
    result = SimpleNamespace(
        cycles=100, peer_applied=tuple(peer_applied or ()),
        peer_wire_trace=tuple(trace), peer_wire_status=tuple(peer_status),
        spi_apb_transactions=tuple(apb), spi_apb_status=tuple(apb_status),
        requests=tuple(requests), requests_total=len(requests),
        requests_truncated=False,
    )
    return build, sample, result


class PulpSpiRuntimeOracleTests(unittest.TestCase):
    def test_declared_peer_arm_and_runtime_evidence_are_audited(self):
        event = SimpleNamespace(slot=0, cycle=5, payload=MISO_WORD)
        applied = {"instance": "spi0", "slot": "spi.arm_word",
                   "cycle": 5, "value": MISO_WORD}
        build, sample, result = _runtime_objects(
            peer_events=(event,), peer_applied=(applied,))
        self.addCleanup(build._raw_layout_dir.cleanup)

        audit = audit_peer_run(build, sample, result)

        check = next(item for item in audit["checks"]
                     if item["check_id"] == "pulp-spi-transfer")
        self.assertEqual("pass", check["status"], audit)
        self.assertEqual([], [item for item in audit["unassessed"]
                              if item["check_id"] == "pulp-spi-transfer"])

    def test_runtime_truncation_prevents_a_false_pulp_spi_pass(self):
        build, sample, result = _runtime_objects(apb_truncated=True)
        self.addCleanup(build._raw_layout_dir.cleanup)

        audit = audit_peer_run(build, sample, result)

        self.assertNotIn("pulp-spi-transfer", {
            item["check_id"] for item in audit["checks"]
            if item["status"] == "pass"
        })
        item = next(item for item in audit["unassessed"]
                    if item["check_id"] == "pulp-spi-transfer")
        self.assertIn("truncated", item["reason"])

    def test_adapter_uses_complete_source_requests_not_write_only_legacy_field(self):
        event = SimpleNamespace(slot=0, cycle=5, payload=MISO_WORD)
        applied = {"instance": "spi0", "slot": "spi.arm_word",
                   "cycle": 5, "value": MISO_WORD}
        build, sample, result = _runtime_objects(
            peer_events=(event,), peer_applied=(applied,))
        self.addCleanup(build._raw_layout_dir.cleanup)
        write_requests = tuple(dict(item) for item in result.requests
                               if item["write"])
        complete_requests = list(write_requests)
        complete_requests.append({
            "request_id": 100, "cycle": 50, "global_address": 0x10000,
            "write": 0, "wdata": 0, "byte_enable": 0,
            "source_id": 0, "accepted": 1,
        })
        result.requests = write_requests
        result.source_requests = tuple(complete_requests)
        result.source_requests_total = len(complete_requests)
        result.source_requests_truncated = False

        audit = audit_peer_run(build, sample, result)

        check = next(item for item in audit["checks"]
                     if item["check_id"] == "pulp-spi-transfer")
        self.assertEqual("pass", check["status"], audit)

    def test_adapter_fails_closed_when_spi_apb_and_obi_capture_disagree(self):
        event = SimpleNamespace(slot=0, cycle=5, payload=MISO_WORD)
        applied = {"instance": "spi0", "slot": "spi.arm_word",
                   "cycle": 5, "value": MISO_WORD}
        build, sample, result = _runtime_objects(
            peer_events=(event,), peer_applied=(applied,))
        self.addCleanup(build._raw_layout_dir.cleanup)
        requests = [dict(item) for item in result.requests]
        requests[0]["wdata"] ^= 1
        result.source_requests = tuple(requests)
        result.source_requests_total = len(requests)
        result.source_requests_truncated = False

        audit = audit_peer_run(build, sample, result)

        self.assertNotIn("pulp-spi-transfer", {
            item["check_id"] for item in audit["checks"]
            if item["status"] == "pass"
        })
        item = next(item for item in audit["unassessed"]
                    if item["check_id"] == "pulp-spi-transfer")
        self.assertIn("source-request-mismatch", item["reason"])

    def test_raw_peer_arm_is_decoded_as_the_rx_expectation(self):
        with tempfile.TemporaryDirectory() as directory:
            tb = Path(directory) / "tb.sv"
            tb.write_text(
                "assign spi0__arm_word_i = spi0__arm_word_i__event_active ? "
                "spi0__arm_word_i__event : raw_bits[31:0];\n"
                "assign spi0__arm_valid_i = spi0__arm_valid_i__event_active ? "
                "spi0__arm_valid_i__event : raw_bits[32:32];\n",
                encoding="utf-8")
            build, sample, result = _runtime_objects(
                raw=(0, 0, 0, 0, 0, MISO_WORD | (1 << 32)))
            self.addCleanup(build._raw_layout_dir.cleanup)
            build.testbench_path = tb

            audit = audit_peer_run(build, sample, result)

        self.assertIn("pulp-spi-transfer", {
            item["check_id"] for item in audit["checks"]
            if item["status"] == "pass"
        }, audit)


if __name__ == "__main__":
    unittest.main()
