"""SPI wire monitors must follow resolved role bindings, not port guesses."""
from __future__ import annotations

import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from myfuzz.composition.soc_image import build_image_plan
from myfuzz.composition.soc_runtime import (
    RuntimeBuild, RuntimeSample, _spi_wire_records, render_profile_testbench,
    run_sample,
)
from tests.composition.test_soc_peer_interrupt_plan import SpiInterruptPlanTests
from tests.integration.test_soc_peer_models import build_pulp_spi_peer_plan


class SpiWireCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SpiInterruptPlanTests.setUpClass()
        cls.plan = SpiInterruptPlanTests.plan

    def test_monitor_uses_four_bound_roles(self) -> None:
        peer = self.plan.peer("spi0")
        records = _spi_wire_records(self.plan)
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual("spi0", record["instance_id"])
        self.assertEqual(
            {role: f"dut.{peer.instance_id}__{peer.binding(role).component_port}"
             for role in ("sck", "cs", "mosi", "miso")},
            record["roles"])
        bench = render_profile_testbench(self.plan)
        self.assertIn("MYFUZZ_PEER_WIRE", bench)
        for signal in record["roles"].values():
            self.assertIn(signal, bench)

    def test_pulp_monitor_uses_all_fourteen_bound_roles_and_captures_apb(self) -> None:
        plan = build_pulp_spi_peer_plan()
        peer = plan.peer("spi0")
        records = _spi_wire_records(plan)
        self.assertEqual(1, len(records))
        self.assertEqual("pulp_spi", records[0]["peer_id"])
        expected_roles = (
            "sck", "csn0", "csn1", "csn2", "csn3", "mode",
            "sdo0", "sdo1", "sdo2", "sdo3",
            "sdi0", "sdi1", "sdi2", "sdi3",
        )
        self.assertEqual(set(expected_roles), set(records[0]["roles"]))
        self.assertEqual(12, plan.instance("spi0").binding.field(
            "spi.bus", "paddr").width)
        self.assertEqual("pulp_spi",
                         records[0]["profile_identity"]["component_id"])
        self.assertEqual("apb_spi_master",
                         records[0]["profile_identity"]["top_module"])
        self.assertTrue(records[0]["profile_identity"]["source_revision"])
        self.assertEqual({"APB_ADDR_WIDTH": 12, "BUFFER_DEPTH": 10},
                         records[0]["parameters"])
        for role in expected_roles:
            self.assertEqual(
                f"dut.spi0__{peer.binding(role).component_port}",
                records[0]["roles"][role])

        bench = render_profile_testbench(plan, image_plan=build_image_plan(plan))
        self.assertIn("MYFUZZ_PEER_WIRE cycle=%0d instance=spi0", bench)
        self.assertIn("MYFUZZ_SPI_APB instance=spi0", bench)
        self.assertIn("MYFUZZ_SPI_APB_SUMMARY instance=spi0", bench)
        self.assertIn("MYFUZZ_SOURCE_REQ seq=%0d", bench)
        self.assertIn("MYFUZZ_REQ seq=%0d", bench)
        for signal in records[0]["roles"].values():
            self.assertIn(signal, bench)
        for field in plan.instance("spi0").binding.endpoint("spi.bus").fields:
            self.assertIn(f"dut.spi0__{field.port}", bench)

    def test_pulp_wire_and_apb_capture_parse_with_explicit_bounds(self) -> None:
        output = "\n".join((
            "MYFUZZ_PEER_WIRE cycle=3 instance=spi0 sck=0 csn0=0 csn1=1 "
            "csn2=1 csn3=1 mode=00 sdo0=1 sdo1=0 sdo2=0 sdo3=0 "
            "sdi0=0 sdi1=1 sdi2=0 sdi3=0",
            "MYFUZZ_PEER_WIRE_SUMMARY instance=spi0 captured=1 total=2 truncated=1",
            "MYFUZZ_REQ seq=7 cycle=3 addr=40001018 write=1 "
            "wdata=12345678 be=f source=1 accepted=1",
            "MYFUZZ_REQ_SUMMARY captured=1 total=8 truncated=1",
            "MYFUZZ_SPI_APB instance=spi0 cycle=4 addr=018 write=1 "
            "wdata=12345678 rdata=00000000 pready=1 pslverr=0",
            "MYFUZZ_SPI_APB_SUMMARY instance=spi0 captured=1 total=2 truncated=1",
            "MYFUZZ_SOC_RUN status=OK cycles=4 request=1",
        ))
        path = Path("/tmp/myfuzz-peer-wire-parse")
        build = RuntimeBuild(
            output_dir=path, top_path=path / "top.sv",
            testbench_path=path / "tb.sv", executable=path / "sim",
            sources=(), raw_width=1, slots=(), observations=(),
            boot_image=None, boot_image_policy="none", build_hash="test",
            peer_wires=({"instance_id": "spi0", "peer_id": "pulp_spi",
                         "spi_window_base": 0x40001000},),
        )
        with patch("myfuzz.composition.soc_runtime.subprocess.run",
                   return_value=CompletedProcess([], 0, stdout=output, stderr="")):
            result = run_sample(build, RuntimeSample(request_id=1, raw=(0,)))
        self.assertEqual(1, len(result.peer_wire_trace))
        self.assertEqual("00", result.peer_wire_trace[0]["mode"])
        self.assertEqual(14, len(result.peer_wire_trace[0]) - 2)
        self.assertEqual({"instance_id": "spi0", "count": 1,
                          "captured": 1, "total": 2, "truncated": True},
                         result.peer_wire_status[0])
        self.assertEqual(0x18, result.spi_apb_transactions[0]["addr"])
        self.assertEqual(0x18, result.spi_apb_transactions[0]["local_address"])
        self.assertTrue(result.spi_apb_transactions[0]["accepted"])
        self.assertEqual(0x12345678, result.spi_apb_transactions[0]["wdata"])
        self.assertEqual(7, result.spi_apb_transactions[0]["source_request_id"])
        self.assertEqual(7, result.requests[0]["request_id"])
        self.assertEqual(0xF, result.requests[0]["byte_enable"])
        self.assertEqual(0x40001018, result.requests[0]["global_address"])
        self.assertEqual(0x40001018, result.requests[0]["address"])
        self.assertEqual(8, result.requests_total)
        self.assertTrue(result.requests_truncated)
        self.assertEqual(7, result.document()["source_requests"][0]["request_id"])
        self.assertEqual({"instance_id": "spi0", "captured": 1,
                          "total": 2, "truncated": True},
                         result.spi_apb_status[0])

    def test_source_request_evidence_is_returned_in_cycle_order(self) -> None:
        output = "\n".join((
            "MYFUZZ_REQ seq=1 cycle=9 addr=40001018 write=1 "
            "wdata=22222222 be=f source=1 accepted=1",
            "MYFUZZ_REQ seq=0 cycle=4 addr=40001004 write=1 "
            "wdata=00000000 be=f source=1 accepted=1",
            "MYFUZZ_REQ_SUMMARY captured=2 total=2 truncated=0",
            "MYFUZZ_SOURCE_REQ seq=2 cycle=10 addr=40001020 write=0 "
            "wdata=00000000 be=f source=1 accepted=1",
            "MYFUZZ_SOURCE_REQ seq=1 cycle=9 addr=40001018 write=1 "
            "wdata=22222222 be=f source=1 accepted=1",
            "MYFUZZ_SOURCE_REQ seq=0 cycle=4 addr=40001004 write=1 "
            "wdata=00000000 be=f source=1 accepted=1",
            "MYFUZZ_SOURCE_REQ_SUMMARY captured=3 total=3 truncated=0",
            "MYFUZZ_SOC_RUN status=OK cycles=10 request=1",
        ))
        path = Path("/tmp/myfuzz-peer-wire-parse")
        build = RuntimeBuild(
            output_dir=path, top_path=path / "top.sv",
            testbench_path=path / "tb.sv", executable=path / "sim",
            sources=(), raw_width=1, slots=(), observations=(),
            boot_image=None, boot_image_policy="none", build_hash="test",
        )
        with patch("myfuzz.composition.soc_runtime.subprocess.run",
                   return_value=CompletedProcess([], 0, stdout=output, stderr="")):
            result = run_sample(build, RuntimeSample(request_id=1, raw=(0,)))

        self.assertEqual([0, 1], [item["request_id"] for item in result.requests])
        self.assertTrue(all(item["write"] == 1 for item in result.requests))
        self.assertEqual([0, 1, 2], [item["request_id"]
                                    for item in result.source_requests])
        self.assertEqual([1, 1, 0], [item["write"]
                                    for item in result.source_requests])
        self.assertEqual(3, result.source_requests_total)
        self.assertEqual(2, result.requests_total)
        document = result.document()
        self.assertEqual([item["request_id"] for item in result.requests],
                         [item["request_id"] for item in document["fabric_requests"]])
        self.assertEqual([0, 1, 2], [item["request_id"]
                                    for item in document["source_requests"]])


if __name__ == "__main__":
    unittest.main()
