"""Behavioural RTL tests for the beat-initiator to peripheral-target adapters.

Every RTL test in this module compiles the adapter with Icarus Verilog and runs a
self-checking scoreboard test bench: the bench drives the processor-memory-beat
initiator side, models a real target-side handshake (including delayed
responses), and asserts on transaction counts and side effects.  No assertion in
this module inspects RTL source text.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from myfuzz.composition.target_adapters import (
    TargetAdapterError,
    resolve_target_adapter,
)

ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl"
OT_PRIM = ROOT / "third_party/soc-opentitan/hw/ip/prim/rtl"
# ---------------------------------------------------------------------------
# simulation helpers
# ---------------------------------------------------------------------------

_HEADER = """`timescale 1ns/1ps
module tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  always #5 clk = ~clk;

  logic req_valid, req_ready, write;
  logic [31:0] addr, wdata, rdata;
  logic [3:0] be;
  logic rsp_valid, rsp_ready, error;

  task tick; @(posedge clk); #1; endtask
  task check(input bit ok, input [8*160-1:0] msg);
    if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
  endtask
  task wait_response(input integer max_cycles);
    integer i;
    begin
      i = 0;
      while (!rsp_valid && (i < max_cycles)) begin tick(); i = i + 1; end
      check(rsp_valid, "beat response arrived within the cycle bound");
    end
  endtask
"""


def _require_tools(test: unittest.TestCase) -> tuple[str, str]:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    test.assertIsNotNone(iverilog, "iverilog is required for the target adapter RTL tests")
    test.assertIsNotNone(vvp, "vvp is required for the target adapter RTL tests")
    return str(iverilog), str(vvp)


def _compile_and_run(
    test: unittest.TestCase,
    body: str,
    sources: list[Path | str],
    *,
    expect_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    iverilog, vvp = _require_tools(test)
    for source in sources:
        test.assertTrue(Path(source).is_file(), f"missing RTL source: {source}")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "tb.vvp"
        bench = Path(directory) / "tb.sv"
        bench.write_text(textwrap.dedent(body), encoding="utf-8")
        compiled = subprocess.run(
            [iverilog, "-g2012", "-s", "tb", "-o", str(output)]
            + [str(source) for source in sources]
            + [str(bench)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stderr)
        result = subprocess.run(
            [vvp, str(output)], cwd=ROOT, text=True, capture_output=True, timeout=60
        )
    if expect_success:
        test.assertEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertIn("PASS", result.stdout, result.stdout + result.stderr)
    else:
        test.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertNotIn("PASS", result.stdout)
    return result


def _sv_literal(value: object) -> str:
    if isinstance(value, bool):
        return "1'b1" if value else "1'b0"
    if isinstance(value, int):
        return str(value)
    raise TypeError(f"unsupported RTL parameter value: {value!r}")


def _elaborate_configuration(
    test: unittest.TestCase, module: str, parameters: list[tuple], sources: list[Path]
) -> None:
    iverilog, vvp = _require_tools(test)
    overrides = ", ".join(f".{name}({_sv_literal(value)})" for name, value in parameters)
    body = (
        "module config_top;\n"
        f"  {module} #({overrides}) u();\n"
        "  initial begin #10; $display(\"ELAB_OK\"); $finish; end\n"
        "endmodule\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "config_top.sv"
        output = Path(directory) / "config_top.vvp"
        source.write_text(body, encoding="utf-8")
        compiled = subprocess.run(
            [iverilog, "-g2012", "-s", "config_top", "-o", str(output), str(source)]
            + [str(item) for item in sources],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stderr)
        result = subprocess.run(
            [vvp, str(output)], cwd=ROOT, text=True, capture_output=True, timeout=60
        )
    test.assertEqual(0, result.returncode, result.stdout + result.stderr)
    test.assertIn("ELAB_OK", result.stdout)


# ---------------------------------------------------------------------------
# real peripheral capability fixtures (facts recorded by task P1)
# ---------------------------------------------------------------------------

def _evidence(fact: str, topic: str, path: str) -> dict:
    return {
        "fact": fact,
        "topic": topic,
        "evidence_path": path,
        "provenance": "rtl_read",
    }


def _apb_target(component: str, version: str, closure: str, **overrides) -> dict:
    target = {
        "component_id": component,
        "protocol": "apb",
        "version": version,
        "data_width": 32,
        "address_width": 12,
        "window": {"base": 0x1000_0000, "size": 0x1000},
        "capabilities": {
            "byte_enable": False,
            "partial_write": False,
            "has_error": False,
        },
        "evidence": [
            _evidence("byte_enable", "byte_strobes", f"configs/soc/closures/{closure}"),
            _evidence("partial_write", "byte_strobes", f"configs/soc/closures/{closure}"),
            _evidence("has_error", "pslverr_handling", f"configs/soc/closures/{closure}"),
        ],
    }
    target.update(overrides)
    return target


def _apb4_target() -> dict:
    # APB4 capability target: the protocol plugin records PSTRB, partial writes
    # and PSLVERR as available.  No pinned PULP IP is APB4 (see
    # configs/soc/closures/pulp_*.json), so this fixture is explicit about
    # coming from the protocol contract instead.
    plugin = "src/myfuzz/protocols/plugins/apb4.json"
    return {
        "component_id": "apb4_partial_write_target",
        "protocol": "apb",
        "version": "4",
        "data_width": 32,
        "address_width": 32,
        "window": {"base": 0x2000_0000, "size": 0x1000},
        "capabilities": {
            "byte_enable": True,
            "partial_write": True,
            "has_error": True,
        },
        "evidence": [
            _evidence("byte_enable", "capability_limits.byte_enable", plugin),
            _evidence("partial_write", "capability_limits.partial_write", plugin),
            _evidence("has_error", "fields.pslverr", plugin),
        ],
    }


def _opentitan_target(component: str, closure: str) -> dict:
    return {
        "component_id": component,
        "protocol": "tl-ul",
        "version": "1",
        "data_width": 32,
        "address_width": 32,
        "window": {"base": 0x4000_0000, "size": 0x1000},
        "capabilities": {
            "byte_enable": True,
            "partial_write": True,
            "has_error": True,
            "integrity": "required",
            "source_width": 8,
            "sink_width": 1,
            "user_width": 23,
            "size_width": 2,
        },
        "evidence": [
            _evidence("byte_enable", "tlul_channel_structure", f"configs/soc/closures/{closure}"),
            _evidence("partial_write", "tlul_opcodes", f"configs/soc/closures/{closure}"),
            _evidence("has_error", "d_error_production", f"configs/soc/closures/{closure}"),
            _evidence("integrity", "integrity_check_path", f"configs/soc/closures/{closure}"),
            _evidence("source_width", "tlul_widths", f"configs/soc/closures/{closure}"),
            _evidence("sink_width", "tlul_widths", f"configs/soc/closures/{closure}"),
            _evidence("user_width", "tlul_widths", f"configs/soc/closures/{closure}"),
            _evidence("size_width", "tlul_widths", f"configs/soc/closures/{closure}"),
        ],
    }


def _zipcpu_uart_target() -> dict:
    path = "configs/soc/closures/zipcpu_uart.json"
    return {
        "component_id": "zipcpu_uart",
        "protocol": "wishbone",
        "version": "classic",
        "data_width": 32,
        "address_width": 2,
        "window": {"base": 0x8000_0000, "size": 0x10},
        "capabilities": {
            "byte_enable": True,
            "partial_write": False,
            "has_error": False,
            "has_address_port": True,
            "address_units": "word",
            "sel_implemented": True,
            "wishbone_flavour": "registered-ack",
            "ack_requires_cyc": True,
        },
        "evidence": [
            _evidence("byte_enable", "byte_enable_setup_register", path),
            _evidence("partial_write", "generic_byte_masked_word_write", path),
            _evidence("has_error", "wishbone_error_retry_and_burst", path),
            _evidence("has_address_port", "address_unit", path),
            _evidence("address_units", "address_unit", path),
            _evidence("sel_implemented", "byte_enable_tx_register", path),
            _evidence("wishbone_flavour", "wishbone_subset", path),
            _evidence("ack_requires_cyc", "cyc_stb_semantics", path),
        ],
    }


def _zipcpu_timer_target() -> dict:
    path = "configs/soc/closures/zipcpu_timer.json"
    return {
        "component_id": "zipcpu_timer",
        "protocol": "wishbone",
        "version": "classic",
        "data_width": 32,
        "address_width": 0,
        "window": {"base": 0xc000_0000, "size": 4},
        "capabilities": {
            "byte_enable": False,
            "partial_write": False,
            "has_error": False,
            "has_address_port": False,
            "address_units": "word",
            "sel_implemented": False,
            "wishbone_flavour": "registered-ack-cyc-ignored",
            "ack_requires_cyc": False,
        },
        "evidence": [
            _evidence("byte_enable", "byte_enable_and_partial_writes", path),
            _evidence("partial_write", "partial_write", path),
            _evidence("has_error", "wishbone_error_retry_and_burst", path),
            _evidence("has_address_port", "address_unit_and_single_register_window", path),
            _evidence("address_units", "address_unit_and_single_register_window", path),
            _evidence("sel_implemented", "byte_enable_and_partial_writes", path),
            _evidence("wishbone_flavour", "wishbone_subset", path),
            _evidence("ack_requires_cyc", "cyc_stb_semantics", path),
        ],
    }


def _beat_backend(**overrides) -> dict:
    backend = {
        "protocol": "processor-memory-beat",
        "version": "1",
        "address_width": 32,
        "data_width": 32,
    }
    backend.update(overrides)
    return backend


def _parameters(result: dict) -> dict:
    return {entry["name"]: entry["value"] for entry in result["parameters"]}


# ---------------------------------------------------------------------------
# resolver tests
# ---------------------------------------------------------------------------

class TargetAdapterResolutionTests(unittest.TestCase):
    def test_resolves_apb3_and_apb4_targets(self) -> None:
        gpio = resolve_target_adapter(
            _beat_backend(), _apb_target("pulp_gpio", "3", "pulp_gpio.json")
        )
        self.assertEqual("beat_to_apb", gpio["rtl_module"])
        self.assertEqual("beat-initiator-to-peripheral-target", gpio["direction"])
        self.assertEqual("beat-to-apb3", gpio["adapter_id"])
        self.assertEqual(0, _parameters(gpio)["HAS_PSTRB"])
        self.assertEqual(0, _parameters(gpio)["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual(0, _parameters(gpio)["HAS_PSLVERR"])
        self.assertEqual(0x1000, _parameters(gpio)["WINDOW_SIZE"])
        self.assertEqual(0x1000_0000, _parameters(gpio)["WINDOW_BASE"])
        self.assertEqual({"base": 0x1000_0000, "size": 0x1000}, gpio["window"])
        self.assertEqual("qualified", gpio["beat_fields"]["be"]["status"])
        self.assertEqual("none", gpio["error_source"])
        self.assertEqual(
            "configs/soc/closures/pulp_gpio.json",
            gpio["capability_evidence"]["partial_write"]["evidence_path"],
        )

        apb4 = resolve_target_adapter(_beat_backend(), _apb4_target())
        self.assertEqual("beat-to-apb4", apb4["adapter_id"])
        self.assertEqual(1, _parameters(apb4)["HAS_PSTRB"])
        self.assertEqual(1, _parameters(apb4)["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual(1, _parameters(apb4)["HAS_PSLVERR"])
        self.assertEqual("honoured", apb4["beat_fields"]["be"]["status"])
        self.assertEqual("target_pin", apb4["error_source"])

    def test_resolves_opentitan_tlul_targets_with_integrity(self) -> None:
        for component, closure in (
            ("opentitan_uart", "opentitan_uart.json"),
            ("opentitan_gpio", "opentitan_gpio.json"),
        ):
            result = resolve_target_adapter(
                _beat_backend(), _opentitan_target(component, closure)
            )
            self.assertEqual("beat_to_tlul", result["rtl_module"])
            self.assertEqual("beat-to-tlul", result["adapter_id"])
            params = _parameters(result)
            self.assertEqual(1, params["GEN_INTEGRITY"])
            self.assertEqual(8, params["SOURCE_WIDTH"])
            self.assertEqual(23, params["USER_WIDTH"])
            self.assertEqual(2, params["SIZE_WIDTH"])
            self.assertEqual("honoured", result["beat_fields"]["be"]["status"])
            self.assertEqual("target_pin", result["error_source"])
            self.assertEqual(
                "required", result["capability_evidence"]["integrity"]["value"]
            )

    def test_a_wide_beat_address_requires_a_narrowing_stage(self) -> None:
        for component, closure in (
            ("opentitan_uart", "opentitan_uart.json"),
            ("opentitan_gpio", "opentitan_gpio.json"),
        ):
            with self.subTest(component=component):
                target = _opentitan_target(component, closure)
                wide = resolve_target_adapter(
                    _beat_backend(address_width=64, data_width=32), target
                )
                # The integrity code covers at most 32 address bits, so the
                # adapter is configured at 32 and declares the stage it needs.
                self.assertEqual(32, _parameters(wide)["ADDRESS_WIDTH"])
                self.assertEqual(
                    {"required": True, "upstream_address_width": 64,
                     "downstream_address_width": 32,
                     "window": {"base": target["window"]["base"],
                                "size": target["window"]["size"]}},
                    wide["address_narrowing"])
                narrow = resolve_target_adapter(_beat_backend(), target)
                self.assertEqual(32, _parameters(narrow)["ADDRESS_WIDTH"])
                self.assertFalse(narrow["address_narrowing"]["required"])

    def test_a_window_above_the_integrity_range_is_rejected(self) -> None:
        target = _opentitan_target("opentitan_uart", "opentitan_uart.json")
        target["window"] = {"base": 0x1_0000_0000, "size": 0x1000}
        with self.assertRaises(ValueError) as caught:
            resolve_target_adapter(_beat_backend(address_width=64, data_width=32), target)
        text = str(caught.exception)
        self.assertIn("unsupported-target-capability:address-window:opentitan_uart", text)
        self.assertIn("integrity-address-width=32", text)

    def test_a_target_without_integrity_keeps_the_full_address_width(self) -> None:
        target = _opentitan_target("opentitan_uart", "opentitan_uart.json")
        target["capabilities"]["integrity"] = "none"
        wide = resolve_target_adapter(_beat_backend(address_width=64, data_width=32), target)
        self.assertEqual(64, _parameters(wide)["ADDRESS_WIDTH"])
        self.assertFalse(wide["address_narrowing"]["required"])

    def test_resolves_zipcpu_uart_registered_ack_configuration(self) -> None:
        result = resolve_target_adapter(_beat_backend(), _zipcpu_uart_target())
        self.assertEqual("beat_to_wishbone", result["rtl_module"])
        params = _parameters(result)
        self.assertEqual(1, params["WB_FLAVOUR"])
        self.assertEqual(2, params["TARGET_ADDRESS_WIDTH"])
        self.assertEqual(1, params["ADDRESS_UNITS"])
        self.assertEqual(0, params["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual(0, params["HAS_ERR"])
        self.assertEqual("fabric", result["error_source"])
        self.assertEqual("qualified", result["beat_fields"]["be"]["status"])
        self.assertEqual(1, result["wishbone"]["stb_pulse_cycles"])
        self.assertEqual(1, result["wishbone"]["cyc_hold_after_stb_cycles"])

    def test_resolves_zipcpu_timer_single_register_window(self) -> None:
        result = resolve_target_adapter(_beat_backend(), _zipcpu_timer_target())
        params = _parameters(result)
        self.assertEqual(2, params["WB_FLAVOUR"])
        self.assertEqual(0, params["TARGET_ADDRESS_WIDTH"])
        self.assertEqual(0, params["SUPPORTS_PARTIAL_WRITE"])
        self.assertEqual(4, params["WINDOW_SIZE"])
        self.assertEqual({"base": 0xC000_0000, "size": 4}, result["window"])
        self.assertEqual("qualified", result["beat_fields"]["addr"]["status"])
        self.assertIn("no address port", result["beat_fields"]["addr"]["detail"])
        self.assertEqual(0, result["wishbone"]["cyc_hold_after_stb_cycles"])
        self.assertIn(
            "unimplemented",
            result["unsupported"][0]["reason"] + result["beat_fields"]["be"]["detail"],
        )

    def test_rejects_cpu_side_adapters_as_targets(self) -> None:
        for protocol in ("obi", "axi4", "ready-valid-memory", "processor-memory-beat"):
            target = dict(_opentitan_target("opentitan_uart", "opentitan_uart.json"))
            target["protocol"] = protocol
            target["version"] = "1"
            with self.assertRaises(ValueError) as caught:
                resolve_target_adapter(_beat_backend(), target)
            self.assertTrue(
                str(caught.exception).startswith(f"not-a-target-protocol:{protocol}"),
                str(caught.exception),
            )
        self.assertIsInstance(
            TargetAdapterError("not-a-target-protocol:obi"), ValueError
        )

    def test_rejects_unknown_target_protocol_and_version(self) -> None:
        for protocol, version in (("usb", "1"), ("apb", "5"), ("tl-ul", "2"), ("wishbone", "b4")):
            target = {
                "component_id": "unknown",
                "protocol": protocol,
                "version": version,
                "data_width": 32,
                "capabilities": {},
                "evidence": [],
            }
            with self.assertRaises(ValueError) as caught:
                resolve_target_adapter(_beat_backend(), target)
            self.assertTrue(
                str(caught.exception).startswith("unsupported-target-protocol:"),
                str(caught.exception),
            )

    def test_rejects_non_beat_initiator_backend(self) -> None:
        for protocol in ("obi", "tl-ul", "wishbone"):
            with self.assertRaises(ValueError) as caught:
                resolve_target_adapter(
                    {"protocol": protocol, "version": "1", "address_width": 32, "data_width": 32},
                    _opentitan_target("opentitan_uart", "opentitan_uart.json"),
                )
            self.assertTrue(
                str(caught.exception).startswith("unsupported-initiator-protocol:"),
                str(caught.exception),
            )
        with self.assertRaises(ValueError) as caught:
            resolve_target_adapter(
                _beat_backend(data_width=16),
                _opentitan_target("opentitan_uart", "opentitan_uart.json"),
            )
        self.assertTrue(
            str(caught.exception).startswith("unsupported-beat-width:"), str(caught.exception)
        )

    def test_rejects_capability_requests_that_would_be_silently_wrong(self) -> None:
        cases = []
        wrong_partial = _apb_target("pulp_gpio", "3", "pulp_gpio.json")
        wrong_partial["capabilities"]["partial_write"] = True
        cases.append(("partial-write", wrong_partial))

        wrong_be = _apb_target("pulp_gpio", "4", "pulp_gpio.json")
        wrong_be["capabilities"]["partial_write"] = True
        wrong_be["capabilities"]["byte_enable"] = False
        wrong_be["evidence"].append(
            _evidence("partial_write", "byte_strobes", "configs/soc/closures/pulp_gpio.json")
        )
        cases.append(("partial-write", wrong_be))

        wrong_sel = _zipcpu_timer_target()
        wrong_sel["capabilities"]["partial_write"] = True
        wrong_sel["evidence"].append(
            _evidence("partial_write", "partial_write", "configs/soc/closures/zipcpu_timer.json")
        )
        cases.append(("partial-write", wrong_sel))

        wrong_flavour = _zipcpu_uart_target()
        wrong_flavour["capabilities"]["wishbone_flavour"] = "pipelined-something"
        cases.append(("wishbone-flavour", wrong_flavour))

        wrong_cyc = _zipcpu_uart_target()
        wrong_cyc["capabilities"]["ack_requires_cyc"] = False
        cases.append(("ack-requires-cyc", wrong_cyc))

        wrong_units = _zipcpu_uart_target()
        wrong_units["capabilities"]["address_units"] = "nibble"
        cases.append(("address-units", wrong_units))

        no_window = _zipcpu_timer_target()
        no_window["window"] = {"base": 0xC000_0000, "size": 0}
        cases.append(("window", no_window))

        misaligned = _zipcpu_timer_target()
        misaligned["window"] = {"base": 0xC000_0002, "size": 4}
        cases.append(("window-alignment", misaligned))

        missing_evidence = _apb_target("pulp_gpio", "3", "pulp_gpio.json")
        missing_evidence["evidence"] = missing_evidence["evidence"][:1]
        cases.append(("missing-evidence", missing_evidence))

        for expected, target in cases:
            with self.subTest(expected=expected, component=target["component_id"]):
                with self.assertRaises(ValueError) as caught:
                    resolve_target_adapter(_beat_backend(), target)
                self.assertTrue(
                    str(caught.exception).startswith("unsupported-target-capability:"),
                    str(caught.exception),
                )
                self.assertIn(expected, str(caught.exception))

    def test_rejects_target_width_mismatch_and_integrity_width(self) -> None:
        wide = _opentitan_target("opentitan_uart", "opentitan_uart.json")
        wide["data_width"] = 64
        with self.assertRaises(ValueError) as caught:
            resolve_target_adapter(_beat_backend(), wide)
        self.assertTrue(
            str(caught.exception).startswith("unsupported-target-width:"),
            str(caught.exception),
        )

        narrow = _opentitan_target("opentitan_uart", "opentitan_uart.json")
        narrow["capabilities"]["user_width"] = 12
        narrow["evidence"].append(
            _evidence("user_width", "tlul_widths", "configs/soc/closures/opentitan_uart.json")
        )
        with self.assertRaises(ValueError) as caught:
            resolve_target_adapter(_beat_backend(), narrow)
        self.assertTrue(
            str(caught.exception).startswith(
                "unsupported-target-capability:integrity-user-width"
            ),
            str(caught.exception),
        )

    def test_resolved_configurations_elaborate(self) -> None:
        cases = [
            resolve_target_adapter(
                _beat_backend(), _apb_target("pulp_gpio", "3", "pulp_gpio.json")
            ),
            resolve_target_adapter(_beat_backend(), _apb4_target()),
            resolve_target_adapter(
                _beat_backend(), _opentitan_target("opentitan_uart", "opentitan_uart.json")
            ),
            resolve_target_adapter(_beat_backend(), _zipcpu_uart_target()),
            resolve_target_adapter(_beat_backend(), _zipcpu_timer_target()),
        ]
        for result in cases:
            with self.subTest(adapter=result["adapter_id"]):
                _elaborate_configuration(
                    self,
                    result["rtl_module"],
                    [(entry["name"], entry["value"]) for entry in result["parameters"]],
                    [ROOT / result["rtl_source"]],
                )

    def test_accepts_soc_plan_target_contract_shapes(self) -> None:
        # soc_plan target contracts carry target_id, a (protocol, version) pair
        # and evidence as a mapping of fact to record.
        target = _zipcpu_timer_target()
        target.pop("component_id")
        target.pop("version")
        target["target_id"] = "zipcpu_timer"
        target["protocol"] = ["wishbone", "classic"]
        target["evidence"] = {
            item["fact"]: {
                "topic": item["topic"],
                "evidence_path": item["evidence_path"],
                "provenance": item["provenance"],
            }
            for item in target["evidence"]
        }
        result = resolve_target_adapter(_beat_backend(), target)
        self.assertEqual("zipcpu_timer", result["component_id"])
        self.assertEqual("beat-to-wishbone-registered-ack-cyc-ignored", result["adapter_id"])
        self.assertEqual(
            "configs/soc/closures/zipcpu_timer.json",
            result["capability_evidence"]["partial_write"]["evidence_path"],
        )

    def test_rejects_unknown_capability_keys(self) -> None:
        target = _apb_target("pulp_gpio", "3", "pulp_gpio.json")
        target["capabilities"]["magic_dma"] = True
        with self.assertRaises(ValueError) as caught:
            resolve_target_adapter(_beat_backend(), target)
        self.assertTrue(
            str(caught.exception).startswith("unsupported-target-capability:unknown"),
            str(caught.exception),
        )

    def test_preserves_known_soc_capabilities_not_consumed_by_adapter(self) -> None:
        target = _opentitan_target("opentitan_uart", "opentitan_uart.json")
        target["capabilities"].update({
            "read": True,
            "write": True,
            "max_wait_cycles": 16,
            "alert": False,
        })
        target["evidence"].extend(
            _evidence(name, "soc_contract", "configs/soc/closures/opentitan_uart.json")
            for name in ("read", "write", "max_wait_cycles", "alert")
        )
        result = resolve_target_adapter(_beat_backend(), target)
        self.assertEqual(
            {"read": True, "write": True, "max_wait_cycles": 16, "alert": False},
            result["unconsumed_capabilities"],
        )


# ---------------------------------------------------------------------------
# APB adapter
# ---------------------------------------------------------------------------

_APB4_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic [31:0] paddr, pwdata, prdata;
  logic [3:0] pstrb;
  logic psel, penable, pwrite, pready, pslverr;

  logic [31:0] mem [0:3];
  integer txn_count;
  logic [3:0] wait_q;
  logic inject_err;
  logic [31:0] seen_paddr, seen_pwdata;
  logic [3:0] seen_pstrb;
  logic seen_pwrite;

  beat_to_apb #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_PSTRB(1),
      .SUPPORTS_PARTIAL_WRITE(1), .HAS_PSLVERR(1), .MAX_WAIT_CYCLES(16),
      .WINDOW_BASE(32'h1000_0000), .WINDOW_SIZE(32'h100)
  ) dut (.*);

  always_ff @(posedge clk) begin
    if (reset) begin
      pready <= 1'b0; pslverr <= 1'b0; prdata <= '0; wait_q <= '0;
      seen_paddr <= '0; seen_pwdata <= '0; seen_pstrb <= '0; seen_pwrite <= 1'b0;
    end else begin
      pslverr <= 1'b0;
      if (psel && !penable) begin
        wait_q <= 4'd2;
        prdata <= mem[paddr[3:2]];
        seen_paddr <= paddr; seen_pwdata <= pwdata;
        seen_pstrb <= pstrb; seen_pwrite <= pwrite;
      end else if (psel && penable) begin
        if (!pready) begin
          if (wait_q != 0) wait_q <= wait_q - 1'b1;
          else begin
            pready <= 1'b1;
            txn_count <= txn_count + 1;
            if (pwrite) mem[paddr[3:2]] <= pwdata;
            if (inject_err) pslverr <= 1'b1;
          end
        end
      end else begin
        pready <= 1'b0;
        wait_q <= '0;
      end
    end
  end

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    inject_err = 1'b0; txn_count = 0;
    mem[0] = 32'h1111_0000; mem[1] = 32'hcafe_babe;
    mem[2] = 32'h2222_0000; mem[3] = 32'h3333_0000;

    tick();
    check(!req_ready, "adapter must not accept while reset is asserted");
    check(!psel && !penable, "no APB activity during reset");
    reset = 1'b0;
    tick();
    check(req_ready && !rsp_valid, "adapter ready after reset");

    // 1) accepted read with delayed target response and scrambled candidates
    write = 1'b0; addr = 32'h1000_0004; be = 4'hf; wdata = 32'hffff_ffff;
    req_valid = 1'b1;
    check(req_ready, "ready before read handshake");
    tick();
    req_valid = 1'b0;
    check(!req_ready, "busy after accepting the read");
    write = 1'b1; addr = 32'hdead_beef; wdata = 32'h5555_5555; be = 4'h1;
    check(psel && !penable, "APB SETUP phase after acceptance");
    check(paddr == 32'h1000_0004 && !pwrite, "latched read address and direction");
    tick();
    check(psel && penable, "APB ACCESS phase");
    tick();
    check(psel && penable && paddr == 32'h1000_0004 && pwdata == 32'hffff_ffff,
          "APB held stable during wait state 1");
    tick();
    check(psel && penable && paddr == 32'h1000_0004 && pwdata == 32'hffff_ffff,
          "APB held stable during wait state 2");
    tick();
    check(psel && penable && paddr == 32'h1000_0004, "APB held on the completing cycle");
    wait_response(4);
    check(!error && rdata == 32'hcafe_babe, "delayed read returns target data");
    check(txn_count == 1, "exactly one APB transfer for the read");
    check(seen_paddr == 32'h1000_0004 && !seen_pwrite && seen_pstrb == 4'h0,
          "target observed the original read request");
    tick();
    check(!rsp_valid, "response consumed");

    // 2) accepted partial write: APB4 drives PSTRB from be
    write = 1'b1; addr = 32'h1000_0008; wdata = 32'h1234_5678; be = 4'b0011;
    req_valid = 1'b1;
    check(req_ready, "ready before write handshake");
    tick();
    req_valid = 1'b0;
    write = 1'b0; addr = 32'h2000_0000; wdata = 32'h9; be = 4'hf;
    check(psel && !penable && pwrite, "APB write SETUP phase");
    check(paddr == 32'h1000_0008 && pwdata == 32'h1234_5678 && pstrb == 4'b0011,
          "write address, data and byte strobes latched");
    tick();
    check(psel && penable && pstrb == 4'b0011, "write ACCESS drives PSTRB");
    wait_response(6);
    check(!error && rdata == 32'h0, "write completes without read data");
    check(mem[2] == 32'h1234_5678, "write performed exactly one side effect");
    check(txn_count == 2, "exactly one APB transfer for the write");
    check(seen_pstrb == 4'b0011 && seen_pwrite && seen_pwdata == 32'h1234_5678,
          "target observed the original write request");
    tick();

    // 3) PSLVERR maps to the beat error response and the adapter recovers
    inject_err = 1'b1;
    write = 1'b0; addr = 32'h1000_0000; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(error && rdata == 32'h0, "PSLVERR becomes the beat error response");
    check(txn_count == 3, "errored transfer is one target transaction");
    tick();
    inject_err = 1'b0;
    write = 1'b0; addr = 32'h1000_000c; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(!error && rdata == 32'h3333_0000, "normal transaction after an error");
    check(txn_count == 4, "recovery performs exactly one target transaction");
    tick();

    // 4) unaddressed window: error response and no APB select
    write = 1'b1; addr = 32'h2000_0000; be = 4'hf; wdata = 32'hdead_c0de;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "out-of-window request errors without a bus cycle");
    check(!psel && !penable, "unselected target sees no select or enable");
    repeat (3) tick();
    check(txn_count == 4, "unselected target sees no transfer");
    check(!psel, "no strobe for an unselected target");
    tick();

    // 5) reset terminates the in-flight transaction with no duplicate effect
    write = 1'b1; addr = 32'h1000_0008; be = 4'hf; wdata = 32'hfeed_face;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    tick();
    check(psel && penable, "transaction in flight before reset");
    reset = 1'b1;
    tick();
    check(!psel && !penable && !rsp_valid && !req_ready,
          "reset terminates the transaction cleanly");
    reset = 1'b0;
    tick();
    check(req_ready && !rsp_valid, "adapter recovers after reset");
    check(txn_count == 4, "interrupted transaction left no duplicated transfer");
    write = 1'b1; addr = 32'h1000_0008; be = 4'hf; wdata = 32'h0bad_f00d;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(!error && mem[2] == 32'h0bad_f00d, "post-reset write applies once");
    check(txn_count == 5, "post-reset write performs exactly one transfer");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)

_APB3_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic [31:0] paddr, pwdata, prdata;
  logic [3:0] pstrb;
  logic psel, penable, pwrite, pready, pslverr;

  logic [31:0] mem [0:3];
  integer txn_count;

  // PULP apb_gpio / apb_spi_master: PREADY is a constant 1 and PSLVERR a constant 0.
  assign pready = 1'b1;
  assign pslverr = 1'b0;

  beat_to_apb #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_PSTRB(0),
      .SUPPORTS_PARTIAL_WRITE(0), .HAS_PSLVERR(0), .MAX_WAIT_CYCLES(16),
      .WINDOW_BASE(32'h1000_0000), .WINDOW_SIZE(32'h1000)
  ) dut (.*);

  always_ff @(posedge clk) begin
    if (reset) begin
      prdata <= '0;
    end else if (psel && !penable) begin
      prdata <= mem[paddr[3:2]];
    end else if (psel && penable && pready) begin
      txn_count <= txn_count + 1;
      if (pwrite) mem[paddr[3:2]] <= pwdata;
    end
  end

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    txn_count = 0;
    mem[0] = 32'h0a0b_0c0d; mem[1] = 32'h1111_2222;
    mem[2] = 32'h0; mem[3] = 32'h0;

    tick();
    check(!psel && !penable && !rsp_valid, "no APB activity during reset");
    reset = 1'b0;
    tick();
    check(req_ready, "ready after reset");

    // full-word read from a PREADY=1 target completes in SETUP then ACCESS
    write = 1'b0; addr = 32'h1000_0000; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(psel && !penable, "APB3 SETUP phase");
    check(!pwrite && paddr == 32'h1000_0000, "read fields latched");
    tick();
    check(psel && penable, "APB3 ACCESS phase");
    wait_response(2);
    check(!error && rdata == 32'h0a0b_0c0d, "constant-PREADY read completes");
    check(txn_count == 1, "exactly one APB transfer for the read");
    tick();

    // full-word write works against a target without PSTRB
    write = 1'b1; addr = 32'h1000_0004; wdata = 32'hc0de_1234; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(psel && !penable && pwrite && pstrb == 4'h0, "APB3 write SETUP ties PSTRB low");
    tick();
    wait_response(2);
    check(!error && mem[1] == 32'hc0de_1234, "full-word write applies");
    check(txn_count == 2, "exactly one APB transfer for the write");
    tick();

    // partial write: rejected with an error response and zero APB activity
    write = 1'b1; addr = 32'h1000_0004; wdata = 32'h5555_aaaa; be = 4'b0001;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error && rdata == 32'h0, "partial write to APB3 is an error response");
    check(!psel && !penable && !pwrite, "rejected partial write issues no APB transfer");
    repeat (4) tick();
    check(!psel, "no strobe persists after the rejection");
    check(mem[1] == 32'hc0de_1234, "rejected partial write has no side effect");
    check(txn_count == 2, "rejected partial write issues zero target transactions");
    tick();

    // partial byte enable on a read is not a write mask: it reads the full word
    write = 1'b0; addr = 32'h1000_0000; be = 4'b0001;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(3);
    check(!error && rdata == 32'h0a0b_0c0d, "reads ignore the write byte enable");
    check(txn_count == 3, "read performs exactly one target transaction");
    tick();

    // recovery after the rejection
    write = 1'b1; addr = 32'h1000_0008; wdata = 32'hfeed_0001; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(3);
    check(!error && mem[2] == 32'hfeed_0001, "normal write after a rejected partial write");
    check(txn_count == 4, "recovery performs exactly one target transaction");
    tick();

    // reset terminates an in-flight write without duplicating it
    write = 1'b1; addr = 32'h1000_000c; wdata = 32'h9999_8888; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    reset = 1'b1;
    tick();
    check(!psel && !penable && !rsp_valid && !req_ready, "reset clears APB3 transaction");
    reset = 1'b0;
    tick();
    check(req_ready && !rsp_valid, "APB3 recovered after reset");
    check(txn_count == 4, "interrupted APB3 write left no duplicate transfer");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)


class ApbTargetAdapterRtlTests(unittest.TestCase):
    def test_apb4_latching_wait_states_errors_and_reset(self) -> None:
        _compile_and_run(self, _APB4_TB, [RTL / "beat_to_apb.sv"])

    def test_apb3_rejects_partial_writes_and_supports_constant_pready(self) -> None:
        _compile_and_run(self, _APB3_TB, [RTL / "beat_to_apb.sv"])


# ---------------------------------------------------------------------------
# TL-UL adapter
# ---------------------------------------------------------------------------

_TLUL_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic a_valid, a_ready;
  logic [2:0] a_opcode, a_param;
  logic [1:0] a_size;
  logic [7:0] a_source;
  logic [31:0] a_address, a_data;
  logic [3:0] a_mask;
  logic [22:0] a_user;

  logic d_valid, d_ready;
  logic [2:0] d_opcode, d_param;
  logic [1:0] d_size;
  logic [7:0] d_source;
  logic d_sink;
  logic [31:0] d_data;
  logic [13:0] d_user;
  logic d_error;

  logic [31:0] mem [0:7];
  integer txn_count;
  logic pending;
  logic [1:0] d_delay;
  logic inject_err;
  logic [31:0] seen_addr, seen_data;
  logic [3:0] seen_mask;
  logic [2:0] seen_opcode;

  // OpenTitan reference encoders: the golden integrity values.
  logic [56:0] cmd_payload;
  logic [63:0] cmd_code;
  logic [38:0] data_code;
  always_comb cmd_payload = {14'b0, 4'h9, a_address, a_opcode, a_mask};
  prim_secded_inv_64_57_enc u_cmd_ref (.data_i(cmd_payload), .data_o(cmd_code));
  prim_secded_inv_39_32_enc u_data_ref (.data_i(a_data), .data_o(data_code));

  beat_to_tlul #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .SIZE_WIDTH(2), .SOURCE_WIDTH(8),
      .SINK_WIDTH(1), .USER_WIDTH(23), .GEN_INTEGRITY(1), .SOURCE_ID(0),
      .MAX_WAIT_CYCLES(16), .WINDOW_BASE(32'h4000_0000), .WINDOW_SIZE(32'h1000)
  ) dut (.*);

  assign a_ready = !pending;

  always_ff @(posedge clk) begin
    if (reset) begin
      pending <= 1'b0; d_delay <= '0; d_valid <= 1'b0; d_error <= 1'b0;
      d_opcode <= '0; d_param <= '0; d_size <= '0; d_source <= '0; d_sink <= 1'b0;
      d_data <= '0; d_user <= '0;
      seen_addr <= '0; seen_data <= '0; seen_mask <= '0; seen_opcode <= '0;
    end else begin
      if (a_valid && a_ready) begin
        pending <= 1'b1;
        d_delay <= 2'd2;
        d_valid <= 1'b0;
        txn_count <= txn_count + 1;
        seen_addr <= a_address; seen_data <= a_data;
        seen_mask <= a_mask; seen_opcode <= a_opcode;
        d_opcode <= (a_opcode == 3'd4) ? 3'd1 : 3'd0;
        d_param <= 3'd0;
        d_size <= a_size;
        d_source <= a_source;
        d_sink <= 1'b0;
        d_error <= inject_err;
        d_user <= 16'hffff;
        if (a_opcode == 3'd0 || a_opcode == 3'd1) mem[a_address[4:2]] <= a_data;
        d_data <= ((a_opcode == 3'd4) && !inject_err) ? mem[a_address[4:2]] : 32'hffff_ffff;
      end else if (pending) begin
        if (d_delay != 0) d_delay <= d_delay - 1'b1;
        else d_valid <= 1'b1;
      end
      if (d_valid && d_ready) begin
        d_valid <= 1'b0;
        pending <= 1'b0;
      end
    end
  end

  task check_integrity;
    logic [6:0] expected_cmd;
    logic [6:0] expected_data;
    begin
      expected_cmd = cmd_code[63:57];
      expected_data = data_code[38:32];
      check(a_user[6:0] == expected_data, "a_user data integrity matches the OpenTitan encoder");
      check(a_user[13:7] == expected_cmd, "a_user command integrity matches the OpenTitan encoder");
      check(a_user[17:14] == 4'h9, "a_user instr_type is MuBi4False");
      check(a_user[22:18] == 5'b0, "a_user reserved bits are zero");
    end
  endtask

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    inject_err = 1'b0; txn_count = 0;
    mem[0] = 32'h0102_0304; mem[1] = 32'hfeed_1234; mem[2] = 32'h0; mem[3] = 32'h0;

    tick();
    check(!a_valid && !d_ready && !req_ready, "reset clears both TL-UL channels");
    reset = 1'b0;
    tick();
    check(req_ready && a_ready, "adapter ready after reset");

    // 1) Get with delayed D channel and scrambled candidate fields
    write = 1'b0; addr = 32'h4000_0004; be = 4'hf; wdata = 32'hdead_beef;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    write = 1'b1; addr = 32'h7777_7777; wdata = 32'h1234_abcd; be = 4'h7;
    check(a_valid, "A channel request in flight");
    check(a_opcode == 3'd4 && a_param == 3'd0 && a_size == 2'd2,
          "Get is a 4-byte transfer with no param");
    check(a_address == 32'h4000_0004 && a_mask == 4'hf, "Get address and mask latched");
    check(a_source == 8'h0, "single outstanding transaction uses a constant source");
    check(a_data == 32'h0, "Get data is zeroed");
    check_integrity();
    tick();
    check(d_ready && !a_valid, "A handshake moves to the D channel");
    check(seen_addr == 32'h4000_0004 && seen_opcode == 3'd4 && seen_mask == 4'hf,
          "target observed the original Get");
    tick();
    check(d_ready && !d_valid, "D channel waits for a delayed response");
    tick();
    tick();
    check(d_valid && d_opcode == 3'd1 && d_source == 8'h0 && !d_error,
          "AccessAckData arrives with the original source");
    tick();
    check(!d_valid, "D handshake consumed");
    wait_response(2);
    check(!error && rdata == 32'hfeed_1234, "Get returns target data");
    check(txn_count == 1, "exactly one target transaction for the Get");
    tick();

    // 2) PutPartialData carries a_mask from be and latches all fields
    write = 1'b1; addr = 32'h4000_0008; wdata = 32'h1234_5678; be = 4'b0011;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    write = 1'b0; addr = 32'h0; wdata = 32'hdead_beef; be = 4'hf;
    check(a_valid && a_opcode == 3'd1 && a_mask == 4'b0011 && a_data == 32'h1234_5678,
          "partial write becomes PutPartialData with a_mask from be");
    check(a_address == 32'h4000_0008, "partial write address latched");
    check_integrity();
    tick();
    check(seen_addr == 32'h4000_0008 && seen_data == 32'h1234_5678 && seen_mask == 4'b0011,
          "target observed the original partial write");
    wait_response(8);
    check(!error && rdata == 32'h0, "write completes without read data");
    check(txn_count == 2, "exactly one target transaction for the partial write");
    check(mem[2] == 32'h1234_5678, "partial write side effect applied once");
    tick();

    // 3) full-word write uses PutFullData
    write = 1'b1; addr = 32'h4000_000c; wdata = 32'h0bad_f00d; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(a_valid && a_opcode == 3'd0 && a_mask == 4'hf && a_data == 32'h0bad_f00d,
          "full-word write becomes PutFullData");
    check_integrity();
    wait_response(8);
    check(!error && mem[3] == 32'h0bad_f00d, "full-word write applies once");
    check(txn_count == 3, "exactly one target transaction for the full write");
    tick();

    // 4) d_error maps to the beat error and errored data is not meaningful
    inject_err = 1'b1;
    write = 1'b0; addr = 32'h4000_0004; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(error && rdata == 32'h0, "d_error becomes the beat error and erases read data");
    check(txn_count == 4, "errored Get is one target transaction");
    tick();

    // 5) recovery after an error
    inject_err = 1'b0;
    write = 1'b0; addr = 32'h4000_0004; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(!error && rdata == 32'hfeed_1234, "Get after an errored Get");
    check(txn_count == 5, "recovery is exactly one target transaction");
    tick();

    // 6) unaddressed window: beat error without any A-channel activity
    write = 1'b1; addr = 32'h5000_0000; wdata = 32'hdead_c0de; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "out-of-window request errors locally");
    check(!a_valid, "unselected target sees no A channel request");
    repeat (3) tick();
    check(txn_count == 5, "unselected target sees no transaction");
    tick();

    // 7) reset terminates the in-flight A channel with no duplicate effect
    write = 1'b1; addr = 32'h4000_0010; wdata = 32'h5555_0001; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(a_valid, "write in flight before reset");
    reset = 1'b1;
    tick();
    check(!a_valid && !d_ready && !rsp_valid && !req_ready, "reset clears the TL-UL adapter");
    reset = 1'b0;
    tick();
    check(req_ready, "TL-UL adapter recovers after reset");
    check(txn_count == 5, "interrupted write left no duplicated transaction");
    write = 1'b1; addr = 32'h4000_0010; wdata = 32'h5555_0002; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(!error && mem[4] == 32'h5555_0002, "post-reset write applies once");
    check(txn_count == 6, "post-reset write is exactly one target transaction");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)

_TLUL_FATAL_TB = textwrap.dedent(
    """\
module tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  beat_to_tlul #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(64), .GEN_INTEGRITY(1)
  ) dut (.clk(clk), .reset(reset));
  initial begin
    #10;
    $display("PASS");
    $finish;
  end
endmodule
"""
)


class TlUlTargetAdapterRtlTests(unittest.TestCase):
    def test_tlul_latching_integrity_errors_and_reset(self) -> None:
        _compile_and_run(
            self,
            _TLUL_TB,
            [
                RTL / "beat_to_tlul.sv",
                OT_PRIM / "prim_secded_inv_39_32_enc.sv",
                OT_PRIM / "prim_secded_inv_64_57_enc.sv",
            ],
        )

    def test_tlul_integrity_width_is_rejected_at_elaboration(self) -> None:
        result = _compile_and_run(
            self,
            _TLUL_FATAL_TB,
            [
                RTL / "beat_to_tlul.sv",
                OT_PRIM / "prim_secded_inv_39_32_enc.sv",
                OT_PRIM / "prim_secded_inv_64_57_enc.sv",
            ],
            expect_success=False,
        )
        self.assertIn("integrity", (result.stdout + result.stderr).lower())


# ---------------------------------------------------------------------------
# Wishbone adapter
# ---------------------------------------------------------------------------

_WB_UART_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic request_accepted, completion;
  logic cyc, stb, we;
  logic [1:0] adr;
  logic [31:0] dat_w, dat_r;
  logic [3:0] sel;
  logic ack, err, stall;

  logic [31:0] mem [0:3];
  integer txn_count;
  integer stb_cycles;
  integer cyc_cycles;
  logic r_stb, r_cyc, ack_q;
  logic stb_d;
  logic err_d;
  logic [31:0] seen_dat_w;
  logic [1:0] seen_adr;
  logic seen_we;
  logic fabric_err;
  integer txn_mark;

  beat_to_wishbone #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .WB_FLAVOUR(1),
      .TARGET_ADDRESS_WIDTH(2), .ADDRESS_UNITS(1), .SUPPORTS_PARTIAL_WRITE(0),
      .HAS_ERR(0), .MAX_WAIT_CYCLES(16),
      .WINDOW_BASE(32'h8000_0000), .WINDOW_SIZE(32'h10)
  ) dut (.*);

  // wbuart-like target: STB alone triggers the action, ACK is registered and
  // gated by CYC one cycle after the STB pulse (ACK in T+2).
  assign ack = ack_q;
  assign err = fabric_err;
  assign stall = 1'b0;
  assign dat_r = mem[adr];

  always_ff @(posedge clk) begin
    if (reset) begin
      r_stb <= 1'b0; r_cyc <= 1'b0; ack_q <= 1'b0; stb_d <= 1'b0; err_d <= 1'b0;
      seen_dat_w <= '0; seen_adr <= '0; seen_we <= 1'b0;
    end else begin
      r_stb <= stb;
      r_cyc <= cyc;
      ack_q <= r_stb && r_cyc;
      if (stb) begin
        txn_count <= txn_count + 1;
        seen_dat_w <= dat_w;
        seen_adr <= adr;
        seen_we <= we;
        if (we) mem[adr] <= dat_w;
      end
      if (stb) stb_cycles <= stb_cycles + 1;
      if (cyc) cyc_cycles <= cyc_cycles + 1;
      if (stb && stb_d) begin
        $display("FAIL: STB was asserted for more than one cycle");
        $fatal(1);
      end
      if (stb && !cyc) begin
        $display("FAIL: STB asserted without CYC");
        $fatal(1);
      end
      if (stb_d && !cyc && !err_d) begin
        $display("FAIL: CYC dropped in the cycle after the STB pulse");
        $fatal(1);
      end
      stb_d <= stb;
      err_d <= err;
    end
  end

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    fabric_err = 1'b0; txn_count = 0; stb_cycles = 0; cyc_cycles = 0;
    mem[0] = 32'h1000_0000; mem[1] = 32'hc0de_1234;
    mem[2] = 32'h0; mem[3] = 32'h0;

    tick();
    check(!cyc && !stb && !rsp_valid, "no bus cycle during reset");
    reset = 1'b0;
    tick();
    check(req_ready, "ready after reset");

    // 1) read: one-cycle STB, CYC held into T+1, registered ACK in T+2
    write = 1'b0; addr = 32'h8000_0004; be = 4'hf; wdata = 32'hffff_ffff;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc && !we, "STB launch with CYC asserted");
    check(adr == 2'b01 && request_accepted, "word address conversion and accept pulse");
    check(sel == 4'hf, "read selects the addressed bytes");
    write = 1'b1; addr = 32'h8000_0008; wdata = 32'h5555_5555; be = 4'h1;
    tick();
    check(!stb && cyc, "STB is a one-cycle pulse and CYC is held into T+1");
    check(!completion, "no completion before the registered ACK");
    tick();
    check(!stb && completion, "registered ACK completes the cycle");
    wait_response(3);
    check(!error && rdata == 32'hc0de_1234, "read returns target data");
    check(txn_count == 1, "exactly one target transaction for the read");
    check(seen_adr == 2'b01 && !seen_we, "target observed the original read");
    tick();

    // 2) full-word write: exactly one side effect despite the 2-cycle ACK
    write = 1'b1; addr = 32'h8000_0008; wdata = 32'h1234_5678; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc && we && sel == 4'hf, "write launches with a full byte select");
    check(adr == 2'b10, "write word address latched");
    check(request_accepted && !completion, "accepted is distinct from completion");
    tick();
    tick();
    wait_response(4);
    check(!error && rdata == 32'h0, "write completes without data");
    check(txn_count == 2, "exactly one target transaction for the write");
    check(mem[2] == 32'h1234_5678, "write side effect applied once");
    check(seen_dat_w == 32'h1234_5678 && seen_we, "target observed the original write");
    tick();

    // 3) partial write is rejected: error response and zero bus activity
    txn_mark = txn_count;
    write = 1'b1; addr = 32'h8000_0008; wdata = 32'h9999_0000; be = 4'b0001;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "partial write to a target without byte masking errors");
    check(!stb && !cyc, "rejected partial write issues no bus cycle");
    repeat (3) tick();
    check(txn_count == txn_mark && mem[2] == 32'h1234_5678,
          "rejected partial write has no side effect");
    check(!stb && !cyc, "no strobe persists after the rejection");
    tick();

    // 4) fabric-side error: the IP has no error pin, the fabric supplies one
    write = 1'b0; addr = 32'h8000_0004; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc, "read launches before the fabric error");
    fabric_err = 1'b1;
    #1;
    check(completion, "fabric error completes the cycle");
    tick();
    fabric_err = 1'b0;
    wait_response(3);
    check(error && rdata == 32'h0, "fabric error becomes the beat error response");
    tick();

    // 5) recovery after the fabric error
    write = 1'b0; addr = 32'h8000_0004; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(5);
    check(!error && rdata == 32'hc0de_1234, "read after a fabric error");
    tick();

    // 6) unaddressed window: no strobe for a target that is not addressed
    txn_mark = txn_count;
    write = 1'b1; addr = 32'h9000_0000; wdata = 32'hdead_c0de; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "out-of-window request errors locally");
    check(!stb && !cyc, "unselected target sees no strobe or cycle");
    repeat (2) tick();
    check(txn_count == txn_mark, "unselected target sees no transaction");
    tick();

    // 7) reset terminates the bus cycle without a duplicate side effect
    txn_mark = txn_count;
    write = 1'b1; addr = 32'h8000_000c; wdata = 32'h0bad_f00d; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc, "write in flight before reset");
    reset = 1'b1;
    tick();
    check(!stb && !cyc && !rsp_valid && !req_ready, "reset terminates the bus cycle");
    reset = 1'b0;
    tick();
    check(req_ready, "Wishbone adapter recovers after reset");
    check(txn_count == txn_mark, "interrupted write left no duplicated target action");
    write = 1'b1; addr = 32'h8000_000c; wdata = 32'h0bad_f00d; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(5);
    check(!error && mem[3] == 32'h0bad_f00d, "post-reset write applies once");
    check(txn_count == txn_mark + 1, "post-reset write is exactly one target transaction");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)

_WB_TIMER_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic request_accepted, completion;
  logic cyc, stb, we;
  logic adr;
  logic [31:0] dat_w, dat_r;
  logic [3:0] sel;
  logic ack, err, stall;

  integer txn_count;
  integer stb_cycles;
  logic [31:0] r_value;
  logic stb_d;
  logic [31:0] seen_dat_w;
  logic seen_we;

  beat_to_wishbone #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .WB_FLAVOUR(2),
      .TARGET_ADDRESS_WIDTH(0), .ADDRESS_UNITS(1), .SUPPORTS_PARTIAL_WRITE(0),
      .HAS_ERR(0), .MAX_WAIT_CYCLES(16),
      .WINDOW_BASE(32'hc000_0000), .WINDOW_SIZE(4)
  ) dut (.*);

  // ziptimer-like target: no address port, i_wb_sel unimplemented, CYC ignored,
  // ACK is a registered copy of STB (one cycle later).
  assign ack = stb_d;
  assign err = 1'b0;
  assign stall = 1'b0;
  assign dat_r = r_value;

  always_ff @(posedge clk) begin
    if (reset) begin
      stb_d <= 1'b0; r_value <= '0;
      seen_dat_w <= '0; seen_we <= 1'b0;
    end else begin
      stb_d <= stb;
      if (stb) begin
        txn_count <= txn_count + 1;
        stb_cycles <= stb_cycles + 1;
        seen_dat_w <= dat_w;
        seen_we <= we;
        if (we) r_value <= dat_w;
      end
      if (stb && stb_d) begin
        $display("FAIL: STB was asserted for more than one cycle");
        $fatal(1);
      end
      if (stb && !cyc) begin
        $display("FAIL: STB asserted without CYC");
        $fatal(1);
      end
    end
  end

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    txn_count = 0; stb_cycles = 0;

    tick();
    check(!cyc && !stb && !rsp_valid, "no bus cycle during reset");
    reset = 1'b0;
    tick();

    // 1) write the single register with a one-cycle STB, ACK in T+1
    write = 1'b1; addr = 32'hc000_0000; wdata = 32'h00ab_cdef; be = 4'hf;
    req_valid = 1'b1;
    check(req_ready, "ready before the single-register write");
    tick();
    req_valid = 1'b0;
    check(stb && cyc && we && request_accepted, "STB launch for the timer register");
    write = 1'b0; addr = 32'hc000_0004; wdata = 32'hffff_ffff; be = 4'h1;
    tick();
    check(!stb && completion, "ziptimer ACK arrives one cycle after STB");
    wait_response(3);
    check(!error && rdata == 32'h0, "timer write completes");
    check(txn_count == 1 && r_value == 32'h00ab_cdef, "single register write applied once");
    check(seen_dat_w == 32'h00ab_cdef && seen_we, "target observed the original write");
    tick();

    // 2) read the single register back
    write = 1'b0; addr = 32'hc000_0000; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc && !we, "read launches one STB pulse");
    tick();
    wait_response(3);
    check(!error && rdata == 32'h00ab_cdef, "timer read returns the written value");
    check(txn_count == 2, "exactly one target transaction for the read");
    tick();

    // 3) sub-word write is rejected: no side effect, no bus cycle
    write = 1'b1; addr = 32'hc000_0000; wdata = 32'h0000_00ff; be = 4'b0001;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "sub-word write to a target without sel support errors");
    check(!stb && !cyc, "rejected sub-word write issues no bus cycle");
    repeat (3) tick();
    check(txn_count == 2 && r_value == 32'h00ab_cdef, "rejected sub-word write has no effect");
    tick();

    // 4) out-of-window access to the single register window
    write = 1'b1; addr = 32'hc000_0004; wdata = 32'hffff_ffff; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(rsp_valid && error, "out-of-window access to the single register errors");
    check(!stb && !cyc, "no address pin and no strobe outside the declared window");
    check(txn_count == 2, "out-of-window access performs no target transaction");
    tick();

    // 5) reset terminates the in-flight cycle without duplicating the write
    write = 1'b1; addr = 32'hc000_0000; wdata = 32'h1234_5678; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc, "write in flight before reset");
    reset = 1'b1;
    tick();
    check(!stb && !cyc && !rsp_valid && !req_ready, "reset terminates the timer cycle");
    reset = 1'b0;
    tick();
    check(req_ready, "timer adapter recovers after reset");
    check(txn_count == 2, "interrupted write left no duplicated transaction");
    write = 1'b1; addr = 32'hc000_0000; wdata = 32'h1234_5678; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(3);
    check(!error && r_value == 32'h1234_5678, "post-reset write applies once");
    check(txn_count == 3, "post-reset write is exactly one target transaction");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)

_WB_CLASSIC_TB = (
    _HEADER
    + textwrap.dedent(
        """

  logic request_accepted, completion;
  logic cyc, stb, we;
  logic [1:0] adr;
  logic [31:0] dat_w, dat_r;
  logic [3:0] sel;
  logic ack, err, stall;

  logic [31:0] mem [0:3];
  integer txn_count;
  logic [1:0] hold_q;
  logic inject_err;
  logic [31:0] seen_dat_w;
  logic [3:0] seen_sel;

  beat_to_wishbone #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .WB_FLAVOUR(0),
      .TARGET_ADDRESS_WIDTH(2), .ADDRESS_UNITS(0), .SUPPORTS_PARTIAL_WRITE(1),
      .HAS_ERR(1), .MAX_WAIT_CYCLES(16),
      .WINDOW_BASE(32'h8000_0000), .WINDOW_SIZE(32'h10)
  ) dut (.*);

  assign stall = 1'b0;
  assign dat_r = mem[adr];

  // classic target: accepts a held CYC/STB cycle and completes on the third one
  always_ff @(posedge clk) begin
    if (reset) begin
      ack <= 1'b0; err <= 1'b0; hold_q <= '0;
      seen_dat_w <= '0; seen_sel <= '0;
    end else begin
      ack <= 1'b0;
      err <= 1'b0;
      if (cyc && stb) begin
        if (hold_q == 2'd2) begin
          hold_q <= '0;
          txn_count <= txn_count + 1;
          seen_dat_w <= dat_w;
          seen_sel <= sel;
          if (inject_err) err <= 1'b1;
          else begin
            ack <= 1'b1;
            if (we) mem[adr] <= dat_w;
          end
        end else hold_q <= hold_q + 1'b1;
      end else hold_q <= '0;
    end
  end

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = '0; wdata = '0; be = '0; rsp_ready = 1'b1;
    inject_err = 1'b0; txn_count = 0;
    mem[0] = 32'h0000_00aa; mem[1] = 32'h0000_00bb;
    mem[2] = 32'h0; mem[3] = 32'h0;

    tick();
    check(!cyc && !stb, "no bus cycle during reset");
    reset = 1'b0;
    tick();
    check(req_ready, "ready after reset");

    // classic read: CYC and STB stay asserted until the target completes
    write = 1'b0; addr = 32'h8000_0001; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc && request_accepted, "classic cycle launched");
    check(adr == 2'b01 && sel == 4'hf, "byte address drives the target address port");
    tick();
    check(stb && cyc && !completion, "classic cycle holds STB while waiting");
    tick();
    check(stb && cyc, "classic cycle still held before completion");
    tick();
    check(completion && !err, "classic ACK completes the cycle");
    check(stb, "STB is still asserted in the ACK cycle");
    wait_response(3);
    check(!error && rdata == 32'h0000_00bb, "classic read returns target data");
    check(txn_count == 1, "exactly one target transaction for the classic read");
    tick();
    check(!stb && !cyc, "classic cycle released after ACK");

    // classic write with a partial byte select is allowed by capability
    write = 1'b1; addr = 32'h8000_0002; wdata = 32'h0000_1234; be = 4'b0011;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    check(stb && cyc && we && sel == 4'b0011, "classic partial write drives sel");
    check(adr == 2'b10, "classic byte address conversion");
    repeat (3) tick();
    wait_response(3);
    check(!error, "classic write completes");
    check(txn_count == 2 && mem[2] == 32'h0000_1234, "classic write applies once");
    check(seen_dat_w == 32'h0000_1234 && seen_sel == 4'b0011, "target observed the write");
    tick();

    // Wishbone ERR maps to the beat error response, then recovery
    inject_err = 1'b1;
    write = 1'b1; addr = 32'h8000_0002; wdata = 32'hdead_beef; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(error && rdata == 32'h0, "Wishbone ERR becomes the beat error response");
    check(txn_count == 3, "errored classic cycle is one target transaction");
    tick();
    inject_err = 1'b0;
    write = 1'b1; addr = 32'h8000_0002; wdata = 32'h0000_4321; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    wait_response(8);
    check(!error && mem[2] == 32'h0000_4321, "classic write after an error");
    check(txn_count == 4, "recovery is exactly one target transaction");
    tick();

    // reset during a classic cycle terminates cleanly
    write = 1'b1; addr = 32'h8000_0003; wdata = 32'h0000_5555; be = 4'hf;
    req_valid = 1'b1;
    tick();
    req_valid = 1'b0;
    tick();
    check(stb && cyc, "classic cycle in flight before reset");
    reset = 1'b1;
    tick();
    check(!stb && !cyc && !rsp_valid && !req_ready, "reset terminates the classic cycle");
    reset = 1'b0;
    tick();
    check(req_ready && !rsp_valid, "classic adapter recovers after reset");

    $display("PASS");
    $finish;
  end
"""
    )
    + "endmodule\n"
)


class WishboneTargetAdapterRtlTests(unittest.TestCase):
    def test_registered_ack_uart_configuration_pulses_stb_and_holds_cyc(self) -> None:
        _compile_and_run(self, _WB_UART_TB, [RTL / "beat_to_wishbone.sv"])

    def test_single_register_no_address_timer_configuration(self) -> None:
        _compile_and_run(self, _WB_TIMER_TB, [RTL / "beat_to_wishbone.sv"])

    def test_classic_configuration_holds_the_cycle_until_completion(self) -> None:
        _compile_and_run(self, _WB_CLASSIC_TB, [RTL / "beat_to_wishbone.sv"])


if __name__ == "__main__":
    unittest.main()
