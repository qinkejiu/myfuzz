"""Step 7: the audit re-reads the generated RTL and detects real wiring errors."""
from __future__ import annotations

import unittest

from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import (
    CPU_HELD_CONSTANT,
    CPU_RESET_NET,
    render_composition,
    source_list,
)
from myfuzz.composition.soc_structure_audit import (
    FAIL,
    PASS,
    StructureAuditError,
    audit_structure,
    extract_netlist,
)

from .soc_generation_fixture import ROOT, example_plan, example_request, tools_available


def _failed_checks(result: dict) -> list[str]:
    return [item["check_id"] for item in result["findings"] if item["status"] == FAIL]


class _AuditFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not tools_available():
            raise unittest.SkipTest("verilator is not installed")
        cls.plan = example_plan()
        cls.text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.sources = [item["path"] for item in source_list(cls.plan)]

    def audit(self, text: str) -> dict:
        return audit_structure(self.plan, top_text=text, source_files=self.sources,
                               base_dir=ROOT)

    def mutate(self, *pairs: tuple[str, str]) -> str:
        text = self.text
        for old, new in pairs:
            self.assertIn(old, text, f"mutation anchor missing: {old}")
            self.assertNotEqual(old, new)
            text = text.replace(old, new)
        return text


class _BfmAuditFixture(unittest.TestCase):
    """The audit over a plan that declares the synthetic master."""

    profile = "contention"

    @classmethod
    def setUpClass(cls) -> None:
        if not tools_available():
            raise unittest.SkipTest("verilator is not installed")
        cls.plan = build_composition(example_request(), base_dir=ROOT,
                                     drive_profile=cls.profile)
        cls.text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.sources = [item["path"] for item in source_list(cls.plan)]

    def audit(self, text: str) -> dict:
        return audit_structure(self.plan, top_text=text, source_files=self.sources,
                               base_dir=ROOT)

    def mutate(self, *pairs: tuple[str, str]) -> str:
        text = self.text
        for old, new in pairs:
            self.assertIn(old, text, f"mutation anchor missing: {old}")
            self.assertNotEqual(old, new)
            text = text.replace(old, new)
        return text


class NetlistExtractionTests(_AuditFixture):
    def test_elaboration_exposes_the_real_instance_and_port_set(self) -> None:
        netlist = extract_netlist(self.text, self.sources, top_module="myfuzz_soc_top",
                                  base_dir=ROOT)
        instances = {str(item["instance"]) for item in netlist.cells}
        self.assertEqual({
            "u_cpu0", "u_cpu0_adapter_0", "u_soc_arbiter", "u_soc_router",
            "u_mem_0", "u_mem_1", "u_gpio0", "u_gpio0_adapter",
            "u_uart0", "u_uart0_adapter", "u_uart1", "u_uart1_adapter",
            "u_irq_controller",
            "u_drive_cpu0__event_i", "u_drive_gpio0__pin_mode_i",
        }, instances)
        ports = {str(item["name"]): (str(item["direction"]), int(item["width"]))
                 for item in netlist.ports}
        self.assertEqual(("input", 4), ports["cpu0__event_i"])
        self.assertEqual(("input", 1), ports["rst_ni"])
        self.assertEqual(15, len(ports))
        self.assertEqual(("output", 4), ports["cpu0__event_i__applied"])
        self.assertEqual(("output", 3), ports["gpio0__pin_mode_i__applied"])
        module = next(item["module"] for item in netlist.cells
                      if item["instance"] == "u_gpio0_adapter")
        self.assertTrue(str(module).startswith("beat_to_apb"))


class CleanAuditTests(_AuditFixture):
    def test_the_generated_soc_passes_every_structural_check(self) -> None:
        result = self.audit(self.text)
        self.assertEqual(PASS, result["summary"]["status"], result["findings"])
        self.assertEqual(0, result["summary"]["failed"])
        self.assertGreaterEqual(result["summary"]["passed"], 9)
        self.assertTrue(result["unknown"])

    def test_behaviour_over_time_is_reported_as_unknown_not_passed(self) -> None:
        result = self.audit(self.text)
        kinds = {item["check_id"] for item in result["unknown"]}
        self.assertIn("protocol_behaviour", kinds)


class FaultInjectionTests(_AuditFixture):
    """A wrong connection must be found even though the plan did not change."""

    def test_swapped_interrupt_sources_are_detected(self) -> None:
        text = self.mutate(("{uart1__irq_o, uart0__irq_o, gpio0__irq_o}",
                            "{uart0__irq_o, uart1__irq_o, gpio0__irq_o}"))
        result = self.audit(text)
        self.assertEqual(FAIL, result["summary"]["status"])
        self.assertIn("interrupt_paths", _failed_checks(result))

    def test_a_source_bound_to_a_constant_is_detected(self) -> None:
        text = self.mutate(("{uart1__irq_o, uart0__irq_o, gpio0__irq_o}",
                            "{uart1__irq_o, uart0__irq_o, 1'b0}"))
        self.assertIn("interrupt_paths", _failed_checks(self.audit(text)))

    def test_cpu_entry_tied_inactive_is_detected(self) -> None:
        text = self.mutate((".irq_external_i(irq_notify)", ".irq_external_i(1'b0)"))
        self.assertIn("interrupt_paths", _failed_checks(self.audit(text)))

    def test_controller_mmio_on_another_target_is_detected(self) -> None:
        text = self.mutate((".req_valid_i(t_req_valid[3])", ".req_valid_i(t_req_valid[2])"))
        self.assertIn("controller_mmio", _failed_checks(self.audit(text)))

    def test_swapped_peripheral_roles_are_detected(self) -> None:
        text = self.mutate((".psel(gpio0__psel)", ".psel(gpio0__pwrite)"),
                           (".pwrite(gpio0__pwrite)", ".pwrite(gpio0__psel)"))
        self.assertIn("target_role_wiring", _failed_checks(self.audit(text)))

    def test_swapped_cpu_adapter_ports_are_detected(self) -> None:
        text = self.mutate((".addr_i(cpu0__obi_addr_o)", ".addr_i(cpu0__obi_wdata_o)"),
                           (".wdata_i(cpu0__obi_wdata_o)", ".wdata_i(cpu0__obi_addr_o)"))
        self.assertIn("cpu_adapter_wiring", _failed_checks(self.audit(text)))

    def test_a_dropped_observation_port_is_detected(self) -> None:
        text = self.mutate((",\n    output logic cpu0__trap_o", ""),
                           (".trap_o(cpu0__trap_o)", ".trap_o()"))
        self.assertIn("top_ports", _failed_checks(self.audit(text)))

    def test_a_fuzz_input_connected_to_an_observation_is_detected(self) -> None:
        text = self.mutate((".event_i(cpu0__event_i__driven)",
                            ".event_i(cpu0__status_o)"),
                           (".value_o(cpu0__event_i__driven)", ".value_o()"))
        failures = _failed_checks(self.audit(text))
        self.assertIn("observation_outputs", failures)

    def test_a_changed_adapter_window_parameter_is_detected(self) -> None:
        text = self.mutate((".WINDOW_BASE(1073745920)", ".WINDOW_BASE(1073750016)"))
        self.assertIn("adapter_parameters", _failed_checks(self.audit(text)))

    def test_memory_reset_polarity_flip_is_detected(self) -> None:
        text = self.mutate((".clock(clk_i), .reset(rst_ni), .flush(1'b0),",
                            ".clock(clk_i), .reset(~rst_ni), .flush(1'b0),"))
        self.assertIn("reset_polarity", _failed_checks(self.audit(text)))

    def test_memory_parameter_limits_are_reported_as_unknown_not_passed(self) -> None:
        """A property this frontend cannot re-read is reported, never assumed."""
        result = self.audit(self.text)
        kinds = {item["check_id"] for item in result["unknown"]}
        self.assertIn("memory_parameters", kinds)


class AuditFailureTests(_AuditFixture):
    def test_a_missing_source_file_is_reported_not_ignored(self) -> None:
        with self.assertRaises(StructureAuditError) as error:
            audit_structure(self.plan, top_text=self.text,
                            source_files=(*self.sources, "rtl/does_not_exist.sv"),
                            base_dir=ROOT)
        self.assertIn("audit-source-missing", str(error.exception))

    def test_broken_rtl_is_reported_as_an_audit_failure(self) -> None:
        text = self.text.replace("module myfuzz_soc_top (", "module myfuzz_soc_top (\n  logic broken;")
        with self.assertRaises(StructureAuditError) as error:
            audit_structure(self.plan, top_text=text, source_files=self.sources, base_dir=ROOT)
        self.assertIn("audit-", str(error.exception))


class LaneOwnershipAuditTests(_AuditFixture):
    """The new checks hold on the CPU-only composition too."""

    def test_the_cpu_lane_is_owned_by_its_adapter_and_its_response_returns(self) -> None:
        result = self.audit(self.text)
        self.assertEqual(PASS, result["summary"]["status"], result["findings"])
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertIn("fabric_source_lanes", findings)
        self.assertIn("response_ownership", findings)
        self.assertIn("cpu_reset_hold", findings)
        # The CPU is not held in the cpu_execute profile, and the audit says so.
        self.assertFalse(findings["cpu_reset_hold"]["expected"]["held_in_reset"])
        self.assertEqual("rst_ni", findings["cpu_reset_hold"]["actual"]["pin"])
        # No synthetic-master checks run when no synthetic master is declared.
        self.assertNotIn("fuzz_master_reset", findings)
        self.assertNotIn("fuzz_master_parameters", findings)

    def test_a_cpu_adapter_on_the_wrong_lane_is_detected(self) -> None:
        """A one-lane composition still has a lane: a constant is not its driver."""
        text = self.mutate((".req_valid_o(src_req_valid[0])", ".req_valid_o(1'b0)"))
        self.assertIn("fabric_source_lanes", _failed_checks(self.audit(text)))

    def test_a_cpu_response_taken_from_another_net_is_detected(self) -> None:
        text = self.mutate((".rsp_valid_i(src_rsp_valid[0])",
                            ".rsp_valid_i(src_rsp_ready[0])"))
        self.assertIn("response_ownership", _failed_checks(self.audit(text)))


class SyntheticMasterAuditTests(_BfmAuditFixture):
    def test_the_synthetic_master_plan_passes_every_check(self) -> None:
        result = self.audit(self.text)
        self.assertEqual(PASS, result["summary"]["status"], result["findings"])
        findings = {item["check_id"]: item for item in result["findings"]}
        for required in ("fabric_source_lanes", "response_ownership", "fuzz_master_reset",
                         "fuzz_master_parameters", "cpu_reset_hold"):
            self.assertIn(required, findings, sorted(findings))
        self.assertEqual(PASS, findings["fuzz_master_reset"]["status"])
        self.assertEqual("~rst_ni", findings["fuzz_master_reset"]["actual"]["pin"])

    def test_a_swapped_response_lane_is_detected(self) -> None:
        text = self.mutate((".rsp_valid_i(src_rsp_valid[0])", ".rsp_valid_i(src_rsp_valid[1])"),
                           (".rsp_valid(src_rsp_valid[1])", ".rsp_valid(src_rsp_valid[0])"))
        self.assertIn("response_ownership", _failed_checks(self.audit(text)))

    def test_a_response_ready_on_the_other_lane_is_detected(self) -> None:
        text = self.mutate((".rsp_ready_o(src_rsp_ready[0])", ".rsp_ready_o(src_rsp_ready[1])"))
        self.assertIn("response_ownership", _failed_checks(self.audit(text)))

    def test_a_swapped_request_lane_is_detected(self) -> None:
        text = self.mutate((".req_valid(src_req_valid[1])", ".req_valid(src_req_valid[0])"))
        self.assertIn("fabric_source_lanes", _failed_checks(self.audit(text)))

    def test_a_flipped_synthetic_reset_is_detected(self) -> None:
        text = self.mutate((".reset(~rst_ni),", ".reset(rst_ni),"))
        failures = _failed_checks(self.audit(text))
        self.assertIn("fuzz_master_reset", failures)
        self.assertIn("reset_polarity", failures)

    def test_a_changed_projection_parameter_is_detected(self) -> None:
        text = self.mutate((".SELECTOR_INVALID(6)", ".SELECTOR_INVALID(7)"))
        self.assertIn("fuzz_master_parameters", _failed_checks(self.audit(text)))

    def test_a_missing_raw_port_is_detected(self) -> None:
        text = self.mutate((",\n    input  logic fuzz_mmio0__stim_offer", ""),
                           (".stim_offer(fuzz_mmio0__stim_offer),", ".stim_offer(1'b0),"))
        self.assertIn("top_ports", _failed_checks(self.audit(text)))


class CpuHoldAuditTests(_BfmAuditFixture):
    """bfm_isolated holds the CPU; the RTL is the evidence, not the metadata."""

    profile = "bfm_isolated"

    def test_the_held_cpu_is_verified_and_visible_in_the_rtl(self) -> None:
        result = self.audit(self.text)
        self.assertEqual(PASS, result["summary"]["status"], result["findings"])
        findings = {item["check_id"]: item for item in result["findings"]}
        self.assertEqual(PASS, findings["cpu_reset_hold"]["status"])
        self.assertTrue(findings["cpu_reset_hold"]["expected"]["held_in_reset"])
        self.assertIn(f"localparam bit {CPU_HELD_CONSTANT} = 1;", self.text)
        self.assertIn(f"wire {CPU_RESET_NET} = rst_ni & ~{CPU_HELD_CONSTANT};", self.text)

    def test_a_released_cpu_is_detected(self) -> None:
        text = self.mutate((f".rst_ni({CPU_RESET_NET}),", ".rst_ni(rst_ni),"))
        self.assertIn("cpu_reset_hold", _failed_checks(self.audit(text)))

    def test_a_deasserted_hold_constant_is_detected(self) -> None:
        text = self.mutate((f"localparam bit {CPU_HELD_CONSTANT} = 1;",
                            f"localparam bit {CPU_HELD_CONSTANT} = 0;"))
        self.assertIn("cpu_reset_hold", _failed_checks(self.audit(text)))

    def test_a_replaced_hold_expression_is_detected(self) -> None:
        text = self.mutate((f"wire {CPU_RESET_NET} = rst_ni & ~{CPU_HELD_CONSTANT};",
                            f"wire {CPU_RESET_NET} = rst_ni;"))
        self.assertIn("cpu_reset_hold", _failed_checks(self.audit(text)))


class ContentionHoldAuditTests(_BfmAuditFixture):
    """contention releases the CPU: a hold structure there is a real fault."""

    profile = "contention"

    def test_a_hold_structure_in_contention_is_detected(self) -> None:
        text = self.mutate(("  localparam integer NUM_TARGETS",
                            f"  localparam bit {CPU_HELD_CONSTANT} = 1;\n"
                            "  localparam integer NUM_TARGETS"))
        self.assertIn("cpu_reset_hold", _failed_checks(self.audit(text)))

    def test_a_cpu_reset_tied_asserted_is_detected(self) -> None:
        text = self.mutate((".rst_ni(rst_ni),\n    .status_o(cpu0__status_o),",
                            ".rst_ni(1'b0),\n    .status_o(cpu0__status_o),"))
        self.assertIn("cpu_reset_hold", _failed_checks(self.audit(text)))



if __name__ == "__main__":
    unittest.main()
