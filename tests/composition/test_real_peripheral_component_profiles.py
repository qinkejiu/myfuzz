"""Original PULP GPIO in the generic profile path, without a target wrapper."""
import json
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import load_component_profile, load_composition_request
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import audit_structure

ROOT = Path(__file__).resolve().parents[2]
GPIO = "configs/peripherals/pulp_gpio/component_profile.json"
CPU = "examples/soc_generation/profiles/novacore.json"
REQUEST = "examples/soc_generation/request-pulp-gpio.json"


class RealPeripheralProfileTests(unittest.TestCase):
    def test_nova_reset_profiles_match_actual_async_rtl(self):
        for name in ("novacore", "novauart", "novagpio"):
            profile = load_component_profile(ROOT / f"examples/soc_generation/profiles/{name}.json")
            rtl = (ROOT / f"examples/soc_generation/rtl/{name}.sv").read_text()
            self.assertIn("posedge clk_i or negedge rst_ni", rtl)
            self.assertFalse(profile.resets[0].synchronous, name)

    def inputs(self):
        self.assertTrue((ROOT / GPIO).is_file(), "missing original PULP GPIO profile")
        self.assertTrue((ROOT / REQUEST).is_file(), "missing first-time CPU + real GPIO request")
        return {name: load_component_profile(ROOT / name) for name in (CPU, GPIO)}

    def test_original_gpio_elaborates_renders_and_audits(self):
        profiles = self.inputs()
        request = load_composition_request(ROOT / REQUEST, profiles=profiles)
        plan = build_composition(request, base_dir=ROOT)
        gpio = next(item for item in plan.instances if item.instance_id == "gpio0")
        self.assertEqual("apb_gpio", gpio.top_module)
        self.assertEqual({"HCLK", "HRESETn", "dft_cg_enable_i", "PADDR", "PWDATA",
                          "PWRITE", "PSEL", "PENABLE", "PRDATA", "PREADY", "PSLVERR",
                          "gpio_in", "gpio_in_sync", "gpio_out", "gpio_dir", "gpio_padcfg",
                          "interrupt"}, {entry.port for entry in gpio.dispositions})
        dispositions = {entry.port: entry.disposition for entry in gpio.dispositions}
        self.assertEqual("observe", dispositions["interrupt"])
        self.assertEqual("constant", dispositions["dft_cg_enable_i"])
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        paths = [item["path"] for item in source_list(plan)]
        self.assertIn("third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv", paths)
        self.assertIn("src/myfuzz/protocols/rtl/beat_to_apb.sv", paths)
        self.assertFalse(any("soc_pulp" in path or "real_targets" in path for path in paths))
        self.assertIn(".HAS_PSTRB(0)", text)
        self.assertIn(".pstrb()", text)
        result = audit_structure(plan, top_text=text, source_files=paths, base_dir=ROOT)
        self.assertEqual("pass", result["summary"]["status"], result)
        parameter_check = next(item for item in result["findings"]
                               if item["check_id"] == "adapter_parameters")
        self.assertEqual("pass", parameter_check["status"])
        self.assertIn(".WINDOW_BASE(1073741824)", text)
        altered = text.replace(".WINDOW_BASE(1073741824)", ".WINDOW_BASE(1073750016)")
        bad = audit_structure(plan, top_text=altered, source_files=paths, base_dir=ROOT)
        self.assertIn("adapter_parameters", [item["check_id"] for item in bad["findings"]
                                             if item["status"] == "fail"])
        wrong_strobe = text.replace(".HAS_PSTRB(0)", ".HAS_PSTRB(1)")
        bad = audit_structure(plan, top_text=wrong_strobe, source_files=paths, base_dir=ROOT)
        self.assertIn("adapter_parameters", [item["check_id"] for item in bad["findings"]
                                             if item["status"] == "fail"])

    def test_apb4_strobe_cannot_be_omitted_like_apb3(self):
        profiles = self.inputs()
        document = json.loads((ROOT / GPIO).read_text())
        document["endpoints"][0]["protocol"] = ["apb", "4"]
        profiles[GPIO] = load_component_profile(document)
        with self.assertRaisesRegex(ValueError, "pstrb"):
            build_composition(load_composition_request(ROOT / REQUEST, profiles=profiles), base_dir=ROOT)

    def test_register_evidence_distinguishes_latched_status_from_pulse_irq(self):
        self.inputs()
        document = json.loads((ROOT / GPIO).read_text())
        status = next(item for item in document["address"]["registers"] if item["offset"] == 0x24)
        self.assertEqual("read_clears", status["side_effect"])
        self.assertFalse(document.get("interrupts"))
        self.assertIn("pulse", " ".join(document["evidence"]["unknown"]).lower())

    def test_omitted_real_port_is_rejected(self):
        profiles = self.inputs()
        document = json.loads((ROOT / GPIO).read_text())
        document["port_actions"] = [item for item in document["port_actions"]
                                    if item["port"] != "dft_cg_enable_i"]
        profiles[GPIO] = load_component_profile(document)
        with self.assertRaisesRegex(ValueError, "dft_cg_enable_i"):
            build_composition(load_composition_request(ROOT / REQUEST, profiles=profiles), base_dir=ROOT)

    def test_pulse_irq_cannot_be_connected_to_level_only_controller(self):
        profiles = self.inputs()
        document = json.loads((ROOT / GPIO).read_text())
        document["port_actions"] = [item for item in document["port_actions"]
                                    if item["port"] != "interrupt"]
        document["endpoints"].append({"endpoint_id": "gpio.irq", "function": "interrupt_source",
                                      "fields": [{"role": "irq", "aliases": ["interrupt"]}]})
        document["interrupts"] = [{"endpoint_id": "gpio.irq", "role": "irq", "trigger": "edge",
                                   "polarity": "active_high", "clock_domain": "core",
                                   "hold": "No level hold: interrupt equals combinational s_rise_int.",
                                   "clear": "Status is read-clear, independently of the output pulse."}]
        with self.assertRaisesRegex(ValueError, "unsupported-interrupt-trigger"):
            profiles[GPIO] = load_component_profile(document)
            build_composition(load_composition_request(ROOT / REQUEST, profiles=profiles), base_dir=ROOT)


if __name__ == "__main__":
    unittest.main()
