"""Composition contract for the real Ibex, PULP GPIO and PULP SPI profiles."""

from __future__ import annotations

import json
import unittest

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import source_list
from tests.composition.soc_generation_fixture import ROOT


REQUEST = ROOT / "examples/soc_generation/request-ibex-pulp-gpio-spi.json"


def load_dual_request():
    document = json.loads(REQUEST.read_text(encoding="utf-8"))
    profiles = {}
    profile_paths = [document["cpu"]["profile"]] + [
        item["profile"] for item in document["peripherals"]
    ]
    for profile_path in profile_paths:
        profile = load_component_profile(ROOT / profile_path)
        profiles[profile_path] = profile
        profiles.setdefault(profile.component_id, profile)
    return load_composition_request(document, profiles=profiles)


class IbexPulpDualProfileTests(unittest.TestCase):
    def test_request_composes_ibex_and_both_pulp_targets(self):
        request = load_dual_request()
        plan = build_composition(request, base_dir=ROOT, drive_profile="cpu_execute")

        instances = {item.instance_id: item for item in plan.instances}
        self.assertEqual({"cpu0", "gpio0", "spi0"}, set(instances))
        self.assertEqual("ibex", instances["cpu0"].component_id)
        self.assertEqual("cpu", instances["cpu0"].kind)
        self.assertEqual("pulp_gpio", instances["gpio0"].component_id)
        self.assertEqual("pulp_spi", instances["spi0"].component_id)
        for instance_id in ("gpio0", "spi0"):
            instance = instances[instance_id]
            self.assertEqual("peripheral", instance.kind)
            self.assertEqual(["apb", "3"],
                             list(instance.profile.endpoints[0].protocol))

        windows = {item["target_id"]: item
                   for item in plan.plan["address_map"]["windows"]}
        gpio = windows["gpio0_win"]
        spi = windows["spi0_win"]
        for window in (gpio, spi):
            self.assertEqual(4096, window["size"])
            self.assertEqual(0, window["base"] % 4096)
        self.assertTrue(gpio["base"] + gpio["size"] <= spi["base"]
                        or spi["base"] + spi["size"] <= gpio["base"])
        self.assertEqual({"cpu_only", "mmio_only", "mixed"},
                         set(request.test_modes))
        self.assertEqual([], plan.spec["interrupt_routes"])
        self.assertEqual([("spi0", "pulp_spi")], sorted(
            (peer.instance_id, peer.peer_id) for peer in plan.peers))
        source_paths = [item["path"] for item in source_list(plan)
                        if item["role"] == "component_source"]
        secded = source_paths.index(
            "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv")
        lockstep = source_paths.index(
            "third_party/rfuzz/upstream/ibex/rtl/ibex_lockstep.sv")
        self.assertLess(secded, lockstep,
                        "the pinned Verilator requires imported packages before modules")
        self.assertEqual(plan.plan_hash,
                         build_composition(request, base_dir=ROOT,
                                           drive_profile="cpu_execute").plan_hash)

    def test_bfm_address_strategy_is_configurable_and_part_of_identity(self):
        request = load_dual_request()
        biased = build_composition(
            request, base_dir=ROOT, drive_profile="bfm_isolated",
            address_strategy="biased")
        raw = build_composition(
            request, base_dir=ROOT, drive_profile="bfm_isolated",
            address_strategy="bias_off")

        self.assertEqual("biased", biased.stimulus["address_strategy"]["selected"])
        self.assertEqual(1, biased.stimulus["rtl_projection"]["parameters"]["ADDRESS_STRATEGY"])
        self.assertEqual("bias_off", raw.stimulus["address_strategy"]["selected"])
        self.assertEqual(0, raw.stimulus["rtl_projection"]["parameters"]["ADDRESS_STRATEGY"])
        self.assertNotEqual(biased.plan_hash, raw.plan_hash)


if __name__ == "__main__":
    unittest.main()
