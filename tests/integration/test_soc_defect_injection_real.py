"""Known SPI RTL fault follows the component in SoC and isolated APB runs."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile, load_composition_request
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_boot_program import ProgramRequest, build_boot_program
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_offline_defect_confirmation import (
    IsolationFixture, confirm_component_offline,
    record_offline_confirmation, validate_offline_confirmation,
)
from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE, build_evidence_package, classify_boundary,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent, PeerStimulusEvent, RuntimeSample, build_profile_runtime, run_sample,
)

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_dependency_replay import applied_legality


NORM = ("For CPOL=0, CPHA=0, an accepted CPU TXDATA byte is transmitted MSB-first "
        "on the eight selected leading SCK edges.")
SPI_SOURCE = ROOT / "examples/soc_generation/rtl/novaspi.sv"
ISOLATION_TB = ROOT / "tests/fixtures/rtl/novaspi_isolation_tb.sv"


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _wire_check(result) -> dict:
    return next(item for item in result.peer_oracle["checks"]
                if item["check_id"] == "spi-transfer-wire")


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for known SPI RTL defect injection")
class SpiDefectInjectionRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        verilator = shutil.which("verilator")
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if not verilator or not iverilog or not vvp:
            raise AssertionError("Verilator, Icarus Verilog and vvp are required")
        cls._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-spi-defect-")
        root = Path(cls._temporary.name)
        original = SPI_SOURCE.read_text(encoding="utf-8")
        anchor = "tx_data_q <= pwdata_i[BITS-1:0];"
        if original.count(anchor) != 1:
            raise AssertionError("SPI TXDATA assignment is no longer unique")
        mutant = original.replace(anchor,
                                  "tx_data_q <= pwdata_i[BITS-1:0] ^ "
                                  "{{(BITS-1){1'b0}}, 1'b1};", 1)
        mutant_path = root / "novaspi-mutant.sv"
        mutant_path.write_text(mutant, encoding="utf-8")
        cls.source_text = {"baseline": original, "mutant": mutant}
        document = json.loads((ROOT / "examples/soc_generation/request-ibex.json")
                              .read_text(encoding="utf-8"))
        document["request_id"] = "ibex-spi-component-defect-attribution"
        document["peripherals"] = [
            {"instance_id": "spi0",
             "profile": "examples/soc_generation/profiles/novaspi.json",
             "parameters": {"BITS": 8, "CPOL": 0, "CPHA": 0,
                            "SCK_HALF_DIV": 4, "CS_SETUP": 2, "CS_HOLD": 2}},
            {"instance_id": "gpio0",
             "profile": "examples/soc_generation/profiles/novagpio.json",
             "parameters": {}},
        ]
        document["peer_models"] = [{
            "instance_id": "spi0", "endpoint_id": "spi.pins", "attach": True,
            "parameters": {"BITS": 8, "CPOL": 0, "CPHA": 0, "CS_ACTIVE_LOW": 1}}]
        profiles = {}
        for relative in ("configs/cpus/ibex/component_profile.json",
                         "examples/soc_generation/profiles/novaspi.json",
                         "examples/soc_generation/profiles/novagpio.json"):
            profile = load_component_profile(ROOT / relative)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        cls.plan = build_composition(load_composition_request(document, profiles=profiles),
                                     base_dir=ROOT)
        cls.program = build_boot_program(cls.plan,
                                         request=ProgramRequest(exercise_all_sources=True))
        image = root / "boot.hex"
        image.write_text("".join(f"{byte:02x}\n" for byte in cls.program.image),
                         encoding="utf-8")
        files = render_composition(cls.plan)
        source_records = source_list(cls.plan)
        cls.include_roots = [item["path"] for item in source_records
                             if item["role"] == "include_root"]
        sources = [item["path"] for item in source_records if item["role"] != "include_root"]
        flags = [f"-I{ROOT / item['path']}" for item in source_records
                 if item["role"] == "include_root"]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        wrapper = root / "verilator-with-profile-flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" %
                           (verilator, " ".join(flags)), encoding="utf-8")
        wrapper.chmod(0o755)
        cls.verilator_wrapper = wrapper
        cls.builds = {}
        for name in ("baseline", "mutant"):
            closure = [mutant_path.as_posix() if item.endswith("/novaspi.sv") or
                       item == "examples/soc_generation/rtl/novaspi.sv" else item
                       for item in sources] if name == "mutant" else sources
            cls.builds[name] = build_profile_runtime(
                cls.plan, output_dir=root / name, base_dir=ROOT,
                top_text=files["myfuzz_soc_top.sv"], sources=closure,
                boot_image=image, verilator=wrapper.as_posix(), timeout_seconds=1800,
                spi_wire_contracts={"spi0": {
                    "txdata_address": 0x40001008,
                    "basis": "independent fixture SPI TXDATA register and timing norm"}})
        trigger = cls.program.document["trigger"]
        cls.sample = RuntimeSample(
            request_id=22, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]),
            peer_events=tuple(PeerStimulusEvent(slot=int(item["slot"]),
                                                cycle=int(item["cycle"]),
                                                payload=int(item["payload"]))
                              for item in trigger["peer_events"]))
        cls.results = {name: run_sample(build, cls.sample, timeout_seconds=1800)
                       for name, build in cls.builds.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def test_component_fault_follows_the_source_and_isolates(self) -> None:
        self.assertEqual("pass", _wire_check(self.results["baseline"])["status"])
        self.assertEqual("mismatch", _wire_check(self.results["mutant"])["status"])

    def test_mutant_evidence_replays_and_confirms_component(self) -> None:
        result = self.results["mutant"]
        self.assertEqual("OK", result.status)
        wire = _wire_check(result)
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        build = self.builds["mutant"]
        criterion = {"criterion_id": "spi-mosi-byte",
                     "specification_text": NORM,
                     "specification_hash": _sha(NORM.encode()),
                     "independent_of_profile": True,
                     "expected": wire["expected"]["mosi"],
                     "observed": wire["observed"]["mosi"]}
        package = build_evidence_package(
            self.plan, build, policy, [result], samples=[self.sample],
            kind="injected_spi_component_fault",
            criteria=[{"criterion_id": "spi-mosi-byte", "statement": NORM,
                       "basis": "standalone APB isolation plus SPI wire contract",
                       "independent": True}],
            legality=applied_legality(build, self.sample, result),
            anomaly={"present": True, "criterion": "spi-mosi-byte",
                     "basis": "independent SPI line-level reference",
                     "basis_independent": True, "reproducible": True,
                     "expected": criterion["expected"],
                     "observed": criterion["observed"]})
        self.assertIn(_sha(self.source_text["mutant"].encode()),
                      package.identity["runtime"]["source_hashes"].values())
        self.assertEqual(COMPONENT_CANDIDATE, classify_boundary(package)[0])
        baseline = self.builds["baseline"]
        confirmation = confirm_component_offline(
            package, plan=self.plan, baseline=baseline, mutant=build,
            fixture=IsolationFixture(testbench=ISOLATION_TB,
                                     top_module="novaspi_isolation_tb",
                                     marker="MYFUZZ_ISOLATED_SPI", source_name="novaspi"),
            criterion=criterion, base_dir=ROOT, include_roots=self.include_roots,
            timeout_seconds=1800, verilator=self.verilator_wrapper.as_posix())
        self.assertEqual("component_confirmed", confirmation.status, confirmation.reason)
        self.assertEqual("offline-isolation-confirmed", confirmation.reason)
        saved = record_offline_confirmation(package, confirmation)
        report = saved.attribution["offline_confirmation"]
        self.assertEqual("component_confirmed", report["status"])
        for key in ("baseline_build_hashes", "mutant_build_hashes",
                    "baseline_structure_audit", "mutant_structure_audit",
                    "mutant_replay", "isolation", "fixture_hash", "criterion"):
            self.assertEqual(confirmation.evidence[key], report["evidence"][key])
        self.assertEqual((COMPONENT_CANDIDATE, "record-integrity-only"),
                         validate_offline_confirmation(saved))


if __name__ == "__main__":
    unittest.main()
