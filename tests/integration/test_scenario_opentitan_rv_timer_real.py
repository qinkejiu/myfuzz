"""Native OpenTitan RV Timer closure and persistent IRQ behavior."""
import hashlib
import json
from pathlib import Path
import unittest

from myfuzz.scenario.rv_timer_session import OpenTitanRvTimerSession

ROOT = Path(__file__).resolve().parents[2]


class RvTimerRealTests(unittest.TestCase):
    def test_source_closure_pinned(self):
        profile = json.loads((ROOT / "configs/peripherals/opentitan_rv_timer/component_profile.json").read_text())
        closure = json.loads((ROOT / "configs/soc/closures/opentitan_rv_timer.json").read_text())
        lock = json.loads((ROOT / "configs/soc/sources.lock.json").read_text())
        files = profile["source"]["files"]
        self.assertEqual(len(files), len(set(files)))
        self.assertEqual(files, closure["source_files"])
        self.assertIn("hw/ip/rv_timer/rtl/rv_timer.sv", files)
        self.assertIn("hw/ip/rv_timer/rtl/rv_timer_reg_top.sv", files)
        self.assertIn("hw/ip/rv_timer/rtl/timer_core.sv", files)
        entry = next(c for c in lock["components"] if c["id"] == "opentitan_rv_timer")
        self.assertEqual(files, entry["source"]["files"])
        pinned = {(x["root"], x["path"]): x["sha256"] for x in closure["closure_files"]}
        self.assertEqual(0, closure["lint"]["errors"])
        self.assertEqual(0, closure["lint"]["warnings"])
        self.assertEqual(0, closure["lint"]["exit_code"])
        self.assertFalse(closure["boundary"]["generated_soc_fabric"])
        recorded = {str(ROOT / x["root"] / x["path"]): x["sha256"]
                    for x in closure["closure_files"]}
        recorded.update({str(ROOT / x["path"]): x["sha256"]
                         for x in closure["local_read_set"]})
        self.assertEqual(set(recorded), {str(ROOT / x) for x in closure["read_set"]})
        for path, digest in recorded.items():
            self.assertEqual(digest, hashlib.sha256(Path(path).read_bytes()).hexdigest())
        for relative in files:
            path = ROOT / profile["source"]["root"] / relative
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, pinned[(profile["source"]["root"], relative)])

    def test_real_irq_clear_and_compare_update_twice_without_reset(self):
        session = OpenTitanRvTimerSession()
        session.begin_case("two-expiries")
        try:
            self.assertEqual(0, session.step_local({})["irq"])
            self.assertRaises(ValueError, session.step_local, {"irq": 1})
            with self.assertRaises(RuntimeError):
                session.write_register(0x10c, 0x10000, be=0b0100)
            session.write_register(0x10c, 0x10000, be=0b0111)
            self.assertEqual(0x10000, session.read_register(0x10c))
            session.write_register(0x118, 40)
            session.write_register(0x11c, 0)
            session.write_register(0x100, 1)
            session.write_register(0x4, 1)
            first = None
            for _ in range(100):
                observation = session.step_local({})
                if observation["irq"]:
                    first = session.local_ticks
                    break
            self.assertIsNotNone(first)
            self.assertEqual(1, session.read_register(0x104) & 1)
            now = session.read_register(0x110)
            session.write_register(0x118, now + 40)
            self.assertEqual(0, session.read_register(0x104) & 1)
            self.assertEqual(0, session.step_local({})["irq"])
            second = None
            for _ in range(100):
                observation = session.step_local({})
                if observation["irq"]:
                    second = session.local_ticks
                    break
            self.assertIsNotNone(second)
            self.assertGreater(second, first)
            session.write_register(0x4, 0)
            session.write_register(0x104, 1)
            self.assertEqual(0, session.step_local({})["irq"])
        finally:
            session.end_case()


if __name__ == "__main__":
    unittest.main()
