import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.master_mutex_v4 import MasterMutexV4, emit_master_mutex_v4_rtl  # noqa: E402


class MasterMutexTest(unittest.TestCase):
    def test_selection_is_locked_until_infrastructure_reset(self):
        mutex = MasterMutexV4()
        self.assertTrue(mutex.begin_testcase(trace_selected=True).trace_drive)
        with self.assertRaisesRegex(Exception, "only at infrastructure reset"):
            mutex.begin_testcase(trace_selected=False)
        self.assertFalse(mutex.infrastructure_reset().locked)
        self.assertTrue(mutex.begin_testcase(trace_selected=False).cpu_drive)

    def test_rtl_is_synthesizable_shape(self):
        self.assertIn("always_ff", emit_master_mutex_v4_rtl())


if __name__ == "__main__":
    unittest.main()
