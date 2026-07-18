import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.process_monitor_v4 import run_polled_process_v4  # noqa: E402


class ProcessMonitorV4Test(unittest.TestCase):
    def test_one_child_is_polled_repeatedly_without_a_worker_thread(self):
        samples = []
        result = run_polled_process_v4(
            [sys.executable, "-c", "import time; time.sleep(0.06); print('done')"],
            cwd=ROOT, timeout_seconds=1, poll_interval_seconds=0.01,
            poll_callback=lambda: samples.append(time.monotonic()),
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "done")
        self.assertGreaterEqual(len(samples), 2)

    def test_timeout_terminates_the_only_child(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_polled_process_v4(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=ROOT, timeout_seconds=0.03, poll_interval_seconds=0.01,
                poll_callback=lambda: None,
            )
        self.assertLess(time.monotonic() - started, 1)


if __name__ == "__main__":
    unittest.main()
