"""Late stdout data must not bind to a fresh real GPIO command."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession


class OldReplyFirst:
    def __init__(self, real_stdout):
        self.real_stdout = real_stdout
        self.old_reply = "RESULT previous_execution 1 0 0 1 0 0 777\n"
        self.real_reads = 0

    def readline(self):
        if self.old_reply is not None:
            line, self.old_reply = self.old_reply, None
            return line
        self.real_reads += 1
        return self.real_stdout.readline()

    def close(self):
        self.real_stdout.close()


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealStaleGpioReplyTests(unittest.TestCase):
    def test_old_execution_reply_precedes_new_real_result(self):
        gpio = OpenTitanGpioSession()
        gpio.begin_case("old-stdout-before-new-gpio-result")
        try:
            proxy = OldReplyFirst(gpio._process.stdout)
            gpio._process.stdout = proxy
            first = gpio.step_local({"gpio_in": 0})
            self.assertEqual(0, first["irq"])
            self.assertEqual(1, gpio.local_ticks)
            self.assertEqual(1, gpio._command_sequence)
            self.assertEqual(1, proxy.real_reads)
            second = gpio.step_local({"gpio_in": 0})
            self.assertEqual(0, second["irq"])
            self.assertEqual(2, gpio.local_ticks)
            self.assertEqual(2, proxy.real_reads)
        finally:
            gpio.end_case()


if __name__ == "__main__":
    unittest.main()
