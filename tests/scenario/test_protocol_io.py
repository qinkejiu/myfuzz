"""A local RTL reply must not block past the testcase command deadline."""

import os
import threading
import time
import unittest

from myfuzz.scenario.protocol_io import (BoundedLineReader,
                                         LocalCommandDeadlineExceeded,
                                         command_deadline, read_startup_ready)


class BoundedLineReaderTests(unittest.TestCase):
    def test_ready_wait_uses_shorter_enclosing_case_deadline(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
        try:
            started = time.monotonic()
            with command_deadline(started + 0.02):
                with self.assertRaises(LocalCommandDeadlineExceeded):
                    read_startup_ready(BoundedLineReader(), stream)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(write_fd)
            stream.close()

    def test_partial_line_times_out_without_waiting_for_newline(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
        try:
            os.write(write_fd, b"RESULT partial")
            reader = BoundedLineReader()
            started = time.monotonic()
            with command_deadline(started + 0.03):
                with self.assertRaises(LocalCommandDeadlineExceeded):
                    reader.readline(stream)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(write_fd)
            stream.close()

    def test_split_and_multiple_lines_are_buffered_per_session(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
        try:
            os.write(write_fd, b"FIRST\nSECOND ")
            reader = BoundedLineReader()

            def finish():
                time.sleep(0.01)
                os.write(write_fd, b"DONE\n")

            worker = threading.Thread(target=finish)
            worker.start()
            with command_deadline(time.monotonic() + 0.5):
                self.assertEqual("FIRST\n", reader.readline(stream))
                self.assertEqual("SECOND DONE\n", reader.readline(stream))
            worker.join()
        finally:
            os.close(write_fd)
            stream.close()

    def test_startup_ready_and_next_short_reply_share_one_read(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
        try:
            os.write(write_fd, b"READY\nOK\n")
            reader = BoundedLineReader(max_line_bytes=6)
            with command_deadline(time.monotonic() + 0.5):
                self.assertEqual("READY", read_startup_ready(reader, stream))
                self.assertEqual("OK\n", reader.readline(stream))
        finally:
            os.close(write_fd)
            stream.close()

    def test_later_buffered_line_still_obeys_line_limit(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
        try:
            os.write(write_fd, b"OK\nTOO-LONG\n")
            reader = BoundedLineReader(max_line_bytes=4)
            with command_deadline(time.monotonic() + 0.5):
                self.assertEqual("OK\n", reader.readline(stream))
                with self.assertRaisesRegex(RuntimeError, "exceeds declared bound"):
                    reader.readline(stream)
        finally:
            os.close(write_fd)
            stream.close()


if __name__ == "__main__":
    unittest.main()
