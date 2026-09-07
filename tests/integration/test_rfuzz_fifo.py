import os
from pathlib import Path
import struct
import tempfile
import unittest
try:
    from myfuzz.integration.rfuzz_fifo import FifoEndpoint
except ImportError:
    FifoEndpoint = None


class FifoTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(FifoEndpoint, "private bounded FIFO endpoint missing")

    def test_fragmented_tokens_and_atomic_reply_and_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            keep = base / "other-server"
            keep.mkdir()
            with FifoEndpoint(base) as server:
                directory = server.directory
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                tx = os.open(directory / "tx.fifo", os.O_RDONLY | os.O_NONBLOCK)
                rx = os.open(directory / "rx.fifo", os.O_WRONLY | os.O_NONBLOCK)
                try:
                    self.assertIsNone(server.receive(timeout=0))
                    os.write(rx, struct.pack("<I",12))
                    self.assertIsNone(server.receive(timeout=0))
                    os.write(rx,struct.pack("<III",34,56,78))
                    self.assertEqual(server.receive(timeout=.1),(12,34))
                    self.assertEqual(server.receive(timeout=.1),(56,78))
                    server.reply((34,12), timeout=.1)
                    self.assertEqual(os.read(tx,8),struct.pack("<II",34,12))
                finally:
                    os.close(tx)
                    os.close(rx)
            self.assertFalse(directory.exists())
            self.assertTrue(keep.is_dir())

    def test_symlink_base_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            link=Path(tmp)/"link"
            link.symlink_to(Path(tmp),target_is_directory=True)
            with self.assertRaises(ValueError):
                FifoEndpoint(link)

    def test_unbounded_deadlines_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, FifoEndpoint(Path(tmp)) as server:
            for timeout in (None, float("nan"), float("inf"), -1, 61, True, "1"):
                with self.subTest(timeout=timeout):
                    with self.assertRaises(ValueError):
                        server.receive(timeout=timeout)
                    with self.assertRaises(ValueError):
                        server.reply((1,2),timeout=timeout)
