from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "memory_gate.py"
SPEC = importlib.util.spec_from_file_location("memory_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
memory_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory_gate)


class MemoryGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.lock_directory = Path(self.temporary_directory.name) / "locks"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_claim_reclaims_lock_owned_by_dead_process(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text(
            json.dumps(
                {
                    "owner": "stale-owner",
                    "memory_mib": 128,
                    "pid": 999_999_999,
                    "timestamp": "2026-07-22T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        memory_gate.claim(
            "build",
            128,
            "current-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
            pid_is_alive=lambda _pid: False,
        )

        record = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual("current-owner", record["owner"])
        self.assertEqual(os.getpid(), record["pid"])

    def test_claim_rejects_second_live_owner_after_timeout(self) -> None:
        memory_gate.claim(
            "build",
            128,
            "first-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )

        with self.assertRaisesRegex(memory_gate.LockBusyError, r"^memory gate 'build' is held by first-owner$"):
            memory_gate.claim(
                "build",
                128,
                "second-owner",
                lock_directory=self.lock_directory,
                timeout_seconds=0,
                available_memory_mib=lambda: 1024,
            )

    def test_release_does_not_remove_another_owners_lock(self) -> None:
        memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )

        self.assertFalse(memory_gate.release("build", "other-owner", lock_directory=self.lock_directory))
        self.assertTrue((self.lock_directory / "build.lock").exists())

    def test_claim_times_out_when_available_memory_is_insufficient(self) -> None:
        with self.assertRaisesRegex(memory_gate.MemoryUnavailableError, r"^memory gate 'build' requires 512 MiB, only 256 MiB available$"):
            memory_gate.claim(
                "build",
                512,
                "owner",
                lock_directory=self.lock_directory,
                timeout_seconds=0,
                available_memory_mib=lambda: 256,
            )


if __name__ == "__main__":
    unittest.main()
