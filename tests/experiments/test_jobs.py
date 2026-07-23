from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.experiments import Job, JobKind, claim_job, release_job, run_job
from myfuzz.experiments import jobs as jobs_module


class JobGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.lock_directory = Path(self.temporary_directory.name) / "locks"
        self.previous_lock_directory = os.environ.get("MYFUZZ_MEMORY_GATE_DIR")
        os.environ["MYFUZZ_MEMORY_GATE_DIR"] = str(self.lock_directory)
        self.job = Job(
            job_id="opaque-job",
            kind=JobKind.BUILD,
            gate_name="build",
            owner="job-opaque-owner",
            requested_mib=1,
            seed=17,
            candidate_hash="sha256:abc",
            build_cache_key="cache",
            worker_limit=1,
        )

    def tearDown(self) -> None:
        if self.previous_lock_directory is None:
            os.environ.pop("MYFUZZ_MEMORY_GATE_DIR", None)
        else:
            os.environ["MYFUZZ_MEMORY_GATE_DIR"] = self.previous_lock_directory
        self.temporary_directory.cleanup()

    def test_claim_records_owner_memory_pid_seed_and_candidate_hash(self) -> None:
        claim = claim_job(self.job, timeout_seconds=0)
        record = json.loads((self.lock_directory / "build.lock").read_text(encoding="utf-8"))

        self.assertEqual(self.job.owner, claim.owner)
        self.assertEqual(self.job.requested_mib, claim.requested_mib)
        self.assertGreater(claim.pid, 0)
        self.assertEqual(self.job.seed, claim.seed)
        self.assertEqual(self.job.candidate_hash, claim.candidate_hash)
        self.assertEqual(self.job.seed, record["seed"])
        self.assertEqual(self.job.candidate_hash, record["candidate_hash"])
        self.assertTrue(release_job(self.job))

    def test_claim_releases_gate_when_its_persisted_record_is_invalid(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        release_calls: list[tuple[str, str]] = []

        class CorruptRecordGate:
            class GateError(RuntimeError):
                pass

            @staticmethod
            def claim(
                _name: str,
                _memory_mib: int,
                _owner: str,
                *,
                timeout_seconds: float,
                record_fields: dict[str, object],
            ) -> Path:
                self.assertEqual({"seed": self.job.seed, "candidate_hash": self.job.candidate_hash}, record_fields)
                lock_path.parent.mkdir()
                lock_path.write_text("not-json", encoding="utf-8")
                return lock_path

            @staticmethod
            def release(name: str, owner: str, **_kwargs: object) -> bool:
                release_calls.append((name, owner))
                lock_path.unlink()
                return True

        with patch.object(jobs_module, "_memory_gate", return_value=CorruptRecordGate):
            with self.assertRaisesRegex(RuntimeError, "memory gate did not persist a readable claim record"):
                claim_job(self.job, timeout_seconds=0)

        self.assertEqual([("build", self.job.owner)], release_calls)
        self.assertFalse(lock_path.exists())

    def test_claim_uses_gate_stale_recovery_and_build_serialization(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text(
            json.dumps({"owner": "stale-owner", "memory_mib": 1, "pid": 999_999_999, "timestamp": "2026-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )

        claim_job(self.job, timeout_seconds=0)
        self.assertEqual(self.job.owner, json.loads(lock_path.read_text(encoding="utf-8"))["owner"])
        with self.assertRaisesRegex(RuntimeError, "memory gate 'build' is held by"):
            claim_job(
                Job(
                    job_id="second",
                    kind=JobKind.BUILD,
                    gate_name="build",
                    owner="job-second-owner",
                    requested_mib=1,
                    seed=19,
                    candidate_hash="sha256:def",
                    build_cache_key="other-cache",
                    worker_limit=1,
                ),
                timeout_seconds=0,
            )
        self.assertTrue(release_job(self.job))

    def test_run_job_releases_claim_when_runner_fails(self) -> None:
        def fail(_job: Job) -> None:
            raise RuntimeError("runner failed")

        with self.assertRaisesRegex(RuntimeError, "runner failed"):
            run_job(self.job, fail, timeout_seconds=0)

        self.assertFalse((self.lock_directory / "build.lock").exists())


if __name__ == "__main__":
    unittest.main()
