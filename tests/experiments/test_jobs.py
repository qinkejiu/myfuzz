from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.experiments import Job, JobClaim, JobKind, claim_job, release_job, run_job
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

    def _record_payload(self, *, token: str = "a" * 32) -> bytes:
        return (
            json.dumps(
                {
                    "owner": self.job.owner,
                    "memory_mib": self.job.requested_mib,
                    "pid": os.getpid(),
                    "timestamp": "2026-07-24T00:00:00+00:00",
                    "token": token,
                    "seed": self.job.seed,
                    "candidate_hash": self.job.candidate_hash,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")

    def _lease_for_path(self, path: Path, *, record_payload: bytes | None = None) -> object:
        metadata = path.lstat()
        return SimpleNamespace(
            path=path,
            owner=self.job.owner,
            token="a" * 32,
            pid=os.getpid(),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            record_payload=self._record_payload() if record_payload is None else record_payload,
        )

    @staticmethod
    def _gate_returning(lease: object) -> type:
        class SnapshotGate:
            class GateError(RuntimeError):
                pass

            @staticmethod
            def claim(*_args: object, **_kwargs: object) -> object:
                return lease

        return SnapshotGate

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
        self.assertEqual(claim.lease.token, record["token"])
        self.assertTrue(release_job(self.job, claim))

    def test_invalid_lease_record_does_not_operator_delete_malformed_successor(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        release_calls: list[tuple[str, str, str, Path, bool]] = []

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
            ) -> object:
                self.assertEqual({"seed": self.job.seed, "candidate_hash": self.job.candidate_hash}, record_fields)
                lock_path.parent.mkdir()
                lock_path.write_text("predecessor", encoding="utf-8")
                metadata = lock_path.stat()
                lease = SimpleNamespace(
                    path=lock_path,
                    owner=_owner,
                    token="a" * 32,
                    pid=os.getpid(),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    record_payload=b"not-json",
                )
                lock_path.unlink()
                lock_path.write_text("malformed-successor", encoding="utf-8")
                return lease

            @staticmethod
            def release(
                name: str,
                owner: str,
                *,
                token: str,
                lock_directory: Path,
                cleanup_unreadable: bool = False,
            ) -> bool:
                release_calls.append((name, owner, token, lock_directory, cleanup_unreadable))
                if cleanup_unreadable:
                    lock_path.unlink()
                    return True
                return False

        with patch.object(jobs_module, "_memory_gate", return_value=CorruptRecordGate):
            with self.assertRaisesRegex(RuntimeError, "memory gate did not persist a readable claim record"):
                claim_job(self.job, timeout_seconds=0)

        self.assertEqual(
            [("build", self.job.owner, "a" * 32, self.lock_directory, False)],
            release_calls,
        )
        self.assertEqual(b"malformed-successor", lock_path.read_bytes())

    def test_claim_does_not_open_fifo_replacement(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        lock_path.parent.mkdir()
        lock_path.write_bytes(self._record_payload())
        lease = self._lease_for_path(lock_path)
        lock_path.unlink()
        os.mkfifo(lock_path)
        gate = self._gate_returning(lease)

        with (
            patch.object(jobs_module, "_memory_gate", return_value=gate),
            patch.object(Path, "read_text", side_effect=AssertionError("scheduler reopened lease path")) as read_text,
        ):
            claim = claim_job(self.job, timeout_seconds=0)

        read_text.assert_not_called()
        self.assertEqual(self.job.seed, claim.seed)
        self.assertTrue(lock_path.exists())

    def test_claim_does_not_follow_symlink_replacement(self) -> None:
        self.lock_directory.mkdir()
        target = Path(self.temporary_directory.name) / "external-record"
        target.write_text("external-successor", encoding="utf-8")
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_bytes(self._record_payload())
        lease = self._lease_for_path(lock_path)
        lock_path.unlink()
        lock_path.symlink_to(target)
        gate = self._gate_returning(lease)

        with (
            patch.object(jobs_module, "_memory_gate", return_value=gate),
            patch.object(Path, "read_text", side_effect=AssertionError("scheduler reopened lease path")) as read_text,
        ):
            claim = claim_job(self.job, timeout_seconds=0)

        read_text.assert_not_called()
        self.assertEqual(self.job.candidate_hash, claim.candidate_hash)
        self.assertTrue(lock_path.is_symlink())
        self.assertEqual(b"external-successor", target.read_bytes())

    def test_claim_does_not_read_oversized_replacement(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        lock_path.parent.mkdir()
        lock_path.write_bytes(self._record_payload())
        lease = self._lease_for_path(lock_path)
        lock_path.unlink()
        lock_path.write_bytes(b"x" * (64 * 1024 + 1))
        gate = self._gate_returning(lease)

        with (
            patch.object(jobs_module, "_memory_gate", return_value=gate),
            patch.object(Path, "read_text", side_effect=AssertionError("scheduler reopened lease path")) as read_text,
        ):
            claim = claim_job(self.job, timeout_seconds=0)

        read_text.assert_not_called()
        self.assertEqual(self.job.owner, claim.owner)
        self.assertEqual(64 * 1024 + 1, lock_path.stat().st_size)

    def test_claim_rejects_oversized_lease_record_with_exact_release_only(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        lock_path.parent.mkdir()
        lock_path.write_bytes(self._record_payload())
        lease = self._lease_for_path(lock_path, record_payload=b"x" * (64 * 1024 + 1))
        release_calls: list[bool] = []

        class OversizedRecordGate(self._gate_returning(lease)):
            @staticmethod
            def release(
                _name: str,
                _owner: str,
                *,
                token: str,
                lock_directory: Path,
                cleanup_unreadable: bool = False,
            ) -> bool:
                self.assertEqual("a" * 32, token)
                self.assertEqual(self.lock_directory, lock_directory)
                release_calls.append(cleanup_unreadable)
                return False

        with patch.object(jobs_module, "_memory_gate", return_value=OversizedRecordGate):
            with self.assertRaisesRegex(RuntimeError, "memory gate did not persist a readable claim record"):
                claim_job(self.job, timeout_seconds=0)

        self.assertEqual([False], release_calls)
        self.assertEqual(self._record_payload(), lock_path.read_bytes())

    def test_claim_uses_gate_stale_recovery_and_build_serialization(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text(
            json.dumps({"owner": "stale-owner", "memory_mib": 1, "pid": 999_999_999, "timestamp": "2026-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )

        claim = claim_job(self.job, timeout_seconds=0)
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
        self.assertTrue(release_job(self.job, claim))

    def test_delayed_release_cannot_remove_same_owner_successor(self) -> None:
        first_claim = claim_job(self.job, timeout_seconds=0)
        self.assertTrue(release_job(self.job, first_claim))
        successor_claim = claim_job(self.job, timeout_seconds=0)

        try:
            self.assertFalse(release_job(self.job, first_claim))
            record = json.loads(successor_claim.lease.path.read_text(encoding="utf-8"))
            self.assertEqual(successor_claim.lease.token, record["token"])
        finally:
            self.assertTrue(release_job(self.job, successor_claim))

    def test_run_job_passes_exact_claim_to_release(self) -> None:
        lease = SimpleNamespace(
            path=self.lock_directory / "build.lock",
            owner=self.job.owner,
            token="b" * 32,
            pid=os.getpid(),
            device=1,
            inode=2,
        )
        claim = JobClaim(
            job_id=self.job.job_id,
            gate_name=self.job.gate_name,
            owner=self.job.owner,
            requested_mib=self.job.requested_mib,
            pid=os.getpid(),
            seed=self.job.seed,
            candidate_hash=self.job.candidate_hash,
            lease=lease,
        )

        with (
            patch.object(jobs_module, "claim_job", return_value=claim) as claim_call,
            patch.object(jobs_module, "release_job", return_value=True) as release_call,
        ):
            result = run_job(self.job, lambda job: job.job_id, timeout_seconds=0)

        self.assertEqual(self.job.job_id, result)
        claim_call.assert_called_once_with(self.job, timeout_seconds=0)
        release_call.assert_called_once_with(self.job, claim)

    def test_run_job_releases_claim_when_runner_fails(self) -> None:
        def fail(_job: Job) -> None:
            raise RuntimeError("runner failed")

        with self.assertRaisesRegex(RuntimeError, "runner failed"):
            run_job(self.job, fail, timeout_seconds=0)

        self.assertFalse((self.lock_directory / "build.lock").exists())


if __name__ == "__main__":
    unittest.main()
