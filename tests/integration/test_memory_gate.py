from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


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

    def _replace_after_observation(self, lock_path: Path, replacement_owner: str):
        original_observe = memory_gate._observe_lock
        begin_replacement = threading.Event()
        replacement_complete = threading.Event()
        thread_errors: list[BaseException] = []
        triggered = False

        def replace_lock() -> None:
            try:
                self.assertTrue(begin_replacement.wait(timeout=2))
                lock_path.unlink()
                memory_gate._write_lock(lock_path, replacement_owner, 128)
            except BaseException as error:
                thread_errors.append(error)
            finally:
                replacement_complete.set()

        replacement_thread = threading.Thread(target=replace_lock)
        replacement_thread.start()

        def observe_then_replace(path: Path, *, allow_unreadable: bool = False):
            nonlocal triggered
            observation = original_observe(path, allow_unreadable=allow_unreadable)
            if path == lock_path and observation is not None and not triggered:
                triggered = True
                begin_replacement.set()
                self.assertTrue(replacement_complete.wait(timeout=2))
            return observation

        return observe_then_replace, replacement_thread, thread_errors

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
                    "token": "stale-token",
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

    def test_claim_does_not_automatically_reclaim_structurally_unreadable_lock(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        malformed_record = {"pid": 999_999_999}
        lock_path.write_text(json.dumps(malformed_record), encoding="utf-8")

        with self.assertRaises(memory_gate.LockBusyError):
            memory_gate.claim(
                "build",
                128,
                "current-owner",
                lock_directory=self.lock_directory,
                timeout_seconds=0,
                available_memory_mib=lambda: 1024,
                pid_is_alive=lambda _pid: False,
            )

        self.assertEqual(malformed_record, json.loads(lock_path.read_text(encoding="utf-8")))

    def test_claim_normalizes_out_of_range_incumbent_pid(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        incumbent = {
            "owner": "incumbent-owner",
            "memory_mib": 128,
            "pid": 1 << 100,
            "timestamp": "2026-07-22T00:00:00+00:00",
            "token": "a" * 32,
        }
        lock_path.write_text(json.dumps(incumbent), encoding="utf-8")

        with self.assertRaisesRegex(memory_gate.GateError, r"PID .* outside the platform process-ID range"):
            memory_gate.claim(
                "build",
                128,
                "contender",
                lock_directory=self.lock_directory,
                timeout_seconds=0,
                available_memory_mib=lambda: 1024,
            )

        self.assertEqual(incumbent, json.loads(lock_path.read_text(encoding="utf-8")))

    def test_stale_reclaim_does_not_remove_replacement_lock(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text(
            json.dumps(
                {
                    "owner": "stale-owner",
                    "memory_mib": 128,
                    "pid": 999_999_999,
                    "timestamp": "2026-07-22T00:00:00+00:00",
                    "token": "stale-token",
                }
            ),
            encoding="utf-8",
        )
        racing_observe, replacement_thread, thread_errors = self._replace_after_observation(
            lock_path, "replacement-owner"
        )

        try:
            with mock.patch.object(memory_gate, "_observe_lock", side_effect=racing_observe):
                with self.assertRaises(memory_gate.LockBusyError):
                    memory_gate.claim(
                        "build",
                        128,
                        "contender",
                        lock_directory=self.lock_directory,
                        timeout_seconds=0,
                        available_memory_mib=lambda: 1024,
                        pid_is_alive=lambda pid: pid != 999_999_999,
                    )
        finally:
            replacement_thread.join(timeout=2)

        self.assertFalse(replacement_thread.is_alive())
        self.assertEqual([], thread_errors)
        record = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual("replacement-owner", record["owner"])

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

    def test_owner_release_does_not_remove_replacement_lock(self) -> None:
        lock_path = memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        token = json.loads(lock_path.read_text(encoding="utf-8"))["token"]
        racing_observe, replacement_thread, thread_errors = self._replace_after_observation(
            lock_path, "replacement-owner"
        )

        try:
            with mock.patch.object(memory_gate, "_observe_lock", side_effect=racing_observe):
                self.assertFalse(
                    memory_gate.release(
                        "build",
                        "lock-owner",
                        token=token,
                        lock_directory=self.lock_directory,
                    )
                )
        finally:
            replacement_thread.join(timeout=2)

        self.assertFalse(replacement_thread.is_alive())
        self.assertEqual([], thread_errors)
        record = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual("replacement-owner", record["owner"])

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

    def test_claim_and_release_reject_nonfinite_wait_configuration(self) -> None:
        for invalid_timeout in (float("nan"), float("inf")):
            with self.subTest(operation="claim", timeout=invalid_timeout):
                with self.assertRaisesRegex(memory_gate.GateError, r"timeout_seconds"):
                    memory_gate.claim(
                        "build",
                        128,
                        "owner",
                        lock_directory=self.lock_directory,
                        timeout_seconds=invalid_timeout,
                        available_memory_mib=lambda: 1024,
                    )
            with self.subTest(operation="release", timeout=invalid_timeout):
                with self.assertRaisesRegex(memory_gate.GateError, r"timeout_seconds"):
                    memory_gate.release(
                        "build",
                        "owner",
                        lock_directory=self.lock_directory,
                        timeout_seconds=invalid_timeout,
                    )

        for invalid_poll in (float("nan"), float("inf")):
            with self.subTest(operation="claim", poll=invalid_poll):
                with self.assertRaisesRegex(memory_gate.GateError, r"poll_seconds"):
                    memory_gate.claim(
                        "build",
                        128,
                        "owner",
                        lock_directory=self.lock_directory,
                        poll_seconds=invalid_poll,
                        available_memory_mib=lambda: 1024,
                    )
            with self.subTest(operation="release", poll=invalid_poll):
                with self.assertRaisesRegex(memory_gate.GateError, r"poll_seconds"):
                    memory_gate.release(
                        "build",
                        "owner",
                        lock_directory=self.lock_directory,
                        poll_seconds=invalid_poll,
                    )

    def test_claim_requires_positive_integer_memory_mib(self) -> None:
        for index, invalid_memory_mib in enumerate((True, 1.5, "128", None)):
            with self.subTest(memory_mib=invalid_memory_mib):
                try:
                    with self.assertRaisesRegex(memory_gate.GateError, r"memory_mib must be a positive integer"):
                        memory_gate.claim(
                            f"build-{index}",
                            invalid_memory_mib,
                            "owner",
                            lock_directory=self.lock_directory,
                            available_memory_mib=lambda: 1024,
                        )
                except TypeError as error:
                    self.fail(f"invalid memory_mib escaped instead of GateError: {error}")

    def test_malformed_memavailable_numeric_is_a_gate_error(self) -> None:
        with mock.patch.object(memory_gate.Path, "open", return_value=io.StringIO("MemAvailable: unknown kB\n")):
            with self.assertRaisesRegex(memory_gate.GateError, r"invalid MemAvailable"):
                memory_gate.available_memory_mib()

    def test_old_token_cannot_release_same_owner_successor(self) -> None:
        first_path = memory_gate.claim(
            "build",
            128,
            "same-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        first_record = json.loads(first_path.read_text(encoding="utf-8"))
        first_path.unlink()
        second_path = memory_gate.claim(
            "build",
            128,
            "same-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        second_record = json.loads(second_path.read_text(encoding="utf-8"))

        try:
            released = memory_gate.release(
                "build",
                "same-owner",
                token=first_record["token"],
                lock_directory=self.lock_directory,
            )
        except TypeError as error:
            self.fail(f"release must accept a token capability: {error}")

        self.assertFalse(released)
        self.assertEqual(second_record, json.loads(second_path.read_text(encoding="utf-8")))

    def test_tokenized_lock_cannot_be_released_without_token(self) -> None:
        lock_path = memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        token = json.loads(lock_path.read_text(encoding="utf-8"))["token"]

        self.assertFalse(memory_gate.release("build", "lock-owner", lock_directory=self.lock_directory))
        self.assertTrue(lock_path.exists())
        try:
            released = memory_gate.release(
                "build",
                "lock-owner",
                token=token,
                lock_directory=self.lock_directory,
            )
        except TypeError as error:
            self.fail(f"release must accept a token capability: {error}")
        self.assertTrue(released)

    def test_malformed_token_cannot_bypass_release_capability(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text(
            json.dumps(
                {
                    "owner": "lock-owner",
                    "memory_mib": 128,
                    "pid": os.getpid(),
                    "timestamp": "2026-07-22T00:00:00+00:00",
                    "token": "not-a-valid-token",
                }
            ),
            encoding="utf-8",
        )

        self.assertFalse(
            memory_gate.release(
                "build",
                "lock-owner",
                token="not-a-valid-token",
                lock_directory=self.lock_directory,
            )
        )
        self.assertTrue(lock_path.exists())
        self.assertTrue(
            memory_gate.release(
                "build",
                "lock-owner",
                lock_directory=self.lock_directory,
                cleanup_unreadable=True,
            )
        )

    def test_cli_claim_returns_token_required_by_release(self) -> None:
        environment = os.environ.copy()
        environment[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)
        claim_result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "cli-owner",
                "--pid",
                str(os.getpid()),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(0, claim_result.returncode, claim_result.stderr)
        lease = json.loads(claim_result.stdout)
        self.assertEqual(os.getpid(), lease["pid"])
        self.assertRegex(lease["token"], r"^[0-9a-f]{32}$")

        release_result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--release",
                "build",
                "--owner",
                "cli-owner",
                "--token",
                lease["token"],
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(0, release_result.returncode, release_result.stderr)
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_cli_rechecks_manual_pid_at_commit_boundary(self) -> None:
        blocking_lease = memory_gate.claim(
            "build",
            1,
            "blocking-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        original_release = memory_gate.release
        stderr = io.StringIO()
        stdout = io.StringIO()
        environment = {memory_gate.LOCK_DIRECTORY_ENV: str(self.lock_directory)}
        wait_intervals: list[float] = []

        def release_during_wait(interval: float) -> None:
            wait_intervals.append(interval)
            self.assertTrue(
                original_release(
                    blocking_lease.claim_name,
                    blocking_lease.owner,
                    token=blocking_lease.token,
                    lock_directory=blocking_lease.path.parent,
                )
            )

        with (
            mock.patch.dict(memory_gate.os.environ, environment),
            mock.patch.object(memory_gate, "pid_is_alive", side_effect=[True, True, False]) as alive,
            mock.patch.object(memory_gate.time, "sleep", side_effect=release_during_wait),
            mock.patch.object(memory_gate.sys, "stdout", stdout),
            mock.patch.object(memory_gate.sys, "stderr", stderr),
        ):
            result = memory_gate.main(
                [
                    "--claim",
                    "build",
                    "--memory-mib",
                    "1",
                    "--owner",
                    "cli-owner",
                    "--pid",
                    str(os.getpid()),
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual(1, len(wait_intervals))
        self.assertEqual(3, alive.call_count)
        self.assertIn("no longer alive", stderr.getvalue())
        self.assertEqual("", stdout.getvalue())
        self.assertFalse((self.lock_directory / "build.lock").exists())
        self.assertEqual([], list(self.lock_directory.glob(".*.tmp")))

    def test_cli_normalizes_out_of_range_manual_pid(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()

        with (
            mock.patch.dict(
                memory_gate.os.environ,
                {memory_gate.LOCK_DIRECTORY_ENV: str(self.lock_directory)},
            ),
            mock.patch.object(memory_gate.sys, "stdout", stdout),
            mock.patch.object(memory_gate.sys, "stderr", stderr),
        ):
            result = memory_gate.main(
                [
                    "--claim",
                    "build",
                    "--memory-mib",
                    "1",
                    "--owner",
                    "cli-owner",
                    "--pid",
                    str(1 << 100),
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("outside the platform process-ID range", stderr.getvalue())
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_cli_failure_reports_retained_lease_capability(self) -> None:
        lease = memory_gate.Lease(
            self.lock_directory / "build.lock",
            "cli-owner",
            "a" * 32,
            os.getpid(),
            1,
            2,
            b"{}\n",
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                memory_gate,
                "claim",
                side_effect=memory_gate.LeaseRetainedError("simulated retained lease", lease),
            ),
            mock.patch.object(memory_gate.sys, "stdout", stdout),
            mock.patch.object(memory_gate.sys, "stderr", stderr),
        ):
            result = memory_gate.main(
                [
                    "--claim",
                    "build",
                    "--memory-mib",
                    "1",
                    "--owner",
                    "cli-owner",
                    "--pid",
                    str(os.getpid()),
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual(lease.as_dict(), json.loads(stdout.getvalue()))
        self.assertIn("simulated retained lease", stderr.getvalue())

    def test_cli_exec_records_workload_pid_and_releases_after_exit(self) -> None:
        lock_path = self.lock_directory / "build.lock"
        result_path = Path(self.temporary_directory.name) / "workload.json"
        workload = (
            "import json, os; from pathlib import Path; "
            f"lock = json.loads(Path({str(lock_path)!r}).read_text(encoding='utf-8')); "
            f"Path({str(result_path)!r}).write_text(json.dumps({{'pid': os.getpid(), 'lock_pid': lock['pid']}}), "
            "encoding='utf-8')"
        )
        environment = os.environ.copy()
        environment[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                workload,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        workload_result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(workload_result["pid"], workload_result["lock_pid"])
        self.assertFalse(lock_path.exists())

    def test_cli_exec_maps_signal_exit_to_shell_status(self) -> None:
        environment = os.environ.copy()
        environment[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(128 + 15, completed.returncode, completed.stderr)
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_cli_release_forwards_bounded_wait_configuration(self) -> None:
        token = "0" * 32
        with mock.patch.object(memory_gate, "release", return_value=True) as mocked_release:
            result = memory_gate.main(
                [
                    "--release",
                    "build",
                    "--owner",
                    "cli-owner",
                    "--token",
                    token,
                    "--timeout-seconds",
                    "0.5",
                    "--poll-seconds",
                    "0.02",
                ]
            )

        self.assertEqual(0, result)
        mocked_release.assert_called_once_with(
            "build",
            "cli-owner",
            token=token,
            cleanup_unreadable=False,
            timeout_seconds=0.5,
            poll_seconds=0.02,
        )

    def test_exec_start_failure_releases_claim_and_reaps_child(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        original_write = memory_gate.os.write

        def fail_start_signal(descriptor: int, data: bytes) -> int:
            if bytes(data) == b"1":
                raise BrokenPipeError("simulated child start failure")
            return original_write(descriptor, data)

        original_wait_for_child = memory_gate._wait_for_child
        waited_child_pids: list[int] = []

        def tracked_wait_for_child(child_pid: int) -> int:
            waited_child_pids.append(child_pid)
            return original_wait_for_child(child_pid)

        previous_lock_directory = os.environ.get(memory_gate.LOCK_DIRECTORY_ENV)
        os.environ[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)
        try:
            try:
                with (
                    mock.patch.object(memory_gate.os, "write", side_effect=fail_start_signal),
                    mock.patch.object(memory_gate, "_wait_for_child", side_effect=tracked_wait_for_child),
                    self.assertRaisesRegex(memory_gate.GateError, r"cannot start gated workload"),
                ):
                    memory_gate._claim_and_exec(arguments)
            except BrokenPipeError as error:
                self.fail(f"child start failure escaped instead of GateError: {error}")
        finally:
            if previous_lock_directory is None:
                os.environ.pop(memory_gate.LOCK_DIRECTORY_ENV, None)
            else:
                os.environ[memory_gate.LOCK_DIRECTORY_ENV] = previous_lock_directory

        self.assertEqual(1, len(waited_child_pids))
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_exec_claim_failure_closes_start_pipe_and_reaps_child(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        child_pids: list[int] = []
        waited_child_pids: list[int] = []
        original_wait_for_child = memory_gate._wait_for_child

        def fail_claim(*_args: object, **kwargs: object) -> memory_gate.Lease:
            child_pids.append(int(kwargs["pid"]))
            raise memory_gate.GateError("simulated claim failure")

        def tracked_wait_for_child(child_pid: int) -> int:
            waited_child_pids.append(child_pid)
            return original_wait_for_child(child_pid)

        try:
            with (
                mock.patch.object(memory_gate, "claim", side_effect=fail_claim),
                mock.patch.object(memory_gate, "_wait_for_child", side_effect=tracked_wait_for_child),
                self.assertRaisesRegex(memory_gate.GateError, r"simulated claim failure"),
            ):
                memory_gate._claim_and_exec(arguments)
        finally:
            if child_pids and not waited_child_pids:
                os.waitpid(child_pids[0], 0)

        self.assertEqual(child_pids, waited_child_pids)

    def test_exec_claim_and_reap_failure_is_a_gate_error(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        original_wait_for_child = memory_gate._wait_for_child

        def fail_claim(*_args: object, **_kwargs: object) -> memory_gate.Lease:
            raise memory_gate.GateError("simulated claim failure")

        def reap_then_fail(child_pid: int) -> int:
            original_wait_for_child(child_pid)
            raise OSError("simulated reap diagnostic")

        try:
            with (
                mock.patch.object(memory_gate, "claim", side_effect=fail_claim),
                mock.patch.object(memory_gate, "_wait_for_child", side_effect=reap_then_fail),
                self.assertRaisesRegex(memory_gate.GateError, r"claim failure.*reap.*failed"),
            ):
                memory_gate._claim_and_exec(arguments)
        except OSError as error:
            self.fail(f"reap failure escaped instead of GateError: {error}")

    def test_exec_retained_claim_and_reap_failure_preserves_lease_capability(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        retained_lease = memory_gate.Lease(
            self.lock_directory / "build.lock",
            "exec-owner",
            "b" * 32,
            os.getpid(),
            1,
            2,
            b"{}\n",
        )
        original_wait_for_child = memory_gate._wait_for_child

        def fail_claim(*_args: object, **_kwargs: object) -> memory_gate.Lease:
            raise memory_gate.LeaseRetainedError("simulated retained claim", retained_lease)

        def reap_then_fail(child_pid: int) -> int:
            original_wait_for_child(child_pid)
            raise OSError("simulated reap diagnostic")

        caught: memory_gate.GateError | None = None
        with (
            mock.patch.object(memory_gate, "claim", side_effect=fail_claim),
            mock.patch.object(memory_gate, "_wait_for_child", side_effect=reap_then_fail),
        ):
            try:
                memory_gate._claim_and_exec(arguments)
            except memory_gate.GateError as error:
                caught = error

        self.assertIsNotNone(caught)
        self.assertIs(retained_lease, getattr(caught, "lease", None))
        self.assertRegex(str(caught), r"retained claim.*reap.*failed")

    def test_exec_start_and_reap_failure_still_releases_lease(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        original_write = memory_gate.os.write
        original_wait_for_child = memory_gate._wait_for_child

        def fail_start_signal(descriptor: int, data: bytes) -> int:
            if bytes(data) == b"1":
                raise BrokenPipeError("simulated child start failure")
            return original_write(descriptor, data)

        def reap_then_fail(child_pid: int) -> int:
            original_wait_for_child(child_pid)
            raise OSError("simulated reap diagnostic")

        previous_lock_directory = os.environ.get(memory_gate.LOCK_DIRECTORY_ENV)
        os.environ[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)
        try:
            try:
                with (
                    mock.patch.object(memory_gate.os, "write", side_effect=fail_start_signal),
                    mock.patch.object(memory_gate, "_wait_for_child", side_effect=reap_then_fail),
                    self.assertRaisesRegex(memory_gate.GateError, r"cannot start gated workload.*reap.*failed"),
                ):
                    memory_gate._claim_and_exec(arguments)
            except OSError as error:
                self.fail(f"start/reap failure escaped instead of GateError: {error}")
        finally:
            if previous_lock_directory is None:
                os.environ.pop(memory_gate.LOCK_DIRECTORY_ENV, None)
            else:
                os.environ[memory_gate.LOCK_DIRECTORY_ENV] = previous_lock_directory

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_exec_wait_failure_retains_lease_capability(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        original_wait_for_child = memory_gate._wait_for_child

        def wait_then_fail(child_pid: int) -> int:
            original_wait_for_child(child_pid)
            raise memory_gate.GateError("simulated wait diagnostic")

        previous_lock_directory = os.environ.get(memory_gate.LOCK_DIRECTORY_ENV)
        os.environ[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)
        caught: memory_gate.GateError | None = None
        try:
            with mock.patch.object(memory_gate, "_wait_for_child", side_effect=wait_then_fail):
                try:
                    memory_gate._claim_and_exec(arguments)
                except memory_gate.GateError as error:
                    caught = error
        finally:
            if previous_lock_directory is None:
                os.environ.pop(memory_gate.LOCK_DIRECTORY_ENV, None)
            else:
                os.environ[memory_gate.LOCK_DIRECTORY_ENV] = previous_lock_directory

        self.assertIsNotNone(caught)
        lease = getattr(caught, "lease", None)
        self.assertIsInstance(lease, memory_gate.Lease)
        assert isinstance(lease, memory_gate.Lease)
        self.assertTrue(lease.path.exists())
        self.assertTrue(
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )
        )

    def test_exec_release_failure_retains_lease_capability(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        previous_lock_directory = os.environ.get(memory_gate.LOCK_DIRECTORY_ENV)
        os.environ[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)
        caught: memory_gate.GateError | None = None
        try:
            with mock.patch.object(
                memory_gate,
                "release",
                side_effect=memory_gate.GateError("simulated release failure"),
            ):
                try:
                    memory_gate._claim_and_exec(arguments)
                except memory_gate.GateError as error:
                    caught = error
        finally:
            if previous_lock_directory is None:
                os.environ.pop(memory_gate.LOCK_DIRECTORY_ENV, None)
            else:
                os.environ[memory_gate.LOCK_DIRECTORY_ENV] = previous_lock_directory

        self.assertIsNotNone(caught)
        lease = getattr(caught, "lease", None)
        self.assertIsInstance(lease, memory_gate.Lease)
        assert isinstance(lease, memory_gate.Lease)
        self.assertTrue(
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )
        )

    def test_exec_false_release_result_accepts_legitimate_successor(self) -> None:
        arguments = memory_gate._parse_arguments(
            [
                "--claim",
                "build",
                "--memory-mib",
                "1",
                "--owner",
                "exec-owner",
                "--exec",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        lock_path = self.lock_directory / "build.lock"
        successor_leases: list[memory_gate.Lease] = []
        original_release = memory_gate.release
        successor_preserved = False

        def replace_with_successor(*_args: object, **_kwargs: object) -> bool:
            lock_path.unlink()
            successor_leases.append(memory_gate._write_lock(lock_path, "successor-owner", 1))
            return False

        with (
            mock.patch.dict(
                memory_gate.os.environ,
                {memory_gate.LOCK_DIRECTORY_ENV: str(self.lock_directory)},
            ),
            mock.patch.object(memory_gate, "release", side_effect=replace_with_successor),
        ):
            try:
                result = memory_gate._claim_and_exec(arguments)
            finally:
                successor_preserved = lock_path.exists()
                successor = successor_leases[0] if successor_leases else None
                if successor is not None:
                    original_release(
                        successor.claim_name,
                        successor.owner,
                        token=successor.token,
                        lock_directory=successor.path.parent,
                    )

        self.assertEqual(0, result)
        self.assertEqual(1, len(successor_leases))
        self.assertTrue(successor_preserved)

    def test_exec_false_release_result_retains_current_lease(self) -> None:
        lease = memory_gate.claim(
            "build",
            1,
            "exec-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )

        try:
            with (
                mock.patch.object(memory_gate, "release", return_value=False),
                self.assertRaises(memory_gate.LeaseRetainedError) as raised,
            ):
                memory_gate._release_retained_lease(lease, "simulated uncertain release")
            self.assertIs(lease, raised.exception.lease)
            self.assertTrue(lease.path.exists())
        finally:
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )

    def test_release_sidecar_failure_after_unlink_is_not_reported_as_retained(self) -> None:
        lease = memory_gate.claim(
            "build",
            1,
            "exec-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        original_release_guard = memory_gate._release_reclaim_guard

        def release_then_fail(descriptor: int) -> None:
            original_release_guard(descriptor)
            raise memory_gate.GateError("simulated sidecar finalization failure")

        caught: memory_gate.GateError | None = None
        with mock.patch.object(memory_gate, "_release_reclaim_guard", side_effect=release_then_fail):
            try:
                memory_gate._release_retained_lease(lease, "simulated release failure")
            except memory_gate.GateError as error:
                caught = error

        self.assertIsNotNone(caught)
        self.assertNotIsInstance(caught, memory_gate.LeaseRetainedError)
        self.assertIsNone(getattr(caught, "lease", None))
        assert caught is not None
        self.assertIn("sidecar finalization failure", str(caught))
        self.assertFalse(lease.path.exists())

    def test_release_waits_for_transient_sidecar_holder(self) -> None:
        lease = memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        guard = memory_gate._try_acquire_reclaim_guard(lease.path)
        self.assertIsNotNone(guard)
        attempted = threading.Event()
        results: list[bool] = []
        thread_errors: list[BaseException] = []
        original_try_acquire = memory_gate._try_acquire_reclaim_guard

        def tracked_try_acquire(path: Path):
            descriptor = original_try_acquire(path)
            if threading.current_thread() is release_thread:
                attempted.set()
            return descriptor

        def release_claim() -> None:
            try:
                results.append(
                    memory_gate.release(
                        "build",
                        "lock-owner",
                        token=lease.token,
                        lock_directory=self.lock_directory,
                    )
                )
            except BaseException as error:
                thread_errors.append(error)

        release_thread = threading.Thread(target=release_claim)
        with mock.patch.object(memory_gate, "_try_acquire_reclaim_guard", side_effect=tracked_try_acquire):
            release_thread.start()
            self.assertTrue(attempted.wait(timeout=2))
            assert guard is not None
            memory_gate._release_reclaim_guard(guard)
            release_thread.join(timeout=2)

        self.assertFalse(release_thread.is_alive())
        self.assertEqual([], thread_errors)
        self.assertEqual([True], results)
        self.assertFalse(lease.exists())

    def test_cooperative_claim_cannot_replace_lock_during_release_unlink(self) -> None:
        lease = memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
        )
        start_contender = threading.Event()
        contender_attempted = threading.Event()
        contender_leases: list[object] = []
        thread_errors: list[BaseException] = []
        original_try_acquire = memory_gate._try_acquire_reclaim_guard
        original_unlink = memory_gate._unlink_if_observed

        def tracked_try_acquire(path: Path):
            descriptor = original_try_acquire(path)
            if threading.current_thread() is contender_thread and descriptor is None:
                contender_attempted.set()
            return descriptor

        def contender() -> None:
            try:
                self.assertTrue(start_contender.wait(timeout=2))
                contender_leases.append(
                    memory_gate.claim(
                        "build",
                        128,
                        "contender",
                        lock_directory=self.lock_directory,
                        timeout_seconds=1,
                        poll_seconds=0.01,
                        available_memory_mib=lambda: 1024,
                    )
                )
            except BaseException as error:
                thread_errors.append(error)

        def unlink_after_contender_attempt(path: Path, expected: object) -> bool:
            start_contender.set()
            self.assertTrue(contender_attempted.wait(timeout=2))
            return original_unlink(path, expected)

        contender_thread = threading.Thread(target=contender)
        with (
            mock.patch.object(memory_gate, "_try_acquire_reclaim_guard", side_effect=tracked_try_acquire),
            mock.patch.object(memory_gate, "_unlink_if_observed", side_effect=unlink_after_contender_attempt),
        ):
            contender_thread.start()
            self.assertTrue(
                memory_gate.release(
                    "build",
                    "lock-owner",
                    token=lease.token,
                    lock_directory=self.lock_directory,
                )
            )
            contender_thread.join(timeout=2)

        self.assertFalse(contender_thread.is_alive())
        self.assertEqual([], thread_errors)
        self.assertEqual(1, len(contender_leases))
        record = json.loads((self.lock_directory / "build.lock").read_text(encoding="utf-8"))
        self.assertEqual("contender", record["owner"])

    def test_claim_persists_record_fields_without_overriding_lease_identity(self) -> None:
        try:
            lease = memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
                record_fields={"seed": 17, "candidate_hash": "sha256:abc"},
            )
        except TypeError as error:
            self.fail(f"claim must remain compatible with record_fields: {error}")

        record = json.loads(lease.read_text(encoding="utf-8"))
        self.assertEqual(17, record["seed"])
        self.assertEqual("sha256:abc", record["candidate_hash"])
        self.assertEqual(lease.token, record["token"])

    def test_claim_lease_carries_exact_bounded_persisted_record_payload(self) -> None:
        lease = memory_gate.claim(
            "build",
            128,
            "lock-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
            record_fields={"seed": 17, "candidate_hash": "sha256:abc"},
        )

        self.assertIsInstance(lease.record_payload, bytes)
        self.assertLessEqual(len(lease.record_payload), memory_gate._MAX_LOCK_RECORD_BYTES)
        self.assertEqual(lease.path.read_bytes(), lease.record_payload)
        record = json.loads(lease.record_payload)
        self.assertEqual(17, record["seed"])
        self.assertEqual("sha256:abc", record["candidate_hash"])
        self.assertEqual(lease.token, record["token"])

        with self.assertRaises(TypeError):
            lease.record_payload[0] = 0

    def test_lease_rejects_mutable_audit_record_payload(self) -> None:
        with self.assertRaises(TypeError):
            memory_gate.Lease(
                self.lock_directory / "build.lock",
                "lock-owner",
                "a" * 32,
                os.getpid(),
                1,
                2,
                bytearray(b"{}\n"),
            )

    def test_claim_rejects_oversized_record_before_publication(self) -> None:
        with self.assertRaisesRegex(memory_gate.GateError, r"lock record exceeds .*byte limit"):
            memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
                record_fields={"audit": "x" * memory_gate._MAX_LOCK_RECORD_BYTES},
            )

        self.assertFalse((self.lock_directory / "build.lock").exists())
        self.assertEqual([], list(self.lock_directory.glob(".build.lock.*.tmp")))

    def test_future_scheduler_contract_retains_metadata_and_lease_token(self) -> None:
        first_lease = memory_gate.claim(
            "build",
            128,
            "scheduler-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
            pid=os.getpid(),
            record_fields={"seed": 17, "candidate_hash": "sha256:first"},
        )
        self.assertTrue(
            memory_gate.release(
                first_lease.claim_name,
                first_lease.owner,
                token=first_lease.token,
                lock_directory=first_lease.path.parent,
            )
        )
        successor_lease = memory_gate.claim(
            "build",
            128,
            "scheduler-owner",
            lock_directory=self.lock_directory,
            available_memory_mib=lambda: 1024,
            pid=os.getpid(),
            record_fields={"seed": 18, "candidate_hash": "sha256:successor"},
        )

        self.assertFalse(
            memory_gate.release(
                first_lease.claim_name,
                first_lease.owner,
                token=first_lease.token,
                lock_directory=first_lease.path.parent,
            )
        )
        record = memory_gate._read_record(successor_lease.path)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(18, record["seed"])
        self.assertEqual("sha256:successor", record["candidate_hash"])
        self.assertEqual(successor_lease.token, record["token"])
        self.assertTrue(
            memory_gate.release(
                successor_lease.claim_name,
                successor_lease.owner,
                token=successor_lease.token,
                lock_directory=successor_lease.path.parent,
            )
        )

    def test_record_fields_cannot_override_required_fields(self) -> None:
        try:
            with self.assertRaisesRegex(memory_gate.GateError, r"cannot replace required"):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                    record_fields={"token": "forged-token"},
                )
        except TypeError as error:
            self.fail(f"claim must validate record_fields: {error}")

    def test_record_fields_reject_nonfinite_json_numbers(self) -> None:
        for index, value in enumerate((float("nan"), float("inf"), float("-inf"))):
            with self.subTest(value=value):
                with self.assertRaisesRegex(memory_gate.GateError, r"record_fields must be JSON serializable"):
                    memory_gate.claim(
                        f"build-{index}",
                        128,
                        "lock-owner",
                        lock_directory=self.lock_directory,
                        available_memory_mib=lambda: 1024,
                        record_fields={"measurement": value},
                    )

                self.assertFalse((self.lock_directory / f"build-{index}.lock").exists())

    def test_write_lock_retries_short_writes_until_payload_is_complete(self) -> None:
        original_write = memory_gate.os.write

        def short_write(descriptor: int, data: bytes) -> int:
            return original_write(descriptor, bytes(data[:3]))

        with mock.patch.object(memory_gate.os, "write", side_effect=short_write):
            lease = memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        record = memory_gate._read_record(lease.path)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("lock-owner", record["owner"])
        self.assertEqual(lease.token, record["token"])

    def test_write_lock_retries_interrupted_write(self) -> None:
        original_write = memory_gate.os.write
        interrupted = False

        def interrupt_once(descriptor: int, data: bytes) -> int:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise InterruptedError("simulated signal")
            return original_write(descriptor, data)

        with mock.patch.object(memory_gate.os, "write", side_effect=interrupt_once):
            lease = memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        self.assertTrue(interrupted)
        record = memory_gate._read_record(lease.path)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("lock-owner", record["owner"])

    def test_lock_create_failure_is_a_gate_error(self) -> None:
        original_open = memory_gate.os.open

        def deny_lock_create(path: object, flags: int, mode: int = 0o777) -> int:
            candidate = Path(path)
            if candidate.parent == self.lock_directory and candidate.name.endswith(".tmp"):
                raise PermissionError("simulated create denial")
            return original_open(path, flags, mode)

        try:
            with (
                mock.patch.object(memory_gate.os, "open", side_effect=deny_lock_create),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot create memory gate lock"),
            ):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
        except PermissionError as error:
            self.fail(f"lock creation failure escaped instead of GateError: {error}")

    def test_fstat_failure_does_not_publish_gate_lock(self) -> None:
        with (
            mock.patch.object(memory_gate.os, "fstat", side_effect=OSError("simulated fstat failure")),
            self.assertRaisesRegex(memory_gate.GateError, r"cannot persist memory gate lock.*fstat failure"),
        ):
            memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_write_failure_removes_only_partial_lock(self) -> None:
        original_write = memory_gate.os.write

        def write_prefix_then_fail(descriptor: int, data: bytes) -> int:
            original_write(descriptor, bytes(data[:1]))
            raise OSError("simulated disk failure")

        try:
            with (
                mock.patch.object(memory_gate.os, "write", side_effect=write_prefix_then_fail),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot persist memory gate lock"),
            ):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
        except OSError as error:
            self.fail(f"write failure escaped instead of GateError: {error}")

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_fsync_failure_removes_partial_lock(self) -> None:
        try:
            with (
                mock.patch.object(memory_gate.os, "fsync", side_effect=OSError("simulated fsync failure")),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot persist memory gate lock"),
            ):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
        except OSError as error:
            self.fail(f"fsync failure escaped instead of GateError: {error}")

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_claim_and_release_fsync_parent_directory_namespace(self) -> None:
        original_fsync = memory_gate.os.fsync
        directory_fsyncs = 0

        def track_directory_fsync(descriptor: int) -> None:
            nonlocal directory_fsyncs
            if memory_gate.stat.S_ISDIR(memory_gate.os.fstat(descriptor).st_mode):
                directory_fsyncs += 1
            original_fsync(descriptor)

        with mock.patch.object(memory_gate.os, "fsync", side_effect=track_directory_fsync):
            lease = memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )
            self.assertTrue(
                memory_gate.release(
                    lease.claim_name,
                    lease.owner,
                    token=lease.token,
                    lock_directory=lease.path.parent,
                )
            )

        self.assertEqual(2, directory_fsyncs)

    def test_publication_directory_fsync_failure_retains_lease_capability(self) -> None:
        original_fsync = memory_gate.os.fsync
        caught: memory_gate.GateError | None = None

        def fail_directory_fsync(descriptor: int) -> None:
            if memory_gate.stat.S_ISDIR(memory_gate.os.fstat(descriptor).st_mode):
                raise OSError("simulated directory fsync failure")
            original_fsync(descriptor)

        with mock.patch.object(memory_gate.os, "fsync", side_effect=fail_directory_fsync):
            try:
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
            except memory_gate.GateError as error:
                caught = error

        self.assertIsInstance(caught, memory_gate.LeaseRetainedError)
        assert isinstance(caught, memory_gate.LeaseRetainedError)
        self.assertIn("directory fsync failure", str(caught))
        lease = caught.lease
        record = memory_gate._read_record(lease.path)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(lease.token, record["token"])
        self.assertTrue(
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )
        )

    def test_publication_finalization_failure_after_unlink_is_not_retained(self) -> None:
        lock_path = self.lock_directory / "build.lock"

        def unlink_then_fail(_directory: Path) -> None:
            lock_path.unlink()
            raise memory_gate.GateError("simulated publication directory fsync failure")

        with (
            mock.patch.object(memory_gate, "_fsync_directory", side_effect=unlink_then_fail),
            self.assertRaises(memory_gate.GateError) as raised,
        ):
            memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        self.assertNotIsInstance(raised.exception, memory_gate.LeaseRetainedError)
        self.assertIsNone(getattr(raised.exception, "lease", None))
        self.assertIn("lease is no longer retained", str(raised.exception))
        self.assertFalse(lock_path.exists())

    def test_close_failure_removes_partial_lock_and_is_a_gate_error(self) -> None:
        original_open = memory_gate.os.open
        original_close = memory_gate.os.close
        lock_descriptor: int | None = None
        close_failed = False

        def track_lock_descriptor(path: object, flags: int, mode: int = 0o777) -> int:
            nonlocal lock_descriptor
            descriptor = original_open(path, flags, mode)
            candidate = Path(path)
            if candidate.parent == self.lock_directory and candidate.name.endswith(".tmp"):
                lock_descriptor = descriptor
            return descriptor

        def fail_lock_close(descriptor: int) -> None:
            nonlocal close_failed
            if descriptor == lock_descriptor and not close_failed:
                close_failed = True
                original_close(descriptor)
                raise OSError("simulated close failure")
            original_close(descriptor)

        try:
            with (
                mock.patch.object(memory_gate.os, "open", side_effect=track_lock_descriptor),
                mock.patch.object(memory_gate.os, "close", side_effect=fail_lock_close),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot persist memory gate lock.*close failure"),
            ):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
        except OSError as error:
            self.fail(f"close failure escaped instead of GateError: {error}")

        self.assertTrue(close_failed)
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_partial_write_and_staging_cleanup_failure_never_publish_gate(self) -> None:
        original_write = memory_gate.os.write

        def write_prefix_then_fail(descriptor: int, data: bytes) -> int:
            original_write(descriptor, bytes(data[:1]))
            raise OSError("simulated disk failure")

        try:
            with (
                mock.patch.object(memory_gate.os, "write", side_effect=write_prefix_then_fail),
                mock.patch.object(memory_gate.os, "unlink", side_effect=PermissionError("cleanup denied")),
                self.assertRaisesRegex(memory_gate.GateError, r"staging cleanup failed.*cleanup denied"),
            ):
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
        except OSError as error:
            self.fail(f"cleanup failure escaped instead of GateError: {error}")

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_published_lock_cleanup_failure_returns_usable_lease_capability(self) -> None:
        original_unlink = memory_gate.os.unlink

        def deny_staging_unlink(path: object) -> None:
            candidate = Path(path)
            if candidate.name.endswith(".tmp"):
                raise PermissionError("cleanup denied")
            original_unlink(path)

        caught: memory_gate.LeaseRetainedError | None = None
        with (
            mock.patch.object(memory_gate.os, "unlink", side_effect=deny_staging_unlink),
        ):
            try:
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
            except memory_gate.LeaseRetainedError as error:
                caught = error

        self.assertIsNotNone(caught)
        assert caught is not None
        self.assertIn("staging cleanup failed", str(caught))
        lease = getattr(caught, "lease", None)
        self.assertIsInstance(lease, memory_gate.Lease)
        assert isinstance(lease, memory_gate.Lease)
        record = json.loads(lease.path.read_text(encoding="utf-8"))
        self.assertEqual(lease.token, record["token"])
        self.assertTrue(
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )
        )

    def test_invalid_utf8_lock_requires_explicit_cleanup(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_bytes(b"\xff\xfeinvalid-lock")

        try:
            self.assertFalse(
                memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=False,
                )
            )
            self.assertTrue(lock_path.exists())
            self.assertTrue(
                memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=True,
                )
            )
        except (TypeError, UnicodeDecodeError) as error:
            self.fail(f"unreadable cleanup must be explicit and normalized: {error}")

        self.assertFalse(lock_path.exists())

    @unittest.skipIf(os.geteuid() == 0, "root can read mode-000 regular files")
    def test_mode_zero_regular_lock_supports_explicit_cleanup(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text("{}", encoding="utf-8")
        lock_path.chmod(0)

        try:
            with self.assertRaisesRegex(memory_gate.GateError, r"cannot read memory gate lock"):
                memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=False,
                )
            self.assertTrue(lock_path.exists())
            self.assertTrue(
                memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=True,
                )
            )
        finally:
            if lock_path.exists():
                lock_path.chmod(0o600)

        self.assertFalse(lock_path.exists())

    def test_lock_observation_uses_nonblocking_nofollow_open(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text("{}", encoding="utf-8")
        original_open = memory_gate.os.open
        observed_flags: list[int] = []

        def capture_flags(path: object, flags: int, mode: int = 0o777) -> int:
            if Path(path) == lock_path:
                observed_flags.append(flags)
            return original_open(path, flags, mode)

        with mock.patch.object(memory_gate.os, "open", side_effect=capture_flags):
            self.assertIsNotNone(memory_gate._observe_lock(lock_path))

        self.assertEqual(1, len(observed_flags))
        self.assertTrue(observed_flags[0] & memory_gate.os.O_NONBLOCK)
        self.assertTrue(observed_flags[0] & memory_gate.os.O_NOFOLLOW)

    def test_fifo_lock_cleanup_is_bounded_and_explicit(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        os.mkfifo(lock_path)
        environment = os.environ.copy()
        environment[memory_gate.LOCK_DIRECTORY_ENV] = str(self.lock_directory)

        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--release",
                    "build",
                    "--owner",
                    "cleanup-owner",
                    "--cleanup-unreadable",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=1,
                env=environment,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"FIFO observation blocked past the bounded cleanup interval: {error}")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertFalse(lock_path.exists())

    def test_symlink_lock_cleanup_unlinks_only_the_symlink(self) -> None:
        self.lock_directory.mkdir()
        target = Path(self.temporary_directory.name) / "external.lock"
        target.write_text("external", encoding="utf-8")
        lock_path = self.lock_directory / "build.lock"
        lock_path.symlink_to(target)

        self.assertTrue(
            memory_gate.release(
                "build",
                "cleanup-owner",
                lock_directory=self.lock_directory,
                cleanup_unreadable=True,
            )
        )

        self.assertFalse(lock_path.exists())
        self.assertEqual("external", target.read_text(encoding="utf-8"))

    def test_special_lock_cleanup_failure_is_a_gate_error(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        os.mkfifo(lock_path)

        try:
            with (
                mock.patch.object(Path, "unlink", side_effect=PermissionError("cleanup denied")),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot remove.*cleanup denied"),
            ):
                memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=True,
                )
        except PermissionError as error:
            self.fail(f"special lock cleanup escaped instead of GateError: {error}")

    def test_huge_integer_and_nonfinite_json_require_explicit_cleanup(self) -> None:
        self.lock_directory.mkdir()
        token = "c" * 32
        payloads = {
            "huge-int": (
                '{"memory_mib":128,"owner":"lock-owner","pid":'
                + "9" * 5000
                + f',"timestamp":"2026-07-22T00:00:00+00:00","token":"{token}"}}'
            ),
            "nan": json.dumps(
                {
                    "memory_mib": 128,
                    "owner": "lock-owner",
                    "pid": os.getpid(),
                    "timestamp": "2026-07-22T00:00:00+00:00",
                    "token": token,
                    "measurement": float("nan"),
                }
            ),
            "infinity": json.dumps(
                {
                    "memory_mib": 128,
                    "owner": "lock-owner",
                    "pid": os.getpid(),
                    "timestamp": "2026-07-22T00:00:00+00:00",
                    "token": token,
                    "measurement": float("inf"),
                }
            ),
        }

        for claim_name, payload in payloads.items():
            with self.subTest(claim_name=claim_name):
                lock_path = self.lock_directory / f"{claim_name}.lock"
                lock_path.write_text(payload, encoding="utf-8")
                try:
                    released = memory_gate.release(
                        claim_name,
                        "lock-owner",
                        token=token,
                        lock_directory=self.lock_directory,
                    )
                except (OverflowError, ValueError) as error:
                    self.fail(f"invalid JSON numeric value escaped instead of cleanup behavior: {error}")
                self.assertFalse(released)
                self.assertTrue(lock_path.exists())
                self.assertTrue(
                    memory_gate.release(
                        claim_name,
                        "cleanup-owner",
                        lock_directory=self.lock_directory,
                        cleanup_unreadable=True,
                    )
                )
                self.assertFalse(lock_path.exists())

    def test_parseable_incomplete_lock_requires_explicit_cleanup(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text("{}", encoding="utf-8")

        self.assertFalse(
            memory_gate.release(
                "build",
                "cleanup-owner",
                lock_directory=self.lock_directory,
                cleanup_unreadable=False,
            )
        )
        self.assertTrue(lock_path.exists())
        self.assertTrue(
            memory_gate.release(
                "build",
                "cleanup-owner",
                lock_directory=self.lock_directory,
                cleanup_unreadable=True,
            )
        )
        self.assertFalse(lock_path.exists())

    def test_unreadable_cleanup_does_not_remove_replacement_lock(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_bytes(b"\xff\xfeinvalid-lock")
        original_observe = memory_gate._observe_lock
        begin_replacement = threading.Event()
        replacement_complete = threading.Event()
        thread_errors: list[BaseException] = []
        triggered = False

        def replace_lock() -> None:
            try:
                self.assertTrue(begin_replacement.wait(timeout=2))
                lock_path.unlink()
                memory_gate._write_lock(lock_path, "replacement-owner", 128)
            except BaseException as error:
                thread_errors.append(error)
            finally:
                replacement_complete.set()

        def observe_then_replace(path: Path, *, allow_unreadable: bool = False):
            nonlocal triggered
            observation = original_observe(path, allow_unreadable=allow_unreadable)
            if path == lock_path and not triggered:
                triggered = True
                begin_replacement.set()
                self.assertTrue(replacement_complete.wait(timeout=2))
            return observation

        replacement_thread = threading.Thread(target=replace_lock)
        replacement_thread.start()
        try:
            with mock.patch.object(memory_gate, "_observe_lock", side_effect=observe_then_replace):
                try:
                    released = memory_gate.release(
                        "build",
                        "cleanup-owner",
                        lock_directory=self.lock_directory,
                        cleanup_unreadable=True,
                    )
                except (TypeError, UnicodeDecodeError) as error:
                    begin_replacement.set()
                    self.fail(f"unreadable cleanup must tolerate malformed UTF-8: {error}")
        finally:
            replacement_thread.join(timeout=2)

        self.assertFalse(released)
        self.assertFalse(replacement_thread.is_alive())
        self.assertEqual([], thread_errors)
        record = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual("replacement-owner", record["owner"])

    @unittest.skipIf(os.geteuid() == 0, "root can read mode-000 regular files")
    def test_mode_zero_cleanup_does_not_remove_replacement_lock(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        lock_path.write_text("{}", encoding="utf-8")
        lock_path.chmod(0)
        original_observe = memory_gate._observe_lock
        begin_replacement = threading.Event()
        replacement_complete = threading.Event()
        thread_errors: list[BaseException] = []
        triggered = False

        def replace_lock() -> None:
            try:
                self.assertTrue(begin_replacement.wait(timeout=2))
                lock_path.unlink()
                memory_gate._write_lock(lock_path, "replacement-owner", 128)
            except BaseException as error:
                thread_errors.append(error)
            finally:
                replacement_complete.set()

        def observe_then_replace(path: Path, *, allow_unreadable: bool = False):
            nonlocal triggered
            observation = original_observe(path, allow_unreadable=allow_unreadable)
            if path == lock_path and observation is not None and not triggered:
                triggered = True
                begin_replacement.set()
                self.assertTrue(replacement_complete.wait(timeout=2))
            return observation

        replacement_thread = threading.Thread(target=replace_lock)
        replacement_thread.start()
        try:
            with mock.patch.object(memory_gate, "_observe_lock", side_effect=observe_then_replace):
                released = memory_gate.release(
                    "build",
                    "cleanup-owner",
                    lock_directory=self.lock_directory,
                    cleanup_unreadable=True,
                )
        finally:
            begin_replacement.set()
            replacement_thread.join(timeout=2)
            if lock_path.exists() and not os.access(lock_path, os.R_OK):
                lock_path.chmod(0o600)

        self.assertFalse(released)
        self.assertFalse(replacement_thread.is_alive())
        self.assertEqual([], thread_errors)
        record = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual("replacement-owner", record["owner"])

    def test_reclaim_guard_closes_descriptor_when_flock_fails(self) -> None:
        self.lock_directory.mkdir()
        lock_path = self.lock_directory / "build.lock"
        opened_descriptors: list[int] = []
        original_open = memory_gate.os.open

        def tracked_open(*args: object, **kwargs: object) -> int:
            descriptor = original_open(*args, **kwargs)
            opened_descriptors.append(descriptor)
            return descriptor

        try:
            try:
                with (
                    mock.patch.object(memory_gate.os, "open", side_effect=tracked_open),
                    mock.patch.object(memory_gate.fcntl, "flock", side_effect=OSError("unsupported flock")),
                    self.assertRaisesRegex(memory_gate.GateError, r"cannot lock reclaim sidecar"),
                ):
                    memory_gate._try_acquire_reclaim_guard(lock_path)
            except OSError as error:
                self.fail(f"flock failure escaped instead of GateError: {error}")

            self.assertEqual(1, len(opened_descriptors))
            with self.assertRaises(OSError):
                os.fstat(opened_descriptors[0])
        finally:
            for descriptor in opened_descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_reclaim_guard_release_closes_descriptor_when_flock_fails(self) -> None:
        self.lock_directory.mkdir()
        guard_path = self.lock_directory / "build.lock.reclaim"
        descriptor = os.open(guard_path, os.O_RDWR | os.O_CREAT, 0o600)

        try:
            try:
                with (
                    mock.patch.object(memory_gate.fcntl, "flock", side_effect=OSError("unlock failed")),
                    self.assertRaisesRegex(memory_gate.GateError, r"cannot unlock reclaim sidecar"),
                ):
                    memory_gate._release_reclaim_guard(descriptor)
            except OSError as error:
                self.fail(f"flock release failure escaped instead of GateError: {error}")

            with self.assertRaises(OSError):
                os.fstat(descriptor)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_claim_rolls_back_lock_when_sidecar_finalization_fails(self) -> None:
        original_release_guard = memory_gate._release_reclaim_guard

        def release_then_fail(descriptor: int) -> None:
            original_release_guard(descriptor)
            raise memory_gate.GateError("simulated sidecar finalization failure")

        with (
            mock.patch.object(memory_gate, "_release_reclaim_guard", side_effect=release_then_fail),
            self.assertRaises(memory_gate.GateError),
        ):
            memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_rollback_directory_fsync_failure_does_not_report_retained_lease(self) -> None:
        original_release_guard = memory_gate._release_reclaim_guard
        original_fsync_directory = memory_gate._fsync_directory
        fsync_calls = 0

        def release_then_fail(descriptor: int) -> None:
            original_release_guard(descriptor)
            raise memory_gate.GateError("simulated sidecar finalization failure")

        def fail_rollback_fsync(directory: Path) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise memory_gate.GateError("simulated rollback directory fsync failure")
            original_fsync_directory(directory)

        with (
            mock.patch.object(memory_gate, "_release_reclaim_guard", side_effect=release_then_fail),
            mock.patch.object(memory_gate, "_fsync_directory", side_effect=fail_rollback_fsync),
            self.assertRaises(memory_gate.GateError) as raised,
        ):
            memory_gate.claim(
                "build",
                128,
                "lock-owner",
                lock_directory=self.lock_directory,
                available_memory_mib=lambda: 1024,
            )

        self.assertNotIsInstance(raised.exception, memory_gate.LeaseRetainedError)
        self.assertIsNone(getattr(raised.exception, "lease", None))
        self.assertIn("simulated rollback directory fsync failure", str(raised.exception))
        self.assertEqual(2, fsync_calls)
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_sidecar_and_rollback_failure_retains_lease_capability(self) -> None:
        original_release_guard = memory_gate._release_reclaim_guard

        def release_then_fail(descriptor: int) -> None:
            original_release_guard(descriptor)
            raise memory_gate.GateError("simulated sidecar finalization failure")

        caught: memory_gate.GateError | None = None
        with (
            mock.patch.object(memory_gate, "_release_reclaim_guard", side_effect=release_then_fail),
            mock.patch.object(memory_gate.Path, "unlink", side_effect=PermissionError("rollback denied")),
        ):
            try:
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
            except memory_gate.GateError as error:
                caught = error

        self.assertIsNotNone(caught)
        lease = getattr(caught, "lease", None)
        self.assertIsInstance(lease, memory_gate.Lease)
        assert isinstance(lease, memory_gate.Lease)
        record = json.loads(lease.path.read_text(encoding="utf-8"))
        self.assertEqual(lease.token, record["token"])
        self.assertTrue(
            memory_gate.release(
                lease.claim_name,
                lease.owner,
                token=lease.token,
                lock_directory=lease.path.parent,
            )
        )

    def test_persistence_and_sidecar_failure_does_not_publish_gate(self) -> None:
        original_release_guard = memory_gate._release_reclaim_guard

        def release_then_fail(descriptor: int) -> None:
            original_release_guard(descriptor)
            raise memory_gate.GateError("simulated sidecar finalization failure")

        caught: memory_gate.GateError | None = None
        with (
            mock.patch.object(memory_gate.os, "fsync", side_effect=OSError("simulated fsync failure")),
            mock.patch.object(memory_gate, "_release_reclaim_guard", side_effect=release_then_fail),
        ):
            try:
                memory_gate.claim(
                    "build",
                    128,
                    "lock-owner",
                    lock_directory=self.lock_directory,
                    available_memory_mib=lambda: 1024,
                )
            except memory_gate.GateError as error:
                caught = error

        self.assertIsNotNone(caught)
        self.assertIsNone(getattr(caught, "lease", None))
        assert caught is not None
        self.assertIn("sidecar finalization failure", str(caught))
        self.assertFalse((self.lock_directory / "build.lock").exists())

    def test_missing_proc_meminfo_is_a_gate_error(self) -> None:
        try:
            with (
                mock.patch.object(memory_gate.Path, "open", side_effect=FileNotFoundError("missing procfs")),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot read Linux /proc/meminfo"),
            ):
                memory_gate.available_memory_mib()
        except FileNotFoundError as error:
            self.fail(f"procfs error escaped instead of GateError: {error}")

    def test_proc_meminfo_decode_failure_is_a_gate_error(self) -> None:
        decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")
        try:
            with (
                mock.patch.object(memory_gate.Path, "open", side_effect=decode_error),
                self.assertRaisesRegex(memory_gate.GateError, r"cannot read Linux /proc/meminfo"),
            ):
                memory_gate.available_memory_mib()
        except UnicodeDecodeError as error:
            self.fail(f"procfs decode error escaped instead of GateError: {error}")

    def test_non_linux_platform_is_reported_as_gate_error(self) -> None:
        with mock.patch.object(memory_gate.sys, "platform", "darwin"):
            with self.assertRaisesRegex(memory_gate.GateError, r"requires Linux"):
                memory_gate.available_memory_mib()

    def test_missing_fcntl_support_is_reported_as_gate_error(self) -> None:
        self.lock_directory.mkdir()
        with mock.patch.object(memory_gate, "fcntl", None):
            try:
                with self.assertRaisesRegex(memory_gate.GateError, r"requires fcntl"):
                    memory_gate._try_acquire_reclaim_guard(self.lock_directory / "build.lock")
            except AttributeError as error:
                self.fail(f"missing fcntl support escaped instead of GateError: {error}")

    def test_stale_reclaim_does_not_follow_lock_symlink(self) -> None:
        self.lock_directory.mkdir()
        external_lock = Path(self.temporary_directory.name) / "external.lock"
        external_record = {
            "owner": "external-owner",
            "memory_mib": 128,
            "pid": 999_999_999,
            "timestamp": "2026-07-22T00:00:00+00:00",
            "token": "external-token",
        }
        external_lock.write_text(json.dumps(external_record), encoding="utf-8")
        lock_path = self.lock_directory / "build.lock"
        lock_path.symlink_to(external_lock)

        with self.assertRaises(memory_gate.LockBusyError):
            memory_gate.claim(
                "build",
                128,
                "contender",
                lock_directory=self.lock_directory,
                timeout_seconds=0,
                available_memory_mib=lambda: 1024,
                pid_is_alive=lambda _pid: False,
            )

        self.assertTrue(lock_path.is_symlink())
        self.assertEqual(external_record, json.loads(external_lock.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
