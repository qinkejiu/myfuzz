from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from myfuzz.integration.memory_lock import MemoryTokenPool


def _acquire_from_child(state_path: Path, connection: object) -> None:
    try:
        pool = MemoryTokenPool(1_000, 2_000, state_path)
        with pool.acquire("child", 400, exclusive_build=True, wait_timeout=3.0):
            connection.send(("acquired", pool.snapshot()["max_active_builds"]))
    except BaseException as error:
        connection.send(("error", repr(error)))
    finally:
        connection.close()


def _acquire_and_exit_without_release(state_path: Path, connection: object) -> None:
    pool = MemoryTokenPool(1_000, 2_000, state_path)
    pool.acquire("crashed-child", 400, exclusive_build=True)
    connection.send("acquired")
    connection.close()
    os._exit(0)


class MemoryTokenPoolTests(unittest.TestCase):
    def test_capacity_and_exact_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(
                soft_limit_bytes=1_000,
                hard_limit_bytes=2_000,
                state_path=Path(temporary) / "state.json",
            )
            first = pool.acquire("first", 400)
            with self.assertRaises(MemoryError):
                pool.acquire("too-large-for-soft-limit", 700)
            pool.release(first)
            second = pool.acquire("second", 700)
            self.assertEqual(pool.snapshot()["active_bytes"], 700)
            pool.release(second)
            self.assertEqual(pool.snapshot()["active_bytes"], 0)
            with self.assertRaises(ValueError):
                pool.release(second)

    def test_exclusive_build_serializes_threads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(1_000, 2_000, Path(temporary) / "state.json")
            active = 0
            maximum = 0
            lock = threading.Lock()
            entered = threading.Event()

            def worker(task_id: str) -> None:
                nonlocal active, maximum
                with pool.acquire(task_id, 400, exclusive_build=True, wait_timeout=2.0):
                    with lock:
                        active += 1
                        maximum = max(maximum, active)
                    entered.set()
                    time.sleep(0.01)
                    with lock:
                        active -= 1

            threads = [threading.Thread(target=worker, args=(f"build-{i}",)) for i in range(2)]
            for thread in threads:
                thread.start()
            self.assertTrue(entered.wait(timeout=2))
            for thread in threads:
                thread.join(timeout=3)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(maximum, 1)
            self.assertEqual(pool.snapshot()["max_active_builds"], 1)

    def test_independent_pool_instances_share_capacity_and_exclusivity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            first_pool = MemoryTokenPool(1_000, 2_000, state_path)
            second_pool = MemoryTokenPool(1_000, 2_000, state_path)
            first = first_pool.acquire("first", 400, exclusive_build=True)
            with self.assertRaises(MemoryError):
                second_pool.acquire("blocked", 100, exclusive_build=True)

            acquired = threading.Event()
            errors: list[BaseException] = []

            def waiter() -> None:
                try:
                    with second_pool.acquire("second", 400, exclusive_build=True, wait_timeout=2.0):
                        acquired.set()
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=waiter)
            thread.start()
            time.sleep(0.03)
            self.assertFalse(acquired.is_set())
            first_pool.release(first)
            self.assertTrue(acquired.wait(timeout=2))
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(first_pool.snapshot()["max_active_builds"], 1)
            self.assertEqual(second_pool.snapshot()["active_bytes"], 0)

    def test_exclusive_build_is_shared_with_a_separate_process(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            pool = MemoryTokenPool(1_000, 2_000, state_path)
            held = pool.acquire("parent", 400, exclusive_build=True)
            parent_connection, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=_acquire_from_child,
                args=(state_path, child_connection),
            )
            process.start()
            child_connection.close()
            try:
                self.assertFalse(parent_connection.poll(0.05))
                pool.release(held)
                self.assertTrue(parent_connection.poll(3.0))
                self.assertEqual(parent_connection.recv(), ("acquired", 1))
            finally:
                process.join(timeout=3)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=3)
                parent_connection.close()
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(pool.snapshot()["active_builds"], 0)

    def test_zombie_process_lease_is_reclaimed_before_waitpid(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            parent_connection, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=_acquire_and_exit_without_release,
                args=(state_path, child_connection),
            )
            process.start()
            child_connection.close()
            try:
                self.assertTrue(parent_connection.poll(3))
                self.assertEqual(parent_connection.recv(), "acquired")
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        stat_text = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii")
                    except OSError:
                        break
                    fields = stat_text[stat_text.rfind(")") + 2 :].split()
                    if fields and fields[0] in {"Z", "X"}:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("child did not reach a terminal process state")

                pool = MemoryTokenPool(1_000, 2_000, state_path)
                with pool.acquire("replacement", 400, exclusive_build=True):
                    self.assertEqual(pool.snapshot()["active_builds"], 1)
                self.assertEqual(pool.snapshot()["history"][0]["status"], "reclaimed")
            finally:
                process.join(timeout=3)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=3)
                parent_connection.close()
            self.assertEqual(process.exitcode, 0)

    def test_context_exception_releases_and_records_status_and_peak_rss(self) -> None:
        class ExpectedFailure(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(1_000, 2_000, Path(temporary) / "state.json")
            with self.assertRaises(ExpectedFailure):
                with pool.lease("failing", 400, exclusive_build=True):
                    raise ExpectedFailure("expected")
            snapshot = pool.snapshot()
            self.assertEqual(snapshot["active_bytes"], 0)
            self.assertEqual(snapshot["active_builds"], 0)
            history = snapshot["history"]
            self.assertEqual(history[-1]["status"], "failed")
            self.assertIsInstance(history[-1]["peak_rss_bytes"], int)
            self.assertGreater(history[-1]["peak_rss_bytes"], 0)

    def test_hard_limit_and_bounded_wait_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(500, 600, Path(temporary) / "state.json")
            with self.assertRaises(MemoryError):
                pool.acquire("over-hard", 601)
            lease = pool.acquire("held", 500)
            try:
                with self.assertRaises(TimeoutError):
                    pool.acquire("blocked", 100, wait_timeout=0.01)
            finally:
                pool.release(lease)

    def test_corrupt_state_and_limit_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "memory token state"):
                MemoryTokenPool(1_000, 2_000, state_path)

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            MemoryTokenPool(1_000, 2_000, state_path)
            with self.assertRaisesRegex(ValueError, "limits"):
                MemoryTokenPool(900, 2_000, state_path)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["soft_limit_bytes"], 1_000)

    def test_state_writer_retries_interruptions_and_short_writes(self) -> None:
        real_write = os.write
        calls = 0

        def unreliable_write(descriptor: int, payload: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise InterruptedError()
            if calls == 2 and len(payload) > 1:
                return real_write(descriptor, payload[: len(payload) // 2])
            return real_write(descriptor, payload)

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "myfuzz.integration.memory_lock.os.write",
            side_effect=unreliable_write,
        ):
            pool = MemoryTokenPool(1_000, 2_000, Path(temporary) / "state.json")
            with pool.acquire("work", 400):
                pass
            self.assertEqual(pool.snapshot()["active_bytes"], 0)
        self.assertGreaterEqual(calls, 4)

    def test_lease_remains_releasable_after_transient_proc_identity_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(1_000, 2_000, Path(temporary) / "state.json")
            with mock.patch(
                "myfuzz.integration.memory_lock._process_start_ticks",
                return_value=None,
            ):
                lease = pool.acquire("work", 400)
            with mock.patch(
                "myfuzz.integration.memory_lock._process_start_ticks",
                return_value=123,
            ):
                pool.release(lease)
            self.assertEqual(pool.snapshot()["active_bytes"], 0)

    def test_post_replace_directory_fsync_error_keeps_acquired_lease_usable(self) -> None:
        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("directory fsync failed after replace")
            real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            pool = MemoryTokenPool(1_000, 2_000, Path(temporary) / "state.json")
            with mock.patch(
                "myfuzz.integration.memory_lock.os.fsync",
                side_effect=fail_directory_fsync,
            ):
                lease = pool.acquire("work", 400, exclusive_build=True)
            self.assertEqual(pool.snapshot()["active_bytes"], 400)
            pool.release(lease)
            self.assertEqual(pool.snapshot()["active_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
