"""Cold-start timing is a separate startup-cost comparison."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.bench_ibex_pulp_cold_start import load_first_records, measure_cold_cases


class _FakeDecoder:
    def __init__(self):
        self.committed = []

    def decode(self, raw, *, coverage_hints):
        self.raw = raw
        self.hints = coverage_hints
        return type("Case", (), {"path_id": "path-a", "case_id": "cold",
                                  "source": type("Source", (), {
                                      "action_id": "cold:cpu.online_instruction"})()})()

    def commit(self, case):
        self.committed.append(case)


class _FakeSession:
    def __init__(self):
        self.submitted = []
        self.finished = 0

    def submit_case(self, case):
        self.submitted.append(case)
        return type("Receipt", (), {"status": "running", "violations": ()})()

    def finish(self):
        self.finished += 1
        return type("Trace", (), {"status": "complete"})()


class ColdBaselineTests(unittest.TestCase):
    def test_optional_fresh_replay_records_exact_match_outside_cold_timing(self):
        row = {"online_raw_records_hex": ["0102030405060708"],
               "online_weights": {"cpu.online_instruction": 7},
               "applied_sources": ["cpu.online_instruction"],
               "path_id": "path-a", "status": "complete"}
        runtime = type("Runtime", (), {})()
        runtime.decoder = _FakeDecoder()
        runtime.session = _FakeSession()
        observed = []

        def replay(trace):
            observed.append(trace)
            return type("Comparison", (), {"matches": True,
                "first_difference": None, "verification_scope": "full"})()

        runtime.replay = replay
        times = iter(range(0, 20))
        result = measure_cold_cases([row], lambda index: runtime,
                                    clock=lambda: next(times), verify_replay=True)[0]
        self.assertEqual(1, len(observed))
        self.assertEqual("complete", observed[0].status)
        self.assertEqual(4, result["total_seconds"])
        self.assertEqual(1, result["replay_seconds"])
        self.assertTrue(result["replay_matches"])
        self.assertIsNone(result["replay_first_difference"])
        self.assertEqual("full", result["replay_verification_scope"])

    def test_optional_fresh_replay_fails_closed_on_difference(self):
        row = {"online_raw_records_hex": ["0102030405060708"],
               "online_weights": {"cpu.online_instruction": 7},
               "applied_sources": ["cpu.online_instruction"],
               "path_id": "path-a", "status": "complete"}
        runtime = type("Runtime", (), {})()
        runtime.decoder = _FakeDecoder()
        runtime.session = _FakeSession()
        runtime.replay = lambda trace: type("Comparison", (), {
            "matches": False, "first_difference": 3,
            "verification_scope": "full"})()
        times = iter(range(0, 20))
        result = measure_cold_cases([row], lambda index: runtime,
                                    clock=lambda: next(times),
                                    verify_replay=True)[0]
        self.assertFalse(result["replay_matches"])
        self.assertEqual(3, result["replay_first_difference"])

    def test_uses_one_fresh_runtime_per_record_and_preserves_raw_weights(self):
        records = [
            {"online_raw_records_hex": ["0102030405060708"],
             "online_weights": {"cpu.online_instruction": 7},
             "applied_sources": ["cpu.online_instruction"],
             "path_id": "path-a", "status": "complete"},
            {"online_raw_records_hex": ["0807060504030201"],
             "online_weights": {"cpu.online_instruction": 3},
             "applied_sources": ["cpu.online_instruction"],
             "path_id": "path-a", "status": "complete"},
        ]
        runtimes = []

        def make_runtime(index):
            runtime = type("Runtime", (), {})()
            runtime.decoder = _FakeDecoder()
            runtime.session = _FakeSession()
            runtimes.append(runtime)
            return runtime

        times = iter(range(0, 100))
        results = measure_cold_cases(records, make_runtime, clock=lambda: next(times))
        self.assertEqual(2, len(runtimes))
        self.assertEqual([bytes.fromhex(row["online_raw_records_hex"][0])
                          for row in records], [runtime.decoder.raw for runtime in runtimes])
        self.assertEqual([row["online_weights"] for row in records],
                         [runtime.decoder.hints for runtime in runtimes])
        self.assertEqual([1, 1], [runtime.session.finished for runtime in runtimes])
        self.assertTrue(all(result["source_compatible"] and result["path_compatible"]
                            for result in results))
        self.assertTrue(all(result["init_seconds"] == 1 and
                            result["decode_seconds"] == 1 and
                            result["execute_seconds"] == 1 and
                            result["finish_seconds"] == 1 for result in results))

    def test_loader_accepts_only_first_n_eight_byte_records(self):
        row = {"online_raw_records_hex": ["0001020304050607"],
               "online_weights": {"cpu.online_instruction": 1},
               "applied_sources": ["cpu.online_instruction"],
               "path_id": "path-a", "status": "complete"}
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
            self.assertEqual(1, len(load_first_records(path, 1)))
            with self.assertRaisesRegex(ValueError, "at most 30"):
                load_first_records(path, 31)
            invalid = dict(row, online_raw_records_hex=["00"])
            path.write_text(json.dumps(invalid) + "\n")
            with self.assertRaisesRegex(ValueError, "eight-byte"):
                load_first_records(path, 1)

    def test_failed_submit_is_charged_to_execution_and_runtime_is_finished(self):
        class FailingSession(_FakeSession):
            def submit_case(self, case):
                raise RuntimeError("local step failed")

        runtime = type("Runtime", (), {})()
        runtime.decoder = _FakeDecoder()
        runtime.session = FailingSession()
        row = {"online_raw_records_hex": ["0102030405060708"],
               "online_weights": {"cpu.online_instruction": 7},
               "applied_sources": ["cpu.online_instruction"],
               "path_id": "path-a", "status": "complete"}
        times = iter(range(0, 20))
        result = measure_cold_cases([row], lambda index: runtime,
                                    clock=lambda: next(times))[0]
        self.assertEqual(1, result["execute_seconds"])
        self.assertEqual(1, result["finish_seconds"])
        self.assertEqual("error", result["cold_status"])
        self.assertEqual(1, runtime.session.finished)


if __name__ == "__main__":
    unittest.main()
