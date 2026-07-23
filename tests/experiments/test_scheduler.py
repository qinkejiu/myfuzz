from __future__ import annotations

import copy
import unittest

from myfuzz.experiments import JobKind, plan_jobs


MIB = 1024 * 1024


def manifest(candidate: str, cache_key: str, peak_mib: int, seeds: list[int]) -> dict[str, object]:
    return {
        "schema_version": "candidate_manifest.v1",
        "candidate_id": candidate,
        "build_cache_key": cache_key,
        "resources": {"peak_rss_bytes": peak_mib * MIB},
        "seeds": seeds,
    }


class SchedulerTest(unittest.TestCase):
    def test_plan_serializes_builds_and_limits_fuzz_slots_from_rss(self) -> None:
        jobs = plan_jobs(
            [manifest("candidate-a", "cache-a", 300, [7, 3]), manifest("candidate-b", "cache-b", 300, [5])],
            host_memory_mib=750,
            max_workers=8,
        )

        builds = [job for job in jobs if job.kind is JobKind.BUILD]
        fuzzes = [job for job in jobs if job.kind is JobKind.FUZZ]
        self.assertEqual(2, len(builds))
        self.assertEqual({"build"}, {job.gate_name for job in builds})
        self.assertEqual(3, len(fuzzes))
        self.assertEqual({2}, {job.worker_limit for job in fuzzes})
        self.assertEqual({"fuzz-slot-0", "fuzz-slot-1"}, {job.gate_name for job in fuzzes})

    def test_planning_is_deterministic_for_reordered_manifests_and_seeds(self) -> None:
        left = [manifest("candidate-a", "cache-a", 200, [9, 1]), manifest("candidate-b", "cache-b", 200, [4])]
        right = copy.deepcopy(list(reversed(left)))
        right[1]["seeds"] = list(reversed(right[1]["seeds"]))

        self.assertEqual(
            plan_jobs(left, host_memory_mib=800, max_workers=3),
            plan_jobs(right, host_memory_mib=800, max_workers=3),
        )

    def test_planning_rejects_a_host_that_cannot_fit_one_measured_worker(self) -> None:
        with self.assertRaisesRegex(ValueError, "host memory cannot fit one measured worker"):
            plan_jobs([manifest("candidate-a", "cache-a", 801, [1])], host_memory_mib=800, max_workers=1)

    def test_shared_build_cache_reserves_the_highest_observed_rss(self) -> None:
        jobs = plan_jobs(
            [manifest("candidate-a", "shared-cache", 128, [1]), manifest("candidate-b", "shared-cache", 300, [2])],
            host_memory_mib=900,
            max_workers=4,
        )

        builds = [job for job in jobs if job.kind is JobKind.BUILD]
        self.assertEqual(1, len(builds))
        self.assertEqual(300, builds[0].requested_mib)


if __name__ == "__main__":
    unittest.main()
