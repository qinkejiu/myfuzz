import json
import tempfile
import unittest
from pathlib import Path

from scripts.runs.run_sequential_coverage_pilot import CoverageAccumulator, JOBS


class CoverageAccumulatorTest(unittest.TestCase):
    def test_campaign_uses_real_opentitan_and_rvx_pairs(self) -> None:
        by_target: dict[str, list] = {}
        for job in JOBS:
            by_target.setdefault(job.target, []).append(job)

        self.assertEqual(
            set(by_target), {"ibex_opentitan_real_ip", "rvx_multicomponent"}
        )
        for jobs in by_target.values():
            self.assertEqual(
                {job.scheme for job in jobs},
                {"baseline_direct_slice", "depaware_projection"},
            )
            self.assertEqual(len({job.coverage_total for job in jobs}), 1)

    def test_only_reads_new_entries_and_ignores_protocol_padding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp)
            (queue / "entry_0.json").write_text(json.dumps({"trace_bits": [1, 0, 2, 9]}))
            accumulator = CoverageAccumulator(3)
            self.assertEqual(accumulator.update(queue), 2)
            (queue / "entry_1.json").write_text(json.dumps({"trace_bits": [0, 3, 0, 9]}))
            self.assertEqual(accumulator.update(queue), 3)
            self.assertEqual(accumulator.processed_entries, 2)


if __name__ == "__main__":
    unittest.main()
