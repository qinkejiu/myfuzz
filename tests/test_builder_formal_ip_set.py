import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import formal_axi_lite_ip_set, formal_ip_windows, validate_formal_ip_sources


class FormalIPSetTest(unittest.TestCase):
    def test_frozen_set_has_six_types_eight_instances_and_nonzero_primary_points(self):
        ips = formal_axi_lite_ip_set()
        self.assertEqual(len(ips), 8)
        self.assertEqual(len({ip.type_id for ip in ips}), 6)
        self.assertTrue(all(ip.primary_point_count > 0 for ip in ips))
        self.assertEqual(len({ip.instance_id for ip in ips}), len(ips))
        self.assertEqual(sum(ip.primary_point_count for ip in ips), 97)

    def test_addresses_are_deterministic_nonoverlapping_and_sources_exist(self):
        windows = sorted(formal_ip_windows(), key=lambda item: item.base)
        for left, right in zip(windows, windows[1:]):
            self.assertLessEqual(left.base + left.size, right.base)
        validate_formal_ip_sources(ROOT / "materials")


if __name__ == "__main__":
    unittest.main()
