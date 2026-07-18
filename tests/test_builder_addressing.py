import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    AddressIntent,
    AddressMode,
    AddressRequest,
    InputValidationError,
    allocate_addresses,
)


def fixed(module, base, size, alignment=None):
    return AddressIntent(module, AddressRequest(AddressMode.FIXED, size, base, alignment))


def auto(module, size, alignment=None):
    return AddressIntent(module, AddressRequest(AddressMode.AUTO, size, None, alignment))


class AddressAllocatorTest(unittest.TestCase):
    def test_fixed_and_auto_requests_remain_separate_from_windows(self):
        plan = allocate_addresses([fixed("rom", 0x1000, 0x300), auto("uart", 0x180)])
        entries = {entry.window.module: entry for entry in plan.entries}
        self.assertEqual(entries["rom"].intent.request.mode, AddressMode.FIXED)
        self.assertEqual(entries["rom"].window.source, "user_fixed")
        self.assertEqual(entries["uart"].intent.request.mode, AddressMode.AUTO)
        self.assertEqual(entries["uart"].window.source, "system_auto")

    def test_exact_non_power_of_two_size_is_preserved(self):
        window = allocate_addresses([auto("regs", 0x180)]).windows[0]
        self.assertEqual(window.size, 0x180)
        self.assertEqual(window.upper - window.base, 0x180)
        self.assertTrue(window.contains(window.upper - 1))
        self.assertFalse(window.contains(window.upper))

    def test_fixed_windows_are_locked_before_auto_placement(self):
        plan = allocate_addresses([
            auto("large", 0x800, 0x800),
            fixed("locked", 0, 0x1000),
            auto("small", 0x100, 0x100),
        ])
        windows = {window.module: window for window in plan.windows}
        self.assertEqual(windows["locked"].base, 0)
        self.assertEqual(windows["large"].base, 0x1000)
        self.assertEqual(windows["small"].base, 0x1800)

    def test_input_order_does_not_change_map(self):
        requests = [auto("b", 0x100), fixed("locked", 0x1000, 0x200), auto("a", 0x300)]
        forward = allocate_addresses(requests).windows
        reverse = allocate_addresses(reversed(requests)).windows
        self.assertEqual(forward, reverse)

    def test_overlapping_fixed_windows_fail(self):
        with self.assertRaisesRegex(InputValidationError, "overlap.*second.*first"):
            allocate_addresses([fixed("first", 0x1000, 0x200), fixed("second", 0x1100, 0x100)])

    def test_upper_bound_overflow_fails(self):
        with self.assertRaisesRegex(InputValidationError, "exceeds address space"):
            allocate_addresses([fixed("bad", 0xF00, 0x200)], address_width=12)

    def test_unplaceable_auto_window_fails(self):
        with self.assertRaisesRegex(InputValidationError, "cannot place"):
            allocate_addresses(
                [fixed("locked", 0, 0xF00), auto("bad", 0x200, 0x100)],
                address_width=12,
            )


if __name__ == "__main__":
    unittest.main()
