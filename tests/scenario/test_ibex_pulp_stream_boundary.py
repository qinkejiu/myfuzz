"""The online Ibex instruction reservation has a fixed execution boundary."""

import unittest

from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_stream_bootstrap,
)


class IbexPulpStreamBoundaryTest(unittest.TestCase):
    def test_default_reservation_uses_ram_before_isr_scratch(self) -> None:
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
        self.assertEqual(bootstrap.instruction_end, 0x2fe00)
        self.assertLessEqual(bootstrap.instruction_end + 64, 0x2ff00)

    def test_guard_cannot_overlap_isr_scratch(self) -> None:
        with self.assertRaises(ValueError):
            make_ibex_pulp_dual_source_stream_bootstrap(instruction_end=0x2ff00)

    def test_fixed_self_loop_follows_last_mutable_instruction(self) -> None:
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
        end = bootstrap.instruction_end
        tail = [image for image in bootstrap.template.initial_images
                if image.address <= end < image.address + len(image.data)]

        self.assertEqual(len(tail), 1)
        image = tail[0]
        offset = end - image.address
        self.assertEqual(image.data[offset:offset + 64],
                         bytes.fromhex("6f000000") * 16)
        self.assertGreaterEqual(image.address, end)


if __name__ == "__main__":
    unittest.main()
