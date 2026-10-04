import dataclasses
import unittest

from myfuzz.local_harness import LocalHarnessRequest, load_local_harness_request


GOOD = {
    "schema_version": "local_harness.v1",
    "profile_path": "configs/peripherals/pulp_gpio/component_profile.json",
    "instance_id": "gpio_a",
    "reset_assert_ticks": 8,
    "reset_release_ticks": 8,
    "max_wait_cycles": 16,
}


class LocalHarnessRequestTests(unittest.TestCase):
    def test_round_trip_is_canonical_and_frozen(self):
        request = load_local_harness_request(GOOD)
        self.assertIsInstance(request, LocalHarnessRequest)
        self.assertEqual(request.document(), GOOD)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.instance_id = "other"
        document = request.document()
        document["instance_id"] = "other"
        self.assertEqual(request.document(), GOOD)

    def test_reject_unknown_and_missing_fields(self):
        with self.assertRaisesRegex(ValueError, "unexpected-request-fields"):
            load_local_harness_request({**GOOD, "raw_sv": "assign irq=1;"})
        for field in GOOD:
            with self.subTest(field=field):
                document = dict(GOOD)
                del document[field]
                with self.assertRaisesRegex(ValueError, "missing-request-fields"):
                    load_local_harness_request(document)

    def test_reject_schema_and_non_mapping(self):
        for value in (None, [], "request"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_local_harness_request(value)
        for value in (None, True, "local_harness.v2"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid-schema-version"):
                load_local_harness_request({**GOOD, "schema_version": value})

    def test_reject_invalid_profile_paths(self):
        for path in ("../outside.json", "/configs/component_profile.json", "configs//component_profile.json",
                     "configs/./component_profile.json", "configs/../component_profile.json",
                     "configs\\component_profile.json", "other/component_profile.json",
                     "configs/foo.json", "configs/foo/component_profile.json/", "configs/\x00/component_profile.json", None):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "invalid-profile-path"):
                load_local_harness_request({**GOOD, "profile_path": path})

    def test_instance_ids(self):
        for value in ("a", "CPU_01", "gpio_a"):
            self.assertEqual(load_local_harness_request({**GOOD, "instance_id": value}).instance_id, value)
        for value in ("", "0cpu", "_cpu", "cpu-a", "cpu\n", "é", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid-instance-id"):
                load_local_harness_request({**GOOD, "instance_id": value})

    def test_timing_bounds_and_types(self):
        for field, minimum in (("reset_assert_ticks", 1), ("reset_release_ticks", 0), ("max_wait_cycles", 1)):
            for value in (minimum, 1024):
                with self.subTest(field=field, value=value):
                    self.assertEqual(load_local_harness_request({**GOOD, field: value}).document()[field], value)
            for value in (minimum - 1, 1025, True, False, 1.0, "8", None):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "invalid-" + field.replace("_", "-")):
                    load_local_harness_request({**GOOD, field: value})
