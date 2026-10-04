"""Generated local harness stages are discoverable as public interfaces."""
import unittest

from myfuzz import local_harness


class LocalHarnessPublicApiTests(unittest.TestCase):
    def test_generated_runtime_pipeline_is_exported(self):
        for name in ('render_local_driver', 'build_local_harness',
                     'GeneratedLocalSession', 'GeneratedPulpGpioSession'):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(local_harness, name, None)))


if __name__ == '__main__':
    unittest.main()
