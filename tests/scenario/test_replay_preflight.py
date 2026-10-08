"""Optional topology preflight runs on the actual runner before RTL begins."""

import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.runner import ScenarioRunner
from tests.scenario import test_replay as replay_fixture


class ReplayPreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = replay_fixture.ReplayTests()
        self.fixture.setUp()
        self.runners = []

    def factory(self):
        runner = self.fixture.factory()
        runner.begin_test = Mock(wraps=runner.begin_test)
        runner.identity_document = Mock(wraps=runner.identity_document)
        self.runners.append(runner)
        return runner

    def test_record_rejection_has_one_factory_no_identity_scan_or_rtl(self):
        def reject(runner):
            self.assertIs(runner, self.runners[0])
            self.assertIsInstance(runner, ScenarioRunner)
            raise ValueError("selected edge has no actual binding")

        with patch("myfuzz.scenario.replay.DependencyScheduler.run") as scheduler:
            with self.assertRaisesRegex(ValueError, "selected edge"):
                record_scenario(self.fixture.genome, self.factory,
                                runner_preflight=reject)
        self.assertEqual(1, len(self.runners))
        self.runners[0].begin_test.assert_not_called()
        self.runners[0].identity_document.assert_not_called()
        scheduler.assert_not_called()
        self.assertEqual(0, self.fixture.instances[0].begins)

    def test_success_and_fresh_replay_check_once_on_each_actual_runner(self):
        seen = []

        def check(runner):
            self.assertEqual(0, self.fixture.instances[-1].begins)
            seen.append(runner)

        reference = record_scenario(self.fixture.genome, self.factory,
                                    runner_preflight=check)
        compared = replay_scenario(self.fixture.genome, self.factory, reference,
                                   runner_preflight=check)
        self.assertTrue(compared.matches)
        self.assertEqual(self.runners, seen)
        self.assertEqual([1, 2], [r.identity_document.call_count for r in self.runners])
        self.assertEqual([1, 1], [r.begin_test.call_count for r in self.runners])

    def test_replay_rejection_precedes_identity_and_begin(self):
        reference = record_scenario(self.fixture.genome, self.factory)
        with self.assertRaisesRegex(ValueError, "route mismatch"):
            replay_scenario(self.fixture.genome, self.factory, reference,
                            runner_preflight=Mock(side_effect=ValueError("route mismatch")))
        self.assertEqual(2, len(self.runners))
        self.runners[-1].identity_document.assert_not_called()
        self.runners[-1].begin_test.assert_not_called()

    def test_invalid_hook_rejects_before_constructing_runner(self):
        factory = Mock(side_effect=AssertionError("must not create runner"))
        with self.assertRaisesRegex(ValueError, "preflight"):
            record_scenario(self.fixture.genome, factory, runner_preflight=1)
        reference = record_scenario(self.fixture.genome, self.factory)
        with self.assertRaisesRegex(ValueError, "preflight"):
            replay_scenario(self.fixture.genome, factory, reference,
                            runner_preflight=1)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
