"""Retirement observations explicitly select the authenticated CPU variant."""
from pathlib import Path
import unittest
from unittest.mock import patch

from myfuzz.scenario import ibex_pulp_dual_source as pulp
from myfuzz.scenario import ibex_uart_online as uart


class RetirementProfileSelectionTests(unittest.TestCase):
    def test_opt_in_selects_rvfi_without_changing_default_profile(self):
        for module, name in ((pulp, 'make_ibex_pulp_dual_source_factory'),
                             (uart, 'make_ibex_uart_online_factory')):
            for enabled in (False, True):
                with self.subTest(module=module.__name__, enabled=enabled):
                    with patch.object(module, '_artifact') as render:
                        getattr(module, name)(Path('/tmp/profile-selection'),
                                              cpu_retirement=enabled)
                    expected = ('configs/cpus/ibex_rvfi_local/component_profile.json'
                                if enabled else module.CPU_PROFILE)
                    self.assertEqual((expected, 'cpu'), render.call_args_list[0].args)

    def test_bad_opt_in_rejected_before_any_artifact_work(self):
        for module, name in ((pulp, 'make_ibex_pulp_dual_source_factory'),
                             (uart, 'make_ibex_uart_online_factory')):
            with patch.object(module, '_artifact') as render:
                with self.assertRaises(ValueError):
                    getattr(module, name)(Path('/tmp/profile-selection'), cpu_retirement=1)
                render.assert_not_called()


if __name__ == '__main__':
    unittest.main()
