"""Exercise L1 fixtures in a fresh interpreter with semantic plugins denied."""
import os
from pathlib import Path
import subprocess
import sys


def test_l1_fixture_suite_does_not_import_functional_consumers():
    root = Path(__file__).resolve().parents[2]
    script = '''
import importlib.abc
import sys
class DenyFunctionalConsumers(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('myfuzz.scenario.') and fullname.rsplit('.', 1)[-1] in {
            'gpio_consumption', 'uart_consumption', 'uart_irq_consumption',
            'uart_retired_read', 'uart_operand_seed', 'uart_operand_use',
            'uart_ram_commit', 'uart_store_memory', 'uart_memory_readback'}:
            raise AssertionError('L1 attempted functional import: ' + fullname)
sys.meta_path.insert(0, DenyFunctionalConsumers())
import pytest
sys.exit(pytest.main(['-q', 'tests/scenario/test_ip_plugin_free_fixtures.py']))
'''
    env = dict(os.environ, PYTHONPATH=str(root / 'src'), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    result = subprocess.run([sys.executable, '-c', script], cwd=root, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert ' passed' in result.stdout
