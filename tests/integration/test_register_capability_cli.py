"""CLI preserves trusted replay's optional preflight report and default layout."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def cli_module():
    spec=importlib.util.spec_from_file_location('register_capability_cli',Path('scripts/run_ibex_pulp_online.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('report', [None, {'schema_version':'register_program_capability_preflight.v1',
    'requested_minimum_level':'L1','verification':None,'grants_functional':False,
    'targets':{'gpio_a':{'assessment':{'effective_level':'L1','verified_level':None,'gaps':['narrow-read']}}}}])
def test_cli_reports_actual_optional_preflight_without_changing_default_fields(report):
    module=cli_module()
    result=SimpleNamespace(matches=True,verification_scope=('register_program_reconstruction',),
        capability_preflight=report,comparison=SimpleNamespace(first_difference=None,difference_context=None,
        actual_trace=SimpleNamespace(events=({},),semantic_sha256='a'*64)))
    output=io.StringIO()
    with patch.object(module,'replay_ibex_pulp_register_files',return_value=result) as replay,redirect_stdout(output):
        assert module.main(['replay-register-programs','--cache-dir','cache','--run-dir','saved'])==0
    document=json.loads(output.getvalue())
    expected=dict(matches=True,verification_scope=['register_program_reconstruction'],event_count=1,
        semantic_sha256='a'*64,first_difference=None,difference_context=None)
    if report is not None:
        expected['capability_preflight']=report
    assert document==expected
    replay.assert_called_once_with(cache_dir=Path('cache'),output_dir=Path('saved'))
