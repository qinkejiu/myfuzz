"""External input sequences are replayed through the same generic entry."""
import json
from pathlib import Path

import pytest

from scripts import run_generic_scenario


ROOT = Path(__file__).resolve().parents[2]
BASE = ['--descriptor', str(ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'),
        '--flow', 'mixed', '--mode', 'original', '--case', '/tmp/unused-external-sequence-test']


def test_external_file_forwards_ordered_cases_to_shared_runtime(tmp_path, monkeypatch, capsys):
    source = tmp_path / 'inputs.json'
    source.write_text(json.dumps(['F4:55000000', 'F2:04100040']), encoding='utf-8')
    calls = []
    def run(desc, **kwargs):
        calls.append(kwargs)
        return {'scenario': desc.scenario_id, 'flow': kwargs['flow'], 'mode': kwargs['mode'],
                'case_count': 2, 'replay_matches': True, 'wall_seconds': 1,
                'plan_identity_sha256': 'a' * 64, 'rounds_per_case': 32}
    monkeypatch.setattr(run_generic_scenario, 'run_descriptor', run)
    assert run_generic_scenario.main([*BASE, '--records-file', str(source)]) == 0
    assert calls[0]['sequence'] == ['F4:55000000', 'F2:04100040']
    assert json.loads(capsys.readouterr().out)['cases'] == 2


@pytest.mark.parametrize('contents', ['{}', '[]', '[1]', '"F1:13000000"', '[', 'null'])
def test_invalid_external_file_refused_without_preparing(tmp_path, monkeypatch, capsys, contents):
    source = tmp_path / 'inputs.json'
    source.write_text(contents, encoding='utf-8')
    monkeypatch.setattr(run_generic_scenario, 'run_descriptor', lambda *a, **kw: pytest.fail('prepared'))
    assert run_generic_scenario.main([*BASE, '--records-file', str(source)]) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'refused'


def test_missing_external_file_refused_without_preparing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_generic_scenario, 'run_descriptor', lambda *a, **kw: pytest.fail('prepared'))
    assert run_generic_scenario.main([*BASE, '--records-file', str(tmp_path / 'missing.json')]) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'refused'
