"""Run-budget selection is explicit and settled before process preparation."""
import json
from pathlib import Path

import pytest

from myfuzz.runtime import generic_campaign
from tests.runtime.test_generic_mixed_entry import descriptor


@pytest.mark.parametrize('value', [0, -1, 65537, True, 1.5])
def test_invalid_round_override_is_refused_before_any_output(tmp_path, monkeypatch, value):
    def no_prepare(**kwargs):
        pytest.fail('invalid budget reached harness preparation')
    monkeypatch.setattr(generic_campaign, 'create_preparation', no_prepare)
    with pytest.raises(generic_campaign.GenericScenarioRefused):
        generic_campaign.run_descriptor(
            descriptor(), flow='F4', mode='original', case_root=tmp_path / 'run',
            base_dir=Path(__file__).resolve().parents[2], rounds=value)
    assert not (tmp_path / 'run').exists()


@pytest.mark.parametrize('override, expected', [(None, 128), (1, 1), (32, 32),
                                                 (65536, 65536)])
def test_effective_rounds_preserve_the_exact_selected_budget(override, expected):
    assert descriptor().rounds == 128
    assert generic_campaign.resolve_rounds(descriptor(), override) == expected


@pytest.mark.parametrize('arguments, expected', [([], None), (['--rounds', '32'], 32)])
def test_scenario_cli_forwards_rounds_to_the_actual_entry(monkeypatch, capsys, arguments, expected):
    from scripts import run_generic_scenario

    calls = []
    def run(desc, **kwargs):
        calls.append(kwargs)
        return {'scenario': desc.scenario_id, 'flow': kwargs['flow'], 'mode': kwargs['mode'],
                'case_count': 1, 'replay_matches': True, 'wall_seconds': 1,
                'plan_identity_sha256': 'a' * 64, 'rounds_per_case': expected or desc.rounds}
    monkeypatch.setattr(run_generic_scenario, 'run_descriptor', run)
    result = run_generic_scenario.main([
        '--descriptor', str(Path(__file__).resolve().parents[2] /
                            'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'),
        '--flow', 'F4', '--mode', 'original', '--case', '/tmp/unused-rounds-test',
        *arguments])
    assert result == 0
    assert len(calls) == 1 and calls[0]['rounds'] == expected
    assert json.loads(capsys.readouterr().out)['rounds_per_case'] == (expected or 128)


def test_cli_enables_bounded_actual_command_capture(monkeypatch, capsys):
    from scripts import run_generic_scenario
    from myfuzz.local_harness.session import LocalCommandTrace

    calls = []
    def run(desc, **kwargs):
        calls.append(kwargs)
        return {'scenario': desc.scenario_id, 'flow': kwargs['flow'], 'mode': kwargs['mode'],
                'case_count': 1, 'replay_matches': True, 'wall_seconds': 1,
                'plan_identity_sha256': 'a' * 64, 'rounds_per_case': 32}
    monkeypatch.setattr(run_generic_scenario, 'run_descriptor', run)
    result = run_generic_scenario.main([
        '--descriptor', str(Path(__file__).resolve().parents[2] /
                            'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'),
        '--flow', 'F4', '--mode', 'original', '--case', '/tmp/unused-trace-test',
        '--record-local-commands'])
    assert result == 0
    assert isinstance(calls[0]['command_trace'], LocalCommandTrace)
