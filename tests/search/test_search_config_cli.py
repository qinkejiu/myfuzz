import json
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]

def test_closed_config_rejects_python_factory(tmp_path):
    from myfuzz.search.config import load_scenario
    p = tmp_path / 'bad.json'
    p.write_text(json.dumps({'schema_version': 'dependency_search_scenario.v1', 'name':'bad', 'backend':'descriptor', 'descriptor':'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json', 'flow':'F4', 'records':['55000000'], 'goal':{'id':'completion'}, 'factory':'os.system'}))
    with pytest.raises(ValueError, match='unknown'):
        load_scenario(p, ROOT)

def test_shipped_scenarios_validate():
    from myfuzz.search.config import load_scenario
    scenarios = [load_scenario(p, ROOT) for p in sorted((ROOT/'configs/search').glob('*.json'))]
    assert len(scenarios) >= 4
    assert {s['flow'] for s in scenarios} >= {'mixed', 'F5', 'F6'}

def test_plan_only_needs_no_execution_arguments():
    result = subprocess.run([sys.executable, str(ROOT/'scripts/run_dependency_search.py'), '--scenario', 'configs/search/timer-ibex.json', '--plan-only'], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    plan=json.loads(result.stdout)
    assert plan['scenario_identity'].startswith('sha256:')
    assert plan['source_sha'].startswith('sha256:')
    assert plan['backend'] in {'storage','descriptor'}
    assert 'shared_catalog_identity' in plan
    assert plan['catalog_materialized'] is False

def test_config_rejects_path_escape_and_nonfinite_records(tmp_path):
    from myfuzz.search.config import load_scenario
    base={'schema_version':'dependency_search_scenario.v1','name':'bad','backend':'descriptor','descriptor':'../x.json','flow':'F4','records':['00'],'goal':{'id':'completion'}}
    p=tmp_path/'bad.json'
    p.write_text(json.dumps(base))
    with pytest.raises(ValueError): load_scenario(p, ROOT)

@pytest.mark.parametrize('name', ['timer-ibex','spi-cv32e40p','gpio-f5','dma-f6','memory-mixed-ibex'])
def test_all_shipped_preflights_are_nonexecuting(name):
    result=subprocess.run([sys.executable,str(ROOT/'scripts/run_dependency_search.py'),'--scenario',f'configs/search/{name}.json','--preflight'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
    plan=json.loads(result.stdout)
    assert plan['native_executed'] is False
    if name in {'gpio-f5','dma-f6'}:
        assert plan['live_state_conditioned'] is False
        assert plan['state_observation']=='unknown'

def test_default_help_names_gpio_scope():
    result=subprocess.run([sys.executable,str(ROOT/'scripts/run_dependency_search.py'),'--help'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode == 0
    assert 'Ibex dual GPIO' in ' '.join(result.stdout.split())
    assert 'research/' not in (ROOT/'scripts/run_dependency_search.py').read_text()

def test_storage_config_cannot_silently_fall_back(tmp_path):
    from myfuzz.search.config import load_scenario
    config=json.loads((ROOT/'configs/search/timer-ibex.json').read_text())
    config['records']=['F4:55000000']
    p=tmp_path/'bad.json'; p.write_text(json.dumps(config))
    with pytest.raises(ValueError,match='storage'):
        load_scenario(p,ROOT)

def test_memory_mixed_configuration_has_all_memory_flows():
    from myfuzz.search.config import load_scenario
    c=load_scenario(ROOT/'configs/search/memory-mixed-ibex.json',ROOT)
    assert {r.split(':')[0] for r in c['records']}=={'F1','F2','F3','F4'}

def test_scenario_gpio_uses_campaign_modes_and_checks_fresh_identity(tmp_path,monkeypatch):
    from myfuzz.search import cli, gpio_search
    scenario=tmp_path/'gpio.json'
    scenario.write_text(json.dumps({'schema_version':'dependency_search_scenario.v1','name':'gpio','backend':'gpio','goal':{'id':'gpio-label'}}))
    calls=[]
    def execute(argv):
        calls.append(argv)
        output = Path(argv[argv.index('--output')+1])
        output.mkdir(parents=True)
        (output/'search-summary.json').write_text(json.dumps({
            'status':'completed', 'mode':argv[argv.index('--mode')+1],
            'verification':{'session_boundary':{'status':'verified','matches':True}}}))
        return 0
    monkeypatch.setattr(gpio_search,'main',execute)
    args=['--scenario',str(scenario),'--cases','1','--seconds','1','--seed','7','--output',str(tmp_path/'run'),'--cache',str(tmp_path/'cache')]
    assert cli.main(args+['--mode','original'])==0
    assert calls[-1][calls[-1].index('--execution-mode')+1]=='search'
    assert calls[-1][calls[-1].index('--output')+1]==str(tmp_path/'run/original')
    assert (tmp_path/'run/original/search-configuration.json').is_file()
    assert cli.main(args+['--mode','fresh'])==0
    assert calls[-1][calls[-1].index('--original')+1]==str(tmp_path/'run/original')
    assert (tmp_path/'run/fresh/search-configuration.json').is_file()
    c=json.loads(scenario.read_text());c['name']='changed';scenario.write_text(json.dumps(c))
    with pytest.raises(SystemExit): cli.main(args+['--mode','fresh'])
    assert len(calls)==2

@pytest.mark.parametrize('flow, record', [('F1','13000000'),('F3','55000000')])
def test_memory_single_flow_preflight_validates_lowering(tmp_path, flow, record):
    config={'schema_version':'dependency_search_scenario.v1','name':flow,'backend':'descriptor',
            'descriptor':'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json',
            'flow':flow,'records':[record], 'goal':{'id':'completion'}}
    path=tmp_path/'scenario.json'; path.write_text(json.dumps(config))
    result=subprocess.run([sys.executable,str(ROOT/'scripts/run_dependency_search.py'),'--scenario',str(path),'--preflight'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0, result.stderr
    data=json.loads(result.stdout)
    assert data['flow']==flow and data['state_observation']=='unknown'
    config['records']=['F4:55000000'];path.write_text(json.dumps(config))
    bad=subprocess.run([sys.executable,str(ROOT/'scripts/run_dependency_search.py'),'--scenario',str(path),'--preflight'],cwd=ROOT,capture_output=True,text=True)
    assert bad.returncode!=0
