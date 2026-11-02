from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

from myfuzz.integration.compiled_f4 import _compare_prefixes


def test_full_comparison_accepts_shared_f5_without_storage_prerequisites():
    prefix={'records':[{'raw':'0000000100000000','flow':'F5','certificate':
        {'schema_version':'compiled_shared_F5_case.v1','irq_consumption':'unknown'}}],
        'semantic_hash':'same'}
    assert _compare_prefixes(prefix,deepcopy(prefix))['matches'] is True
    changed=deepcopy(prefix);changed['records'][0]['raw']='0000000000000000'
    assert _compare_prefixes(prefix,changed)['matches'] is False


def test_script_requires_actual_full_fresh_match():
    spec=importlib.util.spec_from_file_location('shared_f5_cli',Path(__file__).parents[2]/'scripts/run_shared_f5_campaign.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for replay in ({}, {'matches':False,'verification_scope':'full'},
                   {'matches':True,'verification_scope':'partial'}):
        with pytest.raises(ValueError):module.require_full_fresh_match(replay)
    assert module.require_full_fresh_match({'matches':True,'verification_scope':'full',
        'expected_semantic_hash':'a','actual_semantic_hash':'a'})['matches'] is True


def test_backend_advertises_actual_shared_flows_and_routes_f5():
    from types import SimpleNamespace
    from myfuzz.runtime.flows.mixed import MixedStorageFlowBackend
    calls=[]
    runtime=SimpleNamespace(_mixed_flows=True,_memory_flows=True,_f2_flows=False,
        _f5_preparation=object(),submit=lambda raw,**kw:(calls.append((raw,kw)) or {'flow_id':'F5'}),
        runner=object(),session=object(),records=[],finish=lambda:None,feedback=lambda:{},execution_binding=object())
    backend=MixedStorageFlowBackend(runtime=runtime)
    assert backend.flows==frozenset(('F1','F3','F4','F5'))
    with pytest.raises(ValueError):backend.require_flow('F2')
    channel=backend.open();channel._begun=True
    assert channel.submit(b'\0'*8,flow_id='F5')=={'flow_id':'F5'}
    assert calls==[(b'\0'*8,{'flow':'F5'})]


def test_optin_script_rejects_bootstrap_without_actual_irq_isr_chain():
    spec=importlib.util.spec_from_file_location('shared_f5_irq_cli',Path(__file__).parents[2]/'scripts/run_shared_f5_campaign.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(ValueError,match='chain-not-verified'):
        module.require_irq_chain({'records':[],'irq_bootstrap':{'actual_MMIO_events':[1,2,3,4]}})


def test_irq_script_keeps_raw_trace_when_chain_check_fails(tmp_path):
    import gzip,json
    from types import SimpleNamespace
    spec=importlib.util.spec_from_file_location('shared_f5_raw_cli',Path(__file__).parents[2]/'scripts/run_shared_f5_campaign.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    trace=SimpleNamespace(status='complete',local_ticks={'cpu':10},events=[{'kind':'cpu_retire','pc_wdata':0,'pc_rdata':0x10454}])
    path=tmp_path/'trace.json.gz';module.save_raw_trace(path,trace)
    with pytest.raises(ValueError):module.require_irq_chain({'records':[]})
    with gzip.open(path,'rt') as stream:observed=json.load(stream)
    assert observed=={'status':trace.status,'local_ticks':trace.local_ticks,'events':trace.events}
