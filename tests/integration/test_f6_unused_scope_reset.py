"""Policy scope restart tests, without native reset evidence claims."""
import pytest
from tests.integration.f6_compiled_support import inputs,source_versions
from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
from myfuzz.scenario.ledger import TransactionKey


def test_new_execution_can_restart_only_untouched_ready_scope(inputs):
    policy=F6RamDmaPolicy(inputs[0]['execution_contract'])
    policy.begin_case('old-native','same-testcase')
    policy.begin_case('reset-native','same-testcase')
    assert policy.state=='ready' and policy._scope==('reset-native','same-testcase')
    assert policy.records==[] and policy._pending is None


@pytest.mark.parametrize('condition',['same_execution','armed','pending','fault','record','key','read'])
def test_restart_never_cancels_active_or_dirty_transfer(inputs,condition):
    contract=inputs[0]['execution_contract'];policy=F6RamDmaPolicy(contract)
    policy.begin_case('old-native','same-testcase')
    execution='reset-native'
    if condition=='same_execution':execution='old-native'
    elif condition in ('armed','pending'):
        policy.begin_transfer(case_id='logical0',source_versions=source_versions(contract))
        if condition=='pending':
            key=TransactionKey('old-native','same-testcase',contract['dma']['instance_id'],0,'dma-memory',1)
            policy.accepted(key,address=contract['program_contract']['source_address'],write=False,value=0,byte_enable=15,target=None)
    elif condition=='fault':policy._fault=object()
    elif condition=='record':policy._records=[{'unsettled':True}]
    elif condition=='key':policy._keys={'unsettled'}
    elif condition=='read':policy._read=1
    before=(policy.state,policy._scope,policy._pending,policy._case,policy.records)
    with pytest.raises(ValueError,match='active or faulted'):
        policy.begin_case(execution,'same-testcase')
    assert (policy.state,policy._scope,policy._pending,policy._case,policy.records)==before
