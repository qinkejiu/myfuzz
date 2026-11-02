"""Saved level IRQ groups are reconstructed from actual source samples."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
import pytest
from myfuzz.integration.saved_irq_group import frame_for_sample,rebuild_group
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember
from tests.integration.test_shared_irq_bit_offset import _saved_group_world


def level_world(value=1):
    old,sample,events,runner=_saved_group_world(member_epoch=0)
    group=IrqDeliveryGroup(old.group_id,old.target_component,old.target_port,
        (IrqDeliveryMember('dma','irq',mode='level'),old.members[1]))
    frame=events[0];frame['group_sha256']=group.identity_sha256
    row=frame['members'][0];row['mode']='level';row['value']=value
    raw=runner.get(1);raw['outputs']['irq']=value;raw['outputs']['physical']['dma_irq_wire']=value
    row['latest_native_source']=deepcopy(row['native_source'])
    frame['value']=value;frame['active_sources']=['dma.irq'] if value else []
    frame['unique_source']='dma.irq' if value else None
    frame['attribution_status']='unique' if value else 'unknown'
    for k in ('expected_input','actual_pre_input','actual_post_input'):sample[k]=value
    return group,sample,[raw,runner.get(2),frame],runner


@pytest.mark.parametrize('value',[0,1])
def test_level_sample_must_equal_actual_current_level(value):
    group,sample,events,runner=level_world(value)
    assert frame_for_sample(group,sample,events,runner)['value']==value
    events[-1]['members'][0]['value']=1-value
    with pytest.raises(ValueError):frame_for_sample(group,sample,events,runner)


def test_level_rejects_stale_and_cross_epoch_samples():
    group,sample,events,runner=level_world()
    raw=runner.get(1)
    newer={**deepcopy(raw),'event_id':3,'local_tick':2,'outputs':{'irq':0,'physical':{'dma_irq_wire':0}}}
    events.append(newer)
    with pytest.raises(ValueError,match='latest'):frame_for_sample(group,sample,events,runner)
    events.pop();events[-1]['members'][0]['latest_native_source']['reset_epoch']=1
    with pytest.raises(ValueError,match='epoch'):frame_for_sample(group,sample,events,runner)


@pytest.mark.parametrize('mixed',[False,True])
@pytest.mark.parametrize('schema',['zipdma_selected_profile_contract.v1','declared_f6_dma_source_contract.v1'])
def test_rebuild_real_level_and_mixed_topology(mixed,schema):
    dma=IrqDeliveryMember('dma','irq',mode='level')
    members=(dma,IrqDeliveryMember('gpio','interrupt',pulse_width_ticks=4)) if mixed else (dma,)
    group=IrqDeliveryGroup('g' if mixed else 'f6-dma-irq','cpu','irq',members)
    topology={'bindings':[asdict(b) for b in group.member_bindings()],
        'ownership_inputs':[{'component':'cpu','port':'irq','owners':[{'kind':'bound','width':1,
            'bit_offset':0,'producer_ref':group.owner_ref}]}], 'irq_delivery_groups':[group.document()]}
    digest=sha256(json.dumps(topology,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    contract={'cpu':{'instance_id':'cpu'},'dma':{'instance_id':'dma','source_contract':{'schema_version':schema,'irq_trigger':'level'}},
        'irq':{},'program_contract':{'gpio_irq':{'component':'gpio','group_id':'g'}} if mixed else {}}
    # Source behavior must be verified before this projection in production.
    import myfuzz.integration.f6_dma_behavior as semantics
    from unittest.mock import patch
    with patch.object(semantics,'f6_dma_semantics_from_source',return_value=({},{})):
        assert rebuild_group(contract,{'runtime_topology':topology,'topology_binding':{'topology_sha256':digest}},'irq')==group
