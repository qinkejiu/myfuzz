"""Offline OR-group joins against the bound topology and actual raw samples."""
from dataclasses import asdict
from hashlib import sha256
import json
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember


def _require(value,reason):
    if not value:raise ValueError('saved IRQ group '+reason)


def _bound_target_offset(topology,members,cpu_port,group_id,cpu_id):
    """Read the group's real host bit offset from the bound member rows.

    The saved topology records each delivered binding, including the target bit
    the producer drives. Requiring every member to agree derives the group
    offset from raw facts instead of assuming the CPU IRQ field starts at zero.
    """
    offsets=set()
    probe=IrqDeliveryGroup(group_id,cpu_id,cpu_port,members)
    for binding in probe.member_bindings():
        rows=[r for r in topology['bindings']
            if (r.get('source_component'),r.get('source_port'),r.get('target_component'),
                r.get('target_port'),r.get('width'),r.get('source_bit_offset')) ==
               (binding.source_component,binding.source_port,binding.target_component,
                binding.target_port,binding.width,binding.source_bit_offset)]
        _require(len(rows)==1,'bound member missing/duplicate')
        offset=rows[0].get('target_bit_offset')
        _require(type(offset) is int and 0<=offset<64,'bound member target offset invalid')
        offsets.add(offset)
    _require(len(offsets)==1,'bound members disagree on target offset')
    return offsets.pop()


def _declared_input_bit_lo(contract,cpu_port):
    """DUT bit that host bit 0 of the CPU IRQ input maps to.

    The F6 contract pins the CPU's IRQ observation contract. Only a declared
    one-bit input (a real bit-slice row, e.g. ``irq_i[11]``) carries that base;
    a wide vector row starts at its own bit 0.
    """
    provider=contract.get('irq',{}).get('native_take_provider')
    if (type(provider) is dict and provider.get('input_port')==cpu_port
            and provider.get('input_width')==1
            and type(provider.get('input_bit_offset')) is int
            and provider['input_bit_offset']>=0):
        return provider['input_bit_offset']
    return 0


def rebuild_group(contract,binding,cpu_port):
    declaration=contract['program_contract'].get('gpio_irq')
    source=contract['dma'].get('source_contract',{})
    schema=source.get('schema_version')
    if schema is not None:
        from .f6_dma_behavior import f6_dma_irq_trigger
        dma_mode=f6_dma_irq_trigger(source)
    else:
        dma_mode='pulse'
    if declaration is None and dma_mode=='pulse':return None
    topology=binding.get('runtime_topology')
    _require(type(topology) is dict,'bound runtime topology missing')
    digest=sha256(json.dumps(topology,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    _require(digest==binding['topology_binding']['topology_sha256'],'bound topology digest mismatch')
    cpu_id=contract['cpu']['instance_id']
    dma_id=contract['dma']['instance_id']
    members=(IrqDeliveryMember(dma_id,'irq',mode=dma_mode,
        pulse_width_ticks=16 if dma_mode=='pulse' else None),)
    if declaration is not None:
        members+=(IrqDeliveryMember(declaration['component'],'interrupt',pulse_width_ticks=4),)
    group_id=declaration['group_id'] if declaration is not None else 'f6-'+dma_id+'-irq'
    offset=_bound_target_offset(topology,members,cpu_port,group_id,cpu_id)
    expected=IrqDeliveryGroup(group_id,cpu_id,cpu_port,members,
        target_bit_offset=offset,target_input_bit_lo=_declared_input_bit_lo(contract,cpu_port))
    groups=[IrqDeliveryGroup.from_document(d) for d in topology.get('irq_delivery_groups',[])]
    _require(len(groups)==1 and groups[0]==expected,'contract membership/mode mismatch')
    bindings=[asdict(b) for b in expected.member_bindings()]
    _require(all(topology['bindings'].count(row)==1 for row in bindings),'bound member missing')
    _require(not any((r['target_component'],r['target_port'],r['target_bit_offset'])==
        (expected.target_component,expected.target_port,expected.target_bit_offset)
        and r not in bindings for r in topology['bindings']),
        'unrelated additional input driver')
    owners=[r['owners'] for r in topology['ownership_inputs'] if (r['component'],r['port'])==
        (expected.target_component,expected.target_port)]
    _require(len(owners)==1 and len(owners[0])>offset
        and owners[0][offset]['kind']=='bound'
        and type(owners[0][offset].get('width')) is int and owners[0][offset]['width']==1
        and type(owners[0][offset].get('bit_offset')) is int
        and owners[0][offset]['bit_offset']==offset
        and owners[0][offset]['producer_ref']==expected.owner_ref
        and sum(r.get('producer_ref')==expected.owner_ref for r in owners[0])==1,
        'unique group owner mismatch')
    return expected


def frame_for_sample(group,sample,events,runner,*,dma_runtime_name=None):
    rows=[r for r in events if r.get('kind')=='irq_group_delivery' and r.get('group_id')==group.group_id
        and r.get('target_component')==group.target_component and r.get('cpu_tick')==sample['local_tick']
        and r.get('target_epoch')==sample['reset_epoch']]
    _require(len(rows)==1,'actual frame missing/duplicate')
    frame=rows[0]
    _require(frame.get('group_sha256')==group.identity_sha256 and frame.get('target_port')==group.target_port
        and frame.get('native_sample_event_id')==sample['event_id']
        and frame.get('cpu_step_event_id')==sample.get('producer_event_id')
        and frame.get('receipt_id')==sample.get('receipt_id'),'frame/native CPU sample identity mismatch')
    members=frame.get('members');_require(type(members) is list and len(members)==len(group.members),'member count')
    target_epoch=frame.get('target_epoch')
    _require(type(target_epoch) is int and target_epoch>=0,'frame target epoch missing')
    active=[]
    for member,row in zip(group.members,members):
        _require(row.get('source_id')==member.source_id and row.get('mode')==member.mode
            and type(row.get('value')) is int and row['value'] in (0,1),'member declaration/value mismatch')
        ref=row.get('native_source');_require(type(ref) is dict,'member sample reference missing')
        raw=runner.get(ref.get('event_id'))
        _require(ref.get('component')==member.source_component
            and type(raw) is dict and raw.get('kind')=='local_tick_sample'
            and raw.get('event_id')==ref.get('event_id')
            and raw.get('component')==member.source_component and raw.get('local_tick')==ref.get('local_tick')
            and type(raw.get('reset_epoch')) is int and raw['reset_epoch']==ref.get('reset_epoch')
            and raw.get('phase')==ref.get('phase') and raw['event_id']<frame['cpu_step_event_id'],
            'member native sample/epoch mismatch')
        # A member sample must belong to the very epoch the frame was measured
        # in; an old-epoch sample can never authenticate a fresh-epoch frame.
        _require(raw['reset_epoch']==target_epoch and ref.get('reset_epoch')==target_epoch,
            'member native sample epoch differs from the frame target epoch')
        values=raw.get('outputs',{});level=values.get(member.source_port)
        _require(type(level) is int and level in (0,1),'member native level unavailable')
        wire=dma_runtime_name if member==group.members[0] and dma_runtime_name is not None else ref.get('runtime_name')
        _require(type(wire) is str and values.get('physical',{}).get(wire)==level,'member physical level mismatch')
        if member.mode=='level':
            latest_ref=row.get('latest_native_source')
            _require(type(latest_ref) is dict and latest_ref.get('component')==member.source_component,
                'member latest native source missing')
            latest=runner.get(latest_ref.get('event_id'))
            _require(type(latest) is dict and latest.get('kind')=='local_tick_sample'
                and latest.get('event_id')==latest_ref.get('event_id')
                and latest.get('component')==member.source_component
                and type(latest.get('reset_epoch')) is int and type(latest_ref.get('reset_epoch')) is int
                and latest.get('reset_epoch')==latest_ref.get('reset_epoch')==target_epoch
                and latest.get('local_tick')==latest_ref.get('local_tick')
                and latest.get('phase')==latest_ref.get('phase')
                and latest.get('event_id')<frame['cpu_step_event_id'],
                'member latest native sample/epoch mismatch')
            latest_values=latest.get('outputs',{})
            latest_wire=(dma_runtime_name if member==group.members[0] and dma_runtime_name is not None
                         else latest_ref.get('runtime_name'))
            _require(type(latest_wire) is str and latest_values.get(member.source_port)==row['value']
                and latest_values.get('physical',{}).get(latest_wire)==row['value'],
                'member latest level mismatch')
            later=[event for event in events if event.get('kind')=='local_tick_sample'
                and event.get('component')==member.source_component
                and event.get('reset_epoch')==target_epoch
                and type(event.get('event_id')) is int
                and latest['event_id']<event['event_id']<frame['cpu_step_event_id']
                and member.source_port in event.get('outputs',{})]
            _require(not later,'member latest native sample stale')
            _require(level==row['value'],'member native level mismatch')
            if row['value']:
                active.append(member.source_id)
            continue
        starts=[r for r in events if r.get('kind')=='pulse_start'
            and r.get('source') in ([member.source_component,member.source_port],(member.source_component,member.source_port))
            and r.get('target') in ([group.target_component,group.target_port],(group.target_component,group.target_port))
            and r['event_id']<frame['cpu_step_event_id']
            and type(r.get('start_cpu_tick')) is int and type(r.get('end_cpu_tick_exclusive')) is int
            and r['start_cpu_tick']<=sample['local_tick']<r['end_cpu_tick_exclusive']]
        _require(len(starts)<=1 and all(r['end_cpu_tick_exclusive']-r['start_cpu_tick']==member.pulse_width_ticks for r in starts),
            'member pulse interval mismatch')
        _require(row['value']==int(bool(starts)),'member pulse/OR value mismatch')
        if row['value']:
            _require(level==1,'active pulse has no native high source')
            active.append(member.source_id)
    value=int(bool(active))
    _require(frame.get('active_sources')==active and frame.get('unique_source')==(active[0] if len(active)==1 else None)
        and frame.get('attribution_status')==('unique' if len(active)==1 else 'joint' if active else 'unknown')
        and type(frame.get('value')) is int and frame['value']==value
        and all(type(sample.get(k)) is int and sample[k]==value for k in
            ('expected_input','actual_pre_input','actual_post_input')),'native CPU input does not equal member OR')
    return frame
