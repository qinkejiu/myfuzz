"""Document a single F1 instruction's physically sampled retirement."""


def observe_f1_retirement(events, *, cpu, execution_id, epoch, address, word,
                          source_event_id):
    """Return actual RVFI observation or unknown, without awarding feedback credit.

    This uses only events available at the case boundary. A later retirement is
    unknown at this point, not proof of failure; fetch is never retirement.
    """
    unknown = {'status': 'unknown', 'reward_eligible': False}
    if type(source_event_id) is not int:
        return unknown
    matches = []
    for event in events:
        if (event.get('kind') != 'cpu_retire' or event.get('schema_version') != 'cpu_retire.v2'
                or event.get('component') != cpu or event.get('source_component') != cpu
                or event.get('execution_id') != execution_id or event.get('source_epoch') != epoch
                or event.get('reset_epoch') != epoch or event.get('pc_rdata') != address
                or event.get('insn') != word or event.get('valid') != 1
                or type(event.get('event_id')) is not int or event['event_id'] <= source_event_id
                or type(event.get('order')) is not int):
            continue
        observation = event.get('observation')
        if not isinstance(observation, dict) or observation.get('sampling_edge') != 'post_rising':
            continue
        physical = observation.get('physical')
        if not isinstance(physical, dict) or any(physical.get('rvfi_' + key) != event[key]
                for key in ('valid', 'order', 'pc_rdata', 'insn')):
            continue
        matches.append((event, physical))
    if len(matches) != 1:
        return unknown
    event, physical = matches[0]
    def actual(name):
        value = event.get(name)
        return value if type(value) is int and physical.get('rvfi_' + name) == value else None
    return {'status': 'observed', 'event_id': event['event_id'], 'order': event['order'],
            'pc': address, 'instruction': word, 'reset_epoch': epoch,
            'rd_addr': actual('rd_addr'), 'rd_wdata': actual('rd_wdata'),
            'rs1_addr': actual('rs1_addr'), 'rs1_rdata': actual('rs1_rdata'),
            'rs2_addr': actual('rs2_addr'), 'rs2_rdata': actual('rs2_rdata'),
            'trap': actual('trap'), 'reward_eligible': False}


def observe_f1_word_retirements(events, *, cpu, execution_id, epoch, address, raw,
                                source_event_id):
    """Join each of two 16-bit instructions to its own retirement event."""
    if type(raw) is not bytes or len(raw) != 4 or raw[0] & 3 == 3 or raw[2] & 3 == 3:
        raise ValueError('two compressed instruction parcels required')
    observations = [observe_f1_retirement(events, cpu=cpu, execution_id=execution_id,
        epoch=epoch, address=address + offset, word=int.from_bytes(raw[offset:offset+2], 'little'),
        source_event_id=source_event_id) for offset in (0, 2)]
    observed = (all(row['status'] == 'observed' for row in observations)
                and observations[0]['order'] < observations[1]['order'])
    return {'status': 'observed' if observed else 'unknown', 'instructions': observations,
            'reward_eligible': False}
