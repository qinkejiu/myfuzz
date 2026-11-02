"""Pure checks for the native Timer smoke's actual supplied program bytes."""
from scripts.run_cv32e20_irq_smoke import fixed_program


def test_timer_program_reuses_cpu_support_and_emits_exact_legal_mmio_stores():
    from scripts.run_timer_irq_smoke import timer_program
    original = fixed_program(0x10080)
    program = timer_program(0x10080, 0x40001000)
    assert program['images'][str(original['handler'])] == original['images'][str(original['handler'])]
    before = bytes.fromhex(original['images'][str(original['boot'])])[:-4]
    main = bytes.fromhex(program['images'][str(program['boot'])])
    assert main.startswith(before)
    regs = [0] * 32
    stores = []
    for offset in range(len(before), len(main) - 4, 4):
        word = int.from_bytes(main[offset:offset+4], 'little')
        rd, rs = word >> 7 & 31, word >> 15 & 31
        if word & 127 == 0x37:
            regs[rd] = word & 0xFFFFF000
        elif word & 127 == 0x13:
            imm = word >> 20
            if imm & 0x800: imm -= 4096
            regs[rd] = (regs[rs] + imm) & 0xFFFFFFFF
        elif word & 127 == 0x23:
            imm = (word >> 25 << 5) | (word >> 7 & 31)
            if imm & 0x800: imm -= 4096
            stores.append(((regs[rs] + imm) & 0xFFFFFFFF, regs[word >> 20 & 31]))
        else:
            raise AssertionError('unexpected trigger instruction')
    assert stores == [(0x40001004, 0), (0x40001008, 0), (0x40001000, 0xFFFFFFFF)]


def evidence():
    from scripts.run_timer_irq_smoke import timer_program
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    program = timer_program(0x10080, 0x40001000)
    contract = ibex_irq_receipt_contract()
    pc = program['vector'] + 44
    insn = int.from_bytes(bytes.fromhex(program['images'][str(pc)])[:4], 'little')
    events = [dict(event_id=1, kind='instr_response', component='cpu', address=program['boot'])]
    for event_id, (offset, value) in enumerate(((4, 0), (8, 0), (0, 0xFFFFFFFF)), 2):
        events.append(dict(event_id=event_id, kind='mmio_delivery', component='cpu', device_id='active',
            offset=offset, address=0x40001000+offset, write=True, write_value=value))
    events.extend([
        dict(event_id=5, kind='local_tick_sample', component='idle', outputs={'irq_o': 0}),
        dict(event_id=6, kind='local_tick_sample', component='active', local_tick=12,
             phase='post', reset_epoch=0, outputs={'irq_o': 1, 'physical': {'timer_wire': 1}}),
        dict(event_id=7, kind='step', component='cpu'),
        dict(event_id=8, kind='cpu_external_irq_sample', component='cpu', local_tick=50,
            producer_event_id=7, observation_contract=contract,
            expected_input=1, actual_pre_input=1, actual_post_input=1, irq_taken_pre=1),
        dict(event_id=9, kind='cpu_external_irq_taken', component='cpu', local_tick=50,
            producer_event_id=7, sample_event_id=8, observation_contract=contract, irq_taken_pre=1,
            irq_serial_observation={'decision': {'status': 'observed', 'value': 1}}),
        dict(event_id=10, kind='irq_group_delivery', native_take_event_id=9,
            native_sample_event_id=8, cpu_tick=50, value=1, attribution_status='unique',
            unique_source='active.irq_o', active_sources=['active.irq_o'],
            members=[{'source_id': 'active.irq_o', 'native_source': {'event_id': 6,
                'phase': 'post', 'reset_epoch': 0, 'local_tick': 12}}]),
        dict(event_id=11, kind='cpu_retire', schema_version='cpu_retire.v2', component='cpu', valid=1, intr=1, trap=0, halt=0,
            pc_rdata=pc, insn=insn, observation_contract=contract,
            irq_serial_observation={'retirement': {'status': 'observed', 'value': 1}})])
    group = source_group()
    events[9].update(group_id=group.group_id, group_sha256=group.identity_sha256,
                     target_component=group.target_component, target_port=group.target_port)
    return events, program, contract


def source_group():
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    return IrqDeliveryGroup('timer-external-irq', 'cpu', 'irq',
        (IrqDeliveryMember('active', 'irq_o', pulse_width_ticks=16),
         IrqDeliveryMember('idle', 'irq_o', pulse_width_ticks=16)))


def check(events, program, contract):
    from scripts.run_timer_irq_smoke import inspect_evidence
    return inspect_evidence(events, program, contract=contract, active='active', idle='idle',
                            timer_wire='timer_wire', timer_base=0x40001000, group=source_group())


def test_smoke_recomputes_raw_pulse_input_and_serial_without_granting_reward():
    events, program, contract = evidence()
    result = check(events, program, contract)
    assert result['status'] == 'verified'
    assert result['reward_eligible'] is False and result['grants_F5'] is False
    assert result['source_version'] == result['isr_mmio'] == 'unknown'


def test_joint_input_missing_raw_pulse_or_zero_serial_cannot_pass():
    import pytest
    for mutate in (lambda e: e[9].update(attribution_status='joint'),
                   lambda e: e[5]['outputs']['physical'].update(timer_wire=0),
                   lambda e: e[8]['irq_serial_observation']['decision'].update(value=0)):
        events, program, contract = evidence()
        mutate(events)
        with pytest.raises(ValueError): check(events, program, contract)


def test_same_program_generator_accepts_declared_spi_trigger_without_timer_writes():
    from scripts.run_timer_irq_smoke import timer_program
    program = timer_program(0x10080, 0x40001000, trigger_writes=((36, 0x80000000),))
    original = fixed_program(0x10080)
    code = bytes.fromhex(program['images'][str(program['boot'])])
    prefix = bytes.fromhex(original['images'][str(original['boot'])])[:-4]
    assert code.startswith(prefix)
    words = [int.from_bytes(code[i:i+4], 'little') for i in range(len(prefix), len(code)-4, 4)]
    stores = [word for word in words if word & 127 == 0x23]
    assert len(stores) == 1
    assert ((stores[0] >> 25 << 5) | (stores[0] >> 7 & 31)) == 36
    assert program['images'][str(program['handler'])] == original['images'][str(original['handler'])]


def test_declared_output_options_are_explicit_and_timer_defaults_remain_legacy():
    from scripts.run_timer_irq_smoke import source_options
    old = source_options({'timer_request': 'timer.json', 'timer_active_base': 0x40001000,
                          'timer_idle_base': 0x40002000, 'pulse_width_ticks': 16})
    assert old['source_adapter'] is None and old['source_port'] == 'irq_o'
    assert old['active_id'] == 'timer_active' and old['source_bit_offset'] == 0
    new = source_options({'source_request': 'spi.json', 'active_base': 0x40001000,
        'idle_base': 0x40002000, 'pulse_width_ticks': 16, 'source_adapter': 'declared-output.v1',
        'source_port': 'events_o', 'source_bit_offset': 0, 'active_id': 'spi_active',
        'idle_id': 'spi_idle', 'trigger_writes': [[36, 0x80000000]]})
    assert new['source_port'] == 'events_o' and new['trigger_writes'] == ((36, 0x80000000),)


def test_declared_spi_event_checker_uses_configured_raw_port_and_trigger():
    from scripts.run_timer_irq_smoke import inspect_evidence
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    events, program, contract = evidence()
    events = [row for row in events if row['event_id'] not in (2, 3)]
    delivery = next(row for row in events if row['event_id'] == 4)
    delivery.update(offset=36, address=0x40001024, write_value=0x80000000)
    for row in events:
        if row.get('kind') == 'local_tick_sample' and row.get('component') in ('active', 'idle'):
            row['outputs']['events_o'] = row['outputs'].pop('irq_o')
    group = IrqDeliveryGroup('declared', 'cpu', 'irq', (
        IrqDeliveryMember('active', 'events_o'), IrqDeliveryMember('idle', 'events_o')))
    frame = next(row for row in events if row.get('kind') == 'irq_group_delivery')
    frame.update(group_id=group.group_id, group_sha256=group.identity_sha256,
        unique_source='active.events_o', active_sources=['active.events_o'])
    frame['members'][0]['source_id'] = 'active.events_o'
    result = inspect_evidence(events, program, contract=contract, active='active', idle='idle',
        timer_wire='timer_wire', timer_base=0x40001000, group=group, source_port='events_o',
        source_width=2, trigger_writes=((36, 0x80000000),), transport_only=True)
    assert result['scope'] == 'declared-IP-output-to-CPU-first-handler'
    assert result['transport_only'] is True
    assert result['reward_eligible'] is False and result['source_version'] == 'unknown'


def test_protocol_target_factory_rejects_unknown_kind_without_fallback():
    from types import SimpleNamespace
    import pytest
    from scripts.run_timer_irq_smoke import target_session
    with pytest.raises(ValueError):
        target_session(SimpleNamespace(runtime_document={'kind': 'invented'}),
                       base='.', cache='/tmp/unused-declared-target')
