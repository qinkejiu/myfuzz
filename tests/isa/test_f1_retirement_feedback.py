from copy import deepcopy

from myfuzz.isa.f1_retirement import observe_f1_retirement


def retirement(**changes):
    physical = {'rvfi_valid': 1, 'rvfi_order': 7, 'rvfi_pc_rdata': 0x11000,
                'rvfi_insn': 0x00100613, 'rvfi_rd_addr': 12,
                'rvfi_rd_wdata': 1, 'rvfi_trap': 0}
    event = {'kind': 'cpu_retire', 'schema_version': 'cpu_retire.v2',
             'component': 'cpu', 'source_component': 'cpu',
             'execution_id': 'local-execution', 'source_epoch': 2,
             'reset_epoch': 2, 'event_id': 101, 'valid': 1,
             'order': 7, 'pc_rdata': 0x11000, 'insn': 0x00100613,
             'rd_addr': 12, 'rd_wdata': 1, 'trap': 0,
             'observation': {'sampling_edge': 'post_rising', 'physical': physical}}
    event.update(changes)
    return event


def observe(events):
    return observe_f1_retirement(events, cpu='cpu', execution_id='local-execution',
                                 epoch=2, address=0x11000, word=0x00100613,
                                 source_event_id=100)


def test_real_retirement_yields_observed_instruction_and_register_value():
    result = observe([retirement()])
    assert result['status'] == 'observed'
    assert result['event_id'] == 101
    assert result['rd_addr'] == 12 and result['rd_wdata'] == 1
    assert result['reward_eligible'] is False


def test_fetch_missing_or_wrong_scope_remains_unknown():
    assert observe([{'kind': 'instr_response', 'address': 0x11000}])['status'] == 'unknown'
    for change in ({'source_epoch': 1}, {'component': 'other'}, {'execution_id': 'old'},
                   {'event_id': 99}, {'pc_rdata': 0x11004}, {'insn': 0x13}):
        assert observe([retirement(**change)])['status'] == 'unknown'


def test_missing_or_inconsistent_physical_fields_never_fabricate_result():
    event = retirement()
    del event['observation']['physical']['rvfi_rd_wdata']
    result = observe([event])
    assert result['status'] == 'observed' and result['rd_wdata'] is None
    event = retirement()
    event['observation']['physical']['rvfi_insn'] ^= 1
    assert observe([event])['status'] == 'unknown'
    assert observe([retirement(), deepcopy(retirement())])['status'] == 'unknown'


def test_retirement_reports_physically_sampled_register_operands_when_available():
    event = retirement()
    event.update(rs1_addr=12, rs1_rdata=7, rs2_addr=13, rs2_rdata=14)
    event['observation']['physical'].update(rvfi_rs1_addr=12, rvfi_rs1_rdata=7,
                                            rvfi_rs2_addr=13, rvfi_rs2_rdata=14)
    result = observe([event])
    assert (result['rs1_addr'], result['rs1_rdata'], result['rs2_addr'], result['rs2_rdata']) == (12, 7, 13, 14)
    event['observation']['physical']['rvfi_rs1_rdata'] = 8
    assert observe([event])['rs1_rdata'] is None
