"""F5 clear-write and cause-bit accounting on parsed case lines (no RTL)."""
from scripts.run_inprocess_f1f6 import classify_case, correspondence, parse_case_line

IRQ = dict(port='irq_o', bit=0, trigger='level', polarity='active_high',
           pulse_ticks=0, status_offset=0, trigger_offsets=[4, 8, 0],
           status_kind='status', cause_declared=True, cause_bits=[0, 1],
           cause_mask=3, clear={'offset': 0x24, 'value': 1})
WINDOWS = dict(ip_base=0x40001000, ip_size=0x1000, ram_base=0x10000,
               ram_size=0x10000, data_base=0x14000)
LAYOUT = dict(slot=0x12000, slot_return=0x12000, mailbox=0x3000, flag=0x3020,
              result_f5=0x3024, ip_base=0x40001000, data_base=0x14000)


def line(**overrides):
    fields = dict(
        index=0, status='observations_passed', flow='F5',
        record='F5:00000001:00000002:00000003', trigger_writes=3,
        trigger_writes_declared=3, trigger_writes_observed=3, clear_writes=1,
        last_trigger_offset=0, last_trigger_data=3, last_clear_offset=0x24,
        last_clear_data=1, target_reads=1, target_read_offset=0,
        target_read_data=3, irq_edges=1, irq_takes=1, device_high_ticks=1,
        delivered_high_ticks=1, isr_result=3, isr_flag=1, isr_read_addr=0x40001000,
        isr_read_value=3, isr_read_register_kind='status', isr_cause=1)
    fields.update(overrides)
    index, status = fields.pop('index'), fields.pop('status')
    return parse_case_line(
        f'case {index} {status} ' + ' '.join(f'{key} {value}' for key, value in fields.items()),
        flows={'F5'})


def record():
    return dict(flow='F5', fields=(1, 2, 3), text='F5:00000001:00000002:00000003')


def check(case):
    return correspondence(record(), case, layout=LAYOUT, windows=WINDOWS,
                          irq=IRQ, dma=None, protocol='apb3', pins=None)


def test_trigger_and_clear_writes_are_counted_apart_and_both_required():
    assert check(line()) is None
    assert 'trigger' in check(line(trigger_writes_observed=2))
    assert 'clear' in check(line(clear_writes=0))
    assert 'clear' in check(line(last_clear_data=2))


def test_a_declared_cause_bit_must_be_set_and_unknown_is_refused():
    assert check(line(isr_cause='unknown')) is not None
    assert check(line(isr_cause=0)) is not None
    assert check(line(isr_cause=2)) is None


def test_without_a_declared_clear_no_clear_write_is_expected():
    irq = dict(IRQ, clear=None, cause_declared=False, cause_mask=0)
    case = line(clear_writes=0, last_clear_offset=0, last_clear_data=0,
                isr_cause='unknown')
    assert correspondence(record(), case, layout=LAYOUT, windows=WINDOWS,
                          irq=irq, dma=None, protocol='apb3', pins=None) is None


def test_a_level_link_still_asserted_after_the_handler_is_not_a_pass():
    # The C++ host samples each declared level link's raw output at the last
    # tick of the case and prints the mask.  A selected level link whose bit is
    # still set is a real uncleared signal, not a pass and not "not_triggered".
    check_ok = check(line())
    assert check_ok is None
    stuck = line(irq_level_final=1)
    reason = check(stuck)
    assert reason is not None and 'still asserted' in reason


def test_a_stuck_level_on_another_link_does_not_fail_the_selected_link():
    # Only the selected link's bit is attributed to this case.  A different
    # link's stuck level is a cross-case fact for the classifier, not a reason
    # to rewrite this case's own status read.
    assert check(line(irq_level_final=2)) is None


def test_a_reported_level_storm_is_refused_and_classified_as_an_anomaly():
    # The C++ host aborts a level storm at the take limit: the case line carries
    # `level_stuck 1` and the devices were reset, so the final level is 0.  The
    # storm itself is the finding, and it is never "expected" input behaviour.
    storm = line(status='failed', level_stuck=1, irq_takes=5, irq_level_final=0)
    reason = check(storm)
    assert reason is not None and 'storm' in reason
    verdict = classify_case(storm)
    assert verdict['failure_class'] == 'level_irq_left_asserted'
    assert verdict['severity'] == 'anomaly'
    assert verdict['expected'] is False
    # A clean line still carries `level_stuck 0` and is neither refused nor a
    # finding: the new key must not turn an ordinary correct-clear case red.
    assert check(line(level_stuck=0)) is None
    assert classify_case(line(level_stuck=0))['failure_class'] == 'passed'
