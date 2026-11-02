"""A recorded component stream must preserve its live identity and completeness."""
import copy

import pytest


def recorded_trace():
    nonce = 'a' * 32
    return {'schema_version': 'local_command_trace.v1', 'sessions': {
        'device': {'complete': True,
                   'identity': {'build_digest': 'b' * 64, 'binary_sha256': 'c' * 64,
                                'execution_nonce': nonce},
                   'records': [{'sequence': 1, 'reset_epoch': 0,
                                'command': f'CMD {nonce} 1 STEP_WB_REG',
                                'reply': f'RESULT {nonce} 1 0 1 payload'}]}}}


def test_selects_commands_and_actual_replies_from_recorded_session():
    from scripts.measure_local_coverage import select_recorded_session
    commands, replies, binary = select_recorded_session(recorded_trace(), 'device', 'b' * 64)
    assert commands == ['CMD ' + 'a' * 32 + ' 1 STEP_WB_REG']
    assert replies == ['RESULT ' + 'a' * 32 + ' 1 0 1 payload']
    assert binary == 'c' * 64


@pytest.mark.parametrize('mutation', ['incomplete', 'wrong_build', 'wrong_nonce',
                                      'wrong_sequence', 'new_epoch', 'empty'])
def test_refuses_incomplete_or_unrelated_recorded_sessions(mutation):
    from scripts.measure_local_coverage import select_recorded_session
    document = copy.deepcopy(recorded_trace())
    session = document['sessions']['device']
    if mutation == 'incomplete': session['complete'] = False
    elif mutation == 'wrong_build': session['identity']['build_digest'] = 'd' * 64
    elif mutation == 'wrong_nonce': session['identity']['execution_nonce'] = 'd' * 32
    elif mutation == 'wrong_sequence': session['records'][0]['sequence'] = 2
    elif mutation == 'new_epoch': session['records'][0]['reset_epoch'] = 1
    else: session['records'] = []
    with pytest.raises(ValueError):
        select_recorded_session(document, 'device', 'b' * 64)


def long_recorded_trace(count):
    document=recorded_trace()
    row=document['sessions']['device']
    nonce=row['identity']['execution_nonce']
    row['records']=[{'sequence':i,'reset_epoch':0,'command':f'CMD {nonce} {i:x} STEP_WB_REG',
                     'reply':f'RESULT {nonce} {i:x} 0 1 payload'} for i in range(1,count+1)]
    return document


def test_long_prefix_requires_explicit_command_budget_and_is_not_truncated():
    from scripts.measure_local_coverage import select_recorded_session
    trace=long_recorded_trace(513)
    with pytest.raises(ValueError):select_recorded_session(trace,'device','b'*64)
    commands,replies,_=select_recorded_session(trace,'device','b'*64,max_commands=600)
    assert len(commands)==len(replies)==513


def test_explicit_count_budget_does_not_remove_total_wire_byte_limit():
    from scripts.measure_local_coverage import select_recorded_session
    with pytest.raises(ValueError,match='input.*budget'):
        select_recorded_session(long_recorded_trace(513),'device','b'*64,max_commands=600,max_input_bytes=100)
